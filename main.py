import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import time
import datetime
from typing import Optional
from fastapi import FastAPI, Request, Response, WebSocket, HTTPException, status, Query
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

try:
    import psutil
except ImportError:
    psutil = None

from app.config import (
    PORT, HOST, ADMIN_PASSWORD, SECRET_KEY, SERVER_DOMAIN,
    WS_PATH_VLESS, WS_PATH_TROJAN, PRESET_CLEAN_IPS, PRESET_FRAGMENT
)
from app.database import (
    init_db, get_all_users, get_user_by_uuid, get_user_by_username,
    create_user, delete_user, toggle_user_status
)
from app.proxy_engine import handle_vless_websocket, handle_trojan_websocket
from app.generator import (
    generate_vless_link, generate_trojan_link, generate_vmess_link,
    generate_all_links_for_user, generate_base64_subscription,
    generate_clash_meta_yaml, generate_singbox_json
)

app = FastAPI(title="Milijon Proxy Worker", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

START_TIME = time.time()
templates_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app", "templates")
templates = Jinja2Templates(directory=templates_dir)

@app.on_event("startup")
def on_startup():
    init_db()

def check_auth(request: Request):
    auth_header = request.headers.get("Authorization")
    auth_cookie = request.cookies.get("milijon_token")
    expected_token = f"Bearer {ADMIN_PASSWORD}"
    
    if auth_header and auth_header == expected_token:
        return True
    if auth_cookie and auth_cookie == ADMIN_PASSWORD:
        return True
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin credentials")

def get_effective_domain(request: Request) -> str:
    if SERVER_DOMAIN and SERVER_DOMAIN.strip():
        return SERVER_DOMAIN.strip()
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or "localhost"
    if ":" in host and ("railway.app" in host or host.startswith("localhost")):
        pass
    return host.split(":")[0] if "railway.app" in host else host

class UserCreateRequest(BaseModel):
    username: str
    uuid: Optional[str] = None
    password: Optional[str] = None
    expires_at: Optional[str] = None
    country_preset: Optional[str] = "iran"
    notes: Optional[str] = ""

class LoginRequest(BaseModel):
    password: str

@app.get("/", response_class=HTMLResponse)
async def serve_index(request: Request):
    domain = get_effective_domain(request)
    return templates.TemplateResponse("index.html", {
        "request": request,
        "domain": domain,
        "vless_path": WS_PATH_VLESS,
        "trojan_path": WS_PATH_TROJAN
    })

@app.get("/health")
@app.get("/api/health")
@app.get("/api/v1/health")
async def health_check():
    return {
        "status": "healthy",
        "app": "Milijon",
        "uptime_seconds": int(time.time() - START_TIME)
    }

@app.post("/api/login")
@app.post("/api/v1/login")
async def login(req: LoginRequest, response: Response):
    if req.password == ADMIN_PASSWORD:
        response.set_cookie(
            key="milijon_token",
            value=ADMIN_PASSWORD,
            httponly=True,
            samesite="lax",
            max_age=86400 * 30
        )
        return {"success": True, "token": ADMIN_PASSWORD}
    raise HTTPException(status_code=401, detail="رمز عبور اشتباه است / Invalid password")

@app.get("/api/me")
async def check_admin(request: Request):
    check_auth(request)
    return {"authenticated": True}

@app.get("/api/stats")
@app.get("/api/v1/stats")
async def get_system_stats(request: Request):
    check_auth(request)
    uptime_sec = int(time.time() - START_TIME)
    uptime_str = str(datetime.timedelta(seconds=uptime_sec))
    
    users = get_all_users()
    total_users = len(users)
    active_users = sum(1 for u in users if u["is_active"] == 1)
    total_up = sum(u["upload_bytes"] for u in users)
    total_down = sum(u["download_bytes"] for u in users)

    mem, cpu = 0.0, 0.0
    if psutil:
        try:
            mem = psutil.virtual_memory().percent
            cpu = psutil.cpu_percent(interval=None)
        except Exception:
            pass

    return {
        "uptime": uptime_str,
        "uptime_seconds": uptime_sec,
        "total_users": total_users,
        "active_users": active_users,
        "total_upload_bytes": total_up,
        "total_download_bytes": total_down,
        "memory_percent": mem,
        "cpu_percent": cpu,
        "server_domain": get_effective_domain(request),
        "vless_path": WS_PATH_VLESS,
        "trojan_path": WS_PATH_TROJAN,
        "clean_ips": PRESET_CLEAN_IPS,
        "fragment_presets": PRESET_FRAGMENT
    }

@app.get("/api/users")
@app.get("/api/v1/users")
async def list_users(request: Request):
    check_auth(request)
    domain = get_effective_domain(request)
    users = get_all_users()
    result = []
    for u in users:
        u_dict = dict(u)
        u_dict["vless_link"] = generate_vless_link(u_dict, domain, preset=u_dict.get("country_preset", "iran"))
        u_dict["trojan_link"] = generate_trojan_link(u_dict, domain, preset=u_dict.get("country_preset", "iran"))
        u_dict["vmess_link"] = generate_vmess_link(u_dict, domain, preset=u_dict.get("country_preset", "iran"))
        u_dict["sub_url"] = f"{request.base_url}sub/{u_dict['uuid']}"
        result.append(u_dict)
    return result

@app.post("/api/users")
async def add_user(req: UserCreateRequest, request: Request):
    check_auth(request)
    existing = get_user_by_username(req.username)
    if existing:
        raise HTTPException(status_code=400, detail="این نام کاربری از قبل وجود دارد / Username already exists")
    
    user = create_user(
        username=req.username,
        user_uuid=req.uuid,
        password=req.password,
        expires_at=req.expires_at,
        country_preset=req.country_preset or "iran",
        notes=req.notes or ""
    )
    return user

@app.post("/api/users/{user_id}/toggle")
async def toggle_user(user_id: int, request: Request):
    check_auth(request)
    new_status = toggle_user_status(user_id)
    if new_status is None:
        raise HTTPException(status_code=404, detail="کاربر یافت نشد / User not found")
    return {"id": user_id, "is_active": new_status}

@app.delete("/api/users/{user_id}")
async def remove_user(user_id: int, request: Request):
    check_auth(request)
    success = delete_user(user_id)
    if not success:
        raise HTTPException(status_code=404, detail="کاربر یافت نشد / User not found")
    return {"success": True}

@app.get("/api/users/{user_id}/links")
async def get_user_links(user_id: int, request: Request, clean_ip: Optional[str] = None):
    check_auth(request)
    domain = get_effective_domain(request)
    users = get_all_users()
    user = next((u for u in users if u["id"] == user_id), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    preset = user.get("country_preset", "iran")
    vless_direct = generate_vless_link(user, domain, clean_ip=None, preset=preset)
    vless_clean = generate_vless_link(user, domain, clean_ip=clean_ip or PRESET_CLEAN_IPS[preset][0], preset=preset)
    trojan_direct = generate_trojan_link(user, domain, clean_ip=None, preset=preset)
    vmess_direct = generate_vmess_link(user, domain, clean_ip=None, preset=preset)
    
    clash_yaml = generate_clash_meta_yaml(user, domain)
    singbox_json = generate_singbox_json(user, domain)
    sub_url = f"{request.base_url}sub/{user['uuid']}"

    return {
        "user": user,
        "vless_direct": vless_direct,
        "vless_clean": vless_clean,
        "trojan_direct": trojan_direct,
        "vmess_direct": vmess_direct,
        "sub_url": sub_url,
        "clash_yaml": clash_yaml,
        "singbox_json": singbox_json
    }

@app.get("/sub/{token}")
@app.get("/api/v1/sub/{token}")
async def get_subscription(
    token: str,
    request: Request,
    format: Optional[str] = Query(None, alias="type")
):
    token = token.strip()
    user = get_user_by_uuid(token)
    if not user:
        user = get_user_by_username(token)
    
    if not user or user["is_active"] != 1:
        raise HTTPException(status_code=404, detail="اشتراک یافت نشد یا غیرفعال است / Subscription not found or inactive")

    domain = get_effective_domain(request)
    req_format = (format or "b64").lower()

    userinfo_header = f"upload={user['upload_bytes']}; download={user['download_bytes']}; total=1073741824000; expire=0"
    headers = {
        "Subscription-Userinfo": userinfo_header,
        "Profile-Update-Interval": "12",
        "Profile-Title": f"Milijon - {user['username']}"
    }

    if req_format in ["clash", "meta"]:
        yaml_content = generate_clash_meta_yaml(user, domain)
        headers["Content-Disposition"] = f'attachment; filename="milijon_{user["username"]}_clash.yaml"'
        return Response(content=yaml_content, media_type="text/yaml; charset=utf-8", headers=headers)

    elif req_format in ["singbox", "sb"]:
        json_content = generate_singbox_json(user, domain)
        headers["Content-Disposition"] = f'attachment; filename="milijon_{user["username"]}_singbox.json"'
        return Response(content=json_content, media_type="application/json; charset=utf-8", headers=headers)

    elif req_format in ["raw", "plain"]:
        links = generate_all_links_for_user(user, domain)
        return PlainTextResponse("\n".join(links), headers=headers)

    else:
        b64_content = generate_base64_subscription(user, domain)
        headers["Content-Disposition"] = f'inline; filename="Milijon_{user["username"]}.txt"'
        return PlainTextResponse(b64_content, headers=headers)

@app.websocket(WS_PATH_VLESS)
async def vless_websocket_endpoint(websocket: WebSocket):
    await handle_vless_websocket(websocket)

@app.websocket(WS_PATH_TROJAN)
async def trojan_websocket_endpoint(websocket: WebSocket):
    await handle_trojan_websocket(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=HOST, port=PORT, reload=False)
