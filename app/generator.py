import base64
import json
import urllib.parse
from typing import List, Dict, Any
from app.config import WS_PATH_VLESS, WS_PATH_TROJAN, PRESET_CLEAN_IPS, PRESET_FRAGMENT

def generate_vless_link(user: Dict[str, Any], domain: str, clean_ip: str = None, preset: str = "iran") -> str:
    address = clean_ip if clean_ip else domain
    sni = domain
    host = domain
    port = 443
    path = WS_PATH_VLESS
    
    # Regional optimizations
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "host": host,
        "path": path,
        "sni": sni,
        "fp": "chrome"
    }

    if preset == "iran":
        params["path"] = f"{path}?ed=2048"
        params["alpn"] = "h2,http/1.1"
        remark = f"Milijon-VL-IR-{'CleanIP' if clean_ip else 'Direct'}-{user['username']}"
    elif preset == "china":
        params["alpn"] = "h2,http/1.1"
        remark = f"Milijon-VL-CN-{'CDN' if clean_ip else 'Direct'}-{user['username']}"
    elif preset == "russia":
        params["alpn"] = "h2,http/1.1"
        remark = f"Milijon-VL-RU-{'CDN' if clean_ip else 'Direct'}-{user['username']}"
    else:
        remark = f"Milijon-VL-{user['username']}"

    query_str = urllib.parse.urlencode(params)
    return f"vless://{user['uuid']}@{address}:{port}?{query_str}#{urllib.parse.quote(remark)}"

def generate_trojan_link(user: Dict[str, Any], domain: str, clean_ip: str = None, preset: str = "iran") -> str:
    address = clean_ip if clean_ip else domain
    sni = domain
    host = domain
    port = 443
    path = WS_PATH_TROJAN
    
    params = {
        "security": "tls",
        "type": "ws",
        "host": host,
        "path": path,
        "sni": sni,
        "fp": "chrome"
    }

    if preset == "iran":
        params["alpn"] = "h2,http/1.1"
        remark = f"Milijon-TR-IR-{'CleanIP' if clean_ip else 'Direct'}-{user['username']}"
    elif preset == "china":
        params["alpn"] = "h2,http/1.1"
        remark = f"Milijon-TR-CN-{user['username']}"
    else:
        remark = f"Milijon-TR-{user['username']}"

    query_str = urllib.parse.urlencode(params)
    return f"trojan://{user['password']}@{address}:{port}?{query_str}#{urllib.parse.quote(remark)}"

def generate_vmess_link(user: Dict[str, Any], domain: str, clean_ip: str = None, preset: str = "iran") -> str:
    address = clean_ip if clean_ip else domain
    remark = f"Milijon-VMess-{'IR' if preset == 'iran' else 'Global'}-{user['username']}"
    
    vmess_obj = {
        "v": "2",
        "ps": remark,
        "add": address,
        "port": 443,
        "id": user["uuid"],
        "aid": 0,
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": domain,
        "path": f"{WS_PATH_VLESS}?ed=2048" if preset == "iran" else WS_PATH_VLESS,
        "tls": "tls",
        "sni": domain,
        "alpn": "h2,http/1.1"
    }
    raw_json = json.dumps(vmess_obj, ensure_ascii=False)
    b64 = base64.b64encode(raw_json.encode('utf-8')).decode('utf-8')
    return f"vmess://{b64}"

def generate_all_links_for_user(user: Dict[str, Any], domain: str) -> List[str]:
    links = []
    preset = user.get("country_preset", "iran")
    clean_ips = PRESET_CLEAN_IPS.get(preset, PRESET_CLEAN_IPS["iran"])

    # 1. Direct VLESS & Trojan
    links.append(generate_vless_link(user, domain, clean_ip=None, preset=preset))
    links.append(generate_trojan_link(user, domain, clean_ip=None, preset=preset))
    links.append(generate_vmess_link(user, domain, clean_ip=None, preset=preset))

    # 2. Optimized Clean IP links (top 2 clean IPs for this region)
    for i, ip in enumerate(clean_ips[:2]):
        links.append(generate_vless_link(user, domain, clean_ip=ip, preset=preset))
        links.append(generate_trojan_link(user, domain, clean_ip=ip, preset=preset))

    return links

def generate_base64_subscription(user: Dict[str, Any], domain: str) -> str:
    links = generate_all_links_for_user(user, domain)
    raw_sub = "\n".join(links)
    return base64.b64encode(raw_sub.encode('utf-8')).decode('utf-8')

def generate_clash_meta_yaml(user: Dict[str, Any], domain: str) -> str:
    preset = user.get("country_preset", "iran")
    clean_ip = PRESET_CLEAN_IPS.get(preset, ["104.16.132.229"])[0]

    yaml_content = f"""# Milijon Clash Meta / Mihomo Config for {user['username']}
port: 7890
socks-port: 7891
allow-lan: false
mode: rule
log-level: info
ipv6: false

proxies:
  - name: "Milijon-VLESS-Direct"
    type: vless
    server: {domain}
    port: 443
    uuid: {user['uuid']}
    network: ws
    tls: true
    udp: true
    servername: {domain}
    client-fingerprint: chrome
    ws-opts:
      path: "{WS_PATH_VLESS}"
      headers:
        Host: {domain}

  - name: "Milijon-VLESS-CleanIP"
    type: vless
    server: {clean_ip}
    port: 443
    uuid: {user['uuid']}
    network: ws
    tls: true
    udp: true
    servername: {domain}
    client-fingerprint: chrome
    ws-opts:
      path: "{WS_PATH_VLESS}?ed=2048"
      headers:
        Host: {domain}

  - name: "Milijon-Trojan-Direct"
    type: trojan
    server: {domain}
    port: 443
    password: {user['password']}
    network: ws
    tls: true
    udp: true
    sni: {domain}
    client-fingerprint: chrome
    ws-opts:
      path: "{WS_PATH_TROJAN}"
      headers:
        Host: {domain}

proxy-groups:
  - name: "🚀 PROXY"
    type: select
    proxies:
      - "Milijon-VLESS-CleanIP"
      - "Milijon-VLESS-Direct"
      - "Milijon-Trojan-Direct"
      - DIRECT

rules:
  - GEOIP,IR,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🚀 PROXY
"""
    return yaml_content

def generate_singbox_json(user: Dict[str, Any], domain: str) -> str:
    preset = user.get("country_preset", "iran")
    clean_ip = PRESET_CLEAN_IPS.get(preset, ["104.16.132.229"])[0]

    singbox_config = {
        "log": {"level": "info"},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}
        ],
        "outbounds": [
            {
                "type": "selector",
                "tag": "select",
                "outbounds": ["vless-clean-ip", "vless-direct", "trojan-direct", "direct"]
            },
            {
                "type": "vless",
                "tag": "vless-clean-ip",
                "server": clean_ip,
                "server_port": 443,
                "uuid": user["uuid"],
                "tls": {
                    "enabled": True,
                    "server_name": domain,
                    "utls": {"enabled": True, "fingerprint": "chrome"}
                },
                "transport": {
                    "type": "ws",
                    "path": f"{WS_PATH_VLESS}?ed=2048",
                    "headers": {"Host": domain}
                }
            },
            {
                "type": "vless",
                "tag": "vless-direct",
                "server": domain,
                "server_port": 443,
                "uuid": user["uuid"],
                "tls": {
                    "enabled": True,
                    "server_name": domain,
                    "utls": {"enabled": True, "fingerprint": "chrome"}
                },
                "transport": {
                    "type": "ws",
                    "path": WS_PATH_VLESS,
                    "headers": {"Host": domain}
                }
            },
            {
                "type": "trojan",
                "tag": "trojan-direct",
                "server": domain,
                "server_port": 443,
                "password": user["password"],
                "tls": {
                    "enabled": True,
                    "server_name": domain,
                    "utls": {"enabled": True, "fingerprint": "chrome"}
                },
                "transport": {
                    "type": "ws",
                    "path": WS_PATH_TROJAN,
                    "headers": {"Host": domain}
                }
            },
            {"type": "direct", "tag": "direct"}
        ]
    }
    return json.dumps(singbox_config, indent=2)
