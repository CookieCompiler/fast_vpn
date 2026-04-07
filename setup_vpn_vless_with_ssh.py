#!/usr/bin/env python3
import os, subprocess, uuid, secrets, json, textwrap, pathlib, sys

def run(cmd, check=True):
    print("+", " ".join(cmd))
    return subprocess.run(cmd, check=check)

def write(path, data, mode=0o600):
    pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.write(data)
    os.chmod(path, mode)

if os.geteuid() != 0:
    sys.exit("Run as root")

# --- Load / generate env variables ---
SSH_USER = os.environ.get("SERVER_SSH_USER") or "vpnadmin"
SSH_PASS = os.environ.get("SERVER_SSH_PASS") or secrets.token_urlsafe(16)
VLESS_PASS = os.environ.get("VLESS_PASS")  # optional pass field — will be placed in metadata
WG_CLIENT_NAME = os.environ.get("WG_CLIENT_NAME") or "client1"

# VPN / VLESS settings (editable)
WG_INTERFACE = "wg0"
WG_PORT = int(os.environ.get("WG_PORT","51820"))
WG_NETWORK = "10.10.0.0/24"
WG_SERVER_IP = "10.10.0.1/24"
WG_CLIENT_IP = "10.10.0.2/32"

VLESS_PORT = int(os.environ.get("VLESS_PORT","443"))
VLESS_PATH = os.environ.get("VLESS_PATH","/vless")
VLESS_FLOW = os.environ.get("VLESS_FLOW","")  # optional
MAIN_IF = os.environ.get("MAIN_IF","eth0")

# --- Determine external IP ---
try:
    ext_ip = subprocess.check_output(["curl","-fsSL","https://ifconfig.me"]).decode().strip()
except Exception:
    ext_ip = os.environ.get("SERVER_IP","YOUR_SERVER_IP")

# --- Install required packages ---
run(["apt","update"])
run(["apt","install","-y","wireguard","qrencode","curl","iptables","iptables-persistent","unzip","ssh","openssl","wget"])

# --- Create SSH user and set password ---
# create user if not exists
try:
    subprocess.check_call(["id", SSH_USER])
    user_exists = True
except subprocess.CalledProcessError:
    user_exists = False

if not user_exists:
    run(["useradd","-m","-s","/bin/bash",SSH_USER])
# set password
run(["chpasswd"], check=True, )
p = subprocess.Popen(["chpasswd"], stdin=subprocess.PIPE)
p.communicate(f"{SSH_USER}:{SSH_PASS}".encode())
# add to sudoers (NOPASSWD not added, regular sudo)
run(["usermod","-aG","sudo",SSH_USER])

# --- Ensure SSH server allows password auth for this user and disable root login ---
sshd_conf = "/etc/ssh/sshd_config"
# backup
if not os.path.exists(sshd_conf + ".bak"):
    run(["cp",sshd_conf,sshd_conf + ".bak"])
# minimal safe changes: PermitRootLogin no, PasswordAuthentication yes (so created user can use), ChallengeResponseAuthentication no
with open(sshd_conf, "r") as f:
    s = f.read()
def set_conf(s, key, val):
    import re
    if re.search(r'^\s*'+key+r'\s+', s, flags=re.M):
        s = re.sub(r'^\s*'+key+r'.*$', f'{key} {val}', s, flags=re.M)
    else:
        s += f'\n{key} {val}\n'
    return s
s = set_conf(s, "PermitRootLogin", "no")
s = set_conf(s, "PasswordAuthentication", "yes")
s = set_conf(s, "ChallengeResponseAuthentication", "no")
write(sshd_conf, s, 0o600)
run(["systemctl","restart","ssh"])

# --- WireGuard setup ---
# generate keys
priv = subprocess.check_output(["wg","genkey"]).decode().strip()
pub = subprocess.check_output(["bash","-c",f"echo {priv} | wg pubkey"]).decode().strip()
client_priv = subprocess.check_output(["wg","genkey"]).decode().strip()
client_pub = subprocess.check_output(["bash","-c",f"echo {client_priv} | wg pubkey"]).decode().strip()

wg_server_conf = textwrap.dedent(f"""\
[Interface]
Address = {WG_SERVER_IP}
ListenPort = {WG_PORT}
PrivateKey = {priv}

[Peer]
PublicKey = {client_pub}
AllowedIPs = {WG_CLIENT_IP}
""")
write(f"/etc/wireguard/{WG_INTERFACE}.conf", wg_server_conf, 0o600)
run(["systemctl","enable","--now",f"wg-quick@{WG_INTERFACE}"])

wg_client_conf = textwrap.dedent(f"""\
[Interface]
PrivateKey = {client_priv}
Address = {WG_CLIENT_IP}
DNS = 1.1.1.1

[Peer]
PublicKey = {pub}
Endpoint = {ext_ip}:{WG_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
""")
write(f"/root/{WG_CLIENT_NAME}-wg.conf", wg_client_conf, 0o600)

# --- Install Xray (VLESS) ---
XRAY_URL = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
run(["apt","install","-y","ca-certificates","unzip"])
tmpdir = "/tmp/xray_install"
os.makedirs(tmpdir, exist_ok=True)
zipfile = f"{tmpdir}/xray.zip"
run(["wget","-qO",zipfile,XRAY_URL])
run(["unzip","-o",zipfile,"-d",tmpdir])
run(["install","-m","755",f"{tmpdir}/xray","/usr/local/bin/xray"])
os.makedirs("/usr/local/etc/xray", exist_ok=True)

# --- VLESS user ---
user_uuid = os.environ.get("VLESS_UUID") or str(uuid.uuid4())
# if user provided VLESS_PASS, we'll include it in "email" or remark in config metadata
remark = VLESS_PASS or ""

stream_settings = {
    "network": "ws",
    "wsSettings": {"path": VLESS_PATH}
}
client_obj = {"id": user_uuid}
if VLESS_FLOW:
    client_obj["flow"] = VLESS_FLOW
if remark:
    client_obj["email"] = remark

config = {
  "inbounds":[
    {
      "port": VLESS_PORT,
      "protocol": "vless",
      "settings": {"clients": [client_obj]},
      "streamSettings": stream_settings
    }
  ],
  "outbounds":[{"protocol":"freedom","settings":{}}]
}

def clean(d):
    if isinstance(d, dict):
        return {k: clean(v) for k,v in d.items() if v is not None and v != {}}
    if isinstance(d, list):
        return [clean(x) for x in d]
    return d

config = clean(config)
write("/usr/local/etc/xray/config.json", json.dumps(config, indent=2), 0o600)

service = textwrap.dedent("""\
[Unit]
Description=Xray Service
After=network.target

[Service]
User=root
ExecStart=/usr/local/bin/xray -config /usr/local/etc/xray/config.json
Restart=on-failure

[Install]
WantedBy=multi-user.target
""")
write("/etc/systemd/system/xray.service", service, 0o644)
run(["systemctl","daemon-reload"])
run(["systemctl","enable","--now","xray"])

# --- Enable IP forwarding and NAT for WireGuard ---
run(["sysctl","-w","net.ipv4.ip_forward=1"])
write("/etc/sysctl.d/99-sysctl.conf","net.ipv4.ip_forward=1\n",0o644)
run(["iptables","-t","nat","-A","POSTROUTING","-s",WG_NETWORK,"-o",MAIN_IF,"-j","MASQUERADE"])
run(["netfilter-persistent","save"])

# --- Build connection strings ---
wg_qr_path = f"/root/{WG_CLIENT_NAME}-wg.conf"
vless_uri = f"vless://{user_uuid}@{ext_ip}:{VLESS_PORT}?type=ws&path={VLESS_PATH}#{WG_CLIENT_NAME}-vless"

# --- Save env file with credentials (600) ---
env_out = textwrap.dedent(f"""\
SERVER_SSH_USER={SSH_USER}
SERVER_SSH_PASS={SSH_PASS}
VLESS_UUID={user_uuid}
VLESS_PASS={VLESS_PASS or ''}
WG_CLIENT_CONF=/root/{WG_CLIENT_NAME}-wg.conf
WG_INTERFACE={WG_INTERFACE}
VLESS_URI={vless_uri}
""")
write("/root/vpn_credentials.env", env_out, 0o600)

# --- Output summary ---
print("\n--- ACCESS INFO ---")
print(f"SSH user: {SSH_USER}")
print(f"SSH password: {SSH_PASS}")
print(f"SSH connect: ssh {SSH_USER}@{ext_ip}")
print(f"\nWireGuard client conf: {wg_qr_path}")
print(f"VLESS UUID: {user_uuid}")
if VLESS_PASS:
    print(f"VLESS pass (metadata): {VLESS_PASS}")
print(f"VLESS URI (ws): {vless_uri}")
print("\nFiles written: /etc/wireguard/{0}.conf, /root/{1}-wg.conf, /usr/local/etc/xray/config.json, /root/vpn_credentials.env".format(WG_INTERFACE, WG_CLIENT_NAME))
print("\nServices: systemctl status wg-quick@{0} xray ssh".format(WG_INTERFACE))
