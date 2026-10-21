#!/usr/bin/env python3
from bottle import Bottle, request, response, redirect, template
import subprocess, os, json, uuid, datetime, re, base64, hashlib, time, secrets

app = Bottle()

# ================== KONFIGURASI ==================
API_KEY = "fst"
ADMIN_USER = "fst"
ADMIN_PASS = "fst"
SECRET_KEY = secrets.token_hex(32)
PORT = 8880
PREFIX = "/panel"
# =================================================

sessions = {}
login_attempts = {}

def create_session():
    sid = secrets.token_hex(24)
    sessions[sid] = {"time": time.time(), "user": ADMIN_USER}
    return sid

def check_session():
    sid = request.get_cookie("session_id")
    if not sid or sid not in sessions:
        return False
    if time.time() - sessions[sid]["time"] > 12 * 3600:
        del sessions[sid]
        return False
    return True

def require_login(func):
    def wrapper(*args, **kwargs):
        if not check_session():
            return redirect(f"{PREFIX}/login")
        return func(*args, **kwargs)
    return wrapper

def auth_api():
    key = request.headers.get("APIKey") or request.forms.get("apikey")
    if request.json:
        key = key or request.json.get("apikey")
    return key == API_KEY

def require_auth():
    """True jika session valid atau API key valid"""
    return check_session() or auth_api()

def json_response(data, status=200):
    response.content_type = "application/json"
    response.status = status
    return json.dumps(data, ensure_ascii=False)

def get_domain():
    try:
        return open("/etc/xray/domain").read().strip()
    except:
        return os.popen("hostname -f").read().strip() or "localhost"

def run_cmd(cmd, shell=True):
    try:
        r = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=30)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return 1, "", str(e)

def parse_exp_days_left(exp_str):
    """Hitung sisa hari dari string tanggal (YYYY-MM-DD atau YYYY-MM-DD HH:MM:SS)"""
    try:
        exp_str = exp_str.strip()
        if " " in exp_str:
            exp_dt = datetime.datetime.strptime(exp_str, "%Y-%m-%d %H:%M:%S")
        else:
            exp_dt = datetime.datetime.strptime(exp_str, "%Y-%m-%d")
        delta = exp_dt - datetime.datetime.now()
        days = delta.days
        return max(0, days)
    except:
        return 0

def safe_username(user):
    return bool(re.match(r"^[a-zA-Z0-9_-]{3,32}$", user))

# ====================== ROOT / PANEL ======================
@app.route(PREFIX)
@app.route(PREFIX + "/")
def panel_root():
    if check_session():
        return redirect(f"{PREFIX}/dashboard")
    return redirect(f"{PREFIX}/login")

# ====================== LOGIN ======================
@app.route(PREFIX + "/login", method=["GET", "POST"])
def login():
    if check_session():
        return redirect(f"{PREFIX}/dashboard")

    error = ""
    if request.method == "POST":
        username = request.forms.get("username", "").strip()
        password = request.forms.get("password", "")
        ip = request.environ.get("REMOTE_ADDR", "unknown")
        now = time.time()

        if ip in login_attempts:
            attempts = [t for t in login_attempts[ip] if now - t < 600]
            if len(attempts) >= 5:
                error = "Terlalu banyak percobaan. Coba lagi 10 menit kemudian."
                return template(LOGIN_PAGE, error=error, prefix=PREFIX)
            login_attempts[ip] = attempts
        else:
            login_attempts[ip] = []

        if username == ADMIN_USER and password == ADMIN_PASS:
            sid = create_session()
            response.set_cookie("session_id", sid, httponly=True, max_age=12*3600, path="/")
            return redirect(f"{PREFIX}/dashboard")
        else:
            login_attempts[ip].append(now)
            error = "Username atau Password salah"

    return template(LOGIN_PAGE, error=error, prefix=PREFIX)

@app.route(PREFIX + "/logout")
def logout():
    sid = request.get_cookie("session_id")
    if sid and sid in sessions:
        del sessions[sid]
    response.delete_cookie("session_id", path="/")
    return redirect(f"{PREFIX}/login")

# ====================== DASHBOARD ======================
@app.route(PREFIX + "/dashboard")
@require_login
def dashboard():
    return template(DASHBOARD_PAGE, prefix=PREFIX)

# ====================== HELPER: LIST USERS ======================
def list_ssh_users():
    users = []
    db = "/etc/ssh/.ssh.db"
    if not os.path.exists(db):
        return users
    with open(db) as f:
        for line in f:
            line = line.strip()
            if line.startswith("### "):
                parts = line.split()
                if len(parts) >= 3:
                    user = parts[1]
                    exp = " ".join(parts[2:]) if len(parts) > 3 else parts[2]
                    iplim = "1"
                    if os.path.exists(f"/etc/ssh/{user}"):
                        try:
                            iplim = open(f"/etc/ssh/{user}").read().strip()
                        except:
                            pass
                    users.append({
                        "user": user,
                        "expired": exp,
                        "days_left": parse_exp_days_left(exp),
                        "ip_limit": iplim,
                        "protocol": "ssh"
                    })
    return users

def list_xray_users(protocol):
    users = []
    conf_dir = f"/etc/xray/{protocol}"
    db_file = f"{conf_dir}/.{protocol}.db"
    if not os.path.exists(db_file):
        return users
    with open(db_file) as f:
        for line in f:
            line = line.strip()
            if line.startswith("### "):
                parts = line.split()
                if len(parts) >= 3:
                    user = parts[1]
                    exp = parts[2]
                    uuid_or_pass = parts[3] if len(parts) > 3 else ""
                    # cek full datetime di db
                    if len(parts) >= 4 and ":" in parts[3]:
                        exp = f"{parts[2]} {parts[3]}"
                        uuid_or_pass = parts[4] if len(parts) > 4 else ""
                    quota = 0
                    iplim = 0
                    if os.path.exists(f"{conf_dir}/{user}"):
                        try:
                            q = int(open(f"{conf_dir}/{user}").read().strip())
                            quota = round(q / (1024**3), 2)
                        except:
                            pass
                    if os.path.exists(f"{conf_dir}/{user}IP"):
                        try:
                            iplim = open(f"{conf_dir}/{user}IP").read().strip()
                        except:
                            pass
                    users.append({
                        "user": user,
                        "expired": exp,
                        "days_left": parse_exp_days_left(exp),
                        "uuid": uuid_or_pass if protocol != "shadowsocks" else "",
                        "password": uuid_or_pass if protocol == "shadowsocks" else "",
                        "quota_gb": quota,
                        "ip_limit": iplim,
                        "protocol": protocol
                    })
    return users

# ====================== API: LIST ======================
@app.route(PREFIX + "/api/list/<proto>", method=["GET", "POST"])
def api_list(proto):
    if not require_auth():
        return json_response({"ok": False, "msg": "Unauthorized"}, 401)
    proto = proto.lower()
    if proto == "ssh":
        data = list_ssh_users()
    elif proto in ("vmess", "vless", "trojan", "shadowsocks"):
        data = list_xray_users(proto)
    else:
        return json_response({"ok": False, "msg": "Protocol tidak dikenal"}, 400)
    return json_response({"ok": True, "protocol": proto, "count": len(data), "users": data})

@app.route(PREFIX + "/api/list", method=["GET", "POST"])
def api_list_all():
    if not require_auth():
        return json_response({"ok": False, "msg": "Unauthorized"}, 401)
    result = {
        "ssh": list_ssh_users(),
        "vmess": list_xray_users("vmess"),
        "vless": list_xray_users("vless"),
        "trojan": list_xray_users("trojan"),
        "shadowsocks": list_xray_users("shadowsocks"),
    }
    total = sum(len(v) for v in result.values())
    return json_response({"ok": True, "total": total, "data": result})

# ====================== API: CEK / DETAIL USER ======================
@app.route(PREFIX + "/api/cek/<proto>", method=["GET", "POST"])
def api_cek(proto):
    if not require_auth():
        return json_response({"ok": False, "msg": "Unauthorized"}, 401)
    data = request.json or request.forms or request.query
    user = (data.get("user") or "").strip()
    if not user:
        return json_response({"ok": False, "msg": "Parameter wajib: user"}, 400)

    proto = proto.lower()
    domain = get_domain()

    if proto == "ssh":
        users = list_ssh_users()
        found = next((u for u in users if u["user"] == user), None)
        if not found:
            return json_response({"ok": False, "msg": f"User {user} tidak ditemukan"}, 404)
        # cek apakah user linux masih ada
        code, _, _ = run_cmd(f"id {user}")
        found["exists_system"] = (code == 0)
        found["domain"] = domain
        found["link"] = f"https://{domain}:81/ssh-{user}.txt"
        return json_response({"ok": True, **found})

    elif proto in ("vmess", "vless", "trojan", "shadowsocks"):
        users = list_xray_users(proto)
        found = next((u for u in users if u["user"] == user), None)
        if not found:
            return json_response({"ok": False, "msg": f"User {user} tidak ditemukan"}, 404)
        found["domain"] = domain
        # generate link ulang
        uid = found.get("uuid") or found.get("password") or ""
        if proto == "vmess" and uid:
            conf_tls = {"v": "2", "ps": f"{user}-TLS", "add": domain, "port": "443", "id": uid, "aid": "0",
                        "net": "ws", "type": "none", "host": domain, "path": f"/whatever/{proto}", "tls": "tls", "sni": domain}
            conf_non = {"v": "2", "ps": f"{user}-NonTLS", "add": domain, "port": "80", "id": uid, "aid": "0",
                        "net": "ws", "type": "none", "host": domain, "path": f"/whatever/{proto}", "tls": "none"}
            conf_grpc = {"v": "2", "ps": f"{user}-gRPC", "add": domain, "port": "443", "id": uid, "aid": "0",
                         "net": "grpc", "type": "none", "host": domain, "path": f"{proto}-grpc", "tls": "tls", "sni": domain}
            found["tls"] = "vmess://" + base64.b64encode(json.dumps(conf_tls, separators=(',', ':')).encode()).decode()
            found["nontls"] = "vmess://" + base64.b64encode(json.dumps(conf_non, separators=(',', ':')).encode()).decode()
            found["grpc"] = "vmess://" + base64.b64encode(json.dumps(conf_grpc, separators=(',', ':')).encode()).decode()
        elif proto == "vless" and uid:
            found["tls"] = f"vless://{uid}@{domain}:443?path=%2Fwhatever%2Fvless&security=tls&encryption=none&host={domain}&type=ws&sni={domain}#{user}"
            found["nontls"] = f"vless://{uid}@{domain}:80?path=%2Fwhatever%2Fvless&security=none&encryption=none&host={domain}&type=ws#{user}"
            found["grpc"] = f"vless://{uid}@{domain}:443?mode=gun&security=tls&encryption=none&type=grpc&serviceName=vless-grpc&sni={domain}#{user}"
        elif proto == "trojan" and uid:
            found["tls"] = f"trojan://{uid}@{domain}:443?path=%2Fwhatever%2Ftrojan&security=tls&host={domain}&type=ws&sni={domain}#{user}"
            found["nontls"] = f"trojan://{uid}@{domain}:80?path=%2Fwhatever%2Ftrojan&security=none&host={domain}&type=ws#{user}"
            found["grpc"] = f"trojan://{uid}@{domain}:443?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc&sni={domain}#{user}"
        elif proto == "shadowsocks" and uid:
            method = "aes-256-gcm"
            ss_base64 = base64.b64encode(f"{method}:{uid}".encode()).decode()
            found["ws"] = f"ss://{ss_base64}@{domain}:443?plugin=xray-plugin;mux=0;path=/ss-ws;host={domain};tls;network=ws;host={domain}#{user}-WS"
            found["grpc"] = f"ss://{ss_base64}@{domain}:443?plugin=xray-plugin;mux=0;serviceName=ss-grpc;host={domain};tls#{user}-gRPC"
            found["method"] = method
        return json_response({"ok": True, **found})

    return json_response({"ok": False, "msg": "Protocol tidak dikenal"}, 400)

# ====================== API: DELETE ======================
@app.route(PREFIX + "/api/del/<proto>", method="POST")
def api_del(proto):
    if not require_auth():
        return json_response({"ok": False, "msg": "Unauthorized"}, 401)

    data = request.json or request.forms
    user = (data.get("user") or "").strip()
    if not user:
        return json_response({"ok": False, "msg": "Parameter wajib: user"}, 400)
    if not safe_username(user):
        return json_response({"ok": False, "msg": "Username tidak valid"}, 400)

    proto = proto.lower()

    if proto == "ssh":
        db = "/etc/ssh/.ssh.db"
        if not os.path.exists(db) or f"### {user} " not in open(db).read():
            return json_response({"ok": False, "msg": f"User {user} tidak ditemukan"}, 404)

        # ambil exp dulu
        exp = ""
        for line in open(db):
            if line.startswith(f"### {user} "):
                exp = " ".join(line.strip().split()[2:])
                break

        code, _, err = run_cmd(f"userdel -f {user} 2>/dev/null")
        # tetap lanjut hapus db meskipun userdel gagal (mungkin sudah tidak ada)
        run_cmd(f"sed -i '/^### {user} /d' {db}")
        run_cmd(f"rm -f /etc/ssh/{user} /var/www/html/ssh-{user}.txt /etc/xray/log-createssh-{user}.log 2>/dev/null")

        return json_response({
            "ok": True,
            "msg": f"Akun SSH {user} berhasil dihapus",
            "user": user,
            "expired": exp
        })

    elif proto in ("vmess", "vless", "trojan", "shadowsocks"):
        conf_dir = f"/etc/xray/{proto}"
        conf_file = f"{conf_dir}/config.json"
        db_file = f"{conf_dir}/.{proto}.db"

        if not os.path.exists(db_file) or f"### {user} " not in open(db_file).read():
            return json_response({"ok": False, "msg": f"User {user} tidak ditemukan"}, 404)

        # ambil exp
        exp = ""
        for line in open(db_file):
            if line.startswith(f"### {user} "):
                parts = line.strip().split()
                exp = parts[2] if len(parts) > 2 else ""
                break

        # hapus dari config.json (pola ### user ... sampai },{ )
        if os.path.exists(conf_file):
            # hapus baris ### user ... dan baris client berikutnya
            run_cmd(f"sed -i '/^### {user} /,/^}},{{/d' {conf_file}")
            # fallback: hapus hanya baris ###
            run_cmd(f"sed -i '/^### {user} /d' {conf_file}")

        run_cmd(f"sed -i '/^### {user} /d' {db_file}")

        # hapus file terkait
        for f in [f"{conf_dir}/{user}", f"{conf_dir}/{user}IP",
                  f"{conf_dir}/{user}-tls.json", f"{conf_dir}/{user}-non.json",
                  f"{conf_dir}/{user}-grpc.json", f"{conf_dir}/log-create-{user}.log"]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except:
                    pass

        # restart service
        svc = "shadowsocks@config" if proto == "shadowsocks" else f"{proto}@config"
        run_cmd(f"systemctl restart {svc}")

        return json_response({
            "ok": True,
            "msg": f"Akun {proto.upper()} {user} berhasil dihapus",
            "user": user,
            "expired": exp
        })

    return json_response({"ok": False, "msg": "Protocol tidak dikenal"}, 400)

# ====================== API: RENEW ======================
@app.route(PREFIX + "/api/renew/<proto>", method="POST")
def api_renew(proto):
    if not require_auth():
        return json_response({"ok": False, "msg": "Unauthorized"}, 401)

    data = request.json or request.forms
    user = (data.get("user") or "").strip()
    days = data.get("expi") or data.get("days") or data.get("duration") or data.get("active_days")
    iplim = data.get("iplim") or data.get("ip_limit")
    quota = data.get("quota")

    if not user or not days:
        return json_response({"ok": False, "msg": "Parameter wajib: user, expi (hari)"}, 400)
    if not safe_username(user):
        return json_response({"ok": False, "msg": "Username tidak valid"}, 400)

    try:
        days = int(days)
        if days < 0:
            raise ValueError
    except:
        return json_response({"ok": False, "msg": "expi harus angka >= 0"}, 400)

    proto = proto.lower()

    if proto == "ssh":
        db = "/etc/ssh/.ssh.db"
        if not os.path.exists(db) or f"### {user} " not in open(db).read():
            return json_response({"ok": False, "msg": f"User {user} tidak ditemukan"}, 404)

        old_exp = ""
        for line in open(db):
            if line.startswith(f"### {user} "):
                old_exp = " ".join(line.strip().split()[2:])
                break

        # hitung new exp dari old_exp + days (atau dari sekarang jika sudah expired)
        try:
            if " " in old_exp:
                old_dt = datetime.datetime.strptime(old_exp, "%Y-%m-%d %H:%M:%S")
            else:
                old_dt = datetime.datetime.strptime(old_exp, "%Y-%m-%d")
            base = max(old_dt, datetime.datetime.now())
        except:
            base = datetime.datetime.now()

        new_dt = base + datetime.timedelta(days=days)
        new_exp_date = new_dt.strftime("%Y-%m-%d")
        new_exp_full = new_dt.strftime("%Y-%m-%d %H:%M:%S")

        run_cmd(f"sed -i '/^### {user} /c\\### {user} {new_exp_full}' {db}")
        run_cmd(f"chage -E {new_exp_date} {user}")

        if iplim is not None:
            try:
                iplim = int(iplim)
                open(f"/etc/ssh/{user}", "w").write(str(iplim))
            except:
                pass

        return json_response({
            "ok": True,
            "msg": f"Akun SSH {user} berhasil diperpanjang",
            "user": user,
            "old_expired": old_exp,
            "expired": new_exp_full,
            "days_added": days,
            "ip_limit": iplim
        })

    elif proto in ("vmess", "vless", "trojan", "shadowsocks"):
        conf_dir = f"/etc/xray/{proto}"
        conf_file = f"{conf_dir}/config.json"
        db_file = f"{conf_dir}/.{proto}.db"

        if not os.path.exists(db_file) or f"### {user} " not in open(db_file).read():
            return json_response({"ok": False, "msg": f"User {user} tidak ditemukan"}, 404)

        old_exp = ""
        uuid_or_pass = ""
        for line in open(db_file):
            if line.startswith(f"### {user} "):
                parts = line.strip().split()
                if len(parts) >= 4 and ":" in parts[3]:
                    old_exp = f"{parts[2]} {parts[3]}"
                    uuid_or_pass = parts[4] if len(parts) > 4 else ""
                else:
                    old_exp = parts[2] if len(parts) > 2 else ""
                    uuid_or_pass = parts[3] if len(parts) > 3 else ""
                break

        try:
            if " " in old_exp:
                old_dt = datetime.datetime.strptime(old_exp, "%Y-%m-%d %H:%M:%S")
            else:
                old_dt = datetime.datetime.strptime(old_exp, "%Y-%m-%d")
            base = max(old_dt, datetime.datetime.now())
        except:
            base = datetime.datetime.now()

        new_dt = base + datetime.timedelta(days=days)
        new_exp_date = new_dt.strftime("%Y-%m-%d")
        new_exp_full = new_dt.strftime("%Y-%m-%d %H:%M:%S")

        # update db
        if uuid_or_pass:
            run_cmd(f"sed -i '/^### {user} /c\\### {user} {new_exp_full} {uuid_or_pass}' {db_file}")
        else:
            run_cmd(f"sed -i '/^### {user} /c\\### {user} {new_exp_full}' {db_file}")

        # update config.json (hanya tanggal di marker)
        if os.path.exists(conf_file):
            run_cmd(f"sed -i '/^### {user} /c\\### {user} {new_exp_date}' {conf_file}")

        # quota & ip limit
        if quota is not None:
            try:
                quota = int(quota)
                if quota > 0:
                    open(f"{conf_dir}/{user}", "w").write(str(quota * 1024**3))
                else:
                    if os.path.exists(f"{conf_dir}/{user}"):
                        os.remove(f"{conf_dir}/{user}")
            except:
                pass
        if iplim is not None:
            try:
                iplim = int(iplim)
                open(f"{conf_dir}/{user}IP", "w").write(str(iplim))
            except:
                pass

        svc = "shadowsocks@config" if proto == "shadowsocks" else f"{proto}@config"
        run_cmd(f"systemctl restart {svc}")

        return json_response({
            "ok": True,
            "msg": f"Akun {proto.upper()} {user} berhasil diperpanjang",
            "user": user,
            "old_expired": old_exp,
            "expired": new_exp_full,
            "days_added": days,
            "quota_gb": quota,
            "ip_limit": iplim
        })

    return json_response({"ok": False, "msg": "Protocol tidak dikenal"}, 400)

# ====================== SSH CREATE (existing, improved) ======================
@app.route(PREFIX + "/api/ssh", method="POST")
def add_ssh():
    if not require_auth():
        return json_response({"ok": False, "msg": "Unauthorized"}, 401)

    data = request.json or request.forms
    user = (data.get("user") or "").strip()
    passwd = (data.get("pass") or data.get("password") or "").strip()
    expired = data.get("expi") or data.get("expired") or data.get("duration")
    iplim = data.get("iplim") or data.get("ip_limit") or "1"

    if not user or not passwd or not expired:
        return json_response({"ok": False, "msg": "Parameter wajib: user, pass, expi"}, 400)
    if not safe_username(user):
        return json_response({"ok": False, "msg": "Username tidak valid (3-32, a-zA-Z0-9_-)"}, 400)

    try:
        expired = int(expired)
        iplim = int(iplim)
    except:
        return json_response({"ok": False, "msg": "expi & iplim harus angka"}, 400)

    if os.path.exists("/etc/ssh/.ssh.db") and f"### {user} " in open("/etc/ssh/.ssh.db").read():
        return json_response({"ok": False, "msg": f"Username {user} sudah digunakan"}, 409)

    if run_cmd(f"id {user} >/dev/null 2>&1")[0] == 0:
        return json_response({"ok": False, "msg": f"Username {user} sudah ada di sistem"}, 409)

    exp_date = (datetime.datetime.now() + datetime.timedelta(days=expired)).strftime("%Y-%m-%d")
    exp_full = (datetime.datetime.now() + datetime.timedelta(days=expired)).strftime("%Y-%m-%d %H:%M:%S")

    if run_cmd(f'useradd -e {exp_date} -s /bin/false -M {user}')[0] != 0:
        return json_response({"ok": False, "msg": "Gagal membuat user Linux"}, 500)

    if run_cmd(f'echo "{user}:{passwd}" | chpasswd')[0] != 0:
        run_cmd(f'userdel -r {user} 2>/dev/null')
        return json_response({"ok": False, "msg": "Gagal set password"}, 500)

    run_cmd(f'passwd -u {user}')

    if iplim > 0:
        os.makedirs("/etc/ssh", exist_ok=True)
        open(f"/etc/ssh/{user}", "w").write(str(iplim))

    os.makedirs("/etc/ssh", exist_ok=True)
    with open("/etc/ssh/.ssh.db", "a") as f:
        f.write(f"### {user} {exp_full}\n")

    domain = get_domain()
    info = f"Username : {user}\nPassword : {passwd}\nHost     : {domain}\nExpired  : {exp_full}\n"
    os.makedirs("/var/www/html", exist_ok=True)
    open(f"/var/www/html/ssh-{user}.txt", "w").write(info)

    return json_response({
        "ok": True,
        "protocol": "ssh",
        "user": user,
        "pass": passwd,
        "expired": exp_full,
        "ip_limit": iplim,
        "domain": domain,
        "link": f"https://{domain}:81/ssh-{user}.txt"
    })

# ====================== XRAY CREATE ======================
def add_xray(protocol):
    if not require_auth():
        return json_response({"ok": False, "msg": "Unauthorized"}, 401)

    data = request.json or request.forms
    user = (data.get("user") or "").strip()
    duration = data.get("expi") or data.get("duration") or data.get("expired")
    quota = data.get("quota") or "0"
    ip_limit = data.get("iplim") or data.get("ip_limit") or "0"

    if not user or not duration:
        return json_response({"ok": False, "msg": "Parameter wajib: user, expi"}, 400)
    if not safe_username(user):
        return json_response({"ok": False, "msg": "Username tidak valid"}, 400)

    try:
        duration = int(duration)
        quota = int(quota)
        ip_limit = int(ip_limit)
    except:
        return json_response({"ok": False, "msg": "expi/quota/iplim harus angka"}, 400)

    conf_dir = f"/etc/xray/{protocol}"
    conf_file = f"{conf_dir}/config.json"
    db_file = f"{conf_dir}/.{protocol}.db"

    os.makedirs(conf_dir, exist_ok=True)
    if not os.path.exists(conf_file):
        open(conf_file, "w").write('{"inbounds": []}')

    if os.path.exists(conf_file) and f"### {user} " in open(conf_file).read():
        return json_response({"ok": False, "msg": f"Username {user} sudah digunakan"}, 409)
    if os.path.exists(db_file) and f"### {user} " in open(db_file).read():
        return json_response({"ok": False, "msg": f"Username {user} sudah digunakan"}, 409)

    uid = str(uuid.uuid4())
    exp_date = (datetime.datetime.now() + datetime.timedelta(days=duration)).strftime("%Y-%m-%d")
    exp_full = (datetime.datetime.now() + datetime.timedelta(days=duration)).strftime("%Y-%m-%d %H:%M:%S")
    domain = get_domain()

    marker_ws = f"#{protocol}"
    marker_grpc = f"#{protocol}grpc"
    entry = f'### {user} {exp_date}\\n}},{{"id": "{uid}","email": "{user}"'

    ret1 = run_cmd(f"sed -i '/{marker_ws}$/a\\{entry}' {conf_file}")[0]
    ret2 = run_cmd(f"sed -i '/{marker_grpc}$/a\\{entry}' {conf_file}")[0]

    if ret1 != 0 or ret2 != 0:
        return json_response({"ok": False, "msg": "Gagal inject user ke config.json"}, 500)

    for mode, port, tls, path, net in [
        ("tls", "443", "tls", f"/whatever/{protocol}", "ws"),
        ("non", "80", "none", f"/whatever/{protocol}", "ws"),
        ("grpc", "443", "tls", f"{protocol}-grpc", "grpc"),
    ]:
        conf = {
            "v": "2", "ps": f"{user} {mode.upper()}", "add": domain, "port": port,
            "id": uid, "aid": "0", "net": net, "path": path, "type": "none",
            "host": domain, "tls": tls
        }
        open(f"{conf_dir}/{user}-{mode}.json", "w").write(json.dumps(conf, indent=2))

    if quota > 0:
        open(f"{conf_dir}/{user}", "w").write(str(quota * 1024**3))
        open(f"{conf_dir}/{user}IP", "w").write(str(ip_limit))
    elif ip_limit > 0:
        open(f"{conf_dir}/{user}IP", "w").write(str(ip_limit))

    with open(db_file, "a") as f:
        f.write(f"### {user} {exp_full} {uid}\n")

    run_cmd(f"systemctl restart {protocol}@config")

    if protocol == "vmess":
        conf_tls = {"v": "2", "ps": f"{user}-TLS", "add": domain, "port": "443", "id": uid, "aid": "0",
                    "net": "ws", "type": "none", "host": domain, "path": f"/whatever/{protocol}", "tls": "tls", "sni": domain}
        conf_non = {"v": "2", "ps": f"{user}-NonTLS", "add": domain, "port": "80", "id": uid, "aid": "0",
                    "net": "ws", "type": "none", "host": domain, "path": f"/whatever/{protocol}", "tls": "none"}
        conf_grpc = {"v": "2", "ps": f"{user}-gRPC", "add": domain, "port": "443", "id": uid, "aid": "0",
                     "net": "grpc", "type": "none", "host": domain, "path": f"{protocol}-grpc", "tls": "tls", "sni": domain}
        tls_link = "vmess://" + base64.b64encode(json.dumps(conf_tls, separators=(',', ':')).encode()).decode()
        non_link = "vmess://" + base64.b64encode(json.dumps(conf_non, separators=(',', ':')).encode()).decode()
        grpc_link = "vmess://" + base64.b64encode(json.dumps(conf_grpc, separators=(',', ':')).encode()).decode()
    elif protocol == "vless":
        tls_link = f"vless://{uid}@{domain}:443?path=%2Fwhatever%2Fvless&security=tls&encryption=none&host={domain}&type=ws&sni={domain}#{user}"
        non_link = f"vless://{uid}@{domain}:80?path=%2Fwhatever%2Fvless&security=none&encryption=none&host={domain}&type=ws#{user}"
        grpc_link = f"vless://{uid}@{domain}:443?mode=gun&security=tls&encryption=none&type=grpc&serviceName=vless-grpc&sni={domain}#{user}"
    else:
        tls_link = f"trojan://{uid}@{domain}:443?path=%2Fwhatever%2Ftrojan&security=tls&host={domain}&type=ws&sni={domain}#{user}"
        non_link = f"trojan://{uid}@{domain}:80?path=%2Fwhatever%2Ftrojan&security=none&host={domain}&type=ws#{user}"
        grpc_link = f"trojan://{uid}@{domain}:443?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc&sni={domain}#{user}"

    return json_response({
        "ok": True, "protocol": protocol, "user": user, "uuid": uid,
        "expired": exp_full, "quota_gb": quota, "ip_limit": ip_limit, "domain": domain,
        "tls": tls_link, "nontls": non_link, "grpc": grpc_link
    })

@app.route(PREFIX + "/api/vmess", method="POST")
def add_vmess(): return add_xray("vmess")

@app.route(PREFIX + "/api/vless", method="POST")
def add_vless(): return add_xray("vless")

@app.route(PREFIX + "/api/trojan", method="POST")
def add_trojan(): return add_xray("trojan")

# ====================== SHADOWSOCKS ======================
@app.route(PREFIX + "/api/shadowsocks", method="POST")
def add_shadowsocks():
    if not require_auth():
        return json_response({"ok": False, "msg": "Unauthorized"}, 401)

    data = request.json or request.forms
    user = (data.get("user") or "").strip()
    duration = data.get("expi") or data.get("duration") or data.get("expired")
    quota = data.get("quota") or "0"
    ip_limit = data.get("iplim") or data.get("ip_limit") or "0"

    if not user or not duration:
        return json_response({"ok": False, "msg": "Parameter wajib: user, expi"}, 400)
    if not safe_username(user):
        return json_response({"ok": False, "msg": "Username tidak valid"}, 400)

    try:
        duration = int(duration)
        quota = int(quota)
        ip_limit = int(ip_limit)
    except:
        return json_response({"ok": False, "msg": "expi/quota/iplim harus angka"}, 400)

    conf_dir = "/etc/xray/shadowsocks"
    conf_file = f"{conf_dir}/config.json"
    db_file = f"{conf_dir}/.shadowsocks.db"

    os.makedirs(conf_dir, exist_ok=True)
    if not os.path.exists(conf_file):
        open(conf_file, "w").write('{"inbounds": []}')

    if os.path.exists(conf_file) and f"### {user} " in open(conf_file).read():
        return json_response({"ok": False, "msg": f"Username {user} sudah digunakan"}, 409)

    password = str(uuid.uuid4())
    method = "aes-256-gcm"
    exp_date = (datetime.datetime.now() + datetime.timedelta(days=duration)).strftime("%Y-%m-%d")
    exp_full = (datetime.datetime.now() + datetime.timedelta(days=duration)).strftime("%Y-%m-%d %H:%M:%S")
    domain = get_domain()

    entry = f'### {user} {exp_date}\\n}},{{"password": "{password}","method": "{method}","email": "{user}"'

    ret1 = run_cmd(f"sed -i '/#ssws$/a\\{entry}' {conf_file}")[0]
    ret2 = run_cmd(f"sed -i '/#ssgrpc$/a\\{entry}' {conf_file}")[0]

    if ret1 != 0 or ret2 != 0:
        return json_response({"ok": False, "msg": "Gagal inject user ke config.json"}, 500)

    if quota > 0:
        open(f"{conf_dir}/{user}", "w").write(str(quota * 1024**3))
        open(f"{conf_dir}/{user}IP", "w").write(str(ip_limit))
    elif ip_limit > 0:
        open(f"{conf_dir}/{user}IP", "w").write(str(ip_limit))

    with open(db_file, "a") as f:
        f.write(f"### {user} {exp_full} {password}\n")

    run_cmd("systemctl restart shadowsocks@config")

    ss_base64 = base64.b64encode(f"{method}:{password}".encode()).decode()
    ss_ws = f"ss://{ss_base64}@{domain}:443?plugin=xray-plugin;mux=0;path=/ss-ws;host={domain};tls;network=ws;host={domain}#{user}-WS"
    ss_grpc = f"ss://{ss_base64}@{domain}:443?plugin=xray-plugin;mux=0;serviceName=ss-grpc;host={domain};tls#{user}-gRPC"

    return json_response({
        "ok": True, "protocol": "shadowsocks", "user": user, "password": password,
        "method": method, "expired": exp_full, "quota_gb": quota, "ip_limit": ip_limit,
        "domain": domain, "ws": ss_ws, "grpc": ss_grpc
    })

# ====================== TRIAL (buat akun singkat) ======================
@app.route(PREFIX + "/api/trial/<proto>", method="POST")
def api_trial(proto):
    """Buat akun trial (default 1 hari, username random trial-xxxx)"""
    if not require_auth():
        return json_response({"ok": False, "msg": "Unauthorized"}, 401)

    data = request.json or request.forms or {}
    days = data.get("expi") or data.get("days") or 1
    try:
        days = int(days)
    except:
        days = 1

    proto = proto.lower()
    user = "trial-" + secrets.token_hex(3)

    if proto == "ssh":
        passwd = secrets.token_hex(4)
        # reuse add_ssh logic via internal call-like
        request.environ["wsgi.input"] = None  # safety
        # call logic manually
        body = {"user": user, "pass": passwd, "expi": days, "iplim": 1}
        # simulate
        exp_date = (datetime.datetime.now() + datetime.timedelta(days=days)).strftime("%Y-%m-%d")
        exp_full = (datetime.datetime.now() + datetime.timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        if run_cmd(f'useradd -e {exp_date} -s /bin/false -M {user}')[0] != 0:
            return json_response({"ok": False, "msg": "Gagal buat user trial"}, 500)
        run_cmd(f'echo "{user}:{passwd}" | chpasswd')
        run_cmd(f'passwd -u {user}')
        open(f"/etc/ssh/{user}", "w").write("1")
        with open("/etc/ssh/.ssh.db", "a") as f:
            f.write(f"### {user} {exp_full}\n")
        domain = get_domain()
        info = f"Username : {user}\nPassword : {passwd}\nHost     : {domain}\nExpired  : {exp_full}\n"
        open(f"/var/www/html/ssh-{user}.txt", "w").write(info)
        return json_response({
            "ok": True, "protocol": "ssh", "user": user, "pass": passwd,
            "expired": exp_full, "ip_limit": 1, "domain": domain,
            "link": f"https://{domain}:81/ssh-{user}.txt", "trial": True
        })

    elif proto in ("vmess", "vless", "trojan"):
        # call add_xray with forced user
        # we temporarily inject
        class Fake:
            pass
        # simpler: duplicate minimal
        conf_dir = f"/etc/xray/{proto}"
        conf_file = f"{conf_dir}/config.json"
        db_file = f"{conf_dir}/.{proto}.db"
        os.makedirs(conf_dir, exist_ok=True)
        if not os.path.exists(conf_file):
            open(conf_file, "w").write('{"inbounds": []}')
        uid = str(uuid.uuid4())
        exp_date = (datetime.datetime.now() + datetime.timedelta(days=days)).strftime("%Y-%m-%d")
        exp_full = (datetime.datetime.now() + datetime.timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        domain = get_domain()
        marker_ws = f"#{proto}"
        marker_grpc = f"#{proto}grpc"
        entry = f'### {user} {exp_date}\\n}},{{"id": "{uid}","email": "{user}"'
        run_cmd(f"sed -i '/{marker_ws}$/a\\{entry}' {conf_file}")
        run_cmd(f"sed -i '/{marker_grpc}$/a\\{entry}' {conf_file}")
        with open(db_file, "a") as f:
            f.write(f"### {user} {exp_full} {uid}\n")
        run_cmd(f"systemctl restart {proto}@config")
        if proto == "vmess":
            conf_tls = {"v": "2", "ps": f"{user}-TLS", "add": domain, "port": "443", "id": uid, "aid": "0",
                        "net": "ws", "type": "none", "host": domain, "path": f"/whatever/{proto}", "tls": "tls", "sni": domain}
            conf_non = {"v": "2", "ps": f"{user}-NonTLS", "add": domain, "port": "80", "id": uid, "aid": "0",
                        "net": "ws", "type": "none", "host": domain, "path": f"/whatever/{proto}", "tls": "none"}
            conf_grpc = {"v": "2", "ps": f"{user}-gRPC", "add": domain, "port": "443", "id": uid, "aid": "0",
                         "net": "grpc", "type": "none", "host": domain, "path": f"{proto}-grpc", "tls": "tls", "sni": domain}
            tls_link = "vmess://" + base64.b64encode(json.dumps(conf_tls, separators=(',', ':')).encode()).decode()
            non_link = "vmess://" + base64.b64encode(json.dumps(conf_non, separators=(',', ':')).encode()).decode()
            grpc_link = "vmess://" + base64.b64encode(json.dumps(conf_grpc, separators=(',', ':')).encode()).decode()
        elif proto == "vless":
            tls_link = f"vless://{uid}@{domain}:443?path=%2Fwhatever%2Fvless&security=tls&encryption=none&host={domain}&type=ws&sni={domain}#{user}"
            non_link = f"vless://{uid}@{domain}:80?path=%2Fwhatever%2Fvless&security=none&encryption=none&host={domain}&type=ws#{user}"
            grpc_link = f"vless://{uid}@{domain}:443?mode=gun&security=tls&encryption=none&type=grpc&serviceName=vless-grpc&sni={domain}#{user}"
        else:
            tls_link = f"trojan://{uid}@{domain}:443?path=%2Fwhatever%2Ftrojan&security=tls&host={domain}&type=ws&sni={domain}#{user}"
            non_link = f"trojan://{uid}@{domain}:80?path=%2Fwhatever%2Ftrojan&security=none&host={domain}&type=ws#{user}"
            grpc_link = f"trojan://{uid}@{domain}:443?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc&sni={domain}#{user}"
        return json_response({
            "ok": True, "protocol": proto, "user": user, "uuid": uid,
            "expired": exp_full, "quota_gb": 0, "ip_limit": 1, "domain": domain,
            "tls": tls_link, "nontls": non_link, "grpc": grpc_link, "trial": True
        })

    elif proto == "shadowsocks":
        conf_dir = "/etc/xray/shadowsocks"
        conf_file = f"{conf_dir}/config.json"
        db_file = f"{conf_dir}/.shadowsocks.db"
        os.makedirs(conf_dir, exist_ok=True)
        if not os.path.exists(conf_file):
            open(conf_file, "w").write('{"inbounds": []}')
        password = str(uuid.uuid4())
        method = "aes-256-gcm"
        exp_date = (datetime.datetime.now() + datetime.timedelta(days=days)).strftime("%Y-%m-%d")
        exp_full = (datetime.datetime.now() + datetime.timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        domain = get_domain()
        entry = f'### {user} {exp_date}\\n}},{{"password": "{password}","method": "{method}","email": "{user}"'
        run_cmd(f"sed -i '/#ssws$/a\\{entry}' {conf_file}")
        run_cmd(f"sed -i '/#ssgrpc$/a\\{entry}' {conf_file}")
        with open(db_file, "a") as f:
            f.write(f"### {user} {exp_full} {password}\n")
        run_cmd("systemctl restart shadowsocks@config")
        ss_base64 = base64.b64encode(f"{method}:{password}".encode()).decode()
        ss_ws = f"ss://{ss_base64}@{domain}:443?plugin=xray-plugin;mux=0;path=/ss-ws;host={domain};tls;network=ws;host={domain}#{user}-WS"
        ss_grpc = f"ss://{ss_base64}@{domain}:443?plugin=xray-plugin;mux=0;serviceName=ss-grpc;host={domain};tls#{user}-gRPC"
        return json_response({
            "ok": True, "protocol": "shadowsocks", "user": user, "password": password,
            "method": method, "expired": exp_full, "quota_gb": 0, "ip_limit": 1,
            "domain": domain, "ws": ss_ws, "grpc": ss_grpc, "trial": True
        })

    return json_response({"ok": False, "msg": "Protocol tidak dikenal"}, 400)

# ====================== HEALTH ======================
@app.route("/health")
def health():
    return json_response({"ok": True, "status": "running"})

# ====================== HTML ======================
LOGIN_PAGE = '''
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Login - FST Panel</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #e2e8f0;
  }
  .login-box {
    background: #1e293b;
    padding: 40px 36px;
    border-radius: 20px;
    width: 100%;
    max-width: 400px;
    box-shadow: 0 25px 50px -12px rgb(0 0 0 / 0.5);
    border: 1px solid #334155;
  }
  h1 {
    text-align: center;
    font-size: 1.8rem;
    margin-bottom: 8px;
    background: linear-gradient(to right, #60a5fa, #a78bfa);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }
  .sub { text-align: center; color: #94a3b8; margin-bottom: 30px; font-size: 0.95rem; }
  label { display: block; margin-bottom: 6px; font-size: 0.9rem; color: #94a3b8; }
  input {
    width: 100%; padding: 13px 16px; border-radius: 12px;
    border: 1px solid #334155; background: #0f172a; color: white;
    margin-bottom: 18px; font-size: 1rem;
  }
  input:focus { outline: none; border-color: #3b82f6; }
  button {
    width: 100%; padding: 14px; border: none; border-radius: 12px;
    background: linear-gradient(to right, #3b82f6, #8b5cf6);
    color: white; font-weight: 600; font-size: 1rem; cursor: pointer;
  }
  button:hover { opacity: 0.9; }
  .error {
    background: #7f1d1d; color: #fecaca; padding: 12px;
    border-radius: 10px; margin-bottom: 20px; text-align: center; font-size: 0.9rem;
  }
</style>
</head>
<body>
  <div class="login-box">
    <h1>FST Panel</h1>
    <p class="sub">Silakan login untuk melanjutkan</p>
    % if error:
    <div class="error">{{error}}</div>
    % end
    <form method="POST" action="{{prefix}}/login">
      <label>Username</label>
      <input type="text" name="username" required autofocus placeholder="Username">
      <label>Password</label>
      <input type="password" name="password" required placeholder="Password">
      <button type="submit">Masuk</button>
    </form>
  </div>
</body>
</html>
'''

DASHBOARD_PAGE = '''
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FST Panel</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; padding: 16px; }
  .container { max-width: 920px; margin: 0 auto; }
  header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; flex-wrap: wrap; gap: 10px; }
  h1 { font-size: 1.7rem; background: linear-gradient(to right, #60a5fa, #a78bfa); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
  .logout { background: #334155; color: #e2e8f0; border: none; padding: 8px 16px; border-radius: 8px; cursor: pointer; font-size: 0.9rem; text-decoration: none; }
  .logout:hover { background: #475569; }
  .tabs { display: flex; gap: 6px; margin-bottom: 16px; flex-wrap: wrap; }
  .tab { flex: 1; min-width: 70px; padding: 10px 8px; background: #1e293b; border: 1px solid #334155; border-radius: 10px; color: #94a3b8; cursor: pointer; font-weight: 600; font-size: 0.85rem; }
  .tab.active { background: linear-gradient(to right, #3b82f6, #8b5cf6); color: white; border-color: transparent; }
  .subtabs { display: flex; gap: 6px; margin-bottom: 16px; flex-wrap: wrap; }
  .subtab { padding: 8px 14px; background: #1e293b; border: 1px solid #334155; border-radius: 8px; color: #94a3b8; cursor: pointer; font-size: 0.85rem; }
  .subtab.active { background: #334155; color: #60a5fa; border-color: #3b82f6; }
  .card { background: #1e293b; border-radius: 16px; padding: 22px; border: 1px solid #334155; }
  label { display: block; margin-bottom: 5px; font-size: 0.88rem; color: #94a3b8; }
  input, select { width: 100%; padding: 12px 14px; border-radius: 10px; border: 1px solid #334155; background: #0f172a; color: white; margin-bottom: 14px; font-size: 0.95rem; }
  input:focus, select:focus { outline: none; border-color: #3b82f6; }
  .btn { width: 100%; padding: 13px; border: none; border-radius: 10px; background: linear-gradient(to right, #3b82f6, #8b5cf6); color: white; font-weight: 600; font-size: 0.95rem; cursor: pointer; }
  .btn:hover { opacity: 0.9; }
  .btn:disabled { opacity: 0.55; cursor: not-allowed; }
  .btn-danger { background: linear-gradient(to right, #ef4444, #b91c1c); }
  .btn-warn { background: linear-gradient(to right, #f59e0b, #d97706); }
  .btn-ok { background: linear-gradient(to right, #22c55e, #16a34a); }
  .result { display: none; background: #0f172a; border-radius: 12px; padding: 16px; margin-top: 18px; word-break: break-all; border-left: 4px solid #22c55e; font-size: 0.9rem; }
  .result.show { display: block; }
  .result.error { border-left-color: #ef4444; }
  .link-box { background: #1e293b; padding: 10px; border-radius: 8px; margin: 8px 0; font-size: 0.8rem; border: 1px solid #334155; }
  .copy { margin-top: 4px; padding: 6px 12px; background: #334155; border: none; border-radius: 6px; color: white; cursor: pointer; font-size: 0.8rem; }
  .copy:hover { background: #475569; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th, td { padding: 10px 8px; text-align: left; border-bottom: 1px solid #334155; }
  th { color: #94a3b8; font-weight: 600; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 0.75rem; }
  .badge-ok { background: #14532d; color: #86efac; }
  .badge-warn { background: #713f12; color: #fde047; }
  .badge-exp { background: #7f1d1d; color: #fecaca; }
  .actions { display: flex; gap: 6px; flex-wrap: wrap; }
  .actions button { padding: 5px 10px; font-size: 0.75rem; border-radius: 6px; border: none; cursor: pointer; color: white; }
  .act-renew { background: #d97706; }
  .act-del { background: #dc2626; }
  .act-cek { background: #3b82f6; }
  .hidden { display: none !important; }
  .row2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  @media (max-width: 600px) { .row2 { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>FST Panel</h1>
    <a href="{{prefix}}/logout" class="logout">Logout</a>
  </header>

  <div class="tabs">
    <button class="tab active" onclick="switchProto('ssh')">SSH</button>
    <button class="tab" onclick="switchProto('vmess')">VMess</button>
    <button class="tab" onclick="switchProto('vless')">VLess</button>
    <button class="tab" onclick="switchProto('trojan')">Trojan</button>
    <button class="tab" onclick="switchProto('shadowsocks')">SS</button>
  </div>

  <div class="subtabs">
    <button class="subtab active" onclick="switchAction('create')">Buat</button>
    <button class="subtab" onclick="switchAction('list')">List / Cek</button>
    <button class="subtab" onclick="switchAction('renew')">Renew</button>
    <button class="subtab" onclick="switchAction('delete')">Hapus</button>
    <button class="subtab" onclick="switchAction('trial')">Trial</button>
  </div>

  <!-- CREATE -->
  <div id="panel-create" class="card">
    <form id="form-create" onsubmit="doCreate(event)">
      <div id="ssh-fields">
        <label>Username</label>
        <input type="text" name="user" required placeholder="minimal 3 karakter" pattern="[a-zA-Z0-9_-]{3,32}">
        <label>Password</label>
        <input type="text" name="pass" required>
        <div class="row2">
          <div>
            <label>Masa Aktif (hari)</label>
            <input type="number" name="expi" value="30" min="1" required>
          </div>
          <div>
            <label>Batas IP</label>
            <input type="number" name="iplim" value="2" min="1">
          </div>
        </div>
      </div>
      <div id="xray-fields" class="hidden">
        <label>Username</label>
        <input type="text" name="user_x" placeholder="minimal 3 karakter" pattern="[a-zA-Z0-9_-]{3,32}">
        <div class="row2">
          <div>
            <label>Masa Aktif (hari)</label>
            <input type="number" name="expi_x" value="30" min="1">
          </div>
          <div>
            <label>Kuota (GB) — 0 = unlimited</label>
            <input type="number" name="quota" value="0" min="0">
          </div>
        </div>
        <label>Batas IP</label>
        <input type="number" name="iplim_x" value="2" min="0">
      </div>
      <button type="submit" class="btn" id="btn-create">Buat Akun SSH</button>
    </form>
    <div id="result-create" class="result"></div>
  </div>

  <!-- LIST -->
  <div id="panel-list" class="card hidden">
    <button class="btn btn-ok" onclick="loadList()" style="margin-bottom:16px">🔄 Refresh List</button>
    <div id="list-content" style="overflow-x:auto">
      <p style="color:#94a3b8">Klik Refresh untuk memuat daftar akun...</p>
    </div>
    <div id="result-list" class="result"></div>
  </div>

  <!-- RENEW -->
  <div id="panel-renew" class="card hidden">
    <form onsubmit="doRenew(event)">
      <label>Username</label>
      <input type="text" name="user" required placeholder="username yang mau diperpanjang">
      <div class="row2">
        <div>
          <label>Tambah Masa Aktif (hari)</label>
          <input type="number" name="expi" value="30" min="1" required>
        </div>
        <div>
          <label>Batas IP (opsional)</label>
          <input type="number" name="iplim" placeholder="kosongkan = tidak ubah">
        </div>
      </div>
      <div id="renew-quota" class="hidden">
        <label>Kuota (GB, opsional) — 0 = unlimited</label>
        <input type="number" name="quota" placeholder="kosongkan = tidak ubah">
      </div>
      <button type="submit" class="btn btn-warn">Perpanjang Akun</button>
    </form>
    <div id="result-renew" class="result"></div>
  </div>

  <!-- DELETE -->
  <div id="panel-delete" class="card hidden">
    <form onsubmit="doDelete(event)">
      <label>Username yang akan dihapus</label>
      <input type="text" name="user" required placeholder="username">
      <p style="color:#f87171;font-size:0.85rem;margin-bottom:14px">⚠️ Aksi ini permanen. Akun akan dihapus dari sistem.</p>
      <button type="submit" class="btn btn-danger">Hapus Akun</button>
    </form>
    <div id="result-delete" class="result"></div>
  </div>

  <!-- TRIAL -->
  <div id="panel-trial" class="card hidden">
    <form onsubmit="doTrial(event)">
      <label>Durasi Trial (hari)</label>
      <input type="number" name="expi" value="1" min="1" max="7">
      <p style="color:#94a3b8;font-size:0.85rem;margin-bottom:14px">Username akan digenerate otomatis (trial-xxxxxx)</p>
      <button type="submit" class="btn btn-ok">Buat Akun Trial</button>
    </form>
    <div id="result-trial" class="result"></div>
  </div>
</div>

<script>
const PREFIX = "{{prefix}}";
let currentProto = "ssh";
let currentAction = "create";

function switchProto(proto) {
  currentProto = proto;
  document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
  event.target.classList.add("active");
  updateCreateForm();
  if (currentAction === "list") loadList();
  document.getElementById("renew-quota").classList.toggle("hidden", proto === "ssh");
}

function switchAction(act) {
  currentAction = act;
  document.querySelectorAll(".subtab").forEach(t => t.classList.remove("active"));
  event.target.classList.add("active");
  ["create","list","renew","delete","trial"].forEach(a => {
    document.getElementById("panel-" + a).classList.toggle("hidden", a !== act);
  });
  if (act === "list") loadList();
}

function updateCreateForm() {
  const isSsh = currentProto === "ssh";
  document.getElementById("ssh-fields").classList.toggle("hidden", !isSsh);
  document.getElementById("xray-fields").classList.toggle("hidden", isSsh);
  document.getElementById("btn-create").innerText = "Buat Akun " + currentProto.toUpperCase();
  // required toggle
  document.querySelector('#ssh-fields input[name="user"]').required = isSsh;
  document.querySelector('#ssh-fields input[name="pass"]').required = isSsh;
  document.querySelector('#ssh-fields input[name="expi"]').required = isSsh;
  document.querySelector('#xray-fields input[name="user_x"]').required = !isSsh;
  document.querySelector('#xray-fields input[name="expi_x"]').required = !isSsh;
}

async function api(path, body) {
  const res = await fetch(PREFIX + "/api/" + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {})
  });
  return res.json();
}

function showResult(id, ok, html) {
  const el = document.getElementById(id);
  el.className = "result show" + (ok ? "" : " error");
  el.innerHTML = html;
}

function formatLinks(json) {
  let html = "";
  if (json.tls) {
    html += '<div class="link-box"><b>TLS:</b><br>' + json.tls + '</div>';
    html += '<button class="copy" onclick="navigator.clipboard.writeText(\\'' + json.tls.replace(/'/g,"\\\\'") + '\\')">Copy TLS</button>';
    html += '<div class="link-box"><b>Non-TLS:</b><br>' + json.nontls + '</div>';
    html += '<button class="copy" onclick="navigator.clipboard.writeText(\\'' + json.nontls.replace(/'/g,"\\\\'") + '\\')">Copy Non-TLS</button>';
    html += '<div class="link-box"><b>gRPC:</b><br>' + json.grpc + '</div>';
    html += '<button class="copy" onclick="navigator.clipboard.writeText(\\'' + json.grpc.replace(/'/g,"\\\\'") + '\\')">Copy gRPC</button>';
  }
  if (json.ws) {
    html += '<div class="link-box"><b>WS:</b><br>' + json.ws + '</div>';
    html += '<button class="copy" onclick="navigator.clipboard.writeText(\\'' + json.ws.replace(/'/g,"\\\\'") + '\\')">Copy WS</button>';
    html += '<div class="link-box"><b>gRPC:</b><br>' + json.grpc + '</div>';
    html += '<button class="copy" onclick="navigator.clipboard.writeText(\\'' + json.grpc.replace(/'/g,"\\\\'") + '\\')">Copy gRPC</button>';
  }
  if (json.link) html += '<br><a href="' + json.link + '" target="_blank" style="color:#60a5fa">Download Config</a>';
  return html;
}

async function doCreate(e) {
  e.preventDefault();
  const form = e.target;
  const btn = form.querySelector("button");
  btn.disabled = true;
  btn.innerText = "Sedang membuat...";
  let data = {};
  if (currentProto === "ssh") {
    data = { user: form.user.value, pass: form.pass.value, expi: form.expi.value, iplim: form.iplim.value };
  } else {
    data = { user: form.user_x.value, expi: form.expi_x.value, quota: form.quota.value, iplim: form.iplim_x.value };
  }
  try {
    const json = await api(currentProto, data);
    if (json.ok) {
      let html = "<b>✅ Berhasil dibuat!</b><br><br>";
      html += "<b>User:</b> " + json.user + "<br>";
      if (json.pass) html += "<b>Password:</b> " + json.pass + "<br>";
      if (json.uuid) html += "<b>UUID:</b> " + json.uuid + "<br>";
      if (json.password) html += "<b>Password:</b> " + json.password + "<br>";
      if (json.method) html += "<b>Method:</b> " + json.method + "<br>";
      html += "<b>Expired:</b> " + json.expired + "<br>";
      html += formatLinks(json);
      showResult("result-create", true, html);
    } else {
      showResult("result-create", false, "❌ " + (json.msg || "Gagal"));
    }
  } catch (err) {
    showResult("result-create", false, "❌ Error: " + err.message);
  }
  btn.disabled = false;
  btn.innerText = "Buat Akun " + currentProto.toUpperCase();
}

async function loadList() {
  const box = document.getElementById("list-content");
  box.innerHTML = "<p style='color:#94a3b8'>Memuat...</p>";
  try {
    const res = await fetch(PREFIX + "/api/list/" + currentProto);
    const json = await res.json();
    if (!json.ok) {
      box.innerHTML = "<p style='color:#f87171'>" + (json.msg || "Gagal") + "</p>";
      return;
    }
    if (!json.users || json.users.length === 0) {
      box.innerHTML = "<p style='color:#94a3b8'>Belum ada akun " + currentProto.toUpperCase() + "</p>";
      return;
    }
    let html = "<table><thead><tr><th>User</th><th>Expired</th><th>Sisa</th>";
    if (currentProto !== "ssh") html += "<th>Kuota</th>";
    html += "<th>IP</th><th>Aksi</th></tr></thead><tbody>";
    for (const u of json.users) {
      let badge = u.days_left > 7 ? "badge-ok" : (u.days_left > 0 ? "badge-warn" : "badge-exp");
      html += "<tr>";
      html += "<td><b>" + u.user + "</b></td>";
      html += "<td>" + u.expired + "</td>";
      html += "<td><span class='badge " + badge + "'>" + u.days_left + " hari</span></td>";
      if (currentProto !== "ssh") html += "<td>" + (u.quota_gb || 0) + " GB</td>";
      html += "<td>" + (u.ip_limit || "-") + "</td>";
      html += "<td class='actions'>";
      html += "<button class='act-cek' onclick='cekUser(\\"" + u.user + "\\")'>Cek</button>";
      html += "<button class='act-renew' onclick='fillRenew(\\"" + u.user + "\\")'>Renew</button>";
      html += "<button class='act-del' onclick='fillDelete(\\"" + u.user + "\\")'>Hapus</button>";
      html += "</td></tr>";
    }
    html += "</tbody></table>";
    box.innerHTML = html;
  } catch (err) {
    box.innerHTML = "<p style='color:#f87171'>Error: " + err.message + "</p>";
  }
}

async function cekUser(user) {
  try {
    const json = await api("cek/" + currentProto, { user });
    if (json.ok) {
      let html = "<b>📋 Detail " + user + "</b><br><br>";
      html += "<b>Expired:</b> " + json.expired + " (" + json.days_left + " hari)<br>";
      if (json.uuid) html += "<b>UUID:</b> " + json.uuid + "<br>";
      if (json.password) html += "<b>Password:</b> " + json.password + "<br>";
      if (json.quota_gb !== undefined) html += "<b>Kuota:</b> " + json.quota_gb + " GB<br>";
      html += "<b>IP Limit:</b> " + (json.ip_limit || "-") + "<br>";
      html += formatLinks(json);
      showResult("result-list", true, html);
    } else {
      showResult("result-list", false, "❌ " + (json.msg || "Gagal"));
    }
  } catch (err) {
    showResult("result-list", false, "❌ " + err.message);
  }
}

function fillRenew(user) {
  switchActionByName("renew");
  document.querySelector("#panel-renew input[name=user]").value = user;
}

function fillDelete(user) {
  switchActionByName("delete");
  document.querySelector("#panel-delete input[name=user]").value = user;
}

function switchActionByName(act) {
  currentAction = act;
  document.querySelectorAll(".subtab").forEach((t, i) => {
    const names = ["create","list","renew","delete","trial"];
    t.classList.toggle("active", names[i] === act);
  });
  ["create","list","renew","delete","trial"].forEach(a => {
    document.getElementById("panel-" + a).classList.toggle("hidden", a !== act);
  });
}

async function doRenew(e) {
  e.preventDefault();
  const form = e.target;
  const btn = form.querySelector("button");
  btn.disabled = true;
  btn.innerText = "Memproses...";
  const data = { user: form.user.value, expi: form.expi.value };
  if (form.iplim.value) data.iplim = form.iplim.value;
  if (form.quota && form.quota.value !== "") data.quota = form.quota.value;
  try {
    const json = await api("renew/" + currentProto, data);
    if (json.ok) {
      let html = "<b>✅ Berhasil diperpanjang!</b><br><br>";
      html += "<b>User:</b> " + json.user + "<br>";
      html += "<b>Expired lama:</b> " + json.old_expired + "<br>";
      html += "<b>Expired baru:</b> " + json.expired + "<br>";
      html += "<b>Ditambah:</b> " + json.days_added + " hari<br>";
      showResult("result-renew", true, html);
    } else {
      showResult("result-renew", false, "❌ " + (json.msg || "Gagal"));
    }
  } catch (err) {
    showResult("result-renew", false, "❌ " + err.message);
  }
  btn.disabled = false;
  btn.innerText = "Perpanjang Akun";
}

async function doDelete(e) {
  e.preventDefault();
  const form = e.target;
  const user = form.user.value;
  if (!confirm("Yakin hapus akun " + user + " (" + currentProto + ")?")) return;
  const btn = form.querySelector("button");
  btn.disabled = true;
  btn.innerText = "Menghapus...";
  try {
    const json = await api("del/" + currentProto, { user });
    if (json.ok) {
      showResult("result-delete", true, "<b>✅ " + json.msg + "</b>");
      form.user.value = "";
    } else {
      showResult("result-delete", false, "❌ " + (json.msg || "Gagal"));
    }
  } catch (err) {
    showResult("result-delete", false, "❌ " + err.message);
  }
  btn.disabled = false;
  btn.innerText = "Hapus Akun";
}

async function doTrial(e) {
  e.preventDefault();
  const form = e.target;
  const btn = form.querySelector("button");
  btn.disabled = true;
  btn.innerText = "Membuat trial...";
  try {
    const json = await api("trial/" + currentProto, { expi: form.expi.value });
    if (json.ok) {
      let html = "<b>✅ Trial berhasil dibuat!</b><br><br>";
      html += "<b>User:</b> " + json.user + "<br>";
      if (json.pass) html += "<b>Password:</b> " + json.pass + "<br>";
      if (json.uuid) html += "<b>UUID:</b> " + json.uuid + "<br>";
      if (json.password) html += "<b>Password:</b> " + json.password + "<br>";
      html += "<b>Expired:</b> " + json.expired + "<br>";
      html += formatLinks(json);
      showResult("result-trial", true, html);
    } else {
      showResult("result-trial", false, "❌ " + (json.msg || "Gagal"));
    }
  } catch (err) {
    showResult("result-trial", false, "❌ " + err.message);
  }
  btn.disabled = false;
  btn.innerText = "Buat Akun Trial";
}

updateCreateForm();
</script>
</body>
</html>
'''

if __name__ == "__main__":
    print(f"FST Panel running → http://0.0.0.0:{PORT}")
    print(f"Akses: http://domain{PREFIX}")
    print(f"Login: {ADMIN_USER} / {ADMIN_PASS}")
    print("API endpoints:")
    print("  POST /panel/api/ssh|vmess|vless|trojan|shadowsocks  → buat")
    print("  GET/POST /panel/api/list/<proto>                    → list")
    print("  POST /panel/api/cek/<proto>  {user}                 → detail")
    print("  POST /panel/api/renew/<proto> {user,expi,...}       → perpanjang")
    print("  POST /panel/api/del/<proto>  {user}                 → hapus")
    print("  POST /panel/api/trial/<proto> {expi}                → trial")
    app.run(host="0.0.0.0", port=PORT, quiet=True)
