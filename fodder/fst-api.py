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

# ====================== SERVICE STATUS / RESTART ======================
XRAY_SERVICES = [
    ("vmess@config", "VMess"),
    ("vless@config", "VLess"),
    ("trojan@config", "Trojan"),
    ("shadowsocks@config", "Shadowsocks"),
]
SYSTEM_SERVICES = [
    ("ws", "WebSocket"),
    ("dropbear", "Dropbear"),
    ("ssh", "SSH"),
    ("badvpn", "BadVPN"),
    ("limitip", "Limit IP"),
    ("limitquota", "Limit Quota"),
]

def _svc_status(unit):
    code, out, _ = run_cmd(f"systemctl is-active {unit}")
    active = out.strip() == "active"
    code2, en, _ = run_cmd(f"systemctl is-enabled {unit} 2>/dev/null")
    enabled = en.strip() in ("enabled", "enabled-runtime", "static")
    # uptime-ish: ActiveEnterTimestamp
    _, since, _ = run_cmd(f"systemctl show -p ActiveEnterTimestamp --value {unit} 2>/dev/null")
    return {
        "unit": unit,
        "active": active,
        "status": out.strip() or "unknown",
        "enabled": enabled,
        "since": (since or "").strip(),
    }

@app.route(PREFIX + "/api/services", method=["GET", "POST"])
def api_services():
    if not require_auth():
        return json_response({"ok": False, "msg": "Unauthorized"}, 401)
    items = []
    for unit, label in XRAY_SERVICES + SYSTEM_SERVICES:
        st = _svc_status(unit)
        st["name"] = label
        st["group"] = "xray" if unit in [u for u,_ in XRAY_SERVICES] else "system"
        items.append(st)
    # domain & uptime server
    domain = get_domain()
    _, uptime, _ = run_cmd("uptime -p 2>/dev/null || uptime")
    _, load, _ = run_cmd("cat /proc/loadavg 2>/dev/null | awk '{print $1,$2,$3}'")
    mem = ""
    try:
        with open("/proc/meminfo") as f:
            lines = f.readlines()
        total = avail = 0
        for ln in lines:
            if ln.startswith("MemTotal:"): total = int(ln.split()[1])
            if ln.startswith("MemAvailable:"): avail = int(ln.split()[1])
        if total:
            used_pct = round((1 - avail / total) * 100, 1)
            mem = f"{used_pct}% used"
    except:
        pass
    online = sum(1 for i in items if i["active"])
    return json_response({
        "ok": True,
        "domain": domain,
        "uptime": uptime.strip(),
        "load": load.strip(),
        "memory": mem,
        "online": online,
        "total": len(items),
        "services": items,
    })

@app.route(PREFIX + "/api/services/restart", method="POST")
def api_restart_service():
    if not require_auth():
        return json_response({"ok": False, "msg": "Unauthorized"}, 401)
    data = request.json or request.forms or {}
    unit = (data.get("unit") or data.get("service") or "").strip()
    allowed = {u for u, _ in XRAY_SERVICES + SYSTEM_SERVICES}
    if unit not in allowed:
        return json_response({"ok": False, "msg": f"Service tidak diizinkan: {unit}"}, 400)
    if unit == "fst-api":
        # restart self di background
        run_cmd("systemctl restart fst-api")
        return json_response({"ok": True, "msg": "FST API di-restart", "unit": unit})
    code, out, err = run_cmd(f"systemctl restart {unit}")
    st = _svc_status(unit)
    if code != 0 and not st["active"]:
        return json_response({"ok": False, "msg": err or out or "Gagal restart", "unit": unit, **st}, 500)
    return json_response({"ok": True, "msg": f"{unit} di-restart", "unit": unit, **st})

@app.route(PREFIX + "/api/services/restart-all", method="POST")
def api_restart_all_xray():
    if not require_auth():
        return json_response({"ok": False, "msg": "Unauthorized"}, 401)
    results = []
    for unit, label in XRAY_SERVICES:
        run_cmd(f"systemctl restart {unit}")
        st = _svc_status(unit)
        results.append({"name": label, "unit": unit, "active": st["active"]})
    return json_response({"ok": True, "msg": "Semua Xray di-restart", "results": results})

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
<title>Login · FST Panel</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#070b14;--card:rgba(18,24,38,.88);--border:rgba(148,163,184,.12);--text:#e8eef9;--muted:#8b9bb4;--p:#6366f1;--p2:#8b5cf6}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Inter,system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;color:var(--text);background:var(--bg);overflow:hidden;position:relative}
body::before,body::after{content:"";position:absolute;border-radius:50%;filter:blur(90px);z-index:0;pointer-events:none}
body::before{width:440px;height:440px;background:radial-gradient(circle,rgba(99,102,241,.38),transparent 70%);top:-140px;left:-100px;animation:f 12s ease-in-out infinite}
body::after{width:400px;height:400px;background:radial-gradient(circle,rgba(139,92,246,.32),transparent 70%);bottom:-120px;right:-80px;animation:f 14s ease-in-out infinite reverse}
@keyframes f{0%,100%{transform:translate(0,0)}50%{transform:translate(28px,18px)}}
.wrap{position:relative;z-index:1;width:100%;max-width:420px;padding:20px}
.card{background:var(--card);backdrop-filter:blur(28px);-webkit-backdrop-filter:blur(28px);border:1px solid var(--border);border-radius:24px;padding:40px 34px;box-shadow:0 25px 50px -12px rgba(0,0,0,.55);animation:up .45s ease}
@keyframes up{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
.logo{width:56px;height:56px;margin:0 auto 16px;border-radius:16px;background:linear-gradient(135deg,var(--p),var(--p2));display:flex;align-items:center;justify-content:center;font-weight:700;font-size:1.2rem;color:#fff;box-shadow:0 8px 24px rgba(99,102,241,.4)}
h1{text-align:center;font-size:1.5rem;font-weight:700;letter-spacing:-.02em;margin-bottom:4px}
.sub{text-align:center;color:var(--muted);font-size:.88rem;margin-bottom:26px}
label{display:block;font-size:.78rem;font-weight:500;color:var(--muted);margin-bottom:6px}
.field{margin-bottom:14px}
input{width:100%;padding:13px 15px;border-radius:12px;border:1px solid var(--border);background:rgba(7,11,20,.65);color:var(--text);font-size:.94rem;font-family:inherit;transition:border-color .2s,box-shadow .2s}
input:focus{outline:none;border-color:rgba(99,102,241,.55);box-shadow:0 0 0 3px rgba(99,102,241,.14)}
input::placeholder{color:#4a5568}
button{width:100%;margin-top:6px;padding:14px;border:none;border-radius:12px;background:linear-gradient(135deg,var(--p),var(--p2));color:#fff;font-weight:600;font-size:.94rem;font-family:inherit;cursor:pointer;transition:transform .15s,box-shadow .2s;box-shadow:0 8px 20px rgba(99,102,241,.32)}
button:hover{transform:translateY(-1px);box-shadow:0 12px 28px rgba(99,102,241,.42)}
.error{background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.28);color:#fca5a5;padding:11px 13px;border-radius:12px;margin-bottom:16px;text-align:center;font-size:.86rem}
.foot{text-align:center;margin-top:20px;font-size:.72rem;color:#4a5568}
</style>
</head>
<body>
<div class="wrap"><div class="card">
<div class="logo">F</div>
<h1>FST Panel</h1>
<p class="sub">Masuk untuk mengelola VPN</p>
% if error:
<div class="error">{{error}}</div>
% end
<form method="POST" action="{{prefix}}/login">
<div class="field"><label>Username</label><input type="text" name="username" required autofocus placeholder="Username admin"></div>
<div class="field"><label>Password</label><input type="password" name="password" required placeholder="••••••••"></div>
<button type="submit">Masuk</button>
</form>
<p class="foot">Secure session · 12 jam</p>
</div></div>
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
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#070b14;--surface:#0c1220;--card:#121a2b;--border:rgba(148,163,184,.1);
  --text:#e8eef9;--muted:#8494ad;--p:#6366f1;--p2:#8b5cf6;
  --ok:#22c55e;--warn:#f59e0b;--danger:#ef4444;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;line-height:1.5}
.glow{position:fixed;inset:0;pointer-events:none;z-index:0;background:
  radial-gradient(ellipse 55% 35% at 8% -5%,rgba(99,102,241,.14),transparent),
  radial-gradient(ellipse 45% 30% at 95% 5%,rgba(139,92,246,.1),transparent)}
.app{position:relative;z-index:1;max-width:1000px;margin:0 auto;padding:18px 14px 48px}

/* Header */
.hdr{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:20px}
.brand{display:flex;align-items:center;gap:12px}
.bicon{width:42px;height:42px;border-radius:13px;background:linear-gradient(135deg,var(--p),var(--p2));display:flex;align-items:center;justify-content:center;font-weight:700;color:#fff;box-shadow:0 6px 18px rgba(99,102,241,.35)}
.brand h1{font-size:1.2rem;font-weight:700;letter-spacing:-.02em}
.brand small{display:block;font-size:.72rem;color:var(--muted);margin-top:1px}
.btn-g{background:var(--card);border:1px solid var(--border);color:var(--muted);padding:8px 14px;border-radius:10px;font-size:.82rem;font-weight:500;text-decoration:none;cursor:pointer;font-family:inherit;transition:.15s}
.btn-g:hover{color:var(--text);border-color:rgba(148,163,184,.22);background:#1a2438}

/* Stats bar */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:18px}
@media(max-width:700px){.stats{grid-template-columns:repeat(2,1fr)}}
.stat{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:14px 16px;transition:border-color .2s}
.stat:hover{border-color:rgba(99,102,241,.25)}
.stat .l{font-size:.7rem;color:var(--muted);font-weight:500;text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px}
.stat .v{font-size:1.05rem;font-weight:700;letter-spacing:-.01em}
.stat .v.ok{color:#86efac}.stat .v.warn{color:#fde68a}

/* Nav */
.nav-main{display:flex;gap:6px;margin-bottom:14px;flex-wrap:wrap}
.nav-btn{padding:10px 16px;border-radius:11px;border:1px solid var(--border);background:var(--card);color:var(--muted);font-weight:600;font-size:.82rem;cursor:pointer;font-family:inherit;transition:.2s}
.nav-btn:hover{color:var(--text);border-color:rgba(148,163,184,.2)}
.nav-btn.active{background:linear-gradient(135deg,var(--p),var(--p2));border-color:transparent;color:#fff;box-shadow:0 6px 16px rgba(99,102,241,.3)}

/* Proto chips */
.protos{display:flex;gap:6px;margin-bottom:12px;overflow-x:auto;scrollbar-width:none}
.protos::-webkit-scrollbar{display:none}
.chip{flex:1;min-width:68px;padding:9px 10px;border-radius:11px;border:1px solid var(--border);background:var(--card);color:var(--muted);font-weight:600;font-size:.78rem;cursor:pointer;font-family:inherit;transition:.2s;white-space:nowrap;text-align:center}
.chip:hover{border-color:rgba(99,102,241,.35);color:var(--text)}
.chip.active{background:rgba(99,102,241,.18);border-color:rgba(99,102,241,.5);color:#a5b4fc}

/* Action pills */
.acts{display:flex;gap:6px;margin-bottom:16px;flex-wrap:wrap}
.pill{padding:7px 13px;border-radius:999px;border:1px solid var(--border);background:transparent;color:var(--muted);font-size:.78rem;font-weight:500;cursor:pointer;font-family:inherit;transition:.2s}
.pill:hover{color:var(--text);border-color:rgba(148,163,184,.25)}
.pill.active{background:rgba(99,102,241,.14);border-color:rgba(99,102,241,.42);color:#a5b4fc}

/* Panel card */
.panel{background:var(--card);border:1px solid var(--border);border-radius:18px;padding:22px;animation:in .28s ease}
@keyframes in{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.hidden{display:none!important}
label{display:block;font-size:.76rem;font-weight:500;color:var(--muted);margin-bottom:5px}
input{width:100%;padding:11px 13px;border-radius:11px;border:1px solid var(--border);background:var(--surface);color:var(--text);font-size:.88rem;font-family:inherit;margin-bottom:12px;transition:.2s}
input:focus{outline:none;border-color:rgba(99,102,241,.5);box-shadow:0 0 0 3px rgba(99,102,241,.12)}
input::placeholder{color:#3a4658}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:560px){.row2{grid-template-columns:1fr}}

.btn{width:100%;padding:12px 16px;border:none;border-radius:12px;background:linear-gradient(135deg,var(--p),var(--p2));color:#fff;font-weight:600;font-size:.88rem;font-family:inherit;cursor:pointer;transition:.15s;box-shadow:0 6px 16px rgba(99,102,241,.28)}
.btn:hover{transform:translateY(-1px);box-shadow:0 10px 22px rgba(99,102,241,.36)}
.btn:disabled{opacity:.55;cursor:not-allowed;transform:none}
.btn-sm{width:auto;padding:8px 14px;font-size:.78rem;margin-bottom:14px}
.btn-ok{background:linear-gradient(135deg,#22c55e,#16a34a);box-shadow:0 6px 16px rgba(34,197,94,.22)}
.btn-warn{background:linear-gradient(135deg,#f59e0b,#d97706);box-shadow:0 6px 16px rgba(245,158,11,.22)}
.btn-danger{background:linear-gradient(135deg,#ef4444,#b91c1c);box-shadow:0 6px 16px rgba(239,68,68,.22)}
.btn-outline{background:transparent;border:1px solid var(--border);color:var(--muted);box-shadow:none}
.btn-outline:hover{border-color:rgba(99,102,241,.4);color:#a5b4fc}

.result{display:none;margin-top:16px;padding:14px;border-radius:12px;background:var(--surface);border-left:3px solid var(--ok);font-size:.84rem;word-break:break-all;animation:in .25s ease}
.result.show{display:block}.result.error{border-left-color:var(--danger)}
.link-box{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:9px 11px;margin:8px 0 4px;font-size:.74rem;font-family:ui-monospace,monospace;color:#cbd5e1}
.copy{margin:0 5px 8px 0;padding:5px 11px;background:#1a2438;border:1px solid var(--border);border-radius:8px;color:#94a3b8;font-size:.72rem;font-weight:500;cursor:pointer;font-family:inherit}
.copy:hover{background:#243044;color:#fff}
.warn-t{color:#f87171;font-size:.84rem;margin-bottom:12px}
.hint{color:var(--muted);font-size:.84rem;margin-bottom:12px}

/* Services grid */
.svc-head{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:16px}
.svc-head h2{font-size:1rem;font-weight:600}
.svc-actions{display:flex;gap:8px;flex-wrap:wrap}
.svc-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px}
.svc-card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:14px;transition:border-color .2s,transform .15s}
.svc-card:hover{border-color:rgba(148,163,184,.2)}
.svc-card.up{border-color:rgba(34,197,94,.2)}
.svc-card.down{border-color:rgba(239,68,68,.2)}
.svc-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}
.svc-name{font-weight:600;font-size:.88rem}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:7px;box-shadow:0 0 8px currentColor}
.dot.on{background:var(--ok);color:var(--ok)}
.dot.off{background:var(--danger);color:var(--danger)}
.svc-meta{font-size:.72rem;color:var(--muted);margin-bottom:10px}
.svc-meta code{font-size:.68rem;background:rgba(0,0,0,.25);padding:1px 5px;border-radius:4px}
.svc-btn{width:100%;padding:8px;border-radius:9px;border:1px solid var(--border);background:transparent;color:var(--muted);font-size:.76rem;font-weight:500;cursor:pointer;font-family:inherit;transition:.15s}
.svc-btn:hover{border-color:rgba(99,102,241,.4);color:#a5b4fc;background:rgba(99,102,241,.08)}
.svc-btn:disabled{opacity:.5;cursor:wait}
.group-title{font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:600;margin:16px 0 8px;grid-column:1/-1}

/* Table */
.twrap{overflow-x:auto;border-radius:12px;border:1px solid var(--border)}
table{width:100%;border-collapse:collapse;font-size:.8rem}
th,td{padding:10px 11px;text-align:left;border-bottom:1px solid var(--border)}
th{background:var(--surface);color:var(--muted);font-weight:600;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(99,102,241,.04)}
.badge{display:inline-flex;padding:2px 8px;border-radius:999px;font-size:.7rem;font-weight:600}
.badge-ok{background:rgba(34,197,94,.15);color:#86efac}
.badge-warn{background:rgba(245,158,11,.15);color:#fde047}
.badge-exp{background:rgba(239,68,68,.15);color:#fca5a5}
.actions{display:flex;gap:4px;flex-wrap:wrap}
.actions button{padding:4px 9px;font-size:.7rem;font-weight:500;border-radius:6px;border:none;cursor:pointer;color:#fff;font-family:inherit}
.act-cek{background:#3b82f6}.act-renew{background:#d97706}.act-del{background:#dc2626}
.empty{text-align:center;padding:28px 14px;color:var(--muted);font-size:.88rem}
.spin{display:inline-block;width:16px;height:16px;border:2px solid rgba(99,102,241,.25);border-top-color:var(--p);border-radius:50%;animation:sp .65s linear infinite;vertical-align:middle;margin-right:7px}
@keyframes sp{to{transform:rotate(360deg)}}
.toast{position:fixed;bottom:20px;right:20px;z-index:99;background:#1a2438;border:1px solid var(--border);color:var(--text);padding:12px 18px;border-radius:12px;font-size:.84rem;box-shadow:0 12px 32px rgba(0,0,0,.4);animation:in .25s ease;max-width:320px}
.toast.err{border-color:rgba(239,68,68,.4)}
.toast.ok{border-color:rgba(34,197,94,.4)}
</style>
</head>
<body>
<div class="glow"></div>
<div class="app">
  <header class="hdr">
    <div class="brand">
      <div class="bicon">F</div>
      <div><h1>FST Panel</h1><small id="domain-label">VPN Manager</small></div>
    </div>
    <a href="{{prefix}}/logout" class="btn-g">Logout</a>
  </header>

  <div class="stats" id="stats-bar">
    <div class="stat"><div class="l">Services</div><div class="v" id="st-svc">—</div></div>
    <div class="stat"><div class="l">Uptime</div><div class="v" id="st-up" style="font-size:.9rem">—</div></div>
    <div class="stat"><div class="l">Load</div><div class="v" id="st-load" style="font-size:.9rem">—</div></div>
    <div class="stat"><div class="l">Memory</div><div class="v" id="st-mem" style="font-size:.9rem">—</div></div>
  </div>

  <div class="nav-main">
    <button class="nav-btn active" onclick="showSection('accounts')">Akun</button>
    <button class="nav-btn" onclick="showSection('services')">Services</button>
  </div>

  <!-- ===== ACCOUNTS ===== -->
  <div id="sec-accounts">
    <div class="protos">
      <button class="chip active" onclick="switchProto('ssh', this)">SSH</button>
      <button class="chip" onclick="switchProto('vmess', this)">VMess</button>
      <button class="chip" onclick="switchProto('vless', this)">VLess</button>
      <button class="chip" onclick="switchProto('trojan', this)">Trojan</button>
      <button class="chip" onclick="switchProto('shadowsocks', this)">SS</button>
    </div>
    <div class="acts">
      <button class="pill active" onclick="switchAction('create', this)">Buat</button>
      <button class="pill" onclick="switchAction('list', this)">List / Cek</button>
      <button class="pill" onclick="switchAction('renew', this)">Renew</button>
      <button class="pill" onclick="switchAction('delete', this)">Hapus</button>
      <button class="pill" onclick="switchAction('trial', this)">Trial</button>
    </div>

    <div id="panel-create" class="panel">
      <form id="form-create" onsubmit="doCreate(event)">
        <div id="ssh-fields">
          <label>Username</label>
          <input type="text" name="user" required placeholder="min. 3 karakter" pattern="[a-zA-Z0-9_-]{3,32}">
          <label>Password</label>
          <input type="text" name="pass" required placeholder="password">
          <div class="row2">
            <div><label>Masa Aktif (hari)</label><input type="number" name="expi" value="30" min="1" required></div>
            <div><label>Batas IP</label><input type="number" name="iplim" value="2" min="1"></div>
          </div>
        </div>
        <div id="xray-fields" class="hidden">
          <label>Username</label>
          <input type="text" name="user_x" placeholder="min. 3 karakter" pattern="[a-zA-Z0-9_-]{3,32}">
          <div class="row2">
            <div><label>Masa Aktif (hari)</label><input type="number" name="expi_x" value="30" min="1"></div>
            <div><label>Kuota GB (0=unlimited)</label><input type="number" name="quota" value="0" min="0"></div>
          </div>
          <label>Batas IP</label>
          <input type="number" name="iplim_x" value="2" min="0">
        </div>
        <button type="submit" class="btn" id="btn-create">Buat Akun SSH</button>
      </form>
      <div id="result-create" class="result"></div>
    </div>

    <div id="panel-list" class="panel hidden">
      <button class="btn btn-ok btn-sm" onclick="loadList()">Refresh List</button>
      <div id="list-content"><div class="empty">Klik Refresh untuk memuat daftar</div></div>
      <div id="result-list" class="result"></div>
    </div>

    <div id="panel-renew" class="panel hidden">
      <form onsubmit="doRenew(event)">
        <label>Username</label>
        <input type="text" name="user" required placeholder="username">
        <div class="row2">
          <div><label>Tambah hari</label><input type="number" name="expi" value="30" min="1" required></div>
          <div><label>Batas IP (opsional)</label><input type="number" name="iplim" placeholder="kosong = tidak ubah"></div>
        </div>
        <div id="renew-quota" class="hidden">
          <label>Kuota GB (opsional)</label>
          <input type="number" name="quota" placeholder="kosong = tidak ubah">
        </div>
        <button type="submit" class="btn btn-warn">Perpanjang</button>
      </form>
      <div id="result-renew" class="result"></div>
    </div>

    <div id="panel-delete" class="panel hidden">
      <form onsubmit="doDelete(event)">
        <label>Username</label>
        <input type="text" name="user" required placeholder="username">
        <p class="warn-t">Aksi permanen. Akun akan dihapus.</p>
        <button type="submit" class="btn btn-danger">Hapus Akun</button>
      </form>
      <div id="result-delete" class="result"></div>
    </div>

    <div id="panel-trial" class="panel hidden">
      <form onsubmit="doTrial(event)">
        <label>Durasi Trial (hari)</label>
        <input type="number" name="expi" value="1" min="1" max="7">
        <p class="hint">Username otomatis: trial-xxxxxx</p>
        <button type="submit" class="btn btn-ok">Buat Trial</button>
      </form>
      <div id="result-trial" class="result"></div>
    </div>
  </div>

  <!-- ===== SERVICES ===== -->
  <div id="sec-services" class="hidden">
    <div class="panel">
      <div class="svc-head">
        <h2>Status Service</h2>
        <div class="svc-actions">
          <button class="btn btn-sm btn-outline" onclick="loadServices()">Refresh</button>
          <button class="btn btn-sm btn-warn" onclick="restartAllXray()">Restart All Xray</button>
        </div>
      </div>
      <div id="svc-grid" class="svc-grid">
        <div class="empty"><span class="spin"></span>Memuat status...</div>
      </div>
    </div>
  </div>
</div>


<script>
(function(){
"use strict";
var PREFIX = "{{prefix}}";
var currentProto = "ssh";
var currentAction = "create";

function $(sel, root){ return (root||document).querySelector(sel); }
function $all(sel, root){ return Array.prototype.slice.call((root||document).querySelectorAll(sel)); }

function showSection(sec){
  $("#sec-accounts").classList.toggle("hidden", sec !== "accounts");
  $("#sec-services").classList.toggle("hidden", sec !== "services");
  $all(".nav-btn").forEach(function(b,i){
    b.classList.toggle("active", (sec==="accounts"&&i===0)||(sec==="services"&&i===1));
  });
  if(sec === "services") loadServices();
}

function switchProto(p, el){
  currentProto = p;
  $all(".chip").forEach(function(c){ c.classList.remove("active"); });
  if(el) el.classList.add("active");
  updateCreateForm();
  if(currentAction === "list") loadList();
  var rq = $("#renew-quota");
  if(rq) rq.classList.toggle("hidden", p === "ssh");
}

function switchAction(a, el){
  currentAction = a;
  $all(".pill").forEach(function(t){ t.classList.remove("active"); });
  if(el) el.classList.add("active");
  ["create","list","renew","delete","trial"].forEach(function(x){
    var p = $("#panel-"+x);
    if(p) p.classList.toggle("hidden", x !== a);
  });
  if(a === "list") loadList();
}

function switchActionByName(a){
  currentAction = a;
  var names = ["create","list","renew","delete","trial"];
  $all(".pill").forEach(function(t,i){ t.classList.toggle("active", names[i]===a); });
  names.forEach(function(x){
    var p = $("#panel-"+x);
    if(p) p.classList.toggle("hidden", x !== a);
  });
}

function updateCreateForm(){
  var s = currentProto === "ssh";
  var sf = $("#ssh-fields"), xf = $("#xray-fields");
  if(sf) sf.classList.toggle("hidden", !s);
  if(xf) xf.classList.toggle("hidden", s);
  var btn = $("#btn-create");
  if(btn) btn.textContent = "Buat Akun " + currentProto.toUpperCase();
  var u = $("input[name=user]", sf), pass = $("input[name=pass]", sf), ex = $("input[name=expi]", sf);
  var ux = $("input[name=user_x]", xf), exx = $("input[name=expi_x]", xf);
  if(u) u.required = s;
  if(pass) pass.required = s;
  if(ex) ex.required = s;
  if(ux) ux.required = !s;
  if(exx) exx.required = !s;
}

function api(path, body){
  return fetch(PREFIX + "/api/" + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(body || {})
  }).then(function(r){ return r.json(); });
}

function showResult(id, ok, html){
  var el = document.getElementById(id);
  if(!el) return;
  el.className = "result show" + (ok ? "" : " error");
  el.innerHTML = html;
}

function toast(msg, ok){
  var t = document.createElement("div");
  t.className = "toast " + (ok ? "ok" : "err");
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(function(){ t.remove(); }, 3200);
}

function formatLinks(j){
  var h = "";
  function add(label, val){
    if(!val) return;
    h += '<div class="link-box"><b>' + label + '</b><br>' + val + '</div>';
    h += '<button type="button" class="copy" data-copy="' + encodeURIComponent(val) + '">Copy ' + label + '</button>';
  }
  add("TLS", j.tls);
  add("Non-TLS", j.nontls);
  add("gRPC", j.grpc);
  add("WS", j.ws);
  if(j.link) h += '<br><a href="' + j.link + '" target="_blank" style="color:#a5b4fc;font-size:.84rem">Download Config</a>';
  return h;
}

// Event delegation for copy buttons & list actions
document.addEventListener("click", function(e){
  var t = e.target;
  if(t.classList && t.classList.contains("copy") && t.dataset.copy){
    var val = decodeURIComponent(t.dataset.copy);
    if(navigator.clipboard && navigator.clipboard.writeText){
      navigator.clipboard.writeText(val).then(function(){ t.textContent = "Copied!"; });
    } else {
      var ta = document.createElement("textarea");
      ta.value = val; document.body.appendChild(ta); ta.select();
      try{ document.execCommand("copy"); t.textContent = "Copied!"; }catch(x){}
      ta.remove();
    }
    return;
  }
  if(t.dataset && t.dataset.act){
    var act = t.dataset.act, user = t.dataset.user;
    if(act === "cek") cekUser(user);
    else if(act === "renew") fillRenew(user);
    else if(act === "del") fillDelete(user);
    else if(act === "restart") restartSvc(t.dataset.unit, t);
  }
});

function doCreate(e){
  e.preventDefault();
  var f = e.target, btn = f.querySelector("button[type=submit]");
  btn.disabled = true;
  var old = btn.textContent;
  btn.textContent = "Membuat...";
  var data;
  if(currentProto === "ssh"){
    data = { user: f.user.value, pass: f.pass.value, expi: f.expi.value, iplim: f.iplim.value };
  } else {
    data = { user: f.user_x.value, expi: f.expi_x.value, quota: f.quota.value, iplim: f.iplim_x.value };
  }
  api(currentProto, data).then(function(j){
    if(j.ok){
      var h = "<b>Berhasil dibuat</b><br><br><b>User:</b> " + j.user + "<br>";
      if(j.pass) h += "<b>Pass:</b> " + j.pass + "<br>";
      if(j.uuid) h += "<b>UUID:</b> " + j.uuid + "<br>";
      if(j.password) h += "<b>Pass:</b> " + j.password + "<br>";
      if(j.method) h += "<b>Method:</b> " + j.method + "<br>";
      h += "<b>Expired:</b> " + j.expired + "<br>" + formatLinks(j);
      showResult("result-create", true, h);
    } else showResult("result-create", false, (j.msg || "Gagal"));
  }).catch(function(err){
    showResult("result-create", false, err.message);
  }).then(function(){
    btn.disabled = false;
    btn.textContent = old;
  });
}

function loadList(){
  var box = $("#list-content");
  box.innerHTML = '<div class="empty"><span class="spin"></span>Memuat...</div>';
  fetch(PREFIX + "/api/list/" + currentProto, { credentials: "same-origin" })
    .then(function(r){ return r.json(); })
    .then(function(j){
      if(!j.ok){ box.innerHTML = '<div class="empty" style="color:#f87171">' + (j.msg||"Gagal") + '</div>'; return; }
      if(!j.users || !j.users.length){ box.innerHTML = '<div class="empty">Belum ada akun ' + currentProto.toUpperCase() + '</div>'; return; }
      var h = '<div class="twrap"><table><thead><tr><th>User</th><th>Expired</th><th>Sisa</th>';
      if(currentProto !== "ssh") h += "<th>Kuota</th>";
      h += "<th>IP</th><th>Aksi</th></tr></thead><tbody>";
      j.users.forEach(function(u){
        var b = u.days_left > 7 ? "badge-ok" : (u.days_left > 0 ? "badge-warn" : "badge-exp");
        h += "<tr><td><b>" + u.user + "</b></td>";
        h += "<td style='color:#8494ad;font-size:.76rem'>" + u.expired + "</td>";
        h += "<td><span class='badge " + b + "'>" + u.days_left + " hari</span></td>";
        if(currentProto !== "ssh") h += "<td>" + (u.quota_gb||0) + " GB</td>";
        h += "<td>" + (u.ip_limit||"-") + "</td><td class='actions'>";
        h += "<button class='act-cek' data-act='cek' data-user='" + u.user + "'>Cek</button>";
        h += "<button class='act-renew' data-act='renew' data-user='" + u.user + "'>Renew</button>";
        h += "<button class='act-del' data-act='del' data-user='" + u.user + "'>Hapus</button></td></tr>";
      });
      h += "</tbody></table></div>";
      box.innerHTML = h;
    })
    .catch(function(err){
      box.innerHTML = '<div class="empty" style="color:#f87171">' + err.message + '</div>';
    });
}

function cekUser(user){
  api("cek/" + currentProto, { user: user }).then(function(j){
    if(j.ok){
      var h = "<b>" + user + "</b><br><br><b>Expired:</b> " + j.expired + " (" + j.days_left + " hari)<br>";
      if(j.uuid) h += "<b>UUID:</b> " + j.uuid + "<br>";
      if(j.password) h += "<b>Pass:</b> " + j.password + "<br>";
      if(j.quota_gb !== undefined) h += "<b>Kuota:</b> " + j.quota_gb + " GB<br>";
      h += "<b>IP:</b> " + (j.ip_limit||"-") + "<br>" + formatLinks(j);
      showResult("result-list", true, h);
    } else showResult("result-list", false, j.msg||"Gagal");
  }).catch(function(err){ showResult("result-list", false, err.message); });
}

function fillRenew(u){
  switchActionByName("renew");
  var inp = $("#panel-renew input[name=user]");
  if(inp) inp.value = u;
}
function fillDelete(u){
  switchActionByName("delete");
  var inp = $("#panel-delete input[name=user]");
  if(inp) inp.value = u;
}

function doRenew(e){
  e.preventDefault();
  var f = e.target, btn = f.querySelector("button");
  btn.disabled = true; btn.textContent = "Proses...";
  var data = { user: f.user.value, expi: f.expi.value };
  if(f.iplim.value) data.iplim = f.iplim.value;
  if(f.quota && f.quota.value !== "") data.quota = f.quota.value;
  api("renew/" + currentProto, data).then(function(j){
    if(j.ok){
      showResult("result-renew", true, "<b>Berhasil diperpanjang</b><br><br><b>User:</b> " + j.user + "<br><b>Lama:</b> " + j.old_expired + "<br><b>Baru:</b> " + j.expired + "<br><b>+" + j.days_added + " hari</b>");
    } else showResult("result-renew", false, j.msg||"Gagal");
  }).catch(function(err){ showResult("result-renew", false, err.message); })
  .then(function(){ btn.disabled = false; btn.textContent = "Perpanjang"; });
}

function doDelete(e){
  e.preventDefault();
  var f = e.target, user = f.user.value;
  if(!confirm("Hapus akun " + user + " (" + currentProto + ")?")) return;
  var btn = f.querySelector("button");
  btn.disabled = true; btn.textContent = "Menghapus...";
  api("del/" + currentProto, { user: user }).then(function(j){
    if(j.ok){ showResult("result-delete", true, "<b>" + j.msg + "</b>"); f.user.value = ""; }
    else showResult("result-delete", false, j.msg||"Gagal");
  }).catch(function(err){ showResult("result-delete", false, err.message); })
  .then(function(){ btn.disabled = false; btn.textContent = "Hapus Akun"; });
}

function doTrial(e){
  e.preventDefault();
  var f = e.target, btn = f.querySelector("button");
  btn.disabled = true; btn.textContent = "Membuat...";
  api("trial/" + currentProto, { expi: f.expi.value }).then(function(j){
    if(j.ok){
      var h = "<b>Trial OK</b><br><br><b>User:</b> " + j.user + "<br>";
      if(j.pass) h += "<b>Pass:</b> " + j.pass + "<br>";
      if(j.uuid) h += "<b>UUID:</b> " + j.uuid + "<br>";
      if(j.password) h += "<b>Pass:</b> " + j.password + "<br>";
      h += "<b>Expired:</b> " + j.expired + "<br>" + formatLinks(j);
      showResult("result-trial", true, h);
    } else showResult("result-trial", false, j.msg||"Gagal");
  }).catch(function(err){ showResult("result-trial", false, err.message); })
  .then(function(){ btn.disabled = false; btn.textContent = "Buat Trial"; });
}

function loadServices(){
  var grid = $("#svc-grid");
  if(!grid) return;
  fetch(PREFIX + "/api/services", { credentials: "same-origin" })
    .then(function(r){ return r.json(); })
    .then(function(j){
      if(!j.ok){ grid.innerHTML = '<div class="empty">' + (j.msg||"Gagal") + '</div>'; return; }
      if(j.domain){ var dl = $("#domain-label"); if(dl) dl.textContent = j.domain; }
      var st = $("#st-svc");
      if(st) st.innerHTML = '<span class="' + (j.online===j.total?'ok':'warn') + '">' + j.online + '/' + j.total + ' online</span>';
      var su = $("#st-up"); if(su) su.textContent = j.uptime || "—";
      var sl = $("#st-load"); if(sl) sl.textContent = j.load || "—";
      var sm = $("#st-mem"); if(sm) sm.textContent = j.memory || "—";
      var xray = j.services.filter(function(s){ return s.group==="xray"; });
      var sys = j.services.filter(function(s){ return s.group==="system"; });
      var html = '<div class="group-title">Xray Protocols</div>';
      html += xray.map(svcCard).join("");
      html += '<div class="group-title">System Services</div>';
      html += sys.map(svcCard).join("");
      grid.innerHTML = html;
    })
    .catch(function(err){
      if(grid) grid.innerHTML = '<div class="empty" style="color:#f87171">' + err.message + '</div>';
    });
}

function svcCard(s){
  var on = s.active;
  return '<div class="svc-card ' + (on?'up':'down') + '">' +
    '<div class="svc-top"><div class="svc-name"><span class="dot ' + (on?'on':'off') + '"></span>' + s.name + '</div>' +
    '<span class="badge ' + (on?'badge-ok':'badge-exp') + '">' + (on?'Active':'Down') + '</span></div>' +
    '<div class="svc-meta"><code>' + s.unit + '</code> · ' + (s.status||'?') + '</div>' +
    '<button class="svc-btn" data-act="restart" data-unit="' + s.unit + '">Restart</button></div>';
}

function restartSvc(unit, btn){
  if(btn){ btn.disabled = true; btn.textContent = "Restarting..."; }
  api("services/restart", { unit: unit }).then(function(j){
    if(j.ok){ toast(unit + " restarted", true); setTimeout(loadServices, 800); }
    else toast(j.msg||"Gagal restart", false);
  }).catch(function(err){ toast(err.message, false); })
  .then(function(){ if(btn){ btn.disabled = false; btn.textContent = "Restart"; } });
}

function restartAllXray(){
  if(!confirm("Restart semua service Xray?")) return;
  toast("Restarting Xray...", true);
  api("services/restart-all", {}).then(function(j){
    if(j.ok){ toast("Semua Xray di-restart", true); setTimeout(loadServices, 1000); }
    else toast(j.msg||"Gagal", false);
  }).catch(function(err){ toast(err.message, false); });
}

// Wire onclick from HTML attributes that pass this
window.showSection = showSection;
window.switchProto = function(p, el){ switchProto(p, el || (typeof event!=='undefined' && event.currentTarget)); };
window.switchAction = function(a, el){ switchAction(a, el || (typeof event!=='undefined' && event.currentTarget)); };
window.doCreate = doCreate;
window.doRenew = doRenew;
window.doDelete = doDelete;
window.doTrial = doTrial;
window.loadList = loadList;
window.loadServices = loadServices;
window.restartAllXray = restartAllXray;
window.cekUser = cekUser;
window.fillRenew = fillRenew;
window.fillDelete = fillDelete;

updateCreateForm();
loadServices();
setInterval(function(){
  var sec = $("#sec-services");
  if(sec && !sec.classList.contains("hidden")) loadServices();
}, 30000);
})();
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
