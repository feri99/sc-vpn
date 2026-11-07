#!/usr/bin/env python3
from bottle import Bottle, request, response, redirect, template
import subprocess, os, json, uuid, datetime, re, base64, hashlib, time, secrets, hmac, shlex, ipaddress
from functools import wraps

app = Bottle()


# ================== KONFIGURASI ==================
CREDENTIALS_FILE = "/etc/fst-api/credentials.json"

with open(CREDENTIALS_FILE, "r", encoding="utf-8") as f:
    _credentials = json.load(f)

_required_credentials = ("api_key", "admin_user", "admin_pass", "secret_key")
if any(not isinstance(_credentials.get(name), str) or not _credentials[name]
       for name in _required_credentials):
    raise RuntimeError("Konfigurasi kredensial tidak lengkap atau tipenya tidak valid")
API_KEY, ADMIN_USER, ADMIN_PASS, SECRET_KEY = (_credentials[name] for name in _required_credentials)

PORT = 8880
PREFIX = "/panel"
COOKIE_SECURE = os.environ.get("FST_COOKIE_SECURE", "1").lower() not in ("0", "false", "no")
SESSION_IDLE_SECONDS = 30 * 60
SESSION_ABSOLUTE_SECONDS = 12 * 3600
# =================================================

sessions = {}
login_attempts = {}


def verify_admin_password(candidate):
    """Terima format hash PBKDF2 atau plaintext lama; plaintext dibandingkan konstan-waktu."""
    if ADMIN_PASS.startswith("pbkdf2_sha256$"):
        try:
            _, iterations, salt, expected = ADMIN_PASS.split("$", 3)
            iterations = int(iterations)
            if not (100_000 <= iterations <= 2_000_000):
                return False
            actual = hashlib.pbkdf2_hmac("sha256", candidate.encode(), salt.encode(), iterations).hex()
            return hmac.compare_digest(actual, expected)
        except (ValueError, TypeError):
            return False
    return hmac.compare_digest(candidate.encode(), ADMIN_PASS.encode())


def create_session():
    sid = secrets.token_urlsafe(32)
    now = time.time()
    sessions[sid] = {"created": now, "last_activity": now, "user": ADMIN_USER,
                     "csrf": secrets.token_urlsafe(32)}
    return sid


def check_session():
    sid = request.get_cookie("session_id")
    session = sessions.get(sid) if sid else None
    if not session:
        return False
    now = time.time()
    if (now - session["last_activity"] > SESSION_IDLE_SECONDS or
            now - session["created"] > SESSION_ABSOLUTE_SECONDS):
        sessions.pop(sid, None)
        return False
    session["last_activity"] = now
    return True


def csrf_valid():
    """Origin tidak dibatasi; mutasi tetap butuh token rahasia sesi yang cocok."""
    sid = request.get_cookie("session_id")
    session = sessions.get(sid) if sid else None
    if not session:
        return False
    supplied = request.get_header("X-CSRF-Token") or request.forms.get("csrf_token", "")
    return bool(supplied) and hmac.compare_digest(str(supplied), session["csrf"])


def redirect_local(path):
    """Kirim redirect path-relative agar scheme/host browser tidak diganti oleh upstream HTTP."""
    if (not isinstance(path, str) or not path.startswith("/") or path.startswith("//")
            or "\r" in path or "\n" in path):
        raise ValueError("redirect harus berupa path lokal")
    response.status = 303
    response.set_header("Location", path)
    return ""


def require_login(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not check_session():
            return redirect_local(f"{PREFIX}/login")
        return func(*args, **kwargs)
    return wrapper


def request_data(include_query=False):
    data = request.json
    if isinstance(data, dict):
        source = data
    else:
        source = request.forms
        if not source and include_query:
            source = request.query
    # Bentuk nilai menjadi string; tipe JSON kompleks ditolak sebagai input kosong.
    return {str(k): (v if isinstance(v, str) else str(v) if isinstance(v, (int, float)) else "")
            for k, v in source.items()}


def auth_api():
    data = request_data()
    key = request.get_header("APIKey") or data.get("apikey")
    return bool(key) and hmac.compare_digest(str(key), API_KEY)


def require_auth(mutation=False):
    """Terima API key, atau sesi browser yang lulus pemeriksaan CSRF untuk mutasi."""
    if auth_api():
        return True
    if not check_session():
        return False
    return not mutation or csrf_valid()


def json_response(data, status=200):
    response.content_type = "application/json; charset=utf-8"
    response.status = status
    return json.dumps(data, ensure_ascii=False)


@app.hook("after_request")
def add_security_headers():
    response.set_header("X-Content-Type-Options", "nosniff")
    response.set_header("X-Frame-Options", "DENY")
    response.set_header("Referrer-Policy", "no-referrer")
    response.set_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.set_header("Cache-Control", "no-store, max-age=0")
    response.set_header("Content-Security-Policy", "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self' https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self' 'unsafe-inline'")


def get_domain():
    try:
        with open("/etc/xray/domain", encoding="utf-8") as f:
            value = f.read().strip()
    except OSError:
        try:
            result = subprocess.run(["hostname", "-f"], capture_output=True, text=True, timeout=3, check=False)
            value = result.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            value = "localhost"
    value = value.strip().rstrip(".")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        labels = value.split(".")
        if (len(value) <= 253 and labels and all(
                re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                for label in labels)):
            return value
        return "localhost"


def run_cmd(cmd, input_text=None):
    """Jalankan perintah tanpa shell; string dipecah menjadi argv, bukan dieksekusi shell."""
    try:
        argv = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
        if not argv:
            return 1, "", "Perintah kosong"
        r = subprocess.run(argv, capture_output=True, text=True, timeout=30,
                           input=input_text, shell=False, check=False)
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
    except (ValueError, TypeError, AttributeError):
        return 0


def safe_username(user):
    return isinstance(user, str) and bool(re.fullmatch(r"[a-zA-Z0-9_-]{3,32}", user))

# ====================== ROOT / PANEL ======================
@app.route(PREFIX)
@app.route(PREFIX + "/")
def panel_root():
    if check_session():
        return redirect_local(f"{PREFIX}/dashboard")
    return redirect_local(f"{PREFIX}/login")

# ====================== LOGIN ======================
@app.route(PREFIX + "/login", method=["GET", "POST"])
def login():
    if check_session():
        return redirect_local(f"{PREFIX}/dashboard")

    error = ""
    if request.method == "POST":
        # Tidak membatasi header Origin; validasi kredensial dan rate limit tetap berlaku.
        username = request.forms.get("username", "").strip()
        password = request.forms.get("password", "")
        ip = request.environ.get("REMOTE_ADDR", "unknown")
        now = time.time()

        # Bersihkan alamat lama agar dictionary tidak tumbuh tanpa batas.
        for stale_ip in [addr for addr, stamps in login_attempts.items()
                         if not any(now - stamp < 600 for stamp in stamps)]:
            login_attempts.pop(stale_ip, None)
        if ip in login_attempts:
            attempts = [t for t in login_attempts[ip] if now - t < 600]
            login_attempts[ip] = attempts
            if len(attempts) >= 5:
                error = "Terlalu banyak percobaan. Coba lagi 10 menit kemudian."
                return template(LOGIN_PAGE, error=error, prefix=PREFIX)
            login_attempts[ip] = attempts
        else:
            login_attempts[ip] = []

        if (len(username) <= 128 and len(password) <= 1024 and
                hmac.compare_digest(username.encode(), ADMIN_USER.encode()) and
                verify_admin_password(password)):
            login_attempts.pop(ip, None)
            sid = create_session()
            response.set_cookie("session_id", sid, httponly=True, secure=COOKIE_SECURE,
                                samesite="Lax", max_age=SESSION_ABSOLUTE_SECONDS, path="/")
            return redirect_local(f"{PREFIX}/dashboard")
        else:
            login_attempts[ip].append(now)
            error = "Username atau Password salah"

    return template(LOGIN_PAGE, error=error, prefix=PREFIX)

@app.route(PREFIX + "/logout", method="POST")
def logout():
    sid = request.get_cookie("session_id")
    if not check_session() or not csrf_valid():
        return redirect_local(f"{PREFIX}/login")
    sessions.pop(sid, None)
    response.delete_cookie("session_id", path="/", secure=COOKIE_SECURE, samesite="Lax")
    return redirect_local(f"{PREFIX}/login")

# ====================== DASHBOARD ======================
@app.route(PREFIX + "/dashboard")
@require_login
def dashboard():
    sid = request.get_cookie("session_id")
    return template(DASHBOARD_PAGE, prefix=PREFIX, csrf=sessions[sid]["csrf"])

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
                    if not safe_username(user):
                        continue
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
                    if not safe_username(user):
                        continue
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
    data = request_data(include_query=True)
    user = (data.get("user") or "").strip()
    if not user:
        return json_response({"ok": False, "msg": "Parameter wajib: user"}, 400)
    if not safe_username(user):
        return json_response({"ok": False, "msg": "Username tidak valid"}, 400)

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
    if not require_auth(mutation=True):
        return json_response({"ok": False, "msg": "Unauthorized"}, 401)

    data = request_data()
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

        code, _, err = run_cmd(["userdel", "-f", user])
        # tetap lanjut hapus db meskipun userdel gagal (mungkin sudah tidak ada)
        run_cmd(f"sed -i '/^### {user} /d' {db}")
        
        for path in (f"/etc/ssh/{user}", f"/var/www/html/ssh-{user}.txt", f"/etc/xray/log-createssh-{user}.log"):
            try:
                os.remove(path)
            except FileNotFoundError:
                pass

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
    if not require_auth(mutation=True):
        return json_response({"ok": False, "msg": "Unauthorized"}, 401)

    data = request_data()
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
        if not 1 <= days <= 3650:
            raise ValueError
    except:
        return json_response({"ok": False, "msg": "expi harus antara 1 dan 3650 hari"}, 400)

    if iplim is not None:
        try:
            iplim = int(iplim)
            if not 0 <= iplim <= 1000:
                raise ValueError
        except (TypeError, ValueError):
            return json_response({"ok": False, "msg": "iplim harus antara 0 dan 1000"}, 400)
    if quota is not None:
        try:
            quota = int(quota)
            if not 0 <= quota <= 1_000_000:
                raise ValueError
        except (TypeError, ValueError):
            return json_response({"ok": False, "msg": "quota harus antara 0 dan 1000000 GB"}, 400)

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

        # Nilai kredensial di DB dipakai dalam ekspresi sed; batasi sebelum digunakan.
        if uuid_or_pass and not re.fullmatch(r"[A-Za-z0-9-]{1,128}", uuid_or_pass):
            return json_response({"ok": False, "msg": "Data akun tersimpan tidak valid"}, 409)

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
    if not require_auth(mutation=True):
        return json_response({"ok": False, "msg": "Unauthorized"}, 401)

    data = request_data()
    user = (data.get("user") or "").strip()
    passwd = (data.get("pass") or data.get("password") or "").strip()
    expired = data.get("expi") or data.get("expired") or data.get("duration")
    iplim = data.get("iplim") or data.get("ip_limit") or "1"

    if not user or not passwd or not expired:
        return json_response({"ok": False, "msg": "Parameter wajib: user, pass, expi"}, 400)
    if len(passwd) > 256 or any(ch in passwd for ch in ("\n", "\r", ":", "\x00")):
        return json_response({"ok": False, "msg": "Password maksimal 256 karakter dan tidak boleh memuat titik dua atau baris baru"}, 400)
    if not safe_username(user):
        return json_response({"ok": False, "msg": "Username tidak valid (3-32, a-zA-Z0-9_-)"}, 400)

    try:
        expired = int(expired)
        iplim = int(iplim)
        if not (1 <= expired <= 3650 and 1 <= iplim <= 1000):
            raise ValueError
    except:
        return json_response({"ok": False, "msg": "expi harus 1-3650 hari dan iplim 1-1000"}, 400)

    if os.path.exists("/etc/ssh/.ssh.db") and f"### {user} " in open("/etc/ssh/.ssh.db").read():
        return json_response({"ok": False, "msg": f"Username {user} sudah digunakan"}, 409)

    if run_cmd(["id", user])[0] == 0:
        return json_response({"ok": False, "msg": f"Username {user} sudah ada di sistem"}, 409)

    exp_date = (datetime.datetime.now() + datetime.timedelta(days=expired)).strftime("%Y-%m-%d")
    exp_full = (datetime.datetime.now() + datetime.timedelta(days=expired)).strftime("%Y-%m-%d %H:%M:%S")

    if run_cmd(["useradd", "-e", exp_date, "-s", "/bin/false", "-M", user])[0] != 0:
        return json_response({"ok": False, "msg": "Gagal membuat user Linux"}, 500)

    if run_cmd(["chpasswd"], input_text=f"{user}:{passwd}\n")[0] != 0:
        run_cmd(["userdel", "-r", user])
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
    with open(f"/var/www/html/ssh-{user}.txt", "w", encoding="utf-8") as f:
        f.write(info)

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
    if not require_auth(mutation=True):
        return json_response({"ok": False, "msg": "Unauthorized"}, 401)

    data = request_data()
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
        if not (1 <= duration <= 3650 and 0 <= quota <= 1_000_000 and 0 <= ip_limit <= 1000):
            raise ValueError
    except:
        return json_response({"ok": False, "msg": "expi harus 1-3650 hari, quota 0-1000000 GB, dan iplim 0-1000"}, 400)

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
    if not require_auth(mutation=True):
        return json_response({"ok": False, "msg": "Unauthorized"}, 401)

    data = request_data()
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
        if not (1 <= duration <= 3650 and 0 <= quota <= 1_000_000 and 0 <= ip_limit <= 1000):
            raise ValueError
    except:
        return json_response({"ok": False, "msg": "expi harus 1-3650 hari, quota 0-1000000 GB, dan iplim 0-1000"}, 400)

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
    if not require_auth(mutation=True):
        return json_response({"ok": False, "msg": "Unauthorized"}, 401)

    data = request_data()
    days = data.get("expi") or data.get("days") or 1
    try:
        days = int(days)
        if not 1 <= days <= 7:
            raise ValueError
    except (TypeError, ValueError):
        return json_response({"ok": False, "msg": "Durasi trial harus 1-7 hari"}, 400)

    proto = proto.lower()
    user = "trial-" + secrets.token_hex(3)

    if proto == "ssh":
        passwd = secrets.token_hex(4)
        # Buat akun trial SSH dengan input internal yang telah divalidasi.
        exp_date = (datetime.datetime.now() + datetime.timedelta(days=days)).strftime("%Y-%m-%d")
        exp_full = (datetime.datetime.now() + datetime.timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        if run_cmd(["useradd", "-e", exp_date, "-s", "/bin/false", "-M", user])[0] != 0:
            return json_response({"ok": False, "msg": "Gagal buat user trial"}, 500)
        run_cmd(["chpasswd"], input_text=f"{user}:{passwd}\n")
        run_cmd(f'passwd -u {user}')
        open(f"/etc/ssh/{user}", "w").write("1")
        with open("/etc/ssh/.ssh.db", "a") as f:
            f.write(f"### {user} {exp_full}\n")
        domain = get_domain()
        info = f"Username : {user}\nPassword : {passwd}\nHost     : {domain}\nExpired  : {exp_full}\n"
        with open(f"/var/www/html/ssh-{user}.txt", "w", encoding="utf-8") as f:
            f.write(info)
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
    code2, en, _ = run_cmd(["systemctl", "is-enabled", unit])
    enabled = en.strip() in ("enabled", "enabled-runtime", "static")
    # uptime-ish: ActiveEnterTimestamp
    _, since, _ = run_cmd(["systemctl", "show", "-p", "ActiveEnterTimestamp", "--value", unit])
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
    _, uptime, _ = run_cmd(["uptime", "-p"])
    if not uptime:
        _, uptime, _ = run_cmd(["uptime"])
    try:
        with open("/proc/loadavg", encoding="utf-8") as f:
            load = " ".join(f.read().split()[:3])
    except OSError:
        load = ""
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
    if not require_auth(mutation=True):
        return json_response({"ok": False, "msg": "Unauthorized"}, 401)
    data = request_data()
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
    if not require_auth(mutation=True):
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
LOGIN_PAGE = r'''
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
.login-toast{position:fixed;z-index:5;top:18px;left:50%;transform:translate(-50%,-12px);opacity:0;visibility:hidden;background:rgba(15,23,42,.96);border:1px solid rgba(34,197,94,.35);color:#bbf7d0;padding:12px 18px;border-radius:13px;box-shadow:0 16px 42px rgba(0,0,0,.38);font-size:.86rem;transition:opacity .22s,transform .22s,visibility .22s}
.login-toast.show{opacity:1;visibility:visible;transform:translate(-50%,0)}
button:focus-visible,input:focus-visible{outline:2px solid #a5b4fc;outline-offset:3px}
button:active{transform:scale(.985)}
button:disabled{opacity:.72;cursor:wait;transform:none}
button.is-loading{display:flex;align-items:center;justify-content:center;gap:10px}
button.is-loading:before{content:"";width:16px;height:16px;border:2px solid rgba(255,255,255,.35);border-top-color:#fff;border-radius:50%;animation:spin .7s linear infinite}
.error{animation:shake .38s ease both}
@keyframes shake{15%,45%,75%{transform:translateX(-5px)}30%,60%,90%{transform:translateX(5px)}}
@keyframes spin{to{transform:rotate(360deg)}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important}}
</style>
</head>
<body>
<div id="login-toast" class="login-toast" role="status" aria-live="polite">Berhasil logout. Sampai jumpa.</div>
<div class="wrap"><div class="card">
<div class="logo">F</div>
<h1>FST Panel</h1>
<p class="sub">Masuk untuk mengelola VPN</p>
% if error:
<div id="login-server-error" class="error" role="alert">{{error}}</div>
% end
<div id="login-client-error" class="error" role="alert" hidden></div>
<form id="login-form" method="POST" action="{{prefix}}/login">
<div class="field"><label>Username</label><input type="text" name="username" required autofocus placeholder="Username admin"></div>
<div class="field"><label>Password</label><input type="password" name="password" required placeholder="••••••••"></div>
<button type="submit" id="login-submit">Masuk</button>
</form>
<p class="foot">Secure session · 12 jam</p>
</div></div>
<script>
(function(){
  var form=document.getElementById("login-form"),button=document.getElementById("login-submit");
  var clientError=document.getElementById("login-client-error");
  function showError(message){
    if(!clientError)return;
    clientError.textContent=message;
    clientError.hidden=!message;
    if(message){clientError.classList.remove("shake");void clientError.offsetWidth;clientError.classList.add("shake");}
  }
  try{
    if(document.getElementById("login-server-error"))sessionStorage.removeItem("fst_login_pending");
    else if(sessionStorage.getItem("fst_login_pending")==="1"){
      sessionStorage.removeItem("fst_login_pending");
      showError("Sesi belum terbentuk setelah login. Coba masuk kembali.");
    }
    if(sessionStorage.getItem("fst_logout_pending")==="1"){
      sessionStorage.removeItem("fst_logout_pending");
      var notice=document.getElementById("login-toast");
      if(notice){notice.classList.add("show");setTimeout(function(){notice.classList.remove("show");},3000);}
    }
  }catch(ignore){}
  if(!form||!button)return;
  form.addEventListener("submit",function(event){
    if(!form.checkValidity())return;
    if(form.dataset.submitting==="1"){event.preventDefault();return;}
    form.dataset.submitting="1";
    showError("");
    try{sessionStorage.setItem("fst_login_pending","1");}catch(ignore){}
    button.disabled=true;button.classList.add("is-loading");button.textContent="Memeriksa...";
    // Default action continues: browser sends the normal POST and follows the server redirect.
  });
  window.addEventListener("pageshow",function(){
    if(form.dataset.submitting==="1"){
      form.dataset.submitting="0";
      button.disabled=false;button.classList.remove("is-loading");button.textContent="Masuk";
    }
  });
})();
</script>
</body>
</html>

'''

DASHBOARD_PAGE = r'''
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
/* Motion and accessible focus */
:focus-visible{outline:2px solid #a5b4fc;outline-offset:3px}
button:active{transform:scale(.975)}
.btn:disabled,.svc-btn:disabled{transform:none;cursor:wait}
.btn.is-loading,.svc-btn.is-loading{display:inline-flex;align-items:center;justify-content:center;gap:8px}
.btn.is-loading:before,.svc-btn.is-loading:before{content:"";width:14px;height:14px;flex:0 0 14px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:sp .7s linear infinite}
.btn-g.is-loading{opacity:.78;pointer-events:none}
.btn-g.is-loading:before{content:"";display:inline-block;width:12px;height:12px;margin-right:7px;border:2px solid rgba(148,163,184,.3);border-top-color:#a5b4fc;border-radius:50%;vertical-align:-2px;animation:sp .7s linear infinite}
.modal-backdrop{position:fixed;inset:0;z-index:200;display:flex;align-items:center;justify-content:center;padding:18px;background:rgba(2,6,15,.72);backdrop-filter:blur(8px);opacity:0;visibility:hidden;transition:opacity .2s ease,visibility .2s ease}
.modal-backdrop.open{opacity:1;visibility:visible}
.modal-card{position:relative;width:min(100%,520px);max-height:min(86vh,760px);overflow:auto;background:linear-gradient(145deg,#151e31,#0d1422);border:1px solid rgba(148,163,184,.18);border-radius:22px;padding:25px;box-shadow:0 28px 90px rgba(0,0,0,.58);transform:translateY(16px) scale(.97);transition:transform .24s cubic-bezier(.2,.8,.2,1)}
.modal-backdrop.open .modal-card{transform:translateY(0) scale(1)}
.modal-close{position:absolute;right:13px;top:12px;width:34px;height:34px;border-radius:10px;border:1px solid var(--border);background:rgba(255,255,255,.04);color:var(--muted);cursor:pointer;font-size:1.2rem}
.modal-title{font-size:1.12rem;letter-spacing:-.02em;margin:0 42px 12px 0}
.modal-body{font-size:.86rem;color:#dbe5f5;line-height:1.65;overflow-wrap:anywhere}
.modal-body .result{display:block;margin-top:0}
.modal-mark{width:42px;height:42px;border-radius:50%;display:grid;place-items:center;margin-bottom:13px;background:rgba(99,102,241,.16);color:#c4b5fd;border:1px solid rgba(99,102,241,.3);font-weight:800;animation:pop .35s cubic-bezier(.2,.8,.2,1)}
.modal-mark.success{background:rgba(34,197,94,.14);color:#86efac;border-color:rgba(34,197,94,.3)}
.modal-mark.danger{background:rgba(239,68,68,.14);color:#fca5a5;border-color:rgba(239,68,68,.3)}
@keyframes pop{from{transform:scale(.55);opacity:.2}to{transform:scale(1);opacity:1}}
.modal-actions{display:flex;justify-content:flex-end;gap:9px;margin-top:20px}
.modal-actions .btn{width:auto;min-width:112px}
.modal-actions .btn-outline{color:var(--text)}
.toast{animation:toast-in .28s cubic-bezier(.2,.8,.2,1)}
@keyframes toast-in{from{opacity:0;transform:translateY(12px) scale(.98)}to{opacity:1;transform:translateY(0) scale(1)}}
@media(max-width:560px){.modal-card{padding:22px 18px;border-radius:18px}.modal-actions{flex-direction:column-reverse}.modal-actions .btn{width:100%}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important;transition-duration:.01ms!important}}

/* Premium midnight + champagne dashboard skin */
:root{--bg:#080b13;--surface:#0d1421;--card:#111a2a;--border:rgba(211,190,145,.13);--text:#f4f0e7;--muted:#9b9a9a;--p:#c6a66d;--p2:#e5d3a6;--ok:#63c79a;--warn:#dbb66c;--danger:#e47a78;--gold:#d8bd83;--gold-bright:#f0dca7}
body{background:radial-gradient(ellipse at 60% -20%,rgba(149,112,63,.16),transparent 45%),radial-gradient(ellipse at 0% 40%,rgba(42,68,109,.2),transparent 42%),#080b13;color:var(--text);font-family:Inter,ui-sans-serif,system-ui,sans-serif}
.glow{background:radial-gradient(ellipse 48% 36% at 82% 2%,rgba(176,137,73,.12),transparent),radial-gradient(ellipse 48% 42% at 5% 90%,rgba(77,91,143,.12),transparent)}
.app{max-width:1380px;padding:24px 28px 58px}
.hdr{min-height:64px;margin-bottom:22px;padding:0 2px 18px;border-bottom:1px solid rgba(211,190,145,.12)}
.brand{gap:13px}.bicon{width:46px;height:46px;border-radius:15px;background:linear-gradient(145deg,#e4d09a,#987643);color:#17140e;box-shadow:0 8px 24px rgba(186,148,79,.2);font-size:1.05rem;letter-spacing:-.04em}
.brand h1{font-size:1.04rem;letter-spacing:.015em}.brand small{font-size:.69rem;color:#a9a59b;letter-spacing:.08em;text-transform:uppercase}
.hdr-right{display:flex;align-items:center;gap:12px}.top-indicator{display:inline-flex;align-items:center;gap:8px;color:#b5b0a4;font-size:.75rem;border:1px solid var(--border);border-radius:999px;padding:8px 12px;background:rgba(255,255,255,.025)}.top-indicator i{width:7px;height:7px;border-radius:50%;background:#65c99b;box-shadow:0 0 12px rgba(101,201,155,.7)}
.btn-g{display:inline-flex;align-items:center;gap:8px;padding:9px 15px;border-radius:11px;border:1px solid rgba(211,190,145,.18);background:rgba(255,255,255,.035);color:#ded8c9}.btn-g:hover{background:rgba(216,189,131,.1);border-color:rgba(216,189,131,.38);color:#fff}
.welcome-banner{position:relative;display:flex;align-items:center;justify-content:space-between;gap:22px;overflow:hidden;margin:4px 0 22px;padding:26px 30px;border:1px solid rgba(216,189,131,.2);border-radius:23px;background:linear-gradient(112deg,rgba(25,33,49,.97),rgba(24,27,37,.95) 57%,rgba(45,38,27,.92));box-shadow:0 18px 48px rgba(0,0,0,.22)}
.welcome-banner:before{content:"";position:absolute;width:290px;height:290px;right:13%;top:-195px;border:1px solid rgba(216,189,131,.16);border-radius:50%;box-shadow:0 0 0 28px rgba(216,189,131,.025),0 0 0 58px rgba(216,189,131,.018)}
.welcome-copy,.server-plaque{position:relative;z-index:1}.eyebrow{display:flex;align-items:center;gap:9px;color:#d3b978;font-size:.65rem;font-weight:700;letter-spacing:.18em;text-transform:uppercase}.eyebrow:before{content:"";width:21px;height:1px;background:#d3b978}
.welcome-banner h2{font-size:1.62rem;letter-spacing:-.045em;margin:9px 0 5px;font-weight:650}.welcome-banner p{max-width:620px;color:#a9abb2;font-size:.84rem}
.server-plaque{display:flex;align-items:center;gap:12px;min-width:190px;padding:12px 15px;border:1px solid rgba(216,189,131,.18);border-radius:14px;background:rgba(4,8,14,.25)}.plaque-icon{width:34px;height:34px;display:grid;place-items:center;border-radius:11px;background:rgba(216,189,131,.12);color:#e2ca8f;font-size:1rem}.server-plaque small{display:block;color:#8f918f;font-size:.62rem;letter-spacing:.14em;text-transform:uppercase}.server-plaque strong{display:block;margin-top:2px;font-size:.78rem;color:#eee4ce;font-weight:600;overflow-wrap:anywhere}
.dash-layout{display:grid;grid-template-columns:238px minmax(0,1fr);align-items:start;gap:20px}.sidebar{position:sticky;top:18px;padding:17px 12px 13px;border:1px solid var(--border);border-radius:20px;background:linear-gradient(160deg,rgba(18,26,40,.96),rgba(12,17,27,.96));box-shadow:0 18px 45px rgba(0,0,0,.18)}
.side-kicker{padding:5px 11px 9px;color:#797e88;font-size:.62rem;font-weight:700;letter-spacing:.17em;text-transform:uppercase}.side-nav{display:grid;gap:5px}.side-link{position:relative;display:flex;align-items:center;gap:11px;width:100%;min-height:53px;padding:8px 10px;border:1px solid transparent;border-radius:13px;background:transparent;color:#a6a9b0;text-align:left;font-family:inherit;cursor:pointer;transition:background .2s,border-color .2s,color .2s,transform .18s}.side-link:hover{background:rgba(255,255,255,.04);border-color:rgba(216,189,131,.1);color:#f4eee1;transform:translateX(2px)}.side-link.active{color:#f7edcf;border-color:rgba(216,189,131,.2);background:linear-gradient(95deg,rgba(216,189,131,.14),rgba(216,189,131,.035));box-shadow:inset 2px 0 #d8bd83}.side-icon{width:32px;height:32px;flex:0 0 32px;display:grid;place-items:center;border-radius:10px;background:rgba(255,255,255,.045);color:#aaa38e;font-size:.94rem}.side-link.active .side-icon{background:linear-gradient(145deg,rgba(216,189,131,.24),rgba(216,189,131,.08));color:#ecd69e}.side-copy{min-width:0;flex:1}.side-copy b{display:block;font-size:.78rem;font-weight:600;line-height:1.25}.side-copy small{display:block;margin-top:3px;color:#7f8490;font-size:.63rem;line-height:1.2}.side-link.active .side-copy small{color:#b4aa90}.side-arrow{color:#807d73;font-size:1.05rem;opacity:0;transform:translateX(-3px);transition:.2s}.side-link:hover .side-arrow,.side-link.active .side-arrow{opacity:1;transform:none}.side-divider{height:1px;margin:13px 8px;background:rgba(211,190,145,.1)}.sidebar-foot{margin:15px 3px 1px;padding:12px 11px;border:1px solid rgba(211,190,145,.1);border-radius:12px;background:rgba(255,255,255,.018);color:#858891;font-size:.66rem;line-height:1.55}.sidebar-foot b{display:block;margin-bottom:2px;color:#c3b896;font-weight:600;letter-spacing:.04em}
.main-column{min-width:0}.stats{grid-template-columns:repeat(4,minmax(0,1fr));gap:11px;margin:0 0 20px}.stat{position:relative;min-height:119px;overflow:hidden;padding:15px 16px;border-radius:16px;border-color:rgba(211,190,145,.12);background:linear-gradient(145deg,rgba(20,29,44,.98),rgba(13,19,30,.98));box-shadow:0 10px 26px rgba(0,0,0,.13)}.stat:after{content:"";position:absolute;right:-29px;bottom:-52px;width:106px;height:106px;border:1px solid rgba(216,189,131,.08);border-radius:50%;box-shadow:0 0 0 15px rgba(216,189,131,.018)}.stat:hover{border-color:rgba(216,189,131,.27);transform:translateY(-2px)}.stat-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}.stat .l{margin:0;color:#9c9b98;font-size:.64rem;letter-spacing:.12em}.stat-icon{display:grid;place-items:center;width:27px;height:27px;border-radius:8px;background:rgba(216,189,131,.1);color:#ddc78f;font-size:.84rem}.stat .v{font-size:1.18rem;font-weight:650;letter-spacing:-.02em;color:#f1ebdf}.stat .v.ok{color:#8de0b4}.stat .v.warn{color:#edcf8b}.stat-note{margin-top:4px;color:#767d88;font-size:.64rem}
.view-heading{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin:8px 2px 15px}.view-kicker{color:#cfb779;font-size:.62rem;font-weight:700;letter-spacing:.17em;text-transform:uppercase}.view-heading h2{margin:4px 0 2px;font-size:1.3rem;font-weight:650;letter-spacing:-.035em}.view-heading p{color:#9095a0;font-size:.78rem}.view-tag{display:inline-flex;align-items:center;gap:7px;padding:7px 10px;border:1px solid rgba(216,189,131,.14);border-radius:999px;background:rgba(216,189,131,.045);color:#c9bd9e;font-size:.66rem;white-space:nowrap}.view-tag span{width:6px;height:6px;border-radius:50%;background:#d8bd83;box-shadow:0 0 9px rgba(216,189,131,.6)}
.protocol-panel{display:flex;align-items:center;justify-content:space-between;gap:16px;margin:0 0 14px;padding:12px 15px;border:1px solid var(--border);border-radius:15px;background:linear-gradient(110deg,rgba(18,26,40,.94),rgba(15,20,30,.94))}.protocol-caption small{display:block;color:#818590;font-size:.59rem;letter-spacing:.15em;text-transform:uppercase}.protocol-caption strong{display:block;margin-top:2px;color:#e4ddcc;font-size:.77rem;font-weight:600}.protos{justify-content:flex-end;margin:0;overflow:visible}.chip{flex:0 0 auto;min-width:70px;padding:8px 13px;border-color:rgba(211,190,145,.1);background:rgba(255,255,255,.025);color:#9296a0;font-size:.72rem}.chip:hover{border-color:rgba(216,189,131,.28);color:#eee4ce}.chip.active{border-color:rgba(216,189,131,.38);background:linear-gradient(135deg,rgba(216,189,131,.2),rgba(216,189,131,.08));color:#f0dca7;box-shadow:inset 0 0 0 1px rgba(216,189,131,.05)}
.panel{padding:24px;border-radius:18px;border-color:rgba(211,190,145,.13);background:linear-gradient(145deg,rgba(18,26,40,.98),rgba(13,19,30,.98));box-shadow:0 15px 38px rgba(0,0,0,.16)}.panel:not(.hidden){animation:lux-in .32s ease both}@keyframes lux-in{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
label{color:#aaa99f;font-size:.72rem;letter-spacing:.025em}input{border-color:rgba(211,190,145,.12);border-radius:11px;background:rgba(6,10,17,.58);color:#f4f0e7}input:focus{border-color:rgba(216,189,131,.5);box-shadow:0 0 0 3px rgba(216,189,131,.1)}input::placeholder{color:#68707d}
.btn{border-radius:11px;background:linear-gradient(135deg,#e3cf99,#b38c4e);color:#1a160e;box-shadow:0 7px 20px rgba(179,140,78,.19);font-weight:700}.btn:hover{box-shadow:0 11px 26px rgba(179,140,78,.28)}.btn-ok{background:linear-gradient(135deg,#6dcc9f,#368c68);color:#06170e;box-shadow:0 7px 19px rgba(75,176,128,.18)}.btn-warn{background:linear-gradient(135deg,#e3c27f,#af8240);color:#1b160b;box-shadow:0 7px 19px rgba(193,151,78,.17)}.btn-danger{background:linear-gradient(135deg,#e9857d,#ac4f4f);color:#fff7f5;box-shadow:0 7px 19px rgba(205,93,86,.17)}.btn-outline{color:#d4c9b2;border-color:rgba(211,190,145,.18)}.btn-outline:hover{background:rgba(216,189,131,.07);border-color:rgba(216,189,131,.36);color:#f2e6c7}
.result{border:1px solid rgba(99,199,154,.16);border-left:3px solid var(--ok);border-radius:13px;background:rgba(8,14,22,.68);color:#e5e5dc}.result.error{border-color:rgba(228,122,120,.2);border-left-color:var(--danger)}.link-box{background:#0b111c;border-color:rgba(211,190,145,.12);border-radius:9px}.copy{background:#1b2431;border-color:rgba(211,190,145,.13);color:#d3c7ac}.copy:hover{background:#263142;color:#fff}.warn-t{padding:10px 12px;border:1px solid rgba(228,122,120,.17);border-radius:10px;background:rgba(228,122,120,.055);color:#e9a09b}.hint{color:#a9a593}.twrap{border-color:rgba(211,190,145,.12);border-radius:13px}table{font-size:.77rem}th{background:#141d2b;color:#a9a493}td{color:#deded9}tr:hover td{background:rgba(216,189,131,.035)}.badge-ok{background:rgba(99,199,154,.13);color:#9ae2bd}.badge-warn{background:rgba(219,182,108,.15);color:#edcf8b}.badge-exp{background:rgba(228,122,120,.14);color:#f0a09d}.act-cek{background:#536d8b}.act-renew{background:#aa8245}.act-del{background:#a34e4e}
.svc-card{border-color:rgba(211,190,145,.1);background:linear-gradient(145deg,rgba(9,15,24,.72),rgba(13,20,31,.84));border-radius:14px}.svc-card:hover{border-color:rgba(216,189,131,.25);transform:translateY(-2px)}.svc-card.up{border-color:rgba(99,199,154,.2)}.svc-card.down{border-color:rgba(228,122,120,.2)}.svc-btn{border-color:rgba(211,190,145,.15);color:#bab5a8;border-radius:9px}.svc-btn:hover{border-color:rgba(216,189,131,.34);background:rgba(216,189,131,.07);color:#f0dca7}.svc-meta code{background:rgba(216,189,131,.08);color:#d2c39e}.group-title{color:#c3b27f;letter-spacing:.14em}.dot.on{box-shadow:0 0 9px rgba(99,199,154,.7)}
.modal-card{border-color:rgba(216,189,131,.22);background:linear-gradient(145deg,#182233,#101722)}.modal-mark{background:rgba(216,189,131,.12);color:#ead49b;border-color:rgba(216,189,131,.26)}.toast{border-color:rgba(216,189,131,.22);background:#172131;color:#f2eee4}
.side-link:focus-visible,.chip:focus-visible,.btn:focus-visible{outline-color:#e3cf99}
@media(max-width:980px){.app{padding:20px 20px 44px}.dash-layout{grid-template-columns:210px minmax(0,1fr);gap:15px}.sidebar{padding:14px 9px}.side-link{gap:8px;padding:8px}.side-copy small{font-size:.6rem}.stats{gap:8px}.stat{padding:13px}}
@media(max-width:820px){.dash-layout{grid-template-columns:minmax(0,1fr)}.sidebar{position:static;padding:12px}.side-kicker{padding-top:3px}.side-nav{grid-template-columns:repeat(3,minmax(0,1fr));gap:6px}.side-divider,.sidebar-foot{display:none}.side-link{min-height:48px}.side-copy small{display:none}.side-arrow{display:none}.main-column{min-width:0}.welcome-banner{padding:23px}}
@media(max-width:620px){.app{padding:14px 12px 36px}.hdr{margin-bottom:15px;padding-bottom:13px}.hdr-right{gap:7px}.top-indicator{display:none}.welcome-banner{display:block;padding:20px 18px;border-radius:18px}.welcome-banner h2{font-size:1.3rem}.welcome-banner p{font-size:.75rem}.server-plaque{min-width:0;width:max-content;max-width:100%;margin-top:14px;padding:8px 10px}.plaque-icon{width:29px;height:29px}.server-plaque small{font-size:.55rem}.server-plaque strong{font-size:.68rem;max-width:none;white-space:normal}.dash-layout{gap:12px}.side-nav{grid-template-columns:repeat(2,minmax(0,1fr))}.side-link{min-height:48px}.side-copy b{font-size:.72rem}.side-icon{width:29px;height:29px;flex-basis:29px}.stats{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin-bottom:16px}.stat{min-height:106px;padding:12px}.stat .v{font-size:1.04rem}.view-heading{align-items:flex-start;margin:4px 1px 12px}.view-heading h2{font-size:1.14rem}.view-heading p{font-size:.71rem}.view-tag{font-size:.59rem;padding:6px 8px}.protocol-panel{display:block;padding:11px;margin-bottom:11px}.protocol-caption{display:flex;align-items:baseline;gap:8px;margin-bottom:9px}.protocol-caption small{font-size:.56rem}.protocol-caption strong{margin:0}.protos{justify-content:flex-start;overflow-x:auto;padding-bottom:2px}.chip{min-width:64px;padding:8px 11px}.panel{padding:17px 14px;border-radius:15px}.svc-head{align-items:flex-start}.svc-actions .btn{margin-bottom:0}.svc-grid{grid-template-columns:1fr}}
@media(prefers-reduced-motion:reduce){.panel:not(.hidden){animation:none}.side-link:hover,.stat:hover,.svc-card:hover{transform:none}}

.logout-form{margin:0}.logout-link{cursor:pointer;font:inherit}.logout-link:disabled{opacity:.65;cursor:wait}.logout-link.is-loading{position:relative;gap:9px}.logout-link.is-loading:before{content:"";width:13px;height:13px;border:2px solid rgba(255,255,255,.3);border-top-color:#e3cf99;border-radius:50%;animation:spin .7s linear infinite}
</style>
</head>
<body>
<div class="glow"></div>
<div class="app">
  <header class="hdr">
    <div class="brand">
      <div class="bicon">F</div>
      <div><h1>FST Panel</h1><small>Private server console</small></div>
    </div>
    <div class="hdr-right"><span class="top-indicator"><i></i> Admin workspace</span><form id="logout-form" class="logout-form" method="POST" action="{{prefix}}/logout"><input type="hidden" name="csrf_token" value="{{csrf}}"><button type="submit" class="btn-g logout-link"><span>↗</span> Logout</button></form></div>
  </header>

  <section class="welcome-banner">
    <div class="welcome-copy"><div class="eyebrow">CONTROL CENTER</div><h2>VPN Control Center</h2><p>Kelola akses, masa aktif, dan layanan server dalam satu ruang kerja.</p></div>
    <div class="server-plaque"><span class="plaque-icon">◆</span><div><small>Server</small><strong id="domain-label">VPN Manager</strong></div></div>
  </section>

  <div class="stats" id="stats-bar">
        <div class="stat"><div class="stat-top"><div class="l">Services online</div><span class="stat-icon">◉</span></div><div class="v" id="st-svc">—</div><div class="stat-note">Kondisi layanan server</div></div>
        <div class="stat"><div class="stat-top"><div class="l">Uptime</div><span class="stat-icon">◷</span></div><div class="v" id="st-up">—</div><div class="stat-note">Waktu server berjalan</div></div>
        <div class="stat"><div class="stat-top"><div class="l">Server load</div><span class="stat-icon">⌁</span></div><div class="v" id="st-load">—</div><div class="stat-note">Rata-rata beban sistem</div></div>
        <div class="stat"><div class="stat-top"><div class="l">Memory</div><span class="stat-icon">▥</span></div><div class="v" id="st-mem">—</div><div class="stat-note">Penggunaan memori</div></div>
      </div>

  <div class="dash-layout">
    <aside class="sidebar" aria-label="Navigasi utama">
      <div class="side-kicker">Akun</div>
      <nav class="side-nav">
        <button class="side-link active" data-menu="create" onclick="showMenu('create', this)"><span class="side-icon">＋</span><span class="side-copy"><b>Buat akun</b><small>Akun VPN baru</small></span><span class="side-arrow">›</span></button>
        <button class="side-link" data-menu="list" onclick="showMenu('list', this)"><span class="side-icon">▤</span><span class="side-copy"><b>Daftar akun</b><small>Lihat dan cek akun</small></span><span class="side-arrow">›</span></button>
        <button class="side-link" data-menu="renew" onclick="showMenu('renew', this)"><span class="side-icon">↻</span><span class="side-copy"><b>Perpanjang</b><small>Tambah masa aktif</small></span><span class="side-arrow">›</span></button>
        <button class="side-link" data-menu="delete" onclick="showMenu('delete', this)"><span class="side-icon">−</span><span class="side-copy"><b>Hapus akun</b><small>Kelola akses akun</small></span><span class="side-arrow">›</span></button>
        <button class="side-link" data-menu="trial" onclick="showMenu('trial', this)"><span class="side-icon">✧</span><span class="side-copy"><b>Akun trial</b><small>Akses sementara</small></span><span class="side-arrow">›</span></button>
      </nav>
      <div class="side-divider"></div>
      <div class="side-kicker">Sistem</div>
      <nav class="side-nav">
        <button class="side-link" data-menu="services" onclick="showMenu('services', this)"><span class="side-icon">⚙</span><span class="side-copy"><b>Service</b><small>Status dan restart</small></span><span class="side-arrow">›</span></button>
      </nav>
      <div class="sidebar-foot"><b>FST • MANAGEMENT</b>Panel administrasi server VPN</div>
    </aside>

    <main class="main-column">
      

      <div class="view-heading"><div><div class="view-kicker" id="view-kicker">ACCOUNT MANAGEMENT</div><h2 id="view-title">Buat akun baru</h2><p id="view-subtitle">Buat kredensial akses baru untuk protokol pilihan.</p></div><div class="view-tag"><span></span> Workspace</div></div>

  <!-- ===== ACCOUNTS ===== -->
  <div id="sec-accounts">
    <div class="protocol-panel"><div class="protocol-caption"><small>Konfigurasi</small><strong>Pilih protokol</strong></div><div class="protos">
      <button class="chip active" onclick="switchProto('ssh', this)">SSH</button>
      <button class="chip" onclick="switchProto('vmess', this)">VMess</button>
      <button class="chip" onclick="switchProto('vless', this)">VLess</button>
      <button class="chip" onclick="switchProto('trojan', this)">Trojan</button>
      <button class="chip" onclick="switchProto('shadowsocks', this)">SS</button>
    </div></div>

    <div id="panel-create" class="panel">
      <form id="form-create" onsubmit="doCreate(event)">
        <div id="ssh-fields">
          <label>Username</label>
          <input type="text" name="user" required placeholder="min. 3 karakter" pattern="[a-zA-Z0-9_-]{3,32}">
          <label>Password</label>
          <input type="password" name="pass" autocomplete="new-password" maxlength="256" required placeholder="Password akun">
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
          <button class="btn btn-sm btn-warn" onclick="restartAllXray(this)">Restart All Xray</button>
        </div>
      </div>
      <div id="svc-grid" class="svc-grid">
        <div class="empty"><span class="spin"></span>Memuat status...</div>
      </div>
    </div>
  </div>
    </main>
  </div>
</div>
<div id="modal-backdrop" class="modal-backdrop" aria-hidden="true">
  <section class="modal-card" role="dialog" aria-modal="true" aria-labelledby="modal-title">
    <button type="button" class="modal-close" id="modal-close" aria-label="Tutup">×</button>
    <h2 id="modal-title" class="modal-title"></h2>
    <div id="modal-body" class="modal-body"></div>
    <div id="modal-actions" class="modal-actions"></div>
  </section>
</div>

<script>
(function(){
"use strict";
var PREFIX = "{{prefix}}";
var CSRF_TOKEN = "{{csrf}}";
var currentProto = "ssh";
var currentAction = "create";
var pendingModalResolve = null;

function $(sel, root){ return (root||document).querySelector(sel); }
function $all(sel, root){ return Array.prototype.slice.call((root||document).querySelectorAll(sel)); }

var viewCopy={
  create:["ACCOUNT MANAGEMENT","Buat akun baru","Buat kredensial akses baru untuk protokol pilihan."],
  list:["ACCOUNT DIRECTORY","Daftar akun","Lihat status, masa aktif, dan detail akun yang tersedia."],
  renew:["ACCOUNT MANAGEMENT","Perpanjang akun","Perbarui masa aktif dan batas akun yang sudah ada."],
  delete:["ACCOUNT MANAGEMENT","Hapus akun","Hapus akses akun yang tidak lagi digunakan."],
  trial:["QUICK ACCESS","Buat akun trial","Buat akses sementara dengan durasi terbatas."],
  services:["SYSTEM OPERATIONS","Status service","Pantau layanan server dan jalankan restart bila diperlukan."]
};
function setActiveMenu(key){
  $all(".side-link").forEach(function(b){b.classList.toggle("active",b.getAttribute("data-menu")===key);});
}
function setView(key){
  var copy=viewCopy[key]||viewCopy.create;
  var kicker=$("#view-kicker"),title=$("#view-title"),subtitle=$("#view-subtitle");
  if(kicker)kicker.textContent=copy[0];
  if(title)title.textContent=copy[1];
  if(subtitle)subtitle.textContent=copy[2];
}
var logoutForm=$("#logout-form");
if(logoutForm)logoutForm.addEventListener("submit",function(event){
  if(logoutForm.dataset.submitting==="1"){event.preventDefault();return;}
  logoutForm.dataset.submitting="1";
  var button=logoutForm.querySelector(".logout-link");
  if(button){button.disabled=true;button.classList.add("is-loading");button.textContent="Keluar...";}
  try{sessionStorage.setItem("fst_logout_pending","1");sessionStorage.removeItem("fst_login_pending");}catch(ignore){}
  // Default action continues: browser sends POST with hidden csrf_token and follows redirect.
});
window.addEventListener("pageshow",function(){
  if(!logoutForm||logoutForm.dataset.submitting!=="1")return;
  logoutForm.dataset.submitting="0";
  var button=logoutForm.querySelector(".logout-link");
  if(button){button.disabled=false;button.classList.remove("is-loading");button.innerHTML="<span>↗</span> Logout";}
});

function showSection(sec){
  var accounts=$("#sec-accounts"),services=$("#sec-services");
  if(accounts)accounts.classList.toggle("hidden",sec!=="accounts");
  if(services)services.classList.toggle("hidden",sec!=="services");
  var key=sec==="services"?"services":currentAction;
  setActiveMenu(key);setView(key);
  if(sec==="services")loadServices();
}
function showMenu(key,el){
  if(key==="services"){showSection("services");return;}
  showSection("accounts");
  switchAction(key,el);
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
  ["create","list","renew","delete","trial"].forEach(function(x){
    var p=$("#panel-"+x);
    if(p)p.classList.toggle("hidden",x!==a);
  });
  setActiveMenu(a);setView(a);
  if(a==="list")loadList();
}

function switchActionByName(a){ showMenu(a); }

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
    headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF_TOKEN },
    credentials: "same-origin",
    body: JSON.stringify(body || {})
  }).then(function(r){ return r.json(); });
}

function escapeHTML(value){
  return String(value == null ? "" : value).replace(/[&<>"']/g, function(ch){
    return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch];
  });
}
function showResult(id, ok, html){
  var el = document.getElementById(id);
  if(!el) return;
  el.className = "result show" + (ok ? "" : " error");
  el.innerHTML = html;
}
function showModal(title, bodyHTML, actionsHTML){
  var back = $("#modal-backdrop");
  $("#modal-title").textContent = title;
  $("#modal-body").innerHTML = bodyHTML;
  $("#modal-actions").innerHTML = actionsHTML || '<button type="button" class="btn" id="modal-ok">Tutup</button>';
  back.classList.add("open"); back.setAttribute("aria-hidden", "false");
  document.body.style.overflow = "hidden";
  var close = function(){ hideModal(); };
  var closeBtn = $("#modal-close"), okBtn = $("#modal-ok");
  if(closeBtn) closeBtn.onclick = close;
  if(okBtn) okBtn.onclick = close;
  setTimeout(function(){ var first = $("#modal-actions button") || closeBtn; if(first) first.focus(); }, 40);
}
function hideModal(){
  var back = $("#modal-backdrop");
  if(!back) return;
  back.classList.remove("open"); back.setAttribute("aria-hidden", "true");
  document.body.style.overflow = "";
  if(pendingModalResolve){ var resolve = pendingModalResolve; pendingModalResolve = null; resolve(false); }
}
function confirmDelete(user, proto){
  return new Promise(function(resolve){
    pendingModalResolve = resolve;
    var safeUser = escapeHTML(user);
    showModal("Konfirmasi hapus akun", '<div class="success-mark" style="background:rgba(239,68,68,.14);border-color:rgba(239,68,68,.3);color:#fca5a5">!</div><p>Yakin ingin menghapus akun <b>' + safeUser + '</b> (' + escapeHTML(proto.toUpperCase()) + ')?</p><p class="warn-t" style="margin:10px 0 0">Tindakan ini permanen dan tidak dapat dibatalkan.</p>', '<button type="button" class="btn btn-outline" id="modal-cancel">Batal</button><button type="button" class="btn btn-danger" id="modal-confirm">Hapus akun</button>');
    $("#modal-cancel").onclick = function(){ hideModal(); };
    $("#modal-confirm").onclick = function(){ pendingModalResolve = null; hideModal(); resolve(true); };
  });
}
document.addEventListener("keydown", function(e){ if(e.key === "Escape") hideModal(); });
document.addEventListener("click", function(e){ if(e.target && e.target.id === "modal-backdrop") hideModal(); });
function setBusy(btn, label, busy){
  if(!btn) return;
  if(busy){ btn.disabled = true; btn.classList.add("is-loading"); btn.dataset.originalText = btn.textContent; btn.textContent = label; }
  else{ btn.disabled = false; btn.classList.remove("is-loading"); btn.textContent = btn.dataset.originalText || label; }
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
    h += '<div class="link-box"><b>' + escapeHTML(label) + '</b><br>' + escapeHTML(val) + '</div>';
    h += '<button type="button" class="copy" data-copy="' + encodeURIComponent(val) + '">Copy ' + escapeHTML(label) + '</button>';
  }
  add("TLS", j.tls);
  add("Non-TLS", j.nontls);
  add("gRPC", j.grpc);
  add("WS", j.ws);
  if(j.link) h += '<br><a href="' + escapeHTML(j.link) + '" target="_blank" rel="noopener noreferrer" style="color:#a5b4fc;font-size:.84rem">Download Config</a>';
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
  setBusy(btn, "Membuat akun...", true);
  var data = currentProto === "ssh"
    ? { user: f.user.value, pass: f.pass.value, expi: f.expi.value, iplim: f.iplim.value }
    : { user: f.user_x.value, expi: f.expi_x.value, quota: f.quota.value, iplim: f.iplim_x.value };
  api(currentProto, data).then(function(j){
    if(j.ok){
      var h = '<div class="success-mark">✓</div><b>Akun berhasil dibuat</b><br><br><b>User:</b> ' + escapeHTML(j.user) + '<br>';
      if(j.pass) h += '<b>Password:</b> ' + escapeHTML(j.pass) + '<br>';
      if(j.uuid) h += '<b>UUID:</b> ' + escapeHTML(j.uuid) + '<br>';
      if(j.password) h += '<b>Password:</b> ' + escapeHTML(j.password) + '<br>';
      if(j.method) h += '<b>Metode:</b> ' + escapeHTML(j.method) + '<br>';
      h += '<b>Kedaluwarsa:</b> ' + escapeHTML(j.expired) + '<br>' + formatLinks(j);
      showResult("result-create", true, h); showModal("Akun siap digunakan", h);
      f.reset();
    } else showResult("result-create", false, escapeHTML(j.msg || "Gagal membuat akun"));
  }).catch(function(err){ showResult("result-create", false, escapeHTML(err.message)); })
    .then(function(){ setBusy(btn, "Buat akun", false); updateCreateForm(); });
}

function loadList(){
  var box = $("#list-content");
  box.innerHTML = '<div class="empty"><span class="spin"></span>Memuat...</div>';
  fetch(PREFIX + "/api/list/" + currentProto, { credentials: "same-origin" })
    .then(function(r){ return r.json(); })
    .then(function(j){
      if(!j.ok){ box.innerHTML = '<div class="empty" style="color:#f87171">' + escapeHTML(j.msg||"Gagal") + '</div>'; return; }
      if(!j.users || !j.users.length){ box.innerHTML = '<div class="empty">Belum ada akun ' + currentProto.toUpperCase() + '</div>'; return; }
      var h = '<div class="twrap"><table><thead><tr><th>User</th><th>Expired</th><th>Sisa</th>';
      if(currentProto !== "ssh") h += "<th>Kuota</th>";
      h += "<th>IP</th><th>Aksi</th></tr></thead><tbody>";
      j.users.forEach(function(u){
        var b = u.days_left > 7 ? "badge-ok" : (u.days_left > 0 ? "badge-warn" : "badge-exp");
        h += "<tr><td><b>" + escapeHTML(u.user) + "</b></td>";
        h += "<td style='color:#8494ad;font-size:.76rem'>" + escapeHTML(u.expired) + "</td>";
        h += "<td><span class='badge " + b + "'>" + escapeHTML(u.days_left) + " hari</span></td>";
        if(currentProto !== "ssh") h += "<td>" + escapeHTML(u.quota_gb||0) + " GB</td>";
        h += "<td>" + escapeHTML(u.ip_limit||"-") + "</td><td class='actions'>";
        h += "<button class='act-cek' data-act='cek' data-user='" + escapeHTML(u.user) + "'>Cek</button>";
        h += "<button class='act-renew' data-act='renew' data-user='" + escapeHTML(u.user) + "'>Renew</button>";
        h += "<button class='act-del' data-act='del' data-user='" + escapeHTML(u.user) + "'>Hapus</button></td></tr>";
      });
      h += "</tbody></table></div>";
      box.innerHTML = h;
    })
    .catch(function(err){
      box.innerHTML = '<div class="empty" style="color:#f87171">' + escapeHTML(err.message) + '</div>';
    });
}

function cekUser(user){
  api("cek/" + currentProto, { user: user }).then(function(j){
    if(j.ok){
      var h = "<b>" + escapeHTML(user) + "</b><br><br><b>Expired:</b> " + escapeHTML(j.expired) + " (" + escapeHTML(j.days_left) + " hari)<br>";
      if(j.uuid) h += "<b>UUID:</b> " + escapeHTML(j.uuid) + "<br>";
      if(j.password) h += "<b>Pass:</b> " + escapeHTML(j.password) + "<br>";
      if(j.quota_gb !== undefined) h += "<b>Kuota:</b> " + escapeHTML(j.quota_gb) + " GB<br>";
      h += "<b>IP:</b> " + escapeHTML(j.ip_limit||"-") + "<br>" + formatLinks(j);
      showResult("result-list", true, h);
    } else showResult("result-list", false, escapeHTML(j.msg||"Gagal"));
  }).catch(function(err){ showResult("result-list", false, escapeHTML(err.message)); });
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
  setBusy(btn, "Memperpanjang...", true);
  var data = { user: f.user.value, expi: f.expi.value };
  if(f.iplim.value) data.iplim = f.iplim.value;
  if(f.quota && f.quota.value !== "") data.quota = f.quota.value;
  api("renew/" + currentProto, data).then(function(j){
    if(j.ok){
      var h = '<div class="success-mark">✓</div><b>Akun berhasil diperpanjang</b><br><br><b>User:</b> ' + escapeHTML(j.user) + '<br><b>Sebelumnya:</b> ' + escapeHTML(j.old_expired) + '<br><b>Sekarang:</b> ' + escapeHTML(j.expired) + '<br><b>+' + escapeHTML(j.days_added) + ' hari</b>';
      showResult("result-renew", true, h); showModal("Perpanjangan berhasil", h);
    } else showResult("result-renew", false, escapeHTML(j.msg||"Gagal"));
  }).catch(function(err){ showResult("result-renew", false, escapeHTML(err.message)); })
    .then(function(){ setBusy(btn, "Perpanjang", false); });
}

function doDelete(e){
  e.preventDefault();
  var f = e.target, user = f.user.value, btn = f.querySelector("button");
  confirmDelete(user, currentProto).then(function(confirmed){
    if(!confirmed) return;
    setBusy(btn, "Menghapus...", true);
    api("del/" + currentProto, { user: user }).then(function(j){
      if(j.ok){
        var h = '<div class="success-mark">✓</div><b>Akun berhasil dihapus</b><br><br>' + escapeHTML(j.msg);
        showResult("result-delete", true, h); showModal("Penghapusan selesai", h); f.user.value = "";
      } else showResult("result-delete", false, escapeHTML(j.msg||"Gagal"));
    }).catch(function(err){ showResult("result-delete", false, escapeHTML(err.message)); })
      .then(function(){ setBusy(btn, "Hapus Akun", false); });
  });
}

function doTrial(e){
  e.preventDefault();
  var f = e.target, btn = f.querySelector("button");
  setBusy(btn, "Membuat trial...", true);
  api("trial/" + currentProto, { expi: f.expi.value }).then(function(j){
    if(j.ok){
      var h = '<div class="success-mark">✓</div><b>Akun trial berhasil dibuat</b><br><br><b>User:</b> ' + escapeHTML(j.user) + '<br>';
      if(j.pass) h += '<b>Password:</b> ' + escapeHTML(j.pass) + '<br>';
      if(j.uuid) h += '<b>UUID:</b> ' + escapeHTML(j.uuid) + '<br>';
      if(j.password) h += '<b>Password:</b> ' + escapeHTML(j.password) + '<br>';
      h += '<b>Kedaluwarsa:</b> ' + escapeHTML(j.expired) + '<br>' + formatLinks(j);
      showResult("result-trial", true, h); showModal("Trial siap digunakan", h);
    } else showResult("result-trial", false, escapeHTML(j.msg||"Gagal"));
  }).catch(function(err){ showResult("result-trial", false, escapeHTML(err.message)); })
    .then(function(){ setBusy(btn, "Buat Trial", false); });
}

function loadServices(){
  var grid = $("#svc-grid");
  if(!grid) return;
  fetch(PREFIX + "/api/services", { credentials: "same-origin" })
    .then(function(r){ return r.json(); })
    .then(function(j){
      if(!j.ok){ grid.innerHTML = '<div class="empty">' + escapeHTML(j.msg||"Gagal") + '</div>'; return; }
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
      if(grid) grid.innerHTML = '<div class="empty" style="color:#f87171">' + escapeHTML(err.message) + '</div>';
    });
}

function svcCard(s){
  var on = s.active;
  return '<div class="svc-card ' + (on?'up':'down') + '">' +
    '<div class="svc-top"><div class="svc-name"><span class="dot ' + (on?'on':'off') + '"></span>' + escapeHTML(s.name) + '</div>' +
    '<span class="badge ' + (on?'badge-ok':'badge-exp') + '">' + (on?'Active':'Down') + '</span></div>' +
    '<div class="svc-meta"><code>' + escapeHTML(s.unit) + '</code> · ' + escapeHTML(s.status||'?') + '</div>' +
    '<button class="svc-btn" data-act="restart" data-unit="' + escapeHTML(s.unit) + '">Restart</button></div>';
}

function restartSvc(unit, btn){
  if(btn){ btn.disabled = true; btn.classList.add("is-loading"); btn.textContent = "Restarting..."; }
  api("services/restart", { unit: unit }).then(function(j){
    if(j.ok){ showModal("Service berhasil di-restart", '<div class="success-mark">✓</div><p>' + escapeHTML(unit) + ' berhasil dimulai ulang.</p>'); setTimeout(loadServices, 800); }
    else toast(j.msg||"Gagal restart", false);
  }).catch(function(err){ toast(err.message, false); })
  .then(function(){ if(btn){ btn.disabled = false; btn.classList.remove("is-loading"); btn.textContent = "Restart"; } });
}

function restartAllXray(btn){
  showModal("Restart semua service Xray?", '<p>Semua layanan VMess, VLess, Trojan, dan Shadowsocks akan dimulai ulang.</p><p class="hint" style="margin:10px 0 0">Koneksi aktif dapat terputus sebentar.</p>', '<button type="button" class="btn btn-outline" id="modal-cancel">Batal</button><button type="button" class="btn btn-warn" id="modal-confirm">Restart semua</button>');
  $("#modal-cancel").onclick = hideModal;
  $("#modal-confirm").onclick = function(){
    hideModal(); setBusy(btn, "Restarting...", true);
    api("services/restart-all", {}).then(function(j){
      if(j.ok){ showModal("Restart berhasil", '<div class="success-mark">✓</div><p>Semua service Xray berhasil dimulai ulang.</p>'); setTimeout(loadServices, 1000); }
      else toast(j.msg||"Gagal", false);
    }).catch(function(err){ toast(err.message, false); })
      .then(function(){ setBusy(btn, "Restart All Xray", false); });
  };
}

// Wire onclick from HTML attributes that pass this
window.showSection = showSection;
window.showMenu = showMenu;
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
try{
  if(sessionStorage.getItem("fst_login_pending")==="1"){
    sessionStorage.removeItem("fst_login_pending");
    setTimeout(function(){showModal("Berhasil masuk", '<div class="success-mark">✓</div><p>Selamat datang di FST Panel.</p>');},120);
  }
}catch(ignore){}
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
    print(f"FST Panel listening on 0.0.0.0:{PORT}")
    print(f"Akses melalui reverse proxy HTTPS: https://domain{PREFIX}")
    print("API endpoints:")
    print("  POST /panel/api/ssh|vmess|vless|trojan|shadowsocks  → buat")
    print("  GET/POST /panel/api/list/<proto>                    → list")
    print("  POST /panel/api/cek/<proto>  {user}                 → detail")
    print("  POST /panel/api/renew/<proto> {user,expi,...}       → perpanjang")
    print("  POST /panel/api/del/<proto>  {user}                 → hapus")
    print("  POST /panel/api/trial/<proto> {expi}                → trial")
    app.run(host="0.0.0.0", port=PORT, quiet=True)
