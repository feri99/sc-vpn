#!/usr/bin/env bash
# Safely enable DHCPv4 on the user-confirmed SDN NIC and configure the existing
# public/SDN route preference and public-source reply policy. No cloud/API/GitHub
# operations are performed.
set -Eeuo pipefail

VERSION="1.0"
SDN_IF="eth3"
SDN_MAC="c6:04:60:63:9d:b0"
SDN_CIDR="192.168.10.0/24"
PUBLIC_METRIC=200
SDN_METRIC=50
TABLE=1001
ROLLBACK_SECONDS=120
SDN_ID="upcloud_sdn_eth3"
TARGET="/etc/netplan/99-upcloud-sdn-eth3-routing.yaml"
SCRIPT_PATH="$(readlink -f "$0")"

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<EOF
$0 v$VERSION — enable DHCPv4 on the confirmed SDN NIC and configure routing.

Normal run (interactive; exactly one yes/no prompt before changes):
  sudo bash $0

Read-only checks only (does not request DHCP or alter networking):
  sudo bash $0 --dry-run

After a successful apply, keep the change only if connectivity and routes look
healthy by running the printed --commit command within $ROLLBACK_SECONDS seconds.
Otherwise the script automatically removes its Netplan overlay and reapplies
prior Netplan settings. This is a commit command, not another yes/no prompt.

Fixed, verified target: $SDN_IF, MAC $SDN_MAC. The script does not scan for or
substitute another interface/MAC, does not assume DHCP will provide a lease or
gateway, and does not connect to a VPS, call a cloud API, or publish anything.
EOF
}

commit_rollback() {
  local unit="${2:-}" marker lock
  [[ "$#" -eq 2 && "$1" == "--commit" ]] || fail "Usage: $SCRIPT_PATH --commit <rollback-unit>"
  [[ "$unit" =~ ^route-yes-no-sdn-eth3-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || fail "Invalid rollback unit name. Use the exact command printed by the successful run."
  [[ "$EUID" -eq 0 ]] || fail "Run the commit command with sudo/root."
  command -v flock >/dev/null 2>&1 || fail "flock is required to safely cancel the rollback."
  command -v systemctl >/dev/null 2>&1 || fail "systemctl is required to cancel the rollback."
  marker="/run/${unit}.committed"
  lock="/run/${unit}.lock"
  exec 9>"$lock"
  flock -x 9
  [[ -e "$TARGET" ]] || fail "The Netplan overlay is no longer present; it may already have rolled back."
  # The rollback job uses the same lock and checks this marker before acting.
  # This ordering safely handles the timer firing at the same moment as commit.
  : >"$marker"
  if systemctl stop "${unit}.timer"; then
    printf 'Rollback canceled. The current Netplan configuration is kept.\n'
  else
    printf 'Commit marker written. The rollback job will see it and leave the configuration unchanged.\n' >&2
  fi
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then usage; exit 0; fi
if [[ "${1:-}" == "--commit" ]]; then commit_rollback "$@"; exit 0; fi
DRY_RUN=0
if [[ "${1:-}" == "--dry-run" && "$#" -eq 1 ]]; then DRY_RUN=1
elif [[ "$#" -gt 0 ]]; then fail "Unknown argument: $1 (use --help)."
fi

[[ "$EUID" -eq 0 ]] || fail "Jalankan di VPS dengan sudo/root."
for cmd in ip netplan python3 systemd-run systemctl flock tar install cp mktemp date readlink ln mkdir rm chmod cat; do
  command -v "$cmd" >/dev/null 2>&1 || fail "Perintah '$cmd' diperlukan. Belum ada perubahan dibuat."
done
python3 -c 'import yaml' >/dev/null 2>&1 || fail "PyYAML diperlukan (paket Ubuntu: python3-yaml). Belum ada perubahan dibuat."

# Confirm temporary rollback support and staged Netplan validation before asking.
NETPLAN_HELP="$(netplan generate --help 2>&1 || true)"
[[ "$NETPLAN_HELP" == *"--root-dir"* ]] || fail "Versi Netplan harus mendukung 'generate --root-dir' untuk memvalidasi konfigurasi sebelum menulis ke /etc/netplan. Belum ada perubahan dibuat."
systemctl show-environment >/dev/null 2>&1 || fail "systemd manager tidak dapat diakses untuk memasang rollback 120 detik. Belum ada perubahan dibuat."
[[ -d /etc/netplan && -w /etc/netplan && -w /root && -w /run ]] || fail "Direktori Netplan, /root, atau /run tidak dapat ditulis. Belum ada perubahan dibuat."
[[ ! -e "$TARGET" ]] || fail "$TARGET sudah ada; skrip tidak akan menimpa konfigurasi yang ada. Belum ada perubahan dibuat."

# Read-only detection. The same checks are repeated after DHCP succeeds, so
# dynamic values and any route/rule changes are validated before persistent writes.
detect() {
  local mode="$1"
  python3 - "$mode" "$SDN_IF" "$SDN_MAC" "$SDN_CIDR" "$SDN_ID" "$TABLE" <<'PY'
import fnmatch, ipaddress, json, re, subprocess, sys

mode, sdn_if, confirmed_mac, sdn_cidr_s, sdn_id, table_s = sys.argv[1:]

def die(msg):
    print("ERROR: " + msg, file=sys.stderr)
    raise SystemExit(1)

def run_json(args, allow_missing_table=False):
    try:
        p = subprocess.run(args, text=True, capture_output=True, check=True)
        return json.loads(p.stdout or "[]")
    except subprocess.CalledProcessError as e:
        text = (e.stderr or "").replace("\r\n", "\n").strip().splitlines()
        if allow_missing_table and text == [
            "Error: ipv4: FIB table does not exist.", "Dump terminated"
        ]:
            return []
        die("Tidak dapat memeriksa " + " ".join(args) + ": " + (e.stderr or str(e)).strip())
    except json.JSONDecodeError as e:
        die("Output JSON tidak valid dari " + " ".join(args) + ": " + str(e))

def normalize_mac(value):
    if not isinstance(value, str):
        return None
    compact = value.strip().lower().replace(":", "").replace("-", "").replace(".", "")
    if len(compact) != 12 or any(c not in "0123456789abcdef" for c in compact):
        return None
    return ":".join(compact[i:i+2] for i in range(0, 12, 2))

try:
    sdn_net = ipaddress.ip_network(sdn_cidr_s, strict=True)
except ValueError as e:
    die("CIDR SDN internal tidak valid: " + str(e))

try:
    netplan_text = subprocess.run(["netplan", "get"], text=True, capture_output=True, check=True).stdout
    import yaml
    effective = yaml.safe_load(netplan_text) or {}
except subprocess.CalledProcessError as e:
    die("netplan get gagal: " + (e.stderr or "").strip())
except Exception as e:
    die("Tidak dapat membaca konfigurasi Netplan efektif: " + str(e))
network = effective.get("network", effective) if isinstance(effective, dict) else {}
ethernets = network.get("ethernets") or {}
if not isinstance(ethernets, dict) or not ethernets:
    die("Tidak ditemukan definisi ethernet Netplan efektif.")

addr_data = run_json(["ip", "-j", "-4", "addr", "show"])
route_data = run_json(["ip", "-j", "-4", "route", "show", "default"])
rule_data = run_json(["ip", "-j", "-4", "rule", "show"])
link_data = run_json(["ip", "-j", "link", "show"])
sdn_routes = run_json(["ip", "-j", "-4", "route", "show", "dev", sdn_if])

links = {item.get("ifname"): item for item in link_data if item.get("ifname")}
if sdn_if not in links:
    die(f"Interface terkonfirmasi {sdn_if} tidak ditemukan; tidak mencari interface pengganti.")
actual_mac = normalize_mac(links[sdn_if].get("address"))
if actual_mac != normalize_mac(confirmed_mac):
    die(f"MAC {sdn_if} tidak cocok dengan nilai terkonfirmasi {confirmed_mac}; tidak ada perubahan dibuat.")
sdn_was_up = int("UP" in (links[sdn_if].get("flags") or []))

addresses = {}
for item in addr_data:
    name = item.get("ifname")
    if name:
        addresses[name] = []
        for info in item.get("addr_info", []):
            if info.get("family") == "inet":
                try:
                    ip = ipaddress.IPv4Address(info["local"])
                    addresses[name].append({"ip": str(ip), "prefix": int(info.get("prefixlen", 0)), "global": ip.is_global})
                except (KeyError, ValueError, TypeError):
                    pass

# Map interfaces only through selectors the script can verify exactly.
def map_netplan_id(ifname, allow_new=False):
    matches, uncertain, mac_claim = [], [], False
    live_mac = normalize_mac(links.get(ifname, {}).get("address"))
    for nid, cfg in ethernets.items():
        if not isinstance(cfg, dict):
            uncertain.append(nid); continue
        selector = cfg.get("match") or {}
        if not isinstance(selector, dict):
            uncertain.append(nid); continue
        if any(key not in ("name", "macaddress") for key in selector):
            uncertain.append(nid); continue
        matched = True
        if "name" in selector:
            patterns = selector["name"]
            if isinstance(patterns, str): patterns = [patterns]
            if not isinstance(patterns, list) or not patterns or any(not isinstance(p, str) for p in patterns):
                uncertain.append(nid); continue
            matched = any(fnmatch.fnmatchcase(ifname, p) for p in patterns)
        if "macaddress" in selector:
            expected = normalize_mac(selector.get("macaddress"))
            if expected == live_mac and live_mac:
                mac_claim = True
            if expected is None:
                uncertain.append(nid); continue
            matched = matched and bool(live_mac and expected == live_mac)
        if not selector:
            matched = (nid == ifname or cfg.get("set-name") == ifname)
        if matched:
            matches.append((nid, cfg))
    if len(matches) > 1:
        die(f"{ifname} cocok dengan beberapa definisi Netplan; menolak perubahan ambigu.")
    if matches:
        return matches[0]
    if uncertain:
        die(f"Ada selector Netplan yang tidak dapat diverifikasi ({', '.join(uncertain)}); tidak aman memastikan pemetaan {ifname}.")
    if allow_new and mac_claim:
        die(f"MAC {live_mac} sudah diklaim selector Netplan yang tidak cocok unik dengan {ifname}.")
    return None

sdn_mapping = map_netplan_id(sdn_if, allow_new=True)
if sdn_mapping:
    sdn_id, sdn_cfg = sdn_mapping
    sdn_new = 0
    if re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", sdn_id) is None:
        die(f"ID Netplan SDN tidak aman untuk YAML: {sdn_id!r}")
    if sdn_cfg.get("addresses"):
        die(f"Stanza Netplan {sdn_id} memiliki alamat IPv4 statis; skrip tidak akan mencampur DHCP dengan alamat statis.")
    sdn_overrides = sdn_cfg.get("dhcp4-overrides") or {}
    if not isinstance(sdn_overrides, dict):
        die(f"dhcp4-overrides pada stanza {sdn_id} bukan mapping yang dapat diverifikasi.")
    if sdn_overrides.get("use-routes") is False:
        die(f"Stanza Netplan {sdn_id} menonaktifkan rute DHCP; gateway SDN tidak dapat dipastikan.")
    for route in sdn_cfg.get("routes") or []:
        if isinstance(route, dict) and route.get("to") in ("default", "0.0.0.0/0"):
            die(f"Stanza Netplan {sdn_id} sudah memiliki default route statis; menolak menebak perilaku rutenya.")
else:
    sdn_new = 1
    if sdn_id in ethernets:
        die(f"Netplan ID {sdn_id} sudah digunakan; menolak menimpa atau menebak ID lain.")

sdn_leased = [a for a in addresses.get(sdn_if, []) if ipaddress.IPv4Address(a["ip"]) in sdn_net]
sdn_defaults, sdn_dhcp_defaults = [], []
for route in route_data + sdn_routes:
    if route.get("dst") == "default" and route.get("dev") == sdn_if:
        gw = route.get("gateway") or route.get("via")
        if gw:
            try:
                normalized_gw = str(ipaddress.IPv4Address(gw))
                sdn_defaults.append(normalized_gw)
                if (route.get("protocol") or route.get("proto")) == "dhcp":
                    sdn_dhcp_defaults.append(normalized_gw)
            except ValueError:
                pass
sdn_defaults = sorted(set(sdn_defaults))
sdn_dhcp_defaults = sorted(set(sdn_dhcp_defaults))
sdn_recovery = 0

# Preserve the normal route-detection path whenever a valid SDN DHCP lease is
# already live. Recovery is only for the exact clean state: no stanza, no IPv4,
# and no IPv4 route on the confirmed SDN NIC.
if mode == "static":
    if not sdn_new:
        if sdn_mapping[1].get("dhcp4") is not True:
            die(f"Stanza Netplan {sdn_id} belum mengaktifkan dhcp4: true; perbaiki stanza tersebut secara eksplisit sebelum melanjutkan.")
        if len(sdn_leased) != 1 or len(sdn_defaults) != 1:
            die(f"Stanza Netplan {sdn_id} sudah ada, tetapi belum ada satu lease DHCPv4/gateway valid pada {sdn_if}; aktifkan DHCP dengan Netplan terlebih dahulu. Tidak ada perubahan dibuat.")
        if ipaddress.IPv4Address(sdn_defaults[0]) not in sdn_net:
            die(f"Gateway SDN aktif {sdn_defaults[0]} berada di luar {sdn_net}; tidak ada perubahan dibuat.")
    elif not addresses.get(sdn_if) and not sdn_routes and not any(r.get("dev") == sdn_if for r in route_data):
        sdn_recovery = 1
    elif len(sdn_leased) == 1 and len(sdn_defaults) == 1 and len(sdn_dhcp_defaults) == 1:
        if ipaddress.IPv4Address(sdn_defaults[0]) not in sdn_net:
            die(f"Gateway SDN aktif {sdn_defaults[0]} berada di luar {sdn_net}; tidak ada perubahan dibuat.")
    else:
        die(f"{sdn_if} tanpa stanza mempunyai state IPv4/rute parsial atau tidak valid; pemulihan otomatis tidak dijalankan agar konfigurasi normal tidak terganggu.")
elif mode == "lease":
    leased = sdn_leased
    if len(leased) != 1:
        die(f"DHCP tidak menghasilkan tepat satu alamat IPv4 pada {sdn_if} di dalam {sdn_net}; tidak ada Netplan persisten ditulis.")
    if len(sdn_defaults) != 1:
        die(f"DHCP tidak memberikan satu gateway IPv4 yang bisa diverifikasi pada {sdn_if}; gateway yang diamati: {', '.join(sdn_defaults) if sdn_defaults else '(tidak ada)'}. Tidak ada Netplan persisten ditulis.")
    sdn_gw = sdn_defaults[0]
    if ipaddress.IPv4Address(sdn_gw) not in sdn_net:
        die(f"Gateway DHCP {sdn_gw} berada di luar jaringan SDN {sdn_net}; tidak ada Netplan persisten ditulis.")
else:
    die("Mode deteksi internal tidak dikenal.")

# Determine the public IPv4 interface from live public address + default route.
defaults_by_if = {}
for route in route_data:
    if route.get("dst") != "default": continue
    dev, gw = route.get("dev"), route.get("gateway") or route.get("via")
    if dev and gw:
        try: gw = str(ipaddress.IPv4Address(gw))
        except ValueError: continue
        defaults_by_if.setdefault(dev, set()).add(gw)
public_candidates = sorted(
    name for name, vals in addresses.items()
    if any(a["global"] for a in vals) and defaults_by_if.get(name)
)
if len(public_candidates) != 1:
    die("Tidak bisa menentukan satu NIC publik secara unik; kandidat: " + (", ".join(public_candidates) if public_candidates else "(tidak ada)"))
pub_if = public_candidates[0]
pub_addresses = [a for a in addresses[pub_if] if a["global"]]
if len(pub_addresses) != 1:
    die(f"Diharapkan tepat satu IPv4 publik pada {pub_if}; ditemukan {len(pub_addresses)}.")
if len(defaults_by_if[pub_if]) != 1:
    die(f"Diharapkan tepat satu gateway IPv4 pada {pub_if}; ditemukan beberapa/tidak ada.")
pub_ip = pub_addresses[0]["ip"]
pub_prefix = pub_addresses[0]["prefix"]
pub_gw = next(iter(defaults_by_if[pub_if]))
public_mapping = map_netplan_id(pub_if)
if not public_mapping:
    die(f"NIC publik {pub_if} tidak cocok dengan satu definisi Netplan yang dapat diverifikasi.")
pub_id, pub_cfg = public_mapping
if re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", pub_id) is None:
    die(f"ID Netplan publik tidak aman untuk YAML: {pub_id!r}")
if pub_cfg.get("dhcp4") is not True:
    die(f"Definisi Netplan {pub_id} untuk NIC publik tidak memakai dhcp4: true.")
overrides = pub_cfg.get("dhcp4-overrides") or {}
if isinstance(overrides, dict) and overrides.get("use-routes") is False:
    die(f"Definisi Netplan {pub_id} menonaktifkan rute DHCP; menolak mengubah perilaku rute.")
for route in pub_cfg.get("routes") or []:
    if isinstance(route, dict) and route.get("to") in ("default", "0.0.0.0/0"):
        die(f"Definisi Netplan {pub_id} sudah berisi default route statis; menolak menebak prioritas.")

try: table = int(table_s)
except ValueError: die("Nomor routing table internal tidak valid.")
for route in run_json(["ip", "-j", "-4", "route", "show", "table", str(table)], allow_missing_table=True):
    if route.get("dst") == "default":
        die(f"Routing table {table} sudah memiliki default route; tidak akan ditimpa.")
used = set()
for rule in rule_data:
    try: used.add(int(rule.get("priority")))
    except (TypeError, ValueError): pass
priority = next((p for p in range(10000, 11000) if p not in used), None)
if priority is None:
    die("Tidak ada policy-rule priority kosong di 10000..10999.")
for rule in rule_data:
    src = rule.get("from")
    if src and src not in ("all", "0.0.0.0/0"):
        try:
            if ipaddress.IPv4Address(pub_ip) in ipaddress.ip_network(src, strict=False):
                die(f"Aturan policy IPv4 yang ada sudah mencocokkan alamat publik {pub_ip}; periksa aturan sebelum melanjutkan.")
        except ValueError:
            pass

result = {
    "public_if": pub_if, "public_id": pub_id, "public_ip": pub_ip,
    "public_prefix": pub_prefix, "public_gw": pub_gw,
    "sdn_if": sdn_if, "sdn_mac": normalize_mac(confirmed_mac),
    "sdn_was_up": sdn_was_up, "sdn_id": sdn_id, "sdn_new": sdn_new, "sdn_recovery": sdn_recovery,
    "sdn_cidr": str(sdn_net), "table": table, "priority": priority
}
if mode == "lease":
    result.update({"sdn_ip": leased[0]["ip"], "sdn_prefix": leased[0]["prefix"], "sdn_gw": sdn_gw})
print(json.dumps(result))
PY
}

DETECTION_JSON="$(detect static)" || fail "Pra-pemeriksaan read-only gagal; tidak ada file atau pengaturan jaringan yang diubah."
read_value() { python3 - "$DETECTION_JSON" "$1" <<'PY'
import json, sys
print(json.loads(sys.argv[1])[sys.argv[2]])
PY
}
PUB_IF="$(read_value public_if)"
PUB_ID="$(read_value public_id)"
PUB_IP="$(read_value public_ip)"
PUB_PREFIX="$(read_value public_prefix)"
PUB_GW="$(read_value public_gw)"
SDN_WAS_UP="$(read_value sdn_was_up)"
SDN_ID="$(read_value sdn_id)"
SDN_NEW="$(read_value sdn_new)"
SDN_RECOVERY="$(read_value sdn_recovery)"
PRIORITY="$(read_value priority)"

printf 'Pra-pemeriksaan read-only lulus.\n'
printf '  Publik: %s (%s/%s), gateway teramati %s\n' "$PUB_IF" "$PUB_IP" "$PUB_PREFIX" "$PUB_GW"
if [[ "$SDN_NEW" == "1" ]]; then
  if [[ "$SDN_RECOVERY" == "1" ]]; then
    printf '  SDN:    deteksi normal gagal karena stanza/alamat/rute belum ada; recovery terbatas ke %s / %s.\n' "$SDN_IF" "$SDN_MAC"
  else
    printf '  SDN:    lease normal sudah valid; stanza exact-MAC akan ditambahkan seperti jalur normal, tanpa recovery DHCP.\n'
  fi
else
  printf '  SDN:    stanza Netplan %s yang cocok akan dipakai ulang untuk %s, MAC %s.\n' "$SDN_ID" "$SDN_IF" "$SDN_MAC"
fi
printf '  Rute yang direncanakan: metrik SDN %s, metrik publik %s; balasan dari %s memakai tabel %s (prioritas policy %s).\n' "$SDN_METRIC" "$PUBLIC_METRIC" "$PUB_IP" "$TABLE" "$PRIORITY"
printf '  Alamat dan gateway SDN hanya diterima dari lease DHCPv4 live yang lolos validasi.\n'
if (( DRY_RUN )); then
  printf '\nDry-run: tidak meminta DHCP, tidak mengubah link, file, atau konfigurasi jaringan.\n'
  exit 0
fi
if [[ "$SDN_RECOVERY" == "1" ]] && ! command -v dhclient >/dev/null 2>&1; then
  fail "Jalur otomatis memerlukan dhclient (paket Ubuntu: isc-dhcp-client) untuk meminta lease tanpa menulis konfigurasi persisten. Pasang paket itu lalu jalankan ulang; belum ada perubahan dibuat."
fi

[[ -t 0 && -t 1 ]] || fail "Terminal interaktif diperlukan untuk satu konfirmasi yes/no. Jalankan --dry-run untuk pemeriksaan baca-saja."
if [[ "$SDN_RECOVERY" == "1" ]]; then
  DHCP_PLAN="Hanya karena deteksi normal gagal dan eth3 bersih tanpa stanza/alamat/rute, setelah yes skrip akan meminta lease DHCPv4 lalu membuat stanza exact-MAC setelah lease tervalidasi."
elif [[ "$SDN_NEW" == "1" ]]; then
  DHCP_PLAN="Deteksi normal sudah menemukan lease SDN valid; recovery DHCP tidak dijalankan, dan stanza exact-MAC ditambahkan seperti jalur normal."
else
  DHCP_PLAN="Stanza exact-MAC yang sudah ada akan dipakai ulang; skrip tidak menjalankan klien DHCP kedua dan hanya melanjutkan bila lease live masih valid."
fi
cat <<EOF

Konfirmasi tunggal sebelum perubahan:
Jika menjawab yes, skrip memastikan DHCPv4 hanya pada $SDN_IF (MAC $SDN_MAC).
$DHCP_PLAN Skrip lalu memeriksa alamat/gateway yang benar-benar diberikan dan
menerapkan rute yang mengutamakan egress SDN serta mempertahankan
balasan koneksi masuk melalui NIC publik. Nilai gateway tidak ditebak. Jika lease
atau validasi gagal, konfigurasi persisten dipulihkan/tetap tidak berubah. Timer
rollback $ROLLBACK_SECONDS detik dipasang tepat sebelum apply, sehingga waktu
apply memakai sebagian jendelanya; jalankan perintah --commit yang ditampilkan
untuk mempertahankan perubahan. Perubahan rute dapat memutus sesi
SSH; gunakan akses konsol/recovery bila tersedia.

Lanjutkan? (yes/no): 
EOF
IFS= read -r RESPONSE || fail "Tidak dapat membaca jawaban; belum ada perubahan dibuat."
case "$RESPONSE" in
  yes) printf 'Persetujuan diterima; menjalankan DHCP, validasi, dan penerapan dalam proses ini.\n' ;;
  no) printf 'Dibatalkan; tidak ada file atau pengaturan jaringan yang diubah.\n'; exit 0 ;;
  *) fail "Jawab tepat yes atau no; tidak ada perubahan dibuat." ;;
esac

RUNTIME_DIR=""
TMP_YAML=""
TARGET_TMP=""
BACKUP=""
LEASE_STARTED=0
RECOVERY_USED=0
if [[ "$SDN_RECOVERY" == "1" ]]; then RECOVERY_USED=1; fi
CONFIG_INSTALLED=0
ROLLBACK_ARMED=0
SUCCESS=0
KEEP_SDN=0
ROLLBACK_UNIT=""
ROLLBACK_SCRIPT=""
ROLLBACK_MARKER=""
ROLLBACK_LOCK=""

restore_temporary_network() {
  local pid=""
  if [[ -n "$RUNTIME_DIR" && -f "$RUNTIME_DIR/dhclient.pid" ]]; then
    pid="$(cat "$RUNTIME_DIR/dhclient.pid" 2>/dev/null || true)"
    if [[ "$pid" =~ ^[0-9]+$ && -r "/proc/$pid/comm" ]] && [[ "$(cat "/proc/$pid/comm" 2>/dev/null || true)" == "dhclient" ]]; then
      kill "$pid" 2>/dev/null || true
    fi
  fi
  # Static preflight required that eth3 had no IPv4 address or route, so these
  # flushes remove only temporary DHCP state created by this run.
  ip -4 addr flush dev "$SDN_IF" scope global >/dev/null 2>&1 || true
  ip -4 route flush dev "$SDN_IF" >/dev/null 2>&1 || true
  if [[ "$SDN_WAS_UP" == "0" ]]; then ip link set dev "$SDN_IF" down >/dev/null 2>&1 || true; fi
}

on_exit() {
  local rc=$?
  trap - EXIT HUP INT TERM
  if [[ "$SUCCESS" != "1" ]]; then
    if [[ "$ROLLBACK_ARMED" == "1" ]]; then
      exec 8>"$ROLLBACK_LOCK"
      flock -x 8 || true
      : >"$ROLLBACK_MARKER" 2>/dev/null || true
      systemctl stop "${ROLLBACK_UNIT}.timer" >/dev/null 2>&1 || true
    fi
    if [[ "$CONFIG_INSTALLED" == "1" && -e "$TARGET" ]]; then
      printf '\nPenerapan tidak selesai; menghapus overlay dan mencoba menerapkan kembali konfigurasi Netplan sebelumnya.\n' >&2
      rm -f "$TARGET" "$TARGET_TMP" 2>/dev/null || true
      if ! netplan generate || ! netplan apply; then
        printf 'PERINGATAN: pemulihan otomatis Netplan gagal. Arsip cadangan: %s\n' "${BACKUP:-tidak tersedia}" >&2
        printf 'Periksa konsol VPS; overlay yang dibuat skrip berada di %s.\n' "$TARGET" >&2
      else
        printf 'Konfigurasi Netplan sebelumnya diterapkan kembali. Arsip: %s\n' "${BACKUP:-tidak tersedia}" >&2
      fi
    fi
    if [[ "$LEASE_STARTED" == "1" && "$KEEP_SDN" != "1" ]]; then
      restore_temporary_network
      printf 'Keadaan IPv4 sementara pada %s dibersihkan; jika NIC semula DOWN, skrip mengembalikannya ke DOWN.\n' "$SDN_IF" >&2
      printf 'Jika perlu memulihkan manual (hanya setelah memastikan NIC ini tetap tidak dipakai konfigurasi lain): sudo ip -4 addr flush dev %s scope global; sudo ip -4 route flush dev %s; sudo ip link set dev %s down\n' "$SDN_IF" "$SDN_IF" "$SDN_IF" >&2
    fi
  fi
  [[ -z "$TARGET_TMP" ]] || rm -f "$TARGET_TMP" 2>/dev/null || true
  [[ -z "$RUNTIME_DIR" ]] || rm -rf "$RUNTIME_DIR" 2>/dev/null || true
  exit "$rc"
}
trap on_exit EXIT HUP INT TERM

RUNTIME_DIR="$(mktemp -d /run/route-yes-no-sdn-eth3.XXXXXX)" || fail "Tidak dapat membuat direktori runtime sementara."
if [[ "$SDN_RECOVERY" == "1" ]]; then
  LEASE_STARTED=1
  ip link set dev "$SDN_IF" up || fail "Tidak dapat mengaktifkan $SDN_IF; konfigurasi persisten belum diubah."
  printf '\nMeminta lease DHCPv4 satu kali pada %s; menunggu jawaban DHCP...\n' "$SDN_IF"
  if ! dhclient -1 -v -pf "$RUNTIME_DIR/dhclient.pid" -lf "$RUNTIME_DIR/dhclient.leases" "$SDN_IF"; then
    fail "Permintaan DHCPv4 gagal/tidak mendapat lease. Tidak ada konfigurasi persisten ditulis."
  fi
else
  if [[ "$SDN_NEW" == "1" ]]; then
    printf '\nLease SDN sudah valid melalui jalur normal; menambah stanza Netplan exact-MAC tanpa recovery DHCP...\n'
  else
    printf '\nMenggunakan lease DHCPv4 live pada stanza Netplan %s dan memvalidasinya ulang...\n' "$SDN_ID"
  fi
fi

LEASE_JSON="$(detect lease)" || fail "Lease/preflight gagal. Tidak ada konfigurasi persisten ditulis; skrip akan membersihkan state DHCP sementara dan memulihkan keadaan link awal."
read_lease() { python3 - "$LEASE_JSON" "$1" <<'PY'
import json, sys
print(json.loads(sys.argv[1])[sys.argv[2]])
PY
}
PUB_IF="$(read_lease public_if)"
PUB_ID="$(read_lease public_id)"
PUB_IP="$(read_lease public_ip)"
PUB_PREFIX="$(read_lease public_prefix)"
PUB_GW="$(read_lease public_gw)"
SDN_IP="$(read_lease sdn_ip)"
SDN_PREFIX="$(read_lease sdn_prefix)"
SDN_GW="$(read_lease sdn_gw)"
SDN_ID="$(read_lease sdn_id)"
SDN_NEW="$(read_lease sdn_new)"
PRIORITY="$(read_lease priority)"

# dhclient -1 normally exits after binding; if a client process remains, stop
# only the one recorded in this run's private PID file before Netplan takes over.
if [[ -f "$RUNTIME_DIR/dhclient.pid" ]]; then
  PROBE_PID="$(cat "$RUNTIME_DIR/dhclient.pid" 2>/dev/null || true)"
  if [[ "$PROBE_PID" =~ ^[0-9]+$ && -r "/proc/$PROBE_PID/comm" ]] \
     && [[ "$(cat "/proc/$PROBE_PID/comm" 2>/dev/null || true)" == "dhclient" ]] \
     && kill -0 "$PROBE_PID" 2>/dev/null; then
    kill "$PROBE_PID" 2>/dev/null || fail "Tidak dapat menghentikan proses DHCP probe sebelum Netplan mengambil alih."
  fi
fi

printf '\nLease DHCP tervalidasi: %s %s/%s, gateway %s.\n' "$SDN_IF" "$SDN_IP" "$SDN_PREFIX" "$SDN_GW"
printf 'Perilaku rute publik/SDN akan diterapkan sesuai nilai live tersebut; tidak ada alamat/gateway statis yang ditebak.\n'

# Prepare the final YAML only in /run, and validate the merged configuration in
# an isolated root before touching /etc/netplan.
TMP_YAML="$RUNTIME_DIR/99-upcloud-sdn-eth3-routing.yaml"
cat >"$TMP_YAML" <<EOF
# Added by $0 after explicit confirmation; DHCP addresses/gateway are not fixed.
network:
  version: 2
  ethernets:
    $PUB_ID:
      dhcp4-overrides:
        route-metric: $PUBLIC_METRIC
      routes:
        - to: 0.0.0.0/0
          via: $PUB_GW
          table: $TABLE
          on-link: true
      routing-policy:
        - from: $PUB_IP/32
          table: $TABLE
          priority: $PRIORITY
EOF
if [[ "$SDN_NEW" == "1" ]]; then
  cat >>"$TMP_YAML" <<EOF
    $SDN_ID:
      match:
        macaddress: "$SDN_MAC"
      dhcp4: true
      dhcp4-overrides:
        route-metric: $SDN_METRIC
EOF
else
  cat >>"$TMP_YAML" <<EOF
    $SDN_ID:
      dhcp4: true
      dhcp4-overrides:
        route-metric: $SDN_METRIC
EOF
fi

STAGE_ROOT="$RUNTIME_DIR/netplan-root"
mkdir -p "$STAGE_ROOT/etc" "$STAGE_ROOT/lib" "$STAGE_ROOT/run"
for dir in etc/netplan lib/netplan run/netplan; do
  if [[ -d "/$dir" ]]; then
    mkdir -p "$STAGE_ROOT/$(dirname "$dir")"
    cp -a "/$dir" "$STAGE_ROOT/$(dirname "$dir")/"
  fi
done
mkdir -p "$STAGE_ROOT/etc/netplan"
cp "$TMP_YAML" "$STAGE_ROOT/etc/netplan/$(basename "$TARGET")"
if ! netplan generate --root-dir "$STAGE_ROOT"; then
  fail "Validasi konfigurasi Netplan gabungan gagal pada root sementara. Tidak ada file persisten ditulis."
fi
[[ ! -e "$TARGET" ]] || fail "$TARGET muncul sejak pra-pemeriksaan; menolak menimpanya. Tidak ada file persisten ditulis."

# Exercise the exact transient timer mechanism before any persistent Netplan
# write. If this fails, the trap only removes the temporary DHCP state.
PREFLIGHT_UNIT="route-sdn-eth3-preflight-$$-$RANDOM"
if ! systemd-run --unit="$PREFLIGHT_UNIT" --on-active="${ROLLBACK_SECONDS}s" --timer-property=AccuracySec=1s --collect /bin/true; then
  fail "Uji timer rollback systemd gagal; tidak ada file persisten ditulis."
fi
if ! systemctl stop "${PREFLIGHT_UNIT}.timer"; then
  fail "Tidak dapat menghentikan timer uji; tidak ada file persisten ditulis."
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP="/root/netplan-backup-sdn-eth3-${STAMP}-$$.tar.gz"
tar -czf "$BACKUP" -C / etc/netplan || fail "Tidak dapat membuat arsip /etc/netplan; belum ada konfigurasi persisten ditulis."
printf 'Cadangan Netplan dibuat: %s\n' "$BACKUP"

TARGET_TMP="$(mktemp /etc/netplan/.99-upcloud-sdn-eth3-routing.XXXXXX)" || fail "Tidak dapat menyiapkan file Netplan sementara."
install -o root -g root -m 600 "$TMP_YAML" "$TARGET_TMP"
# ln is an atomic no-overwrite operation on the same filesystem.
ln "$TARGET_TMP" "$TARGET" || fail "Tidak dapat memasang overlay tanpa menimpa file yang sudah ada."
CONFIG_INSTALLED=1
rm -f "$TARGET_TMP"
TARGET_TMP=""

ROLLBACK_UNIT="route-yes-no-sdn-eth3-${STAMP}-$$"
ROLLBACK_SCRIPT="/run/${ROLLBACK_UNIT}.sh"
ROLLBACK_MARKER="/run/${ROLLBACK_UNIT}.committed"
ROLLBACK_LOCK="/run/${ROLLBACK_UNIT}.lock"
cat >"$ROLLBACK_SCRIPT" <<EOF
#!/usr/bin/env bash
set -u
ROLLBACK_STATUS=0
exec 9>"$ROLLBACK_LOCK"
flock -x 9
if [[ -e "$ROLLBACK_MARKER" ]]; then
  exit 0
fi
printf 'SDN routing rollback timer fired at %s; restoring prior Netplan source.\\n' "\$(date -u +%FT%TZ)"
if [[ -e "$TARGET" ]]; then
  rm -f "$TARGET"
  if netplan generate && netplan apply; then
    printf 'Automatic rollback completed; previous Netplan configuration was reapplied.\\n'
  else
    printf 'Automatic rollback ERROR: previous Netplan apply failed; inspect VPS console.\\n' >&2
    ROLLBACK_STATUS=1
  fi
fi
if [[ "$RECOVERY_USED" == "1" ]]; then
  ip -4 addr flush dev "$SDN_IF" scope global >/dev/null 2>&1 || true
  ip -4 route flush dev "$SDN_IF" >/dev/null 2>&1 || true
  if [[ "$SDN_WAS_UP" == "0" ]]; then
    ip link set dev "$SDN_IF" down >/dev/null 2>&1 || true
  fi
fi
exit "\$ROLLBACK_STATUS"
EOF
chmod 700 "$ROLLBACK_SCRIPT"
if ! systemd-run --unit="$ROLLBACK_UNIT" --on-active="${ROLLBACK_SECONDS}s" --timer-property=AccuracySec=1s --collect /bin/bash "$ROLLBACK_SCRIPT"; then
  fail "Tidak dapat memasang rollback systemd ${ROLLBACK_SECONDS} detik; overlay akan dipulihkan sebelum keluar."
fi
ROLLBACK_ARMED=1

printf '\nMengaplikasikan konfigurasi Netplan tervalidasi. Jika koneksi berubah, rollback otomatis aktif selama %s detik.\n' "$ROLLBACK_SECONDS"
if ! netplan apply; then
  fail "netplan apply gagal; skrip akan mencoba memulihkan konfigurasi sebelumnya."
fi
SUCCESS=1
KEEP_SDN=1
printf '\nPenerapan selesai. Periksa konektivitas, rute, dan akses publik sekarang.\n'
printf 'Timer %s detik dimulai tepat sebelum apply (waktu apply mengurangi sisa jendela). Jika semuanya benar dan ingin mempertahankan perubahan, jalankan segera:\n  sudo bash %q --commit %q\n' "$ROLLBACK_SECONDS" "$SCRIPT_PATH" "$ROLLBACK_UNIT"
printf 'Jika perintah commit tidak dijalankan sebelum timer habis, timer akan menghapus overlay dan menerapkan kembali konfigurasi Netplan sebelumnya.\n'
printf 'Arsip konfigurasi sebelumnya: %s\n' "$BACKUP"
