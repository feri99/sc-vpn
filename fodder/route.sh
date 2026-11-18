#!/usr/bin/env bash
# Safely identify the SDN NIC, enable DHCPv4 if needed, and configure routing.
# public/SDN route preference and public-source reply policy. No cloud/API/GitHub
# operations are performed.
set -Eeuo pipefail

VERSION="3.1"
SDN_IF=""
SDN_MAC=""
SDN_CIDR="192.168.10.0/24"
PUBLIC_METRIC=200
SDN_METRIC=50
DHCP_PROBE_METRIC=60000
DHCP_PROBE_TIMEOUT=60
DHCP_PROBE_INTERVAL=2
TABLE=1001
SDN_ID="upcloud_sdn"
TARGET="/etc/netplan/99-upcloud-sdn-auto-routing.yaml"
SCRIPT_PATH="$(readlink -f "$0")"

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<EOF
$0 v$VERSION — detect the SDN NIC and safely configure DHCPv4/routing.

Normal run (automatic after read-only preflight; no confirmation prompt):
  sudo bash $0

Read-only checks only (does not request DHCP or alter networking):
  sudo bash $0 --dry-run

Optional SDN network override (default: $SDN_CIDR):
  sudo bash $0 --sdn-cidr 10.20.0.0/24

The script automatically uses netplan apply after its read-only preflight. There
is no confirmation prompt and no automatic rollback. SSH can still disconnect
even if the route change is expected to be safe; use provider console/manual
recovery if needed. During a DHCP probe, only the script's temporary Netplan
overlay is removed and the previous configuration reapplied if probing fails.
After final apply, there is no automatic rollback. A backup is saved for manual
recovery.

The script first looks for a unique live SDN lease/default route in the chosen
CIDR. Recovery without a lease is allowed only when exactly one unused physical
NIC remains besides the public NIC. It stops rather than guessing if evidence
is missing or ambiguous. DHCP values are validated live; no VPS, cloud API, or
GitHub is contacted.
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then usage; exit 0; fi
DRY_RUN=0
while (($#)); do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --sdn-cidr)
      (($# >= 2)) || fail "--sdn-cidr memerlukan CIDR, mis. 10.20.0.0/24."
      SDN_CIDR="$2"; shift 2 ;;
    --sdn-cidr=*) SDN_CIDR="${1#*=}"; shift ;;
    *) fail "Argumen tidak dikenal: $1 (gunakan --help)." ;;
  esac
done

[[ "$EUID" -eq 0 ]] || fail "Jalankan di VPS dengan sudo/root."
for cmd in ip netplan python3 tar install cp mktemp date readlink ln mkdir rm chmod cat stat mv sleep; do
  command -v "$cmd" >/dev/null 2>&1 || fail "Perintah '$cmd' diperlukan. Belum ada perubahan dibuat."
done
python3 -c 'import yaml' >/dev/null 2>&1 || fail "PyYAML diperlukan (paket Ubuntu: python3-yaml). Belum ada perubahan dibuat."

# Confirm isolated Netplan validation support before asking.
NETPLAN_HELP="$(netplan generate --help 2>&1 || true)"
[[ "$NETPLAN_HELP" == *"--root-dir"* ]] || fail "Versi Netplan harus mendukung 'generate --root-dir' untuk memvalidasi konfigurasi sebelum menulis ke /etc/netplan. Belum ada perubahan dibuat."
[[ -d /etc/netplan && -w /etc/netplan && -w /root && -w /run ]] || fail "Direktori Netplan, /root, atau /run tidak dapat ditulis. Belum ada perubahan dibuat."
[[ ! -e "$TARGET" ]] || fail "$TARGET sudah ada; skrip tidak akan menimpa konfigurasi yang ada. Belum ada perubahan dibuat."

# Resolve the SDN interface from live lease/route evidence first. DHCP recovery
# is considered only for one uniquely identifiable, unused physical NIC.
DISCOVERY_JSON="$(python3 - "$SDN_CIDR" "${ROUTE_SDN_SYSFS_ROOT:-/sys}" <<'PY'
import fnmatch, ipaddress, json, os, subprocess, sys
from pathlib import Path

cidr_s, sysfs_root = sys.argv[1:]

def die(msg):
    print("ERROR: " + msg, file=sys.stderr)
    raise SystemExit(1)

def run_json(args):
    try:
        p = subprocess.run(args, text=True, capture_output=True, check=True)
        return json.loads(p.stdout or "[]")
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        detail = getattr(e, "stderr", "") or str(e)
        die("Tidak dapat membaca " + " ".join(args) + ": " + detail.strip())

def norm_mac(value):
    if not isinstance(value, str): return None
    compact = value.strip().lower().replace(":", "").replace("-", "").replace(".", "")
    if len(compact) != 12 or any(c not in "0123456789abcdef" for c in compact): return None
    return ":".join(compact[i:i+2] for i in range(0, 12, 2))

try:
    net = ipaddress.ip_network(cidr_s, strict=True)
except ValueError as e:
    die("CIDR SDN tidak valid: " + str(e))
if not isinstance(net, ipaddress.IPv4Network): die("CIDR SDN harus IPv4.")

try:
    import yaml
    text = subprocess.run(["netplan", "get"], text=True, capture_output=True, check=True).stdout
    effective = yaml.safe_load(text) or {}
except Exception as e:
    die("Tidak dapat membaca konfigurasi Netplan efektif: " + str(e))
network = effective.get("network", effective) if isinstance(effective, dict) else {}
ethernets = network.get("ethernets") or {}
if not isinstance(ethernets, dict): die("Definisi ethernet Netplan tidak dapat diverifikasi.")

links_data = run_json(["ip", "-j", "link", "show"])
addr_data = run_json(["ip", "-j", "-4", "addr", "show"])
routes = run_json(["ip", "-j", "-4", "route", "show"])
links = {x.get("ifname"): x for x in links_data if x.get("ifname")}
if not links: die("Tidak ada interface jaringan yang dapat dibaca dari ip link.")
addresses = {name: [] for name in links}
for item in addr_data:
    name = item.get("ifname")
    for info in item.get("addr_info", []):
        if info.get("family") == "inet":
            try: addresses.setdefault(name, []).append(ipaddress.IPv4Address(info["local"]))
            except (KeyError, ValueError, TypeError): pass
routes_by_if = {}
for route in routes:
    dev = route.get("dev")
    if dev: routes_by_if.setdefault(dev, []).append(route)

# Strongest signal: a live address in the SDN CIDR or a default route whose
# gateway is in that CIDR. A partial match is selected for validation, never
# silently reclassified as a clean recovery candidate.
live_marks = {}
for name in links:
    if name == "lo": continue
    if any(a in net for a in addresses.get(name, [])):
        live_marks.setdefault(name, set()).add("alamat")
for route in routes:
    dev = route.get("dev")
    gw = route.get("gateway") or route.get("via")
    if dev in links and route.get("dst") == "default" and gw:
        try:
            if ipaddress.IPv4Address(gw) in net:
                live_marks.setdefault(dev, set()).add("gateway")
        except ValueError: pass
if len(live_marks) > 1:
    die("Bukti SDN live ambigu pada beberapa interface: " + ", ".join(sorted(live_marks)))

def result(name, basis):
    mac = norm_mac(links.get(name, {}).get("address"))
    if not mac: die(f"MAC live untuk {name} tidak valid; tidak aman melanjutkan.")
    print(json.dumps({"ifname": name, "mac": mac, "basis": basis}))

if live_marks:
    name = next(iter(live_marks))
    result(name, "bukti lease/alamat atau gateway live dalam CIDR SDN")
    raise SystemExit(0)

# No live SDN evidence: determine the public NIC using its global IPv4 and
# default gateway, then use exact Netplan selectors to recognize configured NICs.
defaults = {}
for route in routes:
    if route.get("dst") != "default": continue
    dev, gw = route.get("dev"), route.get("gateway") or route.get("via")
    if dev and gw:
        try: defaults.setdefault(dev, set()).add(str(ipaddress.IPv4Address(gw)))
        except ValueError: pass
public = sorted(name for name, vals in addresses.items()
                if any(a.is_global for a in vals) and defaults.get(name))
if len(public) != 1:
    die("Tanpa lease SDN, tidak bisa menentukan satu NIC publik; kandidat: " + (", ".join(public) if public else "(tidak ada)"))
public_if = public[0]

def map_netplan(name):
    matches, uncertain = [], []
    live_mac = norm_mac(links.get(name, {}).get("address"))
    for nid, cfg in ethernets.items():
        if not isinstance(cfg, dict):
            uncertain.append(nid); continue
        selector = cfg.get("match") or {}
        if not isinstance(selector, dict) or any(k not in ("name", "macaddress") for k in selector):
            uncertain.append(nid); continue
        matched = True
        if "name" in selector:
            patterns = selector["name"]
            if isinstance(patterns, str): patterns = [patterns]
            if not isinstance(patterns, list) or not patterns or any(not isinstance(p, str) for p in patterns):
                uncertain.append(nid); continue
            matched = any(fnmatch.fnmatchcase(name, p) for p in patterns)
        if "macaddress" in selector:
            expected = norm_mac(selector.get("macaddress"))
            if not expected:
                uncertain.append(nid); continue
            matched = matched and bool(live_mac and expected == live_mac)
        if not selector: matched = (nid == name or cfg.get("set-name") == name)
        if matched: matches.append(nid)
    if len(matches) > 1: die(f"{name} cocok dengan beberapa stanza Netplan: " + ", ".join(matches))
    if uncertain: return None, uncertain
    return (matches[0] if matches else None), []

mapped, uncertain = {}, {}
for name in links:
    if name in ("lo", public_if): continue
    nid, unknown = map_netplan(name)
    if unknown: uncertain[name] = unknown
    elif nid: mapped[name] = nid
if uncertain:
    detail = "; ".join(f"{n}: {','.join(ids)}" for n, ids in sorted(uncertain.items()))
    die("Selector Netplan tidak dapat diverifikasi; tidak aman menebak NIC SDN (" + detail + ").")

# With no live SDN address/gateway, configured non-public interfaces are not
# recovery candidates. This excludes utility networks and DHCPv6-only NICs.
physical = []
for name in links:
    if name in ("lo", public_if) or name in mapped: continue
    device = Path(sysfs_root) / "class" / "net" / name / "device"
    if device.exists() or device.is_symlink(): physical.append(name)
if len(physical) != 1:
    excluded = ", ".join(f"{name} (Netplan {nid})" for name, nid in sorted(mapped.items()))
    detail = ", ".join(sorted(physical)) if physical else "(tidak ada; sysfs tidak memberi bukti NIC fisik)"
    die("Interface SDN tidak teridentifikasi dari lease live; kandidat fisik non-publik yang belum dipetakan harus tepat satu, ditemukan: " + detail + ("; NIC terpetakan dikecualikan: " + excluded if excluded else ""))
name = physical[0]
if addresses.get(name) or routes_by_if.get(name):
    die(f"Kandidat fisik {name} memiliki alamat atau rute IPv4 tetapi belum dipetakan Netplan dan tidak cocok dengan CIDR SDN; recovery otomatis ditolak.")
result(name, "satu-satunya NIC fisik non-publik, tanpa IPv4/rute dan tanpa stanza Netplan")
PY
)" || fail "Deteksi interface SDN read-only gagal; tidak ada perubahan dibuat."
SDN_IF="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["ifname"])' "$DISCOVERY_JSON")"
SDN_MAC="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["mac"])' "$DISCOVERY_JSON")"
SDN_BASIS="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["basis"])' "$DISCOVERY_JSON")"
printf 'Deteksi SDN baca-saja: %s (%s); dasar: %s.\n' "$SDN_IF" "$SDN_MAC" "$SDN_BASIS"

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
    die(f"Interface yang terdeteksi otomatis, {sdn_if}, tidak ditemukan; tidak mencari pengganti.")
actual_mac = normalize_mac(links[sdn_if].get("address"))
if actual_mac != normalize_mac(confirmed_mac):
    die(f"MAC live {sdn_if} berubah dari hasil deteksi {confirmed_mac}; tidak ada perubahan dibuat.")

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
public_metrics = set()
for route in route_data:
    if route.get("dst") == "default" and route.get("dev") == pub_if:
        gw = route.get("gateway") or route.get("via")
        if gw == pub_gw:
            try: public_metrics.add(int(route.get("metric", 0)))
            except (TypeError, ValueError): pass
if len(public_metrics) != 1:
    die(f"Tidak bisa memastikan satu metrik default route publik pada {pub_if}; tidak aman menjalankan DHCP probe.")
pub_metric = next(iter(public_metrics))
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
    "public_prefix": pub_prefix, "public_gw": pub_gw, "public_metric": pub_metric,
    "sdn_if": sdn_if, "sdn_mac": normalize_mac(confirmed_mac),
    "sdn_id": sdn_id, "sdn_new": sdn_new, "sdn_recovery": sdn_recovery,
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
PUB_ORIGINAL_METRIC="$(read_value public_metric)"
SDN_ID="$(read_value sdn_id)"
SDN_NEW="$(read_value sdn_new)"
SDN_RECOVERY="$(read_value sdn_recovery)"
PRIORITY="$(read_value priority)"

printf 'Pra-pemeriksaan read-only lulus.\n'
printf '  Publik: %s (%s/%s), gateway teramati %s\n' "$PUB_IF" "$PUB_IP" "$PUB_PREFIX" "$PUB_GW"
if [[ "$SDN_NEW" == "1" ]]; then
  if [[ "$SDN_RECOVERY" == "1" ]]; then
    printf '  SDN:    tidak ada stanza/alamat/rute; recovery terbatas ke NIC unik %s / %s.\n' "$SDN_IF" "$SDN_MAC"
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
if [[ "$SDN_RECOVERY" == "1" ]] && (( PUB_ORIGINAL_METRIC >= DHCP_PROBE_METRIC )); then
  fail "Metrik default publik $PUB_ORIGINAL_METRIC tidak lebih kecil daripada metrik DHCP probe $DHCP_PROBE_METRIC; berhenti agar probe tidak mengambil alih egress publik."
fi

if [[ "$SDN_RECOVERY" == "1" ]]; then
  DHCP_PLAN="Lease diminta dengan Netplan sementara pada NIC unik $SDN_IF; metrik probe $DHCP_PROBE_METRIC menjaga gateway publik (metric $PUB_ORIGINAL_METRIC) tetap lebih diprioritaskan. Tidak membutuhkan dhclient."
elif [[ "$SDN_NEW" == "1" ]]; then
  DHCP_PLAN="Lease SDN normal sudah valid; tidak ada recovery DHCP, stanza exact-MAC ditambahkan."
else
  DHCP_PLAN="Stanza exact-MAC yang ada dipakai ulang; tidak menjalankan probe tambahan dan melanjutkan hanya dengan lease live yang valid."
fi
printf '\nMode otomatis: preflight lulus; %s\n' "$DHCP_PLAN"
printf 'PERINGATAN: skrip akan mengubah jaringan dan menjalankan netplan apply tanpa konfirmasi atau rollback otomatis. SSH masih bisa terputus; gunakan konsol provider/pemulihan manual bila perlu.\n'
printf 'Jika probe DHCP gagal sebelum final overlay, skrip menghapus hanya file probe miliknya dan mencoba menerapkan ulang Netplan sebelumnya. Setelah final overlay/apply dimulai, tidak ada rollback otomatis; cadangan hanya untuk pemulihan manual.\n'

RUNTIME_DIR=""
TMP_YAML=""
PROBE_YAML=""
TARGET_TMP=""
BACKUP=""
PROBE_ID=""
PROBE_ACTIVE=0
LEASE_JSON=""

ensure_backup() {
  [[ -n "$BACKUP" ]] && return 0
  local stamp
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  BACKUP="/root/netplan-backup-sdn-auto-${stamp}-$$.tar.gz"
  if ! tar -czf "$BACKUP" -C / etc/netplan; then
    BACKUP=""
    return 1
  fi
  printf 'Cadangan Netplan dibuat: %s\n' "$BACKUP"
}

validate_overlay() {
  local yaml_file="$1" stage_root="$2" dir
  mkdir -p "$stage_root/etc" "$stage_root/lib" "$stage_root/run" || return 1
  for dir in etc/netplan lib/netplan run/netplan; do
    if [[ -d "/$dir" ]]; then
      mkdir -p "$stage_root/$(dirname "$dir")" || return 1
      cp -a "/$dir" "$stage_root/$(dirname "$dir")/" || return 1
    fi
  done
  mkdir -p "$stage_root/etc/netplan" || return 1
  cp "$yaml_file" "$stage_root/etc/netplan/$(basename "$TARGET")" || return 1
  netplan generate --root-dir "$stage_root"
}

restore_probe() {
  if [[ "$PROBE_ACTIVE" != "1" ]]; then return 0; fi
  if [[ -f "$TARGET" && ! -L "$TARGET" ]] \
    && [[ "$(stat -c '%d:%i' -- "$TARGET" 2>/dev/null || true)" == "$PROBE_ID" ]]; then
    if rm -f -- "$TARGET"; then
      PROBE_ACTIVE=0
      printf 'Probe gagal sebelum final overlay; file probe milik skrip dihapus dan Netplan sebelumnya sedang diterapkan ulang.\n' >&2
      if netplan generate && netplan apply; then
        printf 'Konfigurasi Netplan sebelumnya berhasil diterapkan kembali.\n' >&2
      else
        printf 'PERINGATAN: penerapan ulang Netplan sebelumnya gagal; periksa melalui konsol VPS. Cadangan: %s\n' "${BACKUP:-tidak tersedia}" >&2
      fi
    else
      printf 'PERINGATAN: file probe %s tidak dapat dihapus; tidak ada pemulihan otomatis yang aman.\n' "$TARGET" >&2
    fi
  else
    printf 'PERINGATAN: %s bukan lagi file probe yang dibuat skrip; tidak disentuh.\n' "$TARGET" >&2
  fi
}

on_exit() {
  local rc=$?
  trap - EXIT HUP INT TERM
  restore_probe
  [[ -z "$TARGET_TMP" ]] || rm -f "$TARGET_TMP" 2>/dev/null || true
  [[ -z "$RUNTIME_DIR" ]] || rm -rf "$RUNTIME_DIR" 2>/dev/null || true
  exit "$rc"
}
trap on_exit EXIT HUP INT TERM

RUNTIME_DIR="$(mktemp -d /run/route-yes-no-sdn-auto.XXXXXX)" || fail "Tidak dapat membuat direktori runtime sementara."
if [[ "$SDN_RECOVERY" == "1" ]]; then
  ensure_backup || fail "Tidak dapat membuat cadangan Netplan; probe DHCP tidak dijalankan."
  PROBE_YAML="$RUNTIME_DIR/99-upcloud-sdn-auto-dhcp-probe.yaml"
  cat >"$PROBE_YAML" <<EOF
# Temporary DHCPv4 probe; this file is removed after lease validation.
network:
  version: 2
  ethernets:
    $SDN_ID:
      match:
        macaddress: "$SDN_MAC"
      dhcp4: true
      dhcp4-overrides:
        route-metric: $DHCP_PROBE_METRIC
EOF
  PROBE_STAGE="$RUNTIME_DIR/netplan-probe-root"
  validate_overlay "$PROBE_YAML" "$PROBE_STAGE" || fail "Netplan menolak konfigurasi DHCP probe terisolasi; tidak ada probe jaringan dijalankan."
  TARGET_TMP="$(mktemp /etc/netplan/.99-upcloud-sdn-auto-probe.XXXXXX)" || fail "Tidak dapat menyiapkan file Netplan probe sementara."
  install -o root -g root -m 600 "$PROBE_YAML" "$TARGET_TMP"
  PROBE_ID="$(stat -c '%d:%i' -- "$TARGET_TMP")" || fail "Tidak dapat mencatat identitas file probe."
  PROBE_ACTIVE=1
  ln "$TARGET_TMP" "$TARGET" || fail "Tidak dapat memasang probe tanpa menimpa file Netplan yang sudah ada."
  rm -f "$TARGET_TMP"
  TARGET_TMP=""
  printf '\nMeminta lease DHCPv4 lewat Netplan pada %s; gateway publik tetap diprioritaskan dengan metrik %s. Menunggu hingga %s detik...\n' "$SDN_IF" "$PUB_ORIGINAL_METRIC" "$DHCP_PROBE_TIMEOUT"
  if ! netplan apply; then
    fail "netplan apply untuk DHCP probe gagal; probe akan dibuang dan konfigurasi sebelumnya dicoba diterapkan kembali."
  fi
  LEASE_ERROR="$RUNTIME_DIR/lease-detect.err"
  lease_attempts=$((DHCP_PROBE_TIMEOUT / DHCP_PROBE_INTERVAL))
  for ((attempt=1; attempt<=lease_attempts; attempt++)); do
    if LEASE_JSON="$(detect lease 2>"$LEASE_ERROR")"; then break; fi
    LEASE_JSON=""
    if (( attempt < lease_attempts )); then sleep "$DHCP_PROBE_INTERVAL"; fi
  done
  if [[ -z "$LEASE_JSON" ]]; then
    [[ ! -s "$LEASE_ERROR" ]] || cat "$LEASE_ERROR" >&2
    fail "Netplan tidak memberikan satu lease IPv4/gateway SDN tervalidasi dalam ${DHCP_PROBE_TIMEOUT} detik; probe akan dihapus dan konfigurasi sebelumnya dicoba diterapkan kembali."
  fi
else
  if [[ "$SDN_NEW" == "1" ]]; then
    printf '\nLease SDN normal sudah valid; menambah stanza exact-MAC tanpa DHCP probe tambahan...\n'
  else
    printf '\nMenggunakan lease DHCPv4 live pada stanza Netplan %s dan memvalidasinya ulang...\n' "$SDN_ID"
  fi
  LEASE_JSON="$(detect lease)" || fail "Lease/preflight gagal; tidak ada overlay Netplan final yang ditulis."
fi
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
if [[ "$SDN_RECOVERY" == "1" ]]; then
  # netplan get now sees our temporary probe stanza; it was not in the original
  # configuration, so the final overlay must still include the detected MAC.
  SDN_NEW=1
fi

printf '\nLease DHCP tervalidasi: %s %s/%s, gateway %s.\n' "$SDN_IF" "$SDN_IP" "$SDN_PREFIX" "$SDN_GW"
printf 'Perilaku rute publik/SDN akan diterapkan sesuai nilai live tersebut; tidak ada alamat/gateway statis yang ditebak.\n'

# Prepare the final YAML only in /run, and validate the merged configuration in
# an isolated root before touching /etc/netplan.
TMP_YAML="$RUNTIME_DIR/99-upcloud-sdn-auto-routing.yaml"
cat >"$TMP_YAML" <<EOF
# Added by $0 after read-only preflight; DHCP addresses/gateway are not fixed.
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

STAGE_ROOT="$RUNTIME_DIR/netplan-final-root"
if ! validate_overlay "$TMP_YAML" "$STAGE_ROOT"; then
  fail "Validasi konfigurasi Netplan gabungan gagal pada root sementara. Tidak ada file persisten ditulis."
fi
ensure_backup || fail "Tidak dapat membuat cadangan Netplan; overlay final tidak dipasang."

TARGET_TMP="$(mktemp /etc/netplan/.99-upcloud-sdn-auto-routing.XXXXXX)" || fail "Tidak dapat menyiapkan file Netplan sementara."
install -o root -g root -m 600 "$TMP_YAML" "$TARGET_TMP"
if [[ "$PROBE_ACTIVE" == "1" ]]; then
  [[ -f "$TARGET" && ! -L "$TARGET" ]] \
    && [[ "$(stat -c '%d:%i' -- "$TARGET" 2>/dev/null || true)" == "$PROBE_ID" ]] \
    || fail "File probe berubah sejak dipasang; menolak mengganti file yang bukan milik skrip."
  mv -f -- "$TARGET_TMP" "$TARGET" || fail "Tidak dapat mengganti probe dengan overlay final."
  TARGET_TMP=""
  PROBE_ACTIVE=0
  PROBE_ID=""
else
  [[ ! -e "$TARGET" ]] || fail "$TARGET muncul sejak pra-pemeriksaan; menolak menimpanya."
  # Atomic no-overwrite for the normal lease path.
  ln "$TARGET_TMP" "$TARGET" || fail "Tidak dapat memasang overlay tanpa menimpa file yang sudah ada."
  rm -f "$TARGET_TMP"
  TARGET_TMP=""
fi

printf '\nMenjalankan netplan apply langsung; tidak ada prompt Enter kedua atau rollback otomatis berbatas waktu.\n'
if ! netplan apply; then
  fail "netplan apply gagal; tidak ada rollback otomatis. Overlay tersimpan di $TARGET dan cadangan tersedia di $BACKUP; periksa jaringan melalui konsol provider."
fi
printf '\nKonfigurasi berhasil diterapkan tanpa rollback otomatis. Verifikasi konektivitas, rute, dan akses publik dari sesi atau konsol provider.\n'
printf 'Arsip konfigurasi sebelumnya: %s\n' "$BACKUP"
