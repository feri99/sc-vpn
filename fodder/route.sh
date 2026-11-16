#!/usr/bin/env bash
# Configure DHCP route preference and public-source reply routing on a newly
# created UpCloud VPS already attached to the intended SDN network.
# This script does not create cloud resources and does not change firewall rules.
set -Eeuo pipefail

VERSION="1.0"
SDN_CIDR="192.168.10.0/24"
PUBLIC_IF=""
PUBLIC_IP=""
PUBLIC_PREFIX=""
PUBLIC_GW=""
SDN_IF=""
SDN_IP=""
SDN_PREFIX=""
SDN_GW=""
PUBLIC_METRIC=200
SDN_METRIC=50
TABLE=1001
PRIORITY=""
APPLY=0

SCRIPT_NAME="$(basename "$0")"
TARGET="/etc/netplan/99-upcloud-sdn-nat.yaml"

usage() {
  cat <<EOF
$SCRIPT_NAME v$VERSION — route general IPv4 egress through SDN NAT while
preserving replies to connections arriving on the public interface.

Run order:
  1. In the new UpCloud account, create the SDN network, Router, and new VPN
     Gateway; enable NAT on that Gateway. The default expected SDN CIDR is
     $SDN_CIDR (change it below with --sdn-cidr if you chose another range).
  2. Create the first VPS and attach its SDN interface. Wait until both
     interfaces have DHCP IPv4 addresses and default routes. If the SDN NIC
     has no Netplan stanza, it is added only when its live MAC and DHCP route
     are uniquely verified.
  3. Copy this script to that new VPS, inspect the plan with a dry run, then
     run it there with --apply from an interactive console/SSH session.

No cloud resources are created. No firewall rules are changed. The script
never connects to or configures an existing VPS on its own. The public NIC
must map to an existing Netplan definition. A missing SDN definition is added
only when the SDN NIC has a unique address in the requested CIDR, a DHCP-
observed default gateway, and a valid live MAC; the added stanza uses dhcp4:
true and no guessed static address. Ambiguity or uncertain mapping fails
closed. The default is dry-run; changes require --apply.

Usage:
  sudo bash $SCRIPT_NAME [options]             # dry-run (no changes)
  sudo bash $SCRIPT_NAME --apply [options]     # backup, validate, netplan try

Detection overrides (only provide values you have verified on this VPS):
  --sdn-cidr CIDR       SDN IPv4 range (default: $SDN_CIDR)
  --public-if NAME      Public NIC (auto-detected if uniquely identifiable)
  --public-ip IPv4      Public IPv4 address
  --public-prefix N     Public IPv4 prefix length, 0..32
  --public-gw IPv4      Public IPv4 default-route gateway
  --sdn-if NAME         SDN NIC (auto-detected if uniquely identifiable)
  --sdn-ip IPv4         SDN IPv4 address
  --sdn-prefix N        SDN IPv4 prefix length, 0..32
  --sdn-gw IPv4         SDN default-route gateway
  --public-metric N     DHCP route metric for public NIC (default: $PUBLIC_METRIC)
  --sdn-metric N        DHCP route metric for SDN NIC (default: $SDN_METRIC)
  --table N             Policy-routing table for public-source replies
                        (default: $TABLE)
  --priority N          Policy-rule priority (auto-select a free value if omitted)
  -h, --help            Show this help

What the configuration does:
  * Sets DHCP route metrics to prefer the SDN default route over the public
    default route. DHCP routes and DNS remain enabled; it does not set
    use-routes: false and does not override DNS settings.
  * If no SDN Netplan definition exists, adds one matching the verified live
    MAC with DHCPv4 enabled; it does not invent an address or gateway.
  * Adds a policy rule for the detected public IPv4 source address and a
    dedicated public-gateway default route, so replies to inbound public
    connections (including SSH) leave through the public NIC.
  * Leaves IPv6 behavior, firewall rules, and cloud resources unchanged.

Apply behavior and rollback:
  * Makes a timestamped archive of /etc/netplan under /root before changing it.
  * Runs netplan generate to validate the complete merged configuration.
  * Runs netplan try with a 120-second confirmation window. Confirm only if
    connectivity still works; otherwise do not confirm and let it roll back.
    The script removes its added file and reapplies the previous config if
    validation/confirmation fails. Keep the backup archive for recovery.

After a successful apply, verify from the VPS:
  ip -4 route show default
  ip -4 rule show
  ip -4 route show table $TABLE
  resolvectl status
  ping -4 -c 3 1.1.1.1
  # Optional: from another host, test SSH/public reachability to this VPS.

Requirements: Ubuntu with Netplan, iproute2, Python 3 and PyYAML; run as root.
EOF
}

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

valid_ifname() { [[ "$1" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]]; }
valid_uint() { [[ "$1" =~ ^[0-9]+$ ]]; }

while (($#)); do
  case "$1" in
    --apply) APPLY=1; shift ;;
    --sdn-cidr) (($# >= 2)) || fail "--sdn-cidr requires a value"; SDN_CIDR="$2"; shift 2 ;;
    --public-if) (($# >= 2)) || fail "--public-if requires a value"; PUBLIC_IF="$2"; shift 2 ;;
    --public-ip) (($# >= 2)) || fail "--public-ip requires a value"; PUBLIC_IP="$2"; shift 2 ;;
    --public-prefix) (($# >= 2)) || fail "--public-prefix requires a value"; PUBLIC_PREFIX="$2"; shift 2 ;;
    --public-gw) (($# >= 2)) || fail "--public-gw requires a value"; PUBLIC_GW="$2"; shift 2 ;;
    --sdn-if) (($# >= 2)) || fail "--sdn-if requires a value"; SDN_IF="$2"; shift 2 ;;
    --sdn-ip) (($# >= 2)) || fail "--sdn-ip requires a value"; SDN_IP="$2"; shift 2 ;;
    --sdn-prefix) (($# >= 2)) || fail "--sdn-prefix requires a value"; SDN_PREFIX="$2"; shift 2 ;;
    --sdn-gw) (($# >= 2)) || fail "--sdn-gw requires a value"; SDN_GW="$2"; shift 2 ;;
    --public-metric) (($# >= 2)) || fail "--public-metric requires a value"; PUBLIC_METRIC="$2"; shift 2 ;;
    --sdn-metric) (($# >= 2)) || fail "--sdn-metric requires a value"; SDN_METRIC="$2"; shift 2 ;;
    --table) (($# >= 2)) || fail "--table requires a value"; TABLE="$2"; shift 2 ;;
    --priority) (($# >= 2)) || fail "--priority requires a value"; PRIORITY="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; (($# == 0)) || fail "Unexpected positional arguments" ;;
    *) fail "Unknown option: $1 (use --help)" ;;
  esac
done

[[ $EUID -eq 0 ]] || fail "Run with sudo/root on the new VPS."
command -v ip >/dev/null 2>&1 || fail "iproute2 command 'ip' is required."
command -v netplan >/dev/null 2>&1 || fail "Netplan is not installed; this script is for a Netplan-based Ubuntu VPS."
command -v python3 >/dev/null 2>&1 || fail "Python 3 is required."
python3 -c 'import yaml' >/dev/null 2>&1 || fail "Python PyYAML is required (Ubuntu package: python3-yaml)."

for name in "$PUBLIC_IF" "$SDN_IF"; do
  [[ -z "$name" ]] || valid_ifname "$name" || fail "Invalid interface name: $name"
done
for n in "$PUBLIC_METRIC" "$SDN_METRIC" "$TABLE"; do
  valid_uint "$n" || fail "Metrics and table must be unsigned integers."
done
(( PUBLIC_METRIC > SDN_METRIC )) || fail "--public-metric must be greater than --sdn-metric so SDN wins for the default route."
(( TABLE >= 1 && TABLE <= 4294967295 )) || fail "--table must be between 1 and 4294967295."
if [[ -n "$PRIORITY" ]]; then
  valid_uint "$PRIORITY" || fail "--priority must be an unsigned integer."
  (( PRIORITY >= 1 && PRIORITY <= 32765 )) || fail "--priority must be between 1 and 32765."
fi

# Resolve the live interfaces and verify the effective Netplan DHCP config.
# PyYAML is used only to read `netplan get`; this script does not alter source
# Netplan files, only adds one clearly named overlay after all checks pass.
DETECTION_JSON="$(python3 - "$SDN_CIDR" "$PUBLIC_IF" "$PUBLIC_IP" "$PUBLIC_PREFIX" "$PUBLIC_GW" "$SDN_IF" "$SDN_IP" "$SDN_PREFIX" "$SDN_GW" "$TABLE" "$PRIORITY" <<'PY'
import fnmatch, ipaddress, json, subprocess, sys

(sdn_cidr_s, pub_if_arg, pub_ip_arg, pub_prefix_arg, pub_gw_arg,
 sdn_if_arg, sdn_ip_arg, sdn_prefix_arg, sdn_gw_arg, table_s,
 priority_arg) = sys.argv[1:]

def die(msg):
    print("ERROR: " + msg, file=sys.stderr)
    raise SystemExit(1)

def run_json(args, allow_missing_ipv4_table=False):
    try:
        p = subprocess.run(args, text=True, capture_output=True, check=True)
        return json.loads(p.stdout or "[]")
    except subprocess.CalledProcessError as e:
        expected_table_query = (
            allow_missing_ipv4_table
            and len(args) == 7
            and args[:6] == ["ip", "-j", "-4", "route", "show", "table"]
        )
        diagnostic = (e.stderr or "").replace("\r\n", "\n").strip().splitlines()
        if expected_table_query and diagnostic == [
            "Error: ipv4: FIB table does not exist.",
            "Dump terminated",
        ]:
            return []
        detail = getattr(e, "stderr", "") or str(e)
        die("Could not inspect " + " ".join(args) + ": " + detail.strip())
    except json.JSONDecodeError as e:
        die("Could not inspect " + " ".join(args) + ": " + str(e))

try:
    sdn_net = ipaddress.ip_network(sdn_cidr_s, strict=True)
    if sdn_net.version != 4:
        die("--sdn-cidr must be an IPv4 CIDR.")
except ValueError as e:
    die("Invalid --sdn-cidr: " + str(e))

try:
    netplan_text = subprocess.run(["netplan", "get"], text=True, capture_output=True, check=True).stdout
except subprocess.CalledProcessError as e:
    die("netplan get failed: " + (e.stderr or "").strip())
try:
    import yaml
    effective = yaml.safe_load(netplan_text) or {}
except Exception as e:
    die("Could not parse `netplan get` output with PyYAML: " + str(e))
if "network" in effective:
    network = effective.get("network") or {}
else:
    network = effective
ethernets = network.get("ethernets") or {}
if not isinstance(ethernets, dict) or not ethernets:
    die("No effective Netplan ethernet definitions were found.")

addr_data = run_json(["ip", "-j", "-4", "addr", "show"])
route_data = run_json(["ip", "-j", "-4", "route", "show", "default"])
rule_data = run_json(["ip", "-j", "-4", "rule", "show"])
link_data = run_json(["ip", "-j", "link", "show"])

def normalize_mac(value):
    if not isinstance(value, str):
        return None
    compact = value.strip().lower().replace(":", "").replace("-", "").replace(".", "")
    if len(compact) != 12 or any(ch not in "0123456789abcdef" for ch in compact):
        return None
    return compact

live_macs = {iface.get("ifname"): normalize_mac(iface.get("address"))
             for iface in link_data if iface.get("ifname")}

addresses = {}
for iface in addr_data:
    name = iface.get("ifname")
    if not name:
        continue
    addresses[name] = []
    for info in iface.get("addr_info", []):
        if info.get("family") == "inet" and info.get("scope") == "global":
            try:
                ip = ipaddress.ip_address(info["local"])
            except (KeyError, ValueError):
                continue
            addresses[name].append({"ip": str(ip), "prefix": int(info.get("prefixlen", 0)), "global": ip.is_global})

routes_by_if = {}
dhcp_routes_by_if = {}
for route in route_data:
    dev = route.get("dev")
    gw = route.get("gateway")
    if dev and gw:
        try:
            ipaddress.IPv4Address(gw)
        except ValueError:
            continue
        routes_by_if.setdefault(dev, set()).add(gw)
        if (route.get("protocol") or route.get("proto")) == "dhcp":
            dhcp_routes_by_if.setdefault(dev, set()).add(gw)

# Map each live interface to precisely one effective Netplan ID. Name patterns
# use shell-like glob semantics, and MAC selectors are compared after normalizing
# case and common separators. When multiple selectors exist, all must match.
def netplan_id_for(ifname, allow_new_sdn=False):
    found = []
    live_mac = live_macs.get(ifname)
    uncertain_match = False
    same_mac_claim = False
    for nid, cfg in ethernets.items():
        if not isinstance(cfg, dict):
            uncertain_match = True
            continue
        match = cfg.get("match") or {}
        if not isinstance(match, dict):
            uncertain_match = True
            continue
        expected_mac = None
        if "macaddress" in match:
            expected_mac = normalize_mac(match.get("macaddress"))
            if expected_mac is None:
                uncertain_match = True
            elif live_mac and expected_mac == live_mac:
                same_mac_claim = True
        if any(key not in ("name", "macaddress") for key in match):
            uncertain_match = True
            continue
        matched = True
        if "name" in match:
            patterns = match.get("name")
            if isinstance(patterns, str):
                patterns = [patterns]
            if not isinstance(patterns, list) or not patterns or any(
                not isinstance(pat, str) for pat in patterns
            ):
                uncertain_match = True
            matched = bool(
                isinstance(patterns, list) and patterns
                and any(isinstance(pat, str) and fnmatch.fnmatchcase(ifname, pat)
                        for pat in patterns)
            )
        if matched and "macaddress" in match:
            expected_mac = normalize_mac(match.get("macaddress"))
            matched = bool(live_mac and expected_mac and live_mac == expected_mac)
        if matched and not ("name" in match or "macaddress" in match):
            matched = nid == ifname or cfg.get("set-name") == ifname
        if matched:
            found.append((nid, cfg))
    if len(found) > 1:
        die(
            f"Interface {ifname} maps to {len(found)} effective Netplan definitions; "
            "refusing ambiguous edits. "
            "Check `ip -br -4 addr`, `ip -4 route`, `ip -j link show`, "
            "and `sudo netplan get`, then correct the existing configuration or "
            "provide the output for diagnosis."
        )
    if not found:
        if not allow_new_sdn:
            die(
                f"Interface {ifname} maps to 0 effective Netplan definitions; "
                "refusing to infer a mapping for this interface. Check "
                "`ip -br -4 addr`, `ip -4 route`, `ip -j link show`, and "
                "`sudo netplan get`."
            )
        if uncertain_match:
            die(f"Cannot safely add an SDN definition for {ifname}: existing Netplan selectors include criteria this script cannot verify.")
        if same_mac_claim:
            die(f"Cannot safely add an SDN definition for {ifname}: its live MAC already appears in an existing Netplan selector that does not uniquely match.")
        if not live_mac:
            die(f"Cannot safely add an SDN definition for {ifname}: no valid live MAC address was reported by `ip -j link show`.")
        if sdn_gw not in dhcp_routes_by_if.get(ifname, set()):
            die(f"Cannot safely add an SDN definition for {ifname}: selected gateway {sdn_gw} is not an observed DHCP IPv4 default route.")
        new_id = "upcloud_sdn_nat"
        if new_id in ethernets:
            die(f"Cannot safely add an SDN definition: Netplan ID {new_id} already exists; refusing to overwrite or guess another ID.")
        formatted_mac = ":".join(live_mac[i:i + 2] for i in range(0, 12, 2))
        return new_id, True, formatted_mac
    nid, cfg = found[0]
    if cfg.get("dhcp4") is not True:
        die(f"Netplan definition {nid} for {ifname} does not have dhcp4: true; no static/network mode changes will be guessed.")
    overrides = cfg.get("dhcp4-overrides") or {}
    if isinstance(overrides, dict) and overrides.get("use-routes") is False:
        die(f"Netplan definition {nid} has dhcp4-overrides.use-routes: false; DHCP routes cannot be preserved as requested.")
    for route in cfg.get("routes") or []:
        if isinstance(route, dict) and route.get("to") in ("default", "0.0.0.0/0"):
            die(f"Netplan definition {nid} already has a static IPv4 default route; refusing to guess which route should win.")
    return nid, False, ""

def choose_iface(kind, override, candidates):
    if override:
        if override not in addresses:
            die(f"Selected {kind} interface {override} has no visible IPv4 address on this VPS.")
        if override not in candidates:
            die(f"Selected {kind} interface {override} does not match the observed {kind} network criteria.")
        return override
    if len(candidates) != 1:
        die(f"Could not uniquely detect {kind} interface; candidates: {', '.join(candidates) if candidates else '(none)'}. Supply --{kind}-if only after checking `ip -4 addr` and `ip -4 route`.")
    return candidates[0]

# Public interface must have an IPv4 global address and a DHCP-observed IPv4
# default gateway. SDN must have an address in the expected CIDR and a default
# gateway. Explicit interface flags can disambiguate only among valid matches.
public_candidates = sorted(ifn for ifn, vals in addresses.items()
                           if any(v["global"] for v in vals) and routes_by_if.get(ifn))
sdn_candidates = sorted(ifn for ifn, vals in addresses.items()
                        if any(ipaddress.ip_address(v["ip"]) in sdn_net for v in vals)
                        and routes_by_if.get(ifn))
pub_if = choose_iface("public", pub_if_arg, public_candidates)
sdn_if = choose_iface("sdn", sdn_if_arg, sdn_candidates)
if pub_if == sdn_if:
    die("Public and SDN interfaces resolve to the same device.")

# Select exactly one public/global IPv4 on the public NIC unless explicitly
# supplied, and exactly one address inside the selected SDN CIDR.
def choose_address(ifname, arg, kind, cidr=None):
    vals = addresses.get(ifname, [])
    if arg:
        try:
            given = ipaddress.IPv4Address(arg)
        except ValueError:
            die(f"Invalid --{kind}-ip: {arg}")
        matching = [v for v in vals if v["ip"] == str(given)]
        if not matching:
            die(f"--{kind}-ip {arg} is not assigned to interface {ifname}.")
        val = matching[0]
        if kind == "public" and not given.is_global:
            die("The selected public IPv4 is not globally routable.")
        if cidr is not None and given not in cidr:
            die(f"--{kind}-ip {arg} is outside {cidr}.")
        return val
    valid = [v for v in vals if (v["global"] if kind == "public" else ipaddress.ip_address(v["ip"]) in cidr)]
    if len(valid) != 1:
        die(f"Expected exactly one {kind} IPv4 on {ifname}; found {len(valid)}. Supply --{kind}-ip after checking `ip -4 addr show dev {ifname}`.")
    return valid[0]

pub_addr = choose_address(pub_if, pub_ip_arg, "public")
sdn_addr = choose_address(sdn_if, sdn_ip_arg, "sdn", sdn_net)

def choose_prefix(addr, arg, kind):
    if arg:
        try:
            p = int(arg)
        except ValueError:
            die(f"Invalid --{kind}-prefix: {arg}")
        if not 0 <= p <= 32:
            die(f"--{kind}-prefix must be between 0 and 32.")
        if p != addr["prefix"]:
            die(f"--{kind}-prefix {p} does not match the live prefix {addr['prefix']} on this interface.")
    return addr["prefix"]

pub_prefix = choose_prefix(pub_addr, pub_prefix_arg, "public")
sdn_prefix = choose_prefix(sdn_addr, sdn_prefix_arg, "sdn")

def choose_gateway(ifname, arg, kind):
    observed = sorted(routes_by_if.get(ifname, set()))
    if arg:
        try:
            given = str(ipaddress.IPv4Address(arg))
        except ValueError:
            die(f"Invalid --{kind}-gw: {arg}")
        if given not in observed:
            die(f"--{kind}-gw {given} is not an observed IPv4 default gateway on {ifname}; refusing to invent a route.")
        return given
    if len(observed) != 1:
        die(f"Expected one IPv4 default gateway on {ifname}; found {', '.join(observed) if observed else '(none)'}. Supply --{kind}-gw only if it is shown by `ip -4 route show default dev {ifname}`.")
    return observed[0]

pub_gw = choose_gateway(pub_if, pub_gw_arg, "public")
sdn_gw = choose_gateway(sdn_if, sdn_gw_arg, "sdn")
if ipaddress.IPv4Address(sdn_gw) not in sdn_net:
    die(f"Detected SDN gateway {sdn_gw} is outside {sdn_net}; check --sdn-cidr and the attached network.")

pub_id = netplan_id_for(pub_if)
pub_id = pub_id[0]
sdn_id, sdn_new, sdn_mac = netplan_id_for(sdn_if, allow_new_sdn=True)

try:
    table = int(table_s)
except ValueError:
    die("Invalid policy-routing table number.")
# Refuse to overwrite a live table route or duplicate a live source rule.
for route in run_json(["ip", "-j", "-4", "route", "show", "table", str(table)], allow_missing_ipv4_table=True):
    if route.get("dst") == "default":
        die(f"Routing table {table} already contains a default route; choose another --table after inspecting it.")

used_priorities = set()
for rule in rule_data:
    try:
        used_priorities.add(int(rule.get("priority")))
    except (TypeError, ValueError):
        pass
if priority_arg:
    priority = int(priority_arg)
    if priority in used_priorities:
        die(f"Policy-rule priority {priority} is already in use; choose another --priority.")
else:
    priority = next((p for p in range(10000, 11000) if p not in used_priorities), None)
    if priority is None:
        die("No free policy-rule priority in 10000..10999; provide --priority after inspecting `ip -4 rule`.")

# Check for a live rule already using this public source (avoid duplicate policy).
for rule in rule_data:
    src = rule.get("from")
    if src and src not in ("all", "0.0.0.0/0"):
        try:
            rule_net = ipaddress.ip_network(src, strict=False)
            if ipaddress.IPv4Address(pub_addr["ip"]) in rule_net:
                die(f"An existing IPv4 policy rule already matches public source {pub_addr['ip']}; inspect `ip -4 rule` before proceeding.")
        except ValueError:
            pass

result = {
    "public_if": pub_if, "public_id": pub_id, "public_ip": pub_addr["ip"],
    "public_prefix": pub_prefix, "public_gw": pub_gw,
    "sdn_if": sdn_if, "sdn_id": sdn_id, "sdn_ip": sdn_addr["ip"],
    "sdn_prefix": sdn_prefix, "sdn_gw": sdn_gw, "sdn_cidr": str(sdn_net),
    "sdn_new": int(sdn_new), "sdn_mac": sdn_mac,
    "table": table, "priority": priority
}
print(json.dumps(result))
PY
)" || fail "Network detection failed; no files were changed."

# Extract the validated manifest without introducing shell evaluation.
read_manifest() {
  python3 - "$DETECTION_JSON" "$1" <<'PY'
import json, sys
print(json.loads(sys.argv[1])[sys.argv[2]])
PY
}
PUB_IF_RES="$(read_manifest public_if)"
PUB_ID="$(read_manifest public_id)"
PUB_IP_RES="$(read_manifest public_ip)"
PUB_PREFIX_RES="$(read_manifest public_prefix)"
PUB_GW_RES="$(read_manifest public_gw)"
SDN_IF_RES="$(read_manifest sdn_if)"
SDN_ID="$(read_manifest sdn_id)"
SDN_NEW="$(read_manifest sdn_new)"
SDN_MAC_RES="$(read_manifest sdn_mac)"
SDN_IP_RES="$(read_manifest sdn_ip)"
SDN_PREFIX_RES="$(read_manifest sdn_prefix)"
SDN_GW_RES="$(read_manifest sdn_gw)"
SDN_CIDR_RES="$(read_manifest sdn_cidr)"
TABLE_RES="$(read_manifest table)"
PRIORITY_RES="$(read_manifest priority)"

# Validate IDs and addresses before placing them into YAML. Values are already
# parsed from the live system, but constrain interface IDs to safe YAML tokens.
valid_ifname "$PUB_ID" || fail "Unsafe Netplan ID for public interface: $PUB_ID"
valid_ifname "$SDN_ID" || fail "Unsafe Netplan ID for SDN interface: $SDN_ID"
[[ "$PUB_ID" != "$SDN_ID" ]] || fail "Both interfaces map to the same Netplan ID."
if [[ "$SDN_NEW" == "1" ]]; then
  [[ "$SDN_MAC_RES" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] || fail "Unsafe or invalid live MAC for the new SDN definition."
fi
[[ ! -e "$TARGET" ]] || fail "$TARGET already exists. Review it and choose a safe manual merge; this script will not overwrite it."

if (( APPLY )); then
  [[ -t 0 && -t 1 ]] || fail "--apply requires an interactive terminal for netplan try confirmation; no changes were made."
fi

TMP_YAML="$(mktemp)"
cleanup_tmp() { rm -f "$TMP_YAML"; }
trap cleanup_tmp EXIT

cat >"$TMP_YAML" <<EOF
# Added by $SCRIPT_NAME. DHCP routes/DNS remain enabled.
network:
  version: 2
  ethernets:
    $PUB_ID:
      dhcp4-overrides:
        route-metric: $PUBLIC_METRIC
      routes:
        - to: 0.0.0.0/0
          via: $PUB_GW_RES
          table: $TABLE_RES
          on-link: true
      routing-policy:
        - from: $PUB_IP_RES/32
          table: $TABLE_RES
          priority: $PRIORITY_RES
EOF
if [[ "$SDN_NEW" == "1" ]]; then
  cat >>"$TMP_YAML" <<EOF
    $SDN_ID:
      match:
        macaddress: "$SDN_MAC_RES"
      dhcp4: true
      dhcp4-overrides:
        route-metric: $SDN_METRIC
EOF
else
  cat >>"$TMP_YAML" <<EOF
    $SDN_ID:
      dhcp4-overrides:
        route-metric: $SDN_METRIC
EOF
fi

cat <<EOF
Detected configuration (read-only planning):
  Public: $PUB_IF_RES ($PUB_IP_RES/$PUB_PREFIX_RES), gateway $PUB_GW_RES,
          DHCP route metric $PUBLIC_METRIC; replies use policy table $TABLE_RES
  SDN:    $SDN_IF_RES ($SDN_IP_RES/$SDN_PREFIX_RES), gateway $SDN_GW_RES,
          network $SDN_CIDR_RES, DHCP route metric $SDN_METRIC
EOF
if [[ "$SDN_NEW" == "1" ]]; then
  printf '          new Netplan stanza: exact live MAC %s, dhcp4: true\n' "$SDN_MAC_RES"
fi
cat <<EOF
  Policy-rule priority: $PRIORITY_RES

Netplan overlay that would be added:
EOF
cat "$TMP_YAML"

if (( ! APPLY )); then
  cat <<EOF
Dry-run only: no files or network settings were changed.
If this is the intended newly created VPS, rerun the same command with --apply.
EOF
  exit 0
fi

BACKUP="/root/netplan-backup-upcloud-sdn-nat-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
tar -czf "$BACKUP" -C / etc/netplan || fail "Could not back up /etc/netplan; no configuration was changed."
printf '\nBackup created: %s\n' "$BACKUP"

CONFIG_CREATED=0
CONFIRMED=0
rollback_on_exit() {
  local rc=$?
  trap - EXIT HUP INT TERM
  rm -f "$TMP_YAML" || true
  if (( CONFIG_CREATED && ! CONFIRMED )); then
    printf '\nNot confirmed or an error occurred; removing the overlay and restoring the prior Netplan configuration.\n' >&2
    rm -f "$TARGET" || true
    netplan generate >/dev/null 2>&1 || true
    netplan apply >/dev/null 2>&1 || true
    printf 'Recovery archive remains at: %s\n' "$BACKUP" >&2
  fi
  exit "$rc"
}
trap rollback_on_exit EXIT HUP INT TERM

install -o root -g root -m 600 "$TMP_YAML" "$TARGET"
CONFIG_CREATED=1
if ! netplan generate; then
  fail "netplan generate rejected the merged configuration. The added file will be removed."
fi

cat <<EOF
Starting netplan try (120-second automatic rollback window).
If this session still has working connectivity, press Enter when prompted to
keep the configuration. If connectivity is broken or uncertain, do not confirm;
wait for the timeout and rollback.
EOF
if netplan try --timeout 120; then
  CONFIRMED=1
  printf '\nNetplan change confirmed. Verify routes and DNS with the commands shown by --help.\n'
  printf 'Recovery archive: %s\n' "$BACKUP"
else
  fail "netplan try did not confirm the change; the previous configuration will be restored."
fi
