#!/usr/bin/env python3
# =============================================================================
# netmap — map the network, remember it, and say what is worth attacking
# =============================================================================
#     netmap            scan, save, open the dashboard
#     netmap scan       scan only
#     netmap dash       dashboard only, no traffic
#     netmap show [KEY] print a network as text
#     netmap export     write a report for every known network
#
# What it collects, per network:
#   access points   ssid, bssid, channel, signal, security
#   hosts           ip, mac, vendor, hostname, os guess, role
#   ports           open tcp ports, service names, versions where nmap knows
#   smb             domain, os, signing required or not, shares and access
#   web             status, title, server header, tls certificate subject
#
# Then it ranks the attacks that actually apply to what it found, with the
# evidence next to each one, and shows that next to the network it belongs to.
#
# Storage: ~/.netmap/state.json (0600, dir 0700). Scans merge, they do not
# replace, so a device seen once is remembered forever.
# =============================================================================

import curses
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import unicodedata
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime

HOME = os.path.expanduser("~")
STORE = os.path.join(HOME, ".netmap")
STATE_FILE = os.path.join(STORE, "state.json")

TOP_PORTS = [21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 161, 389, 443,
             445, 515, 548, 554, 587, 631, 636, 993, 995, 1433, 1521, 2049,
             2375, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443, 9000, 9100]

DEEP_PORTS = TOP_PORTS + [111, 427, 500, 623, 873, 902, 1080, 1883, 2000,
                          3260, 4443, 5000, 5060, 5343, 7001, 8000, 8008, 8081,
                          8088, 8090, 8181, 8888, 9200, 10000, 27017]

HTTP_PORTS = [80, 81, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888,
              9000, 9090, 10000]

SERVICE = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 80: "http", 88: "kerberos", 110: "pop3",
    111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "smb", 515: "lpd", 548: "afp",
    554: "rtsp", 587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    2375: "docker", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 5985: "winrm", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9000: "http-alt", 9100: "jetdirect", 9200: "elastic",
    27017: "mongodb",
}


# -----------------------------------------------------------------------------
# helpers
# -----------------------------------------------------------------------------
def sh(cmd, timeout=90):
    try:
        p = subprocess.run(cmd, shell=isinstance(cmd, str),
                           capture_output=True, text=True, timeout=timeout)
        return p.stdout or ""
    except Exception:
        return ""


def have(tool):
    return shutil.which(tool) is not None


def now():
    return datetime.now().isoformat(timespec="seconds")


def load_state():
    if not os.path.exists(STATE_FILE):
        return {"networks": {}}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"networks": {}}


def save_state(state):
    os.makedirs(STORE, exist_ok=True)
    try:
        os.chmod(STORE, 0o700)
    except Exception:
        pass
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, STATE_FILE)
    try:
        os.chmod(STATE_FILE, 0o600)
    except Exception:
        pass


def merge(dst, src):
    """Update dst from src, keeping old values when the new one is empty."""
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            merge(dst[k], v)
        elif isinstance(v, list) and isinstance(dst.get(k), list) and not v:
            continue
        elif v not in ("", None, [], {}):
            dst[k] = v


# -----------------------------------------------------------------------------
# interfaces
# -----------------------------------------------------------------------------
def ifaces():
    out = []
    for line in sh("ip -o -4 addr show scope global").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        out.append((parts[1].split("@")[0], parts[3]))
    return out


def pick_iface(name=None):
    for n, cidr in ifaces():
        if name and n != name:
            continue
        return n, cidr.split("/")[0], cidr
    return None, None, None


def subnet_base(ip):
    return ".".join(ip.split(".")[:3])


def gateway(iface):
    m = re.search(r"default via ([0-9.]+)", sh("ip route show default dev %s" % iface))
    return m.group(1) if m else ""


def ssid_of(iface):
    m = re.search(r"SSID: (.+)", sh("iw dev %s link" % iface))
    return m.group(1).strip() if m else ""


def wifi_security(iface):
    for line in sh("nmcli -t -f GENERAL.CONNECTION dev show %s" % iface).splitlines():
        if line.startswith("GENERAL.CONNECTION:"):
            return line.split(":", 1)[1]
    return ""


# -----------------------------------------------------------------------------
# scanning
# -----------------------------------------------------------------------------
def scan_aps(iface):
    aps = {}
    if have("nmcli"):
        out = sh("nmcli -t -f SSID,BSSID,CHAN,SIGNAL,SECURITY dev wifi list", 60)
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) < 5 or not parts[0]:
                continue
            aps[":".join(parts[1:-3])] = {
                "ssid": parts[0],
                "bssid": ":".join(parts[1:-3]),
                "channel": parts[-3],
                "signal": parts[-2],
                "security": parts[-1] or "OPEN",
            }
    if not aps and have("iw"):
        cur = {}
        for line in sh("iw dev %s scan" % iface, 60).splitlines():
            s = line.strip()
            if s.startswith("BSS "):
                if cur.get("bssid"):
                    aps[cur["bssid"]] = cur
                cur = {"bssid": s.split()[1].split("(")[0], "ssid": "",
                       "channel": "", "signal": "", "security": "OPEN"}
            elif s.startswith("SSID:"):
                cur["ssid"] = s.split(":", 1)[1].strip()
            elif s.startswith("signal:"):
                cur["signal"] = s.split(":", 1)[1].strip().split()[0]
            elif s.startswith("DS Parameter set: channel"):
                cur["channel"] = s.split()[-1]
            elif "RSN:" in s:
                cur["security"] = "WPA2"
        if cur.get("bssid"):
            aps[cur["bssid"]] = cur
    return list(aps.values())


def host_discovery(subnet, iface):
    hosts = {}
    if have("arp-scan"):
        out = sh("arp-scan --localnet --interface=%s --retry=1" % iface, 120)
        for line in out.splitlines():
            m = re.match(r"^([0-9.]+)\s+([0-9a-fA-F:]{17})\s*(.*)$", line)
            if m:
                hosts[m.group(1)] = {"ip": m.group(1),
                                     "mac": m.group(2).lower(),
                                     "vendor": m.group(3).strip()}
        if hosts:
            return hosts
    if have("nmap"):
        out = sh("nmap -sn -n -T4 %s.0/24" % subnet, 240)
        for line in out.splitlines():
            m = re.search(r"Nmap scan report for (?:([^ ]+) \()?([0-9.]+)\)?", line)
            if m:
                hosts[m.group(2)] = {"ip": m.group(2),
                                     "hostname": m.group(1) or "",
                                     "mac": "", "vendor": ""}
        return hosts
    for i in range(1, 255):
        ip = "%s.%d" % (subnet, i)
        if subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                          capture_output=True).returncode == 0:
            hosts[ip] = {"ip": ip, "mac": "", "vendor": ""}
    return hosts


def tcp_open(ip, port, timeout=0.6):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        s.close()


def scan_ports_nmap(ip, ports, deep):
    out = sh(["nmap", "-Pn", "-n", "-T4", "--open", "-oX", "-",
              "-p", ",".join(str(p) for p in ports), ip],
             300 if deep else 120)
    found = []
    try:
        root = ET.fromstring(out)
    except Exception:
        return found
    for host in root.findall("host"):
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is not None and state.get("state") == "open":
                num = int(port.get("portid"))
                svc = port.find("service")
                found.append({
                    "port": num,
                    "service": svc.get("name") if svc is not None
                    else SERVICE.get(num, ""),
                    "product": (svc.get("product") or "") if svc is not None else "",
                    "version": (svc.get("version") or "") if svc is not None else "",
                })
    return found


def smb_probe(ip, deep):
    if not have("nmap"):
        return {}
    script = "smb-os-discovery,smb2-security-mode"
    if deep:
        script += ",smb-enum-shares"
    out = sh(["nmap", "-Pn", "-n", "-p445", "--script", script, ip],
             180 if deep else 90)
    info = {}
    m = re.search(r"Domain name: (\S+)", out)
    if m:
        info["domain"] = m.group(1)
    m = re.search(r"OS: ([^\n]+)", out)
    if m:
        info["os"] = m.group(1).strip()
    m = re.search(r"Computer name: (\S+)", out)
    if m:
        info["hostname"] = m.group(1)
    if re.search(r"signing is required|signing enabled and required", out, re.I):
        info["signing"] = "required"
    elif re.search(r"signing enabled but not required|not required", out, re.I):
        info["signing"] = "not required"
    shares = []
    for m in re.finditer(r"^\|\s+(\S+):\s*\n\|\s+Anonymous access: (\w+)", out, re.M):
        shares.append({"name": m.group(1), "access": m.group(2)})
    if shares:
        info["shares"] = shares
    return info


def http_probe(ip, port):
    info = {"port": port}
    scheme = "https" if port in (443, 8443) else "http"
    url = "%s://%s:%d/" % (scheme, ip, port)
    try:
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(url, headers={"User-Agent": "netmap"})
        with urllib.request.urlopen(req, timeout=4, context=ctx) as r:
            body = r.read(20000).decode("utf-8", "replace")
            info["status"] = r.status
            info["server"] = r.headers.get("Server", "")
            m = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
            if m:
                info["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:90]
    except Exception as e:
        info["error"] = type(e).__name__
    if port in (443, 8443):
        try:
            ctx = ssl._create_unverified_context()
            with socket.create_connection((ip, port), timeout=4) as s:
                with ctx.wrap_socket(s) as tls:
                    cert = tls.getpeercert()
                    subj = dict(x[0] for x in cert.get("subject", []))
                    info["tls_cn"] = subj.get("commonName", "")
        except Exception:
            pass
    return info


def rdns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def guess_role(ports):
    if 88 in ports and 389 in ports:
        return "domain controller"
    if 445 in ports and 3389 in ports:
        return "windows workstation"
    if 445 in ports:
        return "file server / nas"
    if 9100 in ports or 631 in ports:
        return "printer"
    if 554 in ports:
        return "camera / nvr"
    if 80 in ports or 443 in ports:
        return "web device"
    if 22 in ports:
        return "unix host"
    return "unknown"


def scan_host(ip, deep):
    h = {"ip": ip, "ports": [], "last_seen": now()}
    name = rdns(ip)
    if name:
        h["hostname"] = name

    ports = DEEP_PORTS if deep else TOP_PORTS
    if have("nmap"):
        h["ports"] = scan_ports_nmap(ip, ports, deep)
    else:
        h["ports"] = [{"port": p, "service": SERVICE.get(p, "")}
                      for p in ports if tcp_open(ip, p)]

    nums = {p["port"] for p in h["ports"]}
    if 445 in nums:
        smb = smb_probe(ip, deep)
        if smb:
            h["smb"] = smb
    web = [http_probe(ip, p) for p in [x for x in nums if x in HTTP_PORTS][:4]]
    if web:
        h["web"] = web
    h["role"] = guess_role(nums)
    return h


def do_scan(iface=None, deep=False):
    name, ip, cidr = pick_iface(iface)
    if not name:
        print("netmap: no interface with an IPv4 address", file=sys.stderr)
        return None
    subnet = subnet_base(ip)

    print("netmap: %s (%s)  subnet %s.0/24" % (name, ip, subnet))
    print("netmap: access points...", flush=True)
    aps = scan_aps(name)

    print("netmap: hosts...", flush=True)
    hosts = host_discovery(subnet, name)

    print("netmap: probing %d host(s)%s" % (len(hosts), " deeply" if deep else ""))
    out = []
    for n, (hip, base) in enumerate(sorted(hosts.items()), 1):
        if hip == ip:
            continue
        sys.stdout.write("\r  %d/%d  %-15s" % (n, len(hosts), hip))
        sys.stdout.flush()
        h = scan_host(hip, deep)
        merge(h, base)
        out.append(h)
    print()

    ssid = ssid_of(name)
    net = {
        "key": ssid or "%s.0/24" % subnet,
        "ssid": ssid,
        "subnet": "%s.0/24" % subnet,
        "iface": {"iface": name, "ip": ip, "cidr": cidr,
                  "gateway": gateway(name), "ssid": ssid,
                  "security": wifi_security(name)},
        "aps": aps,
        "hosts": out,
        "scanned": now(),
    }
    print("netmap: %d access point(s), %d host(s)" % (len(aps), len(out)))
    return net


# -----------------------------------------------------------------------------
# rules — what is worth attacking, and why
# -----------------------------------------------------------------------------
def rule(score, title, why, noise, command, tool):
    return {"score": round(score, 2), "title": title, "why": why,
            "noise": noise, "command": command, "tool": tool}


def security_kind(sec):
    s = (sec or "").upper()
    if not s or s in ("--", "OPEN"):
        return "open"
    if "802.1X" in s or "EAP" in s or "ENTERPRISE" in s:
        return "enterprise"
    if "WPA3" in s:
        return "wpa3"
    if "WEP" in s:
        return "wep"
    if "WPA" in s:
        return "psk"
    return "other"


def analyse(net):
    out = []
    hosts = net.get("hosts", [])
    aps = net.get("aps", [])
    own = security_kind(net.get("iface", {}).get("security"))

    kinds = {}
    for ap in aps:
        k = security_kind(ap.get("security"))
        kinds[k] = kinds.get(k, 0) + 1

    if own == "open" or kinds.get("open"):
        out.append(rule(
            0.95, "Evil twin + captive portal",
            "the network is open; a clone needs no key and the portal harvests "
            "logins",
            "medium", "sudo twinstart", "twinops"))
    if own == "wep" or kinds.get("wep"):
        out.append(rule(
            0.90, "WEP cracks in minutes",
            "WEP is broken by design; any capture yields the key",
            "low", "aircrack-ng", "aircrack"))
    if own == "enterprise" or kinds.get("enterprise"):
        out.append(rule(
            0.85, "Rogue RADIUS (802.1X twin)",
            "WPA2-Enterprise is in use; clients often skip certificate checks, "
            "so a fake AP collects MSCHAPv2 that cracks offline",
            "medium", "eaphammer -i wlan0 --auth wpa-eap --creds", "eaphammer"))
    if own == "psk" or kinds.get("psk"):
        out.append(rule(
            0.70, "Capture the WPA2 handshake",
            "PSK network; capture an EAPOL exchange or PMKID and crack offline",
            "low", "aireplay-ng --deauth 5 ... + hashcat -m 22000", "aircrack"))

    dcs = [h for h in hosts if h.get("role") == "domain controller" or
           {p["port"] for p in h.get("ports", [])} >= {88, 389}]
    if dcs:
        out.append(rule(
            0.90, "Enumerate users, then roast",
            "a DC is reachable; user enumeration and AS-REP/Kerberoast need no "
            "credentials at all",
            "low", "kerbrute userenum + impacket-GetNPUsers", "impacket"))
        out.append(rule(
            0.88, "NTLM relay chain (rbcd)",
            "DC present and machines authenticate on their own; relay one and "
            "abuse RBCD for local admin",
            "medium", "sudo dcraidstart --profile stealth", "dcraid"))

    relayable = [h for h in hosts
                 if any(p["port"] == 445 for p in h.get("ports", []))
                 and h.get("smb", {}).get("signing") == "not required"]
    if relayable:
        out.append(rule(
            min(0.95, 0.6 + 0.1 * len(relayable)),
            "SMB relay open on %d host(s)" % len(relayable),
            "signing is enabled but not required on " +
            ", ".join(h["ip"] for h in relayable[:3]),
            "medium", "sudo dcraid --mode relay", "dcraid"))

    readable = [(h["ip"], s["name"]) for h in hosts
                for s in h.get("smb", {}).get("shares", [])
                if s.get("access", "").lower().startswith("read")]
    if readable:
        out.append(rule(
            0.92, "Shares readable without credentials (%d)" % len(readable),
            ", ".join("%s/%s" % x for x in readable[:4]),
            "low", "sudo sharestart", "sharestart"))

    panels = []
    for h in hosts:
        for w in h.get("web", []):
            t = (w.get("title", "") + " " + w.get("server", "")).lower()
            if any(k in t for k in ("router", "admin", "login", "camera",
                                    "printer", "nas", "jenkins", "grafana",
                                    "kibana", "tomcat", "phpmyadmin")):
                panels.append("%s:%s %s" % (h["ip"], w["port"],
                                            w.get("title", "")[:28]))
    if panels:
        out.append(rule(
            0.80, "Admin panels, try default logins (%d)" % len(panels),
            ", ".join(panels[:3]),
            "high", "sudo panelstart", "panelstart"))

    if any(any(p["port"] == 161 for p in h.get("ports", [])) for h in hosts):
        out.append(rule(
            0.60, "SNMP community strings",
            "161 is open; public/private often dumps device config, users and "
            "plaintext passwords",
            "low", "snmpwalk -v2c -c public <host>", "snmpwalk"))

    if any(any(p["port"] in (9100, 631) for p in h.get("ports", []))
           for h in hosts):
        out.append(rule(
            0.55, "Printer file access",
            "a printer is exposed; PJL can list and fetch stored documents and "
            "address books",
            "low", "printerkit <host>", "printerkit"))

    if any(any(p["port"] == 554 for p in h.get("ports", [])) for h in hosts):
        out.append(rule(
            0.50, "Camera stream",
            "RTSP is open; many cameras still answer to default credentials",
            "medium", "ffplay rtsp://<host>/", "ffmpeg"))

    if any(any(p["port"] == 3389 for p in h.get("ports", [])) for h in hosts):
        out.append(rule(
            0.45, "RDP exposed",
            "3389 is open; any valid account is a direct desktop",
            "high", "xfreerdp /v:<host>", "freerdp"))

    if not hosts:
        out.append(rule(
            0.10, "Nothing answered",
            "no hosts responded - client isolation, or a portal blocking "
            "east-west traffic",
            "low", "compare with twinstart", "twinops"))

    out.sort(key=lambda r: r["score"], reverse=True)
    return out


# -----------------------------------------------------------------------------
# storage
# -----------------------------------------------------------------------------
def store_scan(net):
    state = load_state()
    nets = state.setdefault("networks", {})
    key = net["key"]
    if key in nets:
        old = nets[key]
        merge(old, {k: v for k, v in net.items() if k not in ("hosts", "aps")})
        by_ip = {h["ip"]: h for h in old.get("hosts", [])}
        for h in net["hosts"]:
            if h["ip"] in by_ip:
                merge(by_ip[h["ip"]], h)
            else:
                by_ip[h["ip"]] = h
        old["hosts"] = list(by_ip.values())
        by_bssid = {a["bssid"]: a for a in old.get("aps", [])}
        for a in net["aps"]:
            by_bssid[a["bssid"]] = a
        old["aps"] = list(by_bssid.values())
        old["scanned"] = net["scanned"]
    else:
        nets[key] = net
    nets[key]["attacks"] = analyse(nets[key])
    save_state(state)
    return nets[key]


# -----------------------------------------------------------------------------
# text output
# -----------------------------------------------------------------------------
def bar(score, width=10):
    n = int(round(score * width))
    return "█" * n + "·" * (width - n)


def show(key=None):
    nets = load_state().get("networks", {})
    if not nets:
        print("netmap: nothing scanned yet. run: netmap scan")
        return
    for k in ([key] if key else sorted(nets)):
        n = nets.get(k)
        if not n:
            continue
        print("=" * 78)
        print("%s   %s   %s" % (k, n.get("subnet", ""), n.get("scanned", "")))
        i = n.get("iface", {})
        print("iface %s  ip %s  gw %s  security %s" % (
            i.get("iface", "?"), i.get("ip", "?"), i.get("gateway", "?"),
            i.get("security", "?")))
        print("\naccess points")
        for a in n.get("aps", [])[:12]:
            print("  %-30s %-18s ch%-3s %-4s %s" % (
                a.get("ssid", "")[:30], a.get("bssid", ""), a.get("channel", ""),
                a.get("signal", ""), a.get("security", "")))
        print("\nhosts")
        for h in sorted(n.get("hosts", []), key=lambda x: x["ip"]):
            ports = ",".join(str(p["port"]) for p in h.get("ports", [])[:10])
            print("  %-15s %-17s %-24s %s" % (
                h.get("ip"), h.get("mac", "-"),
                (h.get("hostname") or h.get("role", ""))[:24], ports))
        print("\nattacks")
        for r in n.get("attacks", []):
            print("  %s %3d%%  %-38s %s" % (bar(r["score"]),
                                            int(r["score"] * 100),
                                            r["title"][:38], r["noise"]))
            print("         %s" % r["why"])
            print("         -> %s" % r["command"])


def export():
    if not load_state().get("networks"):
        print("nothing to export")
        return
    os.makedirs(os.path.join(STORE, "exports"), exist_ok=True)
    path = os.path.join(STORE, "exports",
                        "netmap-%s.txt" % datetime.now().strftime("%Y%m%d-%H%M%S"))
    real = sys.stdout

    class Tee:
        def __init__(self, f):
            self.f = f

        def write(self, s):
            self.f.write(s)
            real.write(s)

        def flush(self):
            self.f.flush()

    with open(path, "w", encoding="utf-8") as f:
        sys.stdout = Tee(f)
        try:
            show()
        finally:
            sys.stdout = real
    print("\nwritten: %s" % path)


# -----------------------------------------------------------------------------
# dashboard
# -----------------------------------------------------------------------------
def wide(text):
    """Clip a string to the number of terminal cells it occupies."""
    out = []
    cells = 0
    for ch in text:
        w = 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        if cells + w > 200:
            break
        out.append(ch)
        cells += w
    return "".join(out)


class Dash:
    def __init__(self, scr):
        self.s = scr
        self.state = load_state()
        self.keys = sorted(self.state.get("networks", {}))
        self.ni = 0
        self.hi = 0
        self.view = "hosts"
        self.msg = ""

    def put(self, y, x, text, attr=0):
        h, w = self.s.getmaxyx()
        if y < 0 or y >= h - 0 or x >= w - 1:
            return
        text = wide(str(text))[:max(0, w - x - 1)]
        try:
            self.s.addstr(y, x, text, attr)
        except curses.error:
            pass

    def draw(self):
        self.s.erase()
        h, w = self.s.getmaxyx()
        self.put(0, 1, " netmap ", curses.A_BOLD | curses.A_REVERSE)
        net = self.state["networks"][self.keys[self.ni]] if self.keys else None
        if net:
            self.put(0, 10, "%s   %s   %d hosts   %s" % (
                net.get("key", ""), net.get("subnet", ""),
                len(net.get("hosts", [])), net.get("scanned", "")[:16]))
        self.put(0, max(0, w - 28), "q quit  s scan  e export", curses.A_DIM)

        self.put(2, 1, "NETWORKS", curses.A_BOLD)
        for i, k in enumerate(self.keys[:max(3, (h - 6) // 3)]):
            n = self.state["networks"][k]
            attr = curses.A_REVERSE if i == self.ni else 0
            self.put(3 + i, 1, "%-28s %2d hosts" % (k[:28], len(n.get("hosts", []))),
                     attr)

        if not net:
            self.put(h - 2, 1, "nothing scanned yet - press s")
            self.s.refresh()
            return

        left = 40
        self.put(2, left, "HOSTS" + ("  (selected)" if self.view == "hosts" else ""),
                 curses.A_BOLD)
        hosts = sorted(net.get("hosts", []),
                       key=lambda x: tuple(int(p) for p in x["ip"].split(".")))
        avail = max(3, h - 12)
        for i, hst in enumerate(hosts[:avail]):
            attr = curses.A_REVERSE if (self.view == "hosts" and i == self.hi) else 0
            ports = ",".join(str(p["port"]) for p in hst.get("ports", [])[:7])
            self.put(3 + i, left, "%-15s %-17s %-20s %s" % (
                hst.get("ip", ""), hst.get("mac") or "-",
                (hst.get("hostname") or hst.get("role") or "")[:20], ports), attr)

        ay = 3 + min(len(hosts), avail) + 1
        self.put(ay, left, "ATTACKS - ranked by fit" +
                 ("  (selected)" if self.view == "attacks" else ""), curses.A_BOLD)
        attacks = net.get("attacks", [])
        for i, r in enumerate(attacks[:max(2, h - ay - 4)]):
            attr = curses.A_REVERSE if (self.view == "attacks" and i == self.hi) else 0
            self.put(ay + 1 + i, left, "%s %3d%%  %-34s %s" % (
                bar(r["score"]), int(r["score"] * 100), r["title"][:34],
                r["noise"]), attr)

        if self.view == "attacks" and attacks:
            r = attacks[min(self.hi, len(attacks) - 1)]
            self.put(h - 3, 1, r["why"], curses.A_DIM)
            self.put(h - 2, 1, "  -> " + r["command"], curses.A_BOLD)
        elif hosts:
            hst = hosts[min(self.hi, len(hosts) - 1)]
            smb = hst.get("smb", {})
            web = "  ".join("%s %s" % (x.get("port"), (x.get("title") or "")[:20])
                            for x in hst.get("web", [])[:2])
            self.put(h - 3, 1, "domain %s   signing %s   %s" % (
                smb.get("domain", "-"), smb.get("signing", "-"), web), curses.A_DIM)
            self.put(h - 2, 1, "ports: " + ",".join(
                str(p["port"]) for p in hst.get("ports", [])), curses.A_DIM)

        if self.msg:
            self.put(h - 1, 1, self.msg, curses.A_BOLD)
        self.s.refresh()

    def rescan(self):
        curses.endwin()
        print("\nnetmap: rescanning...")
        net = do_scan()
        if net:
            store_scan(net)
            self.state = load_state()
            self.keys = sorted(self.state.get("networks", {}))
            self.msg = "rescanned %s" % net["key"]
        input("\npress enter to return")
        self.s.refresh()

    def loop(self):
        curses.curs_set(0)
        self.s.keypad(True)
        while True:
            self.draw()
            k = self.s.getch()
            if k in (ord("q"), 27):
                return
            if k in (curses.KEY_UP, ord("k")) and self.hi > 0:
                self.hi -= 1
            elif k in (curses.KEY_DOWN, ord("j")):
                self.hi += 1
            elif k in (curses.KEY_LEFT, ord("h")):
                self.view, self.hi = "hosts", 0
            elif k in (curses.KEY_RIGHT, ord("l"), 9):
                self.view, self.hi = "attacks", 0
            elif k == ord("s"):
                self.rescan()
            elif k == ord("e"):
                curses.endwin()
                export()
                input("\npress enter")
                self.s.refresh()
            elif k in (ord("n"), ord("p")) and len(self.keys) > 1:
                self.ni = (self.ni + (1 if k == ord("n") else -1)) % len(self.keys)
                self.hi = 0


def dash():
    curses.wrapper(lambda scr: Dash(scr).loop())


# -----------------------------------------------------------------------------
# main
# -----------------------------------------------------------------------------
def main(argv):
    if not os.path.isdir(STORE):
        os.makedirs(STORE, exist_ok=True)

    if not argv:
        net = do_scan()
        if net:
            store_scan(net)
        try:
            dash()
        except Exception as e:
            print("netmap: dashboard failed (%s) - try: netmap show" % e)
        return 0

    cmd = argv[0]
    if cmd == "scan":
        deep = "--deep" in argv
        iface = None
        if "--iface" in argv:
            i = argv.index("--iface")
            if i + 1 < len(argv):
                iface = argv[i + 1]
        net = do_scan(iface, deep)
        if net:
            n = store_scan(net)
            print("\ntop matches for %s:" % n["key"])
            for r in n["attacks"][:6]:
                print("  %3d%%  %-38s %-7s  %s" % (
                    int(r["score"] * 100), r["title"][:38], r["noise"],
                    r["command"]))
        return 0
    if cmd == "dash":
        dash()
        return 0
    if cmd == "show":
        show(argv[1] if len(argv) > 1 else None)
        return 0
    if cmd == "export":
        export()
        return 0
    print("usage: netmap [scan|dash|show|export]")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\nnetmap: stopped")
        sys.exit(130)
