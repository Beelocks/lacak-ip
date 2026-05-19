#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║           IP INTELLIGENCE TRACKER - POWERFUL OSINT ANALYZER             ║
║                        Version 2.0 - Full Edition                       ║
╚══════════════════════════════════════════════════════════════════════════╝

Fitur:
  - Multi-source geolokasi (ip-api, ipinfo, ipwho)
  - Deteksi VPN / Proxy / TOR / Hosting / Datacenter
  - Abuse IP Database check
  - WHOIS lookup
  - Reverse DNS
  - Port scanning (common ports)
  - ASN & Routing info
  - Risk scoring otomatis
  - Laporan detail (terminal & file)
  - Export: JSON, TXT, HTML

Instalasi dependensi:
  pip install requests colorama dnspython python-whois tabulate

Penggunaan:
  python ip_tracker.py
  python ip_tracker.py --ip 8.8.8.8
  python ip_tracker.py --ip 8.8.8.8 --scan-ports --export html
  python ip_tracker.py --file targets.txt --export json
"""

import argparse
import json
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ─── Dependency check ────────────────────────────────────────────────────────
try:
    import requests
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    class Fore:
        GREEN = RED = YELLOW = CYAN = MAGENTA = WHITE = BLUE = RESET = ''
    class Style:
        BRIGHT = DIM = RESET_ALL = ''

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import whois as whois_lib
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False


# ─── Konfigurasi API ──────────────────────────────────────────────────────────
API_CONFIG = {
    # Gratis, tidak perlu API key (rate limit: 45 req/menit)
    "ip_api": {
        "url": "http://ip-api.com/json/{ip}",
        "params": "?fields=status,message,continent,continentCode,country,countryCode,"
                  "region,regionName,city,district,zip,lat,lon,timezone,offset,"
                  "currency,isp,org,as,asname,query,proxy,vpn,tor,hosting,mobile",
        "requires_key": False,
    },
    # Gratis tier: 50.000 req/bulan — daftar di ipinfo.io
    "ipinfo": {
        "url": "https://ipinfo.io/{ip}/json",
        "token_param": "?token={key}",
        "requires_key": True,
        "key": os.environ.get("IPINFO_KEY", ""),   # set env var atau isi di sini
    },
    # Gratis, tidak perlu API key
    "ipwho": {
        "url": "https://ipwho.is/{ip}",
        "requires_key": False,
    },
    # Gratis tier: 1.000 req/hari — daftar di abuseipdb.com
    "abuseipdb": {
        "url": "https://api.abuseipdb.com/api/v2/check",
        "requires_key": True,
        "key": os.environ.get("ABUSEIPDB_KEY", ""),  # set env var atau isi di sini
    },
}

# Port umum untuk scanning
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

TIMEOUT = 5  # detik


# ─── Utilitas Terminal ────────────────────────────────────────────────────────
def banner():
    print(Fore.GREEN + Style.BRIGHT + r"""
██╗██████╗     ████████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗
██║██╔══██╗    ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
██║██████╔╝       ██║   ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝
██║██╔═══╝        ██║   ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
██║██║            ██║   ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
╚═╝╚═╝            ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
    """ + Style.RESET_ALL)
    print(Fore.CYAN + "      IP INTELLIGENCE TRACKER v2.0  |  OSINT Multi-Source Analyzer")
    print(Fore.WHITE + Style.DIM + "      " + "─" * 62)
    print()


def cprint(text, color=Fore.WHITE, bold=False, prefix=""):
    style = Style.BRIGHT if bold else ""
    print(f"{color}{style}{prefix}{text}{Style.RESET_ALL}")


def section(title):
    width = 62
    line = "─" * width
    print()
    print(Fore.CYAN + Style.BRIGHT + f"  ┌{line}┐")
    print(Fore.CYAN + Style.BRIGHT + f"  │  {title:<{width - 2}}│")
    print(Fore.CYAN + Style.BRIGHT + f"  └{line}┘")


def kv(label, value, label_color=Fore.YELLOW, value_color=Fore.WHITE, indent=4):
    spaces = " " * indent
    print(f"{spaces}{label_color}{label:<22}{Style.RESET_ALL}: {value_color}{value}{Style.RESET_ALL}")


def status(msg, kind="info"):
    icons = {"info": "ℹ", "ok": "✔", "err": "✘", "warn": "⚠", "scan": "◉"}
    colors = {
        "info": Fore.CYAN,
        "ok": Fore.GREEN,
        "err": Fore.RED,
        "warn": Fore.YELLOW,
        "scan": Fore.MAGENTA,
    }
    icon = icons.get(kind, "•")
    color = colors.get(kind, Fore.WHITE)
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"  {Fore.WHITE + Style.DIM}[{ts}]{Style.RESET_ALL} {color}{icon} {msg}{Style.RESET_ALL}")


def risk_bar(score, width=30):
    filled = int(score / 100 * width)
    empty = width - filled
    if score < 30:
        color = Fore.GREEN
    elif score < 60:
        color = Fore.YELLOW
    else:
        color = Fore.RED
    bar = color + "█" * filled + Style.DIM + "░" * empty + Style.RESET_ALL
    return f"[{bar}] {color}{score}%{Style.RESET_ALL}"


# ─── Validasi IP ──────────────────────────────────────────────────────────────
def is_valid_ip(ip: str) -> bool:
    ipv4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    ipv6 = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")
    return bool(ipv4.match(ip) or ipv6.match(ip))


def resolve_domain(domain: str) -> str | None:
    """Resolusi domain ke IP."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


# ─── Fetcher API ──────────────────────────────────────────────────────────────
def fetch_ip_api(ip: str) -> dict:
    """ip-api.com — geolokasi + proxy/vpn/tor/hosting (gratis)."""
    cfg = API_CONFIG["ip_api"]
    url = cfg["url"].format(ip=ip) + cfg["params"]
    try:
        r = requests.get(url, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"_error": str(e), "_source": "ip-api.com"}


def fetch_ipwho(ip: str) -> dict:
    """ipwho.is — geolokasi backup (gratis, tanpa key)."""
    url = API_CONFIG["ipwho"]["url"].format(ip=ip)
    try:
        r = requests.get(url, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"_error": str(e), "_source": "ipwho.is"}


def fetch_ipinfo(ip: str) -> dict:
    """ipinfo.io — geolokasi presisi tinggi (perlu API key)."""
    cfg = API_CONFIG["ipinfo"]
    if not cfg["key"]:
        return {"_skipped": "IPINFO_KEY tidak diset"}
    url = cfg["url"].format(ip=ip) + cfg["token_param"].format(key=cfg["key"])
    try:
        r = requests.get(url, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"_error": str(e), "_source": "ipinfo.io"}


def fetch_abuseipdb(ip: str) -> dict:
    """AbuseIPDB — cek reputasi & laporan abuse (perlu API key)."""
    cfg = API_CONFIG["abuseipdb"]
    if not cfg["key"]:
        return {"_skipped": "ABUSEIPDB_KEY tidak diset"}
    headers = {"Key": cfg["key"], "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
    try:
        r = requests.get(cfg["url"], headers=headers, params=params, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json().get("data", {})
    except Exception as e:
        return {"_error": str(e), "_source": "abuseipdb.com"}


def fetch_reverse_dns(ip: str) -> str:
    """Reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "—"


def fetch_whois(ip: str) -> dict:
    """WHOIS lookup (butuh python-whois)."""
    if not HAS_WHOIS:
        return {"_skipped": "python-whois tidak terinstall"}
    try:
        w = whois_lib.whois(ip)
        return {
            "registrar": getattr(w, "registrar", None) or "—",
            "creation_date": str(getattr(w, "creation_date", None) or "—"),
            "expiration_date": str(getattr(w, "expiration_date", None) or "—"),
            "name_servers": getattr(w, "name_servers", None) or [],
            "emails": getattr(w, "emails", None) or [],
            "org": getattr(w, "org", None) or "—",
            "country": getattr(w, "country", None) or "—",
        }
    except Exception as e:
        return {"_error": str(e)}


def scan_port(ip: str, port: int) -> tuple[int, bool, str]:
    """Cek apakah satu port terbuka."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port, result == 0, COMMON_PORTS.get(port, "Unknown")
    except Exception:
        return port, False, COMMON_PORTS.get(port, "Unknown")


def scan_ports(ip: str, ports: dict = COMMON_PORTS, max_workers: int = 50) -> list[dict]:
    """Scan port secara paralel."""
    results = []
    status(f"Memindai {len(ports)} port umum pada {ip}...", "scan")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, ip, p): p for p in ports}
        for future in as_completed(futures):
            port, is_open, service = future.result()
            results.append({"port": port, "open": is_open, "service": service})
    return sorted(results, key=lambda x: x["port"])


# ─── Scoring Risiko ───────────────────────────────────────────────────────────
def calculate_risk(data: dict) -> dict:
    """Hitung skor risiko 0–100 berdasarkan semua indikator."""
    score = 0
    flags = []
    reasons = []

    ip_data = data.get("ip_api", {})
    abuse_data = data.get("abuseipdb", {})

    if ip_data.get("proxy"):
        score += 25
        flags.append("PROXY")
        reasons.append("IP terdeteksi sebagai proxy server")
    if ip_data.get("vpn"):
        score += 25
        flags.append("VPN")
        reasons.append("IP terdeteksi sebagai node VPN")
    if ip_data.get("tor"):
        score += 35
        flags.append("TOR")
        reasons.append("IP adalah node jaringan TOR — anonymity tinggi")
    if ip_data.get("hosting"):
        score += 10
        flags.append("HOSTING")
        reasons.append("IP berasal dari datacenter/hosting provider")
    if ip_data.get("mobile"):
        flags.append("MOBILE")
        reasons.append("Koneksi via jaringan seluler")

    abuse_score = abuse_data.get("abuseConfidenceScore", 0)
    if isinstance(abuse_score, int):
        if abuse_score > 75:
            score += 30
            flags.append("ABUSE-HIGH")
            reasons.append(f"Skor abuse tinggi: {abuse_score}%")
        elif abuse_score > 25:
            score += 15
            flags.append("ABUSE-MED")
            reasons.append(f"Skor abuse sedang: {abuse_score}%")

    open_ports = [p for p in data.get("ports", []) if p["open"]]
    dangerous = {22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC"}
    found_dangerous = [s for p in open_ports if (s := dangerous.get(p["port"]))]
    if found_dangerous:
        score += min(15, len(found_dangerous) * 5)
        flags.append("EXPOSED-PORTS")
        reasons.append(f"Port sensitif terbuka: {', '.join(found_dangerous)}")

    score = min(score, 100)

    if score < 20:
        level = "RENDAH"
        level_color = Fore.GREEN
    elif score < 50:
        level = "SEDANG"
        level_color = Fore.YELLOW
    elif score < 75:
        level = "TINGGI"
        level_color = Fore.RED
    else:
        level = "KRITIS"
        level_color = Fore.RED + Style.BRIGHT

    return {
        "score": score,
        "level": level,
        "level_color": level_color,
        "flags": flags,
        "reasons": reasons,
        "abuse_score": abuse_score if isinstance(abuse_score, int) else 0,
    }


# ─── Tampilan Laporan ─────────────────────────────────────────────────────────
def print_report(ip: str, data: dict, risk: dict):
    """Cetak laporan lengkap ke terminal."""

    ip_d = data.get("ip_api", {})
    ipwho_d = data.get("ipwho", {})
    abuse_d = data.get("abuseipdb", {})
    whois_d = data.get("whois", {})
    ports = data.get("ports", [])
    rdns = data.get("rdns", "—")
    report_id = f"RPT-{int(time.time())}"
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Header laporan ──────────────────────────────────────────────────────
    print()
    print(Fore.WHITE + Style.BRIGHT + "  " + "═" * 62)
    print(Fore.WHITE + Style.BRIGHT + f"  {'LAPORAN INTELIJEN IP':^62}")
    print(Fore.WHITE + Style.BRIGHT + "  " + "═" * 62)
    print(Fore.WHITE + Style.DIM + f"  Laporan ID : {report_id}")
    print(Fore.WHITE + Style.DIM + f"  Dibuat     : {ts}")
    print(Fore.WHITE + Style.DIM + f"  Target     : {ip}")

    # ── 1. Identitas IP ─────────────────────────────────────────────────────
    section("1. IDENTITAS IP")
    kv("IP Address", ip_d.get("query", ip), Fore.YELLOW, Fore.WHITE + Style.BRIGHT)
    kv("Reverse DNS", rdns)
    kv("Tipe IP", "IPv6" if ":" in ip else "IPv4")

    # ── 2. Geolokasi ────────────────────────────────────────────────────────
    section("2. GEOLOKASI")
    kv("Negara", f"{ip_d.get('country','—')} ({ip_d.get('countryCode','—')})")
    kv("Kontinen", f"{ip_d.get('continent','—')} ({ip_d.get('continentCode','—')})")
    kv("Provinsi/Region", ip_d.get("regionName", "—"))
    kv("Kota", ip_d.get("city", "—"))
    kv("Kode Pos", ip_d.get("zip", "—"))
    kv("Koordinat GPS", f"{ip_d.get('lat','—')}, {ip_d.get('lon','—')}")
    kv("Zona Waktu", ip_d.get("timezone", "—"))
    kv("Mata Uang", ip_d.get("currency", "—"))

    # Cross-check dengan ipwho jika berbeda
    if ipwho_d and not ipwho_d.get("_error"):
        ipwho_city = ipwho_d.get("city", "")
        ipwho_country = ipwho_d.get("country", "")
        if ipwho_city and ipwho_city != ip_d.get("city"):
            kv("  ↳ ipwho.is (alt)", f"{ipwho_city}, {ipwho_country}", Fore.WHITE + Style.DIM, Fore.WHITE + Style.DIM)

    # ── 3. Jaringan & ASN ───────────────────────────────────────────────────
    section("3. JARINGAN & ASN")
    kv("ISP", ip_d.get("isp", "—"))
    kv("Organisasi", ip_d.get("org", "—"))
    kv("Autonomous System", ip_d.get("as", "—"))
    kv("Nama AS", ip_d.get("asname", "—"))
    kv("Koneksi Mobile", "Ya ✔" if ip_d.get("mobile") else "Tidak")
    kv("Tipe Jaringan", "Datacenter/Cloud" if ip_d.get("hosting") else
       ("Seluler" if ip_d.get("mobile") else "Residensial/Korporat"))

    # ipinfo tambahan jika ada
    ipinfo_d = data.get("ipinfo", {})
    if ipinfo_d and not ipinfo_d.get("_skipped") and not ipinfo_d.get("_error"):
        kv("  ↳ ipinfo.io org", ipinfo_d.get("org", "—"), Fore.WHITE + Style.DIM, Fore.WHITE + Style.DIM)
        kv("  ↳ ipinfo.io hostname", ipinfo_d.get("hostname", "—"), Fore.WHITE + Style.DIM, Fore.WHITE + Style.DIM)

    # ── 4. Indikator Keamanan ───────────────────────────────────────────────
    section("4. INDIKATOR KEAMANAN")

    indicators = [
        ("Proxy Server", ip_d.get("proxy", False)),
        ("VPN Node", ip_d.get("vpn", False)),
        ("TOR Exit Node", ip_d.get("tor", False)),
        ("Hosting/Datacenter", ip_d.get("hosting", False)),
    ]
    for name, val in indicators:
        status_str = (Fore.RED + "⚠  TERDETEKSI") if val else (Fore.GREEN + "✔  Bersih")
        kv(name, status_str + Style.RESET_ALL)

    # ── 5. Reputasi & Abuse ─────────────────────────────────────────────────
    section("5. REPUTASI & LAPORAN ABUSE")
    if abuse_d.get("_skipped"):
        cprint("  AbuseIPDB tidak aktif — set ABUSEIPDB_KEY untuk menggunakan fitur ini",
               Fore.WHITE + Style.DIM)
    elif abuse_d.get("_error"):
        cprint(f"  Error: {abuse_d['_error']}", Fore.RED + Style.DIM)
    else:
        abuse_score = abuse_d.get("abuseConfidenceScore", 0)
        total_reports = abuse_d.get("totalReports", 0)
        last_reported = abuse_d.get("lastReportedAt", "—") or "—"
        is_public = abuse_d.get("isPublic", "—")
        domain = abuse_d.get("domain", "—")
        usage_type = abuse_d.get("usageType", "—")

        abuse_color = Fore.RED if abuse_score > 75 else (Fore.YELLOW if abuse_score > 25 else Fore.GREEN)
        kv("Skor Kepercayaan Abuse", f"{abuse_color}{abuse_score}%{Style.RESET_ALL}")
        kv("Total Laporan Abuse", str(total_reports))
        kv("Terakhir Dilaporkan", str(last_reported)[:19])
        kv("IP Publik", "Ya" if is_public else "Tidak")
        kv("Domain", domain)
        kv("Tipe Penggunaan", usage_type)

        if abuse_d.get("reports"):
            print()
            cprint("    Riwayat 5 Laporan Terakhir:", Fore.YELLOW, bold=True)
            for rep in abuse_d["reports"][:5]:
                ts_rep = str(rep.get("reportedAt", ""))[:10]
                cats = rep.get("categories", [])
                comment = str(rep.get("comment", ""))[:60]
                print(f"    {Fore.WHITE + Style.DIM}{ts_rep}  "
                      f"{Fore.RED}cats:{cats}  "
                      f"{Fore.WHITE + Style.DIM}{comment}{Style.RESET_ALL}")

    # ── 6. WHOIS ────────────────────────────────────────────────────────────
    section("6. WHOIS INFO")
    if whois_d.get("_skipped"):
        cprint("  WHOIS tidak aktif — install python-whois", Fore.WHITE + Style.DIM)
    elif whois_d.get("_error"):
        cprint(f"  WHOIS error: {whois_d['_error']}", Fore.RED + Style.DIM)
    else:
        kv("Registrar", str(whois_d.get("registrar", "—"))[:60])
        kv("Organisasi", str(whois_d.get("org", "—"))[:60])
        kv("Negara (WHOIS)", str(whois_d.get("country", "—")))
        kv("Tanggal Dibuat", str(whois_d.get("creation_date", "—"))[:25])
        kv("Kadaluarsa", str(whois_d.get("expiration_date", "—"))[:25])
        ns = whois_d.get("name_servers", [])
        if ns:
            kv("Name Servers", ", ".join(list(ns)[:3]) if isinstance(ns, (list, set)) else str(ns))

    # ── 7. Port Scanning ────────────────────────────────────────────────────
    section("7. PORT SCANNING")
    if not ports:
        cprint("  Port scanning tidak dijalankan (tambah flag --scan-ports)", Fore.WHITE + Style.DIM)
    else:
        open_ports = [p for p in ports if p["open"]]
        closed_ports = [p for p in ports if not p["open"]]
        cprint(f"  Total dipindai  : {len(ports)} port", Fore.WHITE)
        cprint(f"  Port terbuka    : {Fore.GREEN}{len(open_ports)}{Style.RESET_ALL}", Fore.WHITE)
        cprint(f"  Port tertutup   : {Fore.WHITE + Style.DIM}{len(closed_ports)}{Style.RESET_ALL}", Fore.WHITE)
        print()
        if open_ports:
            cprint("  Port Terbuka:", Fore.GREEN, bold=True)
            for p in open_ports:
                is_dangerous = p["port"] in [22, 23, 3389, 5900, 1433, 5432, 27017]
                color = Fore.RED if is_dangerous else Fore.GREEN
                warn = "  ⚠ SENSITIF" if is_dangerous else ""
                print(f"    {color}[OPEN]  {p['port']:<6}  {p['service']:<15}{warn}{Style.RESET_ALL}")
        else:
            cprint("  Tidak ada port terbuka yang ditemukan", Fore.GREEN)

    # ── 8. Skor Risiko ──────────────────────────────────────────────────────
    section("8. SKOR RISIKO & REKOMENDASI")
    risk_color = risk["level_color"]
    print(f"\n    Skor Keamanan  : {risk_bar(risk['score'])}")
    print(f"    Tingkat Risiko : {risk_color}{Style.BRIGHT}{risk['level']}{Style.RESET_ALL}")

    if risk["flags"]:
        print()
        cprint("  Faktor Risiko Aktif:", Fore.YELLOW, bold=True)
        for flag in risk["flags"]:
            f_color = Fore.RED if flag not in ["MOBILE", "HOSTING"] else Fore.YELLOW
            print(f"    {f_color}▶ {flag}{Style.RESET_ALL}")

    if risk["reasons"]:
        print()
        cprint("  Detail Temuan:", Fore.WHITE, bold=True)
        for reason in risk["reasons"]:
            print(f"    {Fore.WHITE + Style.DIM}• {reason}{Style.RESET_ALL}")

    print()
    cprint("  Rekomendasi:", Fore.CYAN, bold=True)
    if risk["score"] < 20:
        cprint("  ✔ IP tampak bersih. Tidak ada tindakan khusus diperlukan.", Fore.GREEN)
    elif risk["score"] < 50:
        cprint("  ⚠ Pantau aktivitas dari IP ini. Terapkan logging.", Fore.YELLOW)
    elif risk["score"] < 75:
        cprint("  ⚠ Pertimbangkan untuk memblokir IP ini di firewall.", Fore.RED)
    else:
        cprint("  ✘ Risiko KRITIS — segera blokir & laporkan ke AbuseIPDB!", Fore.RED + Style.BRIGHT)

    # ── Footer ──────────────────────────────────────────────────────────────
    print()
    print(Fore.WHITE + Style.BRIGHT + "  " + "═" * 62)
    print(Fore.WHITE + Style.DIM +
          f"  Sumber data: ip-api.com, ipwho.is, ipinfo.io, abuseipdb.com")
    print(Fore.WHITE + Style.DIM +
          f"  Laporan ini hanya untuk keperluan edukasi & keamanan jaringan")
    print(Fore.WHITE + Style.BRIGHT + "  " + "═" * 62)
    print()


# ─── Export ───────────────────────────────────────────────────────────────────
def export_json(ip: str, data: dict, risk: dict) -> str:
    out = {
        "report_id": f"RPT-{int(time.time())}",
        "generated_at": datetime.now().isoformat(),
        "target_ip": ip,
        "risk": {k: v for k, v in risk.items() if k != "level_color"},
        "data": {k: v for k, v in data.items()},
    }
    filename = f"ip_report_{ip.replace('.', '_')}_{int(time.time())}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2, default=str)
    return filename


def export_txt(ip: str, data: dict, risk: dict) -> str:
    ip_d = data.get("ip_api", {})
    filename = f"ip_report_{ip.replace('.', '_')}_{int(time.time())}.txt"
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "=" * 66,
        " IP INTELLIGENCE TRACKER — LAPORAN ANALISIS",
        "=" * 66,
        f" IP Target     : {ip}",
        f" Dibuat        : {ts}",
        f" Skor Risiko   : {risk['score']}% — {risk['level']}",
        "=" * 66,
        "",
        "[ GEOLOKASI ]",
        f"  Negara       : {ip_d.get('country','—')} ({ip_d.get('countryCode','—')})",
        f"  Kota         : {ip_d.get('city','—')}",
        f"  Koordinat    : {ip_d.get('lat','—')}, {ip_d.get('lon','—')}",
        f"  Zona Waktu   : {ip_d.get('timezone','—')}",
        "",
        "[ JARINGAN ]",
        f"  ISP          : {ip_d.get('isp','—')}",
        f"  AS           : {ip_d.get('as','—')}",
        f"  Tipe         : {'Hosting' if ip_d.get('hosting') else 'Residensial'}",
        "",
        "[ KEAMANAN ]",
        f"  Proxy        : {'TERDETEKSI' if ip_d.get('proxy') else 'Tidak'}",
        f"  VPN          : {'TERDETEKSI' if ip_d.get('vpn') else 'Tidak'}",
        f"  TOR          : {'TERDETEKSI' if ip_d.get('tor') else 'Tidak'}",
        f"  Hosting/DC   : {'Ya' if ip_d.get('hosting') else 'Tidak'}",
        "",
        "[ FAKTOR RISIKO ]",
    ]
    for reason in risk.get("reasons", []):
        lines.append(f"  • {reason}")
    if not risk.get("reasons"):
        lines.append("  • Tidak ada indikator risiko signifikan")

    port_data = data.get("ports", [])
    if port_data:
        open_p = [p for p in port_data if p["open"]]
        lines += ["", "[ PORT SCANNING ]", f"  Terbuka: {len(open_p)} port"]
        for p in open_p:
            lines.append(f"    {p['port']}/{p['service']}")

    lines += ["", "=" * 66, ""]
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return filename


def export_html(ip: str, data: dict, risk: dict) -> str:
    ip_d = data.get("ip_api", {})
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risk_color = {"RENDAH": "#28c840", "SEDANG": "#febc2e", "TINGGI": "#ff5f57", "KRITIS": "#ff0000"}.get(
        risk["level"], "#fff"
    )
    score = risk["score"]
    open_ports = [p for p in data.get("ports", []) if p["open"]]

    port_rows = "".join(
        f"<tr><td>{p['port']}</td><td>{p['service']}</td>"
        f"<td style='color:{'#ff5f57' if p['port'] in [22,23,3389] else '#28c840'}'>OPEN</td></tr>"
        for p in open_ports
    ) or "<tr><td colspan=3 style='color:#555'>Scan tidak dijalankan</td></tr>"

    flags_html = "".join(
        f"<span class='badge'>{f}</span>" for f in risk.get("flags", [])
    ) or "<span style='color:#28c840'>Tidak ada indikator ancaman</span>"

    filename = f"ip_report_{ip.replace('.', '_')}_{int(time.time())}.html"
    html = f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>IP Report — {ip}</title>
<style>
  * {{ box-sizing:border-box; margin:0; padding:0 }}
  body {{ background:#0d1117; color:#e6edf3; font-family:'Courier New',monospace; padding:30px }}
  h1 {{ color:#3fb950; font-size:20px; margin-bottom:6px }}
  .meta {{ color:#8b949e; font-size:12px; margin-bottom:24px }}
  .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:20px }}
  .card {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:16px }}
  .card h3 {{ color:#58a6ff; font-size:12px; letter-spacing:1px; margin-bottom:12px; text-transform:uppercase }}
  .row {{ display:flex; justify-content:space-between; padding:5px 0; border-bottom:1px solid #21262d; font-size:13px }}
  .row:last-child {{ border-bottom:none }}
  .label {{ color:#8b949e }}
  .value {{ color:#e6edf3; text-align:right; max-width:60% }}
  .risk-score {{ font-size:32px; font-weight:bold; color:{risk_color} }}
  .risk-level {{ font-size:14px; color:{risk_color}; margin-top:4px }}
  .bar-wrap {{ background:#21262d; border-radius:4px; height:8px; margin-top:12px }}
  .bar-fill {{ height:100%; border-radius:4px; background:{risk_color}; width:{score}% }}
  .badge {{ background:#3a1a1a; color:#ff5f57; border:1px solid #6e1c1c; border-radius:12px;
            padding:3px 10px; font-size:11px; margin-right:6px }}
  table {{ width:100%; border-collapse:collapse; font-size:12px }}
  td {{ padding:5px 8px; border-bottom:1px solid #21262d }}
  .footer {{ color:#484f58; font-size:11px; text-align:center; margin-top:24px }}
  .full {{ grid-column:1/-1 }}
  .ok {{ color:#28c840 }}
  .err {{ color:#ff5f57 }}
  .warn {{ color:#febc2e }}
</style>
</head>
<body>
<h1>▶ IP INTELLIGENCE REPORT</h1>
<div class="meta">Target: {ip} &nbsp;|&nbsp; Dibuat: {ts} &nbsp;|&nbsp; ID: RPT-{int(time.time())}</div>

<div class="grid">
  <div class="card">
    <h3>Geolokasi</h3>
    <div class="row"><span class="label">IP</span><span class="value">{ip_d.get('query',ip)}</span></div>
    <div class="row"><span class="label">Negara</span><span class="value">{ip_d.get('country','—')} ({ip_d.get('countryCode','—')})</span></div>
    <div class="row"><span class="label">Kota</span><span class="value">{ip_d.get('city','—')}</span></div>
    <div class="row"><span class="label">Koordinat</span><span class="value">{ip_d.get('lat','—')}, {ip_d.get('lon','—')}</span></div>
    <div class="row"><span class="label">Zona Waktu</span><span class="value">{ip_d.get('timezone','—')}</span></div>
  </div>

  <div class="card">
    <h3>Jaringan</h3>
    <div class="row"><span class="label">ISP</span><span class="value">{ip_d.get('isp','—')}</span></div>
    <div class="row"><span class="label">Org</span><span class="value">{ip_d.get('org','—')}</span></div>
    <div class="row"><span class="label">AS</span><span class="value">{ip_d.get('as','—')}</span></div>
    <div class="row"><span class="label">Mobile</span><span class="value {'ok' if not ip_d.get('mobile') else 'warn'}">{('Ya' if ip_d.get('mobile') else 'Tidak')}</span></div>
    <div class="row"><span class="label">Tipe</span><span class="value">{'Hosting/DC' if ip_d.get('hosting') else 'Residensial'}</span></div>
  </div>

  <div class="card">
    <h3>Keamanan</h3>
    <div class="row"><span class="label">Proxy</span><span class="value {'err' if ip_d.get('proxy') else 'ok'}">{('⚠ TERDETEKSI' if ip_d.get('proxy') else '✔ Bersih')}</span></div>
    <div class="row"><span class="label">VPN</span><span class="value {'err' if ip_d.get('vpn') else 'ok'}">{('⚠ TERDETEKSI' if ip_d.get('vpn') else '✔ Bersih')}</span></div>
    <div class="row"><span class="label">TOR</span><span class="value {'err' if ip_d.get('tor') else 'ok'}">{('⚠ TERDETEKSI' if ip_d.get('tor') else '✔ Bersih')}</span></div>
    <div class="row"><span class="label">Hosting</span><span class="value {'warn' if ip_d.get('hosting') else 'ok'}">{('Ya' if ip_d.get('hosting') else 'Tidak')}</span></div>
  </div>

  <div class="card">
    <h3>Skor Risiko</h3>
    <div class="risk-score">{score}%</div>
    <div class="risk-level">{risk['level']}</div>
    <div class="bar-wrap"><div class="bar-fill"></div></div>
    <div style="margin-top:12px">{flags_html}</div>
  </div>

  <div class="card full">
    <h3>Port Terbuka</h3>
    <table>
      <thead><tr><td><b>Port</b></td><td><b>Service</b></td><td><b>Status</b></td></tr></thead>
      <tbody>{port_rows}</tbody>
    </table>
  </div>
</div>

<div class="footer">IP Intelligence Tracker | Data dari ip-api.com, ipwho.is, abuseipdb.com<br>
Hanya untuk keperluan edukasi dan keamanan jaringan yang sah</div>
</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    return filename


# ─── Core: Analisis Satu IP ───────────────────────────────────────────────────
def analyze_ip(ip: str, scan_ports_flag: bool = False, export_fmt: str | None = None) -> dict:
    """Jalankan seluruh analisis untuk satu IP."""

    print()
    section(f"MEMULAI ANALISIS: {ip}")

    # Resolve domain jika bukan IP
    if not is_valid_ip(ip):
        status(f"'{ip}' bukan IP — mencoba resolusi domain...", "info")
        resolved = resolve_domain(ip)
        if not resolved:
            status(f"Gagal resolve domain '{ip}'", "err")
            return {}
        status(f"Domain '{ip}' → {resolved}", "ok")
        ip = resolved

    data = {}

    # ── Fetch semua sumber secara paralel ───────────────────────────────────
    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {
            "ip_api": ex.submit(fetch_ip_api, ip),
            "ipwho": ex.submit(fetch_ipwho, ip),
            "ipinfo": ex.submit(fetch_ipinfo, ip),
            "abuseipdb": ex.submit(fetch_abuseipdb, ip),
            "rdns": ex.submit(fetch_reverse_dns, ip),
            "whois": ex.submit(fetch_whois, ip),
        }

        for name, future in futures.items():
            try:
                result = future.result(timeout=TIMEOUT + 2)
                data[name] = result
                if name == "rdns":
                    status(f"Reverse DNS: {result}", "ok")
                elif isinstance(result, dict) and result.get("_skipped"):
                    status(f"{name}: key tidak diset (skip)", "warn")
                elif isinstance(result, dict) and result.get("_error"):
                    status(f"{name}: error — {result['_error'][:50]}", "err")
                elif name == "ip_api" and isinstance(result, dict) and result.get("status") == "fail":
                    status(f"ip-api: {result.get('message', 'invalid IP')}", "err")
                else:
                    status(f"{name}: data diterima", "ok")
            except Exception as e:
                data[name] = {"_error": str(e)}
                status(f"{name}: timeout/error", "err")

    # ── Port scanning ────────────────────────────────────────────────────────
    if scan_ports_flag:
        data["ports"] = scan_ports(ip)
        open_count = sum(1 for p in data["ports"] if p["open"])
        status(f"Port scanning selesai: {open_count} port terbuka", "ok" if open_count == 0 else "warn")
    else:
        data["ports"] = []

    # ── Hitung risiko ────────────────────────────────────────────────────────
    risk = calculate_risk(data)
    status(f"Skor risiko: {risk['score']}% — {risk['level']}", "ok")

    # ── Print laporan ────────────────────────────────────────────────────────
    print_report(ip, data, risk)

    # ── Export ───────────────────────────────────────────────────────────────
    if export_fmt:
        fmt = export_fmt.lower()
        try:
            if fmt == "json":
                filename = export_json(ip, data, risk)
            elif fmt == "txt":
                filename = export_txt(ip, data, risk)
            elif fmt == "html":
                filename = export_html(ip, data, risk)
            else:
                filename = None
                status(f"Format export tidak dikenal: {fmt}", "warn")

            if filename:
                status(f"Laporan disimpan: {filename}", "ok")
        except Exception as e:
            status(f"Gagal export: {e}", "err")

    return {"ip": ip, "data": data, "risk": risk}


# ─── Mode Batch ───────────────────────────────────────────────────────────────
def process_file(filepath: str, scan_ports_flag: bool, export_fmt: str | None):
    """Proses daftar IP dari file teks."""
    try:
        with open(filepath, "r") as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        status(f"File tidak ditemukan: {filepath}", "err")
        sys.exit(1)

    status(f"Memuat {len(targets)} target dari {filepath}", "info")
    results = []
    for i, target in enumerate(targets, 1):
        print(f"\n  [{i}/{len(targets)}] Target: {target}")
        result = analyze_ip(target, scan_ports_flag, export_fmt)
        results.append(result)
        if i < len(targets):
            time.sleep(1.5)  # Rate limiting

    # Ringkasan batch
    section("RINGKASAN BATCH")
    for r in results:
        if r and r.get("risk"):
            risk = r["risk"]
            color = risk["level_color"]
            print(f"    {Fore.WHITE}{r['ip']:<18}{color}{risk['level']:<10}{Style.RESET_ALL} {risk_bar(risk['score'], 20)}")


# ─── CLI ──────────────────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="IP Intelligence Tracker — OSINT Multi-Source Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh penggunaan:
  python ip_tracker.py
  python ip_tracker.py --ip 8.8.8.8
  python ip_tracker.py --ip google.com --scan-ports
  python ip_tracker.py --ip 1.1.1.1 --export html
  python ip_tracker.py --file targets.txt --export json

Untuk mengaktifkan AbuseIPDB dan ipinfo.io, set environment variable:
  export ABUSEIPDB_KEY=your_key_here
  export IPINFO_KEY=your_key_here
  atau edit langsung di bagian API_CONFIG dalam script ini
        """
    )
    parser.add_argument("--ip", "-i", help="IP address atau domain target")
    parser.add_argument("--file", "-f", help="File teks berisi daftar IP (satu per baris)")
    parser.add_argument("--scan-ports", "-p", action="store_true",
                        help="Jalankan port scanning (20 port umum)")
    parser.add_argument("--export", "-e", choices=["json", "txt", "html"],
                        help="Export laporan ke file")
    return parser.parse_args()


def interactive_mode(scan_ports_flag: bool, export_fmt: str | None):
    """Mode interaktif jika tidak ada argumen CLI."""
    print(Fore.CYAN + "  Masukkan IP address atau nama domain yang ingin dianalisis.")
    print(Fore.WHITE + Style.DIM + "  Ketik 'quit' atau 'exit' untuk keluar.\n")

    while True:
        try:
            target = input(Fore.GREEN + Style.BRIGHT + "  target> " + Style.RESET_ALL).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not target:
            continue
        if target.lower() in ("quit", "exit", "q"):
            cprint("  Keluar dari IP Tracker. Sampai jumpa!", Fore.CYAN)
            break

        # Tanya port scan jika belum diset
        do_scan = scan_ports_flag
        if not do_scan:
            yn = input(Fore.YELLOW + "  Jalankan port scanning? (y/N): " + Style.RESET_ALL).strip().lower()
            do_scan = yn in ("y", "yes")

        analyze_ip(target, do_scan, export_fmt)

        cont = input(Fore.CYAN + "\n  Analisis IP lain? (y/N): " + Style.RESET_ALL).strip().lower()
        if cont not in ("y", "yes"):
            break


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    banner()
    args = parse_args()

    # Cek dependensi opsional
    if not HAS_COLORAMA:
        print("  [SARAN] Install colorama untuk tampilan berwarna: pip install colorama")
    if not HAS_DNS:
        print("  [SARAN] Install dnspython untuk DNS lengkap: pip install dnspython")
    if not HAS_WHOIS:
        print("  [SARAN] Install python-whois untuk WHOIS lookup: pip install python-whois")

    scan_ports_flag = args.scan_ports
    export_fmt = args.export

    if args.file:
        process_file(args.file, scan_ports_flag, export_fmt)
    elif args.ip:
        analyze_ip(args.ip, scan_ports_flag, export_fmt)
    else:
        interactive_mode(scan_ports_flag, export_fmt)


if __name__ == "__main__":
    main()
