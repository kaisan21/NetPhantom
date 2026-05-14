#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════╗
║                        N E T P H A N T O M                       ║
║                    Network Reconnaissance Tool                    ║
║                         Version 1.0.0                             ║
╚═══════════════════════════════════════════════════════════════════╝
  Author  : Kaisan
  License : MIT
  Usage   : python3 netphantom.py  (sudo for raw-packet scans)
"""

# ─────────────────────────── stdlib ────────────────────────────────
import os
import re
import sys
import shutil
import subprocess
import datetime
import ipaddress
import socket
import time
import xml.etree.ElementTree as ET
from pathlib import Path

# ─────────────────────────── third-party ───────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.syntax import Syntax
    from rich.columns import Columns
    from rich import box
    from rich.text import Text
    from rich.live import Live
    from rich.layout import Layout
    from rich.rule import Rule
    from rich.align import Align
except ImportError:
    print("[!] 'rich' library not found. Run: pip install rich")
    sys.exit(1)

# ───────────────────────── globals ─────────────────────────────────
console = Console()
LOG_DIR = Path("netphantom_logs")
LOG_DIR.mkdir(exist_ok=True)

CYBER_BLUE  = "bold cyan"
MATRIX_GRN  = "bold green"
WARN_YELLOW = "bold yellow"
ERR_RED     = "bold red"
DIM_GREY    = "dim white"
ACCENT      = "bright_cyan"

VERSION     = "1.0.0"
TOOL_NAME   = "NetPhantom"

# ═══════════════════════════════════════════════════════════════════
#  BANNER
# ═══════════════════════════════════════════════════════════════════
BANNER = r"""
 ███╗   ██╗███████╗████████╗██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
 ██╔██╗ ██║█████╗     ██║   ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
 ██║╚██╗██║██╔══╝     ██║   ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
 ██║ ╚████║███████╗   ██║   ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
"""

TAGLINE = "[ Advanced Network Reconnaissance & Security Audit Framework ]"


def print_banner():
    console.print(BANNER, style=CYBER_BLUE, highlight=False)
    console.print(Align.center(TAGLINE), style=MATRIX_GRN)
    console.print(Align.center(f"v{VERSION}  ·  Use only on networks you own or have written permission to test"),
                  style=DIM_GREY)
    console.print()


# ═══════════════════════════════════════════════════════════════════
#  UTILITIES
# ═══════════════════════════════════════════════════════════════════

def check_nmap():
    """Ensure nmap is installed."""
    if not shutil.which("nmap"):
        console.print(Panel(
            "[bold red]nmap not found![/]\n\n"
            "Install with:\n"
            "  [cyan]sudo apt install nmap[/]   (Debian/Ubuntu/Kali)\n"
            "  [cyan]brew install nmap[/]        (macOS)",
            title="[red]Dependency Error[/]", border_style="red"))
        sys.exit(1)


def is_root():
    return os.geteuid() == 0


def validate_target(target: str) -> bool:
    """Return True if target is a valid IP, CIDR, or resolvable hostname."""
    # Strip port if given
    target = target.strip()
    # CIDR notation
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass
    # Plain IP
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    # Hostname (try resolve)
    try:
        socket.getaddrinfo(target, None)
        return True
    except socket.gaierror:
        pass
    # IP range like 192.168.1.1-254
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$", target):
        return True
    return False


def prompt_target() -> str:
    while True:
        target = Prompt.ask(f"[{ACCENT}]  Enter target[/] [dim](IP / CIDR / hostname)[/]")
        if validate_target(target):
            return target
        console.print(f"[{ERR_RED}]  Invalid target:[/] [white]{target}[/] — check format and try again.")


def timestamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def log_filename(scan_type: str, fmt: str = "txt") -> Path:
    return LOG_DIR / f"scan_{scan_type}_{timestamp()}.{fmt}"


def run_nmap(args: list[str], log_label: str = "scan",
             save_xml: bool = False) -> str:
    """
    Execute an nmap command, stream output in real-time, and save logs.
    Returns the combined stdout string.
    """
    # Prepend sudo only if not already root and scan needs raw packets
    raw_flags = {"-sS", "-sF", "-sN", "-sX", "-sU", "-sO", "-sA",
                 "-O", "--traceroute", "-f", "--mtu", "-D"}
    needs_raw = bool(raw_flags & set(args))

    if needs_raw and not is_root():
        console.print(f"\n[{WARN_YELLOW}]  This scan requires elevated privileges.[/] "
                      f"Re-launching with [cyan]sudo[/]…\n")
        cmd = ["sudo", "nmap"] + args
    else:
        cmd = ["nmap"] + args

    # XML output path (always generated; user may also get .txt)
    xml_path = log_filename(log_label, "xml")
    txt_path = log_filename(log_label, "txt")

    # Inject XML output flag
    full_cmd = cmd + ["-oX", str(xml_path)]

    console.print(Rule(f"[{CYBER_BLUE}]Running Scan[/]"))
    console.print(f"[{DIM_GREY}]  CMD:[/] {' '.join(full_cmd)}\n")

    output_lines = []
    start = time.time()

    try:
        proc = subprocess.Popen(
            full_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        with Live(console=console, refresh_per_second=8) as live:
            buffer = []
            for line in proc.stdout:
                line = line.rstrip()
                output_lines.append(line)
                buffer.append(line)
                # Show last 18 lines in Live panel
                display = "\n".join(buffer[-18:])
                live.update(Panel(
                    f"[{MATRIX_GRN}]{display}[/]",
                    title=f"[{CYBER_BLUE}] Live Output [/]",
                    border_style="cyan",
                    expand=True
                ))

        proc.wait()
        elapsed = time.time() - start

    except FileNotFoundError:
        console.print(f"[{ERR_RED}]  nmap binary not found. Is it installed?[/]")
        return ""
    except KeyboardInterrupt:
        console.print(f"\n[{WARN_YELLOW}]  Scan interrupted by user.[/]")
        return "\n".join(output_lines)

    full_output = "\n".join(output_lines)

    # Save .txt log
    txt_path.write_text(full_output)
    console.print(f"\n[{MATRIX_GRN}]  ✔  Scan complete[/] in [cyan]{elapsed:.1f}s[/]")
    console.print(f"[{DIM_GREY}]  Logs → {txt_path}  |  {xml_path}[/]")

    # Pretty-print XML summary if it exists
    if save_xml and xml_path.exists():
        _print_xml_summary(xml_path)

    return full_output


# ═══════════════════════════════════════════════════════════════════
#  XML SUMMARY PARSER
# ═══════════════════════════════════════════════════════════════════

def _print_xml_summary(xml_path: Path):
    """Parse nmap XML and render a Rich table of open ports."""
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError:
        return

    for host in root.findall("host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr", "?") if addr_el is not None else "?"
        hostname_el = host.find("hostnames/hostname")
        hname = hostname_el.get("name", "") if hostname_el is not None else ""

        title = f"[{CYBER_BLUE}]{addr}[/]"
        if hname:
            title += f"  [dim]({hname})[/]"

        ports_el = host.find("ports")
        if ports_el is None:
            continue

        table = Table(
            title=title,
            box=box.SIMPLE_HEAVY,
            border_style="cyan",
            header_style=CYBER_BLUE,
            show_lines=True,
        )
        table.add_column("Port",    style="bright_white", no_wrap=True, width=10)
        table.add_column("State",   style=MATRIX_GRN,    no_wrap=True, width=10)
        table.add_column("Service", style="bright_yellow", width=18)
        table.add_column("Version", style="white")

        for port in ports_el.findall("port"):
            portid   = port.get("portid", "?")
            proto    = port.get("protocol", "")
            state_el = port.find("state")
            state    = state_el.get("state", "?") if state_el is not None else "?"
            svc_el   = port.find("service")
            svc_name = svc_el.get("name", "") if svc_el is not None else ""
            svc_prod = svc_el.get("product", "") if svc_el is not None else ""
            svc_ver  = svc_el.get("version", "") if svc_el is not None else ""
            version  = f"{svc_prod} {svc_ver}".strip()

            color = MATRIX_GRN if state == "open" else (WARN_YELLOW if state == "filtered" else DIM_GREY)
            table.add_row(
                f"{portid}/{proto}",
                f"[{color}]{state}[/]",
                svc_name,
                version
            )

        console.print(table)


# ═══════════════════════════════════════════════════════════════════
#  MENU HELPERS
# ═══════════════════════════════════════════════════════════════════

def section_header(title: str):
    console.print()
    console.print(Rule(f"[{CYBER_BLUE}]{title}[/]", style="cyan"))
    console.print()


def build_menu(title: str, items: list[tuple[str, str]]) -> Table:
    t = Table(
        title=f"[{CYBER_BLUE}]{title}[/]",
        box=box.ROUNDED,
        border_style="cyan",
        header_style=CYBER_BLUE,
        show_header=True,
        expand=False,
        min_width=55,
    )
    t.add_column(" #", style="bold cyan",   no_wrap=True, width=4)
    t.add_column("Option",  style="bright_white", min_width=28)
    t.add_column("Details", style=DIM_GREY)
    for idx, (label, detail) in enumerate(items, 1):
        t.add_row(str(idx), label, detail)
    t.add_row("0", "[dim]Back / Exit[/]", "")
    return t


def pick(items: list[tuple[str, str]], title: str = "Select") -> int:
    console.print(build_menu(title, items))
    while True:
        raw = Prompt.ask(f"[{ACCENT}]  Choose[/]")
        if raw.isdigit() and 0 <= int(raw) <= len(items):
            return int(raw)
        console.print(f"[{ERR_RED}]  Enter a number between 0 and {len(items)}[/]")


# ═══════════════════════════════════════════════════════════════════
#  SCAN PROFILES
# ═══════════════════════════════════════════════════════════════════

# ── Basic ───────────────────────────────────────────────────────────
def menu_basic():
    section_header("Basic Scans")
    items = [
        ("Ping Sweep",        "-sn  (no port scan, host discovery)"),
        ("Quick Scan",        "-T4 -F  (top 100 ports, fast)"),
        ("List Scan",         "-sL  (list targets only, no packets sent)"),
        ("Full Port Scan",    "-p- -T4  (all 65535 ports)"),
        ("Top 1000 Ports",    "Default nmap behaviour"),
    ]
    choice = pick(items, "Basic Scans")
    if choice == 0:
        return

    target = prompt_target()

    flag_map = {
        1: (["-sn",    target], "ping_sweep"),
        2: (["-T4", "-F", target], "quick"),
        3: (["-sL",    target], "list"),
        4: (["-p-", "-T4", target], "full_port"),
        5: ([target],               "top1000"),
    }
    args, label = flag_map[choice]
    run_nmap(args, label, save_xml=True)


# ── Advanced ────────────────────────────────────────────────────────
def menu_advanced():
    section_header("Advanced Scans")
    items = [
        ("Service Version Detection", "-sV  (probe open ports for version info)"),
        ("OS Fingerprinting",         "-O   (requires root)"),
        ("Aggressive Scan",           "-A   (OS + version + scripts + traceroute)"),
        ("UDP Scan",                  "-sU  (top UDP ports, requires root)"),
        ("TCP SYN Stealth",           "-sS  (half-open SYN scan, requires root)"),
        ("All Advanced Flags",        "-A -sV -O --version-intensity 9"),
    ]
    choice = pick(items, "Advanced Scans")
    if choice == 0:
        return

    target = prompt_target()

    flag_map = {
        1: (["-sV", target],                               "svc_version"),
        2: (["-O",  target],                               "os_detect"),
        3: (["-A",  target],                               "aggressive"),
        4: (["-sU", "--top-ports", "200", target],         "udp"),
        5: (["-sS", target],                               "syn_stealth"),
        6: (["-A", "-sV", "-O", "--version-intensity", "9", target], "all_adv"),
    }
    args, label = flag_map[choice]
    run_nmap(args, label, save_xml=True)


# ── Stealth & Evasion ───────────────────────────────────────────────
def menu_stealth():
    section_header("Stealth & Firewall Evasion")
    items = [
        ("Fragmentation",        "-f  (split packets into 8-byte fragments)"),
        ("Custom MTU",           "--mtu <size>  (MTU must be multiple of 8)"),
        ("Decoy Scan",           "-D RND:10  (10 random decoy IPs)"),
        ("Custom Decoys",        "-D <ip1,ip2,...>  (specify decoys manually)"),
        ("Idle / Zombie Scan",   "-sI <zombie>  (requires root + zombie host)"),
        ("Source Port Spoof",    "--source-port 53  (appear as DNS query)"),
        ("Randomise Host Order", "--randomize-hosts"),
        ("Slow Scan (Paranoid)", "-T0  (very slow, evades time-based IDS)"),
    ]
    choice = pick(items, "Stealth & Evasion")
    if choice == 0:
        return

    target = prompt_target()
    label  = "stealth"

    if choice == 1:
        args = ["-f", target]
    elif choice == 2:
        mtu = Prompt.ask(f"[{ACCENT}]  MTU size[/] [dim](multiple of 8, e.g. 16)[/]", default="16")
        if not mtu.isdigit() or int(mtu) % 8 != 0:
            console.print(f"[{ERR_RED}]  MTU must be a multiple of 8.[/]"); return
        args = [f"--mtu", mtu, target]; label = "mtu"
    elif choice == 3:
        args = ["-D", "RND:10", target]; label = "decoy_rnd"
    elif choice == 4:
        decoys = Prompt.ask(f"[{ACCENT}]  Decoy IPs[/] [dim](comma-separated)[/]")
        args = ["-D", decoys, target]; label = "decoy_custom"
    elif choice == 5:
        zombie = Prompt.ask(f"[{ACCENT}]  Zombie host IP[/]")
        if not validate_target(zombie):
            console.print(f"[{ERR_RED}]  Invalid zombie IP.[/]"); return
        args = ["-sI", zombie, target]; label = "idle"
    elif choice == 6:
        args = ["--source-port", "53", target]; label = "srcport"
    elif choice == 7:
        args = ["--randomize-hosts", target]; label = "rand_hosts"
    elif choice == 8:
        args = ["-T0", target]; label = "paranoid"

    run_nmap(args, label, save_xml=True)


# ── NSE Scripting Engine ────────────────────────────────────────────
def menu_nse():
    section_header("NSE — Nmap Scripting Engine")
    items = [
        ("Vulnerability Scan",      "--script vuln  (known CVEs, safe)"),
        ("Auth Bypass Checks",      "--script auth  (default credential checks)"),
        ("Malware Discovery",       "--script malware  (backdoor/malware check)"),
        ("HTTP Enumeration",        "--script http-enum,http-headers,http-methods"),
        ("SMB Enumeration",         "--script smb-enum-shares,smb-os-discovery"),
        ("DNS Enumeration",         "--script dns-brute,dns-recursion"),
        ("FTP Checks",              "--script ftp-anon,ftp-bounce,ftp-proftpd-backdoor"),
        ("SSL / TLS Audit",         "--script ssl-cert,ssl-enum-ciphers,ssl-heartbleed"),
        ("Banner Grabbing",         "--script banner  (raw service banners)"),
        ("Safe Script Suite",       "--script safe  (all safe scripts)"),
        ("Custom NSE Script",       "Enter your own --script value"),
    ]
    choice = pick(items, "NSE Submenu")
    if choice == 0:
        return

    target = prompt_target()

    script_map = {
        1:  ("vuln",                                          "nse_vuln"),
        2:  ("auth",                                          "nse_auth"),
        3:  ("malware",                                       "nse_malware"),
        4:  ("http-enum,http-headers,http-methods",           "nse_http"),
        5:  ("smb-enum-shares,smb-os-discovery",              "nse_smb"),
        6:  ("dns-brute,dns-recursion",                       "nse_dns"),
        7:  ("ftp-anon,ftp-bounce,ftp-proftpd-backdoor",      "nse_ftp"),
        8:  ("ssl-cert,ssl-enum-ciphers,ssl-heartbleed",      "nse_ssl"),
        9:  ("banner",                                        "nse_banner"),
        10: ("safe",                                          "nse_safe"),
    }

    if choice == 11:
        custom = Prompt.ask(f"[{ACCENT}]  Script name(s)[/] [dim](e.g. http-title,smtp-commands)[/]")
        script_val, label = custom, "nse_custom"
    else:
        script_val, label = script_map[choice]

    run_nmap(["--script", script_val, target], label, save_xml=True)


# ── Custom Command ──────────────────────────────────────────────────
def menu_custom():
    section_header("Custom nmap Command")
    console.print(f"[{DIM_GREY}]  Enter arguments exactly as you would after 'nmap'.[/]")
    console.print(f"[{DIM_GREY}]  Example:  [cyan]-sV -p 22,80,443 -T4 192.168.1.0/24[/]\n")
    raw = Prompt.ask(f"[{ACCENT}]  nmap[/]")
    parts = raw.split()
    if not parts:
        console.print(f"[{WARN_YELLOW}]  Nothing entered.[/]"); return
    run_nmap(parts, "custom", save_xml=True)


# ── View Logs ───────────────────────────────────────────────────────
def menu_logs():
    section_header("Scan Logs")
    logs = sorted(LOG_DIR.glob("scan_*"))
    if not logs:
        console.print(f"[{WARN_YELLOW}]  No logs found in [cyan]{LOG_DIR}/[/][/]"); return

    table = Table(box=box.SIMPLE_HEAVY, border_style="cyan", header_style=CYBER_BLUE, show_lines=True)
    table.add_column("#",        style="bold cyan", width=4)
    table.add_column("Filename", style="bright_white")
    table.add_column("Size",     style=DIM_GREY, width=10)
    table.add_column("Modified", style=DIM_GREY)
    for i, p in enumerate(logs, 1):
        stat = p.stat()
        size = f"{stat.st_size/1024:.1f} KB"
        mtime = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
        table.add_row(str(i), p.name, size, mtime)
    console.print(table)

    raw = Prompt.ask(f"[{ACCENT}]  View file # (0 to go back)[/]")
    if not raw.isdigit() or int(raw) == 0:
        return
    idx = int(raw) - 1
    if idx < 0 or idx >= len(logs):
        console.print(f"[{ERR_RED}]  Out of range.[/]"); return

    chosen = logs[idx]
    if chosen.suffix == ".xml":
        _print_xml_summary(chosen)
    else:
        content = chosen.read_text(errors="replace")
        console.print(Panel(
            Syntax(content, "text", theme="monokai", word_wrap=True),
            title=f"[{CYBER_BLUE}]{chosen.name}[/]",
            border_style="cyan"
        ))


# ── About / Help ────────────────────────────────────────────────────
def menu_about():
    section_header("About NetPhantom")
    text = (
        f"[{CYBER_BLUE}]Tool:[/]     {TOOL_NAME} v{VERSION}\n"
        f"[{CYBER_BLUE}]Author:[/]   Kaisan\n"
        f"[{CYBER_BLUE}]Purpose:[/]  Authorized network reconnaissance & security auditing\n\n"
        f"[{WARN_YELLOW}]Legal Notice:[/]\n"
        "  Use NetPhantom ONLY on networks and systems you own or have\n"
        "  explicit written authorization to test. Unauthorized scanning\n"
        "  may violate local, national, and international law.\n\n"
        f"[{CYBER_BLUE}]Log directory:[/]  [cyan]{LOG_DIR.resolve()}[/]\n"
        f"[{CYBER_BLUE}]nmap path:[/]      [cyan]{shutil.which('nmap') or 'not found'}[/]\n"
        f"[{CYBER_BLUE}]Running as root:[/] [cyan]{is_root()}[/]\n"
    )
    console.print(Panel(text, title="[cyan]About[/]", border_style="cyan", expand=False))
    Prompt.ask(f"\n[{DIM_GREY}]  Press Enter to return[/]")


# ═══════════════════════════════════════════════════════════════════
#  MAIN MENU
# ═══════════════════════════════════════════════════════════════════

MAIN_ITEMS = [
    ("Basic Scans",             "Ping sweep · Quick · List · Full port"),
    ("Advanced Scans",          "Version · OS · Aggressive · UDP · SYN"),
    ("Stealth & Evasion",       "Fragmentation · Decoys · Idle · Slow"),
    ("NSE Scripting Engine",    "Vuln · Auth · Malware · HTTP · SMB …"),
    ("Custom Command",          "Raw nmap arguments for power users"),
    ("View Logs",               f"Browse saved scans in {LOG_DIR}/"),
    ("About / Help",            "Version info, legal notice, paths"),
]

DISPATCH = {
    1: menu_basic,
    2: menu_advanced,
    3: menu_stealth,
    4: menu_nse,
    5: menu_custom,
    6: menu_logs,
    7: menu_about,
}


def main():
    check_nmap()
    if not is_root():
        console.print(
            Panel(
                f"[{WARN_YELLOW}]Not running as root.[/]  Raw-packet scans (SYN, OS detect, etc.)\n"
                "will be automatically re-launched with [cyan]sudo[/] when needed.",
                border_style="yellow", expand=False
            )
        )

    while True:
        print_banner()
        choice = pick(MAIN_ITEMS, "Main Menu")
        if choice == 0:
            console.print(f"\n[{CYBER_BLUE}]  NetPhantom signing off. Stay ethical. 👻[/]\n")
            sys.exit(0)
        fn = DISPATCH.get(choice)
        if fn:
            try:
                fn()
            except KeyboardInterrupt:
                console.print(f"\n[{WARN_YELLOW}]  Returning to main menu…[/]")
        input("\n  Press Enter to return to main menu…")
        console.clear()


if __name__ == "__main__":
    main()
