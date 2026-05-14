<div align="center">

```
 ███╗   ██╗███████╗████████╗██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
 ██╔██╗ ██║█████╗     ██║   ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
 ██║╚██╗██║██╔══╝     ██║   ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
 ██║ ╚████║███████╗   ██║   ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
```

**Advanced Network Reconnaissance & Security Audit Framework**

![Python](https://img.shields.io/badge/Python-3.9%2B-cyan?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-blue?style=for-the-badge&logo=linux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-1.0.0-brightgreen?style=for-the-badge)
![nmap](https://img.shields.io/badge/Requires-nmap-orange?style=for-the-badge)

> ⚠️ **For authorized use only.** Always obtain written permission before scanning any network or system you do not own.

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Screenshots](#-screenshots)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Scan Profiles](#-scan-profiles)
- [Logging](#-logging)
- [Project Structure](#-project-structure)
- [Legal Notice](#-legal-notice)
- [Author](#-author)
- [License](#-license)

---

## 🔍 Overview

**NetPhantom v1.0.0** is a high-performance, menu-driven CLI wrapper around [Nmap](https://nmap.org/) built in Python. It provides security professionals, sysadmins, and CTF practitioners with an intuitive interface to run everything from simple ping sweeps to advanced NSE script suites — without memorising dozens of flags.

All scan output is automatically saved to timestamped `.txt` and `.xml` logs. A built-in XML parser renders clean, colour-coded port tables directly in the terminal.

---

## ✨ Features

| Category | Capabilities |
|---|---|
| **Basic Scans** | Ping sweep, Quick scan (top 100), List scan, Full 65535-port scan |
| **Advanced Scans** | Service version detection (`-sV`), OS fingerprinting (`-O`), Aggressive (`-A`), UDP, TCP SYN stealth |
| **Stealth & Evasion** | Packet fragmentation (`-f`), Custom MTU, Decoy scans (`-D`), Idle/zombie scan (`-sI`), Source-port spoof, Paranoid timing (`-T0`) |
| **NSE Scripting** | Vuln, Auth bypass, Malware discovery, HTTP enum, SMB enum, DNS brute, FTP checks, SSL/TLS audit, Banner grabbing, Safe suite |
| **Custom Command** | Raw nmap argument passthrough for power users |
| **Log Viewer** | Browse, list, and display saved `.txt` and `.xml` logs inside the terminal |
| **Auto sudo** | Automatically re-launches with `sudo` for raw-packet scans when not running as root |
| **Input Validation** | Validates IPs, CIDRs, ranges, and hostnames before any packet is sent |

---

## 📸 Screenshots

```
╔══════════════════════════════════════════════════╗
║  NetPhantom v1.0.0  ·  Main Menu                 ║
╠══════════════════════════════════════════════════╣
║  1  Basic Scans          Ping · Quick · List …   ║
║  2  Advanced Scans       Version · OS · Aggr …   ║
║  3  Stealth & Evasion    Frags · Decoys · Idle …  ║
║  4  NSE Scripting        Vuln · Auth · Malware … ║
║  5  Custom Command       Raw nmap arguments       ║
║  6  View Logs            Browse saved scans       ║
║  7  About / Help         Info, legal, paths       ║
║  0  Exit                                          ║
╚══════════════════════════════════════════════════╝
  Choose ›
```

---

## 📦 Requirements

| Dependency | Version | Notes |
|---|---|---|
| Python | ≥ 3.9 | Uses `match` syntax internally |
| [nmap](https://nmap.org/) | Any recent | Must be in `$PATH` |
| [rich](https://github.com/Textualize/rich) | ≥ 13.0 | Terminal UI library |

---

## 🚀 Installation

### 1 · Clone the repository

```bash
git clone https://github.com/kaisan21/netphantom.git
cd netphantom
```

### 2 · Install Python dependencies

```bash
pip install rich
# or, using the provided requirements file:
pip install -r requirements.txt
```

### 3 · Ensure nmap is installed

```bash
# Debian / Ubuntu / Kali
sudo apt update && sudo apt install nmap -y

# macOS (Homebrew)
brew install nmap

# Verify
nmap --version
```

### 4 · Run NetPhantom

```bash
# Standard user (raw-packet scans auto-escalate via sudo)
python3 netphantom.py

# Or run as root directly (all features unlocked immediately)
sudo python3 netphantom.py
```

---

## 🖥️ Usage

NetPhantom is fully menu-driven — no flags required. Navigate with number keys:

```
Main Menu → Scan Category → Target Input → (optional parameters) → Live Output
```

**Quick example — scan your local network:**
1. Launch: `python3 netphantom.py`
2. Select `1` → Basic Scans
3. Select `1` → Ping Sweep
4. Enter target: `192.168.1.0/24`
5. Watch live output; logs auto-saved to `netphantom_logs/`

**Power user — pass raw flags:**
1. Select `5` → Custom Command
2. Enter: `-sV -p 22,80,443,8080 -T4 --script http-title 192.168.1.50`

---

## 🔬 Scan Profiles

### Basic
| # | Name | nmap flags |
|---|---|---|
| 1 | Ping Sweep | `-sn` |
| 2 | Quick Scan | `-T4 -F` |
| 3 | List Scan | `-sL` |
| 4 | Full Port | `-p- -T4` |
| 5 | Top 1000 | *(default)* |

### Advanced
| # | Name | nmap flags |
|---|---|---|
| 1 | Service Version | `-sV` |
| 2 | OS Fingerprint | `-O` *(root)* |
| 3 | Aggressive | `-A` *(root)* |
| 4 | UDP | `-sU --top-ports 200` *(root)* |
| 5 | TCP SYN Stealth | `-sS` *(root)* |
| 6 | All Advanced | `-A -sV -O --version-intensity 9` |

### Stealth & Evasion
| # | Name | nmap flags |
|---|---|---|
| 1 | Fragmentation | `-f` |
| 2 | Custom MTU | `--mtu <n>` |
| 3 | Decoy (random) | `-D RND:10` |
| 4 | Decoy (custom) | `-D <ip1,ip2,...>` |
| 5 | Idle/Zombie | `-sI <zombie>` *(root)* |
| 6 | Source Port | `--source-port 53` |
| 7 | Randomise Hosts | `--randomize-hosts` |
| 8 | Paranoid Timing | `-T0` |

### NSE Scripting Engine
| # | Script suite | nmap `--script` value |
|---|---|---|
| 1 | Vulnerability scan | `vuln` |
| 2 | Auth bypass | `auth` |
| 3 | Malware discovery | `malware` |
| 4 | HTTP enumeration | `http-enum,http-headers,http-methods` |
| 5 | SMB enumeration | `smb-enum-shares,smb-os-discovery` |
| 6 | DNS enumeration | `dns-brute,dns-recursion` |
| 7 | FTP checks | `ftp-anon,ftp-bounce,ftp-proftpd-backdoor` |
| 8 | SSL/TLS audit | `ssl-cert,ssl-enum-ciphers,ssl-heartbleed` |
| 9 | Banner grabbing | `banner` |
| 10 | Safe suite | `safe` |
| 11 | Custom | *(user input)* |

---

## 📁 Logging

All scans produce two files automatically:

```
netphantom_logs/
├── scan_aggressive_20240815_142301.txt   ← human-readable output
├── scan_aggressive_20240815_142301.xml   ← machine-readable, parsed for table view
├── scan_nse_vuln_20240815_150042.txt
└── scan_nse_vuln_20240815_150042.xml
```

The **Log Viewer** (menu option 6) lets you browse and read these files without leaving the tool. XML files are rendered as colour-coded port tables.

---

## 🗂️ Project Structure

```
netphantom/
├── netphantom.py          # Main application (single-file)
├── requirements.txt       # Python dependencies
├── README.md              # This file
└── netphantom_logs/       # Auto-created on first run
    └── *.txt / *.xml
```

---

## ⚖️ Legal Notice

> **NetPhantom is a tool for authorized security testing only.**
>
> - You **must** have explicit written permission from the system/network owner before running any scan.
> - Unauthorized port scanning may violate the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent laws in your jurisdiction.
> - The author assumes **no liability** for misuse of this tool.
> - This tool is intended for: penetration testers working under a signed scope-of-work, sysadmins auditing their own infrastructure, students using legal lab environments (HackTheBox, TryHackMe, DVWA, Metasploitable), and CTF (Capture The Flag) competitions.

---

## 👤 Author

**Kaisan**
- Tool: NetPhantom v1.0.0
- Category: Network Security / Recon Automation
- Built with: Python 3 · Rich · Nmap

---

## 📄 License

```
MIT License

Copyright (c) 2024 Kaisan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

<div align="center">

Made with 💙 by Kaisan · NetPhantom v1.0.0

*"Know your network before someone else does."*

</div>
