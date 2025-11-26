#!/usr/bin/env python3
# ultimate_idle_scan.py
# 2025 Tamil Pro Edition – Fully User Input + Reliable Idle Scan
# sudo python3 ultimate_idle_scan.py

from scapy.all import *
import time
import random

print("""
╔══════════════════════════════════════════════════════════╗
║               ULTIMATE IDLE (ZOMBIE) SCAN                ║
║           100% Anonymous – Your IP Never Logs!           ║
╚══════════════════════════════════════════════════════════╝
                                                    by by abd0xa23   \n""")

# ===================== USER INPUT =====================
zombie_ip         = input("Zombie IP (printer/old PC/Cisco ASA): ").strip()
zombie_probe_port = int(input("Zombie Probe Port (usually 80, 443, 9100): ").strip() or "80")
zombie_tcp_flag   = input("Zombie Probe Flag (SA=best, S, A): ").strip().upper() or "SA"

target_ip         = input("Target IP: ").strip()
ports_input       = input("Target Ports (ex: 80 or 22,80,443 or 1-1000 or 200-300): ").strip()

# ===================== PORT PARSER =====================
def parse_ports(text):
    ports = set()
    for part in text.replace(" ", "").split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.update(range(start, end + 1))
        else:
            try:
                ports.add(int(part))
            except:
                pass
    return sorted(ports)

target_ports = parse_ports(ports_input)
if not target_ports:
    print("Invalid ports! Using 80,443")
    target_ports = [80, 443]

# ===================== CORE FUNCTIONS =====================
def get_ipid(zombie_ip, probe_port, flag="SA"):
    sport = random.randint(1024, 65535)
    pkt = IP(dst=zombie_ip)/TCP(sport=sport, dport=probe_port, flags=flag, seq=1000)
    ans = sr1(pkt, timeout=2, verbose=0)
    if ans and ans.haslayer(IP):
        return ans[IP].id
    return None

def trigger_zombie(zombie_ip, target_ip, target_port):
    spoofed = IP(src=zombie_ip, dst=target_ip) / TCP(
        sport=12345,           # Fixed sport = predictable
        dport=target_port,
        flags="S",             # SYN only!
        seq=1000
    )
    send(spoofed, verbose=0)

def idle_scan_port(zombie_ip, zport, tip, tport, flag="SA", retries=3):
    for attempt in range(retries):
        ipid1 = get_ipid(zombie_ip, zport, flag)
        if not ipid1:
            return "Zombie unreachable"

        trigger_zombie(zombie_ip, tip, tport)
        time.sleep(0.35)  # Golden timing

        ipid2 = get_ipid(zombie_ip, zport, flag)
        if not ipid2:
            return "Zombie lost"

        delta = ipid2 - ipid1
        if delta >= 1:
            return f"OPEN   (Δ{delta})"
        elif delta == 0:
            return "CLOSED/FILTERED"
        else:
            if attempt < retries-1:
                time.sleep(0.5)
                continue
            return f"UNRELIABLE (Δ{delta})"
    return "FAILED"

# ===================== START SCAN =====================
print(f"\nZombie        : {zombie_ip}:{zombie_probe_port} (flag={zombie_tcp_flag})")
print(f"Target        : {target_ip}")
print(f"Target Ports  : {target_ports}\n")
print("-" * 60)

results = {}
for port in target_ports:
    print(f"Scanning {target_ip}:{port:5d} → ", end="")
    result = idle_scan_port(zombie_ip, zombie_probe_port, target_ip, port, zombie_tcp_flag)
    results[port] = result
    print(result)

print("-" * 60)
print("FINAL RESULTS:")
for port, status in results.items():
    print(f"  Port {port:5d} → {status}")

print(f"\nScan Complete! Your real IP never touched the target!")
print("You are 100% anonymous – Like a ghost!")
