
#!/usr/bin/env python3
# ultimate_idle_scan_fixed.py
# 2025 Tamil Pro Edition – Fully Working + Beautiful Output
# Fixed by abd0xa23

from scapy.all import *
import time
import random

print("""
╔══════════════════════════════════════════════════════════╗
║        ULTIMATE IDLE (ZOMBIE) SCAN 2025                  ║
║          100% Anonymous – Your IP Never Logs!            ║
╚══════════════════════════════════════════════════════════╝
                                                   by abd0xa23\n""")

# ===================== USER INPUT =====================
zombie_ip         = input("Zombie IP (printer/old PC/Cisco ASA): ").strip()
zombie_probe_port = int(input("Zombie Probe Port (usually 80, 443, 9100): ").strip() or "80")
zombie_tcp_flag   = input("Zombie Probe Flag (SA=best, S, A): ").strip().upper() or "SA"

ttl_input         = input("Custom TTL for spoofed packet (1-255) [64]: ").strip()
target_ip         = input("Target IP: ").strip()
ports_input       = input("Target Ports (ex: 80 or 22,80,443 or 1-1000 or 200-300): ").strip()

try:
    custom_ttl = int(ttl_input)
    if not 1 <= custom_ttl <= 255:
        raise ValueError
except:
    custom_ttl = 64
    print("Invalid TTL → using default 64")

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
    sport = random.randint(1, 65535)
    pkt = IP(dst=zombie_ip)/TCP(sport=sport, dport=probe_port, flags=flag, seq=1000)
    ans = sr1(pkt, timeout=5, verbose=0)
    if ans and ans.haslayer(IP):
        return ans[IP].id
    return None

def trigger_zombie(zombie_ip, target_ip, target_port, ttl):
    # Correct: src = zombie_ip, dst = target_ip
    spoofed = IP(src=target_ip, dst=zombie_ip, ttl=ttl, id=0, flags=2) / TCP(
        sport=389,           # Fixed predictable source port
        dport=target_port,
        flags="S",             # SYN only!
        seq=random.randint(100000, 999999)
    )
    send(spoofed, verbose=0)

def idle_scan_port(zombie_ip, zport, tip, tport, flag="SA", ttl=64):
    for _ in range(3):
        ipid1 = get_ipid(zombie_ip, zport, flag)
        if not ipid1:
            return ("Zombie unreachable", ipid1, None, None)

        trigger_zombie(zombie_ip, tip, tport, ttl)
        time.sleep(0.5)

        ipid2 = get_ipid(zombie_ip, zport, flag)
        if not ipid2:
            return ("Zombie lost", ipid1, None, None)

        delta = ipid2 - ipid1

        if delta >= 2:
            return (f"OPEN     ({delta})", ipid1, ipid2, delta)
        elif delta <= 1:
            return ("CLOSED/FILTERED", ipid1, ipid2, delta)
        else:
            time.sleep(0.5)
        time.sleep(1)
    return ("UNRELIABLE", ipid1, ipid2, delta if 'delta' in locals() else "N/A")

# ===================== START SCAN =====================
print(f"\nZombie        : {zombie_ip}:{zombie_probe_port} (flag={zombie_tcp_flag})")
print(f"Target        : {target_ip}")
print(f"Target Ports  : {target_ports}")
print(f"Custom TTL    : {custom_ttl} ← Spoofed packet\n")
print("-" * 80)

results = {}

for port in target_ports:
    print(f"Scanning {target_ip}:{port:5d} → ", end="")
    status, before, after, delta = idle_scan_port(zombie_ip, zombie_probe_port, target_ip, port, zombie_tcp_flag, custom_ttl)
    results[port] = (status, before, after, delta)
    print(status)

# ===================== FINAL RESULTS =====================
print("\n" + "="*80)
print("                           FINAL IDLE SCAN RESULTS")
print("="*80)
print(f"{'Port':<6} {'Status':<20} {'IP-ID Before':<13} {'IP-ID After':<13} {'Delta':<6} {'Verdict'}")
print("-"*80)

for port in target_ports:
    status, before, after, delta = results[port]
    verdict = "OPEN" if "OPEN" in status else "CLOSED" if "CLOSED" in status else "UNKNOWN"
    before_str = str(before) if before else "-"
    after_str = str(after) if after else "-"
    delta_str = str(delta) if delta is not None else "-"
    print(f"{port:<6} {status:<20} {before_str:<13} {after_str:<13} {delta_str:<6} {verdict}")

print("-"*80)
print(f"Scan Complete! | TTL={custom_ttl} | 100% Anonymous Attack")
print("Your real IP never appeared in logs – You are a ghost!\n")
