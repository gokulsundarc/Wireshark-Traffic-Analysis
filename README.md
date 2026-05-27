# Wireshark Network Traffic Analysis — Findings

## Environment
- Attacker: Kali Linux — <kali-ip>
- Target: Ubuntu Server — <ubuntu-ip>
- Tool: Wireshark

---

## Scenario 1: Baseline Traffic

**Pcap file:** baseline.pcap  
**Total packets:** ~9,000  
**Filters used:**
- `dns` — DNS resolution during apt update and curl
- `tcp.flags.syn==1 && tcp.flags.ack==1` — TCP handshakes
- `icmp` — ping to 8.8.8.8
- `arp` — MAC address resolution

**Observations:**
- Normal DNS queries resolved before each connection
- Clean TCP 3-way handshakes observed (SYN → SYN-ACK → ACK)
- No anomalies detected

**MITRE ATT&CK:** N/A — baseline only

---

## Scenario 2: Port Scan Detection

**Pcap file:** portscan.pcap  
**Total packets:** ~3,000  
**Tool used:** Nmap SYN scan (`nmap -sS`)  
**Filters used:**
- `tcp.flags.syn==1 && tcp.flags.ack==0` — SYN sweep
- `tcp.flags.reset==1` — RSTs from closed ports
- `ip.src == <kali-ip>` — attacker traffic only

**Observations:**
- Hundreds of SYN packets sent to sequential ports in seconds
- RST responses received from closed ports
- Open ports identified: 22 (SSH)
- Statistics → Conversations confirmed high volume of short-lived connections

**IOCs:**
- Source IP: <kali-ip>
- Pattern: Sequential SYN packets across port range
- Timeframe: completed in under 10 seconds

**MITRE ATT&CK:** T1046 — Network Service Discovery

---

## Scenario 3: SSH Brute Force Detection

**Pcap file:** bruteforce.pcap  
**Tool used:** Hydra  
**Filters used:**
- `tcp.port == 22` — all SSH traffic
- `ip.dst == <ubuntu-ip>` — traffic hitting target

**Observations:**
- High volume of TCP connections to port 22 in short timeframe
- Each connection terminated quickly — indicating failed auth attempts
- IO Graph showed clear traffic spike during attack window
- TCP Stream follow confirmed repeated SSH session attempts

**IOCs:**
- Source IP: <kali-ip>
- Destination Port: 22
- Pattern: Rapid repeated connections, each short-lived

**MITRE ATT&CK:** T1110 — Brute Force

---

## Summary

| Scenario | Pcap | Key Filter | MITRE |
|---|---|---|---|
| Baseline | baseline.pcap | `dns`, `icmp`, `tcp` | N/A |
| Port Scan | portscan.pcap | `tcp.flags.syn==1 && tcp.flags.ack==0` | T1046 |
| SSH Brute Force | bruteforce.pcap | `tcp.port==22` | T1110 |
