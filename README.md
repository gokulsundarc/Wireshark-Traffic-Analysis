# Wireshark Network Traffic Analysis — Findings

## Environment
- Attacker: Kali Linux ip — 10.238.164.99
- Target: Ubuntu Server ip — 10.238.164.50
- Tool: Wireshark

---

## Scenario 1: Baseline Traffic

**Pcap file:** baseline.pcap  
**Total packets:** ~9,000  
**Filters used:**
- `dns` — DNS resolution during apt update and curl
  
  <img width="1366" height="702" alt="Screenshot_2026-05-27_01_29_08" src="https://github.com/user-attachments/assets/83c36c35-3b59-4bf3-a843-bf5a8b6482c1" />

- `tcp.flags.syn==1 && tcp.flags.ack==1` — TCP handshakes
  
  <img width="1366" height="702" alt="Screenshot_2026-05-27_01_28_36" src="https://github.com/user-attachments/assets/010e101f-5847-4b6f-a3f3-4a3f9585cb95" />

- `icmp` — ping to 8.8.8.8
  
  <img width="1366" height="702" alt="Screenshot_2026-05-27_02_34_00" src="https://github.com/user-attachments/assets/bd4caaa2-bd5d-4208-8b31-b06fa5728fb0" />

- `arp` — MAC address resolution
- 
  <img width="1366" height="702" alt="Screenshot_2026-05-27_02_35_06" src="https://github.com/user-attachments/assets/67c398a4-b107-4338-b1dd-7cf57f16f529" />


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

<img width="1366" height="702" alt="Screenshot_2026-05-27_02_15_03" src="https://github.com/user-attachments/assets/7617bedb-7f17-46a5-a84e-abc211ce754a" />

**Filters used:**
- `tcp.flags.syn==1 && tcp.flags.ack==0` — SYN sweep

<img width="1366" height="702" alt="Screenshot_2026-05-27_02_27_02" src="https://github.com/user-attachments/assets/24eae1de-570f-43f1-8880-e32df423242f" />


- `tcp.flags.reset==1` — RSTs from closed ports

  <img width="1366" height="702" alt="Screenshot_2026-05-27_01_32_30" src="https://github.com/user-attachments/assets/da3362bc-89c5-4292-b9dc-1faa0d30a1ed" />

- `ip.src == 10.238.164.99` — attacker traffic only
  
  <img width="1366" height="702" alt="Screenshot_2026-05-27_02_27_36" src="https://github.com/user-attachments/assets/a2821ced-7b8e-4fd8-a00f-847bab6a2532" />


**Observations:**
- Hundreds of SYN packets sent to sequential ports in seconds
- RST responses received from closed ports
- Open ports identified: 22 (SSH)
- Statistics → Conversations confirmed high volume of short-lived connections

**IOCs:**
- Source IP: 10.238.164.99
- Pattern: Sequential SYN packets across port range
- Timeframe: completed in under 10 seconds

**MITRE ATT&CK:** T1046 — Network Service Discovery

---

## Scenario 3: SSH Brute Force Detection

**Pcap file:** bruteforce.pcap  
**Tool used:** Hydra  

<img width="1366" height="702" alt="Screenshot_2026-05-27_01_58_51" src="https://github.com/user-attachments/assets/41e128f9-2797-4a59-b730-003f1d7de7ad" />

**Filters used:**
- `tcp.port == 22` — all SSH traffic
  
  <img width="1366" height="702" alt="Screenshot_2026-05-27_01_40_21" src="https://github.com/user-attachments/assets/37facf42-84ee-449a-8f7b-febac1fd3c47" />

- `ip.dst == <ubuntu-ip>` — traffic hitting target

  <img width="1366" height="702" alt="Screenshot_2026-05-27_01_41_33" src="https://github.com/user-attachments/assets/67869b17-f36f-41d6-bb6b-d47e8ffdef60" />


**Observations:**
- High volume of TCP connections to port 22 in short timeframe
- Each connection terminated quickly — indicating failed auth attempts
- IO Graph showed clear traffic spike during attack window
- TCP Stream follow confirmed repeated SSH session attempts

**IOCs:**
- Source IP: 10.238.164.99
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
