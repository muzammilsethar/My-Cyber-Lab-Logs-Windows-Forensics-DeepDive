from scapy.all import sniff, IP, TCP

def packet_callback(packet):
    # Check if packet has IP layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Check for TCP layer (especially Port 443 for Mercor investigation)
        if packet.haslayer(TCP):
            payload_size = len(packet[TCP].payload)
            # If port is 443, mark it as "Exfiltration Check"
            if packet[TCP].dport == 443 or packet[TCP].sport == 443:
                print(f"[!] SECURE TRAFFIC (443) | {src_ip} -> {dst_ip} | Size: {payload_size} bytes")
            else:
                print(f"[*] TCP Traffic | {src_ip} -> {dst_ip} | Port: {packet[TCP].dport}")

print("--- [ Hunter Sniffer Starting: Monitoring Port 443 for Data Exfiltration ] ---")
# Start sniffing (requires sudo/root)
sniff(prn=packet_callback, store=0)
