from scapy.all import rdpcap, ICMP,IP
from collections import Counter

def detect_icmp_flood(pcap_file):
    packets = rdpcap(pcap_file)
    icmp_packets = [pkt for pkt in packets if ICMP in pkt]
    src_ips = [pkt[IP].src for pkt in icmp_packets if IP in pkt]
    # Count occurrences of source IPs
    src_ip_counts = Counter(src_ips)
    # Filter for potential attackers (arbitrary threshold)
    potential_attackers=[]
    for ip, count in src_ip_counts.items():
        if count >1000:
            potential_attackers.append({'attacker_ip':ip,'icmp_count':count})
    # potential_attackers = {ip: count for ip, count in src_ip_counts.items() if count > 1000}  # Threshold set at 1000
    if potential_attackers:
        return potential_attackers
    else:
        return None

