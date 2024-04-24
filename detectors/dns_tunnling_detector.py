from scapy.all import *
from collections import Counter

def detect_dns_tunneling(pcap_file):
    pkts = rdpcap(pcap_file)
    suspicious_pkts = []
    suspected_clients = Counter()
    suspected_servers = Counter()
    for pkt in pkts:
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # DNS Query
            dns_query = pkt[DNS].qd.qname
            if len(dns_query) > 30:  # Arbitrary length threshold
                suspicious_pkts.append(pkt)
                suspected_clients[pkt[IP].src] += 1  # Source IP of the suspicious packet
                suspected_servers[pkt[IP].dst] += 1  # Destination IP (DNS server) of the suspicious packet
    if suspicious_pkts:
        # print("\nSuspected clients:")
        top_suspected_client = suspected_clients.most_common(1)[0][0]
        top_suspected_server = suspected_servers.most_common(1)[0][0]
        reson="The client IP '"+top_suspected_client+" and DNS server '"+top_suspected_server+"' have the highest number of suspicious DNS queries, indicating potential DNS tunneling activity between them."
        return {"victim":top_suspected_client,"suspected_dns_server":top_suspected_server,"Justification":reson}
    else:
        # print("No suspicious DNS traffic found.")
        return None

# Usage
# print(detect_dns_tunneling("../testing_files/dns_tunnaling.pcap"))