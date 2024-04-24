from scapy.all import *
from collections import defaultdict


def detect_dns_poisoning(pcap_file):
    # Reading the pcap file
    packets = rdpcap(pcap_file)

    # This dictionary will hold DNS query IDs and the responses received
    dns_responses = defaultdict(list)

    # Process each packet
    for packet in packets:
        # Filter for DNS response packets
        if packet.haslayer(DNSRR) and packet.haslayer(DNS):
            if packet[DNS].qr == 1:  # DNS 'qr' flag is 1 for responses
                # Collect all the response records
                transaction_id = packet[DNS].id
                for i in range(packet[DNS].ancount):
                    dns_response = packet[DNSRR][i]
                    dns_responses[transaction_id].append(dns_response.rdata)
    results=[]
    # Check for DNS poisoning
    for transaction_id, responses in dns_responses.items():
        if len(set(responses)) > 1:  # More than one unique response suggests possible poisoning
            if isinstance(responses[0], bytes):
                results.append({"Transaction ID":transaction_id,"Domain name":responses[0],"Poisoned IP":responses[1]})

    if results:
        return results
    else:
        return None


# print(detect_dns_poisoning('../testing_files/dns_poisning.pcap'))
