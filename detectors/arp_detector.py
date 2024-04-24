from scapy.all import *
from collections import defaultdict, Counter
import time


def detect_arp_spoofing(pcap_file):
    starting_time= time.time()
    packets = rdpcap(pcap_file)
    arp_packets = [pkt for pkt in packets if ARP in pkt and pkt[ARP].op == 2]  # ARP responses only
    ip_mac_mapping = defaultdict(list)
    spoofed_details = defaultdict(lambda: {"macs": set(), "attacker_mac": "", "reason": ""})
    for arp in arp_packets:
        src_ip = arp[ARP].psrc
        src_mac = arp[ARP].hwsrc
        ip_mac_mapping[src_ip].append(src_mac)
    for ip, macs in ip_mac_mapping.items():
        mac_count = Counter(macs)
        if len(mac_count) > 1:  # Multiple MAC addresses for the same IP
            spoofed_details[ip]["macs"] = set(macs)
            # The attacker might be the one with the most ARP responses sent
            attacker_mac, _ = mac_count.most_common(1)[0]
            spoofed_details[ip]["attacker_mac"] = attacker_mac
            spoofed_details[ip][
                "reason"] = "Multiple MAC addresses claiming the same IP address, with one MAC address being the most frequent."
    if spoofed_details:
        arp_attacks=[]
        print("Potential ARP Spoofing Detected:")
        for ip, details in spoofed_details.items():
            print(f"IP Address: {ip} is potentially spoofed.")
            print(f"Involved MAC Addresses: {', '.join(details['macs'])}")
            print(f"Potential Attacker MAC Address: {details['attacker_mac']}")
            print(f"Reason: {details['reason']}\n")
            attack={'spoofed_ip':ip,'attacker_mac':details['attacker_mac'],'reason':details['reason']}
            arp_attacks.append(attack)
        # arp_attacks.append({'time_taken': time.time()-starting_time})
        return arp_attacks,{'arp_function_time_taken': time.time()-starting_time}
    else:
        print("No potential ARP spoofing detected.")
        return None,{'arp_function_time_taken': time.time()-starting_time}

# For testing  usage
if __name__ == "__main__":
    pcap_file = "../testing_files/arp_spoofing.pcap"
    detect_arp_spoofing(pcap_file)
