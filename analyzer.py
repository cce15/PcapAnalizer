import pyshark
from datetime import datetime, timezone
from detectors import malwares_detector,icmp_flood_detector,arp_detector,dns_tunnling_detector,dns_poisning
import time
import os
import pyfiglet
def print_ascii_detailed_banner(text):

    ascii_banner = pyfiglet.figlet_format(text, font="slant")
    print(ascii_banner)
    print("-------------------")
    print("Course Secure Data Coms & Networks (CYB5290)")
    print("Instructor Name: Dr. Abdullah Aydeger")
    print("Version 1.0")
    print(f"Date: 04/18/2024")
    print(f"By: Haitham, Ayman , Khalid")
    print("-------------------\n")





def analyze_pcap(file_stream):
    print('Loading the File .. \n')
    starting_time = time.time()
    files = {"file": (file_stream, open(file_stream, "rb"), "application/octet-stream")}
    print('File loaded successfully .. \n')
    print('PCAP initial analysis and getting basic statistics ...\n')
    cap = pyshark.FileCapture(file_stream, keep_packets=False)
    total_packets = 0
    total_volume = 0
    protocols = {}
    start_time = None
    end_time = None

    for packet in cap:
        total_packets += 1
        packet_length = int(packet.length)
        total_volume += packet_length

        protocol = packet.highest_layer
        if protocol in protocols:
            protocols[protocol]['packet_count'] += 1
            protocols[protocol]['volume'] += packet_length
        else:
            protocols[protocol] = {'packet_count': 1, 'volume': packet_length}

        packet_time = datetime.fromtimestamp(float(packet.sniff_timestamp), timezone.utc)
        if start_time is None or packet_time < start_time:
            start_time = packet_time
        if end_time is None or packet_time > end_time:
            end_time = packet_time

    sorted_protocols = sorted(protocols.items(), key=lambda x: (x[1]['packet_count'], x[1]['volume']), reverse=True)
    print('Checking for ICMP flood ...\n')
    icmp_flood= icmp_flood_detector.detect_icmp_flood(file_stream)
    print('Checking for ARP poisoning ...\n')
    arp_check=arp_detector.detect_arp_spoofing(file_stream)
    print('Checking for DNS tunneling ...\n')
    dns_tunneling_check=dns_tunnling_detector.detect_dns_tunneling(file_stream)
    # print('Checking for DNS poisoning ...\n')
    # dns_poisoning_check = dns_poisning.detect_dns_poisoning(file_stream)
    print('Searching for malware files ...\n')
    malware_check =malwares_detector.upload_file(files)

    print('Reporting ...\n')

    os.system('cls')
    print_ascii_detailed_banner("PCAP Analyzer")
    print("--------------------------\n      Final Report \n--------------------------\n")
    time_taken = time.time() -starting_time
    return {
        'total_packets': total_packets,
        'total_volume': total_volume,
        'start_time': start_time,
        'end_time': end_time,
        'sorted_protocols': sorted_protocols,
        'Malware_check':malware_check,
        'icmp_flood':icmp_flood,
        'arp_spoofing':arp_check,
        'dns_tunneling':dns_tunneling_check,
        # 'dns_poisoning_check':dns_poisoning_check,
        'time_taken': time_taken
    }