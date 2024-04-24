
def create_table(data):
    # Find the maximum length of each column
    col_widths = [max(len(str(row[i])) for row in data) for i in range(len(data[0]))]

    # Create the horizontal line
    horizontal_line = '+'.join('-' * (width + 2) for width in col_widths)

    # Create the table
    table = horizontal_line + '\n'
    for row in data:
        table += '| ' + ' | '.join(str(row[i]).ljust(col_widths[i]) for i in range(len(row))) + ' |\n'
        table += horizontal_line + '\n'

    return table
def print_full_report(data):

    print("===== Basic Information and Statistics ====\n")
    print(f'Starting Time {data["start_time"].date()}')
    print(f'End Time {data["end_time"].date()}')
    print(f'Total Number of Packets {data["total_packets"]}')
    print(f'Total Data Volume {data["total_volume"]} Bytes')
    print(f'Time to complete this analysis:{data["time_taken"]} Seconds')
    print(f'Number of Used Protocols  {len(data["sorted_protocols"])}\n')
    protocols_list=[]
    protocols_list.append(["Protocol","Number of Packets","Data Volume"])
    for i in data["sorted_protocols"]:
        protocols_list.append([i[0],i[1]["packet_count"],i[1]["volume"]])
    print(create_table(protocols_list))
    if data["Malware_check"] :
        print(f'Malware Check : Malware detected by {data["Malware_check"]["result"]["malicious"]} vendors !\n')
        print("--------------")
        print(f'Malware Details: {data["Malware_check"]["details"]}')
        print("--------------\n")
    else:
        print(f'Malware Check : No Malware Files were Detected')
    if data["icmp_flood"]:
        print(f'ICMP Flood Check : {len(data["icmp_flood"])} attack found!\n')
        for i in data["icmp_flood"]:
            print("--------------")
            print(f'Attacker IP :{i["attacker_ip"]}')
            print(f'ICMP Count :{i["icmp_count"]}')
            print("--------------\n")
    else:
        print(f'ICMP Flood Check : No ICMP Flood Detected')
    if data["arp_spoofing"][0]:
        print(f'ARP Spoofing Check : {len(data["arp_spoofing"][0])} attack found!\n')
        for i in data["arp_spoofing"][0]:
            print("--------------")
            print(f'Spoofed IP :{i["spoofed_ip"]}')
            print(f'Attacker MAC :{i["attacker_mac"]}')
            print(f'Extra details :{i["reason"]}')
            print("--------------\n")
    else:
        print(f'ARP Spoofing Check : No ARP Spoofing Detected')
    if data["dns_tunneling"]:
        print("--------------")
        print(f'DNS Tunneling Check : 1 attack found!\n')
        print(f'Victim IP :{data["dns_tunneling"]["victim"]}')
        print(f'Suspected DNS Server :{data["dns_tunneling"]["suspected_dns_server"]}')
        print(f'Extra details :{data["dns_tunneling"]["Justification"]}')
        print("--------------\n")
    else:
        print(f'DNS Tunneling Check : No DNS Tunneling Detected')












