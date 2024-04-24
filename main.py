import argparse
import sys
from analyzer import  analyze_pcap
import os
import pyfiglet
from reporting import print_full_report

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


def main(args):
    os.system('cls')
    # Access command-line arguments from 'args'
    for arg in vars(args):
        if getattr(args, arg) is None:
            print(f"Error: Missing required argument '{arg}'")
            parser.print_help()
            sys.exit(1)  # Exit with a non-zero status code to indicate an error
    # analyze_pcap('testing_files/arp_spoofing.pcap')

    results= analyze_pcap(args.filename)
    print_full_report(results)
    print("\n")
    # print(results)


if __name__ == "__main__":
    print_ascii_detailed_banner("PCAP Analyzer")
    parser = argparse.ArgumentParser(description="Usage python main.py pcap_file_path")
    parser.add_argument('filename', help='Name of the file to process')
    # Add more arguments as needed
    args = parser.parse_args()
    main(args)
