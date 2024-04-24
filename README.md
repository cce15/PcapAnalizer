# PCAPs ANALYZER

## INTRODUCTION

In today's digital world, the number of cyber threats is increasing incredibly, making it hard for organizations to stay secure because conventional security controls and techniques are not enough, as cyber attackers keep finding new techniques to play around the security measures to compromise systems. Therefore, there is a real need for more developments by security researchers to provide more efficient security solutions like a network traffic threat detection system. This system is designed to analyze network traffic captured in PCAP files and identify some of the known threats as a proof of concept (POC). By using this system, organizations can quickly detect threats in their networks, minimizing the potential required time and effort in case of cyber incidents.

## MAIN IDEA

The project's idea is to develop a software tool that can analyze network traffic data (PCAP files), looking for signs of cyberattacks,  specifically some attacks that were covered during this course. The tool is designed to look for unusual patterns and behaviors that could indicate a security threat. Therefore, the main goal is to provide better insight for the digital forensics specialists and the information security teams in any organization.


## OBJECTIVES
1- Learn how to read and process PCAP files.
2- Learn how to simulate some known cyber threats.
3- Learn how the threat detectors work and how to develop detection algorithms.

## MAIN FUNCTIONS
- **1 Reading PCAP files and performing basic analysis**
- **2 Detect three known network threats**
- **3 Detect any malicious files or malware via virus total service**
- **4 Reporting the results**
- 
## Installation & Testing

To install and run PCAPs ANALYZER, follow these steps:

```bash
git clone https://github.com/cce15/PcapAnalizer
cd PcapAnalizer
pip install -r requirments.txt
python main.py testing_files\icmp_flood.pcap
