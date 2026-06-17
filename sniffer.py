from scapy.all import sniff , IP ,TCP ,UDP ,ICMP,Raw 
from colorama import Fore, Style 
from datetime import datetime 
import argparse


PORT_NAMES = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    22: "SSH",
    21: "FTP",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    3306: "MySQL",
    3389: "RDP",
}

# Configure command-line arguments
parser = argparse.ArgumentParser(description="Basic Network Sniffer")

# Number of packets to capture (0 means capture indefinitely)
parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets (0 = infinite)")
args = parser.parse_args()

# Tracks total packets processed
packet_count = 0


def handle_packet(pkt):
    """
    Callback function executed for every captured packet.

    Responsibilities:
    - Filter non-IP packets
    - Extract source and destination information
    - Identify protocol type (TCP/UDP/ICMP)
    - Display packet details
    - Display payload data if available
    """

    global packet_count
    packet_count += 1

    # Generate capture timestamp
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    if not pkt.haslayer(IP):
        return #drops non ip packet
    
    # Extract source and destination IP addresses
    source = pkt[IP].src
    destination = pkt[IP].dst

    print (Fore.WHITE + "=" * 55)

    if pkt.haslayer(TCP): #TCP packets
                proto_name = PORT_NAMES.get(pkt[TCP].dport) or PORT_NAMES.get(pkt[TCP].sport) or "TCP"
                print( Fore.GREEN + "[TCP]"+ Style.RESET_ALL  +f"  Packet #{packet_count}  |  { timestamp } " + f"|  {source}:{pkt[TCP].sport} ---> {destination}:{pkt[TCP].dport}" + f"  Flags : {pkt[TCP].flags}  [{proto_name}]")
    
    elif pkt.haslayer(UDP): #UDP packets
                proto_name = PORT_NAMES.get(pkt[UDP].dport) or PORT_NAMES.get(pkt[UDP].sport) or "UDP"
                print( Fore.CYAN + "[UDP]" + Style.RESET_ALL  +f"  Packet #{packet_count}  |  { timestamp } "+ f"|  {source}:{pkt[UDP].sport} ---> {destination}:{pkt[UDP].dport}  [{proto_name}]")
    
    elif pkt.haslayer(ICMP):#ICMP packets
                print( Fore.YELLOW+ "[ICMP]" +Style.RESET_ALL  +f"  Packet #{packet_count}  |  { timestamp } " +f"|  {source} ---> {destination}   Packet type : {pkt[ICMP].type}")
    
    else: #other ip protocols
                print(Fore.MAGENTA + "[OTHER]" + Style.RESET_ALL  +f"  Packet #{packet_count}  |  { timestamp } " + f"|  {source}  →  {destination}")
    
      # Check whether packet contains payload data
    if pkt.haslayer(Raw):

        # Decode bytes into readable text
        # Ignore invalid UTF-8 characters
        raw_text = pkt[Raw].load.decode('utf-8',errors='ignore').strip()
        if raw_text: 
            print(Fore.RED + "Payload :" + Style.RESET_ALL, raw_text[:100])         # Display first 100 characters to avoid flooding terminal           


# Start packet capture
# prn specifies the callback function executed for each packet
# count controls the number of packets to capture
sniff(prn=handle_packet, count=args.count)