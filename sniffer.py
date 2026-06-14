from scapy.all import sniff , IP ,TCP ,UDP ,ICMP,Raw 
import hashlib

def handle_packet(pkt):
    print(pkt.summary())
    if pkt.haslayer(IP):
        source = pkt[IP].src
        destination = pkt[IP].dst
        if pkt.haslayer(TCP):
            print("source port :",pkt[TCP].sport)
            print("destination port:",pkt[TCP].dport)
            print("Flags :",pkt[TCP].flags)
        if pkt.haslayer(UDP):
            print("source port :",pkt[UDP].sport)
            print("destination port:",pkt[UDP].dport)
        if pkt.haslayer(ICMP):
            print("Packet type :",pkt[ICMP].type)
        if pkt.haslayer(Raw):
            raw_bytes = (pkt[Raw].load)
            print(raw_bytes,"\n")
            raw_text = raw_bytes.decode('utf-8',errors='ignore').strip()
            print(raw_text[:100])
            
        print("src :",source , "dst:",destination)
    
sniff(prn=handle_packet, count=10)

