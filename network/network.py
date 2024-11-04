import scapy.all as scapy
import datetime
from colorama import Fore, Style, init

init(autoreset=True)

def print_header():
    print("\n" + "="*60)
    print(f"{Fore.GREEN}   🌐 Welcome to The Advanced Packet Sniffer Tool   {Style.RESET_ALL}")
    print("="*60 + "\n")

def packet_callback(packet):
    # Extract basic information
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        # Print packet details with color coding
        print(f"\n{Fore.CYAN}Timestamp: {datetime.datetime.now()} | Protocol: {protocol}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Source IP: {src_ip} | Destination IP: {dst_ip}{Style.RESET_ALL}")

        # Check for TCP packets
        if packet.haslayer(scapy.TCP):
            print(f"{Fore.BLUE}🔹 TCP Packet Detected{Style.RESET_ALL}")
            try:
                if packet.haslayer(scapy.Raw):
                    payload = packet[scapy.Raw].load
                    decoded_payload = payload.decode('utf-8', 'ignore')
                    print(f"{Fore.MAGENTA}Payload (TCP): {decoded_payload}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}No payload in this TCP packet.{Style.RESET_ALL}")
            except (IndexError, UnicodeDecodeError):
                print(f"{Fore.RED}Failed to decode TCP payload.{Style.RESET_ALL}")

        # Check for UDP packets
        elif packet.haslayer(scapy.UDP):
            print(f"{Fore.GREEN}🔹 UDP Packet Detected{Style.RESET_ALL}")
            try:
                if packet.haslayer(scapy.Raw):
                    payload = packet[scapy.Raw].load
                    decoded_payload = payload.decode('utf-8', 'ignore')
                    print(f"{Fore.MAGENTA}Payload (UDP): {decoded_payload}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}No payload in this UDP packet.{Style.RESET_ALL}")
            except (IndexError, UnicodeDecodeError):
                print(f"{Fore.RED}Failed to decode UDP payload.{Style.RESET_ALL}")

def start_sniffing():
    print_header()
    print(f"{Fore.GREEN}⚡ Starting packet sniffing... Ensure you're authorized to monitor this network.{Style.RESET_ALL}")
    
    # Sniff packets and handle each packet with packet_callback
    scapy.sniff(store=False, prn=packet_callback)

if __name__ == "__main__":
    try:
        start_sniffing()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}🚨 Packet sniffing stopped. Remember to use this tool responsibly and ethically.{Style.RESET_ALL}")