import os
import time
from scapy.all import ARP, Ether, srp
from bluetooth import discover_devices
import pyfiglet

# Display banner
def display_banner():
    banner = pyfiglet.figlet_format("Marauders Map")
    print(banner)
    print("Mischief Managed - Python Edition")
    print("-" * 40)

# Network device discovery using ARP
def discover_network_devices():
    print("[*] Scanning for network devices...")
    ip_range = input("Enter IP range (e.g., 192.168.1.1/24): ")
    arp_request = ARP(pdst=ip_range)
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether_frame / arp_request

    answered = srp(packet, timeout=2, verbose=0)[0]
    devices = []

    for sent, received in answered:
        devices.append({'IP': received.psrc, 'MAC': received.hwsrc})

    print("\nDiscovered Network Devices:")
    for device in devices:
        print(f"IP: {device['IP']}, MAC: {device['MAC']}")
    return devices

# Bluetooth device discovery
def discover_bluetooth_devices():
    print("\n[*] Scanning for Bluetooth devices...")
    devices = discover_devices(duration=8, lookup_names=True, flush_cache=True)

    print("\nDiscovered Bluetooth Devices:")
    for addr, name in devices:
        print(f"Device Name: {name}, MAC Address: {addr}")
    return devices

# Map visualization (placeholder)
def visualize_map(devices):
    print("\n[*] Visualizing devices on the map (mockup)...")
    for idx, device in enumerate(devices, start=1):
        print(f"Device {idx}: {device}")
    print("\n[!] Map visualization not implemented yet. Stay tuned!")

# Main function
def main():
    display_banner()

    while True:
        print("\nMenu:")
        print("1. Discover Network Devices")
        print("2. Discover Bluetooth Devices")
        print("3. Visualize Map")
        print("4. Exit")
        choice = input("Select an option: ")

        if choice == "1":
            network_devices = discover_network_devices()
        elif choice == "2":
            bluetooth_devices = discover_bluetooth_devices()
        elif choice == "3":
            # Combine network and Bluetooth devices for visualization
            devices = network_devices + bluetooth_devices
            visualize_map(devices)
        elif choice == "4":
            print("Exiting... Mischief Managed!")
            break
        else:
            print("Invalid option. Please try again.")

# Run the script
if __name__ == "__main__":
    main()