import socket
from scapy.all import sniff, wrpcap
from scapy.layers.l2 import Ether

def resolve_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def process_packet(packet, target_ip, collected_packets, blacklisted_macs):
    if 'IP' in packet:
        source_ip = packet['IP'].src
        dest_ip = packet['IP'].dst
        if source_ip == target_ip or dest_ip == target_ip:
            protocol = packet.sprintf("%IP.proto%")
            dns_name = resolve_dns(dest_ip) if dest_ip != target_ip else resolve_dns(source_ip)
            
            dst_mac = packet[Ether].dst if Ether in packet else 'N/A'
            
            # Check if dst_mac is in the blacklisted MAC addresses
            if dst_mac in blacklisted_macs:
                print(f"Blacklisted MAC address detected: {dst_mac}")
            
            # Store the packet
            collected_packets.append(packet)

if __name__ == '__main__':
    interface_description = 'Local Area Connection* 10'
    device_ip = '192.168.137.29'
    output_file = 'packet_capture.pcap'
    collected_packets = []
    
    # Define the list of blacklisted MAC addresses
    blacklisted_macs = [
        '36:2e:b7:14:cb:98','42:56:21:fc:c9:36',
        '00:1a:2b:3c:4d:5e',
        # Add more MAC addresses as needed
    ]
    
    sniff(iface=interface_description, prn=lambda x: process_packet(x, device_ip, collected_packets, blacklisted_macs), store=0, timeout=10)
    
    if collected_packets:
        wrpcap(output_file, collected_packets)
        print(f"Packets stored in {output_file}")