import socket
from scapy.all import sniff, wrpcap
from scapy.layers.l2 import Ether
import sqlite3
import json

def resolve_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None
    
def store_in_db(device_mac, blacklist_mac):
    conn = sqlite3.connect('new_devices.db')
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO url_alerts_new (mac_address, blacklist_mac) VALUES (?, ?)", (device_mac, blacklist_mac))
        conn.commit()
        print("saved into database")

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return set()
    except Exception as e:
        print(f"Exception in get_allowed_devices: {e}")
        return set()
    finally:
        conn.close()


def process_packet(packet, target_mac, collected_packets, blacklisted_macs,illegal_connections):
    # def process_packet(packet,target_ip, collected_data,connecting_devices):
    
    if 'IP' in packet:
        source_ip = packet['IP'].src
        dest_ip = packet['IP'].dst
        src_mac = packet[Ether].src if Ether in packet else 'N/A'
        dst_mac = packet[Ether].dst if Ether in packet else 'N/A'

        if src_mac == target_mac or dst_mac == target_mac:
            protocol = packet.sprintf("%IP.proto%")
            dns_name = resolve_dns(dest_ip) if dst_mac != target_mac else resolve_dns(source_ip)
            
            # Check if dst_mac is in the blacklisted MAC addresses
            if dst_mac in blacklisted_macs:
                print(f"Blacklisted MAC address detected: {dst_mac}")
                if dst_mac not in illegal_connections:
                    illegal_connections.append(dst_mac)
                    print("hhhhh")
                    store_in_db(target_mac, dst_mac)
        
            # Store the packet
            collected_packets.append(packet)

def monitor_api(interface_description,device_mac):
    illegal_connections = []
    # interface_description = 'Local Area Connection* 10'
    # device_mac = '42:56:21:fc:c9:36'
    # output_file = 'packet_capture.pcap'
    collected_packets = []
    
    # Define the list of blacklisted MAC addresses
    blacklisted_macs = [
        '36:2e:b7:14:cb:98','42:56:21:fc:c9:36',
        '00:1a:2b:3c:4d:5e',
        # Add more MAC addresses as needed
    ]
    
    sniff(iface=interface_description, prn=lambda x: process_packet(x, device_mac, collected_packets, blacklisted_macs,illegal_connections), store=0, timeout=20)
    if illegal_connections:
        print("jjjjjjj")
        
    