#this is the script to get the payload and check if it is encrypted


from scapy.all import *

# Function to analyze packet and check for encryption
def analyze_packet(packet,unencrypted_data ):
    # Check if the packet has a Raw layer (contains payload data)
    if Raw in packet:
        payload = packet[Raw].load  
        # Heuristic to check for encryption
        # Here, we simply check if the payload looks like binary data (not readable text)
        try:
            print("\n")
            # Attempt to decode payload as ASCII (unencrypted payloads often have readable text)
            payload.decode('ascii')
            # print("Unencrypted payload:", payload)
        except UnicodeDecodeError:
            # If decoding fails, it is likely encrypted or binary data
            print("Encrypted or binary payload:", payload)

# Capture packets (you may need to run this with root privileges)
unencrypted_data = []
print("Starting packet capture. Press Ctrl+C to stop.")
try:
    sniff(iface="Local Area Connection* 10", prn=lambda x:analyze_packet(x, unencrypted_data), store=0,timeout=10)
except KeyboardInterrupt:
    print("Packet capture stopped.")
