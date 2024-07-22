import subprocess
import re
import csv
import sqlite3
from scapy.all import sniff, DNS, DNSQR
import socket
import time
import json
from api_usage import monitor_api

def get_active_devices():
    conn = sqlite3.connect('new_devices.db')
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT mac_adress FROM new_devices WHERE status=?", ('active',))
        rows = cursor.fetchall()
        
        if rows:
            
            # Load the allowed devices from JSON strings
            allowed_devices = set()
            for row in rows:
                mac_address = row[0]
                if mac_address:
                    allowed_devices.add(mac_address)

            return allowed_devices  # Return as a set for easy comparison

        return set()  # Return an empty set if no devices are found

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return set()
    except Exception as e:
        print(f"Exception in get_allowed_devices: {e}")
        return set()
    finally:
        conn.close()


if __name__ == '__main__':
    interface ="Local Area Connection* 10"
    active_devices = get_active_devices()
    print(active_devices)
    for devices in active_devices:
        monitor_api(interface, devices)
        print(f"hhhhhh{devices}")