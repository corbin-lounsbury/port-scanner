import socket
import sys
from datetime import datetime

def scan_host(target, port_list:list=[]):
    if not any(port_list):
        port_list.extend(range(1, 65535))
    print("-" * 50)
    print(f"Scanning {len(port_list)} ports on target {target.compressed}")
    print("Scanning started at:" + str(datetime.now()))
    print("-" * 50)
    
    try:
        
        for port in port_list:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect_ex((target.compressed,port))
            if result ==0:
                print("Port {} is open".format(port))
            s.close()
    except KeyboardInterrupt:
        print("\n User terminated the scan!")
        sys.exit()
    except socket.error:
        print("\n Host is not responding!")
        sys.exit()
    finally:
        print("Scan complete! Results are above.")

def scan_network(network_list:list, port_list:list):
    for network in network_list:
        scan_host(network, port_list)