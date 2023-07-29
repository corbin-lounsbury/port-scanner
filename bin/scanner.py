import socket
import sys
from datetime import datetime
from typing import Any

class TargetHost():
    def __init__(self, host, open_ports) -> None:
        self.host = host
        self.open_ports = open_ports
        

def scan_host(target, port_list:list=[]):
    open_port_list = list()
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
                open_port_list.append(port)
            s.close()
    except KeyboardInterrupt:
        print("\n User terminated the scan!")
        sys.exit()
    except socket.error:
        print("\n Host is not responding!")
        sys.exit()
    finally:
        print("Scan complete! Results are above.")
        return TargetHost(target, open_port_list)

def scan_network(host_list:list, port_list:list) -> list:
    result_list = list()
    for host in host_list:
        scan_host(host, port_list)
        result_list.append(TargetHost(host, port_list))
    return result_list