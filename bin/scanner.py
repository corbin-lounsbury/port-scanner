import socket
import sys
from datetime import datetime
from typing import Any

class TargetHost():
    '''
    A class to represent a target host as an object.

    Attributes:
        host (ipaddress.IPv4Address): The target host
        open_ports (list): A list of open ports on the target host

    Methods:
        __init__(self, host, open_ports): Initializes the TargetHost object
    '''
    def __init__(self, host, open_ports) -> None:
        self.host = host
        self.open_ports = open_ports
        

def scan_host(target, port_list:list=[]):
    '''
    Initiates a TCP port scan on a target host

    Args:
        target (ipaddress.IPv4Address): A target host to scan
        port_list (list, optional): A list of ports to scan. Defaults to [].
    
    Returns:
        TargetHost: A TargetHost object containing the target host and a list of open ports
    '''
    open_port_list = list()
    if not any(port_list): # If the port list is empty, scan all ports
        port_list.extend(range(1, 65535))
    
    # Print a banner with information on which host we are scanning and which ports
    print("-" * 50)
    print(f"Scanning {len(port_list)} ports on target {target.compressed}")
    print("Scanning started at:" + str(datetime.now()))
    print("-" * 50)
    
    try: # Try to connect to each port in the port list
        for port in port_list:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect_ex((target.compressed,port))
            if result ==0:
                print("Port {} is open".format(port))
                open_port_list.append(port)
            s.close()
    except KeyboardInterrupt: # If the user presses Ctrl+C, cancel the scan.
        print("\n User terminated the scan!")
        sys.exit()
    except socket.error: # if the host is not responding, cancel the scan.
        print("\n Host is not responding!")
        sys.exit()
    finally: # Print a banner with information on which host we are scanning and which ports
        print("Scan complete! Results are above.")
        return TargetHost(target, open_port_list)

def scan_network(host_list:list, port_list:list) -> list:
    '''
    Initiates a TCP port scan on a list of target hosts

    Args:
        host_list (list): A list of target hosts to scan

    Returns:
        list: A list of TargetHost objects containing the target host and a list of open ports
    '''
    result_list = list()
    for host in host_list: # Iterate through the list of hosts and scan each one
        scan_host(host, port_list)
        result_list.append(TargetHost(host, port_list))
    return result_list