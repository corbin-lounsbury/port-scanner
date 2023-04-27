import sys
import socket
import re
from datetime import datetime
  
def check_input(input):
    ip_match = re.match(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", input)
    hostname_match = is_valid_hostname(input)
    return bool(ip_match or hostname_match)

def is_valid_hostname(hostname):
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    if len(hostname) > 253:
        return False

    labels = hostname.split(".")

    if re.match(r"[0-9]+$", labels[-1]):
        return False

    allowed = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(label) for label in labels)    

def user_port_list() -> list:
    port_list_return = list()
    done = False
    while done is False:
        user_input = input("Enter a numeric port. Press enter when done ")
        if user_input == '':
            done = True
            break
        try:
            port = int(user_input)
            port_list_return.append(port)
        except ValueError:
            print("An invalid value was provided, please try again. Note, only integers (numbers) are accepted")
            
    return port_list_return

def run_scan(target, port_list:list=[]):
    if not any(port_list):
        port_list.extend(range(1, 65535))
    print("-" * 50)
    print("Scanning all ports on target: " + target)
    print("Scanning started at:" + str(datetime.now()))
    print("-" * 50)
    
    try:
        
        for port in port_list:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect_ex((target,port))
            if result ==0:
                print("Port {} is open".format(port))
            s.close()
            
    except KeyboardInterrupt:
            print("\n User terminated the scan!")
            sys.exit()
    except socket.error:
            print("\n Host is not responding!")
            sys.exit()

QUICK_SCAN_PORTS = [22,25,53,80,110,143,443,445,3389,8080]

def main():
    if len(sys.argv) == 2:
        host = socket.gethostbyname(sys.argv[1])
    else:
        ip_is_valid = False
        print("No arguments passed")
        while not ip_is_valid:
            user_input=input("Please enter a fully qualified hostname or IPv4 address: ")
            if check_input(user_input):
                host = socket.gethostbyname(user_input)
                ip_is_valid = True
            else:
                print("You did not give a valid hostname or IP address, please try again.") 
    exit_bool = False
    print("Please select a scan type:")
    print("\n 1: Quick scan of common ports (default) \n 2: Full scan \n 3: Scan one or more specified ports")

    scan_type = int(input("Selection: "))

    while not exit_bool:
        match scan_type:
            case 1:
                run_scan(host, QUICK_SCAN_PORTS)
                exit_bool = True
            case 2:
                run_scan(host)
                exit_bool = True
            case 3:
                user_ports = user_port_list()
                run_scan(host, user_ports)
                exit_bool = True
            case 0:
                exit_bool = True
            case _:
                run_scan(host, QUICK_SCAN_PORTS)

if __name__ == '__main__':
    main()