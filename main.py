import sys
import socket
import re
import ipaddress
from pprint import pprint
from bin.scanner import scan_host, scan_network

def build_network_list(cidr_range:ipaddress.IPv4Network):
    network_list_return = list(cidr_range.hosts())
    return network_list_return

def is_ip(input):
    try:
        ip_match = ipaddress.ip_address(input)
    except ValueError:
        ip_match = False
    return bool(ip_match)

def is_network(input):
    try:
        cidr_block = ipaddress.ip_network(input)
        if cidr_block.prefixlen == 32:
            return False
        else: 
            network_match = True
    except ValueError:
        network_match = False
    return bool(network_match)

def is_valid_hostname(hostname):
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    if len(hostname) > 253:
        return False
    try: 
        labels = hostname.split(".")

        if re.match(r"[0-9]+$", labels[-1]):
            return False

        allowed = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(allowed.match(label) for label in labels)
    except:
        return False    

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

QUICK_SCAN_PORTS = [22,25,53,80,110,143,443,445,3389,8080]

def main():
    if len(sys.argv) == 2:
        if bool(is_ip(sys.argv)) or bool(is_network(sys.argv)) or bool(is_valid_hostname(sys.argv)):
            user_input = sys.argv[1]

    else:
        input_valid = False
        print("No arguments passed")
        while not input_valid:
            user_input=input("Please enter a fully qualified hostname (exmaple.com), IPv4 address (172.16.1.1), or IPv4 network CIDR block (172.16.1.0/24): ")
            if bool(is_ip(user_input)) or bool(is_network(user_input)) or bool(is_valid_hostname(user_input)):
                input_valid = True
            else:
                print("You did not supply a valid input, please try again")


    host_list = list()

    if bool(is_ip(user_input)):
        print("A single host was provided. Scanner will only scan that host")
        ip_address = ipaddress.IPv4Address(user_input)
        host_list.append(ip_address)

    if bool(is_valid_hostname(user_input)):
        print("A hostname was provided. Scanner will get the IP for it only scan that host")
        user_input = socket.gethostbyname(user_input)
        ip_address = ipaddress.IPv4Address(user_input)
        host_list.append(ip_address)

    if bool(is_network(user_input)):
        print("A network CIDR block was provided. A list of hosts will be passed to the scanner ")
        cidr_block = ipaddress.IPv4Network(user_input)
        host_list = build_network_list(cidr_block)

    exit_bool = False
    results_list = list()
    
    while not exit_bool:
        print("Please select a scan type:")
        print("\n 1: Quick scan of common ports (default) \n 2: Full scan \n 3: Scan one or more specified ports")
        if results_list:
            print(" 9: Display results")
        print(" 0: Exit")
        scan_type = int(input("Selection: "))
        match scan_type:
            case 1:
                if len(host_list) == 1:
                    results_list.append(scan_host(host_list[0], QUICK_SCAN_PORTS))
                else:
                    results_list = scan_network(host_list,QUICK_SCAN_PORTS)

            case 2:
                if len(host_list) == 1:
                    results_list.append(scan_host(host_list[0]))
                else:
                    results_list = scan_network(host_list)

            case 3:
                user_ports = user_port_list()
                if len(host_list[0]) == 1:
                    results_list.append(scan_host(host_list, user_ports))
                else:
                    results_list = scan_network(host_list, user_ports)

            case 9:
                if bool(results_list):
                    for result in results_list:
                        print(f"Open ports for {result.host}")
                        print(*result.open_ports)
                else:
                    print("There are no results in memory. Please run a scan before attempting to display results.")
            
            case 0:
                print("Exiting port scanner")
                exit_bool = True

            case _:
                results_list.append(scan_host(host_list, QUICK_SCAN_PORTS))

if __name__ == '__main__':
    main()