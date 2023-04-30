from collections.abc import Callable, Iterable, Mapping
import socket
import sys
import multiprocessing
from multiprocessing import Process, Queue
from datetime import datetime
from typing import Any

class TargetHostThreaded(Process):
    def __init__(self, queue, target, port_list):
        Process.__init__(self)
        self.queue = queue
        self.target = target
        self.port_list = port_list
    
    def scan_host(self, target, port_list:list=[]):
        open_ports = list()
        if not any(port_list):
            port_list.extend(range(1, 65535))
        try: 
            for port in port_list:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.setdefaulttimeout(1)
                result = s.connect_ex((target.compressed,port))
                if result ==0:
                    print("Port {} is open".format(port))
                    open_ports.append(result)
                s.close()
        except KeyboardInterrupt:
            print("\n User terminated the scan!")
            sys.exit()
        except socket.error:
            print("\n Host is not responding!")
            sys.exit()
        finally:
            return open_ports
    
    def run(self):
        results = self.scan_host(self.target.compressed, self.port_list)
        self.queue.put(results)

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

def scan_network_threaded(host_list:list, port_list:list):
    result_list = list()
    queue = Queue()
    number_networks = len(host_list)
    for host in host_list:
        # scan_host(network, port_list)
        result_list.append(scan_host(queue, host, port_list))

        for item in result_list:
            item.start()
        
        while number_networks > 0:
            return_results = queue.get()
            number_networks -=1
        print("test")

def scan_network(host_list:list, port_list:list) -> list:
    result_list = list()
    for host in host_list:
        scan_host(host, port_list)
        result_list.append(TargetHost(host, port_list))
    return result_list