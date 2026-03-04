import socket
import threading
import colorama
from queue import Queue

def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"{colorama.Fore.GREEN}[+] Port {port} is OPEN{colorama.Style.RESET_ALL}")
        sock.close()
    except:
        pass

def scanner(target):
    print(f"{colorama.Fore.CYAN}Scanning top common ports on {target}...{colorama.Style.RESET_ALL}")
    
    # Top 20 common ports
    common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    
    threads = []
    
    for port in common_ports:
        thread = threading.Thread(target=scan_port, args=(target, port))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
        
    print(f"{colorama.Fore.CYAN}Scan complete.{colorama.Style.RESET_ALL}")
