import dns.resolver
import colorama

def enum(domain):
    record_types = ['A', 'MX', 'NS', 'TXT', 'CNAME']
    print(f"{colorama.Fore.CYAN}Enumerating DNS records for {domain}...{colorama.Style.RESET_ALL}\n")
    
    resolver = dns.resolver.Resolver()
    
    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type)
            print(f"{colorama.Fore.YELLOW}[*] {record_type} Records:{colorama.Style.RESET_ALL}")
            for rdata in answers:
                print(f"  - {rdata.to_text()}")
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            print(f"{colorama.Fore.RED}Domain {domain} does not exist.{colorama.Style.RESET_ALL}")
            return
        except Exception as e:
            print(f"{colorama.Fore.RED}Error retrieving {record_type} records: {e}{colorama.Style.RESET_ALL}")
    print("\n")
