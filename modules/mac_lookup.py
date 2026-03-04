from mac_vendor_lookup import MacLookup, BaseMacLookup
import colorama

def lookup(mac_address):
    print(f"{colorama.Fore.CYAN}Looking up vendor for MAC: {mac_address}{colorama.Style.RESET_ALL}")
    try:
        # Update vendor list locally (first time might take a moment)
        BaseMacLookup.cache_path = "mac-vendors.txt" 
        mac = MacLookup()
        # mac.update_vendors() # Optional: force update, but might fail without internet or permissios. 
                               # Usually the library handles cache. Let's try basic lookup.
        
        vendor = mac.lookup(mac_address)
        print(f"{colorama.Fore.GREEN}[+] Vendor: {vendor}{colorama.Style.RESET_ALL}")
    except KeyError:
         print(f"{colorama.Fore.RED}[-] Vendor not found.{colorama.Style.RESET_ALL}")
    except Exception as e:
         print(f"{colorama.Fore.RED}Error: {e}{colorama.Style.RESET_ALL}")
         print(f"{colorama.Fore.YELLOW}Tip: Ensure you are connected to the internet for the first run to download vendor list.{colorama.Style.RESET_ALL}")

