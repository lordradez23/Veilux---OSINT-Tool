import phonenumbers
from phonenumbers import geocoder, carrier
import colorama

def lookup(number):
    print(f"{colorama.Fore.CYAN}Analyzing phone number: {number}...{colorama.Style.RESET_ALL}")
    try:
        parsed_number = phonenumbers.parse(number)
        if not phonenumbers.is_valid_number(parsed_number):
             print(f"{colorama.Fore.RED}[!] Invalid phone number.{colorama.Style.RESET_ALL}")
             return

        country = geocoder.description_for_number(parsed_number, "en")
        carrier_name = carrier.name_for_number(parsed_number, "en")
        
        print(f"{colorama.Fore.RED}[+] Country: {colorama.Fore.WHITE}{country}{colorama.Style.RESET_ALL}")
        print(f"{colorama.Fore.RED}[+] Carrier: {colorama.Fore.WHITE}{carrier_name}{colorama.Style.RESET_ALL}")
        
    except phonenumbers.phonenumberutil.NumberParseException:
        print(f"{colorama.Fore.RED}[!] Error: Could not parse number. Ensure it includes country code (e.g. +1...){colorama.Style.RESET_ALL}")
    except Exception as e:
         print(f"{colorama.Fore.RED}[!] Unexpected Error: {e}{colorama.Style.RESET_ALL}")
