import requests
import colorama

def check(email):
    url = f"https://api.xposedornot.com/v1/check-email/{email}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if "Error" in data:
                 print(f"{colorama.Fore.GREEN}Good news! No breaches found for {email}{colorama.Style.RESET_ALL}")
            else:
                print(f"{colorama.Fore.RED}Breaches found for {email}:{colorama.Style.RESET_ALL}")
                if "Breaches" in data and data["Breaches"]:
                    for breach in data["Breaches"]:
                        print(f"- {breach[0]}")
                else:
                    # In case the structure is different or it's a list
                    print(data)

        elif response.status_code == 404:
             print(f"{colorama.Fore.GREEN}Good news! No breaches found for {email}{colorama.Style.RESET_ALL}")
        else:
            print(f"{colorama.Fore.YELLOW}Could not fetch breach data. Status code: {response.status_code}{colorama.Style.RESET_ALL}")
    except Exception as e:
        print(f"{colorama.Fore.RED}Error checking email breach: {e}{colorama.Style.RESET_ALL}")
