import colorama

def generate(domain):
    print(f"{colorama.Fore.CYAN}Generating Google Dorks for: {domain}{colorama.Style.RESET_ALL}\n")
    
    dorks = {
        "Public Exposed Docs (PDF, XLS, DOC)": f"site:{domain} ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv",
        "Directory Listing": f"site:{domain} intitle:index.of",
        "Configuration Files": f"site:{domain} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ini",
        "Database Files": f"site:{domain} ext:sql | ext:dbf | ext:mdb",
        "Login Pages": f"site:{domain} inurl:login | inurl:signin | intitle:Login | intitle:\"sign in\" | inurl:auth",
        "PHP Errors / Warning": f"site:{domain} \"PHP Parse error\" | \"PHP Warning\" | \"PHP Error\"",
        "Wordpress Entries": f"site:{domain} inurl:wp- | inurl:wp-content | inurl:plugins | inurl:uploads | inurl:themes | inurl:download",
    }
    
    for title, query in dorks.items():
        print(f"{colorama.Fore.YELLOW}[{title}]{colorama.Style.RESET_ALL}")
        print(f"{query}\n")
        
    print(f"{colorama.Fore.GREEN}Copy and paste these queries into Google Search.{colorama.Style.RESET_ALL}")
