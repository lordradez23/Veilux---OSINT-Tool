import time
import sys
import random
import shutil
import colorama
import winsound
import threading

def aggressive_boot():
    """
    Flashes red/white warning to simulate a dangerous system boot while loading.
    """
    messages = [
        "INITIALIZING DEEP RECON MODULES...",
        "ACCESSING RESTRICTED DATABASES...",
        "PROXY CHAINS: ENGAGED",
        "TARGETING SYSTEMS...",
        "PROTOCOL: DIGITAL BLOOD"
    ]
    
    for msg in messages:
        # Flash effect
        sys.stdout.write(f"\r{colorama.Back.RED}{colorama.Fore.WHITE} {msg} {colorama.Style.RESET_ALL}")
        sys.stdout.flush()
        time.sleep(0.3)
        sys.stdout.write(f"\r{colorama.Back.BLACK}{colorama.Fore.RED} {msg} {colorama.Style.RESET_ALL}")
        sys.stdout.flush()
        time.sleep(0.2)
        print()
    print("\n")

def typewriter(text, speed=0.03):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(speed)
    print()

def play_hacker_sounds():
    """
    Plays background typing/hacking sounds using winsound.
    Runs in a separate thread to not block the UI.
    """
    def beep_sequence():
        try:
            # Rapid typing sounds - high frequency short beeps
            for _ in range(20):
                winsound.Beep(800, 50)  # 800Hz for 50ms
                time.sleep(0.1)
        except:
            pass  # Ignore if sound fails
    
    # Run in background thread
    thread = threading.Thread(target=beep_sequence, daemon=True)
    thread.start()

def matrix_rain(duration=3):
    """
    Matrix rain that fills the entire screen and transitions to the banner.
    """
    columns, rows = shutil.get_terminal_size()
    chars = "01"
    
    # Fill the entire screen with matrix rain
    end_time = time.time() + duration
    try:
        while time.time() < end_time:
            line = "".join(random.choice(chars) for _ in range(columns))
            print(f"{colorama.Fore.RED}{line}{colorama.Style.RESET_ALL}")
            time.sleep(0.02)
    except KeyboardInterrupt:
        pass
    
    # Brief pause before banner
    time.sleep(0.3) 

def random_quote():
    quotes = [
        "The quieter you become, the more you are able to hear.",
        "There is no patch for human stupidity.",
        "Access Granted.",
        "We are all connected.",
        "Searching for the truth...",
        "Systems compromised...",
        "Protocol initiated.",
        "Hide No More.",
        "Knowledge is power.",
        "Digital shadows follow everyone."
    ]
    quote = random.choice(quotes)
    print(f"\n{colorama.Fore.RED}\"{quote}\"{colorama.Style.RESET_ALL}\n")
