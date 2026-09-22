import os

class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    BOLD = '\033[1m'
    ENDC = '\033[0m'

os.system('cls' if os.name == 'nt' else 'clear')
print(f"{Colors.CYAN}{Colors.BOLD}===================================================={Colors.ENDC}")
print(f"{Colors.CYAN}{Colors.BOLD}       TRANSPARENT THREAT ENGINE - LAUNCHER         {Colors.ENDC}")
print(f"{Colors.CYAN}{Colors.BOLD}===================================================={Colors.ENDC}\n")

print("Select an execution mode:")
print(f"  {Colors.GREEN}[1]{Colors.ENDC} Transparent Engine (Curated Hackathon Demo)")
print(f"  {Colors.GREEN}[2]{Colors.ENDC} IDS Tripwire (Full X_test.npy Benchmark Scan)")
print(f"  {Colors.GREEN}[3]{Colors.ENDC} Live Scapy Monitor (Real-Time Network Sniffing)\n")

choice = input(f"{Colors.BOLD}Enter 1, 2, or 3: {Colors.ENDC}")

if choice == '1':
    os.system("python transparent_engine.py")
elif choice == '2':
    os.system("python ids_tripwire.py")
elif choice == '3':
    os.system("python live_scapy_monitor.py")
else:
    print("Invalid selection. Exiting.")