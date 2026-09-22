import os
import sys
import time
import random
import warnings
import joblib
import numpy as np
import torch
import torch.nn as nn

# Suppress environment warnings for a clean UI
os.environ["PYTHONWARNINGS"] = "ignore"
warnings.filterwarnings("ignore")
warnings.simplefilter(action='ignore', category=FutureWarning)
warnings.simplefilter(action='ignore', category=UserWarning)

# ==========================================
# 1. ANSI COLORS FOR TERMINAL UI
# ==========================================
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    CRITICAL = '\033[91m'
    BOLD = '\033[1m'
    ENDC = '\033[0m'

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# ==========================================
# 2. VAE ARCHITECTURE
# ==========================================
class LSTM_VAE(nn.Module):
    def __init__(self, n_features=65, seq_length=10, hidden_dim=128, latent_dim=32):
        super(LSTM_VAE, self).__init__()
        self.seq_length = seq_length
        self.encoder_lstm = nn.LSTM(n_features, hidden_dim, num_layers=1, batch_first=True)
        self.mean_layer = nn.Linear(hidden_dim, latent_dim)
        self.logvar_layer = nn.Linear(hidden_dim, latent_dim)
        self.dec_input_layer = nn.Linear(latent_dim, hidden_dim)
        self.decoder_lstm = nn.LSTM(hidden_dim, hidden_dim, num_layers=1, batch_first=True)
        self.output_layer = nn.Linear(hidden_dim, n_features)

    def encode(self, x):
        _, (h_n, _) = self.encoder_lstm(x)
        return self.mean_layer(h_n.squeeze(0)), self.logvar_layer(h_n.squeeze(0))

    def reparameterize(self, mu, logvar):
        std = torch.exp(0.5 * logvar)
        return mu + torch.randn_like(std) * std

    def decode(self, z):
        z_repeated = self.dec_input_layer(z).unsqueeze(1).repeat(1, self.seq_length, 1)
        dec_out, _ = self.decoder_lstm(z_repeated)
        return self.output_layer(dec_out)

    def forward(self, x):
        mu, logvar = self.encode(x)
        z = self.reparameterize(mu, logvar)
        return self.decode(z), mu, logvar

# ==========================================
# 3. MOUNTING ASSETS
# ==========================================
device = torch.device("cpu")
vae_model = LSTM_VAE()
vae_model.load_state_dict(torch.load('models/lstm_vae_best_weights.pth', map_location=device))
vae_model.eval()

rf_classifier = joblib.load('models/stage2_rf_classifier.pkl')
rf_classifier.n_jobs = 1 

X_test = np.load('data/X_test.npy')
THRESHOLD = 2163880361984.0 # Locked threshold

# ==========================================
# 4. PREPARE THE DEMO SCENARIO
# ==========================================
print("[*] Booting Simulator & Hunting for diverse threat signatures...")
benign_sequences = X_test[0:3] # 3 known normal sequences
attack_showcase = {} # Will store unique attack types

# Hunt for up to 5 different real attacks in the dataset
for i in range(100, 25000):
    seq_tensor = torch.tensor(X_test[i:i+1], dtype=torch.float32)
    with torch.no_grad():
        recon, mu, logvar = vae_model(seq_tensor)
        mse = torch.mean((recon - seq_tensor) ** 2).item()
        kld = -0.5 * torch.mean(1 + logvar - mu.pow(2) - logvar.exp()).item()
        score = mse + (0.001 * kld)
    
    if score > THRESHOLD:
        trigger = X_test[i][-1].reshape(1, -1)
        pred = str(rf_classifier.predict(trigger)[0]).upper()
        
        # Save it if it's a new type of attack we haven't found yet
        if pred not in attack_showcase:
            attack_showcase[pred] = X_test[i:i+1]
            print(f" [+] Isolated signature for: {pred}")
            
        if len(attack_showcase) >= 5: # Limit to 5 unique attacks for the demo
            break

if not attack_showcase:
    print("[!] Couldn't find any attacks. Check threshold. Exiting.")
    sys.exit()

time.sleep(2)
clear_screen()
print(f"{Colors.CYAN}{Colors.BOLD}")
print("="*95)
print(" 🌐 NTRO/SIH ZERO-DAY NETWORK MONITOR (MULTI-THREAT SIMULATION) ")
print("="*95)
print(f"{Colors.ENDC}")
print(f"{Colors.BOLD}[*] INGRESS INTERFACE ONLINE. LISTENING FOR TRAFFIC...{Colors.ENDC}\n")
time.sleep(1)

# ==========================================
# 5. EXECUTE SIMULATION
# ==========================================
def process_packet(sequence_tensor, seq_id, is_malicious=False):
    src_ip = f"192.168.1.{random.randint(10, 50)}"
    dst_ip = f"10.0.0.{random.randint(2, 9)}"
    port = 443 if not is_malicious else random.choice([80, 21, 22, 445])
    
    # Calculate actual network intensity from the tensor
    intensity = float(np.max(np.abs(sequence_tensor.numpy())))
    
    print("-" * 95)
    print(f"[{time.strftime('%H:%M:%S')}] {Colors.BLUE}PKT_ID: {seq_id}{Colors.ENDC} | SRC: {src_ip} -> DST: {dst_ip}:{port}")
    print(f"            | {Colors.BOLD}FLOW INTENSITY (Max Amplitude):{Colors.ENDC} {intensity:,.2f}")
    
    time.sleep(1) 
    print(f"            | {Colors.WARNING}[*] Routing to Stage 1 LSTM-VAE for physics validation...{Colors.ENDC}")
    
    with torch.no_grad():
        recon, mu, logvar = vae_model(sequence_tensor)
        mse = torch.mean((recon - sequence_tensor) ** 2).item()
        kld = -0.5 * torch.mean(1 + logvar - mu.pow(2) - logvar.exp()).item()
        score = mse + (0.001 * kld)
        
    time.sleep(1)
    
    if score > THRESHOLD:
        print(f"            | {Colors.CRITICAL}[!] ALERT! Physics Violation Detected (Score: {score:,.0f}){Colors.ENDC}")
        print(f"            | {Colors.WARNING}[*] Extracting payload. Engaging Stage 2 Tactical Officer...{Colors.ENDC}")
        time.sleep(1.5)
        
        trigger_packet = sequence_tensor.numpy()[0, -1].reshape(1, -1)
        pred = rf_classifier.predict(trigger_packet)[0]
        
        print(f"            | {Colors.CRITICAL}🚨 FINAL VERDICT: QUARANTINED [{str(pred).upper()}] 🚨{Colors.ENDC}")
    else:
        print(f"            | {Colors.GREEN}[OK] Normal Traffic Baseline (Score: {score:,.0f} < Threshold). PASS.{Colors.ENDC}")
    print("-" * 95 + "\n")

# --- PHASE 1: NORMAL TRAFFIC ---
print(f"{Colors.GREEN}{Colors.BOLD} >>> PHASE 1: ESTABLISHING NORMAL TRAFFIC BASELINE <<< {Colors.ENDC}")
for i, seq in enumerate(benign_sequences):
    seq_tensor = torch.tensor(seq).unsqueeze(0).to(torch.float32)
    process_packet(seq_tensor, f"SEQ-{i:06d}")
    time.sleep(1.5) 

# --- PHASE 2: ATTACK INJECTIONS ---
print(f"\n{Colors.CRITICAL}{Colors.BOLD} >>> PHASE 2: INJECTING ISOLATED THREAT SIGNATURES <<< {Colors.ENDC}")
time.sleep(2)

attack_id = 999000
for attack_name, attack_seq in attack_showcase.items():
    print(f"\n{Colors.WARNING}[*] Injecting confirmed {attack_name} signature into stream...{Colors.ENDC}")
    time.sleep(1)
    seq_tensor = torch.tensor(attack_seq).to(torch.float32)
    process_packet(seq_tensor, f"SEQ-{attack_id}", is_malicious=True)
    attack_id += 1
    time.sleep(2.5)