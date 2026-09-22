import torch
import torch.nn as nn
import numpy as np
import time
import os
import sys
import joblib
import warnings

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

clear_screen()
print(f"{Colors.CYAN}{Colors.BOLD}")
print("="*85)
print(" 🛡️  NTRO/SIH DUAL-STAGE INTRUSION DETECTION SYSTEM (OFFLINE CLI) ")
print("="*85)
print(f"{Colors.ENDC}")

# ==========================================
# 2. VAE ARCHITECTURE (STAGE 1)
# ==========================================
class LSTM_VAE(nn.Module):
    def __init__(self, n_features, seq_length, hidden_dim=128, latent_dim=32):
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
        h_n = h_n.squeeze(0)
        return self.mean_layer(h_n), self.logvar_layer(h_n)

    def reparameterize(self, mu, logvar):
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        return mu + eps * std

    def decode(self, z):
        z_repeated = self.dec_input_layer(z).unsqueeze(1).repeat(1, self.seq_length, 1)
        dec_out, _ = self.decoder_lstm(z_repeated)
        return self.output_layer(dec_out)

    def forward(self, x):
        mu, logvar = self.encode(x)
        z = self.reparameterize(mu, logvar)
        return self.decode(z), mu, logvar

# ==========================================
# 3. MOUNTING ASSETS (DUAL ENGINES)
# ==========================================
print("[*] Initializing local compute engines...")
device = torch.device("cpu") 

print("[*] Loading Stage 1: Unsupervised VAE Weights...")
vae_model = LSTM_VAE(n_features=65, seq_length=10) 
vae_model.load_state_dict(torch.load('models/lstm_vae_best_weights.pth', map_location=device))
vae_model.eval()

print("[*] Loading Stage 2: Random Forest Tactical Classifier...")
try:
    rf_classifier = joblib.load('models/stage2_rf_classifier.pkl')
    rf_classifier.n_jobs = 1  # <--- ADD THIS LINE
    print(f"[{Colors.GREEN}OK{Colors.ENDC}] Dual-stage threat models engaged.")
except Exception as e:
    print(f"[{Colors.CRITICAL}FAIL{Colors.ENDC}] Stage 2 model missing: {e}")
    sys.exit(1)

print("[*] Mounting local network traffic stream...")
X_test = np.load('data/X_test.npy')
print(f"[{Colors.GREEN}OK{Colors.ENDC}] {len(X_test)} sequence windows ready.\n")

# ==========================================
# 4. THRESHOLD CALIBRATION
# ==========================================
print("[*] Calibrating dynamic threshold (96.3rd percentile)...")
sample_seq = torch.tensor(X_test[:5000], dtype=torch.float32)
with torch.no_grad():
    c_recon, c_mu, c_logvar = vae_model(sample_seq)
    c_mse = torch.mean((c_recon - sample_seq) ** 2, dim=(1, 2))
    c_kld = -0.5 * torch.mean(1 + c_logvar - c_mu.pow(2) - c_logvar.exp(), dim=1)
    calibration_scores = (c_mse + 0.001 * c_kld).numpy()

THRESHOLD = np.percentile(calibration_scores, 96.3)
print(f"[{Colors.GREEN}OK{Colors.ENDC}] Threshold locked at: {THRESHOLD:.4f}\n")

input(f"{Colors.WARNING}Press ENTER to commence live dual-stage packet inspection...{Colors.ENDC}\n")

# ==========================================
# 5. LIVE TRAFFIC SCANNER
# ==========================================
print(f"{Colors.BOLD}TIMESTAMP       SEQ_ID      SCORE           STATUS / THREAT SIGNATURE{Colors.ENDC}")
print("-" * 85)

total_scanned = 0
quarantined = 0
threat_counts = {}

try:
    for i in range(len(X_test)):
        sequence = torch.tensor(X_test[i:i+1], dtype=torch.float32)
        
        # --- STAGE 1: VAE INFERENCE ---
        with torch.no_grad():
            recon, mu, logvar = vae_model(sequence)
            mse = torch.mean((recon - sequence) ** 2).item()
            kld = -0.5 * torch.mean(1 + logvar - mu.pow(2) - logvar.exp()).item()
            anomaly_score = mse + (0.001 * kld)
        
        timestamp = time.strftime("%H:%M:%S")
        seq_id = f"SEQ-{i:06d}"
        
        if anomaly_score > THRESHOLD:
            # --- STAGE 2: THREAT CLASSIFICATION ---
            quarantined += 1
            # Extract the very last packet in the 10-step sequence (Shape: 1x65)
            trigger_packet = X_test[i][-1].reshape(1, -1)
            attack_type = rf_classifier.predict(trigger_packet)[0]
            
            # Log the threat for the post-mortem
            threat_counts[attack_type] = threat_counts.get(attack_type, 0) + 1
            
            status = f"{Colors.CRITICAL}[!] QUARANTINED: {attack_type.upper()}{Colors.ENDC}"
            time.sleep(0.05) # Brief dramatic pause on catches
        else:
            status = f"{Colors.GREEN}[OK] PASS{Colors.ENDC}"
            
        print(f"{timestamp}    {seq_id}   {anomaly_score:<15.4f} {status}")
        
        if i % 100 == 0:
            sys.stdout.flush()
            
        total_scanned += 1

except KeyboardInterrupt:
    print(f"\n\n{Colors.WARNING}[*] DAEMON TERMINATED BY OPERATOR.{Colors.ENDC}")

# ==========================================
# 6. POST-MORTEM REPORT
# ==========================================
print("\n" + "="*85)
print(f"{Colors.CYAN}{Colors.BOLD} 📊 SECURITY OPERATIONS POST-MORTEM REPORT {Colors.ENDC}")
print("="*85)
print(f"Total Sequences Scanned: {total_scanned}")
print(f"Anomalies Quarantined:   {Colors.CRITICAL}{quarantined}{Colors.ENDC}")
print(f"Clean Traffic Passed:    {Colors.GREEN}{total_scanned - quarantined}{Colors.ENDC}")
print("-" * 85)
if quarantined > 0:
    print(f"{Colors.BOLD}DETECTED THREAT SIGNATURES:{Colors.ENDC}")
    for threat, count in threat_counts.items():
        print(f" - {threat}: {count} sequences")
else:
    print("No known threat signatures detected.")
print("="*85 + "\n")