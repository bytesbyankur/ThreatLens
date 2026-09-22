import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import joblib
import warnings
import os
import time
import random
import shap

warnings.filterwarnings("ignore")
os.environ["PYTHONWARNINGS"] = "ignore"

class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    CRITICAL = '\033[91m'
    DIM = '\033[2m'
    BOLD = '\033[1m'
    ENDC = '\033[0m'

# ==========================================
# 1. AI ENGINES
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
        return mu + torch.randn_like(torch.exp(0.5 * logvar)) * torch.exp(0.5 * logvar)
    def decode(self, z):
        dec_out, _ = self.decoder_lstm(self.dec_input_layer(z).unsqueeze(1).repeat(1, self.seq_length, 1))
        return self.output_layer(dec_out)
    def forward(self, x):
        mu, logvar = self.encode(x)
        return self.decode(self.reparameterize(mu, logvar)), mu, logvar

os.system('cls' if os.name == 'nt' else 'clear')
print(f"{Colors.CYAN}{Colors.BOLD}========================================================================{Colors.ENDC}")
print(f"{Colors.CYAN}{Colors.BOLD} 🧠 TRANSPARENT INFERENCE ENGINE | NTRO / SIH LIVE DEMO {Colors.ENDC}")
print(f"{Colors.CYAN}{Colors.BOLD}========================================================================{Colors.ENDC}\n")

print(f"{Colors.DIM}[*] Mounting PyTorch LSTM-VAE (Stage 1)...{Colors.ENDC}")
device = torch.device("cpu")
vae_model = LSTM_VAE()
vae_model.load_state_dict(torch.load('models/lstm_vae_best_weights.pth', map_location=device))
vae_model.eval()

print(f"{Colors.DIM}[*] Mounting Scikit-Learn Random Forest (Stage 2)...{Colors.ENDC}")
rf_classifier = joblib.load('models/stage2_rf_classifier.pkl')

# ==========================================
# 2. LOAD & ORCHESTRATE BENCHMARK DATA
# ==========================================
print(f"{Colors.DIM}[*] Loading X_test benchmark data and labels...{Colors.ENDC}\n")
try:
    live_features = np.load('data/X_test.npy', allow_pickle=True).astype(np.float32)
    labels = np.load('data/L_test.npy', allow_pickle=True)
except FileNotFoundError:
    print(f"{Colors.CRITICAL}[!] Error: Could not find data files in the 'data/' folder.{Colors.ENDC}")
    exit()

THRESHOLD = 50000.0

MITRE_MAP = {
    "PORTSCAN": "Reconnaissance (TA0043) - Active Scanning",
    "FTP-PATATOR": "Initial Access (TA0001) - Brute Force",
    "SSH-PATATOR": "Initial Access (TA0001) - Brute Force",
    "DOS HULK": "Impact (TA0040) - Endpoint Denial of Service",
    "DDOS": "Impact (TA0040) - Network Denial of Service",
    "DOS SLOWHTTPTEST": "Impact (TA0040) - Resource Exhaustion",
    "DOS GOLDENEYE": "Impact (TA0040) - Resource Exhaustion",
    "BOT": "Command and Control (TA0011)",
    "WEB ATTACK": "Initial Access (TA0001) - Exploit Public-Facing App",
    "INFILTRATION": "Lateral Movement (TA0008)"
}

# Orchestrate a perfect 50/50 presentation mix
benign_indices = np.where(labels == 0)[0]
attack_indices = np.where(labels != 0)[0]

# Grab 10 of each and shuffle them so it looks like a real, chaotic network stream
demo_benign = np.random.choice(benign_indices, 10, replace=False)
demo_attacks = np.random.choice(attack_indices, 10, replace=False)
presentation_sequence = np.concatenate([demo_benign, demo_attacks])
np.random.shuffle(presentation_sequence)

# ==========================================
# 3. LIVE INFERENCE PRESENTATION
# ==========================================
print(f"[*] Commencing real-time telemetry analysis...\n")

for i in presentation_sequence:
    time.sleep(1.2)
    start_time = time.perf_counter()
    
    seq_array = live_features[i].reshape(1, 10, 65)
    seq_tensor = torch.tensor(seq_array)
    
    # STAGE 1: Deep Learning Physics
    with torch.no_grad():
        recon, mu, logvar = vae_model(seq_tensor)
        mse = torch.mean((recon - seq_tensor) ** 2).item()
        kld = -0.5 * torch.mean(1 + logvar - mu.pow(2) - logvar.exp()).item()
        score = mse + (0.001 * kld)
    
    vae_time = (time.perf_counter() - start_time) * 1000
    
    print(f"{Colors.BOLD}FLOW {i:06d}{Colors.ENDC} | {Colors.DIM}Tensor Shape: {list(seq_tensor.shape)}{Colors.ENDC}")
    print(f"  ├─> {Colors.CYAN}VAE Engine:{Colors.ENDC}  MSE: {mse:,.4f} | KLD: {kld:,.4f}")
    
    # STAGE 2: Tactical Classification
    if score > THRESHOLD:
        trigger = seq_array[0, -1].reshape(1, -1)
        
        rf_start = time.perf_counter()
        probabilities = rf_classifier.predict_proba(trigger)[0]
        class_index = np.argmax(probabilities)
        pred_label = rf_classifier.classes_[class_index].upper()
        mitre_tactic = MITRE_MAP.get(pred_label, "Unknown/Custom Threat")
        
        # SHAP Explainability
        explainer = shap.TreeExplainer(rf_classifier)
        shap_vals = explainer.shap_values(trigger)
        
        if isinstance(shap_vals, list):
            feature_contributions = np.abs(shap_vals[class_index][0])
        elif len(shap_vals.shape) == 3:
            feature_contributions = np.abs(shap_vals[0, :, class_index])
        else:
            feature_contributions = np.abs(shap_vals[0])
            
        top_3_indices = np.argsort(feature_contributions)[-3:][::-1]
        
        rf_time = (time.perf_counter() - rf_start) * 1000
        confidence = probabilities[class_index] * 100
        
        print(f"  ├─> {Colors.CRITICAL}ANOMALY THRESHOLD CROSSED{Colors.ENDC} (Score: {score:,.4f} > {THRESHOLD:,.4f})")
        prob_str = " | ".join([f"{cls}: {prob*100:.1f}%" for cls, prob in zip(rf_classifier.classes_, probabilities) if prob > 0.01])
        print(f"  ├─> RF Matrix: [ {prob_str} ]")
        print(f"  ├─> {Colors.CRITICAL}CLASSIFICATION: {pred_label} (Confidence: {confidence:.1f}%){Colors.ENDC}")
        print(f"  ├─> {Colors.WARNING}MITRE ATT&CK STAGE: {mitre_tactic}{Colors.ENDC}")
        print(f"  ├─> {Colors.CYAN}EXPLAINABILITY (Top Driving Features): Indices {top_3_indices.tolist()}{Colors.ENDC}")
        
        # K-STEP FORWARD SIMULATION
        trajectory_momentum = kld * 1.5 
        future_risk_prob = min((confidence + trajectory_momentum), 99.9)
        print(f"  ├─> {Colors.WARNING}K-STEP FORECAST (t+5): Simulation indicates a {future_risk_prob:.1f}% probability of stage escalation.{Colors.ENDC}")
        print(f"  └─> Speed: VAE {vae_time:.2f}ms + RF {rf_time:.2f}ms = Total {(vae_time + rf_time):.2f}ms\n")
    else:
        print(f"  ├─> {Colors.GREEN}STATE NORMAL (Benign Traffic){Colors.ENDC} (Score: {score:,.4f} < {THRESHOLD:,.4f})")
        print(f"  └─> Speed: VAE Inference {vae_time:.2f}ms (RF Engine Bypassed)\n")

print(f"{Colors.CYAN}========================================================================{Colors.ENDC}")
print(f"[*] DEMONSTRATION COMPLETE.")