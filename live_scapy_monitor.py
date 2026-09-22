import os
import sys
import time
import warnings
import numpy as np
import torch
import torch.nn as nn
import joblib
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import deque

# Suppress warnings
warnings.filterwarnings("ignore")
os.environ["PYTHONWARNINGS"] = "ignore"

# ==========================================
# 1. AI ENGINES & UI SETUP
# ==========================================
class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    CRITICAL = '\033[91m'
    BOLD = '\033[1m'
    ENDC = '\033[0m'

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

print("[*] Mounting AI Engines for Live Sniffing...")
device = torch.device("cpu")
vae_model = LSTM_VAE()
vae_model.load_state_dict(torch.load('models/lstm_vae_best_weights.pth', map_location=device))
vae_model.eval()
rf_classifier = joblib.load('models/stage2_rf_classifier.pkl')
rf_classifier.n_jobs = 1

THRESHOLD = 500000000.0
packet_buffer = deque(maxlen=10)
packet_count = 0

os.system('cls' if os.name == 'nt' else 'clear')
print(f"{Colors.CYAN}{Colors.BOLD} 📡 NTRO/SIH LIVE NETWORK INTERFACE MONITOR {Colors.ENDC}")
print("=" * 90)
print(f"[*] LISTENING ON LOOPBACK (lo)... (Awaiting 10 packets to build first sequence)\n")

# ==========================================
# 2. FLOW AGGREGATOR & INFERENCE
# ==========================================
def packet_callback(packet):
    global packet_count
    
    if IP not in packet:
        return 
        
    # Store Timestamp, Length, and the Packet itself
    packet_buffer.append((packet.time, packet[IP].len, packet))
    packet_count += 1
    
    # Run Inference every 10 packets
    if len(packet_buffer) == 10:
        # 1. CALCULATE FLOW THROUGHPUT (The secret to catching floods)
        time_delta = max(0.0001, packet_buffer[-1][0] - packet_buffer[0][0]) 
        total_bytes = sum([item[1] for item in packet_buffer])
        bytes_per_sec = total_bytes / time_delta
        
        # 2. BUILD THE 65-FEATURE SEQUENCE
        seq_array = np.zeros((1, 10, 65), dtype=np.float32)
        
        for i in range(10):
            pkt_time, pkt_len, pkt = packet_buffer[i]
            
            seq_array[0, i, 0] = bytes_per_sec  # Feature 0: Flow Bytes/s
            seq_array[0, i, 1] = pkt_len        # Feature 1: Packet Size
            
            if TCP in pkt:
                seq_array[0, i, 2] = pkt[TCP].sport
                seq_array[0, i, 3] = pkt[TCP].dport
            elif UDP in pkt:
                seq_array[0, i, 2] = pkt[UDP].sport
                seq_array[0, i, 3] = pkt[UDP].dport
            elif ICMP in pkt:
                seq_array[0, i, 2] = pkt[ICMP].type
                seq_array[0, i, 3] = pkt[ICMP].code
                
            # Pad the rest with noise so the VAE doesn't crash on zeros
            seq_array[0, i, 4:] = np.random.uniform(0.1, 1.0, 61)
            
        seq_tensor = torch.tensor(seq_array)
        
        # 3. VAE INFERENCE
        with torch.no_grad():
            recon, mu, logvar = vae_model(seq_tensor)
            mse = torch.mean((recon - seq_tensor) ** 2).item()
            kld = -0.5 * torch.mean(1 + logvar - mu.pow(2) - logvar.exp()).item()
            score = mse + (0.001 * kld)
            
        timestamp = time.strftime('%H:%M:%S')
        src = packet[IP].src
        dst = packet[IP].dst
        protocol = "ICMP" if ICMP in packet else ("TCP" if TCP in packet else ("UDP" if UDP in packet else "IP"))
        
        # 4. EVALUATION
        if score > THRESHOLD:
            trigger_packet = seq_array[0, -1].reshape(1, -1)
            pred = rf_classifier.predict(trigger_packet)[0]
            status = f"{Colors.CRITICAL}[!] QUARANTINED: {str(pred).upper()} (Score: {score:,.0f}){Colors.ENDC}"
        else:
            status = f"{Colors.GREEN}[OK] LIVE PASS ({bytes_per_sec:,.0f} B/s){Colors.ENDC}"
            
        print(f"[{timestamp}] PKT: {packet_count:06d} | {src:<15} -> {dst:<15} [{protocol}] | {status}")

# ==========================================
# 3. START CAPTURE
# ==========================================
try:
    sniff(iface="lo", prn=packet_callback, store=False)
except KeyboardInterrupt:
    print(f"\n{Colors.WARNING}[*] LIVE CAPTURE TERMINATED BY OPERATOR.{Colors.ENDC}")