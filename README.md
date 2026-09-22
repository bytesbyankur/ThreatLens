# Transparent Threat Engine (ThreatLens) 🚀

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.10-blue.svg)](https://www.python.org/)

> A dual-stage, AI-driven temporal network monitor that translates complex cyber attacks into explainable, actionable awareness for community networks.

## 📖 Overview

Transparent Threat Engine is a hybrid edge-node cybersecurity solution designed to democratize threat awareness. Moving beyond static, black-box security classifiers, it utilizes a "World Model" approach to learn the temporal state-transitions of cyber attacks. When an anomaly occurs, the engine extracts the specific driving network features and maps the behavior to standard SOC terminology.

This project operates entirely on local hardware via an interactive CLI, making enterprise-grade intrusion detection accessible without expensive cloud overhead or heavy CPU bottlenecks.

### ✨ Key Features
* **Dual-Stage Pipeline:** A lightning-fast PyTorch LSTM-VAE tripwire filters 99% of normal traffic in milliseconds, only waking up the heavy Scikit-Learn Random Forest classifier for actual anomalies.
* **Temporal "World Model" Detection:** Analyzes 3D network traffic sequences (10-packet windows) to catch complex, multi-step attacks that static tools miss.
* **Educational Transparency:** Uses SHAP (SHapley Additive exPlanations) to pinpoint the exact network features (e.g., TCP flags, port patterns) driving the threat.
* **MITRE ATT&CK Translation:** Automatically maps raw network anomalies into industry-standard, plain-English threat stages (e.g., "Reconnaissance - TA0043").
* **Cross-Platform Containerization:** Fully containerized with Docker, ensuring the native Linux CLI and Scapy packet sniffer run flawlessly on any operating system.

---

## 🛠️ Tech Stack

* **Core Logic & Orchestration:** Python, Pandas, NumPy
* **Stage 1 AI (Deep Learning):** PyTorch (LSTM-VAE)
* **Stage 2 AI (Tactical Classifier):** Scikit-Learn (Random Forest), Joblib
* **Explainability:** SHAP
* **Live Network Sniffing:** Scapy, tcpdump, libpcap
* **Deployment:** Docker

---

## 🚀 Getting Started

To ensure cross-platform compatibility and preserve the live CLI demonstration UI, this project is packaged with Docker. 

### Prerequisites
* [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running.

### ⚡ One-Click Installation & Launch

Open your terminal (Bash, PowerShell, or Command Prompt) in the root project directory and execute this single command to build the environment and tap into your host network for live packet sniffing:

```bash
docker build -t threat-engine . && docker run -it --network host --cap-add=NET_ADMIN --cap-add=NET_RAW threat-engine
```

### 🎮 Interactive CLI Menu

Upon launching the container, you will be greeted by the `menu.py` CLI launcher. Select one of the following execution modes:
1. **Transparent Engine (Curated Demo):** Runs a simulation of 50/50 mix benign and attack traffic to demonstrate the SHAP explainability and MITRE mappings.
2. **IDS Tripwire:** Scans the full `X_test.npy` benchmark dataset at maximum speed.
3. **Live Scapy Monitor:** Taps into your active network interface to sniff and evaluate real-time traffic passing through your machine.

---

## 📁 Project Structure

```text
├── data/                       # Contains X_test.npy and L_test.npy benchmark data
├── models/                     # Pre-trained lstm_vae_best.pth and stage2_rf.pkl weights
├── Dockerfile                  # Container blueprint for Python 3.10 and system networking
├── requirements.txt            # Python dependencies (torch, scikit-learn, scapy, etc.)
├── .dockerignore               # Cache exclusions
├── menu.py                     # Main interactive CLI launcher
├── transparent_engine.py       # Core dual-stage demonstration logic
├── ids_tripwire.py             # Full dataset benchmark scanner
├── live_scapy_monitor.py       # Real-time packet capture and inference
└── README.md                   # Project documentation
```

---

## 🤝 Contributing

Contributions are welcome! If you'd like to improve the SHAP extraction speed, add new MITRE ATT&CK heuristics, or optimize the Scapy rolling buffer, please fork the repository and open a Pull Request.

---

## 📝 License

Distributed under the MIT License.