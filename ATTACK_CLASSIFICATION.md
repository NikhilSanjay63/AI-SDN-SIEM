# Attack Classification & Future Scope

This document details how the AI-SDN-SIEM system classifies network attacks and outlines the roadmap for advancing from heuristic-based labeling to true multi-class AI classification.

## 1. Current Heuristic Classification
The system currently uses a **Binary AI Model** (CNN-BiLSTM) to detect if a flow is "Normal" or "Attack". If an attack is detected, a secondary **Heuristic Engine** analyzes the raw features to provide a specific label for the SIEM dashboard.

### Supported Labels
| Label | Detection Logic |
| :--- | :--- |
| **Active Port Scan** | **Stateful:** Source IP hits > 15 unique destination ports in 60s (tracked in Redis) |
| **Slow-and-Low** | AI detected attack + High Inter-Arrival Time (`IAT Mean > 2.0`) + Low Data Volume |
| **TCP SYN Flood** | Protocol is TCP (6) and SYN Flag count > 50 |
| **TCP RST Flood** | Protocol is TCP (6) and RST Flag count > 50 |
| **TCP PSH Flood** | Protocol is TCP (6) and PSH Flag count > 50 |
| **UDP Flood (DoS)** | Protocol is UDP (17) and Packet Rate > 1000 pkts/sec |
| **Brute Force / Exploit** | Target port is 21 (FTP), 22 (SSH), 23 (Telnet), or 3389 (RDP) |
| **High Rate DoS** | Any other high-frequency traffic (> 1000 pkts/sec) |
| **Anomalous Pattern** | AI detected an attack but features didn't match specific heuristics |

---

## 2. Future Scope: Multi-Class AI Classification
To move beyond heuristics and allow the AI model to natively distinguish between attack types, the following steps are required:

### Phase 1: Data Preparation
- **Dataset Expansion:** Use the full **InSDN** or **CIC-IDS2017** datasets without flattening attack labels.
- **Label Mapping:** Map the specific attack names (e.g., `Probe`, `U2R`, `R2L`, `DoS`) to unique integer IDs.
- **Class Balancing:** Apply SMOTE or random oversampling to handle minority attack classes.

### Phase 2: Model Architecture Update
- **Output Layer:** Change the final Dense layer of the CNN-BiLSTM from `Dense(2, activation='softmax')` to `Dense(N, activation='softmax')`, where N is the number of attack classes + 1 (normal).
- **Loss Function:** Switch from Binary Cross-Entropy to **Categorical Cross-Entropy**.

### Phase 3: Integration & Deployment
- **API Mapping:** Update `sdn-service/ai-service/app.py` to map the AI's numerical prediction directly to its class name string.
- **Visuals:** Enhance the SIEM dashboard to show "Top Attack Categories" based on AI-native labels rather than heuristics.

### Phase 4: Adaptive Learning
- Implement a **Human-in-the-Loop** (HITL) system where SOC analysts can flag misclassified attacks to retrain the model on the fly.
