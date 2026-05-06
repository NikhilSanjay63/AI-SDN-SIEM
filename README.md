# 🔐 AI-SDN-SIEM
### An AI‑Driven SIEM Framework for Software‑Defined Networks with Automated Mitigation

---

## 📌 Overview
AI-SDN-SIEM is a robust, AI‑driven Security Information and Event Management (SIEM) framework designed for **Software‑Defined Networks (SDN)**. The system integrates **deep learning–based intrusion detection**, **SDN programmability**, and **real‑time SIEM analytics** to detect and mitigate network attacks automatically.

The architecture features a **CNN‑BiLSTM model** for spatial-temporal flow analysis and a dual-controller SDN setup (Fast Path + Inspection Path) to ensure high performance and security enforcement via **OpenFlow**.

---

## 🚀 Key Improvements (v2.0)
The system has been upgraded with several advanced features:
- **Granular Attack Classification:** Moves beyond binary detection to classify specific attacks (SYN Flood, UDP Flood, Brute Force, etc.) using AI-assisted heuristics.
- **Stateful Detection:** Leverages **Redis** to detect complex patterns like **Active Port Scanning** across multiple flows.
- **Batch Processing:** 10x reduction in REST overhead by processing network flows in batches between the SDN Controller and AI Service.
- **Improved Reliability:** Distributed architecture with Redis-backed state management, ensuring security policies survive service restarts.

---

## 🧠 System Architecture
1. **Traffic Layer (Mininet):** Emulates complex network topologies and generates traffic.
2. **SDN Layer (Ryu):** 
   - `Primary Controller`: Handles L2 learning and fast-path forwarding.
   - `Security Controller`: Buffers flows, extracts 24 features, and communicates with the AI service.
3. **AI Layer (Flask + TFLite):** Uses CNN-BiLSTM and Random Forest models to classify traffic.
4. **SIEM Layer (Fluent Bit + OpenSearch):** Real-time logging, indexing, and visualization of security events.

---

## 🛡️ Supported Attack Mitigation
The system provides automated **OpenFlow DROP** rules and **IP Blacklisting** for:
- **Active Port Scan** (Stateful Redis tracking)
- **Slow-and-Low (Slowloris)** (Temporal anomaly detection)
- **TCP Floods** (SYN, RST, PSH)
- **UDP Floods**
- **Brute Force / Exploit Attempts** (FTP, SSH, Telnet, RDP)
- **High Rate DoS**

---

## ▶️ Execution Guide

### 1. Prerequisites
- Docker & Docker Compose
- Mininet (for traffic generation)
- Python 3.8+

### 2. Start the SIEM Stack
```bash
cd siem-docker-v1
docker-compose up -d
```

### 3. Start the SDN & AI Services
```bash
cd sdn-service
docker-compose up -d
```

### 4. Launch Network Topology
Launch Mininet and connect to the controllers:
```bash
sudo mn --controller=remote,ip=127.0.0.1,port=6633 --controller=remote,ip=127.0.0.1,port=6634 --switch=ovsk,protocols=OpenFlow13 --topo=single,3
```

### 5. Simulate Attacks
- **Port Scan:** `mininet> h1 nmap -sS h2`
- **SYN Flood:** `mininet> h1 hping3 -S --flood h2`
- **UDP Flood:** `mininet> h1 hping3 --udp --flood h2`

---

## 📊 Monitoring & Results
- **AI Logs:** `docker logs -f ai-service`
- **SIEM Dashboard:** Access OpenSearch Dashboards at `http://localhost:5601` to view attack distributions and mitigation rates.
- **Mitigation Check:** `sudo ovs-ofctl -O OpenFlow13 dump-flows s1` to see active DROP rules.

---

## 🔮 Future Scope
- **Multi-Class AI:** Transition from heuristic labeling to native multi-class classification (e.g., Probe, U2R, R2L).
- **Explainable AI (XAI):** Integrating SHAP/LIME to provide human-readable reasons for AI detections.
- **Adaptive Learning:** Implementing online retraining based on analyst feedback.
- **Dynamic Policy:** Policy-driven mitigation levels (e.g., Rate-limiting vs. Blocking).

For detailed classification logic, see [ATTACK_CLASSIFICATION.md](./ATTACK_CLASSIFICATION.md).

---

## 👨‍💻 Author
Vishnu P U
