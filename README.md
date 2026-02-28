# 📡 Wi-Fi Radar
![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**Wi-Fi Radar** is an automated, real-time wireless reconnaissance tool designed to passively intercept, fingerprint, and cluster Wi-Fi probe requests. 

By analyzing the unique Information Elements (IEs) hidden inside 802.11 management frames, Wi-Fi Radar can deanonymize devices employing MAC randomization, track them continuously as "sessions," and visualize the RF landscape on a live web dashboard.

---

## ⚡ Features
- **Auto-Bootstrapping Engine**: Zero configuration required. The script automatically installs required dependencies (`tcpdump`, `scapy`, `ieee-data`) upon execution natively.
- **Smart Interface Management**: Safely detaches the designated monitor-mode Wi-Fi adapter (e.g., your Alfa) from `NetworkManager` without killing your host machine's internet connection.
- **Fingerprinting & Clustering**: Hashes vendor-specific Information Elements payload signatures to group wildly volatile randomized MAC addresses into single physical "Clusters".
- **Real-Time Web Dashboard**: Serves a dynamic HTML/JS dashboard at `http://localhost:8080`, rendering clusters, network sessions, live rolling detections, and confidence models directly in the browser.
- **SSID/MAC Targeting**: Intercept *all* traffic globally across 165 channels, or filter sniffing loops instantly to target only a specific MAC address or SSID broadcast.

---

## 🚀 Installation & Usage

**1. Hardware Requirements**
You need a secondary wireless interface capable of entering **Monitor Mode** (e.g., an Alfa Network adapter). The script will automatically scan your `ip link` tables to detect it.

**2. Running the Engine**
No manual `pip install` is required. Simply clone the repository and run the main entry point with elevated permissions (to control the hardware):

```bash
git clone https://github.com/kalitechhub/wifiradar.git
cd wifiradar
sudo python3 wifi_radar.py start
```

**3. Interactive Prompts**
Upon launch, the terminal will prompt you for optional filters:
- `Filter ProbeReq by SSID (blank=ANY):` Press **Enter** to sniff every network blindly, or type a specific network name (e.g., `HomeBase`) to ONLY lock onto devices looking for that network.

**4. Graceful Shutdown**
When finished, stop the daemon from another terminal so it can securely restore your adapter to managed mode:
```bash
sudo python3 wifi_radar.py stop
```

---

## 📊 The Live Dashboard (`localhost:8080`)
As soon as the engine catches a packet, the Flask backend instantly populates the web GUI. The dashboard is split into three core analytical views:

### 1. Detections (The Raw Feed)
This tab acts as a rolling waterfall of every packet captured by the antenna. It includes the exact **Time**, the **Source MAC Address**, the internal **RSSI** (signal strength), and the **Vendor** (dynamically resolved from the Kali IEEE OUI database). 

### 2. Clusters (Device Deanonymization)
Due to modern privacy features, a single iPhone might transmit probe requests using 15 entirely different MAC addresses in 10 minutes. 

The Clustering engine solves this by hashing the deep Information Elements (IEs) inside the packet frame (such as supported rates and extended capabilities). If 15 different random MAC addresses all share the exact same rare IE fingerprint, Wi-Fi Radar clumps them together into a single **Cluster ID** with an associated mathematical **Confidence Score**.

### 3. Sessions (Time Tracking)
Once physical devices are deanonymized via Clusters, the Session Engine analyzes their chronological presence. It tracks when a cluster arrives in your airspace, when it leaves, and links all historical activity into a single continuous `Duration` string. 

---

### 📝 Logs
All raw PCAP files, stateless API JSON dumps, and CSV detection ledgers are automatically mapped permanently to:
`/root/radar_logs/`

---
*Disclaimer: This tool was built exclusively for RF lab environments and educational research. Do not operate against 802.11 clients without explicit authorization.*
