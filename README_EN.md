# BotHunter - Botnet Detection Tool

BotHunter is a powerful botnet detection and monitoring tool designed to discover and analyze various types of malware and botnet activities. The tool supports multiple detection modes, including C2 (Command & Control) server detection and P2P (Peer-to-Peer) botnet detection.

## 🎯 Key Features

### C2 Botnet Detection
- **Supported Malware Types**:
  - njRAT
  - DarkComet
  - NanoCore
  - Quasar
  - Orcus
  - Poison
  - XtremeRAT
  - BlackShades
  - Bozok
  - NetBus
  - Nuclear
  - Cafeini
  - DarkTrack

### P2P Botnet Detection
- **Supported P2P Botnets**:
  - Sality
  - ZeroAccess
  - GameOver Zeus

### Integration Features
- **Shodan Integration**: Automatically retrieves malware-related IP and port information from Shodan
- **Data Storage**: MongoDB support for storing detection results
- **Message Queue**: Kafka support for real-time data stream processing
- **Logging**: Comprehensive logging and error handling

## 🏗️ Project Architecture

```
BotHunter/
├── main.py                 # Main program entry point
├── lib/                    # Core library files
│   ├── cli.py             # Command line interface
│   ├── core/              # Core functionality modules
│   ├── utils/             # Utility functions
│   ├── shodan_.py         # Shodan API integration
│   ├── mongo_.py          # MongoDB operations
│   ├── kafka_.py          # Kafka message queue
│   └── file_.py           # File operations
├── c2finder/              # C2 botnet detection modules
│   ├── njrat.py
│   ├── darkcomet.py
│   ├── nanocore.py
│   └── ... (other malware detectors)
├── p2pfinder/             # P2P botnet detection modules
│   ├── sality.py
│   ├── zeroaccess.py
│   └── gameoverzeus.py
├── sample/                # Sample files
│   ├── pcap/             # Network packet samples
│   └── file/             # File samples
└── config.ini_example.ini # Configuration file example
```

## 📋 System Requirements

- Python 2.7
- Operating System: Linux/macOS/Windows

## 🔧 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-repo/BotHunter.git
   cd BotHunter
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Install additional dependencies**
   ```bash
   # For P2P detection functionality
   pip install scapy
   
   # For Kafka functionality
   pip install kafka-python
   
   # For Shodan API
   pip install shodan
   ```

4. **Configure settings**
   ```bash
   cp config.ini_example.ini config.ini
   # Edit config.ini file with your API keys and server information
   ```

## ⚙️ Configuration

### config.ini Configuration Items

```ini
[shodan]
apikey = YOUR_SHODAN_API_KEY

[kafka]
bootstrap_servers = ["kafka-server1:9092", "kafka-server2:9092"]
topic = BotHunterFeed

[mongo]
ip = 127.0.0.1
port = 27017
db = your_database
collection = your_collection

[p2p]
mongo = false
file = ./p2pfinder/p2p_ent/filepath
default_ent = {"zeroaccess": [], "gameoverzeus": [], "sality": []}
```

## 🚀 Usage

### Basic Usage

```bash
python main.py
```

### Functionality Overview

1. **C2 Detection Mode**
   - Searches for malware-related IPs and ports through Shodan API
   - Performs malware signature detection on each IP:port combination
   - Supports identification of various RAT (Remote Access Trojan) types

2. **P2P Detection Mode**
   - Actively probes P2P botnet nodes
   - Supports Sality, ZeroAccess, GameOver Zeus and other P2P botnets
   - Discovers nodes through UDP protocol

3. **Data Output**
   - Console output of detection results
   - MongoDB storage of detailed detection information
   - Kafka real-time threat intelligence push

## 🔍 Detection Principles

### C2 Detection
- Uses Shodan to search for `category:malware` to obtain potential malicious IPs
- Performs specific malware protocol handshake detection on each IP
- Analyzes response packet characteristics to determine malware type

### P2P Detection
- Uses predefined P2P botnet protocols
- Sends UDP packets in specific formats
- Parses response data to obtain active node information

## 📊 Output Format

### Detection Result Example
```json
{
  "ip": "192.168.1.100",
  "port": 8080,
  "ratname": "njRAT",
  "type": "c2 botnet",
  "status": "active"
}
```

### MongoDB Storage Format
```json
{
  "task_id": "shodan_get",
  "ip": "192.168.1.100",
  "port": 8080,
  "RAT_info": {
    "RATfinderName": "njRAT",
    "RAT_level": "high",
    "RAT_type": "c2 botnet"
  },
  "threat_level": "high",
  "tags": ["c2", "njRAT"],
  "time": "2023-12-01T10:00:00Z"
}
```

## 🛡️ Security Considerations

- This tool is intended for security research and authorized penetration testing only
- Ensure use in authorized environments
- Comply with local laws and regulations
- Do not scan unauthorized systems

## 🤝 Contributing

We welcome Issue submissions and Pull Requests to improve this project.

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is provided for educational and research purposes only. Users are responsible for ensuring they have proper authorization before using this tool on any network or system. The authors are not responsible for any misuse of this software. 