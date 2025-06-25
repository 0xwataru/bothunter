# BotHunter - 僵尸网络检测工具

BotHunter 是一个强大的僵尸网络检测和监控工具，专门用于发现和分析各种类型的恶意软件和僵尸网络活动。该工具支持多种检测模式，包括C2（命令与控制）服务器检测和P2P（点对点）僵尸网络检测。

## 🎯 主要功能

### C2 僵尸网络检测
- **支持的恶意软件类型**：
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

### P2P 僵尸网络检测
- **支持的P2P僵尸网络**：
  - Sality
  - ZeroAccess
  - GameOver Zeus

### 集成功能
- **Shodan集成**：自动从Shodan获取恶意软件相关的IP和端口信息
- **数据存储**：支持MongoDB存储检测结果
- **消息队列**：支持Kafka进行实时数据流处理
- **日志记录**：完整的日志记录和错误处理

## 🏗️ 项目架构

```
BotHunter/
├── main.py                 # 主程序入口
├── lib/                    # 核心库文件
│   ├── cli.py             # 命令行界面
│   ├── core/              # 核心功能模块
│   ├── utils/             # 工具函数
│   ├── shodan_.py         # Shodan API集成
│   ├── mongo_.py          # MongoDB操作
│   ├── kafka_.py          # Kafka消息队列
│   └── file_.py           # 文件操作
├── c2finder/              # C2僵尸网络检测模块
│   ├── njrat.py
│   ├── darkcomet.py
│   ├── nanocore.py
│   └── ... (其他恶意软件检测器)
├── p2pfinder/             # P2P僵尸网络检测模块
│   ├── sality.py
│   ├── zeroaccess.py
│   └── gameoverzeus.py
├── sample/                # 样本文件
│   ├── pcap/             # 网络数据包样本
│   └── file/             # 文件样本
└── config.ini_example.ini # 配置文件示例
```

## 📋 系统要求

- Python 2.7
- 操作系统：Linux/macOS/Windows

## 🔧 安装步骤

1. **克隆项目**
   ```bash
   git clone https://github.com/your-repo/BotHunter.git
   cd BotHunter
   ```

2. **安装依赖**
   ```bash
   pip install -r requirements.txt
   ```

3. **安装额外依赖**
   ```bash
   # 对于P2P检测功能，需要安装scapy
   pip install scapy
   
   # 对于Kafka功能
   pip install kafka-python
   
   # 对于Shodan API
   pip install shodan
   ```

4. **配置设置**
   ```bash
   cp config.ini_example.ini config.ini
   # 编辑config.ini文件，填入相应的API密钥和服务器信息
   ```

## ⚙️ 配置说明

### config.ini 配置项

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

## 🚀 使用方法

### 基本使用

```bash
python main.py
```

### 功能说明

1. **C2检测模式**
   - 通过Shodan API搜索恶意软件相关的IP和端口
   - 对每个IP:端口组合进行恶意软件特征检测
   - 支持多种RAT（远程访问木马）的识别

2. **P2P检测模式**
   - 对P2P僵尸网络节点进行主动探测
   - 支持Sality、ZeroAccess、GameOver Zeus等P2P僵尸网络
   - 通过UDP协议进行节点发现

3. **数据输出**
   - 控制台输出检测结果
   - MongoDB存储详细检测信息
   - Kafka实时推送威胁情报

## 🔍 检测原理

### C2检测
- 通过Shodan搜索`category:malware`获取潜在恶意IP
- 对每个IP进行特定恶意软件协议的握手检测
- 分析响应数据包特征判断恶意软件类型

### P2P检测
- 使用预定义的P2P僵尸网络协议
- 发送特定格式的UDP数据包
- 解析响应数据获取活跃节点信息

## 📊 输出格式

### 检测结果示例
```json
{
  "ip": "192.168.1.100",
  "port": 8080,
  "ratname": "njRAT",
  "type": "c2 botnet",
  "status": "active"
}
```

### MongoDB存储格式
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

## 🛡️ 安全注意事项

- 本工具仅用于安全研究和合法渗透测试
- 请确保在授权环境中使用
- 遵守当地法律法规
- 不要对未授权的系统进行扫描

## 🤝 贡献指南

欢迎提交Issue和Pull Request来改进这个项目。

## 📄 许可证

本项目采用MIT许可证，详见LICENSE文件。

## 📞 联系方式

如有问题或建议，请通过以下方式联系：
- 提交GitHub Issue
- 发送邮件至项目维护者

## 🔄 更新日志

### v1.0.0
- 初始版本发布
- 支持C2和P2P僵尸网络检测
- 集成Shodan、MongoDB、Kafka功能
- 支持多种恶意软件类型识别

---

**免责声明**：本工具仅用于教育和研究目的。使用者需要确保遵守相关法律法规，并承担使用本工具的所有责任。 