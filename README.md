# azure-home-soc-lab
# 🛡️ SOC Home Lab - Microsoft Sentinel Edition

This project demonstrates how to build a cloud-based Security Operations Center (SOC) using **Microsoft Sentinel**, a SIEM and SOAR platform in Azure. Logs are collected from a simulated home/enterprise lab including Windows systems, honeypots, and custom threat intelligence feeds.

---

## ☁️ Key Components

- **SIEM Platform**: Microsoft Sentinel on Azure
- **Data Sources**: Windows Security Events (via AMA/Log Analytics Agent)
- **Threat Intel**: Custom feed integrated via Azure Logic App or Sentinel API
- **Detection Rules**: KQL queries based on common attack patterns (Brute Force, Persistence)
- **Incident Response**: Basic alerting and rule-based classification

---

## 📁 Project Structure

soc-home-lab/ ├── setup/ # Azure onboarding + connector guides ├── playbooks/ # KQL-based detection rules ├── ti_feeds/ # Custom threat intel integrations ├── logs/ # Example raw logs (ignored) ├── architecture.png # System diagram └── README.md



## ⚙️ Setup Steps

1. ✅ Create Log Analytics Workspace and enable Microsoft Sentinel  
2. ✅ Connect Windows machines using Azure Monitor Agent (AMA)  
3. ✅ Verify data flow via `SecurityEvent` table  
4. ✅ Deploy custom analytics rules from `playbooks/`  
5. ✅ Integrate external threat intelligence feeds (`ti_feeds/`)  

---

## 💡 Detection Example

File: `playbooks/failed_logon_alert.kql`

```kql
SecurityEvent
| where EventID == 4625
| where AccountType == "User"
| summarize FailedCount = count(), Accounts = make_set(TargetUserName)
    by IpAddress = tostring(IpAddress), bin(TimeGenerated, 1h)
| where FailedCount > 1



![Image](https://github.com/user-attachments/assets/a498d6c2-b022-4dbb-815b-055ffd60f681)
