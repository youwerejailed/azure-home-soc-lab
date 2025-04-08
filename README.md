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


![Screenshot 2025-04-08 092257](https://github.com/user-attachments/assets/3c690b51-c911-42de-9aac-238c50ae2676)

## ⚙️ Setup Steps

1. ✅ Create Log Analytics Workspace and enable Microsoft Sentinel  
2. ✅ Connect Windows machines using Azure Monitor Agent (AMA)  
3. ✅ Verify data flow via `SecurityEvent` table  
4. ✅ Deploy custom analytics rules from `playbooks/`  
5. ✅ Integrate external threat intelligence feeds (`ti_feeds/`)


Open Ports
In the lab environment, some inbound ports, specifically the following ports, have been deliberately left open, which results in the system being vulnerable:

Port 80 (HTTP)

Port 22 (SSH)

Port 443 (HTTPS)

Port 3389 (RDP)

The purpose of leaving these ports open is to conduct security tests and observe various attack scenarios. However, this means that the environment is potentially exposed to security risks.


![Screenshot 2025-04-08 093839](https://github.com/user-attachments/assets/b1b82cdd-a154-459f-a311-5a3cb986edaf)





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





