# 🧠 Detections Sigma – Windows Rule Collection

A curated repository of high-quality, vendor-agnostic **Sigma rules** for detecting suspicious and malicious activity in Windows environments. Built to support security operations, threat detection, and hands-on detection engineering.

---

## 📂 Folder Structure

```
rules/
└── windows/
    ├── lsass-access.yml
    ├── powershell-encoded-command.yml
    ├── proc-explorer-lsass.yml
    ├── remote-service-creation.yml
    ├── wmi-spawning-cmd.yml
    ├── suspicious-parent-child.yml
    └── sticky-keys-backdoor.yml
```

Each rule is fully annotated, mapped to MITRE ATT&CK, and includes rationale, FP guidance, and references.

---

## 🔍 What's Inside

- ✅ **Ready-to-use Sigma rules** – stored in structured YAML format
- 🧠 **Mapped to MITRE ATT&CK** – with TTP tags in every rule
- 🛠️ **Tested in lab conditions** – status marked as `experimental`, `testing`, or `stable`
- 🔖 **Tagged and referenced** – each rule contains links to MITRE techniques or relevant docs

---

## 💼 Use Cases

- Threat Detection and Investigation
- SIEM/XDR Alerting Pipelines
- Threat Hunting
- SOC Enablement and Training
- Red Team Behavior Detection

---

## ⚙️ How to Use

### 1. Clone the repository
```bash
git clone https://github.com/WojciechCiemski/detections-sigma.git
cd detections-sigma
```

### 2. Convert a rule to your SIEM format using [sigmac](https://github.com/SigmaHQ/sigma)
```bash
sigmac -t splunk -c config/splunk-windows.yml rules/windows/lsass-access.yml
```

You can replace `splunk` with any supported backend: `elastic`, `sentinel`, `wazuh`, etc.

---

## 🧪 Rule Status Meaning

| Status       | Description                                         |
|--------------|-----------------------------------------------------|
| `experimental` | Draft or new rule not yet validated in test cases   |
| `testing`     | Works in lab, undergoing evaluation or tuning      |
| `stable`      | Confirmed effective and production-ready           |
| `deprecated`  | Obsolete or replaced; not recommended for use      |

---

## 📘 Featured Rules (Windows)

| File Name                        | MITRE Technique       | Status        | Description                                      |
|----------------------------------|------------------------|----------------|--------------------------------------------------|
| `lsass-access.yml`               | T1003.001              | stable         | Detects LSASS memory access (e.g. Mimikatz)     |
| `powershell-encoded-command.yml`| T1059.001              | stable         | Detects encoded PowerShell usage                |
| `proc-explorer-lsass.yml`       | T1003.001              | experimental   | ProcExp accessing LSASS                         |
| `remote-service-creation.yml`   | T1021.002              | stable         | Detects remote service install (lateral move)   |
| `wmi-spawning-cmd.yml`          | T1047, T1059           | testing        | WMI launching cmd.exe (fileless malware)        |
| `suspicious-parent-child.yml`   | T1059.001              | experimental   | Explorer spawning PowerShell                    |
| `sticky-keys-backdoor.yml`      | T1546.008              | experimental   | `sethc.exe` backdoor at logon                   |

---

## 🔐 License

This repository is licensed under the **MIT License**.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

## 🤝 Contributing

Pull requests welcome!  
Please follow Sigma spec and include:
- Clean YAML format
- MITRE tags
- References and rationale
- Status: `experimental` / `testing` / `stable`

---

## 📬 Author
**[Wojciech Ciemski](https://www.linkedin.com/in/wojciech-ciemski)** – [SecurityBezTabu.pl](https://securitybeztabu.pl)  
SOC engineer · educator · detection engineer

---

> Stay tuned – Linux, cloud and network rules coming soon!
