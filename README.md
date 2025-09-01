# 🛡️ SecureAPK – APK Malware Analysis Platform

![Static Analysis](API_WEBAPP/images/splash1.jpg)
SecureAPK is a **multi-platform malware analysis tool** that performs **static APK analysis, ML-based detection, and threat intelligence integration (VirusTotal + MalwareBazaar)**.  
It comes with a **Flask REST API**, a **Web Dashboard**, and an **Android (Flutter) client** with the same analysis capabilities and UI.

---

## 🚀 Features

- 📂 **APK Upload & Analysis**
- 🔍 **Static Analysis** (permissions, certificates, entropy, suspicious strings, IPs/URLs)
- 🤖 **Machine Learning Model** (APK classification + SHAP explainability)
- 🌐 **Threat Intelligence Integration**
  - VirusTotal API
  - MalwareBazaar API
- 📊 **Interactive Web Dashboard**
  - Gauge meter, charts, feature importances
  - YARA rule generator
  - Dark/Light mode
- 📱 **Flutter Android App**
  - Same dashboard as web, native mobile UI
  - Upload APK & view results
- 📑 **Export Results**
  - JSON / CSV / PDF
- 🗂️ **Session History**
  - View past analyses

---

## 🖥️ Project Components

1. **Flask REST API**
   - Provides `/analyze` endpoint for APK submission
   - Handles static analysis, ML model, threat intel
   - Returns structured JSON response

2. **Web Dashboard**
   - Built with Flask + TailwindCSS + JavaScript
   - Visualizes analysis results with charts & animations
   - Includes YARA generator, theme switch, and export options

3. **Flutter Android App**
   - Mirrors the Web UI with Material design
   - Upload APK from device storage
   - Calls the same Flask API for results
   - SDK 34+ compatible

---

## 🧩 Tech Stack

| Layer               | Technology |
|----------------------|------------|
| Backend API          | Python, Flask (REST API) |
| Static Analysis      | Python (`static_analyzer.py`) |
| ML Model             | scikit-learn, SHAP |
| Threat Intelligence  | VirusTotal API, MalwareBazaar API |
| Web Dashboard        | Flask + TailwindCSS + JavaScript (Chart.js, GSAP, Anime.js) |
| Mobile Client        | Flutter (Dart, SDK 34+) |
| Data Formats         | JSON, CSV, PDF |

---

## 🔌 API Usage

**Endpoint:** `/analyze`

### Request

```bash
curl -F "file=@/path/to/app.apk" http://127.0.0.1:5000/analyze 
```
--- 

### Response Example
```bash
{
  "meta": {
    "package": "com.example.app",
    "sha256": "abc123..."
  },
  "analysis": {
    "permissions": ["INTERNET", "READ_SMS"],
    "certificate": "valid",
    "entropy": 6.3
  },
  "intelligence": {
    "virustotal": {"positives": 3, "total": 70},
    "malwarebazaar": {"detections": 1}
  },
  "model": {
    "probability_malicious": 0.87,
    "final_decision": "MALICIOUS"
  }
}
```
---
## 🛠️ Setup Instructions

### 1️⃣ Backend API (Flask)

```bash
# Clone repo
git clone git@github.com:hackyshadab/SecureAPK.git
cd SecureAPK/API_WEBAPP/

# Create virtual environment
python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows

# Install dependencies
pip install -r requirements.txt

# Run Flask API
python app.py

```

📍 **API will be live at:** 
`http://127.0.0.1:5000/analyze`

### 2️⃣ Web Dashboard

```bash
cd SecureAPK/API_WEBAPP/
python app.py
```

### 2️⃣ Android App

```bash
# Go to Flutter project
cd SecureAPK/ANDROIDAPP/

# Get dependencies
flutter pub get

# Run on device/emulator
flutter run
```

## 📍 Requirements

- Flutter SDK **3.22+**
- Android SDK **34+**
- `INTERNET` permission in `AndroidManifest.xml`
- 

## 📸 Screenshots

### Landing Page
![Web Landing](API_WEBAPP/images/land.png)

### Web Dashboard
![Web Dashboard](API_WEBAPP/images/main.png)

### Static Analysis
![Static Analysis](API_WEBAPP/images/static.png)

### ML Results & SHAP Visualization
![ML Analysis](API_WEBAPP/images/ml.png)

### Yara Rule
![Yara Rule](API_WEBAPP/images/yara.png)

### APK Upload & Analysis
![APK Upload](API_WEBAPP/images/andromain.png)

### Android App Static Analysis
![Flutter App](API_WEBAPP/images/staticandro.png)


## ⚠️ Disclaimer

**SecureAPK** is a research and educational platform designed to **analyze APK files, including potentially malicious applications**, in a controlled environment.  
This tool **may expose your system or network to security risks** if used improperly.  

**Important Safety Guidelines for Users:**
- Always use a **sandbox, virtual machine, or isolated environment** when analyzing unknown APKs.  
- Do **not upload or analyze applications without proper authorization** from the app owner.  
- Avoid running malware on production devices or networks.  
- This tool is **for research, testing, and educational purposes only**.  

By using SecureAPK, you agree that you are responsible for your actions and any consequences arising from improper usage.

---

## 📜 License

This project is licensed under the **MIT License**.  

**Key points of the license:**
- ✅ You are free to **use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies** of this software.  
- ✅ Attribution is required: keep the original copyright notice and license in all copies or substantial portions of the software.  
- ✅ There is **no warranty**: the software is provided "as-is", without any guarantees of safety, security, or suitability for any purpose.  

**Summary:** You may use and adapt this tool for educational, research, or personal projects, but you **assume all responsibility** for any risks or damages associated with its use.

