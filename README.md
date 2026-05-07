# 🛡️ VT Hash Scanner & Advanced OSINT Platform

An advanced cybersecurity platform that combines bulk file/URL scanning via VirusTotal with an automated Open Source Intelligence (OSINT) engine for deep threat analysis. Designed with a modern, premium UI to support security analysts in evaluating risks quickly and accurately.

---

## 🌟 Key Features

* **Comprehensive Scanner**: Bulk scanning of Hashes, IPs, and Domains using VirusTotal to evaluate their threat level.
* **Automated OSINT Engine**: A deep, 6-stage automated analysis pipeline for information gathering:
  * **WHOIS Records** to identify domain ownership and registration details.
  * **DNS Records** for mapping infrastructure.
  * **Passive DNS** to track historical resolution changes via VirusTotal.
  * **Subdomain Discovery** utilizing Certificate Transparency Logs (crt.sh).
  * **Typosquatting Detection** to identify potentially malicious look-alike domains.
  * **Detailed IP Reputation** checks using **AbuseIPDB** and VirusTotal.
  * **Live Content Analysis** via **URLScan**.
* **Professional Dashboard**: A modern interface leveraging Glassmorphism design principles, fully supporting RTL (Arabic) layouts.
* **Robust Authentication**: Secure login system using JWT (JSON Web Tokens) with password hashing (bcrypt).
* **Centralized API Key Management**: Easily manage and rotate multiple API keys to ensure continuous scanning and bypass rate limits.

---

## 🛠️ Tech Stack

* **Frontend**: React.js, Vite, React Router, Lucide Icons, Vanilla CSS.
* **Backend**: Python, Flask, SQLite (for users and API keys), PyJWT, bcrypt, requests.

---

## 🚀 Installation & Setup

### Prerequisites:
* Node.js (v18+)
* Python (3.9+)

### 1. Backend Setup

Open your terminal and run the following commands:

```bash
cd backend

# Create a virtual environment
python3 -m venv .venv

# Activate the virtual environment
# On Linux/macOS:
source .venv/bin/activate  
# On Windows:
# .venv\Scripts\activate

# Install required packages
pip install -r requirements.txt

# Run the Flask server
python app.py
```
*The backend server will run on `http://127.0.0.1:5000`. It will automatically initialize the database and create a default admin user.*

### 2. Frontend Setup

Open a new terminal window and run:

```bash
cd frontend

# Install dependencies
npm install

# Start the development server
npm run dev
```
*The frontend application will be available at `http://localhost:5173`.*

---

## 🔐 Default Login Credentials

Upon the first run, the system automatically generates a default administrator account. Use these credentials to log in:
* **Username:** `admin`
* **Password:** `admin123`

*(It is highly recommended to create new accounts and change passwords via the Settings page after your first login).*

---

## ⚙️ Getting Started

1. Log in to the dashboard using the default credentials.
2. Navigate to **Settings** from the sidebar.
3. Add your API keys for the required services (e.g., VirusTotal, AbuseIPDB, IPInfo, URLScan).
4. Go to the **Scanner** to analyze bulk Hashes/IPs/Domains, or use the **Automated OSINT** tool for an in-depth investigation of a specific target.

---

## 📄 License
This project is open-source and available for academic and professional use.
