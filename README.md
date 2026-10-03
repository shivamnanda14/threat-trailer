# 💥 Threat Trailer

> **Stop guessing if a link is safe. Watch it detonate instead.**

Every tool starts with a fundamental **Jarurat** (need): we receive suspicious links daily and usually just guess or click and pray. That massive security gap gave this project its **Purpose**: to build an isolated cloud sandbox that clicks the links so you don't have to. Driven by the **Curiosity** to see exactly how these malicious payloads operate under the hood, Threat Trailer was born.

Threat Trailer is a full-stack cybersecurity SaaS and Chrome Extension that opens shady links in a secure cloud environment, interacts with them, and generates a plain-English threat report.

🔗 **Live Application:** [threat-trailer-app.onrender.com](https://threat-trailer-app.onrender.com)  
🛠 **Chrome Extension:** [Download the latest release](#-chrome-extension-setup-in-30-seconds)

---

## ✨ Key Features

*   **☁️ Isolated Cloud Sandbox:** Safely executes and interacts with malicious URLs without exposing your personal device.
*   **📊 Plain-English Threat Reports:** Generates a definitive Threat Score (0-100) with a clear breakdown of the calculated risks.
*   **📸 Visual Timeline:** Captures step-by-step screenshots from inside the sandbox, showing you the exact traps (fake logins, hidden popups) laid out by the attacker.
*   **💻 Network Forensics:** Exposes raw HTTP requests, server IPs, DNS routing, and background JS payloads for developers and security researchers.
*   **⚙️ AI Engine Config:** Power users can swap the underlying AI models driving the forensics engine.
*   **📚 Historical Logs:** Authenticated users can securely save, manage, and revisit past threat reports.

---

## 🏗️ Architecture & Tech Stack

**Frontend:**
*   Next.js (React)
*   Tailwind CSS (Styling)
*   Lucide React (Icons)
*   Clerk (Authentication)

**Backend & Sandbox:**
*   FastAPI (Python)
*   Prisma ORM
*   PostgreSQL 
*   Playwright / OpenCV (For sandbox interaction and visual capture)

---

## 🚀 Chrome Extension Setup (in 30 seconds)

To make link inspection completely frictionless, we built a custom Chrome Extension. 

1. Download the `ThreatTrailer.zip` file from the [Releases Tab](https://github.com/YOUR_USERNAME/threat-trailer/releases).
2. Extract (Unzip) the downloaded folder.
3. Open Chrome and navigate to: `chrome://extensions/`
4. Toggle **Developer mode** ON in the top right corner.
5. Click **Load unpacked** in the top left and select your extracted folder.
6. *That's it! You can now send any link directly to the detonation engine.*

---

## 💻 Local Development Setup

To run Threat Trailer locally, you will need Node.js and Python installed.

### 1. Clone the Repository
```bash
git clone [https://github.com/YOUR_USERNAME/threat-trailer.git](https://github.com/YOUR_USERNAME/threat-trailer.git)
cd threat-trailer

cd frontend
npm install

# Create a .env.local file and add your Clerk & API keys
cp .env.example .env.local

npm run dev

cd ../backend

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up your environment variables (Database URL, API keys)
cp .env.example .env

# Run the FastAPI server
uvicorn main:app --reload
