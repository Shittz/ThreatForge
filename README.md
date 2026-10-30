# 🛡️ ThreatForge – Security Suite

**Brute-Force Attack Detection and Security Monitoring System**

ThreatForge is an educational cybersecurity project developed using Python and Streamlit. It demonstrates brute-force attack detection, login activity monitoring, basic security scanning, password strength analysis, and security reporting.

## 🎯 Project Objectives

- Detect suspicious login patterns.
- Monitor repeated failed login attempts.
- Identify potential brute-force attacks.
- Perform basic static security checks on source code.
- Evaluate password strength.
- Generate security reports and export login records.

## 🚀 Features

### 1. Attack Detection
- Monitor login attempts.
- Configure failed-attempt thresholds.
- Configure detection time windows.
- Identify suspicious IP addresses.
- Generate risk-level alerts.
- Visualize login statistics.

### 2. Local Login Lab
- Simulated login environment.
- Test successful and failed authentication.
- Generate login events for detection testing.
- Demonstrate brute-force detection safely.

**Demo credentials:**
- Username: `student`
- Password: `ThreatForge123!`

Passwords entered in the Local Login Lab are not stored.

### 3. Security Scanner
- Scan local project files.
- Identify possible hard-coded passwords and API keys.
- Check for potentially unsafe coding patterns.
- Display findings according to severity.

### 4. Credential Security Check
- Evaluate password length.
- Check uppercase and lowercase characters.
- Check numbers and special characters.
- Provide password improvement suggestions.

### 5. Protection Recommendations
Provides security recommendations such as:
- Rate limiting.
- Temporary account/IP lockout.
- Multi-factor authentication.
- Strong password policies.
- Security logging and alerts.

### 6. Security Reports
- View login activity.
- Export login records as CSV.
- Generate downloadable security assessment reports.

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core programming language |
| Streamlit | Web application interface |
| SQLite | Local database |
| Pandas | Data processing |
| Regular Expressions | Pattern matching |
| CSV | Login log export |

## ⚙️ Installation and Setup

### Prerequisites
- Python installed on your computer.
- GitHub project downloaded or cloned.

### 1. Clone the repository

```bash
git clone https://github.com/rekzii23/ThreatForge.git
```

### 2. Enter the project directory

```bash
cd ThreatForge
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Run the application

```bash
python -m streamlit run app.py
```

### 5. Open the application

Visit:

```text
http://localhost:8501
```

## 🔍 How Brute-Force Detection Works

1. Login attempts are recorded.
2. Events are stored in an SQLite database.
3. Failed login attempts are filtered.
4. Attempts are grouped by IP address.
5. The system checks attempts within a configured time window.
6. If the threshold is reached, a suspicious activity alert is generated.

## 📁 Project Structure

```text
ThreatForge/
│
├── app.py
├── requirements.txt
├── README.md
└── .gitignore
```

The SQLite database is generated
