# ThreatForge Security Suite

Includes:
- Brute-force detection
- SQLite event storage
- Suspicious IP/risk detection
- Local static security scanner
- Password-strength checker
- Protective-measure recommendations
- Login charts and event history
- CSV login-log export
- Downloadable security assessment report

## Run
```bash
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Use only on systems/files you own or are authorized to assess. Do not enter real passwords or secrets into the demo.


## Local Login Lab

A fake local login page is included for demonstrations. It records only login success/failure events; entered passwords are never stored.
