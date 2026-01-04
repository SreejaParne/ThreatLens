# Mini SIEM System using Python

## Project Description
This project is a Mini Security Information and Event Management (SIEM) system
that collects logs, detects security attacks, generates alerts, and visualizes
them using a Flask dashboard.

## Features
- Real-time log collection
- Brute-force attack detection
- MITRE ATT&CK mapping
- Alert generation
- Web-based dashboard with attack graphs

## Technologies Used
- Python
- Flask
- Pandas
- Matplotlib
- MITRE ATT&CK Framework

## How to Run
1. Install dependencies:
   pip install -r requirements.txt

2. Start alert engine:
   python3 -m detector.alert_engine

3. Start log generator:
   python3 collector/log_collector.py

4. Start dashboard:
   python3 -m flask --app dashboard.app run -p 8000

5. Open browser:
   http://localhost:8000

## Future Enhancements
- Machine learning-based anomaly detection
- Email/SMS alerting
- Elasticsearch integration