# Mini SIEM System using Python

## Project Description
This project is a Mini Security Information and Event Management (SIEM) system
that collects logs, detects security attacks, generates alerts, and visualizes
them using a Flask dashboard.

## Features
- Real-time log monitoring with auto-refresh every 60 seconds
- Brute-force attack detection
- MITRE ATT&CK mapping
- Alert generation
- Web-based dashboard with attack graphs
- Multiple alert panels: Active, Acknowledged, and Resolved
- Modular code, easy to expand with additional features

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
- Export logs and analytics reports
- User authentication and role-based access
  
## License
This project is for educational and personal use. Feel free to modify and improve.

## Contact
GitHub: https://github.com/SreejaParne
LinkedIn: https://www.linkedin.com/in/sreejaparne/
