# detector/mitre_mapping.py

def get_mitre_info(attack_type):
    """
    MITRE ATT&CK Mapping Engine
    Maps detected attack types to MITRE techniques
    """

    attack_type = attack_type.lower()

    mitre_database = {

        "brute_force": {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "severity": "HIGH"
        },

        "sql_injection": {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "severity": "CRITICAL"
        },

        "xss": {
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "severity": "MEDIUM"
        },

        "port_scan": {
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery",
            "severity": "LOW"
        },

        "malware": {
            "technique_id": "T1204",
            "technique_name": "User Execution",
            "severity": "CRITICAL"
        },
        
        "ddos": {
            "technique_id": "T1498",
            "technique_name": "Network Denial of Service",
            "severity": "CRITICAL"
        },

        "credential_stuffing": {
            "technique_id": "T1110.004",
            "technique_name": "Credential Stuffing",
            "severity": "HIGH"
      },

        "phishing": {
            "technique_id": "T1566",
            "technique_name": "Phishing",
            "severity": "HIGH"
        },
        "ransomware": {
            "technique_id": "T1486",
            "technique_name": "Data Encrypted for Impact",
            "severity": "CRITICAL"
        },

        "privilege_escalation": {
            "technique_id": "T1068",
            "technique_name": "Exploitation for Privilege Escalation",
            "severity": "CRITICAL"
        },

        "lateral_movement": {
            "technique_id": "T1021",
            "technique_name": "Remote Services",
            "severity": "HIGH"
        },

        "data_exfiltration": {
            "technique_id": "T1041",
            "technique_name": "Exfiltration Over C2 Channel",
            "severity": "CRITICAL"
        },

        "command_execution": {
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "severity": "HIGH"
        },

        "file_upload_attack": {
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "severity": "HIGH"
        }
    }

    return mitre_database.get(
        attack_type,
        {
            "technique_id": "T0000",
            "technique_name": "Unknown Technique",
            "severity": "LOW"
        }
    )