import sys
sys.path.append('.')
from database.db_setup import create_table, save_incidents, fetch_incident, fetch_all_incidents

# Step 1 — create table
create_table()

# Step 2 — save a dummy incident
dummy_state = {
    "incident_id": "INC-001",
    "timestamp_processed": "2024-03-22 02:47:00",
    "source_ip": "194.165.16.72",
    "log_source": "auth_logs",
    "suspicious": True,
    "severity": "Critical",
    "confidence_triage": 87.0,
    "signals": ["brute_force", "suspicious_country", "admin_target"],
    "triage_reasoning": "IP scored 87. Russian IP targeting admin account.",
    "attack_type": "Brute Force",
    "primary_mitre_id": "T1110",
    "secondary_mitre_id": "T1078",
    "evidence": "14 failed logins followed by successful admin login at 2:47 AM.",
    "confidence_investigation": 92.0,
    "investigation_reasoning": "Confirmed brute force with successful login.",
    "actions": [{"action": "block_ip"}, {"action": "reset_password"}],
    "escalate_to_human": True,
    "severity_final": "Critical",
    "response_reasoning": "Admin account compromised. Immediate action required.",
    "retriage_count": 0
}

save_incidents(dummy_state)

# Step 3 — fetch it back by ID
print("\n--- Fetching INC-001 ---")
record = fetch_incident("INC-001")
print("source_ip:", record["source_ip"])
print("severity:", record["severity"])
print("signals:", record["signals"])         # should be a list
print("actions:", record["actions"])         # should be a list of dicts
print("escalate_to_human:", record["escalate_to_human"])  # should be True

# Step 4 — fetch all
print("\n--- All incidents ---")
all_records = fetch_all_incidents()
print(f"Total incidents in DB: {len(all_records)}")