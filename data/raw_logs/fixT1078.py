import pandas as pd
import random
from datetime import datetime, timedelta

random.seed(99)

NEW_SUSPICIOUS_IPS = [
    {
        "ip":      "212.83.175.34",
        "country": "Germany",
        "city":    "Frankfurt",
        "targets": [("alice", False), ("bob", False), ("sysadmin", True)],
        "hour":    11,
    },
    {
        "ip":      "62.210.180.229",
        "country": "France",
        "city":    "Paris",
        "targets": [("charlie", False), ("devops", True)],
        "hour":    2,
    },
    {
        "ip":      "89.248.167.131",
        "country": "Netherlands",
        "city":    "Amsterdam",
        "targets": [("diana", False), ("root", True), ("eve", False)],
        "hour":    4,
    },
    {
        "ip":      "171.25.193.78",
        "country": "Sweden",
        "city":    "Stockholm",
        "targets": [("admin", True), ("frank", False)],
        "hour":    23,
    },
]

BASE_DATES = [
    datetime(2024, 1, 19),
    datetime(2024, 1, 21),
    datetime(2024, 1, 23),
    datetime(2024, 1, 26),
]

def generate_t1078_expanded():
    events = []
    for ip_config, base_date in zip(NEW_SUSPICIOUS_IPS, BASE_DATES):
        ip      = ip_config["ip"]
        country = ip_config["country"]
        city    = ip_config["city"]
        hour    = ip_config["hour"]

        for username, is_admin in ip_config["targets"]:
            base       = base_date.replace(hour=hour,
                                           minute=random.randint(0, 59))
            n_failures = random.randint(20, 80)
            n_success  = random.randint(1, 2)

            for i in range(n_failures):
                events.append({
                    "timestamp":   str(base + timedelta(seconds=i * 9)),
                    "source_ip":   ip,
                    "dest_ip":     "10.0.0.1",
                    "username":    username,
                    "event_type":  "LOGIN_FAILED",
                    "auth_method": "password",
                    "status_code": 401,
                    "user_agent":  random.choice([
                                       "Hydra/9.4",
                                       "Medusa/2.2",
                                       "python-requests/2.28.0"
                                   ]),
                    "country":     country,
                    "city":        city,
                    "is_admin":    is_admin
                })

            for j in range(n_success):
                events.append({
                    "timestamp":   str(base + timedelta(seconds=n_failures*9 + j*5 + 10)),
                    "source_ip":   ip,
                    "dest_ip":     "10.0.0.1",
                    "username":    username,
                    "event_type":  "LOGIN_SUCCESS",
                    "auth_method": "password",
                    "status_code": 200,
                    "user_agent":  "Mozilla/5.0",
                    "country":     country,
                    "city":        city,
                    "is_admin":    is_admin
                })
    return events


if __name__ == "__main__":

    existing = pd.read_csv("data/raw_logs/auth_logs.csv")
    print(f"Existing auth_logs rows: {len(existing)}")

    new_events = generate_t1078_expanded()
    new_df     = pd.DataFrame(new_events)
    print(f"New T1078 rows to add:   {len(new_df)}")

    combined = pd.concat([existing, new_df], ignore_index=True)

    # ── FIX: convert everything to string before sorting ──
    combined['timestamp'] = combined['timestamp'].astype(str)
    combined = combined.sort_values("timestamp").reset_index(drop=True)

    print(f"Combined total rows:     {len(combined)}")

    combined.to_csv("data/raw_logs/auth_logs.csv", index=False)
    print("\nSaved successfully.")

    print("\n--- VERIFICATION ---")
    print("Event types:\n",     combined['event_type'].value_counts())
    print("\nTop attack IPs:\n", combined['source_ip'].value_counts().head(12))

    t1078_ips = [c["ip"] for c in NEW_SUSPICIOUS_IPS]
    print("\nT1078 new IPs confirmed:")
    for ip in t1078_ips:
        count = len(combined[combined['source_ip'] == ip])
        print(f"  {ip}: {count} rows")