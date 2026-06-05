import pandas as pd
import random
from datetime import datetime, timedelta

random.seed(42)

# ── CONFIG ──────────────────────────────────────────────────────────────────
START_TIME = datetime(2024, 1, 15, 0, 0, 0)

NORMAL_IPS = [f"10.0.{r}.{e}" 
              for r in range(6) 
              for e in random.sample(range(1, 254), 8)]

ADMIN_USERS    = ["admin", "root", "sysadmin", "devops"]
REGULAR_USERS  = ["alice", "bob", "charlie", "diana", "eve", "frank",
                  "george", "hannah", "ivan", "julia", "kevin", "laura"]
ALL_USERS      = ADMIN_USERS + REGULAR_USERS

# Known attack IPs — same as before so incident_history_tool works
BRUTE_FORCE_IP_NEW      = "185.220.101.45"   # new IP, no history
BRUTE_FORCE_IP_REPEAT   = "194.165.16.72"    # repeat offender — golden demo IP
SUSPICIOUS_IP_BUSINESS  = "103.21.244.0"     # business hours, known region
SUSPICIOUS_IP_NIGHT     = "45.33.32.156"     # 3am, admin, unknown country

# Extra attack IPs to give incident_history_tool meaningful lookups
EXTRA_ATTACK_IPS = [
    "91.108.4.0",       # medium frequency attacker
    "185.143.223.12",   # low frequency attacker
    "179.43.128.0",     # occasional brute force
    "5.188.86.172",     # port scanner that also brute forces
]

COUNTRIES = {
    BRUTE_FORCE_IP_NEW:     ("Netherlands", "Amsterdam"),
    BRUTE_FORCE_IP_REPEAT:  ("Russia",      "Moscow"),
    SUSPICIOUS_IP_BUSINESS: ("Singapore",   "Singapore"),
    SUSPICIOUS_IP_NIGHT:    ("North Korea",  "Pyongyang"),
    "91.108.4.0":           ("China",        "Beijing"),
    "185.143.223.12":       ("Iran",         "Tehran"),
    "179.43.128.0":         ("Romania",      "Bucharest"),
    "5.188.86.172":         ("Ukraine",      "Kyiv"),
}

def rtime(base, max_offset_hours=24*30):
    return base + timedelta(
        hours=random.randint(0, max_offset_hours),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59)
    )

# ── NORMAL TRAFFIC (1500 events) ─────────────────────────────────────────────
def generate_normal(n=1500):
    events = []
    for _ in range(n):
        t    = rtime(START_TIME)
        user = random.choice(ALL_USERS)
        ip   = random.choice(NORMAL_IPS)
        events.append({
            "timestamp":    t,
            "source_ip":    ip,
            "dest_ip":      "10.0.0.1",
            "username":     user,
            "event_type":   random.choice(["LOGIN_SUCCESS", "LOGOUT",
                                           "LOGIN_SUCCESS", "LOGIN_SUCCESS"]),
            "auth_method":  random.choice(["password", "ssh_key", "mfa"]),
            "status_code":  200,
            "user_agent":   "Mozilla/5.0",
            "country":      "India",
            "city":         "Chennai",
            "is_admin":     user in ADMIN_USERS
        })
    return events

# ── BRUTE FORCE: repeat offender (multiple waves) ────────────────────────────
def generate_bf_repeat(n_waves=6):
    """
    194.165.16.72 attacks multiple times over the dataset period.
    Wave 1: fails only (early history)
    Wave 2: fails only
    Wave 3: fails only
    Wave 4: fails only
    Wave 5: fails only
    Wave 6: 47 fails → 1 SUCCESS on admin (the golden demo scenario)
    This gives incident_history_tool 5 prior incidents to find.
    """
    events = []
    base_times = [
        datetime(2024, 1,  10, 2, 14, 0),
        datetime(2024, 1,  12, 3, 45, 0),
        datetime(2024, 1,  13, 1, 22, 0),
        datetime(2024, 1,  14, 4, 10, 0),
        datetime(2024, 1,  15, 2, 55, 0),
        datetime(2024, 1,  16, 3, 12, 0),  # golden demo wave
    ]
    targets = ["alice", "bob", "charlie", "diana", "eve", "admin"]

    for wave, (base, target) in enumerate(zip(base_times, targets)):
        n_fails  = random.randint(20, 50)
        is_admin = target in ADMIN_USERS
        success  = (wave == 5)  # only last wave succeeds

        for i in range(n_fails):
            events.append({
                "timestamp":   base + timedelta(seconds=i * 8),
                "source_ip":   BRUTE_FORCE_IP_REPEAT,
                "dest_ip":     "10.0.0.1",
                "username":    target,
                "event_type":  "LOGIN_FAILED",
                "auth_method": "password",
                "status_code": 401,
                "user_agent":  "Hydra/9.4",
                "country":     "Russia",
                "city":        "Moscow",
                "is_admin":    is_admin
            })
        if success:
            events.append({
                "timestamp":   base + timedelta(seconds=n_fails * 8 + 5),
                "source_ip":   BRUTE_FORCE_IP_REPEAT,
                "dest_ip":     "10.0.0.1",
                "username":    target,
                "event_type":  "LOGIN_SUCCESS",
                "auth_method": "password",
                "status_code": 200,
                "user_agent":  "Hydra/9.4",
                "country":     "Russia",
                "city":        "Moscow",
                "is_admin":    is_admin
            })
    return events

# ── BRUTE FORCE: new IP (single wave, no prior history) ──────────────────────
def generate_bf_new(n_incidents=3):
    """185.220.101.45 — new IP, no history, medium severity"""
    events = []
    base_times = [
        datetime(2024, 1, 15, 14, 23, 0),
        datetime(2024, 1, 20, 11, 5,  0),
        datetime(2024, 1, 25, 16, 40, 0),
    ]
    for base in base_times:
        n_fails = random.randint(30, 50)
        target  = random.choice(REGULAR_USERS)
        for i in range(n_fails):
            events.append({
                "timestamp":   base + timedelta(seconds=i * 10),
                "source_ip":   BRUTE_FORCE_IP_NEW,
                "dest_ip":     "10.0.0.1",
                "username":    target,
                "event_type":  "LOGIN_FAILED",
                "auth_method": "password",
                "status_code": 401,
                "user_agent":  "python-requests/2.28.0",
                "country":     "Netherlands",
                "city":        "Amsterdam",
                "is_admin":    False
            })
    return events

# ── EXTRA ATTACK IPs (give history depth) ────────────────────────────────────
def generate_extra_attackers():
    events = []
    for ip in EXTRA_ATTACK_IPS:
        country, city = COUNTRIES[ip]
        n_incidents   = random.randint(2, 4)
        for _ in range(n_incidents):
            base    = rtime(START_TIME, max_offset_hours=24*20)
            n_fails = random.randint(15, 40)
            target  = random.choice(ALL_USERS)
            for i in range(n_fails):
                events.append({
                    "timestamp":   base + timedelta(seconds=i * 12),
                    "source_ip":   ip,
                    "dest_ip":     "10.0.0.1",
                    "username":    target,
                    "event_type":  "LOGIN_FAILED",
                    "auth_method": "password",
                    "status_code": 401,
                    "user_agent":  "Hydra/9.4",
                    "country":     country,
                    "city":        city,
                    "is_admin":    target in ADMIN_USERS
                })
    return events

# ── SUSPICIOUS LOGIN ──────────────────────────────────────────────────────────
def generate_suspicious_logins():
    events = []

    # Business hours — medium severity
    for _ in range(3):
        base = rtime(datetime(2024, 1, 17, 9, 0, 0), max_offset_hours=24*10)
        base = base.replace(hour=random.randint(9, 17))
        events.append({
            "timestamp":   base,
            "source_ip":   SUSPICIOUS_IP_BUSINESS,
            "dest_ip":     "10.0.0.1",
            "username":    random.choice(REGULAR_USERS),
            "event_type":  "LOGIN_SUCCESS",
            "auth_method": "password",
            "status_code": 200,
            "user_agent":  "Mozilla/5.0",
            "country":     "Singapore",
            "city":        "Singapore",
            "is_admin":    False
        })

    # 3am admin — critical severity
    for _ in range(2):
        base = rtime(datetime(2024, 1, 18, 3, 0, 0), max_offset_hours=24*5)
        base = base.replace(hour=random.randint(2, 4))
        events.append({
            "timestamp":   base,
            "source_ip":   SUSPICIOUS_IP_NIGHT,
            "dest_ip":     "10.0.0.1",
            "username":    random.choice(ADMIN_USERS),
            "event_type":  "LOGIN_SUCCESS",
            "auth_method": "password",
            "status_code": 200,
            "user_agent":  "curl/7.81.0",
            "country":     "North Korea",
            "city":        "Pyongyang",
            "is_admin":    True
        })
    return events

# ── PORT SCAN LOGS WITH IPs ───────────────────────────────────────────────────
def generate_port_scan_with_ips():
    """
    Creates port_scan_logs.csv with real IPs so agents can
    correlate port scan IPs with brute force IPs.
    """
    events      = []
    scan_ips    = [
        "198.51.100.23",     # dedicated scanner
        "5.188.86.172",      # scanner that also brute forces (in auth logs)
        "203.0.113.45",      # occasional scanner
        BRUTE_FORCE_IP_REPEAT,  # repeat offender also port scans first
    ]
    target_host = "10.0.0.50"
    ports       = list(range(20, 1025))

    for ip in scan_ips:
        country, city = COUNTRIES.get(ip, ("Unknown", "Unknown"))
        base          = rtime(START_TIME, max_offset_hours=24*25)
        n_ports       = random.randint(200, len(ports))
        scan_ports    = random.sample(ports, n_ports)

        for i, port in enumerate(sorted(scan_ports)):
            events.append({
                "timestamp":      base + timedelta(milliseconds=i * 50),
                "source_ip":      ip,
                "destination_ip": target_host,
                "source_port":    random.randint(40000, 65000),
                "destination_port": port,
                "protocol":       "TCP",
                "action":         "ALLOW" if port in [22, 80, 443, 8080]
                                          else "DENY",
                "bytes_sent":     60,
                "connection_state": "SYN",
                "country":        country,
                "city":           city
            })

    # Add normal firewall traffic
    for _ in range(500):
        t = rtime(START_TIME)
        events.append({
            "timestamp":        t,
            "source_ip":        random.choice(NORMAL_IPS),
            "destination_ip":   target_host,
            "source_port":      random.randint(1024, 65000),
            "destination_port": random.choice([80, 443, 22, 8080]),
            "protocol":         random.choice(["TCP", "UDP"]),
            "action":           "ALLOW",
            "bytes_sent":       random.randint(60, 1500),
            "connection_state": "ESTABLISHED",
            "country":          "India",
            "city":             "Chennai"
        })

    return events


# ── GENERATE AND SAVE ─────────────────────────────────────────────────────────
if __name__ == "__main__":

    # --- AUTH LOGS ---
    all_auth = (
        generate_normal(1500) +
        generate_bf_repeat(6) +
        generate_bf_new(3) +
        generate_extra_attackers() +
        generate_suspicious_logins()
    )
    auth_df = pd.DataFrame(all_auth).sort_values("timestamp").reset_index(drop=True)
    auth_df.to_csv("data/raw_logs/auth_logs.csv", index=False)
    print(f"Auth logs:      {len(auth_df)} rows")

    # --- PORT SCAN LOGS ---
    scan_events = generate_port_scan_with_ips()
    scan_df     = pd.DataFrame(scan_events).sort_values("timestamp").reset_index(drop=True)
    scan_df.to_csv("data/raw_logs/port_scan_logs.csv", index=False)
    print(f"Port scan logs: {len(scan_df)} rows")

    # --- VERIFICATION ---
    print("\n--- AUTH VERIFICATION ---")
    print("Event types:\n", auth_df['event_type'].value_counts())
    print("\nTop IPs:\n", auth_df['source_ip'].value_counts().head(10))

    print("\n--- PORT SCAN VERIFICATION ---")
    print("Top scanner IPs:\n", scan_df['source_ip'].value_counts().head(8))
    print("Actions:\n", scan_df['action'].value_counts())