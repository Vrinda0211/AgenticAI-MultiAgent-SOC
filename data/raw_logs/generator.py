import pandas as pd
import random
from datetime import datetime, timedelta
import json

# ── CONFIG ──────────────────────────────────────────
START_TIME = datetime(2024, 1, 15, 0, 0, 0)
NORMAL_IPS = [f"10.0.{random.randint(0,5)}.{random.randint(1,254)}" for _ in range(20)]
ADMIN_USERS = ["admin", "root", "sysadmin", "devops"]
REGULAR_USERS = ["alice", "bob", "charlie", "diana", "eve", "frank"]
ALL_USERS = ADMIN_USERS + REGULAR_USERS

# Attack IPs — these will show up in attack scenarios
BRUTE_FORCE_IP_NEW = "185.220.101.45"        # new IP, first time seen
BRUTE_FORCE_IP_REPEAT = "194.165.16.72"      # repeat offender
SUSPICIOUS_LOGIN_IP_BUSINESS = "103.21.244.0" # business hours, known region
SUSPICIOUS_LOGIN_IP_NIGHT = "45.33.32.156"   # 3am, unknown country
PORT_SCAN_IP = "198.51.100.23"

def random_time(base, max_offset_minutes=60):
    return base + timedelta(minutes=random.randint(0, max_offset_minutes),
                           seconds=random.randint(0, 59))

# ── NORMAL AUTH EVENTS ───────────────────────────────
def generate_normal_auth(n=150):
    events = []
    for _ in range(n):
        t = random_time(START_TIME, max_offset_minutes=60*24*7)
        user = random.choice(ALL_USERS)
        ip = random.choice(NORMAL_IPS)
        events.append({
            "timestamp": t,
            "source_ip": ip,
            "destination_ip": "10.0.0.1",
            "username": user,
            "event_type": random.choice(["LOGIN_SUCCESS", "LOGOUT"]),
            "auth_method": random.choice(["password", "ssh_key", "mfa"]),
            "status_code": 200,
            "user_agent": "Mozilla/5.0",
            "country": "India",
            "city": "Chennai",
            "is_admin": user in ADMIN_USERS
        })
    return events

# ── ATTACK 1: BRUTE FORCE (New IP) ──────────────────
def generate_brute_force_new_ip():
    """New IP, targets regular user, fails then stops. Severity: Medium"""
    events = []
    base = datetime(2024, 1, 15, 14, 23, 0)  # business hours
    target_user = "alice"

    # 35 failed attempts
    for i in range(35):
        events.append({
            "timestamp": base + timedelta(seconds=i*10),
            "source_ip": BRUTE_FORCE_IP_NEW,
            "destination_ip": "10.0.0.1",
            "username": target_user,
            "event_type": "LOGIN_FAILED",
            "auth_method": "password",
            "status_code": 401,
            "user_agent": "python-requests/2.28.0",
            "country": "Netherlands",
            "city": "Amsterdam",
            "is_admin": False
        })
    return events

# ── ATTACK 2: BRUTE FORCE (Repeat Offender IP) ───────
def generate_brute_force_repeat_ip():
    """Repeat offender IP, targets admin, succeeds. Severity: Critical"""
    events = []
    base = datetime(2024, 1, 16, 3, 12, 0)  # 3am
    target_user = "admin"

    # 47 failed attempts
    for i in range(47):
        events.append({
            "timestamp": base + timedelta(seconds=i*8),
            "source_ip": BRUTE_FORCE_IP_REPEAT,
            "destination_ip": "10.0.0.1",
            "username": target_user,
            "event_type": "LOGIN_FAILED",
            "auth_method": "password",
            "status_code": 401,
            "user_agent": "Hydra/9.4",
            "country": "Russia",
            "city": "Moscow",
            "is_admin": True
        })

    # 1 success after brute force
    events.append({
        "timestamp": base + timedelta(seconds=47*8 + 5),
        "source_ip": BRUTE_FORCE_IP_REPEAT,
        "destination_ip": "10.0.0.1",
        "username": target_user,
        "event_type": "LOGIN_SUCCESS",
        "auth_method": "password",
        "status_code": 200,
        "user_agent": "Hydra/9.4",
        "country": "Russia",
        "city": "Moscow",
        "is_admin": True
    })
    return events

# ── ATTACK 3: SUSPICIOUS LOGIN (Business Hours) ──────
def generate_suspicious_login_business_hours():
    """New IP, business hours, regular user. Severity: Medium"""
    events = []
    base = datetime(2024, 1, 17, 10, 45, 0)

    events.append({
        "timestamp": base,
        "source_ip": SUSPICIOUS_LOGIN_IP_BUSINESS,
        "destination_ip": "10.0.0.1",
        "username": "bob",
        "event_type": "LOGIN_SUCCESS",
        "auth_method": "password",
        "status_code": 200,
        "user_agent": "Mozilla/5.0",
        "country": "Singapore",
        "city": "Singapore",
        "is_admin": False
    })
    return events

# ── ATTACK 4: SUSPICIOUS LOGIN (3am, Admin) ──────────
def generate_suspicious_login_night_admin():
    """3am, new country, admin account. Severity: Critical"""
    events = []
    base = datetime(2024, 1, 18, 3, 7, 0)

    events.append({
        "timestamp": base,
        "source_ip": SUSPICIOUS_LOGIN_IP_NIGHT,
        "destination_ip": "10.0.0.1",
        "username": "root",
        "event_type": "LOGIN_SUCCESS",
        "auth_method": "password",
        "status_code": 200,
        "user_agent": "curl/7.81.0",
        "country": "North Korea",
        "city": "Pyongyang",
        "is_admin": True
    })
    return events

# ── ATTACK 5: PORT SCAN ───────────────────────────────
def generate_port_scan():
    """Sequential port scanning from single IP"""
    events = []
    base = datetime(2024, 1, 19, 22, 0, 0)
    target = "10.0.0.50"
    common_ports = list(range(20, 1025))  # 1005 ports

    for i, port in enumerate(common_ports):
        events.append({
            "timestamp": base + timedelta(milliseconds=i*50),
            "source_ip": PORT_SCAN_IP,
            "destination_ip": target,
            "source_port": random.randint(40000, 65000),
            "destination_port": port,
            "protocol": "TCP",
            "action": "DENY" if port not in [22, 80, 443] else "ALLOW",
            "bytes_sent": 60,
            "connection_state": "SYN"
        })
    return events

# ── GENERATE AND SAVE ─────────────────────────────────
if __name__ == "__main__":

    # Auth logs
    auth_events = (
        generate_normal_auth(150) +
        generate_brute_force_new_ip() +
        generate_brute_force_repeat_ip() +
        generate_suspicious_login_business_hours() +
        generate_suspicious_login_night_admin()
    )
    auth_df = pd.DataFrame(auth_events).sort_values("timestamp")
    auth_df.to_csv("data/raw_logs/auth_logs.csv", index=False)
    print(f"Auth logs: {len(auth_df)} events")

    # Firewall/network logs (port scan)
    scan_events = generate_port_scan()
    scan_df = pd.DataFrame(scan_events).sort_values("timestamp")
    scan_df.to_csv("data/raw_logs/firewall_logs.csv", index=False)
    print(f"Firewall logs: {len(scan_df)} events")

    print("Done. Check data/raw_logs/")