import pandas as pd
import sys
sys.path.append('.')
from config import SUSPICIOUS_COUNTRIES, REPUTATION_WEIGHTS

def ip_reputation_tool(ip_address):
    fail_count=0
    success_count=0
    df_auth=pd.read_csv('data/cleaned_logs/auth_logs_cleaned.csv')
    result=df_auth[df_auth["source_ip"]==ip_address]
    fail_count=len(result[result["event_type"]=="LOGIN_FAILED"])
    success_count=len(result[result["event_type"]=="LOGIN_SUCCESS"])

    df_port=pd.read_csv('data/cleaned_logs/port_scan_logs_cleaned.csv')
    scanned_ports=0
    result2=df_port[df_port["source_ip"]==ip_address]
    scanned_ports=result2["destination_port"].nunique()

    if not result.empty:
        country=result["country"].iloc[0]
    elif not result2.empty:
        country=result2["country"].iloc[0]
    else :
        country=None
    
    sus_country=country in SUSPICIOUS_COUNTRIES
    admin_targeted=any(result["is_admin"]==True) if not result.empty else False

    score=(REPUTATION_WEIGHTS["failed_login"]*fail_count +
    REPUTATION_WEIGHTS["successful_login_after_failure"]*success_count +
    REPUTATION_WEIGHTS["port_scan"]*scanned_ports +
    REPUTATION_WEIGHTS["suspicious_country"]*sus_country +
    REPUTATION_WEIGHTS["admin_targeted"]*admin_targeted)
    score=min(score,100)

    return{
        "ip_address":ip_address,
        "score":score,
        "failed_logins":fail_count,
        "successful_logins":success_count,
        "ports_scanned":scanned_ports,
        "country":country,
        "suspicious_country":sus_country,
        "admin_targeted":admin_targeted
    }

print(ip_reputation_tool("194.165.16.72"))
print(ip_reputation_tool("999.999.999.999"))