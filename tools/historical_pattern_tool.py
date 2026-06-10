from langchain_core.tools import tool
import pandas as pd
from datetime import datetime, timedelta


@tool
def historical_pattern_tool(ip_address:str)->dict:
    """Given a source IP address, analyzes behavioral patterns and detects which attack 
    types are present — brute force, port scan, or suspicious login — based on the IP's 
    activity across auth and port scan logs."""
    
    df_auth=pd.read_csv('data/cleaned_logs/auth_logs_cleaned.csv')
    df_port=pd.read_csv('data/cleaned_logs/port_scan_logs_cleaned.csv')
    ip_address = str(ip_address).strip()

    df_auth['timestamp']=pd.to_datetime(df_auth['timestamp'])
    df_port['timestamp']=pd.to_datetime(df_port['timestamp'])

    auth_records = df_auth[df_auth["source_ip"] == ip_address]
    port_records = df_port[df_port["source_ip"] == ip_address]

    if auth_records.empty and port_records.empty:
        return {
            "ip_address":ip_address,
            "found":False,
            "patterns_found":[]
        }
    patterns_found=[]
    failed_auth_logs = (auth_records["event_type"] == "LOGIN_FAILED").sum()
    
    #Brute force attack detection
    if(failed_auth_logs>5):
       
        patterns_found.append('brute_force')
        target_users = list(set(auth_records["username"]))
        targeted_admin = (auth_records['is_admin'] == True).any()
      
        brute_force = {
        "detected": True,
        "failed_logins": int(failed_auth_logs),
        "targeted_usernames": target_users,
        "targeted_admin": targeted_admin
        }
    else:
        brute_force = {
        "detected": False,
        "failed_logins": int(failed_auth_logs),
        "targeted_usernames": [],
        "targeted_admin": False
        }

    #Portscan attack detection
    unique_ports_scanned=port_records["destination_port"].nunique()
    if(unique_ports_scanned>10):
        patterns_found.append('port_scan')
        port_times=port_records["timestamp"]
        scan_duration_seconds=(port_times.max()-port_times.min()).total_seconds()
        target_ports = port_records["destination_port"].unique().tolist()[:5]
        port_scan={
            "detected":True,
            "unique_ports_scanned":unique_ports_scanned,
            "scan_duration_seconds":scan_duration_seconds,
            "ports_sample":target_ports
        }
    else:
        port_scan={
            "detected":False,
            "unique_ports_scanned":int(0),
            "scan_duration_seconds":int(0),
            "ports_sample":[]
        }
    #Suspicious login
    
    auth_sorted = auth_records.sort_values("timestamp")
    successful_logins=auth_sorted[auth_sorted["event_type"]=="LOGIN_SUCCESS"]
   
    successful_login_count=len(successful_logins)

    if(successful_logins.empty):
        suspicious_login={
            "detected":False,
            "failed_before_success":int(0),
            "successful_logins": int(0),
            "off_hours_login":None,

        }
    else:
        first_success=successful_logins.iloc[0]
       
        success_time=first_success["timestamp"]
        events_before_success=auth_sorted[auth_sorted["timestamp"]<success_time]
        failures_before_success=len(events_before_success[events_before_success["event_type"]=="LOGIN_FAILED"])
        
        if(successful_login_count > 0 and failures_before_success > 0):
            detected=True
            patterns_found.append('suspicious_login')
            if(success_time.hour<6 or success_time.hour>22):
                off_hours_login=True
            else:
                off_hours_login=False

            suspicious_login={
            "detected":detected,
            "failed_before_success":failures_before_success,
            "successful_logins": successful_login_count,
            "off_hours_login":off_hours_login,

            }
        else:
            suspicious_login={
            "detected":False,
            "failed_before_success":failures_before_success,
            "successful_logins": successful_login_count,
            "off_hours_login":None,

            }

    return {
        "ip_address":ip_address,
        "patterns_found":patterns_found,
        "brute_force":brute_force,
        "port_scan":port_scan,
        "suspicious_login":suspicious_login,
        "found":True
    }


