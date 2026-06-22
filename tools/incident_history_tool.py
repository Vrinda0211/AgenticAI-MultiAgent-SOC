from langchain_core.tools import tool
import pandas as pd

@tool
def incident_history_tool(ip_address:str)->dict:
    """Given a source IP address, retrieves the complete history of all events associated 
    with that IP from both auth logs and port scan logs, including failed logins, successful
    logins, ports scanned, and timestamps."""
    
    df_auth=pd.read_csv('data/cleaned_logs/auth_logs_cleaned.csv')
    df_port=pd.read_csv('data/cleaned_logs/port_scan_logs_cleaned.csv')

    ip_address = str(ip_address).strip()

    auth_records = df_auth[df_auth["source_ip"] == ip_address]
    port_records = df_port[df_port["source_ip"] == ip_address]
    
    if auth_records.empty and port_records.empty:
        return {"ip_address": ip_address,
                "total_events": 0,
                "found": False }
    else:
        total_events =len(auth_records)+len(port_records)
        failed_auth_logs = (auth_records["event_type"] == "LOGIN_FAILED").sum()
        successful_auth_logs = (auth_records["event_type"] == "LOGIN_SUCCESS").sum()
        #print(failed_auth_logs)
        selected_auth_events = ["timestamp","event_type","username","is_admin"]
        auth_events=auth_records[selected_auth_events].head(5).to_dict(orient='records')

        selected_port_events=["timestamp","destination_port","action","connection_state"]
        port_events=port_records[selected_port_events].head(5).to_dict(orient='records')

        
        countries = list(set(auth_records["country"])|set(port_records["country"]))
        unique_ports_scanned=port_records["destination_port"].nunique()

        auth_times=pd.to_datetime(auth_records["timestamp"])
        port_times=pd.to_datetime(port_records["timestamp"])
        all_times=pd.concat([auth_times,port_times])
        first_seen=all_times.min()
        last_seen=all_times.max()

        

        return {
            "ip_address": ip_address,
            "total_events": total_events,
            "auth_events": auth_events,
            "port_scan_events":port_events,
            "failed_logins": int(failed_auth_logs),
            "successful_logins": int(successful_auth_logs),
            "unique_ports_scanned":int(unique_ports_scanned),
            "countries":countries[:3],
            "first_seen":str(first_seen),
            "last_seen":str(last_seen),
            "found":True
        }
       


