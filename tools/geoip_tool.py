from langchain_core.tools import tool
import pandas as pd

@tool
def geoip_tool(ip_address:str)->dict:
    """Given a source IP address, returns the city and country location by looking up the IP in the auth and port scan logs."""
    df_auth=pd.read_csv('data/cleaned_logs/auth_logs_cleaned.csv')
    df_port=pd.read_csv('data/cleaned_logs/port_scan_logs_cleaned.csv')
    result=df_auth[df_auth["source_ip"]==ip_address]
    result_2=df_port[df_port["source_ip"]==ip_address]
    if not result.empty:
        city=result["city"].iloc[0]
        country=result["country"].iloc[0]
    elif not result_2.empty:
        city=result_2["city"].iloc[0]
        country=result_2["country"].iloc[0]
    else :
        return {"city":"Unknown","country":"Unknown","error":"IP not found"}
    return {"city":city,"country":country}