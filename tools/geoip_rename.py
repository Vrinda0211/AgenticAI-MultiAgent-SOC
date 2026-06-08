import pandas as pd

def geoip_tool(ip_address):
    df_auth=pd.read_csv('data/cleaned_logs/auth_logs_cleaned.csv')
    city=df_auth.loc[df_auth["source_ip"]==ip_address,"city"].iloc[0]
    country=df_auth.loc[df_auth["source_ip"]==ip_address,"country"].iloc[0]
    location=(city,country)
    return location