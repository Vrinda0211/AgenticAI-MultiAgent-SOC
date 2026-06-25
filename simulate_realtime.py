import pandas as pd
import time
import requests

df_auth=pd.read_csv('data/cleaned_logs/auth_logs_cleaned.csv').sample(20)
df_port=pd.read_csv('data/cleaned_logs/port_scan_logs_cleaned.csv').sample(20)

if __name__=="__main__":
    print("Starting Real Time Simulation")
    print("Sending Auth Log Events")

    for index,row in df_auth.iterrows():
        requests.post("http://localhost:8000/analyze",json=row.to_dict())
        print(f"Event sent: {row['source_ip']} - {row['event_type']}")
        time.sleep(2)

    print("Sending Port Scan Log Events")

    for index,row in df_port.iterrows():
        requests.post("http://localhost:8000/analyze",json=row.to_dict())
        print(f"Event sent: {row['source_ip']} - {row['action']}")
        time.sleep(2) 
    
    print("Simulation Complete")