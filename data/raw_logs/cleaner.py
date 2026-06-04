import pandas as pd

df_auth=pd.read_csv("data/raw_logs/auth_logs.csv")
df_port=pd.read_csv("data/raw_logs/port_scan_logs.csv")

print(df_auth.shape)
print(df_port.shape)

print(df_auth.isnull().sum())
print(df_port.isnull().sum())

print(df_auth.duplicated().sum())
print(df_port.duplicated().sum())

df_auth['timestamp']=pd.to_datetime(df_auth['timestamp'])
df_port['timestamp']=pd.to_datetime(df_port['timestamp'])
print(df_auth['timestamp'].dtypes)
print(df_port['timestamp'].dtypes)

df_auth=df_auth.apply(lambda x: x.str.strip() if x.dtype=='object' else x)
df_port=df_port.apply(lambda x: x.str.strip() if x.dtype=='object' else x)
print("done")

df_auth.to_csv("auth_logs_cleaned.csv", index=False)
df_port.to_csv("port_scan_logs_cleaned.csv", index=False)

print("Files saved successfully")