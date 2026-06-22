import sqlite3
import os
import json

DB_PATH=os.path.join(os.path.dirname(__file__),"soc_incidents.db")

def get_connection():
    conn=sqlite3.connect(DB_PATH)
    conn.row_factory=sqlite3.Row
    return conn

def create_table():
    conn=get_connection()
    cursor=conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents(
        incident_id TEXT PRIMARY KEY,timestamp_processed TEXT,
                   source_ip TEXT,log_source TEXT,
                   suspicious INTEGER, severity TEXT,
                   confidence_triage REAL,signals TEXT,
                   triage_reasoning TEXT,attack_type TEXT,
                   primary_mitre_id TEXT, secondary_mitre_id TEXT,
                   evidence TEXT,confidence_investigation REAL,
                   investigation_reasoning TEXT, actions TEXT,
                   escalate_to_human INTEGER,severity_final TEXT,
                   response_reasoning TEXT,retriage_count INTEGER,
                   triage_time REAL,investigation_time REAL,response_time REAL,total_time REAL)
            """)
    conn.commit()
    conn.close()
    print(f"DATABASE CREATED AT : {DB_PATH} ")


def save_incidents(state:dict):
    conn=get_connection()
    cursor=conn.cursor()

    cursor.execute(""" 
        INSERT OR REPLACE INTO incidents VALUES(
            ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?       
            )
        """, (
            state.get("incident_id"),
            str(state.get("timestamp_processed")),
            state.get("source_ip"),
            state.get("log_source"),
            1 if state.get("suspicious") else 0,          
            state.get("severity"),
            state.get("confidence_triage"),
            ", ".join(state.get("signals", [])),           
            state.get("triage_reasoning"),
            state.get("attack_type"),
            state.get("primary_mitre_id"),
            state.get("secondary_mitre_id"),
            state.get("evidence"),
            state.get("confidence_investigation"),
            state.get("investigation_reasoning"),
            json.dumps(state.get("actions", [])),          
            1 if state.get("escalate_to_human") else 0,   
            state.get("severity_final"),
            state.get("response_reasoning"),
            state.get("retriage_count", 0),
            state.get("triage_time",0.0),
            state.get("investigation_time",0.0),
            state.get("response_time",0.0),
            state.get("total_time",0.0)
            )
            )

    conn.commit()
    conn.close()
    print(f"INCIDENT {state.get('incident_id')} saved.")


def fetch_incident(incident_id:str)->dict:
        conn=get_connection()
        cursor=conn.cursor()
        cursor.execute("SELECT * FROM incidents WHERE incident_id = ?",(incident_id,))
        row=cursor.fetchone()
        conn.close()
        if row is None:
            return {}
        result=dict(row)
        result["signals"]=result["signals"].split(",") if result["signals"] else []
        result["actions"]=json.loads(result["actions"]) if result["actions"] else []
        result["suspicious"] = bool(result["suspicious"])
        result["escalate_to_human"]=bool(result["escalate_to_human"])
        return result
    
def fetch_all_incidents()->list:
        conn=get_connection()
        cursor=conn.cursor()
        cursor.execute("SELECT * FROM incidents ORDER BY timestamp_processed DESC")
        rows=cursor.fetchall()
        conn.close()
        return[dict(row) for row in rows]
    
if __name__ == "__main__":
        create_table()