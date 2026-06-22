from fastapi import FastAPI,HTTPException
import uvicorn
import sys
sys.path.append('.')
from database.db_setup import fetch_all_incidents,fetch_incident
from graph import pipeline

app=FastAPI(title="SOC Copilot API")

@app.post("/analyze")
def analyze_event(event:dict):
    initial_state={
        "raw_event":event,
        "source_ip":event.get("source_ip",""),
        "log_source":event.get("log_source","auth_logs"),
        "retriage_count":0
    }
    try:
        result=pipeline.invoke(initial_state)
        return result
    except Exception as e:
        raise HTTPException(status_code=500,detail=str(e))
    
@app.get("/incidents")
def get_incidents():
    incidents=fetch_all_incidents()
    return incidents

@app.get("/incidents/{incident_id}")
def get_incident(incident_id:str):
    try:
        incident=fetch_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404,detail="Incident not found")
        return incident
    except Exception as e:
        raise HTTPException(status_code=404,detail=str(e))