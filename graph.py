import time
from langgraph.graph import StateGraph, END
import sys
sys.path.append('.')
from agents.soc_state import SOCState
from agents.triage_agent import run_triage_agent
from agents.investigation_agent import run_investigation_agent
from agents.response_agent import run_response_agent
import uuid
from datetime import datetime
from database.db_setup import create_table, save_incidents

def timed_triage(state: dict)->dict:
    start=time.time()
    state=run_triage_agent(state)
    state["triage_time"]=round(time.time()-start,2)
    print(f"Triage Completed in: {state['triage_time']}s")
    return state

def timed_investigate(state: dict)->dict:
    start=time.time()
    state=run_investigation_agent(state)
    state['investigation_time']=round(time.time()-start,2)
    print(f"Investigation Completed in: {state['investigation_time']}s")
    return state

def timed_response(state: dict)->dict:
    start=time.time()
    state=run_response_agent(state)
    state["response_time"]=round(time.time()-start,2)
    print(f"Response done in: {state['response_time']}s")
    return state

def save_to_database(state: dict)->dict:
    state['incident_id']=str(uuid.uuid4())
    state['timestamp_processed']=datetime.now().isoformat()
    state['total_time']=round(state.get("triage_time",0)+state.get("investigation_time",0)+state.get("response_time",0),2)
    print(f'TOTAL TIME TAKEN : {state['total_time']}s')
    create_table()
    save_incidents(state)
    return state

graph=StateGraph(SOCState)
graph.add_node("triage",timed_triage)
graph.add_node("investigation",timed_investigate)
graph.add_node("response",timed_response)
graph.add_node("database",save_to_database)
graph.set_entry_point("triage")
graph.add_edge("triage", "investigation")
graph.add_edge("response", "database")
graph.add_edge("database", END)

def route_after_investigation(state: dict) -> str:
    if state.get("confidence_investigation", 100) < 60 and state.get("retriage_count", 0) < 2:
        return "triage"
    else:
        return "response"

graph.add_conditional_edges("investigation", route_after_investigation)

pipeline = graph.compile()

if __name__ == "__main__":
    test_state = {
       
        "raw_event": {"source_ip": "10.0.5.41", "log_source": "auth_logs"},
        "source_ip": "10.0.5.41",
        "log_source": "auth_logs",

        "suspicious": False,
        "severity": "",
        "confidence_triage": 0.0,
        "signals": [],
        "triage_reasoning": "",

        "attack_type": "",
        "primary_mitre_id": "",
        "secondary_mitre_id": "",
        "evidence": "",
        "confidence_investigation": 0.0,
        "investigation_reasoning": "",

        "retriage_count": 0,
        "retriage_request": "",

        "actions": [],
        "escalate_to_human": False,
        "severity_final": "",
        "response_reasoning": "",

        "triage_time": 0.0,
        "investigation_time": 0.0,
        "response_time": 0.0,
        "total_time": 0.0,

        "incident_id": "",
        "timestamp_processed": ""
    }

    print(" Starting SOC Pipeline...")
    try:
        result = pipeline.invoke(test_state)

        print("\n=== PIPELINE RESULTS ===")
        print(f"source_ip:              {result.get('source_ip')}")
        print(f"suspicious:             {result.get('suspicious')}")
        print(f"severity:               {result.get('severity')}")
        print(f"attack_type:            {result.get('attack_type')}")
        print(f"primary_mitre_id:       {result.get('primary_mitre_id')}")
        print(f"severity_final:         {result.get('severity_final')}")
        print(f"escalate_to_human:      {result.get('escalate_to_human')}")
        print(f"retriage_count:         {result.get('retriage_count')}")
        print(f"incident_id:            {result.get('incident_id')}")

        print("\n=== TIMING ===")
        print(f"triage_time:            {result.get('triage_time')}s")
        print(f"investigation_time:     {result.get('investigation_time')}s")
        print(f"response_time:          {result.get('response_time')}s")
        print(f"total_time:             {result.get('total_time')}s")

        print("\n=== DATABASE CHECK ===")
        from database.db_setup import fetch_incident
        record = fetch_incident(result.get("incident_id"))
        if record:
            print(f"Saved to DB successfully")
            print(f"   triage_time:        {record.get('triage_time')}s")
            print(f"   investigation_time: {record.get('investigation_time')}s")
            print(f"   response_time:      {record.get('response_time')}s")
            print(f"   total_time:         {record.get('total_time')}s")
        else:
            print("Record not found in DB")
    except Exception as e:
        error_msg=str(e)
        if "Daily quota exhausted" in error_msg:
            print(f'Pipeline STOPPED , DAILY API LIMIT reached')
            print(f'No further requests will be made')
            print(f'Resume after 5:30 AM IST tomorrow.')
        elif "Max retries exceeded"in error_msg:
            print(f'Pipelinr STOPPED , PER-MINUTE LIMIT, retries exhausted')
            print(f'Wait for a few moments and please try again')
        else:
            print(f'Pipeline Error : {error_msg}')






