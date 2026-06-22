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
    if len(state.get("triage_reasoning", "")) > 500:
        state["triage_reasoning"] = state["triage_reasoning"][:500] + "...[truncated]"

    start=time.time()
    state=run_investigation_agent(state)
    state['investigation_time']=round(time.time()-start,2)
    print(f"Investigation Completed in: {state['investigation_time']}s")
    return state

def timed_response(state: dict)->dict:
    if len(state.get("investigation_reasoning", "")) > 1000:
        state["investigation_reasoning"] = state["investigation_reasoning"][:1000] + "...[truncated]"
    if len(state.get("evidence", "")) > 500:
        state["evidence"] = state["evidence"][:500] + "...[truncated]"

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