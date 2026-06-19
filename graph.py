from langgraph.graph import StateGraph, END
import sys
sys.path.append('.')
from agents.soc_state import SOCState
from agents.triage_agent import run_triage_agent
from agents.investigation_agent import run_investigation_agent
from agents.response_agent import run_response_agent

import uuid
from datetime import datetime
from database.db_setup import create_table,save_incidents

def save_to_database(state:dict)->dict:
    state["incident_id"]=str(uuid.uuid4())
    state["timestamp_processed"]=datetime.now().isoformat()
    create_table()
    save_incidents(state)
    return state

graph=StateGraph(SOCState)
graph.add_node("triage",run_triage_agent)
graph.add_node("investigation",run_investigation_agent)
graph.add_node("response",run_response_agent)
graph.add_node("database",save_to_database)

graph.set_entry_point("triage")
graph.add_edge("triage","investigation")
graph.add_edge("response","database")
graph.add_edge("database",END)

def route_after_investigation(state:dict)->str:
    if state.get("confidence_investigation", 100)<60 and state.get("retriage_count",0)<2:
        return "triage"
    else:
        return "response"
    
graph.add_conditional_edges("investigation",route_after_investigation)

pipeline=graph.compile()