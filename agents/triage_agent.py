import os
import sys
from langchain_groq import ChatGroq
from langgraph.prebuilt import create_react_agent
from dotenv import load_dotenv
sys.path.append('.')

from tools.geoip_tool import geoip_tool
from tools.incident_history_tool import incident_history_tool
from tools.ip_reputation_tool import ip_reputation_tool
from utils.rate_limit_handler import call_with_retry  

import warnings
warnings.filterwarnings("ignore")
import re
import json

load_dotenv()

llm = ChatGroq(model="llama-3.3-70b-versatile",api_key=os.getenv("GROQ_API_KEY"),temperature=0)
tools=[geoip_tool,incident_history_tool,ip_reputation_tool]
system_prompt = """You are a cybersecurity Triage Agent in a Security Operations Center (SOC).

Your job is to analyze incoming security events and determine whether they are suspicious enough to investigate.

For every event you receive, you must:
1. Extract the source IP address from the event
2. Call ip_reputation_tool to get the reputation score and signals for that IP
3. Call incident_history_tool to check if this IP has been seen before
4. Call geoip_tool to get the location of the IP
5. Based on the results, determine:
   - Whether the event is suspicious (True/False)
   - Severity level: Critical, High, Medium, or Low
   - Confidence score between 0 and 100
   - List of signals detected from: repeat_ip, suspicious_country, admin_target, off_hours, high_reputation_score, brute_force_pattern, port_scan_pattern
   - A clear reasoning explanation

Severity rules:
- Score 80-100: Critical
- Score 60-79: High
- Score 40-59: Medium
- Score below 40: Low

Always call all three tools before making a decision. Never guess without tool results.

Return your response as valid JSON only, with no extra text before or after:
{
    "suspicious": true,
    "severity": "Critical",
    "confidence": 95,
    "signals": ["repeat_ip", "suspicious_country"],
    "reasoning": "Your explanation here"
}
"""

triage_agent=create_react_agent(model=llm,tools=tools,prompt=system_prompt)
def run_triage_agent(state:dict)->dict:
    raw_event=state["raw_event"]
    message=f"Analyse this security event and determin if it is suspicious:{raw_event}"

    geo_result = geoip_tool.invoke({"ip_address": state["source_ip"]})
    state["country"] = geo_result.get("country", "Unknown")

    #result=triage_agent.invoke({"messages":[{"role":"user","content":message}]})
    result = call_with_retry(
        triage_agent,
        {"messages": [{"role": "user", "content": message}]}
    )

    final_message=result["messages"][-1].content
    if isinstance(final_message, list):
        final_message=final_message[0]["text"]
    state["triage_reasoning"]=final_message
    clean_message=final_message.strip()
    if clean_message.startswith("```"):
        clean_message=re.sub(r'```json|```','',clean_message).strip()
    try:
        parsed=json.loads(clean_message)
        state["suspicious"]=parsed.get("suspicious",True)
        state["severity"]=parsed.get("severity","High")
        state["confidence_triage"]=float(parsed.get("confidence",80))
        state["signals"]=parsed.get("signals",[])
        state["triage_reasoning"]=parsed.get("reasoning",final_message)
    except:
        state["suspicious"]=True
        state["severity"]="High"
        state["confidence_triage"]=80.0
        state["signals"]=[]
        state["triage_reasoning"]=final_message
    state["source_ip"]=state["raw_event"]["source_ip"]
    return state