import os
import sys
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.prebuilt import create_react_agent
from dotenv import load_dotenv
sys.path.append('.')
from tools.mitre_lookup_tool import mitre_lookup_tool
from tools.historical_pattern_tool import historical_pattern_tool
from tools.incident_history_tool import incident_history_tool
from utils.rate_limit_handler import call_with_retry  

import warnings
import re
import json
warnings.filterwarnings("ignore")

load_dotenv()

llm=ChatGoogleGenerativeAI(
    model="gemini-2.5-flash",
    google_api_key=os.getenv("GEMINI_API_KEY"),
    temperature=0
)
tools=[mitre_lookup_tool,historical_pattern_tool,incident_history_tool]

system_prompt="""You are a cybersecurity Investigation Agent in a 
Security Operations Centre(SOC).
You receive escalated alerts from the Triage Agent and perform deep investigation.

For every event you receive, you must:
1. Read the source IP and triage assessment provided in the message
2. Call historical_pattern_tool with the source IP to detect attack patterns (brute_force, port_scan, suspicious_login)
3. Call incident_history_tool with the source IP to gather full event history and evidence
4. Based on patterns found, map to MITRE ATT&CK techniques:
   - brute_force      → T1110
   - port_scan        → T1046
   - suspicious_login → T1078
5. Call mitre_lookup_tool for the PRIMARY technique ID identified
6. If a secondary pattern exists, call mitre_lookup_tool for that technique ID as well
7. Classify the attack type as one of: Brute Force, Port Scan, Suspicious Login, or Combined Attack
8. Build an evidence list strictly from actual tool results — no assumptions

Confidence scoring rules:
- Multiple patterns detected + successful login:     80-100 (High confidence)
- Single pattern with strong signals:                60-79  (Medium confidence)
- Weak or ambiguous signals:                         Below 60 (Low confidence)

If confidence is below 60, explicitly state:
"RETRIAGE NEEDED: <specific reason why evidence is insufficient>"

Always call all relevant tools before making a decision. Never guess without tool results.

Return your response as valid JSON only, with no extra text before or after:
{
    "attack_type": "Brute Force",
    "primary_mitre_id": "T1110",
    "secondary_mitre_id": "T1078",
    "evidence": "235 failed logins, 1 successful login, admin account targeted",
    "confidence_score": 95,
    "investigation_reasoning": "Your explanation here"
}

"""

investigation_agent = create_react_agent(model=llm, tools=tools, prompt=system_prompt)

def run_investigation_agent(state:dict)->dict:
    message=f"""
Investigate this security event:
Source IP: {state['source_ip']}
Triage Assessment: {state['triage_reasoning']}

Determine the attack type, gather evidence, and map to MITRE ATT&CK.
"""
    #result=investigation_agent.invoke({"messages":[{"role":"user","content":message}]})
    result = call_with_retry(
        investigation_agent,
        {"messages": [{"role": "user", "content": message}]}
    )
    final_message=result["messages"][-1].content
    if isinstance(final_message,list):
        final_message=final_message[0]["text"]
    clean_message=final_message.strip()
    if clean_message.startswith("```"):
        clean_message=re.sub(r'```json|```','',clean_message).strip()
    try:
        parsed=json.loads(clean_message)
        state["investigation_reasoning"]=parsed.get("investigation_reasoning",final_message)
        state["attack_type"]=parsed.get("attack_type","Unknown")
        state["primary_mitre_id"]=parsed.get("primary_mitre_id","")
        state["secondary_mitre_id"]=parsed.get("secondary_mitre_id","")
        state["evidence"]=parsed.get("evidence","")
        state["confidence_investigation"]=float(parsed.get("confidence_score",100))
    except:
        state["investigation_reasoning"]=final_message
        state["attack_type"]="Unknown"
        state["primary_mitre_id"]=""
        state["secondary_mitre_id"]=""
        state["evidence"]=""
        state["confidence_investigation"]=100.0
    if "RETRIAGE NEEDED" in state["investigation_reasoning"]:
        state["retriage_count"]=state.get("retriage_count",0)+1
        state["retriage_request"]=state["investigation_reasoning"]
        state["confidence_investigation"]=50.0
    else:
        state["retriage_request"]=""
    return state
    