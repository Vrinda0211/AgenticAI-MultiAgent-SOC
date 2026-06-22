import os
from dotenv import load_dotenv
import sys
sys.path.append('.')
from langchain_groq import ChatGroq
from langgraph.prebuilt import create_react_agent

from tools.escalation_tool import escalation_tool
from tools.remediation_kb_tool import remediation_kb_tool
from utils.rate_limit_handler import call_with_retry  

import warnings
warnings.filterwarnings('ignore')
import re
import json

load_dotenv()

llm=ChatGroq(model="llama-3.1-8b-instant",api_key=os.getenv("GROQ_API_KEY"),temperature=0)
tools=[escalation_tool,remediation_kb_tool]
system_prompt="""You are a cybersecurity Response Agent in a Security Operations Center (SOC).

Your job is to generate context-aware remediation recommendations based on confirmed attack investigations.

For every investigation result you receive, you must:
1. Read the attack type, evidence, severity, and signals from the input
2. Call remediation_kb_tool with the attack type to get recommended actions
3. Call escalation_tool with the following parameters extracted from the input:
   - attack_type: the confirmed attack type
   - severity: the current severity level
   - confidence: the investigation confidence score
   - admin_targeted: True if admin account was targeted
   - successful_login: True if a successful login was detected
   - score: the IP reputation score
4. Based on the results, generate:
   - A prioritized list of actions tied to actual evidence
   - A final severity level
   - An escalation decision with reasons
   - A clear reasoning explanation

Action prioritization rules:
- Priority 1: Actions directly tied to confirmed evidence
- Priority 2: Containment actions like blocking the IP
- Priority 3: Preventive measures

Final severity rules:
- Upgrade to Critical if admin account was compromised
- Upgrade to Critical if escalation tool returns True
- Otherwise keep the severity from the investigation

Never return generic playbook responses. Every action must reference specific evidence from the investigation.

You MUST return your final response as a valid JSON object with NO markdown, NO extra text, NOTHING outside the JSON.
The JSON must follow this exact structure:
{
    "actions": ["action 1", "action 2", "action 3"],
    "escalate_to_human": true,
    "severity_final": "Critical",
    "response_reasoning": "your reasoning here"
}
"""

response_agent=create_react_agent(model=llm,tools=tools,prompt=system_prompt)
def run_response_agent(state:dict)->dict:
   
    attack_type=state.get("attack_type","Unknown")
    severity=state.get("severity","High")
    confidence_investigation=state.get("confidence_investigation",80.0)
    evidence=state.get("evidence","")[:400]
    investigation_reasoning=state.get("investigation_reasoning","")[:400]
    message=f"""Investigate and respond to this confirmed security incident:
    Attack Type:{attack_type}
    Evidence:{evidence}
    Current Severity:{severity}
    Investigation Confidence:{confidence_investigation}
    Investigation Summary:{investigation_reasoning}
    Generate prioritized remediation actions, decide on escalation, and assign a final severity."""
    #result=response_agent.invoke({"messages":[{"role":"user","content":message}]})
    result = call_with_retry(
        response_agent,
        {"messages": [{"role": "user", "content": message}]}
    )
    final_message=result["messages"][-1].content
    if isinstance(final_message,list):
        final_message=final_message[0]["text"]
    try:
       cleaned = final_message.strip()
       if cleaned.startswith("```"):
         cleaned = re.sub(r'```json|```', '', cleaned).strip()
       parsed = json.loads(cleaned)
       state["actions"] = [{"action": a} for a in parsed.get("actions", [])]
       state["escalate_to_human"] = bool(parsed.get("escalate_to_human", False))
       state["severity_final"] = parsed.get("severity_final", severity)
       state["response_reasoning"] = parsed.get("response_reasoning", final_message)
    except:
       print("JSON parse failed — using defaults")
       state["actions"] = []
       state["escalate_to_human"] = False
       state["severity_final"] = severity
       state["response_reasoning"] = final_message
    return state