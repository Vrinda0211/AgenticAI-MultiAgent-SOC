import os
from dotenv import load_dotenv
import sys
sys.path.append('.')
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.prebuilt import create_react_agent

from tools.escalation_tool import escalation_tool
from tools.remediation_kb_tool import remediation_kb_tool

import re
import json

import warnings
warnings.filterwarnings('ignore')

load_dotenv()

llm=ChatGoogleGenerativeAI(model="gemini-2.5-flash",google_api_key=os.getenv("GEMINI_API_KEY"),temperature=0)
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
    evidence=state.get("evidence","")
    severity=state.get("severity","High")
    confidence_investigation=state.get("confidence_investigation",80.0)
    investigation_reasoning=state.get("investigation_reasoning","")
    message=f"""Investigate and respond to this confirmed security incident:
    Attack Type:{attack_type}
    Evidence:{evidence}
    Current Severity:{severity}
    Investigation Confidence:{confidence_investigation}
    Investigation Summary:{investigation_reasoning}
    Generate prioritized remediation actions, decide on escalation, and assign a final severity."""
    result=response_agent.invoke({"messages":[{"role":"user","content":message}]})
    final_message=result["messages"][-1].content
    if isinstance(final_message,list):
        final_message=final_message[0]["text"]
    state["response_reasoning"] = final_message
    
    try:
        cleaned=final_message.strip()
        if cleaned.startswith("```"):
            cleaned=re.sub(r'^```[a-z]*\n?','', cleaned)
            cleaned = re.sub(r'\n?```$', '', cleaned)
            cleaned = cleaned.strip()
        parsed=json.loads(cleaned)
        state['actions']=[{"action":a} for a in parsed.get("actions",[])]
        state["escalate_to_human"]=bool(parsed.get("escalate_to_human",False))
        state["severity_final"]=parsed.get("severity_final",severity)
        state["response_reasoning"]=parsed.get("response_reasoning",final_message)

    except json.JSONDecodeError as e:
        print(f"JSON parse failed : {e}")
        print("FAILING back to raw text storage")
        print["actions"]=[]
        state["escalate_to_human"]=False
        state["severity_final"]=severity
        state["response_reasoning"]=final_message




    print("---RAW output---")
    print(final_message)

    return state

    
if __name__ == "__main__":
    test_state = {
        "attack_type": "Combined Attack",
        "evidence": """- 235 failed login attempts targeting admin account
- Successful admin login at 2024-01-16 03:16:29 (off-hours)
- 829 unique ports scanned in 41.4 seconds
- Source IP from Russia""",
        "severity": "High",
        "confidence_investigation": 95.0,
        "investigation_reasoning": "Multi-stage attack: port scan → brute force → successful admin login off-hours. High confidence combined attack from Russia.",
        "signals": ["brute_force", "suspicious_country", "admin_target", "off_hours"]
    }

    result = run_response_agent(test_state)

    
    print("===========================")

    print("=== PARSED OUTPUT ===")
    print("escalate_to_human:", result["escalate_to_human"])
    print("severity_final:", result["severity_final"])
    print("actions:", result["actions"])
    print("response_reasoning:", result["response_reasoning"][:300])