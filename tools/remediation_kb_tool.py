from langchain_core.tools import tool
import json

@tool
def remediation_kb_tool(attack_type:str)->dict:
    """Given an attack type such as Brute Force, Port Scan, or Suspicious Login, returns the recommended immediate actions, investigation steps, preventive measures, and escalation conditions from the remediation knowledge base."""
    with open("data/remediation_kb.json","r") as f:
        data=json.load(f)
        if attack_type in data:
            return data[attack_type]
        else:
            return {"error": f"Attack type {attack_type} not found"}