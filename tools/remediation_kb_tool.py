import json

def remediation_kb_tool(attack_type):
    with open("data/remediation_kb.json","r") as f:
        data=json.load(f)
        if attack_type in data:
            return data[attack_type]
        else:
            return {"error": f"Attack type {attack_type} not found"}