from langchain_core.tools import tool
import json

@tool
def mitre_lookup_tool(technique_id->str)->dict:
    with open("data/mitre/mitre_techniques.json","r") as f:
        data=json.load(f)
        for technique in data["techniques"]:
            if technique["id"]==technique_id:
                return technique
        return {"error": f"Technique {technique_id} not found"}