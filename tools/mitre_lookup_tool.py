import json
def mitre_lookup_tool(technique_id):
    with open("data/mitre/mitre_techniques.json","r") as f:
        data=json.load(f)
        for technique in data["techniques"]:
            if technique["id"]==technique_id:
                return technique
        return {"error": f"Technique {technique_id} not found"}