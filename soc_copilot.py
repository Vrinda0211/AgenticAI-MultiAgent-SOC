import os
from dotenv import load_dotenv
from langchain_groq import ChatGroq
import sys
sys.path.append('.')
from database.db_setup import fetch_all_incidents,fetch_incident
import re

load_dotenv()
llm=ChatGroq(model="llama-3.3-70b-versatile",api_key=os.getenv("GROQ_API_KEY"))

def get_incident_context(question:str)->str:
    id_match=re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',question,re.IGNORECASE)
    incident_id=id_match.group(0) if id_match else None
    if incident_id:
        incident=fetch_incident(incident_id)
        return str(incident)
    else:
        incidents=fetch_all_incidents()
        return str(incidents)

def answer_question(question:str)->str:
    context=get_incident_context(question)
    prompt=f"""You are an AI SOC Copilot assistant helping a security analyst investigate cybersecurity incidents.

    You have access to the following incident data from the SOC database:
    {context}

    Answer the analyst's question clearly and concisely based on the incident data above.
    If the data doesn't contain enough information to answer, say so honestly.

    Analyst question: {question}"""
    response=llm.invoke(prompt)
    return response.content

if __name__ == "__main__":
    print(answer_question("What are the critical incidents?"))
    print(answer_question("What should I do about the brute force attacks?"))