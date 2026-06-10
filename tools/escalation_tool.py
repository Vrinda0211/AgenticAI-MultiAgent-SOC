from langchain_core.tools import tool

@tool
def escalation_tool(attack_type: str,severity: str,confidence: int,admin_targeted: bool,successful_login: bool,score: int) -> dict:
    
    """Given the attack type, severity, confidence score, admin targeting status, successful login status, 
    and reputation score, decides whether the incident should be escalated to a human analyst and returns 
    the reasons for escalation."""
    reasons=[]
    if severity=='Critical' :
        reasons.append("Severity of threat is Critical")

    if admin_targeted==True and successful_login==True :
        reasons.append("Admin login successful")

    if score>80 :
        reasons.append("High reputation score")
    
    if confidence<50 :
        reasons.append("Low Confidence detected")


    if attack_type=='suspicious_login' and admin_targeted==True :
        reasons.append("Suspicious login targeting admin account detected")
        
    if len(reasons) > 0:
        escalate = True
    else:
        escalate = False


    return{
        "escalate":escalate,
        "reasons":reasons
    }

