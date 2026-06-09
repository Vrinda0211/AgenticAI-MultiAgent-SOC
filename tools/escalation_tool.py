def escalation_tool(attack_type,severity,confidence,admin_targeted,successful_login,score):
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

result = escalation_tool(
    attack_type="suspicious_login",
    severity="High",
    confidence=45,
    admin_targeted=True,
    successful_login=True,
    score=90
)

print(result)