from typing import TypedDict,List,Optional,Dict
class SOCState(TypedDict):
    #Raw event info
    raw_event : Dict
    source_ip : str
    log_source : str
    #Triage agent outputs
    suspicious : bool
    severity : str
    confidence_triage : float
    signals : str
    triage_reasoning : str
    #Investigation agent outputs
    attack_type : str
    primary_mitre_id : str
    secondary_mitre_id : str
    evidence : str
    confidence_investigation : float
    investigation_reasoning : str