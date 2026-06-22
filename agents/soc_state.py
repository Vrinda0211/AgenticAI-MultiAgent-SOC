from typing import TypedDict,List,Optional,Dict
from datetime import datetime
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
    #Feedback loop
    retriage_count : int
    retriage_request : str
    #Response agent outputs
    actions : List[dict]
    escalate_to_human : bool
    severity_final : str
    response_reasoning : str
    #Metadata/ Bookkeeping fields
    incident_id : str
    timestamp_processed : datetime
    #Timestamps fields
    triage_time : float
    investigation_time : float
    response_time : float
    total_time : float
     


    