import os
from dotenv import load_dotenv
from langgraph.graph import StateGraph,END
from langgraph.prebuilt import ToolNode
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import SystemMessage,HumanMessage
from typing import Annotated
import operator

load_dotenv()

from tools.historical_pattern_tool import historical_pattern_tool
from tools.mitre_lookup_tool import mitre_lookup_tool

investigation_tools=[historical_pattern_tool,mitre_lookup_tool]

llm=ChatGoogleGenerativeAI(
    model="gemini-2.5-flash",
    temperature=0,
    google_api_key=os.getenv("GOOGLE_APU_KEY")
)
llm_with_tools=llm.bind_tools(investigation_tools)

INVESTIGATION_PROMPT="""YOU ARE A SOC INVESTIGATION AGENT ANALYSING
ESCALATED THREATS"""