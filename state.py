"""
State schema for the Sentinel investigation agent.

The input `tool_record` matches exactly the normalized JSON shape the
sensing layer (extension scanner + MCP scanner + OAuth scanner + DNS
check) produces — see the merged payload example we designed earlier.
"""
from typing import TypedDict, Annotated, Literal
import operator


class ToolRecord(TypedDict): 
    tool_id: str
    name: str
    vendor: str
    source_type: str
    stated_function: str
    permissions: dict
    network_behavior: dict
    prechecks: dict


class TraceStep(TypedDict):
    stage: Literal["perceive", "plan", "act", "reason"]
    text: str


class ScoreFactor(TypedDict):
    label: str
    contribution: float


class Recommendation(TypedDict):
    action: Literal["revoke", "restrict", "monitor", "approve"]
    instructions: str


class InvestigationState(TypedDict):
    tool_record: ToolRecord
    trace: Annotated[list[TraceStep], operator.add]
    search_queries_run: Annotated[list[str], operator.add]
    search_results: Annotated[list[dict], operator.add]

    # structured findings carried between nodes
    domain_age_days: int | None
    scope_exceeds_function: bool
    ownership_change_found: bool
    breach_or_incident_found: bool
    trains_on_input_found: bool

    follow_up_needed: bool
    follow_up_query: str
    loop_count: int

    factors: list[ScoreFactor]
    risk_score: float
    risk_level: Literal["low", "medium", "high"]
    verdict_line: str
    recommendation: Recommendation
