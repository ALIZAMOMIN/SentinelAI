r"""
The Sentinel investigation agent, built as a LangGraph StateGraph.

Flow:
    perceive -> plan -> act -> reason --(needs follow-up?)--> act (loop, max 2x)
                                       \--(done)--> score -> verdict -> END

Every LLM call asks a narrow, structured question (see prompts.py) —
the model never has to invent an open-ended plan, it fills in small
JSON answers that the graph's own edges use to decide what happens
next. This is the "narrow the question" + "hardcode common triggers
in the graph structure" reliability fix, so a smaller local model can
drive this loop reasonably consistently.
"""
from langgraph.graph import StateGraph, END, START

from state import InvestigationState
from tools import whois_domain_age, web_search, extract_domain
from llm import get_model, call_structured
import prompts as prompts

MAX_FOLLOWUP_LOOPS = 2


def perceive_node(state: InvestigationState) -> dict:
    tool = state["tool_record"]
    domains = tool.get("network_behavior", {}).get("observed_domains", [])
    domain = domains[0] if domains else extract_domain(tool["vendor"])

    age_info = whois_domain_age(domain) if domain else {"age_days": None}
    age_days = age_info.get("age_days")

    scope = tool.get("permissions", {}).get("requested", [])
    drift = tool.get("permissions", {}).get("drift_detected", False)

    age_text = f"{age_days} days old" if age_days is not None else "domain age unknown"
    trace_text = (
        f"Permissions snapshot: {', '.join(scope) if scope else 'none listed'}. "
        f"Vendor domain {domain or 'unresolved'} is {age_text}."
        + (" Permission drift detected since install." if drift else "")
    )

    return {
        "trace": [{"stage": "perceive", "text": trace_text}],
        "domain_age_days": age_days,
    }


def plan_node(state: InvestigationState) -> dict:
    tool = state["tool_record"]
    model = get_model()
    prompt = prompts.PLAN_PROMPT.format(
        name=tool["name"],
        vendor=tool["vendor"],
        stated_function=tool["stated_function"],
        permissions=tool.get("permissions", {}).get("requested", []),
        domain_age=state.get("domain_age_days"),
    )
    result = call_structured(model, prompt)

    scope_exceeds = result.get("scope_exceeds_function", False)
    worth_searching = result.get("worth_searching_vendor", True)

    trace_text = (
        f"Scope {'exceeds' if scope_exceeds else 'appears proportionate to'} the stated function. "
        f"{'Checking vendor standing next.' if worth_searching else 'No further vendor check planned.'}"
    )

    initial_query = f"{tool['vendor']} privacy policy data breach"
    return {
        "trace": [{"stage": "plan", "text": trace_text}],
        "scope_exceeds_function": scope_exceeds,
        "follow_up_needed": worth_searching,
        "follow_up_query": initial_query if worth_searching else "",
        "loop_count": 0,
    }


def act_node(state: InvestigationState) -> dict:
    query = state.get("follow_up_query") or f"{state['tool_record']['vendor']} company information"
    results = web_search(query)

    snippet_count = len(results.get("results", []))
    trace_text = f'Searched "{query}" — found {snippet_count} result(s).'

    return {
        "trace": [{"stage": "act", "text": trace_text}],
        "search_queries_run": [query],
        "search_results": [results],
        "loop_count": state.get("loop_count", 0) + 1,
    }


def reason_node(state: InvestigationState) -> dict:
    model = get_model()
    latest_results = state["search_results"][-1] if state["search_results"] else {"results": []}
    results_text = "\n".join(
        f"- {r['title']}: {r['snippet']}" for r in latest_results.get("results", [])
    ) or "No results found."

    prompt = prompts.REASON_PROMPT.format(
        vendor=state["tool_record"]["vendor"],
        search_results=results_text,
    )
    result = call_structured(model, prompt)

    ownership_change = result.get("ownership_change_found", False)
    breach_found = result.get("breach_or_incident_found", False)
    trains_on_input = result.get("trains_on_input_found", False)
    needs_followup = result.get("needs_followup_search", False)
    followup_query = result.get("followup_query", "")
    summary = result.get("one_line_summary", "No clear summary produced.")

    # Hardcoded graph-level guard: never loop more than MAX_FOLLOWUP_LOOPS times,
    # regardless of what the model wants — this is the "graph structure carries
    # some of the thinking" reliability fix, not left entirely to model judgment.
    can_loop_again = state.get("loop_count", 0) < MAX_FOLLOWUP_LOOPS
    will_follow_up = needs_followup and bool(followup_query) and can_loop_again

    trace_text = summary
    if will_follow_up:
        trace_text += f" Following up on: \"{followup_query}\"."

    return {
        "trace": [{"stage": "reason", "text": trace_text}],
        "ownership_change_found": ownership_change or state.get("ownership_change_found", False),
        "breach_or_incident_found": breach_found or state.get("breach_or_incident_found", False),
        "trains_on_input_found": trains_on_input or state.get("trains_on_input_found", False),
        "follow_up_needed": will_follow_up,
        "follow_up_query": followup_query if will_follow_up else "",
    }


def route_after_reason(state: InvestigationState) -> str:
    return "act" if state.get("follow_up_needed") else "score"


def score_node(state: InvestigationState) -> dict:
    model = get_model()
    tool = state["tool_record"]
    prompt = prompts.SCORE_PROMPT.format(
        scope_exceeds=state.get("scope_exceeds_function", False),
        drift=tool.get("permissions", {}).get("drift_detected", False),
        domain_age=state.get("domain_age_days"),
        ownership_change=state.get("ownership_change_found", False),
        breach_found=state.get("breach_or_incident_found", False),
        trains_on_input=state.get("trains_on_input_found", False),
    )
    result = call_structured(model, prompt)

    factors = [
        {"label": "Scope severity", "contribution": float(result.get("scope_severity", 0))},
        {"label": "Permission drift", "contribution": float(result.get("permission_drift", 0))},
        {"label": "Vendor trust signals", "contribution": float(result.get("vendor_trust_signals", 0))},
        {"label": "Data sensitivity nearby", "contribution": float(result.get("data_sensitivity_nearby", 0))},
    ]
    total = round(sum(f["contribution"] for f in factors), 1)
    total = min(total, 10.0)
    level = "high" if total >= 7 else "medium" if total >= 4 else "low"

    return {"factors": factors, "risk_score": total, "risk_level": level}


def verdict_node(state: InvestigationState) -> dict:
    model = get_model()
    prompt = prompts.VERDICT_PROMPT.format(
        score=state["risk_score"],
        name=state["tool_record"]["name"],
    )
    result = call_structured(model, prompt)

    return {
        "verdict_line": result.get("verdict_line", "Investigation complete."),
        "recommendation": {
            "action": result.get("action", "monitor"),
            "instructions": result.get("instructions", "Review manually."),
        },
    }


def build_graph():
    graph = StateGraph(InvestigationState)

    graph.add_node("perceive", perceive_node)
    graph.add_node("plan", plan_node)
    graph.add_node("act", act_node)
    graph.add_node("reason", reason_node)
    graph.add_node("score", score_node)
    graph.add_node("verdict", verdict_node)

    graph.add_edge(START, "perceive")
    graph.add_edge("perceive", "plan")
    graph.add_edge("plan", "act")
    graph.add_edge("act", "reason")
    graph.add_conditional_edges("reason", route_after_reason, {"act": "act", "score": "score"})
    graph.add_edge("score", "verdict")
    graph.add_edge("verdict", END)

    return graph.compile()
