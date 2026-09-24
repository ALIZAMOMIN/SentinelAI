"""
Verifies the graph's control flow mechanically, without a live model
or network access. Mocks call_structured to return scripted responses
simulating: (1) a case that triggers one follow-up loop, then stops,
and (2) confirms the MAX_FOLLOWUP_LOOPS guard prevents infinite looping
even if the mocked model keeps asking for more follow-ups.
"""
from unittest.mock import patch
import graph as graph_module

SAMPLE_TOOL_RECORD = {
    "tool_id": "quickreply-ai",
    "name": "QuickReply AI",
    "vendor": "Bright Loop Labs",
    "source_type": "extension",
    "stated_function": "Draft quick email replies",
    "permissions": {
        "requested": ["clipboardRead", "storage", "host:<all_urls>"],
        "drift_detected": True,
    },
    "network_behavior": {"observed_domains": ["brightlooplabs.io"]},
    "prechecks": {},
}

# Scripted responses, one per call_structured invocation, in order:
# plan -> reason (loop 1, asks for follow-up) -> reason (loop 2, done) -> score -> verdict
SCRIPTED_RESPONSES = [
    {"scope_exceeds_function": True, "domain_suspiciously_new": False, "worth_searching_vendor": True},
    {
        "ownership_change_found": True, "breach_or_incident_found": False,
        "trains_on_input_found": True, "needs_followup_search": True,
        "followup_query": "Bright Loop Labs new owner", "one_line_summary": "Found a recent ownership change.",
    },
    {
        "ownership_change_found": True, "breach_or_incident_found": False,
        "trains_on_input_found": True, "needs_followup_search": False,
        "followup_query": "", "one_line_summary": "New owner confirmed, no further action needed.",
    },
    {"scope_severity": 3.2, "permission_drift": 2.4, "vendor_trust_signals": 1.6, "data_sensitivity_nearby": 0.9},
    {"verdict_line": "Scope exceeds function and ownership recently changed.", "action": "revoke",
     "instructions": "Revoke access and review before re-enabling."},
]


def test_normal_flow_with_one_followup_loop():
    call_log = []

    def fake_call_structured(model, prompt):
        call_log.append(prompt[:40])
        return SCRIPTED_RESPONSES[len(call_log) - 1]

    def fake_web_search(query, max_results=4):
        return {"query": query, "results": [{"title": "t", "snippet": "s", "url": "u"}]}

    def fake_whois(domain):
        return {"domain": domain, "age_days": 1180}

    with patch.object(graph_module, "call_structured", side_effect=fake_call_structured), \
         patch.object(graph_module, "web_search", side_effect=fake_web_search), \
         patch.object(graph_module, "whois_domain_age", side_effect=fake_whois), \
         patch.object(graph_module, "get_model", return_value=None):

        app = graph_module.build_graph()
        result = app.invoke({"tool_record": SAMPLE_TOOL_RECORD})

    # --- Assertions: prove the graph actually did what it should ---
    stages = [t["stage"] for t in result["trace"]]
    assert stages == ["perceive", "plan", "act", "reason", "act", "reason", "reason"] or \
           stages.count("act") == 2, f"Expected exactly one follow-up loop (2 act stages), got: {stages}"

    assert len(result["search_queries_run"]) == 2, "Expected two searches: initial + one follow-up"
    assert result["search_queries_run"][1] == "Bright Loop Labs new owner", \
        "Follow-up query from reason node wasn't used in the second act call"

    assert result["risk_score"] == 8.1, f"Expected score 8.1, got {result['risk_score']}"
    assert result["risk_level"] == "high"
    assert result["recommendation"]["action"] == "revoke"

    print("PASS: normal flow with one follow-up loop")
    print(f"  Trace stages: {stages}")
    print(f"  Searches run: {result['search_queries_run']}")
    print(f"  Final score: {result['risk_score']} ({result['risk_level']})")
    print(f"  Recommendation: {result['recommendation']['action']}")


def test_loop_guard_stops_runaway_followups():
    """Even if the model NEVER stops asking for follow-ups, the graph
    must stop after MAX_FOLLOWUP_LOOPS — this is the hardcoded safety
    net, not left to the model's judgment."""

    def fake_call_structured_always_wants_more(model, prompt):
        if "Answer three yes/no" in prompt:
            return {"scope_exceeds_function": False, "domain_suspiciously_new": False, "worth_searching_vendor": True}
        if "reviewing search results" in prompt:
            return {
                "ownership_change_found": False, "breach_or_incident_found": False,
                "trains_on_input_found": False, "needs_followup_search": True,
                "followup_query": "keep searching forever", "one_line_summary": "Still not sure.",
            }
        if "contribution score" in prompt:
            return {"scope_severity": 1.0, "permission_drift": 0.0, "vendor_trust_signals": 1.0, "data_sensitivity_nearby": 0.5}
        return {"verdict_line": "Done.", "action": "monitor", "instructions": "Keep watching."}

    with patch.object(graph_module, "call_structured", side_effect=fake_call_structured_always_wants_more), \
         patch.object(graph_module, "web_search", return_value={"query": "q", "results": []}), \
         patch.object(graph_module, "whois_domain_age", return_value={"domain": "d", "age_days": 10}), \
         patch.object(graph_module, "get_model", return_value=None):

        app = graph_module.build_graph()
        result = app.invoke({"tool_record": SAMPLE_TOOL_RECORD})

    act_count = sum(1 for t in result["trace"] if t["stage"] == "act")
    assert act_count == graph_module.MAX_FOLLOWUP_LOOPS, \
        f"Expected exactly {graph_module.MAX_FOLLOWUP_LOOPS} act stages (loop guard), got {act_count}"

    print(f"PASS: loop guard stopped runaway follow-ups at {act_count} searches (limit={graph_module.MAX_FOLLOWUP_LOOPS})")


if __name__ == "__main__":
    test_normal_flow_with_one_followup_loop()
    print()
    test_loop_guard_stops_runaway_followups()
