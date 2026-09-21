"""
Prompts for each graph node.

Per our earlier discussion: smaller local models are much more
reliable at narrow, structured questions than open-ended "decide
what to do" reasoning. Every prompt here asks for a specific,
bounded answer (often JSON) rather than free-form judgment.
"""

PLAN_PROMPT = """You are auditing an AI tool's data access for a security review.

Tool: {name}
Vendor: {vendor}
Stated function: {stated_function}
Requested permissions: {permissions}
Domain age (days): {domain_age}

Answer three yes/no questions as JSON, nothing else:
{{
  "scope_exceeds_function": true/false,
  "domain_suspiciously_new": true/false,
  "worth_searching_vendor": true/false
}}

A domain under 180 days old counts as suspiciously new.
Scope exceeds function if the permissions are broader than the
stated function plausibly requires (e.g. full page read/write for
a tool that only needs to read one field).
"""

REASON_PROMPT = """You are reviewing search results about a vendor for a security audit.

Vendor: {vendor}
Search results:
{search_results}

Answer as JSON, nothing else:
{{
  "ownership_change_found": true/false,
  "breach_or_incident_found": true/false,
  "trains_on_input_found": true/false,
  "needs_followup_search": true/false,
  "followup_query": "<a specific search query, or empty string if none needed>",
  "one_line_summary": "<one plain sentence summarizing what was found>"
}}
"""

SCORE_PROMPT = """Given these signals about an AI tool, assign a contribution
score from 0.0 to 4.0 for each factor below. Higher = more risk.

Signals:
- Scope exceeds stated function: {scope_exceeds}
- Permission drift since install: {drift}
- Domain age (days): {domain_age}
- Ownership change found: {ownership_change}
- Breach or incident found: {breach_found}
- Trains on input by default: {trains_on_input}

Answer as JSON, nothing else:
{{
  "scope_severity": <0.0-4.0>,
  "permission_drift": <0.0-4.0>,
  "vendor_trust_signals": <0.0-4.0>,
  "data_sensitivity_nearby": <0.0-2.0>
}}
"""

VERDICT_PROMPT = """Given a risk score of {score}/10 for "{name}", write ONE plain
sentence (under 25 words) summarizing the verdict, and pick exactly
one recommended action.

Answer as JSON, nothing else:
{{
  "verdict_line": "<one sentence>",
  "action": "revoke" | "restrict" | "monitor" | "approve",
  "instructions": "<2-3 sentences of concrete next steps for the user>"
}}
"""
