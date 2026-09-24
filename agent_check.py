"""

    ollama pull qwen2.5:7b-instruct
    ollama serve      # if not already running

Usage:
    python run_demo.py
"""
import json
from graph import build_graph

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
    "network_behavior": {"observed_domains": ["brightlooplabs.io"]}, #
    "prechecks": {}, #
    
}


def main():
    app = build_graph()
    print(f"Investigating: {SAMPLE_TOOL_RECORD['name']}\n")

    result = app.invoke({"tool_record": SAMPLE_TOOL_RECORD})

    print("=== Investigation trace ===")
    for step in result["trace"]:
        print(f"[{step['stage'].upper()}] {step['text']}")

    print("\n=== Score breakdown ===")
    for factor in result["factors"]:
        print(f"  {factor['label']}: {factor['contribution']}")
    print(f"  TOTAL: {result['risk_score']} / 10  ({result['risk_level']})")

    print(f"\n=== Verdict ===\n{result['verdict_line']}")
    print(f"\n=== Recommendation: {result['recommendation']['action'].upper()} ===")
    print(result["recommendation"]["instructions"])

    print("\n=== Full state (JSON) ===")
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
