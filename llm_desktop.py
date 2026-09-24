"""
Small wrapper around ChatOllama that asks for JSON-mode output and
retries once with a stricter instruction if parsing fails. This is
part of the "narrow the question" reliability fix — every call here
returns a small, fixed-shape JSON object, never open-ended prose.
"""


import json
import re
from langchain_ollama import ChatOllama

DEFAULT_MODEL = "qwen2.5:7b-instruct"


def get_model(model_name: str = DEFAULT_MODEL, temperature: float = 0.1):
    return ChatOllama(model=model_name, temperature=temperature, format="json")


def _extract_json(text: str) -> dict:
    text = text.strip()
    # Models sometimes wrap JSON in ```json fences even in JSON mode — strip if present.
    text = re.sub(r"^```json\s*|\s*```$", "", text, flags=re.MULTILINE)
    return json.loads(text)


def call_structured(model, prompt: str, retries: int = 1) -> dict:
    last_error = None
    for attempt in range(retries + 1):
        try:
            response = model.invoke(prompt)
            content = response.content if hasattr(response, "content") else str(response)
            return _extract_json(content)
        except (json.JSONDecodeError, AttributeError) as e:
            last_error = e
            prompt = prompt + "\n\nReturn ONLY valid JSON, no other text, no markdown fences."
    # Both attempts failed — return a safe default rather than crashing the graph.
    return {"_parse_error": str(last_error)}

'''
if __name__ == '__main__':
    model = get_model()
    check = call_structured(model ,'hi')
    print(check)
'''