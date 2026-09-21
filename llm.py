"""
Small wrapper around Hugging Face InferenceClient that asks for JSON-mode output and
retries once with a stricter instruction if parsing fails. This is
part of the "narrow the question" reliability fix — every call here
returns a small, fixed-shape JSON object, never open-ended prose.
"""


import json
import re
import os

from dotenv import load_dotenv
from huggingface_hub import InferenceClient


load_dotenv()

DEFAULT_MODEL = "openai/gpt-oss-120b:cheapest"


def get_model(model_name: str = DEFAULT_MODEL, temperature: float = 0.1):
    return InferenceClient(
        model=model_name,
        api_key=os.environ["HF_TOKEN"]
    )


def _extract_json(text: str) -> dict:
    text = text.strip()
    # Models sometimes wrap JSON in ```json fences even in JSON mode — strip if present.
    text = re.sub(r"^```json\s*|\s*```$", "", text, flags=re.MULTILINE)
    return json.loads(text)


def call_structured(model, prompt: str, retries: int = 1) -> dict:
    last_error = None

    for attempt in range(retries + 1):
        try:
            response = model.chat.completions.create(
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.1,
            )

            content = response.choices[0].message.content

            return _extract_json(content)

        except (json.JSONDecodeError, AttributeError) as e:
            last_error = e
            prompt = prompt + "\n\nReturn ONLY valid JSON, no other text, no markdown fences."

    # Both attempts failed — return a safe default rather than crashing the graph.
    return {"_parse_error": str(last_error)}