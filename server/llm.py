import re
from openai import OpenAI
from . import settings

_client = OpenAI(base_url=settings.BASE_URL, api_key=settings.API_KEY or "missing", timeout=90, max_retries=1)
FENCE = re.compile(r"```(?:python|py)?\s*\n(.*?)```", re.S)


def chat(model: str, system: str, user: str, max_tokens: int = 6000) -> tuple[str, int, int]:
    r = _client.chat.completions.create(
        model=model, temperature=0, max_tokens=max_tokens,
        messages=[{"role": "system", "content": system}, {"role": "user", "content": user}])
    u = r.usage
    return (r.choices[0].message.content or ""), int(u.prompt_tokens), int(u.completion_tokens)


def extract_code(text: str) -> str:
    m = FENCE.search(text)
    return (m.group(1) if m else text).strip()
