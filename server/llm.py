import logging, re
from openai import OpenAI
from . import settings

_client = OpenAI(base_url=settings.BASE_URL, api_key=settings.API_KEY or "missing", timeout=90, max_retries=1)
log = logging.getLogger('airgap.llm')


def chat(model: str, system: str, user: str, max_tokens: int = 6000) -> tuple[str, int, int]:
    """Reasoning models can spend the whole budget thinking and return empty content; retry once with more room."""
    tin = tout = 0
    text = ""
    for budget in (max_tokens, max_tokens * 2):
        r = _client.chat.completions.create(
            model=model, temperature=0, max_tokens=budget,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}])
        tin += int(r.usage.prompt_tokens); tout += int(r.usage.completion_tokens)
        text = r.choices[0].message.content or ""
        if text.strip():
            break
        log.warning("empty completion model=%s finish_reason=%s completion_tokens=%s budget=%s",
                    model, r.choices[0].finish_reason, r.usage.completion_tokens, budget)
    return text, tin, tout


_FENCE_LINE = re.compile(r"^```[A-Za-z0-9_+-]*$")


def extract_code(text: str) -> str:
    """Pull the Python out of a model reply. Tolerates prose around the block and doubled/stray fences
    (some models emit ```python twice, which a naive regex reads as an empty block)."""
    lines = text.strip().splitlines()
    fences = [i for i, l in enumerate(lines) if _FENCE_LINE.match(l.strip())]
    if fences:
        body = lines[fences[0] + 1: fences[-1]] if len(fences) > 1 else lines[fences[0] + 1:]
        lines = [l for l in body if not _FENCE_LINE.match(l.strip())]
    return "\n".join(lines).strip()
