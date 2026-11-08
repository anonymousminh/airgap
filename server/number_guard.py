"""Deterministic check: every number in the answer must appear in the sandbox's real stdout."""
import re

NUM = re.compile(r"(?<![\w.])[-+]?\$?\d[\d,]*(?:\.\d+)?%?[kKmMbB]?(?![\w])")
MULT = {"k": 1e3, "m": 1e6, "b": 1e9}


def _parse(tok: str):
    t = tok.replace("$", "").replace(",", "").replace("%", "")
    mult = 1.0
    if t and t[-1] in "kKmMbB":
        mult = MULT[t[-1].lower()]; t = t[:-1]
    try:
        v = float(t)
    except ValueError:
        return None, 0
    dec = len(t.split(".")[1]) if "." in t else 0
    return v * mult, dec


def _strip_noise(text: str) -> str:
    text = re.sub(r"(?m)^\s*(?:[-*]|\d+[.)])\s+", "", text)   # list markers
    return re.sub(r"\bQ\d\b", "Q", text)                      # Q3 etc.


def check(answer: str, stdout: str) -> dict:
    src = [v for v, _ in (_parse(m.group()) for m in NUM.finditer(stdout)) if v is not None]
    # also allow derived percentages shown in stdout without % sign handled by raw match
    items = []
    for m in NUM.finditer(_strip_noise(answer)):
        v, dec = _parse(m.group())
        if v is None:
            continue
        ok = False
        for s in src:
            for cand in (s, s * 100, s / 1e3, s / 1e6):
                if round(abs(cand), dec) == round(abs(v), dec) or abs(abs(cand) - abs(v)) <= 0.5 * 10 ** (-dec) * max(1, abs(v)) * 0.002:
                    ok = True; break
            if ok: break
        items.append({"value": m.group(), "matched": ok})
    matched = sum(1 for i in items if i["matched"])
    return {"numbers": items, "numbers_in_answer": len(items), "matched_in_stdout": matched,
            "unmatched": [i["value"] for i in items if not i["matched"]]}
