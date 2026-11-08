import sys; sys.path.insert(0, ".")
from server.llm import extract_code
C = "import pandas as pd\nprint(1)"
cases = {
 "plain fence":        f"```python\n{C}\n```",
 "leading blanks":     f"\n\n```python\n{C}\n```",
 "doubled fence":      f"\n\n```python\n```python\n{C}\n```",
 "prose around":       f"Here you go:\n```python\n{C}\n```\nHope that helps!",
 "no fence":           C,
 "bare ``` fence":     f"```\n{C}\n```",
 "unclosed fence":     f"```python\n{C}",
}
bad = [k for k, v in cases.items() if extract_code(v) != C]
for k in cases: print(("FAIL " if k in bad else "ok   ") + k)
sys.exit(1 if bad else 0)
