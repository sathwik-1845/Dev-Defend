"""
Lightweight classifier stubs:
- "CodeBERT": simulated classifier scoring text for risky tokens.
- "Semgrep": rule-like regex checks for common issues.

Replace with real integrations when ready.
"""
import re
from dataclasses import dataclass

@dataclass
class Finding:
    vulnerability_type: str
    severity: int
    start: int
    end: int
    snippet: str
    source: str  # "codebert" | "semgrep"

RISKY_PATTERNS = [
    (r"exec\\(", "Command Injection", 3),
    (r"eval\\(", "Code Injection", 4),
    (r"\\.format\\(.+\\)\\s*%\\s*", "String Format Injection", 2),
    (r"SELECT\\s+.*\\s+FROM\\s+.*\\+\\s*", "SQL Injection", 4),
    (r"password\\s*=\\s*['\\"]?[^'\\"]+['\\"]?", "Hardcoded Credential", 3),
    (r"subprocess\\.(Popen|call)\\(.*shell\\s*=\\s*True", "Shell Injection", 4),
    (r"pickle\\.loads\\(", "Insecure Deserialization", 3),
    (r"requests\\.(get|post)\\(.*verify\\s*=\\s*False", "TLS Verification Disabled", 2),
    (r"open\\(.+['\\"](w|a)['\\"]\\)", "Insecure File Write", 2),
]

def codebert_like_score(code: str) -> list[Finding]:
    findings: list[Finding] = []
    # naive heuristic: look for suspicious tokens
    tokens = ["eval(", "exec(", "shell=True", "pickle.loads(", "verify=False"]
    for token in tokens:
        for m in re.finditer(re.escape(token), code, flags=re.IGNORECASE):
            vt = "Heuristic Risk"
            sev = 2 if token in ["verify=False"] else 3
            findings.append(Finding(vt, sev, m.start(), m.end(), code[m.start():m.end()+80][:300], "codebert"))
    return findings

def semgrep_like_rules(code: str, language: str) -> list[Finding]:
    findings: list[Finding] = []
    for pat, vt, sev in RISKY_PATTERNS:
        for m in re.finditer(pat, code, flags=re.IGNORECASE | re.DOTALL):
            snippet = code[max(0, m.start()-60): m.end()+60]
            findings.append(Finding(vt, sev, m.start(), m.end(), snippet, "semgrep"))
    return findings

async def classify_code(code: str, language: str) -> list[Finding]:
    # combine + de-duplicate overlapping matches by (vt, span)
    raw = codebert_like_score(code) + semgrep_like_rules(code, language)
    uniq = {}
    for f in raw:
        key = (f.vulnerability_type, f.start, f.end)
        if key not in uniq or uniq[key].severity < f.severity:
            uniq[key] = f
    return list(uniq.values())