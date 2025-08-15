from .classify import Finding
from ..config import settings

# Optional OpenAI client (graceful fallback)
try:
    from openai import OpenAI
    _client = OpenAI(api_key=settings.OPENAI_API_KEY) if settings.OPENAI_API_KEY else None
except Exception:
    _client = None

FIX_PROMPT = """You are a secure code assistant.
The following code is suspected of a {vuln} issue.
Explain the problem briefly, then propose a minimal secure fix.
Return both:
1) An explanation,
2) A patched code block.
Code:
```code
{snippet}
```"""

async def suggest_fix(finding: Finding, language: str) -> tuple[str, str]:
    prompt = FIX_PROMPT.format(vuln=finding.vulnerability_type, snippet=finding.snippet)
    # If no API key or client, return a helpful mock
    if not settings.ENABLE_FIXES or _client is None:
        explanation = f"[MOCK] {finding.vulnerability_type}: Replace unsafe calls and validate inputs."
        patched = f"[MOCK PATCH] // Review and patch snippet safely.\\n{finding.snippet}"
        return explanation, patched

    try:
        resp = _client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a senior application security engineer."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        txt = resp.choices[0].message.content.strip()
        # naive split
        if "```" in txt:
            parts = txt.split("```")
            explanation = parts[0].strip()
            patched = parts[1].replace("code", "").strip() if len(parts) > 1 else finding.snippet
        else:
            explanation, patched = txt, finding.snippet
        return explanation, patched
    except Exception:
        # fallback on any error
        explanation = f"[FALLBACK] {finding.vulnerability_type}: sanitize inputs, avoid dangerous functions."
        patched = f"[FALLBACK PATCH]\\n{finding.snippet}"
        return explanation, patched