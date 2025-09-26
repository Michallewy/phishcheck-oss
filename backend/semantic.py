import os, json
from typing import Dict, Any, List
from langchain_ollama import OllamaLLM

try:
    import httpx
except Exception:
    httpx = None

PROMPT = """Jesteś analitykiem SOC. Oceń treść e-maila pod kątem phishingu.
Uwzględnij:
- język pilności/autorytetu/konsekwencji,
- prośby o dane logowania/płatność/zmianę rachunku,
- linki (maskowanie, skracacze, domeny lookalike/IDN),
- nietypowości językowe,
- dane techniczne: SPF={spf}, DKIM={dkim}, DMARC={dmarc}, powody={reasons}

Zwróć czysty JSON o strukturze:
{{
  "semantic_indicators": [ ... ],
  "likelihood": "high|medium|low",
  "explanation": "zwięzły opis (max 3 zdania)",
  "recommended_actions": ["quarantine","report_to_soc","warn_user"]
}}
Treść (subject: "{subject}"):
---
{body}
---"""

def _ollama_model():
    model = os.getenv("OLLAMA_MODEL", "llama3.1")
    base_url = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
    return OllamaLLM(model=model, base_url=base_url)

def _openai_call(prompt: str) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key or not httpx:
        raise RuntimeError("Brak OPENAI_API_KEY lub httpx")
    url = "https://api.openai.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}"}
    data = {"model": os.getenv("OPENAI_MODEL","gpt-4o-mini"),
            "messages": [{"role":"user","content": prompt}],
            "temperature": 0.2}
    r = httpx.post(url, headers=headers, json=data, timeout=60)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]

def analyze_semantics(body: str, subject: str, tech: Dict[str,Any], reasons: List[str]) -> Dict[str,Any]:
    prompt = PROMPT.format(
        spf=tech.get("spf"), dkim=tech.get("dkim"), dmarc=tech.get("dmarc"),
        reasons=", ".join(reasons), body=body or "(brak treści)", subject=subject or "(brak)"
    )

    # 1) Spróbuj Ollama (lokalny LLM)
    try:
        llm = _ollama_model()
        out = llm.invoke(prompt)
        return out
    except Exception:
        pass

    # 2) Spróbuj OpenAI (jeśli skonfigurowano)
    try:
        out = _openai_call(prompt)
        return out
    except Exception:
        pass

    # 3) Fallback: heurystyki
    inds, actions, likelihood = [], ["warn_user"], "low"
    low_body = (body or "").lower()
    for kw in ["przelew","hasło","zaloguj","potwierdź","natychmiast","faktura","rachunek","autoryzacja"]:
        if kw in low_body: inds.append(f"keyword:{kw}")
    if inds: likelihood = "medium"; actions = ["quarantine","report_to_soc","warn_user"]
    return {
        "semantic_indicators": inds,
        "likelihood": likelihood,
        "explanation": "Heurystyki awaryjne bez LLM.",
        "recommended_actions": actions
    }
