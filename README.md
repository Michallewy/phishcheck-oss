# PhishCheck OSS

Open‑source agent do analizy phishingu z plików `.eml`:

1) **Nagłówki + heurystyki**  
2) **SPF/DKIM/DMARC** (`Authentication-Results` + DNS fallback)  
3) **Semantyka treści** (lokalny LLM przez Ollama / OpenAI / heurystyki)

## Szybki start (Docker Compose)

```bash
cd docker
docker compose up --build
```

- UI: http://localhost:8000/ui  
- API: `POST /api/analyze-eml-file` (multipart) lub `POST /api/analyze-eml` (JSON `{ eml_base64 }`).

## Lokalnie (bez Dockera)

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export OLLAMA_BASE_URL=http://localhost:11434
uvicorn backend.app:app --reload
```

## Zmienne środowiskowe
- `OLLAMA_BASE_URL` (domyślnie `http://ollama:11434`)
- `OLLAMA_MODEL` (domyślnie `llama3.1`)
- `OPENAI_API_KEY` / `OPENAI_MODEL` (opcjonalnie)
- `CORS_ALLOW` (lista dozwolonych originów)

## Bezpieczeństwo i prywatność
- Nie zapisujemy treści e-maili w logach.  
- Wymagany dostęp DNS do rekordów TXT (SPF/DMARC/DKIM).  
- Rozszerzenia: webhook do SIEM, detonacja URL, alignment DMARC, obsługa ARC.
