import os, base64, json
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from .models import AnalyzeEmlRequest, AnalyzeResponse, TechnicalResult, SemanticResult
from .analyzer import analyze_eml_base64
from .semantic import analyze_semantics
import gradio as gr
import requests

app = FastAPI(title="PhishCheck OSS", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ALLOW","*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/analyze-eml", response_model=AnalyzeResponse)
async def analyze_eml(req: AnalyzeEmlRequest):
    result = analyze_eml_base64(req.eml_base64)
    tech = result["technical"]
    sem_raw = analyze_semantics(result.get("body_text"), result.get("subject"), tech, result["reasons"])
    try:
        sem = json.loads(sem_raw) if isinstance(sem_raw, str) else sem_raw
    except Exception:
        sem = {"semantic_indicators": [], "likelihood":"low", "explanation":"LLM output parse error", "recommended_actions":["warn_user"]}

    likelihood_map = {"high": 30, "medium": 15, "low": 0}
    score = min(100, result["score"] + likelihood_map.get(sem.get("likelihood","low"),0))
    verdict = "malicious" if score >= 70 else "suspicious" if score >= 40 else "likely_ok"

    response = AnalyzeResponse(
        overall_verdict=verdict,
        overall_score=score,
        technical=TechnicalResult(**tech),
        semantic=SemanticResult(**sem) if isinstance(sem, dict) else None,
        evidence=result["evidence"],
        recommended_actions=list({*sem.get("recommended_actions",[]), *( ["report_to_soc","quarantine"] if verdict!="likely_ok" else ["no_action"] )}),
        explain="; ".join(result["reasons"])[:500]
    )
    return response

@app.post("/api/analyze-eml-file", response_model=AnalyzeResponse)
async def analyze_eml_file(file: UploadFile = File(...)):
    content = await file.read()
    b64 = base64.b64encode(content).decode()
    return await analyze_eml(AnalyzeEmlRequest(eml_base64=b64))

# =========== Gradio UI ===========
def _ui_infer(file_obj):
    content = file_obj.read()
    b64 = base64.b64encode(content).decode()
    url = os.getenv("BACKEND_URL","http://localhost:8000") + "/api/analyze-eml"
    r = requests.post(url, json={"eml_base64": b64}, timeout=120)
    r.raise_for_status()
    data = r.json()
    md = f"### Verdict: **{data['overall_verdict']}** (score: {data['overall_score']})
"
    md += f"**Tech:** SPF={data['technical']['spf']}, DKIM={data['technical']['dkim']}, DMARC={data['technical']['dmarc']}

"
    if data.get("semantic"):
        md += f"**Semantics:** {data['semantic']['likelihood']} — {data['semantic']['explanation']}

"
    md += f"**Reasons:** {data['explain']}

"
    md += f"**Recommended:** {', '.join(data['recommended_actions'])}
"
    return md, json.dumps(data, indent=2, ensure_ascii=False)

with gr.Blocks(title="PhishCheck OSS") as demo:
    gr.Markdown("# PhishCheck OSS — analiza phishingu (.eml)")
    with gr.Row():
        file = gr.File(label="Przeciągnij plik .eml", file_types=[".eml"])
    btn = gr.Button("Analizuj")
    out_md = gr.Markdown()
    out_json = gr.Code(language="json", label="Surowy wynik (JSON)")
    btn.click(_ui_infer, inputs=[file], outputs=[out_md, out_json])

@app.get("/")
def root():
    return {"status":"ok","app":"PhishCheck OSS"}

# Montujemy Gradio pod /ui
app = gr.mount_gradio_app(app, demo, path="/ui")
