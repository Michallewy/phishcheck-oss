from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class AnalyzeEmlRequest(BaseModel):
    eml_base64: str = Field(..., description="Base64 zakodowany plik .eml")

class TechnicalResult(BaseModel):
    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None
    header_anomalies: List[str] = []
    dns: Dict[str, Any] = {}

class SemanticResult(BaseModel):
    likelihood: str
    semantic_indicators: List[str]
    explanation: str
    recommended_actions: List[str]

class AnalyzeResponse(BaseModel):
    overall_verdict: str
    overall_score: int
    technical: TechnicalResult
    semantic: Optional[SemanticResult] = None
    evidence: Dict[str, Any] = {}
    recommended_actions: List[str] = []
    explain: str
