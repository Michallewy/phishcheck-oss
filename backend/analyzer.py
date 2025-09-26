import base64, email, re
import dns.resolver
import dkim
import spf
from typing import List, Dict, Any
from .utils import domain_of, extract_text_and_html, link_mismatch_indicators

AUTH_RES_RE = re.compile(r'(?i)spf=(\w+).*?dkim=(\w+).*?dmarc=(\w+)', re.DOTALL)

def _txt(domain: str) -> List[str]:
    try:
        return [r.to_text().strip('"') for r in dns.resolver.resolve(domain, 'TXT')]
    except Exception:
        return []

def _dmarc(domain: str) -> Dict[str, Any]:
    try:
        recs = [t for t in _txt(f"_dmarc.{domain}") if t.lower().startswith('v=dmarc1')]
        if not recs: return {"present": False}
        rec = recs[0].lower()
        def kv(k):
            m = re.search(rf'{k}=([^; ]+)', rec)
            return m.group(1) if m else None
        return {"present": True, "p": kv('p'), "sp": kv('sp'), "pct": kv('pct')}
    except Exception:
        return {"present": False}

def _parse_auth_results(headers_text: str):
    m = AUTH_RES_RE.search(headers_text)
    return {"spf": m.group(1), "dkim": m.group(2), "dmarc": m.group(3)} if m else None

def _verify_dkim(raw_msg: bytes) -> str:
    try:
        ok = dkim.verify(raw_msg)
        return "pass" if ok else "fail"
    except Exception:
        return "none"

def _verify_spf(mail_from: str, client_ip: str, helo: str) -> str:
    try:
        result, *_ = spf.check2(i=client_ip or "0.0.0.0", s=mail_from or "", h=helo or "")
        return result
    except Exception:
        return "none"

def analyze_eml_base64(eml_base64: str) -> Dict[str, Any]:
    raw_bytes = base64.b64decode(eml_base64)
    msg = email.message_from_bytes(raw_bytes)

    headers_text = "
".join(f"{k}: {v}" for k,v in msg.items())
    from_addr = msg.get("From","")
    from_dom = domain_of(from_addr)
    return_path = msg.get("Return-Path","{}").strip("<>")
    rp_dom = domain_of(return_path)
    subject = msg.get("Subject","")
    received_spf = msg.get("Received-SPF","")

    auth = _parse_auth_results(headers_text)

    spf_dns = any(t.lower().startswith('v=spf1') for t in _txt(from_dom)) if from_dom else False
    dmarc_dns = _dmarc(from_dom) if from_dom else {"present": False}

    dkim_local = None
    spf_local = None
    if not auth:
        dkim_local = _verify_dkim(raw_bytes)
        client_ip, helo, mail_from = None, None, return_path
        m = re.search(r'client-ip=([\d\.:\w]+)', received_spf)
        if m: client_ip = m.group(1)
        m = re.search(r'helo=([^\s;]+)', received_spf)
        if m: helo = m.group(1)
        spf_local = _verify_spf(mail_from, client_ip, helo)

    anomalies = []
    if from_dom and rp_dom and from_dom != rp_dom:
        anomalies.append("From vs Return-Path domain mismatch")
    if "X-Priority" in headers_text or "Importance: High" in headers_text:
        anomalies.append("High urgency header")

    text, html = extract_text_and_html(msg)
    link_indicators = link_mismatch_indicators(html)

    reasons = []
    risk = 0

    if auth:
        if auth["spf"] != "pass": risk += 25; reasons.append(f"SPF={auth['spf']}")
        if auth["dkim"] != "pass": risk += 25; reasons.append(f"DKIM={auth['dkim']}")
        if auth["dmarc"] not in ("pass","bestguesspass"): risk += 25; reasons.append(f"DMARC={auth['dmarc']}")
    else:
        if dkim_local and dkim_local != "pass": risk += 25; reasons.append(f"DKIM(local)={dkim_local}")
        if spf_local and spf_local not in ("pass","neutral"): risk += 20; reasons.append(f"SPF(local)={spf_local}")
        if not spf_dns: risk += 15; reasons.append("Brak SPF w DNS")
        if not dmarc_dns.get("present"): risk += 15; reasons.append("Brak DMARC w DNS")

    if anomalies:
        risk += 10; reasons += anomalies
    if link_indicators:
        risk += 10; reasons += link_indicators

    score = max(0, min(100, risk))
    verdict = "malicious" if score >= 70 else "suspicious" if score >= 40 else "likely_ok"

    tech = {
        "spf": (auth or {}).get("spf") or spf_local or ("present" if spf_dns else "none"),
        "dkim": (auth or {}).get("dkim") or dkim_local or "none",
        "dmarc": (auth or {}).get("dmarc") or ("present" if dmarc_dns.get("present") else "none"),
        "header_anomalies": anomalies + link_indicators,
        "dns": {"spf_present": spf_dns, "dmarc": dmarc_dns},
    }

    evidence = {
        "from": from_addr,
        "return_path": return_path,
        "subject": subject,
        "authentication_results": (re.search(r'(?im)^Authentication-Results:.*$', headers_text) and re.search(r'(?im)^Authentication-Results:.*$', headers_text).group(0)) or "",
        "received_spf": received_spf[:800],
    }

    rec = []
    if verdict in ("malicious","suspicious"):
        rec = ["report_to_soc", "quarantine", "warn_user"]

    return {
        "verdict": verdict,
        "score": score,
        "reasons": reasons,
        "technical": tech,
        "evidence": evidence,
        "body_text": text[:2000],
        "body_html_present": bool(html),
        "subject": subject
    }
