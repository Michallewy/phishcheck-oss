import re
import tldextract
from bs4 import BeautifulSoup
from email.message import Message

LINK_RE = re.compile(r'https?://[^\s]+', re.I)

def domain_of(addr: str) -> str:
    addr = (addr or "").strip().lower()
    if "@" in addr:
        addr = addr.split("@")[-1].strip(">").strip()
    ext = tldextract.extract(addr)
    return ".".join([p for p in [ext.domain, ext.suffix] if p]) or addr

def extract_text_and_html(msg: Message):
    text, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                payload = part.get_payload(decode=True) or b""
                text += payload.decode(errors="ignore")
            elif ctype == "text/html":
                payload = part.get_payload(decode=True) or b""
                html += payload.decode(errors="ignore")
    else:
        # single part
        ctype = msg.get_content_type()
        payload = msg.get_payload(decode=True) or b""
        if ctype == "text/html":
            html = payload.decode(errors="ignore")
        else:
            text = payload.decode(errors="ignore")
    return text, html

def link_mismatch_indicators(html: str):
    if not html:
        return []
    soup = BeautifulSoup(html, "html.parser")
    indicators = []
    for a in soup.find_all("a"):
        display = (a.get_text() or "").strip()
        href = (a.get("href") or "").strip()
        if not href:
            continue
        # jeśli tekst wygląda jak URL i różni się od href → wskaźnik
        if display and ("http://" in display or "https://" in display) and display != href:
            indicators.append(f"Link mismatch: text='{display}' vs href='{href}'")
        # IDN lub podejrzane subdomeny
        if any(x in href for x in [".ru", ".tk", ".cn"]) or "%xn--" in href.lower():
            indicators.append(f"Suspicious TLD/IDN in href='{href}'")
    return indicators
