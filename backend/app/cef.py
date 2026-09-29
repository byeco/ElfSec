"""CEF dışa aktarım — raporları SIEM'e aktarmak için ekledim.

Derste "kurumsal sistemler CEF formatı bekler" demişlerdi, ben de ekledim:
CEF:0|ElfSec|elfsec|{ver}|{sig-id}|{ad}|{0-10 şiddet}|...
Şiddet: LOW=2, MEDIUM=5, HIGH=8, CRITICAL=10.
"""

from __future__ import annotations

from app.__version__ import __version__

_SEV = {"LOW": 2, "MEDIUM": 5, "HIGH": 8, "CRITICAL": 10}


def _esc(v: object) -> str:
    return str(v or "").replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=").replace("\n", " ")


def to_cef(report: dict) -> str:
    lvl = str(report.get("risk_level", "LOW"))
    sev = _SEV.get(lvl, 2)
    sig = "elfsec-phish" if report.get("phishing_detected") else "elfsec-risk"
    ext = (f"src={_esc(report.get('sender'))} suid={_esc(report.get('uid'))} "
           f"fname={_esc(report.get('file', ''))} cs1={_esc(report.get('subject'))[:200]} "
           f"cs1Label=Subject msg={_esc(report.get('summary'))[:300]} "
           f"cn1={report.get('risk_score', 0)} cn1Label=RiskScore")
    return (f"CEF:0|ElfSec|elfsec|{__version__}|{sig}|"
            f"ElfSec {lvl} risk|{sev}|{ext}")
