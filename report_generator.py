"""
report_generator.py
─────────────────────────────────────────────────────────────────────────────
Core AI module — uses Google Gemini API (FREE, no credit card required).

Model: gemini-1.5-flash (free tier)
  - 15 requests per minute
  - 1 million tokens per minute
  - 1500 requests per day
  - Completely free, no billing needed

Get your free key at: https://aistudio.google.com/app/apikey

Interview explanation:
  "I use the Google Gemini API which is completely free. I send the
   CVE data with a structured prompt asking it to act as a penetration
   tester and return a JSON report. The key skill here is prompt
   engineering — designing the right instructions to get consistent,
   accurate output every time."
─────────────────────────────────────────────────────────────────────────────
"""

import json
import re
import urllib.request
import urllib.error


GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent"


# ── System prompt ──────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a certified penetration tester (OSCP, CEH) with 10 years of experience writing professional vulnerability assessment reports for enterprise clients.

You have deep knowledge of CVE databases, CVSS scoring, OWASP, MITRE ATT&CK, and real-world exploitation techniques.

When given a CVE ID or scan output, generate an ACCURATE and TECHNICALLY CORRECT vulnerability report.

IMPORTANT RULES:
- Use real, accurate CVE data — do not make up details
- CVSS scores must match the official NVD score for known CVEs
- Severity must match CVSS v3 rating: Critical(9.0-10.0), High(7.0-8.9), Medium(4.0-6.9), Low(0.1-3.9)
- Attack scenarios must be realistic and based on known exploitation methods
- Remediation must include specific patch versions, configuration changes, or workarounds

Return ONLY a valid JSON object with exactly these fields — no markdown, no extra text:
{
  "title": "Official vulnerability name, max 8 words",
  "severity": "Critical or High or Medium or Low or Informational",
  "cvss_score": "Official CVSS v3 base score as string e.g. 9.8",
  "cve_id": "CVE-XXXX-XXXXX or N/A",
  "affected_component": "Exact software name and affected versions",
  "executive_summary": "3 sentences. What is vulnerable, what can an attacker do, what is the business risk.",
  "technical_details": "4 sentences. Root cause, attack vector, authentication requirements, privileges gained.",
  "attack_scenario": "Numbered steps. Each step on new line e.g. 1. Step one\\n2. Step two\\n3. Step three",
  "impact": "Bullet points each on new line e.g. - Impact one\\n- Impact two\\n- Impact three",
  "remediation": "Numbered fix steps e.g. 1. Fix one\\n2. Fix two\\n3. Fix three",
  "references": ["URL1", "URL2", "URL3"]
}"""


def _call_gemini(prompt: str, api_key: str) -> str:
    """
    Make a POST request to Google Gemini API.

    Interview explanation:
      "Gemini uses a slightly different API format than OpenAI —
       instead of a messages array it uses a contents array with
       parts. But the concept is the same — you send a prompt and
       get a response back."
    """
    url = f"{GEMINI_API_URL}?key={api_key}"

    payload = json.dumps({
        "system_instruction": {
            "parts": [{"text": SYSTEM_PROMPT}]
        },
        "contents": [{
            "parts": [{"text": prompt}]
        }],
        "generationConfig": {
            "temperature":     0.2,
            "maxOutputTokens": 1500,
        }
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data    = payload,
        headers = {
            "Content-Type": "application/json",
            "User-Agent":   "VulnReport-AI/1.0",
        },
        method = "POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return body["candidates"][0]["content"]["parts"][0]["text"]
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        raise ValueError(f"Gemini API error {e.code}: {error_body}")


def _parse_report(raw: str) -> dict:
    """
    Parse the JSON response from the AI.
    Handles markdown code fences and control characters in AI output.
    """
    # Strip markdown code fences if present
    cleaned = re.sub(r"```(?:json)?\s*|\s*```", "", raw).strip()

    # Remove invalid control characters
    cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', cleaned)

    # Fix unescaped newlines inside JSON strings
    def fix_newlines(m):
        return m.group(0).replace('\n', '\\n').replace('\r', '')
    cleaned = re.sub(r'"[^"\\]*(?:\\.[^"\\]*)*"',
                     fix_newlines, cleaned, flags=re.DOTALL)

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group())
            except Exception:
                raise ValueError("Could not parse AI response. Please try again.")
        else:
            raise ValueError("Could not parse AI response. Please try again.")

    # Ensure all expected fields exist
    required = [
        "title", "severity", "cvss_score", "cve_id",
        "affected_component", "executive_summary", "technical_details",
        "attack_scenario", "impact", "remediation", "references"
    ]
    for field in required:
        if field not in data:
            data[field] = "N/A"

    return data


def generate_report(input_type: str, content: str,
                    target: str, api_key: str) -> dict:
    """
    Build prompt and call Gemini API.

    Two modes:
      cve  → analyse a specific CVE ID
      scan → analyse raw scanner output
    """
    if input_type == "cve":
        prompt = f"""Generate an accurate penetration testing report for this CVE.

CVE ID: {content}
Target Description: {target}

Use the official NVD data for this CVE. Be technically precise about:
- The exact software and versions affected
- The real CVSS v3 base score
- How the vulnerability is actually exploited
- The specific patches or mitigations available

Return the JSON report as specified in your instructions."""

    else:
        prompt = f"""Analyse this security scan output from a penetration test.
Find the MOST CRITICAL vulnerability and generate a detailed report for it.

Target Description: {target}

Scan Output:
{content}

Identify the worst vulnerability, map it to its CVE if possible, and generate
an accurate technical report. Return the JSON report as specified."""

    raw    = _call_gemini(prompt, api_key)
    report = _parse_report(raw)

    report["input_type"] = input_type
    report["target"]     = target

    return report


def get_cve_context(cve_id: str, api_key: str) -> dict:
    """Quick CVE preview — title, severity, CVSS before full report."""
    if not api_key:
        return {"title": cve_id, "severity": "Unknown", "cvss_score": "N/A"}

    prompt = f"""For {cve_id}, return ONLY a JSON object with three fields:
{{"title": "short vulnerability name", "severity": "Critical or High or Medium or Low", "cvss_score": "e.g. 9.8"}}
No other text. No markdown. No code blocks."""

    try:
        raw  = _call_gemini(prompt, api_key)
        data = _parse_report(raw)
        return {
            "title":      data.get("title",      cve_id),
            "severity":   data.get("severity",   "Unknown"),
            "cvss_score": data.get("cvss_score", "N/A"),
        }
    except Exception:
        return {"title": cve_id, "severity": "Unknown", "cvss_score": "N/A"}
