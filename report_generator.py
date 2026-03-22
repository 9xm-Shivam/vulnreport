"""
report_generator.py
─────────────────────────────────────────────────────────────────────────────
Core AI module — uses Groq API (FREE, no credit card required).

Groq runs Llama 3 — a powerful open-source model by Meta.
API is completely free with generous rate limits.

Get your free key at: https://console.groq.com

Interview explanation:
  "I used the Groq API which runs Meta's Llama 3 model. I send a
   structured prompt asking it to act as a penetration tester and
   return a JSON report. Groq is free and extremely fast — it can
   generate responses in under 2 seconds."
─────────────────────────────────────────────────────────────────────────────
"""

import json
import re
import urllib.request
import urllib.error


GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
MODEL        = "llama-3.3-70b-versatile"   # Much larger, more accurate — still free on Groq


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
  "executive_summary": "3 sentences. What is vulnerable, what can an attacker do, what is the business risk. Plain English for a non-technical manager.",
  "technical_details": "4 sentences. Root cause of the vulnerability, the attack vector, authentication requirements, and what privileges an attacker gains.",
  "attack_scenario": "Numbered realistic attack steps. Each step on a new line starting with the number. E.g.: 1. Attacker scans for vulnerable hosts\\n2. Sends crafted payload\\n3. Gains remote code execution",
  "impact": "Bullet points of impact. Each on a new line starting with a dash. E.g.: - Full system compromise\\n- Data exfiltration\\n- Lateral movement",
  "remediation": "Numbered specific fix steps with patch versions where applicable. Each step on a new line. E.g.: 1. Apply patch CVE-XXXX-XXXX\\n2. Upgrade to version X.X.X\\n3. Enable firewall rule",
  "references": ["Official NVD URL", "Vendor advisory URL", "Exploit DB or MITRE URL"]
}"""


def _call_groq(prompt: str, api_key: str) -> str:
    """
    Make a POST request to Groq API.

    Groq uses the same format as OpenAI's API —
    a messages array with role and content.
    """
    payload = json.dumps({
        "model":       MODEL,
        "max_tokens":  1500,
        "temperature": 0.3,   # Lower = more consistent/factual output
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
    }).encode("utf-8")

    req = urllib.request.Request(
        GROQ_API_URL,
        data    = payload,
        headers = {
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        },
        method = "POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return body["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        raise ValueError(f"Groq API error {e.code}: {error_body}")


def _parse_report(raw: str) -> dict:
    """
    Parse the JSON response from the AI.
    Handles markdown code fences and control characters in AI output.
    """
    # Strip markdown code fences if present
    cleaned = re.sub(r"```(?:json)?\s*|\s*```", "", raw).strip()

    # Remove invalid control characters that break json.loads
    # (AI sometimes puts literal newlines inside JSON string values)
    cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', cleaned)

    # Replace unescaped newlines inside JSON strings with \\n
    # This fixes cases where the model writes real newlines in string values
    def fix_newlines(m):
        return m.group(0).replace('\n', '\\n').replace('\r', '')
    cleaned = re.sub(r'"[^"\\]*(?:\\.[^"\\]*)*"', fix_newlines, cleaned, flags=re.DOTALL)

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        # Last resort: extract JSON object
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
    Build the prompt and call Groq API.

    Two modes:
      cve  → analyse a specific CVE ID
      scan → analyse raw scanner output and find worst vulnerability
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

Return the JSON report as specified."""

    else:
        prompt = f"""Analyse this security scan output from a penetration test.
Find the MOST CRITICAL vulnerability and generate a detailed report for it.

Target Description: {target}

Scan Output:
{content}

Identify the worst vulnerability, map it to its CVE if possible, and generate
an accurate technical report. Return the JSON report as specified."""

    raw    = _call_groq(prompt, api_key)
    report = _parse_report(raw)

    # Add metadata
    report["input_type"] = input_type
    report["target"]     = target

    return report


def get_cve_context(cve_id: str, api_key: str) -> dict:
    """
    Quick CVE preview — just title + severity + CVSS before full report.
    """
    if not api_key:
        return {"title": cve_id, "severity": "Unknown", "cvss_score": "N/A"}

    prompt = f"""For {cve_id}, return ONLY a JSON object with three fields:
{{"title": "short vulnerability name", "severity": "Critical or High or Medium or Low", "cvss_score": "e.g. 9.8"}}
No other text. No markdown."""

    try:
        raw  = _call_groq(prompt, api_key)
        data = _parse_report(raw)
        return {
            "title":      data.get("title",      cve_id),
            "severity":   data.get("severity",   "Unknown"),
            "cvss_score": data.get("cvss_score", "N/A"),
        }
    except Exception:
        return {"title": cve_id, "severity": "Unknown", "cvss_score": "N/A"}
