"""
app.py — VulnReport AI (Groq Edition — FREE)
"""

import os
from flask import Flask, render_template, request, jsonify
from report_generator import generate_report, get_cve_context

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/generate", methods=["POST"])
def api_generate():
    data       = request.get_json() or {}
    input_type = data.get("input_type", "cve")
    content    = data.get("content",    "").strip()
    target     = data.get("target",     "Target System").strip()

    if not content:
        return jsonify({"error": "No input provided."}), 400

    api_key = os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        return jsonify({"error": "GROQ_API_KEY not set. See setup instructions in README."}), 500

    try:
        report = generate_report(
            input_type = input_type,
            content    = content,
            target     = target,
            api_key    = api_key,
        )
        return jsonify({"success": True, "report": report})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/cve-info", methods=["POST"])
def api_cve_info():
    data    = request.get_json() or {}
    cve_id  = data.get("cve_id", "").strip().upper()
    api_key = os.environ.get("GROQ_API_KEY", "")

    if not cve_id:
        return jsonify({"error": "No CVE ID provided."}), 400

    try:
        info = get_cve_context(cve_id, api_key)
        return jsonify(info)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    if not os.environ.get("GROQ_API_KEY"):
        print("\n⚠️  Set your FREE Groq API key first:")
        print("   Get it at: https://console.groq.com")
        print("")
        print("   PowerShell: $env:GROQ_API_KEY='your-key-here'")
        print("   CMD:        set GROQ_API_KEY=your-key-here\n")
    print("🔍 VulnReport AI running at http://localhost:5002\n")
    app.run(debug=True, host="0.0.0.0", port=5002)
