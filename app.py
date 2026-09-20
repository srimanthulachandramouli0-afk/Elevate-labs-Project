from flask import Flask, render_template_string, request
import requests
from bs4 import BeautifulSoup
from datetime import datetime

app = Flask(__name__)

PAYLOADS = {
    "XSS": ["<script>alert('XSS')</script>", "'><img src=x onerror=alert(1)>"],
    "SQLi": ["' OR '1'='1", "' OR 1=1--"],
}

def scan_target(url):
    logs = []
    crawled = []
    try:
        r = requests.get(url, timeout=6)
        soup = BeautifulSoup(r.text, 'html.parser')
        forms = soup.find_all('form')
        for f in forms:
            crawled.append(str(f)[:200])

        # Check CSRF
        for f in forms:
            inputs = [i.get('name','') for i in f.find_all('input')]
            if not any('csrf' in x.lower() or 'token' in x.lower() for x in inputs):
                logs.append({"type":"CSRF","severity":"Medium","evidence":f"Form without CSRF token found: {f.get('action')}", "url":url, "time":datetime.now().strftime("%H:%M:%S")})

        # Check XSS
        for p in PAYLOADS["XSS"]:
            try:
                res = requests.get(f"{url}?q={p}", timeout=5)
                if p in res.text:
                    logs.append({"type":"XSS","severity":"High","evidence":f"Payload reflected: {p}", "url":url, "time":datetime.now().strftime("%H:%M:%S")})
                    break
            except: pass

        # Check SQLi
        for p in PAYLOADS["SQLi"]:
            try:
                res = requests.get(f"{url}?id={p}", timeout=5)
                if "sql" in res.text.lower() or "syntax" in res.text.lower():
                    logs.append({"type":"SQL Injection","severity":"Critical","evidence":f"DB error with payload: {p}", "url":url, "time":datetime.now().strftime("%H:%M:%S")})
                    break
            except: pass

    except Exception as e:
        logs.append({"type":"Error","severity":"Low","evidence":str(e),"url":url,"time":datetime.now().strftime("%H:%M:%S")})

    if not logs:
        logs.append({"type":"None - Safe","severity":"Safe","evidence":"No common vulnerabilities found with basic payloads","url":url,"time":datetime.now().strftime("%H:%M:%S")})
    
    return logs, crawled

HTML = """
<!DOCTYPE html>
<html>
<head><title>ElevateLabs Scanner</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{background:#0f172a;color:#fff;font-family:Arial;padding:15px}
.card{background:#1e293b;padding:20px;border-radius:12px;max-width:900px;margin:auto;box-shadow:0 4px 15px rgba(0,0,0,0.3)}
input{width:65%;padding:12px;border-radius:8px;border:none;margin-right:5px}
button{padding:12px 18px;background:#22c55e;border:none;border-radius:8px;color:#fff;font-weight:bold}
table{width:100%;border-collapse:collapse;margin-top:15px}
th,td{padding:10px;border:1px solid #334155;text-align:left;font-size:14px}
th{background:#334155}
.Critical{color:#ef4444;font-weight:bold} .High{color:#f97316} .Medium{color:#eab308} .Safe{color:#22c55e} .Low{color:#94a3b8}
.badge{padding:3px 8px;border-radius:10px;font-size:12px}
</style>
</head>
<body>
<div class="card">
<h2>🔍 Web App Vulnerability Scanner</h2>
<p><b>ElevateLabs - Task 1</b> | OWASP Top 10: XSS, SQLi, CSRF</p>
<form method="POST">
<input name="url" placeholder="Ex: http://testphp.vulnweb.com or http://127.0.0.1:5000" required>
<button>🚀 Scan Now</button>
</form>

{% if logs %}
<h3>📊 Results for {{target}} (Crawled: {{crawled|length}} forms)</h3>
<table>
<tr><th>Type</th><th>Severity</th><th>Evidence</th><th>Time</th></tr>
{% for l in logs %}
<tr><td>{{l.type}}</td><td class="{{l.severity}}">{{l.severity}}</td><td>{{l.evidence}}<br><small>{{l.url}}</small></td><td>{{l.time}}</td></tr>
{% endfor %}
</table>
<h4>🔗 Crawled Forms Preview:</h4>
{% for c in crawled %}<pre style="background:#334155;padding:8px;border-radius:5px;overflow-x:auto">{{c}}</pre>{% endfor %}
{% endif %}
</div>
</body>
</html>
"""

@app.route("/", methods=["GET","POST"])
def home():
    logs, crawled, target = None, [], ""
    if request.method == "POST":
        target = request.form["url"]
        if not target.startswith("http"): target = "http://"+target
        logs, crawled = scan_target(target)
    return render_template_string(HTML, logs=logs, crawled=crawled, target=target)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)