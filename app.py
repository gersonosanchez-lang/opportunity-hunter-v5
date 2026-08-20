from flask import Flask, request, Response
import html
import json
import os
import time

app = Flask(__name__)

HTML = """<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Opportunity Hunter</title>
<style>
body{font-family:Arial,sans-serif;max-width:760px;margin:40px auto;padding:0 18px;line-height:1.5}
.card{border:1px solid #ddd;border-radius:12px;padding:20px;margin:18px 0}
code{word-break:break-all;background:#f4f4f4;padding:2px 5px;border-radius:4px}
.ok{color:#087f23}.warn{color:#9a5b00}
</style>
</head>
<body>{body}</body>
</html>"""

@app.get("/")
def home():
    return HTML.format(body="""
    <div class="card">
      <h1>Opportunity Hunter Gateway</h1>
      <p class="ok">Gateway online.</p>
      <p>Endpoint de saúde: <code>/health</code></p>
      <p>Callback OAuth: <code>/oauth/callback</code></p>
      <p>Webhook Mercado Livre: <code>/webhooks/mercadolivre</code></p>
    </div>
    """)

@app.get("/health")
def health():
    return {"ok": True, "service": "Opportunity Hunter Gateway", "time": int(time.time())}, 200

@app.get("/oauth/callback")
def oauth_callback():
    # Recebe o authorization code do Mercado Livre.
    # O gateway NÃO grava esse código em arquivo.
    code = request.args.get("code", "")
    state = request.args.get("state", "")
    error = request.args.get("error", "")

    if error:
        detail = html.escape(request.args.get("error_description", error))
        return HTML.format(body=f"""
        <div class="card">
          <h2>Autorização não concluída</h2>
          <p class="warn">{detail}</p>
        </div>"""), 400

    if not code:
        return HTML.format(body="""
        <div class="card">
          <h2>Callback recebido</h2>
          <p>Não veio um parâmetro <code>code</code>.</p>
        </div>"""), 400

    return HTML.format(body=f"""
    <div class="card">
      <h2>Autorização recebida</h2>
      <p class="ok">O Mercado Livre redirecionou corretamente para o gateway.</p>
      <p><strong>Authorization code:</strong></p>
      <p><code>{html.escape(code)}</code></p>
      <p><strong>State:</strong> <code>{html.escape(state)}</code></p>
      <p class="warn">Este código é temporário. Nunca envie Client Secret ou Refresh Token para o chat.</p>
    </div>"""), 200

@app.post("/webhooks/mercadolivre")
def mercadolivre_webhook():
    # O Mercado Livre exige resposta HTTP 200 rapidamente.
    payload = request.get_json(silent=True) or {}
    print("Mercado Livre notification:", json.dumps(payload, ensure_ascii=False))
    return Response("OK", status=200, mimetype="text/plain")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
