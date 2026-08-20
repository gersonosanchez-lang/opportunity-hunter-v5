# Opportunity Hunter Gateway V5

Gateway HTTPS para a integração do Opportunity Hunter com o Mercado Livre.

Endpoints:
- `/health`
- `/oauth/callback`
- `/webhooks/mercadolivre`

No Render:
Build: `pip install -r requirements.txt`
Start: `gunicorn app:app`

Depois do deploy, as URLs serão:
OAuth Redirect URI:
`https://SEU-SERVICO.onrender.com/oauth/callback`

Notification Callback URL:
`https://SEU-SERVICO.onrender.com/webhooks/mercadolivre`

Não coloque Client Secret, Refresh Token ou senha neste projeto.
