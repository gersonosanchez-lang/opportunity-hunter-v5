import base64
import hashlib
import html
import logging
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from urllib.parse import urlencode

import requests
from flask import Flask, jsonify, redirect, render_template_string, request, session

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # SQLite local continua funcionando sem o driver instalado.
    psycopg = None
    dict_row = None


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "ALTERE-ESTA-CHAVE-NO-RENDER")
logger = logging.getLogger(__name__)

MERCADOLIVRE_APP_ID = os.environ.get("MERCADOLIVRE_APP_ID", "")
MERCADOLIVRE_CLIENT_SECRET = os.environ.get("MERCADOLIVRE_CLIENT_SECRET", "")
MERCADOLIVRE_REDIRECT_URI = os.environ.get(
    "MERCADOLIVRE_REDIRECT_URI", "https://opportunity-hunter-v5.onrender.com/oauth/callback"
)
MERCADOLIVRE_USE_PKCE = os.environ.get("MERCADOLIVRE_USE_PKCE", "false").lower() == "true"

AUTH_URL = "https://auth.mercadolivre.com.br/authorization"
TOKEN_URL = "https://api.mercadolibre.com/oauth/token"
ME_URL = "https://api.mercadolibre.com/users/me"

# No Render, DATABASE_URL é fornecida pelo PostgreSQL. Sem ela, o app usa
# SQLite local para desenvolvimento e testes.
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
DATABASE_PATH = os.environ.get("OPPORTUNITY_HUNTER_DB", "opportunity_hunter.db")
DATABASE_BACKEND = "PostgreSQL" if DATABASE_URL else "SQLite"
TOKEN_COLUMNS = "access_token, refresh_token, token_type, expires_in, scope, user_id, expires_at, updated_at"


@contextmanager
def conectar_banco():
    """Abre uma conexão curta por requisição; não registra segredos."""
    if DATABASE_URL:
        if psycopg is None:
            raise RuntimeError("psycopg não está instalado; inclua psycopg[binary] nas dependências.")
        conexao = psycopg.connect(DATABASE_URL, row_factory=dict_row, connect_timeout=10)
    else:
        conexao = sqlite3.connect(DATABASE_PATH, timeout=30, isolation_level=None)
        conexao.row_factory = sqlite3.Row
    try:
        yield conexao
    finally:
        conexao.close()


def inicializar_banco():
    tipo_real = "DOUBLE PRECISION" if DATABASE_URL else "REAL"
    with conectar_banco() as conexao:
        with conexao.cursor() if DATABASE_URL else conexao as cursor:
            cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS mercado_livre_token (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    access_token TEXT NOT NULL,
                    refresh_token TEXT NOT NULL,
                    token_type TEXT,
                    expires_in INTEGER,
                    scope TEXT,
                    user_id TEXT,
                    expires_at {tipo_real} NOT NULL,
                    updated_at {tipo_real} NOT NULL
                )
            """)
        if DATABASE_URL:
            conexao.commit()


def _executar(conexao, sql, parametros=()):
    # psycopg usa %s; sqlite usa ?. Mantemos consultas centralizadas para evitar
    # diferenças acidentais entre o ambiente local e o Render.
    if DATABASE_URL:
        sql = sql.replace("?", "%s")
    cursor = conexao.cursor()
    cursor.execute(sql, parametros)
    return cursor


def _linha_para_dict(linha):
    return dict(linha) if linha else None


def _obter_token_na_conexao(conexao, bloquear=False):
    sufixo = " FOR UPDATE" if bloquear and DATABASE_URL else ""
    cursor = _executar(conexao, f"SELECT {TOKEN_COLUMNS} FROM mercado_livre_token WHERE id = 1{sufixo}")
    try:
        return _linha_para_dict(cursor.fetchone())
    finally:
        cursor.close()


def _salvar_token_na_conexao(conexao, dados, token_anterior=None):
    access_token = dados.get("access_token")
    # Em um refresh, a ausência de refresh_token significa que o provedor não o
    # rotacionou; conserva-se o valor anterior. No OAuth inicial ele é obrigatório.
    refresh_token = dados.get("refresh_token") or (token_anterior or {}).get("refresh_token")
    if not access_token or not refresh_token:
        raise ValueError("Mercado Livre não retornou os tokens necessários.")

    try:
        expires_in = int(dados.get("expires_in", 0))
    except (TypeError, ValueError) as erro:
        raise ValueError("expires_in retornado pelo Mercado Livre é inválido.") from erro
    agora = time.time()
    valores = (
        access_token, refresh_token, dados.get("token_type"), expires_in,
        dados.get("scope"), dados.get("user_id"), agora + expires_in, agora,
    )
    if DATABASE_URL:
        sql = """
            INSERT INTO mercado_livre_token (id, access_token, refresh_token, token_type, expires_in, scope, user_id, expires_at, updated_at)
            VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (id) DO UPDATE SET
              access_token = EXCLUDED.access_token, refresh_token = EXCLUDED.refresh_token,
              token_type = EXCLUDED.token_type, expires_in = EXCLUDED.expires_in,
              scope = EXCLUDED.scope, user_id = EXCLUDED.user_id,
              expires_at = EXCLUDED.expires_at, updated_at = EXCLUDED.updated_at
        """
    else:
        sql = """
            INSERT INTO mercado_livre_token (id, access_token, refresh_token, token_type, expires_in, scope, user_id, expires_at, updated_at)
            VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              access_token = excluded.access_token, refresh_token = excluded.refresh_token,
              token_type = excluded.token_type, expires_in = excluded.expires_in,
              scope = excluded.scope, user_id = excluded.user_id,
              expires_at = excluded.expires_at, updated_at = excluded.updated_at
        """
    cursor = _executar(conexao, sql, valores)
    cursor.close()


def salvar_token(dados):
    with conectar_banco() as conexao:
        if DATABASE_URL:
            try:
                _salvar_token_na_conexao(conexao, dados)
                conexao.commit()
            except Exception:
                conexao.rollback()
                raise
        else:
            conexao.execute("BEGIN IMMEDIATE")
            try:
                _salvar_token_na_conexao(conexao, dados)
                conexao.commit()
            except Exception:
                conexao.rollback()
                raise


def obter_token():
    with conectar_banco() as conexao:
        return _obter_token_na_conexao(conexao)


def apagar_token():
    with conectar_banco() as conexao:
        cursor = _executar(conexao, "DELETE FROM mercado_livre_token")
        cursor.close()
        if DATABASE_URL:
            conexao.commit()


def token_valido(token=None):
    token = token if token is not None else obter_token()
    if not token or not token.get("access_token"):
        return False
    try:
        return time.time() < float(token.get("expires_at", 0)) - 60
    except (TypeError, ValueError):
        return False


def _resposta_refresh(refresh_token):
    dados = {
        "grant_type": "refresh_token", "client_id": MERCADOLIVRE_APP_ID,
        "client_secret": MERCADOLIVRE_CLIENT_SECRET, "refresh_token": refresh_token,
    }
    try:
        resposta = requests.post(TOKEN_URL, data=dados, headers={
            "accept": "application/json", "content-type": "application/x-www-form-urlencoded"
        }, timeout=30)
    except requests.RequestException as erro:
        return False, {"erro": "Falha de comunicação com Mercado Livre.", "detalhe": str(erro)}
    try:
        corpo = resposta.json()
    except ValueError:
        corpo = {"resposta": resposta.text}
    if resposta.status_code != 200:
        return False, {"erro": "Mercado Livre recusou o refresh.", "status": resposta.status_code, "resposta": corpo}
    if not isinstance(corpo, dict) or not corpo.get("access_token"):
        return False, {"erro": "Mercado Livre não retornou novo access_token."}
    return True, corpo


def _resumo_token(token):
    return {"user_id": token.get("user_id"), "scope": token.get("scope"), "expires_in": token.get("expires_in")}


def refresh_access_token(force=True):
    """Atualiza uma vez mesmo sob múltiplas requisições concorrentes.

    O bloqueio de linha (PostgreSQL) ou de escrita (SQLite) é mantido até o novo
    par access/refresh ser salvo. Assim, uma segunda requisição lê o token novo
    e não tenta reutilizar um refresh token de uso único.
    """
    with conectar_banco() as conexao:
        try:
            if DATABASE_URL:
                token = _obter_token_na_conexao(conexao, bloquear=True)
            else:
                conexao.execute("BEGIN IMMEDIATE")
                token = _obter_token_na_conexao(conexao)
            if not token:
                raise LookupError("Nenhum token armazenado.")
            if not force and token_valido(token):
                if DATABASE_URL:
                    conexao.commit()
                else:
                    conexao.commit()
                return True, _resumo_token(token)

            sucesso, resultado = _resposta_refresh(token.get("refresh_token"))
            if not sucesso:
                conexao.rollback()
                return False, resultado
            dados_salvar = {
                "access_token": resultado["access_token"],
                "refresh_token": resultado.get("refresh_token"),
                "token_type": resultado.get("token_type", token.get("token_type")),
                "expires_in": resultado.get("expires_in", 0),
                "scope": resultado.get("scope", token.get("scope")),
                "user_id": resultado.get("user_id", token.get("user_id")),
            }
            _salvar_token_na_conexao(conexao, dados_salvar, token)
            conexao.commit()
            return True, _resumo_token(dados_salvar)
        except LookupError as erro:
            conexao.rollback()
            return False, {"erro": str(erro)}
        except Exception:
            conexao.rollback()
            logger.exception("Erro ao atualizar token do Mercado Livre")
            return False, {"erro": "Não foi possível atualizar o token armazenado."}


def configuracao_ok():
    return bool(MERCADOLIVRE_APP_ID and MERCADOLIVRE_CLIENT_SECRET and MERCADOLIVRE_REDIRECT_URI)


def gerar_code_verifier():
    return secrets.token_urlsafe(64)


def gerar_code_challenge(verifier):
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def obter_access_token():
    token = obter_token()
    if token and token_valido(token):
        return True, token["access_token"]
    if token:
        sucesso, resultado = refresh_access_token(force=False)
        if sucesso:
            token = obter_token()
            return True, token["access_token"]
        return False, resultado
    return False, {"erro": "Mercado Livre não está conectado."}


HTML_BASE = """<!doctype html><html lang='pt-BR'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Opportunity Hunter</title><style>body{margin:0;padding:20px;background:#111;color:#eee;font-family:Arial,sans-serif}.container{max-width:760px;margin:auto}.card{background:#1c1c1c;border-radius:14px;padding:24px;margin-bottom:20px}.button{display:inline-block;padding:14px 20px;border-radius:8px;background:#3483fa;color:white;text-decoration:none;margin-top:10px;font-weight:bold}.ok{color:#35d07f}.warn{color:#ffcc00}.error{color:#ff5c5c}pre{white-space:pre-wrap;word-break:break-word}</style></head><body><div class='container'>{{conteudo|safe}}</div></body></html>"""


def pagina(conteudo):
    return render_template_string(HTML_BASE, conteudo=conteudo)


@app.get("/")
def inicio():
    if not configuracao_ok():
        return pagina("<div class='card'><h1>Opportunity Hunter</h1><p class='error'>O Gateway ainda não está configurado.</p><p>Configure no Render: MERCADOLIVRE_APP_ID, MERCADOLIVRE_CLIENT_SECRET, MERCADOLIVRE_REDIRECT_URI e FLASK_SECRET_KEY.</p></div>")
    token = obter_token()
    conectado = bool(token and token.get("access_token"))
    status = "<span class='ok'>Conectado</span>" if conectado else "<span class='warn'>Não conectado</span>"
    user_id = f"<p><strong>User ID:</strong> {html.escape(str(token.get('user_id', '')))}</p>" if conectado else ""
    return pagina(f"<div class='card'><h1>Opportunity Hunter</h1><h2>Gateway Mercado Livre</h2><p>Status: {status}</p>{user_id}<a class='button' href='/oauth/mercadolivre'>Conectar Mercado Livre</a><br><a class='button' href='/oauth/status'>Ver status</a><br><a class='button' href='/api/me'>Testar minha conta</a><br><a class='button' href='/health'>Ver saúde do Gateway</a></div>")


@app.get("/health")
@app.get("/saude")
def health():
    token = obter_token()
    return {"OK": True, "servico": "Opportunity Hunter Gateway", "tempo": int(time.time()), "oauth_configurado": configuracao_ok(), "mercado_livre_conectado": bool(token and token.get("access_token")), "token_valido": token_valido(token)}, 200


@app.get("/oauth/mercadolivre")
def oauth_mercadolivre():
    if not configuracao_ok():
        return pagina("<div class='card'><h2>Configuração incompleta</h2><p class='error'>As credenciais do Mercado Livre não foram configuradas no Render.</p></div>"), 500
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    parametros = {
        "response_type": "code",
        "client_id": MERCADOLIVRE_APP_ID,
        "redirect_uri": MERCADOLIVRE_REDIRECT_URI,
        "state": state,
        # O refresh token só é disponibilizado quando o acesso offline é
        # solicitado. Sem ele não há como manter a conexão após expirar.
        "scope": "offline_access",
    }
    if MERCADOLIVRE_USE_PKCE:
        verifier = gerar_code_verifier()
        session["code_verifier"] = verifier
        parametros.update({"code_challenge": gerar_code_challenge(verifier), "code_challenge_method": "S256"})
    else:
        session.pop("code_verifier", None)
    return redirect(AUTH_URL + "?" + urlencode(parametros))


@app.get("/oauth/callback")
def oauth_callback():
    erro = request.args.get("error", "")
    if erro:
        return pagina(f"<div class='card'><h2>Autorização não concluída</h2><p class='error'>{html.escape(request.args.get('error_description', erro))}</p><a class='button' href='/'>Voltar</a></div>"), 400
    codigo = request.args.get("code", "")
    if not codigo:
        return pagina("<div class='card'><h2>Retorno inválido</h2><p class='error'>O Mercado Livre não enviou o código de autorização.</p></div>"), 400
    estado_salvo = session.get("oauth_state", "")
    if not estado_salvo:
        return pagina("<div class='card'><h2>Estado OAuth ausente</h2><p class='error'>A sessão OAuth não está mais disponível.</p></div>"), 400
    if not secrets.compare_digest(request.args.get("state", ""), estado_salvo):
        return pagina("<div class='card'><h2>Falha de segurança</h2><p class='error'>O parâmetro state não corresponde ao iniciado pelo Gateway.</p></div>"), 400
    session.pop("oauth_state", None)
    dados = {"grant_type": "authorization_code", "client_id": MERCADOLIVRE_APP_ID, "client_secret": MERCADOLIVRE_CLIENT_SECRET, "code": codigo, "redirect_uri": MERCADOLIVRE_REDIRECT_URI}
    if MERCADOLIVRE_USE_PKCE:
        verifier = session.pop("code_verifier", None)
        if not verifier:
            return pagina("<div class='card'><h2>PKCE incompleto</h2><p class='error'>O code_verifier não foi encontrado.</p></div>"), 400
        dados["code_verifier"] = verifier
    try:
        resposta = requests.post(TOKEN_URL, data=dados, headers={"accept": "application/json", "content-type": "application/x-www-form-urlencoded"}, timeout=30)
    except requests.RequestException as exc:
        return pagina(f"<div class='card'><h2>Erro de comunicação</h2><p class='error'>Não foi possível comunicar com o Mercado Livre.</p><pre>{html.escape(str(exc))}</pre></div>"), 502
    try:
        dados_token = resposta.json()
    except ValueError:
        dados_token = {}
    if resposta.status_code != 200:
        publico = {chave: dados_token[chave] for chave in ("error", "error_description", "message") if isinstance(dados_token, dict) and chave in dados_token}
        return pagina(f"<div class='card'><h2>Mercado Livre recusou a autorização</h2><p class='error'>Não foi possível concluir a conexão.</p><p>HTTP: {resposta.status_code}</p><pre>{html.escape(str(publico or {'erro': 'Autorização recusada'}))}</pre><a class='button' href='/'>Voltar</a></div>"), 400
    if not isinstance(dados_token, dict) or not dados_token.get("access_token") or not dados_token.get("refresh_token"):
        campos = sorted(dados_token.keys()) if isinstance(dados_token, dict) else [type(dados_token).__name__]
        logger.error("Resposta OAuth sem tokens obrigatórios; campos recebidos: %s", campos)
        return pagina("<div class='card'><h2>Resposta OAuth incompleta</h2><p class='error'>O Mercado Livre não retornou access_token e refresh_token. Inicie a conexão novamente.</p></div>"), 502
    try:
        salvar_token(dados_token)
    except Exception:
        logger.exception("Erro ao salvar token OAuth")
        return pagina("<div class='card'><h2>Erro ao salvar conexão</h2><p class='error'>A autorização foi recebida, mas o Gateway não conseguiu salvar os dados.</p></div>"), 500
    return pagina(f"<div class='card'><h2 class='ok'>Mercado Livre conectado!</h2><p>A autorização foi concluída com sucesso.</p><p><strong>User ID:</strong> {html.escape(str(dados_token.get('user_id', '')))}</p><p><strong>Escopo:</strong> {html.escape(str(dados_token.get('scope', '')))}</p><a class='button' href='/api/me'>Testar conexão</a><br><a class='button' href='/'>Voltar</a></div>")


@app.get("/oauth/status")
def oauth_status():
    token = obter_token()
    return jsonify({"oauth_configurado": configuracao_ok(), "conectado": bool(token and token.get("access_token")), "token_valido": token_valido(token), "user_id": token.get("user_id") if token else None, "scope": token.get("scope") if token else None, "expires_in": token.get("expires_in") if token else None, "armazenamento": DATABASE_BACKEND})


@app.get("/api/me")
def api_me():
    sucesso, resultado = obter_access_token()
    if not sucesso:
        return jsonify({"OK": False, "erro": "Mercado Livre não conectado.", "detalhes": resultado}), 401
    try:
        resposta = requests.get(ME_URL, headers={"Authorization": "Bearer " + resultado}, timeout=30)
    except requests.RequestException as erro:
        return jsonify({"OK": False, "erro": "Falha ao consultar Mercado Livre.", "detalhe": str(erro)}), 502
    try:
        dados = resposta.json()
    except ValueError:
        dados = {"resposta": resposta.text}
    if resposta.status_code != 200:
        return jsonify({"OK": False, "status": resposta.status_code, "erro": "Mercado Livre recusou a consulta.", "resposta": dados}), resposta.status_code
    campos_publicos = ("id", "nickname", "site_id", "user_type")
conta_resumida = {
    campo: dados[campo]
    for campo in campos_publicos
    if campo in dados
} if isinstance(dados, dict) else {}

return jsonify({
    "OK": True,
    "mensagem": "Conexão com Mercado Livre confirmada.",
    "mercado_livre": conta_resumida,
})


@app.get("/oauth/refresh")
def oauth_refresh():
    sucesso, resultado = refresh_access_token(force=True)
    if not sucesso:
        return jsonify({"OK": False, "resultado": resultado}), 400
    return jsonify({"OK": True, "mensagem": "Token atualizado com sucesso.", **resultado})


@app.get("/oauth/logout")
def oauth_logout():
    apagar_token()
    return pagina("<div class='card'><h2>Mercado Livre desconectado</h2><p class='ok'>Os tokens armazenados pelo Gateway foram removidos.</p><a class='button' href='/'>Voltar</a></div>")


@app.get("/api/system")
def api_system():
    return jsonify({"aplicacao": "Opportunity Hunter V5", "gateway": "online", "oauth_configurado": configuracao_ok(), "mercado_livre": "conectado" if obter_token() else "não conectado", "pkce": MERCADOLIVRE_USE_PKCE, "armazenamento": DATABASE_BACKEND, "proxima_fase": "Análise de oportunidades"})


@app.errorhandler(404)
def pagina_404(erro):
    return pagina("<div class='card'><h2>Página não encontrada</h2><p class='error'>O endereço solicitado não existe.</p><a class='button' href='/'>Voltar ao Opportunity Hunter</a></div>"), 404


@app.errorhandler(500)
def pagina_500(erro):
    return pagina("<div class='card'><h2>Erro interno</h2><p class='error'>O Gateway encontrou um erro interno.</p><a class='button' href='/'>Voltar</a></div>"), 500


inicializar_banco()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
