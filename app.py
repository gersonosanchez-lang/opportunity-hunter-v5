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
SEARCH_URL = "https://api.mercadolibre.com/sites/MLB/search"

# Primeiro recorte do Opportunity Hunter: itens leves, padronizados e de
# compra recorrente. A consulta pode ser alterada pelo usuário na tela.
CONSULTA_INICIAL_FERRAMENTAS = "broca aco rapido"
LIMITE_SCANNER = 20
FERRAMENTAS_CATEGORY_ID = "MLB263532"

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


def _numero_scanner(valor, nome, minimo, maximo):
    """Converte entradas brasileiras (por exemplo, 12,50) com limites claros."""
    texto = str(valor or "").strip()
    # Com vírgula, ponto é separador de milhar; sem vírgula, preservamos o
    # ponto para também aceitar chamadas de API no formato decimal usual.
    if "," in texto:
        texto = texto.replace(".", "").replace(",", ".")
    if not texto:
        raise ValueError(f"Informe {nome}.")
    try:
        numero = float(texto)
    except ValueError as erro:
        raise ValueError(f"{nome.capitalize()} precisa ser um número válido.") from erro
    if not minimo <= numero <= maximo:
        raise ValueError(f"{nome.capitalize()} deve ficar entre {minimo:g} e {maximo:g}.")
    return numero


def parametros_scanner(argumentos):
    consulta = str(argumentos.get("q", "")).strip()
    if not 2 <= len(consulta) <= 80:
        raise ValueError("Informe um produto entre 2 e 80 caracteres.")
    return {
        "consulta": consulta,
        "custo": _numero_scanner(argumentos.get("custo"), "o custo de compra", 0.01, 5000),
        "taxa_percentual": _numero_scanner(argumentos.get("taxa", "16"), "a taxa estimada", 0, 100),
        "frete": _numero_scanner(argumentos.get("frete", "0"), "a reserva de frete", 0, 5000),
    }


def moeda_brl(valor):
    texto = f"{float(valor):,.2f}"
    return "R$ " + texto.replace(",", "X").replace(".", ",").replace("X", ".")


def analisar_item_ferramenta(item, parametros):
    """Produz uma estimativa explicável; não é uma previsão de venda ou lucro."""
    try:
        preco = float(item.get("price"))
    except (TypeError, ValueError):
        return None
    if preco <= 0:
        return None

    envio = item.get("shipping") if isinstance(item.get("shipping"), dict) else {}
    frete_gratis = bool(envio.get("free_shipping"))
    reserva_frete = parametros["frete"] if frete_gratis else 0.0
    taxa = preco * parametros["taxa_percentual"] / 100
    lucro = preco - parametros["custo"] - taxa - reserva_frete
    margem = lucro / preco * 100
    condicao = str(item.get("condition", "")).lower()
    if condicao != "new":
        return None
    pontos = 0
    motivos = []

    if margem >= 30:
        pontos += 55
        motivos.append(f"margem estimada de {margem:.1f}%")
    elif margem >= 25:
        pontos += 45
        motivos.append(f"margem estimada de {margem:.1f}%")
    elif margem >= 15:
        pontos += 25
        motivos.append(f"margem estimada de {margem:.1f}%")
    elif margem > 0:
        pontos += 8
        motivos.append(f"margem baixa: {margem:.1f}%")
    else:
        motivos.append(f"margem negativa: {margem:.1f}%")

    if 60 <= preco <= 250:
        pontos += 15
        motivos.append("ticket na faixa inicial")
    if condicao == "new":
        pontos += 15
        motivos.append("anúncio novo")
    if item.get("original_price"):
        pontos += 5
        motivos.append("preço promocional identificado")

    pontos = min(pontos, 100)
    if pontos >= 70:
        sinal = "Oportunidade para avaliar"
    elif pontos >= 40:
        sinal = "Avaliar com cuidado"
    else:
        sinal = "Descartar por enquanto"

    return {
        "id": str(item.get("id", "")),
        "titulo": str(item.get("title", "Item sem título")),
        "url": str(item.get("permalink", "")),
        "preco": round(preco, 2),
        "frete_gratis": frete_gratis,
        "taxa_estimada": round(taxa, 2),
        "reserva_frete": round(reserva_frete, 2),
        "lucro_estimado": round(lucro, 2),
        "margem_percentual": round(margem, 1),
        "pontuacao": pontos,
        "sinal": sinal,
        "motivos": motivos,
    }


def buscar_oportunidades_ferramentas(parametros):
    """Consulta dados públicos de anúncios; não compra, publica ou altera itens."""
    headers = {"accept": "application/json"}
    sucesso, access_token = obter_access_token()
    if sucesso:
        headers["Authorization"] = "Bearer " + access_token
    try:
        resposta = requests.get(
            SEARCH_URL,
            params={
                "q": parametros["consulta"],
                "category": FERRAMENTAS_CATEGORY_ID,
                "limit": LIMITE_SCANNER,
            },
            headers=headers,
            timeout=20,
        )
        resposta.raise_for_status()
        corpo = resposta.json()
    except requests.RequestException as erro:
        logger.warning("Falha ao consultar busca pública do Mercado Livre: %s", erro)
        raise RuntimeError("Não foi possível consultar os anúncios agora. Tente novamente em instantes.") from erro
    except ValueError as erro:
        raise RuntimeError("O Mercado Livre retornou uma resposta inválida para a busca.") from erro

    resultados = corpo.get("results", []) if isinstance(corpo, dict) else []
    oportunidades = [
        analise
        for item in resultados
        if isinstance(item, dict)
        for analise in [analisar_item_ferramenta(item, parametros)]
        if analise is not None
    ]
    return sorted(oportunidades, key=lambda item: (item["pontuacao"], item["margem_percentual"]), reverse=True)


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
    return pagina(f"<div class='card'><h1>Opportunity Hunter</h1><h2>Gateway Mercado Livre</h2><p>Status: {status}</p>{user_id}<a class='button' href='/scanner/ferramentas'>Scanner de Ferramentas</a><br><a class='button' href='/oauth/mercadolivre'>Conectar Mercado Livre</a><br><a class='button' href='/oauth/status'>Ver status</a><br><a class='button' href='/api/me'>Testar minha conta</a><br><a class='button' href='/health'>Ver saúde do Gateway</a></div>")


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
    """Teste de conexão sem expor a resposta completa do perfil do usuário."""
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
    # /api/me é uma rota de diagnóstico acessível pelo navegador. A API do
    # Mercado Livre devolve dados pessoais (e-mail, telefone e endereço), que
    # não devem ser retransmitidos por esta aplicação. Mantemos somente campos
    # mínimos para confirmar que a conta autenticada é a esperada.
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


def token_csrf_scanner():
    token = session.get("scanner_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["scanner_csrf_token"] = token
    return token


def pagina_scanner_ferramentas(argumentos, resultados=None, erro=None):
    resultados = resultados or []
    csrf_token = html.escape(token_csrf_scanner(), quote=True)
    consulta = html.escape(str(argumentos.get("q", CONSULTA_INICIAL_FERRAMENTAS)), quote=True)
    custo = html.escape(str(argumentos.get("custo", "35,00")), quote=True)
    taxa = html.escape(str(argumentos.get("taxa", "16")), quote=True)
    frete = html.escape(str(argumentos.get("frete", "0")), quote=True)

    aviso_erro = f"<p class='error'>{html.escape(erro)}</p>" if erro else ""
    linhas = []
    for item in resultados:
        url = item["url"] if item["url"].startswith("https://") else "#"
        titulo = html.escape(item["titulo"])
        motivos = html.escape(" • ".join(item["motivos"]))
        classe = "ok" if item["pontuacao"] >= 70 else "warn" if item["pontuacao"] >= 40 else "error"
        linhas.append(
            "<tr>"
            f"<td><a href='{html.escape(url, quote=True)}' target='_blank' rel='noopener'>{titulo}</a></td>"
            f"<td>{moeda_brl(item['preco'])}</td>"
            f"<td>{moeda_brl(item['lucro_estimado'])}</td>"
            f"<td>{item['margem_percentual']:.1f}%</td>"
            f"<td class='{classe}'>{html.escape(item['sinal'])}<br><small>{motivos}</small></td>"
            "</tr>"
        )
    if resultados:
        total_oportunidades = sum(item["pontuacao"] >= 70 for item in resultados)
        tabela = (
            f"<p class='ok'>{total_oportunidades} item(ns) marcado(s) para avaliação humana, de {len(resultados)} anúncio(s) analisado(s).</p>"
            "<div style='overflow-x:auto'><table><thead><tr><th>Produto</th><th>Preço anunciado</th><th>Lucro estimado</th><th>Margem</th><th>Sinal</th></tr></thead>"
            f"<tbody>{''.join(linhas)}</tbody></table></div>"
        )
    elif not erro and "q" in argumentos:
        tabela = "<p class='warn'>Nenhum anúncio utilizável foi encontrado para essa busca.</p>"
    else:
        tabela = "<p class='warn'>Informe o custo de compra e inicie a primeira análise.</p>"

    return f"""
    <style>
      .scanner-form {{ display:grid; gap:12px; max-width:620px; }}
      .scanner-form label {{ display:grid; gap:5px; font-weight:bold; }}
      .scanner-form input {{ box-sizing:border-box; padding:10px; border-radius:6px; border:1px solid #555; background:#101010; color:#eee; font-size:16px; }}
      table {{ width:100%; border-collapse:collapse; margin-top:16px; }}
      th, td {{ padding:10px; border-bottom:1px solid #444; text-align:left; vertical-align:top; }}
      th {{ color:#ffcc00; }} a {{ color:#78adff; }} small {{ color:#bbb; font-weight:normal; }}
    </style>
    <div class='card'>
      <h1>Scanner de Ferramentas</h1>
      <p>Analisa anúncios públicos de ferramentas leves e estima margem a partir do seu custo. Não compra, publica nem altera anúncios.</p>
      <form class='scanner-form' method='post' action='/scanner/ferramentas'>
        <input type='hidden' name='csrf_token' value='{csrf_token}'>
        <label>Produto ou termo de busca
          <input name='q' value='{consulta}' minlength='2' maxlength='80' required>
        </label>
        <label>Seu custo de compra por unidade (R$)
          <input name='custo' value='{custo}' inputmode='decimal' required>
        </label>
        <label>Taxa estimada do Mercado Livre (%)
          <input name='taxa' value='{taxa}' inputmode='decimal' required>
        </label>
        <label>Reserva de frete por unidade quando houver frete grátis (R$)
          <input name='frete' value='{frete}' inputmode='decimal' required>
        </label>
        <button class='button' type='submit'>Analisar oportunidades</button>
      </form>
      <p><small>Estimativa inicial: confirme custos, frete, impostos, fornecedor, qualidade e regras da categoria antes de comprar estoque.</small></p>
      {aviso_erro}
      {tabela}
      <a class='button' href='/'>Voltar</a>
    </div>
    """


@app.route("/scanner/ferramentas", methods=["GET", "POST"])
def scanner_ferramentas():
    if request.method == "GET":
        return pagina(pagina_scanner_ferramentas({}))

    argumentos = request.form.to_dict(flat=True)
    token_recebido = argumentos.pop("csrf_token", "")
    if not token_recebido or not secrets.compare_digest(token_recebido, session.get("scanner_csrf_token", "")):
        return pagina(pagina_scanner_ferramentas(argumentos, erro="A sessão do formulário expirou. Atualize a página e tente novamente.")), 400
    if "q" not in argumentos:
        return pagina(pagina_scanner_ferramentas(argumentos))
    try:
        parametros = parametros_scanner(argumentos)
        resultados = buscar_oportunidades_ferramentas(parametros)
    except (ValueError, RuntimeError) as erro:
        return pagina(pagina_scanner_ferramentas(argumentos, erro=str(erro))), 400
    return pagina(pagina_scanner_ferramentas(argumentos, resultados=resultados))


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


