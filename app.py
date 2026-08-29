import os
import time
import secrets
import hashlib
import base64
import html
import sqlite3
from urllib.parse import urlencode

import requests
from flask import (
    Flask,
    request,
    redirect,
    render_template_string,
    session,
    jsonify,
)


# ============================================================
# OPPORTUNITY HUNTER V5
# Gateway OAuth - Mercado Livre
# ============================================================

app = Flask(__name__)


# ============================================================
# CONFIGURAÇÃO
# ============================================================

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "ALTERE-ESTA-CHAVE-NO-RENDER"
)

MERCADOLIVRE_APP_ID = os.environ.get(
    "MERCADOLIVRE_APP_ID",
    ""
)

MERCADOLIVRE_CLIENT_SECRET = os.environ.get(
    "MERCADOLIVRE_CLIENT_SECRET",
    ""
)

MERCADOLIVRE_REDIRECT_URI = os.environ.get(
    "MERCADOLIVRE_REDIRECT_URI",
    "https://opportunity-hunter-v5.onrender.com/oauth/callback"
)

MERCADOLIVRE_USE_PKCE = (
    os.environ.get(
        "MERCADOLIVRE_USE_PKCE",
        "false"
    ).lower()
    == "true"
)


AUTH_URL = (
    "https://auth.mercadolivre.com.br/authorization"
)

TOKEN_URL = (
    "https://api.mercadolibre.com/oauth/token"
)

ME_URL = (
    "https://api.mercadolibre.com/users/me"
)


# ============================================================
# BANCO DE DADOS
# ============================================================

# Por enquanto usamos SQLite.
#
# IMPORTANTE:
# No Render gratuito, o arquivo pode ser perdido em um novo
# deploy/restart. Depois podemos configurar armazenamento
# persistente ou PostgreSQL.
#
# O objetivo desta etapa é tirar o token da memória e deixar
# a arquitetura pronta para persistência.
# ============================================================

DATABASE_PATH = os.environ.get(
    "OPPORTUNITY_HUNTER_DB",
    "opportunity_hunter.db"
)


def conectar_banco():

    conexao = sqlite3.connect(
        DATABASE_PATH,
        timeout=30
    )

    conexao.row_factory = sqlite3.Row

    return conexao


def inicializar_banco():

    conexao = conectar_banco()

    try:

        conexao.execute("""
            CREATE TABLE IF NOT EXISTS mercado_livre_token (
                id INTEGER PRIMARY KEY,
                access_token TEXT NOT NULL,
                refresh_token TEXT NOT NULL,
                token_type TEXT,
                expires_in INTEGER,
                scope TEXT,
                user_id TEXT,
                expires_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )
        """)

        conexao.commit()

    finally:

        conexao.close()


# Inicializa o banco quando o aplicativo sobe.
inicializar_banco()


# ============================================================
# HTML
# ============================================================

HTML_BASE = """
<!DOCTYPE html>
<html lang="pt-BR">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>Opportunity Hunter</title>

    <style>

        body {
            margin: 0;
            padding: 20px;
            background: #111;
            color: #eee;
            font-family: Arial, sans-serif;
        }

        .container {
            max-width: 760px;
            margin: auto;
        }

        .card {
            background: #1c1c1c;
            border-radius: 14px;
            padding: 24px;
            margin-bottom: 20px;
            box-shadow: 0 4px 20px rgba(0,0,0,.3);
        }

        h1 {
            margin-top: 0;
        }

        h2 {
            color: #ffcc00;
        }

        .button {
            display: inline-block;
            padding: 14px 20px;
            border-radius: 8px;
            background: #3483fa;
            color: white;
            text-decoration: none;
            margin-top: 10px;
            font-weight: bold;
        }

        .button:hover {
            opacity: .9;
        }

        .ok {
            color: #35d07f;
        }

        .warn {
            color: #ffcc00;
        }

        .error {
            color: #ff5c5c;
        }

        code {
            background: #000;
            padding: 3px 6px;
            border-radius: 5px;
        }

        pre {
            background: #000;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-word;
        }

    </style>

</head>

<body>

<div class="container">

{{conteudo|safe}}

</div>

</body>

</html>
"""


# ============================================================
# PÁGINA
# ============================================================

def pagina(conteudo):

    return render_template_string(
        HTML_BASE,
        conteudo=conteudo
    )


# ============================================================
# CONFIGURAÇÃO
# ============================================================

def configuracao_ok():

    return bool(
        MERCADOLIVRE_APP_ID
        and MERCADOLIVRE_CLIENT_SECRET
        and MERCADOLIVRE_REDIRECT_URI
    )


# ============================================================
# PKCE
# ============================================================

def gerar_code_verifier():

    return secrets.token_urlsafe(64)


def gerar_code_challenge(verifier):

    digest = hashlib.sha256(
        verifier.encode("ascii")
    ).digest()

    return (
        base64.urlsafe_b64encode(digest)
        .rstrip(b"=")
        .decode("ascii")
    )


# ============================================================
# TOKEN - BANCO
# ============================================================

def salvar_token(dados):

    access_token = dados.get(
        "access_token"
    )

    refresh_token = dados.get(
        "refresh_token"
    )

    if not access_token or not refresh_token:

        raise ValueError(
            "Mercado Livre não retornou os tokens necessários."
        )

    expires_in = int(
        dados.get(
            "expires_in",
            0
        )
    )

    expires_at = (
        time.time()
        + expires_in
    )

    agora = time.time()

    conexao = conectar_banco()

    try:

        conexao.execute(
            "DELETE FROM mercado_livre_token"
        )

        conexao.execute("""
            INSERT INTO mercado_livre_token (
                id,
                access_token,
                refresh_token,
                token_type,
                expires_in,
                scope,
                user_id,
                expires_at,
                updated_at
            )
            VALUES (
                1,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?
            )
        """, (
            access_token,
            refresh_token,
            dados.get("token_type"),
            expires_in,
            dados.get("scope"),
            dados.get("user_id"),
            expires_at,
            agora
        ))

        conexao.commit()

    finally:

        conexao.close()


def obter_token():

    conexao = conectar_banco()

    try:

        resultado = conexao.execute("""
            SELECT
                access_token,
                refresh_token,
                token_type,
                expires_in,
                scope,
                user_id,
                expires_at,
                updated_at
            FROM mercado_livre_token
            WHERE id = 1
        """).fetchone()

        if not resultado:

            return None

        return dict(resultado)

    finally:

        conexao.close()


def apagar_token():

    conexao = conectar_banco()

    try:

        conexao.execute(
            "DELETE FROM mercado_livre_token"
        )

        conexao.commit()

    finally:

        conexao.close()


def token_valido():

    token = obter_token()

    if not token:

        return False

    access_token = token.get(
        "access_token"
    )

    if not access_token:

        return False

    expires_at = float(
        token.get(
            "expires_at",
            0
        )
    )

    # Margem de segurança de 60 segundos.
    return time.time() < (
        expires_at - 60
    )


# ============================================================
# REFRESH TOKEN
# ============================================================

def refresh_access_token():

    token = obter_token()

    if not token:

        return False, {
            "erro":
                "Nenhum token armazenado."
        }

    refresh_token = token.get(
        "refresh_token"
    )

    if not refresh_token:

        return False, {
            "erro":
                "Refresh token não encontrado."
        }

    dados = {

        "grant_type":
            "refresh_token",

        "client_id":
            MERCADOLIVRE_APP_ID,

        "client_secret":
            MERCADOLIVRE_CLIENT_SECRET,

        "refresh_token":
            refresh_token
    }

    try:

        resposta = requests.post(
            TOKEN_URL,
            data=dados,
            headers={
                "accept":
                    "application/json",

                "content-type":
                    "application/x-www-form-urlencoded"
            },
            timeout=30
        )

    except requests.RequestException as erro:

        return False, {

            "erro":
                "Falha de comunicação com Mercado Livre.",

            "detalhe":
                str(erro)
        }

    try:

        dados_resposta = resposta.json()

    except Exception:

        dados_resposta = {
            "resposta":
                resposta.text
        }

    if resposta.status_code != 200:

        return False, {

            "erro":
                "Mercado Livre recusou o refresh.",

            "status":
                resposta.status_code,

            "resposta":
                dados_resposta
        }

    novo_access_token = (
        dados_resposta.get(
            "access_token"
        )
    )

    novo_refresh_token = (
        dados_resposta.get(
            "refresh_token"
        )
        or refresh_token
    )

    if not novo_access_token:

        return False, {
            "erro":
                "Mercado Livre não retornou novo access_token."
        }

    dados_salvar = {

        "access_token":
            novo_access_token,

        "refresh_token":
            novo_refresh_token,

        "token_type":
            dados_resposta.get(
                "token_type",
                token.get("token_type")
            ),

        "expires_in":
            dados_resposta.get(
                "expires_in",
                0
            ),

        "scope":
            dados_resposta.get(
                "scope",
                token.get("scope")
            ),

        "user_id":
            dados_resposta.get(
                "user_id",
                token.get("user_id")
            )
    }

    salvar_token(
        dados_salvar
    )

    return True, {
        "user_id":
            dados_salvar.get("user_id"),

        "scope":
            dados_salvar.get("scope"),

        "expires_in":
            dados_salvar.get("expires_in")
    }


# ============================================================
# GARANTIR TOKEN
# ============================================================

def obter_access_token():

    token = obter_token()

    if token and token_valido():

        return True, token.get(
            "access_token"
        )

    if token:

        sucesso, resultado = (
            refresh_access_token()
        )

        if sucesso:

            novo_token = obter_token()

            return True, novo_token.get(
                "access_token"
            )

        return False, resultado

    return False, {
        "erro":
            "Mercado Livre não está conectado."
    }


# ============================================================
# PÁGINA PRINCIPAL
# ============================================================

@app.get("/")
def inicio():

    if not configuracao_ok():

        return pagina("""
        <div class="card">

            <h1>Opportunity Hunter</h1>

            <p class="error">
                O Gateway ainda não está configurado.
            </p>

            <p>
                Configure as variáveis do Mercado Livre
                no Render.
            </p>

            <ul>
                <li>MERCADOLIVRE_APP_ID</li>
                <li>MERCADOLIVRE_CLIENT_SECRET</li>
                <li>MERCADOLIVRE_REDIRECT_URI</li>
                <li>FLASK_SECRET_KEY</li>
            </ul>

        </div>
        """)

    token = obter_token()

    conectado = bool(
        token
        and token.get("access_token")
    )

    if conectado:

        status = (
            '<span class="ok">'
            'Conectado'
            '</span>'
        )

        user_id = html.escape(
            str(
                token.get(
                    "user_id",
                    ""
                )
            )
        )

        informacao = f"""
        <p>
            <strong>User ID:</strong>
            {user_id}
        </p>
        """

    else:

        status = (
            '<span class="warn">'
            'Não conectado'
            '</span>'
        )

        informacao = ""

    conteudo = f"""
    <div class="card">

        <h1>Opportunity Hunter</h1>

        <h2>Gateway Mercado Livre</h2>

        <p>
            Status: {status}
        </p>

        {informacao}

        <a
            class="button"
            href="/oauth/mercadolivre"
        >
            Conectar Mercado Livre
        </a>

        <br>

        <a
            class="button"
            href="/oauth/status"
        >
            Ver status
        </a>

        <br>

        <a
            class="button"
            href="/api/me"
        >
            Testar minha conta
        </a>

        <br>

        <a
            class="button"
            href="/health"
        >
            Ver saúde do Gateway
        </a>

    </div>
    """

    return pagina(conteudo)


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
@app.get("/saude")
def health():

    token = obter_token()

    return {

        "OK":
            True,

        "servico":
            "Opportunity Hunter Gateway",

        "tempo":
            int(time.time()),

        "oauth_configurado":
            configuracao_ok(),

        "mercado_livre_conectado":
            bool(
                token
                and token.get("access_token")
            ),

        "token_valido":
            token_valido()

    }, 200


# ============================================================
# INICIAR OAUTH
# ============================================================

@app.get("/oauth/mercadolivre")
def oauth_mercadolivre():

    if not configuracao_ok():

        return pagina("""
        <div class="card">

            <h2>Configuração incompleta</h2>

            <p class="error">
                As credenciais do Mercado Livre
                não foram configuradas no Render.
            </p>

        </div>
        """), 500

    state = secrets.token_urlsafe(32)

    session["oauth_state"] = state

    parametros = {

        "response_type":
            "code",

        "client_id":
            MERCADOLIVRE_APP_ID,

        "redirect_uri":
            MERCADOLIVRE_REDIRECT_URI,

        "state":
            state
    }

    if MERCADOLIVRE_USE_PKCE:

        verifier = (
            gerar_code_verifier()
        )

        challenge = (
            gerar_code_challenge(
                verifier
            )
        )

        session["code_verifier"] = (
            verifier
        )

        parametros[
            "code_challenge"
        ] = challenge

        parametros[
            "code_challenge_method"
        ] = "S256"

    else:

        session.pop(
            "code_verifier",
            None
        )

    url = (
        AUTH_URL
        + "?"
        + urlencode(parametros)
    )

    return redirect(url)


# ============================================================
# CALLBACK OAUTH
# ============================================================

@app.get("/oauth/callback")
def oauth_callback():

    erro = request.args.get(
        "error",
        ""
    )

    if erro:

        detalhe = html.escape(
            request.args.get(
                "error_description",
                erro
            )
        )

        return pagina(f"""
        <div class="card">

            <h2>Autorização não concluída</h2>

            <p class="error">
                {detalhe}
            </p>

            <a
                class="button"
                href="/"
            >
                Voltar
            </a>

        </div>
        """), 400

    codigo = request.args.get(
        "code",
        ""
    )

    if not codigo:

        return pagina("""
        <div class="card">

            <h2>Retorno inválido</h2>

            <p class="error">
                O Mercado Livre não enviou
                o código de autorização.
            </p>

        </div>
        """), 400

    estado_recebido = request.args.get(
        "state",
        ""
    )

    estado_salvo = session.get(
        "oauth_state",
        ""
    )

    if not estado_salvo:

        return pagina("""
        <div class="card">

            <h2>Estado OAuth ausente</h2>

            <p class="error">
                A sessão OAuth não está mais disponível.
            </p>

            <p>
                Tente iniciar a conexão novamente.
            </p>

        </div>
        """), 400

    if not secrets.compare_digest(
        estado_recebido,
        estado_salvo
    ):

        return pagina("""
        <div class="card">

            <h2>Falha de segurança</h2>

            <p class="error">
                O parâmetro state recebido
                não corresponde ao iniciado
                pelo Gateway.
            </p>

        </div>
        """), 400

    session.pop(
        "oauth_state",
        None
    )

    dados = {

        "grant_type":
            "authorization_code",

        "client_id":
            MERCADOLIVRE_APP_ID,

        "client_secret":
            MERCADOLIVRE_CLIENT_SECRET,

        "code":
            codigo,

        "redirect_uri":
            MERCADOLIVRE_REDIRECT_URI
    }

    if MERCADOLIVRE_USE_PKCE:

        verifier = session.pop(
            "code_verifier",
            None
        )

        if not verifier:

            return pagina("""
            <div class="card">

                <h2>PKCE incompleto</h2>

                <p class="error">
                    O code_verifier não foi encontrado.
                </p>

                <p>
                    Tente iniciar a conexão novamente.
                </p>

            </div>
            """), 400

        dados[
            "code_verifier"
        ] = verifier

    try:

        resposta = requests.post(

            TOKEN_URL,

            data=dados,

            headers={

                "accept":
                    "application/json",

                "content-type":
                    "application/x-www-form-urlencoded"
            },

            timeout=30
        )

    except requests.RequestException as erro:

        return pagina(f"""
        <div class="card">

            <h2>Erro de comunicação</h2>

            <p class="error">
                Não foi possível comunicar
                com o Mercado Livre.
            </p>

            <pre>{html.escape(
                str(erro)
            )}</pre>

        </div>
        """), 502

    try:

        dados_token = (
            resposta.json()
        )

    except Exception:

        dados_token = {
            "resposta":
                resposta.text
        }

    if resposta.status_code != 200:

        # Não mostramos client_secret,
        # access_token ou refresh_token.
        erro_publico = {}

        if isinstance(
            dados_token,
            dict
        ):

            for chave in (
                "error",
                "error_description",
                "message"
            ):

                if chave in dados_token:

                    erro_publico[
                        chave
                    ] = dados_token[chave]

        if not erro_publico:

            erro_publico = {
                "erro":
                    "Mercado Livre recusou a autorização."
            }

        return pagina(f"""
        <div class="card">

            <h2>
                Mercado Livre recusou
                a autorização
            </h2>

            <p class="error">
                Não foi possível concluir
                a conexão.
            </p>

            <p>
                HTTP:
                {resposta.status_code}
            </p>

            <pre>{html.escape(
                str(erro_publico)
            )}</pre>

            <a
                class="button"
                href="/"
            >
                Voltar
            </a>

        </div>
        """), 400

    try:

        salvar_token(
            dados_token
        )

    except Exception as erro:

        return pagina(f"""
        <div class="card">

            <h2>Erro ao salvar conexão</h2>

            <p class="error">
                A autorização foi recebida,
                mas o Gateway não conseguiu
                salvar os dados.
            </p>

            <pre>{html.escape(
                str(erro)
            )}</pre>

        </div>
        """), 500

    user_id = html.escape(
        str(
            dados_token.get(
                "user_id",
                ""
            )
        )
    )

    scope = html.escape(
        str(
            dados_token.get(
                "scope",
                ""
            )
        )
    )

    return pagina(f"""
    <div class="card">

        <h2 class="ok">
            Mercado Livre conectado!
        </h2>

        <p>
            A autorização foi concluída
            com sucesso.
        </p>

        <p>
            <strong>User ID:</strong>
            {user_id}
        </p>

        <p>
            <strong>Escopo:</strong>
            {scope}
        </p>

        <p class="ok">
            O token foi armazenado pelo Gateway.
        </p>

        <a
            class="button"
            href="/api/me"
        >
            Testar conexão
        </a>

        <br>

        <a
            class="button"
            href="/"
        >
            Voltar
        </a>

    </div>
    """)


# ============================================================
# STATUS OAUTH
# ============================================================

@app.get("/oauth/status")
def oauth_status():

    token = obter_token()

    conectado = bool(
        token
        and token.get("access_token")
    )

    resposta = {

        "oauth_configurado":
            configuracao_ok(),

        "conectado":
            conectado,

        "token_valido":
            token_valido(),

        "user_id":
            token.get("user_id")
            if token else None,

        "scope":
            token.get("scope")
            if token else None,

        "expires_in":
            token.get("expires_in")
            if token else None,

        "armazenamento":
            "SQLite"
    }

    return jsonify(
        resposta
    )


# ============================================================
# TESTAR CONTA
# ============================================================

@app.get("/api/me")
def api_me():

    sucesso, resultado = (
        obter_access_token()
    )

    if not sucesso:

        return jsonify({

            "OK":
                False,

            "erro":
                "Mercado Livre não conectado.",

            "detalhes":
                resultado

        }), 401

    access_token = resultado

    if not access_token:

        return jsonify({

            "OK":
                False,

            "erro":
                "Access token não disponível."

        }), 401

    try:

        resposta = requests.get(

            ME_URL,

            headers={

                "Authorization":
                    "Bearer " + access_token
            },

            timeout=30
        )

    except requests.RequestException as erro:

        return jsonify({

            "OK":
                False,

            "erro":
                "Falha ao consultar Mercado Livre.",

            "detalhe":
                str(erro)

        }), 502

    try:

        dados = resposta.json()

    except Exception:

        dados = {
            "resposta":
                resposta.text
        }

    if resposta.status_code != 200:

        # Se o token tiver sido recusado,
        # não expomos o token na resposta.
        return jsonify({

            "OK":
                False,

            "status":
                resposta.status_code,

            "erro":
                "Mercado Livre recusou a consulta.",

            "resposta":
                dados

        }), resposta.status_code

    return jsonify({

        "OK":
            True,

        "mercado_livre":
            dados

    })


# ============================================================
# REFRESH MANUAL
# ============================================================

@app.get("/oauth/refresh")
def oauth_refresh():

    sucesso, resultado = (
        refresh_access_token()
    )

    if not sucesso:

        return jsonify({

            "OK":
                False,

            "resultado":
                resultado

        }), 400

    return jsonify({

        "OK":
            True,

        "mensagem":
            "Token atualizado com sucesso.",

        "user_id":
            resultado.get(
                "user_id"
            ),

        "scope":
            resultado.get(
                "scope"
            ),

        "expires_in":
            resultado.get(
                "expires_in"
            )

    })


# ============================================================
# DESCONECTAR
# ============================================================

@app.get("/oauth/logout")
def oauth_logout():

    apagar_token()

    return pagina("""
    <div class="card">

        <h2>Mercado Livre desconectado</h2>

        <p class="ok">
            Os tokens armazenados pelo Gateway
            foram removidos.
        </p>

        <a
            class="button"
            href="/"
        >
            Voltar
        </a>

    </div>
    """)


# ============================================================
# INFORMAÇÕES DO SISTEMA
# ============================================================

@app.get("/api/system")
def api_system():

    token = obter_token()

    return jsonify({

        "aplicacao":
            "Opportunity Hunter V5",

        "gateway":
            "online",

        "oauth_configurado":
            configuracao_ok(),

        "mercado_livre":
            "conectado"
            if token
            else "não conectado",

        "pkce":
            MERCADOLIVRE_USE_PKCE,

        "armazenamento":
            "SQLite",

        "proxima_fase":
            "Análise de oportunidades"

    })


# ============================================================
# ERROS
# ============================================================

@app.errorhandler(404)
def pagina_404(erro):

    return pagina("""
    <div class="card">

        <h2>Página não encontrada</h2>

        <p class="error">
            O endereço solicitado não existe.
        </p>

        <a
            class="button"
            href="/"
        >
            Voltar ao Opportunity Hunter
        </a>

    </div>
    """), 404


@app.errorhandler(500)
def pagina_500(erro):

    return pagina("""
    <div class="card">

        <h2>Erro interno</h2>

        <p class="error">
            O Gateway encontrou um erro interno.
        </p>

        <a
            class="button"
            href="/"
        >
            Voltar
        </a>

    </div>
    """), 500


# ============================================================
# EXECUÇÃO LOCAL
# ============================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            "10000"
        )
    )

    app.run(
        host="0.0.0.0",
        port=port
    )
