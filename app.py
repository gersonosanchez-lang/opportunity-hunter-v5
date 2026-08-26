import os
import time
import secrets
import hashlib
import base64
import html
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
# ARMAZENAMENTO TEMPORÁRIO
# ============================================================

TOKEN_DATA = {}


# ============================================================
# HTML BASE
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

{{conteudo}}

</div>

</body>

</html>
"""


# ============================================================
# FUNÇÃO PARA RENDERIZAR PÁGINAS
# ============================================================

def pagina(conteudo):

    return render_template_string(
        HTML_BASE,
        conteudo=conteudo
    )


# ============================================================
# VERIFICAR CONFIGURAÇÃO
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
# TOKEN
# ============================================================

def token_valido():

    if not TOKEN_DATA:
        return False

    access_token = TOKEN_DATA.get(
        "access_token"
    )

    if not access_token:
        return False

    expires_at = TOKEN_DATA.get(
        "expires_at",
        0
    )

    return time.time() < expires_at


def limpar_token():

    TOKEN_DATA.clear()


# ============================================================
# REFRESH TOKEN
# ============================================================

def refresh_access_token():

    refresh_token = TOKEN_DATA.get(
        "refresh_token"
    )

    if not refresh_token:

        return False, {
            "erro":
                "Não existe refresh_token armazenado."
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

    expires_in = int(
        dados_resposta.get(
            "expires_in",
            0
        )
    )

    TOKEN_DATA.clear()

    TOKEN_DATA.update({

        "access_token":
            novo_access_token,

        "refresh_token":
            novo_refresh_token,

        "token_type":
            dados_resposta.get(
                "token_type"
            ),

        "expires_in":
            expires_in,

        "scope":
            dados_resposta.get(
                "scope"
            ),

        "user_id":
            dados_resposta.get(
                "user_id"
            ),

        "expires_at":
            time.time()
            + expires_in
    })

    return True, TOKEN_DATA


# ============================================================
# PÁGINA PRINCIPAL
# ============================================================

@app.get("/")
def inicio():

    if not configuracao_ok():

        conteudo = """
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
        """

        return pagina(conteudo)

    conectado = bool(
        TOKEN_DATA.get(
            "access_token"
        )
    )

    if conectado:

        status = (
            '<span class="ok">'
            'Conectado'
            '</span>'
        )

    else:

        status = (
            '<span class="warn">'
            'Não conectado'
            '</span>'
        )

    conteudo = f"""
    <div class="card">

        <h1>Opportunity Hunter</h1>

        <h2>Gateway Mercado Livre</h2>

        <p>
            Status: {status}
        </p>

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

    </div>
    """

    return pagina(conteudo)


# ============================================================
# SAÚDE
# ============================================================

@app.get("/saúde")
@app.get("/saude")
def saude():

    return {

        "OK":
            True,

        "serviço":
            "Portal do Caçador de Oportunidades",

        "tempo":
            int(time.time()),

        "oauth_configurado":
            configuracao_ok(),

        "mercado_livre_conectado":
            bool(
                TOKEN_DATA.get(
                    "access_token"
                )
            )

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

        verifier = gerar_code_verifier()

        challenge = gerar_code_challenge(
            verifier
        )

        session["code_verifier"] = verifier

        parametros["code_challenge"] = challenge

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

            </div>
            """), 400

        dados["code_verifier"] = verifier

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

        dados_token = resposta.json()

    except Exception:

        dados_token = {
            "resposta":
                resposta.text
        }

    if resposta.status_code != 200:

        return pagina(f"""
        <div class="card">

            <h2>
                Mercado Livre recusou
                a autorização
            </h2>

            <p class="error">
                Não foi possível trocar o código
                pelo access token.
            </p>

            <p>
                HTTP:
                {resposta.status_code}
            </p>

            <pre>{html.escape(
                str(dados_token)
            )}</pre>

            <a
                class="button"
                href="/"
            >
                Voltar
            </a>

        </div>
        """), 400

    expires_in = int(
        dados_token.get(
            "expires_in",
            0
        )
    )

    TOKEN_DATA.clear()

    TOKEN_DATA.update({

        "access_token":
            dados_token.get(
                "access_token"
            ),

        "refresh_token":
            dados_token.get(
                "refresh_token"
            ),

        "token_type":
            dados_token.get(
                "token_type"
            ),

        "expires_in":
            expires_in,

        "scope":
            dados_token.get(
                "scope"
            ),

        "user_id":
            dados_token.get(
                "user_id"
            ),

        "expires_at":
            time.time()
            + expires_in
    })

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

    conectado = bool(
        TOKEN_DATA.get(
            "access_token"
        )
    )

    return jsonify({

        "oauth_configurado":
            configuracao_ok(),

        "conectado":
            conectado,

        "user_id":
            TOKEN_DATA.get(
                "user_id"
            ),

        "scope":
            TOKEN_DATA.get(
                "scope"
            ),

        "expires_in":
            TOKEN_DATA.get(
                "expires_in"
            ),

        "token_valido":
            token_valido()

    })


# ============================================================
# TESTAR CONTA MERCADO LIVRE
# ============================================================

@app.get("/api/me")
def api_me():

    if not token_valido():

        sucesso, resultado = (
            refresh_access_token()
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

    access_token = TOKEN_DATA.get(
        "access_token"
    )

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

        return jsonify({

            "OK":
                False,

            "status":
                resposta.status_code,

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
            "Token atualizado.",

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

    limpar_token()

    session.pop(
        "oauth_state",
        None
    )

    session.pop(
        "code_verifier",
        None
    )

    return pagina("""
    <div class="card">

        <h2>Mercado Livre desconectado</h2>

        <p>
            O token armazenado em memória
            foi removido.
        </p>

        <a
            class="button"
            href="/"
        >
            Voltar
        </a>

    </div>
    """), 200


# ============================================================
# EXECUÇÃO LOCAL
# ============================================================

if __name__ == "__main__":

    porta = int(
        os.environ.get(
            "PORT",
            "10000"
        )
    )

    app.run(
        host="0.0.0.0",
        port=porta
    )
