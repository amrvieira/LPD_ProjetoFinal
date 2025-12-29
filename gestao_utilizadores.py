import os
import json
import hashlib
from chaves_assimetricas import gerar_par_chaves_utilizador

CAMINHO_BD_UTILIZADORES = "utilizadores.json"


def _ler_bd_utilizadores():
    """
    Lê a base de dados de utilizadores (ficheiro JSON).
    Se não existir, devolve um dicionário vazio.
    """
    if not os.path.isfile(CAMINHO_BD_UTILIZADORES):
        return {}

    with open(CAMINHO_BD_UTILIZADORES, "r", encoding="utf-8") as f:
        try:
            dados = json.load(f)
        except json.JSONDecodeError:
            return {}

    return dados


def _escrever_bd_utilizadores(dados):
    """
    Escreve o dicionário de utilizadores no ficheiro JSON.
    """
    with open(CAMINHO_BD_UTILIZADORES, "w", encoding="utf-8") as f:
        json.dump(dados, f, indent=2, ensure_ascii=False)


def _hash_password(password):
    """
    Calcula o hash SHA-256 de uma password (string).
    Nota: para produção, seria melhor usar algo com salt + KDF,
    mas para ambiente académico SHA-256 serve para ilustrar o conceito.
    """
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def criar_utilizador(username, password, pasta_chaves="chaves_utilizadores"):
    """
    Cria um novo utilizador:
      - Gera par de chaves RSA;
      - Guarda a password com hash;
      - Regista o caminho da chave pública.
    """
    username = username.strip()

    if not username:
        print("[ERRO] Username inválido.")
        return

    if not password:
        print("[ERRO] Password não pode ser vazia.")
        return

    bd = _ler_bd_utilizadores()

    if username in bd:
        print(f"[AVISO] Já existe um utilizador com o nome '{username}'.")
        return

    # Gera par de chaves para o utilizador
    caminho_priv, caminho_pub = gerar_par_chaves_utilizador(username, pasta_chaves=pasta_chaves)

    registo = {
        "username": username,
        "password_hash": _hash_password(password),
        "chave_publica": caminho_pub,
        "chave_privada": caminho_priv,  # útil para documentação / ferramentas de consulta
    }

    bd[username] = registo
    _escrever_bd_utilizadores(bd)

    print(f"[OK] Utilizador '{username}' criado e registado com sucesso.")


def autenticar_utilizador(username, password):
    """
    Verifica se o username e password correspondem a um utilizador válido.
    Devolve o dicionário de dados do utilizador se correto, ou None se falhar.
    """
    bd = _ler_bd_utilizadores()

    if username not in bd:
        print("[ERRO] Utilizador não encontrado.")
        return None

    registo = bd[username]
    password_hash = _hash_password(password)

    if password_hash != registo.get("password_hash"):
        print("[ERRO] Password incorreta.")
        return None

    return registo

