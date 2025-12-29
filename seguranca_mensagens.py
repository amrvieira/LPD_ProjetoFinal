import os
from cryptography.fernet import Fernet


def gerar_chave_simetrica(caminho_ficheiro="chave_simetrica.key"):
    """
    Gera uma nova chave simétrica (Fernet) e guarda-a num ficheiro.
    Só deve ser usada uma vez para criar a chave partilhada.
    """

    if os.path.exists(caminho_ficheiro):
        print(f"[AVISO] O ficheiro de chave '{caminho_ficheiro}' já existe. Não foi gerada nova chave.")
        return

    chave = Fernet.generate_key()

    with open(caminho_ficheiro, "wb") as f:
        f.write(chave)

    print(f"[OK] Chave simétrica gerada e guardada em: {caminho_ficheiro}")


def carregar_chave_simetrica(caminho_ficheiro="chave_simetrica.key"):
    """
    Carrega a chave simétrica a partir de um ficheiro
    e devolve um objeto Fernet pronto a usar.
    """

    if not os.path.isfile(caminho_ficheiro):
        raise FileNotFoundError(
            f"Ficheiro de chave não encontrado: {caminho_ficheiro}. "
            f"Primeiro gera a chave com gerar_chave_simetrica()."
        )

    with open(caminho_ficheiro, "rb") as f:
        chave = f.read().strip()

    return Fernet(chave)


def _obter_fernet(fernet_ou_chave):
    """
    Função interna de apoio.

    Garante que, independentemente do que for passado (objeto Fernet, chave
    em bytes/string ou até caminho para ficheiro), devolvemos SEMPRE um
    objeto Fernet válido.
    """

    # Caso ideal: já é um objeto Fernet
    if hasattr(fernet_ou_chave, "encrypt") and hasattr(fernet_ou_chave, "decrypt"):
        return fernet_ou_chave

    # Se for string e corresponder a um ficheiro existente, assumimos que é
    # o caminho para o ficheiro de chave.
    if isinstance(fernet_ou_chave, str) and os.path.isfile(fernet_ou_chave):
        with open(fernet_ou_chave, "rb") as f:
            chave = f.read().strip()
        return Fernet(chave)

    # Caso contrário, assumimos que é a própria chave (em str ou bytes)
    if isinstance(fernet_ou_chave, str):
        chave_bytes = fernet_ou_chave.encode("utf-8")
    else:
        chave_bytes = fernet_ou_chave

    return Fernet(chave_bytes)


def cifrar_mensagem(texto, fernet_ou_chave):
    """
    Recebe um texto (string) e devolve bytes cifrados com a chave Fernet.

    Aceita:
      - objeto Fernet,
      - chave em bytes/string,
      - caminho para o ficheiro de chave.
    """

    f = _obter_fernet(fernet_ou_chave)

    if isinstance(texto, str):
        dados = texto.encode("utf-8")
    else:
        dados = texto

    token = f.encrypt(dados)
    return token


def decifrar_mensagem(dados_cifrados, fernet_ou_chave):
    """
    Recebe bytes cifrados e devolve o texto original (string).
    Se a desencriptação falhar, devolve None.

    Aceita:
      - objeto Fernet,
      - chave em bytes/string,
      - caminho para o ficheiro de chave.
    """

    if dados_cifrados is None:
        return None

    f = _obter_fernet(fernet_ou_chave)

    if isinstance(dados_cifrados, str):
        token = dados_cifrados.encode("utf-8")
    else:
        token = dados_cifrados

    try:
        texto_bytes = f.decrypt(token)
        return texto_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return None
