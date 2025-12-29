import os
from cryptography.fernet import Fernet

#gera chave simétrica e guarda em ficheiro
def gerar_chave_simetrica(caminho_ficheiro="chave_simetrica.key"):

    if os.path.exists(caminho_ficheiro): 
        print(f"[!] O ficheiro de chave '{caminho_ficheiro}' já existe. Não foi gerada nova chave.")
        return
    
    chave = Fernet.generate_key()

    with open(caminho_ficheiro, "wb") as f:
        f.write(chave)

    print(f"[+] Chave simétrica gerada e guardada em {caminho_ficheiro}")

#carrega chave simétrica de ficheiro

def carregar_chave_simetrica(caminho_ficheiro="chave_simetrica.key"):

    if not os.path.isfile(caminho_ficheiro):
        raise FileNotFoundError(
            f" Ficheiro de chave não encontrado: {caminho_ficheiro}"
            f"Primeiro gere a chave com gerar_chave_simetrica()."
        )
    
    with open(caminho_ficheiro, "rb") as f:
        chave = f.read().strip()

    return Fernet(chave)

# recebe text (string) e devolve texto cifrado (bytes)
def cifrar_mensagem(fernet, texto):
    if isinstance(texto, str):
        texto = texto.encode("utf-8")
    else:
        dados = texto

    token = fernet.encrypt(dados)
    return token

# recebe bytes cifrados e devolve texto original (string)
def decifrar_mensagem(dados_cifrados, fernet):

    if dados_cifrados is None:
        return None
    
    if isinstance(dados_cifrados, str):
        token = dados_cifrados.encode("utf-8")
    else:
        token = dados_cifrados
    try:
        texto_bytes = fernet.decrypt(token)
        return texto_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return None