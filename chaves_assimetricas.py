import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def gerar_par_chaves_utilizador(nome_utilizador, pasta_chaves="chaves_utilizadores", password_privada=None):
    """
    Gera um par de chaves RSA para um utilizador e guarda-as em ficheiros PEM.
    - chave privada:  nome_utilizador_priv.pem
    - chave pública:  nome_utilizador_pub.pem

    Se 'password_privada' for fornecida, a chave privada é guardada cifrada.
    """

    os.makedirs(pasta_chaves, exist_ok=True)

    caminho_priv = os.path.join(pasta_chaves, f"{nome_utilizador}_priv.pem")
    caminho_pub = os.path.join(pasta_chaves, f"{nome_utilizador}_pub.pem")

    if os.path.exists(caminho_priv) or os.path.exists(caminho_pub):
        print(f"[AVISO] Já existem chaves para o utilizador '{nome_utilizador}'. Nada foi gerado.")
        return caminho_priv, caminho_pub

    # Gera chave privada RSA 2048 bits
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Extrai chave pública
    chave_publica = chave_privada.public_key()

    # Serializa a chave privada
    if password_privada:
        algoritmo_encriptacao = serialization.BestAvailableEncryption(password_privada.encode("utf-8"))
    else:
        algoritmo_encriptacao = serialization.NoEncryption()

    pem_priv = chave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,    # <-- isto estava errado antes
        encryption_algorithm=algoritmo_encriptacao,
    )

    with open(caminho_priv, "wb") as f:
        f.write(pem_priv)

    # Serializa a chave pública
    pem_pub = chave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(caminho_pub, "wb") as f:
        f.write(pem_pub)

    print(f"[OK] Par de chaves RSA gerado para o utilizador '{nome_utilizador}'.")
    print(f"     Chave privada: {caminho_priv}")
    print(f"     Chave pública: {caminho_pub}")

    return caminho_priv, caminho_pub


def carregar_chave_publica(caminho_chave_publica):
    """
    Carrega uma chave pública RSA a partir de um ficheiro PEM.
    """
    with open(caminho_chave_publica, "rb") as f:
        dados = f.read()
    chave_publica = serialization.load_pem_public_key(dados)
    return chave_publica


def carregar_chave_privada(caminho_chave_privada, password=None):
    """
    Carrega uma chave privada RSA a partir de um ficheiro PEM.
    Se a chave estiver cifrada, a 'password' deve ser fornecida.
    """
    with open(caminho_chave_privada, "rb") as f:
        dados = f.read()

    if password is not None:
        password_bytes = password.encode("utf-8")
    else:
        password_bytes = None

    chave_privada = serialization.load_pem_private_key(
        dados,
        password=password_bytes,
    )
    return chave_privada


def cifrar_com_chave_publica(texto, caminho_chave_publica):
    """
    Cifra um texto (string) usando a chave pública RSA.
    Devolve bytes cifrados.
    """
    chave_publica = carregar_chave_publica(caminho_chave_publica)

    if isinstance(texto, str):
        dados = texto.encode("utf-8")
    else:
        dados = texto

    dados_cifrados = chave_publica.encrypt(
        dados,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return dados_cifrados


def decifrar_com_chave_privada(dados_cifrados, caminho_chave_privada, password=None):
    """
    Decifra bytes cifrados com a chave pública correspondente,
    utilizando a chave privada RSA.
    Devolve o texto (string) ou None em caso de erro.
    """
    try:
        chave_privada = carregar_chave_privada(caminho_chave_privada, password=password)
        dados_decifrados = chave_privada.decrypt(
            dados_cifrados,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return dados_decifrados.decode("utf-8", errors="ignore")
    except Exception as erro:
        print(f"[ERRO] Falha ao decifrar com a chave privada: {erro}")
        return None
