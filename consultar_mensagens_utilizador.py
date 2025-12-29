import os
import base64

from chaves_assimetricas import decifrar_com_chave_privada


def pedir_caminho_ficheiro(pergunta, predefinido=None):
    """
    Pede ao utilizador um caminho para ficheiro.
    Se o utilizador carregar só Enter, usa o valor predefinido (se existir).
    Valida se o ficheiro existe.
    """
    while True:
        if predefinido:
            texto = input(f"{pergunta} [{predefinido}]: ").strip()
            if not texto:
                texto = predefinido
        else:
            texto = input(f"{pergunta}: ").strip()

        if not texto:
            print("[ERRO] Caminho inválido.\n")
            continue

        if not os.path.isfile(texto):
            print(f"[ERRO] O ficheiro '{texto}' não existe.\n")
            continue

        return texto


def ler_registos_arquivo(caminho_arquivo):
    """
    Lê o ficheiro de arquivo de mensagens de um utilizador.

    Cada linha tem o formato:
      TIMESTAMP|DIRECAO|BASE64_DA_MENSAGEM_CIFRADA

    Devolve uma lista de dicionários com esses campos.
    """
    registos = []

    with open(caminho_arquivo, "r", encoding="utf-8", errors="ignore") as f:
        for linha in f:
            linha = linha.strip()
            if not linha:
                continue

            partes = linha.split("|", 2)
            if len(partes) != 3:
                # linha inesperada, ignoramos
                continue

            timestamp, direcao, dados_b64 = partes
            registos.append(
                {
                    "timestamp": timestamp,
                    "direcao": direcao,
                    "dados_b64": dados_b64,
                }
            )

    return registos


def consultar_mensagens():
    print("=== Consulta de Mensagens Arquivadas (por utilizador) ===\n")

    username = input("Nome de utilizador a consultar (ex.: antonio): ").strip()
    if not username:
        print("[ERRO] Nome de utilizador inválido.")
        return

    # Caminho predefinido para o ficheiro de arquivo desse utilizador
    caminho_arquivo_predef = os.path.join("arquivos_mensagens", f"{username}.log")

    caminho_arquivo = pedir_caminho_ficheiro(
        "Caminho para o ficheiro de arquivo de mensagens",
        predefinido=caminho_arquivo_predef if os.path.isfile(caminho_arquivo_predef) else None,
    )

    # Caminho predefinido para chave privada desse utilizador
    caminho_priv_predef = os.path.join("chaves_utilizadores", f"{username}_priv.pem")

    caminho_chave_privada = pedir_caminho_ficheiro(
        "Caminho para a chave privada do utilizador (ficheiro .pem)",
        predefinido=caminho_priv_predef if os.path.isfile(caminho_priv_predef) else None,
    )

    # Para já assumimos que a chave privada NÃO está protegida com password
    # Se quiseres, mais tarde podemos pedir password aqui.
    password_chave = None

    registos = ler_registos_arquivo(caminho_arquivo)
    if not registos:
        print("\n[INFO] Não foram encontrados registos válidos de mensagens neste ficheiro.")
        return

    print("\n=== Mensagens decifradas para o utilizador", username, "===\n")

    total_ok = 0
    total_falha = 0

    for reg in registos:
        timestamp = reg["timestamp"]
        direcao = reg["direcao"]
        dados_b64 = reg["dados_b64"]

        try:
            dados_cifrados = base64.b64decode(dados_b64)
        except Exception:
            print(f"[AVISO] Linha com Base64 inválido em {timestamp}, ignorada.")
            total_falha += 1
            continue

        texto = decifrar_com_chave_privada(
            dados_cifrados,
            caminho_chave_privada,
            password=password_chave,
        )

        if texto is None:
            print(f"[AVISO] Não foi possível decifrar a mensagem em {timestamp}.")
            total_falha += 1
            continue

        total_ok += 1
        print(f"[{timestamp}] ({direcao})")
        print(texto)
        print("-" * 60)

    print("\n=== Resumo ===")
    print(f"Mensagens decifradas com sucesso: {total_ok}")
    print(f"Mensagens que não foi possível decifrar: {total_falha}")
    print("=== Fim da consulta ===\n")


def main():
    consultar_mensagens()


if __name__ == "__main__":
    main()
