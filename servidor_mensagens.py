import os
import socket
import base64
from datetime import datetime

from seguranca_mensagens import (
    carregar_chave_simetrica,
    cifrar_mensagem,
    decifrar_mensagem,
)
from gestao_utilizadores import autenticar_utilizador
from chaves_assimetricas import cifrar_com_chave_publica


# Permite ao operador do servidor escrever em várias linhas
def ler_mensagem_multilinha(rotulo):
    print(f"{rotulo} - escreve a tua mensagem (linha vazia para terminar):")
    linhas = []
    while True:
        linha = input()
        if linha == "":
            break
        linhas.append(linha)
    mensagem = "\n".join(linhas).strip()
    return mensagem


def arquivar_mensagem(username, texto, caminho_chave_publica, direcao="cliente"):
    """
    Arquiva uma mensagem cifrada com a chave pública do utilizador.
    Guarda num ficheiro de texto, apenas no lado do servidor.

    Formato de cada linha:
      TIMESTAMP | DIRECAO | DADOS_CIFRADOS_BASE64
    """
    os.makedirs("arquivos_mensagens", exist_ok=True)
    caminho_ficheiro = os.path.join("arquivos_mensagens", f"{username}.log")

    # Cifrar conteúdo com RSA (chave pública do utilizador)
    dados_cifrados = cifrar_com_chave_publica(texto, caminho_chave_publica)
    dados_b64 = base64.b64encode(dados_cifrados).decode("ascii")

    timestamp = datetime.now().isoformat(timespec="seconds")
    linha = f"{timestamp}|{direcao}|{dados_b64}\n"

    with open(caminho_ficheiro, "a", encoding="utf-8") as f:
        f.write(linha)


def tratar_cliente(socket_cliente, fernet):
    """
    Gere a sessão com um cliente:
      1) Envia mensagem de boas-vindas (cifrada);
      2) Recebe credenciais e autentica o utilizador;
      3) Troca mensagens cifradas;
      4) Arquiva todas as mensagens no servidor usando RSA (chave pública do utilizador).
    """

    mensagem_boas_vindas = (
        "Ligação estabelecida com o servidor (canal cifrado).\n"
        "Por favor autentica-te com o teu nome de utilizador e password.\n"
        "O formato de login é: LOGIN <utilizador> <password>\n"
        "Depois poderás trocar mensagens seguras.\n"
        "Para terminar a sessão, escreve SAIR.\n"
    )
    token_boas_vindas = cifrar_mensagem(mensagem_boas_vindas, fernet)
    socket_cliente.sendall(token_boas_vindas)

    # === Fase 1: autenticação do utilizador ===
    dados_login = socket_cliente.recv(4096)
    if not dados_login:
        print("[*] Cliente desligou-se antes de enviar credenciais.")
        return

    texto_login = decifrar_mensagem(dados_login, fernet)
    if texto_login is None:
        print("[ERRO] Não foi possível decifrar as credenciais recebidas.")
        return

    texto_login = texto_login.strip()
    # Esperamos algo do género: LOGIN username password
    partes = texto_login.split()
    if len(partes) < 3 or partes[0].upper() != "LOGIN":
        print("[ERRO] Formato de login inválido.")
        mensagem_erro = "Formato de login inválido. Usa: LOGIN <utilizador> <password>."
        socket_cliente.sendall(cifrar_mensagem(mensagem_erro, fernet))
        return

    username = partes[1]
    password = " ".join(partes[2:])  # junta o resto como password

    registo = autenticar_utilizador(username, password)
    if registo is None:
        print(f"[ERRO] Falha de autenticação para o utilizador '{username}'.")
        msg = "Autenticação falhou. Verifica o utilizador e a password."
        socket_cliente.sendall(cifrar_mensagem(msg, fernet))
        return

    print(f"[OK] Utilizador autenticado: {username}")
    socket_cliente.sendall(cifrar_mensagem("LOGIN_OK", fernet))

    caminho_chave_publica = registo.get("chave_publica")

    # === Fase 2: troca de mensagens cifradas e arquivo ===
    while True:
        dados_cifrados = socket_cliente.recv(4096)

        if not dados_cifrados:
            print(f"[*] Cliente {username} terminou a ligação.")
            break

        texto_recebido = decifrar_mensagem(dados_cifrados, fernet)
        if texto_recebido is None:
            print("[ERRO] Não foi possível decifrar a mensagem recebida.")
            break

        texto_recebido = texto_recebido.strip()

        if texto_recebido.upper() == "SAIR":
            print(f"[*] Utilizador {username} pediu para terminar a sessão.")
            break

        print(f"Mensagem recebida de {username}:")
        print(texto_recebido)
        print("-" * 40)

        # Arquivar mensagem do cliente
        try:
            arquivar_mensagem(username, texto_recebido, caminho_chave_publica, direcao="cliente")
        except Exception as erro:
            print(f"[AVISO] Não foi possível arquivar a mensagem do cliente: {erro}")

        # Resposta do operador do servidor
        resposta = ler_mensagem_multilinha(f"Servidor para {username}")

        if not resposta:
            print("[*] Mensagem vazia, nada enviado.")
            continue

        if resposta.upper() == "SAIR":
            token_sair = cifrar_mensagem("SAIR", fernet)
            socket_cliente.sendall(token_sair)
            print("[*] Servidor solicitou fim de sessão.")
            break

        # Enviar resposta cifrada
        token_resposta = cifrar_mensagem(resposta, fernet)
        socket_cliente.sendall(token_resposta)

        # Arquivar resposta do servidor
        try:
            arquivar_mensagem(username, resposta, caminho_chave_publica, direcao="servidor")
        except Exception as erro:
            print(f"[AVISO] Não foi possível arquivar a mensagem do servidor: {erro}")


def iniciar_servidor(host="0.0.0.0", porta=5000, fernet=None):
    if fernet is None:
        raise ValueError("Objeto Fernet inválido (chave simétrica não carregada).")

    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind((host, porta))
    servidor.listen(1)

    print(f"Servidor de mensagens (cifrado + multiutilizador) iniciado em {host}:{porta}")
    print("A aguardar ligação...\n")

    try:
        while True:
            socket_cliente, endereco_cliente = servidor.accept()
            print(f"[+] Cliente ligado {endereco_cliente[0]}:{endereco_cliente[1]}")

            try:
                tratar_cliente(socket_cliente, fernet)
            except Exception as erro:
                print(f"[ERRO] Ocorreu um problema com o cliente: {erro}")
            finally:
                print("[*] Ligação terminada.\n")
                socket_cliente.close()
                print("A aguardar nova ligação...\n")

    except KeyboardInterrupt:
        print("\n[!] Servidor encerrado pelo utilizador.")
    finally:
        servidor.close()
        print("[*] Servidor encerrado.")


def main():
    print("=== Servidor de Mensagens (cifrado + multiutilizador) ===")
    texto_porta = input("Porta para o servidor (predefinida 5000): ").strip()
    if texto_porta:
        try:
            porta = int(texto_porta)
        except ValueError:
            print("[ERRO] Porta inválida. A usar porta predefinida 5000.")
            porta = 5000
    else:
        porta = 5000

    caminho_chave = "chave_simetrica.key"
    try:
        fernet = carregar_chave_simetrica(caminho_chave)
    except Exception as erro:
        print(f"[ERRO] Não foi possível carregar a chave simétrica: {erro}")
        return

    iniciar_servidor(porta=porta, fernet=fernet)


if __name__ == "__main__":
    main()
