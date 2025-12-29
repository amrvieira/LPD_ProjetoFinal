import socket
import getpass
from seguranca_mensagens import (
    carregar_chave_simetrica,
    cifrar_mensagem,
    decifrar_mensagem,
)


# Permite escrever mensagens em várias linhas
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


def efectuar_login(cliente, fernet):
    """
    Pede ao utilizador username e password e envia-as ao servidor,
    cifradas, num comando LOGIN.
    """

    username = input("Nome de utilizador: ").strip()
    password = getpass.getpass("Password: ")

    if not username or not password:
        print("[ERRO] Username ou password vazios.")
        return None

    comando_login = f"LOGIN {username} {password}"

    # AQUI assumimos que 'fernet' é um OBJETO Fernet
    token_login = cifrar_mensagem(comando_login, fernet)
    cliente.sendall(token_login)

    # Aguarda resposta
    dados_resposta = cliente.recv(4096)
    if not dados_resposta:
        print("[ERRO] Servidor não respondeu ao login.")
        return None

    texto = decifrar_mensagem(dados_resposta, fernet)
    if texto is None:
        print("[ERRO] Não foi possível decifrar resposta ao login.")
        return None

    texto = texto.strip()
    if texto.upper().startswith("LOGIN_OK"):
        print("[OK] Autenticação bem sucedida.")
        return username

    print(f"[ERRO] Login falhou: {texto}")
    return None


# Liga-se ao servidor de mensagens e inicia conversa (canal cifrado)
def ligar_ao_servidor(endereco_servidor, porta_servidor, fernet):

    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        print(f"[+] A ligar ao servidor {endereco_servidor}:{porta_servidor}...")
        cliente.connect((endereco_servidor, porta_servidor))
        print("[+] Ligação estabelecida.\n")

        # Recebe mensagem inicial do servidor (cifrada)
        try:
            dados_iniciais = cliente.recv(4096)
            if dados_iniciais:
                texto_inicial = decifrar_mensagem(dados_iniciais, fernet)
                if texto_inicial is not None:
                    print(texto_inicial)
        except Exception:
            pass

        # Fase de login
        username = efectuar_login(cliente, fernet)
        if username is None:
            print("[*] Sessão terminada por falha de autenticação.")
            return

        # Ciclo principal de envio de mensagens
        while True:
            mensagem = ler_mensagem_multilinha(f"{username}")

            if not mensagem:
                print("[*] Mensagem vazia, nada enviado.")
                continue

            # Envia mensagem cifrada ao servidor
            token_envio = cifrar_mensagem(mensagem, fernet)
            cliente.sendall(token_envio)

            if mensagem.upper() == "SAIR":
                print("[*] A terminar ligação com o servidor.")
                break

            # Aguarda resposta do servidor (cifrada)
            dados_resposta = cliente.recv(4096)
            if not dados_resposta:
                print("[*] Servidor fechou a ligação.")
                break

            resposta = decifrar_mensagem(dados_resposta, fernet)
            if resposta is None:
                print("[ERRO] Não foi possível decifrar a resposta do servidor.")
                break

            resposta = resposta.strip()
            print("[Servidor]")
            print(resposta)
            print("-" * 40)

            if resposta.upper() == "SAIR":
                print("[*] Servidor terminou a sessão.")
                break

    except ConnectionRefusedError:
        print("[ERRO] Não foi possível ligar ao servidor.")
    except KeyboardInterrupt:
        print("\n[!] Ligação encerrada pelo utilizador.")
    finally:
        cliente.close()
        print("[*] Ligação encerrada.")


def main():
    print("=== Cliente de Mensagens (cifrado + multiutilizador) ===")

    endereco = input("Endereço IP do servidor (ex: 127.0.0.1): ").strip()
    if not endereco:
        print("[ERRO] Endereço IP inválido.")
        return

    texto_porta = input("Porta do servidor (ex: 5000): ").strip()
    try:
        porta = int(texto_porta)
    except ValueError:
        print("[ERRO] Porta inválida.")
        return

    caminho_chave = "chave_simetrica.key"
    try:
        fernet = carregar_chave_simetrica(caminho_chave)
    except Exception as erro:
        print(f"[ERRO] Não foi possível carregar a chave simétrica: {erro}")
        return

    # DEBUG opcional: confirma tipo de fernet
    # print("[DEBUG] Tipo de fernet no cliente:", type(fernet))

    ligar_ao_servidor(endereco, porta, fernet)


if __name__ == "__main__":
    main()

    
    

