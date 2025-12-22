import socket

#permite mensagens em varias linhas
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

# Liga-se ao servidor de mensagens e inicia conversa
def ligar_ao_servidor(endereco_servidor, porta_servidor):

    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        print(f"[+] A ligar ao servidor {endereco_servidor}:{porta_servidor}...")
        cliente.connect((endereco_servidor, porta_servidor))
        print("[+] Ligação estabelecida.\n")

        # Recebe a mensagem de boas-vindas do servidor
        try:
            dados_iniciais = cliente.recv(4096)
            if dados_iniciais:
                texto_inicial = dados_iniciais.decode("utf-8", errors="ignore")
                print(texto_inicial)
        except Exception:
            # Se der erro na leitura inicial ignora
            pass

        # Ciclo principal de envio de mensagens
        while True:
            # Usa a função de multi-linha
            mensagem = ler_mensagem_multilinha("Tu")

            if not mensagem:
                print("[*] Mensagem vazia, nada enviado.")
                continue

            # Envia mensagem ao servidor
            cliente.sendall((mensagem + "\n").encode("utf-8"))

            if mensagem.upper() == "SAIR":
                print("[*] A terminar ligação com o servidor.")
                break

            # Aguarda resposta do servidor
            dados_resposta = cliente.recv(4096)
            if not dados_resposta:
                print("[*] Servidor fechou a ligação.")
                break

            resposta = dados_resposta.decode("utf-8", errors="ignore").strip()
            print(f"[Servidor]\n{resposta}")
            print("-" * 40)

            if resposta.upper() == "SAIR":
                print("[*] Servidor terminou a sessão.")
                break

    except ConnectionRefusedError:
        print(f"[ERRO] Não foi possível ligar ao servidor.")
    except KeyboardInterrupt:
        print("\n[!] Ligação encerrada pelo utilizador.")
    finally:
        cliente.close()
        print("[*] Ligação encerrada.")


def main():
    print("=== Cliente de Mensagens ===")

    endereco = input("Endereço IP do serfidor (ex: 172.0.0.1): ").strip()
    if not endereco:
        print("[ERRO] Endereço IP inválido.")
        return

    texto_porta = input("Porta do servidor (ex: 5000): ").strip()
    try:
        porta = int(texto_porta)
    except ValueError:
        print("[ERRO] Porta inválida.")
        return

    ligar_ao_servidor(endereco, porta)

if __name__ == "__main__":
    main() 
    
    

