import socket

#Inicia servidor de mensagens 
def iniciar_servidor(host="0.0.0.0", porta=5000):

    #criar socket TCP
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    #reutilizar porta após terminar o programa 
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    #bind ao endereço e porta 
    servidor.bind((host, porta))

    #coloca socket em escuta 
    servidor.listen(1)

    print(f"Servidor mensagens iniciado em {host}:{porta}")
    print("A aguardar ligação...\n")

    try:
        while True:
            #espera ligação
            socket_cliente, endereco_cliente = servidor.accept()
            print(f"[+] Cliente ligado {endereco_cliente[0]}:{endereco_cliente[1]}")

            try:
                tratar_cliente(socket_cliente)
            except Exception as erro:
                print(f"[ERRO] Ocorreu um problea com o cliente: {erro}")
            finally:
                print("[*] Ligação terminada. \n")
                socket_cliente.close()
                print(" A aguardar nova ligação...\n")
    
    except KeyboardInterrupt:
        print("\n[!] Servidor encerrado pelo utilizador.")
    finally:
        servidor.close()
        print("[*] Servidor encerrado.")

#Permite ao utilizador escrever em várias linhas
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

# funcção que gera conversa com cliente 
def tratar_cliente(socket_cliente):
   
    mensagem_boas_vindas = (
        "Ligação estabelecida com o servidor.\n"
        "Escreve as tuas mensagens e prime Enter.\n"
        "Podes escrever várias linhas; termina com uma linha vazia.\n"
        "Para terminar a sessão, escreve SAIR numa linha.\n"
    )
    socket_cliente.sendall(mensagem_boas_vindas.encode("utf-8"))

    while True:
        dados = socket_cliente.recv(4096)

        if not dados:
            # O cliente fechou a ligação
            print("[*] Cliente terminou a ligação.")
            break

        texto_recebido = dados.decode("utf-8", errors="ignore").strip()

        if texto_recebido.upper() == "SAIR":
            print("[*] Cliente pediu para terminar a sessão.")
            break

        print("Cliente:")
        print(texto_recebido)
        print("-" * 40)

        # Pede ao operador do servidor para responder
        resposta = ler_mensagem_multilinha("Servidor")

        if not resposta:
            print("[*] Mensagem vazia, nada enviado.")
            continue

        if resposta.upper() == "SAIR":
            socket_cliente.sendall("SAIR\n".encode("utf-8"))
            print("[*] Servidor solicitou fim de sessão.")
            break

        # Envia a resposta (que pode ter várias linhas)
        socket_cliente.sendall((resposta + "\n").encode("utf-8"))
    
def main():
    print("=== Servidor de Mensagens ===")

    #pode perguntar porta ao utilizador (Enter para usar 5000)
    texto_porta = input("Porta para o servidor (predefinida 5000): ").strip()
    if texto_porta:
        try:
            porta = int(texto_porta)
        except ValueError:
            print("[ERRO] Porta inválida. A usar porta predefinida 5000.")
            porta = 5000
    else:
        porta = 5000        

    iniciar_servidor(porta=porta)

if __name__ == "__main__":
    main()