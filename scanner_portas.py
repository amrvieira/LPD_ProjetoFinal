import socket
from datetime import datetime


def fazer_scan_host(endereco_ip, porta_inicial, porta_final, timeout=0.3):
    """
    Faz um scan as portas
    no intervalo [porta_inicial, porta_final].

    Devolve:
        lista_portas_abertas, duracao
    """

    lista_portas_abertas = []

    # Definir o timeout para as ligações (em segundos)
    socket.setdefaulttimeout(timeout)

    momento_inicio = datetime.now()

    for porta in range(porta_inicial, porta_final + 1):
        socket_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            # devolve 0 se a ligação for bem sucedida
            resultado = socket_tcp.connect_ex((endereco_ip, porta))
            if resultado == 0:
                lista_portas_abertas.append(porta)

        except socket.error:
            # Se houver erro numa porta específica, ignora-o e continua
            pass

        finally:
            socket_tcp.close()

    momento_fim = datetime.now()
    duracao = momento_fim - momento_inicio

    return lista_portas_abertas, duracao


def pedir_intervalo_portas():
    """
    Pede ao utilizador a porta inicial e final
    """
    while True:
        try:
            texto_inicial = input("Porta inicial: ")
            texto_final = input("Porta final: ")

            porta_inicial = int(texto_inicial)
            porta_final = int(texto_final)

            if porta_inicial < 1 or porta_final > 65535 or porta_inicial > porta_final:
                print("Intervalo de portas inválido.\n")
                continue

            return porta_inicial, porta_final

        except ValueError:
            print("Entrada inválida. Tem de colocar numeros inteiros.\n")


def pedir_lista_alvos():
    """
    Pede ao utilizador uma lista de endereços (IP ou nomes) separados por vírgulas
    """
    while True:
        texto = input(
            "Endereços IP ou nomes dos hosts, separados por vírgulas\n"
            "Exemplo: 127.0.0.1, 192.168.1.10, localhost\n"
            "Introduz os alvos: "
        )

        partes = [parte.strip() for parte in texto.split(",") if parte.strip()]

        if not partes:
            print("Não foi introduzido nenhum alvo. Tenta novamente.\n")
            continue

        return partes


def main():
    print("=== Scanner de Portas ===\n")

    # Pedir lista de alvos
    lista_alvos = pedir_lista_alvos()

    # Pedir intervalo de portas (será o mesmo para todos os alvos)
    print("\nIntervalo de portas a analisar:")
    porta_inicial, porta_final = pedir_intervalo_portas()

    print(f"\nA iniciar scan de portas de {porta_inicial} a {porta_final}...")
    print(f"Número de alvos: {len(lista_alvos)}\n")

    # Percorrer cada alvo e fazer o scan
    for alvo in lista_alvos:
        try:
            endereco_ip = socket.gethostbyname(alvo)
        except socket.gaierror:
            print(f"\n[ERRO] Não foi possível resolver o endereço: {alvo}")
            continue

        print(f"\n--- A fazer scan ao alvo {alvo} (IP: {endereco_ip}) ---")

        try:
            portas_abertas, duracao = fazer_scan_host(
                endereco_ip=endereco_ip,
                porta_inicial=porta_inicial,
                porta_final=porta_final,
                timeout=0.3,   # valor pode ser ajustado conforme necessário
            )

        except KeyboardInterrupt:
            print("\n[!] Operação interrompida pelo utilizador.")
            return

        if portas_abertas:
            print("Portas abertas encontradas:")
            for porta in portas_abertas:
                print(f" - Porta {porta} aberta")
        else:
            print("Não foram encontradas portas abertas no intervalo definido.")

        print(f"Scan ao alvo {alvo} concluído em {duracao}.")

    print("\n=== Scan concluído para todos os alvos. Obrigado por usar o Scanner de Portas. ===")


if __name__ == "__main__":
    main()
