import os
import re


def obter_pais_por_ip(ip):
    """
    Nesta fase, devolve apenas um texto genérico.
    Mais tarde, vamos integrar uma base de dados GeoIP para obter
    o país real associado ao IP.
    """
    return "Desconhecido (GeoIP ainda não implementado)"


def pedir_caminho_ficheiro():
    """
    Pede ao utilizador o caminho completo para o ficheiro de log
    e valida se o ficheiro existe.
    """
    while True:
        caminho = input("Caminho para o ficheiro de log: ").strip()

        if not caminho:
            print("Indica um caminho válido.\n")
            continue

        if not os.path.isfile(caminho):
            print("O ficheiro indicado não existe. Tenta novamente.\n")
            continue

        return caminho


def analisar_log_ssh(caminho_ficheiro):
    """
    Analisa um ficheiro de log de SSH (por exemplo auth.log)
    e procura tentativas de acesso inválidas:
      - 'Failed password'
      - 'Invalid user'

    Devolve um dicionário com estatísticas agregadas por IP de origem.
    """

    padrao_ip = re.compile(r"from (\d{1,3}(?:\.\d{1,3}){3})")

    total_linhas = 0
    total_tentativas_invalidas = 0
    por_ip = {}

    with open(caminho_ficheiro, "r", encoding="utf-8", errors="ignore") as f:
        for linha in f:
            total_linhas += 1

            # Consideramos como tentativas inválidas linhas que contenham estas expressões
            if "Failed password" in linha or "Invalid user" in linha:
                total_tentativas_invalidas += 1

                ip_encontrado = None
                ip_match = padrao_ip.search(linha)
                if ip_match:
                    ip_encontrado = ip_match.group(1)

                # Extrair timestamp
                timestamp = linha[:15]

                if ip_encontrado:
                    if ip_encontrado not in por_ip:
                        por_ip[ip_encontrado] = {
                            "pais": obter_pais_por_ip(ip_encontrado),
                            "tentativas": 0,
                            "timestamps": [],
                        }

                    por_ip[ip_encontrado]["tentativas"] += 1

                    # Guardar alguns timestamps
                    if len(por_ip[ip_encontrado]["timestamps"]) < 20:
                        por_ip[ip_encontrado]["timestamps"].append(timestamp)

    resultado = {
        "tipo": "ssh",
        "ficheiro": caminho_ficheiro,
        "total_linhas": total_linhas,
        "total_tentativas_invalidas": total_tentativas_invalidas,
        "por_ip": por_ip,
    }

    return resultado

#analisa logs ufw
def analisar_log_ufw(caminho_ficheiro):
 
    padrao = re.compile(
        r'^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*?\[UFW BLOCK\].*?'
        r'SRC=(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3}).*?'
        r'DST=(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3}).*?'
        r'PROTO=(?P<proto>\w+)'
        r'(?:.*?DPT=(?P<dpt>\d+))?'
    )

    total_linhas = 0
    total_blocos = 0
    por_ip = {}

    with open(caminho_ficheiro, "r", encoding="utf-8", errors="ignore") as f:
        for linha in f:
            total_linhas += 1
            linha = linha.strip()
            if not linha:
                continue

            m = padrao.search(linha)
            if not m:
                # Linha não corresponde ao padrão  (ignora)
                continue

            total_blocos += 1

            ip_origem = m.group("src_ip")
            timestamp = m.group("timestamp")
            proto = m.group("proto")
            dpt = m.group("dpt") 

            if ip_origem not in por_ip:
                por_ip[ip_origem] = {
                    "pais": obter_pais_por_ip(ip_origem),
                    "blocos": 0,
                    "portas_destino": {},
                    "protocolos": {},
                    "timestamps": [],
                }

            info = por_ip[ip_origem]
            info["blocos"] += 1

            # Contar portas de destino mais usadas
            if dpt:
                info["portas_destino"][dpt] = info["portas_destino"].get(dpt, 0) + 1

            # Contar protocolos usados
            info["protocolos"][proto] = info["protocolos"].get(proto, 0) + 1

            # Guardar alguns timestamps
            if len(info["timestamps"]) < 10:
                info["timestamps"].append(timestamp)

    resultado = {
        "tipo": "ufw",
        "ficheiro": caminho_ficheiro,
        "total_linhas": total_linhas,
        "total_blocos": total_blocos,
        "por_ip": por_ip,
    }

    return resultado


def mostrar_resumo_ssh(resultado):
    """
    Mostra no ecrã um resumo da análise de logs SSH.
    """
    print("\n=== Resumo da análise de logs SSH ===")
    print(f"Ficheiro analisado: {resultado['ficheiro']}")
    print(f"Total de linhas lidas: {resultado['total_linhas']}")
    print(f"Total de tentativas inválidas encontradas: {resultado['total_tentativas_invalidas']}")

    if not resultado["por_ip"]:
        print("\nNão foram encontradas tentativas inválidas associadas a IPs.\n")
        return

    # IPs com mais tentativas inválidas
    ips_ordenados = sorted(
        resultado["por_ip"].items(),
        key=lambda item: item[1].get("tentativas", 0),
        reverse=True,
    )

    print("\nIPs com mais tentativas inválidas:\n")
    for ip, info in ips_ordenados[:5]:
        pais = info.get("pais", "Desconhecido (sem informação de GeoIP)")
        tentativas = info.get("tentativas", 0)
        print(f" - {ip}  |  País: {pais}  |  Tentativas: {tentativas}")

    print("\nDetalhe por IP de origem:\n")

    for ip, info in ips_ordenados:
        pais = info.get("pais", "Desconhecido (sem informação de GeoIP)")
        print(f"IP: {ip}  |  País: {pais}")
        print(f"  Número de tentativas inválidas: {info.get('tentativas', 0)}")
        if info.get("timestamps"):
            print("  Alguns timestamps das tentativas:")
            for ts in info["timestamps"]:
                print(f"    - {ts}")
        print("-" * 50)

    print("=== Fim do resumo SSH ===\n")


def mostrar_resumo_ufw(resultado):
    """
    Mostra no ecrã um resumo da análise de logs UFW (firewall).
    """
    print("\n=== Resumo da análise de logs UFW (firewall) ===")
    print(f"Ficheiro analisado: {resultado['ficheiro']}")
    print(f"Total de linhas lidas: {resultado['total_linhas']}")
    print(f"Total de blocos UFW encontrados: {resultado['total_blocos']}")

    if not resultado["por_ip"]:
        print("\nNão foram encontrados blocos associados a IPs.\n")
        return

    # IPs com mais blocos
    ips_ordenados = sorted(
        resultado["por_ip"].items(),
        key=lambda item: item[1].get("blocos", 0),
        reverse=True,
    )

    print("\nIPs com mais blocos UFW:\n")
    for ip, info in ips_ordenados[:5]:
        pais = info.get("pais", "Desconhecido (sem informação de GeoIP)")
        blocos = info.get("blocos", 0)
        print(f" - {ip}  |  País: {pais}  |  Blocos: {blocos}")

    print("\nDetalhe por IP de origem:\n")

    for ip, info in ips_ordenados:
        pais = info.get("pais", "Desconhecido (sem informação de GeoIP)")
        print(f"IP: {ip}  |  País: {pais}")
        print(f"  Número de blocos: {info.get('blocos', 0)}")

        # Portas de destino mais usadas
        if info.get("portas_destino"):
            print("  Portas de destino mais frequentes:")
            portas_ordenadas = sorted(
                info["portas_destino"].items(),
                key=lambda item: item[1],
                reverse=True,
            )
            for porta, contagem in portas_ordenadas[:5]:
                print(f"    - Porta {porta}: {contagem} vezes")

        # Protocolos usados
        if info.get("protocolos"):
            print("  Protocolos utilizados:")
            for proto, contagem in info["protocolos"].items():
                print(f"    - {proto}: {contagem} vezes")

        if info.get("timestamps"):
            print("  Alguns timestamps dos blocos:")
            for ts in info["timestamps"]:
                print(f"    - {ts}")

        print("-" * 50)

    print("=== Fim do resumo UFW ===\n")

def escolher_tipo_log():
    """
    Pede ao utilizador para escolher o tipo de log a analisar: SSH ou UFW.
    """
    while True:
        print("=== Analisador de Logs ===")
        print("1) Analisar logs SSH (ex.: auth.log)")
        print("2) Analisar logs UFW (firewall, ex.: ufw.log)")
        escolha = input("Que tipo de log queres analisar? (1=SSH, 2=UFW): ").strip()

        if escolha == "1":
            return "ssh"
        elif escolha == "2":
            return "ufw"
        else:
            print("Opção inválida. Tenta novamente.\n")


def main():
    tipo_log = escolher_tipo_log()
    caminho = pedir_caminho_ficheiro()

    if tipo_log == "ssh":
        resultado = analisar_log_ssh(caminho)
        mostrar_resumo_ssh(resultado)
    else:  # ufw
        resultado = analisar_log_ufw(caminho)
        mostrar_resumo_ufw(resultado)


if __name__ == "__main__":
    main()
