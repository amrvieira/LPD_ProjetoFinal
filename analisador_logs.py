import os
import re
import geoip2.database
import geoip2.errors
import ipaddress


# ============================================================
# GeoIP2 (MaxMind GeoLite2)
# ============================================================

# Caminho base de dadosGeoLite2-City.mmdb
GEOIP_DB_PATH = os.path.join(os.path.dirname(__file__), "GeoLite2-City-2025.mmdb")

geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)

# considerar um IP como "suspeito"
LIMIAR_TENTATIVAS_SSH_SUSPEITO = 100   # tentativas inválidas de SSH
LIMIAR_BLOCOS_UFW_SUSPEITO = 200       # blocos na firewall UFW


def obter_pais_por_ip(ip):
    """
    Devolve uma string com o país associado ao IP, uso GeoIP2/GeoLite2.
    """
    try: 
        resposta = geoip_reader.city(ip)
    except geoip2.errors.AddressNotFoundError:
        return "Desconhecido (IP não encontrado na base GeoIP)"
    except Exception:
        # Em caso de erro, o analisador de logs continua a funcionar
        return "Desconhecido (erro ao consultar GeoIP)"
    
    pais = resposta.country
    if not pais:
        return "Desconhecido (sem dados de país)"
    if pais.iso_code:
        return pais.iso_code
    if pais.name:
        return pais.name
    return "Desconhecido (sem dados de país)"

# ============================================================
# Funções comuns de apoio
# ============================================================

# Pede ao utilizador o caminho para o ficheiro de log
def pedir_caminho_ficheiro():

    while True:
        caminho = input("Caminho completo para o ficheiro de log: ").strip()

        if not caminho:
            print("Por favor, indica um caminho válido.\n")
            continue

        if not os.path.isfile(caminho):
            print("O ficheiro indicado não existe. Tenta novamente.\n")
            continue

        return caminho


# ============================================================
# Análise de logs SSH (auth.log)
# ============================================================

# Analisar ficheiro de log SSH
def analisar_log_ssh(caminho_ficheiro):
   
    padrao_ip = re.compile(r"from (\d{1,3}(?:\.\d{1,3}){3})")

    total_linhas = 0
    total_tentativas_invalidas = 0
    por_ip = {}

    with open(caminho_ficheiro, "r", encoding="utf-8", errors="ignore") as f:
        for linha in f:
            total_linhas += 1

            # Considera como tentativas inválidas o que contenha estas strings
            if "Failed password" in linha or "Invalid user" in linha:
                total_tentativas_invalidas += 1

                ip_encontrado = None
                ip_match = padrao_ip.search(linha)
                if ip_match:
                    ip_encontrado = ip_match.group(1)

                # Extrai timestamp
                timestamp = linha[:15]

                if ip_encontrado:
                    if ip_encontrado not in por_ip:
                        por_ip[ip_encontrado] = {
                            "pais": obter_pais_por_ip(ip_encontrado),
                            "tentativas": 0,
                            "timestamps": [],
                        }

                    por_ip[ip_encontrado]["tentativas"] += 1

                    # Guarda alguns timestamps
                    if len(por_ip[ip_encontrado]["timestamps"]) < 10:
                        por_ip[ip_encontrado]["timestamps"].append(timestamp)

    resultado = {
        "tipo": "ssh",
        "ficheiro": caminho_ficheiro,
        "total_linhas": total_linhas,
        "total_tentativas_invalidas": total_tentativas_invalidas,
        "por_ip": por_ip,
    }

    return resultado


# ============================================================
# Análise de logs UFW (firewall, ufw.log)
# ============================================================

# Analisar ficheiro de log UFW
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
                # Linha não corresponde ao padrão esperado (ignoramos)
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


# ============================================================
# Funções para apresentar resultados
# ============================================================

# Calcula resumo por país
def calcular_resumo_por_pais(dados_por_ip, chave_contagem):
    
    por_pais = {}

    for ip, info in dados_por_ip.items():
        pais = info.get("pais", "Desconhecido")
        quantidade = info.get(chave_contagem, 0)

        if quantidade <= 0:
            continue

        por_pais[pais] = por_pais.get(pais, 0) + quantidade

    return por_pais

# Mostrar resumo por país
def mostrar_resumo_por_pais(dados_por_ip, chave_contagem, rotulo_evento):
    
    por_pais = calcular_resumo_por_pais(dados_por_ip, chave_contagem)

    if not por_pais:
        print("\n[Resumo por país] Não há dados suficientes para calcular estatísticas por país.\n")
        return

    # Ordenar países por eventos
    paises_ordenados = sorted(por_pais.items(), key=lambda item: item[1], reverse=True)
    total_eventos = sum(por_pais.values())

    print(f"\nResumo por país ({rotulo_evento}):")
    print(f"Total de eventos considerados: {total_eventos}\n")

    # Mostrar top 10 países (pode alterar conforem necessário)
    for pais, quantidade in paises_ordenados[:10]:
        percentagem = (quantidade / total_eventos) * 100 if total_eventos > 0 else 0
        print(f" - {pais}: {quantidade} ({percentagem:.2f}%)")

    print() 

# Verifica se um IP é privado
def eh_ip_privado(ip):
    try:
        endereco = ipaddress.ip_address(ip)
        return endereco.is_private
    except ValueError:
        return False

# Mostra IPs suspeitos
def mostrar_ips_suspeitos(dados_por_ip, chave_contagem, limiar, rotulo_evento):

    suspeitos = []

    for ip, info in dados_por_ip.items():
        quantidade = info.get(chave_contagem, 0)
        if quantidade >= limiar:
            suspeitos.append((ip, quantidade, info.get("pais", "Desconhecido")))

    if not suspeitos:
        print(f"\n[IPs Suspeitos] Não foram encontrados IPs com {chave_contagem} >= {limiar} ({rotulo_evento}).\n")
        return
    
    suspeitos.sort(key=lambda item: item[1], reverse=True)

    print(f"\n=== IPs Suspeitos ({rotulo_evento} >= {limiar}) ===\n")
    for ip, quantidade, pais in suspeitos:
        print(f" - {ip} País: {pais} | {chave_contagem.capitalize()}: {quantidade}")
        print()

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
    
    mostrar_ips_suspeitos( 
        resultado["por_ip"],
        chave_contagem="tentativas",
        limiar=LIMIAR_TENTATIVAS_SSH_SUSPEITO,
        rotulo_evento="tentativas inválidas de SSH"
    )
    
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

    mostrar_resumo_por_pais(resultado["por_ip"], "tentativas", "tentativas inválidas")
    print("=== Fim do resumo SSH ===\n")

#Mostra resumo da análise de logs UFW
def mostrar_resumo_ufw(resultado):

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
    
    mostrar_ips_suspeitos(
        resultado["por_ip"],
        chave_contagem="blocos",
        limiar=LIMIAR_BLOCOS_UFW_SUSPEITO,
        rotulo_evento="blocos UFW"
    )
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

    mostrar_resumo_por_pais(resultado["por_ip"], "blocos", "blocos UFW")
    print("=== Fim do resumo UFW ===\n")


# ============================================================
# Menu e função principal
# ============================================================

# Menu para escolher tipo de log
def escolher_tipo_log():

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

