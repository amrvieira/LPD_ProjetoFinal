import os
import re

def obter_pais_por_ip(ip):
    """
    desenvolve apenas texto genérico para simular a obtenção do país por IP.
    """

#pede ao utilizador o caminho do ficheiro de logs (valida se
def pedir_caminho_ficheiro():

    while True:
        caminho = input("Caminho do ficheiro de logs: ").strip()

        if not caminho:
            print("Por favor, indica um caminho válido.\n")
            continue

        if not os.path.isfile(caminho):
            print("Ficheiro não encontrado. Tenta novamente.\n")
            continue
        return caminho
    
#analisa ficheiro de logs SSH (analisatentativas de login falhadas)
def analisar_log_ssh(caminho_ficheiro):

    padrao_ip = re.compile(r"from (\d{1,3}(?:\.\d{1,3}){3})")
    total_linhas = 0
    total_tentativas_invalidas = 0
    por_ip = {}

    with open(caminho_ficheiro, "r", encoding="utf-8", errors="ignore") as f:
        for linha in f:
            total_linhas += 1
            if "Failed password" in linha or "Invalid user" in linha:
                total_tentativas_invalidas += 1

                ip_encontrado = None
                ip_match = padrao_ip.search(linha)
                if ip_match:
                    ip_encontrado = ip_match.group(1)
                #Extrair timestamp 
                timestamp = linha [:15]

                if ip_encontrado:
                    if ip_encontrado not in por_ip:
                        por_ip[ip_encontrado] = {
                            "tentativas": 0,
                            "timestamps": []
                        }
                    por_ip[ip_encontrado]["tentativas"] += 1

                    #apenas alguns exemplos de timestamps
                    if len (por_ip[ip_encontrado]["timestamps"]) < 10:
                        por_ip[ip_encontrado]["timestamps"].append(timestamp)
                    por_ip[ip_encontrado]["timestamps"].append(timestamp)
             
    resultado = {
        "tipo": "SSH",
        "ficheiro": caminho_ficheiro,
        "total_linhas": total_linhas,
        "total_tentativas_invalidas": total_tentativas_invalidas,
        "por_ip": por_ip,   
    }   
    return resultado

#Analidsa ficheiro de logs HTTP (codigos HTTP>=404)
def analisador_log_http(caminho_ficheiro):

    padrao_ip = re.compile(
        r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
        r'"(?P<metodo>\S+) (?P<path>\S+) \S+" (?P<status>\d{3}) (?P<tamanho>\S+)'                      
    )
    total_linhas = 0
    total_perdidos = 0
    total_erros = 0
    por_ip = {}

    with open(caminho_ficheiro, "r", encoding="utf-8", errors="ignore") as f:
        for linha in f:
            total_linhas += 1
            linha = linha.strip()
            if not linha:
                continue

            m = padrao_http.match(linha)
            if not m:
                #nao corresponde ao formato, ignora
                continue
            total_pedidos += 1

            ip = m.group("ip")
            timestamp = m.group("timestamp")
            status = int(m.group("status"))
            #metodo = m.group("metodo")
            #path = m.group("path")

            if ip not in por_ip:
                por_ip[ip] = {
                    "pais": obter_pais_por_ip(ip),
                    "pedidos": 0,
                    "erros": 0,
                    "timestamps": [],
                }

            por_ip[ip]["pedidos"] += 1
            if status >= 400:
                por_ip[ip]["erros"] += 1
                total_erros += 1
            
            if len(por_ip[ip]["timestamps"]) < 10:
                por_ip[ip]["timestamps"].append(timestamp)
    
    resultado = {
        "tipo": "HTTP",
        "ficheiro": caminho_ficheiro,
        "total_linhas": total_linhas,
        "total_pedidos": total_pedidos,
        "total_erros": total_erros,
        "por_ip": por_ip,   
    }
    return resultado

#mostra no ecran a analise logs SSH
def mostrar_resumo_ssh(resultado):
    
    print("\n=== Resumo da Análise de Logs SSH ===")
    print(f"Ficheiro analisado: {resultado['ficheiro']}")
    print(f"Total de linhas: {resultado['total_linhas']}")      
    print(f"Total de tentativas de login inválidas: {resultado['total_tentativas_invalidas']}\n")   

    if not resultado['por_ip']:
        print("Nenhuma tentativa de login inválida encontrada.\n")
        return
    
    print("\nDetalhes por IP de origem:\n")

    for ip, info in resultado['por_ip'].items():
        print(f"IP: {ip} | País: {info['pais']}")
        print(f"  Tentativas inválidas: {info['tentativas']}")
        if info['timestamps']:
                print("  Exemplos de timestamps:")
                for ts in info['timestamps']:
                    print(f"    - {ts}")
        print("_" * 40)

    print("\n=== Fim do Resumo SSH===\n")

    # mostra resumo analise logs HTTP
def mostrar_resumo_http(resultado):
        print("\n=== Resumo da Análise de Logs HTTP ===")
        print(f"Ficheiro analisado: {resultado['ficheiro']}")
        print(f"Total de linhas: {resultado['total_linhas']}")
        print(f"Total de pedidos HTTP: {resultado['total_pedidos']}")
        print(f"Total de erros HTTP (códigos >=400): {resultado['total_erros']}\n")

        if not resultado['por_ip']:
            print("Nenhum pedido HTTP encontrado.\n")
            return
        
        print("\nDetalhes por IP de origem:\n")

        for ip, info in resultado['por_ip'].items():
            print(f"IP: {ip} | País: {info['pais']}")
            print(f"  Pedidos HTTP: {info['pedidos']}")
            print(f"  Erros HTTP: {info['erros']}")
            if info['timestamps']:
                print("  Exemplos de timestamps:")
                for ts in info['timestamps']:
                    print(f"    - {ts}")
            print("_" * 40)

        print("\n=== Fim do Resumo HTTP===\n")

def escolher_tipo_log():
        """
        Pede ao utilizador para escolher o tipo de log a analisar (SSH ou HTTP)
        """

        while True:
            print("=== Analisador de Logs ===")
            print("1. Logs SSH")
            print("2. Logs HTTP")   
            escolha = input("Que tipo de log queres analisar? (1=SSH, 2=HTTP): ").strip()
            if escolha == "1":
                return "SSH"
            elif escolha == "2":
                return "HTTP"
            else:
                print("Escolha inválida. Por favor, digita 1 para SSH ou 2 para HTTP.\n")   
      
def main():
    tipo_log = escolher_tipo_log()
    caminho_ficheiro = pedir_caminho_ficheiro()

    if tipo_log == "SSH":
        resultado = analisar_log_ssh(caminho_ficheiro)
        mostrar_resumo_ssh(resultado)
    elif tipo_log == "HTTP":
        resultado = analisador_log_http(caminho_ficheiro)
        mostrar_resumo_http(resultado)

if __name__ == "__main__":
    main()