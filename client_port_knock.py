#!/usr/bin/env python3
import argparse
import os
import socket
import subprocess
import sys
import time
from typing import List

# envia knocks através de TCP para a porta especificada
def fazer_knock_com_socket(host: str, portas: List[int], atraso: float, timeout: float) -> None:
    for porta in portas: 
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host, porta))
        except Exception:
            #porta fechada ou a firewall descartou o pacote
            pass
        finally:
            sock.close()
        time.sleep(atraso)

# envia knocks (TCP SYN). Requer root/cap_net_raw
def fazer_knock_com_scapy(host: str, portas: List[int], atraso: float) -> None:
    from scapy.all import IP, TCP, send

    for porta in portas:
        pacote = IP(dst=host)/TCP(dport=porta, flags="S")
        send(pacote, verbose=False)
        time.sleep(atraso)
    
# tenta abrir ligação SSH após a sequência de knocks
def tentar_ssh(host: str, utilizador: str, porta_ssh: int) -> int:
    print("[*] A tentar SSH...")
    comando = ["ssh", f"{utilizador}@{host}", "-p", str(porta_ssh)]
    try:
        return subprocess.call(comando)
    except FileNotFoundError:
        print("[ERRO] Cliente SSH não encontrado.", file=sys.stderr)
        return 5
    
def ler_argumentos() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Cliente de Port Knocking (abre SSH no servidor via iptables 'recent')."
    )
    parser.add_argument("host", help="IP/DNS do servidor")
    parser.add_argument("--portas", default="10001,10002,10003",
                        help="Sequência de portas (ex: 10001,10002,10003)")
    parser.add_argument("--atraso", type=float, default=0.4,
                        help="Atraso entre knocks (segundos)")
    parser.add_argument("--timeout", type=float, default=0.25,
                        help="Timeout do connect() (segundos) quando usar sockets")
    parser.add_argument("--usar-scapy", action="store_true",
                        help="Usar Scapy (TCP SYN) (requer sudo/root)")
    parser.add_argument("--utilizador-ssh", default=None,
                        help="Se definido, tenta SSH após knocks (ex: antonio)")
    parser.add_argument("--porta-ssh", type=int, default=22,
                        help="Porta SSH (default 22)")
    return parser.parse_args()

def validar_portas(texto_portas: str) -> List[int]:
    portas = [int(x.strip()) for x in texto_portas.split(",") if x.strip()]
    if len (portas) < 2:
        raise ValueError("Deve especificar pelo menos duas portas.")
    return portas

def main() -> int:
    args = ler_argumentos()

    try:
        portas = validar_portas(args.portas)
    except ValueError as e:
        print(f"[ERRO] {e}", file=sys.stderr)
        return 2

    print(f"[+] Alvo: {args.host}")
    print(f"[+] Sequência de knocking: {portas} (atraso={args.atraso}s)")

    if args.usar_scapy:
        if os.geteuid() != 0:
            print("[ERRO] Scapy requer sudo/root para enviar pacotes SYN.", file=sys.stderr)
            return 3
        try:
            fazer_knock_com_scapy(args.host, portas, args.atraso)
        except ImportError:
            print("[ERRO] Scapy não está instalado. Instala com: pip install scapy", file=sys.stderr)
            return 4
    else:
        fazer_knock_com_socket(args.host, portas, args.atraso, args.timeout)

    print("[OK] Knocks enviados.")

    if args.utilizador_ssh:
        return tentar_ssh(args.host, args.utilizador_ssh, args.porta_ssh)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())