#!/usr/bin/env python3
"""
Sentinela Automática de Rede Otimizada

Objetivo:
- Detecção de Rede, Hosts e Serviços Abertos (nmap).
- Monitoramento de Conexões em tempo real (psutil/Heurísticas de IDS).
- Captura de Tráfego (tshark).
- Enriquecimento de Dados (rDNS para IPs desconhecidos).
- Análise de Vulnerabilidades Básica (scan de portas nmap).
- Geração de Relatórios detalhados (JSON/Markdown).

Uso típico:
    python3 auto_network_sentinel.py

Pressione Ctrl+C para encerrar a sessão de vigilância.
"""

import subprocess
import sys
import time
import signal
import json
import shutil
import threading
import socket
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set

import psutil


BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

# Limites para detecção de Varredura (ajustados para serem mais sensíveis)
SCAN_PORT_THRESHOLD = 15  # Antes: 30
SCAN_CONN_THRESHOLD = 40  # Antes: 50


class AutoNetworkSentinel:
    def __init__(self) -> None:
        self.start_time = datetime.now()
        ts = self.start_time.strftime("%Y%m%d_%H%M%S")
        self.session_id = f"rede_{ts}"
        self.report_md = LOG_DIR / f"sentinela_rede_{ts}.md"
        self.report_json = LOG_DIR / f"sentinela_rede_{ts}.json"
        self.tshark_proc: Optional[subprocess.Popen] = None
        self.stop_flag = False
        self.alerts: List[Dict] = []
        
        # Estruturas de Dados Enriquecidas
        self.ip_ports_seen: Dict[str, Set[int]] = {}
        self.ip_conn_count: Dict[str, int] = {}
        self.ip_rdns_cache: Dict[str, Optional[str]] = {} # Cache para rDNS

    # ---------------------- utilidades ---------------------- #

    def run_command(self, cmd: List[str], timeout: int = 40) -> Tuple[int, str, str]:
        """
        Executa comando externo. Timeout aumentado.
        """
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        except subprocess.TimeoutExpired:
            return -1, "", "Timeout"
        except FileNotFoundError as e:
            return -1, "", str(e)
        except Exception as e:
            return -1, "", str(e)
    
    def resolve_rdns(self, ip: str) -> Optional[str]:
        """
        Resolve rDNS (nome do host) para um IP, usando cache.
        """
        if ip in self.ip_rdns_cache:
            return self.ip_rdns_cache[ip]
        
        try:
            # Tenta obter o nome do host em 0.5 segundos
            name, _, _ = socket.gethostbyaddr(ip)
            self.ip_rdns_cache[ip] = name
            return name
        except socket.herror:
            self.ip_rdns_cache[ip] = None
            return None
        except Exception:
            self.ip_rdns_cache[ip] = None
            return None

    # ---------------------- detecção de rede ---------------------- #

    def detect_network(self) -> Dict:
        # ... (Mantém a lógica de detecção de rede original com ip route)
        # Código mantido idêntico ao original
        info: Dict[str, Optional[str]] = {
            "interface": None,
            "ip": None,
            "cidr": None,
            "gateway": None,
            "subnet": None,
        }

        # gateway + interface padrão
        code, out, _ = self.run_command(["ip", "route", "show", "default"], timeout=10)
        if code == 0 and out:
            parts = out.split()
            try:
                gw_index = parts.index("via") + 1
                dev_index = parts.index("dev") + 1
                info["gateway"] = parts[gw_index]
                info["interface"] = parts[dev_index]
            except (ValueError, IndexError):
                pass

        if info["interface"]:
            # IP + CIDR da interface
            code, out, _ = self.run_command(
                ["ip", "-o", "-f", "inet", "addr", "show", "dev", info["interface"]], timeout=10
            )
            if code == 0 and out:
                parts = out.split()
                try:
                    cidr = parts[3]  # inet X/Y
                    info["cidr"] = cidr
                    info["ip"] = cidr.split("/")[0]
                    info["subnet"] = cidr
                except (IndexError, ValueError):
                    pass

        return info
    
    def discover_hosts_and_services(self, subnet: str, my_ip: Optional[str]) -> Tuple[List[str], Dict[str, List[str]]]:
        """
        Aprimorado: Descobre hosts (nmap -sn) e executa um scan de portas e serviços
        (nmap -sV) nos hosts descobertos.
        """
        if not subnet:
            return [], {}

        print(f"[*] 1/2: Descobrindo hosts ativos na sub-rede {subnet} com nmap -sn...")
        code, out, err = self.run_command(["nmap", "-sn", subnet], timeout=120)
        
        hosts: List[str] = []
        host_services: Dict[str, List[str]] = {}

        if code != 0:
            print(f"[!] Falha ao executar nmap -sn: {err or 'erro desconhecido'}")
            return hosts, host_services

        current_ip: Optional[str] = None
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Nmap scan report for "):
                parts = line.split()
                ip = parts[-1]
                current_ip = ip
            elif line.startswith("Host is up") and current_ip:
                if current_ip != my_ip:
                    hosts.append(current_ip)
                current_ip = None
        
        print(f"[+] 1/2: {len(hosts)} host(s) ativo(s) encontrado(s) na LAN (excluindo o host local)")
        
        if not hosts:
            return hosts, host_services

        # --- Etapa 2: Scan de Serviços e Vulnerabilidades Básicas (nmap -sV) ---
        print("[*] 2/2: Iniciando scan de portas e serviços abertos (nmap -sV) nos hosts descobertos...")
        
        # Executar scan de serviços nas 1000 portas mais comuns
        # Tempo de timeout aumentado para 5 minutos
        target_list = hosts
        cmd = ["nmap", "-sV", "-T4"] + target_list # -T4 é um timing mais rápido
        
        code, out, err = self.run_command(cmd, timeout=300) # 5 minutos
        
        if code != 0:
            print(f"[!] Falha ao executar nmap -sV: {err or 'erro desconhecido'}")
            return hosts, host_services

        current_ip = None
        service_list: List[str] = []

        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Nmap scan report for "):
                # Salva o serviço do IP anterior e limpa para o novo
                if current_ip and service_list:
                    host_services[current_ip] = service_list
                
                parts = line.split()
                current_ip = parts[-1]
                service_list = []
                
            elif current_ip and line and not line.startswith("Host is up") and not line.startswith("Not shown"):
                # Captura linhas de serviço abertas (ex: 22/tcp open ssh OpenSSH 8.2p1)
                # O critério é se tem 'open' na linha e começa com um número de porta.
                try:
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] == "open" and parts[0].split('/')[0].isdigit():
                        service_list.append(f"{parts[0]}/{parts[2]} ({' '.join(parts[3:])})")
                except IndexError:
                    continue
        
        # Salva o último IP
        if current_ip and service_list:
            host_services[current_ip] = service_list

        print(f"[+] 2/2: Scan de serviços finalizado. Dados prontos para relatório.")
        return hosts, host_services

    # ---------------------- tshark / captura ---------------------- #

    def start_tshark_capture(self, interface: str) -> Optional[Path]:
        # ... (Mantém o código tshark original)
        code, _, _ = self.run_command(["tshark", "-D"], timeout=10)
        if code != 0:
            return None

        pcap_path = LOG_DIR / f"sentinela_rede_{self.start_time.strftime('%Y%m%d_%H%M%S')}.pcap"
        try:
            self.tshark_proc = subprocess.Popen(
                ["tshark", "-i", interface, "-w", str(pcap_path), "-q"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            print(f"[+] Captura de tráfego iniciada com tshark em: {pcap_path}")
            return pcap_path
        except Exception as e:
            print(f"[!] Não foi possível iniciar tshark: {e}")
            self.tshark_proc = None
            return None

    def stop_tshark_capture(self) -> None:
        # ... (Mantém o código stop_tshark_capture original)
        if self.tshark_proc and self.tshark_proc.poll() is None:
            try:
                self.tshark_proc.terminate()
                try:
                    self.tshark_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.tshark_proc.kill()
            except Exception:
                pass


    # ---------------------- monitoramento em tempo real (IDS) ---------------------- #

    def check_for_scan_alert(self, r_ip: str, ports: Set[int], count: int) -> None:
        """
        Lógica de IDS aprimorada para detectar varredura.
        """
        # Limite ajustado para ser mais sensível
        if len(ports) >= SCAN_PORT_THRESHOLD and count >= SCAN_CONN_THRESHOLD:
            
            alert = {
                "type": "possible_scan",
                "ip": r_ip,
                "unique_ports": len(ports),
                "connections": count,
                "time": datetime.now().isoformat(),
                "rdns": self.resolve_rdns(r_ip),
            }
            # Evitar duplicar o mesmo alerta para o mesmo IP
            if not any(a.get("ip") == r_ip and a.get("type") == "possible_scan" for a in self.alerts):
                self.alerts.append(alert)
                print(
                    f"\n🚨 ALERTA (IDS): possível varredura/scan de {r_ip} "
                    f"({len(ports)} portas, {count} conexões)"
                )
    
    def monitor_loop(self, my_ip: Optional[str]) -> None:
        """
        Loop de vigilância silenciosa otimizado.
        """
        print("\n[*] Iniciando vigilância silenciosa da rede (Ctrl+C para encerrar)...")

        while not self.stop_flag:
            try:
                conns = psutil.net_connections(kind="inet")
            except Exception as e:
                print(f"[!] Erro ao ler conexões: {e}")
                time.sleep(3)
                continue

            for c in conns:
                if not c.raddr:
                    continue
                r_ip = c.raddr.ip
                
                # Ignorar IPs locais (loopback, meu IP, gateway, etc.) para foco em comunicação externa
                if r_ip.startswith("127.") or r_ip == "::1" or (my_ip and r_ip == my_ip):
                     continue
                
                # Otimização: Apenas IPs com porta remota válida
                try:
                    r_port = c.raddr.port
                except AttributeError:
                    continue 

                # 1. Registrar portas e contagens
                ports = self.ip_ports_seen.setdefault(r_ip, set())
                ports.add(r_port)
                count = self.ip_conn_count.get(r_ip, 0) + 1
                self.ip_conn_count[r_ip] = count

                # 2. Executar heurística IDS (Scan Alert)
                # Otimização: Usamos uma função separada para manter o loop limpo
                self.check_for_scan_alert(r_ip, ports, count)
                
            time.sleep(3)

    # ---------------------- relatórios ---------------------- #

    def write_initial_report(self, netinfo: Dict, hosts: List[str], host_services: Dict[str, List[str]], pcap_path: Optional[Path]) -> None:
        # Lógica inicial para escrever o MD
        with self.report_md.open("w", encoding="utf-8") as f:
            f.write("## Sessão de Vigilância de Rede\n\n")
            f.write(f"- **Início**: {self.start_time.isoformat()}\n")
            f.write(f"- **Sessão**: `{self.session_id}`\n\n")

            f.write("### Contexto da Rede Atual\n\n")
            f.write(f"- **Interface**: {netinfo.get('interface') or 'desconhecida'}\n")
            f.write(f"- **IP local**: {netinfo.get('ip') or 'desconhecido'}\n")
            f.write(f"- **Gateway**: {netinfo.get('gateway') or 'desconhecido'}\n")
            f.write(f"- **Sub-rede**: {netinfo.get('subnet') or 'desconhecida'}\n")
            f.write(f"- **Hosts descobertos na LAN**: {len(hosts)}\n")
            if pcap_path:
                f.write(f"- **Captura de tráfego**: `{pcap_path}`\n")
            
            f.write("\n### Análise de Vulnerabilidades (Hosts da LAN)\n\n")
            if hosts:
                for ip in hosts:
                    f.write(f"- **Host `{ip}`**:\n")
                    services = host_services.get(ip)
                    if services:
                        f.write(f"  - Serviços abertos: **{len(services)}**\n")
                        for service in services:
                            f.write(f"    - `{service}`\n")
                    else:
                        f.write("  - Nenhum serviço aberto significativo (nmap -sV).\n")
            else:
                f.write("- Nenhum host ativo na LAN para escanear.\n")

            f.write("\n### O que está sendo monitorado\n\n")
            f.write("- **Conexões de rede ativas** do sistema local.\n")
            f.write(f"- **Padrões de varredura** (IDS) (Limite: {SCAN_PORT_THRESHOLD} portas / {SCAN_CONN_THRESHOLD} conexões).\n")
            
            f.write("\n---\n\n")
            f.write("_A vigilância está em andamento. Pressione Ctrl+C para encerrar e gerar o relatório final._\n")

    def write_final_report(
        self,
        netinfo: Dict,
        hosts: List[str],
        host_services: Dict[str, List[str]],
        pcap_path: Optional[Path],
    ) -> None:
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()

        # 1. Enriquecer Estatísticas de IPs no JSON (Adicionar rDNS)
        ip_stats_with_rdns = {}
        for ip, ports in self.ip_ports_seen.items():
            ip_stats_with_rdns[ip] = {
                "unique_ports": len(ports),
                "connections": self.ip_conn_count.get(ip, 0),
                "rdns": self.ip_rdns_cache.get(ip),
            }
            
        # 2. Gerar JSON estruturado
        summary = {
            "session_id": self.session_id,
            "start_time": self.start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": duration,
            "network": netinfo,
            "hosts_lan": hosts,
            "lan_services_scan": host_services, # Novo dado
            "alerts": self.alerts,
            "tshark_pcap": str(pcap_path) if pcap_path else None,
            "ip_stats": ip_stats_with_rdns, # Otimizado com rDNS
        }

        with self.report_json.open("w", encoding="utf-8") as jf:
            json.dump(summary, jf, indent=2, ensure_ascii=False)

        # 3. Anexar resumo final ao markdown
        with self.report_md.open("a", encoding="utf-8") as f:
            f.write("\n\n---\n\n")
            f.write("### Encerramento da Sessão\n\n")
            f.write(f"- **Fim**: {end_time.isoformat()}\n")
            f.write(f"- **Duração**: {duration:.1f} segundos\n")
            f.write(f"- **Arquivo JSON detalhado**: `{self.report_json.name}`\n")
            
            # Repetir a seção de vulnerabilidades para completude do relatório final
            f.write("\n### Análise de Vulnerabilidades da LAN (Hosts Descobertos)\n\n")
            if hosts:
                for ip in hosts:
                    f.write(f"- **Host `{ip}`**:\n")
                    services = host_services.get(ip)
                    if services:
                        f.write(f"  - **{len(services)} Serviço(s) Abertos Encontrados**\n")
                        for service in services:
                            f.write(f"    - `{service}`\n")
                    else:
                        f.write("  - Nenhum serviço aberto significativo (nmap -sV).\n")
            
            f.write("\n### Estatísticas de IPs observados (Tráfego de Saída)\n\n")
            if self.ip_ports_seen:
                # Ordenar por conexões decrescentes para facilitar a análise
                sorted_stats = sorted(
                    ip_stats_with_rdns.items(), 
                    key=lambda item: item[1]['connections'], 
                    reverse=True
                )
                
                for ip, stats in sorted_stats:
                    rdns_info = f"({stats['rdns']})" if stats['rdns'] else ""
                    f.write(
                        f"- `{ip}` {rdns_info}: {stats['unique_ports']} porta(s) distinta(s), "
                        f"{stats['connections']} conexão(ões)\n"
                    )
            else:
                f.write("- Nenhum IP externo significativo observado.\n")

            f.write("\n### Alertas Gerados (IDS Heurístico)\n\n")
            if self.alerts:
                for a in self.alerts:
                    if a.get("type") == "possible_scan":
                        rdns_info = f" ({a['rdns']})" if a.get("rdns") else ""
                        f.write(
                            f"- 🚨 **Varredura/Scan** de `{a['ip']}`{rdns_info}: "
                            f"{a['unique_ports']} portas, {a['connections']} conexões. Tempo: {a['time']}\n"
                        )
                    # Adicionar espaço para outros tipos de alerta futuros aqui
            else:
                f.write("- Nenhum alerta crítico gerado durante a sessão.\n")

            if pcap_path:
                f.write(
                    "\n### Captura de Tráfego\n\n"
                    f"- Um arquivo `.pcap` foi salvo em `{pcap_path}` para análise posterior com Wireshark.\n"
                )

    def open_report_in_viewer(self) -> None:
        # ... (Mantém o código open_report_in_viewer original)
        viewer = shutil.which("xdg-open")
        if not viewer:
            return
        try:
            subprocess.Popen(
                [viewer, str(self.report_md)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass


def main() -> None:
    sentinel = AutoNetworkSentinel()

    netinfo = sentinel.detect_network()
    my_ip = netinfo.get("ip")
    
    # --- Passo 1: Descoberta e Análise de Vulnerabilidades ---
    # Captura Hosts e Serviços abertos em um único passo
    hosts, host_services = sentinel.discover_hosts_and_services(netinfo.get("subnet") or "", my_ip)

    # --- Passo 2: Inicialização do Monitoramento Passivo ---
    pcap_path = None
    if netinfo.get("interface"):
        pcap_path = sentinel.start_tshark_capture(netinfo["interface"])

    # --- Passo 3: Relatório Inicial com dados de vulnerabilidade ---
    sentinel.write_initial_report(netinfo, hosts, host_services, pcap_path)
    print(f"[+] Relatório em andamento (Markdown): {sentinel.report_md}")

    # --- Passo 4: Loop de Monitoramento (IDS) ---
    def handle_sigint(signum, frame): # type: ignore[override]
        sentinel.stop_flag = True

    signal.signal(signal.SIGINT, handle_sigint)

    # Otimização: Roda o monitoramento psutil no thread principal.
    # Se fossemos adicionar um monitoramento de Sniffing (ex: Scapy), rodaríamos ele em um thread separado.
    monitor_thread = threading.Thread(target=sentinel.monitor_loop, args=(my_ip,), daemon=True)
    monitor_thread.start()
    
    # Mantém o thread principal vivo
    try:
        while monitor_thread.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        sentinel.stop_flag = True
        
    # Espera o thread do monitoramento encerrar, caso não tenha terminado
    if monitor_thread.is_alive():
        monitor_thread.join(timeout=5)


    # --- Passo 5: Encerramento e Relatório Final ---
    sentinel.stop_tshark_capture()
    sentinel.write_final_report(netinfo, hosts, host_services, pcap_path)

    print(f"\n[+] Sessão encerrada. Relatório: {sentinel.report_md}")
    print(f"[+] Detalhes em JSON: {sentinel.report_json}")
    print("[*] Tentando abrir o relatório Markdown no visualizador padrão...")
    sentinel.open_report_in_viewer()


if __name__ == "__main__":
    if not sys.platform.startswith("linux"):
        print("Este script foi projetado para Linux (Debian).")
        sys.exit(1)
    # Requer sudo para nmap e tshark na maioria dos sistemas
    if shutil.which("nmap") is None:
        print("[!] Erro: nmap não encontrado no PATH. Instale-o (sudo apt install nmap).")
        sys.exit(1)
    
    try:
        main()
    except Exception as e:
        print(f"[!] Erro inesperado: {e}")
        sys.exit(1)