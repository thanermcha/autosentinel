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
import ipaddress
import argparse
import os
from collections import Counter, defaultdict
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

# Janela para deduplicação de conexões (evita inflar contagens por amostragem)
CONN_DEDUPE_WINDOW_SECONDS = 30
CONN_STATE_TTL_SECONDS = 180


class AutoNetworkSentinel:
    def __init__(self, policy: Optional[Dict] = None) -> None:
        self.start_time = datetime.now()
        ts = self.start_time.strftime("%Y%m%d_%H%M%S")
        self.session_id = f"rede_{ts}"
        self.report_md = LOG_DIR / f"sentinela_rede_{ts}.md"
        self.report_json = LOG_DIR / f"sentinela_rede_{ts}.json"
        self.tshark_proc: Optional[subprocess.Popen] = None
        self.tshark_meta_proc: Optional[subprocess.Popen] = None
        self.stop_flag = False
        self.alerts: List[Dict] = []

        # Política de resposta (mitigação/coleta)
        self.policy: Dict = policy or {}
        self.incidents_dir = LOG_DIR / "incidents"
        self.incidents_dir.mkdir(exist_ok=True)
        
        # Estruturas de Dados Enriquecidas
        self.ip_ports_seen: Dict[str, Set[int]] = {}
        # "samples": quantas vezes vimos o IP em amostragens psutil
        self.ip_conn_samples: Dict[str, int] = {}
        # "unique": estimativa de conexões únicas na janela (dedupe por tupla)
        self.ip_conn_unique: Dict[str, int] = {}
        self.ip_rdns_cache: Dict[str, Optional[str]] = {} # Cache para rDNS
        self.conn_last_seen: Dict[Tuple, float] = {}

        # Compatibilidade: versões antigas usavam ip_conn_count (agora é split em samples/unique)
        # Mantemos um alias para evitar crash de código/relatórios que ainda referenciem o nome antigo.
        self.ip_conn_count = self.ip_conn_samples

        # Enriquecimento: atribuição por processo (host local)
        self.pid_cache: Dict[int, Dict[str, Optional[str]]] = {}
        self.process_conn_count: Counter[str] = Counter()
        self.process_unique_remote_ips: Dict[str, Set[str]] = defaultdict(set)
        self.process_unique_remote_ports: Dict[str, Set[int]] = defaultdict(set)
        self.process_remote_ip_count: Dict[str, Counter[str]] = defaultdict(Counter)

        # Enriquecimento: domínios/hosts (DNS / TLS SNI / HTTP Host)
        self.domain_count: Counter[str] = Counter()
        self.remote_ip_domains: Dict[str, Set[str]] = defaultdict(set)
        self.remote_ip_domain_count: Dict[str, Counter[str]] = defaultdict(Counter)
        self.meta_events_path = LOG_DIR / f"sentinela_rede_{ts}_meta.jsonl"
        self._meta_events_fh = None  # lazy-open

        # Baseline/diff
        self.baseline_path: Optional[Path] = None
        self.baseline_loaded: Optional[Dict] = None
        self.baseline_diff: Dict = {}

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

    def _is_lan_ip(self, ip: str, local_subnet: Optional[str]) -> bool:
        """
        Retorna True se o IP estiver dentro da sub-rede local (quando conhecida).
        """
        if not local_subnet:
            return False
        try:
            net = ipaddress.ip_network(local_subnet, strict=False)
            addr = ipaddress.ip_address(ip)
            return addr in net
        except Exception:
            return False

    def _policy_bool(self, key: str, default: bool = False) -> bool:
        try:
            return bool(self.policy.get(key, default))
        except Exception:
            return default

    def _policy_list(self, key: str) -> List[str]:
        val = self.policy.get(key, [])
        if isinstance(val, list):
            return [str(x) for x in val]
        return []

    def _ip_in_any_cidr(self, ip: str, cidrs: List[str]) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            return False
        for c in cidrs:
            try:
                net = ipaddress.ip_network(c, strict=False)
                if addr in net:
                    return True
            except Exception:
                continue
        return False

    def _is_allowlisted_ip(self, ip: str, local_subnet: Optional[str]) -> bool:
        if ip.startswith("127.") or ip == "::1":
            return True
        allow_ips = set(self._policy_list("allowlist_ips"))
        allow_cidrs = self._policy_list("allowlist_cidrs")
        if ip in allow_ips:
            return True
        if allow_cidrs and self._ip_in_any_cidr(ip, allow_cidrs):
            return True
        # Por padrão, também considera a LAN como "não-bloqueável", a menos que explicitamente habilitado
        if self._is_lan_ip(ip, local_subnet) and not self._policy_bool("block_lan_ips", False):
            return True
        return False

    def _run_cmd_capture(self, cmd: List[str], timeout: int = 8) -> Dict[str, object]:
        code, out, err = self.run_command(cmd, timeout=timeout)
        return {"cmd": cmd, "code": code, "stdout": out, "stderr": err}

    def _write_text(self, path: Path, text: str) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        except Exception:
            pass

    def collect_forensics_snapshot(self, incident_id: str) -> Dict[str, object]:
        """
        Coleta evidências locais (best-effort) no momento de um alerta.
        Não requer rede; não executa retaliação externa.
        """
        snap_dir = self.incidents_dir / incident_id
        snap_dir.mkdir(exist_ok=True)
        data: Dict[str, object] = {
            "incident_id": incident_id,
            "time": datetime.now().isoformat(),
            "files": {},
            "commands": [],
        }

        cmds: List[Tuple[str, List[str], int]] = [
            ("ss_tcp", ["ss", "-tpn"], 8),
            ("ss_udp", ["ss", "-upn"], 8),
            ("ip_addr", ["ip", "addr"], 6),
            ("ip_route", ["ip", "route"], 6),
            ("ip_neigh", ["ip", "neigh"], 6),
            ("ps_aux", ["ps", "auxfww"], 10),
        ]
        if shutil.which("lsof"):
            cmds.append(("lsof_inet", ["lsof", "-nP", "-i"], 12))
        if shutil.which("journalctl"):
            cmds.append(("journalctl_5m", ["journalctl", "-S", "-5min", "--no-pager"], 12))
        if shutil.which("dmesg"):
            cmds.append(("dmesg_tail", ["dmesg", "--ctime"], 8))

        for name, cmd, tmo in cmds:
            res = self._run_cmd_capture(cmd, timeout=tmo)
            data["commands"].append(res)
            out_path = snap_dir / f"{name}.txt"
            content = (res.get("stdout") or "") if isinstance(res.get("stdout"), str) else ""
            err = (res.get("stderr") or "") if isinstance(res.get("stderr"), str) else ""
            self._write_text(out_path, (content + ("\n\n[stderr]\n" + err if err else ""))[:2_000_000])
            data["files"][name] = str(out_path)

        return data

    def mitigate_block_ip(self, ip: str, incident_id: str, local_subnet: Optional[str]) -> Dict[str, object]:
        """
        Mitigação defensiva local: tenta bloquear um IP no host local.
        Por padrão, funciona em dry-run.
        """
        dry_run = self._policy_bool("dry_run", True)
        method = str(self.policy.get("block_method", "auto"))

        if self._is_allowlisted_ip(ip, local_subnet):
            return {"action": "block_ip", "ip": ip, "status": "skipped_allowlist"}

        # Seleção simples de método
        if method == "auto":
            if shutil.which("ufw"):
                method = "ufw"
            elif shutil.which("iptables"):
                method = "iptables"
            else:
                method = "none"

        cmds: List[List[str]] = []
        if method == "ufw":
            # --force evita prompt interativo
            cmds = [["ufw", "--force", "deny", "from", ip, "to", "any"]]
        elif method == "iptables":
            cmds = [["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]]
        else:
            return {"action": "block_ip", "ip": ip, "status": "unsupported", "method": method}

        results = []
        for cmd in cmds:
            if dry_run:
                results.append({"cmd": cmd, "dry_run": True})
            else:
                results.append(self._run_cmd_capture(cmd, timeout=8))

        # Persistir ação em arquivo do incidente
        try:
            act_path = self.incidents_dir / incident_id / "mitigation.json"
            act_path.write_text(json.dumps({"method": method, "results": results}, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass

        return {"action": "block_ip", "ip": ip, "status": "attempted", "method": method, "results": results}

    def record_incident(self, alert: Dict, netinfo: Dict, local_subnet: Optional[str]) -> Dict[str, object]:
        """
        Registra um incidente e executa ações pró-ativas locais (mitigação + forense), conforme política.
        """
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        ip = str(alert.get("ip") or "unknown")
        itype = str(alert.get("type") or "unknown")
        incident_id = f"{self.session_id}_{itype}_{ip}_{ts}".replace(":", "_")

        incident: Dict[str, object] = {
            "incident_id": incident_id,
            "time": datetime.now().isoformat(),
            "alert": alert,
            "network": netinfo,
            "actions": [],
        }

        if self._policy_bool("collect_forensics_on_alert", True):
            incident["forensics"] = self.collect_forensics_snapshot(incident_id)

        if self._policy_bool("auto_mitigate", False):
            incident["actions"].append(self.mitigate_block_ip(ip, incident_id, local_subnet))

        # Salva incidente
        try:
            inc_path = self.incidents_dir / incident_id / "incident.json"
            inc_path.parent.mkdir(parents=True, exist_ok=True)
            inc_path.write_text(json.dumps(incident, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass

        return incident

    def _get_pid_info(self, pid: Optional[int]) -> Dict[str, Optional[str]]:
        """
        Resolve informações úteis do processo (best-effort), com cache.
        """
        if not pid:
            return {"pid": None, "name": None, "exe": None, "username": None}
        if pid in self.pid_cache:
            return self.pid_cache[pid]
        info: Dict[str, Optional[str]] = {"pid": str(pid), "name": None, "exe": None, "username": None}
        try:
            p = psutil.Process(pid)
            info["name"] = p.name()
            try:
                info["exe"] = p.exe()
            except Exception:
                info["exe"] = None
            try:
                info["username"] = p.username()
            except Exception:
                info["username"] = None
        except Exception:
            # processo pode ter terminado / sem permissão
            pass
        self.pid_cache[pid] = info
        return info

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
                    # subnet "real" (rede), ex: 192.168.15.0/24
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                        info["subnet"] = str(net)
                    except Exception:
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

        def _clean_ip_token(tok: str) -> str:
            # nmap pode retornar "(192.168.x.y)" quando há hostname
            t = tok.strip()
            if t.startswith("(") and t.endswith(")"):
                t = t[1:-1].strip()
            return t

        current_ip: Optional[str] = None
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Nmap scan report for "):
                parts = line.split()
                ip = _clean_ip_token(parts[-1])
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

    def start_tshark_metadata_stream(self, interface: str) -> bool:
        """
        Inicia um stream passivo de metadados via tshark (DNS/TLS SNI/HTTP Host),
        salvando eventos em JSONL e alimentando estatísticas para o relatório.
        """
        code, _, _ = self.run_command(["tshark", "-D"], timeout=10)
        if code != 0:
            return False

        # Importante: isto NÃO é "intrusivo" — apenas lê pacotes (como Wireshark).
        # Observação: em Wi‑Fi sem monitor mode/espelhamento, normalmente só verá tráfego do próprio host.
        fields = [
            "frame.time_epoch",
            "_ws.col.Protocol",
            "ip.src", "ip.dst",
            "ipv6.src", "ipv6.dst",
            "tcp.srcport", "tcp.dstport",
            "udp.srcport", "udp.dstport",
            "dns.qry.name", "dns.resp.name",
            "tls.handshake.extensions_server_name",
            "http.host", "http.request.uri",
            "http.user_agent",
        ]

        # Filtro: coletar somente o que ajuda a "identificar" tráfego (sem payload).
        display_filter = (
            "dns or tls.handshake.extensions_server_name or http.host"
        )

        cmd = ["tshark", "-i", interface, "-l", "-n", "-q",
               "-Y", display_filter,
               "-T", "fields",
               "-E", "separator=\t",
               "-E", "occurrence=f",
               "-E", "quote=n"] + sum([["-e", f] for f in fields], [])

        try:
            self.tshark_meta_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        except Exception:
            self.tshark_meta_proc = None
            return False

        def _meta_reader() -> None:
            assert self.tshark_meta_proc is not None
            stdout = self.tshark_meta_proc.stdout
            if stdout is None:
                return
            for raw_line in stdout:
                if self.stop_flag:
                    break
                line = raw_line.rstrip("\n")
                if not line:
                    continue
                parts = line.split("\t")
                # Preenche faltantes para garantir indexação estável
                if len(parts) < len(fields):
                    parts += [""] * (len(fields) - len(parts))
                rec = dict(zip(fields, parts))

                # Normaliza IPs (IPv4/IPv6)
                src_ip = rec.get("ip.src") or rec.get("ipv6.src") or ""
                dst_ip = rec.get("ip.dst") or rec.get("ipv6.dst") or ""

                # Extrai "domínio" (melhor esforço)
                domain = (
                    (rec.get("dns.qry.name") or "").strip()
                    or (rec.get("tls.handshake.extensions_server_name") or "").strip()
                    or (rec.get("http.host") or "").strip()
                )
                if domain:
                    self.domain_count[domain] += 1
                    if dst_ip:
                        self.remote_ip_domains[dst_ip].add(domain)
                        self.remote_ip_domain_count[dst_ip][domain] += 1

                # Persistência (JSONL) — útil pra triagem rápida sem abrir o pcap
                try:
                    if self._meta_events_fh is None:
                        self._meta_events_fh = self.meta_events_path.open("a", encoding="utf-8")
                    evt = {
                        "time_epoch": rec.get("frame.time_epoch"),
                        "protocol": rec.get("_ws.col.Protocol"),
                        "src_ip": src_ip or None,
                        "dst_ip": dst_ip or None,
                        "tcp_dstport": rec.get("tcp.dstport") or None,
                        "udp_dstport": rec.get("udp.dstport") or None,
                        "dns_qry_name": rec.get("dns.qry.name") or None,
                        "tls_sni": rec.get("tls.handshake.extensions_server_name") or None,
                        "http_host": rec.get("http.host") or None,
                        "http_uri": rec.get("http.request.uri") or None,
                        "http_user_agent": rec.get("http.user_agent") or None,
                    }
                    self._meta_events_fh.write(json.dumps(evt, ensure_ascii=False) + "\n")
                    self._meta_events_fh.flush()
                except Exception:
                    # Não derruba o sentinela por falha de IO
                    pass

        t = threading.Thread(target=_meta_reader, daemon=True)
        t.start()
        return True

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
        if self.tshark_meta_proc and self.tshark_meta_proc.poll() is None:
            try:
                self.tshark_meta_proc.terminate()
                try:
                    self.tshark_meta_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.tshark_meta_proc.kill()
            except Exception:
                pass
        try:
            if self._meta_events_fh is not None:
                self._meta_events_fh.close()
        except Exception:
            pass


    # ---------------------- monitoramento em tempo real (IDS) ---------------------- #

    def check_for_scan_alert(self, r_ip: str, ports: Set[int], count: int, netinfo: Optional[Dict] = None, local_subnet: Optional[str] = None) -> None:
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
                # Resposta pró-ativa local (sem retaliação)
                try:
                    if netinfo is not None:
                        self.record_incident(alert, netinfo, local_subnet)
                except Exception:
                    pass
    
    def monitor_loop(self, my_ip: Optional[str], local_subnet: Optional[str], netinfo: Dict) -> None:
        """
        Loop de vigilância silenciosa otimizado.
        """
        print("\n[*] Iniciando vigilância silenciosa da rede (Ctrl+C para encerrar)...")

        while not self.stop_flag:
            now = time.time()
            # limpeza periódica do estado de dedupe
            try:
                if self.conn_last_seen:
                    stale = [k for k, ts in self.conn_last_seen.items() if (now - ts) > CONN_STATE_TTL_SECONDS]
                    for k in stale:
                        self.conn_last_seen.pop(k, None)
            except Exception:
                pass

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

                # Dedupe por tupla para não inflar estatísticas por amostragem
                l_ip = getattr(c.laddr, "ip", None) if getattr(c, "laddr", None) else None
                l_port = getattr(c.laddr, "port", None) if getattr(c, "laddr", None) else None
                pid_val = getattr(c, "pid", None)
                ctype = getattr(c, "type", None)
                status = getattr(c, "status", None)
                key = (pid_val, l_ip, l_port, r_ip, int(r_port), ctype, status)
                last = self.conn_last_seen.get(key)
                is_new = (last is None) or ((now - last) > CONN_DEDUPE_WINDOW_SECONDS)
                self.conn_last_seen[key] = now

                # Atribuir ao processo (quando possível)
                pid_info = self._get_pid_info(pid_val)
                proc_label = pid_info.get("name") or (f"pid:{pid_info.get('pid')}" if pid_info.get("pid") else "desconhecido")
                self.process_conn_count[proc_label] += 1
                self.process_unique_remote_ips[proc_label].add(r_ip)
                self.process_unique_remote_ports[proc_label].add(int(r_port))
                self.process_remote_ip_count[proc_label][r_ip] += 1

                # 1. Registrar portas e contagens
                ports = self.ip_ports_seen.setdefault(r_ip, set())
                ports.add(r_port)
                samples = self.ip_conn_samples.get(r_ip, 0) + 1
                self.ip_conn_samples[r_ip] = samples
                if is_new:
                    self.ip_conn_unique[r_ip] = self.ip_conn_unique.get(r_ip, 0) + 1
                count_for_alert = self.ip_conn_unique.get(r_ip, 0)

                # 2. Executar heurística IDS (Scan Alert)
                # Otimização: Usamos uma função separada para manter o loop limpo
                self.check_for_scan_alert(r_ip, ports, count_for_alert, netinfo=netinfo, local_subnet=local_subnet)
                
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
            f.write("- **Atribuição por processo** (quando disponível via PID: qual programa gerou a conexão).\n")
            f.write("- **Metadados de tráfego** via tshark (DNS / TLS SNI / HTTP Host), sem inspecionar payload.\n")
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
                "connections_samples": self.ip_conn_samples.get(ip, 0),
                "connections_unique_estimate": self.ip_conn_unique.get(ip, 0),
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
            "traffic_enrichment": {
                "meta_events_jsonl": str(self.meta_events_path) if self.meta_events_path.exists() else None,
                "top_domains": self.domain_count.most_common(50),
                "remote_ip_domains": {ip: sorted(list(domains)) for ip, domains in self.remote_ip_domains.items()},
                "remote_ip_domain_top": {
                    ip: cnt.most_common(10) for ip, cnt in self.remote_ip_domain_count.items()
                },
                "process_top": self.process_conn_count.most_common(30),
                "process_unique_remotes": {
                    proc: len(ips) for proc, ips in self.process_unique_remote_ips.items()
                },
                "process_remote_top": {
                    proc: cnt.most_common(10) for proc, cnt in self.process_remote_ip_count.items()
                },
            },
            "policy": self.policy,
            "baseline": {
                "path": str(self.baseline_path) if self.baseline_path else None,
                "diff": self.baseline_diff,
            },
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
                    key=lambda item: item[1].get('connections_unique_estimate', 0), 
                    reverse=True
                )
                
                for ip, stats in sorted_stats:
                    rdns_info = f"({stats['rdns']})" if stats['rdns'] else ""
                    f.write(
                        f"- `{ip}` {rdns_info}: {stats['unique_ports']} porta(s) distinta(s), "
                        f"{stats.get('connections_unique_estimate', 0)} conexão(ões) únicas (est.), "
                        f"{stats.get('connections_samples', 0)} amostras\n"
                    )
            else:
                f.write("- Nenhum IP externo significativo observado.\n")

            f.write("\n### Enriquecimento de Tráfego (DNS / TLS SNI / HTTP Host)\n\n")
            if self.domain_count:
                f.write("- **Top domínios observados** (contagem aproximada de eventos):\n")
                for dom, cnt in self.domain_count.most_common(25):
                    f.write(f"  - `{dom}`: {cnt}\n")
            else:
                f.write("- Nenhum domínio/host foi observado via metadados (DNS/SNI/HTTP).\\\n")
                f.write("  - Dica: em Wi‑Fi sem espelhamento/monitor mode, normalmente você só vê o tráfego do próprio host.\n")

            f.write("\n### Destinos Enriquecidos (IP → domínios)\n\n")
            if self.remote_ip_domain_count:
                # Ordena IPs por volume de conexões (psutil), e mostra os top domínios por IP (tshark)
                top_ips = sorted(self.ip_conn_unique.items(), key=lambda x: x[1], reverse=True)[:10]
                for ip, conn_cnt in top_ips:
                    domains_top = self.remote_ip_domain_count.get(ip)
                    if not domains_top:
                        continue
                    rdns_info = self.ip_rdns_cache.get(ip)
                    rdns_str = f" ({rdns_info})" if rdns_info else ""
                    f.write(f"- `{ip}`{rdns_str}: **{conn_cnt}** conexões (host local)\\\n")
                    for dom, dcnt in domains_top.most_common(5):
                        f.write(f"  - `{dom}`: {dcnt}\n")
            else:
                f.write("- Sem dados suficientes para mapear IP → domínio (nesta sessão).\n")

            f.write("\n### Tráfego por Processo (host local)\n\n")
            if self.process_conn_count:
                f.write("- **Top processos por conexões observadas** (aproximação por amostragem `psutil`):\n")
                for proc, cnt in self.process_conn_count.most_common(15):
                    rems = len(self.process_unique_remote_ips.get(proc, set()))
                    ports = len(self.process_unique_remote_ports.get(proc, set()))
                    f.write(f"  - `{proc}`: {cnt} conexões, {rems} IPs remotos, {ports} portas remotas\n")
                f.write("\n- **Top destinos por processo** (amostra):\n")
                for proc, _ in self.process_conn_count.most_common(5):
                    top_dsts = self.process_remote_ip_count.get(proc)
                    if not top_dsts:
                        continue
                    f.write(f"  - `{proc}`:\n")
                    for dip, dcnt in top_dsts.most_common(5):
                        rdns_info = self.ip_rdns_cache.get(dip)
                        rdns_str = f" ({rdns_info})" if rdns_info else ""
                        f.write(f"    - `{dip}`{rdns_str}: {dcnt}\n")
            else:
                f.write("- Não foi possível atribuir conexões a processos (sem permissão ou sem dados de PID).\n")

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

            f.write("\n### Resposta Pró-ativa / Incidentes\n\n")
            f.write(f"- Pasta de incidentes (evidências/ações): `{self.incidents_dir}`\n")
            if self._policy_bool('auto_mitigate', False):
                dry = self._policy_bool("dry_run", True)
                f.write(f"- Auto-mitigação: **habilitada** (dry-run: **{dry}**)\n")
            else:
                f.write("- Auto-mitigação: desabilitada (padrão seguro)\n")

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


def load_policy(path: Optional[str]) -> Dict:
    if not path:
        return {}
    try:
        p = Path(path).expanduser().resolve()
        if not p.exists():
            return {}
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}

def load_baseline(path: Path) -> Optional[Dict]:
    try:
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

def snapshot_baseline(s: AutoNetworkSentinel) -> Dict:
    return {
        "time": datetime.now().isoformat(),
        "top_processes": [p for p, _ in s.process_conn_count.most_common(50)],
        "top_domains": [d for d, _ in s.domain_count.most_common(200)],
        "top_remote_ips": [ip for ip, _ in sorted(s.ip_conn_unique.items(), key=lambda x: x[1], reverse=True)[:200]],
    }

def diff_baseline(current: Dict, baseline: Optional[Dict]) -> Dict:
    if not baseline:
        return {"status": "no_baseline"}
    cur_procs = set(current.get("top_processes", []))
    cur_domains = set(current.get("top_domains", []))
    cur_ips = set(current.get("top_remote_ips", []))
    base_procs = set(baseline.get("top_processes", []))
    base_domains = set(baseline.get("top_domains", []))
    base_ips = set(baseline.get("top_remote_ips", []))
    return {
        "status": "ok",
        "new_processes": sorted(list(cur_procs - base_procs))[:50],
        "new_domains": sorted(list(cur_domains - base_domains))[:100],
        "new_remote_ips": sorted(list(cur_ips - base_ips))[:100],
    }

def save_baseline(path: Path, snap: Dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(snap, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="AutoSentinel — monitoramento defensivo da rede (uso autorizado).")
    ap.add_argument("--policy", default=str((BASE_DIR / "policy.json")), help="Caminho do arquivo policy.json")
    ap.add_argument("--auto-mitigate", action="store_true", help="Habilita mitigação automática local (bloqueio) conforme policy")
    ap.add_argument("--no-forensics", action="store_true", help="Desabilita coleta forense ao disparar alertas")
    ap.add_argument("--dry-run", action="store_true", help="Não aplica comandos de mitigação; apenas registra (recomendado)")
    ap.add_argument("--block-method", choices=["auto", "ufw", "iptables", "none"], default=None, help="Método de bloqueio local")
    ap.add_argument("--baseline", default=str((LOG_DIR / "baseline.json")), help="Caminho do baseline.json")
    ap.add_argument("--update-baseline", action="store_true", help="Atualiza baseline.json ao final da sessão")
    return ap.parse_args()

def main() -> None:
    args = parse_args()
    policy = load_policy(args.policy)
    # Overrides via CLI (prioridade sobre arquivo)
    if args.auto_mitigate:
        policy["auto_mitigate"] = True
    if args.no_forensics:
        policy["collect_forensics_on_alert"] = False
    if args.dry_run:
        policy["dry_run"] = True
    if args.block_method is not None:
        policy["block_method"] = args.block_method

    # Defaults seguros
    policy.setdefault("dry_run", True)
    policy.setdefault("auto_mitigate", False)
    policy.setdefault("collect_forensics_on_alert", True)
    policy.setdefault("block_method", "auto")

    sentinel = AutoNetworkSentinel(policy=policy)

    netinfo = sentinel.detect_network()
    my_ip = netinfo.get("ip")
    local_subnet = netinfo.get("subnet")
    
    # --- Passo 1: Descoberta e Análise de Vulnerabilidades ---
    # Captura Hosts e Serviços abertos em um único passo
    hosts, host_services = sentinel.discover_hosts_and_services(netinfo.get("subnet") or "", my_ip)

    # --- Passo 2: Inicialização do Monitoramento Passivo ---
    pcap_path = None
    if netinfo.get("interface"):
        pcap_path = sentinel.start_tshark_capture(netinfo["interface"])
        # Stream passivo de metadados (DNS/SNI/HTTP) para melhorar a identificação de tráfego
        ok_meta = sentinel.start_tshark_metadata_stream(netinfo["interface"])
        if ok_meta:
            print(f"[+] Enriquecimento de tráfego (metadados) ativo em: {sentinel.meta_events_path}")

    # --- Passo 3: Relatório Inicial com dados de vulnerabilidade ---
    sentinel.write_initial_report(netinfo, hosts, host_services, pcap_path)
    print(f"[+] Relatório em andamento (Markdown): {sentinel.report_md}")

    # --- Passo 4: Loop de Monitoramento (IDS) ---
    def handle_sigint(signum, frame): # type: ignore[override]
        sentinel.stop_flag = True

    signal.signal(signal.SIGINT, handle_sigint)

    # Otimização: Roda o monitoramento psutil no thread principal.
    # Se fossemos adicionar um monitoramento de Sniffing (ex: Scapy), rodaríamos ele em um thread separado.
    monitor_thread = threading.Thread(target=sentinel.monitor_loop, args=(my_ip, local_subnet, netinfo), daemon=True)
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

    # Baseline/diff
    try:
        sentinel.baseline_path = Path(args.baseline).expanduser().resolve()
        sentinel.baseline_loaded = load_baseline(sentinel.baseline_path)
        snap = snapshot_baseline(sentinel)
        sentinel.baseline_diff = diff_baseline(snap, sentinel.baseline_loaded)
        if args.update_baseline:
            save_baseline(sentinel.baseline_path, snap)
    except Exception:
        pass

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