# USAGE — AutoSentinel

Este documento descreve **como executar**, **o que o AutoSentinel faz em cada etapa** e **como interpretar os resultados gerados**.

---

## Execução Básica

O AutoSentinel foi projetado para **Linux (Debian/Ubuntu)** e **requer privilégios elevados** devido ao uso de `nmap` e `tshark`.

```bash
sudo python3 AutoSentinel.py
```

## Execução Pró-ativa (mitigação, baseline e forense)

O AutoSentinel pode registrar incidentes e (opcionalmente) aplicar mitigação local (bloqueio de IP) **no host onde ele está rodando**.

> ✅ Uso defensivo e autorizado.  
> ⚠️ O AutoSentinel **não é ferramenta de retaliação** e não deve ser usado para “escanear invasores” na internet.

### 1) Dry-run (recomendado)

Simula bloqueios (registra comandos) sem alterar firewall:

```bash
sudo python3 AutoSentinel.py --auto-mitigate --dry-run
```

### 2) Aplicando bloqueios reais (cuidado)

```bash
sudo python3 AutoSentinel.py --auto-mitigate --block-method ufw
```

Artefatos e evidências ficam em:

```text
logs/incidents/<incident_id>/
```

### 3) Baseline / Diff (o que mudou entre sessões)

```bash
# Atualiza baseline ao final da sessão
sudo python3 AutoSentinel.py --update-baseline
```

Na próxima execução, o relatório final mostra **novos processos**, **novos IPs remotos** e **novos domínios** (quando observáveis).

> ⚠️ **Importante**
>
> * Execute sempre com `sudo`
> * Não execute em redes que você não possui autorização

Para encerrar a sessão de vigilância:

```text
Ctrl + C
```

O encerramento é **controlado** e gera automaticamente os relatórios finais.

---

## Fluxo de Funcionamento

O AutoSentinel executa as etapas abaixo **em ordem**:

### 1️⃣ Detecção de Rede

Identifica automaticamente:

* Interface de rede ativa
* IP local
* Gateway
* Sub-rede (CIDR)

Ferramentas utilizadas:

* `ip route`
* `ip addr`

---

### 2️⃣ Descoberta de Hosts e Serviços (Ativo)

Executa:

```bash
nmap -sn <sub-rede>
```

Depois, para cada host ativo identificado:

```bash
nmap -sV -T4 <hosts>
```

Resultado:

* Lista de hosts ativos na LAN
* Portas abertas
* Serviços detectados
* Base inicial para análise de vulnerabilidades

---

### 3️⃣ Captura de Tráfego (Passiva)

Inicia captura silenciosa usando `tshark`:

* Interface detectada automaticamente
* Saída em arquivo `.pcap`
* Compatível com **Wireshark**

O arquivo gerado fica em:

```text
logs/sentinela_rede_<timestamp>.pcap
```

---

### 3️⃣.1 Enriquecimento de Tráfego (Metadados: DNS / TLS SNI / HTTP Host)

Além do `.pcap`, o AutoSentinel tenta gerar um arquivo de **eventos de metadados** (formato **JSONL**: 1 JSON por linha) para facilitar a identificação de tráfego sem abrir o Wireshark:

```text
logs/sentinela_rede_<timestamp>_meta.jsonl
```

O que ele captura (best-effort, sem payload):

* Consultas DNS (`dns.qry.name`)
* SNI de TLS (quando presente) (`tls.handshake.extensions_server_name`)
* Host/URI de HTTP (quando presente) (`http.host`, `http.request.uri`)

> ⚠️ Observação importante: em **Wi‑Fi comum**, sem espelhamento de porta (SPAN) / monitor mode, normalmente você verá **principalmente o tráfego do próprio computador** onde o script está rodando.

Exemplos rápidos de triagem:

```bash
# Ver os 50 últimos eventos
tail -n 50 logs/sentinela_rede_*_meta.jsonl

# Filtrar por um domínio (DNS/SNI/HTTP Host)
grep -i "google" logs/sentinela_rede_*_meta.jsonl | head

# Se tiver jq instalado: top hosts (simples)
jq -r '.dns_qry_name // .tls_sni // .http_host // empty' logs/sentinela_rede_*_meta.jsonl \
  | sort | uniq -c | sort -nr | head -n 25
```

---

### 4️⃣ Monitoramento em Tempo Real (IDS Heurístico)

Enquanto o script está ativo, o AutoSentinel monitora:

* Conexões de rede ativas (`psutil`)
* IPs remotos acessados
* Portas distintas utilizadas
* Volume de conexões por IP
* **Processos responsáveis** (quando disponível via PID)

#### Heurística de Alerta

Um alerta é disparado quando um IP remoto excede:

* **15 portas distintas**
* **40 conexões**

Tipo de alerta:

* `possible_scan`

Cada alerta inclui:

* IP
* Quantidade de portas
* Quantidade de conexões
* Timestamp
* rDNS (quando disponível)

---

### 5️⃣ Relatórios Gerados

Ao finalizar a sessão (`Ctrl+C`), o AutoSentinel gera:

#### 📄 Markdown (Leitura Humana)

```text
logs/sentinela_rede_<timestamp>.md
```

Inclui:

* Contexto da rede
* Hosts da LAN
* Serviços abertos
* Alertas detectados
* Estatísticas de tráfego
* Referência ao arquivo `.pcap`

#### 📊 JSON (Análise Estruturada)

```text
logs/sentinela_rede_<timestamp>.json
```

Ideal para:

* Integração com SIEM
* Dashboards
* Análise posterior automatizada

Também inclui dados de enriquecimento, como:

* Top processos por conexões observadas (host local)
* Top domínios/hosts observados via metadados (DNS/SNI/HTTP)
* Mapeamento IP → domínios (quando possível)

---

## Abrindo os Relatórios

O relatório Markdown é aberto automaticamente usando:

```bash
xdg-open
```

Caso não abra, execute manualmente:

```bash
xdg-open logs/sentinela_rede_<timestamp>.md
```

---

## Boas Práticas de Uso

✔ Execute em ambientes controlados
✔ Use para **baseline de rede**
✔ Compare sessões em horários diferentes
✔ Analise `.pcap` no Wireshark quando alertas forem gerados

---

## Aviso Legal

Este projeto é destinado a **uso educacional, defensivo e autorizado**.

O uso indevido é de **responsabilidade exclusiva do operador**.

---

🔐 *AutoSentinel — Vigilância inteligente, passiva e documentada.*
