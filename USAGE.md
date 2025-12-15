# USAGE — AutoSentinel

Este documento descreve **como executar**, **o que o AutoSentinel faz em cada etapa** e **como interpretar os resultados gerados**.

---

## Execução Básica

O AutoSentinel foi projetado para **Linux (Debian/Ubuntu)** e **requer privilégios elevados** devido ao uso de `nmap` e `tshark`.

```bash
sudo python3 AutoSentinel.py
```

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

### 4️⃣ Monitoramento em Tempo Real (IDS Heurístico)

Enquanto o script está ativo, o AutoSentinel monitora:

* Conexões de rede ativas (`psutil`)
* IPs remotos acessados
* Portas distintas utilizadas
* Volume de conexões por IP

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
