# 📌 CHANGELOG — AutoSentinel (Notas de Atualização)

Este documento resume as mudanças do **AutoSentinel** e serve como “norte” para quem chega no repositório agora.

> **Uso responsável:** ferramenta defensiva para redes próprias/autorizadas.  
> O AutoSentinel **não** é feito para retaliação (“escanear invasores” na internet).

---

## 2025-12-20 — Atualização “Proativa + Forense + Baseline”

### Principais novidades

- **Modo pró‑ativo (opt‑in)**  
  - Adicionada **CLI** (linha de comando) e um arquivo `policy.json` para controlar comportamento.  
  - A mitigação automática (ex.: bloqueio de IP local) é **desabilitada por padrão**.
  - Suporte a **dry-run** (recomendado): registra comandos sem aplicar mudanças no firewall.

- **Incidentes + coleta forense automática (local)**  
  - Ao disparar um alerta, o AutoSentinel cria um diretório em `logs/incidents/<incident_id>/` contendo:
    - `incident.json` (alerta + ações)
    - snapshots locais (best-effort) como `ss`, `ps`, `ip`, `journalctl` (quando disponível)
    - `mitigation.json` (quando mitigação estiver ativa)

- **Enriquecimento de tráfego (metadados)**
  - Além do `.pcap`, o AutoSentinel tenta gerar:
    - `logs/sentinela_rede_<timestamp>_meta.jsonl`
  - Esse arquivo ajuda a identificar tráfego via:
    - DNS (consultas)
    - TLS SNI (quando disponível)
    - HTTP Host/URI (quando disponível)

- **Atribuição de tráfego por processo (host local)**
  - O relatório final passa a mostrar “top processos” e destinos por processo (quando o PID está disponível).

- **Baseline/Diff entre sessões**
  - Novo `baseline.json` (configurável por CLI) para destacar **mudanças** entre sessões:
    - novos processos
    - novos domínios
    - novos IPs remotos

### Correções/qualidade dos dados

- **Sub-rede exibida corretamente** (ex.: `192.168.15.0/24`, em vez de `192.168.15.6/24`).
- **Parsing de IPs do Nmap**: remove parênteses quando o output vem como `hostname (IP)`.
- **Estatísticas de conexões mais fiéis**:
  - separa “**conexões únicas (estimadas)**” vs “**amostras**”, reduzindo contagens infladas por amostragem do `psutil`.

---

## Como usar as novidades (resumo prático)

### Execução padrão (conservadora)

```bash
sudo python3 AutoSentinel.py
```

### Baseline (para comparar sessões)

```bash
sudo python3 AutoSentinel.py --update-baseline
```

### Pró‑ativo em modo seguro (dry-run)

```bash
sudo python3 AutoSentinel.py --auto-mitigate --dry-run
```

### Pró‑ativo aplicando bloqueio (cuidado)

```bash
sudo python3 AutoSentinel.py --auto-mitigate --block-method ufw
```

> Recomendação: use `--dry-run` por alguns dias, ajuste o `policy.json` e só então aplique bloqueios reais.

---

## Onde olhar os resultados

- **Relatório Markdown**: `logs/sentinela_rede_<timestamp>.md`  
- **Relatório JSON**: `logs/sentinela_rede_<timestamp>.json`  
- **PCAP**: `logs/sentinela_rede_<timestamp>.pcap` (Wireshark)  
- **Metadados (JSONL)**: `logs/sentinela_rede_<timestamp>_meta.jsonl`  
- **Incidentes**: `logs/incidents/<incident_id>/`

---

## Limitações importantes (contexto real)

- Em **Wi‑Fi comum**, sem espelhamento (SPAN) / monitor mode, você costuma ver principalmente o tráfego do **host** onde o script roda.
- Bloqueio automático via firewall é **host-based** (no PC onde roda) — não substitui regras no roteador/firewall de borda.

---

## Próximos passos (roadmap sugerido)

- Painel visual interativo a partir de:
  - `sentinela_rede_*.json` + `*_meta.jsonl` + `logs/incidents/*`
- Regras adicionais de detecção (ex.: “novos domínios fora de horário”, “novo processo falando com IPs externos”, “beaconing”).
- Integrações (opcionais): export para SIEM/Elastic/Wazuh.


