# 🧭 Playbook de Resposta a Incidente — Perda de Acesso ao Instagram

Este guia é **defensivo** e focado em **recuperação** e **investigação** no seu ambiente (contas/dispositivos/rede).

> ⚠️ Importante  
> - Não vou orientar qualquer tentativa de “invadir” a conta ou terceiros.  
> - Priorize **conter** o incidente (reduzir risco) antes de tentar “entender tudo”.

---

## 0) Objetivo (o que você quer alcançar)

- **Recuperar o acesso** (ou no mínimo impedir que piore)
- **Remover persistência** (se algum dispositivo estiver comprometido)
- **Coletar evidências** (para você entender a causa: phishing, reuse de senha, malware, sessão roubada)
- **Evitar repetição** (higiene de senhas, 2FA, hardening do roteador)

---

## 1) Contenção imediata (faça agora)

### 1.1 Proteja seu e‑mail primeiro (é a “chave mestra”)

- Troque a senha do **e‑mail** (Gmail/Outlook/etc.) por uma senha **forte e única**
- Ative/garanta **2FA** no e‑mail (preferência: app autenticador ou chave FIDO2)
- Revise “**dispositivos conectados**” e “**sessões ativas**” do e‑mail e encerre as desconhecidas
- Revise regras de **encaminhamento** / **filtros** (atacantes costumam criar forward silencioso)

### 1.2 Recupere o Instagram (fluxo oficial)

- Use “Esqueci minha senha” e siga o fluxo do app/site
- Se houver alerta “e‑mail/telefone alterado”, procure por mensagens do Instagram e use “**reverter alteração**”
- Revise “**Atividade de login**” / “**onde você está conectado**” e encerre sessões desconhecidas

> Se você tiver e‑mail do Instagram sobre troca de e‑mail/senha, **salve** esses e‑mails (e cabeçalhos, se possível).

### 1.3 Trave o resto (reduz efeito dominó)

- Troque senhas de contas com **mesma senha** do Instagram (se existir)
- Habilite 2FA nas contas principais (e‑mail, banco, redes sociais)
- Se você usa gerenciador de senhas, revise se houve vazamento/alerta

---

## 2) Hipóteses mais comuns (para guiar a investigação)

- **Reuse de senha** (Instagram + outra conta vazada)
- **Phishing** (link falso pedindo login/2FA)
- **Malware/infostealer** no PC (roubo de cookies/sessão)
- **Sessão/cookie sequestrado** (extensão maliciosa, navegador comprometido)
- **Fraqueza no e‑mail** (o atacante controla o e‑mail e “reseta” tudo)

---

## 3) Evidência e investigação no(s) PC(s)

> Objetivo aqui: identificar **novo processo**, **persistência** e **comunicação estranha**.

### 3.1 Colete sinais básicos (rápido)

- Verifique extensões do navegador (Chrome/Firefox): remova as desconhecidas
- Verifique “aplicativos instalados recentemente” e serviços iniciando com o sistema

### 3.2 Execute o AutoSentinel em modo forense (recomendado)

No PC onde você suspeita que ocorreu o evento (e idealmente nos 3 PCs):

```bash
cd autosentinel
sudo python3 AutoSentinel.py --update-baseline
```

Para operar “pró‑ativo” mas sem bloquear nada (dry-run):

```bash
sudo python3 AutoSentinel.py --auto-mitigate --dry-run --update-baseline
```

O que olhar:

- `logs/sentinela_rede_*.md` (top processos + destinos)
- `logs/sentinela_rede_*_meta.jsonl` (DNS/SNI/HTTP Host)
- `logs/incidents/*/` (se algum alerta disparar, terá snapshots e `incident.json`)
- `baseline.json` + seção de diff no relatório (novos processos/domínios/IPs)

### 3.3 Se você suspeita de infostealer

Sem “limpar tudo” ainda:

- Faça **backup de evidências** (logs e outputs acima)
- Considere isolar o PC (tirar da rede) até revisar
- Se possível, rode antivírus/anti‑malware confiável e atualize o sistema

---

## 4) Evidência e investigação no roteador (Intelbras IWR 3000N)

Esse modelo é antigo; o foco é reduzir exposição e ver se existe algo anômalo:

- Confirme que **admin remota pela WAN** está desativada (se houver opção)
- Desative **UPnP** e **WPS** se não precisar
- Troque a senha de administração do roteador (forte, única)
- Verifique lista de dispositivos conectados (DHCP/ARP)

> Firmware: se for equipamento de operadora/travado, evite “flash por fora”. O ganho maior costuma ser colocar um roteador melhor “na frente” (quando possível) ou isolar por rede/SSID.

---

## 5) Estratégia “boa o bastante” para casa (3 PCs)

Se o objetivo é **monitorar continuamente** com pouca fricção:

- Rodar AutoSentinel em cada PC em sessões (ex.: 30–60 min) e comparar baseline/diff
- Centralizar logs depois (copiar `logs/` para uma máquina “analista”)
- Se você quiser “ver a rede toda”, considere um ponto de observação no gateway (SPAN/TAP/roteador com logs melhores)

---

## 6) O que eu preciso de você (para guiar melhor)

Responda com o que você souber:

1) Você ainda tem acesso ao **e‑mail** associado ao Instagram?  
2) Você recebeu e‑mails de “senha/e‑mail alterado”? (data/hora)  
3) Você tinha **2FA** no Instagram? (SMS/app)  
4) Você clicou em algum link suspeito ou instalou algo nos últimos dias?  
5) O incidente aconteceu em qual PC (ou celular)?


