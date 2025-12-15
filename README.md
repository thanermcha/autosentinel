# 🛡️ Auto Sentinel Network

**Vigilância de Rede Proativa para Pequenas e Médias Empresas (PMEs)**

---

## 📌 Visão Geral

Olá! Sou **Thaner Maia**, criador do **Auto Sentinel Network**. Este projeto nasceu de uma necessidade real: proteger pequenas e médias empresas contra ataques básicos (e recorrentes) de rede que passam despercebidos até causarem danos reais.

O Auto Sentinel Network é um **sentinela leve, prático e open-source**, criado para transformar monitoramento técnico em **informação acionável para gestão**, ajudando empresários, gestores de TI e profissionais técnicos a **visualizar riscos**, **detectar comportamentos suspeitos** e **agir rapidamente**.

---

## 🎯 Por que você precisa do Auto Sentinel?

Ataques cibernéticos não começam, na maioria das vezes, com algo sofisticado. Eles começam com:

* Varreduras silenciosas de portas
* Serviços desatualizados
* Má configuração de rede
* Falta de monitoramento contínuo

Esses vetores são especialmente comuns em PMEs.

O **Auto Sentinel Network** atua exatamente nesses pontos, oferecendo **duas camadas essenciais de defesa** em um único script Python:

### 🔍 1. Avaliação de Vulnerabilidades (VAS)

* Escaneia a rede local
* Identifica hosts ativos
* Detecta portas abertas e serviços expostos
* Evidencia **pontos de entrada fáceis** para invasores

### 🚨 2. IDS Heurístico (Detecção de Intrusão)

* Monitora conexões em tempo real
* Detecta padrões suspeitos (scans rápidos, excesso de conexões)
* Gera alertas imediatos

> **Objetivo:** permitir decisões rápidas e conscientes, mesmo para quem não é especialista em segurança.

---

## 🧭 Índice

* [💻 Instalação Rápida](#-instalação-rápida)
* [📦 Pré-requisitos](#-pré-requisitos)
* [🐧 Instalação no Linux](#-instalação-no-linux)
* [🪟 Instalação no Windows (WSL)](#-instalação-no-windows-wsl)
* [🚀 Como Executar](#-como-executar)
* [📊 Análise dos Resultados](#-análise-dos-resultados)
* [📄 Logs e Relatórios](#-logs-e-relatórios)
* [⚠️ Avisos Importantes](#️-avisos-importantes)
* [✅ Conclusão](#-conclusão)

---

## 💻 Instalação Rápida

### 📦 Pré-requisitos

O Auto Sentinel depende de ferramentas de baixo nível para análise de rede:

| Componente | Tipo              | Função                        | Instalação (Debian/Ubuntu) |
| ---------- | ----------------- | ----------------------------- | -------------------------- |
| Python 3   | Linguagem         | Executar o script             | `sudo apt install python3` |
| Nmap       | Scanner           | Avaliação de vulnerabilidades | `sudo apt install nmap`    |
| Tshark     | Captura           | Base do IDS                   | `sudo apt install tshark`  |
| Psutil     | Biblioteca Python | Monitorar conexões            | `pip install psutil`       |

---

## 🐧 Instalação no Linux

### 1️⃣ Clonar o repositório

```bash
git clone https://github.com/seu-usuario/AutoSentinelNetwork.git
cd AutoSentinelNetwork
```

### 2️⃣ Instalar ferramentas do sistema

```bash
sudo apt update
sudo apt install python3 nmap tshark -y
```

### 3️⃣ Instalar dependências Python

```bash
pip install -r requirements.txt
```

---

## 🪟 Instalação no Windows (WSL)

> **Recomendado:** Windows Subsystem for Linux (WSL 2)

### 1️⃣ Ativar o WSL (PowerShell como Administrador)

```powershell
wsl --install
```

### 2️⃣ Dentro do WSL

Siga exatamente os mesmos passos descritos na seção **Instalação no Linux**.

---

## 🚀 Como Executar

> ⚠️ O script **precisa ser executado com sudo** para acesso a rede e captura de pacotes.

```bash
sudo python3 AutoSentinel.py
```

### O que acontece durante a execução?

1. 🔍 Varredura da rede local (Nmap)
2. 👁️ Monitoramento contínuo de conexões
3. 🚨 Alertas em tempo real
4. 📄 Geração automática de relatórios

Pressione **CTRL + C** para encerrar e gerar os arquivos finais.

---

## 📊 Análise dos Resultados

Os resultados são salvos na pasta `logs/`:

### �� Relatório Markdown (`.md`)

* Visão gerencial
* Alertas resumidos
* Hosts e serviços identificados

### 🧪 Relatório Técnico (`.json`)

* Dados completos de análise
* Ideal para integrações futuras

### 📡 Captura de Tráfego (`.pcap`)

* Pode ser analisado no **Wireshark**

---

## ⚠️ Avisos Importantes

* Use **apenas em redes que você possui autorização**
* Ferramenta educacional e defensiva
* Não substitui firewall ou SOC profissional

---

## ✅ Conclusão

O **Auto Sentinel Network** democratiza o acesso à segurança de rede, permitindo que PMEs adotem uma postura **proativa**, baseada em dados e monitoramento real.

Segurança não é produto. É **processo contínuo**.

Contribuições, melhorias e feedbacks são bem-vindos.

---

📌 **Autor:** Thaner Maia
🌐 **Projeto:** Auto Sentinel Network
🛡️ **Licença:** Open Source
# autosentinel
