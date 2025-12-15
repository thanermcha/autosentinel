# 📦 Instalação — Auto Sentinel Network

Este documento descreve o processo de instalação do **Auto Sentinel Network** de forma clara e reproduzível, tanto em Linux quanto em Windows (via WSL).

---

## 📌 Requisitos Gerais

O Auto Sentinel Network depende de **ferramentas de sistema** e **bibliotecas Python** para funcionar corretamente.

### 🔧 Ferramentas de Sistema (obrigatórias)

| Ferramenta | Função                              |
| ---------- | ----------------------------------- |
| Python 3   | Execução do script principal        |
| Nmap       | Varredura de hosts e portas (VAS)   |
| Tshark     | Captura de pacotes (IDS heurístico) |

### 📚 Biblioteca Python

| Biblioteca | Função                            |
| ---------- | --------------------------------- |
| psutil     | Monitoramento de conexões de rede |

---

## 🐧 Instalação no Linux (Debian, Ubuntu, Mint, Zorin)

> ✅ Plataforma recomendada para uso real e laboratórios

### 1️⃣ Atualizar o sistema

```bash
sudo apt update && sudo apt upgrade -y
```

### 2️⃣ Instalar ferramentas de sistema

```bash
sudo apt install -y python3 python3-pip nmap tshark
```

> Durante a instalação do **tshark**, permita a captura de pacotes para usuários não-root **ou** execute sempre o script com `sudo`.

### 3️⃣ Clonar o repositório

```bash
git clone https://github.com/thanermcha/autosentinel.git
cd autosentinel
```

### 4️⃣ Instalar dependências Python

```bash
pip3 install -r requirements.txt
```

---

## 🪟 Instalação no Windows (WSL 2)

> ⚠️ Execução nativa no Windows **não é recomendada** devido a limitações de captura de pacotes.

### 1️⃣ Ativar o WSL 2 (PowerShell como Administrador)

```powershell
wsl --install
```

* Reinicie o sistema se solicitado
* Configure o usuário Linux

### 2️⃣ Dentro do terminal WSL

Siga **exatamente** os mesmos passos descritos na seção **Instalação no Linux**.

---

## 🔐 Permissões Necessárias

O Auto Sentinel Network executa operações de baixo nível:

* Varredura de rede
* Captura de pacotes
* Inspeção de conexões

👉 Por isso, deve ser executado com:

```bash
sudo python3 AutoSentinel.py
```

---

## 🧪 Verificação Pós-instalação

Antes da primeira execução, valide:

```bash
which nmap
which tshark
python3 --version
```

Se todos retornarem caminhos válidos, o ambiente está pronto.

---

## ⚠️ Observações Importantes

* Use apenas em redes próprias ou autorizadas
* Ferramenta defensiva e educacional
* Não substitui firewall ou SOC

---

📌 **Documento:** INSTALL.md
🛡️ **Projeto:** Auto Sentinel Network
