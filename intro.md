# 🛡️ Auto Sentinel Network: Vigilância de Rede Proativa para o Seu Negócio

Olá\! Sou o Thaner, criador do **Auto Sentinel Network**, e este projeto nasceu da frustração de ver Pequenas e Médias Empresas (PMEs como a minha, ideiasblah.com.br) vulneráveis a ataques básicos de rede. Se você é um empresário, gestor de TI ou alguém preocupado com a segurança digital da sua empresa, esta ferramenta é o seu sentinela pessoal, fácil de usar, prático e aberto para colaboração de modo que o maior número de pessoas possam se beneficiar desta solução básica, que nasceu de um problema e necessidades reais, após ter toda a minha rede explorada e infectada por malwares, rootkits e sabe-se lá o que mais, algo que ainda está endo investigado e que aos poucos será reveleado. 

### 🎯 Por Que Você Precisa do Sentinela?

Ataques cibernéticos e vazamentos de dados não são exclusividade das grandes corporações. Na verdade, a maioria dos ataques começa com varreduras silenciosas em busca de portas abertas e serviços desatualizados – exatamente o que as PMEs costumam negligenciar.

O Auto Sentinel Network oferece duas defesas cruciais em um único e leve script Python:

1.  **Avaliação de Vulnerabilidades (VAS)**: Escaneia sua rede local em busca de portas abertas, mostrando exatamente quais são os **pontos de entrada fáceis** para um invasor.
2.  **Sistema de Detecção de Intrusão (IDS) Heurístico**: Monitora o tráfego em tempo real, alertando imediatamente sobre padrões suspeitos, como tentativas rápidas de varredura ou conexões excessivas a IPs desconhecidos.

**Nossa missão é transformar monitoramento técnico em relatórios acionáveis para gestão.**

-----

## 🧭 Índice do `README.md`

1.  [🎯 Por Que Você Precisa do Sentinela?](https://www.google.com/search?q=%23-por-que-voc%C3%AA-precisa-do-sentinela)
2.  [💻 Instalação Rápida e Uso (Multiplataforma)](https://www.google.com/search?q=%23-instala%C3%A7%C3%A3o-r%C3%A1pida-e-uso-multiplataforma)
      * [Pré-requisitos Fundamentais](https://www.google.com/search?q=%23pr%C3%A9-requisitos-fundamentais)
      * [Instalação no Linux (Debian, Ubuntu, Mint, Zorin)](https://www.google.com/search?q=%23instala%C3%A7%C3%A3o-no-linux-debian-ubuntu-mint-zorin)
      * [Instalação no Windows (Recomendado: WSL)](https://www.google.com/search?q=%23instala%C3%A7%C3%A3o-no-windows-recomendado-wsl)
3.  [�� Como Usar e Executar o Sentinela](https://www.google.com/search?q=%23-como-usar-e-executar-o-sentinela)
4.  [📊 Guia de Análise dos Resultados](https://www.google.com/search?q=%23-guia-de-an%C3%A1lise-dos-resultados)
      * [Análise de Vulnerabilidade da LAN (Nmap)](https://www.google.com/search?q=%23an%C3%A1lise-de-vulnerabilidade-da-lan-nmap)
      * [Análise de Tráfego e Alertas (IDS)](https://www.google.com/search?q=%23an%C3%A1lise-de-tr%C3%A1fego-e-alertas-ids)
5.  [✅ Conclusão: Segurança Profissional Acessível](https://www.google.com/search?q=%23-conclus%C3%A3o-seguran%C3%A7a-profissional-acess%C3%ADvel)

-----

## 💻 Instalação Rápida e Uso (Multiplataforma)

Para que o Sentinela possa escanear e capturar o tráfego de rede (funções que exigem acesso de baixo nível), ele precisa de **três componentes principais**: as ferramentas de sistema (`nmap`, `tshark`) e a biblioteca Python (`psutil`).

### Pré-requisitos Fundamentais

Você deve garantir que os seguintes itens estejam instalados no seu sistema **antes** de instalar as bibliotecas Python. O `requirements.txt` cuidará do `psutil`.

| Componente | Tipo | Objetivo no Projeto | Instalação (Debian/Ubuntu) |
| :--- | :--- | :--- | :--- |
| **Python 3** | Linguagem | Executar o script principal. | `sudo apt install python3` |
| **Nmap** | Ferramenta Externa | Varredura de hosts e serviços abertos (Avaliação de Vulnerabilidade). | `sudo apt install nmap` |
| **Tshark** | Ferramenta Externa | Captura de pacotes (Base do IDS heurístico). | `sudo apt install tshark` |
| **Psutil** | Biblioteca Python | Monitorar conexões ativas em tempo real. | `pip install psutil` |

### Instalação no Linux (Debian, Ubuntu, Mint, Zorin)

Esta é a plataforma recomendada por sua estabilidade e suporte nativo às ferramentas de rede.

#### 1\. Clonar o Repositório

```bash
# Clone o projeto (ou baixe o arquivo ZIP)
git clone https://github.com/SeuUsuario/AutoSentinelNetwork.git
cd AutoSentinelNetwork
```

#### 2\. Instalar as Ferramentas de Sistema

Este comando instala o Python 3 e as duas ferramentas cruciais de rede (`nmap` e `tshark`):

```bash
# Instala as ferramentas externas essenciais:
sudo apt update
sudo apt install python3 nmap tshark -y
```

#### 3\. Instalar a Dependência Python

Com as ferramentas de sistema prontas, instale a biblioteca de monitoramento usando o `pip`:

```bash
# Instala a dependência psutil
pip install -r requirements.txt
```

### Instalação no Windows (Recomendado: WSL)

Para um ambiente estável e idêntico ao Linux, recomendamos o uso do **Windows Subsystem for Linux (WSL)**, disponível no Windows 10 e 11.

#### 1\. Configurar o WSL 2 (Windows 10/11)

Abra o **Prompt de Comando** ou **PowerShell como Administrador** e execute:

```powershell
wsl --install
```

  * Isso instalará o Ubuntu (ou outra distribuição de sua escolha). Siga as instruções na tela para criar seu usuário e senha no Linux.
  * Após a instalação, você terá um terminal Linux no Windows.

#### 2\. Continuar a Instalação (Dentro do Terminal WSL)

No terminal WSL (Ubuntu), siga exatamente os mesmos passos da seção [Instalação no Linux (Debian, Ubuntu, Mint, Zorin)](https://www.google.com/search?q=%23instala%C3%A7%C3%A3o-no-linux-debian-ubuntu-mint-zorin) (Clonar, Instalar Ferramentas, Instalar Dependências).

-----

## 🚀 Como Usar e Executar o Sentinela

Uma vez que você clonou o repositório e instalou **TODAS** as dependências (sistema e Python), execute o script com `sudo` (necessário para `nmap` e `tshark`):

```bash
# Certifique-se de estar dentro da pasta AutoSentinelNetwork
sudo python3 auto_network_sentinel.py
```

### O que acontece após a execução?

1.  **Fase 1: Varredura da LAN (Nmap)**: O script mapeia sua rede para identificar hosts e portas abertas.
2.  **Fase 2: Vigilância Silenciosa (IDS)**: O script inicia a captura de tráfego (`tshark`) e o monitoramento de conexões (`psutil`), procurando padrões de ataque.
3.  **Alertas Imediatos**: Se um padrão de varredura ou excesso de conexões for detectado, um alerta será emitido na tela (ex: `🚨 ALERTA (IDS): possível varredura/scan de X.X.X.X...`).
4.  **Parada e Relatório Final**: Pressione $\text{Ctrl} + \text{C}$ a qualquer momento para encerrar a vigilância e gerar os relatórios finais em `logs/`.

-----

## 📊 Guia de Análise dos Resultados

Após encerrar a sessão com $\text{Ctrl} + \text{C}$, o script gera dois arquivos cruciais na pasta `logs/`: um `*.md` (Markdown, relatório gerencial) e um `*.json` (detalhes técnicos).

### Análise de Vulnerabilidade da LAN (Nmap)

**Onde Ver:** Seção **"Análise de Vulnerabilidades da LAN"** no relatório `.md`.

  * **O que procurar:** Qualquer porta aberta em hosts da sua rede que **não** deveria estar acessível (ex: porta 22 - SSH em uma impressora, porta 3389 - RDP em um servidor não usado).
  * **Ação de Gestão:** Cada serviço aberto desnecessário (ex: Samba antigo, serviço de impressora desconhecido) é um risco de exploração. Aja imediatamente para fechar ou restringir o acesso a essas portas usando o firewall.

### Análise de Tráfego e Alertas (IDS)

**Onde Ver:** Seção **"Alertas Gerados (IDS Heurístico)"** e **"Estatísticas de IPs observados"** no relatório \`.md$.

| Item | O que significa? | Nível de Risco | Ação Recomendada |
| :--- | :--- | :--- | :--- |
| **🚨 ALERTA (IDS): possível Varredura/Scan** | Um IP (interno ou externo) tentou se conectar a muitas portas diferentes em pouco tempo. | **Alto** | Se for um IP externo e desconhecido, **bloqueie-o imediatamente** no seu roteador/firewall principal. |
| **IPs com Altas Conexões/Portas Distintas** | Indica um sistema (seu computador, um servidor ou uma estação de trabalho) que está se comunicando ativamente com o mundo exterior. | **Médio** | **Investigue** o host local para garantir que a comunicação seja legítima (ex: não é um malware enviando dados). |
| **Arquivos `.pcap`** | A captura de tráfego completa da sessão. | **Técnico** | Use o **Wireshark** (ferramenta de análise de rede) para abrir este arquivo e analisar os pacotes brutos que geraram os alertas. |

## ✅ Conclusão: Segurança Profissional Acessível

O Auto Sentinel Network coloca nas suas mãos uma ferramenta de nível empresarial, mas com a simplicidade que uma PME precisa. Lembre-se, a segurança é um processo contínuo. Use o Sentinela regularmente para ter certeza de que as vulnerabilidades antigas não voltaram e que sua rede está livre de atividades suspeitas.

Fique à vontade para contribuir, sugerir melhorias e proteger sua rede\!

** Disclaimer ** Após sofrer por algumas vezes com explorações e malwares de todos os tipos, passei alguns meses da minha vida estudando cybersegurança, administração de sistemas, redes e servidores de maneira autônoma e pro-ativa, aplicando em minhas próprias redes, sites, servidores, clientes e parceiros, técnicas avançadas de cybesegurança através da otimização e "hardening" de sistemas, monitormaneto constante, exploração de vulnerabilidades (pentesting) e boas práticas de gestão de segurança da informação, o que considero ser algo essencial para qualquer negócio, que vislumbre se manter ativo digilalmente. Hoje como já consegui, até aonde meu pequeno conhecimento permite enxegar, mitigar técnicas de ataques avançadas, persistentes e nocivas que comprometeram toda minha rede local, incluindo dispositivos móveis,gatways,  laptops e desktops, mesmo com utilização de diversos antí-virus e ferramentas como vpn, scanners e recursos nativos (os ataques percebidos por mim foram em sua maioria executados através do Windows 10, mas também tive evidências após migrar para Kali Linux, Debian 13 (minha distro atual), a qual por razões de estabilidade e segurança optei por utilizar, por ser uma das mais seguras, permitindo que você aprenda de modo mais profundo e práticas facilmente adaptadas para servidores, sendo a mãe da principal distro para este serviço atualmente, (Ubuntu/Ubuntu Server) utilizada em meus servidores atuais. 
