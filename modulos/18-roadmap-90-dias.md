# Roadmap de 90 dias para o analista SOC N1

Saber redes de forma solta não transforma ninguém em analista. O que transforma é **rotina**: estudar todo dia um pedaço, praticar em laboratório, escrever o que aprendeu e repetir. Este módulo existe para tirar você do estado "li muita coisa e não sei por onde começar" e colocar num plano de 90 dias com entregáveis verificáveis. No SOC (Security Operations Center, o centro de operações de segurança), o analista N1 é medido por consistência: ele triaga dezenas de alertas por turno, decide rápido e documenta. Os 90 dias abaixo treinam exatamente essa consistência.

Índice do módulo:

- Premissas, método de estudo e cronograma das 13 semanas
- Dias 1 a 30 — Fundamentos de rede e sistemas
- Dias 31 a 60 — Defesa e ferramentas
- Dias 61 a 90, portfólio, certificação e vida pós-dia-90

## Premissas de tempo

O plano assume um ritmo realista para quem trabalha ou estuda em outro turno.

| Perfil | Dias úteis | Fim de semana | Total semanal |
|---|---|---|---|
| Integral (recomendado) | 2 a 3 horas/dia | 4 horas no sábado | 14 a 19 horas |
| Meio período | 1 hora/dia | 2 horas no sábado | 7 horas |

O perfil integral cumpre os 90 dias como escrito. O perfil de **meio período** leva de 5 a 6 meses no mesmo conteúdo — e tudo bem, desde que você não corte o que sustenta o plano. O que cortar e o que jamais cortar:

| Pode cortar no meio período | Nunca cortar |
|---|---|
| Leitura de RFCs (Request for Comments, os documentos oficiais dos protocolos) na íntegra | Laboratórios práticos |
| Segundo laboratório de reforço da semana | Writeup (relatório escrito) de cada laboratório |
| Módulos "extras" de nuvem e contêineres | Revisão espaçada semanal |
| Simulados de certificação além de um por mês | Leitura de log real toda semana |

Regra prática: se em uma semana só sobrar tempo para **uma** coisa, que seja executar um laboratório e escrever o writeup. Ler sem praticar produz a ilusão de competência que o primeiro turno real destrói.

### O que você precisa ter

| Item | Mínimo | Confortável |
|---|---|---|
| Máquina | 8 GB de RAM, 100 GB livres, CPU com virtualização (VT-x/AMD-V) ligada na BIOS | 16 GB de RAM, SSD de 250 GB livres |
| Hipervisor | VirtualBox ou VMware Workstation Player (gratuitos) | Proxmox ou Hyper-V |
| VMs (máquinas virtuais) | 1 Windows Server de avaliação como controlador de domínio `corp.local`, 1 Windows 10/11 cliente, 1 Ubuntu Server | + 1 Security Onion (2 vCPU, 8 GB) |
| Contas gratuitas | TryHackMe (free tier), LetsDefend (free), Splunk Free, Microsoft 365 Developer Program, Shodan (free) | + Azure/Sentinel trial, Elastic Cloud trial |
| Ferramentas locais | Wireshark, Zeek, Suricata, Sysmon, PowerShell 7, VS Code, Git | + tcpdump, jq, Obsidian |
| Caderno | Um repositório Git com Markdown | Obsidian sincronizado + Git |

Todos os laboratórios usam domínios e endereços fictícios: `corp.local` e `empresa-exemplo.com.br` para a rede interna, `example.com` para parceiros, `10.10.0.0/16` para o escritório e as faixas de documentação `203.0.113.0/24`, `198.51.100.0/24` e `192.0.2.0/24` como se fossem internet. Usuários de teste: `jsilva`, `maria.costa`, `admin.rodrigo`, `svc_backup`.

## Método de estudo

Estudar para SOC não é ler apostila. É treinar um reflexo de decisão sob pressão. Cinco práticas sustentam isso.

**1. Estudo ativo, nunca passivo.** Antes de abrir o material, escreva a pergunta que você quer responder ("por que um 4625 com Status 0xC000006A é diferente de 0xC0000064?"). Depois de estudar, responda de memória e só então confira. Assistir vídeo com o material aberto ao lado é passivo e não fixa nada.

**2. Anotação em formato de cartão de triagem.** Cada conceito vira uma nota curta com quatro campos fixos: *o que é*, *como aparece no log*, *normal x suspeito*, *próximo passo*. Esse é o formato que você vai usar no trabalho, então treine nele desde o dia 1.

**3. Repetição espaçada.** Revise cada nota em D+1, D+3, D+7, D+21. Quinze minutos no começo de cada sessão bastam. Portas, EventIDs e flags TCP só grudam por repetição.

**4. Ensinar para aprender.** Uma vez por semana, explique um conceito em voz alta em até três minutos, como se falasse com um colega do help desk. Se você trava, o buraco está identificado — é ali que você volta a estudar.

**5. Writeup de cada laboratório.** Todo laboratório termina em um arquivo Markdown com: objetivo, topologia (IPs fictícios), o que foi executado, evidência (log ou captura), conclusão e o que faria diferente. O writeup é o que vira portfólio no dia 90 e é o que o recrutador consegue ler.

### Modelo de nota — exemplo preenchido

Conceito: falha de logon por senha errada no Windows.

```
Windows Security Log — EventID 4625
An account failed to log on.
  Account Name:     jsilva
  Account Domain:   CORP
  Failure Reason:   Unknown user name or bad password.
  Status:           0xC000006D
  Sub Status:       0xC000006A
  Logon Type:       3
  Workstation Name: NB-FIN-014
  Source Network Address: 10.10.42.87
  Source Port:      51344
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `EventID` | `4625` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não. `4625` = **falha** de logon |
| `Account Name` | `jsilva` | A conta envolvida. Terminada em `$` é **conta de computador**, não de pessoa |
| `Account Domain` | `CORP` | Domínio da conta |
| `Failure Reason` | `Unknown user name or bad password.` | Motivo da falha em texto — legível, mas **use o `Sub Status` na regra** |
| `Status` | `0xC000006D` | Código geral do resultado. `0xC000006D` = falha genérica de logon — o `Sub Status` é que diz a causa real |
| `Sub Status` | `0xC000006A` | **O código que diz a causa real** — o `Status` costuma ser genérico. `0xC000006A` = **senha errada** |
| `Logon Type` | `3` | **Como a sessão foi iniciada.** `3` = **rede** — acesso a compartilhamento, RPC, WinRM. É o tipo que domina em movimento lateral |
| `Workstation Name` | `NB-FIN-014` | Nome que a máquina de origem **declarou**. Vem do próprio cliente, logo é falsificável — trate como pista, não como identidade |
| `Source Network Address` | `10.10.42.87` | **IP de origem.** Vazio ou `-` significa que a sessão foi local, e `::1`/`127.0.0.1` que veio da própria máquina |
| `Source Port` | `51344` | Porta de origem, efêmera |

</details>

Leitura dos campos: `Status 0xC000006D` é a falha genérica de credencial; o `Sub Status 0xC000006A` especifica **senha incorreta para um usuário que existe** (já `0xC0000064` seria usuário inexistente, e `0xC0000234` conta bloqueada). `Logon Type 3` é logon de rede (SMB, compartilhamento, autenticação remota), diferente do `Type 10` de RDP (Remote Desktop Protocol, área de trabalho remota).

O que o N1 observa: dois ou três 4625 isolados de um usuário no horário comercial é normal (digitou errado, voltou de férias). Suspeito é o **padrão**: mesmo IP de origem gerando 4625 contra dezenas de contas diferentes em poucos minutos (password spraying, MITRE ATT&CK **T1110.003**), ou muitos 4625 com `Sub Status 0xC0000064` — usuários que nem existem, sinal de lista importada de fora.

Erro comum de analista júnior: fechar o alerta olhando só a contagem de eventos. O que importa é a razão *contagem de contas distintas por IP de origem*. Cinco falhas em cinco contas diferentes é bem mais grave que cinquenta falhas na mesma conta.

```spl
index=wineventlog EventCode=4625
| stats dc(Account_Name) as contas count as tentativas by Source_Network_Address
| where contas >= 8 AND tentativas >= 12
| sort - contas
```
Linha 1 filtra apenas falhas de logon. Linha 2 conta usuários distintos (`dc` = distinct count) e o total de tentativas por IP de origem. Linha 3 mantém só os IPs que erraram em oito ou mais contas — assinatura de spray, não de erro de digitação. Linha 4 ordena pelo pior caso.

## Estrutura em três fases de 30 dias

| Fase | Dias | Objetivo | Entregável final | Critério de aprovação para avançar |
|---|---|---|---|---|
| 1 — Fundamentos de rede e sistemas | 1 a 30 | Ler um pacote e um log de sistema operacional sem ajuda | Repositório com 8 writeups e um mapa da rede de laboratório | Explicar em 5 minutos o caminho completo de `https://www.example.com` (DNS → TCP → TLS → HTTP) e identificar em uma captura o handshake TCP, a consulta DNS e o SNI do TLS |
| 2 — Defesa e ferramentas | 31 a 60 | Operar firewall, IDS e SIEM e escrever consultas próprias | SIEM com dados ingeridos e 5 detecções escritas por você | Ingerir logs de firewall e Windows no Splunk/Sentinel, escrever uma consulta SPL e uma KQL que disparem numa simulação controlada, e explicar por que cada uma gera falso positivo |
| 3 — Ameaças, investigação e empregabilidade | 61 a 90 | Triar um alerta ponta a ponta e se apresentar ao mercado | 3 investigações completas + currículo e portfólio publicados | Fechar uma investigação com linha do tempo, mapeamento MITRE ATT&CK, veredito (verdadeiro ou falso positivo) e recomendação de contenção, em até 40 minutos |

Não avance por calendário: avance por critério. Se no dia 30 você ainda não consegue explicar o caminho de uma requisição HTTPS, gaste mais uma semana na fase 1. A fase 2 sobre base fraca produz um analista que sabe clicar no SIEM e não sabe o que está vendo.

## Cronograma semana a semana

| Semana | Tema | Módulos do curso | Labs a executar | Recurso externo sugerido | Entregável da semana |
|---|---|---|---|---|---|
| 1 | Modelos OSI/TCP-IP, endereçamento IPv4 e sub-redes | 1, 2 | Montar `10.10.0.0/16` no VirtualBox; dividir em /24 por setor; testar conectividade com `ping` e `tracert` | TryHackMe — trilha "Network Fundamentals" | Diagrama da rede de laboratório + tabela de sub-redes |
| 2 | Camada 2, ARP, switching e VLAN | 2, 3 | Capturar ARP no Wireshark; observar tabela ARP antes/depois; filtro `arp.opcode == 2` | Wireshark User's Guide (capítulos 1 a 4) | Writeup "Como o ARP resolve um IP em MAC" |
| 3 | TCP, UDP, flags e portas | 3, 4 | Capturar handshake com filtro `tcp.flags.syn==1 && tcp.flags.ack==0`; comparar sessão normal x porta fechada (RST) | RFC 9293 (seções de estados TCP) | Tabela pessoal de portas e flags + writeup |
| 4 | DNS, DHCP, HTTP e TLS | 4, 5 | Capturar `dns.log`, `http.log` e `ssl.log` no Zeek; identificar o SNI de `www.example.com` | Zeek — documentação dos logs base | Writeup do caminho completo de uma requisição HTTPS (**critério da fase 1**) |
| 5 | Windows, Active Directory e Kerberos | 6, 7 | Subir `corp.local`; ingressar cliente; gerar 4624/4625/4768/4769 com `jsilva` e `maria.costa` | Microsoft Learn — "Windows Security auditing" | Tabela de EventIDs de autenticação com normal x suspeito |
| 6 | Linux, syslog e Sysmon | 6, 8 | Instalar Sysmon com configuração pública; gerar eventos 1, 3 e 22; ler `/var/log/auth.log` | Sysmon — documentação Sysinternals | Writeup comparando Sysmon 1 x Windows 4688 |
| 7 | Firewall e proxy: Palo Alto, FortiGate, ASA, Squid | 9, 10 | Ler logs TRAFFIC/THREAT de exemplo; mapear campos de negação; correlacionar proxy x firewall | Palo Alto — referência de campos de log | Dicionário de campos dos 4 produtos |
| 8 | IDS/IPS: Suricata e Zeek | 10, 11 | Rodar Suricata sobre PCAP de laboratório; ler `eve.json`; escrever uma regra própria simples | Suricata — guia de regras | Uma regra própria + evidência do alerta em `eve.json` |
| 9 | SIEM: ingestão, SPL e KQL | 12, 13 | Ingerir firewall + Windows no Splunk Free; escrever 1 SPL e 1 KQL de spray | Splunk Search Tutorial e Microsoft Sentinel KQL docs | 5 detecções documentadas (**critério da fase 2**) |
| 10 | MITRE ATT&CK e rastros de ferramentas ofensivas | 14 | Mapear os alertas das semanas 8 e 9 para técnicas Txxxx; documentar o rastro em log de PsExec e Kerberoasting (4769 com criptografia RC4) | MITRE ATT&CK Navigator | Matriz ATT&CK preenchida com sua cobertura |
| 11 | Triagem de alertas e resposta a incidentes | 15, 16 | 5 alertas do LetsDefend do início ao fim, cronometrados | LetsDefend — trilha SOC Analyst (free) | 5 tickets com veredito e justificativa |
| 12 | Phishing, análise de e-mail e malware básico | 16, 17 | Analisar cabeçalhos de e-mail fictício; extrair IOCs; consultar reputação | Trilha de phishing do TryHackMe | Investigação completa nº 1 com linha do tempo |
| 13 | Portfólio, currículo e entrevista | 18 | Publicar repositório; ensaiar 10 perguntas técnicas em voz alta | Guias de entrevista para SOC N1 | Portfólio público + currículo + investigações nº 2 e 3 (**critério da fase 3**) |

Uma observação sobre carga: as semanas 9 e 13 são as mais pesadas. Se o seu calendário tem uma semana de férias ou um pico no trabalho, planeje que ela caia na semana 6 ou 12, não na 9.

### Exercícios — Premissas, método de estudo e cronograma das 13 semanas

1. Você está no perfil de meio período (1 hora por dia). Na semana 8 sobraram apenas 3 horas na semana toda. Liste, em ordem, o que você executa e o que corta, justificando com a regra do plano.
2. Calcule quantas horas de estudo o perfil integral acumula ao fim das 13 semanas, usando 2,5 horas nos dias úteis e 4 horas no sábado. Compare com o perfil de meio período (1 hora nos dias úteis e 2 horas no sábado).
3. Leia o log abaixo e responda: verdadeiro positivo ou falso positivo? Qual o próximo passo da investigação?

```
Windows Security — 09:02:11  EventID 4625  Account: maria.costa  Sub Status: 0xC000006A  Logon Type: 3  Source: 10.10.42.87
Windows Security — 09:02:14  EventID 4625  Account: jsilva       Sub Status: 0xC000006A  Logon Type: 3  Source: 10.10.42.87
Windows Security — 09:02:16  EventID 4625  Account: admin.rodrigo Sub Status: 0xC000006A Logon Type: 3  Source: 10.10.42.87
Windows Security — 09:02:19  EventID 4625  Account: svc_backup   Sub Status: 0xC000006A  Logon Type: 3  Source: 10.10.42.87
Windows Security — 09:04:02  EventID 4624  Account: svc_backup   Logon Type: 3           Source: 10.10.42.87
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `EventID` | `4625  Account: maria.costa` / `4625  Account: jsilva` / `4625  Account: admin.rodrigo` / `4625  Account: svc_backup` … | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não |
| `Sub Status` | `0xC000006A` | **O código que diz a causa real** — o `Status` costuma ser genérico. `0xC000006A` = **senha errada** |
| `Logon Type` | `3` | **Como a sessão foi iniciada.** `3` = **rede** — acesso a compartilhamento, RPC, WinRM. É o tipo que domina em movimento lateral |
| `Source` | `10.10.42.87` | Provedor que gerou o evento |

</details>

4. Um colega chegou ao dia 30 e consegue recitar de cor a tabela de portas, mas não consegue explicar por que uma consulta DNS aparece antes do handshake TCP numa captura. Ele pode avançar para a fase 2? Justifique pelo critério de aprovação.
5. Escreva o campo "normal x suspeito" de uma nota de triagem para o EventID 4769 (solicitação de ticket de serviço Kerberos), citando a técnica MITRE correspondente ao abuso mais comum.

<details><summary>Ver gabarito</summary>

**1.** Executa o laboratório do Suricata sobre o PCAP e escreve o writeup — nessa ordem, consumindo as 3 horas. Corta a leitura do guia de regras na íntegra e o segundo laboratório de reforço. A regra do plano é explícita: se sobrar tempo para uma só coisa, é laboratório + writeup, porque leitura sem prática produz ilusão de competência. Revisão espaçada (15 minutos) entra dentro do próprio bloco, não é item separado.

**2.** Integral: 5 dias × 2,5 h = 12,5 h + 4 h de sábado = 16,5 h por semana; 16,5 × 13 = **214,5 horas**. Meio período: 5 × 1 h + 2 h = 7 h por semana; 7 × 13 = **91 horas**. A diferença de 123,5 horas é a razão pela qual o perfil de meio período leva de 5 a 6 meses para cobrir o mesmo conteúdo — o plano não fica mais fácil, fica mais longo.

**3.** **Verdadeiro positivo**, com forte indício de comprometimento. O padrão é password spraying (MITRE **T1110.003**): um único IP de origem (10.10.42.87) falhando contra **quatro contas distintas** em oito segundos, todas com `Sub Status 0xC000006A` — senha errada para usuários que existem, ou seja, quem tentou já tinha uma lista válida de nomes. O agravante está na última linha: às 09:04 houve um **4624 de sucesso** para `svc_backup`, uma conta de serviço, vinda do mesmo IP. Contas de serviço não fazem logon interativo nem mudam de máquina de origem sem motivo. Próximos passos, nesta ordem: (a) identificar o host 10.10.42.87 no inventário e seu usuário legítimo; (b) verificar no firewall e no Sysmon o que `svc_backup` fez após o 09:04:02 — processos criados (Sysmon 1) e conexões de rede (Sysmon 3); (c) checar se houve movimentação lateral para outros hosts com a mesma conta; (d) escalar para o N2 e propor contenção (isolar o host, desabilitar ou rotacionar a credencial de serviço). Não feche como "usuário esqueceu a senha": um usuário esquece **a própria** senha, não a de quatro contas.

**4.** **Não pode avançar.** O critério da fase 1 não é decorar tabela, é explicar o caminho completo de `https://www.example.com` — DNS resolve o nome antes de existir qualquer conexão, porque o TCP precisa de um endereço IP de destino para abrir o handshake SYN → SYN/ACK → ACK; só depois vem o TLS com o SNI. Quem não vê essa ordem numa captura não vai conseguir, na fase 2, dizer se um alerta de conexão a IP suspeito começou por uma resolução DNS legítima ou por conexão direta a IP literal (sinal clássico de artefato malicioso). Recomendação: mais uma semana na fase 1, focada no laboratório da semana 4 com Zeek (`dns.log`, `conn.log`, `ssl.log`).

**5.** Campo "normal x suspeito" do 4769 (Kerberos service ticket request): **normal** — volume alto e contínuo durante o dia, tipo de criptografia `0x12` (AES256), nomes de serviço correspondentes a compartilhamentos e servidores que o usuário realmente acessa. **Suspeito** — uma única conta solicitando tickets para muitos SPNs (Service Principal Names) diferentes em poucos minutos, e sobretudo tipo de criptografia `0x17` (RC4) quando o domínio já opera em AES: é o rastro típico de Kerberoasting, **MITRE T1558.003**, em que o atacante pede tickets de contas de serviço para tentar quebrar a senha offline. O próximo passo é cruzar o `Account Name` do 4769 com a estação de origem e verificar processos criados nela.

</details>


## Dias 1 a 30 — Fundamentos de rede e sistemas

Pense nos primeiros 30 dias como aprender a dirigir antes de correr. Ninguém entra num carro de corrida sem saber onde fica o freio. No SOC (Security Operations Center, o centro de operações de segurança), o "freio" é entender como um pacote sai de uma máquina e chega em outra. Sem isso, todo alerta vira adivinhação.

A regra deste mês é simples: **teoria curta de manhã, prática longa depois**. Cada dia abaixo tem um tema, a seção deste curso que você deve ler, um laboratório e o tempo estimado. Nenhum dia fica vazio — inclusive os dias de descanso, que são obrigatórios (cérebro cansado não consolida memória).

### Semana 1 — Como um pacote viaja (Módulos 1 e 2)

| Dia | Tema do dia | O que estudar | Prática ou laboratório | Tempo |
|---|---|---|---|---|
| 1 | O que é uma rede e por que o SOC olha para ela | Módulo 1, seções "O que é uma rede" e "Cliente e servidor" | Desenhe no papel a rede da sua casa: roteador, celular, notebook. Marque quem é cliente e quem é servidor. | 1h30 |
| 2 | Modelo OSI e TCP/IP lado a lado | Módulo 1, seção "As camadas" | Para 5 protocolos (HTTP, TCP, IP, Ethernet, DNS) diga a camada de cada um, sem consultar. | 2h |
| 3 | Endereço MAC, ARP e o switch | Módulo 2, seção "Camada 2" | `arp -a` no Windows e no Linux. Anote o MAC do gateway. Compare com o fabricante pelo OUI. | 2h |
| 4 | Endereçamento IPv4, público vs privado (RFC1918) | Módulo 2, seção "Camada 3" | Classifique 10 IPs como privado ou público, incluindo 10.10.4.20, 172.16.9.3, 203.0.113.45. | 2h |
| 5 | Máscara, CIDR, rede e broadcast | Módulo 2, seção "Sub-redes" | Calcule rede, broadcast e faixa útil de 10.10.20.0/26, 192.168.4.0/28 e 172.16.0.0/22. À mão, sem calculadora online. | 2h30 |
| 6 | **Revisão da semana 1** | Refazer os exercícios dos Módulos 1 e 2 | Explique em voz alta, para uma cadeira vazia, o caminho de um pacote do seu PC até um servidor web. Se travar, volte ao tópico. | 1h30 |
| 7 | **Descanso** | — | Nada de estudo. Descanso é parte do plano. | 0 |

### Semana 2 — TCP, UDP e portas (Módulo 3)

| Dia | Tema do dia | O que estudar | Prática ou laboratório | Tempo |
|---|---|---|---|---|
| 8 | Camada 4: o conceito de porta e de socket | Módulo 3, seção "Portas" | `netstat -ano` (Windows) e `ss -tunap` (Linux). Identifique 5 conexões estabelecidas e o processo dono. | 2h |
| 9 | TCP: three-way handshake e flags | Módulo 3, seção "TCP" | Wireshark: filtro `tcp.flags.syn==1 && tcp.flags.ack==0`. Capture um acesso a um site e ache SYN, SYN-ACK, ACK. | 2h30 |
| 10 | Encerramento, RST e retransmissão | Módulo 3, seção "TCP" | Filtro `tcp.flags.reset==1`. Explique a diferença entre porta fechada (RST) e porta filtrada (sem resposta). | 2h |
| 11 | UDP e ICMP (tipos e códigos) | Módulo 3, seção "UDP e ICMP" | `ping` e `tracert`. No Wireshark, veja o `icmp.type==8` (echo request) e `icmp.type==0` (echo reply). | 2h |
| 12 | As portas que o N1 precisa saber de cabeça | Módulo 3, tabela de portas | Faça flashcards de 20 portas. Meta: acertar 12 em menos de 60 segundos. | 2h |
| 13 | **Revisão da semana 2 + leitura de log de firewall** | Módulo 3 inteiro | Leia 20 linhas de log Palo Alto e classifique cada uma como permitida ou negada. | 2h |
| 14 | **Descanso** | — | Descanso. | 0 |

Exemplo do log que você vai ler no dia 13 (Palo Alto, formato CSV do tipo TRAFFIC — campos separados por vírgula):

```
Sep 03 09:14:22 fw-core-01 1,2026/09/03 09:14:22,001801099999,TRAFFIC,end,2561,2026/09/03 09:14:20,10.10.20.37,203.0.113.45,192.0.2.10,203.0.113.45,Regra-Saida-Web,jsilva,,ssl,vsys1,Interna,Externa,ae1.20,ae1.10,Log-Forward,2026/09/03 09:14:21,84213,1,51422,443,41255,443,0x400053,tcp,allow,18422,4210,14212,54,ANY
```

<details><summary>Ver legenda</summary>

| Posição | Campo | Valor no exemplo | O que significa |
|---|---|---|---|
| 1 | *(cabeçalho syslog)* | `Sep 03 09:14:22 fw-core-01` | **Não é campo do CSV** — é o cabeçalho do syslog. O `1` no fim já é o primeiro campo reservado |
| 2 / 7 | Receive / Generated Time | `2026/09/03 09:14:22` e `09:14:20` | Quando o firewall recebeu e quando ocorreu. **Dois segundos de diferença**: o evento aconteceu antes de ser registrado |
| 3 | Serial Number | `001801099999` | Qual equipamento gerou |
| 4 / 5 | Type / Subtype | `TRAFFIC` / `end` | Log de sessão, no fim |
| 6 | — | `2561` | Reservado pelo fabricante |
| 8 / 9 | Source / Destination Address | `10.10.20.37` / `203.0.113.45` | Origem interna e destino externo |
| 10 / 11 | NAT Source / Destination IP | `192.0.2.10` / `203.0.113.45` | Endereço público de saída e destino |
| 12 | Rule Name | `Regra-Saida-Web` | A regra que permitiu |
| 13 / 14 | Source / Destination User | `jsilva` / *(vazio)* | Usuário resolvido; o de destino vem vazio, como é normal em tráfego de saída |
| 15 / 16 | Application / Virtual System | `ssl` / `vsys1` | App-ID e firewall virtual |
| 17 / 18 | Source / Destination Zone | `Interna` / `Externa` | O sentido do tráfego |
| 19 / 20 | Inbound / Outbound Interface | `ae1.20` / `ae1.10` | Subinterfaces de *port-channel* |
| 21 / 22 | Log Action / — | `Log-Forward` / `2026/09/03 09:14:21` | Perfil de log e campo reservado |
| 23 / 24 | Session ID / Repeat Count | `84213` / `1` | Sessão e contagem |
| 25 / 26 | Source / Destination Port | `51422` / `443` | Porta efêmera e HTTPS |
| 27 / 28 | NAT Source / Destination Port | `41255` / `443` | Portas após tradução |
| 29 / 30 / 31 | Flags / Protocol / Action | `0x400053` / `tcp` / `allow` | Bits, protocolo e veredito |
| 32 / 33 / 34 / 35 | Bytes / Sent / Received / Packets | `18422` / `4210` / `14212` / `54` | Volume total, por direção, e pacotes |
| *(último campo)* | Category | `ANY` | Sem categoria de URL atribuída. **Atenção à posição**: esta linha tem 36 campos e acaba aqui, mas na ordem real do PAN-OS a `Category` é a posição **38** — o exemplo saltou `Start Time` (36) e `Elapsed Time` (37). Num log verdadeiro, contar até 36 dá o horário de início, não a categoria |

</details>

Campos que importam para o N1: origem `10.10.20.37`, destino `203.0.113.45`, usuário `jsilva`, aplicação `ssl`, porta destino `443`, ação `allow`, bytes enviados e recebidos. **Normal:** estação interna falando 443 com destino externo, poucos KB. **Suspeito:** a mesma estação abrindo centenas de sessões por minuto para o mesmo IP, ou tráfego `ssl` numa porta esquisita como 4444. **Erro comum de júnior:** olhar só a ação `allow` e ignorar o volume de bytes — exfiltração de dados quase sempre é uma sessão *permitida*.

### Semana 3 — DNS, HTTP e TLS (Módulos 4 e 5)

| Dia | Tema do dia | O que estudar | Prática ou laboratório | Tempo |
|---|---|---|---|---|
| 15 | DNS: o que é, resolver, tipos de registro | Módulo 4, seção "Como o DNS funciona" | `nslookup -type=A www.example.com` e `-type=MX example.com`. Anote o que voltou. | 2h |
| 16 | DNS nos logs e domínios suspeitos | Módulo 4, seção "DNS no SOC" | Leia um `dns.log` do Zeek e liste os 5 domínios menos frequentes do arquivo. | 2h30 |
| 17 | HTTP: métodos, códigos de status, User-Agent | Módulo 5, seção "HTTP" | Wireshark com filtro `http.request`. Identifique método, host e User-Agent de 10 requisições. | 2h |
| 18 | Proxy web e o que ele registra | Módulo 5, seção "Proxy" | Leia 30 linhas de Squid `access.log` e separe `TCP_MISS/200` de `TCP_DENIED/403`. | 2h |
| 19 | TLS/HTTPS: handshake, SNI, certificado, JA3 | Módulo 5, seção "TLS" | Zeek `ssl.log`: liste os `server_name` (SNI) e os certificados autoassinados. | 2h30 |
| 20 | **Revisão das semanas 1 a 3** | Módulos 1 a 5 | Refaça o cálculo de sub-rede do dia 5 cronometrado e a tabela de portas do dia 12. | 2h |
| 21 | **Descanso** | — | Descanso. | 0 |

Como o DNS aparece num log real (Zeek `dns.log`, campos separados por TAB):

```
1756890912.481203  CxT9a2  10.10.20.37  51833  10.10.0.10  53  udp  41022  0.041  cdn-updates.example.com  1  C_INTERNET  1  A  0  NOERROR  F  F  T  T  0  203.0.113.88  300  F
1756890925.118740  CqR4b8  10.10.20.37  51999  10.10.0.10  53  udp  9931   0.038  a7f3k9x2m1q8.empresa-exemplo.com.br  1  C_INTERNET  16  TXT  0  NOERROR  F  F  T  T  0  -  -  F
```

Leitura dos campos: horário, ID da conexão, IP de origem, porta de origem, servidor DNS, porta 53, protocolo UDP, o nome consultado (`query`), o tipo (`A` ou `TXT`) e o código de resposta (`NOERROR`, `NXDOMAIN`). **Normal:** consultas tipo A para nomes legíveis. **Suspeito:** a segunda linha — subdomínio longo e aleatório com registro `TXT` é o padrão clássico de túnel de DNS ou de canal de comando e controle (MITRE ATT&CK T1071.004, *Application Layer Protocol: DNS*). **Erro comum de júnior:** fechar o caso porque "é só DNS, porta 53 é permitida". O que importa é o *nome consultado* e a *frequência*, não a porta.

### Semana 4 — Windows, Linux e a primeira triagem (Módulo 6)

| Dia | Tema do dia | O que estudar | Prática ou laboratório | Tempo |
|---|---|---|---|---|
| 22 | Linux básico para o SOC | Módulo 6, seção "Linux" | Pratique `grep`, `cut`, `sort`, `uniq -c`, `wc -l` num arquivo de log. Ache o IP que mais aparece. | 2h30 |
| 23 | Permissões, processos e serviços no Linux | Módulo 6, seção "Linux" | `ps aux`, `systemctl status`, `journalctl -u ssh`. Ache uma tentativa de login falhada. | 2h |
| 24 | Windows: contas, grupos e o Active Directory | Módulo 6, seção "Windows e AD" | `whoami /groups`, `net user`. Desenhe a diferença entre conta local e conta de domínio `corp.local`. | 2h |
| 25 | Logon events: 4624, 4625 e os Logon Types | Módulo 6, seção "Windows Security" | Visualizador de Eventos: filtre 4624 e anote o Logon Type de cada um. | 2h30 |
| 26 | Kerberos e criação de processo: 4768, 4769, 4776, 4688 | Módulo 6, seção "Autenticação" | Correlacione um 4768 (TGT) com o 4769 (ticket de serviço) seguinte, pelo nome de usuário. | 2h30 |
| 27 | Sysmon: eventos 1, 3 e 22 | Módulo 6, seção "Sysmon" | Instale o Sysmon num laboratório e gere um evento 1 (processo) e um 22 (consulta DNS). | 2h |
| 28 | PowerShell básico e Windows Firewall | Módulo 6, seção "Windows" | `Get-Process`, `Get-NetTCPConnection`, `Test-NetConnection -Port 443`. | 2h |
| 29 | **Revisão geral e simulado** | Módulos 1 a 6 | Faça o simulado do checkpoint abaixo, cronometrado, sem consultar nada. | 3h |
| 30 | **Checkpoint do dia 30 + descanso ativo** | — | Corrija o simulado, anote os erros, planeje os 30 dias seguintes (ver trecho "Dias 31 a 60"). | 1h30 |

Exemplo do dia 25 (Windows Security, Event ID 4625 — falha de logon):

```
EventID: 4625
Account Name:   maria.costa
Account Domain: CORP
Failure Reason: Unknown user name or bad password.
Status:         0xC000006D
Sub Status:     0xC000006A
Logon Type:     3
Workstation Name: WS-VENDAS-14
Source Network Address: 10.10.31.88
Process Name:   -
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `EventID` | `4625` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não. `4625` = **falha** de logon |
| `Account Name` | `maria.costa` | A conta envolvida. Terminada em `$` é **conta de computador**, não de pessoa |
| `Account Domain` | `CORP` | Domínio da conta |
| `Failure Reason` | `Unknown user name or bad password.` | Motivo da falha em texto — legível, mas **use o `Sub Status` na regra** |
| `Status` | `0xC000006D` | Código geral do resultado. `0xC000006D` = falha genérica de logon — o `Sub Status` é que diz a causa real |
| `Sub Status` | `0xC000006A` | **O código que diz a causa real** — o `Status` costuma ser genérico. `0xC000006A` = **senha errada** |
| `Logon Type` | `3` | **Como a sessão foi iniciada.** `3` = **rede** — acesso a compartilhamento, RPC, WinRM. É o tipo que domina em movimento lateral |
| `Workstation Name` | `WS-VENDAS-14` | Nome que a máquina de origem **declarou**. Vem do próprio cliente, logo é falsificável — trate como pista, não como identidade |
| `Source Network Address` | `10.10.31.88` | **IP de origem.** Vazio ou `-` significa que a sessão foi local, e `::1`/`127.0.0.1` que veio da própria máquina |
| `Process Name` | `-` | Caminho completo do executável |

</details>

Campos: `Logon Type 3` significa logon de rede (acesso a compartilhamento ou autenticação remota), diferente do tipo 2 (interativo, teclado) e do tipo 10 (RDP). `Sub Status 0xC000006A` = senha errada com usuário que existe; `0xC0000064` = usuário não existe. **Normal:** um ou dois 4625 por dia de alguém que errou a senha. **Suspeito:** 40 eventos 4625 do mesmo `10.10.31.88` contra 40 usuários diferentes em 3 minutos — isso é *password spraying* (MITRE ATT&CK T1110.003). **Erro comum de júnior:** escalar cada 4625 isolado. O sinal está no *padrão*: muitos usuários com poucas tentativas cada.

Consulta pronta para treinar no dia 29:

```spl
index=windows EventCode=4625            /* só falhas de logon */
| bin _time span=5m                      /* agrupa em janelas de 5 minutos */
| stats dc(Account_Name) as usuarios count as tentativas by src_ip, _time
| where usuarios >= 10                   /* muitos usuários = spray, não erro de digitação */
| sort - usuarios
```

```kusto
SecurityEvent
| where EventID == 4625                       // falhas de logon
| summarize usuarios = dcount(TargetAccount), tentativas = count()
    by IpAddress, bin(TimeGenerated, 5m)      // janela de 5 minutos por IP de origem
| where usuarios >= 10                        // limiar de password spraying
| order by usuarios desc
```

### Checkpoint do dia 30 — auto-avaliação objetiva

Sem consultar nada, sem internet, com cronômetro. Você deve conseguir:

| # | Você deve conseguir... | Critério de aprovação |
|---|---|---|
| 1 | Calcular rede, broadcast e faixa útil de um /26 | Em menos de 1 minuto, no papel |
| 2 | Explicar o three-way handshake com as flags certas | SYN → SYN-ACK → ACK, em voz alta, em 60 segundos |
| 3 | Dizer o que roda em 12 portas de cabeça | 22, 25, 53, 80, 88, 135, 389, 443, 445, 636, 3389, 3306 — 12 de 12 |
| 4 | Diferenciar RST de "sem resposta" numa varredura | Explicar porta fechada vs filtrada |
| 5 | Ler uma linha de TRAFFIC do Palo Alto | Apontar origem, destino, app, porta, ação e bytes |
| 6 | Ler um `dns.log` do Zeek e apontar 1 domínio suspeito | Justificar pelo nome e pelo tipo de registro |
| 7 | Explicar 4624 vs 4625 e 3 Logon Types | Tipos 2, 3 e 10 corretos |
| 8 | Achar o IP mais frequente de um log com linha de comando | `grep`/`cut`/`sort`/`uniq -c`/`sort -nr`/`head` |
| 9 | Diferenciar IP privado de público | 10 de 10 acertos |
| 10 | Escrever uma busca simples que conta eventos por IP | SPL ou KQL, sintaxe válida |

**Aprovado:** 8 ou mais itens. **Se não passar:** não avance para o dia 31. Reserve de 3 a 5 dias extras e refaça **só os itens que falharam** — não recomece o mês inteiro. Erro em sub-redes (item 1) é o mais comum e o mais grave: bloqueia toda a análise de tráfego lateral. Erro em portas (item 3) resolve-se com 20 minutos de flashcards por dia. Se falhou em 5 ou mais itens, o problema costuma ser método, não capacidade: reduza a teoria pela metade e dobre o tempo de laboratório.

### Exercícios — Dias 1 a 30 — Fundamentos de rede e sistemas

1. **Cálculo.** A estação `10.10.20.37/26` precisa falar com `10.10.20.70`. Os dois estão na mesma sub-rede? Qual o endereço de rede e o de broadcast do /26 da estação?
2. **Leitura de log.** Na linha do Palo Alto da semana 2, o campo de aplicação é `ssl` e a porta de destino é 443. Um analista diz: "é HTTPS legítimo, pode fechar". Que dois campos você olharia antes de concordar?
3. **Verdadeiro ou falso positivo?** Um sensor gera alerta para a consulta `a7f3k9x2m1q8.empresa-exemplo.com.br` do tipo TXT, feita pela estação `10.10.20.37`. O domínio pertence à própria empresa. É falso positivo?
4. **Próximo passo.** Você vê 40 eventos 4625 vindos de `10.10.31.88` contra 40 contas distintas em 3 minutos, e logo depois **um** evento 4624 com Logon Type 3 da mesma origem, para a conta `svc_backup`. Qual é o próximo passo?
5. **Portas.** Um host interno `10.10.44.9` abre conexões TCP para `10.10.0.10` nas portas 88, 389 e 445 durante o dia inteiro. Isso é normal?

<details><summary>Ver gabarito</summary>

1. Um /26 tem máscara 255.255.255.192 e blocos de 64 endereços: 10.10.20.0, .64, .128, .192. O host `.37` está no bloco 10.10.20.0/26 (rede 10.10.20.0, broadcast 10.10.20.63, úteis .1 a .62). O host `.70` cai no bloco seguinte, 10.10.20.64/26. **Não estão na mesma sub-rede** — a conversa passa pelo gateway e, portanto, pode ser vista e filtrada pelo firewall. Esse detalhe muda a investigação: existe log de roteamento para consultar.

2. Os **bytes enviados vs recebidos** e a **duração/quantidade de sessões**. Aplicação `ssl` na 443 com 4 KB recebidos e 400 MB enviados é o retrato de exfiltração. Também vale checar o `server_name` (SNI) no log de TLS: se o certificado for autoassinado ou o SNI não existir, o "HTTPS legítimo" fica bem menos legítimo. Ação permitida nunca é, sozinha, prova de que está tudo bem.

3. **Não é falso positivo automático.** Ser um domínio da empresa não inocenta a consulta: o subdomínio é aleatório e longo, e o tipo é TXT, que carrega texto arbitrário — a assinatura de túnel de DNS (T1071.004). Um invasor pode ter registrado um subdomínio delegado ou pode ser um servidor interno comprometido. Próximo passo: verificar se a estação faz essas consultas em intervalo regular (batimento de C2), quem é o servidor autoritativo do subdomínio e se há processo suspeito no Sysmon evento 22 da mesma estação.

4. **Isolar a prioridade certa.** Os 40 falhas são password spraying (T1110.003); o **4624 seguinte é o mais importante**: significa que uma tentativa deu certo, e numa conta de serviço (`svc_backup`), que normalmente não faz logon de rede a partir de estações. Sequência: (a) confirmar a origem `10.10.31.88` — de quem é a máquina; (b) elevar o caso, porque houve autenticação bem-sucedida; (c) pedir contenção da conta e da estação conforme o procedimento interno; (d) buscar 4769 (ticket de serviço) da conta logo após o 4624, para ver a que recurso ela foi. Nunca feche o incidente só porque "a maioria falhou".

5. **É normal e esperado.** As portas 88 (Kerberos), 389 (LDAP) e 445 (SMB) contra um mesmo servidor são o padrão de uma estação falando com um controlador de domínio do `corp.local` — autenticação, consulta de diretório e políticas de grupo. Ficaria suspeito se essas mesmas portas fossem abertas por uma estação contra **muitas outras estações** (movimento lateral) ou contra um servidor que não é controlador de domínio. Contexto do destino é o que separa rotina de incidente.

</details>


## Dias 31 a 60 — Defesa e ferramentas

Nos primeiros 30 dias você aprendeu a "gramática" da rede: endereço, porta, protocolo, pacote. Agora entra a fase em que essa gramática vira trabalho de plantão. Pense na diferença entre saber ler música e conseguir tocar num ensaio com a banda inteira: o segundo mês é o ensaio. Você vai parar de estudar o que é um firewall e vai começar a ler o log de um firewall real às duas da manhã, com um alerta piscando.

Este bloco cobre os Módulos 7 a 13 (firewall e proxy, IDS e IPS, endpoint e EDR, autenticação Windows e Active Directory, SIEM e correlação), mais Wireshark e SIEM na prática, com os laboratórios do Módulo 16 encaixados nos dias em que a teoria correspondente acabou de ser vista. A regra é sempre a mesma: teoria de manhã ou no início da sessão, mão na massa logo em seguida, porque conhecimento de log que não passou pelos seus dedos evapora em uma semana.

### Semana 5 (dias 31 a 37) — Firewall e proxy

| Dia | Tema do dia | O que estudar | Prática ou laboratório | Tempo |
|---|---|---|---|---|
| 31 | Firewall: o porteiro do prédio | Módulo 7, seções 1 a 3: stateful vs stateless, zonas, política allow/deny, NAT | Desenhar no papel o fluxo de um pacote de 10.10.20.45 até 203.0.113.10 passando por 3 regras | 2h |
| 32 | Log de firewall Palo Alto (CSV TRAFFIC) | Módulo 7, seção 4: campos do TRAFFIC log, ação, bytes, sessão | Ler 20 linhas de TRAFFIC e classificar allow, deny e drop | 2h |
| 33 | Log de firewall FortiGate e Cisco ASA | Módulo 7, seção 5: formato key=value e `%ASA-6-302013` | Traduzir a mesma conexão nos 3 formatos (Palo, Forti, ASA) | 2h |
| 34 | Proxy web e inspeção TLS | Módulo 8: proxy explícito vs transparente, categorias, CONNECT, SSL inspection | Ler `access.log` do Squid e identificar 3 downloads de executável | 2h |
| 35 | Proxy em nuvem: Netskope e Zscaler | Módulo 8, parte final: SWG (Secure Web Gateway), campos do NSS feed | Comparar campo a campo Squid × Zscaler NSS × Netskope | 2h |
| 36 | Lab 16.1 — Montar o laboratório caseiro (parte 1) | Módulo 16, laboratório 1: VirtualBox, rede interna, VM Windows 10 e VM Linux | Subir as 2 VMs, conferir ping entre 192.168.56.10 e 192.168.56.20 | 3h |
| 37 | Revisão da semana + descanso ativo | Reler suas próprias anotações, sem material novo | Flashcards de campos de log; parar em 1h e descansar | 1h |

O log de firewall é o documento mais lido do plantão N1. Comece pelo formato CSV do Palo Alto Networks, porque ele é posicional e obriga você a decorar a ordem dos campos:

```
1,2026/03/12 09:41:22,001901000123,TRAFFIC,end,2561,2026/03/12 09:41:22,10.10.20.45,203.0.113.10,192.0.2.7,203.0.113.10,Regra-Saida-Usuarios,corp\jsilva,,web-browsing,vsys1,Trust,Untrust,ae1.20,ae2.100,Log-Padrao,2026/03/12 09:41:24,88214,1,51422,443,42188,443,0x400053,tcp,allow,14822,4210,10612,42,2026/03/12 09:40:58,3,computer-and-internet-info,0,7302011,0x0,10.0.0.0-10.255.255.255,US,,21,21
```

<details><summary>Ver legenda</summary>

| Posição | Campo | Valor no exemplo | O que significa |
|---|---|---|---|
| 1, 6, 39 | — | `1`, `2561`, `0` | Reservados pelo fabricante. **Comece a contar pela posição 2** |
| 2 / 7 | Receive / Generated Time | `2026/03/12 09:41:22` | Quando o firewall recebeu e quando ocorreu |
| 3 | Serial Number | `001901000123` | Qual equipamento gerou |
| 4 / 5 | Type / Subtype | `TRAFFIC` / `end` | Log de sessão, registrado no **fim** — só o `end` traz os totais |
| 8 / 9 | Source / Destination Address | `10.10.20.45` / `203.0.113.10` | Origem interna e destino externo |
| 10 / 11 | NAT Source / Destination IP | `192.0.2.7` / `203.0.113.10` | O IP público com que a sessão saiu, e o destino |
| 12 | Rule Name | `Regra-Saida-Usuarios` | A regra que decidiu |
| 13 / 14 | Source / Destination User | `corp\jsilva` / *(vazio)* | Usuário resolvido pelo User-ID |
| 15 | Application | `web-browsing` | App-ID: navegação HTTP identificada por inspeção |
| 16 | Virtual System | `vsys1` | Firewall virtual |
| 17 / 18 | Source / Destination Zone | `Trust` / `Untrust` | O sentido do tráfego |
| 19 / 20 | Inbound / Outbound Interface | `ae1.20` / `ae2.100` | Subinterfaces de *port-channel* |
| 21 / 22 | Log Action / — | `Log-Padrao` / `2026/03/12 09:41:24` | Perfil de log e campo reservado |
| 23 / 24 | Session ID / Repeat Count | `88214` / `1` | Sessão e contagem |
| 25 / 26 | Source / Destination Port | `51422` / `443` | Porta efêmera e HTTPS |
| 27 / 28 | NAT Source / Destination Port | `42188` / `443` | Portas após tradução |
| 29 / 30 / 31 | Flags / Protocol / Action | `0x400053` / `tcp` / `allow` | Bits, protocolo e veredito |
| 32 | Bytes | `14822` | Total nos dois sentidos |
| 33 / 34 | Bytes Sent / Received | `4210` / `10612` | Volume em cada direção |
| 35 | Packets | `42` | Total de pacotes |
| 36 / 37 | Start Time / Elapsed | `2026/03/12 09:40:58` / `3` | Início e duração: **3 segundos** |
| 38 | Category | `computer-and-internet-info` | Categoria de URL do destino |
| 40 / 41 | Sequence Number / Action Flags | `7302011` / `0x0` | Sequencial do log e bits da ação |
| 42 / 43 | Source / Destination Location | `10.0.0.0-10.255.255.255` / `US` | Faixa interna na origem, país no destino |
| 44 | — | `-` | Reservado |
| 45 / 46 | Packets Sent / Received | `21` / `21` | Pacotes em cada direção |

</details>

Campos que importam para o N1, na ordem em que aparecem: tipo de log (`TRAFFIC`), horário, IP de origem `10.10.20.45`, IP de destino `203.0.113.10`, IP traduzido pelo NAT `192.0.2.7`, nome da regra `Regra-Saida-Usuarios`, usuário `corp\jsilva`, aplicação `web-browsing`, zona de origem `Trust`, zona de destino `Untrust`, porta de origem `51422`, porta de destino `443`, protocolo `tcp`, ação `allow`, bytes totais `14822`, bytes enviados `4210`, bytes recebidos `10612`, pacotes `42`, categoria de URL `computer-and-internet-info`.

O que o SOC N1 observa: normal é um usuário nomeado saindo pela regra esperada, para porta 443, com bytes recebidos maiores que os enviados (você baixa mais do que envia ao navegar). Suspeito é o inverso — 4 MB enviados e 8 KB recebidos para um destino sem categoria — porque isso é o formato de exfiltração de dados (MITRE ATT&CK T1041, exfiltração pelo canal de comando e controle).

O mesmo evento em FortiGate, formato chave=valor, mais fácil de ler porque cada campo se identifica:

```
date=2026-03-12 time=09:41:22 devname="FGT-MATRIZ" devid="FG100F0000012345" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=10.10.20.45 srcport=51422 srcintf="port2" dstip=203.0.113.10 dstport=443 dstintf="port1" poluuid="a1b2" sessionid=88214 proto=6 action="accept" policyid=12 policyname="Saida-Usuarios" service="HTTPS" srccountry="Reserved" dstcountry="United States" user="jsilva" sentbyte=4210 rcvdbyte=10612 duration=3 appcat="Web.Client"
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `date` | `2026-03-12` | Data local **do equipamento**, não UTC. Correlacionar com um log em UTC sem acertar o fuso desalinha a timeline |
| `time` | `09:41:22` | Hora local do equipamento |
| `devname` | `"FGT-MATRIZ"` | Nome do equipamento que gerou o log |
| `devid` | `"FG100F0000012345"` | Número de série do equipamento — numa frota, é ele que identifica qual falou |
| `logid` | `"0000000013"` | Identificador do **tipo** de log. **É por ele que se filtra no SIEM**: o texto muda entre versões do FortiOS, o número não |
| `type` | `"traffic"` | Categoria do log: `traffic` é sessão, `event` é evento do próprio aparelho, `utm` é inspeção de conteúdo |
| `subtype` | `"forward"` | Subcategoria: `forward` é tráfego que atravessa, `local` é destinado ao próprio firewall, `vpn` é túnel, `webfilter` e `ips` são inspeção |
| `level` | `"notice"` | Severidade atribuída pelo FortiOS (`notice`, `warning`, `alert`, `critical`). **Quem a escolhe é o fabricante**, não o seu SOC |
| `srcip` | `10.10.20.45` | IP de origem |
| `srcport` | `51422` | Porta de origem, efêmera e sorteada pelo cliente |
| `srcintf` | `"port2"` | Interface por onde o tráfego **entrou** — dá o sentido, que o IP sozinho não dá |
| `dstip` | `203.0.113.10` | IP de destino |
| `dstport` | `443` | Porta de destino — é ela que aponta o serviço |
| `dstintf` | `"port1"` | Interface por onde o tráfego **saiu** |
| `poluuid` | `"a1b2"` | UUID da regra. **Sobrevive à renumeração**, ao contrário do `policyid` |
| `sessionid` | `88214` | Identificador da sessão na tabela de estado — casa o início e o fim da mesma conexão |
| `proto` | `6` | Número do protocolo IP: **`6` é TCP, `17` é UDP, `1` é ICMP**. Vem em número, não em nome |
| `action` | `"accept"` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |
| `policyid` | `12` | **Número da regra que decidiu.** Sem ele não se sabe por que o tráfego passou ou parou |
| `policyname` | `"Saida-Usuarios"` | Nome da regra — mais legível que o número, e sobrevive à renumeração |
| `service` | `"HTTPS"` | Nome do **objeto de serviço** do FortiGate, não a porta literal. Um objeto chamado `HTTPS` pode ter sido configurado noutra porta |
| `srccountry` | `"Reserved"` | País de origem por geolocalização. Para IP privado vem `Reserved` |
| `dstcountry` | `"United States"` | País de destino por geolocalização |
| `user` | `"jsilva"` | Conta autenticada — o que transforma "um IP" em "uma pessoa" |
| `sentbyte` | `4210` | Bytes enviados **pela origem**. O ponto de vista é o da origem, não do firewall |
| `rcvdbyte` | `10612` | Bytes recebidos pela origem. **Comparar com `sentbyte` é o que revela exfiltração** |
| `duration` | `3` | Duração da sessão em **segundos** |
| `appcat` | `"Web.Client"` | Categoria da aplicação identificada |
| — | — | Este é o exemplo mais completo do curso: tem `poluuid` (que sobrevive à renumeração), `srccountry`/`dstcountry`, `appcat` e `sessionid`. Vale como referência dos nomes de campo do FortiOS |

</details>

Aqui `proto=6` é TCP (protocolo 6 na tabela IANA; 17 é UDP e 1 é ICMP) e `action="accept"` equivale ao `allow` do Palo Alto. No Cisco ASA a construção de sessão aparece assim:

```
Mar 12 09:41:22 fw-asa-01 %ASA-6-302013: Built outbound TCP connection 88214 for outside:203.0.113.10/443 (203.0.113.10/443) to inside:10.10.20.45/51422 (192.0.2.7/51422)
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| *(cabeçalho syslog)* | `Mar 12 09:41:22 fw-asa-01` | **Não faz parte da mensagem do ASA** — é o que o syslog acrescenta à frente: data, hora e nome do equipamento |
| `%ASA` | `%ASA` | Etiqueta do produto: identifica a linha como vinda de um firewall ASA |
| severidade | `6` | Escala syslog do Cisco, de 0 (emergência) a 7 (depuração): `6` é **informational**. **Severidade baixa não quer dizer evento sem importância** — quem a escolhe é o fabricante, não o seu SOC |
| *message ID* | `302013` | Conexão TCP construída — entrou na tabela de estado. **É por este número que se escreve a regra no SIEM**: o texto da mensagem muda entre versões do software, o ID não |
| direção | `outbound` | **Quem iniciou**, não a direção dos bytes: `outbound` é de dentro para fora, `inbound` é de fora para dentro |
| id da conexão | `88214` | Número da conexão na tabela de estado. **É a chave para casar com o `302014`** que a encerra |
| lado remoto | `outside:203.0.113.10/443` | Interface, IP e porta do host **remoto**. Vem primeiro, logo depois do `for` — é isso que faz a linha parecer invertida |
| *(entre parênteses)* | `(203.0.113.10/443)` | O endereço **traduzido** desse lado. Igual ao real significa que não houve NAT nesta ponta |
| lado local | `inside:10.10.20.45/51422` | Interface, IP e porta do host **local**, antes da tradução |
| *(entre parênteses)* | `(192.0.2.7/51422)` | O endereço com que o host local saiu. **Este par — IP público mais porta — é o que desfaz o NAT** num pedido externo |

</details>


Erro comum de analista júnior: tratar `action=allow` como "está tudo bem". O firewall permitiu porque a regra permite — a regra não sabe se o destino é malicioso. Um beacon de command and control (comando e controle) passa por uma regra de saída com `allow` mil vezes por dia.

### Semana 6 (dias 38 a 44) — IDS, IPS e Suricata

| Dia | Tema do dia | O que estudar | Prática ou laboratório | Tempo |
|---|---|---|---|---|
| 38 | IDS vs IPS: detectar × barrar | Módulo 9, seções 1 e 2: inline vs span, assinatura vs anomalia | Tabela comparativa própria IDS/IPS/EDR/SIEM (rascunho) | 2h |
| 39 | Suricata: anatomia da assinatura | Módulo 9, seção 3: `alert`, `sid`, `signature`, `severity`, `category` | Ler 15 alertas EVE JSON e separar verdadeiro/falso positivo | 2h |
| 40 | Zeek: o diário da rede | Módulo 10: `conn.log`, `dns.log`, `http.log`, `ssl.log` e o campo `uid` | Correlacionar um `uid` entre `conn.log` e `dns.log` | 2h |
| 41 | Lab 16.2 — Suricata e Zeek no laboratório | Módulo 16, laboratório 2: instalar Suricata na VM Linux, ler `eve.json` | Gerar tráfego HTTP e ver o alerta nascer | 3h |
| 42 | Sala prática online (rede) | Sem leitura nova | Sala de análise de tráfego numa plataforma de laboratório online (TryHackMe ou equivalente institucional) | 3h |
| 43 | Wireshark na prática — parte 1 | Módulo 11: filtros de exibição, `follow TCP stream`, `Statistics > Conversations` | Abrir captura de laboratório e listar top 5 conversas | 3h |
| 44 | Revisão + descanso | Revisar as 3 semanas anteriores | Refazer 10 exercícios já resolvidos, sem consultar o gabarito | 1h30 |

Alerta do Suricata no formato EVE JSON, que é o padrão que você verá no SIEM:

```json
{"timestamp":"2026-03-12T14:07:31.442188+0000","flow_id":1934857201,"in_iface":"eth0","event_type":"alert","src_ip":"10.10.20.45","src_port":49855,"dest_ip":"198.51.100.77","dest_port":443,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2027865,"rev":3,"signature":"ET MALWARE Possible Malicious TLS Certificate - Self Signed","category":"A Network Trojan was detected","severity":1},"tls":{"subject":"CN=localhost","issuerdn":"CN=localhost","sni":"cdn.empresa-exemplo.com.br","version":"TLS 1.2"}}
```

Leitura campo a campo: `event_type: alert` distingue de `flow`, `dns` e `http`; `signature_id` (o SID) é o identificador da regra e serve para pesquisar histórico; `severity: 1` é a mais alta na convenção do Suricata (1 = alta, 3 = baixa); `action: allowed` diz que o sensor está em modo IDS, apenas observando. O bloco `tls` é o que decide o caso: certificado autoassinado com `CN=localhost`, mas com SNI (Server Name Indication, o nome do site pedido no handshake) fingindo ser um CDN corporativo. Certificado que não bate com o nome pedido é sinal clássico de canal de comando e controle sobre TLS (T1573.002).

O que o SOC N1 observa: normal é certificado emitido por autoridade conhecida e SNI coerente com o destino. Suspeito é autoassinado, validade de poucos dias, ou SNI vazio com destino em endereço direto. Erro comum: fechar o alerta porque "está no HTTPS, então é criptografado e não dá para ver nada". Dá — o handshake TLS é em texto claro até o certificado, e o Zeek registra isso em `ssl.log`.

### Semana 7 (dias 45 a 51) — Endpoint, EDR e autenticação Windows

| Dia | Tema do dia | O que estudar | Prática ou laboratório | Tempo |
|---|---|---|---|---|
| 45 | EDR: o que ele vê que a rede não vê | Módulo 12, seções 1 e 2: processo, árvore de processos, telemetria | Desenhar a árvore `winword.exe → cmd.exe → powershell.exe` | 2h |
| 46 | Sysmon: eventos 1, 3 e 22 | Módulo 12, seção 3: criação de processo, conexão de rede, consulta DNS | Instalar Sysmon na VM Windows do laboratório e ler o log | 3h |
| 47 | Windows Security: 4624 e 4625 | Módulo 13, seção 1: logon types 2, 3, 5, 10; `Status`/`Sub Status` do 4625 | Classificar 10 logons por tipo | 2h |
| 48 | Kerberos nos logs: 4768, 4769, 4776 | Módulo 13, seção 2: TGT, TGS, NTLM, tipos de criptografia | Identificar um 4769 com `Ticket Encryption Type 0x17` | 2h |
| 49 | Rastro de ferramentas ofensivas | Módulo 13, seção 3: o que Mimikatz, Rubeus, Impacket e PsExec deixam em log | Listar EventIDs esperados para cada uma (só o rastro, nunca o uso) | 2h |
| 50 | Lab 16.3 — Logon falho e força bruta | Módulo 16, laboratório 3: gerar 4625 em série na VM e observar o padrão | Contar tentativas por minuto e por conta | 3h |
| 51 | Revisão + descanso | Consolidar tabela de EventIDs | Parar cedo; dormir bem antes da semana de SIEM | 1h |

Evento 4625 (falha de logon) do Windows Security, resumido nos campos úteis:

```
EventID=4625
Account Name:        maria.costa
Account Domain:      CORP
Failure Reason:      Unknown user name or bad password
Status:              0xC000006D
Sub Status:          0xC000006A
Logon Type:          3
Workstation Name:    WKS-VENDAS-07
Source Network Address: 10.10.30.88
Logon Process:       NtLmSsp
Authentication Package: NTLM
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `EventID` | `4625` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não. `4625` = **falha** de logon |
| `Account Name` | `maria.costa` | A conta envolvida. Terminada em `$` é **conta de computador**, não de pessoa |
| `Account Domain` | `CORP` | Domínio da conta |
| `Failure Reason` | `Unknown user name or bad password` | Motivo da falha em texto — legível, mas **use o `Sub Status` na regra** |
| `Status` | `0xC000006D` | Código geral do resultado. `0xC000006D` = falha genérica de logon — o `Sub Status` é que diz a causa real |
| `Sub Status` | `0xC000006A` | **O código que diz a causa real** — o `Status` costuma ser genérico. `0xC000006A` = **senha errada** |
| `Logon Type` | `3` | **Como a sessão foi iniciada.** `3` = **rede** — acesso a compartilhamento, RPC, WinRM. É o tipo que domina em movimento lateral |
| `Workstation Name` | `WKS-VENDAS-07` | Nome que a máquina de origem **declarou**. Vem do próprio cliente, logo é falsificável — trate como pista, não como identidade |
| `Source Network Address` | `10.10.30.88` | **IP de origem.** Vazio ou `-` significa que a sessão foi local, e `::1`/`127.0.0.1` que veio da própria máquina |
| `Logon Process` | `NtLmSsp` | Componente que processou o logon (`Kerberos`, `NtLmSsp`, `User32`, `Advapi`) |
| `Authentication Package` | `NTLM` | Pacote que autenticou: `Kerberos`, `NTLM` ou `Negotiate` |

</details>

Tradução: `Logon Type 3` é logon de rede (acesso a compartilhamento ou autenticação remota), diferente do tipo 2 (teclado da máquina) e do tipo 10 (RDP, área de trabalho remota). `Sub Status 0xC000006A` significa senha errada com usuário existente; `0xC0000064` significa usuário inexistente. Essa diferença é a linha entre password spraying (T1110.003, senha única contra muitas contas, gera muitos `0xC000006A` de contas diferentes) e enumeração de usuários (muitos `0xC0000064`).

E o par correspondente do Kerberos, evento 4769 (solicitação de ticket de serviço):

```
EventID=4769
Account Name:        jsilva@CORP.LOCAL
Service Name:        svc_backup
Client Address:      ::ffff:10.10.20.45
Ticket Options:      0x40810000
Ticket Encryption Type: 0x17
Failure Code:        0x0
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `EventID` | `4769` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não. `4769` = **ticket de serviço** do Kerberos pedido (o "crachá de sala") |
| `Account Name` | `jsilva@CORP.LOCAL` | A conta envolvida. Terminada em `$` é **conta de computador**, não de pessoa |
| `Service Name` | `svc_backup` | O serviço para o qual o ticket foi pedido. Terminado em `$` é uma conta de computador |
| `Client Address` | `::ffff:10.10.20.45` | IP do cliente que pediu o ticket. **Cuidado com o formato**: o Windows costuma escrevê-lo embrulhado em notação IPv6, como `::ffff:10.10.10.50` — é IPv4, não um endereço IPv6, e uma regra que case só `\d+\.\d+\.\d+\.\d+` deixa esses passar |
| `Ticket Options` | `0x40810000` | Bits com as opções pedidas para o ticket (renovável, encaminhável...) |
| `Ticket Encryption Type` | `0x17` | **Cifra do ticket.** `0x17` = **RC4** — fraco; pedido num domínio que usa AES pode indicar *Kerberoasting* |
| `Failure Code` | `0x0` | **Código de falha do Kerberos.** `0x0` = sucesso |

</details>

`Ticket Encryption Type 0x17` é RC4-HMAC, criptografia fraca. Um único 4769 com 0x17 pode ser sistema legado; dezenas deles pedidos pela mesma conta para várias contas de serviço em poucos minutos é o padrão de Kerberoasting (T1558.003). Erro comum de júnior: abrir incidente no primeiro 0x17. O sinal é volume e variedade de serviços, não o evento isolado.

### Semana 8 (dias 52 a 60) — SIEM, queries e integração

| Dia | Tema do dia | O que estudar | Prática ou laboratório | Tempo |
|---|---|---|---|---|
| 52 | O que é um SIEM | Módulo 13, parte final: coleta, normalização, correlação, retenção | Mapear 5 fontes de log da empresa fictícia até o SIEM | 2h |
| 53 | SPL do Splunk — busca básica | Sintaxe: `index`, `search`, `stats`, `table`, `where` | Escrever 5 buscas próprias | 3h |
| 54 | KQL do Sentinel/Defender | Sintaxe: `where`, `summarize`, `project`, `bin` | Traduzir as 5 buscas do dia 53 para KQL | 3h |
| 55 | Lab 16.4 — SIEM caseiro | Módulo 16, laboratório 4: enviar Sysmon e Suricata para o SIEM do laboratório | Buscar seus próprios eventos gerados no dia 46 | 3h |
| 56 | Metodologia dos 10 passos numa captura | Módulo 11, parte final: aplicar a metodologia numa PCAP desconhecida | Análise completa com relatório de 1 página | 3h |
| 57 | Sala prática online (Windows/AD) | Sem leitura nova | Sala de análise de log de autenticação numa plataforma online | 3h |
| 58 | Triagem cronometrada | Sem leitura nova | 6 alertas em 90 minutos, decidir verdadeiro ou falso positivo com justificativa | 2h |
| 59 | Revisão geral do bloco | Reler as tabelas dos dias 31 a 58 | Refazer os laboratórios que deram errado | 2h |
| 60 | Checkpoint do dia 60 | Autoavaliação | Prova prática (abaixo) | 2h |

Duas buscas equivalentes, uma em cada linguagem. Primeiro SPL (Search Processing Language, do Splunk), para achar contas com muitas falhas de logon:

```spl
index=windows EventCode=4625
| eval sub=Sub_Status
| stats count AS falhas, dc(Account_Name) AS contas BY Source_Network_Address, sub
| where falhas > 20
| sort - falhas
```

Linha 1 filtra o índice de eventos Windows e o EventID de falha de logon. Linha 2 apenas renomeia o campo para encurtar. Linha 3 agrupa por IP de origem e por sub-status, contando falhas e quantas contas distintas foram tentadas (`dc` é distinct count). Linha 4 mantém só o que passou de 20 falhas. Linha 5 ordena do maior para o menor.

Agora a mesma ideia em KQL (Kusto Query Language, do Microsoft Sentinel e do Defender):

```kql
SecurityEvent
| where TimeGenerated > ago(1h)          // janela de 1 hora
| where EventID == 4625                   // falha de logon
| summarize falhas = count(),             // total de falhas
            contas = dcount(TargetUserName) // contas distintas tentadas
          by IpAddress, SubStatus
| where falhas > 20                       // corta o ruído
| order by falhas desc
```

Erro comum de júnior: escrever a query sem janela de tempo. Sem `ago(1h)` ou sem seletor de período, você varre meses de dados, o SIEM engasga e o resultado não significa nada operacionalmente.

### Checkpoint do dia 60

No dia 60 você deve conseguir fazer o seguinte **sem consultar o material e sem ajuda de colega**:

| Competência | Como se prova |
|---|---|
| Ler log de firewall | Explicar 10 linhas de Palo Alto, FortiGate e Cisco ASA, dizendo origem, destino, regra, ação e se o volume de bytes é coerente |
| Ler log de proxy | Num `access.log` de Squid ou feed Zscaler/Netskope, apontar método, código de resposta, categoria e por que a URL foi bloqueada |
| Escrever query simples | Uma busca em SPL e a equivalente em KQL, com filtro de tempo, agregação e corte de ruído, escritas do zero em até 10 minutos |
| Analisar captura desconhecida | Aplicar os 10 passos da metodologia numa PCAP nova e entregar 1 página com conclusão e nível de confiança |
| Distinguir as camadas de defesa | Explicar em voz alta, em 3 minutos, a diferença entre IDS, IPS, EDR e SIEM, com um exemplo de detecção que só cada um faz |
| Classificar autenticação Windows | Diferenciar 4624 de 4625, logon type 3 de 10, e sub status `0xC000006A` de `0xC0000064` |

Resumo das quatro tecnologias, que costuma cair em entrevista e em prova prática:

| Tecnologia | Onde fica | O que vê | Age? | Ponto cego |
|---|---|---|---|---|
| IDS | Espelho de tráfego (SPAN/TAP) | Pacotes na rede | Não, só alerta | Tráfego criptografado sem inspeção |
| IPS | Inline, no caminho do pacote | Pacotes na rede | Sim, bloqueia | Falso positivo derruba serviço legítimo |
| EDR | Dentro do endpoint | Processos, arquivos, registro, memória | Sim, isola e mata processo | Máquina sem agente instalado |
| SIEM | Central, recebe de todos | Logs já gerados por outros | Não diretamente | Só enxerga o que foi enviado para ele |

**Plano de recuperação se você não passar.** Não pule para o dia 61. Reserve de 5 a 7 dias extras e trate assim: se a falha foi em log de firewall ou proxy, repita os dias 32 a 35 lendo 30 linhas por dia em voz alta, explicando campo a campo. Se a falha foi em query, refaça só os dias 53 e 54, mas escrevendo 3 queries novas por dia sobre perguntas que você mesmo inventa ("quais 10 IPs internos mais falharam autenticação hoje?"). Se a falha foi na captura, repita o dia 56 com três PCAPs diferentes de laboratório, sempre com a metodologia impressa ao lado. Se a falha foi conceitual (IDS × IPS × EDR × SIEM), grave você mesmo explicando em 3 minutos e ouça — onde você gaguejar é onde não entendeu. Atraso planejado não é fracasso; chegar ao dia 61 sem base é.

### Exercícios — Dias 31 a 60 — Defesa e ferramentas

1. No log Palo Alto do dia 32, a estação 10.10.20.45 do usuário `corp\jsilva` gerou, em uma hora, 340 sessões para 198.51.100.77:443, cada uma com `sentbyte` entre 380 e 420 e `rcvdbyte` entre 90 e 130, com intervalo médio de 10,6 segundos entre sessões. Isso é comportamento normal de navegação? Justifique e nomeie a técnica MITRE ATT&CK.

2. Você recebe dois blocos de 4625 no mesmo minuto. Bloco A: 60 eventos, IP de origem 10.10.30.88, 60 contas diferentes, todos com `Sub Status 0xC000006A`. Bloco B: 60 eventos, IP de origem 10.10.30.88, uma única conta `admin.rodrigo`, todos `0xC000006A`. Qual é qual, e qual dos dois tem maior chance de gerar bloqueio de conta?

3. Um alerta do Suricata dispara `ET POLICY Dropbox User Login` com `severity: 3`, origem 10.10.20.61 (usuário `maria.costa`), destino 203.0.113.44:443, no horário comercial. A política da empresa fictícia permite armazenamento em nuvem corporativo e bloqueia pessoal. Verdadeiro positivo, falso positivo, ou depende? Qual o próximo passo?

4. Escreva em KQL uma consulta que liste, na última hora, os IPs de destino externos que receberam mais de 50 MB de uma mesma estação interna, ordenados do maior para o menor. Use a tabela `CommonSecurityLog` com os campos `DestinationIP`, `SourceIP` e `SentBytes`.

5. Numa captura desconhecida, você vê 1.400 pacotes TCP de 10.10.20.45 para 198.51.100.90, todos com a flag SYN, portas de destino de 20 a 1024, sem nenhum SYN-ACK de volta. Qual filtro de exibição do Wireshark isola exatamente esses pacotes e o que o padrão indica?

<details><summary>Ver gabarito</summary>

**1.** Não é navegação normal. Navegação real tem `rcvdbyte` muito maior que `sentbyte` (a página que você baixa pesa mais que o pedido) e intervalos irregulares, porque depende do clique humano. Aqui há três marcas de beacon: volume minúsculo e quase constante nos dois sentidos, `sentbyte` maior que `rcvdbyte`, e periodicidade de ~10 segundos com pouca variação (jitter baixo). São 340 sessões em 3.600 segundos, ou seja, uma a cada 10,6 segundos — máquina, não pessoa. Técnica: T1071.001 (Application Layer Protocol: Web Protocols) para o canal de comando e controle. Próximo passo do N1: verificar reputação de 198.51.100.77, buscar o mesmo destino em outras estações e escalar para o N2 com a linha do tempo.

**2.** Bloco A é password spraying (T1110.003): uma senha provável testada contra muitas contas, por isso 60 contas distintas com senha errada (`0xC000006A` = usuário existe, senha incorreta). Bloco B é força bruta contra conta única (T1110.001). O que tem maior chance de bloquear conta é o **Bloco B**, porque a política de lockout conta falhas por conta; no spraying o atacante distribui justamente para ficar abaixo do limite de cada conta. Detalhe importante: se o sub status fosse `0xC0000064`, seria enumeração de usuários, não teste de senha.

**3.** Depende — e essa é a resposta correta. O Suricata não sabe a política da sua empresa; ele apenas identificou tráfego de um serviço de armazenamento pessoal. `severity: 3` e categoria `ET POLICY` indicam violação de política, não malware. Próximo passo: confirmar no proxy (Netskope, Zscaler ou Squid) se o acesso foi com conta corporativa ou pessoal, verificar o volume enviado e checar se `maria.costa` tem exceção aprovada. Se houve upload grande com conta pessoal, deixa de ser violação de política e vira suspeita de exfiltração (T1567.002). Se foi só um login sem upload e a conta é corporativa aprovada, fecha como falso positivo com justificativa escrita.

**4.**
```kql
CommonSecurityLog
| where TimeGenerated > ago(1h)              // janela obrigatória
| where SourceIP startswith "10."            // só origem interna
| where DestinationIP !startswith "10."      // só destino externo
| summarize total = sum(SentBytes) by SourceIP, DestinationIP
| where total > 52428800                     // 50 MB em bytes
| order by total desc
```
Cada linha: janela de tempo primeiro (economiza processamento), filtro de origem interna, exclusão de destino interno para sobrar só saída, soma dos bytes enviados agrupada pelo par origem-destino, corte em 50 MB (50 × 1024 × 1024 = 52.428.800) e ordenação decrescente. Sem a janela `ago(1h)` a consulta varreria toda a retenção.

**5.** Filtro: `tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == 10.10.20.45`. A condição `syn == 1 && ack == 0` isola o SYN puro (o primeiro pacote do handshake), separando-o do SYN-ACK da resposta. O padrão — muitos SYN, portas sequenciais, nenhuma resposta — é varredura de portas do tipo SYN scan (T1046, Network Service Discovery). A ausência de SYN-ACK significa que as portas estão fechadas ou filtradas; se houvesse RST de volta seriam portas fechadas com host vivo. Próximo passo do N1: identificar o dono de 10.10.20.45, verificar se existe janela autorizada de varredura de vulnerabilidades e, não havendo, escalar como possível host comprometido fazendo reconhecimento interno.

</details>


## Dias 61 a 90 — Integração, portfólio e prontidão para o plantão

Os dois primeiros blocos (dias 1 a 30 e 31 a 60, tratados nos trechos anteriores) construíram base e ferramentas. O último bloco é diferente: aqui você para de aprender coisas novas em ritmo alto e passa a **juntar as peças**. Analogia: nos dois primeiros meses você aprendeu a dirigir num estacionamento vazio; agora você entra no trânsito com semáforo, pedestre e buzina.

A regra deste bloco é: **todo dia produz um artefato**. Um writeup, uma query comentada, um print anotado, uma linha de cheat sheet. Se o dia terminou sem arquivo salvo, o dia não contou.

### Cronograma dia a dia — dias 61 a 90

| Dia | Módulo / foco | Atividade prática | Artefato do dia |
|---|---|---|---|
| 61 | M14 — Proxy e web | Ler `access.log` do Squid, separar `TCP_MISS/200` de `TCP_DENIED/403` | Tabela de códigos de resultado |
| 62 | M14 — Proxy e web | Netskope/Zscaler: categoria de URL, ação `allow` vs `block` | Writeup: navegação normal vs beacon |
| 63 | M14 — Proxy e web | User-Agent estranho, POST grande para domínio novo (T1071.001) | 5 queries SPL de proxy |
| 64 | M14 — Proxy e web | Download de executável via HTTP em `http.log` do Zeek | Mini-relatório de captura pública |
| 65 | M15 — E-mail | Cabeçalhos: SPF, DKIM, DMARC; `Received:` de baixo para cima | Cheat sheet de cabeçalho |
| 66 | M15 — E-mail | Phishing reportado: extrair URL, hash de anexo, remetente | Roteiro de triagem de phishing |
| 67 | M15 — E-mail | Correlacionar e-mail → proxy → EDR (quem clicou, T1566.002) | Writeup de cadeia completa |
| 68 | M16 — Nuvem e identidade | Sign-in logs do Entra ID: `errorCode 50126`, viagem impossível | 3 queries KQL comentadas |
| 69 | M16 — Nuvem e identidade | MFA fatigue e consentimento de app malicioso (T1621, T1528) | Tabela normal vs suspeito |
| 70 | M16 — Nuvem e identidade | Revisão de logs de acesso a storage e chave de API exposta | Writeup curto |
| 71 | **Portfólio** | Criar repositório no GitHub, README, estrutura de pastas | Repositório publicado |
| 72 | M17 — Resposta a incidente | Ciclo: detectar, triar, conter, erradicar, recuperar, lições | Fluxograma próprio |
| 73 | M17 — Resposta a incidente | Escrever ticket de escalonamento com evidência e timeline | Modelo de ticket |
| 74 | M17 — Resposta a incidente | Cadeia de custódia, o que **não** fazer na máquina do usuário | Checklist de contenção |
| 75 | Lab integrador 1 | Phishing → credencial → logon anômalo (4624 tipo 10) | Relatório de 2 páginas |
| 76 | Lab integrador 1 | Fechar o relatório: linha do tempo, IoC, recomendação | Relatório publicado |
| 77 | Lab integrador 2 | Varredura interna → movimento lateral → 4688 suspeito | Relatório de 2 páginas |
| 78 | Lab integrador 2 | Mapear cada passo para MITRE ATT&CK (T1046, T1021.002, T1059.001) | Matriz de mapeamento |
| 79 | Lab integrador 3 | Exfiltração: DNS longo + TLS para IP sem SNI conhecido | Relatório de 2 páginas |
| 80 | **Portfólio** | Consolidar coleção de queries SPL e KQL, comentar linha a linha | Arquivo `queries.md` |
| 81 | **Portfólio** | Documentar o laboratório caseiro (topologia, VMs, versões) | `lab/README.md` + diagrama |
| 82 | **Portfólio** | Escrever o artigo técnico (1 tema, 1200 palavras) | Artigo publicado |
| 83 | Entrevista | 30 perguntas técnicas clássicas, responder em voz alta | Banco de respostas |
| 84 | Entrevista | Explicar handshake TCP, DNS e Kerberos em 3 minutos cada | Roteiro de explicação |
| 85 | **Simulado** | 60 questões cronometradas (rede + Windows + log) | Nota + erros anotados |
| 86 | Revisão dirigida | Refazer só os temas errados no simulado | Fichas de correção |
| 87 | **Simulado** | Segundo simulado, meta acima de 75% | Nota + comparação |
| 88 | Entrevista | Simulação de triagem ao vivo: alerta na tela, 10 minutos | Gravação/anotação |
| 89 | Portfólio | Revisar tudo, corrigir português, remover dado sensível | Repositório final |
| 90 | **Checkpoint** | Auto-avaliação final e plano dos próximos 90 dias | Documento de plano |

### Exemplo prático de artefato — dia 68 (nuvem e identidade)

Cenário fictício: a usuária `maria.costa@empresa-exemplo.com.br` aparece com falhas de autenticação vindas de `203.0.113.44` e, dez minutos depois, um sucesso vindo de `198.51.100.9`.

```
2026-09-04T09:12:03Z SigninLogs userPrincipalName=maria.costa@empresa-exemplo.com.br
  ipAddress=203.0.113.44 resultType=50126 resultDescription="Invalid username or password"
  appDisplayName="Office 365 Exchange Online" clientAppUsed="Other clients"
  authenticationRequirement=singleFactorAuthentication location="XX"
2026-09-04T09:22:47Z SigninLogs userPrincipalName=maria.costa@empresa-exemplo.com.br
  ipAddress=198.51.100.9 resultType=0 resultDescription="Success"
  appDisplayName="Office 365 Exchange Online" clientAppUsed="Browser"
  authenticationRequirement=multiFactorAuthentication mfaDetail="PhoneAppNotification"
```

Campos que importam: `resultType=50126` é senha errada; `resultType=0` é sucesso; `clientAppUsed="Other clients"` indica protocolo legado sem MFA (autenticação multifator), alvo clássico de força bruta; `authenticationRequirement` diz se o MFA foi exigido.

```kql
// Falhas seguidas de sucesso para o mesmo usuário em janela curta
SigninLogs
| where TimeGenerated > ago(24h)                       // janela de busca
| summarize falhas = countif(ResultType != 0),         // conta tentativas erradas
            sucessos = countif(ResultType == 0),       // conta logins válidos
            ips = make_set(IPAddress, 10)              // lista os IPs envolvidos
            by UserPrincipalName, bin(TimeGenerated, 30m)
| where falhas >= 5 and sucessos >= 1                  // padrão de brute force bem-sucedido
```

**O que o N1 observa:** normal é falha isolada seguida de sucesso do mesmo IP (usuário digitou errado). Suspeito é falha em massa de um IP e sucesso de **outro** IP, ainda mais com protocolo legado no meio. **Erro comum de júnior:** ver `resultType=0` e fechar o alerta como benigno — o sucesso é justamente a parte grave.

## Entregáveis de portfólio e como usá-los na entrevista

| Entregável | O que contém | Como usar na entrevista |
|---|---|---|
| Repositório GitHub | README com índice, pastas por tema | "Posso te mostrar em vez de descrever" |
| Writeups de investigação | 3 relatórios dos labs integradores | Prova que você sabe escrever timeline e conclusão |
| Mini-relatórios de capturas públicas | Análise de PCAP do Malware-Traffic-Analysis e do Wireshark Sample Captures | Mostra leitura de tráfego real, não só teoria |
| Documentação do lab caseiro | Topologia, VMs, versões, como reproduzir | Demonstra autonomia e método |
| Coleção de queries SPL e KQL | 20 a 30 queries comentadas linha a linha | Responde "você sabe pesquisar em SIEM?" |
| Cheat sheet próprio | Portas, EventIDs, flags TCP, filtros Wireshark | Mostra que você organiza conhecimento |
| Artigo técnico | Um tema explicado do zero | Mostra comunicação escrita, item que o N1 usa todo dia |

Regra de ouro do portfólio: **nada de dado real**. Use `corp.local`, `10.10.20.0/24`, `192.0.2.x` e usuários fictícios como `jsilva` e `svc_backup`. Um recrutador que vê IP de cliente real no seu GitHub descarta a candidatura, com razão.

Na entrevista, cada entregável responde uma pergunta implícita: o writeup responde "você pensa em ordem?"; a query responde "você dá conta da ferramenta?"; o lab responde "você faz sem ninguém mandar?".

## Checkpoint do dia 90 — auto-avaliação final

Marque de 1 a 5. Abaixo de 3 significa refazer os dias correspondentes.

| Competência | Verificação objetiva |
|---|---|
| Endereçamento e sub-rede | Calcular faixa de `10.10.40.0/22` de cabeça |
| TCP/UDP e handshake | Explicar SYN, SYN-ACK, ACK e diferenciar RST de timeout |
| DNS | Ler `dns.log` do Zeek e apontar consulta suspeita |
| HTTP e TLS | Identificar SNI, certificado autoassinado e JA3 anômalo |
| Firewall | Ler Palo Alto CSV e FortiGate key=value sem consultar manual |
| Windows | Distinguir 4624 tipo 3 de tipo 10, e 4625 de 4776 |
| Kerberos | Explicar 4768 e 4769 e por que RC4 no 4769 chama atenção |
| Sysmon | Usar Event ID 1, 3 e 22 numa mesma investigação |
| SIEM | Escrever SPL e KQL do zero para uma hipótese |
| Escrita | Produzir ticket de escalonamento em 15 minutos |
| MITRE ATT&CK | Mapear 10 técnicas comuns sem consultar |
| Postura | Dizer "não sei, vou verificar" com um plano junto |

## Plano de certificação encaixado no cronograma

A certificação não substitui o plano; ela **carimba** o que o plano construiu.

| Certificação | Quando estudar | Quando agendar | Observação |
|---|---|---|---|
| CompTIA Network+ | Dias 1 a 40, em paralelo | Prova por volta do dia 45 | Ideal se você vem de fora de TI |
| CompTIA Security+ | Dias 40 a 80 | Prova entre o dia 95 e 110 | Mais pedida em vaga de N1 |
| Blue Team Level 1 (BTL1) | Após o dia 90 | Meses 4 a 6 | Prática, muito alinhada ao plantão |
| Splunk Core Certified User | Dias 55 a 75 | Prova até o dia 100 | Curta, reforça o portfólio de queries |

Agende a prova **antes** de se sentir pronto: a data cria o prazo. Reserve os dias 85 e 87 do plano para simulado; se a nota do simulado passar de 80% duas vezes, agende para dez dias depois.

## Como manter depois do dia 90

- **Rotina semanal de laboratório:** 2 horas, um cenário novo por semana. Alterne captura pública, log do Windows e cenário de nuvem.
- **Leitura de threat intel:** 20 minutos por dia, três fontes fixas (CISA advisories, blog de fornecedor do seu stack, relatório mensal de um time de pesquisa). Anote apenas técnicas novas, não notícia.
- **Comunidade:** um grupo ativo, uma pergunta feita por semana, uma resposta dada por semana. Ensinar consolida mais que ler.
- **Caminho para o Nível 2:** o N2 é quem investiga o que o N1 escalona. Para chegar lá, aprofunde em três frentes: análise forense de endpoint (memória, artefatos de execução), engenharia de detecção (escrever e ajustar regra, medir falso positivo) e threat hunting com hipótese. Um N1 que entrega hunt documentado vira N2 antes do prazo formal.

## O dia a dia do plantão, sem romantismo

Turno de plantão tem escala 12x36 ou 6x1 em muitos lugares, e madrugada é real. A maior parte dos alertas é falso positivo — scanner autorizado, backup do `svc_backup`, atualização em massa. Isso gera fadiga de alerta: depois de 40 alertas iguais, o 41º passa batido. As defesas contra isso são processo, não força de vontade: checklist fixo de triagem, pausa a cada duas horas, rodízio de fila entre colegas e feedback formal para ajustar a regra que gera ruído. Você não será o herói que pega o APT sozinho; será a pessoa que, num dia comum, percebeu que aquele 4769 com criptografia RC4 não combinava com a estação da `maria.costa` e escalonou com evidência organizada. É esse trabalho repetido, bem documentado, que sustenta a carreira.

### Exercícios — Dias 61 a 90, portfólio, certificação e vida pós-dia-90

1. Você está no dia 78 e precisa mapear este evento para MITRE ATT&CK. Qual técnica e por quê?

```
EventID=4688 Computer=WS-FIN-014.corp.local SubjectUserName=jsilva
NewProcessName=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentProcessName=C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
CommandLine="powershell.exe -nop -w hidden -enc <cadeia base64 omitida>"
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `EventID` | `4688` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não. `4688` = **criação de processo** |
| `Computer` | `WS-FIN-014.corp.local` | **Onde o evento nasceu.** Em logon, é a máquina onde a sessão acontece — não necessariamente onde a credencial foi validada |
| `SubjectUserName` | `jsilva` | A conta que pediu a ação |
| `NewProcessName` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | Caminho do processo criado |
| `ParentProcessName` | `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE` | Caminho do processo pai |
| `CommandLine` | `"powershell.exe -nop -w hidden -enc <cadeia base64 omitida>"` | Linha de comando. `-enc` indica comando em Base64 e `-w hidden` janela oculta |

</details>

2. Um colega quer publicar no portfólio um writeup com o IP `189.45.22.7`, o domínio do cliente e o nome real do gerente. Cite três correções obrigatórias antes de publicar.

3. Verdadeiro ou falso positivo? Alerta "possível exfiltração DNS" às 03:10:

```
1757041800.221  10.10.30.55  53312  10.10.10.5  53  udp  0  -
  update-check.a1b2c3.example.com  1  A  0  NOERROR  F  F  T  T  0  198.51.100.77  300
```

Consulta única, resposta NOERROR, TTL 300, domínio com rótulo aleatório de 6 caracteres. Qual o próximo passo?

4. No dia 85 você tirou 62% no simulado, com erros concentrados em sub-rede e Kerberos. Descreva o ajuste dos dias 86 e 87 e diga se você agenda a prova.

5. Calcule: a rede do laboratório é `172.16.8.0/21`. Qual o primeiro host, o último host e o endereço de broadcast?

<details><summary>Ver gabarito</summary>

**1.** Duas técnicas, não uma. `T1566.001` (Phishing: Spearphishing Attachment) é a hipótese de entrada, porque o processo pai é o WINWORD.EXE — documento do Office iniciando PowerShell não é comportamento de escritório. E `T1059.001` (Command and Scripting Interpreter: PowerShell) para a execução em si. Os indicadores fortes são o par pai/filho anômalo e os parâmetros `-w hidden` (janela oculta) e `-enc` (comando codificado). Próximo passo: buscar Sysmon Event ID 3 (conexão de rede) do mesmo PID e Event ID 22 (consulta DNS) na mesma janela, para descobrir com quem o PowerShell falou. Erro comum: classificar só como "PowerShell suspeito" e perder o vetor de entrada.

**2.** (a) `189.45.22.7` é IP público roteável de terceiro — substituir por faixa de documentação, `203.0.113.7` ou `198.51.100.7`. (b) O domínio do cliente identifica a empresa e viola confidencialidade — trocar por `empresa-exemplo.com.br` ou `corp.local`. (c) Nome real de pessoa é dado pessoal, protegido por LGPD e RGPD — trocar por `jsilva` ou `maria.costa`. Bônus: revisar prints em busca de hostname, número de ticket e nome de ferramenta interna, que também identificam o cliente.

**3.** Provavelmente **falso positivo**, mas com uma verificação antes de fechar. Argumentos a favor: exfiltração por DNS costuma gerar **volume** — dezenas a milhares de consultas com rótulos longos, tipos TXT ou NULL, e respostas grandes. Aqui há uma consulta única, tipo A, resposta NOERROR normal e TTL padrão de 300. O rótulo aleatório sozinho é fraco: CDN, telemetria e antivírus usam subdomínio gerado. Próximo passo antes de fechar: (i) contar consultas do host `10.10.30.55` para `*.example.com` nas últimas 24 horas — se for uma a cada 5 minutos, muda de figura e vira beacon (T1071.004); (ii) verificar em Sysmon Event ID 22 qual processo fez a consulta; (iii) checar reputação do domínio e do IP `198.51.100.77`. Erro comum: fechar imediatamente porque "só teve uma consulta", sem olhar a série temporal.

**4.** 62% está longe da meta de 75%. No dia 86, refazer **apenas** os dois temas errados, não a matéria inteira: 90 minutos de cálculo de sub-rede com 20 exercícios cronometrados, e 90 minutos relendo o fluxo Kerberos com os EventIDs 4768 (TGT solicitado), 4769 (ticket de serviço) e 4771 (pré-autenticação falhou), montando uma tabela própria. No dia 87, refazer o simulado. Não agende a prova ainda: a regra é duas notas acima de 80%. Agende quando o segundo simulado confirmar, marcando a data para cerca de dez dias depois.

**5.** `/21` deixa 21 bits de rede e 11 de host, logo o bloco tem 2048 endereços e o salto é de 8 no terceiro octeto. Rede: `172.16.8.0`. Primeiro host: `172.16.8.1`. Broadcast: `172.16.15.255`. Último host: `172.16.15.254`. Máscara: `255.255.248.0`.

</details>

## Mini-laboratório — Fechamento dos 90 dias: montar o repositório e reproduzir um caso ponta a ponta

**Pré-requisitos:** Git instalado, conta no GitHub, Wireshark, VirtualBox com uma VM Ubuntu e uma VM Windows de avaliação, e uma captura pública baixada de um repositório de amostras de tráfego.

**Passo 1 — estrutura do repositório.**

```bash
mkdir -p soc-portfolio/{writeups,queries,lab,cheatsheets,artigos}
cd soc-portfolio
git init
printf '# Portfólio SOC N1\n\nEstudos, labs e writeups. Dados fictícios.\n' > README.md
git add . && git commit -m "chore(portfolio): estrutura inicial"
```

*Observar:* cinco pastas e um commit. **Critério:** `git log --oneline` mostra o commit.

**Passo 2 — analisar uma captura pública.**

```bash
tshark -r amostra.pcap -q -z conv,tcp | head -20
tshark -r amostra.pcap -Y "http.request" -T fields -e ip.src -e http.host -e http.request.uri | head -20
tshark -r amostra.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head
```

*Observar:* os pares que mais trocam bytes, os domínios HTTP e os nomes DNS mais consultados. **Critério:** você consegue nomear o host mais conversador e um domínio candidato a comando e controle.

**Passo 3 — escrever o writeup.** Em `writeups/caso-01.md`, use as seções: Resumo, Linha do tempo, Evidências (com blocos de log), Hipótese, Mapeamento MITRE, Recomendação. Substitua todo IP público real por `203.0.113.x`.

**Passo 4 — comentar as queries.** Em `queries/spl-kql.md`, salve pelo menos 10 queries com um comentário por linha. Exemplo de SPL:

```spl
index=proxy sourcetype=squid:access          `` fonte de log do proxy ``
| stats count, sum(bytes_out) as saida by src_ip, dest_host   `` volume por destino ``
| where saida > 50000000                     `` mais de 50 MB enviados ``
| sort - saida                               `` maiores primeiro ``
```

**Passo 5 — documentar o lab.** Em `lab/README.md`, registre topologia (rede interna `10.10.20.0/24`), papel de cada VM, versões e como reproduzir.

**Passo 6 — publicar.** `git add . && git commit -m "docs(portfolio): caso 01, queries e lab"` e envie para o GitHub.

**Critério de sucesso final:** um estranho clona o repositório, lê o README e reproduz o caso 01 sem te perguntar nada; e nenhuma busca por dado real (IP de cliente, nome de pessoa, hostname corporativo) retorna resultado.

## O que um SOC Level 1 realmente precisa saber

- 🟢 Todo dia do plano precisa terminar com um artefato salvo; conhecimento não documentado evapora.
- 🟢 Portfólio sem dado real: faixas de documentação (`203.0.113.x`, `198.51.100.x`, `192.0.2.x`), RFC1918 e usuários fictícios.
- 🟢 Writeup tem estrutura fixa: resumo, timeline, evidência, hipótese, MITRE, recomendação.
- 🟢 Sucesso de logon (`resultType=0`, 4624) depois de rajada de falhas é o momento mais grave, não o mais tranquilo.
- 🟢 Saber escrever ticket de escalonamento em 15 minutos vale tanto quanto saber ler o log.
- 🟡 Cadeia pai/filho anômala (Office iniciando PowerShell) é sinal forte: `T1566.001` mais `T1059.001`.
- 🟡 Query em SIEM precisa ser sua: comentada linha a linha, em SPL e KQL, pronta para adaptar.
- 🟡 Certificação carimba, não substitui: Network+ ou Security+ para a vaga, BTL1 para a prática.
- 🟡 Correlacionar três fontes (e-mail, proxy, endpoint) é o que separa triagem de palpite.
- 🔴 Threat hunting com hipótese e engenharia de detecção são a ponte para o Nível 2.
- 🔴 Análise forense de endpoint (memória e artefatos de execução) é o aprofundamento seguinte.
- 🔴 Fadiga de alerta se combate com processo — checklist, rodízio, pausa e feedback para ajustar a regra ruidosa.

## Resumo em 10 linhas

1. O plano de 90 dias tem três blocos: fundamentos, defesa e ferramentas, e integração com portfólio.
2. Os dias 61 a 90 cobrem proxy e web, e-mail, nuvem e identidade, e resposta a incidente.
3. Três laboratórios integradores simulam phishing, movimento lateral e exfiltração, cada um virando relatório.
4. Sete entregáveis compõem o portfólio: repositório, writeups, análises de captura, doc do lab, queries, cheat sheet e artigo.
5. Cada entregável responde uma pergunta implícita da entrevista sobre método, ferramenta e autonomia.
6. Dado fictício é regra absoluta: nada de IP de cliente, nome de pessoa ou hostname corporativo.
7. O checkpoint do dia 90 avalia doze competências objetivas; nota abaixo de 3 manda refazer o bloco.
8. A certificação encaixa no cronograma: estudo em paralelo, simulado nos dias 85 e 87, prova agendada após 80%.
9. Depois do dia 90, a manutenção é semanal: duas horas de lab, leitura diária curta de threat intel e comunidade.
10. O caminho para o Nível 2 passa por forense de endpoint, engenharia de detecção e hunting documentado.



---
