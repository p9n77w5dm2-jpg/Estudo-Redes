# Módulo 15 — Roadmap de conhecimentos para o analista SOC N1

## Por que este módulo importa para o SOC

Você já viu pacotes, protocolos, logs e alertas nos módulos anteriores. Falta agora a pergunta prática: **o que exatamente eu preciso saber para ser contratado, aprovado no período de experiência e promovido em um SOC (Security Operations Center — Centro de Operações de Segurança)?** Este módulo transforma o conteúdo do curso em um mapa de competências com prioridade, definição de domínio e teste de proficiência. Ele serve para você se autoavaliar com honestidade, montar um plano de estudo de 90 dias e chegar na entrevista técnica sabendo o que a banca vai perguntar — e por quê.

### Índice do módulo

- O que faz um SOC N1 e os conhecimentos obrigatórios
- Conhecimentos intermediários e avançados
- Autoavaliação, certificações, recursos e erros que reprovam

## O dia a dia real de um analista SOC N1

Pense em um SOC como o **pronto-socorro de um hospital**. Chega gente o tempo todo. O analista N1 (Nível 1) é o profissional da triagem: ele não faz cirurgia, mas decide quem tem um arranhão, quem tem uma fratura e quem está infartando. Errar a triagem custa caro nos dois sentidos — mandar todo mundo para a cirurgia trava o hospital; mandar o infarto para casa mata o paciente.

O turno normalmente é de 6, 8 ou 12 horas, em regime 24x7. O trabalho gira em torno da **fila de alertas** do SIEM (Security Information and Event Management — sistema que junta e correlaciona logs de toda a empresa). Cada alerta tem um **SLA** (Service Level Agreement — acordo de nível de serviço), que é o tempo máximo para você tocar naquele item. Números típicos de mercado:

| Severidade | Primeiro toque (SLA) | Conclusão ou escalonamento |
|---|---|---|
| Crítica | 15 minutos | 30 minutos |
| Alta | 30 minutos | 2 horas |
| Média | 2 horas | 8 horas |
| Baixa | 8 horas | 24 horas |

O ciclo de trabalho de cada alerta é sempre o mesmo:

1. **Pegar o alerta** (assumir o ticket, para ninguém trabalhar em duplicidade).
2. **Triar**: entender o que a regra detectou e por quê.
3. **Enriquecer**: quem é o usuário, qual é a máquina, o IP é interno ou externo, a reputação do domínio, o país de origem.
4. **Decidir**: falso positivo, verdadeiro positivo benigno (atividade real mas autorizada) ou verdadeiro positivo malicioso.
5. **Agir dentro do playbook**: fechar com justificativa, pedir contenção ou escalar para o N2.
6. **Documentar**: escrever a investigação de forma que outra pessoa entenda sem falar com você.
7. **Passar o turno**: repassar ao colega o que ficou aberto, o que está em observação e o que mudou no ambiente.

### O que NÃO é responsabilidade do N1

Isto reprova em entrevista com a mesma força que o desconhecimento técnico:

- **Não** faz engenharia reversa de malware nem análise profunda de memória (isso é N3 / DFIR).
- **Não** escreve nem altera regra de firewall, política de proxy ou regra de correlação em produção por conta própria.
- **Não** derruba máquina de executivo, não bloqueia IP e não desativa conta sem seguir o playbook e a autorização definida.
- **Não** conversa diretamente com a imprensa, com o cliente final ou com o jurídico sobre incidente.
- **Não** decide sozinho se um incidente é "grave" — quem classifica gravidade acima de um limiar é o N2 ou o coordenador.
- **Não** apaga, "limpa" ou altera evidência (log, arquivo, e-mail suspeito) — isso quebra a cadeia de custódia.

### Como isso aparece nos logs

O alerta que chega na sua fila quase sempre nasce de uma linha de log crua. Exemplo real de tentativa de autenticação falha no Windows:

```
EventID: 4625
Log Name: Security
Account Name:   jsilva
Account Domain: CORP
Failure Reason: Unknown user name or bad password
Status:         0xC000006D
Sub Status:     0xC000006A
Logon Type:     3
Workstation Name: NB-VENDAS-07
Source Network Address: 10.10.24.51
Source Port: 49877
```

Leitura dos campos: `4625` é falha de logon; `Logon Type: 3` é logon de rede (acesso a compartilhamento, autenticação SMB), não é alguém digitando no teclado da máquina; `Sub Status 0xC000006A` significa **senha errada com usuário existente** (se fosse `0xC0000064` seria usuário inexistente); `Source Network Address` é de onde partiu a tentativa.

**O que o N1 observa:** três falhas seguidas de `jsilva` na estação dele às 9h da manhã é troca de senha recente — normal. Duzentas falhas em 90 segundos, com `Sub Status 0xC0000064` variando nomes de usuário, partindo de 10.10.24.51, é enumeração de contas (MITRE ATT&CK T1110.003, password spraying) — suspeito.

**Erro comum de analista júnior:** olhar só a quantidade e ignorar o `Sub Status` e o `Logon Type`. Cem falhas do mesmo usuário na mesma máquina costuma ser serviço com senha antiga em cache; cem falhas de cem usuários diferentes é ataque.

## Conhecimentos obrigatórios por área

Legenda de prioridade: 🟢 **Essencial** (sem isso você não passa no período de experiência) · 🟡 **Importante** (cobrado em 3 a 6 meses) · 🔴 **Avançado** (diferencial para subir a N2).

### Redes

| # | Prioridade | Conhecimento | O que significa dominar | Teste de proficiência |
|---|---|---|---|---|
| 1 | 🟢 | Modelo OSI e TCP/IP | Saber em qual camada cada problema vive e qual evidência existe nela | Em que camada atua um proxy web e em que camada atua um firewall de pacotes? |
| 2 | 🟢 | Endereçamento IPv4 e máscara | Ler CIDR e dizer se dois IPs estão na mesma rede | 10.10.24.51/22 e 10.10.27.9 estão na mesma sub-rede? Qual o broadcast? |
| 3 | 🟢 | RFC1918 x IP público | Distinguir interno de externo antes de julgar o alerta | Classifique: 172.16.5.3, 172.32.5.3, 203.0.113.10 |
| 4 | 🟢 | Portas e serviços comuns | Saber de cabeça 20/21, 22, 23, 25, 53, 80, 88, 135, 139, 389, 443, 445, 3389, 5985 | Qual serviço usa 88/TCP e por que ele importa em ataque de credencial? |
| 5 | 🟢 | Handshake TCP e flags | Interpretar SYN, SYN-ACK, ACK, RST, FIN em log de firewall | O que significa uma sequência de SYN sem SYN-ACK para 500 portas? |
| 6 | 🟢 | DNS na prática | Entender consulta, resposta, NXDOMAIN e resolução recursiva | Como identificar exfiltração via DNS em um `dns.log` do Zeek? |
| 7 | 🟢 | NAT e PAT | Explicar por que 40 máquinas aparecem com o mesmo IP público | Como achar a máquina real por trás de 203.0.113.20 em um alerta externo? |
| 8 | 🟡 | HTTP e HTTPS/TLS | Saber o que dá para ver com TLS (SNI, JA3, certificado) e o que não dá | Com tráfego TLS 1.3 sem inspeção, qual campo ainda revela o destino? |
| 9 | 🟡 | Proxy e web gateway | Ler `access.log` do Squid, Zscaler ou Netskope e entender categoria e ação | O que significa `TCP_DENIED/403` no Squid? |
| 10 | 🟡 | VPN e acesso remoto | Diferenciar túnel completo de split tunnel e ler log de conexão | Usuário conectado da VPN e do escritório ao mesmo tempo: o que investigar? |
| 11 | 🟡 | ICMP | Saber tipo 8/0 (echo) e tipo 3 (destino inacessível) e o abuso de túnel | Por que ICMP com payload de 1.400 bytes constante é suspeito? |
| 12 | 🔴 | Captura com Wireshark/tcpdump | Aplicar filtro de exibição e seguir um fluxo | Escreva o filtro para tráfego HTTP de/para 10.10.24.51 |

### Sistemas operacionais

| # | Prioridade | Conhecimento | O que significa dominar | Teste de proficiência |
|---|---|---|---|---|
| 13 | 🟢 | Windows: processos e serviços | Saber o pai legítimo de `svchost.exe`, `lsass.exe`, `explorer.exe` | Qual é o processo pai normal de `svchost.exe`? |
| 14 | 🟢 | Windows Security EventIDs | Reconhecer 4624, 4625, 4648, 4688, 4720, 4768, 4769, 4776 | O que 4768 registra e por que ele é chave em ataque Kerberos? |
| 15 | 🟢 | Logon Types | Diferenciar 2 (console), 3 (rede), 10 (RDP), 5 (serviço) | Conta de serviço `svc_backup` com Logon Type 10: normal ou não? |
| 16 | 🟢 | Sysmon básico | Ler EventID 1 (criação de processo), 3 (conexão de rede), 22 (consulta DNS) | Qual EventID do Sysmon liga um processo a um domínio consultado? |
| 17 | 🟡 | Linux: usuários e permissões | Entender `/etc/passwd`, sudo, `auth.log` e SSH | Como identificar força bruta SSH no `/var/log/auth.log`? |
| 18 | 🟡 | Linha de comando Windows | Reconhecer uso suspeito de `powershell.exe`, `wmic`, `rundll32`, `certutil` | Por que `certutil` aparece em alerta de download malicioso? |
| 19 | 🟡 | Persistência básica | Saber onde malware costuma se fixar (Run keys, tarefas agendadas, serviços) | Cite duas chaves de Registro usadas para execução no boot |
| 20 | 🔴 | Estrutura de sistema de arquivos | Saber quais diretórios são graváveis por usuário comum e por isso favoritos de malware | Por que execução a partir de `%APPDATA%` merece atenção? |

### Active Directory e identidade

| # | Prioridade | Conhecimento | O que significa dominar | Teste de proficiência |
|---|---|---|---|---|
| 21 | 🟢 | O que é domínio, DC e GPO | Explicar a diferença entre conta local e conta de domínio | Onde ficam registrados os 4624 de uma autenticação de domínio? |
| 22 | 🟢 | Kerberos em linguagem simples | Entender TGT, TGS e por que 4769 aparece em massa | Qual EventID indica pedido de ticket de serviço? |
| 23 | 🟡 | Grupos privilegiados | Saber que Domain Admins, Enterprise Admins e Schema Admins são alvo prioritário | Alerta: `jsilva` adicionado a Domain Admins às 3h. Próximo passo? |
| 24 | 🟡 | MFA e SSO | Entender por que "login bem-sucedido sem MFA" é sinal de alerta | O que é MFA fatigue e como aparece no log de identidade? |
| 25 | 🔴 | Rastro de ferramentas de credencial | Reconhecer o padrão em log deixado por acesso a LSASS ou Kerberoasting | Quais EventIDs você correlaciona ao suspeitar de Kerberoasting? |

### Segurança e ameaças

| # | Prioridade | Conhecimento | O que significa dominar | Teste de proficiência |
|---|---|---|---|---|
| 26 | 🟢 | Tríade CIA | Classificar impacto em confidencialidade, integridade e disponibilidade | Ransomware afeta quais pilares? |
| 27 | 🟢 | Falso positivo x verdadeiro positivo | Escrever a justificativa técnica do fechamento | Fechei como FP: o que precisa estar escrito no ticket? |
| 28 | 🟢 | IoC (Indicador de Comprometimento) | Extrair hash, IP, domínio e URL de um alerta e pesquisar reputação | Cite três tipos de IoC e onde você os consultaria |
| 29 | 🟢 | Phishing | Ler cabeçalho de e-mail, checar SPF, DKIM e DMARC e domínio parecido | `empresa-exemp1o.com.br` chegou ao usuário. O que você verifica primeiro? |
| 30 | 🟡 | MITRE ATT&CK | Mapear alerta para tática e técnica (Txxxx) | A que técnica corresponde password spraying? |
| 31 | 🟡 | Malware: famílias e comportamento | Diferenciar downloader, ransomware, infostealer e RAT pelo comportamento em rede | Beacon C2 tem que assinatura de tráfego típica? |
| 32 | 🟡 | Cadeia de ataque (kill chain) | Situar o alerta na fase: acesso inicial, execução, movimento lateral, exfiltração | 4625 em massa está em qual fase? |
| 33 | 🔴 | Análise de e-mail com anexo | Detonar em sandbox autorizada e ler o veredito | Que dado do relatório de sandbox você leva para o ticket? |

### Ferramentas

| # | Prioridade | Conhecimento | O que significa dominar | Teste de proficiência |
|---|---|---|---|---|
| 34 | 🟢 | SIEM (busca básica) | Filtrar por tempo, host, usuário e IP sem depender de dashboard pronto | Monte a busca dos 4625 do usuário `maria.costa` nas últimas 24h |
| 35 | 🟢 | SPL do Splunk | Escrever `index`, `stats`, `table`, `sort` | Conte falhas de logon por IP de origem |
| 36 | 🟡 | KQL (Sentinel/Defender) | Escrever `where`, `summarize`, `project`, `bin` | Agrupe eventos por hora usando `bin` |
| 37 | 🟢 | EDR (console) | Achar a linha do tempo de um processo em um endpoint | Onde você vê a árvore de processos de um alerta? |
| 38 | 🟢 | Ticketing | Registrar linha do tempo, evidência, ação e recomendação | O que nunca pode faltar em um ticket que você escala? |
| 39 | 🟡 | Fontes de reputação | Consultar hash e domínio em fonte confiável sem vazar dado interno | Por que não se deve enviar documento interno para site público de análise? |
| 40 | 🟡 | Firewall/proxy (leitura) | Ler CSV de Palo Alto e `key=value` do FortiGate | Em Palo Alto, qual campo diz se a sessão foi permitida ou negada? |

### Processos

| # | Prioridade | Conhecimento | O que significa dominar | Teste de proficiência |
|---|---|---|---|---|
| 41 | 🟢 | Playbook | Seguir o passo a passo sem improvisar e sinalizar quando ele não cobre o caso | O playbook não prevê seu cenário. O que você faz? |
| 42 | 🟢 | SLA e priorização | Saber qual dos cinco alertas abertos você pega primeiro | Crítico com 12 min e alto com 25 min: qual primeiro? |
| 43 | 🟢 | Escalonamento | Escalar com contexto suficiente para o N2 não recomeçar do zero | Liste cinco itens obrigatórios ao escalar |
| 44 | 🟢 | Passagem de turno | Deixar registrado aberto, em observação e pendências | Como você repassa um caso ainda inconclusivo? |
| 45 | 🟡 | Cadeia de custódia | Preservar evidência sem alterar o original | Por que não se deve abrir o anexo suspeito na sua própria estação? |
| 46 | 🟡 | Classificação de severidade | Aplicar o critério da empresa, não o seu instinto | O que muda a severidade: o ativo ou o alerta? |

### Soft skills

| # | Prioridade | Conhecimento | O que significa dominar | Teste de proficiência |
|---|---|---|---|---|
| 47 | 🟢 | Escrita técnica objetiva | Descrever fato, evidência e conclusão separadamente | Reescreva "achei estranho" em linguagem de ticket |
| 48 | 🟢 | Ceticismo disciplinado | Não fechar como FP só porque "sempre foi FP" | Quando um FP recorrente deve virar pedido de ajuste de regra? |
| 49 | 🟢 | Comunicação sob pressão | Avisar cedo, com o que se sabe, sem esperar certeza total | Você suspeita de ransomware às 4h. Espera o turno da manhã? |
| 50 | 🟡 | Aprendizado contínuo | Transformar cada caso novo em anotação reutilizável | Como você documenta um aprendizado para o time? |

### Exercícios — O que faz um SOC N1 e os conhecimentos obrigatórios

1. **Sub-rede.** A estação `NB-VENDAS-07` tem IP 10.10.24.51/22. O servidor de arquivos é 10.10.27.9. Eles estão na mesma sub-rede? Qual é o endereço de rede e o de broadcast?

2. **Leitura de log.** Analise o trecho abaixo do Palo Alto (TRAFFIC, CSV) e diga o que aconteceu:

```
2026-09-03 02:14:07,TRAFFIC,end,10.10.24.51,203.0.113.44,45312,443,tcp,ssl,DMZ-Out,allow,842,138204,197,"Trust","Untrust","corp\jsilva"
```

3. **Verdadeiro ou falso positivo?** Chega o alerta: "Múltiplas falhas de autenticação". No log, 187 eventos 4625 em 4 minutos, `Sub Status 0xC0000064`, 187 nomes de usuário diferentes, todos vindos de 10.10.60.12, `Logon Type: 3`. Falso positivo ou verdadeiro positivo? Qual técnica MITRE?

4. **Próximo passo.** Confirmado o cenário do exercício 3, cite as três primeiras ações do N1, na ordem, e diga o que deve constar no escalonamento.

5. **Fronteira de papel.** Durante a madrugada você identifica que 10.10.60.12 é a origem do ataque. Você mesmo bloqueia o IP no firewall? Justifique.

<details><summary>Ver gabarito</summary>

**1.** Máscara /22 = 255.255.252.0, ou seja, blocos de 4 no terceiro octeto. O bloco que contém 24 vai de **10.10.24.0** (rede) até **10.10.27.255** (broadcast). Como 27 está dentro do intervalo 24–27, **sim, estão na mesma sub-rede** e a comunicação entre eles não passa pelo roteador — o que significa que o firewall provavelmente **não** registra esse tráfego. Aprendizado: em rede plana, ausência de log de firewall não é prova de ausência de tráfego.

**2.** Sessão SSL/TLS iniciada às 02h14 pela estação interna 10.10.24.51 para o IP público 203.0.113.44 na porta 443, ação `allow`, com 842 bytes enviados e 138.204 bytes recebidos em 197 pacotes, associada ao usuário `corp\jsilva`. Pontos de atenção: horário fora do expediente e razão de bytes fortemente assimétrica (muito mais download do que upload), típico de download de arquivo grande. Não é conclusivo por si só — pode ser atualização de software. O N1 enriquece: reputação do IP, categoria do destino, se outras máquinas falam com o mesmo IP e se há evento de EDR no mesmo minuto.

**3.** **Verdadeiro positivo.** O que decide é a combinação: `0xC0000064` significa **usuário inexistente**, e são 187 nomes distintos partindo de uma única origem em 4 minutos, com `Logon Type: 3` (rede). Isso é **enumeração/spray de contas** — MITRE ATT&CK **T1110.003 (Password Spraying)**, dentro da tática TA0006 (Credential Access). Se fosse um único usuário com muitas falhas e `0xC000006A` (senha errada, usuário existe), a hipótese principal seria credencial antiga em cache de serviço, e provavelmente falso positivo.

**4.** Ordem correta: (a) **identificar o ativo 10.10.60.12** — nome da máquina, dono, se é servidor, estação ou host não gerenciado; (b) **verificar se houve sucesso** — procurar 4624 vindo do mesmo IP na mesma janela, porque falha em massa sem sucesso é ruído contido, falha com um sucesso no meio é comprometimento; (c) **escalar dentro do SLA de severidade crítica**. O escalonamento precisa conter: janela de tempo exata com fuso, IP e hostname de origem, contas alvo (quantidade e se alguma é privilegiada), evidência bruta (as consultas usadas e a amostra de log), o que já foi verificado e descartado, e a hipótese com a técnica MITRE.

**5.** **Não.** Bloqueio de IP em firewall é ação de contenção que exige playbook, autorização e registro — e o IP é **interno**, então bloqueá-lo pode derrubar um serviço legítimo comprometido e ainda destruir a chance de observar o atacante. O N1 **solicita** a contenção pelo canal definido (N2, plantão de rede ou processo de resposta a incidente) e documenta o pedido, o horário e quem autorizou. Agir por conta própria fora do playbook é um dos motivos mais frequentes de reprovação em período de experiência.

</details>


## Conhecimentos intermediários — o degrau que separa o "abridor de ticket" do analista

Se os conhecimentos obrigatórios (vistos no trecho anterior) são a habilitação de motorista, os intermediários são a experiência de dirigir na chuva. Você já sabe o que é um pacote e um alerta; agora precisa saber **operar as máquinas onde o incidente acontece** e **escrever o que encontrou**.

A prioridade continua com a mesma escala do trecho anterior:

| Marcador | Significado | Prazo realista |
|---|---|---|
| 🔴 P1 | Cobrado já no estágio ou nos primeiros 90 dias | 0–3 meses |
| 🟡 P2 | Esperado para sair da tutela do N2 | 3–9 meses |
| 🟢 P3 | Diferencial que abre a porta do N2 | 9–18 meses |

### Sistemas operacionais e linha de comando

| # | Item | Prio | Dominar significa | Teste de proficiência |
|---|---|---|---|---|
| 1 | Linux — navegação e arquivos | 🔴 P1 | `cd`, `ls -la`, `cat`, `less`, `find`, permissões `rwx` | Achar todos os arquivos modificados nas últimas 24h em `/etc` |
| 2 | Linux — leitura de log | 🔴 P1 | `grep`, `tail -f`, `awk`, `cut`, `sort \| uniq -c` | Listar os 10 IPs que mais aparecem em `/var/log/auth.log` |
| 3 | Linux — processos e rede | 🟡 P2 | `ps aux`, `ss -tulpn`, `crontab -l`, `systemctl` | Descobrir qual processo escuta a porta 4444 |
| 4 | Arquivos-chave do Linux | 🟡 P2 | `/etc/passwd`, `/etc/crontab`, `~/.ssh/authorized_keys`, `.bash_history` | Explicar por que uma chave nova em `authorized_keys` é achado grave |
| 5 | Windows — estrutura | 🔴 P1 | `C:\Windows\System32`, perfis, serviços, tarefas agendadas | Dizer se `svchost.exe` fora de System32 é normal |
| 6 | Registro do Windows | 🟡 P2 | Chaves `Run`, `RunOnce`, `Services` como persistência (T1547) | Apontar 3 chaves usadas para autostart |
| 7 | Contas e grupos locais | 🔴 P1 | Administradores, `Domain Admins`, contas de serviço | Diferenciar conta de serviço de conta humana pelo padrão de logon |
| 8 | PowerShell para investigação | 🟡 P2 | `Get-WinEvent`, `Get-Process`, `Get-NetTCPConnection`, `Get-LocalUser` | Extrair todos os 4625 das últimas 2h de um servidor |
| 9 | Sysmon | 🟡 P2 | Evento 1 (processo), 3 (conexão), 22 (DNS) | Reconstruir a árvore pai→filho de um processo suspeito |
| 10 | Expressões regulares (regex) | 🟡 P2 | Âncoras, classes, quantificadores, grupos | Escrever regex que casa IPv4 e não casa `999.1.1.1` |

**Analogia:** aprender PowerShell é como ganhar a chave-mestra do prédio. Antes você perguntava ao zelador (o N2) o que havia em cada sala; agora abre a porta sozinho.

```powershell
# Últimos logons falhados (4625) do servidor SRV-FILE01 nas últimas 2 horas
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = (Get-Date).AddHours(-2)
} | Select-Object TimeCreated,
    @{n='Usuario'; e={$_.Properties[5].Value}},
    @{n='IP_Origem'; e={$_.Properties[19].Value}}
```

**Erro comum de analista júnior:** rodar `Get-WinEvent` sem `-FilterHashtable`, usando `Where-Object` depois. O comando puxa milhões de eventos para a memória e trava a estação. Filtre **na fonte**, sempre.

### Nuvem, e-mail e criptografia

| # | Item | Prio | Dominar significa | Teste de proficiência |
|---|---|---|---|---|
| 11 | Modelo de responsabilidade compartilhada | 🟡 P2 | O provedor protege a nuvem; você protege o que está nela | Dizer de quem é a culpa num bucket público |
| 12 | AWS CloudTrail | 🟡 P2 | Registra chamadas de API: quem, quando, de onde | Identificar `ConsoleLogin` sem MFA |
| 13 | Azure Entra ID sign-in logs | 🟡 P2 | Logon, risco, país, aplicação, resultado | Achar logon de país onde a empresa não opera |
| 14 | VPC Flow Logs / NSG Flow Logs | 🟢 P3 | O "NetFlow" da nuvem: aceito/negado por fluxo | Ver se um EC2 falou com IP externo |
| 15 | SPF, DKIM e DMARC | 🔴 P1 | Três verificações antienganação de remetente | Explicar por que SPF passa e DMARC falha |
| 16 | Cabeçalho de e-mail | 🔴 P1 | Ler `Received`, `Return-Path`, `Authentication-Results` | Achar o IP real do primeiro salto |
| 17 | Phishing: tipos e indicadores | 🔴 P1 | Domínio parecido, urgência, anexo, link encurtado | Classificar um e-mail em 5 minutos |
| 18 | Hash x cifra | 🔴 P1 | Hash é mão única (SHA-256); cifra é reversível | Dizer por que não se "decifra" um hash |
| 19 | Simétrica x assimétrica | 🟡 P2 | AES usa uma chave; RSA/ECDSA usam par público/privado | Explicar por que TLS usa as duas |
| 20 | PKI e certificados | 🟡 P2 | CA, cadeia de confiança, validade, CN/SAN | Julgar um certificado autoassinado em servidor interno |

**Como aparece nos logs** — autenticação de e-mail e uma falha de DMARC:

```
Authentication-Results: mx.empresa-exemplo.com.br;
  spf=pass (sender IP is 203.0.113.44) smtp.mailfrom=envio-marketing.example.com;
  dkim=fail (body hash did not verify) header.d=example.com;
  dmarc=fail action=quarantine header.from=empresa-exemplo.com.br
Received: from mail.example.com (203.0.113.44) by mx.empresa-exemplo.com.br
  with SMTP id 8FA21C; Tue, 3 Sep 2026 09:14:22 -0300
Return-Path: <cobranca@envio-marketing.example.com>
From: "Financeiro" <financeiro@empresa-exemplo.com.br>
```

Campos: `spf=pass` diz apenas que o IP 203.0.113.44 pode enviar por `envio-marketing.example.com` — o domínio do envelope. `header.from` é o que o usuário **vê**: `empresa-exemplo.com.br`. Como os dois não batem e o DKIM falhou, o DMARC falha por falta de alinhamento. **Normal:** os três `pass` e alinhamento com o domínio da empresa. **Suspeito:** SPF `pass` de um domínio de terceiro carregando um `From` interno — spoofing clássico (T1566).

**Erro comum:** ver `spf=pass` e liberar o e-mail. SPF valida o envelope, não o remetente exibido.

### Processo, escrita e sobrevivência no turno

| # | Item | Prio | Dominar significa | Teste de proficiência |
|---|---|---|---|---|
| 21 | CVE, CVSS e EPSS | 🟡 P2 | CVSS mede gravidade técnica; EPSS mede chance de exploração | Priorizar CVSS 9.8 sem exposição x 7.5 exposto |
| 22 | Vetor CVSS 3.1 | 🟡 P2 | AV, AC, PR, UI, S, C, I, A | Ler `AV:N/AC:L/PR:N/UI:N` sem consultar tabela |
| 23 | Gestão de vulnerabilidade | 🟢 P3 | Descoberta, priorização, remediação, verificação | Explicar por que patch não é o fim do ciclo |
| 24 | ITIL: incidente x requisição x problema | 🔴 P1 | Incidente interrompe; problema é a causa-raiz | Classificar um chamado corretamente |
| 25 | SLA, prioridade e escalonamento | 🔴 P1 | Impacto x urgência; quando passar para o N2 | Dizer o SLA do seu maior severidade |
| 26 | Higiene de ticket | 🔴 P1 | Timestamp com fuso, IOC, evidência bruta, hipótese | Outro analista continua sem te perguntar nada |
| 27 | Escrita de relatório | 🟡 P2 | Resumo executivo, linha do tempo, evidência, recomendação | Uma página que o gerente entende sem jargão |
| 28 | Comunicação sob pressão | 🟡 P2 | Fato x hipótese, "não sei ainda" é resposta válida | Dar update de 3 frases numa ponte de crise |
| 29 | Gestão de turno e handover | 🟡 P2 | Passar bastão com pendências e contexto | Handover escrito em 10 linhas |
| 30 | Fadiga de alerta | 🟡 P2 | Reconhecer queda de atenção; pedir tuning da regra | Propor supressão com justificativa e risco residual |

**Erro comum:** escrever no ticket "usuário clicou em link malicioso, encerrado". Sem hora, sem URL, sem host, sem quem confirmou. Seis meses depois, na auditoria, esse ticket não prova nada.

## Conhecimentos avançados — o que te promove

Estes não são cobrados de um N1 recém-contratado. São o que faz um N1 virar N2.

| # | Item | Prio | Dominar significa | Teste de proficiência |
|---|---|---|---|---|
| 31 | Engenharia de detecção: ciclo | 🟢 P3 | Hipótese → lógica → teste → tuning → documentação | Descrever o ciclo de uma regra que você melhorou |
| 32 | Regras Sigma | 🟢 P3 | Detecção em formato portável entre SIEMs | Ler uma regra Sigma e dizer o que ela pega |
| 33 | KQL intermediário | 🟢 P3 | `summarize`, `join`, `bin`, `let` | Contar 4625 por conta em janelas de 5 minutos |
| 34 | SPL intermediário | 🟢 P3 | `stats`, `eventstats`, `transaction`, `lookup` | Achar beaconing por desvio-padrão de intervalo |
| 35 | Baseline e detecção de anomalia | 🟢 P3 | Saber o que é "normal" antes de chamar de anômalo | Explicar por que 200 DNS/min pode ser normal |
| 36 | Threat hunting por hipótese | 🟢 P3 | Buscar sem alerta, partindo de TTP do ATT&CK | Escrever hipótese testável em uma frase |
| 37 | Pirâmide da Dor | 🟢 P3 | Hash é barato de trocar; TTP dói | Dizer por que bloquear hash rende pouco |
| 38 | Triagem de malware (estática) | 🟢 P3 | Hash, strings, tipo de arquivo, VirusTotal, sandbox | Triar um binário sem executá-lo na sua máquina |
| 39 | Leitura de sandbox | 🟢 P3 | Traduzir relatório em IOC e comportamento | Extrair C2 e persistência de um relatório |
| 40 | Ordem de volatilidade | 🟢 P3 | RAM antes de disco; disco antes de backup | Ordenar a coleta numa máquina ligada |
| 41 | Cadeia de custódia | 🟢 P3 | Quem coletou, quando, hash da evidência | Justificar hash antes e depois da cópia |
| 42 | Artefatos forenses Windows | 🟢 P3 | Prefetch, Amcache, ShimCache, MFT, `$UsnJrnl` | Dizer qual artefato prova execução |
| 43 | Captura e leitura de PCAP | 🟢 P3 | `tcpdump`, filtros Wireshark, `follow stream` | Filtrar `http.request.method == "POST"` |
| 44 | Análise de C2 e beaconing | 🟢 P3 | Intervalo regular, jitter, tamanho constante | Reconhecer batimento de 60s em conn.log |
| 45 | Contenção e erradicação | 🟢 P3 | Isolar host, revogar sessão, resetar credencial | Dizer a ordem correta e o porquê |

### Como o avançado aparece no log — beaconing em Zeek `conn.log`

```
ts                   uid        id.orig_h    id.orig_p id.resp_h      id.resp_p proto service duration orig_bytes resp_bytes conn_state
2026-09-03T10:00:03Z CxT9a1     10.10.24.57  49871     203.0.113.90   443       tcp   ssl     0.412    512        1104       SF
2026-09-03T10:01:04Z CxT9a2     10.10.24.57  49883     203.0.113.90   443       tcp   ssl     0.398    512        1104       SF
2026-09-03T10:02:03Z CxT9a3     10.10.24.57  49890     203.0.113.90   443       tcp   ssl     0.421    512        1112       SF
```

Campos: `ts` é o horário; `id.orig_h` a origem interna; `id.resp_h` o destino; `orig_bytes`/`resp_bytes` o volume em cada direção; `conn_state SF` significa conexão TCP completa e encerrada normalmente. **Normal:** navegação humana tem intervalos irregulares e volumes variados. **Suspeito:** aqui há uma conexão a cada ~60 segundos, sempre com 512 bytes de subida — assinatura de canal de comando e controle (T1071.001).

```spl
index=zeek sourcetype=zeek:conn dest_ip=203.0.113.90
| streamstats current=f last(_time) as prox by src_ip   /* horário da conexão seguinte */
| eval intervalo = prox - _time                          /* espaço entre conexões */
| stats count, avg(intervalo) as media, stdev(intervalo) as desvio by src_ip
| where count > 20 AND desvio < 5                        /* muitas conexões, muito regulares */
```

**Erro comum:** olhar só o destino e concluir "IP não está em lista de bloqueio, é falso positivo". A regularidade é o indicador — o IP pode ser novo e ainda não catalogado.

### Exercícios — Conhecimentos intermediários e avançados

1. No cabeçalho de e-mail mostrado acima, o SPF passou. O e-mail deve ser liberado? Justifique citando qual verificação falhou e por quê.
2. Um servidor Linux (`10.10.30.12`) foi comprometido. Escreva o comando que lista os 10 IPs com mais tentativas em `/var/log/auth.log` e explique o que cada parte faz.
3. Um analista recebe a CVE-2026-XXXX com vetor `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (CVSS 9.8) num servidor sem exposição à internet, e outra com CVSS 7.5 num servidor web público com exploração ativa. Qual priorizar e por quê?
4. Analisando o `conn.log` acima, o alerta "conexão com IP desconhecido" é verdadeiro ou falso positivo? Qual o próximo passo da investigação?
5. Você chega numa estação Windows ainda ligada, suspeita de comprometimento. Liste a ordem de coleta pela ordem de volatilidade e diga qual artefato prova **execução** de um binário.

<details><summary>Ver gabarito</summary>

**1.** Não deve ser liberado. O `spf=pass` valida apenas que 203.0.113.44 pode enviar em nome de `envio-marketing.example.com`, que é o domínio do envelope (`Return-Path`). O `header.from` exibido ao usuário é `empresa-exemplo.com.br` — domínio diferente. Sem alinhamento e com `dkim=fail`, o `dmarc=fail action=quarantine` é o veredito correto: é tentativa de spoofing do próprio domínio da empresa (T1566). Ação: manter em quarentena, verificar se outros destinatários receberam e buscar o remetente em toda a base.

**2.** `grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -10`. O `grep` filtra só as linhas de falha; o `awk` extrai o campo do IP; `sort` agrupa valores iguais lado a lado (pré-requisito do `uniq`); `uniq -c` conta as repetições; `sort -rn` ordena do maior para o menor numericamente; `head -10` mostra os dez primeiros. Confirme o índice do campo com `tail -1` antes, porque o formato varia por distribuição.

**3.** Priorize a CVSS 7.5. O CVSS mede gravidade técnica em ambiente teórico, não risco real. A 9.8 tem `AV:N` (rede), mas se o servidor não é alcançável da internet nem de rede de usuário, o vetor de ataque prático não existe hoje. A 7.5 tem exposição pública e exploração ativa — nesse caso, EPSS alto e presença no catálogo de vulnerabilidades exploradas mandam mais que o número do CVSS. Regra: risco = gravidade × exposição × probabilidade de exploração.

**4.** Verdadeiro positivo provável — e o motivo não é o IP, é o **padrão**. Três conexões com intervalo de ~60 s, duração quase idêntica e 512 bytes de subida constantes formam batimento de C2 (T1071.001). Próximos passos, nesta ordem: (a) verificar em `ssl.log` o SNI e o certificado (autoassinado ou JA3 raro reforça a hipótese); (b) em `dns.log`, ver qual domínio resolveu para 203.0.113.90; (c) no EDR do host 10.10.24.57, achar o processo dono da conexão via Sysmon evento 3 e sua árvore pelo evento 1; (d) se confirmar processo não autorizado, acionar contenção — isolar o host antes de erradicar. Não bloqueie só o IP: isso avisa o atacante e ele troca de infraestrutura em minutos (base da Pirâmide da Dor).

**5.** Ordem de volatilidade: (1) memória RAM e estado de rede/processos ativos, (2) sessões e usuários logados, (3) disco — arquivos temporários e sistema de arquivos, (4) logs remotos e backups. Não desligue nem reinicie: isso destrói a RAM e as conexões ativas. O artefato que melhor prova **execução** é o Prefetch (`C:\Windows\Prefetch`), que registra nome do binário, contagem e horários de execução. ShimCache e Amcache indicam presença/registro do arquivo, mas nem sempre execução efetiva — confundir os dois é erro clássico em relatório. Gere o hash da imagem coletada antes e depois da cópia e registre na cadeia de custódia.

</details>


## Checklist de auto-avaliação

Antes de aceitar um plantão, faça o que um piloto faz antes de decolar: passar o dedo numa lista e responder honestamente "sei ou não sei". A tabela abaixo tem uma linha por tema do curso. Marque **uma** coluna por linha:

- **Não sei** — nunca ouvi falar.
- **Já vi** — reconheço o nome, mas não explico.
- **Sei explicar** — explico para um colega em dois minutos.
- **Sei fazer sozinho** — resolvo um alerta real sem pedir ajuda.

| # | Tema | Não sei | Já vi | Sei explicar | Sei fazer sozinho |
|---|------|:---:|:---:|:---:|:---:|
| 1 | Modelo OSI e TCP/IP, encapsulamento | ☐ | ☐ | ☐ | ☐ |
| 2 | Endereçamento IPv4, máscara, CIDR e sub-rede | ☐ | ☐ | ☐ | ☐ |
| 3 | Faixas privadas RFC1918, NAT e IP público | ☐ | ☐ | ☐ | ☐ |
| 4 | Switching, VLAN, ARP e MAC | ☐ | ☐ | ☐ | ☐ |
| 5 | Roteamento, gateway padrão e tabela de rotas | ☐ | ☐ | ☐ | ☐ |
| 6 | TCP: three-way handshake, flags SYN/ACK/RST/FIN | ☐ | ☐ | ☐ | ☐ |
| 7 | UDP e ICMP (type 8/0, type 3 code 3) | ☐ | ☐ | ☐ | ☐ |
| 8 | Portas e serviços comuns (22, 53, 80, 443, 445, 3389) | ☐ | ☐ | ☐ | ☐ |
| 9 | DNS: query, resposta, NXDOMAIN, DoH e tunelamento | ☐ | ☐ | ☐ | ☐ |
| 10 | DHCP e correlação IP → host → usuário | ☐ | ☐ | ☐ | ☐ |
| 11 | HTTP/HTTPS, códigos de status, User-Agent | ☐ | ☐ | ☐ | ☐ |
| 12 | TLS: handshake, SNI, certificado, JA3 | ☐ | ☐ | ☐ | ☐ |
| 13 | Proxy e web gateway (Squid, Netskope, Zscaler) | ☐ | ☐ | ☐ | ☐ |
| 14 | Firewall e leitura de log (Palo Alto, FortiGate, ASA) | ☐ | ☐ | ☐ | ☐ |
| 15 | IDS/IPS e Suricata EVE JSON | ☐ | ☐ | ☐ | ☐ |
| 16 | Zeek: conn.log, dns.log, http.log, ssl.log | ☐ | ☐ | ☐ | ☐ |
| 17 | Wireshark e tcpdump: filtros e follow stream | ☐ | ☐ | ☐ | ☐ |
| 18 | VPN e acesso remoto | ☐ | ☐ | ☐ | ☐ |
| 19 | Windows Security: 4624/4625/4768/4769/4776/4688 | ☐ | ☐ | ☐ | ☐ |
| 20 | Sysmon 1/3/22 e correlação processo → rede | ☐ | ☐ | ☐ | ☐ |
| 21 | SIEM: busca SPL e KQL, triagem e escalonamento | ☐ | ☐ | ☐ | ☐ |

**Como usar:** qualquer linha em "Não sei" ou "Já vi" vira estudo da semana. A meta realista para entrar num SOC N1 (Security Operations Center, Centro de Operações de Segurança, nível 1) é ter as linhas 1 a 12 e 19 a 21 em "Sei explicar" ou melhor.

---

## Trilha de certificações comentada

Certificação não substitui prática, mas abre porta de RH e organiza o estudo. A ordem abaixo é por custo-benefício para quem está entrando.

| Ordem | Certificação | O que cobre | Para quem serve | Quando fazer |
|---|---|---|---|---|
| 1 | **CompTIA Network+** | Fundamentos de rede: OSI, IPv4/IPv6, sub-rede, cabeamento, roteamento, troubleshooting | Quem não tem base de redes | Antes de tudo, se as linhas 1–8 do checklist estão fracas |
| 2 | **CompTIA Security+** | Fundamentos de segurança: criptografia, controles, tipos de ataque, resposta a incidente | Requisito de vaga mais comum para N1 | Logo após Network+, ou como primeira se já sabe redes |
| 3 | **TryHackMe — trilha SOC Level 1** | Laboratório guiado: Wireshark, Zeek, Suricata, Splunk, análise de phishing, Windows/Sysmon | Quem precisa de mão na massa barato | Em paralelo com Security+, do primeiro mês em diante |
| 4 | **LetsDefend — trilha SOC Analyst** | Simulação de fila de alertas real: triagem, playbook, fechar como verdadeiro/falso positivo | Treinar o *fluxo* do plantão, não só a teoria | Depois de dominar o básico de log |
| 5 | **Splunk Core Certified User** | SPL básico, busca, campos, relatórios e dashboards | Quem vai cair num SOC com Splunk | Quando o SIEM do seu SOC for Splunk |
| 6 | **Microsoft SC-200 (Security Operations Analyst)** | Microsoft Sentinel, Defender XDR, KQL, regras de detecção e caça | SOC com stack Microsoft (maioria do mercado corporativo) | Após 3–6 meses de plantão |
| 7 | **Blue Team Level 1 (BTL1)** | Prova prática de 24h: phishing, forense, SIEM, threat intel, resposta a incidente | Quem quer provar capacidade prática, não decoreba | Ao final do primeiro ano |
| 8 | **Cisco CCNA** | Rede a sério: switching, VLAN, roteamento, ACL, configuração de equipamento | Quem quer virar referência de rede no time | Quando quiser sair do N1 pelo lado de rede |
| 9 | **CompTIA CySA+** | Análise de comportamento, gestão de vulnerabilidade, resposta a incidente | Ponte para N2 | Segundo ano |
| 10 | **GIAC GCIA / GCIH** | GCIA: análise profunda de tráfego e IDS. GCIH: manuseio de incidente e técnicas de ataque | Avançado, caro — normalmente pago pela empresa | Quando já for N2/N3 ou tiver patrocínio |

Regra prática: **Security+ abre a porta, TryHackMe/LetsDefend te fazem passar no teste técnico, SC-200 ou Splunk te tornam produtivo no primeiro mês.**

---

## Recursos gratuitos que valem o tempo

### Laboratórios práticos
- **Security Onion** — distribuição gratuita com Zeek, Suricata, Elastic e Kibana em uma máquina virtual. É o laboratório mais próximo de um SOC real.
- **TryHackMe** — parte das salas do nível iniciante é gratuita.
- **LetsDefend** — plano gratuito com um número limitado de alertas por dia.
- **DetectionLab / Windows Sandbox / VirtualBox** — ambiente Windows descartável para gerar EventID 4625 e Sysmon sem risco.
- **CyberDefenders** e **Blue Team Labs Online** — desafios de análise com casos gratuitos.

### Capturas de treino (arquivos `.pcap`)
- **Malware-Traffic-Analysis.net** — capturas reais com exercícios e gabarito. Melhor recurso gratuito que existe para leitura de tráfego.
- **Wireshark Sample Captures** (wiki oficial) — capturas pequenas por protocolo, ótimas para aprender filtros.
- **Netresec** — lista consolidada de repositórios públicos de PCAP.

### Leitura e referência
- **MITRE ATT&CK** — catálogo de técnicas com códigos T1059 (Command and Scripting Interpreter), T1071 (Application Layer Protocol), T1110 (Brute Force), T1550.003 (Pass the Ticket).
- **RFCs** quando a dúvida for de protocolo, e a documentação oficial de Palo Alto, Fortinet, Cisco, Microsoft e Zeek para significado de campo de log.
- **NIST SP 800-61** — guia de tratamento de incidente.

### Blogs de threat intel
- The DFIR Report, Talos Intelligence (Cisco), Unit 42 (Palo Alto), Microsoft Security Blog, CISA Advisories, Google Threat Intelligence/Mandiant, SANS Internet Storm Center (diário curto, excelente hábito).

### Serviços de consulta
- VirusTotal, AbuseIPDB, urlscan.io, Shodan, MXToolbox — todos com camada gratuita. Lembre: reputação é **indício**, não veredito.

### Comunidades
- Subreddits r/cybersecurity, r/blueteamsec e r/AskNetsec; comunidades de Discord/Slack de Security Onion, TryHackMe e BlueTeam; grupos brasileiros de resposta a incidente.

---

## Os 10 erros que reprovam um N1

| # | Erro | O que fazer no lugar |
|---|------|----------------------|
| 1 | **Fechar alerta sem investigar** ("já vi isso, é falso positivo") | Toda conclusão precisa de evidência anexada: log, host, usuário, horário. Se não sabe justificar, não fechou — só ignorou. |
| 2 | **Não documentar** | Escreva no ticket o que viu, o que consultou e por que decidiu. O ticket é para o colega do próximo turno e para a auditoria. |
| 3 | **Escalar tudo** | Antes de escalar, faça o mínimo: identifique o host, o usuário, o destino e verifique se é comportamento conhecido. Escalone com hipótese, não com "olha isso aqui". |
| 4 | **Nunca escalar** | Estourou o tempo de triagem definido no playbook ou há sinal de comprometimento (credencial, movimento lateral, exfiltração)? Escale imediatamente. Segurar alerta grave por orgulho é o erro mais caro. |
| 5 | **Confiar cegamente em reputação** | "VirusTotal 0/70" não inocenta: infraestrutura nova nasce limpa. "12/70" não condena: falso positivo de motor genérico é comum. Use reputação como um voto entre vários. |
| 6 | **Ignorar fuso horário** | Firewall em UTC, endpoint em horário local, SIEM em outro. Sempre normalize para UTC no ticket e escreva o fuso explicitamente. Sem isso a linha do tempo do incidente fica errada. |
| 7 | **Não ler a regra que disparou** | Leia a lógica da detecção antes de julgar o alerta. Você precisa saber *o que* a regra procurava para dizer se ela acertou. |
| 8 | **Confundir IP de NAT com máquina** | Vários hosts saem pelo mesmo IP público. Correlacione com log de DHCP, de proxy ou de autenticação para chegar ao host e ao usuário reais. |
| 9 | **Analisar amostra ou link em máquina de produção** | Detonação só em sandbox isolada. Nunca clicar no link do phishing no navegador corporativo. |
| 10 | **Olhar um evento isolado** | Um 4625 é ruído; 300 em dois minutos de um só IP é ataque de força bruta (T1110). Sempre pergunte: quantas vezes, em quanto tempo, de onde e para quantos destinos? |

**Erro bônus, o mais comum de todos:** copiar o veredito do colega sem repetir a checagem. Se o alerta é seu, a evidência tem que ser sua.

### Exercícios — Auto-avaliação, certificações, recursos e erros que reprovam

**1.** Você recebe este trecho do SIEM. Diga qual erro da lista de dez está prestes a cometer se fechar como falso positivo por reputação limpa.

```
Sep 03 14:22:11 fw01 1,2026/09/03 14:22:11,014201007777,TRAFFIC,end,2562,2026/09/03 14:22:11,10.10.24.57,203.0.113.44,192.0.2.10,203.0.113.44,regra-saida-internet,jsilva,,ssl,vsys1,Interna,Externa,ae1.24,ae1.10,Log-Forward,2026/09/03 14:22:11,88421,1,52344,443,17233,443,0x400053,tcp,allow,824512,4210,820302,1842,2026/09/03 13:50:02,1928,any,0,7734512,0x0,10.10.24.0-10.10.24.255,US,0,1690,152
```

**2.** Este evento veio com carimbo `2026-09-03T02:14:07Z` e o analista escreveu no ticket "logon às 02:14, madrugada, suspeito". A empresa fica em São Paulo (UTC−3). Qual é o horário local e a conclusão muda?

```
<134>1 2026-09-03T02:14:07Z dc01.corp.local Microsoft-Windows-Security-Auditing 4624 - - EventID=4624 LogonType=3 TargetUserName=maria.costa TargetDomainName=CORP IpAddress=10.10.31.88 AuthenticationPackageName=Kerberos
```

**3.** Um candidato tem Security+ e nenhuma prática. Ele quer a próxima certificação. Pela tabela de custo-benefício, o que recomendar e por quê?

**4.** Verdadeiro ou falso positivo? Justifique com base no que falta investigar.

```json
{"timestamp":"2026-09-03T15:41:02.117Z","event_type":"alert","src_ip":"10.10.24.57","src_port":51122,"dest_ip":"198.51.100.77","dest_port":53,"proto":"UDP","alert":{"signature":"ET DNS Query for Suspicious .top Domain","category":"Potentially Bad Traffic","severity":2},"dns":{"rrname":"a7f3k9d2b1c8.example.com","rrtype":"TXT"}}
```

**5.** Escreva a busca SPL que responde ao erro nº 10 (evento isolado) para EventID 4625.

<details><summary>Ver gabarito</summary>

**1.** Erro nº 5 — confiar cegamente em reputação. O log é `TRAFFIC` do Palo Alto (formato CSV): origem `10.10.24.57` (RFC1918, host interno), destino `203.0.113.44` porta `443`, aplicação `ssl`, ação `allow`, usuário `jsilva`. O ponto que salta aos olhos não é reputação e sim volume e duração: `824512` bytes totais com `820302` vindos do lado que envia (saída), sessão iniciada às 13:50 e ainda ativa às 14:22 — mais de 30 minutos. Upload muito maior que download em sessão longa é padrão de exfiltração (T1041). Reputação limpa do IP não muda nada, porque infraestrutura recém-criada nasce sem histórico. Próximo passo: ver o `ssl.log` do Zeek para SNI e certificado, e checar o Sysmon EventID 3 no host para saber qual processo abriu a conexão.

**2.** `Z` significa UTC. UTC−3 → **23:14 do dia 02/09**, horário de São Paulo. Não é madrugada, é fim de expediente/noite — muito menos anômalo. A conclusão muda: o argumento "madrugada" cai. Além disso, `LogonType=3` é logon de rede (acesso a compartilhamento ou serviço) com `Kerberos` a partir de `10.10.31.88`, um IP interno — comportamento comum. Erro cometido: nº 6, ignorar fuso. Regra: normalize tudo para UTC e escreva o fuso ao lado.

**3.** **TryHackMe (trilha SOC Level 1)** e depois **LetsDefend**. Motivo: Security+ já cobre a teoria e o filtro de RH; o que reprova o candidato na entrevista técnica é não saber ler um log nem descrever um fluxo de triagem. As trilhas práticas custam pouco, dão exatamente essa vivência e podem ser feitas em paralelo. SC-200 ou Splunk Core viriam depois, decididos pela stack do SOC onde ele for contratado. CCNA e GCIA seriam desperdício de dinheiro nesse momento.

**4.** **Indeterminado com forte suspeita — não feche.** É um alerta Suricata (EVE JSON): consulta DNS do tipo `TXT` para um subdomínio com rótulo aleatório de 12 caracteres (`a7f3k9d2b1c8`). Registro TXT é usado legitimamente por SPF e DKIM, mas consulta de TXT com rótulo aleatório partindo de estação de usuário é assinatura clássica de tunelamento de DNS ou canal de comando e controle (T1071.004). O que falta: (a) contar quantas consultas desse padrão no `dns.log` do Zeek na última hora — uma é ruído, centenas é túnel; (b) verificar o comprimento médio das respostas; (c) correlacionar com Sysmon EventID 22 (`DNSEvent`) no host `10.10.24.57` para saber qual processo consultou. Fechar agora seria o erro nº 1 combinado com o nº 10.

**5.**
```spl
index=windows EventCode=4625
| eval origem=coalesce(Source_Network_Address, IpAddress)
| bin _time span=5m
| stats count AS tentativas, dc(Account_Name) AS contas_distintas, values(Account_Name) AS contas by _time, origem, ComputerName
| where tentativas > 20 OR contas_distintas > 5
| sort - tentativas
```
Linha 1: só falhas de logon. Linha 2: normaliza o nome do campo de IP de origem, que varia por versão. Linha 3: agrupa em janelas de 5 minutos. Linha 4: conta tentativas e contas distintas por janela, origem e destino. Linha 5: separa força bruta (muitas tentativas, uma conta) de password spraying (poucas tentativas, muitas contas). Linha 6: ordena pelo pior caso.

Equivalente em KQL (Sentinel):
```kql
SecurityEvent
| where EventID == 4625                       // falhas de logon
| summarize tentativas = count(),             // volume na janela
            contas = dcount(TargetAccount)    // contas distintas
    by bin(TimeGenerated, 5m), IpAddress, Computer
| where tentativas > 20 or contas > 5         // separa brute force de spraying
| order by tentativas desc
```

</details>

---

## Mini-laboratório — Montando seu próprio SOC de bancada

**Objetivo:** provar, com evidência sua, que você sabe gerar tráfego, capturá-lo, lê-lo e escrever um ticket. Ao final você terá material real para colocar no currículo.

**Pré-requisitos:** VirtualBox instalado, uma máquina virtual Ubuntu Server (2 vCPU, 4 GB), Wireshark na sua máquina física, acesso à internet.

**Passo 1 — Preparar o alvo isolado.** Na VM Ubuntu, com rede em modo *Host-only* mais NAT, instale as ferramentas.
```bash
sudo apt update && sudo apt install -y tcpdump nmap tshark zeek
ip -4 addr show   # anote o IP host-only, algo como 192.168.56.101
```
*O que observar:* o IP host-only é privado (RFC1918) e não sai para a internet. Isso mantém o laboratório contido.

**Passo 2 — Capturar enquanto gera tráfego.** Em um terminal, inicie a captura.
```bash
sudo tcpdump -i any -w /tmp/lab-soc.pcap -s 0 not port 22
```
Em outro terminal, gere tráfego DNS, HTTP e um scan contra a própria VM.
```bash
dig TXT example.com
curl -s -o /dev/null -w "%{http_code}\n" http://example.com/
nmap -sS -p 1-1000 127.0.0.1
```
*O que observar:* o scan deve gerar centenas de pacotes com flag SYN. Encerre a captura com `Ctrl+C` e confira o total.

**Passo 3 — Processar com Zeek.**
```bash
mkdir -p /tmp/zeek-out && cd /tmp/zeek-out
zeek -r /tmp/lab-soc.pcap
ls   # conn.log, dns.log, http.log (e outros, conforme o tráfego)
cat dns.log | zeek-cut ts id.orig_h query qtype_name rcode_name
```
*O que observar:* o `dns.log` deve mostrar a consulta `TXT` para `example.com`. O `conn.log` deve mostrar dezenas de conexões com estado `S0` (SYN enviado, sem resposta) — a assinatura de um scan de portas.

**Passo 4 — Ler no Wireshark.** Copie o `.pcap` para sua máquina e aplique, um de cada vez, estes filtros de exibição.
```
dns.qry.type == 16
http.request
tcp.flags.syn == 1 && tcp.flags.ack == 0
```
*O que observar:* o primeiro isola a consulta TXT; o segundo mostra o `GET` com o cabeçalho `User-Agent` do curl; o terceiro isola só os SYN do scan.

**Passo 5 — Escrever o ticket.** Em cinco linhas, registre: horário em UTC, IP de origem, IP de destino, o que aconteceu, e sua conclusão (verdadeiro positivo simulado) com a evidência que a sustenta.

**Critério de sucesso:** você consegue apontar, no `conn.log`, a linha do scan; no `dns.log`, a consulta TXT; e no Wireshark, o pacote HTTP correspondente — e explicar os três em voz alta, sem consultar este material.

---

## O que um SOC Level 1 realmente precisa saber

- 🟢 Identificar em um log de firewall os cinco campos que resolvem 80% da triagem: horário, IP de origem, IP de destino, porta e ação.
- 🟢 Diferenciar IP privado (RFC1918) de IP público e entender que NAT esconde vários hosts atrás de um único endereço.
- 🟢 Ler o three-way handshake do TCP e reconhecer o padrão de scan (muitos SYN sem ACK de volta).
- 🟢 Traduzir todo horário para UTC antes de montar uma linha do tempo — e escrever o fuso no ticket.
- 🟢 Ler os EventIDs de autenticação do Windows: 4624 (sucesso), 4625 (falha), 4768/4769 (Kerberos), 4776 (NTLM) e 4688 (criação de processo).
- 🟢 Nunca fechar um alerta sem evidência escrita, e nunca segurar um alerta grave por medo de escalar.
- 🟡 Interpretar `conn.log`, `dns.log`, `http.log` e `ssl.log` do Zeek e um alerta Suricata em formato EVE JSON.
- 🟡 Escrever busca básica em SPL (Splunk) e em KQL (Sentinel/Defender) com agregação por janela de tempo.
- 🟡 Correlacionar rede e endpoint: ligar uma conexão de saída ao processo que a abriu, usando Sysmon EventID 1, 3 e 22.
- 🟡 Usar reputação (VirusTotal, AbuseIPDB, urlscan.io) como um voto entre vários, jamais como veredito.
- 🔴 Analisar um `.pcap` no Wireshark seguindo o fluxo TCP e extraindo indicadores de comprometimento.
- 🔴 Reconhecer o rastro em log de ferramentas ofensivas conhecidas (Mimikatz, Rubeus, Impacket, Responder, BloodHound, PsExec) para descrever o comportamento e mapeá-lo ao MITRE ATT&CK.

---

## Resumo em 10 linhas

1. O papel do N1 é triar com método, não adivinhar: toda conclusão precisa de evidência anexada ao ticket.
2. A base obrigatória é rede — OSI, IP, sub-rede, TCP, DNS, HTTP, TLS — porque todo alerta chega como tráfego ou como log de quem viu tráfego.
3. Somada a ela vem a base de identidade Windows: 4624, 4625, 4768, 4769, 4776 e 4688.
4. O nível intermediário é ler Zeek e Suricata, escrever SPL e KQL e correlacionar rede com endpoint via Sysmon.
5. O nível avançado é análise de `.pcap`, caça a ameaças e mapeamento consistente para MITRE ATT&CK.
6. Use o checklist de 21 temas para transformar "não sei" em plano de estudo semanal.
7. A trilha de certificação com melhor retorno para entrar é Network+ (se faltar base), Security+, TryHackMe e LetsDefend.
8. Depois, a stack do seu SOC decide: SC-200 para Microsoft, Splunk Core para Splunk; BTL1, CySA+, CCNA e GIAC vêm mais tarde.
9. Recurso gratuito não falta: Security Onion, Malware-Traffic-Analysis.net, MITRE ATT&CK, The DFIR Report e SANS ISC sustentam anos de estudo.
10. Os erros que reprovam são de disciplina, não de conhecimento: não investigar, não documentar, ignorar fuso, confiar em reputação e olhar evento isolado.



---
