# Módulo 11 — Logs e Investigação

## Por que este módulo importa para o SOC

Um analista de SOC (Security Operations Center, ou Centro de Operações de Segurança) quase nunca vê o ataque acontecer com os próprios olhos. O que ele vê é o **rastro**: linhas de texto gravadas por firewalls, servidores, estações de trabalho e serviços de nuvem. Se você não sabe ler essas linhas, não sabe fazer segurança defensiva. Este módulo ensina de onde vem o log, como ele chega até a sua tela, e como transformar texto bruto em uma decisão: "isso é normal" ou "isso precisa subir para o N2".

**Índice do módulo:**

- Por que existe log, o ciclo do dado e Syslog
- Windows Event Logs e Sysmon
- Logs de firewall, proxy, DNS e nuvem — e como ler um log
- IOCs, Pirâmide da Dor e o fluxo de triagem do N1

---

## Por que existe log

### O que é

Pense na portaria de um prédio. O porteiro anota num caderno: quem entrou, a que horas, para qual apartamento, e quando saiu. Ninguém lê esse caderno todo dia. Mas no dia em que sumiu uma bicicleta da garagem, aquele caderno vira a única fonte de verdade.

**Log** é exatamente isso: o caderno da portaria de cada sistema. É um registro em texto de que **algo aconteceu** em um determinado momento.

**Telemetria** é o conjunto de tudo que um sistema emite sobre si mesmo — logs, métricas (números medidos ao longo do tempo, como uso de CPU) e traces (o caminho de uma requisição). No SOC, quando alguém diz "não temos telemetria desse servidor", quer dizer: aquele servidor é um ponto cego.

### Log, evento, alerta e incidente — a diferença que o N1 precisa saber

Essas quatro palavras são usadas como sinônimos por analistas iniciantes, e isso causa confusão em reunião.

| Termo | O que é | Exemplo |
|---|---|---|
| **Log** | A linha crua gravada pelo sistema | `%ASA-6-302013: Built outbound TCP connection...` |
| **Evento** | O log já normalizado, com campos nomeados | `src_ip=10.10.20.55, dst_port=443, action=allow` |
| **Alerta** | Um evento (ou conjunto deles) que bateu numa regra de detecção | "5 falhas de logon seguidas de 1 sucesso para jsilva" |
| **Incidente** | Um alerta que a triagem confirmou como atividade real e maligna | "Conta de jsilva comprometida por password spraying" |

Milhões de logs viram milhares de eventos, que viram dezenas de alertas, que viram (com sorte) um ou dois incidentes por semana. O trabalho do N1 vive na fronteira entre **alerta** e **incidente**.

**Erro comum de analista júnior:** tratar todo alerta como incidente e abrir chamado de crise. Alerta é hipótese; incidente é hipótese confirmada.

---

## O ciclo do dado — da placa de rede até o seu ticket

### Como funciona, etapa por etapa

1. **Coleta** — um agente (Splunk Universal Forwarder, Elastic Agent, Wazuh) ou um encaminhamento nativo (Syslog, WEF) pega o log na origem e envia para a plataforma. Se falha aqui, tudo depois é cego.
2. **Normalização** — campos diferentes com o mesmo significado viram um nome só. `src`, `srcip`, `source_address` e `ip_origem` viram `source.ip`. É o que permite buscar um endereço IP em 20 produtos diferentes com uma consulta só.
3. **Parsing** — a linha de texto é quebrada em campos. Um log CSV do Palo Alto vira 60 colunas nomeadas. Se o parser está errado, o campo vem vazio e a regra de detecção nunca dispara.
4. **Enriquecimento** — a plataforma acrescenta contexto que o log não tinha: geolocalização do IP, reputação em threat intel, dono do ativo, departamento do usuário.
5. **Correlação** — regras juntam eventos de fontes diferentes. Ex.: falha de autenticação no Active Directory **mais** conexão de saída para país incomum **mais** download grande no proxy, tudo do mesmo host em 10 minutos.
6. **Alerta** — a correlação bateu; um caso é criado na fila.
7. **Triagem (N1)** — você lê, valida, classifica como verdadeiro positivo, falso positivo ou benigno-verdadeiro.
8. **Escalonamento** — o que é real e relevante sobe para o N2/N3 com evidência anexada.

### Retenção, indexação e custo

**Retenção** é por quanto tempo o log fica guardado. Um ataque descoberto hoje pode ter começado há 4 meses; se a retenção é de 30 dias, a investigação morre. Um desenho comum: 90 dias "quentes" (buscáveis em segundos) e 12 meses "frios" (em armazenamento barato, buscáveis em horas).

**Indexação** é o que torna a busca rápida. Indexar tudo custa caro; indexar de menos torna a caça a ameaças inviável.

### Timestamp e fuso horário — o erro clássico

Toda linha de log tem um carimbo de tempo. O problema é que cada equipamento pode gravar em um fuso diferente.

| Fonte | Como grava | Risco |
|---|---|---|
| Firewall FortiGate | Hora local do dispositivo | Diferença de 3h em relação a UTC |
| AWS CloudTrail | Sempre UTC (`Z` no fim) | Nenhum, se você souber |
| Windows Security | Hora local, mas exportado em UTC pelo agente | Dupla conversão errada |

O erro clássico: o analista vê um logon suspeito às **14:05** no Windows e uma conexão de saída às **11:05** no firewall e conclui que não têm relação. Na verdade é o mesmo instante — um está em hora de Brasília (UTC-3) e o outro em UTC. A investigação inteira é descartada por causa de fuso.

**Regra prática do SOC: normalize tudo para UTC no armazenamento e converta para o fuso local só na tela.**

### Por que o NTP importa

**NTP** (Network Time Protocol, ou Protocolo de Tempo de Rede), que roda em **UDP porta 123**, sincroniza o relógio de todos os equipamentos com uma fonte confiável. Sem NTP, um servidor com relógio 8 minutos adiantado quebra a ordem dos eventos: parece que a conexão de saída aconteceu **antes** do logon que a causou. Correlação por janela de tempo (`| transaction maxspan=5m`) simplesmente não fecha.

---

## Syslog — o idioma comum dos equipamentos

### O que é

Syslog é o "cartão-postal padronizado" que praticamente todo equipamento de rede sabe escrever: firewall, switch, roteador, Linux, appliance de proxy. Nasceu no Unix nos anos 80 e virou padrão de fato.

### RFC 3164 vs RFC 5424

| Característica | RFC 3164 (BSD, legado) | RFC 5424 (moderno) |
|---|---|---|
| Ano | 2001 (documenta prática antiga) | 2009 |
| Timestamp | `Mmm dd hh:mm:ss` — **sem ano e sem fuso** | ISO 8601 com fuso e milissegundos |
| Tamanho máximo | 1024 bytes | Sem limite rígido definido |
| Campos estruturados | Não existem | Sim (`STRUCTURED-DATA`) |
| Identificação | Só hostname e tag | Hostname, app-name, procid, msgid |

O RFC 3164 sem ano é uma dor real: em janeiro, um log de 31 de dezembro pode ser indexado no ano errado.

### Severidades — tabela completa (0 a 7)

| Código | Nome | Significado | Uso típico no SOC |
|---|---|---|---|
| 0 | Emergency | Sistema inutilizável | Raro; ação imediata |
| 1 | Alert | Ação imediata necessária | Falha de HA no firewall |
| 2 | Critical | Condição crítica | Disco cheio, hardware |
| 3 | Error | Erro | Falha de serviço, túnel VPN caiu |
| 4 | Warning | Aviso | Certificado prestes a expirar |
| 5 | Notice | Normal, mas significativo | Mudança de configuração |
| 6 | Informational | Informativo | **Tráfego permitido — o volume do SOC** |
| 7 | Debug | Depuração | Ruído; desligar em produção |

Atenção: **quanto MENOR o número, mais grave**. Júnior costuma inverter e filtrar `severity>4` achando que pega o pior.

### Facilities — tabela completa

| Cód. | Facility | Cód. | Facility |
|---|---|---|---|
| 0 | kern (kernel) | 12 | NTP |
| 1 | user | 13 | log audit |
| 2 | mail | 14 | log alert |
| 3 | daemon | 15 | clock daemon (cron) |
| 4 | **auth** (segurança/autorização) | 16 | local0 |
| 5 | syslog (interno) | 17 | local1 |
| 6 | lpr (impressão) | 18 | local2 |
| 7 | news | 19 | local3 |
| 8 | uucp | 20 | local4 |
| 9 | cron | 21 | local5 |
| 10 | **authpriv** (auth privada) | 22 | local6 |
| 11 | ftp | 23 | local7 |

As `localN` (16–23) são as que fabricantes usam para separar fluxos: é comum o firewall mandar tráfego em `local4` e ameaças em `local5`.

### O cálculo do PRI

O campo `PRI` (prioridade) é um número só, calculado assim:

```
PRI = (facility × 8) + severity
```

Exemplo: `authpriv` (10) com severidade `Warning` (4) → `(10 × 8) + 4 = 84`, e aparece como `<84>` no início da mensagem.

### Mensagem RFC 5424 dissecada campo a campo

```
<86>1 2026-09-03T14:22:07.451Z fw-borda-01.corp.local FortiGate 5412 ID47215 [origin ip="10.10.5.1"] Deny outbound to 203.0.113.45:4444 user=jsilva
```

| Parte | Valor | O que significa |
|---|---|---|
| `<86>` | PRI | facility 10 (authpriv) × 8 + severidade 6 (info) |
| `1` | VERSION | Versão 1 = RFC 5424 |
| `2026-09-03T14:22:07.451Z` | TIMESTAMP | ISO 8601; o `Z` indica UTC |
| `fw-borda-01.corp.local` | HOSTNAME | Quem gerou |
| `FortiGate` | APP-NAME | Aplicação/processo |
| `5412` | PROCID | Identificador do processo |
| `ID47215` | MSGID | Tipo de mensagem |
| `[origin ip="10.10.5.1"]` | STRUCTURED-DATA | Pares chave=valor já estruturados |
| `Deny outbound to ...` | MSG | Texto livre |

### Transporte

| Transporte | Porta | Característica |
|---|---|---|
| UDP | **514** | Padrão histórico. Rápido, sem confirmação — **perde pacote em silêncio** |
| TCP | **514** | Entrega confiável, detecta queda de conexão |
| TLS | **6514** | TCP com criptografia (RFC 5425); protege contra leitura e adulteração no caminho |

### Relay e collector

- **Collector** (coletor): o destino final que grava e indexa. Ex.: o servidor do SIEM.
- **Relay**: um intermediário que recebe e reencaminha. Serve para agregar filiais, atravessar firewalls com uma regra só, e converter UDP em TCP/TLS antes da travessia da WAN.

Os dois programas mais comuns em Linux são **rsyslog** (padrão no RHEL/Ubuntu, muito rápido, filas em disco) e **syslog-ng** (configuração mais expressiva, bom para roteamento complexo). Ambos fazem coletor e relay.

### Limitações que o SOC precisa conhecer

1. **UDP perde pacote em silêncio.** Sob rajada, o log da evidência simplesmente não chega, e ninguém é avisado.
2. **A mensagem pode ser forjada.** Syslog puro não autentica a origem: qualquer host da rede pode enviar um pacote UDP 514 dizendo ser `fw-borda-01`. Por isso: TLS mútuo, ACL na porta do coletor, e desconfiança de logs cujo IP de origem não bate com o hostname declarado.
3. **RFC 3164 trunca em 1024 bytes** — URLs longas de proxy chegam cortadas.

### Como aparece nos logs (fluxo real chegando ao SIEM)

```
Sep  3 14:22:07 asa-dmz-01 %ASA-6-302013: Built outbound TCP connection 88214 for outside:203.0.113.45/4444 (203.0.113.45/4444) to inside:10.10.20.55/51022 (198.51.100.7/51022)
Sep  3 14:22:09 srv-linux-04 sshd[2214]: Failed password for invalid user admin from 10.10.20.55 port 44120 ssh2
```

Campos do `%ASA-6-302013`: `%ASA` = produto, `6` = severidade informational, `302013` = ID da mensagem (conexão TCP estabelecida). Depois: interface e IP de destino (`outside:203.0.113.45/4444`), interface e IP de origem (`inside:10.10.20.55/51022`) e o IP traduzido por NAT (`198.51.100.7`).

**O que o SOC N1 observa:** saída para a porta **4444** é clássico de shell reverso; combinada, 2 segundos depois, com tentativa de SSH interna a partir do mesmo host, indica movimentação lateral (MITRE ATT&CK **T1021.004**).

### Consultas de referência

```spl
index=syslog sourcetype=cisco:asa
| eval severity=mvindex(split(msg_id,"-"),1)   /* extrai a severidade do %ASA-x- */
| where dest_port IN (4444, 5555, 1337)        /* portas comuns de shell reverso */
| stats count values(dest_ip) by src_ip        /* agrupa por host de origem */
```

```kql
Syslog
| where TimeGenerated > ago(24h)               // janela de 24 horas
| where Facility == "authpriv" and SeverityLevel <= 4   // Warning ou pior
| summarize Total=count() by Computer, SyslogMessage    // ranking por host
| order by Total desc
```

---

### Exercícios — Por que existe log, o ciclo do dado e Syslog

1. Um log chega marcado `<134>`. Qual é a facility e qual é a severidade?
2. O Windows do host `WS-JSILVA-01` registra um logon suspeito às `14:05` (hora de Brasília, UTC-3). O firewall registra uma conexão de saída para `203.0.113.45` às `17:06` em UTC. São o mesmo evento? Justifique.
3. Leia o par de logs abaixo. Este alerta é verdadeiro ou falso positivo? Qual o próximo passo?

```
<86>1 2026-09-03T02:14:33.010Z fw-borda-01.corp.local FortiGate 4110 ID20 [origin ip="10.10.5.1"] action=deny srcip=10.10.30.71 dstip=203.0.113.45 dstport=4444 service=tcp/4444 user=svc_backup
Sep  3 02:14:35 srv-app-02 sshd[8891]: Accepted password for svc_backup from 10.10.30.71 port 40122 ssh2
```

4. Um analista propõe passar todo o syslog da matriz para UDP 514 "porque é mais rápido e não trava". Cite dois riscos concretos dessa decisão para a investigação.
5. Explique, em uma frase para o gestor, por que um servidor sem NTP sincronizado inutiliza uma regra de correlação de 5 minutos.

<details><summary>Ver gabarito</summary>

**1.** `134 ÷ 8 = 16`, resto `6`. Facility **16 = local0**; severidade **6 = Informational**. Ou seja: mensagem informativa de um fluxo que o fabricante mapeou em `local0` — tipicamente tráfego permitido, alto volume, baixo valor isolado.

**2.** Sim, são o mesmo instante aproximado. `14:05` em UTC-3 equivale a `17:05` UTC; o firewall registrou `17:06` UTC, ou seja, **1 minuto depois** do logon. A correlação é válida e reforça a hipótese: alguém entrou na estação e imediatamente abriu conexão externa. Descartar por "diferença de 3 horas" é o erro clássico de fuso.

**3.** É **verdadeiro positivo provável**, e o detalhe importante é que o alerta tem duas metades contraditórias. O firewall **negou** a saída para a porta 4444 (bom), mas dois segundos depois o `svc_backup` fez logon SSH **bem-sucedido** no `srv-app-02` a partir do mesmo host. Três agravantes: (a) `svc_backup` é conta de serviço e não deveria fazer logon interativo; (b) horário 02:14 fora do expediente; (c) autenticação por senha, não por chave. Próximo passo: isolar logicamente `10.10.30.71`, buscar todas as autenticações de `svc_backup` nas últimas 72 horas, verificar se a senha da conta de serviço vazou e checar processos filhos criados após o logon no `srv-app-02` (Sysmon Event ID 1). Escalar para o N2.

**4.** (a) **Perda silenciosa de evidência**: sob rajada de tráfego, pacotes UDP são descartados sem retransmissão nem aviso — a linha que provaria o ataque some e o SIEM não acusa lacuna. (b) **Forja de origem**: sem sessão nem autenticação, qualquer máquina da rede pode enviar mensagens se passando pelo firewall de borda, poluindo a linha do tempo ou encobrindo o ataque real. Bônus: em RFC 3164 há truncamento em 1024 bytes.

**5.** "Se o relógio do servidor está fora de sincronia, os eventos entram na plataforma com a hora errada — a regra procura fatos que aconteceram juntos dentro de 5 minutos e nunca os encontra, porque um deles foi carimbado fora da janela."

</details>


## Windows Event Logs — o diário de bordo do sistema operacional

Imagine um prédio comercial com várias portarias. Uma portaria anota quem entrou e saiu (crachá, hora, porta usada). Outra anota quando o elevador quebrou. Outra anota quando um inquilino novo mudou para o prédio. São livros diferentes, cada um com um assunto. O Windows funciona igual: ele não guarda tudo num arquivo só, guarda em **canais** (channels), e cada canal tem um assunto.

**O que é:** o Event Log do Windows é o sistema de registro nativo do sistema operacional. Cada acontecimento vira um **evento** com número, hora e dados estruturados, guardado em arquivos `.evtx` dentro de `C:\Windows\System32\winevt\Logs\`.

**Como funciona:** um componente do Windows (chamado **Provider**, ou provedor) publica o evento; o serviço `EventLog` grava no canal certo. Cada canal tem tamanho máximo — quando enche, os eventos mais antigos são apagados. Por isso o SOC envia (encaminha) tudo para um SIEM (Security Information and Event Management — a plataforma central de logs).

### Os canais clássicos

| Canal | O que guarda | Uso no SOC |
|---|---|---|
| **Security** | Logon, logoff, Kerberos, criação de processo, mudanças em contas e grupos | O mais importante. Base de quase toda investigação |
| **System** | Serviços, drivers, desligamentos, erros de hardware | Serviço criado por atacante, driver suspeito |
| **Application** | Erros de programas instalados | Crash de agente de segurança (pode ser sabotagem) |
| **Setup** | Instalação do Windows e de atualizações | Raro no dia a dia |
| **ForwardedEvents** | Eventos vindos de OUTRAS máquinas via WEF (Windows Event Forwarding) | Coletor central sem agente |

### Canais de "Applications and Services" que o SOC precisa conhecer

Estes ficam em `Applications and Services Logs → Microsoft → Windows → ...` e são frequentemente esquecidos por analistas juniores.

| Canal (nome completo) | Por que interessa |
|---|---|
| `Microsoft-Windows-PowerShell/Operational` | Evento **4104** grava o bloco de script executado. Detecta PowerShell ofuscado |
| `Microsoft-Windows-Sysmon/Operational` | Sysmon (detalhado adiante) — o canal mais rico que existe |
| `Microsoft-Windows-TaskScheduler/Operational` | Tarefa agendada criada (persistência, MITRE **T1053.005**) |
| `Microsoft-Windows-WMI-Activity/Operational` | Consultas e assinaturas WMI (persistência **T1546.003**, execução remota) |
| `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` | Sessões RDP (Remote Desktop Protocol, porta **3389**) — evento **21** conexão, **25** reconexão |
| `Microsoft-Windows-DNS-Server/Analytical` | Em servidor DNS: cada consulta resolvida. Achado de ouro para domínio malicioso |

**Erro comum de analista júnior:** procurar tudo no canal Security. Um PowerShell malicioso pode não gerar nada relevante no Security e estar inteiro no canal PowerShell/Operational.

## Anatomia de um evento

Todo evento do Windows é, por baixo, um XML. Ver o XML uma vez ensina mais do que dez telas do Event Viewer.

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"
              Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4625</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Channel>Security</Channel>
    <Computer>SRV-FILES01.corp.local</Computer>
    <TimeCreated SystemTime="2026-09-03T14:22:07.4471120Z" />
    <EventRecordID>8842119</EventRecordID>
    <Security />
  </System>
  <EventData>
    <Data Name="TargetUserName">admin.rodrigo</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="Status">0xc000006d</Data>
    <Data Name="SubStatus">0xc000006a</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="IpAddress">10.10.40.55</Data>
    <Data Name="WorkstationName">WKS-VENDAS12</Data>
    <Data Name="ProcessName">-</Data>
  </EventData>
</Event>
```

Lendo campo a campo:

| Campo | Significado |
|---|---|
| **Provider** | Quem publicou. Aqui, a auditoria de segurança do Windows |
| **EventID** | O número do tipo de evento. **4625** = falha de logon |
| **Level** | Gravidade: 1 Critical, 2 Error, 3 Warning, 4 Information, 0 undefined (o Security usa 0) |
| **Channel** | Em qual livro foi gravado |
| **Computer** | Máquina que gerou — não confunda com quem tentou o acesso |
| **TimeCreated** | Hora em **UTC**. Fuso errado destrói uma timeline |
| **EventRecordID** | Número sequencial. Salto grande = log pode ter sido limpo |
| **EventData** | O conteúdo específico do EventID |

No exemplo: `SubStatus 0xc000006a` = senha errada (a conta existe). `LogonType 3` = logon de rede (compartilhamento, SMB na porta **445**). Origem `10.10.40.55` tentando `admin.rodrigo`.

**O que o SOC N1 observa:** um 4625 isolado é digitação errada. Trinta 4625 em dois minutos, do mesmo IP, contra usuários diferentes, é **password spraying** (MITRE **T1110.003**). Se depois vier um **4624** de sucesso do mesmo IP, escale imediatamente.

**Erro comum:** confundir `0xc000006a` (senha errada) com `0xc0000064` (usuário inexistente). O segundo, em massa, indica enumeração de contas — atacante ainda descobrindo nomes.

### Ferramentas: Event Viewer, wevtutil e Get-WinEvent

```powershell
# Últimos 20 logons com falha, já filtrado no motor do log (rápido)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-2)} -MaxEvents 20

# Criação de processo (4688) contendo powershell na linha de comando
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match 'powershell' } | Select-Object -First 10 TimeCreated, Message

# XPath: 4625 apenas do usuário admin.rodrigo
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4625]] and *[EventData[Data[@Name='TargetUserName']='admin.rodrigo']]"

# Linha de comando nativa (funciona sem PowerShell)
wevtutil qe Security /q:"*[System[(EventID=4624)]]" /c:5 /f:text /rd:true
```

**Erro comum:** usar `Get-WinEvent -LogName Security | Where-Object {...}` sem FilterHashtable. Isso lê milhões de eventos para a memória e trava a máquina. Filtre sempre no `-FilterHashtable` ou `-FilterXPath`.

## Sysmon — a câmera de segurança que faltava

**O que é:** o **Sysmon** (System Monitor) é uma ferramenta gratuita da Microsoft (suíte Sysinternals) que se instala como driver e serviço e grava, no canal `Microsoft-Windows-Sysmon/Operational`, detalhes que o Windows padrão não registra.

**Analogia:** o Event Log é a portaria anotando quem entrou. O Sysmon é a câmera com áudio: mostra quem entrou, com quem falou, o que carregava na mão e para onde ligou.

**Por que instalar:** sem Sysmon, você vê "processo iniciado". Com Sysmon, você vê a **linha de comando completa**, o **hash** do arquivo, o **processo pai** e as **conexões de rede por processo**.

### EventIDs essenciais

| ID | Evento | O que entrega |
|---|---|---|
| **1** | Process Create | CommandLine, Hashes, ParentImage, User, ProcessGuid |
| **3** | Network Connection | Processo + IP/porta origem e destino |
| **5** | Process Terminated | Fim do processo — fecha a janela de atividade |
| **7** | Image Loaded (DLL) | DLL não assinada carregada por processo legítimo |
| **8** | CreateRemoteThread | Injeção de código entre processos (**T1055**) |
| **10** | ProcessAccess | Acesso à memória de outro processo — clássico de dump do LSASS (**T1003.001**) |
| **11** | FileCreate | Arquivo criado, com caminho e hora |
| **12/13/14** | Registry (create/delete, set value, rename) | Persistência em chaves Run (**T1547.001**) |
| **22** | DNS Query | Qual processo consultou qual domínio |
| **23** | FileDelete (arquivado) | Apagamento de rastro, com cópia do arquivo |
| **25** | Process Tampering | Process hollowing / imagem alterada em memória |

```
EventID: 1
UtcTime: 2026-09-03 14:31:02.118
ProcessGuid: {a1b2c3d4-1111-6650-1c00-000000000900}
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -nop -w hidden -enc SQBFAFgA...
User: CORP\jsilva
Hashes: SHA256=9F914D42706FE215501044ACD85A32D58AAEF1419D404FDDFA5D3B48F66CCD9F
ParentImage: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
ParentCommandLine: "WINWORD.EXE" /n "C:\Users\jsilva\Downloads\fatura.docm"
```

```
EventID: 3
UtcTime: 2026-09-03 14:31:04.902
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: CORP\jsilva
Protocol: tcp
SourceIp: 10.10.40.55
DestinationIp: 203.0.113.77
DestinationPort: 443
DestinationHostname: cdn-update.example.com
```

```
EventID: 22
UtcTime: 2026-09-03 14:31:04.410
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
QueryName: cdn-update.example.com
QueryResults: type: 5 203.0.113.77;
```

**O que o SOC N1 observa:** Word como processo pai do PowerShell é anormal em qualquer empresa. `-nop -w hidden -enc` (sem perfil, janela escondida, comando codificado) é padrão de execução escondida. Junte 1 + 22 + 3 e você tem a história: macro no documento → PowerShell → resolveu domínio → conectou em IP externo.

**Erro comum:** tratar o evento 3 sozinho. Conexão para porta 443 é normal; o que torna suspeito é **qual processo** fez a conexão.

```sql
-- SPL (Splunk): PowerShell filho de Office
index=win sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
| search ParentImage IN ("*WINWORD.EXE","*EXCEL.EXE") Image="*powershell.exe"
| table _time, Computer, User, ParentCommandLine, CommandLine
```

```kusto
// KQL (Defender/Sentinel): processo acessando memória do LSASS
DeviceEvents
| where ActionType == "OpenProcessApiCall"          // corresponde ao Sysmon 10
| where FileName =~ "lsass.exe"                      // alvo típico de dump de credenciais
| where InitiatingProcessFileName !in~ ("MsMpEng.exe","csrss.exe")  // exclui legítimos
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

Ferramentas como Mimikatz, Rubeus e Impacket deixam rastro exatamente aí: Sysmon 10 sobre o LSASS, 4688/Sysmon 1 com nomes de binário renomeados, e 4769 (tickets Kerberos) em volume anormal. O N1 não precisa saber usá-las — precisa reconhecer a assinatura no log.

### Exercícios — Windows Event Logs e Sysmon

1. Um evento 4625 tem `LogonType 3`, `SubStatus 0xc0000064` e `IpAddress 10.10.40.55`, repetido 47 vezes em 90 segundos contra 47 nomes de usuário diferentes. Qual é a técnica e por que o SubStatus importa?
2. Você recebe um alerta de Sysmon EventID 1: `Image: C:\Users\maria.costa\AppData\Local\Temp\svchost.exe`, `ParentImage: C:\Program Files\7-Zip\7zFM.exe`. Verdadeiro ou falso positivo? Justifique.
3. Um analista quer todos os 4624 das últimas 24 horas e escreve `Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4624}`. O que há de errado e qual é a versão correta?
4. Sysmon 22 mostra `QueryName: a7f3k9x2m.example.com` consultado por `notepad.exe`. Qual o próximo passo da investigação?
5. No canal Security, o EventRecordID salta de 8842119 para 8842120, mas os horários pulam de 03:10 para 09:47. O que isso pode indicar e qual EventID você procuraria?

<details><summary>Ver gabarito</summary>

**1.** Password spraying / enumeração de contas (MITRE T1110.003). `0xc0000064` significa "usuário não existe" — 47 nomes diferentes falhando por inexistência indica que o atacante está **descobrindo nomes válidos**, não testando senhas. Se o SubStatus fosse `0xc000006a` (senha errada), as contas existiriam e o risco de sucesso seria maior. Ação: isolar/investigar 10.10.40.55 e verificar se houve algum 4624 subsequente da mesma origem.

**2.** Fortemente suspeito. `svchost.exe` é um binário legítimo do Windows que vive em `C:\Windows\System32`, nunca em `AppData\Local\Temp`. É masquerading (MITRE T1036.005). O processo pai ser o 7-Zip indica que veio de um arquivo compactado aberto pela usuária — provável anexo de phishing. Próximo passo: pegar o hash do evento 1, checar reputação, procurar Sysmon 3 e 22 do mesmo ProcessGuid.

**3.** O pipe traz **todos** os eventos do canal Security para a memória antes de filtrar — em um controlador de domínio isso significa milhões de registros e travamento. Correto: `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-1)}` — o filtro é aplicado dentro do motor do Event Log.

**4.** Duas anomalias: o Bloco de Notas não faz consultas DNS de rede por conta própria, e o nome do domínio tem cara de gerado por algoritmo (DGA — Domain Generation Algorithm). Próximo passo: correlacionar pelo ProcessGuid os eventos Sysmon 1 (linha de comando e processo pai do notepad.exe) e 3 (para qual IP conectou), depois checar no proxy/firewall se a conexão foi permitida e se outras máquinas resolveram o mesmo domínio.

**5.** Números de registro contínuos com um buraco de horas indicam que o log foi **limpo** ou que a coleta parou. Procure o EventID **1102** (log de auditoria de segurança apagado, MITRE T1070.001) e, no canal System, o **104** (limpeza de outro canal). Verifique também se o agente de coleta ficou fora do ar no período — as duas hipóteses precisam ser descartadas antes de concluir sabotagem.

</details>


## Logs de firewall, proxy, DNS e nuvem — e como ler um log

Já vimos por que o log existe e como ele viaja até o SIEM, e já vimos o mundo Windows. Agora vamos aos logs que o analista de SOC (Security Operations Center, o centro de operações de segurança) abre dezenas de vezes por dia: firewall, proxy, DNS, e-mail, VPN e nuvem. No fim, um método simples para ler qualquer linha de log, mesmo uma que você nunca viu.

### Log de firewall — a portaria do condomínio

**O que é.** Imagine a portaria de um condomínio. O porteiro anota num caderno: quem chegou, de onde veio, para qual apartamento ia, a que horas, e se deixou entrar ou barrou. O log de firewall é esse caderno. Cada linha é uma **sessão** (uma conversa de rede) que passou — ou tentou passar — pelo equipamento.

**Como funciona.** O firewall compara cada pacote com uma lista de regras, de cima para baixo. Assim que uma regra bate, ele aplica a ação (permitir ou negar) e escreve a linha.

#### Campos comuns de um log de firewall

| Campo | O que é | O que ele entrega ao analista |
|---|---|---|
| Timestamp | Data e hora do evento | Ancora o evento na linha do tempo; permite correlacionar com outras fontes |
| IP de origem (src) | Quem iniciou a conversa | Identifica a máquina/pessoa suspeita |
| IP de destino (dst) | Com quem falou | Permite consultar reputação do destino |
| Porta de origem | Porta efêmera do cliente (1024–65535) | Serve para casar a mesma sessão em fontes diferentes |
| Porta de destino | Serviço procurado (443, 22, 3389...) | Diz **o que** ele quis fazer |
| Protocolo | TCP, UDP, ICMP | Muda a leitura: UDP não tem handshake |
| Ação | allow, deny, drop, reset | Diz se houve risco real ou tentativa barrada |
| Bytes enviados/recebidos | Volume de dados | Detecta exfiltração e canais de comando e controle |
| Zona origem/destino | Trust, DMZ, Untrust | Diz se o tráfego cruzou fronteira de confiança |
| Regra (rule) | Nome da política aplicada | Mostra *por que* passou; útil para pedir bloqueio |
| Usuário | Login associado ao IP | Transforma "um IP" em "uma pessoa" |
| Duração / sessão | Tempo e ID da sessão | Sessões longuíssimas = túnel ou C2 |

**Exemplo prático.** A estação `10.10.20.55` do usuário `jsilva` abre uma conexão HTTPS para `203.0.113.44`.

**Como aparece nos logs (Palo Alto, CSV TRAFFIC):**

```
1,2026/09/03 14:22:07,001801099999,TRAFFIC,end,2561,2026/09/03 14:22:07,10.10.20.55,203.0.113.44,0.0.0.0,0.0.0.0,Regra-Saida-Internet,corp\jsilva,,ssl,vsys1,Trust,Untrust,ethernet1/2,ethernet1/1,Log-Forward,2026/09/03 14:22:07,84213,1,51422,443,0,0,0x400053,tcp,allow,148920,4210,144710,182,2026/09/03 14:18:31,216
```

Lendo os campos que importam: `TRAFFIC` (tipo), origem `10.10.20.55`, destino `203.0.113.44`, regra `Regra-Saida-Internet`, usuário `corp\jsilva`, aplicação `ssl`, zonas `Trust → Untrust`, portas `51422 → 443`, protocolo `tcp`, ação `allow`, bytes totais `148920`, bytes enviados `4210`, bytes recebidos `144710`, duração `216` segundos.

**Como aparece nos logs (FortiGate, key=value):**

```
date=2026-09-03 time=14:31:02 devname="FGT-BR-01" type="traffic" subtype="forward" srcip=10.10.20.55 srcport=52880 dstip=198.51.100.77 dstport=445 proto=6 action="deny" policyid=12 srcintf="port3" dstintf="port1" service="SMB" sentbyte=0 rcvdbyte=0 user="jsilva" msg="Bloqueado por politica"
```

**Como aparece nos logs (Cisco ASA):**

```
%ASA-6-302013: Built outbound TCP connection 88213 for outside:203.0.113.44/443 (203.0.113.44/443) to inside:10.10.20.55/51422 (192.0.2.10/51422)
```

**O que o SOC N1 observa.** Normal: estação interna falando 443/TCP com destinos conhecidos, bytes recebidos maiores que enviados. Suspeito: `deny` repetido para a porta 445 saindo para a internet (T1021.002), muitos destinos diferentes na mesma porta em poucos segundos (varredura, T1046), ou sessão com bytes **enviados** muito maiores que os recebidos (possível exfiltração, T1041).

**Erro comum de analista júnior.** Ver `action=deny` e fechar o chamado como "bloqueado, tudo certo". O bloqueio protegeu a rede, mas **a máquina interna que tentou** continua possivelmente comprometida. Investigue a origem, não o destino.

### Log de proxy — o fiscal da navegação

**O que é.** O proxy é o intermediário entre o navegador e a internet: nada sai direto, tudo passa por ele. É como um despachante que leva todos os pedidos e anota cada um.

| Campo | O que entrega |
|---|---|
| Usuário | Quem navegou (autenticado, não só IP) |
| URL completa | O recurso exato acessado |
| Categoria | Classificação do site (notícias, malware, recém-registrado) |
| Método HTTP | GET (busca), POST (envia dados) — POST grande é sinal de exfiltração |
| Status | 200 ok, 403 bloqueado, 302 redirecionado, 407 falta autenticação |
| User-Agent | Qual programa navegou; agente estranho = script/malware |
| Bytes de subida | Quanto **saiu** da empresa |
| Bytes de descida | Quanto **entrou** |
| Referer | De onde o clique veio (útil em phishing) |
| Ação | allowed, blocked, coached |

**Squid access.log:**

```
1756908672.431   1842 10.10.20.55 TCP_MISS/200 148920 GET http://cdn.example.com/atualiza.exe jsilva DIRECT/203.0.113.44 application/octet-stream
```

**Netskope (evento de tráfego web):**

```
timestamp=2026-09-03T14:44:11Z user=maria.costa@empresa-exemplo.com.br srcip=10.10.31.22 url=hxxps://arquivos.example.com/upload category="Cloud Storage" http_method=POST response_code=200 useragent="python-requests/2.31.0" req_bytes=734512890 resp_bytes=1204 referer="-" action=allow
```

**Zscaler NSS:**

```
2026-09-03 14:45:02 user=jsilva@empresa-exemplo.com.br url=news.example.com/index.html urlcategory=News action=Allowed reqsize=812 respsize=44210 useragent=Mozilla/5.0 statuscode=200 referer=https://intranet.corp.local/
```

**O que o SOC N1 observa.** Suspeito: `User-Agent` de biblioteca (`python-requests`, `curl`) num equipamento de escritório; POST de 734 MB para armazenamento em nuvem; categoria "Newly Registered Domain". **Erro comum:** confiar no User-Agent como identidade — ele é texto livre e pode ser qualquer coisa; use-o como pista, nunca como prova.

### Log de DNS — a lista telefônica

**O que é.** DNS (Domain Name System, sistema de nomes de domínio) traduz nome em número: `www.example.com` vira `203.0.113.10`. O log de DNS registra a pergunta antes mesmo de a conexão existir — por isso é a fonte mais precoce de detecção.

| Campo | O que entrega |
|---|---|
| Cliente que perguntou | Máquina de origem |
| Query (nome) | O domínio procurado |
| Tipo (A, AAAA, TXT, MX, NULL) | TXT/NULL em volume = túnel DNS (T1071.004) |
| Resposta / answers | IP retornado |
| rcode | NOERROR, NXDOMAIN (não existe), SERVFAIL |

**Zeek dns.log:**

```
1756909021.554  CjX9tk2h  10.10.20.55  53914  10.10.0.5  53  udp  41022  0.031  a7f3b91c2e.cdn-update.example.com  1  C_INTERNET  16  TXT  0  NOERROR  F  F  T  T  0  -  -  F
```

Cliente `10.10.20.55` perguntou por `a7f3b91c2e.cdn-update.example.com`, tipo **TXT**, resposta `NOERROR`. Subdomínio aleatório e longo + TXT repetido = suspeita de túnel DNS.

**Sysmon Event ID 22 (DNS query):** registra a consulta **junto com o processo** que a fez. Se `Image: C:\Users\jsilva\AppData\Local\Temp\atualiza.exe` consultou esse domínio, deixou de ser suspeita e virou investigação.

### E-mail, VPN e nuvem

- **Gateway de e-mail:** `2026-09-03T09:12:44Z sender=cobranca@fatura-example.com recipient=maria.costa@empresa-exemplo.com.br subject="Fatura em atraso" verdict=QUARANTINE spf=fail dkim=none attachment="fatura.html"`
- **VPN (Cisco ASA):** `%ASA-6-113039: Group <SSL-Corp> User <jsilva> IP <198.51.100.90> AnyConnect parent session started.`
- **AWS CloudTrail:** `{"eventTime":"2026-09-03T15:02:11Z","eventName":"CreateAccessKey","userIdentity":{"userName":"svc_backup"},"sourceIPAddress":"203.0.113.201","awsRegion":"us-east-1","eventSource":"iam.amazonaws.com"}`
- **Azure AD (Microsoft Entra ID) Sign-in log:** `{"userPrincipalName":"admin.rodrigo@empresa-exemplo.com.br","ipAddress":"192.0.2.88","resultType":"50126","status":"Invalid username or password","clientAppUsed":"Other clients","location":"BR"}`
- **Microsoft 365 Unified Audit Log:** `{"CreationTime":"2026-09-03T15:20:03","Operation":"New-InboxRule","UserId":"maria.costa@empresa-exemplo.com.br","Parameters":[{"Name":"MoveToFolder","Value":"RSS Feeds"},{"Name":"DeleteMessage","Value":"True"}]}` — regra que apaga mensagens é sinal clássico de conta comprometida (T1564.008).

### Como ler um log — método em 4 passos

1. **Identifique a fonte.** Firewall? Proxy? Nuvem? Sem isso você não sabe o significado dos campos.
2. **Identifique o timestamp e o fuso.** UTC ou horário local? Uma diferença de 3 horas destrói uma linha do tempo.
3. **Encontre sujeito (quem), objeto (o que), ação e resultado.** Quase todo log responde a essas quatro perguntas.
4. **Traduza para uma frase em português.** Se você não consegue escrever a frase, ainda não entendeu a linha.

### Dissecação guiada

**1) Palo Alto TRAFFIC (acima).** Fonte: firewall. Hora: 03/09/2026 14:22:07. Quem: `jsilva` em `10.10.20.55`. O quê: `203.0.113.44:443` via `ssl`. Resultado: `allow`, 4.210 bytes subiram e 144.710 desceram em 216 s.
→ *"Às 14:22, o usuário jsilva acessou por HTTPS o servidor 203.0.113.44 e a conexão foi permitida, com download maior que o upload — perfil de navegação normal."*

**2) FortiGate deny.** → *"Às 14:31, a estação de jsilva tentou abrir SMB (porta 445) para um endereço público e o firewall bloqueou pela política 12; nenhum byte trafegou."*

**3) Cisco ASA 302013.** → *"O ASA criou uma conexão TCP de saída da máquina interna 10.10.20.55 (traduzida para 192.0.2.10) até 203.0.113.44 na porta 443."*

**4) Squid.** → *"jsilva baixou por HTTP o arquivo executável atualiza.exe de cdn.example.com, com 148.920 bytes e resposta 200; o proxy permitiu."*

**5) Netskope.** → *"maria.costa enviou 734 MB para um site de armazenamento em nuvem usando a biblioteca python-requests, e o envio foi permitido."*

**6) Zeek dns.log.** → *"A máquina 10.10.20.55 consultou um subdomínio aleatório de cdn-update.example.com pedindo registro TXT, e o servidor respondeu com sucesso."*

**7) Azure AD 50126.** → *"admin.rodrigo teve uma tentativa de login recusada por senha inválida, vinda de 192.0.2.88, usando cliente legado (Other clients)."*

**8) CloudTrail.** → *"A identidade svc_backup criou uma nova chave de acesso na AWS a partir de 203.0.113.201."*

### Consultas rápidas

```spl
index=firewall action=allow          | rem: apenas sessões permitidas
| stats sum(bytes_out) AS saida BY src_ip, dest_ip   | rem: soma o que saiu por par de IPs
| where saida > 500000000            | rem: acima de 500 MB, investigar exfiltração
| sort - saida
```

```kql
SigninLogs                                  // logins do Entra ID
| where ResultType == "50126"               // senha inválida
| summarize Tentativas = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 10m)
| where Tentativas > 15                     // rajada = possível password spraying (T1110.003)
```

### Exercicios — Logs de firewall, proxy, DNS e nuvem — e como ler um log

1. No log Palo Alto, quantos bytes **saíram** da empresa e quantos **entraram**? Esse perfil é mais compatível com download ou com exfiltração?
2. Traduza para uma frase em português a linha do gateway de e-mail e diga se o SOC precisa agir.
3. O log FortiGate mostra `action="deny"` e `sentbyte=0`. Um colega quer fechar como falso positivo. Ele está certo?
4. No log Netskope, cite **dois** indicadores de suspeita e qual seria o próximo passo da investigação.
5. Um alerta dispara com o log Zeek dns.log. Qual fonte adicional você consultaria para saber **qual programa** fez a consulta?

<details><summary>Ver gabarito</summary>

1. Saíram 4.210 bytes (`bytes_sent`) e entraram 144.710 bytes (`bytes_received`). Muito mais desceu do que subiu, perfil típico de navegação/download. Exfiltração teria o padrão invertido: upload grande, download pequeno.

2. *"Às 09:12 UTC, um remetente do domínio fatura-example.com enviou para maria.costa uma mensagem com assunto 'Fatura em atraso' e um anexo HTML; o gateway colocou em quarentena, e as verificações SPF falharam e DKIM não existia."* Sim, o SOC deve agir: mesmo em quarentena, vale checar se outras caixas receberam a mesma campanha e se alguém liberou a mensagem. Anexo HTML é vetor comum de phishing de credenciais (T1566.001).

3. Não. O bloqueio protegeu a saída, mas a pergunta importante é **por que uma estação de escritório tentou SMB (445/TCP) para a internet**. Isso é comportamento de malware ou de ferramenta de movimentação lateral/roubo de hash. Próximo passo: verificar o processo de origem na máquina (Sysmon Event ID 3, conexão de rede) e checar se houve repetição.

4. (a) `useragent="python-requests/2.31.0"` — biblioteca de script num equipamento de usuário final; (b) `req_bytes=734512890` — cerca de 734 MB de **upload** para armazenamento em nuvem. Próximo passo: identificar o processo e o usuário na estação `10.10.31.22`, verificar se existe automação legítima aprovada e, em paralelo, correlacionar com o firewall para ver se houve mais destinos. Se não houver justificativa, tratar como possível exfiltração (T1567.002) e escalar para o N2.

5. O Sysmon **Event ID 22 (DNS query)**, que registra a consulta junto com o campo `Image` (caminho do processo). O log do servidor DNS mostra só o IP do cliente; o Sysmon mostra qual binário perguntou, o que separa navegador legítimo de executável em pasta temporária.

</details>


## IOCs — as impressões digitais do atacante

Imagine um roubo em um prédio. O ladrão deixa para trás: uma digital no vidro, a placa do carro de fuga, o número do celular pré-pago que usou e a marca do pé-de-cabra. Cada um desses vestígios ajuda a polícia a identificar o mesmo criminoso em outro roubo.

**O que é.** IOC (Indicator of Compromise, ou Indicador de Comprometimento) é um dado técnico e objetivo que sugere que uma máquina ou conta foi comprometida. É um "fato" que você pode procurar nos logs.

**Como funciona.** Alguém analisa um incidente, extrai os vestígios técnicos e publica. Seu SIEM (Security Information and Event Management — a plataforma que junta e correlaciona todos os logs, vista nos trechos anteriores deste módulo) passa a comparar cada evento novo contra essa lista.

### Tipos de IOC

| Tipo | Exemplo fictício | Onde aparece |
|---|---|---|
| Hash MD5 | `d41d8cd98f00b204e9800998ecf8427e` | Sysmon Event ID 1, antivírus |
| Hash SHA1 | `da39a3ee5e6b4b0d3255bfef95601890afd80709` | EDR, VirusTotal |
| Hash SHA256 | `e3b0c44298fc1c149afbf4c8996fb924...b855` | Sysmon 1, Defender |
| Endereço IP | `203.0.113.45` | Firewall, proxy, Zeek `conn.log` |
| Domínio | `atualizacao-fatura.example.com` | DNS, proxy |
| URL | `hxxp://203.0.113.45/adm/pn.bin` | Proxy, e-mail gateway |
| E-mail remetente | `cobranca@empresa-exemplo.com.br` | Gateway de e-mail |
| Nome de arquivo | `fatura_setembro.pdf.exe` | Sysmon 11, EDR |
| Chave de registro | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater` | Sysmon 13 |
| Mutex | `Global\jK28xQ1` | EDR, sandbox |
| Certificado TLS | Serial / thumbprint SHA1 | Zeek `ssl.log`, `x509.log` |
| JA3 / JA3S | `a0e9f5d64349fb13191bc781f81f42e1` | Zeek `ssl.log`, Suricata |

> JA3 é uma "impressão digital" do jeito que um programa inicia uma conexão criptografada (TLS). Dois programas diferentes negociam de formas diferentes — mesmo sem abrir o conteúdo, o jeito de cumprimentar denuncia quem está falando.

**Como aparece nos logs.** Sysmon Event ID 3 (conexão de rede) com destino em um IP marcado como malicioso:

```
<Event><System><EventID>3</EventID></System><EventData>
 <Data Name="UtcTime">2026-09-03 14:02:11.884</Data>
 <Data Name="Image">C:\Users\jsilva\AppData\Local\Temp\fatura.exe</Data>
 <Data Name="User">CORP\jsilva</Data>
 <Data Name="Protocol">tcp</Data>
 <Data Name="SourceIp">10.10.24.57</Data>
 <Data Name="DestinationIp">203.0.113.45</Data>
 <Data Name="DestinationPort">443</Data>
</EventData></Event>
```

Campos: `Image` é o programa que abriu a conexão (rodando de `Temp` — já é ruim); `User` é a conta; `SourceIp` a máquina interna; `DestinationIp`/`DestinationPort` o destino externo.

**O que o N1 observa.** Normal: `chrome.exe` em `C:\Program Files\...` falando 443 com destinos conhecidos. Suspeito: executável em `\AppData\Local\Temp\` ou `\Downloads\` abrindo conexão de saída, principalmente fora do horário comercial.

**Erro comum de júnior.** Tratar todo IOC como verdade absoluta. Um IP de nuvem pública pode hospedar malware hoje e um site legítimo amanhã. IOC é pista, não sentença.

## A Pirâmide da Dor

David Bianco desenhou a Pirâmide da Dor para responder: *quanta dor eu causo ao atacante quando bloqueio este indicador?* Quanto mais alto o nível, mais caro fica para o adversário mudar.

```
              /\        TTPs            -> Muito difícil de mudar
             /  \       Ferramentas     -> Desafiador
            /    \      Artefatos rede/host -> Irritante
           /      \     Domínios        -> Simples
          /        \    IPs             -> Fácil
         /__________\   Hashes          -> Trivial
```

| Nível | O que é | Custo para o atacante trocar |
|---|---|---|
| Hash | Impressão digital do arquivo | Trivial — 1 byte muda o hash |
| IP | Endereço do servidor | Fácil — aluga outro por horas |
| Domínio | Nome usado no comando e controle | Simples — registra outro por poucos dólares |
| Artefato de rede/host | Padrão de User-Agent, URI, chave de registro, nome de serviço | Irritante — exige mexer no código |
| Ferramenta | Mimikatz, Impacket, Responder, PsExec | Desafiador — precisa aprender/escrever outra |
| TTP | Tática, Técnica e Procedimento (o *modo de agir*) | Muito difícil — é o jeito de trabalhar dele |

**Por que isso muda a caça.** Se você só bloqueia hash e IP, o atacante volta em minutos. Se você detecta o *comportamento* — por exemplo, "processo não-LSASS lendo memória do LSASS", que é a técnica MITRE ATT&CK T1003.001 (OS Credential Dumping: LSASS Memory) — você pega Mimikatz, Rubeus e qualquer sucessor ainda não inventado.

### IOC contra IOA

- **IOC** = evidência do passado. "O arquivo com hash X apareceu." Responde *o que aconteceu*.
- **IOA** (Indicator of Attack, Indicador de Ataque) = comportamento em andamento. "O Word abriu um PowerShell que baixou algo." Responde *o que está acontecendo agora*.

IOA fica no topo da pirâmide; IOC na base. Bom SOC usa os dois.

## Threat intel e o cuidado com reputação

| Fonte | O que é | Cuidado |
|---|---|---|
| MISP | Plataforma aberta para compartilhar IOCs entre empresas | Qualidade depende de quem publica |
| AlienVault OTX | Comunidade aberta de "pulsos" de ameaça | Muito ruído; qualquer um publica |
| VirusTotal | Multi-antivírus + telemetria de arquivos e URLs | 1 ou 2 motores marcando ≠ malicioso |
| AbuseIPDB | Reputação de IP por denúncias | IP de NAT/CGNAT compartilhado gera falso positivo |

**Erro comum de júnior.** Ver "3/72 detecções" no VirusTotal e escalar como incidente crítico. Motores heurísticos erram muito. Olhe *quais* motores, a data do primeiro envio e o comportamento observado — não só o número.

**STIX/TAXII em resumo.** STIX (Structured Threat Information eXpression) é o *idioma* padronizado em JSON para descrever ameaça (indicador, campanha, ator, relação entre eles). TAXII (Trusted Automated eXchange of Intelligence Information) é o *correio* — o protocolo HTTPS que entrega esse conteúdo do provedor para o seu SIEM. Analogia: STIX é a carta escrita num formato que todos leem; TAXII é o carteiro.

## Regra SIGMA explicada linha a linha

SIGMA é o formato aberto para escrever regras de detecção em log — a mesma regra é convertida para Splunk, Sentinel, Elastic. É o "escreva uma vez, use em qualquer SIEM".

```yaml
title: Logon interativo com conta de servico
id: 8f3b1c02-4a77-4e19-b0aa-6f1c2d3e4f50
status: experimental
description: Conta de servico nao deve fazer logon interativo em estacao
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType:
      - 2
      - 10
    TargetUserName|startswith: 'svc_'
  filter:
    ComputerName|startswith: 'SRV-ADM'
  condition: selection and not filter
falsepositives:
  - Manutencao autorizada por administrador
level: high
tags:
  - attack.lateral_movement
  - attack.t1078.002
```

Linha a linha: `title` é o nome do alerta que chega até você; `id` é o identificador único (cite-o no ticket); `logsource` diz onde procurar — log de Segurança do Windows; `selection` é o gatilho: Event ID 4624 (logon bem-sucedido) com `LogonType` 2 (teclado local) ou 10 (RDP — Remote Desktop Protocol), e usuário começando com `svc_`; `filter` é a exceção — servidores administrativos onde isso é esperado; `condition` combina os dois: dispara se casar com `selection` e não com `filter`; `falsepositives` avisa o que checar antes de escalar; `level` é a severidade; `tags` mapeia para MITRE ATT&CK T1078.002 (Valid Accounts: Domain Accounts).

Equivalente em SPL (Splunk):

```
index=wineventlog EventCode=4624              /* logons bem-sucedidos */
| where LogonType IN (2,10)                    /* interativo local ou RDP */
| search Account_Name="svc_*"                  /* contas de servico */
| search NOT ComputerName="SRV-ADM*"           /* exclui servidores de administracao */
| table _time, ComputerName, Account_Name, LogonType, Source_Network_Address
```

Equivalente em KQL (Microsoft Sentinel):

```kql
SecurityEvent
| where EventID == 4624                              // logon com sucesso
| where LogonType in (2, 10)                         // interativo e RDP
| where TargetUserName startswith "svc_"             // contas de servico
| where Computer !startswith "SRV-ADM"               // exceção conhecida
| project TimeGenerated, Computer, TargetUserName, LogonType, IpAddress
| sort by TimeGenerated desc
```

## O fluxo de triagem do N1

Pense num pronto-socorro. O paciente chega, alguém mede sinais vitais, decide se é urgente, registra a ficha e chama o especialista se precisar. Triagem de SOC é exatamente isso.

### Passo a passo

1. **Receber.** Pegue o alerta na fila. Anote hora de recebimento em UTC (Tempo Universal Coordenado — o fuso de referência mundial; o SOC trabalha nele para não confundir turnos em países diferentes).
2. **Entender a regra que disparou.** Leia o título, a descrição e os `falsepositives` da regra. Se você não sabe o que a regra procura, não sabe se ela acertou.
3. **Coletar contexto.** Quem é o usuário (`jsilva` é do financeiro ou é `admin.rodrigo` do TI?), qual o host, qual a criticidade do ativo (estação comum ou controlador de domínio?), qual o horário (14h de terça ou 03h de domingo?).
4. **Validar em fonte independente.** O alerta veio do EDR? Confirme no firewall, no proxy, no DNS. Duas fontes concordando valem muito mais que uma.
5. **Enriquecer.** Reputação do IP/domínio/hash, geolocalização, WHOIS (idade do domínio — domínio criado há 2 dias é péssimo sinal), histórico do host nos últimos 7 dias.
6. **Decidir.** Três saídas possíveis:
   - **Falso positivo** — a regra errou; o evento nem aconteceu como descrito.
   - **Benigno verdadeiro** — aconteceu de verdade, mas é atividade legítima (o `svc_backup` rodando o backup noturno).
   - **Verdadeiro positivo** — é atividade maliciosa ou suspeita real.
7. **Documentar.** Escreva a nota antes de fechar. Ticket sem nota é trabalho perdido.
8. **Escalar** ao N2 quando os critérios objetivos abaixo forem atendidos.

### Template de nota de ticket

```
RESUMO
Alerta "Logon interativo com conta de servico" (SIGMA 8f3b1c02) disparou para
svc_backup no host WS-FIN-014 (10.10.24.57). Classificacao: verdadeiro positivo.

TIMELINE (UTC)
2026-09-03 14:02:11Z  Sysmon EID 3: fatura.exe (Temp) -> 203.0.113.45:443
2026-09-03 14:04:38Z  Windows 4624 LogonType 10, svc_backup em WS-FIN-014
2026-09-03 14:05:02Z  Palo Alto THREAT: sessao bloqueada, assinatura C2 generico
2026-09-03 14:20:00Z  Analista N1 iniciou triagem

EVIDENCIAS
- Sysmon EID 1 e 3 no host WS-FIN-014
- Log TRAFFIC/THREAT do firewall (session id 118246)
- Consulta DNS para atualizacao-fatura.example.com as 14:02:09Z

IOCs
- SHA256: e3b0c44298fc1c149afbf4c8996fb924...b855 (fatura.exe)
- IP: 203.0.113.45 (porta 443)
- Dominio: atualizacao-fatura.example.com (registrado ha 3 dias)

HOSTS E USUARIOS AFETADOS
- Host: WS-FIN-014 / 10.10.24.57
- Usuarios: jsilva (sessao ativa), svc_backup (conta de servico usada)

ACOES TOMADAS
- Host isolado na rede as 14:31Z via EDR
- IP e dominio submetidos a bloqueio no proxy e firewall
- Senha de svc_backup marcada para rotacao (pedido ao time de identidade)

RECOMENDACAO
Escalar ao N2 para analise forense do host e verificacao de movimento lateral.

NIVEL DE CONFIANCA: Alto (3 fontes independentes concordam)
```

### Template de escalonamento para o N2

```
PARA: SOC N2 - Plantao
PRIORIDADE: P2
TICKET: INC-2026-09-4471
ATIVO CRITICO? Nao (estacao de trabalho, usuario padrao)

POR QUE ESTOU ESCALANDO
Execucao suspeita a partir de %TEMP% com conexao externa para dominio
recem-registrado, seguida de uso de conta de servico em logon RDP.
Suspeita de comprometimento inicial com tentativa de movimento lateral.

O QUE JA FIZ
Enriquecimento completo (VirusTotal, WHOIS, AbuseIPDB), correlacao com
firewall e DNS, isolamento do host, nota de ticket preenchida.

O QUE NAO CONSIGO FAZER NO MEU NIVEL
Coleta de memoria do host, analise do binario, consulta a logs do controlador
de dominio para 4768/4769 relacionados a svc_backup.

MITRE ATT&CK SUSPEITO
T1204.002 (User Execution: Malicious File), T1078.002 (Valid Accounts)

JANELA DE INVESTIGACAO: 2026-09-03 13:30Z a 15:00Z
```

### Critérios objetivos de escalonamento imediato

| Situação | Ação |
|---|---|
| Ativo crítico envolvido (controlador de domínio, servidor de banco, ERP) | Escalar já |
| Conta administrativa ou de serviço comprometida | Escalar já |
| Sinal de ransomware (renomeação em massa, apagamento de shadow copies) | Escalar já e acionar plantão |
| Exfiltração aparente (volume anômalo de saída, upload para nuvem não corporativa) | Escalar já |
| Ferramenta de dumping de credencial detectada (T1003) | Escalar já |
| Mais de 3 hosts com o mesmo IOC em 1 hora | Escalar já |
| Alerta que você não entende após 20 minutos de triagem | Escalar — dúvida não é vergonha |

**Erro comum de júnior.** Ficar 2 horas tentando "resolver sozinho" um caso que já batia critério de escalonamento na primeira leitura. Tempo é a moeda do SOC.

### Exercícios — IOCs, Pirâmide da Dor e o fluxo de triagem do N1

1. Um analista bloqueou o hash SHA256 de um malware no EDR e declarou o caso encerrado. Em qual nível da Pirâmide da Dor ele atuou e qual o risco dessa decisão?
2. Leia o log e diga se é falso positivo, benigno verdadeiro ou verdadeiro positivo:
```
type=traffic subtype=start srcip=10.10.30.12 srcport=51044 dstip=203.0.113.90
dstport=443 action=accept app=SSL user="svc_backup" duration=0
policyid=17 devname="FGT-CORP-01" date=2026-09-03 time=03:14:22
```
Contexto: `svc_backup` só deve falar com `10.20.0.0/16`; `203.0.113.90` tem 0/72 no VirusTotal.
3. O alerta indica que `admin.rodrigo` fez logon 4624 LogonType 3 em `DC-CORP-01` às 02:47 UTC de domingo. Qual o próximo passo da investigação e quais dois campos você olha primeiro?
4. Classifique cada item pelo nível da Pirâmide da Dor: (a) `192.0.2.77`; (b) uso de PsExec para execução remota; (c) User-Agent `Mozilla/4.0 (compatible; Updater)`; (d) `d41d8cd98f00b204e9800998ecf8427e`.
5. Um domínio tem 4/72 detecções no VirusTotal, foi registrado há 900 dias e é o portal de RH da empresa. Qual sua classificação e o que escrever na nota?

<details><summary>Ver gabarito</summary>

1. Atuou no nível **hash** — a base da pirâmide, "trivial" de contornar. Basta o atacante recompilar ou adicionar 1 byte ao arquivo e o hash muda completamente; o bloqueio vira inútil em minutos. O correto é subir a pirâmide: identificar o *comportamento* (execução a partir de `%TEMP%`, chave de persistência em `Run`, padrão de conexão) e criar detecção sobre isso. Bloquear o hash é válido, mas nunca é o fim da investigação.

2. **Verdadeiro positivo** (suspeito, precisa escalar). O log FortiGate em `key=value` mostra: `srcip=10.10.30.12` (host interno) falando com `dstip=203.0.113.90:443` externo, usando a conta `svc_backup`, às **03:14 UTC**. Três sinais somados: conta de serviço saindo do escopo definido (`10.20.0.0/16`), destino externo e horário fora do expediente. O "0/72 no VirusTotal" **não inocenta** ninguém — infraestrutura nova de atacante costuma ser limpa justamente por ser nova. Reputação limpa é ausência de evidência, não evidência de ausência.

3. Próximo passo: **coletar contexto e validar em fonte independente**. Os dois campos primeiro: `IpAddress` (de qual origem veio o logon de rede — máquina do próprio administrador ou host aleatório?) e `LogonProcessName`/`AuthenticationPackageName` (NTLM em vez de Kerberos num controlador de domínio é sinal de alerta). Em seguida procure 4768/4769 (bilhetes Kerberos) e 4776 no controlador, e confirme com o próprio administrador se havia manutenção agendada. Logon Type 3 é logon de rede, não interativo — comum em acesso a compartilhamento, mas em DC de madrugada exige verificação. Como envolve conta administrativa em ativo crítico, já bate critério de **escalonamento imediato**.

4. (a) `192.0.2.77` = **IP** (fácil de trocar). (b) PsExec = **Ferramenta** (desafiador). (c) User-Agent customizado = **Artefato de rede** (irritante). (d) MD5 = **Hash** (trivial). Ordem de valor defensivo, do maior para o menor: b > c > a > d.

5. **Falso positivo** (ou benigno verdadeiro, se o acesso realmente ocorreu). Domínio corporativo legítimo, com 900 dias de idade e uso conhecido; 4 detecções em 72 motores são quase certamente heurísticas genéricas. Na nota escreva: domínio validado como ativo corporativo de RH, idade 900 dias, detecções restritas a motores heurísticos sem consenso, sem comportamento anômalo associado no host. Recomende **criar exceção/allowlist documentada** para reduzir ruído futuro, citando quem aprovou.

</details>

## Mini-laboratório — Logs e investigação

**Objetivo.** Gerar eventos reais, encontrá-los no log e produzir uma nota de ticket completa, do zero ao fim.

**Pré-requisitos.** Windows 10/11 com direitos de administrador, Sysmon (gratuito, Microsoft Sysinternals) e Wireshark instalados. Alternativa 100% Linux: Docker + Zeek.

**Passo 1 — Instalar o Sysmon com configuração base.**
```
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon" -Force
& "$env:TEMP\Sysmon\Sysmon64.exe" -accepteula -i
```
*Observe:* o serviço `Sysmon64` deve aparecer como `Running` em `Get-Service Sysmon64`.

**Passo 2 — Gerar um evento de rede rastreável.** Com o Wireshark capturando na interface ativa e o filtro de exibição `dns`, execute:
```
Resolve-DnsName -Name example.com -Type A
```
*Observe:* no Wireshark, a pergunta e a resposta DNS na porta 53. No Visualizador de Eventos, em `Applications and Services Logs > Microsoft > Windows > Sysmon > Operational`, procure o **Event ID 22** (DNSEvent) com `QueryName: example.com`.

**Passo 3 — Gerar um logon falhado.** Em uma janela nova, tente autenticar com uma conta local inexistente:
```
runas /user:CORP\usuario.inexistente cmd.exe
```
Digite qualquer texto quando pedir a senha. *Observe:* no log de Segurança, o **Event ID 4625** (falha de logon) com `Status 0xC0000064` (usuário não existe) ou `0xC000006A` (senha errada).

**Passo 4 — Consultar por linha de comando.**
```
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddMinutes(-15)} |
  Select-Object TimeCreated, Id, @{n='Conta';e={$_.Properties[5].Value}} | Format-Table -AutoSize
```
*Observe:* a hora do evento, o Event ID e a conta tentada.

**Passo 5 — Correlacionar e escrever.** Junte os três achados (DNS via Sysmon 22, falha de logon 4625, captura Wireshark) em uma linha do tempo em UTC e preencha o **template de nota de ticket** desta seção. Classifique o caso — neste laboratório o resultado correto é **benigno verdadeiro**, pois você mesmo gerou a atividade.

**Critério de sucesso.** Você conseguiu: (1) localizar cada evento pelo Event ID correto; (2) alinhar os três em uma timeline com horários coerentes; (3) preencher a nota com resumo, timeline, evidências e nível de confiança justificado.

**Limpeza.** `& "$env:TEMP\Sysmon\Sysmon64.exe" -u` remove o Sysmon.

## O que um SOC Level 1 realmente precisa saber

- 🟢 Todo log tem no mínimo: **quando, quem, o quê, onde e resultado**. Se falta o "quando" em UTC, a investigação já nasce torta.
- 🟢 **Event ID 4624** é logon com sucesso e **4625** é falha; o `LogonType` (2 local, 3 rede, 10 RDP) muda completamente o significado do evento.
- 🟢 **Sysmon 1** (criação de processo), **3** (conexão de rede) e **22** (consulta DNS) são o tripé de visibilidade em endpoint.
- 🟢 Executável rodando a partir de `%TEMP%`, `%APPDATA%` ou `Downloads` é sempre digno de investigação.
- 🟢 O fluxo de triagem é fixo: **receber → entender a regra → contexto → validar em fonte independente → enriquecer → decidir → documentar → escalar**.
- 🟢 As três classificações são **falso positivo**, **benigno verdadeiro** e **verdadeiro positivo** — saiba diferenciar as duas últimas.
- 🟡 A **Pirâmide da Dor** ordena indicadores por custo de troca: hash e IP são descartáveis; ferramenta e TTP doem de verdade.
- 🟡 Reputação (VirusTotal, AbuseIPDB) é **um** sinal, nunca o veredito: 0 detecções não inocenta e 3 detecções não condenam.
- 🟡 **IOC** olha para o passado; **IOA** olha para o comportamento em andamento. Detecção madura combina os dois.
- 🟡 Ticket sem nota estruturada é trabalho perdido — o N2 e a auditoria leem a sua nota, não a sua memória.
- 🔴 **SIGMA** permite escrever a detecção uma vez e traduzir para Splunk (SPL) e Sentinel (KQL); ler uma regra é habilidade de N1, escrever já é passo para N2.
- 🔴 **STIX/TAXII** é o par idioma + transporte da inteligência automatizada; entender o conceito basta no N1.

## Resumo em 10 linhas

1. Log existe para responder quem fez o quê, onde, quando e com qual resultado — e sem ele não há investigação.
2. O ciclo do dado vai de geração e coleta a normalização, correlação, retenção e descarte, e o Syslog é o transporte clássico dessa cadeia.
3. No Windows, os Event IDs de Segurança (4624, 4625, 4688, 4768, 4769, 4776) contam a história de contas e processos.
4. O Sysmon amplia essa visão com criação de processo (1), conexão de rede (3) e consulta DNS (22).
5. Firewall, proxy, DNS e nuvem cobrem o lado da rede — e cada produto tem seu formato: CSV no Palo Alto, `key=value` no FortiGate, JSON no Suricata.
6. Ler um log é identificar os campos de tempo, origem, destino, identidade, ação e resultado antes de qualquer conclusão.
7. IOCs são vestígios técnicos: hashes, IPs, domínios, URLs, chaves de registro, mutex, certificados e JA3.
8. A Pirâmide da Dor mostra que bloquear hash e IP incomoda pouco, enquanto detectar ferramenta e TTP realmente custa caro ao atacante.
9. O N1 segue um fluxo fixo de triagem e sempre valida em fonte independente antes de decidir entre falso positivo, benigno verdadeiro e verdadeiro positivo.
10. Documentar em UTC com timeline, evidências, IOCs e nível de confiança — e escalar sem hesitar quando os critérios objetivos forem atingidos — é o que separa um bom analista de um analista lento.



---
