# Módulo 6 — Portas e Protocolos (Parte 1)

Todo incidente que você vai analisar no SOC (Security Operations Center, o Centro de Operações de Segurança) tem uma porta envolvida. Um alerta de "conexão suspeita" só faz sentido quando você sabe o que deveria estar rodando naquela porta. Saber que a porta 22 é SSH, que a 23 nunca deveria existir na rede corporativa e que a porta 445 falando com a internet é quase sempre problema — isso separa o analista que fecha o ticket como falso positivo em dois minutos do analista que escala um incidente real.

## Índice do módulo

- Conceito de porta e protocolos 20 a 80
- Protocolos 110 a 161 e tabela-resumo

## O que é uma porta

Imagine um prédio de apartamentos. O endereço da rua (Rua das Flores, 100) leva o carteiro até o prédio certo, mas não até a pessoa certa. É o número do apartamento (301) que entrega a carta na mão do morador.

Na rede é igual: o **endereço IP** é o prédio e a **porta** é o apartamento. O IP `10.10.20.55` leva o pacote até a máquina certa; a porta `443` entrega esse pacote ao programa certo dentro da máquina — no caso, o servidor web.

A combinação dos dois chama-se **socket**: `10.10.20.55:443`. Uma conexão completa é sempre formada por quatro informações (o que chamamos de "quádrupla"): IP de origem, porta de origem, IP de destino, porta de destino.

```
192.168.15.42:52310  ->  10.10.20.55:443
   (cliente)               (servidor)
```

O número da porta cabe em 16 bits, ou seja, vai de 0 a 65535. A IANA (Internet Assigned Numbers Authority, o órgão que padroniza números da internet) dividiu esse espaço em três faixas:

| Faixa | Nome | Uso |
|---|---|---|
| 0 – 1023 | Well-known (bem conhecidas) | Serviços padrão: HTTP, SSH, DNS. No Linux exigem privilégio de root para abrir |
| 1024 – 49151 | Registradas | Aplicações registradas: MySQL 3306, RDP 3389, MSSQL 1433 |
| 49152 – 65535 | Dinâmicas / efêmeras | Portas de origem escolhidas na hora pelo sistema operacional |

### Como o sistema escolhe a porta de origem

Quando o notebook da usuária `maria.costa` abre o navegador e acessa `intranet.corp.local`, o destino é fixo (porta 80 ou 443), mas a origem não. O sistema operacional sorteia uma porta livre da faixa efêmera — por exemplo `52310` — e a usa como "remetente". Se ela abrir dez abas, teremos dez portas de origem diferentes, e é assim que o sistema sabe qual resposta pertence a qual aba.

Faixas efêmeras por sistema: Windows moderno usa 49152–65535; Linux usa por padrão 32768–60999.

**Erro comum de analista júnior:** ver a porta `52310` num log e tentar descobrir "qual serviço é a porta 52310". Não é serviço nenhum. **A porta que identifica o serviço é sempre a de destino** na conexão iniciada pelo cliente.

### "Porta aberta" não é "serviço vulnerável"

Um scan de rede devolve "porta 3389 aberta" e o júnior abre um incidente crítico. Calma. Porta aberta significa apenas que existe um programa escutando ali. Vulnerabilidade depende de qual software é, qual versão, se está exposto à internet, se exige autenticação forte e se há exploração conhecida. Um RDP (Remote Desktop Protocol) aberto só para a rede interna, com MFA (autenticação multifator) e patch em dia, é operação normal. O mesmo RDP exposto em IP público é incidente. Contexto é tudo.

## Como listar portas em uso

**Windows** — `netstat -ano` mostra conexões e o PID (Process ID, identificador do processo) dono de cada uma:

```
C:\> netstat -ano | findstr LISTENING
  Proto  Endereço local        Endereço externo    Estado       PID
  TCP    0.0.0.0:445           0.0.0.0:0           LISTENING    4
  TCP    0.0.0.0:3389          0.0.0.0:0           LISTENING    1284
  TCP    10.10.20.55:49670     203.0.113.77:443    ESTABLISHED  6612
```

Depois use `tasklist /FI "PID eq 6612"` para descobrir o executável.

**Linux** — `ss -tulpn` (`-t` TCP, `-u` UDP, `-l` só escutando, `-p` processo, `-n` sem resolver nomes):

```
$ sudo ss -tulpn
Netid State  Local Address:Port   Peer Address:Port  Process
tcp   LISTEN 0.0.0.0:22           0.0.0.0:*          users:(("sshd",pid=901,fd=3))
tcp   LISTEN 127.0.0.1:3306       0.0.0.0:*          users:(("mysqld",pid=1422,fd=21))
```

Note a diferença: `0.0.0.0:22` escuta em todas as interfaces (acessível pela rede); `127.0.0.1:3306` escuta só localmente (não acessível de fora). Isso muda completamente a avaliação de risco.

**Sysmon Event ID 3 (Network connection detected)** — no endpoint, é a fonte mais rica, porque liga a conexão ao processo:

```
EventID: 3
UtcTime: 2026-09-03 14:22:41.118
Image: C:\Users\jsilva\AppData\Local\Temp\update.exe
User: CORP\jsilva
Protocol: tcp
SourceIp: 10.10.20.55       SourcePort: 51122
DestinationIp: 203.0.113.44 DestinationPort: 443
DestinationHostname: cdn.empresa-exemplo.com.br
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `EventID` | `3` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não. `3` = Sysmon **Network Connect** |
| `UtcTime` | `2026-09-03 14:22:41.118` | Instante do evento **em UTC**, o que dispensa converter fuso ao correlacionar |
| `Image` | `C:\Users\jsilva\AppData\Local\Temp\update.exe` | Caminho do executável (nomenclatura do Sysmon) |
| `User` | `CORP\jsilva` | Conta sob a qual o processo corre |
| `Protocol` | `tcp` | Protocolo de transporte da conexão |
| `SourceIp` | `10.10.20.55` | IP de origem da conexão |
| `SourcePort` | `51122` | Porta de origem |
| `DestinationIp` | `203.0.113.44` | IP de destino da conexão |
| `DestinationPort` | `443` | Porta de destino |
| `DestinationHostname` | `cdn.empresa-exemplo.com.br` | Nome do host de destino, quando o Sysmon consegue resolvê-lo |

</details>

O que o SOC N1 observa: processo em `\Temp\` abrindo conexão de saída é anômalo; `chrome.exe` fazendo o mesmo é rotina.

## Protocolos porta a porta

### Portas 20 e 21 — FTP (File Transfer Protocol)

- **O que é:** protocolo antigo de transferência de arquivos. Usa **duas** portas: a **21** é o canal de controle (comandos `USER`, `PASS`, `RETR`) e a **20** é o canal de dados (o arquivo em si) no modo ativo. No modo passivo, o servidor informa uma porta alta e o cliente conecta nela — por isso firewalls sofrem com FTP.
- **Quando é utilizado:** integrações legadas, envio de arquivos para parceiros, backup de equipamentos de rede. Substituído por SFTP (SSH File Transfer Protocol, porta 22) e FTPS (FTP sobre TLS, porta 990). **O tráfego FTP puro trafega em texto claro, inclusive a senha.**
- **Como aparece em log** (Zeek `ftp.log`):

```
#ts        uid            id.orig_h    id.orig_p  id.resp_h    id.resp_p  user     command  arg                    reply_code
1756909361 CkTf9x2yLm3q   10.10.30.18  50122      198.51.100.60 21        svc_backup RETR   /dados/clientes_2026.csv 226
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `ts` | `1756909361` | Instante do comando em epoch Unix (aqui sem a fração de segundo) |
| `uid` | `CkTf9x2yLm3q` | Conexão de controle do FTP — cruza com o `conn.log`. **A transferência em si sai por outra conexão**, na porta de dados |
| `id.orig_h` / `id.orig_p` | `10.10.30.18` / `50122` | Quem iniciou: um servidor interno |
| `id.resp_h` / `id.resp_p` | `198.51.100.60` / `21` | Destino **externo** na porta 21 — FTP saindo da rede |
| `user` | `svc_backup` | Credencial usada. FTP é em texto claro: **esta conta e a senha atravessaram a rede legíveis** |
| `command` | `RETR` | A ação: `RETR` baixa do servidor, `STOR` envia, `LIST` lista, `DELE` apaga |
| `arg` | `/dados/clientes_2026.csv` | O alvo do comando — o nome do arquivo já diz o tamanho do problema |
| `reply_code` | `226` | Código de resposta do FTP. `226` = transferência concluída com sucesso; `530` seria autenticação recusada e `550` acesso negado |

</details>


- **Riscos:** credenciais em texto claro capturáveis por sniffer; servidor com login anônimo habilitado; canal ideal para **exfiltração** de dados em massa (MITRE ATT&CK T1048 — Exfiltration Over Alternative Protocol).
- **Alertas comuns de SOC:** FTP saindo para IP público não catalogado; volume de upload muito acima da linha de base; `USER anonymous`; dezenas de `reply_code 530` (falha de login) indicando força bruta.

### Porta 22 — SSH (Secure Shell)

- **O que é:** acesso remoto criptografado a servidores e equipamentos de rede. Também transporta SFTP e SCP.
- **Quando é utilizado:** administração de Linux, switches, firewalls; automação com Ansible; e **túneis**. O parâmetro `-L` cria um túnel local e o `-R` um túnel reverso, que expõe uma porta da rede interna para fora — mecanismo legítimo, mas frequentemente abusado como canal de comando e controle e de exfiltração (T1572 — Protocol Tunneling).
- **Como aparece em log** (syslog do servidor Linux):

```
Sep  3 09:14:02 srv-app01 sshd[2211]: Failed password for invalid user admin from 203.0.113.90 port 44112 ssh2
Sep  3 09:14:05 srv-app01 sshd[2213]: Failed password for root from 203.0.113.90 port 44130 ssh2
Sep  3 09:16:41 srv-app01 sshd[2290]: Accepted publickey for admin.rodrigo from 10.10.5.22 port 51002 ssh2: RSA SHA256:9c1f...
```

Leitura: duas linhas `Failed password` do mesmo IP externo em segundos = tentativa de força bruta (T1110). A terceira linha é o padrão saudável: `Accepted publickey`, origem interna, usuário nominal.

- **Riscos:** força bruta; chave pública maliciosa inserida em `~/.ssh/authorized_keys` garantindo persistência silenciosa (T1098.004); túnel reverso furando o perímetro.
- **Alertas comuns de SOC:** SSH **de dentro para fora** rumo à internet (raro e suspeito); acesso com conta de serviço em horário atípico; muitos `Failed password` seguidos de um `Accepted` — sinal de força bruta bem-sucedida, sempre escalar.

### Porta 23 — Telnet

- **O que é:** o avô do SSH. Acesso remoto a linha de comando **totalmente em texto claro** — usuário e senha viajam legíveis.
- **Quando é utilizado:** idealmente nunca. Sobrevive em switches antigos, impressoras, catracas, câmeras e outros dispositivos IoT (Internet of Things, "internet das coisas").
- **Como aparece em log** (Cisco ASA):

```
%ASA-6-302013: Built inbound TCP connection 88213 for outside:203.0.113.15/49820 (203.0.113.15/49820) to inside:10.10.60.31/23 (10.10.60.31/23)
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `%ASA` | `%ASA` | Etiqueta do produto: identifica a linha como vinda de um firewall ASA |
| severidade | `6` | Escala syslog do Cisco, de 0 (emergência) a 7 (depuração): `6` é **informational**. **Severidade baixa não quer dizer evento sem importância** — quem a escolhe é o fabricante, não o seu SOC |
| *message ID* | `302013` | Conexão TCP construída — entrou na tabela de estado. **É por este número que se escreve a regra no SIEM**: o texto da mensagem muda entre versões do software, o ID não |
| direção | `inbound` | **Quem iniciou**, não a direção dos bytes: `outbound` é de dentro para fora, `inbound` é de fora para dentro |
| id da conexão | `88213` | Número da conexão na tabela de estado. **É a chave para casar com o `302014`** que a encerra |
| lado remoto | `outside:203.0.113.15/49820` | Interface, IP e porta do host **remoto**. Vem primeiro, logo depois do `for` — é isso que faz a linha parecer invertida |
| *(entre parênteses)* | `(203.0.113.15/49820)` | O endereço **traduzido** desse lado. Igual ao real significa que não houve NAT nesta ponta |
| lado local | `inside:10.10.60.31/23` | Interface, IP e porta do host **local**, antes da tradução |
| *(entre parênteses)* | `(10.10.60.31/23)` | O endereço com que o host local saiu. **Este par — IP público mais porta — é o que desfaz o NAT** num pedido externo |
| — | — | **Porta 23 é Telnet, em texto claro, e a conexão veio de fora.** Sem NAT em nenhuma ponta, o host interno está publicado diretamente. É achado de auditoria antes de ser incidente |

</details>


- **Riscos:** captura trivial de credenciais; o worm **Mirai** construiu uma botnet gigantesca justamente varrendo a porta 23 com senhas padrão de fábrica.
- **Alertas comuns de SOC:** qualquer conexão Telnet aceita; varredura da porta 23 vinda de um host interno (indica máquina comprometida procurando IoT vulnerável).

### Porta 25 — SMTP (Simple Mail Transfer Protocol)

- **O que é:** protocolo de **envio** de e-mail entre servidores.
- **Quando é utilizado:** troca de mensagens entre servidores de correio; impressoras e sistemas internos que disparam notificações. Clientes finais hoje usam 587 (submissão autenticada) ou 465 (TLS implícito).
- **Como aparece em log** (FortiGate, formato chave=valor):

```
date=2026-09-03 time=11:02:47 devname="FGT-CORP-01" type="traffic" subtype="forward" srcip=10.10.44.90 srcport=51204 dstip=198.51.100.25 dstport=25 proto=6 action="accept" sentbyte=48211900 rcvdbyte=9120 app="SMTP" policyid=14
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `date` | `2026-09-03` | Data local **do equipamento**, não UTC. Correlacionar com um log em UTC sem acertar o fuso desalinha a timeline |
| `time` | `11:02:47` | Hora local do equipamento |
| `devname` | `"FGT-CORP-01"` | Nome do equipamento que gerou o log |
| `type` | `"traffic"` | Categoria do log: `traffic` é sessão, `event` é evento do próprio aparelho, `utm` é inspeção de conteúdo |
| `subtype` | `"forward"` | Subcategoria: `forward` é tráfego que atravessa, `local` é destinado ao próprio firewall, `vpn` é túnel, `webfilter` e `ips` são inspeção |
| `srcip` | `10.10.44.90` | IP de origem |
| `srcport` | `51204` | Porta de origem, efêmera e sorteada pelo cliente |
| `dstip` | `198.51.100.25` | IP de destino |
| `dstport` | `25` | Porta de destino — é ela que aponta o serviço |
| `proto` | `6` | Número do protocolo IP: **`6` é TCP, `17` é UDP, `1` é ICMP**. Vem em número, não em nome |
| `action` | `"accept"` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |
| `sentbyte` | `48211900` | Bytes enviados **pela origem**. O ponto de vista é o da origem, não do firewall |
| `rcvdbyte` | `9120` | Bytes recebidos pela origem. **Comparar com `sentbyte` é o que revela exfiltração** |
| `app` | `"SMTP"` | Aplicação identificada pelo controle de aplicação, por inspeção do conteúdo |
| `policyid` | `14` | **Número da regra que decidiu.** Sem ele não se sabe por que o tráfego passou ou parou |

</details>

`proto=6` é TCP; `sentbyte=48211900` são ~48 MB enviados por uma estação comum via SMTP direto — comportamento típico de exfiltração ou de máquina infectada enviando spam.

- **Riscos:** relay aberto (servidor que aceita enviar e-mail de qualquer um, virando plataforma de spam); falsificação do remetente (spoofing) quando faltam SPF, DKIM e DMARC; phishing; exfiltração por anexo (T1048.003).
- **Alertas comuns de SOC:** estação de trabalho falando SMTP direto com a internet (só o servidor de e-mail deveria fazer isso); pico de conexões na porta 25; e-mail interno cujo domínio do remetente não passa em SPF.

### Porta 53 — DNS (Domain Name System)

- **O que é:** a agenda telefônica da internet, que traduz `intranet.corp.local` em `10.10.20.55`. Usa UDP para consultas normais e TCP para respostas grandes e transferência de zona.
- **Quando é utilizado:** em praticamente toda conexão — o DNS vem antes de tudo.
- **Como aparece em log** (Zeek `dns.log`):

```
1756900112 CxT4a9  10.10.20.55  53881  10.10.10.5  53  udp  intranet.corp.local  A  NOERROR
```

- **Riscos:** tunelamento de DNS para exfiltração (T1071.004), domínios gerados por algoritmo (DGA), resolução para domínios recém-registrados.
- **Alertas comuns de SOC:** consultas a subdomínios longos e aleatórios, volume anormal de queries por host, uso de resolvedor externo não autorizado. **O tratamento completo do DNS está no Módulo 5** — aqui basta fixar que a porta é a 53, UDP e TCP.

### Portas 67 e 68 — DHCP (Dynamic Host Configuration Protocol)

- **O que é:** o protocolo que entrega automaticamente IP, máscara, gateway e servidor DNS a cada máquina que entra na rede. O servidor escuta na **UDP 67** e o cliente na **UDP 68**.
- **Quando é utilizado:** sempre que um dispositivo se conecta ao cabo ou ao Wi-Fi. O processo tem quatro passos, o **DORA**:
  1. **Discover** — o cliente grita em broadcast: "existe algum servidor DHCP aí?"
  2. **Offer** — o servidor responde oferecendo `10.10.20.55` por 8 dias.
  3. **Request** — o cliente aceita formalmente aquela oferta (em broadcast, para os outros servidores saberem que ele já escolheu).
  4. **Acknowledge** — o servidor confirma e registra o empréstimo (lease).
- **Como aparece em log** (log do serviço DHCP do Windows Server, CSV):

```
ID,Data,Hora,Descrição,Endereço IP,Nome do host,Endereço MAC
11,09/03/26,08:31:12,Renew,10.10.20.55,NB-JSILVA.corp.local,00155DAB12F4
10,09/03/26,08:47:55,Assign,10.10.20.87,NB-MCOSTA.corp.local,00155DAB77C1
```

`ID 10` = novo endereço concedido, `ID 11` = renovação. As colunas de nome de host e MAC (endereço físico da placa de rede) são o coração de uma investigação.

- **Riscos:** **rogue DHCP** — um servidor DHCP não autorizado responde primeiro e entrega um gateway ou DNS controlado pelo atacante, permitindo interceptar todo o tráfego (T1557, ataque de intermediário). **DHCP starvation** — o atacante pede milhares de endereços até esgotar a faixa, derrubando a rede e abrindo caminho para o rogue assumir.
- **Por que o log de DHCP é essencial:** o alerta chega dizendo "o IP 10.10.20.87 baixou um arquivo malicioso às 09h10". IP interno é emprestado e muda. Sem o log de DHCP você não sabe **qual máquina** era aquele IP naquele minuto. Com ele, você amarra IP → MAC → nome do host → usuário. Sempre olhe o lease vigente **no horário do evento**, não o de agora.
- **Alertas comuns de SOC:** DHCP Offer vindo de MAC ou IP fora da lista de servidores autorizados; explosão de Discovers do mesmo segmento; máquina cujo hostname não bate com o padrão de nomenclatura da empresa.

### Porta 80 — HTTP (HyperText Transfer Protocol)

- **O que é:** o protocolo da web **sem criptografia**. Tudo — URL, cabeçalhos, formulário de login, cookie de sessão — trafega legível na rede.
- **Quando é utilizado:** sites legados, portais cativos de Wi-Fi, painéis de impressoras e câmeras, e verificações de saúde de aplicação. Hoje quase todo tráfego legítimo é HTTPS na 443.
- **Como aparece em log** (Zeek `http.log`):

```
1756913001 CfW22b 10.10.20.55 51544 203.0.113.201 80 1 POST 203.0.113.201 /a/gate.php - 1.1 Mozilla/4.0 (compatible) 812 0 200 OK
```

Campos-chave: método `POST`, host que é um **IP cru** em vez de nome, URI `/gate.php` e `user_agent` genérico "Mozilla/4.0 (compatible)". Cada um desses isolado é fraco; os quatro juntos são assinatura clássica de comando e controle (T1071.001).

- **Riscos:** credenciais e cookies capturáveis em texto claro; download de payload; C2 (Command and Control) disfarçado de navegação comum.
- **Alertas comuns de SOC:** requisições HTTP com Host igual a IP; user-agent estranho ou vazio (`curl`, `python-requests`, `WinHTTP`); POSTs periódicos do mesmo tamanho a cada N segundos (beaconing).

## Consultas prontas

```spl
index=network sourcetype=pan:traffic dest_port IN (21,23,25)
| search NOT dest_ip IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
| stats count sum(bytes_out) AS bytes_out BY src_ip, dest_ip, dest_port
| where bytes_out > 10000000
```
Linha 1: filtra tráfego de firewall nas portas em texto claro. Linha 2: mantém só destinos na internet. Linha 3: agrupa por par origem/destino. Linha 4: destaca quem enviou mais de 10 MB — candidato a exfiltração.

```kql
DeviceNetworkEvents
| where RemotePort == 22 and RemoteIPType == "Public"   // SSH saindo para a internet
| where InitiatingProcessFileName !in ("ssh.exe","git.exe")  // remove ferramentas esperadas
| summarize Conexoes=count() by DeviceName, RemoteIP, InitiatingProcessFileName
| order by Conexoes desc
```

### Exercícios — Conceito de porta e protocolos 20 a 80

1. No log `10.10.20.55:51122 -> 203.0.113.44:443`, qual é a porta do serviço, qual faixa da IANA ela pertence e a que faixa pertence a porta 51122?
2. O SIEM alerta: "porta 3389 aberta em SRV-FIN-02". O `ss -tulpn` equivalente mostra escuta apenas em `127.0.0.1`. Verdadeiro ou falso positivo? Justifique.
3. Você recebe: "o host 10.10.20.87 acessou domínio malicioso às 09h10 de 03/09". Ao consultar o inventário agora, esse IP pertence a outra máquina. Qual é o próximo passo da investigação?
4. Leia: `sshd[2211]: Failed password for invalid user admin from 203.0.113.90` repetido 40 vezes, seguido de `Accepted password for svc_backup from 203.0.113.90`. Qual a classificação e a ação imediata?
5. Um servidor de aplicação enviou 48 MB pela porta 25 para um IP público. Cite duas hipóteses e o dado que decide entre elas.

<details><summary>Ver gabarito</summary>

1. O serviço é a porta **443 (HTTPS)**, faixa **well-known (0–1023)**. A porta **51122** é **efêmera/dinâmica (49152–65535)**, sorteada pelo sistema operacional como origem — não representa serviço nenhum. Erro clássico é tentar identificar "o serviço da porta 51122".
2. **Falso positivo** (ou, no mínimo, risco muito baixo). Escuta em `127.0.0.1` significa loopback: só processos da própria máquina alcançam aquela porta; não há exposição de rede. Se estivesse em `0.0.0.0`, aí sim caberia avaliar segmentação, MFA e patch. Documente a evidência do `ss` no ticket antes de fechar.
3. Consultar o **log de DHCP no horário do evento**, não o inventário atual. O lease vigente às 09h10 dá o MAC e o hostname reais (por exemplo `NB-MCOSTA.corp.local`), e daí você chega ao usuário e ao endpoint para coletar Sysmon Event ID 3 e 1. IP interno é empréstimo temporário; sem correlação temporal você investiga a máquina errada.
4. **Força bruta bem-sucedida** (T1110) — o padrão "muitas falhas seguidas de um sucesso, mesmo IP de origem". É incidente, escalar imediatamente. Ações: isolar ou bloquear `203.0.113.90` na borda, desabilitar/rotacionar a credencial de `svc_backup`, inspecionar `~/.ssh/authorized_keys` em busca de chave inserida pelo atacante (persistência, T1098.004) e levantar o que a sessão executou depois do login.
5. Hipótese A: exfiltração de dados por e-mail (T1048.003). Hipótese B: função legítima da aplicação, como relatório mensal com anexo grande enviado ao servidor de correio. **O dado que decide é o IP de destino**: se for o servidor SMTP corporativo homologado, é comportamento esperado e deve constar da linha de base; se for um IP público arbitrário, estação ou servidor falando SMTP direto com a internet é desvio de política e vira incidente. Some a isso a análise de destinatários e o histórico de volume do host.

</details>


## Porta 110 — POP3 (Post Office Protocol version 3)

**O que é.** Imagine uma caixa de correio física: você vai lá, tira todas as cartas e leva para casa. A caixa fica vazia. É exatamente isso que o POP3 faz — o cliente de e-mail baixa as mensagens do servidor e, por padrão, apaga do servidor.

**Como funciona.** TCP/110 em texto claro; TCP/995 é o POP3S (com TLS — Transport Layer Security, a camada que cifra o tráfego). Comandos simples em texto: `USER`, `PASS`, `LIST`, `RETR`, `DELE`, `QUIT`.

**Quando é utilizado.** Sistemas legados, impressoras multifuncionais, aparelhos antigos, integrações caseiras. Em ambiente moderno (Microsoft 365, Google Workspace) o POP3 costuma estar desativado.

**Exemplo prático.** A estação `10.10.20.45` do usuário `jsilva` conecta em `mail.corp.local` (`10.10.5.10`) na porta 110 às 03:12 da manhã — horário em que ninguém deveria estar lendo e-mail.

**Como aparece em log** (FortiGate, formato key=value):

```
date=2026-09-03 time=03:12:41 devname="FGT-CORE-01" devid="FG100E0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=10.10.20.45 srcport=51422 dstip=10.10.5.10 dstport=110 proto=6 action="accept" policyid=17 service="POP3" sentbyte=2140 rcvdbyte=418992 duration=96 app="POP3" user="jsilva"
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `date` | `2026-09-03` | Data local **do equipamento**, não UTC. Correlacionar com um log em UTC sem acertar o fuso desalinha a timeline |
| `time` | `03:12:41` | Hora local do equipamento |
| `devname` | `"FGT-CORE-01"` | Nome do equipamento que gerou o log |
| `devid` | `"FG100E0000000001"` | Número de série do equipamento — numa frota, é ele que identifica qual falou |
| `logid` | `"0000000013"` | Identificador do **tipo** de log. **É por ele que se filtra no SIEM**: o texto muda entre versões do FortiOS, o número não |
| `type` | `"traffic"` | Categoria do log: `traffic` é sessão, `event` é evento do próprio aparelho, `utm` é inspeção de conteúdo |
| `subtype` | `"forward"` | Subcategoria: `forward` é tráfego que atravessa, `local` é destinado ao próprio firewall, `vpn` é túnel, `webfilter` e `ips` são inspeção |
| `level` | `"notice"` | Severidade atribuída pelo FortiOS (`notice`, `warning`, `alert`, `critical`). **Quem a escolhe é o fabricante**, não o seu SOC |
| `srcip` | `10.10.20.45` | IP de origem |
| `srcport` | `51422` | Porta de origem, efêmera e sorteada pelo cliente |
| `dstip` | `10.10.5.10` | IP de destino |
| `dstport` | `110` | Porta de destino — é ela que aponta o serviço |
| `proto` | `6` | Número do protocolo IP: **`6` é TCP, `17` é UDP, `1` é ICMP**. Vem em número, não em nome |
| `action` | `"accept"` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |
| `policyid` | `17` | **Número da regra que decidiu.** Sem ele não se sabe por que o tráfego passou ou parou |
| `service` | `"POP3"` | Nome do **objeto de serviço** do FortiGate, não a porta literal. Um objeto chamado `HTTPS` pode ter sido configurado noutra porta |
| `sentbyte` | `2140` | Bytes enviados **pela origem**. O ponto de vista é o da origem, não do firewall |
| `rcvdbyte` | `418992` | Bytes recebidos pela origem. **Comparar com `sentbyte` é o que revela exfiltração** |
| `duration` | `96` | Duração da sessão em **segundos** |
| `app` | `"POP3"` | Aplicação identificada pelo controle de aplicação, por inspeção do conteúdo |
| `user` | `"jsilva"` | Conta autenticada — o que transforma "um IP" em "uma pessoa" |

</details>

Campos: `srcip/srcport` = origem; `dstip/dstport` = destino (110 = POP3); `proto=6` = TCP; `rcvdbyte` alto = muito dado descendo (caixa inteira sendo baixada); `action=accept` = a política 17 permitiu.

**Riscos.** Credencial em texto claro (captura passiva na rede); exfiltração de caixa postal inteira; uso como canal de comando e controle rudimentar.

**Alertas comuns de SOC.** "POP3 em texto claro para fora da rede", "login POP3 de país incomum", "volume anormal de download POP3".

**O que o SOC N1 observa.** Normal: impressora conhecida falando POP3 com o servidor interno. Suspeito: estação de usuário falando POP3 com IP público (ex.: `203.0.113.77`) e `rcvdbyte` na casa dos megabytes.

**Erro comum de analista júnior.** Fechar o caso porque "é só e-mail". POP3 para IP externo em texto claro é exfiltração até prova em contrário.

---

## Porta 123 — NTP (Network Time Protocol)

**O que é.** É o relógio da rede. Pense num maestro dando o compasso: se cada músico tocar no seu próprio tempo, a orquestra vira barulho. O NTP dá o compasso para todos os servidores, firewalls e estações.

**Como funciona.** UDP/123. Servidores organizados em camadas (stratum 0 = relógio atômico/GPS; stratum 1 = servidor ligado direto nele; e assim por diante). O cliente pergunta a hora, mede o atraso do caminho e ajusta o próprio relógio.

### Por que relógio certo é crítico para o SOC (pergunta clássica de entrevista)

1. **Correlação no SIEM.** O SIEM (Security Information and Event Management, a plataforma que junta os logs de todos os equipamentos) monta a linha do tempo do ataque. Se o firewall está 7 minutos adiantado e o controlador de domínio 3 minutos atrasado, o "logon suspeito" aparece *antes* da conexão que o originou. A investigação vira ficção.
2. **Kerberos.** O protocolo de autenticação do Active Directory usa carimbos de tempo para impedir *replay* (reenviar um ticket capturado). A tolerância padrão é de **5 minutos**. Fora disso, a autenticação falha com `KRB_AP_ERR_SKEW` e o usuário simplesmente não entra.
3. **Certificados e TLS.** Validade de certificado é comparada com o relógio local. Relógio errado = erro de certificado em massa.

**Exemplo prático.** Servidor `srv-app-03` (`10.10.7.30`) perde o NTP interno e deriva 9 minutos. `maria.costa` para de conseguir acessar o compartilhamento de rede.

**Como aparece em log** (Windows Security, falha Kerberos):

```
Event ID: 4771
Log Name: Security
Source: Microsoft-Windows-Security-Auditing
Kerberos pre-authentication failed.
Account Name:      maria.costa
Service Name:      krbtgt/CORP.LOCAL
Client Address:    ::ffff:10.10.7.30
Failure Code:      0x25
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `Event ID` | `4771` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não. `4771` = **pré-autenticação** Kerberos falhou |
| `Log Name` | `Security` | Qual registro guarda o evento: `Security` é o de auditoria, `System` o do sistema, `Microsoft-Windows-Sysmon/Operational` o do Sysmon |
| `Source` | `Microsoft-Windows-Security-Auditing` | Provedor que gerou o evento |
| `Account Name` | `maria.costa` | A conta envolvida. Terminada em `$` é **conta de computador**, não de pessoa |
| `Service Name` | `krbtgt/CORP.LOCAL` | O serviço para o qual o ticket foi pedido. Terminado em `$` é uma conta de computador |
| `Client Address` | `::ffff:10.10.7.30` | IP do cliente que pediu o ticket. Vem como `::ffff:10.10.10.50` — **é IPv4 embrulhado em notação IPv6**, não um endereço IPv6 |
| `Failure Code` | `0x25` | **Código de falha do Kerberos.** `0x25` = **relógio fora de sincronia** entre cliente e DC (o Kerberos tolera poucos minutos) |

</details>

`Failure Code 0x25` = **KDC_ERR_SKEW**: diferença de relógio entre cliente e KDC (Key Distribution Center, o serviço do controlador de domínio que emite tickets). Não é ataque — é NTP quebrado.

### Amplificação NTP (monlist)

O comando de diagnóstico `monlist` (implementações antigas do `ntpd`) devolve a lista dos últimos 600 clientes atendidos. Uma pergunta de ~230 bytes gera uma resposta de vários kilobytes: fator de amplificação que já passou de **500x**. O atacante forja o IP de origem (spoofing) e o servidor NTP despeja o tráfego na vítima. É DDoS refletido — MITRE ATT&CK **T1498.002 (Reflection Amplification)**.

**Como aparece em log** (Suricata EVE JSON):

```json
{"timestamp":"2026-09-03T14:22:09.771Z","event_type":"alert","src_ip":"198.51.100.42","src_port":39122,"dest_ip":"10.10.5.60","dest_port":123,"proto":"UDP","alert":{"signature":"ET DOS Possible NTP DDoS Inbound Frequent Un-Authed MON_LIST Requests IMPL 0x03","category":"Attempted Denial of Service","severity":2}}
```

**Riscos.** Servidor NTP interno exposto à Internet virando arma de DDoS; manipulação de hora para invalidar logs e quebrar autenticação.

**Alertas comuns de SOC.** "NTP monlist request", "estação usando NTP externo não autorizado", "clock skew em massa no domínio".

**O que o SOC N1 observa.** Normal: estações falando NTP só com o controlador de domínio. Suspeito: máquina falando UDP/123 direto com IP público, ou pico de UDP/123 de entrada.

**Erro comum de analista júnior.** Tratar dezenas de eventos 4771/0x25 como ataque de força bruta. Código `0x25` é relógio, não senha.

---

## Porta 135 — RPC / DCOM (Remote Procedure Call / Distributed COM)

**O que é.** É a recepção de um prédio. Você chega, pergunta "onde fica o setor X?" e a recepcionista diz "sala 49172". A porta 135 é o *endpoint mapper*: ela não faz o trabalho, ela diz em qual porta alta (dinâmica, faixa 49152–65535 no Windows moderno) o serviço realmente está.

**Quando é utilizado.** Administração remota legítima: WMI (Windows Management Instrumentation), replicação do Active Directory, MMC, agentes de inventário, PsExec e Impacket em operações administrativas — e também em mãos erradas.

**Ligação com movimento lateral.** Executar comando remoto via WMI/DCOM é técnica clássica: MITRE **T1021.003 (Remote Services: DCOM)** e **T1047 (Windows Management Instrumentation)**. O rastro típico: conexão 135 → porta alta, seguida de logon tipo 3 na máquina destino e um processo filho de `WmiPrvSE.exe`.

**Exemplo prático.** A conta `svc_backup` sai de `10.10.20.45` (estação comum, não é servidor de backup) para `10.10.7.30` na 135.

**Como aparece em log** (Sysmon Event ID 1 no destino):

```
Event ID: 1 (Process Create)
UtcTime: 2026-09-03 15:04:11.220
Image: C:\Windows\System32\cmd.exe
CommandLine: cmd.exe /c ipconfig /all
ParentImage: C:\Windows\System32\wbem\WmiPrvSE.exe
User: CORP\svc_backup
LogonId: 0x3E7A9
```

`ParentImage = WmiPrvSE.exe` é a assinatura de execução remota por WMI. Um `cmd.exe` nascendo do provedor WMI quase nunca é uso normal de estação.

**Consulta SPL (Splunk):**

```
index=windows EventCode=1 ParentImage="*\\WmiPrvSE.exe"
| search Image IN ("*\\cmd.exe","*\\powershell.exe","*\\rundll32.exe")
| stats count values(CommandLine) as cmds by host, User
| where count > 0
```

Linha 1 filtra criação de processo com pai WMI; linha 2 restringe a interpretadores; linha 3 agrupa por host e conta.

**Consulta KQL (Microsoft Defender / Sentinel):**

```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"          // pai = provedor WMI
| where FileName in~ ("cmd.exe","powershell.exe","rundll32.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

**Riscos.** Execução remota de código, movimento lateral, coleta de informação. Porta 135 exposta à Internet é achado crítico.

**Alertas comuns de SOC.** "DCOM lateral movement", "WMI remote process creation", "RPC scan interno".

**Erro comum de analista júnior.** Ver 135 e concluir "é só o Windows conversando". Contexto manda: servidor→servidor pode ser normal; estação→estação quase nunca é.

---

## Portas 137, 138 e 139 — NetBIOS

Trio legado do Windows, ainda vivo em muitas redes.

| Porta | Nome | Transporte | Função |
|---|---|---|---|
| 137 | NetBIOS Name Service (NBNS/NBT-NS) | UDP | Resolve nomes na rede local por broadcast |
| 138 | NetBIOS Datagram Service | UDP | Mensagens sem conexão, navegação de rede |
| 139 | NetBIOS Session Service | TCP | Sessão de compartilhamento de arquivos (SMB antigo) |

**Analogia.** O NBNS é gritar no corredor: "alguém aí é o SERVIDOR-RH?". Quem responder primeiro é aceito como verdadeiro. Não há verificação de identidade.

**O ataque de poisoning (envenenamento).** Ferramentas como **Responder** ficam ouvindo esses gritos e respondem "sou eu" a qualquer nome não resolvido — inclusive erros de digitação (`\\servidorr-rh`). A vítima então tenta autenticar no atacante e entrega o desafio/resposta NTLM, que pode ser quebrado offline. MITRE **T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)**.

**Como aparece em log** (Zeek `conn.log`, campos separados por tabulação):

```
#fields ts  uid  id.orig_h  id.orig_p  id.resp_h  id.resp_p  proto  service  duration  orig_bytes  resp_bytes  conn_state
1788451331.117  CqR2k3xE1  10.10.20.45  137  10.10.20.99  137  udp  dns  0.004  50  62  SF
1788451331.402  CmT9p1aQ4  10.10.20.45  49711  10.10.20.99  445  tcp  smb  1.221  1840  980  SF
```

<details><summary>Ver legenda</summary>

| Campo | 1ª linha (NetBIOS) / 2ª linha (SMB) | O que significa |
|---|---|---|
| `ts` | `1788451331.117` / `1788451331.402` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos — as duas ações distam **285 milissegundos**, o que exclui ação humana |
| `uid` | `CqR2k3xE1` / `CmT9p1aQ4` | Duas conexões distintas, logo dois `uid` |
| `id.orig_h` | `10.10.20.45` | A mesma estação nas duas: é ela a vítima |
| `id.orig_p` | `137` / `49711` | Porta de origem. Na 1ª é **137, e não uma porta efêmera** — o NetBIOS name service fala de 137 para 137 |
| `id.resp_h` | `10.10.20.99` | Quem respondeu: outra **estação**, não um servidor. É o ponto central do achado |
| `id.resp_p` | `137` / `445` | Destino: primeiro resolução de nome NetBIOS, depois SMB |
| `proto` | `udp` / `tcp` | NetBIOS name service sobre UDP; SMB sobre TCP |
| `service` | `dns` / `smb` | O Zeek rotula o NetBIOS name service como `dns` porque o formato da mensagem é o mesmo — não se assuste com o rótulo |
| `duration` | `0.004` / `1.221` | Duração em segundos |
| `orig_bytes` / `resp_bytes` | `50`/`62` e `1840`/`980` | Payload em cada direção |
| `conn_state` | `SF` | As duas completaram. **É isso que torna o caso grave**: a autenticação SMB contra a máquina errada teve sucesso |

</details>

Leitura: a estação `.45` perguntou um nome NetBIOS, quem respondeu foi `.99` (uma estação, não um servidor) e logo em seguida a `.45` autenticou SMB contra a `.99`. Esse encadeamento em segundos é a marca do poisoning.

**Riscos.** Roubo de hash NTLM, relay para outros servidores, escalonamento até conta administrativa.

**Alertas comuns de SOC.** "NBT-NS response from non-server host", "múltiplas respostas NBNS do mesmo host", "SMB authentication to workstation".

**O que o SOC N1 observa.** Normal: broadcasts 137/138 constantes e sem resposta (ruído de fundo). Suspeito: um único host respondendo a *muitos* nomes diferentes.

**Erro comum de analista júnior.** Descartar como "protocolo velho, ignora". É justamente o legado que sustenta o ataque.

---

## Porta 143 — IMAP (Internet Message Access Protocol)

**O que é.** Diferente do POP3, aqui a caixa continua no servidor e o cliente apenas espelha o conteúdo. É a caixa postal que você consulta de vários lugares — celular, notebook, navegador — e todos veem o mesmo estado.

**Como funciona.** TCP/143 em claro; TCP/993 é IMAPS (com TLS). Suporta pastas, marcação de lido/não lido, busca no servidor.

**Riscos.** Credencial em claro na 143; **password spraying** contra IMAP para burlar MFA (autenticação multifator), já que protocolos legados frequentemente não a exigem; criação de regra de encaminhamento oculta após o comprometimento.

**Como aparece em log** (Cisco ASA):

```
%ASA-6-302013: Built inbound TCP connection 884512 for outside:203.0.113.90/49330 (203.0.113.90/49330) to inside:10.10.5.10/143 (198.51.100.20/143)
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `%ASA` | `%ASA` | Etiqueta do produto: identifica a linha como vinda de um firewall ASA |
| severidade | `6` | Escala syslog do Cisco, de 0 (emergência) a 7 (depuração): `6` é **informational**. **Severidade baixa não quer dizer evento sem importância** — quem a escolhe é o fabricante, não o seu SOC |
| *message ID* | `302013` | Conexão TCP construída — entrou na tabela de estado. **É por este número que se escreve a regra no SIEM**: o texto da mensagem muda entre versões do software, o ID não |
| direção | `inbound` | **Quem iniciou**, não a direção dos bytes: `outbound` é de dentro para fora, `inbound` é de fora para dentro |
| id da conexão | `884512` | Número da conexão na tabela de estado. **É a chave para casar com o `302014`** que a encerra |
| lado remoto | `outside:203.0.113.90/49330` | Interface, IP e porta do host **remoto**. Vem primeiro, logo depois do `for` — é isso que faz a linha parecer invertida |
| *(entre parênteses)* | `(203.0.113.90/49330)` | O endereço **traduzido** desse lado. Igual ao real significa que não houve NAT nesta ponta |
| lado local | `inside:10.10.5.10/143` | Interface, IP e porta do host **local**, antes da tradução |
| *(entre parênteses)* | `(198.51.100.20/143)` | O endereço com que o host local saiu. **Este par — IP público mais porta — é o que desfaz o NAT** num pedido externo |
| — | — | **Porta 143 é IMAP sem TLS** (a versão cifrada é a 993), exposta à Internet através de NAT: `10.10.5.10` é publicado como `198.51.100.20`. Credenciais de correio a atravessar a rede em claro |

</details>


**Alertas comuns de SOC.** "Legacy auth IMAP sign-in", "IMAP brute force", "impossible travel em cliente IMAP".

**Erro comum de analista júnior.** Ver muitas falhas seguidas de um sucesso e fechar como "usuário esqueceu a senha". Em spraying o padrão é *poucas* tentativas para *muitas* contas.

---

## Porta 161 — SNMP (Simple Network Management Protocol)

**O que é.** É o painel de instrumentos dos equipamentos de rede. O sistema de monitoração pergunta ao switch "quanto de tráfego passou nesta porta?" e recebe a resposta. UDP/161 para consultas; UDP/162 para *traps* (o equipamento avisando sozinho que algo aconteceu).

**Versões.**

| Versão | Autenticação | Cifra | Veredito |
|---|---|---|---|
| v1 | Community string em texto claro | Não | Obsoleta |
| v2c | Community string em texto claro | Não | Ainda comum, insegura |
| v3 | Usuário + autenticação (SHA) | Sim (AES) | Recomendada |

A *community string* funciona como uma senha compartilhada. Os padrões de fábrica são `public` (leitura) e `private` (leitura e escrita) — e trafegam legíveis no fio. Com `private`, um atacante pode **alterar** configuração do equipamento.

**Reconhecimento de rede.** Uma consulta SNMP autorizada pelo `public` entrega inventário completo: modelo, versão de firmware, interfaces, tabela ARP, tabela de roteamento, nomes de usuários locais em alguns casos. É reconhecimento de altíssimo valor — MITRE **T1046 (Network Service Discovery)**.

**Amplificação.** A consulta `GetBulk` gera resposta muito maior que a pergunta; com IP de origem forjado, vira refletor de DDoS (amplificação na faixa de 6x a mais de 100x, dependendo do dispositivo).

**Como aparece em log** (Palo Alto, CSV THREAT — campos principais):

```
1,2026/09/03 16:41:02,013201002145,THREAT,vulnerability,2561,2026/09/03 16:41:02,198.51.100.66,10.10.1.1,0.0.0.0,0.0.0.0,rule-inbound-mgmt,,,snmp,vsys1,untrust,mgmt,ethernet1/1,ethernet1/3,LOG-PROFILE,2026/09/03 16:41:02,0,1,48122,161,0,0,0x2000,udp,alert,"SNMP Default Community String Usage",40021,any,medium
```

Campos-chave: `THREAT` = log de ameaça; origem `198.51.100.66` (externa) para `10.10.1.1` (switch interno); `udp`, porta destino `161`; assinatura `SNMP Default Community String Usage`; severidade `medium`.

**O que o SOC N1 observa.** Normal: apenas o servidor de monitoração (ex.: `10.10.9.20`) falando SNMP com os equipamentos. Suspeito: qualquer outra origem, e principalmente origem externa.

**Erro comum de analista júnior.** Ver `medium` e despriorizar. Community string padrão exposta na borda é caminho direto para reconhecimento e, com `private`, para alteração de configuração.

---

## Tabela-resumo — portas desta parte

| Porta | Protocolo | TCP/UDP | É cifrado? | Risco | Alerta típico |
|---|---|---|---|---|---|
| 110 | POP3 | TCP | Não (995 = POP3S) | Alto | Credencial em claro / download massivo de caixa |
| 123 | NTP | UDP | Não (autenticação opcional) | Médio | monlist / amplificação / clock skew no domínio |
| 135 | RPC-DCOM | TCP | Não (integridade via RPC) | Alto | Execução remota WMI / movimento lateral |
| 137 | NetBIOS Name Service | UDP | Não | Alto | NBT-NS poisoning (Responder) |
| 138 | NetBIOS Datagram | UDP | Não | Médio | Broadcast anômalo / enumeração |
| 139 | NetBIOS Session | TCP | Não | Alto | SMB legado / relay NTLM |
| 143 | IMAP | TCP | Não (993 = IMAPS) | Alto | Legacy auth / password spraying |
| 161 | SNMP v1/v2c | UDP | Não (v3 = cifrado) | Alto | Community string padrão / amplificação |

---

### Exercícios — Protocolos 110 a 161 e tabela-resumo

1. **Leitura de log.** Você recebe 340 eventos `4771` com `Failure Code: 0x25` de 12 servidores diferentes, todos no intervalo de 20 minutos. Qual a causa mais provável e qual o próximo passo?
2. **Verdadeiro ou falso positivo?** Alerta "SNMP Default Community String Usage" com origem `10.10.9.20` e destino `10.10.1.1`, porta UDP/161, ocorrendo a cada 5 minutos há 8 meses. O que você conclui?
3. **Próximo passo da investigação.** Zeek mostra `10.10.20.45` consultando NBNS e a estação `10.10.20.99` respondendo a 47 nomes distintos em 3 minutos, seguida de conexões SMB para a `.99`. O que você faz primeiro?
4. **Cálculo.** Um servidor NTP vulnerável responde `monlist` com 4.600 bytes para uma consulta de 230 bytes. Qual o fator de amplificação? Se o atacante enviar 1.000 consultas por segundo, qual o tráfego gerado contra a vítima em megabits por segundo?
5. **Decisão.** Palo Alto registra `10.10.20.45` (estação de `jsilva`) conectando em `203.0.113.77:110` com `rcvdbyte` de 512 MB às 03:12. Classifique a severidade e liste três ações imediatas.

<details><summary>Ver gabarito</summary>

**1.** `0x25` é **KDC_ERR_SKEW** — diferença de relógio, não senha errada. O volume em vários servidores ao mesmo tempo aponta para falha da fonte de tempo (servidor NTP interno fora do ar ou o PDC Emulator sem sincronia externa). Próximo passo: verificar o serviço de tempo no controlador de domínio com o papel PDC Emulator, confirmar alcance ao servidor NTP e comparar relógios. Só depois de descartar isso é que se cogita ataque. Erro clássico: abrir incidente de força bruta.

**2.** **Falso positivo operacional** — mas com dívida de segurança real. A origem é o servidor de monitoração interno, o destino é um switch, a periodicidade é fixa e o histórico é longo: é a coleta legítima. Porém a assinatura confirma que a community string é a padrão (`public`), em SNMP v1/v2c, sem cifra. Fecha-se o alerta como benigno **e abre-se um item para a equipe de rede**: migrar para SNMPv3 ou, no mínimo, trocar a community e restringir por lista de acesso. Fechar sem registrar a recomendação é meio serviço.

**3.** É o padrão clássico de **NBT-NS poisoning** (T1557.001), típico de Responder rodando na `10.10.20.99`. Uma estação não tem motivo para responder a dezenas de nomes distintos. Primeiro passo: **isolar a `10.10.20.99` da rede** (contenção) e preservar evidência — não desligar a máquina, para não perder memória. Em seguida: identificar quem está logado nela, verificar eventos 4624 tipo 3 chegando nela (contas que autenticaram no atacante) e forçar troca de senha dessas contas. Escalar para N2.

**4.** Fator = 4.600 ÷ 230 = **20x**. Tráfego = 1.000 × 4.600 bytes = 4.600.000 bytes/s. Em bits: 4.600.000 × 8 = 36.800.000 bits/s ≈ **36,8 Mbps**. Observação: com um servidor devolvendo listas completas o fator real pode passar de 500x — daí o `monlist` ter sido historicamente um dos piores vetores de amplificação.

**5.** **Severidade alta / possível exfiltração de dados.** Justificativa: POP3 em texto claro, destino externo, 512 MB baixados, fora do horário. Três ações: (a) isolar ou bloquear a estação `10.10.20.45` e o destino `203.0.113.77` no firewall; (b) verificar autenticação da conta `jsilva` nas últimas 72 horas (4624/4625, origens, MFA) e forçar troca de senha; (c) escalar para N2 com evidências — logs de tráfego, processo responsável (Sysmon ID 1 e ID 3 correlacionados pelo `ProcessGuid`) e reputação do IP de destino. Não fechar como "usuário configurou e-mail pessoal" sem confirmar com o próprio usuário e com o gestor.

</details>

---

## Mini-laboratório — Portas e protocolos essenciais

**Objetivo.** Ver com os próprios olhos o tráfego das portas estudadas e reconhecê-lo em captura.

**Pré-requisitos.** VirtualBox com uma máquina virtual Linux (Ubuntu Server é suficiente), Wireshark instalado, `tcpdump` e `nmap` na VM, rede em modo *Host-only* ou *NAT Network* — **nunca** aponte o `nmap` para redes que não sejam suas.

**Passo 1 — Preparar a captura.**
```bash
sudo tcpdump -i any -n -w /tmp/lab-portas.pcap 'port 110 or port 123 or port 135 or port 137 or port 138 or port 139 or port 143 or port 161'
```
Observe: o filtro BPF limita a captura só às portas do módulo. `-n` evita resolução de nomes (que geraria tráfego extra).

**Passo 2 — Gerar tráfego NTP legítimo.**
```bash
ntpdate -q pool.ntp.org
```
Observe: no Wireshark, filtro `ntp`. Veja os campos *Stratum*, *Reference Timestamp* e *Transmit Timestamp*. Critério: pelo menos um par pergunta/resposta UDP/123.

**Passo 3 — Descoberta de portas em alvo próprio.**
```bash
sudo nmap -sS -p 110,123,135,137,139,143,161 -sV 192.168.56.0/24
```
Observe: a coluna STATE (`open`, `closed`, `filtered`) e a coluna SERVICE. Em Wireshark, filtro `tcp.flags.syn==1 && tcp.flags.ack==0` mostra o SYN scan; `tcp.flags.reset==1` mostra as portas fechadas respondendo RST.

**Passo 4 — Ver NetBIOS na prática.** Em uma VM Windows na mesma rede, abra o Explorador e digite um nome inexistente (`\\servidor-que-nao-existe`).
Observe no Wireshark: filtro `nbns`. Você verá o broadcast de consulta sem resposta. Esse é exatamente o pedido que um atacante responderia.

**Passo 5 — Analisar captura pública.** Baixe uma captura da wiki oficial do Wireshark (Sample Captures) contendo SNMP e aplique o filtro `snmp`. Expanda o campo `community` — a string aparece legível. É a prova visual de por que v1/v2c é inseguro.

**Critério de sucesso.** Você consegue: (1) identificar cada protocolo pelo filtro correto no Wireshark; (2) explicar por que a community string é visível; (3) apontar no `conn.log` do Zeek (se usar Security Onion) qual campo indica o serviço.

---

## O que um SOC Level 1 realmente precisa saber

- 🟢 **Porta é o "número do apartamento"** do serviço; IP é o prédio. Sem porta, não se sabe com quem se está falando.
- 🟢 **Decorar o mapa básico**: 20/21 FTP, 22 SSH, 23 Telnet, 25 SMTP, 53 DNS, 80 HTTP, 110 POP3, 123 NTP, 135 RPC, 137-139 NetBIOS, 143 IMAP, 161 SNMP, 443 HTTPS, 445 SMB.
- 🟢 **Protocolo em texto claro = risco imediato**: Telnet, FTP, POP3, IMAP, SNMP v1/v2c. Existe versão cifrada para praticamente todos.
- 🟢 **TCP tem handshake (SYN, SYN-ACK, ACK); UDP não tem.** Por isso UDP é o transporte preferido para amplificação (DNS, NTP, SNMP).
- 🟢 **Contexto vale mais que a porta.** A mesma porta 135 é rotina entre servidores e é alarme entre estações.
- 🟡 **Relógio sincronizado é pré-requisito de investigação.** Sem NTP, a linha do tempo do SIEM não presta e o Kerberos quebra (tolerância de 5 minutos, erro `0x25`).
- 🟡 **NetBIOS/LLMNR são o combustível do Responder.** Um host respondendo a muitos nomes diferentes é sinal forte de poisoning (T1557.001).
- 🟡 **Autenticação legada (POP3/IMAP) contorna MFA.** Spraying nesses protocolos é vetor comum de comprometimento de conta.
- 🟡 **Saber ler os campos do log importa mais que decorar produto**: origem, destino, porta, ação, bytes, usuário, horário.
- 🔴 **Movimento lateral por DCOM/WMI** (T1021.003, T1047) deixa rastro de `WmiPrvSE.exe` como processo pai — saiba montar essa consulta em SPL e KQL.
- 🔴 **Amplificação refletida** (T1498.002): entenda o cálculo do fator e por que servidor de infraestrutura nunca deve ficar exposto à Internet.
- 🔴 **Nunca feche alerta só porque a severidade é média.** Community string padrão, POP3 externo e SMB para estação são achados que escalam.

---

## Resumo em 10 linhas

1. Porta identifica o serviço dentro do host; TCP é orientado a conexão, UDP não é.
2. As portas conhecidas (0–1023) concentram os serviços clássicos que o SOC vê todo dia.
3. Protocolos antigos nasceram sem cifra: FTP, Telnet, POP3, IMAP e SNMP v1/v2c expõem credenciais.
4. Para quase todos existe o equivalente cifrado (SFTP/FTPS, SSH, POP3S 995, IMAPS 993, SNMPv3).
5. NTP na UDP/123 sustenta a correlação no SIEM e o Kerberos; erro `0x25` é relógio, não senha.
6. RPC/DCOM na 135 aponta para portas altas e é caminho de execução remota via WMI.
7. NetBIOS 137/138/139 é legado sem verificação de identidade — base do poisoning com Responder.
8. SNMP entrega inventário completo da rede e, com community `private`, permite alterar configuração.
9. UDP sem estado permite forjar origem: NTP e SNMP viram refletores de DDoS amplificado.
10. O trabalho do N1 é ler o log com contexto — origem, destino, horário, volume — e escalar com evidência.



---
