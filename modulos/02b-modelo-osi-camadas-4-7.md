# Módulo 2 — Modelo OSI: Camadas 4 a 7

## Por que este módulo importa para o SOC

Quase todo alerta que chega na fila de um analista de SOC Nível 1 (N1) nasce em uma destas quatro camadas. É na Camada 4 que se decide se uma conexão existiu de verdade ou foi só uma tentativa; é na Camada 7 que aparece o nome do domínio acessado, o comando digitado e o arquivo baixado. Um analista que sabe ler o campo `conn_state` do Zeek ou o `session_end_reason` do firewall fecha um falso positivo em dois minutos. Quem não sabe, escala tudo para o N2 e vira gargalo. Este módulo transforma essas camadas em algo prático: o que olhar, onde olhar e o que significa.

### Índice do módulo

- Camada 4 — Transporte
- Camadas 5 e 6 — Sessão e Apresentação
- Camada 7 — Aplicação e tabela-resumo das 7 camadas

---

Este trecho é a continuação do Módulo 2: nas camadas 1 a 3 vimos o cabo, o quadro Ethernet e o endereço IP que leva o pacote de uma rede a outra. Agora subimos um degrau — chegamos onde o SOC realmente trabalha.

## Camada 4 — Transporte

### O que é

Imagine um prédio de escritórios com um único endereço na rua. O carteiro (Camada 3, o IP) entrega tudo na portaria. Mas dentro do prédio existem centenas de salas. A Camada 4 é o número da sala: ela diz **qual programa**, dentro daquela máquina, deve receber os dados. Esse número da sala se chama **porta**.

A Camada 4 (Transporte) tem três trabalhos: identificar a aplicação de destino (porta), decidir se a entrega precisa de confirmação e controlar o ritmo do envio para não afogar o receptor.

### Como funciona: TCP e UDP

Existem dois protocolos principais. **TCP** (Transmission Control Protocol, ou Protocolo de Controle de Transmissão) é a carta registrada com aviso de recebimento. **UDP** (User Datagram Protocol, ou Protocolo de Datagrama de Usuário) é o cartão postal: você joga na caixa e torce.

| Característica | TCP | UDP |
|---|---|---|
| Estabelece conexão antes? | Sim (three-way handshake) | Não |
| Confirma o recebimento? | Sim (ACK) | Não |
| Retransmite o que se perdeu? | Sim | Não |
| Garante a ordem de chegada? | Sim (número de sequência) | Não |
| Controle de fluxo (janela) | Sim | Não |
| Tamanho do cabeçalho | 20 bytes (mínimo) | 8 bytes |
| Velocidade | Menor | Maior |
| Uso típico | HTTPS (443), SSH (22), RDP (3389), SMB (445) | DNS (53), NTP (123), SNMP (161), VPN (500/4500) |
| Visibilidade no SOC | Alta — dá para ver o estado da sessão | Baixa — sem estado, mais fácil de forjar |

Portas vão de 1 a 65535. De 1 a 1023 são as **portas conhecidas** (serviços de sistema); de 1024 a 49151 são registradas; de 49152 a 65535 são as **portas efêmeras**, que o cliente sorteia para si mesmo em cada conexão. Por isso, no log, a porta de origem do usuário é sempre um número alto e aleatório — isso é normal, não é anomalia.

### O three-way handshake

Antes de trocar qualquer dado, o TCP faz um aperto de mão em três tempos. É como ligar para alguém: "Alô?" / "Alô, estou ouvindo" / "Ótimo, então escuta".

```
Cliente 10.10.20.45:51422            Servidor 203.0.113.77:443
        |                                        |
        |------- SYN, Seq=1000 ----------------->|   1) Quero abrir
        |                                        |
        |<-- SYN+ACK, Seq=5000, Ack=1001 --------|   2) Aceito, e também quero
        |                                        |
        |------- ACK, Seq=1001, Ack=5001 ------->|   3) Confirmado, conexão aberta
        |                                        |
        |========= dados (PSH+ACK) =============>|
```

O **número de sequência** (Seq) é o número da primeira letra do pedaço enviado; o **número de confirmação** (Ack) é o número da próxima letra que o receptor espera receber. Se o pedaço não chega, não vem Ack e o emissor **retransmite** depois de um tempo. A **janela** (window) é quantos bytes o receptor aguenta receber sem confirmar — janela zero significa "pare, estou cheio". O **MSS** (Maximum Segment Size, tamanho máximo do segmento) é o maior pedaço de dados que cabe em um pacote, tipicamente 1460 bytes numa rede Ethernet com MTU de 1500.

### As flags TCP

| Flag | Nome | O que significa |
|---|---|---|
| SYN | Synchronize | Pedido de abertura de conexão; sincroniza números de sequência |
| ACK | Acknowledge | Confirma o recebimento de dados |
| FIN | Finish | Encerramento educado: "acabei de falar" |
| RST | Reset | Encerramento abrupto: "corta agora"; também é a resposta a uma porta fechada |
| PSH | Push | Entregue esses dados à aplicação imediatamente, sem esperar o buffer encher |
| URG | Urgent | Marca dados urgentes; praticamente não é usado hoje e é suspeito quando aparece |

**Encerramento com FIN**: cada lado manda seu FIN e recebe um ACK — quatro pacotes, conexão fechada com educação. **Encerramento com RST**: um único pacote derruba tudo na hora. RST é normal quando um serviço não existe naquela porta, quando o firewall corta a sessão ou quando a aplicação trava. Uma *rajada* de RST, porém, merece olhar.

### Exemplo prático

A estação `NB-JSILVA` (10.10.20.45), do usuário `jsilva`, abre uma sessão HTTPS para `portal.example.com` (203.0.113.77).

### Como aparece nos logs

Palo Alto, log TRAFFIC em CSV (campos selecionados):

```
2026-09-03 09:14:22,012801234567,TRAFFIC,end,10.10.20.45,203.0.113.77,
51422,443,ssl,tcp,allow,VLAN-USERS,INTERNET,ethernet1/2,ethernet1/1,
1842,24,1310,1114,tcp-fin,jsilva
```

<details><summary>Ver legenda</summary>

| Posição no exemplo | Campo | Valor | O que significa |
|---|---|---|---|
| 1 | Receive Time | `2026-09-03 09:14:22` | Quando o firewall recebeu o evento |
| 2 | Serial Number | `012801234567` | Número de série do equipamento |
| 3 / 4 | Type / Subtype | `TRAFFIC` / `end` | Log de sessão, registrado no fim da conexão |
| 5 / 6 | Source / Destination Address | `10.10.20.45` / `203.0.113.77` | Origem e destino — **camada 3** |
| 7 / 8 | Source / Destination Port | `51422` / `443` | Porta efêmera de origem e porta de destino — **camada 4** |
| 9 | Application | `ssl` | Aplicação identificada por inspeção — **camada 7** |
| 10 | Protocol | `tcp` | Protocolo de transporte |
| 11 | Action | `allow` | O veredito da política |
| 12 / 13 | Source / Destination Zone | `VLAN-USERS` / `INTERNET` | As zonas de origem e destino |
| 14 / 15 | Inbound / Outbound Interface | `ethernet1/2` / `ethernet1/1` | Interfaces física de entrada e de saída |
| 16 | Bytes | `1842` | Total nos dois sentidos |
| 17 | Packets | `24` | Total de pacotes |
| 18 / 19 | Bytes Sent / Received | `1310` / `1114` | Volume em cada direção |
| 20 | Session End Reason | `tcp-fin` | **O campo que o N1 mais usa para triagem.** `tcp-fin` = fim normal; `tcp-rst-from-client`/`-server` = alguém cortou; `aged-out` = a sessão ficou parada e expirou (típico de conexão que nunca completou ou de canal ocioso); `policy-deny` = barrada pela política |
| 21 | Source User | `jsilva` | Usuário resolvido pelo User-ID |
| — | — | — | **Este exemplo é um recorte de campos selecionados**, não a ordem real do PAN-OS |

</details>


FortiGate, formato chave=valor:

```
date=2026-09-03 time=09:15:41 devname="FGT-EDGE-01" type="traffic" subtype="forward"
srcip=10.10.20.45 srcport=51988 dstip=203.0.113.90 dstport=445 proto=6
action="deny" policyid=12 service="SMB" sentbyte=0 rcvdbyte=0 duration=0 user="jsilva"
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `date` | `2026-09-03` | Data local **do equipamento**, não UTC. Correlacionar com um log em UTC sem acertar o fuso desalinha a timeline |
| `time` | `09:15:41` | Hora local do equipamento |
| `devname` | `"FGT-EDGE-01"` | Nome do equipamento que gerou o log |
| `type` | `"traffic"` | Categoria do log: `traffic` é sessão, `event` é evento do próprio aparelho, `utm` é inspeção de conteúdo |
| `subtype` | `"forward"` | Subcategoria: `forward` é tráfego que atravessa, `local` é destinado ao próprio firewall, `vpn` é túnel, `webfilter` e `ips` são inspeção |
| `srcip` | `10.10.20.45` | IP de origem |
| `srcport` | `51988` | Porta de origem, efêmera e sorteada pelo cliente |
| `dstip` | `203.0.113.90` | IP de destino |
| `dstport` | `445` | Porta de destino — é ela que aponta o serviço |
| `proto` | `6` | Número do protocolo IP: **`6` é TCP, `17` é UDP, `1` é ICMP**. Vem em número, não em nome |
| `action` | `"deny"` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |
| `policyid` | `12` | **Número da regra que decidiu.** Sem ele não se sabe por que o tráfego passou ou parou |
| `service` | `"SMB"` | Nome do **objeto de serviço** do FortiGate, não a porta literal. Um objeto chamado `HTTPS` pode ter sido configurado noutra porta |
| `sentbyte` | `0` | Bytes enviados **pela origem**. O ponto de vista é o da origem, não do firewall |
| `rcvdbyte` | `0` | Bytes recebidos pela origem. **Comparar com `sentbyte` é o que revela exfiltração** |
| `duration` | `0` | Duração da sessão em **segundos** |
| `user` | `"jsilva"` | Conta autenticada — o que transforma "um IP" em "uma pessoa" |

</details>

`proto=6` é TCP (17 seria UDP). `sentbyte=0` com `action="deny"` significa que nada trafegou: só houve a tentativa.

Cisco ASA:

```
%ASA-6-302013: Built outbound TCP connection 884512 for outside:203.0.113.77/443
 (203.0.113.77/443) to inside:10.10.20.45/51422 (198.51.100.10/51422)
%ASA-6-302014: Teardown TCP connection 884512 for outside:203.0.113.77/443
 to inside:10.10.20.45/51422 duration 0:02:11 bytes 24310 TCP FINs
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `%ASA` | `%ASA` | Etiqueta do produto: identifica a linha como vinda de um firewall ASA |
| severidade | `6` | Escala syslog do Cisco, de 0 (emergência) a 7 (depuração): `6` é **informational**. **Severidade baixa não quer dizer evento sem importância** — quem a escolhe é o fabricante, não o seu SOC |
| *message ID* | `302013` | Conexão TCP construída — entrou na tabela de estado. **É por este número que se escreve a regra no SIEM**: o texto da mensagem muda entre versões do software, o ID não |
| direção | `outbound` | **Quem iniciou**, não a direção dos bytes: `outbound` é de dentro para fora, `inbound` é de fora para dentro |
| id da conexão | `884512` | Número da conexão na tabela de estado. **É a chave para casar com o `302014`** que a encerra |
| lado remoto | `outside:203.0.113.77/443` | Interface, IP e porta do host **remoto**. Vem primeiro, logo depois do `for` — é isso que faz a linha parecer invertida |
| *(entre parênteses)* | `(203.0.113.77/443)` | O endereço **traduzido** desse lado. Igual ao real significa que não houve NAT nesta ponta |
| lado local | `inside:10.10.20.45/51422` | Interface, IP e porta do host **local**, antes da tradução |
| *(entre parênteses)* | `(198.51.100.10/51422)` | O endereço com que o host local saiu. **Este par — IP público mais porta — é o que desfaz o NAT** num pedido externo |
| *message ID* (2ª linha) | `302014` | Conexão TCP encerrada. **Contar `302013` e `302014` como dois eventos duplica a mesma sessão** no relatório |
| id da conexão | `884512` | O **mesmo** número da 1ª linha: é assim que se sabe que falam da mesma conexão |
| `duration` | `0:02:11` | Quanto tempo a conexão viveu, em `h:mm:ss` |
| `bytes` | `24310` | Total transferido na sessão. **Só existe no `302014`** — quando o `302013` é escrito, ainda não há o que contar |
| motivo | `TCP FINs` | Como terminou: `TCP FINs` é fim limpo nos dois sentidos; `TCP Reset-O` é RST vindo de fora (**O** de *Outside*); `TCP Reset-I` de dentro; `SYN Timeout` nunca completou; `Deny Terminate` a política cortou |

</details>


Zeek, `conn.log` (colunas resumidas):

```
ts=1756890862.114  id.orig_h=10.10.20.45  id.orig_p=51422
id.resp_h=203.0.113.77  id.resp_p=443  proto=tcp  service=ssl
duration=131.44  orig_bytes=24310  resp_bytes=118422  conn_state=SF  history=ShADadFf
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `ts` | `1756890862.114` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos |
| `id.orig_h` / `id.orig_p` | `10.10.20.45` / `51422` | Origem e porta de origem — quem abriu a sessão |
| `id.resp_h` / `id.resp_p` | `203.0.113.77` / `443` | Destino e porta de destino: HTTPS |
| `proto` | `tcp` | Protocolo de transporte |
| `service` | `ssl` | Serviço identificado por inspeção do conteúdo, não pela porta |
| `duration` | `131.44` | Duração em segundos |
| `orig_bytes` / `resp_bytes` | `24310` / `118422` | Payload em cada direção, sem cabeçalhos |
| `conn_state` | `SF` | Desfecho da conexão — a tabela abaixo destrincha todos os valores |
| `history` | `ShADadFf` | **A conexão contada pacote a pacote.** Cada letra é uma flag na ordem em que apareceu; MAIÚSCULA = originador, minúscula = respondedor. `S` SYN, `h` SYN-ACK, `A`/`a` ACK, `D`/`d` dados, `F`/`f` FIN. Aqui: abriu, trocou dados nos dois sentidos e fechou limpo — sem precisar abrir o pacote |

</details>

### A tabela dos conn_state do Zeek

Esta tabela é o instrumento de trabalho diário do N1. Ela responde, em uma letra, "essa conexão aconteceu de verdade?".

| conn_state | O que aconteceu | Leitura para o SOC |
|---|---|---|
| **S0** | SYN enviado, nenhuma resposta | Ninguém atendeu. Em massa = varredura de portas ou host desligado |
| **S1** | Conexão estabelecida, nunca encerrada no log | Sessão aberta ou ainda em curso quando o log foi escrito |
| **SF** | Conexão normal, aberta e fechada corretamente | Comunicação real ocorreu; olhe os bytes trocados |
| **REJ** | Conexão recusada (o destino respondeu RST ao SYN) | A porta existe no host, mas está fechada. Muitos REJ = varredura |
| **RSTO** | Estabelecida, e a **origem** enviou RST | Cliente cortou; comum em aplicação que fecha mal |
| **RSTR** | Estabelecida, e o **respondedor** (servidor) enviou RST | Servidor ou firewall derrubou a sessão |
| **RSTOS0** | Origem mandou SYN e depois RST; sem SYN-ACK do outro lado | Comportamento anômalo de varredura |
| **RSTRH** | Respondedor mandou SYN-ACK e depois RST; o SYN não foi visto | Geralmente sensor vendo só metade do tráfego |
| **SH** | Origem mandou SYN e depois FIN; sem SYN-ACK | "Meia conexão"; típico de varredura ou tráfego assimétrico |
| **SHR** | Respondedor mandou SYN-ACK e depois FIN | Fluxo assimétrico visto pelo sensor |
| **OTH** | Sem SYN nenhum; tráfego no meio da conversa | Sensor entrou tarde, ou tráfego fora do padrão |

Regra de bolso: **S0 em massa = varredura**. **REJ em massa = varredura em host que existe**. **SF com poucos bytes e muita repetição = possível canal de comando e controle (C2) com batimento regular**.

### Ataques na Camada 4

- **SYN flood** (MITRE ATT&CK T1498 — Network Denial of Service): o atacante despeja milhares de SYN e nunca responde ao SYN-ACK. A tabela de conexões do servidor lota e ele para de atender gente de verdade. No Zeek, é um mar de `S0`.
- **Varredura de portas** (T1046 — Network Service Discovery): SYN scan (manda SYN e olha se vem SYN-ACK ou RST), FIN scan (manda só FIN), NULL scan (nenhuma flag ligada) e XMAS scan (FIN+PSH+URG ligados ao mesmo tempo, "piscando como uma árvore de Natal"). Pacotes sem SYN ou com FIN/PSH/URG juntos não existem em tráfego legítimo — é assinatura de varredura.
- **Injeção de RST** (T1565): alguém no caminho forja um RST e derruba a sessão dos outros. Aparece como rajada de `RSTR`/`RSTO` sem motivo de aplicação.
- **Sequestro de sessão** (T1563 — Remote Service Session Hijacking): o atacante adivinha ou observa os números de sequência e injeta dados na conexão alheia. Hoje é raro em TCP moderno, mas continua relevante em protocolos sem criptografia.

Suricata, EVE JSON de uma varredura detectada:

```json
{"timestamp":"2026-09-03T09:22:10.442Z","event_type":"alert","src_ip":"10.10.55.201",
"src_port":44112,"dest_ip":"10.10.20.45","dest_port":3389,"proto":"TCP",
"alert":{"signature":"ET SCAN Potential SYN Scan","category":"Attempted Information Leak",
"severity":2},"flow":{"pkts_toserver":1,"pkts_toclient":0,"bytes_toserver":74,
"bytes_toclient":0}}
```

`pkts_toclient: 0` confirma que ninguém respondeu — só a sonda saiu.

### O que o SOC N1 observa

| Sinal | Normal | Suspeito |
|---|---|---|
| SYN sem ACK | Alguns, por host offline | Centenas de destinos diferentes em minutos, vindos de um único IP interno |
| Portas de destino | Poucas e repetidas (443, 53, 445) | Sequência crescente (22, 23, 25, 80, 110...) — varredura |
| RST | Ocasional, fim de app | Rajada concentrada em segundos |
| `session_end_reason` | `tcp-fin` | `aged-out` repetido para o mesmo destino externo |
| Duração e bytes | Variados | Sempre iguais, a cada 60 s — batimento de C2 |

Consulta SPL (Splunk) para caçar varredura:

```
index=firewall sourcetype=pan:traffic action=allow OR action=deny
| stats dc(dest_port) as portas_distintas, dc(dest_ip) as destinos by src_ip
| where portas_distintas > 50
| sort - portas_distintas
```

Linha 1 filtra os logs de firewall. Linha 2 conta, por IP de origem, quantas portas e quantos destinos distintos ele tocou. Linha 3 mantém só quem tocou mais de 50 portas. Linha 4 ordena do pior para o menos pior.

Consulta KQL (Microsoft Sentinel), mesma lógica:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(1h)                     // última hora
| where DeviceVendor == "Palo Alto Networks"        // só o firewall
| summarize Portas = dcount(DestinationPort),       // portas distintas por origem
            Destinos = dcount(DestinationIP)
    by SourceIP, bin(TimeGenerated, 5m)             // em janelas de 5 minutos
| where Portas > 50                                 // limiar de varredura
| order by Portas desc
```

### Erro comum de analista júnior

Tratar `conn_state=S0` como "ataque bem-sucedido". S0 significa exatamente o contrário: **nada foi estabelecido**. O erro gêmeo é fechar como falso positivo um `SF` com poucos bytes só porque "quase não trafegou" — pouco tráfego, repetido em intervalo fixo, é justamente a cara de um canal de C2. Outro deslize clássico: achar que a porta de origem 51422 é "porta suspeita". Ela é efêmera e aleatória por definição; a porta que importa é a de **destino**.

### Exercícios — Camada 4 — Transporte

1. O host interno 10.10.55.201 gerou, em 90 segundos, 1.842 registros no `conn.log` do Zeek com `conn_state=S0`, para 610 endereços distintos da faixa 10.10.0.0/16, em 3 portas (22, 445, 3389). O que está acontecendo e qual a primeira ação do N1?
2. Um alerta de firewall mostra `session_end_reason=aged-out` em 40 sessões de 10.10.20.45 para 198.51.100.55:8443, uma a cada 60 segundos, sempre com 512 bytes enviados. Verdadeiro ou falso positivo? Justifique.
3. Explique a diferença prática, para a investigação, entre `conn_state=REJ` e `conn_state=S0` ao avaliar se um host de destino existe na rede.
4. Numa conexão TCP, o cliente enviou SYN com Seq=4000. Qual valor de Ack o servidor coloca no SYN-ACK? E se o servidor escolher Seq=9000, qual será o Ack do terceiro pacote?
5. Um pacote chega com as flags FIN, PSH e URG ligadas simultaneamente, sem nenhum handshake anterior. Que tipo de atividade é essa e por que ela nunca aparece em tráfego legítimo?

<details><summary>Ver gabarito</summary>

**1.** É uma varredura de portas interna (MITRE T1046). O padrão delator é a combinação de três fatos: muitos destinos distintos, poucas portas e todas de administração remota (SSH, SMB, RDP), e `conn_state=S0` — ou seja, nenhuma resposta. Primeira ação do N1: identificar o que é 10.10.55.201 (ativo de inventário, dono, função). Se for uma ferramenta autorizada de gestão de vulnerabilidades, é atividade esperada e deve ser documentada na lista de exceções. Se for a estação de um usuário comum, escale imediatamente — máquina de usuário não varre a rede sozinha.

**2.** Muito provavelmente **verdadeiro positivo**, e o candidato natural é um canal de comando e controle (C2). O que denuncia não é o `aged-out` isolado, e sim a **regularidade**: intervalo fixo de 60 segundos, volume constante de 512 bytes e porta não padrão (8443). Comportamento humano é irregular; automação é metronômica. Próximo passo: verificar a reputação do destino, procurar o `ssl.log` do Zeek para ver o certificado e o SNI, e conferir no EDR qual processo em 10.10.20.45 abriu o socket.

**3.** `REJ` significa que o destino **respondeu** com RST — logo o host existe, está ligado e alcançável, apenas aquela porta está fechada. `S0` significa silêncio absoluto — pode ser host inexistente, desligado, ou um firewall que descarta o pacote sem responder. Na prática: uma varredura que retorna muitos `REJ` já confirmou o mapa de hosts vivos, o que é mais grave do ponto de vista de reconhecimento.

**4.** O servidor responde com `Ack = 4001`, porque o SYN consome um número de sequência e o servidor espera o byte seguinte. Se o servidor usar `Seq=9000`, o terceiro pacote do handshake sai do cliente com `Seq=4001` e `Ack=9001`, pela mesma regra.

**5.** É um XMAS scan (varredura "árvore de Natal"), variante de T1046. Em tráfego legítimo, FIN só aparece dentro de uma conexão já estabelecida, URG praticamente caiu em desuso e essas três flags nunca são combinadas por uma pilha TCP normal. A técnica existe porque diferentes sistemas operacionais respondem de formas distintas a pacotes inválidos, o que permite deduzir se a porta está aberta. Para o N1, a regra é direta: pacote sem handshake anterior e com combinação de flags impossível é reconhecimento, não erro de rede.

</details>


## Camada 5 — Sessão: a conversa que começa, dura e termina

Imagine uma ligação telefônica. Alguém disca, o outro atende, os dois conversam por dez minutos e um deles desliga. A camada 4 (Transporte, vista no trecho anterior) é o cabo telefônico que garante que a voz chega inteira. A **camada 5 (Sessão)** é o combinado de que aquela ligação específica existe, quem está falando com quem, e quando ela acaba.

### O que é

A camada de Sessão cria, mantém e encerra a "conversa lógica" entre duas aplicações. Ela responde a três perguntas: **quem sou eu nesta conexão**, **por quanto tempo continuo sendo reconhecido** e **quando essa identidade deixa de valer**.

### Como funciona

A sessão tem três fases:

| Fase | O que acontece | Exemplo prático |
|---|---|---|
| Estabelecimento | Autenticação e criação de um identificador de sessão | Usuário `jsilva` faz logon e o Windows cria um Logon ID |
| Manutenção | O identificador é reapresentado a cada pedido | O navegador reenvia o cookie a cada clique |
| Encerramento | O identificador é invalidado | Logoff, timeout ou fechamento do compartilhamento |

Dois objetos carregam essa identidade:

- **Token de sessão** — um "crachá" que o servidor entrega após o logon. No Windows é o *access token*, ligado a um **Logon ID** (aquele valor hexadecimal como `0x3E7A1B4`).
- **Cookie de sessão** — o mesmo crachá, mas guardado no navegador e reenviado no cabeçalho HTTP a cada requisição.

Protocolos que vivem nessa camada:

| Protocolo | Sigla aberta | Para que serve | Portas típicas |
|---|---|---|---|
| NetBIOS | *Network Basic Input/Output System* | Nomes e sessões legadas em rede Windows | 137/UDP, 138/UDP, 139/TCP |
| RPC | *Remote Procedure Call* — chamada de procedimento remoto | Um computador executa função em outro | 135/TCP + portas dinâmicas 49152–65535 |
| SMB | *Server Message Block* | Compartilhamento de arquivos e impressoras Windows | 445/TCP |
| SOCKS | *SOCKet Secure* | Proxy genérico que repassa qualquer tráfego | 1080/TCP (padrão) |

O **SOCKS** merece atenção: ele é um proxy de sessão, não entende o conteúdo. Por isso é muito usado por atacantes para tunelar tráfego — é a base do "pivoting" dentro da rede.

### Exemplo prático

A estação `WKS-0142` (IP `10.10.20.44`) acessa o compartilhamento `\\FS-CORP01\Financeiro` no servidor `10.10.5.10`, com o usuário `maria.costa`. Isso gera: um logon de rede no servidor, uma sessão SMB e, no fim do expediente, um logoff.

### Como aparece nos logs

```
Windows Security — Event ID 4624 (An account was successfully logged on)
Subject Security ID:    NULL SID
New Logon Account Name: maria.costa
New Logon Account Domain: CORP
New Logon Logon ID:     0x8A31C7
Logon Type:             3
Logon Process:          NtLmSsp
Authentication Package: NTLM
Workstation Name:       WKS-0142
Source Network Address: 10.10.20.44
Source Port:            49721
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `Event ID` | `4624 (An account was successfully logged on)` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não |
| `Subject Security ID` | `NULL SID` | SID de quem pediu a ação |
| `New Logon Account Name` | `maria.costa` | A conta da nova sessão |
| `New Logon Account Domain` | `CORP` | Domínio da conta da nova sessão |
| `New Logon Logon ID` | `0x8A31C7` | O identificador da nova sessão |
| `Logon Type` | `3` | **Como a sessão foi iniciada.** `3` = **rede** — acesso a compartilhamento, RPC, WinRM. É o tipo que domina em movimento lateral |
| `Logon Process` | `NtLmSsp` | Componente que processou o logon (`Kerberos`, `NtLmSsp`, `User32`, `Advapi`) |
| `Authentication Package` | `NTLM` | Pacote que autenticou: `Kerberos`, `NTLM` ou `Negotiate` |
| `Workstation Name` | `WKS-0142` | Nome que a máquina de origem **declarou**. Vem do próprio cliente, logo é falsificável — trate como pista, não como identidade |
| `Source Network Address` | `10.10.20.44` | **IP de origem.** Vazio ou `-` significa que a sessão foi local, e `::1`/`127.0.0.1` que veio da própria máquina |
| `Source Port` | `49721` | Porta de origem, efêmera |

</details>

```
Windows Security — Event ID 5140 (A network share object was accessed)
Account Name:      maria.costa
Account Domain:    CORP
Logon ID:          0x8A31C7
Object Type:       File
Share Name:        \\*\Financeiro
Share Path:        \??\D:\Dados\Financeiro
Source Address:    10.10.20.44
Source Port:       49721
Access Mask:       0x1
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `Event ID` | `5140 (A network share object was accessed)` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não |
| `Account Name` | `maria.costa` | A conta envolvida. Terminada em `$` é **conta de computador**, não de pessoa |
| `Account Domain` | `CORP` | Domínio da conta |
| `Logon ID` | `0x8A31C7` | **Costura os eventos da mesma sessão**: o 4624 que a abre, os 5140 de acesso e o 4634 que a fecha trazem o mesmo valor |
| `Object Type` | `File` | Tipo do objeto acedido (`File`, `Directory`, `Key`) |
| `Share Name` | `\\*\Financeiro` | O compartilhamento acedido. **`C$`, `ADMIN$` e `IPC$` são administrativos**, e não uso comum |
| `Share Path` | `\??\D:\Dados\Financeiro` | Caminho real no disco por trás do compartilhamento |
| `Source Address` | `10.10.20.44` | IP de origem |
| `Source Port` | `49721` | Porta de origem, efêmera |
| `Access Mask` | `0x1` | Permissões pedidas em bits: `0x1` leitura, `0x2` escrita, `0x4` acrescentar |

</details>

```
Windows Security — Event ID 4634 (An account was logged off)
Account Name: maria.costa
Logon ID:     0x8A31C7
Logon Type:   3
```

**Lendo as duas linhas.** A primeira é o retrato de um implante: conectou direto ao IP, sem SNI, com certificado autoassinado e `CN=localhost` contra um endereço público. Se o mesmo `ja3` aparecer em várias estações falando com IPs diferentes e sem SNI, há um binário comum instalado na frota — e é por aí que se acha o resto das máquinas infectadas. A segunda linha é o oposto: TLS 1.3, SNI coerente com o *subject* e cadeia `ok`.

### O que o SOC N1 observa

| Normal | Suspeito |
|---|---|
| 4624 tipo 3 de estação para servidor de arquivos, em horário comercial | 4624 tipo 3 seguido de 5140 em `\\*\ADMIN$` ou `\\*\C$` — assinatura de PsExec/Impacket (T1021.002) |
| Poucas sessões SMB por usuário | Um único usuário abrindo sessão em 40 servidores em 5 minutos |
| `svc_backup` acessando o share de backup à noite | Conta de serviço com logon tipo 3 vindo de estação de usuário comum |
| Logon ID com 4624 e 4634 correspondentes | 4624 sem 4634 por dias, com atividade contínua — sessão possivelmente sequestrada |

### Ataques de camada 5

- **Sequestro de sessão (*session hijacking*)** — o atacante rouba o identificador válido e passa a agir como o usuário, sem nunca saber a senha.
- **Roubo de cookie** — malware ou script extrai o cookie do navegador (MITRE **T1539 — Steal Web Session Cookie**).
- **Pass-the-cookie** — o cookie roubado é injetado em outro navegador, em outro país, e a aplicação aceita: a autenticação multifator já foi satisfeita quando o cookie nasceu.
- **Replay** — o mesmo pacote de autenticação é reenviado para obter acesso novamente.

**Erro comum de analista júnior:** fechar o alerta de "logon impossível" só porque o usuário confirmou "sim, fui eu que entrei hoje de manhã". Em pass-the-cookie o logon legítimo da manhã é justamente a origem do cookie; o que interessa é a sessão paralela, de outro IP, usando o mesmo identificador. Sempre compare o `Logon ID` / ID da sessão, não a pessoa.

## Camada 6 — Apresentação: o tradutor e o cofre

Pense num contrato entre uma empresa brasileira e uma japonesa. Existe o mensageiro (camadas de baixo) e existe o **tradutor juramentado**, que converte o idioma e ainda coloca o documento num envelope lacrado. A **camada 6 (Apresentação)** é esse tradutor: ela decide **como os dados são representados**, se são **comprimidos** e se são **criptografados**.

### Representação e encoding

*Encoding* é a regra que transforma letras em números.

| Encoding | O que é | Observação para o SOC |
|---|---|---|
| ASCII | *American Standard Code for Information Interchange* | 128 caracteres, sem acento |
| UTF-8 | *Unicode Transformation Format, 8 bits* | Padrão da web, suporta "ç", "ã", "é" |
| Base64 | Converte binário em 64 caracteres imprimíveis | **Não é criptografia** — é só reescrita, reversível por qualquer um |

**Base64 não protege nada**, mas é o disfarce favorito de atacantes: cabe dentro de um campo de texto, passa em proxy e engana quem lê rápido. Reconheça pelo alfabeto `A–Z a–z 0–9 + /`, comprimento múltiplo de 4 e o preenchimento com `=` no fim.

```
Sysmon — Event ID 1 (Process creation)
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -nop -w hidden -enc SQBuAHYAbwBrAGUALQBXAGUAYg...
ParentImage: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
User: CORP\jsilva
Hashes: SHA256=A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90
```

**O que ler aqui:** o `-enc` indica comando codificado em Base64 (T1027 — *Obfuscated Files or Information*); `-w hidden` esconde a janela; e o `ParentImage` sendo o Word é o sinal mais forte de todos — documento gerando PowerShell é cadeia clássica de macro maliciosa. O analista N1 **não executa** o conteúdo: apenas decodifica em ambiente controlado ou encaminha ao N2.

### Criptografia, TLS e certificados

**TLS** (*Transport Layer Security*, sucessor do SSL — *Secure Sockets Layer*) é o envelope lacrado. Ele nasce de um "aperto de mão" (*handshake*) em que o servidor apresenta seu **certificado digital**.

| Elemento do certificado | O que significa | Sinal de alerta |
|---|---|---|
| CA (*Certificate Authority*) | Autoridade que assina e garante o certificado | Emissor desconhecido ou igual ao próprio sujeito |
| Cadeia (*chain*) | Certificado → CA intermediária → CA raiz confiável | Cadeia incompleta ou quebrada |
| SAN (*Subject Alternative Name*) | Lista de nomes válidos para aquele certificado | SAN vazio ou com nome que não bate com o site |
| Validade | Datas de início e fim | Validade de poucos dias, ou emitido há 2 horas |
| Autoassinado (*self-signed*) | O próprio servidor assinou seu certificado | Muito comum em servidores de comando e controle (C2) |

Como o conteúdo vai cifrado, o SOC usa **impressões digitais do handshake**, que são visíveis mesmo sem descriptografar:

- **JA3** — impressão do *cliente* (a forma como o programa que iniciou a conexão se apresenta). Ferramentas maliciosas costumam ter JA3 próprio.
- **JA3S** — impressão do *servidor* na resposta.
- **JARM** — impressão ativa: a ferramenta provoca o servidor e classifica a resposta; ajuda a agrupar servidores C2.

### Ataques de camada 6

- **SSL stripping** — o atacante força a vítima a usar HTTP em vez de HTTPS, ficando com tudo em texto claro.
- **Certificado autoassinado de C2** — o malware fala TLS, mas o certificado é falso e genérico (T1573 — *Encrypted Channel*).
- **Downgrade** — negociação forçada para versão antiga e frágil (TLS 1.0/SSLv3).

### Como aparece no ssl.log do Zeek

```
#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p version cipher server_name subject issuer validation_status ja3 ja3s established
1725364812.441 CkT9x2a 10.10.20.44 51422 203.0.113.77 443 TLSv12 TLS_RSA_WITH_AES_256_CBC_SHA - CN=localhost CN=localhost self signed certificate 51c64c77e60f3980eea90869b68c58a8 ec74a5c51106f0419184d0dd08fb05bc T
1725364901.207 CmP4r7b 10.10.20.51 51503 198.51.100.20 443 TLSv13 TLS_AES_128_GCM_SHA256 portal.empresa-exemplo.com.br CN=portal.empresa-exemplo.com.br CN=Example RSA CA ok a0e9f5d64349fb13191bc781f81f42e1 f4febc55ea12b31ae17cfb7e614afda8 T
```

<details><summary>Ver legenda</summary>

| Campo | 1ª linha (suspeita) / 2ª linha (normal) | O que significa |
|---|---|---|
| `ts` | `1725364812.441` / `1725364901.207` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos |
| `uid` | `CkT9x2a` / `CmP4r7b` | Liga este handshake à conexão correspondente no `conn.log` |
| `id.orig_h` / `id.orig_p` | `10.10.20.44:51422` / `10.10.20.51:51503` | Cliente e porta efêmera |
| `id.resp_h` / `id.resp_p` | `203.0.113.77:443` / `198.51.100.20:443` | Servidor e porta |
| `version` | `TLSv12` / `TLSv13` | Versão do TLS negociada. TLS 1.0 e 1.1 aqui são achado de auditoria |
| `cipher` | `TLS_RSA_WITH_AES_256_CBC_SHA` / `TLS_AES_128_GCM_SHA256` | Conjunto de cifras acordado. O primeiro usa RSA e CBC — combinação antiga, sem *forward secrecy* |
| `server_name` | `-` / `portal.empresa-exemplo.com.br` | O SNI (*Server Name Indication*): o nome que o cliente pediu, **visível mesmo com o tráfego cifrado**. Vazio significa conexão direta ao IP, sem nome |
| `subject` | `CN=localhost` / `CN=portal.empresa-exemplo.com.br` | A quem o certificado foi emitido |
| `issuer` | `CN=localhost` / `CN=Example RSA CA` | Quem assinou. Emissor igual ao *subject* = autoassinado |
| `validation_status` | `self signed certificate` / `ok` | Resultado da validação da cadeia contra as CA confiáveis |
| `ja3` | `51c64c77…` / `a0e9f5d6…` | Impressão digital do **cliente**, derivada de como ele monta o ClientHello. Não muda com o IP nem com o domínio: identifica o binário |
| `ja3s` | `ec74a5c5…` / `f4febc55…` | A mesma ideia para a resposta do **servidor** — serve para agrupar infraestrutura de C2 |
| `established` | `T` | O handshake completou (`T`) ou foi interrompido (`F`) |

</details>

**Explicando os campos:** `server_name` vem do SNI (*Server Name Indication*) — o nome que o cliente pediu, visível mesmo com tráfego cifrado. Na primeira linha ele está vazio (`-`): o cliente conectou direto pelo IP, sem nome, comportamento típico de implante e não de navegador. `validation_status` mostra `self signed certificate` contra um IP público, com `CN=localhost` — combinação altamente suspeita. `ja3` identifica o cliente; se o mesmo JA3 aparece em várias estações falando com IPs diferentes e sem SNI, há um binário comum instalado na frota. A segunda linha é o oposto: TLS 1.3, SNI coerente, cadeia `ok`.

### Consultas para triagem

```spl
index=zeek sourcetype=zeek:ssl
| search validation_status!="ok"
| stats count values(server_name) as sni values(ja3) as ja3 by id.orig_h id.resp_h
| where count > 5
```
Linha 1 seleciona o ssl.log. Linha 2 mantém só handshakes com validação problemática. Linha 3 agrupa por par origem/destino trazendo SNI e JA3. Linha 4 destaca comunicação repetida — sinal de *beacon*, não de erro pontual.

```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort == 443 and isempty(RemoteUrl)      // TLS sem nome de destino
| summarize Conexoes = count(), Destinos = dcount(RemoteIP) by DeviceName, InitiatingProcessFileName
| where Conexoes > 50 and Destinos < 3                // muitas conexões, poucos destinos
| order by Conexoes desc
```

**Erro comum de analista júnior:** tratar todo certificado autoassinado como incidente. Impressoras, switches, iDRAC/iLO e appliances internos usam autoassinado o tempo todo — e isso é normal em `10.10.x.x`. O que muda o quadro é autoassinado em **IP público**, com SNI vazio e periodicidade regular.

### Exercícios — Camadas 5 e 6 — Sessão e Apresentação

1. Na estação `10.10.20.44` você encontra 4624 tipo 3 para `admin.rodrigo` com Logon ID `0x5F21A0`, seguido de 5140 em `\\*\ADMIN$` em seis servidores diferentes em 90 segundos. Qual a hipótese e qual o próximo passo?
2. O ssl.log mostra `10.10.30.9 → 10.10.30.200:443`, `validation_status = self signed certificate`, `server_name = -`, uma conexão a cada 12 horas. Verdadeiro ou falso positivo?
3. Um Sysmon Event ID 1 traz `powershell.exe -enc <string Base64>` com pai `explorer.exe`, usuário `svc_backup`, às 03h10. O que você verifica antes de escalar?
4. Explique por que a autenticação multifator não impede pass-the-cookie e qual evidência confirma o ataque.
5. Cinquenta estações apresentam o mesmo valor de `ja3` conversando com `203.0.113.90:443` sem SNI. O que isso indica?

<details><summary>Ver gabarito</summary>

1. **Movimentação lateral com ferramenta tipo PsExec/Impacket (T1021.002).** O acesso a `ADMIN$` é o passo de cópia do serviço remoto; a velocidade (seis servidores em 90 segundos) descarta ação humana manual. Próximo passo: correlacionar o Logon ID `0x5F21A0` em cada servidor de destino, procurar Event ID 7045 (instalação de serviço) e 4688/Sysmon 1 nos alvos, e confirmar com o dono da conta se havia manutenção agendada. Se não houver, conter a origem `10.10.20.44`.

2. **Provavelmente falso positivo.** Destino é RFC1918 (`10.10.30.200`), portanto ativo interno, e a periodicidade de 12 horas com um único destino combina com verificação de gerenciamento (appliance, hipervisor, impressora). Confirme no inventário o que é o `.200`. Um C2 real quase sempre aponta para IP externo — se o destino fosse `203.0.113.x`, a leitura se inverteria.

3. **Nem escalar direto, nem fechar.** Verifique: (a) `svc_backup` é conta de serviço — ela deveria estar interativa sob `explorer.exe`? Normalmente não, e isso já é anomalia; (b) 03h10 pode bater com janela legítima de backup; (c) decodifique o Base64 em ambiente controlado, sem executar; (d) confira o hash SHA256 em base de reputação. Conta de serviço com sessão interativa é o ponto mais grave do conjunto.

4. Porque a MFA valida o **estabelecimento** da sessão, não a **manutenção** dela. Depois de aprovada, o servidor confia no cookie/token; quem apresentar o cookie válido é aceito sem novo desafio. Evidência: mesma sessão (mesmo identificador) usada a partir de dois IPs/geolocalizações/user-agents distintos, sem novo evento de autenticação entre eles.

5. Indica **um binário comum instalado na frota** falando com o mesmo servidor externo. JA3 igual significa mesma biblioteca TLS e mesma configuração de cliente; ausência de SNI reforça que não é navegador. Pode ser software legítimo de gestão implantado por GPO — ou um implante distribuído. Próximo passo: identificar em uma estação qual processo abre a conexão (Sysmon Event ID 3, campo `Image`) e comparar com o inventário de software aprovado.

</details>


## Camada 7 — Aplicação: onde o usuário (e o atacante) realmente conversa

### O que é

Imagine um escritório internacional. A camada 4 (Transporte, vista antes) é a transportadora que garante que a encomenda chegue inteira. As camadas 5 e 6 cuidam de manter a conversa aberta e traduzir o idioma. A **camada 7** é a reunião em si: o conteúdo do que se fala. É aqui que existem palavras como "quero a página de login", "me diga o endereço IP do site", "envie este e-mail".

Para o SOC (Security Operations Center, o centro de operações de segurança), a camada 7 é a camada mais rica: é a única que mostra **intenção**. Um pacote TCP na porta 443 não diz nada; uma requisição HTTP dizendo `POST /admin/upload.aspx` com um arquivo `.aspx` anexado diz muito.

### Como funciona

A camada 7 define o **formato da mensagem**: quais comandos existem, o que é cabeçalho, o que é corpo. Cada protocolo tem seu próprio "idioma".

| Protocolo | Nome por extenso | Porta padrão | Para que serve | O que o SOC olha |
|---|---|---|---|---|
| HTTP | HyperText Transfer Protocol | 80/TCP | Navegação web sem criptografia | URL, método, User-Agent, status |
| HTTPS | HTTP Secure (HTTP sobre TLS) | 443/TCP | Navegação web criptografada | SNI, certificado, JA3, volume |
| DNS | Domain Name System | 53/UDP e 53/TCP | Traduz nome em endereço IP | Domínios raros, DGA, tunelamento |
| SMTP | Simple Mail Transfer Protocol | 25, 587, 465/TCP | Envio de e-mail | Remetente, anexo, spoofing |
| FTP | File Transfer Protocol | 21/TCP (controle) | Transferência de arquivos em claro | Credencial em texto puro, exfiltração |
| SSH | Secure Shell | 22/TCP | Administração remota criptografada | Força bruta, túnel reverso |
| RDP | Remote Desktop Protocol | 3389/TCP | Área de trabalho remota Windows | Exposição à internet, força bruta |
| SNMP | Simple Network Management Protocol | 161/UDP | Monitoramento de equipamento de rede | Community "public", reconhecimento |
| LDAP | Lightweight Directory Access Protocol | 389/TCP, 636/TCP (LDAPS) | Consulta ao diretório (Active Directory) | Enumeração massiva (BloodHound) |

### Métodos HTTP e códigos de status

O **método** é o verbo do pedido. O **código de status** é a resposta do servidor.

| Método | Significado | Sinal para o SOC |
|---|---|---|
| GET | Buscar um recurso | Normal; suspeito se a URL carrega comandos |
| POST | Enviar dados ao servidor | Login, upload, também exfiltração |
| PUT | Gravar um arquivo no servidor | Raro em produção; upload de web shell |
| DELETE | Apagar recurso | Raríssimo; investigar sempre |
| HEAD | Só cabeçalhos | Usado por varredura automática |
| OPTIONS | Perguntar o que é permitido | Reconhecimento de API |

| Faixa | Significado | Leitura no SOC |
|---|---|---|
| 2xx | Sucesso (200 OK, 201 Created) | Um 200 após muitos 404 pode significar que o atacante **achou** algo |
| 3xx | Redirecionamento (301, 302) | Cadeia de redirects é comum em phishing |
| 4xx | Erro do cliente (401, 403, 404) | Muitos 404 seguidos = varredura de diretórios |
| 5xx | Erro do servidor (500, 502) | Muitos 500 podem indicar tentativa de injeção quebrando a aplicação |

### User-Agent: a assinatura de quem fala

O **User-Agent** é um cabeçalho HTTP em que o programa se identifica. É como a pessoa dizer o nome dela ao entrar na recepção — e, como recepção, dá para mentir. Mas atacantes e ferramentas automáticas frequentemente **não mentem**, por preguiça ou porque a ferramenta usa o padrão.

| User-Agent | O que costuma indicar |
|---|---|
| `Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/128.0` | Navegador real de usuário |
| `curl/8.4.0` | Script ou teste manual; num endpoint interno pode ser legítimo |
| `python-requests/2.31.0` | Automação; frequente em C2 caseiro e scraping |
| `Mozilla/5.0 (Windows NT; ...) WindowsPowerShell/5.1.19041` | `Invoke-WebRequest`/`Invoke-RestMethod` — download em máquina de usuário é alerta |
| `Go-http-client/1.1` | Muitos frameworks ofensivos modernos |
| Vazio ou string sem sentido | Anômalo por definição |

**Regra prática:** um User-Agent de script saindo de um **notebook de usuário final** para um domínio externo raro é sinal forte. O mesmo User-Agent saindo de um **servidor de integração** pode ser o dia a dia. Contexto do host decide.

### Ataques que vivem na camada 7

| Ataque | O que é, em uma frase | MITRE ATT&CK |
|---|---|---|
| SQL Injection (SQLi) | Texto enviado num campo é interpretado como comando de banco de dados | T1190 |
| Cross-Site Scripting (XSS) | Código de script é refletido para o navegador de outra vítima | T1059.007 |
| RCE (Remote Code Execution) | Falha permite executar comando no servidor | T1190 |
| Web shell | Arquivo enviado ao servidor web que vira console do atacante | T1505.003 |
| C2 sobre HTTPS | Malware conversa com o operador dentro de tráfego 443 legítimo aparente | T1071.001 |
| Phishing | E-mail/página que engana o usuário para roubar credencial | T1566 |

Nenhum payload é apresentado aqui: o valor para o N1 é reconhecer o **rastro**, não reproduzir o ataque.

### Exemplo prático

A estação `10.10.24.87` do usuário `jsilva` começa a falar com `203.0.113.45` (domínio `cdn-update.example.com`) a cada 60 segundos, sempre com o mesmo tamanho de requisição.

### Como aparece nos logs

Squid `access.log` — varredura de diretórios contra o portal interno:

```
1756900012.331    142 10.10.24.87 TCP_MISS/404 512 GET http://portal.corp.local/admin/ - HIER_DIRECT/10.10.5.10 text/html
1756900012.488    139 10.10.24.87 TCP_MISS/404 512 GET http://portal.corp.local/backup/ - HIER_DIRECT/10.10.5.10 text/html
1756900012.641    145 10.10.24.87 TCP_MISS/404 512 GET http://portal.corp.local/.git/config - HIER_DIRECT/10.10.5.10 text/html
1756900012.802    311 10.10.24.87 TCP_MISS/200 8412 GET http://portal.corp.local/uploads/ - HIER_DIRECT/10.10.5.10 text/html
```

<details><summary>Ver legenda</summary>

| Campo | Valor nas quatro linhas | O que significa |
|---|---|---|
| *timestamp* | `.331`, `.488`, `.641`, `.802` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos. **Quatro pedidos em 471 milissegundos** — velocidade de ferramenta |
| duração | `142`, `139`, `145`, `311` | Milissegundos. A 4ª demorou o dobro: houve conteúdo real para entregar |
| cliente | `10.10.24.87` | Sempre a mesma origem — é ela que está varrendo |
| resultado/status | `TCP_MISS/404` ×3, depois `TCP_MISS/200` | **A sequência é o achado**: três caminhos que não existem e um que existe |
| bytes | `512`, `512`, `512`, `8412` | Os `404` devolvem sempre a mesma página de erro; o `200` devolveu 8 KB de conteúdo |
| método | `GET` | Pedido simples de leitura |
| URL | `/admin/`, `/backup/`, `/.git/config`, `/uploads/` | **A lista denuncia a intenção**: são caminhos de dicionário de ferramenta de varredura, e `/.git/config` é tentativa de ler o repositório do site |
| usuário | `-` | Sem autenticação no proxy |
| hierarquia/destino | `HIER_DIRECT/10.10.5.10` | O proxy foi direto ao portal interno |
| tipo de conteúdo | `text/html` | O MIME devolvido |

</details>


Zeek `http.log` — User-Agent anômalo:

```
#fields ts  uid  id.orig_h  id.orig_p  id.resp_h  id.resp_p  method  host  uri  user_agent  status_code  resp_body_len
1756900130.221  CvT8gh2Kd  10.10.24.87  51422  203.0.113.45  443  POST  cdn-update.example.com  /api/v2/telemetry  python-requests/2.31.0  200  48
1756900190.204  CvT8gh2Kd  10.10.24.87  51438  203.0.113.45  443  POST  cdn-update.example.com  /api/v2/telemetry  python-requests/2.31.0  200  48
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `ts` | `1756900130.221` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos |
| `uid` | `CvT8gh2Kd` | Conexão que transportou esta requisição — cruza com o `conn.log` |
| `id.orig_h` / `id.orig_p` | `10.10.24.87` / `51422` | Cliente e porta de origem |
| `id.resp_h` / `id.resp_p` | `203.0.113.45` / `443` | Servidor e porta |
| `method` | `POST` | Método HTTP. `POST` repetido para o mesmo caminho é envio de dados, não navegação |
| `host` | `cdn-update.example.com` | Cabeçalho `Host` — o domínio que o cliente pediu. Nomes que imitam CDN são disfarce comum |
| `uri` | `/api/v2/telemetry` | Caminho requisitado. "telemetria" é rótulo frequente em canal de C2 |
| `user_agent` | `python-requests/2.31.0` | Como o cliente se identifica. **Biblioteca de script, não navegador** — numa estação de usuário é sinal forte |
| `status_code` | `200` | Resposta HTTP do servidor |
| `resp_body_len` | `48` | Tamanho do corpo devolvido, em bytes. Sempre igual = resposta programada, não conteúdo |

</details>

POST repetido a cada 60 s, resposta sempre de 48 bytes: batimento (beacon) de C2. Um usuário real nunca é tão pontual.

Palo Alto — log THREAT (formato CSV, campos separados por vírgula):

```
1,2026/09/03 11:42:07,013201004215,THREAT,vulnerability,2561,2026/09/03 11:42:07,10.10.24.87,198.51.100.22,,,regra-saida-web,jsilva,,web-browsing,vsys1,Trust,Untrust,ae1.10,ae1.20,LogForward,2026/09/03 11:42:07,102331,1,51550,80,0,0,0x80003000,tcp,alert,"/login.php",SQL Injection Attempt(31842),any,high,client-to-server
```

Campos-chave: origem `10.10.24.87`, destino `198.51.100.22`, usuário `jsilva`, aplicação `web-browsing`, ação `alert`, assinatura `SQL Injection Attempt`, severidade `high`, direção `client-to-server`.

FortiGate WAF (formato chave=valor):

```
date=2026-09-03 time=11:45:02 devname="FGT-DC01" type="utm" subtype="waf" action="blocked" srcip=198.51.100.77 dstip=10.10.5.10 service="HTTPS" url="/uploads/img.aspx" httpmethod="PUT" agent="curl/8.4.0" attack="Web Shell Upload" severity="critical" msg="WAF signature match"
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `date` | `2026-09-03` | Data local **do equipamento**, não UTC. Correlacionar com um log em UTC sem acertar o fuso desalinha a timeline |
| `time` | `11:45:02` | Hora local do equipamento |
| `devname` | `"FGT-DC01"` | Nome do equipamento que gerou o log |
| `type` | `"utm"` | Categoria do log: `traffic` é sessão, `event` é evento do próprio aparelho, `utm` é inspeção de conteúdo |
| `subtype` | `"waf"` | Subcategoria: `forward` é tráfego que atravessa, `local` é destinado ao próprio firewall, `vpn` é túnel, `webfilter` e `ips` são inspeção |
| `action` | `"blocked"` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |
| `srcip` | `198.51.100.77` | IP de origem |
| `dstip` | `10.10.5.10` | IP de destino |
| `service` | `"HTTPS"` | Nome do **objeto de serviço** do FortiGate, não a porta literal. Um objeto chamado `HTTPS` pode ter sido configurado noutra porta |
| `url` | `"/uploads/img.aspx"` | URL pedida |
| `httpmethod` | `"PUT"` | Método HTTP do pedido |
| `agent` | `"curl/8.4.0"` | *User-agent* declarado pelo cliente. **Biblioteca ou ferramenta aqui, numa estação de usuário, é anomalia** |
| `attack` | `"Web Shell Upload"` | Nome da assinatura de IPS que disparou |
| `severity` | `"critical"` | Gravidade atribuída à assinatura |
| `msg` | `"WAF signature match"` | Texto livre com a descrição legível. **Não use este campo em regras** — muda entre versões |

</details>

`PUT` de um `.aspx` para `/uploads/`, com `curl` — tentativa de subir web shell, bloqueada.

Sysmon Event ID 1 (criação de processo) — o EDR vendo o resultado no endpoint:

```
EventID: 1
UtcTime: 2026-09-03 11:46:31.402
Image: C:\Windows\System32\cmd.exe
ParentImage: C:\Windows\System32\inetsrv\w3wp.exe
CommandLine: cmd.exe /c whoami
User: CORP\svc_web
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `EventID` | `1` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não. `1` = Sysmon **Process Create** |
| `UtcTime` | `2026-09-03 11:46:31.402` | Instante do evento **em UTC**, o que dispensa converter fuso ao correlacionar |
| `Image` | `C:\Windows\System32\cmd.exe` | Caminho do executável (nomenclatura do Sysmon) |
| `ParentImage` | `C:\Windows\System32\inetsrv\w3wp.exe` | Caminho do processo **pai**. **É aqui que o Sysmon brilha**: Word ou Excel como pai de `powershell.exe` é sinal forte por si só |
| `CommandLine` | `cmd.exe /c whoami` | Linha de comando. `-enc` indica comando em Base64 e `-w hidden` janela oculta |
| `User` | `CORP\svc_web` | Conta sob a qual o processo corre |

</details>

O servidor web (`w3wp.exe`) sendo **pai** de um `cmd.exe` é o padrão clássico de web shell executando comando. Nenhum servidor web saudável faz isso.

### O que o SOC N1 observa: normal vs suspeito

| Normal | Suspeito |
|---|---|
| Navegador com User-Agent completo, destinos conhecidos | `python-requests` de notebook para domínio novo |
| Poucos 404 dispersos | Dezenas de 404 em segundos, seguidos de um 200 |
| Intervalo entre conexões irregular | Intervalo fixo (60 s, 300 s) com jitter mínimo |
| `w3wp.exe` gerando processos de aplicação | `w3wp.exe` gerando `cmd.exe` ou `powershell.exe` |

### Erro comum de analista júnior

Fechar o alerta de WAF porque a `action` é `blocked`. Bloqueado significa que **aquela** tentativa falhou — não que o atacante desistiu. O passo certo é verificar se o mesmo IP teve alguma requisição com `200` antes ou depois.

### Consultas rápidas

```spl
index=proxy sourcetype=squid:access
| where NOT match(http_user_agent, "Mozilla")            /* tira navegador real */
| stats count dc(dest_domain) as dominios by src_ip, http_user_agent
| where count > 50                                        /* volume automatizado */
```

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("w3wp.exe","httpd.exe","nginx.exe")  // pai = servidor web
| where FileName in~ ("cmd.exe","powershell.exe","bash")                    // filho = shell
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

## Tabela-resumo das 7 camadas — consulta rápida

| # | Camada | PDU | Dispositivo típico | Protocolo exemplo | Ataque típico | Ferramenta de análise |
|---|---|---|---|---|---|---|
| 7 | Aplicação | Dados / mensagem | Proxy, WAF, EDR | HTTP, DNS, SMTP, LDAP | SQLi, XSS, web shell, C2 | Zeek `http.log`, Squid, WAF, Splunk |
| 6 | Apresentação | Dados | Terminador TLS, gateway | TLS, JPEG, ASCII | Downgrade TLS, certificado forjado | Zeek `ssl.log`, `openssl s_client` |
| 5 | Sessão | Dados | Gateway, servidor | NetBIOS, RPC, SMB (sessão) | Sequestro de sessão, cookie roubado | Wireshark, logs de aplicação |
| 4 | Transporte | Segmento (TCP) / Datagrama (UDP) | Firewall stateful, balanceador | TCP, UDP | Varredura de portas, SYN flood | `nmap`, Suricata, Zeek `conn.log` |
| 3 | Rede | Pacote | Roteador, firewall L3 | IP, ICMP, IPsec | Spoofing de IP, túnel ICMP | `traceroute`, NetFlow, Zeek |
| 2 | Enlace | Quadro (frame) | Switch, ponto de acesso | Ethernet, ARP, 802.1Q | Envenenamento ARP, MAC flooding | `arp -a`, Wireshark, logs do switch |
| 1 | Física | Bit | Cabo, transceptor, hub | RJ45, fibra, RF | Grampo físico, corte de link | `ethtool`, contadores da porta |

### Exercícios — Camada 7 — Aplicação e tabela-resumo das 7 camadas

1. No `access.log` do Squid há 47 respostas `404` da origem `10.10.24.87` em 9 segundos e, logo depois, um `200`. Qual é a hipótese e qual o próximo passo?
2. Um alerta aponta `python-requests/2.31.0` saindo de `10.10.31.15` para `203.0.113.90`. Descobrindo que `10.10.31.15` é o servidor de integração `srv-etl01`, o alerta é verdadeiro ou falso positivo? O que confirma?
3. O WAF FortiGate bloqueou um `PUT /uploads/img.aspx` vindo de `198.51.100.77`. O caso está encerrado? Justifique e diga o que consultar.
4. Um evento Sysmon ID 1 mostra `ParentImage: w3wp.exe` e `CommandLine: cmd.exe /c whoami`, usuário `CORP\svc_web`. Qual a camada envolvida, qual a técnica MITRE e qual a ação imediata?
5. Usando a tabela-resumo, indique em qual camada atua cada item: envenenamento ARP, SYN flood, XSS e corte de fibra.

<details><summary>Ver gabarito</summary>

1. **Varredura de diretórios** (directory brute force). O volume e a velocidade descartam navegação humana. Próximo passo: identificar **qual** URL retornou `200` — é o recurso que o atacante encontrou — e verificar se houve requisição `POST`/`PUT` depois dela. Confirmar também se `10.10.24.87` é estação legítima ou host comprometido.

2. Provavelmente **falso positivo**, mas só depois de confirmar três coisas: (a) o destino `203.0.113.90` é um parceiro/API conhecido e documentado; (b) o intervalo das conexões acompanha a janela do job de ETL, não um beacon fixo de 60 s; (c) o processo pai no EDR é o serviço de integração, não algo como `winword.exe`. Sem esses três, mantenha como suspeito. Documente como exceção com escopo de host + destino, nunca uma exceção global do User-Agent.

3. **Não está encerrado.** `action="blocked"` cobre só aquela requisição. Consulte todo o histórico do IP `198.51.100.77` nas últimas 24 h procurando qualquer resposta `200` ou `201`, e verifique no servidor `10.10.5.10` se surgiu arquivo novo em `/uploads/`. Cheque também Sysmon ID 1 procurando `w3wp.exe` como processo pai.

4. Camada **7 (Aplicação)** — o vetor entrou por HTTP e virou execução no servidor. Técnica **T1505.003 (Server Software Component: Web Shell)**, com execução via **T1059**. Ação imediata: escalar para N2, isolar o servidor da rede conforme o procedimento, preservar o arquivo em `/uploads/` e os logs do IIS. Não apague o arquivo — é evidência.

5. Envenenamento ARP = camada **2**; SYN flood = camada **4**; XSS = camada **7**; corte de fibra = camada **1**.

</details>

## Mini-laboratório — Modelo OSI, camadas 4 a 7 na prática

**Objetivo:** capturar e identificar, numa única sessão, tráfego das camadas 4, 6 e 7.

**Pré-requisitos:** VirtualBox com uma máquina Ubuntu Desktop, Wireshark, `tcpdump`, `nmap` e Docker instalados na VM. Tudo gratuito. Não execute nada disso na rede corporativa — use apenas a rede interna da VM.

**Passo 1 — Subir um alvo local.**
```bash
docker run -d --name lab-web -p 8080:80 nginx:alpine
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/
```
*Observar:* deve imprimir `200`. Esse é o servidor do laboratório.

**Passo 2 — Camada 4: varredura de portas.**
```bash
sudo tcpdump -i lo -w /tmp/lab-l4.pcap &
nmap -sS -p 20-100,8080 127.0.0.1
sudo pkill tcpdump
```
*Observar:* no Wireshark, filtro `tcp.flags.syn==1 && tcp.flags.ack==0`. Portas fechadas respondem `RST, ACK`; a 8080 responde `SYN, ACK`. Isso é camada 4 pura, sem conteúdo.

**Passo 3 — Camada 7: HTTP em claro e User-Agent.**
```bash
sudo tcpdump -i lo -w /tmp/lab-l7.pcap &
curl http://127.0.0.1:8080/pagina-inexistente
curl -A "python-requests/2.31.0" http://127.0.0.1:8080/
sudo pkill tcpdump
```
*Observar:* filtro Wireshark `http.request`. Você verá `GET`, o `User-Agent` e os status `404` e `200`. Compare os dois User-Agents lado a lado.

**Passo 4 — Camada 6: TLS e SNI.**
```bash
sudo tcpdump -i any -w /tmp/lab-tls.pcap port 443 &
curl -s https://example.com/ > /dev/null
sudo pkill tcpdump
```
*Observar:* filtro `tls.handshake.type == 1` (Client Hello). Localize a extensão **server_name (SNI)** com `example.com` em texto claro, mesmo a conexão sendo criptografada. É por isso que o proxy consegue registrar o domínio sem quebrar o TLS.

**Passo 5 — Limpeza.**
```bash
docker rm -f lab-web
rm -f /tmp/lab-l4.pcap /tmp/lab-l7.pcap /tmp/lab-tls.pcap
```

**Critério de sucesso:** você conseguiu apontar, em capturas suas, (a) um `SYN/ACK` de porta aberta, (b) um `RST/ACK` de porta fechada, (c) um método HTTP com status e User-Agent, e (d) o SNI dentro do Client Hello.

## O que um SOC Level 1 realmente precisa saber

- 🟢 Camada 4 identifica o **serviço** (porta), camada 7 identifica a **intenção** (conteúdo). O alerta útil quase sempre nasce na 7.
- 🟢 Decorar as portas de referência: 22 SSH, 25/587 SMTP, 53 DNS, 80 HTTP, 389/636 LDAP, 443 HTTPS, 445 SMB, 3389 RDP.
- 🟢 Ler as faixas de status HTTP: 2xx sucesso, 3xx redirecionamento, 4xx erro do cliente, 5xx erro do servidor. Muitos 404 seguidos de um 200 é o padrão de varredura bem-sucedida.
- 🟢 User-Agent de script (`curl`, `python-requests`, PowerShell) saindo de estação de usuário final merece investigação; de servidor de integração, contexto.
- 🟢 `action=blocked` no WAF ou no firewall não encerra o caso — encerra **aquela** tentativa.
- 🟡 Em HTTPS o conteúdo é opaco, mas SNI, certificado, volume e periodicidade continuam visíveis; beacon com intervalo fixo é o sinal mais confiável de C2.
- 🟡 Servidor web (`w3wp.exe`, `httpd`, `nginx`) como processo pai de `cmd.exe` ou `powershell.exe` é indicador forte de web shell (T1505.003).
- 🟡 Sempre correlacionar três fontes antes de concluir: rede (Zeek/firewall), proxy/WAF e endpoint (EDR/Sysmon). Uma fonte só produz conclusão frágil.
- 🟡 Saber a que camada pertence o problema acelera o encaminhamento: camada 1 e 2 vão para a equipe de rede, 3 e 4 para firewall/rede, 5 a 7 para segurança e aplicação.
- 🔴 Consultas próprias em SPL e KQL, com filtro por processo pai e por raridade de destino, transformam o N1 de leitor de alerta em caçador.
- 🔴 Entender que atacante troca de porta e de User-Agent com facilidade; comportamento (periodicidade, volume, cadeia de processos) é mais difícil de disfarçar do que assinatura.
- 🔴 Preservar evidência antes de remediar: arquivo suspeito, log de aplicação e captura de rede. Apagar o artefato destrói a investigação.

## Resumo em 10 linhas

1. O modelo OSI (Open Systems Interconnection) divide a comunicação em 7 camadas, da física à aplicação.
2. A camada 4 (Transporte) escolhe TCP ou UDP, controla portas e garante — ou não — a entrega.
3. As camadas 5 e 6 mantêm a sessão viva e cuidam de formato e criptografia, com destaque para o TLS.
4. A camada 7 (Aplicação) é onde HTTP, DNS, SMTP, SSH, RDP, SNMP e LDAP realmente conversam.
5. Métodos HTTP e códigos de status contam a história do ataque: 404 em série, 200 revelador, 500 de injeção.
6. O User-Agent identifica o programa; scripts em estações de usuário são anomalia até prova em contrário.
7. SQLi, XSS, RCE, web shell, C2 sobre HTTPS e phishing são os ataques que vivem na camada 7.
8. Proxy, WAF e EDR são as três lentes do SOC sobre essa camada; nenhuma sozinha basta.
9. Beacon com intervalo fixo e servidor web gerando shell são os dois padrões que o N1 nunca deve deixar passar.
10. A tabela-resumo das 7 camadas é sua consulta rápida no plantão: camada, PDU, dispositivo, protocolo, ataque e ferramenta.



---
