# Módulo 3 — TCP/IP na prática para o SOC

## Por que este módulo importa para o SOC

Todo alerta que chega ao seu console — um bloqueio de firewall, uma tentativa de autenticação, um beacon de malware — é, no fundo, um pacote que atravessou uma pilha de protocolos. Se você não entende essa pilha, você lê logs como quem lê um idioma estrangeiro: reconhece palavras soltas, mas não a frase. Este módulo constrói essa base do zero, sem pressupor que você já saiba o que é uma rede.

**Índice do módulo:**

- História, arquitetura e comparação com o OSI
- IP, TCP, UDP, ICMP e ARP campo a campo
- Packet flow completo: do navegador até a resposta

---

## De onde veio o TCP/IP

### O que é

Analogia: imagine o sistema postal. Existe o envelope (com endereço de origem e destino), o serviço que garante que a carta chegou (aviso de recebimento), e a carta em si (o conteúdo). O TCP/IP é exatamente isso, só que para dados — um conjunto de regras que permite que máquinas diferentes, de fabricantes diferentes, conversem.

Tecnicamente, **TCP/IP** (*Transmission Control Protocol / Internet Protocol* — Protocolo de Controle de Transmissão / Protocolo da Internet) é uma família de protocolos organizada em camadas.

### Como funciona a história

No fim dos anos 1960, a **ARPANET** — rede da **DARPA** (*Defense Advanced Research Projects Agency*, a agência de pesquisa do Departamento de Defesa dos Estados Unidos) — conectava poucas universidades com um protocolo chamado NCP. O problema: cada rede nova falava um dialeto diferente.

Em 1974, **Vint Cerf** e **Bob Kahn** publicaram o trabalho que resolveu isso, propondo um protocolo capaz de interligar redes distintas — daí o termo *internetworking*, que virou "internet". A especificação amadureceu e, em setembro de 1981, saíram as duas RFCs (*Request for Comments*, os documentos-padrão da internet) que ainda hoje são a base de tudo:

| RFC | Protocolo | O que define |
|---|---|---|
| **RFC 791** | IP | Endereçamento e roteamento de pacotes |
| **RFC 793** | TCP | Conexão confiável, ordenada, com retransmissão |
| RFC 768 | UDP | Envio sem conexão, sem garantia de entrega |
| RFC 792 | ICMP | Mensagens de controle e erro (ping, unreachable) |

Em 1º de janeiro de 1983 a ARPANET migrou oficialmente para TCP/IP — o "flag day" que costuma ser citado como o nascimento da internet.

### Por que o TCP/IP venceu o OSI

O **OSI** (*Open Systems Interconnection*), da ISO, era o modelo oficial, aprovado por comitês internacionais. Perdeu por motivos práticos:

- O TCP/IP já **rodava** enquanto o OSI ainda era documento.
- Era gratuito e vinha embutido no BSD Unix, distribuído às universidades.
- Especificação simples, implementável por um programador em semanas.
- O governo dos EUA financiou a adoção real, não a teórica.

Resultado: o OSI sobreviveu como **vocabulário**; o TCP/IP sobreviveu como **software**.

---

## Arquitetura em camadas

### O que é uma camada

Analogia: uma empresa de entregas. O atendente não precisa saber dirigir o caminhão; o motorista não precisa saber o que tem na caixa. Cada função só conversa com a de cima e a de baixo. Isso é encapsulamento.

### As 4 camadas do TCP/IP

| # | Camada | Função | Exemplos | Unidade de dados |
|---|---|---|---|---|
| 4 | **Aplicação** | O que o usuário quer fazer | HTTP, DNS, SMTP, TLS, SMB, Kerberos | Dados / mensagem |
| 3 | **Transporte** | Entregar ao processo certo, com ou sem garantia | TCP (porta), UDP (porta) | Segmento (TCP) / Datagrama (UDP) |
| 2 | **Internet** | Endereçar e rotear entre redes | IP, ICMP, ARP (auxiliar) | Pacote |
| 1 | **Acesso à Rede** | Colocar bits no meio físico | Ethernet, Wi-Fi, MAC | Quadro (frame) |

A **variante didática de 5 camadas** apenas divide a camada 1 em duas: **Física** (cabo, sinal elétrico, rádio) e **Enlace** (Ethernet, endereço MAC, switch). É útil no SOC porque separa "o cabo caiu" de "a tabela ARP foi envenenada" — problemas completamente distintos.

### Comparação lado a lado

| OSI | Camada TCP/IP | O que você vê no SOC |
|---|---|---|
| 7 Aplicação | Aplicação | URL, query DNS, comando SMB |
| 6 Apresentação | Aplicação | Certificado TLS, JA3, encoding |
| 5 Sessão | Aplicação | Ticket Kerberos, sessão RDP |
| 4 Transporte | Transporte | Porta de origem/destino, flags TCP |
| 3 Rede | Internet | IP de origem/destino, TTL, roteamento |
| 2 Enlace | Acesso à Rede | Endereço MAC, VLAN, ARP |
| 1 Física | Acesso à Rede | Porta do switch, link down |

Regra de bolso: **OSI 5, 6 e 7 colapsam na Aplicação do TCP/IP; OSI 1 e 2 colapsam no Acesso à Rede. As camadas 3 e 4 são um para um.**

### Exemplo prático

O usuário `jsilva` (estação `10.10.20.45`) acessa `www.example.com` (`203.0.113.10`):

- Aplicação: requisição HTTP GET com `Host: www.example.com`
- Transporte: TCP, porta de origem 51422, porta de destino 443
- Internet: IP origem 10.10.20.45 → IP destino 203.0.113.10
- Acesso à Rede: quadro Ethernet até o MAC do gateway `10.10.20.1`

### Como aparece nos logs

Firewall Palo Alto, log TRAFFIC (formato CSV):

```
1,2026/09/03 09:14:22,001801012345,TRAFFIC,end,2561,2026/09/03 09:14:22,10.10.20.45,203.0.113.10,192.0.2.7,203.0.113.10,Regra-Saida-Web,corp\jsilva,,ssl,vsys1,Trust,Untrust,ethernet1/2,ethernet1/1,Log-Padrao,2026/09/03 09:14:20,84213,1,51422,443,41022,443,0x400053,tcp,allow,8412,3120,5292,24,2026/09/03 09:13:58,22,computer-and-internet-info,0,987654321,0x0,10.10.0.0-10.10.255.255,US,0,14,10
```

Leitura campo a campo, mapeada nas camadas:

| Valor no log | Campo | Camada TCP/IP |
|---|---|---|
| `10.10.20.45` / `203.0.113.10` | IP origem / destino | Internet |
| `192.0.2.7` | IP de origem após NAT | Internet |
| `tcp` | Protocolo de transporte | Transporte |
| `51422` / `443` | Porta origem / destino | Transporte |
| `ssl` | App-ID identificado | Aplicação |
| `ethernet1/2` | Interface de entrada | Acesso à Rede |
| `allow` | Ação da regra | Decisão do firewall |

O mesmo evento em Zeek (`conn.log`), separado por tabulação:

```
1756890862.114203	CxT8y21kRm9pQ	10.10.20.45	51422	203.0.113.10	443	tcp	ssl	3.214	1820	7301	SF	T	0	ShADadFf	14	2568	12	7845	-
```

Campos que importam: `ts` (timestamp Unix), `uid` (identificador único da conexão — use-o para cruzar com `ssl.log` e `dns.log`), `id.orig_h`/`id.orig_p` (origem), `id.resp_h`/`id.resp_p` (destino), `service` (aplicação detectada), `conn_state` = `SF` (conexão normal, aberta e fechada corretamente) e `history` = `ShADadFf` (histórico de flags TCP).

### O que o SOC N1 observa

| Sinal | Normal | Suspeito |
|---|---|---|
| Porta 443 com `service=ssl` | Coerente | `service=-` na 443 pode ser túnel ou protocolo não-TLS |
| `conn_state` | `SF` | `S0` (SYN sem resposta) em massa = varredura, T1046 |
| Volume por conexão | Variável | Bytes enviados >> recebidos em saída = possível exfiltração |
| Camada de aplicação | Identificada | App-ID `unknown-tcp` em porta padrão pede análise |

### Erro comum de analista júnior

Confundir **porta** com **aplicação**. Porta 443 é camada de Transporte; TLS é camada de Aplicação. Nada obriga um atacante a colocar TLS na 443 — e é por isso que o campo `service` do Zeek ou o App-ID do Palo Alto valem mais que o número da porta.

---

## Por que o SOC precisa dos dois modelos

O OSI é a **língua franca do troubleshooting**: quando o engenheiro de rede diz "é problema de camada 2", todo mundo entende que se fala de switch, VLAN ou ARP. O TCP/IP é **o que realmente roda** na máquina. Saber traduzir entre os dois é o que permite escalar um incidente com a linguagem certa e ler o log com a precisão certa.

Consulta rápida em Splunk (SPL) para achar conexões TCP sem resposta:

```spl
index=zeek sourcetype=zeek:conn conn_state="S0"
| stats dc(id.resp_p) as portas_distintas count by id.orig_h
| where portas_distintas > 50
| sort - portas_distintas
```

Linha 1: filtra conexões que só tiveram SYN. Linha 2: conta portas distintas por origem. Linha 3: mantém quem tocou mais de 50 portas. Linha 4: ordena pelo pior caso.

Equivalente em KQL (Microsoft Sentinel):

```kql
// Conexões de saída agrupadas por host de origem
DeviceNetworkEvents
| where TimeGenerated > ago(1h)
| where ActionType == "ConnectionFailed"
| summarize PortasDistintas = dcount(RemotePort) by DeviceName, LocalIP
| where PortasDistintas > 50
```

---

### Exercícios — História, arquitetura e comparação com o OSI

1. No log Palo Alto acima, em qual camada do TCP/IP e em qual camada do OSI está o valor `51422`? E o valor `ssl`?
2. Um analista abre um chamado dizendo "problema de camada 3". Três evidências chegam: (a) a porta do switch está *down*; (b) o `traceroute` para 203.0.113.10 morre no terceiro salto; (c) o certificado TLS está expirado. Qual delas realmente é camada 3 do OSI?
3. Verdadeiro ou falso positivo? Um alerta dispara: "Tráfego não-web na porta 80". O Zeek mostra `service=ssh` para `10.10.20.45 → 198.51.100.22:80`, `conn_state=SF`, duração 3.600 segundos, 12 KB enviados e 480 KB recebidos.
4. Qual o próximo passo da investigação no exercício 3?
5. Por que o modelo de 5 camadas ajuda quando a suspeita é envenenamento de ARP?

<details><summary>Ver gabarito</summary>

**1.** `51422` é a porta de origem: camada de **Transporte** no TCP/IP e **camada 4** no OSI. `ssl` é a aplicação identificada pelo App-ID: camada de **Aplicação** no TCP/IP, o que no OSI corresponde às camadas **5, 6 e 7** juntas (sessão, apresentação e aplicação colapsam em uma só no TCP/IP). Esse colapso é justamente a diferença estrutural entre os dois modelos.

**2.** Apenas **(b)**. O `traceroute` trabalha com IP e TTL — camada 3 do OSI, camada Internet do TCP/IP. A porta do switch *down* é camada 1 (física); o certificado expirado é camada 6/7. Nomear a camada errada faz o chamado ir para a equipe errada e o tempo de resposta dobrar.

**3.** **Verdadeiro positivo, e prioritário.** Três indicadores se somam: (i) protocolo de aplicação SSH em porta 80, ou seja, aplicação e porta divergem — o inspetor de protocolo do Zeek olha o conteúdo, não o número da porta; (ii) sessão de uma hora, típica de canal interativo ou túnel, não de navegação; (iii) proporção invertida de bytes para uma saída HTTP. O padrão é consistente com uso de porta comum para evadir filtro de egresso — MITRE ATT&CK **T1571 (Non-Standard Port)**, possivelmente combinado com **T1572 (Protocol Tunneling)**.

**4.** Nesta ordem: (a) usar o `uid` do `conn.log` para puxar `ssl.log`, `dns.log` e `http.log` da mesma conexão e ver se houve resolução DNS prévia; (b) identificar o usuário e o processo na estação `10.10.20.45` via Sysmon **Event ID 3** (conexão de rede, que traz `Image` e `User`) e correlacionar com **Event ID 1** (criação de processo); (c) verificar a reputação de `198.51.100.22` e se outras estações falaram com o mesmo destino; (d) escalar ao N2 com a hipótese formulada — nunca isolar a máquina por conta própria sem seguir o playbook de contenção.

**5.** Porque o modelo de 4 camadas junta cabo e Ethernet em "Acesso à Rede", enquanto o ARP é um problema de **enlace** (camada 2 do OSI): o atacante responde consultas ARP associando o IP do gateway ao próprio MAC. Separar física de enlace deixa claro que o cabo está perfeito e o que está corrompido é a tabela de mapeamento IP↔MAC — diagnóstico e remediação totalmente diferentes.

</details>


## IP, TCP, UDP, ICMP e ARP campo a campo

Pense num pacote de rede como uma encomenda dos Correios. O **cabeçalho** é a etiqueta colada na caixa: quem enviou, para quem vai, quantas vezes ainda pode ser reencaminhada, o que tem dentro. O analista de SOC (Security Operations Center, centro de operações de segurança) vive de ler etiquetas. Nesta seção abrimos cada etiqueta campo a campo.

### O cabeçalho IP — a etiqueta de endereçamento

**O que é.** IP (Internet Protocol, protocolo de internet) é o responsável por dizer *de onde vem* e *para onde vai* cada pacote. Ele não garante entrega, não garante ordem — é o carteiro que só olha o endereço.

**Como funciona.** Todo pacote IPv4 começa com 20 bytes fixos:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-------+-------+---------------+-------------------------------+
|Version|  IHL  |     DSCP/ECN  |         Total Length          |
+-------+-------+---------------+-----+-------------------------+
|         Identification        |Flags|     Fragment Offset     |
+---------------+---------------+-----+-------------------------+
|      TTL      |    Protocol   |        Header Checksum        |
+---------------+---------------+-------------------------------+
|                     Source IP Address                         |
+---------------------------------------------------------------+
|                   Destination IP Address                      |
+---------------------------------------------------------------+
```

| Campo | Tamanho | O que entrega ao analista |
|---|---|---|
| Version | 4 bits | 4 = IPv4, 6 = IPv6. Regra só para IPv4 não vê tráfego IPv6 — ponto cego clássico. |
| IHL (Internet Header Length) | 4 bits | Tamanho do cabeçalho em palavras de 32 bits. Valor 5 = 20 bytes (normal). Maior que 5 = há *options* IP, raríssimo em rede corporativa e digno de investigação. |
| DSCP/ECN | 8 bits | Marcação de qualidade de serviço (voz, vídeo). Útil para separar tráfego de VoIP de tráfego genérico. |
| Total Length | 16 bits | Tamanho total (cabeçalho + dados), máximo 65535. Pacotes minúsculos repetidos podem indicar varredura. |
| Identification | 16 bits | Número que agrupa fragmentos do mesmo pacote original. |
| Flags | 3 bits | DF (Don't Fragment) e MF (More Fragments). |
| Fragment Offset | 13 bits | Posição do fragmento dentro do pacote original. |
| TTL (Time To Live) | 8 bits | Contador que cai 1 a cada roteador. Chega a 0, o pacote morre. |
| Protocol | 8 bits | 1 = ICMP, 6 = TCP, 17 = UDP, 47 = GRE, 50 = ESP. |
| Header Checksum | 16 bits | Verificação de integridade do cabeçalho. |
| Source / Destination | 32 bits cada | Endereço de origem e de destino. |

**TTL é a pista mais subestimada do cabeçalho.** Cada sistema operacional começa com um valor padrão: Linux e macOS usam 64, Windows usa 128, alguns equipamentos de rede usam 255. Se você recebe um pacote com TTL 57, a conta é simples: 64 − 57 = **7 saltos** de distância, e a origem é provavelmente Linux. Um host que se declara "servidor Windows" mas chega com TTL 60 merece uma pergunta.

**Fragmentação como evasão.** Um IDS (Intrusion Detection System, sistema de detecção de intrusão) precisa remontar fragmentos para ver a assinatura maliciosa. Fragmentos minúsculos, sobrepostos ou fora de ordem historicamente serviram para escapar dessa remontagem. Como defesa, o que o SOC observa é o *sintoma*: volume anormal de fragmentos, sobreposição, fragmentos que nunca completam. Não é sua função reproduzir a técnica; é sua função reconhecer o rastro.

**Exemplo prático.** O host `10.10.20.45` (estação da usuária `maria.costa`) conversa com `203.0.113.77`.

**Como aparece nos logs** — Suricata EVE JSON:

```json
{"timestamp":"2026-09-03T09:14:22.104+0000","event_type":"alert","src_ip":"203.0.113.77",
 "dest_ip":"10.10.20.45","proto":"IP","alert":{"signature":"SURICATA IPv4 fragmentation overlap",
 "category":"Protocol Command Decode","severity":2},"flow_id":882910334,
 "ip":{"ttl":57,"id":42311,"flags":"MF","frag_offset":185}}
```

Leitura dos campos: `proto` mostra que o alerta é da camada IP; `ip.ttl` 57 sugere origem Linux a sete saltos; `ip.flags` MF significa que há mais fragmentos a caminho; `frag_offset` 185 indica que este fragmento começa no byte 1480 do pacote original.

**O que o SOC N1 observa.** Normal: TTL coerente com o tipo de host, IHL 5, poucos fragmentos (típico de VPN ou túnel). Suspeito: fragmentos sobrepostos, IHL maior que 5, TTL que não bate com o sistema operacional declarado no inventário.

**Erro comum de analista júnior.** Tratar TTL como valor absoluto ("TTL 57 é anormal"). Não é: TTL só faz sentido comparado ao padrão do sistema operacional e ao número de saltos esperado do caminho.

### O cabeçalho TCP — a conversa com confirmação

**O que é.** TCP (Transmission Control Protocol, protocolo de controle de transmissão) é a carta registrada com aviso de recebimento: numera, confirma e reenvia o que se perdeu.

```
+-------------------------------+-------------------------------+
|          Source Port          |       Destination Port        |
+---------------------------------------------------------------+
|                        Sequence Number                        |
+---------------------------------------------------------------+
|                     Acknowledgment Number                     |
+-------+-----------+-----------+-------------------------------+
| Offset| Reserved  |   Flags   |            Window             |
+-------+-----------+-----------+-------------------------------+
|           Checksum            |        Urgent Pointer         |
+-------------------------------+-------------------------------+
```

| Campo | O que entrega ao analista |
|---|---|
| Source / Destination Port | Identifica o serviço (443 HTTPS, 3389 RDP, 445 SMB). Porta de destino alta e incomum = candidato a canal de comando e controle. |
| Sequence Number | Numeração dos bytes enviados. Permite remontar a sessão. |
| Acknowledgment Number | Próximo byte esperado. Confirma o que chegou. |
| Data Offset | Tamanho do cabeçalho TCP. 5 = 20 bytes; maior indica options (MSS, SACK, timestamps). |
| Flags | SYN abre, ACK confirma, FIN encerra educadamente, RST derruba, PSH entrega já, URG urgente. |
| Window | Quantos bytes o receptor aceita sem confirmar. Window 0 = receptor sobrecarregado. |
| Checksum | Integridade de cabeçalho + dados. |

A abertura de conexão é o *three-way handshake*: SYN → SYN/ACK → ACK. Uma varredura de portas costuma deixar SYN sem ACK, ou SYN seguido de RST.

**Como aparece nos logs** — Cisco ASA:

```
%ASA-6-302013: Built outbound TCP connection 51224 for outside:203.0.113.90/443
 (203.0.113.90/443) to inside:10.10.20.45/49877 (198.51.100.10/49877)
%ASA-6-302014: Teardown TCP connection 51224 for outside:203.0.113.90/443
 to inside:10.10.20.45/49877 duration 0:00:02 bytes 1842 TCP FINs
```

`302013` é conexão criada, `302014` é conexão encerrada; `duration` e `bytes` são o par de ouro para achar sessão longa com pouco dado — sinal clássico de *beacon*.

**Erro comum de analista júnior.** Confundir "conexão criada" com "conexão bem-sucedida". O ASA registra 302013 quando o firewall permite o fluxo, não quando o handshake completa.

### O cabeçalho UDP — simples, rápido e sem testemunhas

```
+-------------------------------+-------------------------------+
|          Source Port          |       Destination Port        |
+-------------------------------+-------------------------------+
|            Length             |           Checksum            |
+-------------------------------+-------------------------------+
```

Apenas 8 bytes. UDP (User Datagram Protocol, protocolo de datagrama de usuário) é o cartão-postal: sai, e ninguém confirma. Isso o torna atraente para dois abusos.

**Exfiltração:** dados escondidos em consultas DNS (Domain Name System, sistema de nomes de domínio) na porta 53, que quase toda rede libera — técnica MITRE ATT&CK **T1071.004** e **T1048**. **Amplificação:** o atacante forja o endereço de origem e uma resposta pequena vira uma resposta enorme contra a vítima (DNS, NTP, memcached) — **T1498.002**.

```
type=traffic subtype=forward srcip=10.10.20.45 dstip=10.10.0.53 proto=17
 service=DNS dstport=53 sentbyte=48210 rcvdbyte=6120 duration=612
 hostname="a7f3b2c9d1e4.tunnel.example.com" action=accept
```

Log FortiGate em `key=value`: `proto=17` é UDP; `sentbyte` muito maior que `rcvdbyte` em DNS é invertido em relação ao normal (consulta pequena, resposta maior) e o `hostname` longo e aleatório é a assinatura de túnel DNS.

### ICMP — o protocolo dos recados de erro

ICMP (Internet Control Message Protocol, protocolo de mensagens de controle da internet) é o bilhete que o roteador cola na encomenda devolvida.

| Tipo | Código | Nome | Leitura para o SOC |
|---|---|---|---|
| 0 | 0 | Echo Reply | Resposta ao ping. Host vivo. |
| 3 | 0 | Net Unreachable | Rota inexistente. |
| 3 | 1 | Host Unreachable | Rede existe, host não responde. |
| 3 | 3 | Port Unreachable | Porta UDP fechada — base da varredura UDP. |
| 3 | 4 | Fragmentation Needed and DF Set | Problema de MTU; causa de "site que não carrega". |
| 3 | 13 | Communication Administratively Prohibited | Firewall ou ACL bloqueou. |
| 5 | 0/1 | Redirect | Roteador manda usar outro gateway. Em LAN, pode ser desvio malicioso. |
| 8 | 0 | Echo Request | O ping propriamente dito. |
| 11 | 0 | TTL Exceeded in Transit | TTL chegou a zero. É o que faz o traceroute funcionar. |
| 11 | 1 | Fragment Reassembly Time Exceeded | Fragmentos incompletos. |

**Ping passo a passo.** `10.10.20.45` envia ICMP tipo 8 para `10.10.0.10`. O destino responde tipo 0. O tempo entre os dois é a latência.

**Traceroute passo a passo.** A estação envia um pacote com TTL 1. O primeiro roteador decrementa para 0 e devolve **tipo 11 código 0**, revelando seu endereço. Repete com TTL 2, TTL 3, e assim por diante, desenhando o caminho salto a salto.

**ICMP tunneling** (**T1095**): o campo de dados do ping aceita carga arbitrária, então dá para esconder tráfego ali. **Ping sweep** (**T1018**/**T1046**): um host manda echo request para toda a faixa procurando quem está vivo.

```
2026-09-03T10:02:11Z 10.10.20.45 10.10.30.1 - - icmp 8 0 OTH T F 0 0 1 84 0 0
2026-09-03T10:02:11Z 10.10.20.45 10.10.30.2 - - icmp 8 0 OTH T F 0 0 1 84 0 0
2026-09-03T10:02:11Z 10.10.20.45 10.10.30.3 - - icmp 8 0 OTH T F 0 0 1 84 0 0
```

`conn.log` do Zeek: origem única, destinos sequenciais, mesmo tamanho (84 bytes), tudo no mesmo segundo — assinatura de ping sweep.

```spl
index=network sourcetype=zeek:conn proto=icmp
| stats dc(id.resp_h) AS destinos_unicos by id.orig_h
| where destinos_unicos > 50
```
Linha 1 filtra ICMP no Zeek; linha 2 conta destinos distintos por origem; linha 3 destaca quem tocou mais de 50 hosts.

**O que o SOC N1 observa.** Normal: monitoração pingando servidores em intervalo fixo. Suspeito: pacote ICMP com carga grande (acima de ~100 bytes de dados) ou fluxo ICMP contínuo para um IP externo.

**Erro comum de analista júnior.** Fechar o caso porque "é só um ping". ICMP com payload consistente e destino externo é candidato a canal de exfiltração.

### ARP — traduzindo IP em endereço físico

**O que é.** ARP (Address Resolution Protocol, protocolo de resolução de endereços) descobre o MAC (Media Access Control, endereço físico da placa de rede) correspondente a um IP dentro da mesma rede local. É gritar no corredor: "quem é o 10.10.20.1?".

- **ARP Request:** broadcast perguntando quem tem determinado IP.
- **ARP Reply:** unicast respondendo "sou eu, meu MAC é este".
- **Gratuitous ARP:** anúncio não solicitado; legítimo em failover de cluster, suspeito quando repetido sem motivo.
- **Cache ARP:** tabela local com o que já foi aprendido, guardada por poucos minutos.

**ARP spoofing** (**T1557.002**): a máquina do atacante responde no lugar do gateway e o tráfego passa por ela. O rastro é um MAC associado a dois IPs, ou o IP do gateway trocando de MAC. Ferramentas como Responder exploram esse tipo de envenenamento em rede local; o que interessa aqui é o rastro, não o uso.

```
<134>1 2026-09-03T10:40:02.221Z sw-core-01.corp.local dot1x - ARP-INSPECT
 [meta] "Invalid ARP reply on Gi1/0/14 vlan 20 sender_ip=10.10.20.1
 sender_mac=00:1a:2b:3c:4d:99 binding_mac=00:1a:2b:3c:4d:01 action=drop"
```

Syslog RFC5424 de switch com Dynamic ARP Inspection: `sender_ip` é o gateway, `sender_mac` não bate com `binding_mac` do DHCP snooping — resposta forjada, descartada.

```kql
// Detecta um MAC anunciando vários IPs na mesma janela
DeviceNetworkEvents
| where TimeGenerated > ago(1h)                       // última hora
| where Protocol == "Arp"                             // apenas ARP
| summarize ips = dcount(LocalIP) by LocalMAC = tostring(AdditionalFields.MAC)
| where ips > 3                                       // um MAC com mais de 3 IPs
```

**Erro comum de analista júnior.** Confundir gratuitous ARP legítimo de um cluster em failover com ataque. Antes de escalar, confirme com a equipe de rede se há IP virtual naquele segmento.

### Exercícios — IP, TCP, UDP, ICMP e ARP campo a campo

1. Um pacote chega ao sensor com TTL 122 e o inventário diz que a origem `10.10.40.18` é um servidor Windows. Quantos saltos o pacote percorreu e a informação é coerente?
2. No log ASA abaixo, o que chama atenção e qual a hipótese?
   `%ASA-6-302014: Teardown TCP connection 90211 for outside:203.0.113.55/8443 to inside:10.10.20.45/50122 duration 8:00:04 bytes 4120 TCP FINs`
3. Um alerta diz "possível ping sweep a partir de 10.10.0.240". Você descobre que esse IP é o servidor de monitoração da equipe de infraestrutura, que varre a faixa 10.10.30.0/24 às 02:00 todo dia. Verdadeiro ou falso positivo? Justifique.
4. A estação de `jsilva` (10.10.20.61) gerou 48 MB enviados e 2 MB recebidos em consultas UDP porta 53 para o resolver interno, com nomes longos e aleatórios. Qual o próximo passo da investigação?
5. Qual código ICMP você espera ver quando uma porta UDP fechada é sondada, e por que isso é útil para quem faz varredura?

<details><summary>Ver gabarito</summary>

1. **6 saltos, e é coerente.** Windows inicia o TTL em 128; 128 − 122 = 6 roteadores atravessados. Se o mesmo host aparecesse com TTL 58, o valor inicial seria 64 (padrão Linux) e haveria contradição com o inventário — sinal de spoofing, de NAT mal documentado ou de registro de inventário desatualizado. Nunca conclua nada só pelo TTL: use-o como pista para confrontar com o CMDB.

2. **Sessão de 8 horas com apenas 4120 bytes trocados.** A média é de menos de 1 byte por segundo — ninguém navega assim. O padrão é típico de *beacon* de comando e controle mantendo a conexão viva (T1071). Some-se a isso a porta 8443, que é HTTPS alternativo e menos monitorada. Próximo passo: correlacionar com logs de proxy e de EDR na estação `10.10.20.45`, verificar qual processo abriu o socket (Sysmon Event ID 3) e checar a reputação de `203.0.113.55`.

3. **Falso positivo, mas só depois de validado.** Três checagens fecham o caso: o IP de origem bate com o inventário do servidor de monitoração; o horário é o da janela agendada; e o alcance é exatamente a faixa configurada. Se qualquer um dos três divergir — por exemplo, o mesmo IP varrendo 10.10.50.0/24 às 14:00 — vira incidente, porque um servidor de monitoração comprometido é um excelente ponto de partida para reconhecimento. Documente a exceção com escopo (IP + faixa + janela), nunca com "ignorar esse IP".

4. **Hipótese: túnel ou exfiltração via DNS (T1048/T1071.004).** A proporção está invertida: em DNS normal, a consulta é pequena e a resposta é maior. Passos: (a) extrair os nomes consultados do `dns.log` do Zeek e medir entropia e comprimento dos rótulos; (b) identificar o domínio pai e verificar quando foi registrado e sua reputação; (c) no endpoint, achar o processo responsável pelas consultas (Sysmon Event ID 22, DNS query); (d) se confirmado, isolar a estação e bloquear o domínio pai no resolver. Não bloqueie a porta 53 inteira — isso derruba a rede toda.

5. **ICMP tipo 3, código 3 (Port Unreachable).** Como UDP não tem handshake, a única resposta que diferencia "porta fechada" de "porta aberta" é justamente essa mensagem de erro: porta fechada devolve tipo 3/código 3, porta aberta normalmente fica em silêncio. Por isso varreduras UDP são lentas e barulhentas em ICMP. Para o SOC, um pico de ICMP 3/3 saindo de um único host interno para muitos destinos é forte indício de varredura de reconhecimento (T1046).

</details>


## Packet flow completo: do navegador até a resposta

Imagine que você pede uma pizza por telefone. Você não sabe o endereço da pizzaria de cor, então consulta uma lista (isso é o DNS). Depois o motoboy sai, e a cada esquina ele pergunta o caminho a um guarda diferente (isso é o roteamento salto a salto). O destino final — a casa do cliente — nunca muda, mas quem carrega a pizza muda a cada trecho. Essa é exatamente a diferença entre o endereço IP (Internet Protocol, protocolo da internet, que não muda) e o endereço MAC (Media Access Control, controle de acesso ao meio, que muda a cada salto). Guarde isso: é a pegadinha clássica de entrevista para SOC (Security Operations Center, centro de operações de segurança).

Vamos abrir, passo a passo, o que acontece quando a usuária **maria.costa**, na estação `10.10.20.57`, digita `https://loja.example.com` no navegador.

### Os 24 passos, do teclado até o FIN

1. **Digitação e normalização da URL.** O navegador entende que o esquema é HTTPS (HyperText Transfer Protocol Secure), a porta padrão é a **443/TCP** e o nome do host é `loja.example.com`.
2. **Cache do navegador (DNS interno).** O Chrome/Edge guarda respostas de DNS (Domain Name System, sistema de nomes de domínio) por alguns minutos. Se houver entrada válida, os passos 4 a 10 são pulados — e você **não verá nenhum log de DNS**. Isso explica muita "conexão sem consulta DNS" que assusta analista junior.
3. **Cache do sistema operacional.** No Windows, é o serviço DNS Client (`dnscache`). Comando de leitura: `ipconfig /displaydns`.
4. **Arquivo hosts.** `C:\Windows\System32\drivers\etc\hosts` (Linux: `/etc/hosts`). Tem prioridade sobre o DNS. Malware usa esse arquivo para sequestrar nomes — técnica MITRE **T1565.001** (Stored Data Manipulation). Sysmon Event ID 11 (File Create) nesse caminho é achado de alta prioridade.
5. **Consulta ao resolvedor local.** A estação envia uma query recursiva ao DNS configurado por DHCP — normalmente o controlador de domínio `10.10.10.10`, em **UDP/53**.
6. **Resolvedor pergunta aos root servers.** O servidor recursivo pergunta a um dos 13 conjuntos raiz "quem cuida de `.com`?". A raiz não sabe o IP final; ela **refere** (referral) os servidores TLD (Top-Level Domain, domínio de topo).
7. **Resolvedor pergunta ao TLD `.com`.** O TLD responde com os servidores autoritativos de `example.com` (registros NS).
8. **Resolvedor pergunta ao autoritativo.** O autoritativo responde o registro **A** (IPv4) ou **AAAA** (IPv6): `loja.example.com A 203.0.113.45`.
9. **Cache em cascata.** O resolvedor guarda a resposta pelo TTL (Time To Live, tempo de vida) e devolve à estação. A estação também guarda.
10. **Estação decide: local ou remoto?** Aplica a máscara. `10.10.20.57/24` e `203.0.113.45` não estão na mesma rede, logo o pacote vai ao **gateway padrão** `10.10.20.1`.
11. **ARP para o gateway.** A estação não conhece o MAC do gateway. Envia um **ARP Request** em broadcast (`ff:ff:ff:ff:ff:ff`): "quem tem 10.10.20.1?".
12. **ARP Reply.** O roteador responde com o MAC dele, ex. `00:1a:2b:3c:4d:5e`. Entra na tabela ARP (`arp -a`).
13. **Montagem do quadro (frame).** MAC de origem = estação; MAC de destino = **gateway**; IP de origem = `10.10.20.57`; IP de destino = `203.0.113.45`. Repare: o MAC de destino **não é** o do servidor.
14. **Primeiro salto.** O roteador recebe o quadro, **descarta o cabeçalho Ethernet**, olha a tabela de rotas, decrementa o TTL do IP em 1, recalcula o checksum e **monta um quadro novo** com MAC de origem dele e MAC de destino do próximo salto.
15. **Salto a salto até a borda.** Repete-se em cada roteador. **O par IP origem/destino permanece igual do começo ao fim; o par MAC muda em cada trecho.** Exceção: o IP de origem muda quando há NAT (passo 16).
16. **NAT no firewall de borda.** O firewall troca `10.10.20.57:51422` pelo IP público da empresa `198.51.100.7:41003` (PAT/Source NAT) e guarda a tradução na tabela de sessões. Sem esse mapeamento e sem o log correspondente, você **não consegue** ligar um alerta externo à estação interna.
17. **TCP SYN.** A estação envia o primeiro pacote do three-way handshake, com a flag SYN e um ISN (Initial Sequence Number, número de sequência inicial) aleatório.
18. **TCP SYN-ACK.** O servidor `203.0.113.45` responde com SYN+ACK.
19. **TCP ACK.** A estação confirma. Sessão **ESTABLISHED**. Só agora existe "conexão".
20. **TLS ClientHello.** O navegador envia versões suportadas, cifras e a extensão **SNI** (Server Name Indication) contendo `loja.example.com` em texto claro (exceto quando há ECH). O SNI é a principal fonte de visibilidade de nome em tráfego cifrado.
21. **TLS ServerHello + Certificado.** O servidor escolhe a cifra, envia a cadeia de certificados; o cliente valida assinatura, validade e nome (CN/SAN).
22. **Troca de chaves + Finished.** ECDHE gera a chave de sessão; ambos enviam Finished. Em TLS 1.3 isso cabe em 1-RTT. Daqui em diante tudo é cifrado.
23. **HTTP GET.** Dentro do túnel: `GET / HTTP/1.1` com `Host:` e `User-Agent:`.
24. **Resposta e encerramento.** `HTTP/1.1 200 OK` mais o corpo. Ao fim: FIN → ACK → FIN → ACK (ou RST abrupto).

### Diagrama ASCII do fluxo

```
maria.costa (10.10.20.57)
   |  [2-4] cache navegador / cache SO / hosts
   |  [5] DNS query UDP/53 --> DC 10.10.10.10
   |                              |--[6] root  ".com fica com..."
   |                              |--[7] TLD   "example.com fica com..."
   |                              |--[8] auth  "A 203.0.113.45"
   |  [11-12] ARP: "quem tem 10.10.20.1?" -> 00:1a:2b:3c:4d:5e
   v
[SW acesso] --> [GW 10.10.20.1] --> [core] --> [FW borda / NAT]
 MAC muda        MAC muda            MAC muda    IP origem muda p/ 198.51.100.7
 IP  igual       IP  igual           IP  igual   (unica excecao ao "IP nao muda")
   |
   |  [17-19] SYN -> SYN/ACK -> ACK   (porta 443/TCP)
   |  [20-22] ClientHello(SNI) -> ServerHello+Cert -> KeyExchange -> Finished
   |  [23-24] GET / -> 200 OK -> FIN/ACK
   v
loja.example.com (203.0.113.45)
```

### Como aparece nos logs

Zeek separa cada etapa em um arquivo diferente — é o melhor material didático que existe:

```
# dns.log
1725364801.114  CxA1b2  10.10.20.57  51999  10.10.10.10  53  udp  loja.example.com  1  A  0  NOERROR  F  203.0.113.45  300.000

# conn.log
1725364801.402  CyD3e4  10.10.20.57  51422  203.0.113.45  443  tcp  ssl  12.771  1842  38210  SF  ShADadFf

# ssl.log
1725364801.688  CyD3e4  TLSv13  TLS_AES_256_GCM_SHA384  loja.example.com  CN=loja.example.com  T  ok
```

Campos que importam: em `dns.log`, o par query/answers e o TTL; em `conn.log`, `conn_state=SF` significa handshake completo e encerramento normal (`S0` = SYN sem resposta, `REJ` = RST); em `ssl.log`, `server_name` é o SNI e `validation_status=ok` indica certificado confiável.

Palo Alto entrega a mesma sessão em uma linha CSV com o NAT já resolvido:

```
1,2026/09/03 10:00:14,001801023456,TRAFFIC,end,2561,2026/09/03 10:00:14,10.10.20.57,203.0.113.45,198.51.100.7,203.0.113.45,Permitir-Web,corp\maria.costa,,ssl,vsys1,Trust,Untrust,ae1.20,ae2.10,LogTudo,51422,41003,443,443,0x400053,tcp,allow,40052,1842,38210,44,web-browsing
```

Leia assim: campos 8 e 9 são IP de origem e destino **antes** do NAT; 10 e 11 são **depois**. Portas 24 e 25 (`51422` → `41003`) mostram a tradução. É exatamente essa linha que amarra `198.51.100.7` de volta à `maria.costa`.

FortiGate, no formato chave=valor:

```
date=2026-09-03 time=10:00:14 devname="FGT-BORDA" type="traffic" subtype="forward" srcip=10.10.20.57 srcport=51422 dstip=203.0.113.45 dstport=443 transip=198.51.100.7 transport=41003 action="accept" policyid=12 service="HTTPS" user="maria.costa" sentbyte=1842 rcvdbyte=38210 duration=12
```

Cisco ASA registra a criação e a remoção da tradução:

```
%ASA-6-302013: Built outbound TCP connection 884512 for outside:203.0.113.45/443 (203.0.113.45/443) to inside:10.10.20.57/51422 (198.51.100.7/41003)
%ASA-6-302014: Teardown TCP connection 884512 duration 0:00:12 bytes 40052 TCP FINs
```

### O que o SOC N1 observa

| Sinal | Normal | Suspeito |
|---|---|---|
| DNS | poucas queries, TTL padrão, nome corporativo | centenas de subdomínios aleatórios no mesmo domínio (DNS tunneling, T1071.004) |
| conn_state Zeek | `SF` | muitos `S0` seguidos para IPs diferentes (varredura, T1046) |
| SNI vs DNS | SNI bate com a query anterior | conexão TLS sem query DNS correspondente = IP fixado no código (T1071.001) |
| NAT | 1 sessão por aba | milhares de sessões/minuto de 1 host |
| Certificado | `validation_status=ok` | autoassinado, validade de 1 dia, CN genérico |

**Erro comum de analista junior:** bloquear o IP público `198.51.100.7` visto em um alerta externo. Esse é o **seu** IP de NAT — bloqueá-lo derruba a empresa inteira. Sempre traduza primeiro, usando o log de NAT e o horário exato.

### Consultas prontas

```spl
index=firewall sourcetype=pan:traffic dest_port=443
| eval nat_pair=src_ip." -> ".src_translated_ip           /* liga interno ao publico */
| stats dc(dest_ip) as destinos, sum(bytes_out) as saida by src_ip, user
| where destinos > 200 OR saida > 500000000                /* varredura ou exfiltracao */
```

```kql
DeviceNetworkEvents
| where RemotePort == 443 and ActionType == "ConnectionSuccess"
| where isnotempty(RemoteUrl)                              // SNI/URL observado
| summarize Conexoes=count(), Destinos=dcount(RemoteIP) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m)
| where Destinos > 100                                     // muitos destinos em 5 min
```

### Exercícios — Packet flow completo: do navegador até a resposta

1. A estação `10.10.20.57` acessa `203.0.113.45`, passando por 3 roteadores. Quantos pares de MAC diferentes existem no caminho e quantos pares de IP?
2. No `conn.log` aparecem 400 linhas com `conn_state=S0`, origem `10.10.20.57`, destinos `10.10.30.1` a `10.10.30.254`, portas 22 e 445, em 40 segundos. Verdadeiro ou falso positivo? Qual a técnica MITRE?
3. Há `ssl.log` com `server_name=cdn.example.com` mas nenhuma entrada em `dns.log` nos 10 minutos anteriores. Cite duas explicações benignas e uma maliciosa.
4. Um alerta de terceiro reporta abuso vindo de `198.51.100.7:41003` às 10:00:14. Qual é o próximo passo exato da investigação?

<details><summary>Ver gabarito</summary>

1. **4 pares de MAC** (estação→R1, R1→R2, R2→R3, R3→servidor) e **1 par de IP** (`10.10.20.57` → `203.0.113.45`), que só muda se houver NAT na borda — e aí a mudança é do IP de origem, não do destino. O TTL do IP cai de 128 para 125.
2. **Verdadeiro positivo provável.** `S0` = SYN enviado sem resposta; 254 destinos em portas de administração (22 SSH e 445 SMB) em 40 segundos é varredura de rede — **T1046 (Network Service Discovery)**. Próximo passo: identificar o processo que originou, via Sysmon Event ID 3 (Network Connection) correlacionando porta de origem e horário; se for `nmap.exe` ou script, escalar.
3. Benignas: (a) a resposta veio do **cache** do navegador ou do sistema, então não houve query nova; (b) a resolução aconteceu por outro caminho — DoH (DNS over HTTPS) ou um proxy que resolveu pelo cliente. Maliciosa: conexão a IP **fixado no código** (hardcoded) do malware, que evita o DNS de propósito — combine com `validation_status` do certificado e reputação do destino.
4. Consultar o log de NAT do firewall (Palo Alto campos 10/11 e 25, ou ASA `%ASA-6-302013`) filtrando pela **porta traduzida 41003** no minuto do evento. Isso devolve o IP interno e, com o User-ID, o usuário. Só depois isole a estação. Nunca bloqueie o próprio IP público de saída.

</details>

## Mini-laboratório — TCP/IP na prática, do DNS ao TLS

**Pré-requisitos:** VirtualBox com uma VM Linux (Ubuntu Desktop) ou um Windows com Wireshark instalado; permissão para capturar tráfego na própria máquina de laboratório.

1. Abra o Wireshark e inicie a captura na interface ativa. Limpe o cache: no Windows, `ipconfig /flushdns`; no Linux, `sudo resolvectl flush-caches`.
2. Limpe a tabela ARP: `arp -d *` (Windows, terminal como administrador) ou `sudo ip neigh flush all`.
3. No navegador, acesse um site HTTPS público qualquer. Pare a captura após 15 segundos.
4. Aplique o filtro `arp`. **Observe:** o Request em broadcast e o Reply com o MAC do gateway.
5. Filtro `dns`. **Observe:** a query, o tipo A e a resposta. Anote o IP retornado.
6. Filtro `tcp.flags.syn==1 && tcp.flags.ack==0`. **Observe:** o SYN inicial e a porta de origem alta.
7. Filtro `tls.handshake.type==1`. Expanda até `server_name`. **Observe:** o SNI em texto claro.
8. Filtro `tls.handshake.type==11`. **Observe:** a cadeia de certificados.
9. Clique com o botão direito em qualquer pacote da sessão → Follow → TCP Stream. **Observe:** os dados de aplicação estão cifrados.
10. Rode `tracert 8.8.8.8` (ou `traceroute`) e compare: o IP de destino é sempre o mesmo; cada linha é um roteador diferente.

**Critério de sucesso:** você consegue apontar, na sua própria captura, o ARP Reply, a resposta DNS, os três pacotes do handshake, o SNI e o certificado — e explicar por que o MAC de destino do primeiro pacote é o do gateway, não o do servidor.

## O que um SOC Level 1 realmente precisa saber

- 🟢 O IP de origem/destino não muda ponta a ponta; o MAC muda a cada salto. A única exceção ao IP é o NAT.
- 🟢 Antes de bloquear um IP público, verifique se ele não é o IP de NAT da própria empresa.
- 🟢 Portas-chave de cor: 53 DNS, 80 HTTP, 443 HTTPS, 22 SSH, 3389 RDP, 445 SMB, 88 Kerberos, 389/636 LDAP.
- 🟢 As três etapas do handshake TCP: SYN, SYN-ACK, ACK. Sessão sem ACK final não é conexão.
- 🟢 SNI é o nome do site visível mesmo em tráfego cifrado — é a sua principal pista em HTTPS.
- 🟡 `conn_state` do Zeek: `SF` normal, `S0` sem resposta (varredura), `REJ` recusado.
- 🟡 Conexão TLS sem consulta DNS anterior merece verificação: cache, DoH ou IP fixado no malware.
- 🟡 ARP não tem autenticação; entradas duplicadas para o gateway sugerem ARP spoofing (T1557.002).
- 🟡 O arquivo hosts tem prioridade sobre o DNS; criação ou alteração dele é sinal forte (T1565.001).
- 🔴 Correlacionar horário com precisão exige NTP sincronizado e ciência do fuso de cada log.
- 🔴 Volume anômalo de subdomínios no mesmo domínio pai indica DNS tunneling (T1071.004).
- 🔴 Certificado autoassinado, de validade curta ou com CN genérico em destino externo pede análise de C2.

## Resumo em 10 linhas

1. TCP/IP tem 4 camadas e é o modelo que realmente roda na rede; o OSI serve de vocabulário.
2. IP entrega o pacote fim a fim; Ethernet entrega o quadro apenas até o próximo salto.
3. Por isso o par de MAC muda em cada trecho e o par de IP permanece — salvo NAT.
4. ARP resolve IP em MAC dentro do segmento local, sem qualquer autenticação.
5. DNS traduz nome em IP percorrendo resolvedor, raiz, TLD e servidor autoritativo.
6. Cache de navegador, cache do sistema e arquivo hosts podem eliminar a consulta DNS.
7. TCP estabelece sessão com três pacotes e a encerra com FIN/ACK ou RST.
8. TLS negocia cifra e chaves; o SNI e o certificado são a visibilidade que resta ao SOC.
9. Cada etapa cai em um log diferente: dns.log, conn.log, ssl.log, firewall e NAT.
10. Investigação sólida começa traduzindo o NAT e termina no usuário e no processo de origem.



---
