# Módulo 12 — Wireshark e análise de pacotes para o SOC

## Por que este módulo importa para o SOC

Alertas mentem. O log de um firewall diz que houve "tráfego suspeito", mas não diz o que estava dentro do pacote. A captura de pacotes é a única fonte de verdade que mostra byte a byte o que aconteceu na rede — quem falou com quem, em que ordem, com qual protocolo e com qual certificado. Um analista de SOC Nível 1 que sabe abrir uma captura e responder "isto é ruído de aplicação corporativa" ou "isto é comando e controle" resolve o chamado sozinho, em vez de escalar tudo para o Nível 2. Este módulo ensina a chegar lá.

Índice do módulo:

- Fundamentos de captura, interface e filtros de captura
- Filtros de exibição e funções de investigação
- Investigações práticas e metodologia de análise

## O que é sniffing e o modo promíscuo

**O que é.** Imagine uma sala de reuniões onde todo mundo fala em voz alta. Normalmente você presta atenção apenas quando alguém diz o seu nome e ignora o resto. *Sniffing* (farejar tráfego) é decidir prestar atenção em **tudo** o que é dito na sala, mesmo o que não é para você.

**Como funciona.** A placa de rede — NIC, de *Network Interface Card* — recebe eletricamente vários quadros (frames) e, por padrão, descarta os que não têm o seu endereço MAC (*Media Access Control*, o endereço físico da placa) nem um endereço de broadcast/multicast. O **modo promíscuo** desliga esse descarte: a placa entrega ao sistema operacional tudo o que chegar nela. É por isso que o Wireshark pergunta se você quer habilitar promíscuo ao iniciar a captura.

**Exemplo prático.** A estação `10.10.20.45` (usuária `maria.costa`) está em modo promíscuo. Ela vê todo o tráfego que **chega ao cabo dela** — mas, num switch moderno, isso é quase só o tráfego dela mesma. O modo promíscuo é condição necessária, não suficiente.

### Por que você não vê o tráfego dos outros num switch

Um **hub** antigo repetia cada bit para todas as portas: qualquer máquina via tudo. Um **switch** aprende os endereços MAC e entrega o quadro **só na porta do destinatário**. Resultado: mesmo em modo promíscuo, você recebe apenas o seu tráfego, o broadcast (ARP, DHCP) e o multicast. Para ver o tráfego dos outros é preciso pedir isso à infraestrutura.

| Ponto de captura | O que é | Vantagem | Limitação |
|---|---|---|---|
| Porta espelho (SPAN, *Switched Port Analyzer*) | O switch copia o tráfego de portas/VLANs para uma porta de monitoração | Sem hardware extra, configurável remotamente | Descarta pacotes se o espelho saturar; pode não copiar erros de camada 2 |
| TAP (*Test Access Point*) | Equipamento físico inserido no cabo que duplica o sinal | Não perde pacote, invisível na rede | Custa dinheiro e exige parar o link para instalar |
| No próprio host | Wireshark/tcpdump rodando no servidor ou no endpoint | Vê tráfego já descriptografado por proxy local; ótimo para triagem rápida | Se o host estiver comprometido, a captura não é confiável |

**O que o SOC N1 observa.** Se a captura do SPAN mostra só um lado da conversa (só pacotes de ida, nunca de volta), quase sempre o espelho foi configurado com direção `rx` apenas — não é evasão do atacante, é erro de configuração.

**Erro comum de analista júnior.** Concluir "o servidor não respondeu" a partir de uma captura assimétrica. Antes de abrir incidente, confirme com a equipe de rede como o SPAN foi configurado.

### Captura em Wi-Fi e o modo monitor

No Wi-Fi o ar é compartilhado, então tecnicamente todos os quadros passam pela sua antena. Mas para ver quadros 802.11 de outros clientes você precisa do **modo monitor** (diferente de promíscuo): a placa deixa de se associar a uma rede e passa a escutar um canal. Sem modo monitor, o Wireshark no Windows normalmente mostra apenas pacotes Ethernet "falsos" gerados pelo driver. Além disso, tráfego WPA2/WPA3 aparece criptografado; sem a chave e sem ter capturado o *handshake* de 4 vias, você vê apenas metadados.

### Aspecto legal e de privacidade — leia antes de capturar

**Capturar tráfego corporativo exige autorização formal, por escrito, do responsável pela segurança da informação e, dependendo do caso, do jurídico e do RH.** Uma captura de rede contém conteúdo de e-mail, mensagens, credenciais e dados pessoais de colegas e de clientes — dado pessoal protegido pela LGPD no Brasil e pelo RGPD na Europa. Regras práticas do SOC:

- Nunca inicie captura em produção por conta própria: registre chamado, obtenha aprovação e guarde a evidência da aprovação.
- Aplique **minimização**: capture apenas o host, a porta e a janela de tempo necessários ao caso.
- Trate o arquivo `.pcap` como evidência classificada — armazenamento restrito, prazo de retenção definido e descarte controlado.
- Jamais compartilhe capturas fora da organização sem autorização explícita.

## A interface do Wireshark

A janela principal tem três painéis:

1. **Lista de pacotes** (topo): uma linha por pacote, com número, tempo, origem, destino, protocolo, tamanho e resumo.
2. **Detalhes do pacote** (meio): a árvore de camadas — Frame, Ethernet, IP, TCP/UDP, aplicação. Expandir essa árvore é onde a investigação acontece de verdade.
3. **Bytes do pacote** (base): o conteúdo cru em hexadecimal e ASCII. Clicar num campo da árvore destaca os bytes correspondentes.

### Colunas úteis e como adicionar

Clique com o botão direito no campo desejado na árvore de detalhes e escolha *Apply as Column*. Ou vá em *Edit → Preferences → Appearance → Columns*.

| Coluna | Campo | Para que serve no SOC |
|---|---|---|
| Delta time | `frame.time_delta_displayed` | Ver batimento regular de C2 (*command and control*) — pacotes a cada 60s exatos |
| Porta de origem | `tcp.srcport` | Identificar varredura e reuso de portas efêmeras |
| Porta de destino | `tcp.dstport` | Separar 443 legítimo de 443 em IP suspeito |
| SNI | `tls.handshake.extensions_server_name` | Ver o domínio pedido mesmo em HTTPS, sem descriptografar |
| HTTP Host | `http.host` | Domínio em tráfego não criptografado |

### Perfis, resolução de nomes e tempo em UTC

**Perfis** (*Edit → Configuration Profiles*) guardam colunas, filtros e cores por tipo de investigação — um perfil "DNS", outro "TLS", outro "Kerberos". Trocar de perfil leva um clique.

**Resolução de nomes** (*View → Name Resolution*): a resolução de MAC (fabricante) e de portas ajuda; a **resolução de rede (DNS reverso) deve ficar desligada** por padrão, porque gera consultas ao vivo a partir da sua máquina — pode avisar o atacante de que você está investigando o domínio dele.

**Tempo em UTC** é obrigatório em SOC: *View → Time Display Format → UTC Date and Time of Day*. Sem isso, correlacionar a captura com o SIEM (que costuma gravar em UTC) vira caça a fuso horário.

## Filtro de captura ≠ filtro de exibição

Esta é a pegadinha clássica de entrevista e de prova.

| | Filtro de captura | Filtro de exibição |
|---|---|---|
| Sintaxe | BPF (*Berkeley Packet Filter*) | Sintaxe própria do Wireshark |
| Quando age | Antes de gravar — o que não passa é **perdido para sempre** | Depois, sobre o arquivo já gravado |
| Exemplo | `host 10.10.20.45 and port 443` | `ip.addr == 10.10.20.45 && tcp.port == 443` |
| Onde fica | Campo na tela inicial de captura | Barra verde acima da lista de pacotes |
| Risco | Filtrar demais e destruir a evidência | Nenhum — é reversível |

**Erro comum de analista júnior.** Digitar `ip.addr == 10.10.20.45` no campo de filtro de captura. O Wireshark recusa com erro de sintaxe, e o júnior conclui que "o Wireshark está bugado". São linguagens diferentes.

### Sintaxe BPF na prática

Primitivas: `host`, `net`, `port`, `portrange`, `src`, `dst`, `tcp`, `udp`, `icmp`, combinadas por `and`, `or`, `not`.

```
host 10.10.20.45
net 10.10.20.0/24
port 53
src host 10.10.20.45 and dst port 443
tcp and not port 22
udp port 53 or udp port 5353
net 10.10.0.0/16 and not net 10.10.99.0/24
```

**Ring buffer.** Para captura contínua sem encher o disco, use múltiplos arquivos rotativos: no Wireshark, *Capture Options → Output → Create a new file automatically*, definindo tamanho (ex.: 100 MB) e quantos arquivos manter (ex.: 20). Assim você tem sempre as últimas horas sem risco de parar o servidor por disco cheio.

## Equivalentes em linha de comando

### tcpdump

| Opção | Efeito |
|---|---|
| `-i eth0` | Interface de captura |
| `-n` | Não resolve nomes (evita DNS e acelera) |
| `-w arquivo.pcap` | Grava em arquivo |
| `-r arquivo.pcap` | Lê um arquivo já gravado |
| `-c 100` | Para após 100 pacotes |
| `-s 0` | Captura o pacote inteiro (snaplen ilimitado) |

```bash
# Grava todo o tráfego HTTPS de um host suspeito, pacote inteiro, sem DNS
tcpdump -i eth0 -n -s 0 -w /var/log/pcap/caso4711.pcap 'host 10.10.20.45 and port 443'

# Lê o arquivo e mostra só os 50 primeiros pacotes DNS
tcpdump -n -r /var/log/pcap/caso4711.pcap -c 50 'udp port 53'
```

### tshark e dumpcap

```bash
# tshark: lista domínios consultados por DNS, um por linha
tshark -r caso4711.pcap -Y "dns.flags.response == 0" -T fields -e frame.time_utc -e ip.src -e dns.qry.name

# tshark: extrai o SNI de cada handshake TLS
tshark -r caso4711.pcap -Y "tls.handshake.type == 1" -T fields -e ip.dst -e tls.handshake.extensions_server_name

# dumpcap: captura com ring buffer de 20 arquivos de 100 MB
dumpcap -i eth0 -b filesize:100000 -b files:20 -w /var/log/pcap/ring.pcap -f "not port 22"
```

`dumpcap` é o motor de captura do Wireshark; usá-lo direto consome menos CPU e é a escolha certa para captura longa em servidor.

### Como aparece nos logs

O SIEM não vê o pacote, mas vê a mesma sessão. Zeek `conn.log` (campos separados por tabulação):

```
#fields ts        uid                id.orig_h    id.orig_p  id.resp_h       id.resp_p  proto  service  duration  orig_bytes  resp_bytes  conn_state
1756880412.113    CjHk2a1Yx9QbNf3m   10.10.20.45  51422      203.0.113.77    443        tcp    ssl      1801.442  18422       9633        SF
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `ts` | `1756880412.113` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos |
| `uid` | `CjHk2a1Yx9QbNf3m` | Identificador único da conexão. **É a ponte entre o pacote e o SIEM**: com ele você acha esta mesma sessão no `ssl.log` e no `dns.log` |
| `id.orig_h` / `id.orig_p` | `10.10.20.45` / `51422` | Cliente e porta efêmera |
| `id.resp_h` / `id.resp_p` | `203.0.113.77` / `443` | Servidor externo e porta HTTPS |
| `proto` | `tcp` | Transporte |
| `service` | `ssl` | Serviço identificado pela inspeção do conteúdo |
| `duration` | `1801.442` | Duração: 30 minutos com a conexão aberta |
| `orig_bytes` | `18422` | Payload enviado pelo cliente |
| `resp_bytes` | `9633` | Payload devolvido. **Meia hora de sessão movendo só 28 KB** — não é navegação nem download; é canal mantido aberto |
| `conn_state` | `SF` | Conexão completa e encerrada normalmente |

</details>


Palo Alto, TRAFFIC em CSV (campos relevantes):

```
1,2026/09/03 14:20:11,013201004567,TRAFFIC,end,2561,2026/09/03 14:20:11,10.10.20.45,203.0.113.77,0.0.0.0,0.0.0.0,regra-saida-corp,corp\maria.costa,,ssl,vsys1,Trust,Untrust,ethernet1/2,ethernet1/1,Log-Forward,2026/09/03 14:20:11,88213,1,51422,443,0,0,0x19,tcp,allow,28055,18422,9633,64,...
```

<details><summary>Ver legenda</summary>

| Posição | Campo | Valor no exemplo | O que significa |
|---|---|---|---|
| 1, 6 | — | `1`, `2561` | Reservados pelo fabricante |
| 2 / 7 | Receive / Generated Time | `2026/09/03 14:20:11` | Quando o firewall recebeu e quando ocorreu |
| 3 | Serial Number | `013201004567` | Qual equipamento gerou |
| 4 / 5 | Type / Subtype | `TRAFFIC` / `end` | Log de sessão, no fim |
| 8 / 9 | Source / Destination Address | `10.10.20.45` / `203.0.113.77` | **O mesmo par que você acabou de ver no Wireshark** — o firewall vê a sessão, não os pacotes |
| 10 / 11 | NAT Source / Destination IP | `0.0.0.0` / `0.0.0.0` | Sem NAT nesta sessão |
| 12 | Rule Name | `regra-saida-corp` | A regra que permitiu |
| 13 / 14 | Source / Destination User | `corp\maria.costa` / *(vazio)* | Usuário resolvido |
| 15 / 16 | Application / Virtual System | `ssl` / `vsys1` | App-ID e firewall virtual |
| 17 / 18 | Source / Destination Zone | `Trust` / `Untrust` | O sentido do tráfego |
| 19 / 20 | Inbound / Outbound Interface | `ethernet1/2` / `ethernet1/1` | Interfaces de entrada e saída |
| 21 / 22 | Log Action / — | `Log-Forward` / `2026/09/03 14:20:11` | Perfil de log e campo reservado |
| 23 / 24 | Session ID / Repeat Count | `88213` / `1` | Sessão e contagem |
| 25 / 26 | Source / Destination Port | `51422` / `443` | **A mesma porta efêmera do pacote no Wireshark** — é por ela que se casa a captura com o log |
| 27 / 28 | NAT Source / Destination Port | `0` / `0` | Sem tradução |
| 29 | Flags | `0x19` | Bits da sessão (valor diferente do `0x400053` dos outros exemplos: aqui não houve NAT) |
| 30 / 31 | Protocol / Action | `tcp` / `allow` | Protocolo e veredito |
| 32 / 33 / 34 / 35 | Bytes / Sent / Received / Packets | `28055` / `18422` / `9633` / `64` | Volume total, por direção, e pacotes. **O Wireshark contaria mais bytes**, porque conta cabeçalhos que o firewall não soma |

</details>


**O que o SOC N1 observa.** Normal: sessões SSL curtas para domínios conhecidos, bytes de resposta maiores que os de envio (navegação). Suspeito: sessão de 30 minutos para um IP sem SNI reconhecido, com envio maior que a resposta — padrão de exfiltração ou de canal C2 (MITRE ATT&CK T1071 — *Application Layer Protocol*).

Consulta SPL (Splunk) para achar sessões longas com poucos bytes, típicas de *beaconing*:

```spl
index=firewall sourcetype=pan:traffic action=allow
| stats count avg(duration) as dur_media sum(bytes_out) as saida by src_ip, dest_ip, dest_port
| where count > 50 AND dur_media < 5
| sort - count
```

Linha 1 filtra tráfego permitido do Palo Alto; linha 2 agrupa por par origem/destino somando bytes; linha 3 mantém pares com muitas sessões curtas; linha 4 ordena pelos mais repetitivos.

KQL (Microsoft Sentinel), mesma ideia sobre logs de dispositivo de rede:

```kql
CommonSecurityLog
| where TimeGenerated > ago(24h) and DeviceAction == "allow"    // últimas 24h, só permitido
| summarize sessoes = count(), bytes = sum(SentBytes) by SourceIP, DestinationIP, DestinationPort
| where sessoes > 50 and bytes < 100000                          // muitas sessões, pouco volume
| order by sessoes desc                                          // mais repetitivo primeiro
```

### Exercícios — Fundamentos de captura, interface e filtros de captura

1. Você precisa capturar, num servidor Linux de produção, apenas o tráfego entre `10.10.20.45` e a rede `172.16.30.0/24`, ignorando SSH, gravando pacote inteiro num arquivo. Escreva a linha de `tcpdump`.
2. Um analista abriu o Wireshark, digitou `ip.addr == 10.10.20.45` no campo da tela inicial de captura e recebeu erro. Explique o que ele fez de errado e dê a versão correta.
3. A captura feita via SPAN mostra pacotes de `10.10.20.45` para `203.0.113.77:443`, mas nenhuma resposta. O analista abriu incidente de "servidor externo indisponível". Isso é verdadeiro ou falso positivo? Justifique.
4. No `conn.log` do Zeek acima, `duration` é 1801,44 s com `orig_bytes` 18422 e `resp_bytes` 9633 para a porta 443. Qual é o próximo passo da investigação de um N1?
5. Por que a resolução de nomes de rede deve ficar desligada no Wireshark durante uma investigação de incidente?

<details><summary>Ver gabarito</summary>

**1.** `tcpdump -i eth0 -n -s 0 -w /var/log/pcap/caso.pcap 'host 10.10.20.45 and net 172.16.30.0/24 and not port 22'`. O filtro está entre aspas simples porque `and`/`not` são palavras do BPF, não do shell. `-s 0` garante o pacote completo (sem truncar o payload), `-n` evita consultas DNS a partir do servidor e `-w` grava para análise posterior. Antes de rodar em produção: autorização formal registrada em chamado.

**2.** Ele misturou as duas linguagens. O campo da tela inicial aceita **filtro de captura** em sintaxe **BPF**; `ip.addr` é sintaxe de **filtro de exibição**. A versão correta para captura é `host 10.10.20.45`. O filtro de exibição `ip.addr == 10.10.20.45` vale depois, na barra verde, sobre o pcap já gravado.

**3.** Provável **falso positivo**. Captura assimétrica é sintoma clássico de SPAN configurado apenas na direção `rx` (ou espelhando uma única porta do caminho). O passo correto é confirmar a configuração do espelho com a equipe de rede e validar a conectividade por outra fonte — o log do firewall, por exemplo, que no caso mostra `allow` com 9.633 bytes de resposta, provando que o servidor respondeu sim.

**4.** Sessão TLS de 30 minutos com mais bytes saindo (18,4 KB) do que voltando (9,6 KB) merece triagem, não incidente imediato. Próximos passos: (a) usar o `uid` `CjHk2a1Yx9QbNf3m` para achar a linha correspondente em `ssl.log` e ler o SNI e o emissor do certificado; (b) verificar em `dns.log` qual consulta resolveu para `203.0.113.77`; (c) checar reputação do destino; (d) confirmar com o dono da estação se há aplicação legítima (backup, VPN, videoconferência) que justifique a sessão longa. Só escale se o SNI for desconhecido ou o certificado autoassinado.

**5.** Porque a resolução reversa dispara consultas DNS reais a partir da máquina do analista para os domínios sob investigação. Isso pode alertar a infraestrutura do atacante de que o domínio está sendo analisado, além de poluir a linha do tempo com tráfego gerado pela própria investigação. Mantenha `-n` no tcpdump e a resolução de rede desativada no Wireshark.

</details>


## Filtros de exibição: a lupa sobre a captura

Imagine que você gravou oito horas de câmera de segurança de um prédio. A gravação inteira já está no disco — o que você precisa agora é de um controle que diga "mostre-me apenas as pessoas que entraram pela porta dos fundos entre 2h e 3h da manhã". Você não apaga o resto da fita; apenas esconde o que não interessa.

É exatamente isso que o **filtro de exibição** (*display filter*) do Wireshark faz. Ele é diferente do filtro de captura (visto no trecho anterior deste módulo): o filtro de captura decide o que entra no arquivo — e o que ficou de fora está perdido para sempre. O filtro de exibição decide apenas o que aparece na tela, e pode ser trocado quantas vezes você quiser sobre o mesmo arquivo `.pcap`.

Na prática: você captura com filtro largo (ou sem filtro nenhum) e investiga com filtros de exibição estreitos. O campo de filtro fica na barra logo abaixo dos ícones; fica **verde** quando a sintaxe está válida, **vermelho** quando está errada e **amarelo** quando está válida mas provavelmente não faz o que você espera (o clássico `ip.addr != x`, que veremos adiante).

### Tabela de referência rápida de filtros de exibição

| Filtro | O que faz | Quando o SOC N1 usa |
|---|---|---|
| `tcp.port == 443` | Mostra pacotes cujo porta de origem **ou** destino TCP seja 443 | Isolar tráfego HTTPS de uma conversa |
| `dns` | Todo tráfego do protocolo DNS (*Domain Name System*, o "catálogo telefônico" que traduz nome em IP) | Caçar consultas a domínio suspeito, DNS tunneling |
| `icmp` | Mensagens de controle da rede (ping, "destino inalcançável") | Varredura de rede, tunelamento por ICMP |
| `http` | Requisições e respostas HTTP em claro (porta 80 por padrão) | Ver URL, User-Agent, download de arquivo |
| `tls` | Registros TLS (*Transport Layer Security*, a criptografia do HTTPS) | Ver handshake, certificado e nome do site mesmo sem decifrar |
| `ip.addr == 10.10.5.20` | Pacotes em que **origem ou destino** é esse IP | "Tudo que a estação do jsilva falou" |
| `ip.src == 10.10.5.20` | Apenas pacotes **saindo** desse IP | Confirmar quem iniciou |
| `ip.dst == 203.0.113.45` | Apenas pacotes **chegando** nesse IP | Confirmar o destino externo |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | Só o **primeiro** pacote de cada conexão TCP (SYN puro) | Contar tentativas de conexão; detectar varredura de portas |
| `tcp.analysis.flags` | Tudo que o Wireshark marcou como anomalia TCP | Diagnóstico rápido de rede "lenta" |
| `tcp.analysis.retransmission` | Pacotes reenviados por falta de confirmação | Perda de pacote, link saturado, firewall descartando |
| `http.request.method == "POST"` | Envios de dados do cliente para o servidor | Exfiltração, envio de credencial, upload em webshell |
| `http.host contains "example"` | Requisições cujo cabeçalho Host contenha o texto | Achar acesso a domínio de interesse |
| `dns.qry.name contains "example"` | Consultas DNS cujo nome perguntado contenha o texto | Caçar subdomínio de comando e controle |
| `dns.flags.rcode == 3` | Respostas **NXDOMAIN** (nome não existe) | Volume alto = DGA (domínio gerado por algoritmo) ou erro de configuração |
| `tls.handshake.type == 1` | Apenas o **ClientHello** (primeiro passo do HTTPS) | Ver quem está tentando falar TLS e com quem |
| `tls.handshake.extensions_server_name` | O campo SNI (*Server Name Indication*), o nome do site em texto claro | Descobrir o destino do HTTPS sem decifrar nada |
| `frame contains "senha"` | Procura a sequência de bytes em qualquer lugar do pacote | Busca bruta por string quando não se sabe o protocolo |
| `smb2` | Compartilhamento de arquivos Windows (porta 445) | Movimento lateral, acesso a `ADMIN$`, ransomware |
| `kerberos` | Autenticação do Active Directory (porta 88) | Kerberoasting, tíquetes anômalos |
| `ldap` | Consultas ao diretório (porta 389/636) | Enumeração de AD (rastro típico de BloodHound) |
| `ftp` | Comandos FTP em texto claro (porta 21) | Credencial trafegando sem criptografia |
| `arp.duplicate-address-detected` | Dois MACs reivindicando o mesmo IP | Forte indício de ARP spoofing (Responder, MITM) |
| `eth.addr == 00:1a:2b:3c:4d:5e` | Filtra pelo endereço físico da placa de rede | Rastrear máquina que troca de IP por DHCP |
| `udp.length > 300` | Datagramas UDP acima de um tamanho | DNS anormalmente grande = possível tunelamento |
| `frame.time >= "2026-09-03 14:00:00"` | Recorte por janela de tempo | Alinhar a captura com o horário do alerta do SIEM |

### Operadores e a armadilha do `!=`

| Operador | Significado | Exemplo |
|---|---|---|
| `==` | Igual | `tcp.port == 22` |
| `!=` | Diferente (perigoso em campos duplicados) | `udp.port != 53` |
| `>` `<` `>=` `<=` | Comparações numéricas | `frame.len > 1400` |
| `contains` | Contém a sequência de bytes/texto | `http.user_agent contains "curl"` |
| `matches` | Expressão regular (regex), sem diferenciar maiúsculas | `http.host matches "cdn[0-9]+"` |
| `&&` (ou `and`) | E lógico | `ip.src == 10.10.5.20 && tcp.port == 445` |
| `\|\|` (ou `or`) | OU lógico | `dns \|\| icmp` |
| `!` (ou `not`) | Negação do conjunto | `!(arp \|\| stp)` |

**A armadilha clássica:** `ip.addr != 10.10.5.20` **não** significa "esconda esse IP". O campo `ip.addr` existe duas vezes em cada pacote (origem e destino), e o filtro é verdadeiro se **qualquer uma** das ocorrências for diferente. Num pacote de 10.10.5.20 para 203.0.113.45, o campo de destino já é diferente — então o pacote aparece. O jeito correto é negar o conjunto inteiro:

```
!(ip.addr == 10.10.5.20)
```

O Wireshark inclusive pinta o campo de amarelo para avisar. A mesma regra vale para `tcp.port`, `udp.port` e `eth.addr`.

## Dissecação camada a camada

### Um pacote HTTP

Aplicando `http.request.method == "POST"` numa captura da estação da maria.costa, o painel de detalhes mostra as camadas empilhadas como envelopes, um dentro do outro:

```
Frame 8123: 612 bytes on wire (4896 bits), 612 bytes captured
Ethernet II, Src: 00:1a:2b:3c:4d:5e, Dst: 00:aa:bb:cc:dd:01
    Type: IPv4 (0x0800)
Internet Protocol Version 4, Src: 10.10.5.31, Dst: 203.0.113.77
    Time to Live: 128
    Protocol: TCP (6)
Transmission Control Protocol, Src Port: 51234, Dst Port: 80, Seq: 1, Len: 546
    Flags: 0x018 (PSH, ACK)
Hypertext Transfer Protocol
    POST /upload/img.php HTTP/1.1\r\n
    Host: cdn7.empresa-exemplo.com.br\r\n
    User-Agent: python-requests/2.31.0\r\n
    Content-Type: application/octet-stream\r\n
    Content-Length: 402\r\n
MIME Multipart Media Encapsulation
```

Leitura em português: a **camada 2 (Ethernet)** diz qual placa de rede falou com qual — útil só dentro da mesma rede local. A **camada 3 (IP)** diz o endereço lógico de origem e destino; o *Time to Live* 128 sugere origem Windows. A **camada 4 (TCP)** traz as portas e as flags PSH+ACK (dados sendo empurrados numa conexão já estabelecida). A **camada 7 (HTTP)** é o conteúdo: método POST, caminho, host, e o `User-Agent` — aqui está o alarme. Um navegador diria `Mozilla/5.0`; `python-requests` num POST de 402 bytes para um "CDN" é script, não gente.

### Um TLS ClientHello

Com `tls.handshake.type == 1`:

```
Transmission Control Protocol, Src Port: 51877, Dst Port: 443
Transport Layer Security
    TLSv1.2 Record Layer: Handshake Protocol: Client Hello
        Content Type: Handshake (22)
        Version: TLS 1.0 (0x0301)
        Handshake Type: Client Hello (1)
        Random: 5f2a...9c1b
        Cipher Suites (14 suites)
        Extension: server_name (len=27)
            Server Name: painel.example.com
        Extension: supported_versions: TLS 1.3, TLS 1.2
```

Mesmo sem decifrar nada, o **SNI** entrega o destino real: `painel.example.com`. É por isso que proxy e firewall conseguem bloquear categoria de site em HTTPS.

## Como isso aparece nos logs de produto

O que você vê no Wireshark tem um equivalente no SIEM. O Zeek registra o mesmo ClientHello em `ssl.log`:

```
#fields ts  uid  id.orig_h  id.orig_p  id.resp_h  id.resp_p  version  server_name  ja3  established
1756900812.441  CqR8xT1  10.10.5.31  51877  203.0.113.77  443  TLSv12  painel.example.com  a0e9f5b6...  T
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `ts` | `1756900812.441` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos |
| `uid` | `CqR8xT1` | Identificador único da conexão — permite cruzar com o `conn.log` |
| `id.orig_h` / `id.orig_p` | `10.10.5.31` / `51877` | Cliente e porta efêmera |
| `id.resp_h` / `id.resp_p` | `203.0.113.77` / `443` | Servidor e porta |
| `version` | `TLSv12` | Versão do TLS negociada |
| `server_name` | `painel.example.com` | O SNI do ClientHello — **o mesmo campo que você acabou de ver no Wireshark**, agora já extraído |
| `ja3` | `a0e9f5b6…` | Impressão digital do cliente TLS, calculada a partir da ordem das cifras e extensões do ClientHello. É o que permite reconhecer o binário mesmo trocando IP e domínio |
| `established` | `T` | O handshake completou |

</details>


O mesmo POST aparece assim num FortiGate (formato chave=valor):

```
date=2026-09-03 time=14:22:11 devname="FGT-CORP-01" type="traffic" subtype="forward" srcip=10.10.5.31 srcport=51234 dstip=203.0.113.77 dstport=80 proto=6 action="accept" policyid=17 service="HTTP" sentbyte=1284 rcvdbyte=310 app="HTTP.BROWSER" user="maria.costa"
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `date` | `2026-09-03` | Data local **do equipamento**, não UTC. Correlacionar com um log em UTC sem acertar o fuso desalinha a timeline |
| `time` | `14:22:11` | Hora local do equipamento |
| `devname` | `"FGT-CORP-01"` | Nome do equipamento que gerou o log |
| `type` | `"traffic"` | Categoria do log: `traffic` é sessão, `event` é evento do próprio aparelho, `utm` é inspeção de conteúdo |
| `subtype` | `"forward"` | Subcategoria: `forward` é tráfego que atravessa, `local` é destinado ao próprio firewall, `vpn` é túnel, `webfilter` e `ips` são inspeção |
| `srcip` | `10.10.5.31` | IP de origem |
| `srcport` | `51234` | Porta de origem, efêmera e sorteada pelo cliente |
| `dstip` | `203.0.113.77` | IP de destino |
| `dstport` | `80` | Porta de destino — é ela que aponta o serviço |
| `proto` | `6` | Número do protocolo IP: **`6` é TCP, `17` é UDP, `1` é ICMP**. Vem em número, não em nome |
| `action` | `"accept"` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |
| `policyid` | `17` | **Número da regra que decidiu.** Sem ele não se sabe por que o tráfego passou ou parou |
| `service` | `"HTTP"` | Nome do **objeto de serviço** do FortiGate, não a porta literal. Um objeto chamado `HTTPS` pode ter sido configurado noutra porta |
| `sentbyte` | `1284` | Bytes enviados **pela origem**. O ponto de vista é o da origem, não do firewall |
| `rcvdbyte` | `310` | Bytes recebidos pela origem. **Comparar com `sentbyte` é o que revela exfiltração** |
| `app` | `"HTTP.BROWSER"` | Aplicação identificada pelo controle de aplicação, por inspeção do conteúdo |
| `user` | `"maria.costa"` | Conta autenticada — o que transforma "um IP" em "uma pessoa" |

</details>

E numa consulta de caça no Splunk (SPL) e no Sentinel (KQL):

```spl
index=zeek sourcetype=zeek:ssl                        
| search server_name!="*.empresa-exemplo.com.br"      
| stats count dc(id.resp_h) as ips by ja3, server_name 
| where count < 5                                      
```

Linha 1 seleciona os logs SSL do Zeek; linha 2 remove o que é do próprio domínio corporativo; linha 3 agrupa por impressão JA3 e nome do servidor contando destinos distintos; linha 4 mantém apenas o que é raro — o raro é o que merece olhar.

```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)                        // janela de 24 horas
| where RemotePort == 443 and InitiatingProcessFileName in ("python.exe","powershell.exe")  // TLS iniciado por script
| summarize Conexoes=count() by DeviceName, RemoteUrl, InitiatingProcessFileName
| order by Conexoes desc
```

**O que o SOC N1 observa.** Normal: `User-Agent` de navegador, SNI de domínios conhecidos, poucos NXDOMAIN, retransmissões esporádicas. Suspeito: POST repetitivo em intervalo fixo (batimento de comando e controle, MITRE **T1071.001** — Application Layer Protocol: Web Protocols), rajada de NXDOMAIN (**T1568.002** — DGA), consultas DNS com nomes longuíssimos e `udp.length` alto (**T1071.004** — DNS tunneling), enxurrada de SYN sem ACK para muitas portas (**T1046** — Network Service Discovery).

**Erro comum de analista júnior:** filtrar por `http` e concluir "não há tráfego web nenhum". Hoje quase tudo é HTTPS — o filtro certo é `tls` (ou `tcp.port == 443`). O segundo erro é usar `ip.addr != x` e achar que limpou a tela.

## Funções de investigação

### Follow Stream

Clique com o botão direito num pacote → **Follow** → **TCP Stream** (ou HTTP/TLS Stream). O Wireshark remonta todos os pacotes daquela conversa na ordem certa e mostra o diálogo completo: em vermelho o que o cliente enviou, em azul o que o servidor respondeu. É a diferença entre ler letras soltas e ler a carta inteira. Em TLS Stream você verá bytes cifrados — a menos que tenha as chaves.

### Statistics

| Menu | Para que serve |
|---|---|
| **Capture File Properties** | Duração, número de pacotes, taxa média — confirma se a captura cobre o horário do alerta |
| **Protocol Hierarchy** | Percentual por protocolo; "37% de DNS" numa captura de escritório é anormal |
| **Conversations** | Pares origem-destino com bytes e duração; ordene por bytes para achar exfiltração |
| **Endpoints** | Lista de IPs/MACs isolados, com resolução geográfica opcional |
| **IO Graph** | Gráfico de tráfego no tempo; picos regulares revelam batimento automatizado |

### Expert Information

Reúne o que o Wireshark considera anômalo, em quatro níveis: *Error*, *Warning*, *Note* e *Chat*. Retransmissões, portas reutilizadas e checksums inválidos aparecem aqui. Cuidado: erro de checksum em placa moderna quase sempre é **falso positivo** causado por *checksum offload* (a placa calcula depois da captura).

### Export Objects

**File → Export Objects → HTTP / SMB / TFTP / IMF** lista todos os arquivos transferidos e permite salvá-los. É assim que o SOC recupera o executável baixado por uma vítima e envia o hash SHA-256 para análise. Salve sempre em pasta isolada e nunca execute o arquivo.

### Decode As

Quando um serviço roda em porta fora do padrão (HTTP na 8081, por exemplo), o Wireshark mostra "TCP genérico". Botão direito → **Decode As** → escolha HTTP, e a dissecação passa a funcionar.

### Decifrar TLS com SSLKEYLOGFILE

Navegadores podem gravar as chaves de sessão num arquivo texto, cujo caminho é indicado pela variável de ambiente `SSLKEYLOGFILE`. Em **Preferences → Protocols → TLS → (Pre)-Master-Secret log filename**, você aponta esse arquivo e o Wireshark passa a mostrar o conteúdo em claro. Isso só funciona em máquina de laboratório onde você mesmo gerou as chaves — não é técnica de interceptação de terceiros, e o arquivo de chaves deve ser tratado como segredo.

### Regras de colorização

**View → Coloring Rules** define cores por filtro. Uma regra útil: pintar de vermelho `tcp.analysis.retransmission` e de laranja `dns.flags.rcode == 3`. Assim, problemas saltam aos olhos antes de você digitar qualquer filtro.

### Exercícios — Filtros de exibição e funções de investigação

1. Você quer ver todo o tráfego da estação 10.10.5.20 **exceto** o que fala com o controlador de domínio 10.10.1.10. Escreva o filtro correto.
2. Um alerta diz "possível varredura de portas partindo de 10.10.5.31". Qual filtro de exibição confirma ou descarta isso, e qual número você vai olhar?
3. No `ssl.log` do Zeek você encontra 480 conexões em 8 horas para `sync.example.com`, todas com o mesmo JA3, intervalo de 60 segundos, 512 bytes cada. Verdadeiro ou falso positivo? Qual o próximo passo?
4. Uma captura mostra 1.200 respostas DNS com `dns.flags.rcode == 3` em 5 minutos, todas de 10.10.5.44. Que hipóteses você levanta e como as separa?
5. O analista afirma: "há 4.000 erros de checksum, a rede está com defeito". Como você valida essa conclusão?

<details><summary>Ver gabarito</summary>

**1.** `ip.addr == 10.10.5.20 && !(ip.addr == 10.10.1.10)`. Escrever `ip.addr != 10.10.1.10` falharia: como o campo aparece duas vezes por pacote (origem e destino), basta uma das ocorrências ser diferente para o filtro dar verdadeiro, e o tráfego com o controlador continuaria visível. O Wireshark pinta a barra de amarelo justamente para avisar disso.

**2.** Filtro: `ip.src == 10.10.5.31 && tcp.flags.syn == 1 && tcp.flags.ack == 0`. Ele mostra apenas o primeiro pacote de cada tentativa de conexão. O número a olhar é a contagem exibida na barra de status ("Displayed") e, em **Statistics → Conversations**, quantas portas de destino distintas aparecem. Dezenas de portas diferentes no mesmo destino em poucos segundos, sem resposta SYN/ACK, indicam varredura (MITRE T1046). Se forem poucas portas conhecidas (443, 445, 3389) para muitos destinos, pode ser um agente de inventário legítimo — verifique o processo de origem no Sysmon Event ID 3.

**3.** Comportamento fortemente suspeito, não é ruído comum: periodicidade rígida de 60 segundos, tamanho constante e JA3 único são a assinatura clássica de batimento de comando e controle (T1071.001). Próximo passo: identificar o processo que abriu a conexão (Sysmon Event ID 3 correlacionando por IP e porta de origem), verificar se `sync.example.com` foi registrado recentemente, e no Wireshark aplicar `tls.handshake.extensions_server_name contains "sync"` seguido de **Statistics → IO Graph** para confirmar visualmente o intervalo fixo. Só depois disso escale para o N2 com o pacote de evidências.

**4.** Hipóteses: (a) malware com algoritmo gerador de domínios tentando achar seu servidor ativo (T1568.002); (b) aplicação mal configurada consultando sufixo DNS inexistente; (c) máquina retirada de um domínio antigo ainda procurando serviços. Para separar: aplique `dns.flags.rcode == 3` e observe os nomes consultados — nomes aleatórios e sem sentido apontam para (a); o mesmo nome repetido centenas de vezes aponta para (b) ou (c). Confirme com o processo de origem no Sysmon Event ID 22 (consulta DNS).

**5.** Provavelmente falso positivo. Em placas modernas o cálculo do checksum é delegado ao hardware e acontece **depois** que o Wireshark captura o pacote na máquina de origem, então a captura local mostra checksum "inválido" para tráfego perfeitamente saudável. Valide de duas formas: veja se os erros aparecem só nos pacotes **enviados** pela própria máquina de captura (sinal claro de offload) e desative **Preferences → Protocols → IPv4/TCP → Validate checksum**. Se quiser medir saúde real da rede, use `tcp.analysis.retransmission` e `tcp.analysis.lost_segment`, que refletem perda de verdade.

</details>


## Investigações práticas guiadas

Até aqui você aprendeu a capturar tráfego e a filtrar o que interessa. Agora vem a parte que realmente paga o salário do analista: pegar uma captura e responder "o que aconteceu aqui?". Pense num médico de plantão — ele não olha o exame inteiro célula por célula; ele tem uma sequência de perguntas que faz sempre, na mesma ordem. É isso que vamos construir.

Todas as investigações abaixo usam dados fictícios: rede interna `10.10.20.0/24` (domínio `corp.local`) e "internet" nas faixas de documentação `203.0.113.x` e `198.51.100.x`.

### Investigação 1 — Identificar um port scan

**Objetivo:** confirmar se um host interno está varrendo portas de outros hosts.

**O que é:** um *port scan* (varredura de portas) é alguém batendo em todas as portas de uma máquina para ver quais estão abertas — como um ladrão andando pelo corredor girando cada maçaneta.

**Filtros em sequência:**

```
tcp.flags.syn == 1 && tcp.flags.ack == 0
ip.src == 10.10.20.57
tcp.flags.reset == 1
```

**O que observar:** em `Statistics > Conversations > TCP`, um mesmo IP de origem abrindo centenas de conversas, cada uma com 1 ou 2 pacotes apenas. Muitos `SYN` saindo e muitos `RST, ACK` voltando (porta fechada). Portas de destino em ordem crescente ou seguindo a lista padrão do nmap (21, 22, 23, 25, 80, 139, 443, 445, 3389).

**Como aparece nos logs (Palo Alto, CSV TRAFFIC):**

```
FUTURE_USE,2026/09/03 09:14:22,001801012345,TRAFFIC,end,2560,2026/09/03 09:14:22,10.10.20.57,10.10.20.15,0.0.0.0,0.0.0.0,rule-lan-lan,,,incomplete,vsys1,LAN,LAN,ethernet1/2,ethernet1/3,LogFwd,2026/09/03 09:14:22,0,1,51422,445,0,0,0x19,tcp,allow,74,74,0,1,0,not-applicable
```

<details><summary>Ver legenda</summary>

| Posição | Campo | Valor no exemplo | O que significa |
|---|---|---|---|
| 1 | — | `FUTURE_USE` | Reservado pelo fabricante. Aqui o exemplo escreve o nome do campo em vez de um valor |
| 2 / 7 | Receive / Generated Time | `2026/09/03 09:14:22` | Quando o firewall recebeu e quando ocorreu |
| 3 | Serial Number | `001801012345` | Qual equipamento gerou |
| 4 / 5 | Type / Subtype | `TRAFFIC` / `end` | Log de sessão, no fim |
| 6 | — | `2560` | Reservado pelo fabricante |
| 8 / 9 | Source / Destination Address | `10.10.20.57` / `10.10.20.15` | **Origem e destino na mesma sub-rede**: é tráfego interno |
| 10 / 11 | NAT Source / Destination IP | `0.0.0.0` / `0.0.0.0` | Sem NAT, como se espera em tráfego lado a lado |
| 12 | Rule Name | `rule-lan-lan` | A regra que trata tráfego LAN para LAN |
| 13 / 14 | Source / Destination User | `-` / `-` | Sem usuário resolvido |
| 15 | Application | `incomplete` | **O campo mais importante deste exemplo.** `incomplete` significa que o handshake TCP **nunca completou**, logo o App-ID não teve conteúdo para identificar. É a assinatura de varredura ou de host que não respondeu |
| 16 | Virtual System | `vsys1` | Firewall virtual |
| 17 / 18 | Source / Destination Zone | `LAN` / `LAN` | Mesma zona nos dois lados |
| 19 / 20 | Inbound / Outbound Interface | `ethernet1/2` / `ethernet1/3` | Interfaces de entrada e saída |
| 21 / 22 | Log Action / — | `LogFwd` / `2026/09/03 09:14:22` | Perfil de log e campo reservado |
| 23 | Session ID | `0` | **Zero: não houve sessão estabelecida** para receber um identificador |
| 24 | Repeat Count | `1` | Contagem de repetições |
| 25 / 26 | Source / Destination Port | `51422` / `445` | Porta efêmera e **SMB** |
| 27 / 28 | NAT Source / Destination Port | `0` / `0` | Sem tradução |
| 29 / 30 / 31 | Flags / Protocol / Action | `0x19` / `tcp` / `allow` | Bits, protocolo e veredito. **`allow` engana**: a política permitiu, mas nada se estabeleceu |
| 32 / 33 / 34 | Bytes / Sent / Received | `74` / `74` / `0` | **74 bytes num sentido e zero no outro** — é o tamanho de um único SYN sem resposta |
| 35 | Packets | `1` | **Um pacote.** Confirma: só a sonda saiu |
| 36 / 37 | Start Time / Elapsed | `0` / `not-applicable` | Sem início e sem duração, porque não houve sessão |

</details>

Campos: origem `10.10.20.57`, destino `10.10.20.15`, aplicação `incomplete` (o handshake nunca fechou), porta destino `445`, apenas 1 pacote e 74 bytes. Centenas de linhas `incomplete` do mesmo IP em segundos = varredura. Técnica MITRE: **T1046 — Network Service Discovery**.

**Normal vs suspeito:** scanner de vulnerabilidade autorizado também gera isso — por isso o N1 sempre confere se o IP de origem está na lista de scanners aprovados antes de escalar.

**Erro comum de júnior:** olhar um único pacote SYN e abrir incidente. Um SYN isolado é só uma conexão. O que caracteriza scan é o **volume** e a **dispersão** de portas/destinos.

### Investigação 2 — Detectar beaconing de C2

**Objetivo:** achar uma máquina infectada "ligando para casa" em intervalos regulares. C2 = *Command and Control* (comando e controle), o servidor do atacante.

**Analogia:** um funcionário que sai para fumar exatamente a cada 60 segundos, sempre 45 segundos, sempre no mesmo lugar. Humano nenhum é tão pontual — máquina é.

**Filtros e ferramentas em sequência:**

```
ip.addr == 10.10.20.88 && tcp.port == 443
Statistics > Conversations  (ordenar por Packets / Duration)
Statistics > I/O Graph  (intervalo 1 seg, filtro ip.dst == 203.0.113.45)
```

**O que observar:** no **I/O Graph**, picos idênticos e igualmente espaçados — um "pente" perfeito. Em **Conversations**, a coluna *Bytes A→B* praticamente constante (ex.: sempre 512 bytes) e centenas de sessões curtas com o mesmo destino. Delta entre pacotes: use a coluna `tcp.time_delta` ou `frame.time_delta_displayed`.

**Como aparece nos logs (Zeek `conn.log`):**

```
ts              uid     id.orig_h    id.orig_p  id.resp_h     id.resp_p  proto  service  duration  orig_bytes  resp_bytes  conn_state
1756891200.114  CqL1a2  10.10.20.88  49711      203.0.113.45  443        tcp    ssl      0.412     512         1460        SF
1756891260.121  CqL1a3  10.10.20.88  49712      203.0.113.45  443        tcp    ssl      0.408     512         1460        SF
1756891320.118  CqL1a4  10.10.20.88  49713      203.0.113.45  443        tcp    ssl      0.415     512         1460        SF
```

<details><summary>Ver legenda</summary>

| Campo | Valor nas três linhas | O que significa |
|---|---|---|
| `ts` | `1756891200.114`, `1756891260.121`, `1756891320.118` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos. **Exatamente 60 segundos de intervalo** — o batimento |
| `uid` | `CqL1a2`, `CqL1a3`, `CqL1a4` | Três conexões distintas, cada uma com seu identificador |
| `id.orig_h` / `id.orig_p` | `10.10.20.88` / `49711`, `49712`, `49713` | Sempre a mesma estação; a porta efêmera avança de uma em uma, como acontece em conexões consecutivas do mesmo processo |
| `id.resp_h` / `id.resp_p` | `203.0.113.45` / `443` | Sempre o mesmo destino externo, em HTTPS |
| `proto` / `service` | `tcp` / `ssl` | Transporte e serviço identificado |
| `duration` | `0.412`, `0.408`, `0.415` | Duração quase idêntica — máquina, não pessoa |
| `orig_bytes` | `512` nas três | Payload enviado **sempre igual**: é o mesmo pedido a repetir |
| `resp_bytes` | `1460` nas três | Payload devolvido, também constante: resposta programada |
| `conn_state` | `SF` | Todas normais. **Nenhum campo isolado acusa nada** — é a regularidade entre as linhas que denuncia |

</details>

Os `ts` diferem exatamente 60 segundos; `orig_bytes` é sempre 512. Isso é beaconing — **T1071.001 (Application Layer Protocol: Web)**.

**Erro comum de júnior:** confundir com atualização de antivírus ou telemetria do Windows, que também é periódica. A diferença está no destino: reputação do IP, idade do domínio e se o certificado TLS faz sentido.

### Investigação 3 — DNS tunneling

**Objetivo:** detectar exfiltração de dados escondida em consultas DNS. DNS = *Domain Name System*, a "lista telefônica" que traduz nome em IP.

**Analogia:** alguém contrabandeando um livro inteiro escrevendo uma frase por vez no verso de cartões-postais.

**Filtros em sequência:**

```
dns
dns.qry.type == 16
dns.qry.name.len > 50
Statistics > DNS  (contagem por tipo de registro)
```

**O que observar:** subdomínios enormes e aleatórios, muitas respostas TXT, e um único domínio-pai concentrando milhares de consultas.

**Como aparece nos logs (Zeek `dns.log`):**

```
ts            id.orig_h    query                                            qtype_name  rcode_name
1756891402.7  10.10.20.88  a7f3b91c8e2d4a6f0b5c.tun.empresa-exemplo.com.br  TXT         NOERROR
1756891403.1  10.10.20.88  c2e8d40a91b7f3c65a1e.tun.empresa-exemplo.com.br  TXT         NOERROR
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `ts` | `1756891402.7` / `1756891403.1` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos. Duas consultas separadas por **0,4 segundo** |
| `id.orig_h` | `10.10.20.88` | A mesma estação do exemplo anterior — o `conn.log` e o `dns.log` estão contando o mesmo incidente |
| `query` | `a7f3b91c8e2d4a6f0b5c.tun.empresa-exemplo.com.br` | O nome consultado. **O subdomínio de 20 caracteres é o dado**, codificado; o domínio-pai (`tun.…`) é o servidor controlado pelo atacante |
| `qtype_name` | `TXT` | Registro de texto livre — cabe muito mais informação que um `A`, e por isso é o tipo preferido para tunelamento |
| `rcode_name` | `NOERROR` | Resolveu: o domínio existe e está respondendo |

</details>

**Consulta SPL (Splunk) para caçar em escala:**

```spl
index=dns sourcetype=zeek:dns
| eval sub=mvindex(split(query,"."),0)          `# pega o primeiro rótulo do domínio`
| eval tam=len(sub)                              `# mede o tamanho desse rótulo`
| where tam > 30                                 `# rótulos longos são anômalos`
| stats count, dc(query) as unicos by id.orig_h  `# agrupa por host de origem`
| where count > 200
```

**Erro comum de júnior:** marcar como malicioso todo domínio de aparência aleatória. CDNs e antivírus na nuvem também usam subdomínios longos — confira o domínio-pai e o volume por host. Técnica: **T1071.004** e **T1048 (exfiltração por protocolo alternativo)**.

### Investigação 4 — Credenciais em texto claro (HTTP, FTP, Telnet)

**Objetivo:** provar, dentro do seu próprio laboratório, que protocolos sem criptografia expõem senha.

**Filtros em sequência:**

```
http.request.method == "POST"
ftp.request.command == "USER" || ftp.request.command == "PASS"
telnet
```

Depois: clique com o botão direito no pacote > **Follow > TCP Stream**.

**O que observar:** no FTP você lê `USER jsilva` e `PASS ...` em texto puro. No Telnet, cada tecla digitada aparece como um pacote separado. No HTTP, o corpo do POST mostra os campos do formulário.

**Como aparece nos logs (Cisco ASA):**

```
%ASA-6-302013: Built outbound TCP connection 84512 for outside:203.0.113.77/21 (203.0.113.77/21) to inside:10.10.20.41/50122 (198.51.100.9/50122)
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `%ASA` | `%ASA` | Etiqueta do produto: identifica a linha como vinda de um firewall ASA |
| severidade | `6` | Escala syslog do Cisco, de 0 (emergência) a 7 (depuração): `6` é **informational**. **Severidade baixa não quer dizer evento sem importância** — quem a escolhe é o fabricante, não o seu SOC |
| *message ID* | `302013` | Conexão TCP construída — entrou na tabela de estado. **É por este número que se escreve a regra no SIEM**: o texto da mensagem muda entre versões do software, o ID não |
| direção | `outbound` | **Quem iniciou**, não a direção dos bytes: `outbound` é de dentro para fora, `inbound` é de fora para dentro |
| id da conexão | `84512` | Número da conexão na tabela de estado. **É a chave para casar com o `302014`** que a encerra |
| lado remoto | `outside:203.0.113.77/21` | Interface, IP e porta do host **remoto**. Vem primeiro, logo depois do `for` — é isso que faz a linha parecer invertida |
| *(entre parênteses)* | `(203.0.113.77/21)` | O endereço **traduzido** desse lado. Igual ao real significa que não houve NAT nesta ponta |
| lado local | `inside:10.10.20.41/50122` | Interface, IP e porta do host **local**, antes da tradução |
| *(entre parênteses)* | `(198.51.100.9/50122)` | O endereço com que o host local saiu. **Este par — IP público mais porta — é o que desfaz o NAT** num pedido externo |
| — | — | **Porta 21 é FTP em texto claro, a sair para a Internet.** Esta linha é só a conexão de **controle**: a transferência em si abre outra conexão, e sem capturar as duas não se sabe o que foi movido |

</details>

Conexão de saída na porta 21 (FTP) — o N1 deve questionar por que uma estação usa FTP para a internet.

**Erro comum de júnior:** achar que "é só laboratório". A lição real é: qualquer porta 21, 23 ou 80 com autenticação é um achado a reportar. Nunca copie a senha capturada para o ticket.

### Investigação 5 — SMB e movimento lateral

**Objetivo:** ver se uma conta está saltando de máquina em máquina. SMB = *Server Message Block*, o protocolo de compartilhamento de arquivos do Windows (porta 445).

**Filtros em sequência:**

```
tcp.port == 445
smb2.cmd == 3            (Tree Connect — conexão a um compartilhamento)
smb2.filename contains "ADMIN$" || smb2.filename contains "IPC$"
```

**O que observar:** um mesmo usuário conectando em `ADMIN$` ou `C$` de vários servidores em poucos minutos; escrita de arquivo `.exe` remoto (rastro típico de PsExec e de ferramentas Impacket).

**Como aparece nos logs (Windows Security):**

```
EventID 4624  Logon Type 3  Account Name: svc_backup  Source Network Address: 10.10.20.88  Workstation: WKS-FIN-07
EventID 4672  Special privileges assigned to new logon  Account Name: svc_backup
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `EventID` | `4624` / `4672  Special privileges assigned to new logon` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não. `4624` = logon **bem-sucedido** |
| `Logon Type` | `3` | **Como a sessão foi iniciada.** `3` = **rede** — acesso a compartilhamento, RPC, WinRM. É o tipo que domina em movimento lateral |
| `Account Name` | `svc_backup` | A conta envolvida. Terminada em `$` é **conta de computador**, não de pessoa |
| `Source Network Address` | `10.10.20.88` | **IP de origem.** Vazio ou `-` significa que a sessão foi local, e `::1`/`127.0.0.1` que veio da própria máquina |
| `Workstation` | `WKS-FIN-07` | Nome declarado pela máquina de origem |

</details>

Logon Type 3 = logon de rede. Uma conta de serviço fazendo Type 3 em dez servidores diferentes em 5 minutos é **T1021.002 (SMB/Admin Shares)**.

**KQL (Microsoft Sentinel):**

```kql
SecurityEvent
| where EventID == 4624 and LogonType == 3          // logons de rede apenas
| summarize Alvos = dcount(Computer) by Account, bin(TimeGenerated, 10m)  // quantos destinos por conta
| where Alvos >= 5                                  // conta tocando muitos hosts = suspeito
```

**Erro comum de júnior:** ignorar contas de serviço porque "é normal ela acessar tudo". Justamente por isso elas são o alvo preferido.

### Investigação 6 — TLS anômalo

**Objetivo:** identificar sessão criptografada suspeita sem quebrar a criptografia.

**Filtros em sequência:**

```
tls.handshake.type == 1          (Client Hello)
tls.handshake.extensions_server_name
tls.handshake.type == 11         (Certificate)
```

**O que observar:** Client Hello **sem** a extensão SNI (*Server Name Indication*, o nome do site pedido); certificado autoassinado com *issuer* igual ao *subject*; validade de poucos dias; campos genéricos como `CN=localhost`. O **JA3** é uma "impressão digital" da forma como o cliente inicia o TLS — hashes conhecidos de malware são catalogados publicamente.

**Como aparece nos logs (Zeek `ssl.log`):**

```
ts            id.orig_h    id.resp_h     server_name  validation_status                             ja3
1756891500.2  10.10.20.88  203.0.113.45  -            self signed certificate in certificate chain  e7d705a3286e19ea42f587b344ee6865
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `ts` | `1756891500.2` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos |
| `id.orig_h` | `10.10.20.88` | A mesma estação dos dois exemplos anteriores |
| `id.resp_h` | `203.0.113.45` | O destino externo |
| `server_name` | `-` | O SNI está **vazio**: o cliente conectou direto pelo IP, sem pedir nome nenhum. Navegador não faz isso; implante faz |
| `validation_status` | `self signed certificate in certificate chain` | A cadeia do certificado não chega a nenhuma CA confiável — há um autoassinado no meio |
| `ja3` | `e7d705a3286e19ea42f587b344ee6865` | Impressão digital do cliente TLS. Guarde este valor: procurá-lo na frota revela as outras máquinas com o mesmo binário |

</details>

`server_name` vazio (`-`) e `validation_status` de autoassinado = escalar. **T1573 (Encrypted Channel)**.

**Erro comum de júnior:** tratar todo certificado autoassinado como incidente. Impressoras, switches e appliances internos usam autoassinado o tempo todo. O que pesa é o destino ser **externo**.

## Metodologia — analisando uma captura desconhecida em 10 passos

1. **Protocol Hierarchy** (`Statistics > Protocol Hierarchy`) — veja a composição do tráfego. Um protocolo com percentual estranho já denuncia o caso.
2. **Capture File Properties** (`Statistics > Capture File Properties`) — janela de tempo, total de pacotes, taxa média. Situe o incidente no tempo.
3. **Endpoints** (`Statistics > Endpoints > IPv4`) — quem são os participantes; ordene por bytes.
4. **Conversations** — quem fala com quem, por quanto tempo, quantos bytes em cada direção.
5. **Separe interno de externo** — filtro `!(ip.addr == 10.10.20.0/24 && ip.dst == 10.10.20.0/24)` isola o que sai da rede.
6. **DNS primeiro** — `dns` mostra as intenções antes das conexões. Nomes resolvidos contam a história.
7. **HTTP e TLS** — `http.request || tls.handshake.type == 1` revela destinos, User-Agent e SNI.
8. **Procure o anômalo** — `Expert Information` (`Analyze > Expert Information`) lista retransmissões, resets e erros de protocolo.
9. **Extraia objetos** — `File > Export Objects > HTTP/SMB` para arquivos transferidos; calcule o hash e consulte a base de reputação.
10. **Conclua e extraia IOCs** — *Indicators of Compromise* (indicadores de comprometimento): IPs, domínios, hashes, URIs, JA3. Escreva a linha do tempo em uma frase por evento.

### Capturas públicas reais para praticar

| Fonte | O que oferece |
|---|---|
| malware-traffic-analysis.net | PCAPs reais de infecções com exercícios e respostas |
| wiki.wireshark.org/SampleCaptures | Capturas por protocolo, ideais para aprender filtros |
| CyberDefenders (cyberdefenders.org) | Desafios *blue team* com PCAP e perguntas guiadas |

### Exercícios — Investigações práticas e metodologia de análise

1. Em `Conversations` você vê `10.10.20.88 → 203.0.113.45`, 480 sessões em 8 horas, sempre 512 bytes de ida. Qual é o intervalo médio entre sessões e o que isso indica?
2. Um alerta diz "DNS tunneling" para o host `10.10.20.41`, consultando `cdn-4f8a.telemetria.example.com` do tipo A, 12 vezes em 1 hora. Verdadeiro ou falso positivo?
3. `ssl.log` mostra `server_name` vazio e certificado autoassinado, mas o destino é `10.10.20.9` (impressora interna). Qual o próximo passo?
4. Você vê 300 pacotes SYN de `10.10.20.57` para 300 portas de `10.10.20.15`, com `RST, ACK` de volta em quase todas, exceto nas portas 445 e 3389. O que aconteceu?

<details><summary>Ver gabarito</summary>

1. 8 horas = 28.800 segundos ÷ 480 sessões = **60 segundos exatos**. Intervalo fixo com tamanho de payload constante é a assinatura clássica de **beaconing de C2**. Próximo passo: reputação do IP `203.0.113.45`, verificar o processo de origem no EDR e isolar o host se confirmado.
2. **Falso positivo provável.** São consultas do tipo **A**, não TXT; 12 por hora é volume baixíssimo; o rótulo `cdn-4f8a` tem 8 caracteres, longe dos 30+ típicos de tunelamento. Padrão compatível com CDN. Documente e feche, sem escalar.
3. **Não escale ainda.** Autoassinado em ativo interno (impressora, switch, iDRAC) é o comportamento esperado. Confirme o ativo no inventário e verifique se o destino é interno. Só vira incidente se o destino for **externo** ou se o ativo não existir no inventário.
4. É um **port scan** com resultado: `RST, ACK` significa porta fechada; a ausência de resposta ou o `SYN, ACK` nas portas **445 (SMB)** e **3389 (RDP)** indica portas abertas descobertas. Trate como reconhecimento (**T1046**) e verifique se `10.10.20.57` é um scanner autorizado antes de abrir incidente.

</details>

## Mini-laboratório — Wireshark na prática

**Pré-requisitos:** VirtualBox com duas VMs em rede interna — uma Ubuntu (`10.10.20.15`) e uma Kali ou Ubuntu com nmap (`10.10.20.57`); Wireshark instalado na máquina que vai capturar.

**Passo 1 — capturar.** Na VM alvo, execute:

```bash
sudo tcpdump -i enp0s3 -w /tmp/lab-soc.pcap
```

Observe: o contador de pacotes cresce. Critério: o arquivo existe e tem mais de 0 bytes.

**Passo 2 — gerar o scan.** Na VM atacante:

```bash
nmap -sS -p 1-1000 10.10.20.15
```

Observe: o nmap lista portas `open` e `closed`.

**Passo 3 — analisar.** Encerre o tcpdump com `Ctrl+C`, abra o arquivo no Wireshark e aplique:

```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

Observe: centenas de linhas do mesmo par origem/destino. Abra `Statistics > Conversations`. Critério de sucesso: você consegue nomear as portas abertas apenas olhando quais responderam `SYN, ACK`.

**Passo 4 — captura pública.** Baixe um PCAP de `wiki.wireshark.org/SampleCaptures` e execute os 10 passos da metodologia, escrevendo uma linha por passo. Critério de sucesso: um parágrafo final descrevendo o que a captura contém e ao menos três IOCs listados.

## O que um SOC Level 1 realmente precisa saber

- 🟢 Abrir um PCAP e rodar Protocol Hierarchy, Endpoints e Conversations antes de qualquer filtro.
- 🟢 Diferença entre filtro de captura (BPF, antes) e filtro de exibição (depois) — não confundir a sintaxe.
- 🟢 Ler o three-way handshake e reconhecer SYN, SYN-ACK, ACK, RST e FIN.
- 🟢 Reconhecer um port scan por volume de SYN e por conversas de 1 a 2 pacotes.
- 🟢 Usar `Follow > TCP Stream` para ler uma sessão inteira em texto.
- 🟡 Identificar beaconing pelo I/O Graph: intervalo regular e tamanho constante.
- 🟡 Saber que portas 21, 23 e 80 com autenticação expõem credencial em texto claro.
- 🟡 Extrair IOCs corretamente: IP, domínio, hash, URI, JA3 — e nunca colar senha no ticket.
- 🟡 Correlacionar o PCAP com log de firewall, Zeek e Windows Security antes de escalar.
- 🔴 Analisar TLS sem descriptografar: SNI, certificado, validade, JA3.
- 🔴 Detectar DNS tunneling por tamanho de rótulo, tipo TXT e volume por domínio-pai.
- 🔴 Reconstruir movimento lateral por SMB cruzando `smb2.cmd` com EventID 4624 Logon Type 3.

## Resumo em 10 linhas

1. Wireshark mostra o pacote como ele é; nenhum log substitui essa verdade.
2. Filtro de captura reduz o que entra; filtro de exibição reduz o que você vê.
3. Sempre comece pela estatística, nunca pelo pacote isolado.
4. Port scan é volume e dispersão, não um SYN sozinho.
5. Beaconing se revela pela regularidade do intervalo e pela constância do tamanho.
6. DNS tunneling aparece em rótulos longos, registros TXT e volume por domínio-pai.
7. FTP, Telnet e HTTP entregam credencial em texto claro — reporte, não copie.
8. SMB em ADMIN$ com a mesma conta em vários hosts é movimento lateral.
9. TLS suspeito se lê pelo SNI ausente, pelo certificado autoassinado externo e pelo JA3.
10. A investigação só termina quando existe uma linha do tempo e uma lista de IOCs.



---
