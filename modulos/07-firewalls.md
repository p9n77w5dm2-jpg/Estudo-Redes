# Módulo 07 — Firewalls

## Por que este módulo importa para o SOC

O firewall é o primeiro lugar onde o tráfego da empresa é aceito ou recusado, e é também a fonte de log mais consultada por um analista de SOC (Security Operations Center, ou Centro de Operações de Segurança) de nível 1. Praticamente todo alerta de "conexão para IP malicioso", "exfiltração de dados" ou "varredura de portas" começa ou termina numa linha de log de firewall. Se você entende o que o equipamento estava tentando fazer quando gerou aquela linha, você acerta o veredito. Se não entende, você fecha chamado como falso positivo sem saber, ou escala tudo e vira ruído para o N2.

### Índice do módulo

- O que é um firewall: stateless, stateful e NGFW
- Regras, NAT, PAT e ACLs
- Análise de logs reais de firewall

## O que é um firewall

**O que é.** Imagine a portaria de um prédio comercial. O porteiro tem uma lista: quem pode entrar, para qual andar, e em que horário. Quem não está na lista fica na calçada. O firewall é exatamente esse porteiro, só que a "pessoa" é um pacote de rede, o "andar" é o endereço IP de destino com a porta, e a "lista" é o conjunto de regras.

**Como funciona.** O firewall fica no caminho entre duas redes (por exemplo, a rede interna da empresa e a internet). Cada pacote que passa é comparado com as regras, de cima para baixo, até casar com uma. A ação da regra que casou é aplicada: permitir (allow) ou negar (deny/drop). Se nenhuma regra casar, vale a regra final implícita, que em firewall bem configurado é **negar tudo**.

A diferença entre as gerações de firewall está em **quanto** o porteiro consegue enxergar: só o crachá (stateless), o crachá mais a lembrança de quem já entrou (stateful), ou o crachá, a memória, o conteúdo da mochila e a identidade real da pessoa (NGFW).

### Comparação entre as gerações

| Geração | O que inspeciona | Guarda estado? | Precisa regra de volta? | Onde ainda se usa |
|---|---|---|---|---|
| Filtro de pacotes (stateless) | IP de origem/destino, porta, protocolo, flags TCP | Não | **Sim** — uma regra de ida e outra de volta | ACL de roteador, AWS NACL |
| Stateful | Tudo do stateless + tabela de estado da conexão (entende o handshake TCP) | Sim | **Não** — a volta é liberada automaticamente | Cisco ASA, firewall de borda clássico |
| Proxy / application gateway | Termina a conexão e a refaz; lê o protocolo da camada 7 (HTTP, FTP) | Sim | Não (o proxy é o cliente) | Squid, proxies web corporativos |
| NGFW (Next-Generation Firewall) | Tudo acima + aplicação independente de porta, usuário, IPS, antivírus, URL, sandbox, TLS, threat intel | Sim | Não | Palo Alto, FortiGate, Check Point, Cisco FTD |

**Stateless** não tem memória. Se `10.10.20.55` abre uma conexão para o servidor web `203.0.113.40:443`, o administrador precisa escrever duas regras: uma permitindo a saída para a porta 443 e outra permitindo a resposta que volta com porta de origem 443 para a porta alta do cliente. Isso obriga a liberar faixas amplas de portas altas (1024–65535), o que é frágil.

**Stateful** resolve isso. Ao ver o `SYN` de saída, o firewall cria uma entrada na tabela de estado: origem, destino, portas, protocolo e o estágio do handshake TCP (SYN enviado, SYN-ACK recebido, estabelecido). A resposta que corresponde àquela entrada é liberada sem regra explícita. Um pacote com flag `ACK` chegando sem entrada na tabela é descartado — é exatamente esse comportamento que produz a mensagem de "Deny TCP (no connection)" do Cisco ASA.

**Proxy / application gateway** vai além: ele não encaminha o pacote, ele **é** o destino. O cliente fala com o proxy, o proxy abre uma segunda conexão com o servidor. Isso permite ver e registrar a URL inteira, mas custa desempenho e exige configuração no cliente ou interceptação transparente.

**NGFW** junta tudo e acrescenta contexto. Os recursos que caracterizam um NGFW:

- **Identificação de aplicação independente de porta** — reconhece que o tráfego na porta 443 é `ssh` tunelado ou `bittorrent`, não "https".
- **Identidade de usuário** — casa o IP `10.10.20.55` com `corp.local\jsilva` via integração com o Active Directory.
- **IPS embutido** (Intrusion Prevention System) — bloqueia exploração de vulnerabilidade conhecida por assinatura.
- **Antivírus e filtro de URL** — inspeciona arquivos em trânsito e categoriza sites.
- **Sandbox** — detona arquivo desconhecido em ambiente isolado (WildFire, FortiSandbox, Threat Emulation).
- **Inspeção TLS** — descriptografa o tráfego HTTPS para poder inspecionar.
- **Threat intelligence** — listas dinâmicas de IPs e domínios sabidamente maliciosos.

### Exemplo prático

`corp.local\maria.costa`, na máquina `10.10.30.77`, acessa `www.empresa-exemplo.com.br` (`203.0.113.10`) na porta 443. Um firewall stateless veria "TCP 10.10.30.77:51422 → 203.0.113.10:443, permitido". Um NGFW registra: usuário `maria.costa`, aplicação `web-browsing` sobre `ssl`, categoria de URL `business-and-economy`, nenhuma ameaça, 14 KB enviados e 220 KB recebidos.

### Como aparece nos logs

Palo Alto, log de TRAFFIC em CSV (campos abreviados para leitura):

```
1,2026/09/03 10:14:22,001801012345,TRAFFIC,end,2562,2026/09/03 10:14:22,10.10.30.77,203.0.113.10,192.0.2.25,203.0.113.10,Regra-Saida-Web,corp.local\maria.costa,,ssl,vsys1,Trust,Untrust,ae1.100,ae1.200,Log-Forward,51422,443,tcp,allow,241664,14336,227328,186,web-browsing,business-and-economy
```

<details><summary>Ver legenda</summary>

| Posição no exemplo | Campo | Valor | O que significa |
|---|---|---|---|
| 1, 6 | — | `1`, `2562` | Reservados pelo fabricante |
| 2 / 7 | Receive / Generated Time | `2026/09/03 10:14:22` | Quando o firewall recebeu e quando ocorreu |
| 3 | Serial Number | `001801012345` | Qual equipamento gerou |
| 4 / 5 | Type / Subtype | `TRAFFIC` / `end` | Log de sessão, no fim |
| 8 / 9 | Source / Destination Address | `10.10.30.77` / `203.0.113.10` | Origem interna e destino externo |
| 10 / 11 | NAT Source / Destination IP | `192.0.2.25` / `203.0.113.10` | Endereço público de saída e destino |
| 12 | Rule Name | `Regra-Saida-Web` | A regra que decidiu |
| 13 / 14 | Source / Destination User | `corp.local\maria.costa` / `-` | Usuário resolvido, com o domínio completo |
| 15 / 16 | Application / Virtual System | `ssl` / `vsys1` | App-ID e firewall virtual |
| 17 / 18 | Source / Destination Zone | `Trust` / `Untrust` | O sentido do tráfego |
| 19 / 20 | Inbound / Outbound Interface | `ae1.100` / `ae1.200` | Subinterfaces de *port-channel* |
| 21 | Log Action | `Log-Forward` | Perfil de encaminhamento |
| 22 / 23 | Source / Destination Port | `51422` / `443` | Porta efêmera e porta de destino |
| 24 / 25 | Protocol / Action | `tcp` / `allow` | Protocolo e veredito |
| 26 | Bytes | `241664` | Total nos dois sentidos: 236 KB |
| 27 / 28 | Bytes Sent / Received | `14336` / `227328` | **14 KB a subir contra 222 KB a descer** — proporção normal de navegação. O inverso disto é que seria exfiltração |
| 29 | Packets | `186` | Total de pacotes |
| 30 / 31 | Application / Category | `web-browsing` / `business-and-economy` | Aplicação e categoria de URL do destino |
| — | — | — | **Recorte de 31 campos**, com as portas trazidas para a posição 22; o formato completo tem outra ordem |

</details>


FortiGate, formato chave=valor:

```
date=2026-09-03 time=10:15:03 devname="FGT-BORDA-01" type="traffic" subtype="forward" level="notice" srcip=10.10.30.77 srcport=51500 dstip=203.0.113.10 dstport=443 srcintf="port2" dstintf="port1" policyid=12 sessionid=88213 proto=6 action="accept" user="maria.costa" service="HTTPS" app="HTTPS.BROWSER" sentbyte=14336 rcvdbyte=227328 duration=186
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `date` | `2026-09-03` | Data local **do equipamento**, não UTC. Correlacionar com um log em UTC sem acertar o fuso desalinha a timeline |
| `time` | `10:15:03` | Hora local do equipamento |
| `devname` | `"FGT-BORDA-01"` | Nome do equipamento que gerou o log |
| `type` | `"traffic"` | Categoria do log: `traffic` é sessão, `event` é evento do próprio aparelho, `utm` é inspeção de conteúdo |
| `subtype` | `"forward"` | Subcategoria: `forward` é tráfego que atravessa, `local` é destinado ao próprio firewall, `vpn` é túnel, `webfilter` e `ips` são inspeção |
| `level` | `"notice"` | Severidade atribuída pelo FortiOS (`notice`, `warning`, `alert`, `critical`). **Quem a escolhe é o fabricante**, não o seu SOC |
| `srcip` | `10.10.30.77` | IP de origem |
| `srcport` | `51500` | Porta de origem, efêmera e sorteada pelo cliente |
| `dstip` | `203.0.113.10` | IP de destino |
| `dstport` | `443` | Porta de destino — é ela que aponta o serviço |
| `srcintf` | `"port2"` | Interface por onde o tráfego **entrou** — dá o sentido, que o IP sozinho não dá |
| `dstintf` | `"port1"` | Interface por onde o tráfego **saiu** |
| `policyid` | `12` | **Número da regra que decidiu.** Sem ele não se sabe por que o tráfego passou ou parou |
| `sessionid` | `88213` | Identificador da sessão na tabela de estado — casa o início e o fim da mesma conexão |
| `proto` | `6` | Número do protocolo IP: **`6` é TCP, `17` é UDP, `1` é ICMP**. Vem em número, não em nome |
| `action` | `"accept"` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |
| `user` | `"maria.costa"` | Conta autenticada — o que transforma "um IP" em "uma pessoa" |
| `service` | `"HTTPS"` | Nome do **objeto de serviço** do FortiGate, não a porta literal. Um objeto chamado `HTTPS` pode ter sido configurado noutra porta |
| `app` | `"HTTPS.BROWSER"` | Aplicação identificada pelo controle de aplicação, por inspeção do conteúdo |
| `sentbyte` | `14336` | Bytes enviados **pela origem**. O ponto de vista é o da origem, não do firewall |
| `rcvdbyte` | `227328` | Bytes recebidos pela origem. **Comparar com `sentbyte` é o que revela exfiltração** |
| `duration` | `186` | Duração da sessão em **segundos** |

</details>

Aqui `proto=6` é TCP (17 seria UDP), `policyid=12` é a regra e `action="accept"` o veredito.

Cisco ASA, firewall stateful clássico — repare nas duas mensagens complementares:

```
%ASA-6-302013: Built outbound TCP connection 445120 for outside:203.0.113.10/443 (203.0.113.10/443) to inside:10.10.30.77/51422 (192.0.2.25/51422)
%ASA-6-302014: Teardown TCP connection 445120 for outside:203.0.113.10/443 to inside:10.10.30.77/51422 duration 0:03:06 bytes 241664 TCP FINs
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `%ASA` | `%ASA` | Etiqueta do produto: identifica a linha como vinda de um firewall ASA |
| severidade | `6` | Escala syslog do Cisco, de 0 (emergência) a 7 (depuração): `6` é **informational**. **Severidade baixa não quer dizer evento sem importância** — quem a escolhe é o fabricante, não o seu SOC |
| *message ID* | `302013` | Conexão TCP construída — entrou na tabela de estado. **É por este número que se escreve a regra no SIEM**: o texto da mensagem muda entre versões do software, o ID não |
| direção | `outbound` | **Quem iniciou**, não a direção dos bytes: `outbound` é de dentro para fora, `inbound` é de fora para dentro |
| id da conexão | `445120` | Número da conexão na tabela de estado. **É a chave para casar com o `302014`** que a encerra |
| lado remoto | `outside:203.0.113.10/443` | Interface, IP e porta do host **remoto**. Vem primeiro, logo depois do `for` — é isso que faz a linha parecer invertida |
| *(entre parênteses)* | `(203.0.113.10/443)` | O endereço **traduzido** desse lado. Igual ao real significa que não houve NAT nesta ponta |
| lado local | `inside:10.10.30.77/51422` | Interface, IP e porta do host **local**, antes da tradução |
| *(entre parênteses)* | `(192.0.2.25/51422)` | O endereço com que o host local saiu. **Este par — IP público mais porta — é o que desfaz o NAT** num pedido externo |
| *message ID* (2ª linha) | `302014` | Conexão TCP encerrada. **Contar `302013` e `302014` como dois eventos duplica a mesma sessão** no relatório |
| id da conexão | `445120` | O **mesmo** número da 1ª linha: é assim que se sabe que falam da mesma conexão |
| `duration` | `0:03:06` | Quanto tempo a conexão viveu, em `h:mm:ss` |
| `bytes` | `241664` | Total transferido na sessão. **Só existe no `302014`** — quando o `302013` é escrito, ainda não há o que contar |
| motivo | `TCP FINs` | Como terminou: `TCP FINs` é fim limpo nos dois sentidos; `TCP Reset-O` é RST vindo de fora (**O** de *Outside*); `TCP Reset-I` de dentro; `SYN Timeout` nunca completou; `Deny Terminate` a política cortou |
| — | — | **É este par de linhas que prova que o firewall é *stateful*.** Um filtro sem estado não teria o que encerrar: não guarda que a sessão existiu |

</details>


```
%ASA-6-106015: Deny TCP (no connection) from 198.51.100.203/45012 to 192.0.2.25/443 flags ACK on interface outside
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `%ASA` | `%ASA` | Etiqueta do produto: identifica a linha como vinda de um firewall ASA |
| severidade | `6` | Escala syslog do Cisco, de 0 (emergência) a 7 (depuração): `6` é **informational**. **Severidade baixa não quer dizer evento sem importância** — quem a escolhe é o fabricante, não o seu SOC |
| *message ID* | `106015` | Pacote TCP negado por não pertencer a conexão nenhuma. **É por este número que se escreve a regra no SIEM**: o texto da mensagem muda entre versões do software, o ID não |
| `from` | `198.51.100.203/45012` | Origem do pacote |
| `to` | `192.0.2.25/443` | Destino |
| `flags` | `ACK` | **O campo decisivo.** Um `ACK` isolado, sem o `SYN` que abre a conversa, é um pacote no meio de uma sessão que o firewall não conhece |
| `on interface` | `outside` | Por onde chegou |
| — | — | **É o *stateful* a funcionar**, e não um ataque necessariamente: pode ser sessão que expirou de um lado e não do outro, rota assimétrica, ou varredura com `ACK` para mapear firewall. Uma rajada destes de uma só origem inclina para a última |

</details>

### O que o SOC N1 observa

| Situação | Leitura normal | Leitura suspeita |
|---|---|---|
| `action=allow` com poucos bytes recebidos e muitos enviados | upload de arquivo em serviço corporativo | possível exfiltração |
| Aplicação `ssl` sem `web-browsing` para IP cru, sem domínio | serviço legítimo mal categorizado | túnel ou C2 (comando e controle) |
| Muitos `%ASA-6-106015` de um único IP externo | ruído de internet | varredura direcionada (MITRE T1046) |
| Aplicação identificada difere da porta (ex.: `ssh` na 443) | raro | evasão de política, investigar |
| Sessões curtas e periódicas para o mesmo destino | verificação de atualização | *beaconing* de malware (T1071) |

Consulta em SPL (Splunk) para achar destinos com muito volume de saída:

```
index=firewall sourcetype=pan:traffic action=allow
| stats sum(bytes_out) AS enviados, count AS sessoes BY src_user, dest_ip, app
| where enviados > 500000000
| sort - enviados
```

Linha 1 filtra apenas tráfego permitido do Palo Alto. Linha 2 agrupa por usuário, destino e aplicação. Linha 3 mantém quem enviou mais de 500 MB. Linha 4 ordena do maior para o menor.

O mesmo raciocínio em KQL (Microsoft Sentinel):

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h) and DeviceVendor == "Palo Alto Networks"
| where DeviceAction == "allow"
| summarize Enviados = sum(SentBytes), Sessoes = count() by SourceUserName, DestinationIP, ApplicationProtocol
| where Enviados > 500000000
| order by Enviados desc
```

Linha 2 limita a 24 horas e ao fabricante. Linha 3 pega o que foi permitido. Linha 4 soma bytes por usuário/destino/aplicação. Linha 5 aplica o corte de volume.

### Erro comum de analista júnior

Tratar `allow` como "está tudo certo". Um NGFW permite a sessão **e** registra ameaça em log separado (THREAT no Palo Alto, `type="utm"` no FortiGate). Outro erro clássico: ver `%ASA-6-106015` e abrir incidente de invasão — na maioria das vezes é pacote fora de estado, resultado de sessão expirada ou roteamento assimétrico, não intrusão.

## Fabricantes reais e o que caracteriza cada um

| Fabricante | O que caracteriza | Detalhe útil para o N1 |
|---|---|---|
| **Palo Alto Networks** | App-ID (aplicação), User-ID (usuário), Content-ID; sandbox WildFire | Logs em CSV separados por tipo: TRAFFIC, THREAT, URL, WILDFIRE |
| **Fortinet FortiGate** | Bom custo-benefício, perfis UTM, FortiSandbox, ecossistema Security Fabric | Log key=value, sempre com `policyid` e `action` |
| **Check Point** | Política unificada, SmartConsole, blades (IPS, Threat Emulation) | Logs no SmartLog; campo `rule_name` e `action` |
| **Cisco ASA** | Stateful clássico, sem inspeção de aplicação nativa | Mensagens `%ASA-<sev>-<id>`; decorar 302013, 302014, 106023, 106015 |
| **Cisco FTD (Firepower Threat Defense)** | Sucessor do ASA com IPS Snort embutido, gerenciado pelo FMC | Log de conexão com `Application Protocol` e `Intrusion Event` |
| **pfSense / OPNsense** | Open source sobre FreeBSD e pf; muito usado em laboratório e PME | Log em formato `filterlog`, campos separados por vírgula |

## Firewalls de nuvem

Na nuvem não existe uma "caixa" na borda; o controle é aplicado por software junto ao recurso. Duas camadas convivem na AWS (Amazon Web Services):

| Característica | Security Group (AWS) | NACL (AWS) | NSG (Azure) |
|---|---|---|---|
| Onde se aplica | Na interface de rede da instância | Na sub-rede inteira | Na sub-rede e/ou na interface de rede |
| Estado | **Stateful** | **Stateless** | **Stateful** |
| Regras de negação | Não existem, só permitir | Permite **e** nega | Permite e nega |
| Ordem de avaliação | Todas as regras somadas | Por número de regra, a primeira que casa vence | Por prioridade (100–4096) |
| Regra de volta | Automática | **Precisa ser escrita** | Automática |

NACL significa Network Access Control List (lista de controle de acesso de rede) e NSG significa Network Security Group (grupo de segurança de rede). A confusão mais frequente em investigação: um tráfego permitido no Security Group ainda pode ser barrado pela NACL da sub-rede, e como a NACL é stateless, é comum a ida passar e a **volta** ser negada — o sintoma é conexão que "trava" em vez de recusar imediatamente.

### Exercícios — O que é um firewall: stateless, stateful e NGFW

1. Um analista precisa liberar, num filtro **stateless**, o acesso de `10.10.40.10` ao servidor `203.0.113.60` na porta TCP 443. Quantas regras ele escreve e como fica cada uma (origem, destino, portas)?
2. Leia a linha e diga se o veredito é suspeito, e por quê:
   ```
   date=2026-09-03 time=03:12:44 devname="FGT-BORDA-01" type="traffic" subtype="forward" srcip=10.10.20.31 srcport=49155 dstip=198.51.100.77 dstport=443 policyid=12 proto=6 action="accept" user="svc_backup" app="SSH" sentbyte=980 rcvdbyte=640 duration=61
   ```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `date` | `2026-09-03` | Data local **do equipamento**, não UTC. Correlacionar com um log em UTC sem acertar o fuso desalinha a timeline |
| `time` | `03:12:44` | Hora local do equipamento |
| `devname` | `"FGT-BORDA-01"` | Nome do equipamento que gerou o log |
| `type` | `"traffic"` | Categoria do log: `traffic` é sessão, `event` é evento do próprio aparelho, `utm` é inspeção de conteúdo |
| `subtype` | `"forward"` | Subcategoria: `forward` é tráfego que atravessa, `local` é destinado ao próprio firewall, `vpn` é túnel, `webfilter` e `ips` são inspeção |
| `srcip` | `10.10.20.31` | IP de origem |
| `srcport` | `49155` | Porta de origem, efêmera e sorteada pelo cliente |
| `dstip` | `198.51.100.77` | IP de destino |
| `dstport` | `443` | Porta de destino — é ela que aponta o serviço |
| `policyid` | `12` | **Número da regra que decidiu.** Sem ele não se sabe por que o tráfego passou ou parou |
| `proto` | `6` | Número do protocolo IP: **`6` é TCP, `17` é UDP, `1` é ICMP**. Vem em número, não em nome |
| `action` | `"accept"` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |
| `user` | `"svc_backup"` | Conta autenticada — o que transforma "um IP" em "uma pessoa" |
| `app` | `"SSH"` | Aplicação identificada pelo controle de aplicação, por inspeção do conteúdo |
| `sentbyte` | `980` | Bytes enviados **pela origem**. O ponto de vista é o da origem, não do firewall |
| `rcvdbyte` | `640` | Bytes recebidos pela origem. **Comparar com `sentbyte` é o que revela exfiltração** |
| `duration` | `61` | Duração da sessão em **segundos** |

</details>

3. O SIEM abriu alerta "possível intrusão externa" com base em 40 eventos `%ASA-6-106015` vindos de `198.51.100.203` para `192.0.2.25`, todos com `flags ACK`. Alerta verdadeiro ou falso positivo? Qual o próximo passo?
4. Uma aplicação em EC2 (`10.10.50.20`) responde a testes internos, mas nenhuma resposta chega ao cliente externo. O Security Group permite 443 de qualquer origem. Onde investigar em seguida e por quê?
5. No log Palo Alto do exemplo, o campo de IP de origem após NAT é `192.0.2.25`. Que informação isso dá ao N1 numa investigação com um parceiro externo?

<details><summary>Ver gabarito</summary>

**1.** Duas regras. Ida: origem `10.10.40.10`, porta de origem qualquer (ou 1024–65535), destino `203.0.113.60`, porta de destino 443, TCP, permitir. Volta: origem `203.0.113.60`, porta de origem 443, destino `10.10.40.10`, porta de destino 1024–65535, TCP, permitir. Justamente por precisar dessa faixa larga na volta é que o stateless é considerado frágil — o stateful dispensa a segunda regra porque a resposta casa com a entrada da tabela de estado.

**2.** Suspeito. O NGFW identificou a aplicação como `SSH` mas o destino é a porta 443, ou seja, a aplicação não corresponde à porta — indício clássico de túnel ou de tentativa de evadir política (MITRE T1071 / T1572). Agrava o quadro: usuário `svc_backup` (conta de serviço não deveria abrir SSH para a internet), horário 03:12 e volume pequeno com duração de 61 segundos, compatível com *beaconing*. Próximo passo: verificar se há repetição periódica para o mesmo destino e escalar.

**3.** Muito provavelmente falso positivo de intrusão. `106015` significa pacote TCP com `ACK` chegando sem conexão correspondente na tabela de estado — o firewall stateful está fazendo exatamente o trabalho dele. As causas usuais são sessão expirada (timeout), retransmissão tardia ou roteamento assimétrico. Próximo passo: confirmar se existiram eventos `302013` anteriores da mesma dupla IP/porta (sessão que existiu e expirou) e checar se `192.0.2.25` é o IP público de NAT de um serviço legítimo. Só vira suspeita real se os pacotes forem `SYN` para muitas portas distintas — aí é varredura (T1046).

**4.** Na NACL da sub-rede. O Security Group é stateful, então a resposta sairia sozinha; mas a NACL é **stateless** e exige regra de saída explícita para as portas efêmeras (1024–65535). Sem ela, a ida entra e a volta é negada, produzindo justamente o sintoma de conexão que trava sem erro imediato. Verificar também se alguma regra de `deny` com número menor está vencendo, já que a NACL avalia por ordem numérica.

**5.** O `192.0.2.25` é o endereço que o mundo externo enxerga. Se um parceiro ou um provedor reportar abuso vindo desse IP, é ele que aparecerá no relato; para descobrir **quem** dentro da empresa gerou o tráfego, o N1 precisa correlacionar horário e porta de origem com o log de NAT do firewall e chegar ao IP interno `10.10.30.77` e ao usuário `maria.costa`. Sem esse mapeamento, a investigação para na borda.

</details>


## Regras de firewall: a anatomia de uma linha que decide tudo

Imagine a portaria de um prédio comercial. O porteiro tem uma prancheta com uma lista numerada: "linha 1 — entregadores da padaria podem subir até o 3º andar", "linha 2 — visitantes precisam de crachá", "linha 3 — ninguém mais entra". Ele lê de cima para baixo, para na **primeira linha que casa** com quem está na frente dele, faz o que a linha manda e **não lê o resto**. Um firewall funciona exatamente assim.

Uma regra é uma linha dessa prancheta. Ela responde: *quem*, *vindo de onde*, *indo para onde*, *usando o quê*, e *o que eu faço com isso*.

### Anatomia completa de uma regra

| Campo | O que significa | Exemplo fictício |
|---|---|---|
| Ordem (ID) | Posição na lista. Define quem é lido primeiro | 12 |
| Zona de origem | Segmento de onde o tráfego sai | `LAN_Usuarios` |
| Zona de destino | Segmento para onde vai | `DMZ` |
| Endereço de origem | IP ou grupo de IPs que inicia a conexão | `10.10.20.0/24` |
| Endereço de destino | IP ou grupo alvo | `10.10.50.15` |
| Serviço / porta | Protocolo e porta de destino | `tcp/443` |
| Aplicação | O que o tráfego realmente é, identificado por inspeção (recurso de NGFW) | `ssl`, `ms-rdp` |
| Usuário | Identidade do AD associada ao IP | `corp.local\jsilva` |
| Ação | `allow`, `deny` (descarta e avisa) ou `drop` (descarta em silêncio) | `allow` |
| Log | Registrar no início da sessão, no fim, ou não registrar | `log at session end` |
| Perfil de segurança | Antivírus, IPS, filtro de URL, anti-spyware aplicados à sessão | `Perfil-Padrao` |

**Sigla aberta:** NGFW = *Next-Generation Firewall*, firewall de nova geração — aquele que enxerga aplicação e usuário, não só IP e porta. ACL = *Access Control List*, lista de controle de acesso. NAT = *Network Address Translation*, tradução de endereços de rede. PAT = *Port Address Translation*, tradução de endereços de porta.

### Como funciona o processamento

1. Chega um pacote que inicia uma conexão nova.
2. O firewall percorre as regras **de cima para baixo**.
3. Na **primeira correspondência** ele para e aplica a ação. Nenhuma regra abaixo é avaliada.
4. Se nada casou, entra o **deny implícito**: tudo que não foi explicitamente permitido é negado. Em muitos produtos essa regra final não gera log por padrão — e é justamente por isso que o SOC "não vê" bloqueios que aconteceram.

**O pecado capital: a regra `any any allow`.** É a linha que permite qualquer origem, qualquer destino, qualquer serviço. Colocada no topo, ela transforma o firewall num cabo de rede caro: todas as regras abaixo ficam decorativas e a segmentação deixa de existir. Ela costuma nascer como "regra temporária só para o teste de sexta" e permanece por anos.

**Shadowing (regra sombreada):** quando uma regra mais ampla vem antes de uma mais específica, a de baixo nunca é atingida. Se a regra 10 permite `10.10.20.0/24 → any tcp/443` e a regra 40 tenta bloquear `10.10.20.55 → 203.0.113.77 tcp/443`, o bloqueio **nunca acontece**. Verificar contadores de *hit count* zerados é o exame de rotina da higiene de regras, junto com: remover regras sem uso há 90 dias, trocar `any` por objetos nomeados, exigir dono e chamado em cada descrição, e revisar trimestralmente.

### Como aparece nos logs

Log de tráfego do Palo Alto (CSV, campos abreviados) mostrando qual regra decidiu:

```
1,2026/09/03 10:14:22,001801012345,TRAFFIC,end,2561,2026/09/03 10:14:22,10.10.20.55,203.0.113.77,192.0.2.10,203.0.113.77,Regra-Saida-Web,corp.local\jsilva,,ssl,vsys1,LAN_Usuarios,Internet,ae1.20,ae1.10,Log-Forward,2026/09/03 10:14:22,88213,1,51422,443,41022,443,0x400053,tcp,allow,14820,3821,10999,42
```

<details><summary>Ver legenda</summary>

| Posição | Campo | Valor no exemplo | O que significa |
|---|---|---|---|
| 1, 6 | — | `1`, `2561` | Reservados pelo fabricante |
| 2 / 7 | Receive / Generated Time | `2026/09/03 10:14:22` | Quando o firewall recebeu e quando ocorreu |
| 3 | Serial Number | `001801012345` | Qual equipamento gerou |
| 4 / 5 | Type / Subtype | `TRAFFIC` / `end` | Log de sessão, no fim |
| 8 / 9 | Source / Destination Address | `10.10.20.55` / `203.0.113.77` | Origem interna e destino externo |
| 10 / 11 | NAT Source / Destination IP | `192.0.2.10` / `203.0.113.77` | Endereço público de saída e destino |
| 12 | Rule Name | `Regra-Saida-Web` | **O campo central deste exemplo.** É a única forma de saber *qual* regra da lista casou primeiro — e, portanto, por que o tráfego passou |
| 13 / 14 | Source / Destination User | `corp.local\jsilva` / *(vazio)* | Usuário resolvido pelo User-ID |
| 15 / 16 | Application / Virtual System | `ssl` / `vsys1` | App-ID e firewall virtual |
| 17 / 18 | Source / Destination Zone | `LAN_Usuarios` / `Internet` | As zonas nomeadas conforme o desenho da rede |
| 19 / 20 | Inbound / Outbound Interface | `ae1.20` / `ae1.10` | Subinterfaces de *port-channel* |
| 21 / 22 | Log Action / — | `Log-Forward` / `2026/09/03 10:14:22` | Perfil de log e campo reservado |
| 23 / 24 | Session ID / Repeat Count | `88213` / `1` | Sessão e contagem de repetições |
| 25 / 26 | Source / Destination Port | `51422` / `443` | Porta efêmera e porta de destino |
| 27 / 28 | NAT Source / Destination Port | `41022` / `443` | Portas após tradução |
| 29 / 30 / 31 | Flags / Protocol / Action | `0x400053` / `tcp` / `allow` | Bits da sessão, protocolo e veredito |
| 32 / 33 / 34 / 35 | Bytes / Sent / Received / Packets | `14820` / `3821` / `10999` / `42` | Volume total, por direção, e pacotes |

</details>

Campos que importam: `10.10.20.55` = IP de origem real; `203.0.113.77` = destino; `192.0.2.10` = **IP de origem após NAT**; `Regra-Saida-Web` = nome da regra que casou; `jsilva` = usuário; `ssl` = aplicação; `allow` = ação; `51422` e `41022` = porta de origem antes e depois do NAT.

FortiGate no formato chave=valor:

```
date=2026-09-03 time=10:15:03 devname="FGT-MATRIZ" type="traffic" subtype="forward" level="notice" srcip=10.10.20.55 srcport=51890 dstip=203.0.113.77 dstport=443 policyid=12 policyname="Saida-Web-Usuarios" action="accept" service="HTTPS" transip=192.0.2.10 transport=41090 sentbyte=14820 rcvdbyte=3821
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `date` | `2026-09-03` | Data local **do equipamento**, não UTC. Correlacionar com um log em UTC sem acertar o fuso desalinha a timeline |
| `time` | `10:15:03` | Hora local do equipamento |
| `devname` | `"FGT-MATRIZ"` | Nome do equipamento que gerou o log |
| `type` | `"traffic"` | Categoria do log: `traffic` é sessão, `event` é evento do próprio aparelho, `utm` é inspeção de conteúdo |
| `subtype` | `"forward"` | Subcategoria: `forward` é tráfego que atravessa, `local` é destinado ao próprio firewall, `vpn` é túnel, `webfilter` e `ips` são inspeção |
| `level` | `"notice"` | Severidade atribuída pelo FortiOS (`notice`, `warning`, `alert`, `critical`). **Quem a escolhe é o fabricante**, não o seu SOC |
| `srcip` | `10.10.20.55` | IP de origem |
| `srcport` | `51890` | Porta de origem, efêmera e sorteada pelo cliente |
| `dstip` | `203.0.113.77` | IP de destino |
| `dstport` | `443` | Porta de destino — é ela que aponta o serviço |
| `policyid` | `12` | **Número da regra que decidiu.** Sem ele não se sabe por que o tráfego passou ou parou |
| `policyname` | `"Saida-Web-Usuarios"` | Nome da regra — mais legível que o número, e sobrevive à renumeração |
| `action` | `"accept"` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |
| `service` | `"HTTPS"` | Nome do **objeto de serviço** do FortiGate, não a porta literal. Um objeto chamado `HTTPS` pode ter sido configurado noutra porta |
| `transip` | `192.0.2.10` | IP após tradução — **o endereço com que a sessão saiu** |
| `transport` | `41090` | Porta após tradução. Cuidado: **não é "protocolo de transporte"**, é a porta traduzida |
| `sentbyte` | `14820` | Bytes enviados **pela origem**. O ponto de vista é o da origem, não do firewall |
| `rcvdbyte` | `3821` | Bytes recebidos pela origem. **Comparar com `sentbyte` é o que revela exfiltração** |
| — | — | `policyname` ao lado do `policyid` é o que evita o erro clássico de citar "regra 12" depois de alguém renumerar as regras |

</details>

Cisco ASA construindo e derrubando a conexão:

```
%ASA-6-302013: Built outbound TCP connection 88213 for outside:203.0.113.77/443 (203.0.113.77/443) to inside:10.10.20.55/51422 (192.0.2.10/41022)
%ASA-4-106023: Deny tcp src inside:10.10.20.55/49301 dst dmz:10.10.50.15/3389 by access-group "INSIDE_IN"
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `%ASA` | `%ASA` | Etiqueta do produto: identifica a linha como vinda de um firewall ASA |
| severidade | `6` | Escala syslog do Cisco, de 0 (emergência) a 7 (depuração): `6` é **informational**. **Severidade baixa não quer dizer evento sem importância** — quem a escolhe é o fabricante, não o seu SOC |
| *message ID* | `302013` | Conexão TCP construída — entrou na tabela de estado. **É por este número que se escreve a regra no SIEM**: o texto da mensagem muda entre versões do software, o ID não |
| direção | `outbound` | **Quem iniciou**, não a direção dos bytes: `outbound` é de dentro para fora, `inbound` é de fora para dentro |
| id da conexão | `88213` | Número da conexão na tabela de estado. **É a chave para casar com o `302014`** que a encerra |
| lado remoto | `outside:203.0.113.77/443` | Interface, IP e porta do host **remoto**. Vem primeiro, logo depois do `for` — é isso que faz a linha parecer invertida |
| *(entre parênteses)* | `(203.0.113.77/443)` | O endereço **traduzido** desse lado. Igual ao real significa que não houve NAT nesta ponta |
| lado local | `inside:10.10.20.55/51422` | Interface, IP e porta do host **local**, antes da tradução |
| *(entre parênteses)* | `(192.0.2.10/41022)` | O endereço com que o host local saiu. **Este par — IP público mais porta — é o que desfaz o NAT** num pedido externo |
| *message ID* (2ª linha) | `106023` | Pacote negado por lista de acesso — **severidade `4` (warning), mais alta que a da 1ª linha** |
| `src` / `dst` | `inside:10.10.20.55/49301` / `dmz:10.10.50.15/3389` | O **mesmo host** da 1ª linha, agora a tentar RDP (3389) contra a DMZ |
| `by access-group` | `"INSIDE_IN"` | A lista que negou |
| — | — | As duas linhas juntas contam a história: a máquina navega normalmente **e** tenta alcançar a DMZ por RDP. A primeira é ruído; a segunda é o achado |

</details>

**O que o SOC N1 observa.** Normal: usuário conhecido, regra nominal, aplicação coerente com a porta. Suspeito: tráfego permitido por uma regra genérica (`Permit-Any-Temp`), aplicação `unknown-tcp` na porta 443, ou volume de saída muito acima do padrão do usuário — indício de exfiltração (MITRE ATT&CK T1048).

**Erro comum de júnior:** olhar só `action=allow` e encerrar. A pergunta certa é *qual regra permitiu*. Um `allow` por uma regra ampla e antiga é um achado, não um encerramento.

## NAT e PAT: onde o IP muda de identidade

Analogia: o condomínio tem um único endereço na rua. Todas as cartas saem com esse endereço, e o porteiro anota numa caderneta qual apartamento mandou cada carta, para saber a quem entregar a resposta. NAT é essa troca de endereço; a caderneta é a tabela de tradução.

| Tipo | Como funciona | Uso típico |
|---|---|---|
| NAT estático | 1 IP interno ↔ 1 IP público fixo, nos dois sentidos | Servidor publicado |
| NAT dinâmico | Vários internos usam um pool de públicos, um por vez | Saída com pool |
| PAT / overload | Muitos internos usam **um** IP público, diferenciados pela porta de origem | Saída padrão da empresa |
| Destination NAT | Traduz o destino: público → interno (port forwarding) | Publicar `192.0.2.20:443` para `10.10.50.15:443` |
| Hairpin (NAT loopback) | Cliente interno acessa o próprio servidor pelo IP público e "volta" no firewall | Usuário abrindo o site da empresa de dentro |

### O ponto mais importante para o SOC

**Depois do NAT, o IP de origem deixa de identificar a máquina.** Se o alerta do provedor de nuvem diz "ataque vindo de 192.0.2.10", esse é o IP público do PAT — atrás dele podem estar 800 estações. O N1 precisa correlacionar **três coisas**: IP público, **porta de origem traduzida** e **horário exato** (com fuso). Só o trio identifica a sessão.

```
# Splunk — encontrar a máquina real por trás do IP público e da porta traduzida
index=firewall sourcetype=pan:traffic src_translated_ip="192.0.2.10" src_translated_port=41022
| eval janela=strftime(_time,"%F %T")
| table janela src_ip src_port src_translated_ip src_translated_port dest_ip dest_port user rule
```

```kql
// Sentinel — mesma correlação em log de FortiGate normalizado
CommonSecurityLog
| where DeviceVendor == "Fortinet"                       // só o firewall
| where TimeGenerated between (datetime(2026-09-03T10:10:00Z) .. datetime(2026-09-03T10:20:00Z))
| where AdditionalExtensions has "transip=192.0.2.10"    // IP pós-NAT do alerta
| project TimeGenerated, SourceIP, SourcePort, DestinationIP, DestinationPort, DeviceAction
```

A mesma lógica vale para **CGNAT** (*Carrier-Grade NAT*, o NAT do provedor, onde milhares de assinantes dividem um IP) e para o proxy: o IP que o servidor web vê é o do proxy, e o IP real do cliente vai no cabeçalho **X-Forwarded-For**. No Squid:

```
1756894522.310    412 10.10.20.55 TCP_MISS/200 5120 GET https://intranet.empresa-exemplo.com.br/rel - HIER_DIRECT/198.51.100.40 text/html
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| *timestamp* | `1756894522.310` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos |
| duração | `412` | Milissegundos para atender |
| cliente | `10.10.20.55` | **O IP privado de quem realmente pediu** — é este o dado que o NAT apaga na saída |
| resultado/status | `TCP_MISS/200` | Buscou na origem e recebeu 200 OK |
| bytes | `5120` | 5 KB entregues |
| método | `GET` | Pedido de leitura |
| URL | `https://intranet.empresa-exemplo.com.br/rel` | O recurso pedido |
| hierarquia/destino | `HIER_DIRECT/198.51.100.40` | O IP para onde o proxy foi. Do lado de fora, o servidor registra o **IP público do NAT**, não o `10.10.20.55` |
| — | — | **É por isso que o log do proxy resolve o caso**: ele é o único ponto que guarda o par "IP privado ↔ pedido", com hora exata |

</details>

**Erro clássico de júnior:** bloquear ou "isolar" o IP público do próprio NAT, derrubando a internet da empresa inteira; ou abrir chamado dizendo "máquina infectada: 192.0.2.10", que não é máquina nenhuma. Outro: confiar cegamente no X-Forwarded-For, que pode ser forjado quando o cabeçalho não vem de um proxy confiável.

## ACLs: o firewall de linha de comando

ACL é a lista de regras do roteador Cisco. Duas famílias:

| Tipo | Numeração | Filtra por |
|---|---|---|
| Standard | 1–99, 1300–1999 | Apenas IP de **origem** |
| Extended | 100–199, 2000–2699 | Origem, destino, protocolo e porta |

A **wildcard mask** é a máscara ao contrário: onde o bit é `0`, tem de casar; onde é `255`, ignora. Conversão: `255.255.255.0` → subtrair de `255.255.255.255` → `0.0.0.255`.

```
access-list 110 permit tcp 10.10.20.0 0.0.0.255 host 10.10.50.15 eq 443
access-list 110 deny   tcp 10.10.20.0 0.0.0.255 10.10.50.0 0.0.0.255 eq 3389
access-list 110 deny   ip any any log
interface GigabitEthernet0/1
 ip access-group 110 in
```

`in` filtra o que **entra** na interface; `out`, o que sai por ela. Ordem importa igual às regras de NGFW, e o `deny ip any any log` explícito no fim existe só para gerar log do que o deny implícito engoliria em silêncio.

### Exercícios — Regras, NAT, PAT e ACLs

1. Converta `255.255.240.0` em wildcard mask e diga qual faixa a ACL `permit ip 172.16.32.0 0.0.15.255 any` cobre.
2. A regra 10 é `LAN_Usuarios → Internet, any, any, allow`. A regra 45 é `10.10.20.55 → 203.0.113.77, tcp/445, deny`. O host 10.10.20.55 conseguiu falar em tcp/445 com 203.0.113.77. Por quê, e como corrigir?
3. Um provedor externo reporta varredura vinda de `192.0.2.10` às 10:14:22 UTC, porta de origem 41022. Qual é o próximo passo da investigação e qual campo do log do Palo Alto você usa?
4. Alerta: "IP interno 192.0.2.10 comunicando com destino malicioso". Verdadeiro ou falso positivo? Justifique.
5. No log do Squid acima, o servidor `intranet.empresa-exemplo.com.br` registrou o acesso vindo de `198.51.100.40`. Como identificar o usuário real?

<details><summary>Ver gabarito</summary>

1. `255.255.255.255 - 255.255.240.0 = 0.0.15.255`. Um /20 cobre 16 endereços de terceiro octeto: de **172.16.32.0 até 172.16.47.255** (4094 hosts úteis). O `any` no destino significa qualquer destino.

2. **Shadowing.** O firewall para na primeira correspondência: a regra 10 já permitiu tudo, então a 45 nunca é avaliada — o *hit count* dela deve estar em zero. Correção: mover a regra 45 para cima da 10 e, principalmente, eliminar a regra ampla, substituindo `any` por objetos de serviço nomeados. Regra `any any allow` em produção é achado de auditoria.

3. `192.0.2.10` é o IP pós-NAT da empresa, não uma máquina. O próximo passo é buscar no log de tráfego do firewall a sessão com **NAT source IP = 192.0.2.10 e NAT source port = 41022** naquele minuto (campos `natsrc`/`natsport` no Palo Alto, `transip`/`transport` no FortiGate) para recuperar o `src_ip` real e o campo de usuário. Só então se isola a estação. Atenção ao fuso: converta UTC para o horário local do log.

4. **Falso positivo de rotulagem, não de detecção.** `192.0.2.10` é IP público de documentação usado aqui como IP de saída do PAT — não é "IP interno". O evento pode ser real, mas a atribuição está errada. Nunca bloqueie o IP de NAT da própria empresa: isso derruba a saída de todos. Reclassifique e siga o fluxo do item 3.

5. O IP `198.51.100.40` é o do proxy. O rastro real está no `access.log` do Squid (que traz `10.10.20.55`) e, na aplicação, no cabeçalho **X-Forwarded-For**. Correlacione `10.10.20.55` com o log de autenticação do Windows (Event ID **4624**, logon bem-sucedido) para chegar ao usuário, por exemplo `jsilva`. Trate X-Forwarded-For como confiável apenas quando inserido pelo seu próprio proxy.

</details>


## Análise de logs reais de firewall

Imagine a portaria de um prédio grande. O porteiro anota num caderno cada pessoa que entrou, quem barrou, a que horas, para qual apartamento e quanto tempo ficou. O log de firewall é exatamente esse caderno — só que com milhões de linhas por dia. Nas seções anteriores vimos o que é um firewall (stateless, stateful e NGFW) e como regras, NAT e ACL decidem quem passa. Agora vamos ler o caderno.

O ponto mais importante para quem nunca estudou redes: **todo log de firewall responde às mesmas cinco perguntas** — quem falou (IP de origem), com quem (IP de destino), por qual porta/protocolo, o que o firewall decidiu (permitir ou negar) e quanto de dado passou. Cada fabricante escreve isso num formato diferente, mas as perguntas não mudam.

### Palo Alto Networks — log TRAFFIC em CSV

O Palo Alto envia o log em CSV (Comma-Separated Values, valores separados por vírgula): campos na ordem, separados por vírgula, sem nome.

```
Sep 03 09:14:22 fw-core-01.corp.local 1,2026/09/03 09:14:22,013201002138,TRAFFIC,end,2561,2026/09/03 09:14:22,10.10.24.57,203.0.113.45,192.0.2.10,203.0.113.45,Regra-Saida-Internet,jsilva,,ssl,vsys1,Trust,Untrust,ae1.100,ae1.200,Log-Forward-SOC,2026/09/03 09:14:20,84213,1,51422,443,45001,443,0x400053,tcp,allow,1842300,9120,1833180,214,2026/09/03 09:11:58,142,computer-and-internet-info,0,9384756,0x0,10.0.0.0-10.255.255.255,US,,118,96,tcp-fin,0,0,0,0,,fw-core-01,from-policy
```

<details><summary>Ver legenda</summary>

| Campo | Significado | Por que interessa |
|---|---|---|
| `TRAFFIC` | Tipo de log (sessão de tráfego) | Separa tráfego de `THREAT`, `URL`, `SYSTEM` |
| `end` | Subtipo: sessão encerrada | `start` só abre; `end` traz bytes finais e duração |
| `10.10.24.57` | Source IP (IP de origem) | Identifica a máquina interna |
| `203.0.113.45` | Destination IP (IP de destino) | Reputação, país, ASN |
| `192.0.2.10` | NAT source IP (IP público após tradução) | Correlacionar com log de proxy/ISP |
| `Regra-Saida-Internet` | Nome da regra que casou | Se casou na regra "catch-all", há falha de política |
| `jsilva` | Source user (usuário, via User-ID) | Liga IP a pessoa sem precisar de DHCP |
| `ssl` | App-ID (aplicação identificada) | Porta 443 com App-ID `ssl` genérico ≠ `google-base` |
| `51422` / `443` | Porta de origem / destino | 443 = HTTPS; porta alta de origem é normal |
| `tcp` / `allow` | Protocolo / ação | `allow`, `deny`, `drop`, `reset-both` |
| `1842300` | Bytes total da sessão | Base para detectar exfiltração |
| `9120` / `1833180` | Bytes enviados / recebidos | Assimetria é o sinal de ouro |
| `142` | Duração em segundos | Sessão longa + volume = suspeita |
| `tcp-fin` | Motivo do encerramento | `tcp-rst-from-server` sugere bloqueio remoto |

</details>

**O que o N1 observa:** normal é `bytes_sent` menor que `bytes_received` em navegação (você baixa mais do que envia). Suspeito é o contrário.

**Erro comum de júnior:** somar `bytes` e achar que é tudo saída. `bytes` é a soma de ida e volta; use `bytes_sent` para exfiltração.

### Palo Alto — log THREAT

```
Sep 03 09:15:03 fw-core-01.corp.local 1,2026/09/03 09:15:03,013201002138,THREAT,spyware,2561,2026/09/03 09:15:03,10.10.24.57,198.51.100.77,192.0.2.10,198.51.100.77,Regra-Saida-Internet,maria.costa,,dns,vsys1,Trust,Untrust,ae1.100,ae1.200,Log-Forward-SOC,2026/09/03 09:15:03,84990,1,53211,53,0,0,0x2000,udp,block-url,"suspicious-domain.example.com",Suspicious DNS Query(14988271),any,high,client-to-server,9384799,0x0,10.0.0.0-10.255.255.255,US,,,1,,,,,,,,0,0,0,0,,fw-core-01,,,,,0,,0,,N/A,spyware,AppThreat-8912-9021
```

<details><summary>Ver legenda</summary>

| Campo | Significado | Por que interessa |
|---|---|---|
| `THREAT` / `spyware` | Log de ameaça, categoria spyware | Indica assinatura acionada, não só tráfego |
| `block-url` | Ação tomada | `alert` = passou! `block-*`/`reset-both` = barrado |
| `"suspicious-domain..."` | Nome do recurso (URL, domínio, arquivo) | O IOC (Indicator of Compromise) que você pesquisa |
| `Suspicious DNS Query(14988271)` | Nome e ID da assinatura | Base para checar falso positivo conhecido |
| `high` | Severidade | Prioriza a fila |
| `client-to-server` | Direção | `server-to-client` = tentativa de entrada |

</details>

**Erro comum de júnior:** ver um log THREAT e assumir bloqueio. Se a ação é `alert`, o pacote **passou** — a investigação é mais urgente, não menos.

### FortiGate — formato key=value

O FortiGate escreve `chave=valor`, o que facilita a leitura humana.

```
date=2026-09-03 time=09:20:11 devname="fgt-edge-01" devid="FG100ETK18000000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.10.24.57 srcport=52011 srcintf="port2" dstip=203.0.113.45 dstport=8443 dstintf="port1" action="accept" policyid=7 policyname="LAN-to-WAN" proto=6 service="HTTPS-ALT" duration=902 sentbyte=48211934 rcvdbyte=18420 srccountry="Reserved" dstcountry="Netherlands" user="jsilva" appcat="unknown"
```

<details><summary>Ver legenda</summary>

| Campo | Significado | Por que interessa |
|---|---|---|
| `type=traffic` / `subtype=forward` | Tráfego roteado entre interfaces | `local` = destinado ao próprio firewall |
| `action="accept"` | Decisão | `accept`, `deny`, `close`, `timeout` |
| `policyid=7` | ID da regra aplicada | Auditar regra permissiva demais |
| `proto=6` | Número do protocolo IP | 6 = TCP, 17 = UDP, 1 = ICMP |
| `duration=902` | Segundos de sessão | 902 s = 15 minutos |
| `sentbyte` / `rcvdbyte` | Bytes enviados / recebidos | Aqui: 48 MB enviados vs 18 KB recebidos |
| `dstcountry` | País de destino (GeoIP) | País fora do perfil da empresa |
| `appcat="unknown"` | Categoria de aplicação | `unknown` em porta alta é bandeira amarela |

</details>

### Cisco ASA — syslog com código %ASA

O ASA usa mensagens numeradas. `%ASA-6-302013` = severidade 6 (informational), mensagem 302013.

```
Sep 03 09:22:47 asa-dmz-01 %ASA-6-302013: Built outbound TCP connection 8841203 for outside:203.0.113.45/443 (203.0.113.45/443) to inside:10.10.24.57/51899 (192.0.2.10/51899)
Sep 03 09:23:02 asa-dmz-01 %ASA-6-106023: Deny tcp src inside:10.10.31.14/49215 dst dmz:10.20.5.30/3389 by access-group "inside_access_in" [0x8a2f11cc, 0x0]
```

<details><summary>Ver legenda</summary>

| Campo | Significado | Por que interessa |
|---|---|---|
| `%ASA-6-302013` | Conexão TCP **construída** (permitida) | Evento de sessão aberta |
| `Built outbound` | Direção: de dentro para fora | `inbound` = originada externamente |
| `8841203` | Connection ID | Casa com o `302014` (Teardown) que fecha |
| `outside:203.0.113.45/443` | Interface:IP/porta reais | Antes do NAT entre parênteses |
| `(192.0.2.10/51899)` | IP/porta após NAT | Traduz interno para público |
| `%ASA-6-106023` | Pacote **negado** por ACL | O log de bloqueio mais consultado |
| `by access-group "inside_access_in"` | ACL que negou | Aponta onde ajustar/investigar |

</details>

**Erro comum de júnior:** confundir `106023` (negado por ACL) com `106100` (log por regra com `log` habilitado, que pode ser permit). Leia o verbo: `Deny` ou `permitted`.

### iptables (Linux) e pfSense

```
Sep  3 09:25:31 srv-web-01 kernel: [128472.339] IPT-DROP-IN IN=eth0 OUT= MAC=00:16:3e:aa:bb:cc SRC=203.0.113.201 DST=10.10.50.12 LEN=60 TOS=0x00 TTL=54 ID=32914 DF PROTO=TCP SPT=61233 DPT=22 WINDOW=29200 RES=0x00 SYN URGP=0
```

```
Sep  3 09:26:04 pf-branch-02 filter[112]: 5,,,1717001234,em0,match,block,in,4,0x0,,52,41022,0,DF,6,tcp,60,198.51.100.90,10.10.60.25,44120,445,0,S,3841002,,29200,,mss;sackOK;TS
```

<details><summary>Ver legenda</summary>

| Campo | Significado | Por que interessa |
|---|---|---|
| `IPT-DROP-IN` | Prefixo do log (definido na regra) | Diz qual cadeia/regra gerou |
| `IN=eth0` / `OUT=` | Interface de entrada / saída | `OUT` vazio = pacote para o próprio host |
| `SRC` / `DST` | Origem e destino | Base de tudo |
| `TTL=54` | Time To Live restante | TTL baixo sugere muitos saltos (origem remota) |
| `PROTO=TCP` `DPT=22` | Protocolo e porta destino | 22 = SSH; 445 = SMB |
| `SYN` | Flag TCP presente | Só SYN = tentativa de abrir conexão |
| `block,in` (pfSense) | Ação e direção | `pass` seria permitido |
| `,S,` (pfSense) | Flags TCP (S = SYN) | Varredura gera muitos SYN sem ACK |

</details>

---

## Três mini-investigações do N1

### Investigação 1 — Beaconing (batimento cardíaco do malware)

**Analogia:** um funcionário sai para fumar exatamente a cada 5 minutos, sempre no mesmo lugar, 24 horas por dia. Humano não faz isso; máquina faz.

```
date=2026-09-03 time=02:00:07 devname="fgt-edge-01" type="traffic" srcip=10.10.24.57 srcport=49871 dstip=203.0.113.88 dstport=443 action="accept" duration=3 sentbyte=812 rcvdbyte=640 policyid=7 appcat="unknown"
date=2026-09-03 time=02:05:08 devname="fgt-edge-01" type="traffic" srcip=10.10.24.57 srcport=49903 dstip=203.0.113.88 dstport=443 action="accept" duration=3 sentbyte=818 rcvdbyte=640 policyid=7 appcat="unknown"
date=2026-09-03 time=02:10:07 devname="fgt-edge-01" type="traffic" srcip=10.10.24.57 srcport=49944 dstip=203.0.113.88 dstport=443 action="accept" duration=2 sentbyte=809 rcvdbyte=640 policyid=7 appcat="unknown"
date=2026-09-03 time=02:15:08 devname="fgt-edge-01" type="traffic" srcip=10.10.24.57 srcport=49990 dstip=203.0.113.88 dstport=443 action="accept" duration=3 sentbyte=815 rcvdbyte=640 policyid=7 appcat="unknown"
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `date` | `2026-09-03` | Data local **do equipamento**, não UTC. Correlacionar com um log em UTC sem acertar o fuso desalinha a timeline |
| `time` | `02:00:07` / `02:05:08` / `02:10:07` / `02:15:08` | Hora local do equipamento |
| `devname` | `"fgt-edge-01"` | Nome do equipamento que gerou o log |
| `type` | `"traffic"` | Categoria do log: `traffic` é sessão, `event` é evento do próprio aparelho, `utm` é inspeção de conteúdo |
| `srcip` | `10.10.24.57` | IP de origem |
| `srcport` | `49871` / `49903` / `49944` / `49990` | Porta de origem, efêmera e sorteada pelo cliente |
| `dstip` | `203.0.113.88` | IP de destino |
| `dstport` | `443` | Porta de destino — é ela que aponta o serviço |
| `action` | `"accept"` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |
| `duration` | `3` / `2` | Duração da sessão em **segundos** |
| `sentbyte` | `812` / `818` / `809` / `815` | Bytes enviados **pela origem**. O ponto de vista é o da origem, não do firewall |
| `rcvdbyte` | `640` | Bytes recebidos pela origem. **Comparar com `sentbyte` é o que revela exfiltração** |
| `policyid` | `7` | **Número da regra que decidiu.** Sem ele não se sabe por que o tráfego passou ou parou |
| `appcat` | `"unknown"` | Categoria da aplicação identificada |

</details>

**Raciocínio passo a passo do N1:**
1. Intervalo entre eventos: 02:00:07 → 02:05:08 → 02:10:07 → 02:15:08. Diferença de 300 s com variação de ±1 s. **Jitter quase zero.**
2. Volume constante e minúsculo (≈ 810 bytes enviados, 640 recebidos). Não é download de conteúdo — é troca de comando.
3. Horário: 02:00 da madrugada, sem usuário logado. Navegação humana não ocorre aí.
4. `appcat="unknown"` na porta 443: tráfego não identificado como aplicação legítima.
5. Checar o destino `203.0.113.88` em threat intel e verificar quantos hosts internos falam com ele. Se for **só um**, aponta para comprometimento daquele host, não para serviço corporativo.
6. Excluir causas benignas: agente de antivírus, telemetria, monitoramento. Verificar processo no host via EDR/Sysmon Event ID 3 (Network connection).

**Decisão:** **escalar para N2** como suspeita de C2 (Command and Control) — MITRE ATT&CK T1071.001 (Application Layer Protocol: Web Protocols) com T1573 possível. Isolar o host se a política permitir.

### Investigação 2 — Port scan interno

**Analogia:** alguém andando pelo corredor girando a maçaneta de todas as portas, uma por uma.

```
Sep 03 10:41:02 asa-dmz-01 %ASA-6-106023: Deny tcp src inside:10.10.31.14/51001 dst dmz:10.20.5.30/21 by access-group "inside_access_in" [0x8a2f11cc, 0x0]
Sep 03 10:41:02 asa-dmz-01 %ASA-6-106023: Deny tcp src inside:10.10.31.14/51002 dst dmz:10.20.5.30/22 by access-group "inside_access_in" [0x8a2f11cc, 0x0]
Sep 03 10:41:02 asa-dmz-01 %ASA-6-106023: Deny tcp src inside:10.10.31.14/51003 dst dmz:10.20.5.30/23 by access-group "inside_access_in" [0x8a2f11cc, 0x0]
Sep 03 10:41:03 asa-dmz-01 %ASA-6-106023: Deny tcp src inside:10.10.31.14/51004 dst dmz:10.20.5.31/445 by access-group "inside_access_in" [0x8a2f11cc, 0x0]
Sep 03 10:41:03 asa-dmz-01 %ASA-6-106023: Deny tcp src inside:10.10.31.14/51005 dst dmz:10.20.5.32/3389 by access-group "inside_access_in" [0x8a2f11cc, 0x0]
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| *(cabeçalho syslog)* | `Sep 03 10:41:02 asa-dmz-01` | **Não faz parte da mensagem do ASA** — é o que o syslog acrescenta à frente: data, hora e nome do equipamento |
| `%ASA` | `%ASA` | Etiqueta do produto: identifica a linha como vinda de um firewall ASA |
| severidade | `6` | Escala syslog do Cisco, de 0 (emergência) a 7 (depuração): `6` é **informational**. **Severidade baixa não quer dizer evento sem importância** — quem a escolhe é o fabricante, não o seu SOC |
| *message ID* | `106023` | Pacote negado por lista de acesso. **É por este número que se escreve a regra no SIEM**: o texto da mensagem muda entre versões do software, o ID não |
| `src` | `inside:10.10.31.14/51001 … /51005` | Interface, IP e porta de **origem**. Aqui a interface é o nome que o ASA dá à zona, e é ela que dá o sentido do tráfego |
| `dst` | `dmz:10.20.5.30/21, /22, /23, depois .31/445 e .32/3389` | Interface, IP e porta de **destino** |
| `by access-group` | ``"inside_access_in"`` | **A lista de acesso que negou**, e a interface onde está aplicada. Sem este campo não se sabe qual regra corrigir |
| `[0x8a2f11cc, 0x0]` | *(par de hashes)* | Identificador interno da **entrada exata** da ACL que casou. É o que permite ao time de rede achar a linha sem contar regras à mão |
| — | — | **Leia as cinco linhas como uma só coisa.** As portas de origem sobem de 51001 a 51005, as de destino percorrem 21, 22, 23, 445 e 3389, e os IPs de destino avançam .30, .31, .32 — tudo em **2 segundos**. Isso é uma ferramenta a varrer a DMZ, não uma pessoa a errar o endereço |

</details>

**Raciocínio passo a passo:**
1. Uma origem (`10.10.31.14`), muitos destinos e muitas portas em **poucos segundos**. Padrão de varredura, não de uso.
2. Portas de origem sequenciais (51001, 51002, 51003...) — assinatura de ferramenta automatizada.
3. Portas de destino "interessantes": 21 (FTP), 22 (SSH), 23 (Telnet), 445 (SMB), 3389 (RDP). É descoberta de serviços administráveis.
4. Identificar o host: consultar DHCP/User-ID/inventário. Se for `10.10.31.14` = estação de `admin.rodrigo` do time de Infraestrutura, pode ser scan autorizado.
5. Checar se existe janela de varredura aprovada (scanner de vulnerabilidade) ou chamado aberto naquele horário.

**Decisão:** se o IP for o scanner de vulnerabilidades corporativo, com janela documentada, **fechar como falso positivo** registrando a evidência (número do chamado + IP do scanner na lista de exceções). Se for uma estação de usuário comum, **escalar** — MITRE T1046 (Network Service Discovery). Regra prática: falso positivo só se você **provar** a autorização; suposição não vale.

### Investigação 3 — Exfiltração por assimetria de bytes

**Analogia:** um caminhão que entra vazio na fábrica e sai carregado, à meia-noite, todos os dias.

```
Sep 03 23:14:55 fw-core-01.corp.local 1,2026/09/03 23:14:55,013201002138,TRAFFIC,end,2561,2026/09/03 23:14:55,10.10.24.57,203.0.113.150,192.0.2.10,203.0.113.150,Regra-Saida-Internet,jsilva,,ssl,vsys1,Trust,Untrust,ae1.100,ae1.200,Log-Forward-SOC,2026/09/03 21:02:11,85110,1,52788,443,41288,443,0x400053,tcp,allow,4831002144,4830880000,122144,3211,2026/09/03 21:02:09,7964,unknown,0,9385221,0x0,10.0.0.0-10.255.255.255,NL,,412,388,tcp-fin,0,0,0,0,,fw-core-01,from-policy
```

<details><summary>Ver legenda</summary>

| Posição | Campo | Valor no exemplo | O que significa |
|---|---|---|---|
| 1 | *(cabeçalho syslog)* | `Sep 03 23:14:55 fw-core-01.corp.local` | **Não é campo do CSV.** É o cabeçalho que o syslog acrescenta antes da linha; se você contar campos a partir daqui, tudo desloca uma posição |
| 2 / 7 | Receive / Generated Time | `2026/09/03 23:14:55` | Quando o firewall recebeu e quando ocorreu |
| 3 | Serial Number | `013201002138` | Qual equipamento gerou |
| 4 / 5 | Type / Subtype | `TRAFFIC` / `end` | Log de sessão, no fim |
| 6, 39, 44 | — | `2561`, `0`, `-` | Reservados pelo fabricante |
| 8 / 9 | Source / Destination Address | `10.10.24.57` / `203.0.113.150` | Origem interna e destino externo |
| 10 / 11 | NAT Source / Destination IP | `192.0.2.10` / `203.0.113.150` | Endereço público de saída e destino |
| 12 | Rule Name | `Regra-Saida-Internet` | A regra que permitiu |
| 13 / 14 | Source / Destination User | `jsilva` / `-` | Usuário resolvido |
| 15 / 16 | Application / Virtual System | `ssl` / `vsys1` | App-ID e firewall virtual |
| 17 / 18 | Source / Destination Zone | `Trust` / `Untrust` | O sentido do tráfego |
| 19 / 20 | Inbound / Outbound Interface | `ae1.100` / `ae1.200` | Subinterfaces de *port-channel* |
| 21 / 22 | Log Action / — | `Log-Forward-SOC` / `2026/09/03 21:02:11` | Perfil de log e campo reservado |
| 23 / 24 | Session ID / Repeat Count | `85110` / `1` | Sessão e contagem |
| 25 / 26 | Source / Destination Port | `52788` / `443` | Porta efêmera e HTTPS |
| 27 / 28 | NAT Source / Destination Port | `41288` / `443` | Portas após tradução |
| 29 / 30 / 31 | Flags / Protocol / Action | `0x400053` / `tcp` / `allow` | Bits, protocolo e veredito |
| 32 | Bytes | `4831002144` | Total: **4,8 GB** |
| 33 / 34 | Bytes Sent / Received | `4830880000` / `122144` | **4,83 GB a subir contra 122 KB a descer.** É a inversão da proporção normal: o caminhão entrou vazio e saiu carregado |
| 35 | Packets | `3211` | Total de pacotes |
| 36 / 37 | Start Time / Elapsed | `2026/09/03 21:02:09` / `7964` | Início e duração: **2h13 de sessão** |
| 38 | Category | `unknown` | Categoria não atribuída — destino que o fabricante não classifica |
| 40 / 41 | Sequence Number / Action Flags | `9385221` / `0x0` | Sequencial e bits da ação |
| 42 / 43 | Source / Destination Location | `10.0.0.0-10.255.255.255` / `NL` | Faixa interna na origem; **destino nos Países Baixos** |
| 45 / 46 | Packets Sent / Received | `412` / `388` | Pacotes em cada direção |
| 47 | Session End Reason | `tcp-fin` | Fim normal: a sessão não foi cortada, terminou sozinha |
| 48–51 | Device Group Hierarchy | `0`, `0`, `0`, `0` | Níveis da hierarquia de grupos no Panorama; zero quando o aparelho não é gerido por grupo |
| 52 / 53 | vsys Name / Device Name | `-` / `fw-core-01` | Nome do sistema virtual e do equipamento |
| 54 | Action Source | `from-policy` | **De onde veio a decisão**: da política escrita (`from-policy`), de uma lista dinâmica ou de uma sobreposição do aparelho |

</details>

**Raciocínio passo a passo:**
1. `bytes_sent` ≈ 4.830.880.000 (≈ 4,5 GB) contra `bytes_received` ≈ 122.144 (≈ 119 KB). Razão de aproximadamente **39.500 para 1**.
2. `duration` = 7964 s ≈ 2 h 12 min. Sessão única e longa — não é navegação.
3. Início às 21:02, fim às 23:14: fora do expediente.
4. `App-ID` genérico e categoria `unknown` na porta 443: não é serviço corporativo conhecido (não é OneDrive, não é Google Drive homologado).
5. Destino em país fora do perfil (`NL`) e sem histórico prévio de acesso pelo restante da empresa.
6. Correlacionar: houve leitura em massa de arquivos no file server? Windows Event ID 4663 (acesso a objeto) ou 4688 (criação de processo) mostrando ferramenta de compressão logo antes?

**Decisão:** **escalar imediatamente** como possível exfiltração — MITRE T1048 (Exfiltration Over Alternative Protocol) / T1567 (Exfiltration Over Web Service). Pedir contenção do host e preservação de evidência.

---

## Queries prontas: SPL (Splunk) e KQL (Sentinel/Defender)

### Top negados por origem

```spl
index=firewall (action=deny OR action=drop OR action=block)
| stats count AS negados, dc(dest_port) AS portas_distintas, dc(dest_ip) AS destinos BY src_ip
| where negados > 100
| sort - negados
| head 20
```
Linha 1 filtra só bloqueios (o nome da ação varia por fabricante, por isso o `OR`). Linha 2 conta bloqueios e mede **variedade** de portas e destinos — varredura tem variedade alta. Linha 3 corta ruído. Linhas 4-5 ordenam e limitam.

```kql
// Top origens bloqueadas nas últimas 24 h
CommonSecurityLog
| where TimeGenerated > ago(24h)                       // janela de busca
| where DeviceAction in ("deny","drop","block","reset-both")  // só bloqueios
| summarize Negados = count(),
            PortasDistintas = dcount(DestinationPort),
            DestinosDistintos = dcount(DestinationIP)
          by SourceIP                                   // agrupa por origem
| where Negados > 100                                   // remove ruído normal
| order by Negados desc
```

### Conexões permitidas para país incomum

```spl
index=firewall action=allow
| iplocation dest_ip
| search Country!="Brazil" AND Country!="United States"
| stats sum(bytes_out) AS bytes_enviados, count AS sessoes BY src_ip, dest_ip, Country
| where bytes_enviados > 50000000
| sort - bytes_enviados
```
`iplocation` enriquece com GeoIP. O filtro remove os países esperados. O `where` de 50 MB descarta acessos triviais.

```kql
// Saída permitida para países fora do perfil, com volume relevante
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceAction == "allow"
| where isnotempty(RemoteCountry)
| where RemoteCountry !in ("Brazil","United States","Portugal")  // perfil da empresa
| summarize BytesEnviados = sum(SentBytes), Sessoes = count()
          by SourceIP, DestinationIP, RemoteCountry
| where BytesEnviados > 50000000                        // ~50 MB
| order by BytesEnviados desc
```

### Sessões de longa duração e alto volume de saída

```spl
index=firewall action=allow duration>3600
| eval razao_saida=round(bytes_out/(bytes_in+1),2)
| where bytes_out > 100000000 AND razao_saida > 10
| table _time, src_ip, user, dest_ip, dest_port, duration, bytes_out, bytes_in, razao_saida
| sort - bytes_out
```
`duration>3600` = mais de 1 hora. `razao_saida` calcula quantas vezes o envio supera o recebimento (o `+1` evita divisão por zero). Razão maior que 10 com mais de 100 MB é o perfil clássico de exfiltração.

```kql
// Sessões longas com forte assimetria de saída
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceAction == "allow" and toint(ReceivedBytes) >= 0
| extend Dur = toint(coalesce(column_ifexists("CommunicationDirection",""), "0"))
| extend RazaoSaida = todouble(SentBytes) / (todouble(ReceivedBytes) + 1)
| where SentBytes > 100000000 and RazaoSaida > 10      // >100 MB e 10x mais saída
| project TimeGenerated, SourceIP, SourceUserName, DestinationIP,
          DestinationPort, SentBytes, ReceivedBytes, RazaoSaida
| order by SentBytes desc
```

### Exercícios — Análise de logs reais de firewall

1. No log FortiGate da seção key=value (`duration=902 sentbyte=48211934 rcvdbyte=18420`), calcule a razão enviado/recebido e diga se o padrão é de download ou de possível exfiltração.
2. Leia esta linha e diga o que aconteceu: `%ASA-6-106023: Deny udp src inside:10.10.24.57/53411 dst outside:198.51.100.5/53 by access-group "inside_access_in"`. Qual serviço foi barrado e por que isso é comum numa rede com DNS interno obrigatório?
3. Um log Palo Alto THREAT mostra `severity=critical` e ação `alert` para o host 10.10.60.25. O analista fechou o ticket dizendo "o firewall bloqueou". Verdadeiro ou falso positivo? Justifique.
4. Você vê 3.000 eventos `%ASA-6-106023` numa hora, todos com origem 10.10.31.14 e destinos variados nas portas 445 e 3389. Qual é o **próximo passo** da investigação, antes de escalar?
5. Escreva, em uma linha de SPL, o filtro que isola sessões permitidas com mais de 1 GB enviados nas últimas 24 horas.

<details><summary>Ver gabarito</summary>

1. 48.211.934 ÷ 18.420 ≈ **2.617 para 1**. O host enviou ~46 MB e recebeu ~18 KB, em 902 s (15 min), para a Holanda numa porta alternativa (8443) com `appcat="unknown"`. Isso é o oposto de download — é o perfil de **possível exfiltração**. Escalar.

2. Foi barrada uma consulta **DNS** (UDP porta 53) saindo de uma estação diretamente para um servidor DNS externo. É comum e geralmente **esperado**: a política obriga todas as estações a usarem os DNS internos (`10.10.1.10`, por exemplo), e o firewall nega DNS direto para a internet. Ainda assim, se o volume for alto e persistente, vale checar tunelamento de DNS (MITRE T1071.004) — um bloqueio repetido pode ser malware tentando um resolvedor próprio.

3. **Fechamento incorreto.** Ação `alert` significa que o firewall **registrou e deixou passar**. Só `block-*`, `drop` ou `reset-both` indicam bloqueio. Com severidade `critical` e tráfego permitido, o caso deveria ser reaberto e escalado, verificando no EDR o que o host fez depois do evento.

4. Antes de escalar: **identificar o host e verificar autorização**. Consultar inventário/DHCP/User-ID para saber de quem é `10.10.31.14`, checar se o IP pertence ao scanner de vulnerabilidades corporativo, e procurar chamado ou janela de varredura aprovada no horário. Também verificar se algum destino **aceitou** conexão (evento `302013` Built) — se tudo foi negado, o impacto é menor; se algo passou, a prioridade sobe. Sem essa checagem você corre o risco de escalar um scan legítimo (ruído) ou fechar um ataque real como falso positivo.

5. `index=firewall action=allow earliest=-24h bytes_out>1073741824` (1 GB = 1.073.741.824 bytes; `earliest=-24h` define a janela).

</details>

## Mini-laboratório — Firewalls: regras, NAT e leitura de logs

**Objetivo:** montar um firewall com regras, gerar tráfego permitido e negado, e ler os logs resultantes.

**Pré-requisitos:** uma máquina virtual Linux (Ubuntu Server) no VirtualBox — gratuito; ou Docker no Linux. Wireshark e nmap instalados. Nunca varra rede que não seja sua.

**Passo 1 — Preparar o alvo.** Na VM, suba um serviço web simples:
```
sudo apt update && sudo apt install -y nginx nmap tcpdump
sudo systemctl start nginx
ip a | grep "inet "
```
Anote o IP da VM (algo como `192.168.56.20`). *Observar:* `curl http://192.168.56.20` deve responder HTML.

**Passo 2 — Criar regras com log.** Bloqueie SSH e registre o descarte:
```
sudo iptables -N LOG_DROP
sudo iptables -A LOG_DROP -j LOG --log-prefix "IPT-DROP-IN " --log-level 4
sudo iptables -A LOG_DROP -j DROP
sudo iptables -A INPUT -p tcp --dport 22 -j LOG_DROP
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -L INPUT -n -v --line-numbers
```
*Observar:* a listagem mostra as regras na ordem e os contadores `pkts`/`bytes` de cada uma — a primeira regra que casa vence.

**Passo 3 — Gerar tráfego permitido e negado.** Do host (fora da VM):
```
nmap -Pn -p 22,80,443 192.168.56.20
```
*Observar:* porta 80 `open`, porta 22 `filtered` (DROP não responde nada), porta 443 `closed` ou `filtered`.

**Passo 4 — Ler os logs.** Na VM:
```
sudo dmesg | grep IPT-DROP-IN | tail -20
sudo journalctl -k --since "10 min ago" | grep IPT-DROP-IN
```
*Observar:* cada linha traz `SRC=`, `DST=`, `PROTO=TCP`, `DPT=22` e a flag `SYN`. Identifique o IP do seu host como `SRC`.

**Passo 5 — Confirmar no Wireshark.** Capture na interface da rede host-only enquanto repete o nmap:
```
sudo tcpdump -i any -n "tcp port 22 or tcp port 80" -c 40 -w /tmp/lab-fw.pcap
```
Abra o arquivo no Wireshark e aplique o filtro `tcp.flags.syn == 1 && tcp.flags.ack == 0`.
*Observar:* para a porta 80 existe SYN seguido de SYN-ACK; para a porta 22 há SYN e retransmissões **sem resposta** — a diferença visual entre `DROP` (silêncio) e `REJECT` (RST).

**Passo 6 — Comparar DROP e REJECT.**
```
sudo iptables -I INPUT 1 -p tcp --dport 3389 -j REJECT --reject-with tcp-reset
nmap -Pn -p 3389 192.168.56.20
```
*Observar:* agora o nmap reporta `closed`, porque recebeu RST.

**Critério de sucesso:** você tem, ao mesmo tempo, (a) linhas de log `IPT-DROP-IN` com origem, destino e porta corretas, (b) uma captura mostrando SYN sem resposta na 22 e handshake completo na 80, e (c) capacidade de explicar por que a 22 aparece `filtered` e a 3389 aparece `closed`.

**Limpeza:** `sudo iptables -F && sudo iptables -X`

## O que um SOC Level 1 realmente precisa saber

- 🟢 Firewall stateful guarda a tabela de conexões: a resposta volta sem precisar de regra explícita; stateless olha pacote a pacote.
- 🟢 Todo log de firewall responde às mesmas cinco perguntas: origem, destino, porta/protocolo, ação e volume.
- 🟢 `allow`/`accept`/`Built` = passou. `deny`/`drop`/`block`/`reset-both` = barrado. Ler o verbo antes de concluir qualquer coisa.
- 🟢 Ação `alert` num log de ameaça significa que o tráfego **passou** — é mais urgente, não menos.
- 🟢 Regra fecha no **primeiro casamento**, de cima para baixo; a ordem das regras é a política real.
- 🟢 NAT (Network Address Translation) troca o IP interno pelo público; sem o campo de NAT no log, você não correlaciona com fontes externas.
- 🟡 Beaconing se reconhece por intervalo regular, jitter baixo, payload pequeno e destino único — não pelo volume.
- 🟡 Exfiltração se reconhece por assimetria: `bytes_sent` muito maior que `bytes_received`, sessão longa, fora de horário.
- 🟡 Port scan se reconhece por uma origem contra muitos destinos/portas em poucos segundos, com portas de origem sequenciais.
- 🟡 Falso positivo só se fecha com **prova** de autorização (chamado, janela de manutenção, IP do scanner documentado).
- 🔴 App-ID/`appcat` genérico ou `unknown` na porta 443 indica tráfego não identificado — candidato a túnel ou C2.
- 🔴 Correlacionar firewall com EDR/Sysmon (Event ID 3, conexão de rede) e Windows Security (4624, 4688) transforma um evento isolado em uma história completa.

## Resumo em 10 linhas

1. O firewall é a portaria da rede: decide quem entra, quem sai e registra tudo.
2. Stateless olha pacotes isolados; stateful acompanha a conversa; NGFW ainda identifica a aplicação e o usuário.
3. Regras são avaliadas de cima para baixo e param no primeiro casamento — ordem é política.
4. NAT e PAT traduzem endereços internos em públicos; o log precisa mostrar os dois lados.
5. Cada fabricante escreve diferente: Palo Alto em CSV, FortiGate em `chave=valor`, Cisco ASA em códigos `%ASA-x-xxxxxx`, iptables/pfSense em syslog.
6. Os campos que resolvem 90% dos casos são origem, destino, porta, ação, bytes enviados, bytes recebidos e duração.
7. Beaconing aparece como conexões pequenas em intervalo quase perfeito, normalmente de madrugada.
8. Port scan aparece como uma origem tentando muitas portas e muitos destinos em segundos.
9. Exfiltração aparece como sessão longa com muito mais dado saindo do que entrando, para destino sem histórico.
10. SPL e KQL transformam esses padrões em consultas repetíveis: top negados, país incomum, sessão longa com alto volume de saída.



---
