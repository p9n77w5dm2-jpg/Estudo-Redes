# Segurança de Rede na Prática: IDS, IPS, NDR e o Ecossistema do SOC

## Por que este módulo importa para o SOC

Até aqui você aprendeu como o tráfego se move pela rede. Agora vamos falar de quem **vigia** esse tráfego. Todo alerta que cai na sua fila de analista N1 nasceu de uma dessas ferramentas: um sensor que leu um pacote, um agente que viu um processo nascer, uma plataforma que juntou tudo. Se você não souber **o que cada ferramenta enxerga — e principalmente o que ela é cega para ver** — você vai fechar como falso positivo um ataque real, ou vai escalar como incidente um backup que roda toda terça-feira. Este módulo te dá esse mapa.

### Índice do módulo

- IDS, IPS e NDR
- SIEM, EDR, XDR, SOAR e o ecossistema completo
- Fluxo de investigação ponta a ponta, níveis do SOC e frameworks

---

## IDS — Intrusion Detection System (Sistema de Detecção de Intrusão)

### O que é

Imagine uma câmera de segurança na portaria do prédio. Ela **vê** todo mundo que entra e sai, **grava** e **dispara um alarme** quando reconhece alguém da lista de procurados. Mas ela não tranca a porta. Se o ladrão entrar, a câmera vai registrar bonitinho o ladrão entrando.

Isso é um IDS: um sensor **passivo**, que fica **fora do caminho do tráfego**, apenas observando uma cópia dos pacotes e gerando alertas. Ele **detecta**, não **impede**.

### Como funciona por dentro

O IDS recebe uma cópia do tráfego por um destes caminhos:

| Método | Como funciona | Observação |
|---|---|---|
| Porta espelho (SPAN / port mirror) | O switch copia o tráfego de uma ou mais portas para a porta onde está o sensor | Barato, mas o switch pode descartar cópias sob carga alta |
| TAP (Test Access Point) | Aparelho físico no cabo que duplica o sinal | Não perde pacote, não depende da CPU do switch |
| Packet broker | Agrega vários TAPs/SPANs e distribui para vários sensores | Usado em ambientes grandes |

Sobre a cópia, o sensor aplica dois tipos de lógica:

- **Detecção por assinatura**: procura um padrão conhecido (uma sequência de bytes, uma URI, um User-Agent). Excelente para ameaça conhecida, cego para ameaça nova.
- **Detecção por anomalia**: compara com o comportamento considerado normal. Pega o desconhecido, mas gera mais ruído.

E há duas famílias de IDS por posição:

| Tipo | Onde roda | O que vê | O que NÃO vê |
|---|---|---|---|
| NIDS (Network IDS) | Sensor na rede | Pacotes de vários hosts, varredura, C2, exfiltração | Conteúdo cifrado, tráfego que não passa pelo sensor, ação local no endpoint |
| HIDS (Host IDS) | Agente dentro do servidor | Alteração de arquivo, log local, processo, integridade | Tráfego de outras máquinas, ataque contra host sem agente |

### Ferramentas reais

- **Snort** — o IDS/IPS clássico, baseado em assinatura, mantido pela Cisco.
- **Suricata** — multi-thread, entende assinaturas no formato Snort, e além de alertar gera metadados (fluxo, DNS, TLS, HTTP) em EVE JSON.
- **Zeek** (antigo Bro) — **atenção: o Zeek não é um IDS de assinatura**. Ele é, antes de tudo, um **gerador de metadados de rede**. Em vez de dizer "isso é malicioso", ele diz "houve uma conexão de A para B, na porta 443, durou 12 segundos, o certificado TLS tinha este nome". Quem decide se é malicioso é você, ou o SIEM. É por isso que o Zeek é a melhor fonte de dados para **caçar** e para **investigar**.

Principais logs que o Zeek gera:

| Log | Conteúdo |
|---|---|
| `conn.log` | Toda conexão: IPs, portas, bytes, duração, estado |
| `dns.log` | Consulta e resposta DNS |
| `http.log` | Método, host, URI, User-Agent, código de resposta |
| `ssl.log` | Versão TLS, SNI (nome do site pedido), emissor do certificado, JA3 |
| `files.log` | Arquivos trafegados e seus hashes |
| `notice.log` | Observações que o Zeek achou dignas de nota |

### Exemplo prático

O host `10.10.20.45` (estação da usuária `maria.costa`) faz uma consulta DNS estranha e depois um download HTTP.

```
# Zeek dns.log (campos separados por TAB)
1725360012.481936  CTr8s1Aq2Xb  10.10.20.45  51422  10.10.0.10  53  udp  38119  0.043  cdn-update-check.example.com  1  C_INTERNET  1  A  0  NOERROR  F  F  T  T  0  203.0.113.77  300.000000  F
```

Leitura campo a campo: horário em epoch, identificador único do fluxo (`uid`), IP e porta de origem, IP e porta do servidor DNS, protocolo, ID da transação, tempo de resposta, **nome consultado**, classe, tipo de registro (A), código de retorno `NOERROR`, flags, e a **resposta: 203.0.113.77**.

```
# Zeek http.log
1725360013.002110  CTr8s1Aq2Xb  10.10.20.45  49733  203.0.113.77  80  1  GET  cdn-update-check.example.com  /pkg/upd.bin  -  1.1  Mozilla/4.0 (compatible)  0  184320  200  OK  -  -  (empty)  -  -  -  -  FhK2mR  -  application/octet-stream
```

Campos importantes: método `GET`, host, **URI** `/pkg/upd.bin`, **User-Agent** `Mozilla/4.0 (compatible)` (agente antigo e genérico — sinal clássico de ferramenta automatizada), `184320` bytes recebidos, status `200`, tipo `application/octet-stream` (binário).

### O que o SOC N1 observa

| Normal | Suspeito |
|---|---|
| Consulta DNS a domínio corporativo conhecido | Domínio recém-registrado, ou com nome que imita marca conhecida |
| User-Agent de navegador atual e completo | User-Agent genérico, vazio ou de biblioteca (`curl`, `python-requests`) |
| Download de arquivo por HTTPS a partir de CDN conhecida | Binário baixado por **HTTP puro** direto de um IP |
| `conn.log` com sessões curtas e variadas | Conexões de duração igual, repetindo em intervalo fixo (batimento de C2) |

### Erro comum de analista júnior

Achar que "o IDS não bloqueou, então não era nada". O IDS **não bloqueia por natureza**. Alerta de IDS com status "allowed" não significa benigno — significa que o tráfego passou e você precisa verificar o que aconteceu no destino.

---

## IPS — Intrusion Prevention System (Sistema de Prevenção de Intrusão)

### O que é

Se o IDS é a câmera, o IPS é o **segurança na catraca**. Todo mundo tem que passar por ele. Ele confere e, se reconhecer o problema, **barra na hora**. O preço disso é óbvio: se o segurança errar, ele barra o funcionário certo — e a produção para.

### Como funciona

O IPS é **inline**: o tráfego atravessa o aparelho. Ao casar uma assinatura, ele pode **drop** (descartar o pacote), **reset** (enviar TCP RST derrubando a sessão) ou **alert** (só registrar). Hoje o IPS quase sempre é um módulo dentro do firewall de próxima geração (Palo Alto, FortiGate, Check Point, Cisco Firepower).

Conceitos que você precisa dominar:

| Conceito | Significado | Consequência prática |
|---|---|---|
| Modo de aprendizado (learning / monitor) | O IPS roda em modo alerta por semanas antes de bloquear | Serve para descobrir quais assinaturas gerariam falso positivo na sua rede |
| Fail-open | Se o aparelho travar, o tráfego **continua passando** | Prioriza disponibilidade, abre janela de risco |
| Fail-close | Se o aparelho travar, o tráfego **para** | Prioriza segurança, derruba o negócio |
| Ajuste (tuning) | Colocar assinatura em exceção por origem/destino | Reduz ruído; tem que ser documentado |

Falso positivo em IPS é caro: uma assinatura mal ajustada pode cortar a integração de pagamento da empresa às 3h da manhã. Por isso mudança de política de IPS passa por processo de mudança formal.

### Como aparece nos logs

Log de ameaça do Palo Alto (formato CSV do tipo THREAT):

```
1,2026/09/03 14:22:07,013201004545,THREAT,vulnerability,2561,2026/09/03 14:22:07,10.10.30.88,203.0.113.42,192.0.2.10,203.0.113.42,Regra-Saida-Internet,corp\jsilva,,web-browsing,vsys1,Confianca,Nao-Confiavel,ethernet1/2,ethernet1/1,Log-Forward,2026/09/03 14:22:09,84213,1,51844,80,42133,80,0x400000,tcp,reset-both,"/admin/config.php",HTTP Directory Traversal Attempt(30845),any,high,client-to-server,7719211,0x0,10.10.30.0-10.10.30.255,US,0,,0,,,1
```

Campos que importam para o N1: tipo `THREAT` / subtipo `vulnerability`; **origem 10.10.30.88**, **destino 203.0.113.42**; a regra que casou; o usuário `corp\jsilva`; a aplicação `web-browsing`; a **ação `reset-both`** (derrubou os dois lados — ou seja, **bloqueou**); a URI `/admin/config.php`; o nome e o ID da assinatura `HTTP Directory Traversal Attempt(30845)`; a severidade `high`; e a direção `client-to-server`.

FortiGate, no formato chave=valor:

```
date=2026-09-03 time=14:31:55 devname="FG-CORP-01" devid="FG100ETK20000123" logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" srcip=203.0.113.201 srcport=44120 dstip=10.10.50.20 dstport=445 proto=6 action="dropped" policyid=12 attack="MS.SMB.Server.Trans.Peeking.Data.Information.Disclosure" severity="critical" attackid=42501 profile="ips_perimetro" incidentserialno=1096312 msg="applications3: MS.SMB.Server..."
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `date` | `2026-09-03` | Data local **do equipamento**, não UTC. Correlacionar com um log em UTC sem acertar o fuso desalinha a timeline |
| `time` | `14:31:55` | Hora local do equipamento |
| `devname` | `"FG-CORP-01"` | Nome do equipamento que gerou o log |
| `devid` | `"FG100ETK20000123"` | Número de série do equipamento — numa frota, é ele que identifica qual falou |
| `logid` | `"0419016384"` | Identificador do **tipo** de log. **É por ele que se filtra no SIEM**: o texto muda entre versões do FortiOS, o número não |
| `type` | `"utm"` | Categoria do log: `traffic` é sessão, `event` é evento do próprio aparelho, `utm` é inspeção de conteúdo |
| `subtype` | `"ips"` | Subcategoria: `forward` é tráfego que atravessa, `local` é destinado ao próprio firewall, `vpn` é túnel, `webfilter` e `ips` são inspeção |
| `eventtype` | `"signature"` | Tipo do evento dentro da categoria UTM |
| `level` | `"alert"` | Severidade atribuída pelo FortiOS (`notice`, `warning`, `alert`, `critical`). **Quem a escolhe é o fabricante**, não o seu SOC |
| `srcip` | `203.0.113.201` | IP de origem |
| `srcport` | `44120` | Porta de origem, efêmera e sorteada pelo cliente |
| `dstip` | `10.10.50.20` | IP de destino |
| `dstport` | `445` | Porta de destino — é ela que aponta o serviço |
| `proto` | `6` | Número do protocolo IP: **`6` é TCP, `17` é UDP, `1` é ICMP**. Vem em número, não em nome |
| `action` | `"dropped"` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |
| `policyid` | `12` | **Número da regra que decidiu.** Sem ele não se sabe por que o tráfego passou ou parou |
| `attack` | `"MS.SMB.Server.Trans.Peeking.Data.Information.Disclosure"` | Nome da assinatura de IPS que disparou |
| `severity` | `"critical"` | Gravidade atribuída à assinatura |
| `attackid` | `42501` | Identificador numérico da assinatura — é por ele que se pesquisa na base do fabricante |
| `profile` | `"ips_perimetro"` | Perfil de segurança que estava aplicado à regra |
| `incidentserialno` | `1096312` | Número que agrupa os eventos do mesmo incidente de IPS |
| `msg` | `"applications3: MS.SMB.Server..."` | Texto livre com a descrição legível. **Não use este campo em regras** — muda entre versões |
| — | — | `attackid` é o que se pesquisa na base do fabricante; `attack` é o nome legível. E `incidentserialno` agrupa os eventos do mesmo incidente — é por ele que se vê se foi uma tentativa ou uma série |

</details>

Aqui: `action="dropped"` (bloqueado), origem externa `203.0.113.201` atacando o SMB (porta 445) de um servidor interno, severidade crítica.

### O que o SOC N1 observa

- **Ação**: `dropped` / `reset-both` = bloqueado. `allowed` / `alert` = **passou**, e isso muda a urgência completamente.
- **Direção**: `client-to-server` de dentro para fora pode ser um usuário navegando; de fora para dentro contra um servidor exposto é bem mais grave.
- **Repetição**: uma assinatura disparando 4.000 vezes em 10 minutos da mesma origem geralmente é varredura automatizada; disparando 1 vez de forma bem-sucedida contra um servidor crítico é mais preocupante.

### Erro comum de analista júnior

Ver severidade `critical` e escalar imediatamente sem olhar a **ação**. Se o IPS já bloqueou (`dropped`) uma tentativa vinda da internet contra a borda, isso é o controle funcionando. O que muda o jogo é: passou? o alvo é vulnerável? houve tráfego de resposta depois?

---

## NDR — Network Detection and Response (Detecção e Resposta de Rede)

### O que é

O IDS reconhece rostos da lista de procurados. O NDR é o porteiro veterano que trabalha no prédio há 15 anos: ele não tem lista nenhuma, mas sabe que **aquele morador nunca desce às 3h da manhã carregando caixas** — e estranha.

NDR é análise **comportamental** do tráfego. Ele constrói um **baseline** (o retrato do que é normal para cada host, usuário e segmento) e alerta quando o comportamento se desloca.

### Como funciona

1. Coleta metadados de fluxo (NetFlow, IPFIX, sFlow) ou pacote completo.
2. Aprende, por semanas, o padrão de cada ativo: com quem fala, em quais portas, em que volume, em que horário.
3. Aplica modelos comportamentais e aprendizado de máquina para achar desvios.

O ponto forte do NDR é que boa parte da detecção **não depende de ler o conteúdo**. Mesmo com tudo cifrado em TLS, ele ainda vê:

| Sinal (visível mesmo cifrado) | Ameaça associada | Técnica MITRE ATT&CK |
|---|---|---|
| Conexões em intervalo regular, mesmo tamanho (batimento) | Canal de comando e controle | T1071 — Application Layer Protocol |
| Host de escritório falando SMB/WinRM com dezenas de outros hosts | Movimento lateral | T1021 — Remote Services |
| Volume de saída muito acima do baseline daquele host | Exfiltração de dados | T1048 — Exfiltration Over Alternative Protocol |
| Muitas consultas DNS longas para o mesmo domínio pai | Túnel DNS | T1071.004 — DNS |
| Um host varrendo faixas inteiras em portas comuns | Descoberta de rede | T1046 — Network Service Discovery |

Produtos de mercado: **Darktrace**, **Vectra AI**, **ExtraHop Reveal(x)**, **Cisco Secure Network Analytics (Stealthwatch)**, **Corelight** (Zeek comercializado), **Arista Awake**.

### O ponto cego do NDR

- Ele vê **que** houve conversa, não **o que** foi dito, quando há cifra (sem descriptografia).
- Precisa de tempo de aprendizado: nas primeiras semanas gera muito ruído.
- Se o ataque acontece **dentro de um único host** (malware que não sai para a rede), o NDR não vê nada — isso é território do EDR.
- Tráfego que não passa pelo ponto de coleta (VM para VM no mesmo hipervisor, nuvem sem espelhamento) é invisível.

### Erro comum de analista júnior

Tratar alerta de NDR como se fosse assinatura: "qual foi o malware?". NDR não diz malware, diz **desvio de comportamento**. A investigação certa é comparar com o histórico daquele host e perguntar: isso já acontecia antes? existe mudança legítima (servidor novo, backup novo, ferramenta nova) que explique?

---

## Anatomia de um alerta Suricata em EVE JSON

Este é o formato que você mais vai ler na vida real. EVE significa Extensible Event Format, e é JSON — uma linha por evento.

```json
{
  "timestamp": "2026-09-03T14:47:12.338921+0000",
  "flow_id": 1284419307749321,
  "in_iface": "eth1",
  "event_type": "alert",
  "src_ip": "10.10.20.45",
  "src_port": 49788,
  "dest_ip": "203.0.113.77",
  "dest_port": 443,
  "proto": "TCP",
  "community_id": "1:9Xk2pQ0mRr8sT1uV3wY5zA7bC9d=",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2028371,
    "rev": 3,
    "signature": "ET MALWARE Observed Cobalt Strike Beacon TLS Certificate (Fake CN)",
    "category": "A Network Trojan was detected",
    "severity": 1,
    "metadata": {
      "attack_target": ["Client_Endpoint"],
      "created_at": ["2026_02_11"],
      "mitre_technique_id": ["T1071.001"]
    }
  },
  "tls": {
    "sni": "cdn-update-check.example.com",
    "version": "TLS 1.2",
    "subject": "CN=localhost",
    "issuerdn": "CN=localhost",
    "ja3": {"hash": "72a589da586844d7f0818ce684948eea"}
  },
  "flow": {
    "pkts_toserver": 41,
    "pkts_toclient": 38,
    "bytes_toserver": 6120,
    "bytes_toclient": 9844,
    "start": "2026-09-03T14:46:58.104332+0000"
  }
}
```

Dissecando campo a campo:

<details><summary>Ver legenda</summary>

| Campo | Significado | Por que importa para o N1 |
|---|---|---|
| `timestamp` | Momento do evento, com fuso | Base da linha do tempo da investigação |
| `flow_id` / `community_id` | Identificadores do fluxo | Permitem correlacionar o mesmo fluxo entre Suricata, Zeek e SIEM |
| `event_type: alert` | É um alerta (poderia ser `dns`, `http`, `tls`, `flow`) | Filtra o que é detecção do que é só metadado |
| `src_ip` / `dest_ip` / `dest_port` | Quem falou com quem | Origem interna 10.10.20.45 saindo para 203.0.113.77:443 |
| `alert.action: allowed` | **O tráfego passou** | Suricata estava em modo IDS, não IPS. A conexão aconteceu. |
| `alert.signature_id` (`sid`) | Número único da regra | Serve para pesquisar histórico e ajustar exceções |
| `alert.rev` | Revisão da regra | Regra atualizada pode mudar comportamento |
| `alert.signature` | Nome legível da regra | Diz o que a regra acredita ter encontrado |
| `alert.severity` | 1 = mais grave | Ajuda a priorizar a fila |
| `metadata.mitre_technique_id` | Mapeia para o ATT&CK | T1071.001 = C2 sobre protocolo web |
| `tls.sni` | Nome do site pedido no handshake | Visível mesmo com o conteúdo cifrado |
| `tls.subject` / `issuerdn` | Dono e emissor do certificado | `CN=localhost` autoassinado em servidor de internet é anormal |
| `tls.ja3.hash` | Impressão digital do cliente TLS | Identifica a ferramenta que abriu a conexão, não o site |
| `flow.pkts_*` / `bytes_*` | Volume nos dois sentidos | Pouco tráfego e sessão longa combina com canal de controle |

</details>

### O que é a assinatura que disparou

`ET MALWARE Observed Cobalt Strike Beacon TLS Certificate (Fake CN)` vem do conjunto de regras **Emerging Threats**. Ela não lê o conteúdo cifrado — ela olha o **certificado apresentado durante o handshake TLS**, que trafega **em claro**. O Cobalt Strike, ferramenta legítima de teste de intrusão amplamente abusada por atacantes, historicamente sobe seu servidor com um certificado autoassinado de características previsíveis. A regra casa esse padrão de certificado. Ou seja: a detecção acontece **antes** da cifra começar, o que é exatamente por isso que ela funciona.

Isso também explica seu limite: se o operador trocar o certificado por um emitido por uma autoridade pública válida, essa assinatura específica **não dispara mais** — e a detecção passa a depender do NDR (batimento, volume, JA3 fora do baseline).

---

## Comparativo rápido

| | IDS | IPS | NDR |
|---|---|---|---|
| Posição na rede | Fora do caminho (SPAN/TAP) | Inline | Fora do caminho (metadados/fluxo) |
| Age sobre o tráfego? | Não | Sim, bloqueia | Geralmente não (alguns integram resposta) |
| Base de detecção | Assinatura + anomalia | Assinatura + reputação | Comportamento + baseline |
| Funciona com tráfego cifrado? | Parcial (SNI, certificado, JA3) | Parcial (ou com descriptografia) | Sim, por padrão de comportamento |
| Risco de derrubar produção | Nenhum | Alto | Baixo |
| Ponto cego principal | Conteúdo cifrado; ação local no host | Igual ao IDS + risco de falso positivo | Não diz "qual malware"; precisa de aprendizado |
| Exemplos | Snort, Suricata, Zeek | Palo Alto, FortiGate, Firepower | Darktrace, Vectra, ExtraHop, Corelight |

## Consultas de apoio

Splunk (SPL), contando disparos de assinatura por origem:

```spl
index=ids sourcetype=suricata:eve event_type=alert
| stats count AS disparos, dc(dest_ip) AS destinos_distintos by src_ip, alert.signature, alert.action
| where disparos > 20
| sort - disparos
```

Linha 1 filtra só eventos de alerta do Suricata. Linha 2 agrupa por origem, assinatura e ação, contando disparos e quantos destinos distintos foram tocados. Linha 3 mantém só o que repetiu bastante. Linha 4 ordena do maior para o menor.

Microsoft Sentinel (KQL), procurando candidatos a batimento de C2:

```kql
CommonSecurityLog
| where TimeGenerated > ago(24h)                    // janela de 24 horas
| where DeviceVendor == "Palo Alto Networks"        // só logs do firewall
| where DestinationIP !startswith "10."             // exclui destino interno
| summarize conexoes = count(),
            bytes = sum(SentBytes),
            desvio = stdev(todouble(SentBytes))
          by SourceIP, DestinationIP, DestinationPort
| where conexoes > 100 and desvio < 200             // muitas sessões de tamanho quase igual
| order by conexoes desc
```

A lógica: canal de controle automatizado tende a gerar **muitas conexões com tamanho muito parecido**, logo o desvio padrão dos bytes enviados fica baixo. Usuário humano navegando gera desvio alto.

---

### Exercícios — IDS, IPS e NDR

1. No log THREAT do Palo Alto mostrado acima, a ação foi `reset-both` e a severidade `high`. Um colega quer abrir incidente de comprometimento. Você concorda? Justifique com base em dois campos do log.

2. O alerta EVE JSON do Suricata traz `"action": "allowed"`, `tls.subject = "CN=localhost"` e um fluxo de 41 pacotes de saída contra 38 de entrada em 14 segundos. Isso é verdadeiro ou falso positivo? Qual o **próximo passo** da investigação e qual log você buscaria primeiro?

3. Um servidor de aplicação `10.10.50.20` normalmente envia 200 MB por dia para a internet. Na terça-feira ele enviou 14 GB para `198.51.100.30` na porta 443, entre 02h e 04h. O IDS de assinatura não gerou nenhum alerta. Explique por que o IDS ficou calado e qual tecnologia deveria ter pegado isso.

4. O NDR alertou "comunicação interna anômala": a estação `10.10.20.45` abriu SMB (porta 445) contra 37 servidores em 6 minutos. O usuário logado é `svc_backup`. Liste três perguntas de verificação antes de escalar.

5. Cálculo de cobertura: sua rede tem 4 saídas para a internet, mas há sensor Suricata espelhado em apenas 2 delas. Se o tráfego se distribui igualmente, qual percentual do tráfego de saída seu IDS **não** enxerga? Que tipo de ameaça isso favorece?

<details><summary>Ver gabarito</summary>

**1.** Não, ainda não é incidente de comprometimento. Dois campos decidem: **ação = `reset-both`**, ou seja, o IPS derrubou os dois lados da sessão — o ataque não se completou; e **direção = `client-to-server`** com origem interna `10.10.30.88` indo para fora, o que caracteriza um usuário (`corp\jsilva`) navegando e recebendo/enviando conteúdo que casou com a assinatura de directory traversal, não um servidor interno sendo invadido. O tratamento correto é registrar, verificar se há repetição pelo mesmo host e checar se `jsilva` acessou o mesmo destino outras vezes. Escalar só se houver padrão persistente ou se a ação tivesse sido `allow`.

**2.** Trata-se de um **verdadeiro positivo altamente provável**, e o mais importante: `"action": "allowed"` significa que o Suricata estava em modo IDS — **a conexão ocorreu**. Três indícios se somam: certificado autoassinado com `CN=localhost` em um servidor de internet (nenhum serviço legítimo faz isso), volume baixo e simétrico com sessão longa (perfil de canal de controle), e a assinatura mapeada para T1071.001. Próximo passo: buscar o `conn.log` e o `ssl.log` do Zeek pelo mesmo `community_id`/`uid` para ver **quantas vezes** e **em que intervalo** essa conexão se repetiu — se houver periodicidade, é batimento de C2. Em seguida, consultar o EDR do host `10.10.20.45` para identificar o **processo** que abriu o socket, e isolar a estação conforme o playbook. Não feche como falso positivo por "não sei qual é o malware".

**3.** O IDS de assinatura ficou calado porque **não existe assinatura para "enviar muitos bytes"**. O tráfego estava em TLS na porta 443, o conteúdo era ilegível para o sensor, e nenhum padrão conhecido apareceu no handshake. Quem pega isso é o **NDR**: 14 GB contra um baseline de 200 MB é um desvio de 70 vezes, em horário fora do expediente, para um destino externo novo. Mapeia para T1048 (exfiltração por protocolo alternativo). Um SIEM com regra de volume também pegaria, se alguém tiver escrito a regra.

**4.** Perguntas obrigatórias antes de escalar: (a) **Isso já acontecia antes?** Consultar o baseline do NDR e o histórico de `conn.log` dos últimos 30 dias para essa origem — se o padrão for semanal, é a rotina de backup. (b) **A conta `svc_backup` deveria estar logada em uma estação de usuário?** Conta de serviço interativa em estação é anomalia clássica; verificar Windows Security 4624 com `Logon Type` e a estação de origem. (c) **Houve mudança legítima?** Consultar o registro de mudanças: novo agente de backup, novo inventário, varredura de vulnerabilidade agendada. Bônus: verificar se `10.10.20.45` é mesmo servidor de backup ou uma estação comum — estação de escritório falando SMB com 37 servidores é movimento lateral (T1021.002) até prova em contrário.

**5.** Com 4 saídas e sensor em 2, a cobertura é 2/4 = 50%. Logo, **50% do tráfego de saída é invisível** ao IDS. Isso favorece qualquer ameaça que use as saídas não monitoradas: canal de comando e controle, exfiltração e download de segundo estágio passam sem alerta. Pior: gera falsa sensação de segurança, porque o painel mostra "0 alertas" naquele caminho. A correção é instalar TAP/SPAN nas outras duas saídas, ou concentrar a saída em menos pontos monitorados.

</details>


## SIEM — o cérebro que junta tudo num lugar só

Imagine um shopping com 200 câmeras. Cada câmera grava sozinha, num gravador diferente, com relógios desajustados. Se alguém furta uma loja e foge pelo estacionamento, o segurança precisa ir de gravador em gravador. Agora imagine que todas as câmeras mandam a imagem para uma sala única, com relógio sincronizado, etiqueta em cada gravação e um sistema que avisa quando alguém corre no corredor. Essa sala é o SIEM.

**O que é.** SIEM significa **Security Information and Event Management** (Gestão de Informação e Eventos de Segurança). É a plataforma central que coleta logs de todos os equipamentos, normaliza esses logs para um formato comum, correlaciona eventos de fontes diferentes e gera alertas.

**Como funciona.** O caminho do dado no SIEM tem cinco etapas:

| Etapa | O que acontece | Exemplo |
|---|---|---|
| **Log source** (fonte de log) | O equipamento que gera o evento | Firewall FortiGate, Domain Controller, proxy Zscaler |
| **Coleta** | Agente ou coletor recebe via syslog, API ou arquivo | Splunk Universal Forwarder, Sentinel Data Connector |
| **Parser** | Quebra o texto bruto em campos | `srcip=10.10.20.55` vira o campo `src_ip` |
| **Normalização** | Mapeia campos diferentes para um nome único | `srcip` (Fortinet), `src` (Palo Alto) e `IpAddress` (Windows) viram todos `src_ip` |
| **Correlação** | Regra que cruza eventos e dispara alerta | 10 eventos 4625 seguidos de um 4624 do mesmo IP |

Sem normalização não existe busca única. É por isso que a maioria dos SIEM adota um modelo de dados: **CIM** no Splunk (Common Information Model), **ASIM** no Microsoft Sentinel (Advanced Security Information Model), **ECS** no Elastic (Elastic Common Schema).

**Casos de uso, dashboards e retenção.** Um *caso de uso* é a pergunta de segurança que a regra responde ("alguém está tentando adivinhar senha?"). O *dashboard* mostra o panorama (top IPs bloqueados, volume de eventos por fonte). A *retenção* é por quanto tempo o dado fica pesquisável — tipicamente 90 dias em disco rápido (hot) e 1 ano ou mais em arquivo frio (cold). Quando o N1 abre um caso de dois meses atrás e não acha nada, quase sempre o dado saiu do hot.

### Produtos de SIEM que você vai encontrar

| Produto | Fabricante | Linguagem de busca | Observação |
|---|---|---|---|
| Splunk Enterprise Security | Splunk / Cisco | SPL | Muito usado em grandes empresas |
| Microsoft Sentinel | Microsoft | KQL | Nativo em nuvem Azure |
| IBM QRadar | IBM | AQL | Forte em correlação de ofensas |
| Elastic SIEM | Elastic | KQL/EQL/Lucene | Sobre o Elasticsearch |
| Wazuh | Open source | Filtros e regras XML | Gratuito, também faz HIDS |

### Como o N1 constrói uma busca

A receita é sempre a mesma: **fonte → janela de tempo → filtro → agrupamento**.

Cenário fictício: o alerta diz que houve muitas falhas de logon contra o servidor `dc01.corp.local` (10.10.5.10).

**Como aparece nos logs** — Windows Security, EventID 4625 (falha de logon):

```
EventID: 4625
Account Name:      jsilva
Account Domain:    CORP
Failure Reason:    Unknown user name or bad password
Status:            0xC000006D
Sub Status:        0xC000006A
Logon Type:        3
Workstation Name:  NB-VENDAS-07
Source Network Address: 10.10.20.55
Source Port:       49877
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `EventID` | `4625` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não. `4625` = **falha** de logon |
| `Account Name` | `jsilva` | A conta envolvida. Terminada em `$` é **conta de computador**, não de pessoa |
| `Account Domain` | `CORP` | Domínio da conta |
| `Failure Reason` | `Unknown user name or bad password` | Motivo da falha em texto — legível, mas **use o `Sub Status` na regra** |
| `Status` | `0xC000006D` | Código geral do resultado. `0xC000006D` = falha genérica de logon — o `Sub Status` é que diz a causa real |
| `Sub Status` | `0xC000006A` | **O código que diz a causa real** — o `Status` costuma ser genérico. `0xC000006A` = **senha errada** |
| `Logon Type` | `3` | **Como a sessão foi iniciada.** `3` = **rede** — acesso a compartilhamento, RPC, WinRM. É o tipo que domina em movimento lateral |
| `Workstation Name` | `NB-VENDAS-07` | Nome que a máquina de origem **declarou**. Vem do próprio cliente, logo é falsificável — trate como pista, não como identidade |
| `Source Network Address` | `10.10.20.55` | **IP de origem.** Vazio ou `-` significa que a sessão foi local, e `::1`/`127.0.0.1` que veio da própria máquina |
| `Source Port` | `49877` | Porta de origem, efêmera |

</details>

Campos que importam: `Logon Type 3` é logon pela rede (SMB, compartilhamento); `Sub Status 0xC000006A` é senha errada com usuário existente; `0xC0000064` seria usuário inexistente; `Source Network Address` é de onde veio a tentativa.

**Busca em SPL (Splunk):**

```
index=windows EventCode=4625 earliest=-1h
| stats count AS falhas, dc(Account_Name) AS usuarios BY Source_Network_Address
| where falhas > 20
| sort - falhas
```
Linha 1: escolhe o índice, o evento e a janela de 1 hora. Linha 2: conta falhas e usuários distintos por IP de origem. Linha 3: só mostra origens com mais de 20 falhas. Linha 4: ordena da maior para a menor.

**A mesma busca em KQL (Sentinel):**

```kql
SecurityEvent
| where TimeGenerated > ago(1h)              // janela de 1 hora
| where EventID == 4625                       // falha de logon
| summarize falhas = count(),                 // total de falhas
            usuarios = dcount(TargetUserName) // quantos usuários distintos
    by IpAddress
| where falhas > 20                           // limiar de ruído
| order by falhas desc
```

**O que o N1 observa.** Normal: 3 a 5 falhas de um usuário só, seguidas de um 4624 (sucesso) — é gente errando a senha. Suspeito: **1 IP × muitos usuários** (password spraying, MITRE **T1110.003**) ou **1 usuário × centenas de senhas** (brute force, **T1110.001**).

**Erro comum de analista júnior:** contar só o número de falhas e ignorar `dc(usuarios)`. Vinte falhas de um usuário é dedo gordo; vinte falhas contra vinte usuários diferentes é ataque.

## EDR — a câmera dentro do computador

Se o firewall é a portaria do prédio, o **EDR** é a câmera dentro do apartamento. **EDR** significa **Endpoint Detection and Response** (Detecção e Resposta em Endpoint).

**O que é.** Um agente de software instalado no notebook ou servidor que grava tudo o que acontece ali dentro e permite reagir remotamente.

**Como funciona.** Ele coleta quatro famílias de telemetria: **processo** (quem executou o quê, com qual linha de comando, filho de quem), **arquivo** (criação, escrita, hash), **registro** (chaves do Windows alteradas) e **rede** (qual processo abriu qual conexão). Sobre isso roda a **detecção comportamental**: em vez de procurar um vírus conhecido, procura um comportamento errado — Word abrindo PowerShell, por exemplo.

**Exemplo prático.** A estação `NB-VENDAS-07` (10.10.20.55), do usuário `jsilva`, executa uma macro de planilha.

**Como aparece nos logs** — Sysmon EventID 1 (criação de processo):

```
EventID: 1
UtcTime: 2026-09-03 14:22:11.442
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -nop -w hidden -enc <cadeia base64 removida>
ParentImage: C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE
User: CORP\jsilva
Hashes: SHA256=A1B2C3D4E5F6...
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `EventID` | `1` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não. `1` = Sysmon **Process Create** |
| `UtcTime` | `2026-09-03 14:22:11.442` | Instante do evento **em UTC**, o que dispensa converter fuso ao correlacionar |
| `Image` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | Caminho do executável (nomenclatura do Sysmon) |
| `CommandLine` | `powershell.exe -nop -w hidden -enc <cadeia base64 removida>` | Linha de comando. `-enc` indica comando em Base64 e `-w hidden` janela oculta |
| `ParentImage` | `C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE` | Caminho do processo **pai**. **É aqui que o Sysmon brilha**: Word ou Excel como pai de `powershell.exe` é sinal forte por si só |
| `User` | `CORP\jsilva` | Conta sob a qual o processo corre |
| `Hashes` | `SHA256=A1B2C3D4E5F6...` | Resumos criptográficos do executável — servem para procurar o mesmo binário na frota |

</details>

Sysmon EventID 3 é conexão de rede e 22 é consulta DNS feita pelo processo. O par 1 + 3 mostra quem executou e para onde falou.

A **árvore de processos** (process tree) é a linhagem: `EXCEL.EXE → powershell.exe → cmd.exe`. Excel não é pai natural de PowerShell — isso é **T1059.001** (interpretador PowerShell).

**Resposta.** Dois recursos salvam o dia: **isolamento de host** (network containment — o EDR corta toda a rede da máquina, mantendo só a conexão com o console) e **live response** (sessão remota para coletar arquivo, matar processo, listar serviços). Produtos comuns: **CrowdStrike Falcon**, **Microsoft Defender for Endpoint** e **SentinelOne**.

**O que o N1 observa.** Normal: PowerShell filho de `explorer.exe` num script de TI. Suspeito: PowerShell filho de Office, com `-w hidden` e `-enc`, seguido de conexão para um IP externo como 203.0.113.77.

**Erro comum de analista júnior:** isolar a máquina antes de coletar o essencial — ou, pior, isolar um servidor de produção sem avisar o dono do serviço. Isolamento é decisão, não reflexo.

## XDR, SOAR e os complementos do ecossistema

**XDR** — **Extended Detection and Response** (Detecção e Resposta Estendida). É o EDR que deixa de olhar só o endpoint e passa a correlacionar cinco domínios: **endpoint, rede, identidade, e-mail e nuvem**. O ganho é juntar sozinho a história: e-mail com anexo → processo suspeito no notebook → logon anômalo no Entra ID → download no SharePoint. O que o N1 faria em quatro consoles, o XDR entrega como um incidente só.

**SOAR** — **Security Orchestration, Automation and Response** (Orquestração, Automação e Resposta). É o robô que executa a rotina chata. Três usos principais: **playbook** (a receita passo a passo do incidente), **enriquecimento automático** (pegar o IP 203.0.113.77 e já trazer reputação, país e histórico interno antes do analista abrir o caso) e **contenção automatizada** (bloquear o IP no firewall, desabilitar a conta, isolar o host). Regra de ouro: contenção automática só onde o falso positivo custa pouco.

**UEBA** — **User and Entity Behavior Analytics** (Análise de Comportamento de Usuário e Entidade). Aprende o padrão normal de cada pessoa e aponta o desvio: `maria.costa` sempre acessa 3 pastas por dia e hoje acessou 400.

**TIP** — **Threat Intelligence Platform** (Plataforma de Inteligência de Ameaças). Guarda e distribui indicadores (IP, domínio, hash) para o SIEM e o firewall consultarem.

**NAC** — **Network Access Control** (Controle de Acesso à Rede). Decide quem entra na rede cabeada ou Wi-Fi, geralmente com 802.1X; joga máquina desconhecida numa VLAN de quarentena.

**DLP** — **Data Loss Prevention** (Prevenção de Perda de Dados). Vigia o dado saindo: e-mail com planilha de clientes, upload para nuvem pessoal, cópia para pendrive.

**WAF** — **Web Application Firewall** (Firewall de Aplicação Web). Fica na frente do site e filtra ataque de aplicação (SQL injection, XSS) que o firewall de rede não enxerga, porque para ele é só HTTPS legítimo.

Detecção em rede propriamente dita (IDS, IPS e NDR) é assunto de outro trecho deste módulo.

### O ecossistema, do dado à contenção

```
   ENDPOINT            REDE                NUVEM / SAAS
  (EDR agent)     (firewall, proxy,       (Entra ID, M365,
   Sysmon          Zeek, NetFlow)          AWS CloudTrail)
      |                  |                       |
      +--------+---------+-----------+-----------+
               |                     |
        [ COLETORES / FORWARDERS / CONNECTORS ]
               |
               v
   +-------------------------------------------+
   |                  SIEM                     |
   |  parser -> normalizacao -> correlacao     |
   |  regras | casos de uso | dashboards       |
   +-------------------------------------------+
          |                       ^
          v                       | consulta / caca
     [ ALERTA / CASO ]            |
          |                       |
          v                       |
   +------------------+           |
   | ANALISTA SOC N1  |-----------+
   +------------------+
          | decide
          v
   +------------------+      +----------------------+
   |      SOAR        |----->| CONTENCAO            |
   | playbook +       |      | bloqueio no firewall |
   | enriquecimento   |      | isolar host (EDR)    |
   +------------------+      | desabilitar conta AD |
                             +----------------------+
```

### Que pergunta cada ferramenta responde

| Pergunta que preciso responder | Ferramenta que responde |
|---|---|
| "Esse IP externo conversou com alguém da empresa hoje?" | SIEM (logs de firewall e proxy) |
| "Qual processo abriu essa conexão e quem é o pai dele?" | EDR |
| "Que arquivo esse malware criou no disco?" | EDR |
| "Esse hash já é conhecido como malicioso?" | TIP |
| "O e-mail, o notebook e o logon na nuvem são o mesmo incidente?" | XDR |
| "Esse usuário está agindo fora do padrão dele?" | UEBA |
| "Alguém enviou base de clientes para fora?" | DLP |
| "Esse notebook desconhecido pode entrar na rede?" | NAC |
| "Nosso site está sofrendo SQL injection?" | WAF |
| "Como bloquear o IP e isolar o host sem abrir 4 consoles?" | SOAR |
| "Quantas vezes isso aconteceu nos últimos 90 dias?" | SIEM (retenção) |

### Exercícios — SIEM, EDR, XDR, SOAR e o ecossistema completo

1. Em uma hora, o SIEM registra do IP 10.10.20.55: 240 eventos 4625 contra 240 contas diferentes, cada conta com exatamente 1 falha, e 1 evento 4624 (sucesso) para a conta `svc_backup`. Classifique a técnica e diga se é verdadeiro ou falso positivo.
2. Escreva em SPL uma busca que liste, na última hora, IPs de origem com mais de 15 falhas 4625 e mais de 10 usuários distintos.
3. O Sysmon EventID 1 mostra `ParentImage: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE` e `Image: powershell.exe` com `-w hidden -enc`. Qual é o próximo passo da investigação e qual ferramenta você usa?
4. O usuário `maria.costa` fez logon às 03:10 de um IP 198.51.100.42, país diferente do habitual, e em seguida baixou 800 arquivos do SharePoint. Qual ferramenta levanta o desvio de comportamento e qual junta os dois eventos num só incidente?
5. O playbook de SOAR propõe bloquear automaticamente todo IP com reputação ruim. Cite um risco concreto e uma salvaguarda.

<details><summary>Ver gabarito</summary>

1. **Password spraying — T1110.003**, e é **verdadeiro positivo**. A assinatura é 1 tentativa por conta contra muitas contas (evita bloqueio de conta), não muitas tentativas numa conta. O agravante é o 4624 final: uma conta de serviço (`svc_backup`) autenticou com sucesso logo depois. Ação imediata do N1: escalar para N2, isolar/verificar a origem 10.10.20.55 e sinalizar a conta `svc_backup` para reset e revisão de sessões.

**2.**
```
index=windows EventCode=4625 earliest=-1h
| stats count AS falhas, dc(Account_Name) AS usuarios BY Source_Network_Address
| where falhas > 15 AND usuarios > 10
| sort - falhas
```
   O `dc()` (distinct count) é o que separa erro de digitação de ataque distribuído por contas.

3. Próximo passo: abrir a **árvore de processos no EDR** e verificar os filhos do PowerShell e as conexões de rede (Sysmon EventID 3 / telemetria de rede do EDR) — para onde ele falou e o que gravou em disco. Ferramenta: **EDR** (CrowdStrike Falcon, Defender for Endpoint ou SentinelOne). Documento hash e linha de comando; só depois considero isolamento, avisando o dono da máquina. Word como pai de PowerShell oculto e codificado é padrão de macro maliciosa (**T1059.001**).

4. O desvio de comportamento é levantado pelo **UEBA** (horário, geografia e volume fora da linha de base da `maria.costa`). Quem junta o logon de identidade com a atividade em SaaS num incidente único é o **XDR** — ou, se não houver XDR, uma regra de correlação no **SIEM** cruzando logs de identidade e de nuvem. Atenção: 198.51.100.42 é faixa de documentação, usada aqui como exemplo.

5. Risco concreto: bloquear um IP compartilhado — o gateway de saída de um parceiro, um CDN ou o próprio IP de saída da VPN corporativa — derrubando serviço legítimo para muita gente (falso positivo caro). Salvaguardas possíveis: manter uma **allowlist** de IPs críticos e de infraestrutura conhecida; exigir aprovação humana para bloqueios de faixa ou de destinos de alta criticidade; aplicar bloqueio com validade temporária (por exemplo 24 horas) e revisão; e restringir a automação total aos casos em que o custo do falso positivo é baixo.

</details>


## Fluxo de investigação ponta a ponta: um alerta real, sete ferramentas

Imagine um detetive que recebe uma denúncia anônima: "vi um homem estranho saindo do prédio às 14h". Sozinha, a denúncia não prova nada. O detetive então cruza fontes: a câmera da portaria, o registro de visitantes, o extrato do cartão de acesso, a placa do carro no estacionamento. Cada fonte confirma ou derruba a anterior. Uma investigação de SOC (Security Operations Center, ou Centro de Operações de Segurança) funciona exatamente assim: o alerta é a denúncia, e as ferramentas são as câmeras.

Vamos seguir um caso completo, do começo ao fim. Cenário fictício: estação de trabalho `WKS-FIN-041` (IP `10.10.20.41`), usuária `maria.costa`, domínio `corp.local`.

### Etapa 1 — O alerta do EDR: processo suspeito

O EDR (Endpoint Detection and Response, ferramenta de detecção e resposta no equipamento do usuário) dispara: "Office application spawning script interpreter".

```kql
// Defender / Sentinel — KQL
DeviceProcessEvents
| where Timestamp between (datetime(2026-09-02 13:55) .. datetime(2026-09-02 14:15))
| where DeviceName == "WKS-FIN-041"                    // limita a máquina do alerta
| where InitiatingProcessFileName in ("WINWORD.EXE","EXCEL.EXE")  // processo pai = Office
| where FileName in~ ("powershell.exe","wscript.exe","cmd.exe")   // filho = interpretador
| project Timestamp, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

**Evidência:** `WINWORD.EXE` (PID 4120) criou `powershell.exe` (PID 6688) às 14:02:11, sob a conta `maria.costa`.

### Etapa 2 — A árvore de processos

Um documento do Word abrindo o PowerShell nunca é comportamento normal de escritório. O Sysmon (agente gratuito da Microsoft que registra atividade detalhada do sistema) confirma a linhagem com o EventID 1 (criação de processo):

```
<Event><System><EventID>1</EventID></System>
 UtcTime: 2026-09-02 14:02:11.442
 ProcessId: 6688
 Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 User: CORP\maria.costa
 ParentProcessId: 4120
 ParentImage: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
 IntegrityLevel: Medium
</Event>
```

<details><summary>Ver legenda</summary>

| Campo | Significado | Por que importa |
|---|---|---|
| `ParentImage` | quem criou o processo | Office criando shell = anomalia clássica |
| `IntegrityLevel` | nível de privilégio | `Medium` = usuário comum, ainda sem escalação |
| `User` | conta que executou | define o escopo do incidente |

</details>

Isso mapeia para **T1566.001 (Spearphishing Attachment)** e **T1059.001 (PowerShell)** no MITRE ATT&CK.

### Etapa 3 — A conexão de rede do processo

Sysmon EventID 3 (conexão de rede) amarra o processo ao tráfego:

```
EventID: 3  UtcTime: 2026-09-02 14:02:19.108
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ProcessId: 6688  User: CORP\maria.costa
Protocol: tcp  Initiated: true
SourceIp: 10.10.20.41  SourcePort: 51204
DestinationIp: 203.0.113.77  DestinationPort: 443
DestinationHostname: cdn-update.example.com
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `EventID` | `3` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não. `3` = Sysmon **Network Connect** |
| `UtcTime` | `2026-09-02 14:02:19.108` | Instante do evento **em UTC**, o que dispensa converter fuso ao correlacionar |
| `Image` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | Caminho do executável (nomenclatura do Sysmon) |
| `ProcessId` | `6688` | PID do processo |
| `User` | `CORP\maria.costa` | Conta sob a qual o processo corre |
| `Protocol` | `tcp` | Protocolo de transporte da conexão |
| `Initiated` | `true` | `true` quando a conexão **partiu** desta máquina |
| `SourceIp` | `10.10.20.41` | IP de origem da conexão |
| `SourcePort` | `51204` | Porta de origem |
| `DestinationIp` | `203.0.113.77` | IP de destino da conexão |
| `DestinationPort` | `443` | Porta de destino |
| `DestinationHostname` | `cdn-update.example.com` | Nome do host de destino, quando o Sysmon consegue resolvê-lo |

</details>

O PowerShell abriu conexão HTTPS para um host externo oito segundos após nascer.

### Etapa 4 — Pivotar para o SIEM: a consulta DNS

O SIEM (Security Information and Event Management, plataforma que junta os logs de todas as ferramentas) permite perguntar: quem resolveu esse nome, e quando?

```
# Splunk — SPL
index=network sourcetype=zeek:dns query="cdn-update.example.com"
| eval hora=strftime(_time,"%H:%M:%S")                 # formata o horário
| stats count min(_time) as primeira by id.orig_h, query, answers
| sort primeira                                        # primeira máquina a resolver
```

```
# zeek dns.log
ts=1756821730.981 uid=CwT4x2 id.orig_h=10.10.20.41 id.resp_h=10.10.0.53
query=cdn-update.example.com qtype_name=A rcode_name=NOERROR
answers=203.0.113.77 TTLs=60.000000
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `ts` | `1756821730.981` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos |
| `uid` | `CwT4x2` | Identificador único da conexão |
| `id.orig_h` | `10.10.20.41` | Quem perguntou — **a única máquina da rede que resolveu este domínio**, e é isso que a torna o paciente zero |
| `id.resp_h` | `10.10.0.53` | O resolvedor interno que atendeu |
| `query` | `cdn-update.example.com` | O nome consultado |
| `qtype_name` | `A` | Registro de endereço IPv4 |
| `rcode_name` | `NOERROR` | Resolveu com sucesso |
| `answers` | `203.0.113.77` | O IP devolvido — é por ele que se procura no `conn.log` quem mais falou com esse destino |
| `TTLs` | `60.000000` | Validade em cache, em segundos. **TTL de 60 s é típico de infraestrutura descartável**, feita para trocar de IP rápido |

</details>

**Evidência:** apenas `10.10.20.41` resolveu o domínio, TTL (Time To Live, tempo de vida do registro em cache) de 60 segundos — típico de infraestrutura descartável.

### Etapa 5 — O proxy: onde estava o download

```
# Squid access.log
1756821612.004  318 10.10.20.41 TCP_MISS/200 184320 GET
http://files.example.com/invoice_0902.doc - HIER_DIRECT/198.51.100.44 application/msword
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| *timestamp* | `1756821612.004` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos — **dez minutos antes do alerta**, e é isso que faz deste registro a origem da cadeia |
| duração | `318` | Milissegundos para atender |
| cliente | `10.10.20.41` | A estação — a mesma que resolveu o domínio no `dns.log` da etapa anterior |
| resultado/status | `TCP_MISS/200` | Buscou na origem e recebeu 200 OK: o download foi concluído |
| bytes | `184320` | 184 KB entregues |
| método | `GET` | Pedido de leitura |
| URL | `http://files.example.com/invoice_0902.doc` | O arquivo baixado. Nome de fatura é o engodo mais comum em phishing |
| usuário | `-` | Sem autenticação no proxy nesse pedido |
| hierarquia/destino | `HIER_DIRECT/198.51.100.44` | O IP de onde veio o documento |
| tipo de conteúdo | `application/msword` | MIME de documento Word — o que permite macro |

</details>

**Evidência:** dez minutos antes do alerta, a mesma máquina baixou `invoice_0902.doc` (184 KB, código 200 = sucesso). Achamos a origem: um anexo/download de fatura falsa.

### Etapa 6 — O firewall: o destino externo

```
# Palo Alto TRAFFIC (CSV)
2026/09/02 14:02:19,013201001234,TRAFFIC,end,10.10.20.41,203.0.113.77,
Trust,Untrust,ethernet1/2,ethernet1/1,rule-outbound-web,maria.costa,
ssl,443,51204,allow,1892,742,1150,14,3
```

<details><summary>Ver legenda</summary>

| Posição no exemplo | Campo | Valor | O que significa |
|---|---|---|---|
| 1 | Receive Time | `2026/09/02 14:02:19` | Quando o firewall registrou |
| 2 | Serial Number | `013201001234` | Qual equipamento gerou |
| 3 / 4 | Type / Subtype | `TRAFFIC` / `end` | Log de sessão, no fim |
| 5 / 6 | Source / Destination Address | `10.10.20.41` / `203.0.113.77` | **A mesma origem e o mesmo destino das etapas anteriores** — é aqui que a cadeia fecha: DNS resolveu, proxy baixou, firewall confirma para onde |
| 7 / 8 | Source / Destination Zone | `Trust` / `Untrust` | O sentido do tráfego |
| 9 / 10 | Inbound / Outbound Interface | `ethernet1/2` / `ethernet1/1` | Interfaces de entrada e saída |
| 11 | Rule Name | `rule-outbound-web` | A regra que permitiu a saída |
| 12 | Source User | `maria.costa` | Usuário resolvido pelo User-ID |
| 13 | Application | `ssl` | App-ID identificou TLS |
| 14 / 15 | Destination / Source Port | `443` / `51204` | **Repare na ordem invertida**: neste recorte a porta de destino vem antes da de origem |
| 16 | Action | `allow` | O veredito |
| 17 | Bytes | `1892` | Total nos dois sentidos |
| 18 / 19 | Bytes Sent / Received | `742` / `1150` | Volume em cada direção — pouquíssimo tráfego, compatível com um beacon |
| 20 / 21 | Packets Sent / Received | `14` / `3` | Pacotes em cada direção |
| — | — | — | **Recorte de 21 campos**, com ordem própria; o formato completo tem mais de 46 |

</details>

Campos: origem, destino, zonas, regra aplicada (`rule-outbound-web`), usuário, aplicação (`ssl`), ação (`allow`), bytes enviados/recebidos. **1150 bytes enviados e 742 recebidos, em 14 pacotes** — sessão curta, padrão de *beacon* (sinal periódico de C2, Command and Control, servidor de comando do atacante). Técnica **T1071.001**.

### Etapa 7 — O AD e o usuário

```
# Windows Security 4624 — logon bem-sucedido
EventID=4624  Account Name: maria.costa  Logon Type: 2 (interativo)
Workstation: WKS-FIN-041  Source Network Address: 10.10.20.41  Time: 08:12:04
# Windows Security 4768 — TGT Kerberos solicitado
EventID=4768  Account Name: maria.costa  Ticket Encryption Type: 0x12  Result Code: 0x0
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `EventID` | `4624` / `4768` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não. `4624` = logon **bem-sucedido**; `4768` = **TGT** do Kerberos pedido — nasce no controlador de domínio |
| `Account Name` | `maria.costa` | A conta envolvida. Terminada em `$` é **conta de computador**, não de pessoa |
| `Logon Type` | `2 (interativo)` | **Como a sessão foi iniciada.** |
| `Workstation` | `WKS-FIN-041` | Nome declarado pela máquina de origem |
| `Source Network Address` | `10.10.20.41  Time: 08:12:04` | **IP de origem.** Vazio ou `-` significa que a sessão foi local, e `::1`/`127.0.0.1` que veio da própria máquina |
| `Ticket Encryption Type` | `0x12` | **Cifra do ticket.** `0x12` = **AES256** — o normal num domínio moderno |
| `Result Code` | `0x0` | **Código de resultado do Kerberos.** `0x0` = sucesso |

</details>

Nenhum 4625 (falha de logon), nenhum 4769 anômalo para outros serviços, nenhum logon tipo 3 (rede) partindo da estação para outros servidores. **Conclusão: a conta não foi usada para movimentação lateral ainda.**

### Conclusão e contenção

Verdadeiro positivo, estágio inicial de comprometimento. Ações: isolar `WKS-FIN-041` pela rede via EDR, bloquear `cdn-update.example.com` e `203.0.113.77` no firewall e no proxy, forçar redefinição de senha de `maria.costa`, buscar o mesmo hash do documento em toda a frota e escalar para N2.

**Erro comum de analista júnior:** fechar o alerta como falso positivo porque "o antivírus não detectou nada" e o firewall marcou `allow`. `allow` significa apenas que a política permitiu — não que o tráfego é legítimo.

## Níveis do SOC e quem faz o quê

| Função | Responsabilidade principal | Fim do trabalho |
|---|---|---|
| N1 (triagem) | receber a fila, classificar, enriquecer, escalar | decide: falso positivo ou escala |
| N2 (análise) | investigação profunda, correlação multi-fonte, escopo | determina alcance e causa |
| N3 / forense | memória, disco, engenharia reversa, atribuição | reconstrói o ataque inteiro |
| Threat hunter | busca hipótese sem alerta prévio | gera novas detecções |
| Engenheiro de detecção | escreve e afina regras, reduz ruído | melhora a fila do N1 |
| Resposta a incidente (IR) | comanda contenção, comunicação, recuperação | encerra o incidente |

### Métricas e SLA

- **Fila**: alertas aguardando triagem. Fila crescendo = detecção ruidosa ou equipe subdimensionada.
- **Severidade**: crítica/alta/média/baixa. Define a ordem de atendimento.
- **SLA de triagem** típico: crítica em 15 minutos, alta em 30, média em 4 horas, baixa em 24 horas.
- **MTTD** (Mean Time To Detect, tempo médio até detectar): do primeiro evento malicioso ao alerta.
- **MTTR** (Mean Time To Respond, tempo médio até responder): do alerta à contenção efetiva.

### Monitoramento versus caçada

Monitoramento é reativo: a ferramenta avisa, você responde. Caçada (*threat hunting*) é proativa: você parte de uma hipótese ("existe PowerShell fazendo conexões de 60 em 60 segundos que ninguém alertou?") e procura sem alerta nenhum. O N1 vive no monitoramento, mas boas observações do N1 viram hipóteses de caçada.

## Frameworks que o N1 usa de verdade

### MITRE ATT&CK

**Tática** é o *porquê* (o objetivo: Acesso Inicial, Execução, Persistência, Movimento Lateral, Exfiltração). **Técnica** é o *como* (T1059 Command and Scripting Interpreter; T1003 OS Credential Dumping). Na triagem, o N1 usa a matriz para responder: em que fase estamos? Um alerta de Acesso Inicial isolado é grave; o mesmo alerta somado a um de Movimento Lateral é incidente.

### Cyber Kill Chain

Sete fases lineares: reconhecimento, armamento, entrega, exploração, instalação, comando e controle, ações sobre objetivos. Serve para explicar a narrativa e para saber quanto antes na cadeia você conseguiu quebrar o ataque. No caso acima, quebramos em "comando e controle".

### Diamond Model

Quatro vértices: **adversário**, **infraestrutura**, **capacidade** e **vítima**. No nosso caso: infraestrutura = `203.0.113.77`; capacidade = documento com macro; vítima = `maria.costa`. Girar o diamante ("que outras vítimas falaram com essa infraestrutura?") é o que transforma um alerta em uma varredura da frota.

### NIST SP 800-61 — ciclo de resposta

1. **Preparação** — logs, playbooks, contatos, ferramentas prontas antes do incidente.
2. **Detecção e análise** — exatamente as sete etapas que fizemos acima.
3. **Contenção, erradicação e recuperação** — isolar, remover, restaurar e validar.
4. **Lições aprendidas** — o que faltou de log? Que regra nova nasce disso?

### Exercícios — Fluxo de investigação ponta a ponta, níveis do SOC e frameworks

1. O firewall registrou `allow` para `10.10.20.41 → 203.0.113.77:443`. O analista fechou o alerta como falso positivo. Ele está certo? Justifique.
2. Um alerta crítico entrou às 09:00 e foi triado às 09:40. O SLA de crítica é 15 minutos. Qual é o atraso e o que isso indica sobre a operação?
3. O evento malicioso ocorreu às 14:02, o alerta apareceu às 14:20 e a máquina foi isolada às 15:05. Calcule MTTD e MTTR.
4. Você vê 40 eventos 4625 seguidos de um 4624 para `svc_backup`, vindos de `10.10.30.15`. Qual tática e técnica do ATT&CK, e qual o próximo passo?
5. No caso investigado, em que fase da Cyber Kill Chain o ataque foi interrompido?

<details><summary>Ver gabarito</summary>

1. **Errado.** `allow` descreve a decisão da política de firewall, não a legitimidade do tráfego. A regra `rule-outbound-web` libera HTTPS de saída para todo mundo; o que torna o evento suspeito é a origem do processo (PowerShell filho do Word), o domínio recém-criado com TTL de 60s e o volume baixo e regular de bytes, típico de beacon.
2. Atraso de **25 minutos** além do SLA. Indica fila saturada, falta de priorização automática por severidade ou equipe subdimensionada no turno. Vale checar quantos alertas de baixa severidade foram triados antes do crítico.
3. **MTTD = 18 minutos** (14:02 → 14:20, evento até alerta). **MTTR = 45 minutos** (14:20 → 15:05, alerta até contenção). Tempo total de exposição: 63 minutos.
4. Tática **Credential Access**, técnica **T1110 (Brute Force)** — 40 falhas (4625) seguidas de sucesso (4624) é tentativa de adivinhação bem-sucedida. Agravante: `svc_backup` é conta de serviço, que não deveria fazer logon interativo. Próximo passo: verificar o `Logon Type` do 4624, listar tudo que a conta acessou depois do sucesso (4769 por serviço), e escalar imediatamente para N2 — conta de serviço comprometida costuma virar movimento lateral em minutos.
5. Fase **6, comando e controle (C2)**. A entrega (download da fatura falsa), a exploração (macro) e a instalação já haviam ocorrido; quebramos a cadeia antes de "ações sobre objetivos" (exfiltração ou ransomware).

</details>

## Mini-laboratório — Segurança de rede e investigação ponta a ponta

**Pré-requisitos:** VirtualBox com uma máquina Linux (Ubuntu Server é suficiente), Wireshark e tcpdump instalados, acesso à internet. Tudo gratuito.

1. **Preparar a captura.** Na VM Linux: `sudo tcpdump -i any -n -w /tmp/lab13.pcap` e deixe rodando.
2. **Gerar tráfego DNS e HTTP legítimos.** Em outro terminal: `dig www.example.com` e `curl -s http://example.com > /dev/null`.
   *Observe:* consulta A e resposta com rcode NOERROR.
3. **Gerar um padrão de beacon inofensivo.** `for i in $(seq 1 10); do curl -s http://example.com/ping > /dev/null; sleep 60; done`
   *Observe:* dez conexões de tamanho quase idêntico, espaçadas regularmente. Esse é o padrão que denuncia C2.
4. **Encerrar a captura** com Ctrl+C e abrir o arquivo no Wireshark.
5. **Aplicar os filtros de display:** `dns` para ver as resoluções; `http.request` para ver os GET; `tcp.flags.syn==1 && tcp.flags.ack==0` para contar tentativas de conexão.
6. **Medir a regularidade.** Em Statistics → Conversations, aba TCP, compare a coluna Duration e Bytes entre as conexões.

**Critério de sucesso:** você consegue apontar, apenas olhando o intervalo entre conexões e a semelhança de bytes, quais sessões parecem automatizadas — sem nenhum alerta de ferramenta paga.

## O que um SOC Level 1 realmente precisa saber

- 🟢 Alerta isolado não é conclusão: confirme com pelo menos duas fontes independentes antes de fechar.
- 🟢 `allow` no firewall significa política permissiva, nunca tráfego confiável.
- 🟢 Office criando `powershell.exe`, `wscript.exe` ou `cmd.exe` é anomalia até prova em contrário (T1059).
- 🟢 EventIDs de cabeceira: 4624 (logon ok), 4625 (falha), 4768/4769 (Kerberos), 4688 e Sysmon 1 (processo), Sysmon 3 (rede), Sysmon 22 (DNS).
- 🟢 Sempre registre no chamado a consulta usada e a evidência obtida, não apenas a conclusão.
- 🟡 Beacon se reconhece por regularidade de intervalo e semelhança de bytes, não por volume alto.
- 🟡 Domínio novo com TTL baixo e primeira resolução recente na empresa é indicador forte.
- 🟡 Saiba a diferença entre IDS, IPS e NDR e onde cada um enxerga — assunto tratado antes neste módulo.
- 🟡 Respeite a severidade e o SLA da fila: crítica primeiro, sempre.
- 🔴 Girar o Diamond Model (buscar outras vítimas da mesma infraestrutura) transforma um alerta em varredura de frota.
- 🔴 Caçada parte de hipótese sem alerta; comece propondo hipóteses a partir do que você viu na triagem.
- 🔴 Contenção mal feita destrói evidência: isole a rede, não desligue a máquina, sem orientação do IR.

## Resumo em 10 linhas

1. Segurança de rede no SOC é cruzar fontes, não confiar em uma ferramenta só.
2. O EDR mostra o processo; o Sysmon mostra a linhagem e a conexão.
3. O SIEM é o ponto de pivô que amarra endpoint, DNS, proxy, firewall e AD.
4. DNS revela a intenção; proxy revela a origem do download; firewall revela o destino e o volume.
5. O AD responde se a conta já foi usada para se mover lateralmente.
6. Beacon se identifica por padrão temporal e de tamanho, não por tráfego pesado.
7. N1 tria e escala; N2 aprofunda; N3 faz forense; hunter e engenheiro de detecção alimentam a fila.
8. Fila, severidade, SLA, MTTD e MTTR medem a saúde da operação.
9. ATT&CK dá tática e técnica; Kill Chain dá a narrativa; Diamond Model expande o escopo.
10. NIST 800-61 fecha o ciclo: preparar, detectar, conter, aprender — e a lição vira regra nova.



---
