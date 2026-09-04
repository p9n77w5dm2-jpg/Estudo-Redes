# Módulo 1 — Fundamentos de Redes

## Por que este módulo importa para o SOC

Todo alerta que chega ao Centro de Operações de Segurança (SOC, do inglês *Security Operations Center*) nasce de alguma coisa que trafegou por uma rede. Se você não entende quem é o cliente, quem é o servidor, o que é normal em uma rede local e o que é normal em um enlace de longa distância, você vai tratar comportamento legítimo como ataque e ataque como ruído. Este módulo constrói a base para ler qualquer log de firewall, proxy ou sensor de rede com segurança.

Índice do módulo:

- Rede, Internet/Intranet, LAN, WAN, MAN, WLAN
- VPN, VLAN, DMZ, segmentação e topologias
- Cenários práticos: escritório, home office e cloud

## O que é uma rede

**O que é.** Imagine um prédio de escritórios com centenas de salas. Cada sala tem um número. Para mandar um documento da sala 305 para a sala 712, você escreve o número da sala de destino no envelope e entrega ao contínuo, que conhece o caminho pelos corredores. Uma rede de computadores é exatamente isso: um conjunto de máquinas que trocam envelopes (pacotes) endereçados.

**Como funciona.** Quatro elementos aparecem sempre:

| Elemento | Analogia do prédio | Definição técnica |
|---|---|---|
| **Host** | A sala com uma pessoa dentro | Máquina com endereço IP que origina ou consome dados (notebook, servidor, celular) |
| **Nó** | O contínuo, o elevador | Qualquer ponto da rede, incluindo equipamentos que só encaminham (switch, roteador) |
| **Meio** | O corredor, o elevador, o correio | O caminho físico: cabo de cobre, fibra óptica, rádio (Wi-Fi) |
| **Protocolo** | A regra "escreva o número da sala no canto superior direito" | Conjunto de regras que define formato e ordem das mensagens (IP, TCP, HTTP, DNS) |

Todo host é um nó, mas nem todo nó é um host: um switch encaminha e não consome o conteúdo.

### Cliente-servidor vs. P2P

No modelo **cliente-servidor**, um lado pede e o outro atende: o notebook de `jsilva` (10.10.20.45) abre uma conexão para o servidor de arquivos `fs01.corp.local` (10.10.5.10). É o modelo dominante no ambiente corporativo — e é o que faz um SOC conseguir dizer "este IP é servidor, aquele é estação".

No modelo **P2P** (*peer-to-peer*, ponto a ponto), cada máquina é cliente e servidor ao mesmo tempo. BitTorrent é P2P legítimo; muitos malwares também usam P2P para controle. Numa rede corporativa, uma estação de trabalho que passa a receber conexões de entrada de dezenas de IPs externos é um forte indício de comprometimento.

### Largura de banda vs. latência

**Largura de banda** é a quantidade de dados por segundo (a largura do corredor: quantas pessoas passam lado a lado). **Latência** é o tempo de ida e volta (quanto tempo o contínuo leva para chegar lá). São independentes: um enlace de satélite pode ter 100 Mbps de banda e 600 ms de latência. Para o SOC isso importa porque exfiltração aparece como volume anormal (banda) e *beaconing* de malware aparece como conexões curtas em intervalo regular (padrão temporal, não volume).

**Como aparece nos logs.** Palo Alto, log TRAFFIC em CSV — sessão normal de navegação:

```
1,2026/09/03 09:14:22,001801011111,TRAFFIC,end,2561,2026/09/03 09:14:22,10.10.20.45,203.0.113.44,192.0.2.10,203.0.113.44,Regra-Saida-Usuarios,jsilva,,ssl,vsys1,Confianca,Internet,ethernet1/2,ethernet1/1,Log-Padrao,2026/09/03 09:14:20,88431,1,51422,443,41022,443,0x400053,tcp,allow,18422,6114,12308,42,2026/09/03 09:13:55,27,computer-and-internet-info,0,72910,0x0,BR,US,0,24,18
```

Campos-chave: `10.10.20.45` é o IP de origem (host interno), `203.0.113.44` o destino, `jsilva` o usuário resolvido, `51422` a porta de origem efêmera, `443` a porta de destino, `allow` a ação, `18422` os bytes totais, `27` a duração em segundos e `42` o número de pacotes.

**O que o SOC N1 observa.** Normal: portas de origem altas e variadas, destino 443, duração compatível com navegação. Suspeito: mesma origem e mesmo destino repetindo sessões de 2 a 3 segundos a cada 60 segundos exatos, com poucos bytes — assinatura clássica de *beaconing* de canal de comando e controle (MITRE ATT&CK T1071 — Application Layer Protocol).

**Erro comum de analista júnior.** Achar que "poucos bytes = irrelevante". Beaconing é justamente de baixo volume; o que denuncia é a regularidade, não o tamanho.

## Internet, Intranet e Extranet

**O que é.** A Internet é a rede pública mundial — o serviço postal do país inteiro. A **Intranet** é a rede interna da empresa, com recursos que só funcionam de dentro (o correio interno do prédio). A **Extranet** é um pedaço da intranet aberto de forma controlada para parceiros — a sala de reunião do térreo, onde o fornecedor entra com crachá de visitante.

| Rede | Alcance | Exemplo fictício | Controle de acesso típico |
|---|---|---|---|
| Internet | Público mundial | `www.empresa-exemplo.com.br` | Nenhum ou autenticação da aplicação |
| Intranet | Só colaboradores | `portal.corp.local` | Domínio, autenticação Kerberos |
| Extranet | Parceiros externos | `parceiros.empresa-exemplo.com.br` | VPN, certificado, MFA |

**Como aparece nos logs.** Proxy Squid, `access.log`, acesso interno e acesso externo:

```
1756890912.431   214 10.10.20.45 TCP_MISS/200 8421 GET http://portal.corp.local/rh/ferias - HIER_DIRECT/10.10.5.30 text/html
1756890975.882   642 10.10.20.45 TCP_DENIED/403 3901 CONNECT arquivos-livres.example.com:443 jsilva HIER_NONE/- text/html
```

Campos: *timestamp* Unix, duração em milissegundos, IP do cliente, código de resultado/status HTTP, bytes, método, URL, usuário e destino. `TCP_DENIED/403` significa que a política do proxy bloqueou.

**O que o SOC N1 observa.** Normal: usuário interno acessando intranet e sites de categoria de negócio. Suspeito: host interno consultando recursos da extranet fora do horário e a partir de um IP de origem que não pertence à faixa daquele escritório.

**Erro comum de analista júnior.** Tratar `TCP_DENIED` como incidente encerrado. O bloqueio prova que a política funcionou, não que a máquina está limpa: se houve 200 tentativas em 5 minutos, algo automatizado está rodando no *endpoint*.

## LAN — Local Area Network

**O que é.** LAN (*Local Area Network*, rede local) é a rede de um andar, de um prédio ou de um escritório — tudo que está sob o mesmo teto e sob a mesma administração.

**Como funciona.** O equipamento central é o **switch**, que trabalha com endereços MAC (*Media Access Control*, o endereço físico gravado na placa de rede). O switch aprende em qual porta está cada MAC e encaminha o quadro só para lá. Quando o destino é desconhecido ou é um *broadcast* (endereço de difusão `ff:ff:ff:ff:ff:ff`), o quadro vai para todas as portas. O conjunto de portas que recebe esse broadcast é o **domínio de broadcast**. Protocolos como ARP (*Address Resolution Protocol*) e DHCP (*Dynamic Host Configuration Protocol*) dependem dele.

**Exemplo prático.** Escritório de São Paulo: faixa 10.10.20.0/24, gateway 10.10.20.1, 254 hosts possíveis, um único domínio de broadcast. `maria.costa` está em 10.10.20.77.

**Como aparece nos logs.** Zeek, `conn.log` (formato tabulado):

```
#fields ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state
1756891044.118	CmXQ2p1a9Kz	10.10.20.77	49212	10.10.5.10	445	tcp	smb	3.221	4820	19044	SF
1756891050.902	CqW8f3Lb2Rt	10.10.20.77	49301	10.10.20.9	445	tcp	smb	0.118	0	0	S0
```

Campos: `ts` é o tempo, `uid` o identificador único da conexão, `id.orig_h`/`id.orig_p` origem e porta, `id.resp_h`/`id.resp_p` destino e porta, `conn_state` o desfecho — `SF` é conexão completa e encerrada normalmente; `S0` é SYN enviado sem resposta alguma.

**O que o SOC N1 observa.** Normal: uma estação falando SMB (porta 445) com o servidor de arquivos. Suspeito: a mesma estação abrindo `S0` na porta 445 contra dezenas de IPs sequenciais da própria LAN — varredura lateral (T1046 — Network Service Discovery). Ferramentas como Impacket e PsExec deixam esse rastro de muitas conexões 445 partindo de um host que normalmente só é cliente.

**Erro comum de analista júnior.** Ignorar tráfego interno porque "não passou pelo firewall de borda". A maior parte do movimento lateral nunca cruza a borda.

## WAN — Wide Area Network

**O que é.** WAN (*Wide Area Network*, rede de longa distância) liga sites geograficamente separados — a matriz no Brasil e a filial em Portugal. Não é você quem passa o cabo: você contrata uma **operadora**.

**Como funciona.** Três tecnologias dominam:

| Tecnologia | O que é | Característica para o SOC |
|---|---|---|
| **MPLS** (*Multiprotocol Label Switching*) | Circuito privado da operadora, com rótulos em vez de roteamento IP puro | Tráfego não passa pela Internet pública; latência previsível; caro |
| **SD-WAN** (*Software-Defined WAN*) | Camada de software que usa vários links (fibra, banda larga, 4G/5G) e escolhe o melhor por aplicação | Um mesmo fluxo pode sair por links e IPs públicos diferentes — cuidado ao correlacionar por IP |
| **Link de Internet dedicado** | Banda larga empresarial com IP fixo | Exposto à Internet; exige firewall e IPS na borda |

**Exemplo prático.** A matriz (10.10.0.0/16) e a filial (172.16.30.0/24) se enxergam por MPLS. Um usuário da filial acessa o ERP na matriz.

**Como aparece nos logs.** FortiGate, formato chave=valor:

```
date=2026-09-03 time=10:02:41 devname="FGT-Matriz" devid="FGT60F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=172.16.30.51 srcport=52133 srcintf="wan2-mpls" dstip=10.10.5.60 dstport=1433 dstintf="port3" action="accept" policyid=42 service="MS-SQL" proto=6 duration=118 sentbyte=88410 rcvdbyte=1204553 user="maria.costa"
```

Campos: `srcintf` é a interface de entrada (aqui o enlace MPLS), `dstport=1433` é SQL Server, `policyid` a regra que permitiu, `sentbyte`/`rcvdbyte` o volume em cada direção.

**O que o SOC N1 observa.** Normal: filial consultando o banco pelo enlace MPLS dentro do horário comercial. Suspeito: `rcvdbyte` na casa de gigabytes numa madrugada, indicando cópia em massa de base de dados (T1030 — Data Transfer Size Limits, quando fatiado).

**Erro comum de analista júnior.** Assumir que tráfego vindo por MPLS é "interno e confiável". A filial pode estar comprometida; o enlace privado só garante privacidade do transporte, não a idoneidade da origem.

## MAN — Metropolitan Area Network

**O que é.** MAN (*Metropolitan Area Network*, rede metropolitana) fica entre a LAN e a WAN: cobre uma cidade ou região metropolitana. Típico de empresas com vários prédios na mesma capital, universidades com campi espalhados e prefeituras.

**Como funciona.** Normalmente é fibra óptica de uma operadora local entregando alta banda e baixa latência entre unidades da mesma cidade — funciona quase como uma LAN estendida, o que a torna útil e perigosa ao mesmo tempo: se você trata a MAN como zona confiável, um prédio comprometido alcança todos os outros. Recomendação de arquitetura: firewall entre unidades, mesmo na MAN.

**Exemplo prático.** Sede (10.10.0.0/16) e Centro de Distribuição (10.20.0.0/16) na mesma cidade, ligados por fibra metropolitana. Cisco ASA registrando a construção da sessão:

```
%ASA-6-302013: Built inbound TCP connection 884213 for man-cd:10.20.4.15/50122 (10.20.4.15/50122) to inside:10.10.5.10/445 (10.10.5.10/445)
```

Leitura: `%ASA-6` é severidade 6 (informativo), `302013` é o *message ID* de construção de conexão TCP, `man-cd` é o nome da interface do enlace metropolitano.

**O que o SOC N1 observa.** Normal: poucos servidores do CD falando com serviços específicos da sede. Suspeito: estações comuns do CD abrindo 445, 3389 (RDP) ou 5985 (WinRM) contra a sede.

**Erro comum de analista júnior.** Confundir `%ASA-6-302013` (conexão construída) com `%ASA-6-302014` (conexão encerrada) e contar a mesma sessão duas vezes no relatório.

## WLAN — Wireless LAN

**O que é.** WLAN (*Wireless Local Area Network*, rede local sem fio) é a LAN entregue por rádio — o Wi-Fi. O padrão é a família IEEE 802.11 (802.11n, 802.11ac, 802.11ax/Wi-Fi 6).

**Como funciona.** O **AP** (*Access Point*, ponto de acesso) transmite um **SSID** (*Service Set Identifier*), que é o nome da rede que aparece no celular. O cliente associa-se ao AP e autentica. A segurança é dada pelo protocolo de criptografia:

| Protocolo | Situação | Observação para o SOC |
|---|---|---|
| WEP | Obsoleto e quebrado | Se aparecer, é achado de auditoria imediato |
| WPA2-PSK | Senha compartilhada | Todo mundo com a mesma senha; sem identidade individual |
| WPA2-Enterprise | 802.1X com RADIUS | Autentica por usuário; log correlacionável |
| WPA3 | Atual, usa SAE | Resiste a ataque de dicionário offline |

### Riscos clássicos de Wi-Fi

- **Rogue AP** (ponto de acesso não autorizado): alguém liga um roteador próprio na tomada de rede da empresa, criando uma porta de entrada sem controle. MITRE T1200 (Hardware Additions).
- **Evil twin** (gêmeo maligno): um atacante cria um AP com o mesmo SSID corporativo, mas fora do controle da empresa, para capturar credenciais e sessões. É um caso de T1557 (Adversary-in-the-Middle).
- **Deauth** (desautenticação): quadros de gerência forçam o cliente a se desconectar, empurrando-o para o evil twin. Em WPA2 sem 802.11w (*Protected Management Frames*), esses quadros não são autenticados.

**Como aparece nos logs.** Controlador Wi-Fi enviando syslog RFC5424:

```
<134>1 2026-09-03T22:41:08.114Z wlc01.corp.local AireOS - AP-EVENT - Rogue AP 'CORP-WIFI' detected on channel 6 by AP-SP-3F-02, BSSID a4:5e:60:11:22:33, RSSI -41 dBm, classification: malicious, reason: same-SSID-unknown-BSSID
<134>1 2026-09-03T22:41:23.507Z wlc01.corp.local AireOS - CLIENT-EVENT - Deauthentication flood detected: 214 deauth frames in 10s targeting client 3c:22:fb:aa:bb:cc on AP-SP-3F-02
<134>1 2026-09-03T22:41:44.902Z wlc01.corp.local AireOS - AUTH-EVENT - Client maria.costa MAC 3c:22:fb:aa:bb:cc failed 802.1X authentication on SSID CORP-WIFI, EAP failure, retries=6
```

Campos: `<134>` é a prioridade syslog, `BSSID` é o MAC do rádio do AP (o SSID pode ser copiado, o BSSID legítimo é conhecido pelo inventário), `RSSI -41 dBm` indica sinal muito forte — ou seja, o rogue está fisicamente perto do prédio.

**O que o SOC N1 observa.** Normal: rogues classificados como *friendly* (Wi-Fi do vizinho, SSIDs de operadora). Suspeito: SSID corporativo com BSSID fora do inventário, seguido de rajada de *deauth* e falhas de 802.1X do mesmo cliente — a sequência inteira é o roteiro de um evil twin.

**Erro comum de analista júnior.** Fechar o alerta de rogue AP como falso positivo só porque "sempre aparecem rogues". Filtre pelo SSID da empresa: rogue com SSID próprio e BSSID desconhecido nunca é ruído.

### Consultas de apoio

SPL (Splunk), para encontrar rogue AP com SSID corporativo:

```spl
index=wireless sourcetype=cisco:wlc "Rogue AP"
| rex field=_raw "Rogue AP '(?<ssid>[^']+)'.*BSSID (?<bssid>[0-9a-f:]{17}).*classification: (?<classe>\w+)"
| search ssid="CORP-WIFI"
| lookup aps_autorizados.csv bssid OUTPUT status
| where isnull(status)
| stats count min(_time) as primeiro max(_time) as ultimo by bssid, classe
```

Linha a linha: filtra os eventos de rogue do controlador; extrai SSID, BSSID e classificação do texto bruto; mantém apenas o SSID da empresa; cruza com a lista de APs autorizados; guarda só os BSSIDs que não estão na lista; e resume por BSSID com primeira e última ocorrência.

KQL (Microsoft Sentinel), para detectar rajada de falhas de autenticação Wi-Fi:

```kql
Syslog
| where TimeGenerated > ago(24h)                       // janela de 24 horas
| where Computer == "wlc01.corp.local"                 // apenas o controlador Wi-Fi
| where SyslogMessage has "failed 802.1X"              // somente falhas de autenticação
| extend usuario = extract(@"Client (\S+) MAC", 1, SyslogMessage)   // extrai o usuário
| summarize falhas = count() by usuario, bin(TimeGenerated, 5m)     // agrupa em janelas de 5 min
| where falhas > 20                                    // limiar de rajada
| order by falhas desc                                 // maiores primeiro
```

### Exercícios — Rede, Internet/Intranet, LAN, WAN, MAN, WLAN

1. **Cálculo de escopo.** O escritório usa 10.10.20.0/24. Quantos endereços de host utilizáveis existem e qual é o endereço de broadcast dessa LAN? Quantos domínios de broadcast existem se toda a faixa estiver em uma única VLAN?
2. **Leitura de log.** No `conn.log` do Zeek acima, a segunda linha traz `conn_state=S0`, `orig_bytes=0` e `resp_bytes=0` para 10.10.20.9:445. O que esse desfecho indica e por que ele é mais interessante para o SOC do que a primeira linha, que foi `SF`?
3. **Verdadeiro ou falso positivo?** O controlador Wi-Fi gera "Rogue AP 'NET-VIZINHO-2G' detected, classification: friendly, RSSI -84 dBm". Isso é incidente? Justifique com dois critérios objetivos.
4. **Próximo passo da investigação.** O log do FortiGate mostra `srcip=172.16.30.51` da filial acessando `dstport=1433` na matriz às 03h12, com `rcvdbyte=6144000000`. Liste os três próximos passos, em ordem.
5. **Conceito aplicado.** Um usuário reclama que "a rede está lenta" ao usar um sistema hospedado no exterior, mas o teste de velocidade mostra 900 Mbps. Explique, usando banda e latência, o que provavelmente está acontecendo e qual campo de log ajuda a confirmar.

<details><summary>Ver gabarito</summary>

**1.** Um /24 tem 256 endereços no total; descontando o endereço de rede (10.10.20.0) e o de broadcast (10.10.20.255), sobram **254 hosts utilizáveis**. O endereço de broadcast é **10.10.20.255**. Com toda a faixa em uma única VLAN, existe **um único domínio de broadcast** — o que significa que ARP e DHCP de qualquer host alcançam todos os outros 253, e é exatamente por isso que segmentar (próximo trecho do módulo) reduz superfície de ataque.

**2.** `S0` significa que a origem enviou o SYN e **não houve nenhuma resposta** — nem SYN/ACK nem RST. Com zero bytes nos dois sentidos, não houve sessão. É mais interessante que a linha `SF` porque `SF` é uma conversa completa e esperada com o servidor de arquivos, enquanto `S0` repetido na porta 445 contra vários IPs da própria LAN é a assinatura de varredura de serviços (T1046) ou de tentativa de movimento lateral. O passo seguinte é contar quantos destinos distintos aquele host tentou na porta 445 na mesma janela de tempo.

**3.** **Falso positivo.** Dois critérios: (a) o SSID `NET-VIZINHO-2G` **não é** o SSID corporativo `CORP-WIFI`, então não há tentativa de personificar a rede da empresa; (b) o RSSI de **-84 dBm** é sinal muito fraco, compatível com um AP distante, fora do prédio — diferente dos -41 dBm do exemplo de evil twin. Some a isso a classificação `friendly` do próprio controlador. Documente e feche, mas mantenha a regra que alerta somente para SSID corporativo com BSSID fora do inventário.

**4.** Ordem recomendada: (a) **confirmar o volume e a linha de base** — 6,1 GB recebidos de um servidor SQL às 03h12 é normal para essa origem? Compare com os últimos 30 dias do mesmo `srcip`/`dstport`; (b) **identificar o processo e o usuário na estação de origem** com Sysmon Event ID 1 (criação de processo) e Event ID 3 (conexão de rede) no host 172.16.30.51, e verificar se houve logon anômalo com Windows Security 4624 (logon) e 4625 (falha de logon) nessa madrugada; (c) **acionar contenção e escalar para N2** — isolar 172.16.30.51, preservar evidência e verificar no banco quais tabelas foram lidas. Nunca comece pelo bloqueio cego do IP sem preservar o contexto, mas também não demore: exfiltração é irreversível.

**5.** Banda e latência são grandezas independentes. O teste de 900 Mbps mede **largura de banda**; a lentidão percebida vem da **latência alta** (ida e volta longa até o servidor no exterior), que penaliza aplicações "conversadoras", com muitas requisições pequenas e sequenciais — cada uma paga o tempo de ida e volta. O campo de log que ajuda a confirmar é a **duração da sessão** (`duration` no Zeek, `duration` no FortiGate, `elapsed` no Palo Alto) comparada com os bytes transferidos: sessões longas movendo poucos bytes indicam latência, não saturação de banda. Se fosse saturação, você veria também descartes e sessões com bytes altos e throughput baixo no mesmo enlace, afetando todos os usuários daquele site — e não apenas um sistema.

</details>


## VPN, VLAN, DMZ, segmentação e topologias

Nas seções anteriores vimos o que é uma rede e os tipos por alcance (LAN, WAN, MAN, WLAN). Agora vamos ao que realmente aparece no dia a dia do SOC: como a rede é **dividida por dentro**. Um analista Nível 1 que não entende segmentação lê um log de firewall e não consegue responder à pergunta mais básica de todas: *"esse tráfego deveria existir?"*.

### VPN — o túnel privado dentro da rua pública

**O que é.** Imagine que você precisa mandar um documento sigiloso pelos Correios. Você não escreve num cartão postal: coloca dentro de um envelope lacrado e opaco. A VPN (*Virtual Private Network*, Rede Privada Virtual) é esse envelope lacrado dentro da Internet pública.

**Como funciona.** O computador do usuário cria um túnel cifrado até um concentrador VPN (o firewall da empresa, por exemplo). Tudo que passa dentro do túnel fica ilegível para quem estiver no meio do caminho — o Wi-Fi do aeroporto, o provedor, o vizinho. Ao sair do túnel, o usuário recebe um endereço IP interno da empresa e passa a "estar dentro" da rede corporativa.

**Exemplo prático.** A usuária `maria.costa`, de casa, com IP público `203.0.113.45`, conecta à VPN da `empresa-exemplo.com.br` e recebe o IP interno `10.20.30.55` do pool de VPN. A partir daí ela acessa o servidor de arquivos `10.10.5.20` como se estivesse no escritório.

**Como aparece nos logs.** Log de conexão VPN em FortiGate (formato chave=valor):

```
date=2026-09-03 time=08:14:22 devname="FGT-MATRIZ" devid="FG100F0000000001" logid="0101039947" type="event" subtype="vpn" level="notice" action="ssl-login-fail" user="maria.costa" remip=203.0.113.45 tunneltype="ssl-web" tunnelip=N/A group="VPN_Colaboradores" reason="sslvpn_login_permission_denied" msg="SSL user failed to logged in"
```

| Campo | Significado |
|---|---|
| `action` | Resultado: `ssl-login-fail`, `tunnel-up`, `tunnel-down` |
| `user` | Conta que tentou autenticar |
| `remip` | IP público de origem (de onde o usuário veio) |
| `tunnelip` | IP interno entregue ao usuário após o login |
| `reason` | Motivo da falha (senha, MFA, permissão de grupo) |

**O que o SOC N1 observa.** *Normal:* `maria.costa` conecta de um IP brasileiro, das 8h às 18h, com um ou dois `tunnel-up` por dia. *Suspeito:* dezenas de `ssl-login-fail` para usuários diferentes vindos do mesmo `remip` (password spraying, MITRE **T1110.003**); ou um `tunnel-up` bem-sucedido de um país onde a empresa não opera 20 minutos depois de um login no Brasil (viagem impossível, **T1078** — contas válidas).

**Erro comum de analista júnior.** Confundir o `remip` com o IP do atacante *dentro* da rede. Depois que o túnel sobe, todo o tráfego interno da Maria aparece com o `tunnelip` (`10.20.30.55`), não com `203.0.113.45`. Sem correlacionar os dois, você perde o rastro no meio da investigação. O detalhamento de protocolos e criptografia de VPN fica para o **Módulo 9**.

### VLAN — dividir o prédio sem quebrar parede

**O que é.** Um prédio com um único salão aberto: todo mundo ouve todo mundo. A VLAN (*Virtual Local Area Network*, Rede Local Virtual) constrói paredes lógicas nesse salão — sem obra, só configuração no switch.

**Como funciona.** O padrão **IEEE 802.1Q** insere uma etiqueta (*tag*) de 4 bytes no quadro Ethernet, contendo o **VLAN ID** (de 1 a 4094). Duas configurações de porta importam:

| Tipo de porta | Uso | Tag |
|---|---|---|
| **Access** | Onde se pluga o computador do usuário | Sai sem tag; o switch aplica a VLAN da porta |
| **Trunk** | Ligação entre switches ou para o firewall | Carrega várias VLANs, cada quadro com sua tag 802.1Q |

Cada VLAN é um **domínio de broadcast separado**: um ARP disparado na VLAN 20 não chega à VLAN 30. Para uma VLAN falar com outra, o tráfego precisa passar por um roteador ou firewall — e é exatamente aí que o SOC ganha visibilidade.

**Exemplo prático.** Na `empresa-exemplo.com.br`: VLAN 10 = Servidores (`10.10.0.0/16`), VLAN 20 = Estações (`10.20.0.0/16`), VLAN 30 = Câmeras e IoT (`192.168.30.0/24`), VLAN 99 = Gerência dos switches.

**VLAN hopping.** Ataque em que o invasor faz o quadro chegar a uma VLAN em que ele não deveria estar, explorando porta configurada com negociação automática de trunk ou usando dupla etiqueta 802.1Q (MITRE **T1599** — *Network Boundary Bridging*). Defesa: desligar negociação automática de trunk, não usar a VLAN 1, e definir a VLAN nativa do trunk como uma VLAN sem uso.

**Como aparece nos logs.** Palo Alto, log TRAFFIC (CSV) — repare nos campos de zona, que na prática espelham as VLANs:

```
1,2026/09/03 09:12:44,013201001234,TRAFFIC,end,2561,2026/09/03 09:12:44,10.20.14.87,10.10.5.20,,,Regra-Estacoes-Servidores,jsilva,,ms-ds-smb,vsys1,VLAN20-ESTACOES,VLAN10-SERVIDORES,ethernet1/2,ethernet1/3,Log-Padrao,2026/09/03 09:12:44,84512,1,51422,445,0,0,0x53,tcp,allow,18422,9210,9212,44
```

| Posição do campo | Nome | Valor no exemplo |
|---|---|---|
| 8 / 9 | IP origem / destino | `10.20.14.87` / `10.10.5.20` |
| 12 | Regra aplicada | `Regra-Estacoes-Servidores` |
| 13 | Usuário de origem | `jsilva` |
| 15 | Aplicação | `ms-ds-smb` |
| 17 / 18 | **Zona origem / destino** | `VLAN20-ESTACOES` / `VLAN10-SERVIDORES` |
| 25 / 26 | Porta origem / destino | `51422` / `445` |
| 30 | Ação | `allow` |

**O que o SOC N1 observa.** *Normal:* estação da VLAN 20 acessando o file server na VLAN 10 pela porta 445. *Suspeito:* origem na **VLAN30-IOT** (câmera) acessando servidor na VLAN 10 por 445 — câmera não faz SMB. Ou uma única origem falando 445 com 200 destinos em minutos: varredura lateral (**T1021.002**).

**Erro comum de analista júnior.** Olhar só IP de origem e destino e ignorar as zonas. O mesmo IP `10.20.14.87` pode ser legítimo indo para a zona de servidores e altamente anômalo indo para a zona de gerência dos switches.

### DMZ — a recepção da empresa

**O que é.** A DMZ (*DeMilitarized Zone*, Zona Desmilitarizada) é a recepção do prédio: visitantes entram nela, mas não passam para o andar dos cofres sem crachá e acompanhante.

**O que fica lá.** Servidores que precisam ser acessados pela Internet: web público, proxy reverso, SMTP de borda, portal de parceiros. **O que não fica:** Active Directory, banco de dados com informações de clientes, backup.

**Fluxo permitido (regra de ouro).**

| Sentido | Permitido? |
|---|---|
| Internet → DMZ | Sim, só nas portas do serviço (443, 25) |
| DMZ → Rede Interna | Muito restrito, alvo e porta específicos |
| Rede Interna → DMZ | Sim, administração controlada |
| DMZ → Internet | Restrito, e sempre registrado em log |

**Exemplo prático.** O servidor web `10.30.1.10` (zona `DMZ`) só pode falar com o banco `10.10.9.40` (zona `INTERNA`) na porta 1433. Nada mais.

**Como aparece nos logs.** Cisco ASA, negando uma conexão que sai da DMZ para a rede interna:

```
%ASA-4-106023: Deny tcp src DMZ:10.30.1.10/49877 dst INTERNA:10.10.2.15/445 by access-group "dmz_access_in" [0x0, 0x0]
```

`%ASA-4-106023` é o código de "pacote negado por lista de acesso". `src DMZ` e `dst INTERNA` são os nomes das interfaces — a mesma ideia de zona do Palo Alto.

**O que o SOC N1 observa.** *Normal:* servidor DMZ falando 1433 com um único banco. *Suspeito:* o exemplo acima — o servidor web tentando SMB (445) contra uma estação interna. Isso é o desenho clássico de um servidor de borda comprometido tentando movimento lateral (**T1210**). Um único evento pode ser configuração errada; uma sequência crescente para destinos diferentes é incidente.

**Erro comum de analista júnior.** Fechar o alerta porque "o firewall bloqueou, então está tudo bem". O bloqueio protegeu a rede interna, mas **não explica por que o servidor da DMZ tentou aquilo**. O host de origem precisa ser investigado.

### Segmentação, micro-segmentação e Zero Trust

**Segmentação** é dividir a rede em zonas com regras entre elas (o que fizemos com VLAN e DMZ). **Micro-segmentação** leva isso ao extremo: a política é aplicada por carga de trabalho, servidor a servidor — dois servidores na mesma VLAN podem estar proibidos de se falar.

**Zero Trust** é o princípio por trás: "nunca confie, sempre verifique". Estar dentro da rede não concede permissão nenhuma; toda conexão é autenticada e autorizada.

**Por que segmentação trava ransomware.** O ransomware moderno raramente cifra só a máquina infectada. Ele varre a rede e se espalha por SMB (445), RDP (3389) e WMI (135 + portas dinâmicas). Exemplo: `jsilva` abre um anexo malicioso na estação `10.20.14.87`. Sem segmentação, essa estação alcança as 400 outras estações e os 30 servidores — o incidente vira parada total. Com segmentação, a política bloqueia estação↔estação e só permite estação→servidor nas portas de negócio. A varredura bate na parede, gera centenas de `deny` no firewall — e esse pico de negações é justamente o sinal que o SOC detecta cedo.

Consulta Splunk (SPL) para achar esse padrão:

```spl
index=firewall action=deny dest_port IN (445,3389,135)
| stats dc(dest_ip) AS destinos_unicos count AS tentativas by src_ip, src_zone
| where destinos_unicos > 20
| sort - destinos_unicos
```

Linha 1: só eventos negados nas portas de movimento lateral. Linha 2: conta quantos destinos **distintos** cada origem tentou. Linha 3: mantém apenas quem falou com mais de 20 destinos. Linha 4: ordena do pior para o menor.

Equivalente em KQL (Microsoft Sentinel):

```kql
CommonSecurityLog
| where DeviceAction == "deny" and DestinationPort in (445, 3389, 135)   // negações nas portas de lateralização
| summarize destinos = dcount(DestinationIP), tentativas = count()
    by SourceIP, DeviceInboundInterface                                   // agrupa por origem e zona
| where destinos > 20                                                     // filtra varredura ampla
| order by destinos desc
```

### Topologias — o desenho físico e lógico da rede

| Topologia | Diagrama | Onde se usa hoje |
|---|---|---|
| Barramento | `A---B---C---D` (cabo único) | Obsoleta em Ethernet; sobrevive em CAN bus e alguns sistemas industriais |
| Estrela | todos ligados a um switch central | Padrão absoluto de LAN corporativa |
| Anel | cada nó ligado a dois vizinhos, fechando o ciclo | Anéis metropolitanos de operadora, redes industriais com protocolo de recuperação rápida |
| Malha | todos ligados a todos | Núcleo de operadoras, VPN site-a-site full mesh, Wi-Fi mesh |
| Árvore | núcleo → distribuição → acesso | Campus e prédios com vários andares |
| Híbrida | mistura das anteriores | Praticamente toda empresa real |
| Spine-leaf | cada leaf ligado a todos os spines | Data center e nuvem modernos |
| Hub-and-spoke | matriz ao centro, filiais em volta | WAN corporativa e VNets/VPCs em nuvem |

```
ESTRELA                 ANEL                    ÁRVORE
    PC1                  A---B                   [Núcleo]
     |                   |   |                    /     \
PC2-[SW]-PC3             D---C              [Dist1]   [Dist2]
     |                                        /  \       /  \
    PC4                                    SW1  SW2   SW3  SW4

MALHA                   SPINE-LEAF              HUB-AND-SPOKE
 A-----B              [Spine1] [Spine2]           Filial1
 |\   /|                 | \    /  |                  |
 | \ / |              [Leaf1][Leaf2][Leaf3]   Filial2-[MATRIZ]-Filial3
 |  X  |                 |     |     |                |
 | / \ |               srv   srv    srv            Filial4
 D-----C
```

Para o SOC, a topologia responde a uma pergunta prática: **onde eu consigo capturar o tráfego?** Numa estrela/árvore, o espelhamento de porta no switch de distribuição vê quase tudo. Em spine-leaf, tráfego leste-oeste entre servidores no mesmo leaf pode nunca subir ao ponto de captura — daí a necessidade de sensores distribuídos ou logs de fluxo.

### Exercícios — VPN, VLAN, DMZ, segmentação e topologias

1. Um log Palo Alto TRAFFIC traz zona de origem `VLAN30-IOT`, IP `192.168.30.77`, destino `10.10.5.20` na porta 445, ação `allow`. As câmeras da empresa ficam na VLAN 30. Isso é verdadeiro ou falso positivo? Qual o próximo passo?
2. O FortiGate registra 47 eventos `action="ssl-login-fail"` em 6 minutos, com `remip=198.51.100.22`, cada um com um `user` diferente (`jsilva`, `maria.costa`, `admin.rodrigo`, ...). Que técnica é essa e qual a técnica MITRE ATT&CK correspondente?
3. Aparece `%ASA-4-106023: Deny tcp src DMZ:10.30.1.10/50122 dst INTERNA:10.10.9.40/1433`. A política diz que o servidor web da DMZ pode falar 1433 com o banco `10.10.9.40`. Como você classifica esse evento?
4. Uma estação em `10.20.14.87` gera 380 eventos `deny` em 4 minutos, porta 445, contra 190 IPs distintos da faixa `10.20.0.0/16`. Descreva o cenário e os três próximos passos da investigação.
5. Quantas VLANs distintas você pode identificar com o padrão 802.1Q, e por que uma porta *access* nunca deveria receber quadros com tag?

<details><summary>Ver gabarito</summary>

**1.** Fortemente suspeito, provável verdadeiro positivo. Câmeras IP não usam SMB (445) contra file server — o normal seria RTSP (554) ou HTTP para o gravador. Como a ação é `allow`, a regra de firewall está frouxa. Próximos passos: identificar o dispositivo em `192.168.30.77` no inventário; verificar se de fato é câmera ou se alguém plugou um notebook numa porta da VLAN 30; consultar todos os destinos que esse IP tocou nas últimas 24h; escalar para revisão da regra entre `VLAN30-IOT` e `VLAN10-SERVIDORES`, que não deveria permitir 445.

**2.** *Password spraying*: uma senha comum testada contra muitos usuários, em vez de muitas senhas contra um usuário — assim o atacante evita bloquear as contas. MITRE **T1110.003** (*Brute Force: Password Spraying*). Sinal característico: um único `remip`, muitos `user` diferentes, poucas tentativas por conta. Verifique imediatamente se algum `tunnel-up` bem-sucedido veio do mesmo `remip` logo depois; se sim, o incidente já é comprometimento de conta (**T1078**).

**3.** Falso positivo de configuração, não incidente. O destino e a porta são exatamente os permitidos pela política, mas o firewall negou — indica erro na ordem ou no escopo da regra (ACL mal aplicada na interface, ou uma regra anterior mais ampla capturando o tráfego). Encaminhar para o time de redes como problema de configuração e verificar se a aplicação web está apresentando erro de conexão ao banco. Sinal de alerta seria porta diferente de 1433 ou destino diferente de `10.10.9.40`.

**4.** Varredura SMB interna, comportamento clássico de propagação de ransomware ou movimento lateral (**T1021.002** e **T1046**). A segmentação funcionou: os 380 `deny` mostram que a política estação↔estação está bloqueando. Próximos passos: (a) isolar `10.20.14.87` da rede; (b) buscar no EDR/Sysmon os processos criados nessa máquina no período — Sysmon EventID 1 (criação de processo) e 3 (conexão de rede) — procurando execução a partir de pastas temporárias; (c) verificar nos logs do Windows quais contas autenticaram nessa estação (EventID 4624, atenção a Logon Type 3) e se alguma delas tem privilégio elevado, para dimensionar o alcance.

**5.** O campo VLAN ID do 802.1Q tem 12 bits, o que daria 4096 valores; a VLAN 0 e a 4095 são reservadas, restando **1 a 4094** utilizáveis (na prática também se evita a VLAN 1, padrão de fábrica). Uma porta *access* pertence a uma única VLAN e entrega o quadro sem tag ao dispositivo final; se ela aceitasse quadros etiquetados, um host poderia escolher sozinho em qual VLAN quer entrar — exatamente o caminho do *VLAN hopping* (**T1599**).

</details>


## Cenários práticos: escritório, home office e cloud

Até aqui vimos os conceitos separados. Agora vamos juntar tudo em três desenhos que você vai encontrar no dia a dia de um SOC (Security Operations Center, ou Centro de Operações de Segurança). A analogia: um prédio de escritórios com andares e crachá, um apartamento onde todo mundo divide a mesma fechadura, e um condomínio alugado na nuvem onde você configura o porteiro por software.

### Cenário 1 — Escritório corporativo (matriz e filial)

**O que é:** a rede que a empresa controla fisicamente, dividida em VLANs (Virtual Local Area Network, rede local virtual — já citada no trecho anterior) para que setores diferentes não se enxerguem sem passar pelo firewall.

**Como funciona:** cada VLAN recebe uma faixa de IP própria. O firewall roteia entre elas e aplica regras. O proxy inspeciona a navegação. O DC (Domain Controller, controlador de domínio) autentica os usuários. A DMZ (DeMilitarized Zone, zona desmilitarizada) hospeda o que a internet acessa.

```
      INTERNET (203.0.113.0/24)
            |
      [ Firewall Palo Alto ]---[ DMZ 172.16.50.0/24 ]--- web01 172.16.50.10
            |                                            mail01 172.16.50.20
      +-----+------------------------------+
      |                                    |
  MATRIZ (São Paulo)                  FILIAL (Recife)
  Core Switch                         Switch L3
   |- VLAN 10 Usuarios   10.10.10.0/24     |- VLAN 110 Usuarios 10.20.10.0/24
   |- VLAN 20 Servidores 10.10.20.0/24     |- VLAN 130 Voz      10.20.30.0/24
   |     dc01 10.10.20.5                   |- VLAN 140 Guest    10.20.40.0/24
   |     proxy01 10.10.20.30               |
   |- VLAN 30 Voz        10.10.30.0/24     +--- Túnel site-to-site ---+
   |- VLAN 40 Guest      10.10.40.0/24
```

| VLAN | Nome | Faixa | Gateway | Sai para internet? | Fala com VLAN 20? |
|---|---|---|---|---|---|
| 10 | Usuários matriz | 10.10.10.0/24 | 10.10.10.1 | Sim, via proxy | Sim, portas de negócio |
| 20 | Servidores | 10.10.20.0/24 | 10.10.20.1 | Só updates | — |
| 30 | Voz (VoIP) | 10.10.30.0/24 | 10.10.30.1 | Não | Não |
| 40 | Guest | 10.10.40.0/24 | 10.10.40.1 | Sim, direto | **Não** |
| 110 | Usuários filial | 10.20.10.0/24 | 10.20.10.1 | Sim, via proxy | Sim, via túnel |
| — | DMZ | 172.16.50.0/24 | 172.16.50.1 | Entrada 443 | Não inicia sessão |

**Exemplo prático:** o usuário `jsilva` (10.10.10.87) abre o portal interno e depois autentica no domínio `corp.local`.

**Como aparece nos logs** — Palo Alto TRAFFIC (CSV) e Windows Security:

```
1,2026/09/03 09:12:44,014201, TRAFFIC,end,2049,10.10.10.87,10.10.20.30,203.0.113.9,198.51.100.44,Regra-Users-Proxy,corp\jsilva,,web-browsing,vsys1,VLAN10-Users,DMZ-Out,ae1.10,ae1.50,Log-Fwd,tcp,allow,18422,3122,15300,42,443
```

```
EventID 4624 | Logon Type 3 | Account Name: jsilva | Domain: CORP
Source Network Address: 10.10.10.87 | Logon Process: Kerberos | Computer: DC01
```

| Campo do log | Significa |
|---|---|
| `TRAFFIC ... end` | Sessão encerrada e contabilizada |
| `10.10.10.87 → 10.10.20.30` | Origem (VLAN 10) e destino (proxy na VLAN 20) |
| `203.0.113.9 / 198.51.100.44` | IP traduzido por NAT e destino público real |
| `VLAN10-Users → DMZ-Out` | Zonas de origem e destino no firewall |
| `allow / tcp / 443` | Ação, protocolo e porta |
| 4624 Logon Type 3 | Logon de rede (acesso a recurso), não interativo |

**O que o SOC N1 observa:**

| Normal | Suspeito |
|---|---|
| VLAN 10 → proxy 10.10.20.30 na 8080/443 | VLAN 10 saindo direto para internet, ignorando o proxy |
| Guest só com destino internet | Guest (10.10.40.x) tentando 445/3389 na VLAN 20 |
| DMZ recebendo 443 de fora | DMZ **iniciando** conexão para 10.10.20.5 (movimento lateral, T1021) |
| 4624 tipo 3 em horário comercial | 4625 em rajada seguido de um 4624 (força bruta bem-sucedida, T1110) |

**Erro comum de analista júnior:** ver o IP do proxy (10.10.20.30) como origem e investigar o servidor de proxy. O usuário real está no campo de usuário do log ou no `X-Forwarded-For` do Squid — sempre pivote para o log do proxy antes de acusar um host.

### Cenário 2 — Home office

**O que é:** o computador corporativo dentro de uma rede doméstica que a empresa não administra. Analogia: seu crachá funciona, mas a portaria do prédio é do vizinho.

**Como funciona:** o roteador doméstico faz NAT (Network Address Translation, tradução de endereços) — todos os aparelhos da casa saem com um único IP público. A VPN (Virtual Private Network) cria um túnel cifrado até a empresa.

```
  Casa 192.168.1.0/24
   |- notebook corp  192.168.1.20  --> tunel VPN --> 10.99.5.0/24 (pool VPN)
   |- TV / babá eletrônica (IoT) 192.168.1.40
   |- celular pessoal 192.168.1.55
        |
   [ Roteador NAT ] IP público 198.51.100.77
        |
   INTERNET --> [ Concentrador VPN 203.0.113.20 ] --> VLAN 20 Servidores
```

| Item | Split tunnel | Full tunnel |
|---|---|---|
| Tráfego corporativo | Vai pelo túnel | Vai pelo túnel |
| Navegação pessoal | Sai direto pela casa | Vai pelo túnel e passa no proxy |
| Visibilidade do SOC | Parcial | Total |
| Risco | Máquina fala com IoT e internet sem inspeção | Mais lento, mais carga no link |

**Como aparece nos logs** — FortiGate (key=value) e Cisco ASA:

```
date=2026-09-03 time=21:03:11 devname="FGT-VPN01" type="event" subtype="vpn" action="tunnel-up" user="maria.costa" remip=198.51.100.77 assignip=10.99.5.34 tunneltype="ssl-web" duration=0 msg="SSL VPN tunnel up"
```

```
%ASA-6-302013: Built inbound TCP connection 88213 for outside:198.51.100.77/51422 (198.51.100.77/51422) to inside:10.10.20.5/445 (10.10.20.5/445)
```

Campos: `remip` é o IP público da casa; `assignip` é o IP que a empresa emprestou para a máquina; `tunneltype` mostra a tecnologia; no ASA, `302013` significa conexão TCP construída, com origem `outside` e destino interno na porta 445 (SMB).

**O que o SOC N1 observa:** normal é um `tunnel-up` por usuário, de um IP compatível com o país esperado. Suspeito é o mesmo usuário com dois `remip` distantes em minutos (viagem impossível, T1078), ou VPN de madrugada seguida de varredura em 10.10.20.0/24.

**Erro comum de analista júnior:** achar que o IP do túnel (10.99.5.34) identifica a máquina para sempre. O pool é dinâmico — sem correlacionar com o log de `tunnel-up` no horário exato, você acusa o usuário errado.

### Cenário 3 — Ambiente cloud (VPC/VNet)

**O que é:** VPC (Virtual Private Cloud) na AWS ou VNet na Azure — sua rede privada dentro do provedor.

```
  VPC 10.30.0.0/16
   |- Subnet publica  10.30.1.0/24  -> [Internet Gateway] -> internet
   |     bastion 10.30.1.10 (IP público 192.0.2.55)
   |     NAT Gateway 10.30.1.20
   |- Subnet privada  10.30.10.0/24 -> saída via NAT Gateway
         app01 10.30.10.11 | db01 10.30.10.30
```

| Controle | Onde atua | Estado | Regras |
|---|---|---|---|
| Security Group | Na interface da instância | Com estado (resposta liberada) | Só permitir |
| NACL | Na borda da subnet | Sem estado (precisa regra de volta) | Permitir e negar, numeradas |
| Internet Gateway | Entrada e saída pública | — | Dá caminho a IP público |
| NAT Gateway | Só saída da subnet privada | — | Esconde os IPs privados |

**Como aparece nos logs** — VPC Flow Logs (formato padrão versão 2):

```
2 123456789012 eni-0ab12cd34ef56 192.0.2.203 10.30.1.10 41522 22 6 24 3120 1756890000 1756890060 REJECT OK
```

| Posição | Campo | Valor | Leitura |
|---|---|---|---|
| 1 | version | 2 | Formato do registro |
| 2 | account-id | 123456789012 | Conta AWS |
| 3 | interface-id | eni-0ab12cd34ef56 | Placa de rede do bastion |
| 4-5 | srcaddr / dstaddr | 192.0.2.203 → 10.30.1.10 | Quem fala com quem |
| 6-7 | srcport / dstport | 41522 → 22 | Porta alta de origem, SSH no destino |
| 8 | protocol | 6 | 6 = TCP (1 = ICMP, 17 = UDP) |
| 9-10 | packets / bytes | 24 / 3120 | Volume no intervalo |
| 11-12 | start / end | epoch | Janela agregada (não é pacote a pacote) |
| 13 | action | REJECT | Bloqueado por SG ou NACL |
| 14 | log-status | OK | Registro completo |

**O que o SOC N1 observa:** normal é `ACCEPT` na 22 apenas do IP corporativo para o bastion. Suspeito é rajada de `REJECT` na 22 vinda de vários IPs (varredura, T1046) ou — pior — `ACCEPT` de db01 (10.30.10.30) direto para a internet, o que indica exfiltração (T1041).

```spl
index=aws sourcetype=aws:cloudwatchlogs:vpcflow dstport=22 action=REJECT
| stats count dc(dstaddr) as alvos by srcaddr
| where count > 50
```
Linha 1 filtra flow logs de SSH negado; linha 2 conta tentativas e alvos distintos por origem; linha 3 mantém só quem insistiu muito.

```kql
AzureNetworkAnalytics_CL
| where DestPort_d == 22 and FlowStatus_s == "D"      // D = negado
| summarize Tentativas = count() by SrcIP_s, bin(TimeGenerated, 5m)
| where Tentativas > 50
```

**Erro comum de analista júnior:** tratar `REJECT` como "nada aconteceu". O REJECT prova que alguém tentou; o valor está em ver se, na mesma janela, existe um `ACCEPT` do mesmo IP.

### Exercícios — Cenários práticos: escritório, home office e cloud

1. Um host 10.10.40.15 (Guest) aparece em log Palo Alto com destino 10.10.20.5 porta 445, ação `deny`. É verdadeiro ou falso positivo?
2. `maria.costa` tem `tunnel-up` com `remip=198.51.100.77` às 21:03 e outro `tunnel-up` com `remip=203.0.113.200` às 21:19. Qual o próximo passo?
3. No flow log `... 10.30.10.30 198.51.100.90 51199 443 6 8800 9400000 ... ACCEPT OK`, o que chama atenção?
4. Quantos hosts utilizáveis cabem em 10.10.10.0/24 e por que a VLAN de voz costuma ser separada?
5. Em split tunnel, por que a navegação do usuário não aparece no Squid corporativo?

<details><summary>Ver gabarito</summary>

1. **Verdadeiro positivo de política, com risco baixo.** A tabela mostra que Guest não pode falar com a VLAN 20; o `deny` provou que a segmentação funciona. Ainda assim investigue: 445 é SMB e pode ser malware varrendo. Verifique se houve outras portas e outros destinos do mesmo IP; se sim, escale.
2. **Viagem impossível (T1078).** Próximo passo: confirmar se o segundo IP é de outro país/ASN, checar se houve MFA nos dois logons, procurar 4624/4768 no `corp.local` vindos do IP do pool VPN daquele momento e contatar a usuária por canal fora de banda antes de derrubar a sessão.
3. **Exfiltração provável (T1041).** É o banco de dados da subnet privada iniciando saída para a internet na 443 com 9,4 MB. Banco não deveria sair; e mesmo saída de update passaria por destinos conhecidos. Escale e peça bloqueio no Security Group.
4. **254 hosts** (256 endereços menos rede e broadcast). Voz fica separada por qualidade (priorização de tráfego) e por segurança: telefones IP são difíceis de atualizar e não devem alcançar servidores.
5. Porque o tráfego pessoal sai direto pelo roteador de casa (198.51.100.77) sem entrar no túnel — o proxy nunca vê a requisição. A visibilidade vem só do agente de endpoint, se houver.

</details>

## Mini-laboratório — Fundamentos de redes

**Pré-requisitos:** VirtualBox, uma VM Linux (Ubuntu Server), Wireshark instalado no host, acesso administrativo local. Nada exposto à internet.

1. No VirtualBox, crie duas VMs com adaptador **Rede Interna** chamada `lab-vlan10`. Defina manualmente `10.10.10.20/24` e `10.10.10.21/24`.
   *Observar:* `ip addr show` deve listar a faixa correta.
2. Na VM A, capture: `sudo tcpdump -i enp0s3 -n -w /tmp/lab.pcap`.
3. Na VM B, gere tráfego: `ping -c 4 10.10.10.20` e depois `nmap -sT -p 22,80,445 10.10.10.20`.
   *Observar:* respostas ICMP tipo 0 (echo reply) e RST das portas fechadas.
4. Pare a captura (Ctrl+C) e abra `/tmp/lab.pcap` no Wireshark.
5. Aplique os filtros `icmp`, depois `tcp.flags.syn==1 && tcp.flags.ack==0` e por fim `tcp.flags.reset==1`.
   *Observar:* o SYN sem resposta ACK caracteriza porta filtrada; SYN seguido de RST é porta fechada.
6. Repita o passo 3 com `-p 22` apenas e compare a contagem de pacotes.

**Critério de sucesso:** você consegue apontar, no Wireshark, um three-way handshake completo, um RST e a diferença visual entre varredura e conexão legítima.

## O que um SOC Level 1 realmente precisa saber

- 🟢 Diferenciar IP privado (RFC1918) de IP público e reconhecer as faixas de documentação em exercícios.
- 🟢 Ler um log de firewall identificando origem, destino, porta, zona e ação.
- 🟢 Saber que porta indica serviço: 22 SSH, 53 DNS, 80/443 web, 445 SMB, 3389 RDP, 389/636 LDAP, 88 Kerberos.
- 🟢 Entender NAT: o IP público sozinho não identifica a máquina interna.
- 🟢 Reconhecer 4624 (logon bem-sucedido), 4625 (falha) e o tipo de logon.
- 🟡 Explicar por que VLAN e DMZ existem e o que significa um `deny` entre segmentos.
- 🟡 Distinguir split tunnel de full tunnel e o impacto disso na visibilidade.
- 🟡 Diferenciar Security Group (com estado) de NACL (sem estado) na AWS.
- 🟡 Ler um VPC Flow Log campo a campo e interpretar ACCEPT versus REJECT.
- 🔴 Correlacionar VPN, DHCP e logon de domínio para atribuir um IP dinâmico a uma pessoa.
- 🔴 Reconhecer padrões de movimento lateral e exfiltração a partir de metadados de fluxo.
- 🔴 Escrever consultas SPL e KQL que agrupem por origem e filtrem por limiar.

## Resumo em 10 linhas

1. Rede é um conjunto de dispositivos que trocam dados sob regras comuns, os protocolos.
2. LAN, WAN, MAN e WLAN descrevem o alcance físico; internet e intranet, o escopo de acesso.
3. Endereço IP identifica o host e a máscara define quem é vizinho na mesma rede.
4. NAT permite que muitos hosts privados compartilhem um IP público — e complica a atribuição.
5. VLAN separa logicamente setores no mesmo switch; DMZ isola o que a internet toca.
6. VPN estende a rede corporativa até a casa do usuário, com túnel cifrado.
7. No escritório, o tráfego típico passa por proxy, firewall e controlador de domínio.
8. Em home office, a rede compartilhada e os dispositivos IoT ampliam a superfície de risco.
9. Na cloud, VPC, subnets, Security Groups, NACLs e gateways substituem cabos e switches.
10. O SOC N1 vive de comparar o que é normal naquele desenho com o que fugiu do padrão.



---
