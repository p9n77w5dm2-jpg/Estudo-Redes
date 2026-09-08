# Módulo 5 — DNS para analistas de SOC

## Por que este módulo importa para o SOC

Quase todo ataque moderno passa pelo DNS (Domain Name System, ou Sistema de Nomes de Domínio) em algum momento: o malware precisa descobrir o endereço do servidor de comando e controle, o phishing precisa que a vítima resolva um domínio recém-registrado, e a exfiltração de dados às vezes viaja disfarçada dentro de consultas DNS. Como o DNS é liberado em praticamente todas as redes, ele virou o caminho mais confiável do atacante — e, por isso mesmo, uma das fontes de log mais valiosas que você terá como analista N1. Entender como uma resolução funciona é o que separa "vi um domínio estranho" de "sei exatamente o que aconteceu, quem pediu e o que fazer agora".

### Índice do módulo

- O que é DNS e como funciona uma resolução
- Tipos de registro DNS
- Ataques que usam DNS
- Como investigar DNS no SOC

## O que é DNS

**O que é.** Imagine uma lista telefônica antiga: você sabe o nome da pessoa ("Padaria do João"), mas para ligar precisa do número. A lista traduz nome em número. O DNS faz exatamente isso na internet: você digita `www.empresa-exemplo.com.br` e o DNS devolve `203.0.113.45`, o endereço IP (Internet Protocol) do servidor.

**Por que existe.** Computadores só sabem conversar por número (endereço IP). Pessoas não decoram números, e — mais importante — os números mudam o tempo todo (troca de provedor, balanceamento de carga, nuvem). O DNS cria uma camada de nomes estável por cima de endereços instáveis.

**Como funciona, em uma frase.** O DNS é um banco de dados gigante, distribuído pelo mundo, em que cada organização é responsável (autoritativa) apenas pelo seu próprio pedaço.

### A hierarquia: lendo um nome da direita para a esquerda

Nomes DNS são lidos ao contrário do que você está acostumado — do mais genérico (direita) para o mais específico (esquerda).

```
www.vendas.empresa-exemplo.com.br.
 |     |          |            |  |
 |     |          |            |  +-- root (o ponto final, quase sempre invisível)
 |     |          |            +----- TLD: .br (Top Level Domain)
 |     |          +------------------ 2º nível: empresa-exemplo.com.br
 |     +----------------------------- subdomínio: vendas
 +----------------------------------- host: www
```

| Nível | Nome técnico | Exemplo | Quem controla |
|---|---|---|---|
| Raiz | root | `.` (ponto final) | 13 conjuntos de servidores raiz globais |
| 1º | TLD (Top Level Domain) | `.com`, `.br`, `.io` | Registries (Verisign, NIC.br, etc.) |
| 2º | domínio de segundo nível | `empresa-exemplo.com.br` | A própria empresa |
| 3º+ | subdomínio | `vendas.empresa-exemplo.com.br` | A própria empresa |
| Folha | host / FQDN | `www.vendas.empresa-exemplo.com.br.` | A própria empresa |

FQDN significa Fully Qualified Domain Name (nome de domínio totalmente qualificado): o nome completo, do host até a raiz. O ponto final é o que torna o nome "qualificado". Você raramente o digita, mas ele existe em todo pacote DNS — e aparece assim em alguns logs.

**Erro comum de analista júnior.** Achar que `empresa-exemplo.com.br` e `login.empresa-exemplo.com.br.atacante-cdn.xyz` são o mesmo domínio. Não são. O que manda é o final do nome, não o começo. O segundo pertence a `atacante-cdn.xyz`. Sempre leia o nome da direita para a esquerda.

## Os atores de uma resolução

| Ator | O que faz | Analogia | Onde vive na empresa |
|---|---|---|---|
| Stub resolver | Biblioteca dentro do sistema operacional do usuário. Só sabe perguntar. | Você pegando o telefone | Notebook do jsilva (10.10.20.15) |
| Resolver recursivo | Faz o trabalho pesado: pergunta a todo mundo até achar a resposta. Guarda em cache. | A telefonista que procura para você | DC/DNS interno 10.10.10.5 |
| Forwarder | Resolver que não pesquisa sozinho: repassa para outro resolver | A telefonista que liga para outra central | 10.10.10.5 encaminha para 203.0.113.10 |
| Servidor autoritativo | Dono da verdade sobre um domínio. Responde só do que é dele. | A própria padaria informando o número | Servidor DNS do domínio |
| Cache | Memória temporária de respostas já obtidas | Bloquinho de anotações da telefonista | No resolver e no próprio Windows |

## A resolução completa, passo a passo

Cenário: o usuário `jsilva`, na máquina `10.10.20.15`, abre `www.example.com` no navegador. O DNS interno da empresa é `10.10.10.5` e ainda não tem nada em cache.

```
 [1] stub (10.10.20.15)  --- RECURSIVA: "quero www.example.com resolvido" --->  [resolver 10.10.10.5]
                                                                                       |
                                                          [2] ITERATIVA: "quem sabe de .com?"
                                                                                       v
                                                                              [ servidor ROOT ]
                                                          [3] "não sei o IP, pergunte aos TLD .com"
                                                                                       |
                                                          [4] ITERATIVA: "quem sabe de example.com?"
                                                                                       v
                                                                              [ servidor TLD .com ]
                                                          [5] "não sei o IP, o autoritativo é ns1.example.com"
                                                                                       |
                                                          [6] ITERATIVA: "qual o A de www.example.com?"
                                                                                       v
                                                                          [ autoritativo ns1.example.com ]
                                                          [7] "A = 203.0.113.45, TTL 3600"
                                                                                       |
 [8] stub <---------------- resposta final + guarda em CACHE por 3600s ----------------+
 [9] navegador abre TCP 443 para 203.0.113.45
```

**Recursiva x iterativa — a diferença que cai em toda entrevista.** Na consulta **recursiva** (passo 1) o cliente diz "resolva isso para mim e só volte com a resposta final". Na consulta **iterativa** (passos 2 a 7) o servidor pergunta e recebe de volta uma *referência* ("não sei, pergunte àquele ali"), tendo que continuar sozinho. O stub sempre faz recursiva; o resolver recursivo faz iterativas mundo afora. No cabeçalho DNS isso é a flag **RD** (Recursion Desired) no pedido e **RA** (Recursion Available) na resposta.

### Como aparece nos logs

Zeek `dns.log` (um dos formatos mais usados em SOC):

```
#fields ts      uid          id.orig_h    id.orig_p  id.resp_h   id.resp_p  proto  trans_id  query            qtype_name  rcode_name  AA  RD  RA  TTLs    answers
1756900412.113  CwXy1a2Bc3D  10.10.20.15  51422      10.10.10.5  53         udp    43119     www.example.com  A           NOERROR     F   T   T   3600.0  203.0.113.45
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `ts` | `1756900412.113` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos |
| `uid` | `CwXy1a2Bc3D` | Identificador único da conexão — cruza com o `conn.log` |
| `id.orig_h` / `id.orig_p` | `10.10.20.15` / `51422` | Quem perguntou: a estação e a porta efêmera de onde saiu a consulta |
| `id.resp_h` / `id.resp_p` | `10.10.10.5` / `53` | Qual resolvedor respondeu, na porta 53 |
| `proto` | `udp` | DNS usa UDP por padrão; TCP entra quando a resposta não cabe em um datagrama |
| `trans_id` | `43119` | Número que casa a pergunta com a resposta. **Valor previsível abre porta a envenenamento de cache** |
| `query` | `www.example.com` | O nome consultado — o campo mais usado em caça |
| `qtype_name` | `A` | Tipo de registro pedido: `A` endereço IPv4, `AAAA` IPv6, `TXT` texto livre, `MX` correio, `SRV` serviço |
| `rcode_name` | `NOERROR` | Resultado. `NXDOMAIN` = o nome não existe; em rajada é indício de DGA |
| `AA` | `F` | *Authoritative Answer* — se quem respondeu é a autoridade do domínio ou só repassou do cache |
| `RD` | `T` | *Recursion Desired* — o cliente pediu ao resolvedor que fosse buscar a resposta |
| `RA` | `T` | *Recursion Available* — o servidor aceita fazer recursão. Um resolvedor exposto à Internet com `RA=T` é risco de amplificação |
| `TTLs` | `3600.0` | Tempo de vida da resposta em cache, em segundos. TTL muito baixo (30–60 s) é típico de infraestrutura descartável |
| `answers` | `203.0.113.45` | O que o servidor devolveu |

</details>


Windows/Sysmon Event ID 22 (DNS query), o melhor amigo do N1 porque traz o **processo** que perguntou:

```
EventID: 22
UtcTime: 2026-09-03 14:33:32.113
Image: C:\Users\jsilva\AppData\Local\Temp\atualizador.exe
QueryName: cdn-update.example.com
QueryStatus: 0
QueryResults: type:  5 cdn-update-edge.example.com;::ffff:203.0.113.77;
User: CORP\jsilva
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `EventID` | `22` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não. `22` = Sysmon **DNS Query** |
| `UtcTime` | `2026-09-03 14:33:32.113` | Instante do evento **em UTC**, o que dispensa converter fuso ao correlacionar |
| `Image` | `C:\Users\jsilva\AppData\Local\Temp\atualizador.exe` | Caminho do executável (nomenclatura do Sysmon) |
| `QueryName` | `cdn-update.example.com` | O nome consultado no DNS |
| `QueryStatus` | `0` | Código de resultado da consulta (`0` é sucesso) |
| `QueryResults` | `type:  5 cdn-update-edge.example.com;::ffff:203.0.113.77` | O que o DNS respondeu |
| `User` | `CORP\jsilva` | Conta sob a qual o processo corre |

</details>

`Image` é o executável que fez a consulta, `QueryStatus: 0` significa sucesso, `QueryResults` traz a cadeia de respostas.

**O que o SOC N1 observa.** Normal: navegador (`chrome.exe`, `msedge.exe`) e serviços do sistema consultando domínios conhecidos, via o resolver corporativo. Suspeito: um binário em `\AppData\Local\Temp\` fazendo consultas DNS; consulta indo direto para um IP externo na porta 53, ignorando o resolver interno; rajadas de NXDOMAIN.

**Erro comum de analista júnior.** Fechar o caso ao ver que o `id.orig_h` do log do servidor DNS é `10.10.10.5`. Esse é o resolver, não a vítima. Você precisa do log do endpoint (Sysmon 22) ou do log de consultas do próprio servidor DNS para chegar na máquina real.

## Cache e TTL

**O que é.** TTL (Time To Live, tempo de vida) é quantos segundos uma resposta pode ficar guardada antes de ser perguntada de novo. É o prazo de validade da anotação da telefonista.

**Como funciona.** O autoritativo define o TTL. Resolvers e o próprio sistema operacional respeitam esse prazo, respondendo do cache sem gerar tráfego novo. Um site normal usa TTL de 300 a 86400 segundos (5 minutos a 1 dia).

| TTL observado | Leitura típica | Ação do N1 |
|---|---|---|
| 3600–86400 | Infraestrutura estável | Normal |
| 300–600 | CDN, balanceamento, nuvem | Normal, contextualizar |
| 60–120 | Failover agressivo ou infra dinâmica | Observar |
| 0–60 com IPs variando | Possível fast flux / C2 (T1568.001) | Escalar com contexto |

**O que o SOC N1 observa.** TTL muito baixo somado a **muitos IPs diferentes para o mesmo nome em pouco tempo** é a assinatura de *fast flux*: o atacante troca o endereço do servidor a cada minuto para escapar de bloqueio por IP. TTL baixo sozinho não é incidente — a Netflix e a Cloudflare do mundo real usam TTL baixo o dia todo.

**Erro comum de analista júnior.** Abrir incidente só porque o TTL é 60. Sem variação de IP, sem domínio recém-registrado e sem processo suspeito, é só engenharia de disponibilidade.

## Transporte: UDP 53, TCP 53 e EDNS0

**O que é.** DNS nasceu em cima de UDP (User Datagram Protocol) na porta 53 porque a pergunta e a resposta cabem em um pacote e velocidade importa mais que confiabilidade.

**Quando usa TCP 53.** Quando a resposta não cabe no limite (originalmente 512 bytes), o servidor marca a flag **TC** (truncated) e o cliente refaz a pergunta por TCP 53. Também usa TCP para transferência de zona (AXFR/IXFR) entre servidores DNS.

**EDNS0** (Extension Mechanisms for DNS, RFC 6891) permite negociar respostas UDP maiores (tipicamente 1232 ou 4096 bytes), evitando o retorno ao TCP. É pré-requisito prático para DNSSEC, cujas assinaturas são grandes.

| Situação | Transporte | Observação no SOC |
|---|---|---|
| Consulta comum | UDP 53 | Baseline |
| Resposta truncada (TC=1) | TCP 53 | Normal e esperado |
| AXFR (transferência de zona) | TCP 53 | Suspeito se vier de host que não é DNS secundário (T1590.002) |
| Respostas gigantes por UDP | UDP 53 + EDNS0 | Se for para vítima externa, pode ser amplificação DDoS |

```
# Filtro Wireshark: DNS que precisou de TCP
tcp.port == 53
# Filtro Wireshark: respostas truncadas
dns.flags.truncated == 1
```

## DoH e DoT: o pesadelo de visibilidade

**O que é.** DoH (DNS over HTTPS, porta 443) e DoT (DNS over TLS, porta 853) criptografam a consulta DNS. Ótimo para privacidade do usuário na cafeteria; péssimo para o SOC, porque o log de DNS simplesmente **desaparece** — a consulta vira tráfego HTTPS comum.

**Como funciona.** O navegador ou o malware abre uma conexão TLS direto com um resolver público (por exemplo `1.1.1.1` ou `8.8.8.8`) e manda as consultas dentro dela, ignorando o resolver corporativo, o bloqueio de domínios e o seu Zeek `dns.log`.

**Como detectar (sem quebrar a criptografia).**

| Sinal | O que procurar |
|---|---|
| Porta 853 | Qualquer saída TCP/853 é DoT — nunca é acidente |
| IPs de resolvers públicos na 443 | Conexões TLS para faixas conhecidas de DNS público a partir de endpoints |
| SNI/certificado | `ssl.log` do Zeek com `server_name` de serviço DoH conhecido |
| Domínio canário | `use-application-dns.net` |
| Queda de volume | Endpoint que parou de gerar consultas no DNS interno mas continua navegando |

**O domínio canário `use-application-dns.net`.** É um mecanismo oficial: se a rede responde **NXDOMAIN** para esse nome, o Firefox desliga o DoH automaticamente. Ou seja, o time de rede deve configurar o DNS interno para responder NXDOMAIN nesse nome. Para o N1: ver esse nome sendo consultado é normal (é o navegador testando); ver a rede respondendo NOERROR nele significa que o controle está mal configurado.

**Como aparece nos logs.** FortiGate (formato chave=valor), sessão DoT saindo de um endpoint:

```
date=2026-09-03 time=14:41:07 devname="FGT-CORP-01" devid="FG100F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=10.10.20.15 srcport=49877 srcintf="port3" dstip=203.0.113.53 dstport=853 dstintf="wan1" proto=6 action="accept" policyid=12 service="tcp/853" sentbyte=4210 rcvdbyte=9880 app="DNS.over.TLS" user="jsilva"
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `date` | `2026-09-03` | Data local **do equipamento**, não UTC. Correlacionar com um log em UTC sem acertar o fuso desalinha a timeline |
| `time` | `14:41:07` | Hora local do equipamento |
| `devname` | `"FGT-CORP-01"` | Nome do equipamento que gerou o log |
| `devid` | `"FG100F0000000001"` | Número de série do equipamento — numa frota, é ele que identifica qual falou |
| `logid` | `"0000000013"` | Identificador do **tipo** de log. **É por ele que se filtra no SIEM**: o texto muda entre versões do FortiOS, o número não |
| `type` | `"traffic"` | Categoria do log: `traffic` é sessão, `event` é evento do próprio aparelho, `utm` é inspeção de conteúdo |
| `subtype` | `"forward"` | Subcategoria: `forward` é tráfego que atravessa, `local` é destinado ao próprio firewall, `vpn` é túnel, `webfilter` e `ips` são inspeção |
| `level` | `"notice"` | Severidade atribuída pelo FortiOS (`notice`, `warning`, `alert`, `critical`). **Quem a escolhe é o fabricante**, não o seu SOC |
| `srcip` | `10.10.20.15` | IP de origem |
| `srcport` | `49877` | Porta de origem, efêmera e sorteada pelo cliente |
| `srcintf` | `"port3"` | Interface por onde o tráfego **entrou** — dá o sentido, que o IP sozinho não dá |
| `dstip` | `203.0.113.53` | IP de destino |
| `dstport` | `853` | Porta de destino — é ela que aponta o serviço |
| `dstintf` | `"wan1"` | Interface por onde o tráfego **saiu** |
| `proto` | `6` | Número do protocolo IP: **`6` é TCP, `17` é UDP, `1` é ICMP**. Vem em número, não em nome |
| `action` | `"accept"` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |
| `policyid` | `12` | **Número da regra que decidiu.** Sem ele não se sabe por que o tráfego passou ou parou |
| `service` | `"tcp/853"` | Nome do **objeto de serviço** do FortiGate, não a porta literal. Um objeto chamado `HTTPS` pode ter sido configurado noutra porta |
| `sentbyte` | `4210` | Bytes enviados **pela origem**. O ponto de vista é o da origem, não do firewall |
| `rcvdbyte` | `9880` | Bytes recebidos pela origem. **Comparar com `sentbyte` é o que revela exfiltração** |
| `app` | `"DNS.over.TLS"` | Aplicação identificada pelo controle de aplicação, por inspeção do conteúdo |
| `user` | `"jsilva"` | Conta autenticada — o que transforma "um IP" em "uma pessoa" |

</details>

`srcip` = endpoint interno, `dstport=853` + `proto=6` (TCP) = DoT, `action="accept"` mostra que a política **permitiu** — este é o achado.

**O que o SOC N1 observa.** Normal: endpoints falando 53 apenas com o resolver interno. Suspeito: qualquer TCP/853 saindo; endpoint com tráfego web alto e zero consultas no DNS interno; processo não-navegador conversando TLS com resolver público.

**Erro comum de analista júnior.** Tratar DoH/DoT como malware. Muitas vezes é o próprio navegador do usuário com configuração padrão. O achado real é de **política**: a saída deveria estar bloqueada e não estava.

## DNSSEC em resumo

**O que é.** DNSSEC (Domain Name System Security Extensions) assina digitalmente as respostas DNS. É o lacre de segurança na embalagem: não esconde o conteúdo, mas prova que ninguém trocou.

**O que resolve:** falsificação de resposta (cache poisoning, spoofing). **O que NÃO resolve:** confidencialidade — a consulta continua em texto claro (esse é o papel do DoH/DoT). Também não impede que um domínio malicioso seja assinado corretamente: DNSSEC prova autenticidade, não bondade.

**Como aparece.** Novos tipos de registro (`RRSIG` com a assinatura, `DNSKEY` com a chave, `DS` ligando a zona pai à filha) e a flag **AD** (Authenticated Data) na resposta do resolver validador. Respostas ficam grandes, daí a dependência de EDNS0.

## Consultas prontas

```spl
index=dns sourcetype=zeek:dns
| eval ttl_min=mvindex(TTLs,0)
| where ttl_min<=60                     /* TTL agressivamente baixo */
| stats dc(answers) as ips_distintos count as consultas by query, id_orig_h
| where ips_distintos>=5                /* mesmo nome, muitos IPs = possível fast flux */
| sort - ips_distintos
```

```kql
// Sentinel/Defender: saída de DNS criptografado a partir de endpoints
DeviceNetworkEvents
| where Timestamp > ago(24h)                          // janela de 1 dia
| where RemotePort == 853                             // DoT é sempre TCP/853
   or (RemotePort == 443 and RemoteUrl has "dns-query") // caminho típico de DoH
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe") // ruído esperado
| summarize Consultas=count(), Destinos=make_set(RemoteIP, 10)
        by DeviceName, InitiatingProcessFileName, AccountName
| order by Consultas desc
```

### Exercícios — O que é DNS e como funciona uma resolução

1. Leia o FQDN `portal.rh.empresa-exemplo.com.br.` e identifique: raiz, TLD, domínio de segundo nível, subdomínio e host.
2. Você recebe o alerta "domínio com TTL de 45 segundos acessado por 10.10.20.15". No Zeek `dns.log`, o mesmo `query` retornou 8 endereços diferentes em 6 minutos, e o Sysmon 22 mostra `Image: C:\Users\maria.costa\AppData\Local\Temp\svc-host.exe`. Verdadeiro ou falso positivo? Justifique.
3. Um segundo alerta traz TTL de 60 segundos para `cdn.example.com`, consultado por `msedge.exe`, sempre resolvendo para 2 IPs da mesma faixa. Verdadeiro ou falso positivo? Qual a diferença em relação ao exercício 2?
4. O FortiGate registra `srcip=10.10.20.15 dstip=198.51.100.53 dstport=853 action="accept"`. Qual é o próximo passo da investigação?
5. Você vê no `dns.log` a consulta `use-application-dns.net` com `rcode_name=NOERROR`. O que isso indica e o que deve ser recomendado?

<details><summary>Ver gabarito</summary>

**1.** Lendo da direita para a esquerda: o ponto final é a **raiz**; `br` é o **TLD**; `empresa-exemplo.com.br` é o **domínio de segundo nível** (no padrão brasileiro, `.com.br` funciona como sufixo de registro); `rh` é o **subdomínio**; `portal` é o **host**. O conjunto todo, com o ponto final, é o **FQDN**.

**2.** **Verdadeiro positivo provável.** Três indicadores somados: TTL muito baixo, muitos IPs distintos em poucos minutos (padrão de fast flux, MITRE ATT&CK T1568.001 Dynamic Resolution: Fast Flux DNS) e — o mais forte — o processo que consulta é um binário em `\AppData\Local\Temp\`, local de execução típico de malware e não de software corporativo. Próximo passo: isolar o endpoint, coletar hash do binário, verificar Sysmon Event ID 1 (criação de processo) para saber quem lançou o executável, e Event ID 3 para as conexões de rede subsequentes.

**3.** **Falso positivo.** TTL baixo isoladamente é engenharia de disponibilidade: CDNs usam justamente isso para trocar de servidor rapidamente. Os diferenciais em relação ao caso anterior são o processo legítimo (`msedge.exe`), a baixa dispersão de IPs (2, e da mesma faixa) e a ausência de outros sinais. Documente o motivo do fechamento e considere pedir uma exceção de tuning para esse domínio.

**4.** É saída de **DoT** (DNS over TLS, TCP/853) permitida pela política — visibilidade de DNS perdida para esse host. Passos: (a) identificar no endpoint qual processo abriu a conexão (Sysmon Event ID 3 filtrando porta 853); (b) se for navegador, é configuração do usuário — tratar como desvio de política; se for processo desconhecido, tratar como possível C2 e escalar; (c) recomendar ao time de rede o bloqueio de TCP/853 na saída e o encaminhamento forçado de todo DNS ao resolver interno.

**5.** O canário `use-application-dns.net` está sendo resolvido com sucesso (NOERROR). Isso significa que o mecanismo que desliga o DoH automático do Firefox **não está ativo**: a rede deveria responder NXDOMAIN para esse nome. A consulta em si é comportamento normal do navegador. Recomendação: configurar o DNS interno para retornar NXDOMAIN nesse domínio, restaurando a visibilidade das consultas no resolver corporativo.

</details>


## Tipos de registro DNS

Pense na zona DNS de um domínio como a **agenda de contatos de uma empresa grande**. Nela não existe só o telefone das pessoas: tem o endereço do prédio, o nome do porteiro, o setor que recebe as cartas, o recado colado na porta e a lista de quem tem permissão para emitir crachá. Cada uma dessas informações fica numa linha diferente, com um rótulo próprio. No DNS, esses rótulos são os **tipos de registro** (record types).

Um registro DNS sempre tem a mesma estrutura de linha em um arquivo de zona:

```
nome    TTL   classe  tipo   valor
www     3600  IN      A      203.0.113.10
```

- **nome** — o rótulo (host) dentro do domínio. O `@` significa o próprio domínio.
- **TTL** (Time To Live, tempo de vida) — quantos segundos o resolvedor pode guardar a resposta em cache.
- **classe** — quase sempre `IN` (Internet).
- **tipo** — o que essa linha significa (A, MX, TXT...).
- **valor** — o dado em si.

Para o analista de SOC (Security Operations Center, centro de operações de segurança) nível 1, saber ler tipo por tipo é o que separa "o alerta mostra um domínio estranho" de "o alerta mostra um domínio estranho **cujo TXT tem 400 bytes de base64**, e isso é canal de comando e controle".

### A e AAAA — o endereço da casa

**O que é:** o registro **A** (Address) traduz um nome para um endereço IPv4. O **AAAA** (lê-se "quad-A") faz o mesmo para IPv6, que é quatro vezes maior — daí os quatro As.

```
www      3600 IN A     203.0.113.10
www      3600 IN AAAA  2001:db8:beef::10
```

**Consulta:**

```
nslookup -type=A www.empresa-exemplo.com.br
dig +short www.empresa-exemplo.com.br A
dig www.empresa-exemplo.com.br AAAA
```

**Como aparece nos logs** (Zeek `dns.log`, campos separados por TAB):

```
#fields ts  uid       id.orig_h    id.resp_h  proto query                          qtype_name rcode_name answers        TTLs
1725360012.441  CxT9a1  10.10.20.55  10.10.0.53  udp  www.empresa-exemplo.com.br    A          NOERROR    203.0.113.10   3600
1725360014.902  CzP4b7  10.10.20.55  10.10.0.53  udp  cdn-update.example.com        AAAA       NXDOMAIN   -              -
```

<details><summary>Ver legenda</summary>

| Campo | 1ª linha (normal) / 2ª linha (falha) | O que significa |
|---|---|---|
| `ts` | `1725360012.441` / `1725360014.902` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos |
| `uid` | `CxT9a1` / `CzP4b7` | Identificador único da conexão |
| `id.orig_h` | `10.10.20.55` | Quem perguntou: a estação |
| `id.resp_h` | `10.10.0.53` | O servidor DNS **interno** — é o que se espera; um resolvedor público aqui é fuga de política |
| `proto` | `udp` | Transporte da consulta |
| `query` | `www.empresa-exemplo.com.br` / `cdn-update.example.com` | O nome consultado |
| `qtype_name` | `A` / `AAAA` | Tipo de registro: endereço IPv4 e IPv6 |
| `rcode_name` | `NOERROR` / `NXDOMAIN` | `NOERROR` resolveu; `NXDOMAIN` significa que o nome não existe |
| `answers` | `203.0.113.10` / `-` | A resposta. Vazia (`-`) quando não houve resolução |
| `TTLs` | `3600` / `-` | Validade em cache, em segundos |

</details>


**O que o SOC N1 observa:** normal é uma estação resolver dezenas de nomes conhecidos por hora. Suspeito é o mesmo host gerando centenas de `NXDOMAIN` por minuto — sinal clássico de DGA (Domain Generation Algorithm, algoritmo gerador de domínios), técnica MITRE **T1568.002**.

**Erro comum de júnior:** achar que `AAAA` é erro de digitação e ignorar. Muito malware moderno resolve por IPv6 justamente porque o bloqueio da empresa só cobre IPv4.

### CNAME — o apelido

**O que é:** CNAME (Canonical Name, nome canônico) é um **encaminhamento de nome**, como um recado que diz "quem procura o Fulano, procure na sala do Beltrano".

```
loja     3600 IN CNAME  loja-prod.cdn-exemplo.net.
```

```
dig +short loja.empresa-exemplo.com.br CNAME
nslookup -type=CNAME loja.empresa-exemplo.com.br
```

**Relevância para o SOC:** cadeias longas de CNAME apontando para domínios recém-registrados são típicas de *domain fronting* e de sequestro de subdomínio (**subdomain takeover**): o CNAME aponta para um recurso de nuvem que a empresa já apagou, e um terceiro registra aquele recurso e passa a servir conteúdo em nome da empresa.

### MX — a caixa de correio

**O que é:** MX (Mail Exchanger, trocador de correio) diz para quem entregar e-mail daquele domínio. Tem um número de **prioridade** — menor número é tentado primeiro.

```
@        3600 IN MX  10 mx1.empresa-exemplo.com.br.
@        3600 IN MX  20 mx2.empresa-exemplo.com.br.
```

```
dig +short empresa-exemplo.com.br MX
nslookup -type=MX empresa-exemplo.com.br
```

**Relevância:** em investigação de phishing, o MX do domínio remetente diz se aquele domínio realmente recebe e-mail. Domínio de phishing muitas vezes tem MX apontando para provedor gratuito ou não tem MX nenhum.

### TXT — o mural de recados (e o disfarce preferido do atacante)

**O que é:** TXT guarda texto livre. Como aceita qualquer coisa, virou o lugar onde o mundo colou três mecanismos de segurança de e-mail — e onde atacantes escondem dados.

#### SPF (Sender Policy Framework)

Lista **quais servidores podem enviar** e-mail em nome do domínio. É a portaria dizendo "só entrega carta assinada por estes carteiros".

```
@   3600 IN TXT "v=spf1 ip4:203.0.113.20 include:_spf.provedor-exemplo.net -all"
```

`ip4:` autoriza um IP, `include:` importa a lista de outro domínio, `-all` (hard fail) manda rejeitar todo o resto. `~all` é *softfail* — apenas marca.

#### DKIM (DomainKeys Identified Mail)

É a **assinatura digital** da mensagem. O servidor de envio assina o e-mail com uma chave privada; a chave pública fica publicada em um TXT no seletor.

```
sel2025._domainkey  3600 IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."
```

`sel2025` é o **seletor**, escrito no cabeçalho `DKIM-Signature: ... s=sel2025; d=empresa-exemplo.com.br`. Se o conteúdo foi alterado no caminho, a assinatura quebra.

#### DMARC (Domain-based Message Authentication, Reporting and Conformance)

É a **política**: o que fazer quando SPF e DKIM falham, e para onde mandar relatório.

```
_dmarc  3600 IN TXT "v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:dmarc@empresa-exemplo.com.br"
```

`p=` é a política do domínio (`none` só observa, `quarantine` manda para spam, `reject` rejeita), `sp=` é para subdomínios, `rua=` é o endereço dos relatórios agregados.

```
dig +short _dmarc.empresa-exemplo.com.br TXT
dig +short sel2025._domainkey.empresa-exemplo.com.br TXT
nslookup -type=TXT _dmarc.empresa-exemplo.com.br
```

**TXT como canal de C2 (comando e controle):** como o TXT devolve texto arbitrário e quase ninguém bloqueia DNS, malware usa consultas TXT para receber comandos e exfiltrar dados codificados em base64 — MITRE **T1071.004** (Application Layer Protocol: DNS) e **T1048** (exfiltração por canal alternativo).

```
1725360220.118  CjK2m9  10.10.20.55  10.10.0.53  udp  aG9zdG5hbWU9V0swMTIz.c2.example.com  TXT  NOERROR  "R1VJRDo5OTk7Q01EOnNsZWVw"  60
1725360221.004  CjK2m9  10.10.20.55  10.10.0.53  udp  bWVtPTE2Ry51c2Vy.c2.example.com      TXT  NOERROR  "T0s="                      60
```

**Normal vs suspeito:** normal é um punhado de TXT por dia (validação de domínio, SPF). Suspeito é TXT repetitivo, TTL baixíssimo (60 ou menos), subdomínio longo em base64 e sempre o mesmo domínio-pai.

**Erro comum de júnior:** ver `NOERROR` e fechar o alerta como benigno. `NOERROR` só diz que a resposta veio — não diz que era legítima.

### PTR — a lista telefônica ao contrário

**O que é:** PTR (Pointer, ponteiro) faz o caminho inverso: dado um IP, devolve um nome. Fica em uma zona especial, `in-addr.arpa` (IPv4) ou `ip6.arpa` (IPv6), com os octetos invertidos.

O IP `203.0.113.10` vira `10.113.0.203.in-addr.arpa`.

```
10   3600 IN PTR  www.empresa-exemplo.com.br.
```

```
nslookup 203.0.113.10
dig +short -x 203.0.113.10
```

**Por que enriquece um alerta:** um alerta de firewall traz um IP cru. O PTR transforma `10.10.20.55` em `NB-JSILVA-01.corp.local` — em dois segundos você sabe **de quem é a máquina** sem abrir o inventário. Cuidado: o PTR é definido pelo dono do bloco de IP, então em IP externo ele é uma **pista**, não uma prova.

### NS e SOA — quem manda na zona

**NS** (Name Server) lista os servidores autoritativos do domínio. **SOA** (Start of Authority, início de autoridade) é a "certidão" da zona: servidor primário, e-mail do responsável e os temporizadores.

```
@   3600 IN NS   ns1.empresa-exemplo.com.br.
@   3600 IN NS   ns2.empresa-exemplo.com.br.
@   3600 IN SOA  ns1.empresa-exemplo.com.br. hostmaster.empresa-exemplo.com.br. (
                 2026090301 ; serial
                 7200       ; refresh
                 3600       ; retry
                 1209600    ; expire
                 3600 )     ; minimum TTL
```

```
dig empresa-exemplo.com.br NS +short
dig empresa-exemplo.com.br SOA
nslookup -type=SOA empresa-exemplo.com.br
```

**Relevância:** mudança inesperada de NS é sequestro de domínio. O **serial** do SOA subindo fora de janela de mudança indica alteração não autorizada na zona.

### SRV — onde mora o serviço (e como o Windows acha o domínio)

**O que é:** SRV (Service) diz **em qual host e porta** um serviço roda. O nome segue o formato `_servico._protocolo.dominio`, e o valor traz prioridade, peso, porta e alvo.

```
_ldap._tcp.dc._msdcs.corp.local. 600 IN SRV 0 100 389 dc01.corp.local.
_kerberos._tcp.corp.local.       600 IN SRV 0 100 88  dc01.corp.local.
```

Esse primeiro registro é **o mais importante do Active Directory**: é por ele que a estação Windows descobre qual é o controlador de domínio antes de autenticar. Se ele sumir ou apontar para o host errado, o parque inteiro para de logar.

```
nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.local
dig _ldap._tcp.dc._msdcs.corp.local SRV
```

**Relevância para o SOC:** ferramentas de reconhecimento de AD (BloodHound, Impacket) consultam esses SRV logo no início. Uma estação comum consulta `_ldap._tcp` de vez em quando; um host varrendo **todos** os SRV de `_msdcs` em segundos é enumeração — MITRE **T1018**.

### CAA — quem pode emitir certificado

**O que é:** CAA (Certification Authority Authorization) lista as autoridades certificadoras autorizadas a emitir certificado TLS para o domínio.

```
@  3600 IN CAA 0 issue "ca-exemplo.net"
@  3600 IN CAA 0 iodef "mailto:soc@empresa-exemplo.com.br"
```

```
dig +short empresa-exemplo.com.br CAA
```

**Relevância:** certificado emitido por CA fora da lista CAA é forte indício de emissão fraudulenta.

### NULL e ANY — os coringas do tunneling

**NULL** aceita qualquer sequência de bytes e por isso é o tipo favorito de ferramentas de **DNS tunneling** (encapsular tráfego dentro de consultas DNS). **ANY** pedia todos os registros de uma vez; hoje muitos servidores respondem `NOTIMP` ou uma resposta mínima, justamente porque `ANY` era usado para amplificação em ataques de negação de serviço. Ver `qtype_name` igual a `NULL` no `dns.log` de uma estação de escritório é anormal por definição — nenhum aplicativo corporativo comum pede NULL.

### Tabela-resumo dos tipos

| Tipo | Número | Para que serve | Valor típico | Sinal de alerta no SOC |
|---|---|---|---|---|
| A | 1 | Nome → IPv4 | `203.0.113.10` | Muitos NXDOMAIN (DGA), TTL baixíssimo (fast flux) |
| AAAA | 28 | Nome → IPv6 | `2001:db8::10` | Saída por IPv6 fora de política de bloqueio |
| CNAME | 5 | Apelido de nome | `alvo.example.com.` | Cadeia longa, alvo de nuvem órfão (takeover) |
| MX | 15 | Servidor de e-mail | `10 mx1...` | Domínio de phishing sem MX ou em provedor gratuito |
| TXT | 16 | Texto livre (SPF/DKIM/DMARC) | `"v=spf1 ..."` | Base64 longo, TTL 60, C2 (T1071.004) |
| PTR | 12 | IP → nome (`in-addr.arpa`) | `host.corp.local.` | Enriquecimento; ausência em IP interno |
| NS | 2 | Servidores autoritativos | `ns1...` | Troca inesperada = sequestro de domínio |
| SOA | 6 | Certidão da zona | serial + timers | Serial alterado fora de janela |
| SRV | 33 | Serviço, host e porta | `0 100 389 dc01...` | Varredura de `_msdcs` (T1018) |
| CAA | 257 | CAs autorizadas | `0 issue "ca..."` | Certificado emitido por CA fora da lista |
| NULL | 10 | Bytes arbitrários | binário | Praticamente sempre tunneling |
| ANY | 255 | Pedia tudo | — | Amplificação / reconhecimento |

### Arquivo de zona completo comentado

```dns
$TTL 3600                                  ; TTL padrão: 1 hora
$ORIGIN empresa-exemplo.com.br.            ; tudo sem ponto final recebe este sufixo

@   IN SOA ns1.empresa-exemplo.com.br. hostmaster.empresa-exemplo.com.br. (
        2026090301  ; serial — sobe a cada alteração (AAAAMMDDnn)
        7200        ; refresh — de quanto em quanto o secundário confere
        3600        ; retry — espera antes de tentar de novo se falhar
        1209600     ; expire — quando o secundário desiste da zona (14 dias)
        3600 )      ; minimum — TTL de resposta negativa (NXDOMAIN)

@       IN NS    ns1.empresa-exemplo.com.br.   ; servidor autoritativo primário
@       IN NS    ns2.empresa-exemplo.com.br.   ; secundário
ns1     IN A     203.0.113.2                   ; glue do primário
ns2     IN A     198.51.100.2                  ; glue do secundário

@       IN A     203.0.113.10                  ; site no domínio raiz
www     IN A     203.0.113.10                  ; mesmo IP do raiz
www     IN AAAA  2001:db8:beef::10             ; versão IPv6 do site
loja    IN CNAME loja-prod.cdn-exemplo.net.    ; apelido para o CDN

@       IN MX 10 mx1.empresa-exemplo.com.br.   ; correio principal
@       IN MX 20 mx2.empresa-exemplo.com.br.   ; correio reserva
mx1     IN A     203.0.113.20
mx2     IN A     198.51.100.20

@       IN TXT   "v=spf1 ip4:203.0.113.20 include:_spf.provedor-exemplo.net -all"
_dmarc  IN TXT   "v=DMARC1; p=reject; rua=mailto:dmarc@empresa-exemplo.com.br"
sel2025._domainkey IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkq...AQAB"

@       IN CAA 0 issue "ca-exemplo.net"        ; só esta CA pode emitir
@       IN CAA 0 iodef "mailto:soc@empresa-exemplo.com.br" ; avisar o SOC

_sip._tcp  IN SRV 10 60 5060 sbc01.empresa-exemplo.com.br. ; telefonia
```

### Caçando por tipo de registro

```spl
index=zeek sourcetype=zeek:dns qtype_name IN ("TXT","NULL")
| eval sub=mvindex(split(query,"."),0)
| eval tam=len(sub)
| where tam > 30
| stats count, dc(query) as nomes_unicos, values(qtype_name) as tipos by id.orig_h
| where count > 50
```

Linha 1 filtra só TXT e NULL. Linha 2 pega o rótulo mais à esquerda. Linha 3 mede o tamanho. Linha 4 mantém rótulos longos (sinal de dado codificado). Linha 5 agrupa por host de origem. Linha 6 corta o ruído.

```kql
// Sentinel/Defender — enumeração de SRV do Active Directory
DnsEvents
| where TimeGenerated > ago(1h)                       // janela de 1 hora
| where QueryType in ("SRV")                          // só consultas de serviço
| where Name has "_msdcs" or Name startswith "_ldap"  // nomes de infraestrutura AD
| summarize Consultas = count(), Distintos = dcount(Name) by ClientIP
| where Distintos > 15                                // host varrendo muitos SRV
| order by Distintos desc
```

### Exercícios — Tipos de registro DNS

1. Escreva o nome de consulta PTR correspondente ao IP `198.51.100.77` e o comando `dig` que o resolve.
2. O domínio `empresa-exemplo.com.br` tem `v=spf1 ip4:203.0.113.20 -all` e `p=reject` no DMARC. Chega um e-mail de `financeiro@empresa-exemplo.com.br` entregue pelo IP `192.0.2.99`, sem DKIM válido. O que deveria ter acontecido com a mensagem?
3. Leia o log e decida: verdadeiro ou falso positivo?

```
1725363001.220 Cq1  10.10.20.55 10.10.0.53 udp  d3JrPTAx.tun.example.com  NULL NOERROR - 60
1725363001.910 Cq2  10.10.20.55 10.10.0.53 udp  bWVtPTE2.tun.example.com  NULL NOERROR - 60
1725363002.640 Cq3  10.10.20.55 10.10.0.53 udp  dXNyPWpz.tun.example.com  NULL NOERROR - 60
```

4. Um alerta traz apenas o IP interno `10.10.20.55`. Qual tipo de registro você consulta primeiro para saber de qual máquina se trata, e qual o comando?
5. Uma estação consultou `_ldap._tcp.dc._msdcs.corp.local` três vezes em 8 horas. Isso é enumeração de Active Directory? Qual o próximo passo?

<details><summary>Ver gabarito</summary>

**1.** Inverte-se a ordem dos octetos e acrescenta-se o sufixo da zona reversa: `77.100.51.198.in-addr.arpa`. Comando: `dig +short -x 198.51.100.77` (o `-x` monta esse nome automaticamente) ou `dig +short 77.100.51.198.in-addr.arpa PTR`.

**2.** O SPF falha (o IP `192.0.2.99` não está autorizado e a política é `-all`, hard fail) e o DKIM também falha. Com DMARC `p=reject`, o servidor destinatário deveria **rejeitar** a mensagem. Se ela foi entregue na caixa do usuário, o problema não é o DNS: é o gateway de e-mail não estar aplicando DMARC. Isso vira um achado de configuração, além do incidente de phishing.

**3.** Verdadeiro positivo, com altíssima confiança. Três indicadores somados: tipo **NULL** (nenhum aplicativo corporativo legítimo consulta NULL), rótulo à esquerda em base64 curto e variável a cada consulta, e **TTL 60** para impedir cache — o atacante precisa que toda consulta chegue ao servidor autoritativo dele. O padrão é DNS tunneling / exfiltração (T1071.004 e T1048). Próximo passo: isolar `10.10.20.55`, bloquear `tun.example.com` e o domínio-pai no DNS interno, e levantar o processo de origem via Sysmon Event ID 22 (DNS query) para saber qual binário fez as consultas.

**4.** Consulta **PTR** (reversa), pois traduz IP em nome de host: `nslookup 10.10.20.55` ou `dig +short -x 10.10.20.55`. Se a zona reversa interna estiver populada, isso devolve algo como `NB-JSILVA-01.corp.local` e já indica o usuário provável. Se não houver PTR, o caminho alternativo é o lease do servidor DHCP ou o inventário. Atenção: em IP externo o PTR é pista, não prova, porque é o dono do bloco quem o define.

**5.** Não. Três consultas em 8 horas é comportamento **normal** de qualquer estação ingressada no domínio — é assim que o Windows localiza o controlador de domínio (renovação de tíquete, mudança de rede, reinício). Enumeração se caracteriza por **volume e variedade**: dezenas de nomes distintos sob `_msdcs` em poucos segundos. Próximo passo: fechar como falso positivo, mas antes ajustar a regra para exigir contagem de nomes distintos (como no KQL acima, `Distintos > 15`) em vez de disparar por qualquer consulta SRV.

</details>


## Ataques que usam DNS

O DNS (Domain Name System, ou Sistema de Nomes de Domínio) é a lista telefônica da internet — e, como toda lista telefônica, dá para adulterar as páginas, usar o serviço de informações como canal de recados ou simplesmente ligar tantas vezes que a central cai. Nesta seção vamos ver os ataques que o analista de SOC (Security Operations Center, o centro de operações de segurança) N1 encontra na prática, sempre com a mesma espinha: o que é, como funciona, exemplo, log, o que observar e o erro típico de quem está começando.

Um lembrete importante: quase todo ataque aqui é detectado nos logs de resolução que você aprendeu a ler antes. O que muda é **o padrão**, não o campo.

### DNS spoofing e cache poisoning

**O que é.** Imagine alguém que troca o número do seu banco na agenda telefônica do prédio inteiro. Você disca certo, mas cai no golpista. Isso é *spoofing* de DNS: o atacante entrega uma resposta falsa para uma consulta legítima. Quando essa resposta falsa fica **guardada** no cache do resolvedor, todo mundo que usa aquele resolvedor é envenenado junto — é o *cache poisoning* (envenenamento de cache).

**Como funciona.** O DNS clássico usa UDP porta 53, sem criptografia e sem autenticação. Quem responder primeiro com o Transaction ID (identificador da transação) correto e a porta de origem certa vence. O atacante na mesma rede (ou capaz de adivinhar esses valores) responde antes do servidor real. É a técnica T1557 (Adversary-in-the-Middle) e T1584.002 no MITRE ATT&CK.

**Exemplo.** Na rede 10.10.20.0/24, o notebook de `jsilva` pergunta por `portal.empresa-exemplo.com.br`. O resolvedor legítimo devolveria 203.0.113.20; o atacante devolve 198.51.100.77, um servidor de captura de credenciais.

**Como aparece no log.** Zeek `dns.log`, duas respostas para a mesma consulta:

```
#fields ts  uid         id.orig_h    id.resp_h   proto query                              qtype_name rcode_name answers        TTL
1725372011.204 CJ8xk1  10.10.20.55  10.10.10.5  udp   portal.empresa-exemplo.com.br      A          NOERROR    203.0.113.20   3600
1725372011.209 CJ8xk1  10.10.20.55  10.10.10.5  udp   portal.empresa-exemplo.com.br      A          NOERROR    198.51.100.77  30
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `ts` | `1725372011.204` e `1725372011.209` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos. **Repare nos 5 milissegundos de diferença** entre as duas linhas |
| `uid` | `CJ8xk1` | O **mesmo** identificador nas duas linhas: é uma única consulta com duas respostas — o coração do problema |
| `id.orig_h` | `10.10.20.55` | Quem perguntou |
| `id.resp_h` | `10.10.10.5` | O resolvedor consultado |
| `proto` | `udp` | DNS sobre UDP não tem sessão: qualquer um que chegue primeiro com o `trans_id` certo é aceito |
| `query` | `portal.empresa-exemplo.com.br` | O nome consultado, idêntico nas duas |
| `qtype_name` | `A` | Registro de endereço IPv4 |
| `rcode_name` | `NOERROR` | As duas respostas dizem "resolvi com sucesso" |
| `answers` | `203.0.113.20` / `198.51.100.77` | **Dois IPs diferentes para o mesmo nome.** A segunda resposta é a forjada |
| `TTL` | `3600` / `30` | Validade em cache. O TTL curto da resposta falsa é deliberado: o atacante quer que o cliente volte a perguntar logo, para reenvenenar |

</details>


**O que o N1 observa.** Normal: uma resposta por consulta, TTL coerente com o domínio. Suspeito: **duas respostas** para o mesmo `uid`, TTL absurdamente baixo (30 segundos num domínio que sempre usa 3600) e um IP de resposta que nunca apareceu no histórico daquele domínio.

**Erro comum de júnior.** Achar que TTL baixo é sempre ataque. CDNs (Content Delivery Networks, redes de entrega de conteúdo) usam TTL de 30 a 60 segundos o tempo todo. O sinal é a *mudança* de comportamento, não o valor isolado.

### DNS hijacking: registrador e resolvedor do roteador

**O que é.** Em vez de mentir na resposta, o atacante muda a fonte da verdade. Duas variantes: (1) invade a conta no **registrador** de domínio e troca os servidores autoritativos; (2) invade o **roteador** do escritório ou da casa do funcionário e troca o resolvedor DHCP.

**Exemplo.** O roteador da filial passa a entregar por DHCP o DNS 198.51.100.44 em vez do 10.10.10.5 corporativo. Todo o tráfego de nomes da filial passa pelo atacante.

**Como aparece no log.** FortiGate, formato chave=valor:

```
date=2026-09-03 time=09:12:44 devname="FGT-FILIAL-01" type="traffic" subtype="forward" srcip=10.10.30.61 srcport=51422 dstip=198.51.100.44 dstport=53 proto=17 action="accept" service="DNS" sentbyte=78 rcvdbyte=142 policyid=12
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `date` | `2026-09-03` | Data local **do equipamento**, não UTC. Correlacionar com um log em UTC sem acertar o fuso desalinha a timeline |
| `time` | `09:12:44` | Hora local do equipamento |
| `devname` | `"FGT-FILIAL-01"` | Nome do equipamento que gerou o log |
| `type` | `"traffic"` | Categoria do log: `traffic` é sessão, `event` é evento do próprio aparelho, `utm` é inspeção de conteúdo |
| `subtype` | `"forward"` | Subcategoria: `forward` é tráfego que atravessa, `local` é destinado ao próprio firewall, `vpn` é túnel, `webfilter` e `ips` são inspeção |
| `srcip` | `10.10.30.61` | IP de origem |
| `srcport` | `51422` | Porta de origem, efêmera e sorteada pelo cliente |
| `dstip` | `198.51.100.44` | IP de destino |
| `dstport` | `53` | Porta de destino — é ela que aponta o serviço |
| `proto` | `17` | Número do protocolo IP: **`6` é TCP, `17` é UDP, `1` é ICMP**. Vem em número, não em nome |
| `action` | `"accept"` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |
| `service` | `"DNS"` | Nome do **objeto de serviço** do FortiGate, não a porta literal. Um objeto chamado `HTTPS` pode ter sido configurado noutra porta |
| `sentbyte` | `78` | Bytes enviados **pela origem**. O ponto de vista é o da origem, não do firewall |
| `rcvdbyte` | `142` | Bytes recebidos pela origem. **Comparar com `sentbyte` é o que revela exfiltração** |
| `policyid` | `12` | **Número da regra que decidiu.** Sem ele não se sabe por que o tráfego passou ou parou |

</details>

Campos: `srcip` é a estação; `dstip` é para onde ela mandou DNS; `proto=17` é UDP; `dstport=53` é DNS.

**O que o N1 observa.** Normal: 100% das consultas vão para os resolvedores internos aprovados. Suspeito: qualquer host falando porta 53 com IP externo — a política deveria bloquear. Some a isso mudança de NS (Name Server) no domínio da empresa.

**Erro comum de júnior.** Fechar o caso como "usuário configurou 8.8.8.8 na mão". Pode ser — mas confirme, porque o mesmo padrão é a assinatura de roteador comprometido (T1584.001).

### DNS tunneling em detalhe

**O que é.** Se todo o resto está bloqueado, o DNS quase sempre passa. O atacante então usa o DNS como cano: encapsula dados dentro dos nomes consultados e das respostas. É como mandar um livro inteiro escrevendo uma letra por cartão-postal endereçado ao mesmo bairro. Ferramentas conhecidas: **iodine** (túnel IP sobre DNS) e **dnscat2** (canal de comando e controle). MITRE T1071.004 (C2 sobre DNS) e T1048.003 (exfiltração).

**Como funciona.** O atacante controla o autoritativo de `tunel.example.com`. O malware consulta `<dados-codificados>.tunel.example.com`; a resposta em TXT ou NULL carrega o retorno. Cada consulta é um pacote.

**Exemplo.** A estação 10.10.20.88 do usuário `maria.costa` faz 4.200 consultas em 12 minutos, todas terminando em `.tunel.example.com`.

**Como aparece no log.** Zeek `dns.log`:

```
ts=1725375600.117 id.orig_h=10.10.20.88 query=k3j9fq0zx1mn4bvc7lp2ad8s.tunel.example.com qtype_name=TXT rcode_name=NOERROR
ts=1725375600.402 id.orig_h=10.10.20.88 query=p0w8e7r5t4y3u2i1o9a8s7d6.tunel.example.com qtype_name=TXT rcode_name=NOERROR
ts=1725375600.688 id.orig_h=10.10.20.88 query=zq2xw3ce4vr5bt6ny7mu8il9.tunel.example.com qtype_name=NULL rcode_name=NOERROR
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `ts` | `1725375600.117`, `.402`, `.688` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos. Três consultas em menos de 600 ms do mesmo cliente |
| `id.orig_h` | `10.10.20.88` | Sempre a mesma estação — é ela que carrega o túnel |
| `query` | `k3j9fq0zx1mn4bvc7lp2ad8s.tunel.example.com` | O nome consultado. **O subdomínio é o dado**: 24 caracteres de lixo aparente que na verdade são o payload codificado, e o domínio-pai (`tunel.example.com`) é o servidor do atacante |
| `qtype_name` | `TXT`, `TXT`, `NULL` | `TXT` carrega texto livre e `NULL` dados arbitrários — os dois tipos preferidos para tunelamento, porque cabem muito mais bytes que um `A` |
| `rcode_name` | `NOERROR` | Todas resolveram: o domínio existe e o servidor do atacante está respondendo |

</details>

**Limiares práticos.** Use estes números como ponto de partida e ajuste ao seu ambiente:

| Indicador | Normal | Suspeito |
|---|---|---|
| Tamanho médio da consulta | 20 a 35 caracteres | acima de 50; rótulo único com mais de 40 caracteres |
| Entropia de Shannon do subdomínio | 2,5 a 3,5 bits/caractere | acima de 4,0 |
| Consultas por host para o mesmo domínio pai/hora | menos de 50 | acima de 500 (alto risco acima de 1.000) |
| Percentual de TXT/NULL no total do host | menos de 2% | acima de 15% |
| Subdomínios únicos sob o mesmo pai/dia | dezenas | milhares |
| Razão bytes de consulta / bytes de resposta | ~1:3 (pergunta curta, resposta maior) | próximo de 1:1 ou invertido |

Consulta SPL (Splunk) para caçar volume por domínio pai:

````spl
index=dns sourcetype=zeek:dns
| eval parent=mvindex(split(query,"."), -2) + "." + mvindex(split(query,"."), -1)   ``` monta o domínio pai (ex.: example.com) ```
| eval qlen=len(query)                                                              ``` tamanho da consulta em caracteres ```
| stats count AS consultas, dc(query) AS subdominios_unicos, avg(qlen) AS tam_medio BY id.orig_h, parent
| where consultas > 500 AND subdominios_unicos > 300 AND tam_medio > 50            ``` os três sinais juntos ```
| sort - consultas
````

**Erro comum de júnior.** Marcar como túnel qualquer domínio com subdomínio estranho. Antivírus, telemetria de EDR e serviços de reputação usam subdomínios longos e aleatórios de forma **legítima** — é a base do falso positivo típico aqui. Verifique o domínio pai antes de escalar.

### DGA — Domain Generation Algorithm

**O que é.** DGA (Algoritmo de Geração de Domínios) é o malware que sorteia centenas de nomes por dia e tenta cada um até achar o que o dono registrou. Derrubar um domínio não mata o canal. Famílias clássicas: Conficker e Emotet. MITRE T1568.002.

**Como funciona.** Como a maioria dos nomes sorteados não existe, o host gera uma **rajada de NXDOMAIN** (resposta "domínio não existe").

**Como aparece no log.** Suricata EVE JSON:

```json
{"timestamp":"2026-09-03T10:04:12.331+0000","event_type":"dns","src_ip":"10.10.40.77","dns":{"type":"answer","rrname":"qkzvbnrtwsxdplm.info","rcode":"NXDOMAIN"}}
{"timestamp":"2026-09-03T10:04:12.512+0000","event_type":"dns","src_ip":"10.10.40.77","dns":{"type":"answer","rrname":"mzxcvbnqwertyup.biz","rcode":"NXDOMAIN"}}
```

Caça em KQL (Microsoft Sentinel/Defender), contando NXDOMAIN por host:

```kql
DnsEvents
| where TimeGenerated > ago(1h)                       // janela de uma hora
| where ResultCode == 3                               // 3 = NXDOMAIN
| summarize nx = count(), dominios = dcount(Name) by ClientIP   // conta falhas e nomes distintos
| where nx > 200 and dominios > 150                   // rajada com pouca repetição = DGA
| order by nx desc
```

**Normal vs suspeito.** Uma estação saudável gera de 5 a 30 NXDOMAIN por hora (erro de digitação, sufixo de busca). Acima de 200 por hora, com nomes distintos e sem sentido, é DGA.

**Erro comum de júnior.** Confundir com sufixo de busca DHCP mal configurado, que gera NXDOMAIN em massa para nomes internos como `impressora.corp.local.corp.local`. Se os nomes são pronunciáveis e internos, é configuração, não malware.

### Fast Flux, Double Flux e domain shadowing

**Fast Flux** é o domínio que troca de IP a cada poucos minutos, usando TTL de 60 segundos e dezenas de endereços diferentes num dia. **Double Flux** troca também os servidores NS. **Domain shadowing** (T1584.001) é o atacante que, tendo roubado a conta do registrador de uma empresa legítima, cria subdomínios como `wm3.empresa-exemplo.com.br` sem tocar no site principal — herda a boa reputação do domínio pai.

Sinal para o N1: mais de 10 endereços A distintos para o mesmo nome em uma hora, TTL de 60 ou menos e IPs em países e provedores sem relação entre si. Falso positivo: balanceadores globais e CDNs fazem exatamente isso — a diferença é que os IPs de uma CDN pertencem a um punhado de ASNs conhecidos.

### NXDOMAIN flood, DNS water torture e amplificação

**NXDOMAIN flood** e **DNS water torture** (também chamado *random subdomain attack*) atacam o servidor: milhares de consultas a subdomínios inexistentes forçam o resolvedor a perguntar ao autoritativo, esgotando cache e conexões. Se o alvo é o domínio da sua empresa, seus próprios clientes ficam sem resolver.

**Amplificação DDoS** usa o DNS ao contrário: o atacante forja o IP de origem da vítima e consulta um resolvedor aberto com `ANY` ou `DNSKEY`. Uma pergunta de 60 bytes vira uma resposta de 3.000 bytes — fator de amplificação em torno de 50x. Se o seu resolvedor for aberto, você é o cúmplice, não a vítima (T1498.002).

```
%ASA-4-733100: [ Scanning ] drop rate-1 exceeded. Current burst rate is 3200 per second, max configured rate is 100
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `%ASA` | `%ASA` | Etiqueta do produto: identifica a linha como vinda de um firewall ASA |
| severidade | `4` | Escala syslog do Cisco, de 0 (emergência) a 7 (depuração): `4` é **warning**. **Severidade baixa não quer dizer evento sem importância** — quem a escolhe é o fabricante, não o seu SOC |
| *message ID* | `733100` | Limiar de detecção de varredura excedido. **É por este número que se escreve a regra no SIEM**: o texto da mensagem muda entre versões do software, o ID não |
| `[ Scanning ]` | `Scanning` | **Qual detector disparou.** O ASA tem vários (`Scanning`, `Bad Pkts`, `Firewall`, `ICMP`); este conta hosts e portas distintos por origem |
| `drop rate-1 exceeded` | `rate-1` | O ASA mantém **vários intervalos de média** (`rate-1`, `rate-2`...) com limiares próprios. `rate-1` é o mais curto — é ele que pega rajadas |
| `Current burst rate` | `3200 per second` | A taxa medida no momento |
| `max configured rate` | `100` | O limiar configurado. **3200 contra 100: 32 vezes acima** |
| — | — | Esta mensagem diz que o *limiar* foi cruzado, **não quem foi**. Para achar a origem é preciso o `show threat-detection` ou os logs de conexão do mesmo intervalo |

</details>

**O que o N1 observa.** Tráfego UDP/53 de **entrada** vindo da internet para um servidor interno, respostas muito maiores que perguntas e um único IP alvo repetido. Falso positivo: pico legítimo em campanha de marketing ou lançamento.

### Typosquatting, homoglifos, punycode e NRD

**Typosquatting** é registrar `empresa-exemplo.com.br` com uma letra trocada. **Homoglifos** usam caracteres de outro alfabeto que parecem idênticos (o "а" cirílico no lugar do "a" latino). Esses nomes viajam na rede em **punycode**, com o prefixo `xn--`:

```
2026-09-03 11:22:03 10.10.20.55 GET https://xn--empresa-xemplo-2nb.com/login 200 "Mozilla/5.0" category=newly_registered_domain action=blocked
```

**NRD** (Newly Registered Domain, domínio registrado recentemente) é qualquer domínio com menos de 30 dias de vida. São suspeitos porque campanhas de phishing e infraestrutura de C2 (comando e controle) usam domínios descartáveis, criados dias antes. Regra prática: NRD com menos de 7 dias acessado por um único host, logo após um e-mail, é prioridade alta.

**Erro comum de júnior.** Bloquear todo `xn--` sem olhar. Domínios brasileiros e europeus legítimos com acento (`ação`, `münchen`) também viram `xn--`. O que importa é a **semelhança visual com uma marca sua**.

### Sinkholing

**Sinkhole** (sumidouro) é a defesa: o resolvedor da empresa responde a domínios maliciosos conhecidos com um IP interno controlado, por exemplo 10.10.99.9. O malware "liga" e cai no seu servidor de captura. Toda conexão para o IP de sinkhole é, na prática, um host infectado com nome e sobrenome. Não é alerta de rede sob ataque — é lista de máquinas a limpar.

### Exercícios — Ataques que usam DNS

1. Um host fez 1.800 consultas em uma hora para subdomínios de `cdn-metrics.example.com`, tamanho médio de consulta de 68 caracteres, 96% do tipo TXT. Quantos dos seis indicadores da tabela de tunelamento estão estourados e qual é sua conclusão preliminar?
2. Leia o log e diga o que está errado:
```
ts=1725379000.10 id.orig_h=10.10.20.55 id.resp_h=10.10.10.5 query=intranet.corp.local qtype_name=A rcode_name=NOERROR answers=10.10.15.40 TTL=3600
ts=1725379200.44 id.orig_h=10.10.20.55 id.resp_h=198.51.100.44 query=intranet.corp.local qtype_name=A rcode_name=NOERROR answers=198.51.100.90 TTL=60
```

<details><summary>Ver legenda</summary>

| Campo | 1ª linha / 2ª linha | O que significa |
|---|---|---|
| `ts` | `1725379000.10` / `1725379200.44` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos — as duas consultas distam pouco mais de 3 minutos |
| `id.orig_h` | `10.10.20.55` | A mesma estação nas duas |
| `id.resp_h` | `10.10.10.5` / `198.51.100.44` | **O resolvedor mudou**: primeiro o DNS interno, depois um servidor externo |
| `query` | `intranet.corp.local` | O mesmo nome interno nas duas — e `.corp.local` não deveria ser perguntado fora |
| `qtype_name` | `A` | Registro de endereço |
| `rcode_name` | `NOERROR` | As duas responderam com sucesso, o que é o mais grave da segunda |
| `answers` | `10.10.15.40` / `198.51.100.90` | A resposta interna é privada; a externa aponta para um IP público |
| `TTL` | `3600` / `60` | Validade em cache; o TTL curto na segunda é padrão de infraestrutura efêmera |

</details>

3. Alerta: "Possível DGA — host 10.10.40.12 com 640 NXDOMAIN na última hora". Investigando, os nomes são `srv-financeiro.corp.local.corp.local` e similares. Verdadeiro ou falso positivo? Justifique.
4. Uma consulta DNS de 60 bytes gerou resposta de 3.000 bytes. Qual o fator de amplificação e qual é o próximo passo do N1?
5. O SIEM mostra 30 estações conectando ao IP 10.10.99.9 na porta 80. Esse IP é o sinkhole corporativo. Qual é o próximo passo?

<details><summary>Ver gabarito</summary>

1. **Quatro de seis** indicadores estourados: tamanho médio 68 (limiar 50), volume 1.800/hora (limiar 500), 96% de TXT (limiar 15%) e provavelmente entropia alta. Faltam confirmar entropia medida e subdomínios únicos. Conclusão preliminar: **forte suspeita de tunelamento DNS**. Mas atenção ao falso positivo clássico: o nome `cdn-metrics` sugere telemetria legítima. Próximo passo obrigatório antes de escalar: verificar quem é o dono do domínio pai, se ele está na lista de fornecedores aprovados e se **outros** hosts também consultam. Um único host = suspeito; a frota inteira = produto legítimo.

2. Duas anomalias combinadas. Primeiro, um nome **interno** (`corp.local`) foi resolvido por um servidor **externo** (198.51.100.44) — jamais deveria sair da rede. Segundo, a resposta mudou de um IP privado válido (10.10.15.40) para um IP público com TTL despencando de 3600 para 60. Isso é **DNS hijacking** do resolvedor da estação ou do roteador. Ação: isolar o host, verificar a configuração de DNS da interface e o DHCP do segmento.

3. **Falso positivo.** O sufixo `corp.local` aparece duplicado — sintoma clássico de lista de sufixos de busca (DNS search suffix) mal configurada via DHCP ou de aplicação que concatena o domínio duas vezes. Nomes de DGA são impronunciáveis e usam TLDs externos (.info, .biz, .top). O sinal decisivo é a **legibilidade** e o fato de serem nomes internos. Encaminhe para a equipe de infraestrutura ajustar o DHCP, não para resposta a incidentes.

4. Fator = 3.000 ÷ 60 = **50x**. Próximo passo: confirmar se o servidor consultado é um **resolvedor aberto** da sua organização (respondendo a consultas recursivas vindas da internet). Se for, a empresa está sendo usada como refletor num ataque contra terceiros. Ação: restringir recursão a redes internas e ativar limitação de taxa de resposta no servidor DNS. Verifique também se o IP de origem das consultas é sempre o mesmo — indício de que ele é a vítima real.

5. Sinkhole não é um ataque em andamento contra a rede: é a **lista de máquinas infectadas**. Cada uma das 30 estações tentou falar com um domínio malicioso conhecido e foi desviada. Próximo passo: extrair o nome do domínio que cada host tentou resolver (o `query` no log de DNS logo antes da conexão), identificar a família de malware, cruzar com o EDR para achar o processo responsável e abrir um incidente de contenção por host. Trate volume de 30 máquinas como possível surto, não como 30 casos isolados.

</details>


## Como investigar DNS no SOC

Investigar DNS é parecido com investigar a lista de telefonemas de um escritório. Você não ouve a conversa, mas vê **quem ligou, para quem, a que horas e quantas vezes**. Se um ramal ligou 4.000 vezes em uma hora para um número que ninguém nunca discou antes, isso chama atenção mesmo sem saber o conteúdo da ligação. No SOC (Security Operations Center, o centro de operações de segurança), o log de DNS (Domain Name System, o sistema que traduz nome em endereço IP) é exatamente essa lista de telefonemas.

### Fontes de log de DNS e o que cada uma entrega

**O que é:** cada produto do ambiente enxerga um pedaço diferente da mesma consulta. **Como funciona:** o pedido nasce no processo do computador (Sysmon vê), sai pela rede (Zeek e firewall veem), chega ao servidor DNS interno (Windows DNS vê) e é encaminhado para um resolvedor em nuvem (Umbrella e Netskope veem). **O que o SOC N1 observa:** quanto mais fontes correlacionadas, menor a chance de erro; a fonte que diz **qual processo** fez a consulta é a mais valiosa.

| Fonte | O que entrega de melhor | Limitação principal |
|---|---|---|
| Windows DNS Server (log analítico, EventID 257) | Nome consultado, IP do cliente interno, tipo de registro | Não diz o processo; volume altíssimo |
| Zeek `dns.log` | Consulta + resposta + tempo, campo a campo | Não vê DNS criptografado (DoH/DoT) |
| Sysmon EventID 22 | **Processo** que fez a consulta e o caminho do executável | Só em hosts com Sysmon instalado |
| Firewall / proxy (porta 53) | Quem falou com qual servidor DNS | Muitas vezes só metadado, sem o nome |
| Cisco Umbrella | Veredito (allowed/blocked) e categoria do domínio | Vê o IP público de saída, não o host |
| Netskope | Usuário identificado + categoria + ação | Depende do cliente instalado |

#### Windows DNS Server — EventID 257

```
Log Name:      Microsoft-Windows-DNSServer/Analytical
Source:        Microsoft-Windows-DNSServer
Event ID:      257
Task Category: RESPONSE_SUCCESS
Description:
RESPONSE_SUCCESS: TCP=0; InterfaceIP=10.10.0.10; Destination=10.10.24.87;
AA=0; AD=0; QNAME=aatbxq7v3k9zplmn.example.com; QTYPE=16; XID=41988;
DNSSEC=0; RCODE=0; Port=53412; Flags=32896
```

Campos: `Destination` é o **host que perguntou** (10.10.24.87), `QNAME` é o nome consultado, `QTYPE=16` é registro TXT, `RCODE=0` significa resposta sem erro (`RCODE=3` seria NXDOMAIN, ou seja, domínio inexistente). **Suspeito:** subdomínio longo e aleatório com QTYPE=16 — padrão típico de exfiltração por DNS (MITRE ATT&CK T1071.004).

#### Zeek `dns.log` — campo a campo

```
#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto trans_id query qclass_name qtype_name rcode_name AA RD RA answers TTLs rejected
1725364812.441  CxT8hM2  10.10.24.87  53412  10.10.0.10  53  udp  41988
aatbxq7v3k9zplmn.example.com  C_INTERNET  TXT  NOERROR  F  T  T
"v=1;ZGF0YQ==" 60  F
```

<details><summary>Ver legenda</summary>

| Campo | Significado | Uso no SOC |
|---|---|---|
| `ts` | Data/hora em epoch | Montar a linha do tempo |
| `uid` | Identificador único da conexão | Cruzar com `conn.log` |
| `id.orig_h` | IP de origem (o host que perguntou) | Identificar a máquina |
| `id.resp_h` | IP do servidor DNS respondendo | Detectar DNS não autorizado |
| `query` | Nome consultado | Coração da análise |
| `qtype_name` | Tipo de registro (A, AAAA, TXT, NULL) | TXT/NULL em volume = alerta |
| `rcode_name` | Resultado (NOERROR, NXDOMAIN, SERVFAIL) | Muitos NXDOMAIN = DGA |
| `answers` | Resposta devolvida | IP suspeito ou dado codificado |
| `TTLs` | Tempo de vida do registro em segundos | TTL muito baixo = fast flux |
| `rejected` | Se a consulta foi rejeitada | Contexto |

</details>

#### Sysmon EventID 22 (DNS query)

```
Event ID: 22
UtcTime: 2026-09-03 14:20:12.441
ProcessGuid: {a1b2c3d4-1111-2222-3333-444455556666}
ProcessId: 7412
QueryName: aatbxq7v3k9zplmn.example.com
QueryStatus: 0
QueryResults: type: 16 v=1;ZGF0YQ==;
Image: C:\Users\jsilva\AppData\Local\Temp\update_helper.exe
User: CORP\jsilva
```

**O que o SOC N1 observa:** `Image` apontando para `AppData\Local\Temp` fazendo consulta DNS é altamente suspeito. Normal seria `chrome.exe`, `svchost.exe` ou `outlook.exe`.

#### Firewall FortiGate (key=value) e Palo Alto (CSV)

```
date=2026-09-03 time=14:20:13 devname="FGT-CORP-01" type="traffic" subtype="forward"
srcip=10.10.24.87 srcport=53412 dstip=203.0.113.45 dstport=53 proto=17
service="DNS" action="accept" policyid=12 sentbyte=94 rcvdbyte=210 duration=2
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `date` | `2026-09-03` | Data local **do equipamento**, não UTC. Correlacionar com um log em UTC sem acertar o fuso desalinha a timeline |
| `time` | `14:20:13` | Hora local do equipamento |
| `devname` | `"FGT-CORP-01"` | Nome do equipamento que gerou o log |
| `type` | `"traffic"` | Categoria do log: `traffic` é sessão, `event` é evento do próprio aparelho, `utm` é inspeção de conteúdo |
| `subtype` | `"forward"` | Subcategoria: `forward` é tráfego que atravessa, `local` é destinado ao próprio firewall, `vpn` é túnel, `webfilter` e `ips` são inspeção |
| `srcip` | `10.10.24.87` | IP de origem |
| `srcport` | `53412` | Porta de origem, efêmera e sorteada pelo cliente |
| `dstip` | `203.0.113.45` | IP de destino |
| `dstport` | `53` | Porta de destino — é ela que aponta o serviço |
| `proto` | `17` | Número do protocolo IP: **`6` é TCP, `17` é UDP, `1` é ICMP**. Vem em número, não em nome |
| `service` | `"DNS"` | Nome do **objeto de serviço** do FortiGate, não a porta literal. Um objeto chamado `HTTPS` pode ter sido configurado noutra porta |
| `action` | `"accept"` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |
| `policyid` | `12` | **Número da regra que decidiu.** Sem ele não se sabe por que o tráfego passou ou parou |
| `sentbyte` | `94` | Bytes enviados **pela origem**. O ponto de vista é o da origem, não do firewall |
| `rcvdbyte` | `210` | Bytes recebidos pela origem. **Comparar com `sentbyte` é o que revela exfiltração** |
| `duration` | `2` | Duração da sessão em **segundos** |

</details>

```
1,2026/09/03 14:20:13,013201004215,THREAT,spyware,2562,2026/09/03 14:20:13,
10.10.24.87,203.0.113.45,0.0.0.0,0.0.0.0,Regra-Saida-DNS,corp\jsilva,,dns,vsys1,
Trust,Untrust,ethernet1/2,ethernet1/1,Log-Forward,,,dns,alert,
"aatbxq7v3k9zplmn.example.com",Suspicious DNS Query,informational,client-to-server
```

`dstip=203.0.113.45` na porta 53 significa que o host falou com um **DNS externo**, contornando o servidor interno 10.10.0.10 — política quebrada e indício forte.

#### Cisco Umbrella e Netskope

```
"2026-09-03 14:20:12","PC-FIN-014","PC-FIN-014","198.51.100.20","203.0.113.45",
"Blocked","1 (A)","NOERROR","aatbxq7v3k9zplmn.example.com","Command and Control,Malware"
```

```
{"timestamp":"2026-09-03T14:20:12Z","user":"jsilva@empresa-exemplo.com.br",
"device":"PC-FIN-014","srcip":"10.10.24.87","url":"aatbxq7v3k9zplmn.example.com",
"category":"Newly Registered Domain","action":"block","policy":"Bloqueio-NRD","app":"DNS"}
```

**Erro comum de analista júnior:** ver `action=block` e fechar o chamado. Bloqueado significa que **aquela** tentativa falhou — o host continua infectado e vai tentar outro domínio.

### Processo de triagem de um alerta de DNS suspeito

1. **Registre o alerta**: horário exato (com fuso), regra que disparou e severidade.
2. **Identifique o host e o usuário**: converta IP em nome de máquina e dono via inventário; confirme se o IP não mudou por DHCP no horário do evento.
3. **Extraia os indicadores**: domínio completo, subdomínio, tipo de registro, IP respondido, servidor DNS usado.
4. **Verifique o volume**: quantas consultas ao mesmo domínio, em qual janela, quantos hosts distintos afetados.
5. **Descubra o processo**: busque Sysmon EventID 22 no mesmo segundo para saber qual executável perguntou.
6. **Confirme se houve conexão real**: houve tráfego para o IP respondido (Zeek `conn.log`, firewall)? Consulta sem conexão tem impacto muito menor.
7. **Cheque o veredito das camadas**: Umbrella, Netskope e proxy bloquearam ou permitiram?
8. **Enriqueça os indicadores** (próxima seção) antes de julgar.
9. **Classifique**: falso positivo, benigno explicado ou incidente verdadeiro.
10. **Decida a ação**: fechar com justificativa, monitorar por 24h ou escalar para o N2 com evidências.

### Enriquecimento e critérios de escalação

| Ferramenta | O que responde | Sinal de risco |
|---|---|---|
| WHOIS | Idade do domínio | Registrado há menos de 30 dias |
| VirusTotal | Reputação em múltiplos motores | 5+ motores marcando malicioso |
| urlscan.io | O que a página faz ao abrir | Página de login clonada da empresa |
| Passive DNS | Histórico de IPs do domínio | Troca de IP a cada poucos minutos |
| Categorização (Umbrella/Netskope) | Classe do domínio | Command and Control, NRD, Phishing |

**Escale para o N2 quando:** houver conexão estabelecida após a resolução; o processo consultante for desconhecido ou estiver em pasta temporária; mais de um host consultar o mesmo domínio raro; houver padrão periódico (beaconing); ou o alvo for conta privilegiada como `admin.rodrigo` ou `svc_backup`.

### Queries prontas

```spl
# Top NXDOMAIN por host — indício clássico de DGA
index=dns sourcetype=zeek:dns rcode_name="NXDOMAIN"
| stats count AS nxdomains dc(query) AS dominios_unicos BY id.orig_h
| where nxdomains > 200
| sort - nxdomains

# Consultas com nome muito longo — possível exfiltração via DNS (T1071.004)
index=dns sourcetype=zeek:dns
| eval tamanho=len(query)
| where tamanho > 60
| table _time id.orig_h query qtype_name tamanho

# Contagem de consultas por host (volume anormal)
index=dns sourcetype=zeek:dns earliest=-1h
| stats count BY id.orig_h
| sort - count | head 20

# Domínio visto pela primeira vez no ambiente (últimas 24h vs 30 dias)
index=dns sourcetype=zeek:dns earliest=-30d
| eval dominio=mvindex(split(query,"."), -2) . "." . mvindex(split(query,"."), -1)
| stats min(_time) AS primeira_vez count BY dominio
| where primeira_vez > relative_time(now(), "-24h")
```

```kql
// Top NXDOMAIN por host
DnsEvents
| where TimeGenerated > ago(1h)
| where ResponseCode == 3                    // 3 = NXDOMAIN
| summarize nxdomains = count(), unicos = dcount(Name) by ClientIP
| where nxdomains > 200
| order by nxdomains desc

// Consultas com nome muito longo
DeviceDnsEvents
| where TimeGenerated > ago(24h)
| extend tamanho = strlen(DnsQuery)          // comprimento do nome consultado
| where tamanho > 60
| project TimeGenerated, DeviceName, InitiatingProcessFileName, DnsQuery, tamanho

// Contagem de consultas por host
DeviceDnsEvents
| where TimeGenerated > ago(1h)
| summarize consultas = count() by DeviceName
| order by consultas desc | take 20

// Domínio visto pela primeira vez no ambiente
DeviceDnsEvents
| where TimeGenerated > ago(30d)
| extend dominio = strcat(split(DnsQuery, ".")[-2], ".", split(DnsQuery, ".")[-1])
| summarize primeira_vez = min(TimeGenerated), total = count() by tostring(dominio)
| where primeira_vez > ago(24h)              // só o que apareceu nas últimas 24h
| order by primeira_vez desc
```

### Exercícios — Como investigar DNS no SOC

1. No log do Zeek acima, qual campo prova que a máquina 10.10.24.87 usou o servidor DNS corporativo e não um externo?
2. Um alerta mostra 3.400 NXDOMAIN em 20 minutos vindos de 10.10.31.5, todos com nomes de 12 caracteres aleatórios em `.example.com`. Verdadeiro ou falso positivo? Justifique.
3. O Umbrella registrou `Blocked` para `aatbxq7v3k9zplmn.example.com` no host PC-FIN-014. O analista quer fechar o chamado. Qual é o próximo passo correto?
4. Você tem apenas o log do FortiGate mostrando `dstip=203.0.113.45 dstport=53`. Qual fonte você busca em seguida para saber **qual processo** gerou a consulta, e por quê?
5. Um domínio criado há 4 dias, com TTL de 30 segundos e 2 detecções no VirusTotal, foi resolvido e seguido de uma conexão TCP/443 de 6 MB de saída. Escalar ou não?

<details><summary>Ver gabarito</summary>

1. O campo `id.resp_h` com valor `10.10.0.10`, que é o IP do servidor DNS interno. Se ali aparecesse um IP público como 203.0.113.45, seria DNS externo e violação de política.
2. **Verdadeiro positivo provável.** Volume alto de NXDOMAIN com nomes aleatórios de comprimento fixo é a assinatura de um DGA (Domain Generation Algorithm, algoritmo que gera domínios), usado por malware para encontrar seu servidor de comando e controle. Próximo passo: Sysmon EventID 22 para achar o processo e isolar o host.
3. Não fechar. Bloqueio impede aquela resolução, mas não remove a infecção. É preciso identificar o processo (Sysmon 22), verificar se houve resolução bem-sucedida por outro caminho (DNS externo direto, DoH) e checar se outros hosts consultam o mesmo domínio.
4. Sysmon EventID 22 no endpoint, porque é a única fonte listada que registra o `Image` (caminho do executável) e o usuário associados à consulta. O firewall só enxerga IP e porta.
5. **Escalar.** Domínio recém-registrado + TTL muito baixo + detecção em VirusTotal já seriam suficientes; a conexão de 6 MB **de saída** após a resolução indica possível exfiltração de dados e transforma o caso em incidente para o N2.

</details>

## Mini-laboratório — DNS

**Pré-requisitos:** VirtualBox com uma máquina Ubuntu, `tcpdump`, `dig`, Wireshark e Docker instalados. Tudo gratuito.

1. Suba o Zeek em contêiner para analisar uma captura:
   `docker run --rm -it -v $PWD:/data zeek/zeek:latest bash`
2. Em outro terminal, capture o tráfego DNS por 60 segundos:
   `sudo tcpdump -i any -n port 53 -w /tmp/dns-lab.pcap`
3. Gere consultas variadas enquanto captura:
   `dig A example.com`, `dig TXT example.com`, `dig MX example.com`, `dig naoexiste-abcxyz.example.com`
4. Observe: a última consulta deve retornar `status: NXDOMAIN` na saída do `dig`.
5. Processe a captura com Zeek: `zeek -r /data/dns-lab.pcap` e abra o `dns.log` gerado.
6. Confirme no `dns.log` as colunas `query`, `qtype_name` e `rcode_name` para cada consulta feita.
7. Abra o mesmo arquivo no Wireshark e aplique o filtro `dns.flags.rcode == 3` para isolar os NXDOMAIN.
8. Aplique o filtro `dns.qry.type == 16` para ver apenas as consultas TXT.

**Critério de sucesso:** você consegue apontar, no `dns.log`, exatamente qual linha corresponde ao NXDOMAIN e qual corresponde à consulta TXT, e explicar em voz alta o que cada campo significa.

## O que um SOC Level 1 realmente precisa saber

- 🟢 DNS traduz nome em endereço IP e usa a porta 53, em UDP para consultas normais e TCP para respostas grandes e transferência de zona.
- 🟢 Os tipos de registro mais vistos no dia a dia são A, AAAA, CNAME, MX, TXT, NS e PTR.
- 🟢 `RCODE=0` é NOERROR e `RCODE=3` é NXDOMAIN; muitos NXDOMAIN concentrados em um host é o sinal número um de DGA.
- 🟢 Sysmon EventID 22 é a fonte que diz **qual processo** consultou — sempre busque por ela.
- 🟢 Um host falando na porta 53 com IP público, sem passar pelo DNS interno, é violação de política e merece investigação.
- 🟡 No Zeek `dns.log`, os campos que mais decidem uma triagem são `id.orig_h`, `query`, `qtype_name`, `rcode_name` e `answers`.
- 🟡 Enriquecimento mínimo antes de julgar: idade do domínio (WHOIS), reputação (VirusTotal) e categoria (Umbrella/Netskope).
- 🟡 Bloqueado não significa resolvido: o host segue potencialmente comprometido até prova em contrário.
- 🟡 Domínio recém-registrado (menos de 30 dias) e TTL muito baixo são indícios fortes, mas nunca são prova isolada.
- 🔴 Exfiltração por DNS (MITRE ATT&CK T1071.004) aparece como nomes longos e aleatórios com registros TXT ou NULL em volume anormal.
- 🔴 DoH (DNS over HTTPS) e DoT (DNS over TLS) escondem o nome consultado do Zeek e do firewall; nesse cenário o endpoint vira a única testemunha.
- 🔴 Correlacionar consulta com conexão real no `conn.log` separa ruído de incidente: resolução sem sessão subsequente tem impacto baixo.

## Resumo em 10 linhas

1. DNS é a agenda telefônica da internet: transforma nomes legíveis em endereços IP.
2. A resolução passa por cache local, servidor recursivo, raiz, TLD e servidor autoritativo.
3. Os registros mais relevantes para o SOC são A, AAAA, CNAME, MX, TXT, NS e PTR.
4. Atacantes usam DNS para comando e controle, exfiltração de dados, tunelamento e phishing.
5. As fontes de log úteis são Windows DNS (EventID 257), Zeek `dns.log`, Sysmon 22, firewall, Umbrella e Netskope.
6. Só o endpoint (Sysmon 22) revela qual processo fez a consulta, e isso quase sempre decide a triagem.
7. A triagem segue uma ordem: identificar host, extrair indicadores, medir volume, achar o processo e confirmar conexão.
8. Enriquecimento com WHOIS, VirusTotal, urlscan.io e passive DNS transforma suspeita em veredito.
9. Escale ao N2 quando houver conexão estabelecida, processo desconhecido, múltiplos hosts ou conta privilegiada envolvida.
10. Queries de NXDOMAIN, nomes longos, volume por host e domínio inédito cobrem a maioria dos casos reais de DNS malicioso.



---
