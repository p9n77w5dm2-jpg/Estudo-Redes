# Módulo 08 — Proxies, Web Gateways e Inspeção TLS

## Por que este módulo importa para o SOC

Quase todo ataque moderno passa pela porta 443. O malware baixa a segunda fase por HTTPS, o comando e controle (C2, do inglês *Command and Control*) se disfarça de tráfego web normal e o vazamento de dados sai por um upload para um serviço de nuvem qualquer. O firewall vê só "IP 10.10.20.45 falou com 203.0.113.77 na porta 443". O proxy vê a URL completa, o nome do usuário autenticado, o tamanho do upload, a categoria do site e o veredito do antivírus. Para um analista de SOC Nível 1, o log de proxy costuma ser a diferença entre "alguém na rede acessou algo estranho" e "a usuária maria.costa baixou um executável de um domínio criado há 3 dias, às 14h07".

**Índice do módulo:**

- Forward, reverse e transparent proxy, e inspeção TLS
- SWG, CASB, DLP, ZTNA, SASE e os produtos de mercado
- Logs de proxy na prática e investigação no SOC

---

## O que é um proxy: o despachante

Imagine que você precisa resolver algo num cartório de outra cidade. Você pode ir pessoalmente, ou pode contratar um **despachante**: você entrega o pedido a ele, ele vai até o cartório, resolve em nome dele mesmo, e volta com o resultado. O cartório nunca viu você — viu o despachante. E o despachante, por ter lido seu pedido inteiro, pôde dizer "esse documento está errado, não vou nem levar".

Proxy é exatamente isso: um intermediário que **fala em nome de outro**.

### A diferença fundamental para o firewall

Essa distinção é a pergunta de entrevista mais comum sobre o tema, e a que mais confunde analista iniciante:

| Aspecto | Firewall (camada 3/4) | Proxy (camada 7) |
|---|---|---|
| O que faz com o pacote | **Encaminha** (roteia) | **Termina** a conexão e abre outra |
| Conexões TCP envolvidas | Uma só, ponta a ponta | **Duas**: cliente↔proxy e proxy↔servidor |
| O que enxerga | IP, porta, protocolo, flags | URL, método HTTP, cabeçalhos, corpo, arquivo |
| Identidade | Só o endereço IP | **Nome do usuário** autenticado |
| Decisão típica | Permitir/negar porta 443 | Negar `/download/setup.exe` em site sem categoria |

Quando o cliente 10.10.20.45 usa um proxy, o servidor na internet vê a conexão vindo do IP do proxy, nunca do IP do cliente. Isso muda tudo na hora de investigar.

---

## Forward proxy: da rede interna para a internet

**O que é.** O proxy que fica na saída da empresa. O fluxo é `usuário → proxy → internet`. É o guarda da portaria decidindo quem sai e para onde.

**Como funciona.** O navegador, em vez de abrir conexão direta com o site, abre com o proxy e pede: `GET http://www.example.com/pagina HTTP/1.1`. Para HTTPS, o navegador manda `CONNECT www.example.com:443` — o proxy então abre o túnel.

### Explícito versus implícito

**Proxy explícito** é aquele em que o cliente *sabe* que existe um proxy e foi configurado para usá-lo. As portas clássicas são **3128** (padrão do Squid) e **8080**. A configuração pode ser:

- **Manual**: o endereço `proxy.corp.local:3128` digitado nas configurações do sistema.
- **PAC** (*Proxy Auto-Config*): um arquivo JavaScript, tipicamente `http://proxy.corp.local/proxy.pac`, que diz para cada destino se vai direto ou pelo proxy.
- **WPAD** (*Web Proxy Auto-Discovery Protocol*): o cliente procura sozinho o arquivo PAC via DHCP ou DNS (nome `wpad.corp.local`). Cômodo, mas historicamente abusado — quando o nome WPAD não existe no DNS, ferramentas como Responder podem responder no lugar dele e se colocar no meio do caminho. Para o SOC N1, consulta a `wpad` vindo de máquina que não deveria usar WPAD é sinal de alerta.

**Proxy implícito (ou forçado)** é quando o cliente não tem nada configurado e a rede o obriga a passar — é o transparent proxy, tratado adiante.

### Autenticação de usuário: o ouro do log de proxy

O forward proxy pode exigir que o usuário se identifique antes de navegar. Os métodos comuns são **NTLM**, **Kerberos/Negotiate** (autenticação transparente com a conta do domínio, sem pedir senha) e **Basic** (usuário e senha em texto codificado em Base64 — desaconselhado sem TLS).

O resultado é que o log de proxy carrega o campo de usuário. Enquanto o firewall registra "10.10.20.45", o proxy registra "jsilva". Se aquela máquina é compartilhada, se o DHCP trocou o endereço, se a estação foi reinstalada — nada disso importa: **o proxy é a fonte mais rica para atribuir atividade web a uma pessoa**.

**Exemplo prático.** A estação 10.10.20.45 (usuário jsilva) acessa `arquivos.empresa-exemplo.com.br` por HTTPS.

#### Como aparece nos logs

Squid `access.log` (formato nativo, campos separados por espaço):

```
1756900412.317   1183 10.10.20.45 TCP_TUNNEL/200 84213 CONNECT arquivos.empresa-exemplo.com.br:443 jsilva HIER_DIRECT/203.0.113.44 -
1756900430.882    412 10.10.20.45 TCP_DENIED/403 3921 GET http://downloads.example.com/setup.exe maria.costa HIER_NONE/- text/html
```

<details><summary>Ver legenda</summary>

| Campo | 1ª linha (túnel HTTPS) / 2ª linha (bloqueio) | O que significa |
|---|---|---|
| *timestamp* | `1756900412.317` / `1756900430.882` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos |
| duração | `1183` / `412` | Milissegundos. No túnel, mede o tempo em que a conexão ficou aberta |
| cliente | `10.10.20.45` | O IP de origem em ambos |
| resultado/status | `TCP_TUNNEL/200` / `TCP_DENIED/403` | `TCP_TUNNEL` = túnel HTTPS estabelecido, **e a partir daí o proxy só conta bytes**; `TCP_DENIED` = a política barrou antes de sair |
| bytes | `84213` / `3921` | 84 KB atravessaram o túnel; no bloqueio, o tamanho da página de erro |
| método | `CONNECT` / `GET` | `CONNECT` pede o túnel para HTTPS; `GET` é HTTP em claro |
| URL | `arquivos.empresa-exemplo.com.br:443` / `http://downloads.example.com/setup.exe` | No `CONNECT` só há host e porta — **o caminho e o conteúdo vão cifrados**. No `GET` bloqueado dá para ver o arquivo pretendido |
| usuário | `jsilva` / `maria.costa` | Conta autenticada no proxy — o que permite investigar por pessoa, e não por IP |
| hierarquia/destino | `HIER_DIRECT/203.0.113.44` / `HIER_NONE/-` | `HIER_NONE` confirma que o pedido bloqueado **não chegou a sair** |
| tipo de conteúdo | `-` / `text/html` | Vazio no túnel: o proxy não sabe o que passou lá dentro |

</details>


Zscaler NSS (formato web, chave=valor simplificado):

```
time=2026-09-03 14:07:12 user=jsilva@empresa-exemplo.com.br department=Financeiro clientip=10.10.20.45 serverip=203.0.113.44 url=arquivos.empresa-exemplo.com.br/relatorio.xlsx urlcategory=File_Host action=Allowed reqsize=1204 respsize=84213 threatname=None appname=Generic_File_Hosting
```

Aqui o `urlcategory` (categoria da URL) e o `appname` são o que permitem responder "que tipo de site é esse?" sem sair do log.

#### O que o SOC N1 observa

| Sinal | Normal | Suspeito |
|---|---|---|
| Usuário no log | Conta nominal (jsilva) | `-` (não autenticado) em volume alto |
| Categoria | Business, News, SaaS conhecido | *Newly Registered Domain*, *Uncategorized*, *Anonymizer* |
| Método | GET/POST para sites conhecidos | POST grande e repetitivo para domínio sem categoria (possível exfiltração, T1048) |
| Ritmo | Irregular, com pausas humanas | Requisições a cada 60s exatos, 24h por dia (*beaconing* de C2, T1071.001) |
| *User-Agent* | Navegador atualizado | `python-requests`, `curl`, string vazia ou aleatória |

**Erro comum de analista júnior:** ver `TCP_DENIED/403` e fechar o chamado como "bloqueado, tudo certo". O bloqueio protegeu aquela requisição, mas não explica **por que** a estação tentou. Se um processo tentou baixar `setup.exe` de um domínio sem categoria, há algo executando na máquina — o bloqueio é o sintoma, não a conclusão.

---

## Reverse proxy: da internet para o servidor interno

**O que é.** O caminho contrário: `internet → proxy → servidor interno`. É a recepcionista do prédio — o visitante fala com ela, e ela é quem sabe em qual sala o assunto será tratado.

**Como funciona.** O nome público `www.empresa-exemplo.com.br` resolve para o IP do reverse proxy (por exemplo, 203.0.113.10). Ele recebe a requisição e a repassa para um dos servidores internos (10.10.60.11, 10.10.60.12). Produtos típicos: NGINX, HAProxy, F5 BIG-IP, Cloudflare, AWS Application Load Balancer.

**Para que serve:**

- **Balanceamento de carga**: distribui as requisições entre vários servidores.
- **Terminação TLS**: o certificado fica no proxy; o servidor interno pode falar HTTP simples.
- **WAF** (*Web Application Firewall*): inspeciona a requisição procurando injeção de SQL, *cross-site scripting* e similares.
- **CDN** (*Content Delivery Network*): cache do conteúdo perto do visitante.
- **Ocultação do servidor**: a internet nunca aprende o IP nem a versão real do servidor de origem.

### O X-Forwarded-For e a pegadinha clássica

Como o servidor interno recebe todas as conexões vindas do proxy, do ponto de vista dele **todo mundo tem o mesmo IP**. Para não perder a origem real, o reverse proxy adiciona o cabeçalho **XFF** (`X-Forwarded-For`) com o IP verdadeiro do visitante (o padrão moderno equivalente é `Forwarded`).

```
198.51.100.23 - - [03/Sep/2026:14:09:41 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0" XFF="198.51.100.23"
203.0.113.10 - - [03/Sep/2026:14:09:42 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0" XFF="198.51.100.23, 203.0.113.10"
```

**Erro comum de analista júnior:** abrir o log da aplicação, ver 4.000 falhas de login vindas de 203.0.113.10 e escrever no chamado "ataque de força bruta originado do IP 203.0.113.10 — bloquear". Esse é o IP do próprio balanceador. Bloqueá-lo derruba o site inteiro. A origem real está no XFF. Cuidado adicional: o XFF é um cabeçalho **enviado pelo cliente** e pode ser forjado — confie apenas no valor que o *seu* proxy escreveu (tipicamente o último da lista antes do salto interno).

---

## Transparent proxy: o que o cliente não sabe

**O que é.** Um proxy pelo qual o tráfego passa sem que o cliente tenha sido configurado para isso. A rede desvia o tráfego das portas 80 e 443 para o proxy, via política de roteamento, WCCP (*Web Cache Communication Protocol*) ou regra de redirecionamento no firewall.

**Vantagem:** cobre tudo, inclusive dispositivos que não permitem configurar proxy (impressoras, IoT, celulares de visitante).

**Limitações que importam ao SOC:**

- **Não há autenticação de usuário natural** — sem o diálogo de proxy, o log volta a ter apenas IP. Alguns produtos contornam isso amarrando IP a usuário via logs de logon do controlador de domínio (evento **4624**), o que é uma inferência, não uma prova.
- **Só pega o que é redirecionado**: tráfego em portas fora da regra passa livre.
- Aplicações com **certificate pinning** ou mTLS quebram sem aviso claro para o usuário.

---

## Inspeção TLS: abrir o envelope lacrado

**O que é.** TLS (*Transport Layer Security*) criptografa o conteúdo entre o navegador e o site. Isso é ótimo para privacidade e péssimo para defesa: um malware baixado por HTTPS é invisível para quem só olha o tráfego. A **inspeção TLS** (também chamada de *SSL inspection*, *TLS interception* ou *break and inspect*) permite ao proxy ler o conteúdo.

**Como funciona.** É um homem-no-meio autorizado. O proxy quebra a conexão em duas:

1. Cliente → proxy: o proxy **gera na hora** um certificado para `www.example.com` e o assina com a **CA interna** (*Certificate Authority*, autoridade certificadora) da empresa.
2. Proxy → servidor: o proxy faz a conexão TLS real, valida o certificado verdadeiro do site.

O navegador só aceita o passo 1 porque o certificado raiz da CA interna foi instalado como confiável em todas as estações (por GPO, MDM ou imagem). Sem essa confiança prévia, o usuário veria erro de certificado em todo site.

**Exemplo prático.** A estação 10.10.20.45 acessa `www.example.com`. No Zeek, o campo `issuer` do `ssl.log` denuncia a inspeção:

```
#fields ts  uid  id.orig_h  id.orig_p  id.resp_h  id.resp_p  version  cipher  server_name  established  issuer
1756901301.442  CxTk9r2Yh8Qa  10.10.20.45  51422  203.0.113.44  443  TLSv13  TLS_AES_256_GCM_SHA384  www.example.com  T  CN=Proxy-Corp-CA,O=Empresa Exemplo,C=BR
1756901355.907  Cq8Lm4Tb1Zd7  10.10.20.61  49877  198.51.100.90  443  TLSv12  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256  -  T  CN=R11,O=Lets Encrypt,C=US
```

<details><summary>Ver legenda</summary>

| Campo | 1ª linha (inspecionada) / 2ª linha (não inspecionada) | O que significa |
|---|---|---|
| `ts` | `1756901301.442` / `1756901355.907` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos |
| `uid` | `CxTk9r2Yh8Qa` / `Cq8Lm4Tb1Zd7` | Identificador único de cada conexão |
| `id.orig_h` / `id.orig_p` | `10.10.20.45:51422` / `10.10.20.61:49877` | Cliente e porta efêmera |
| `id.resp_h` / `id.resp_p` | `203.0.113.44:443` / `198.51.100.90:443` | Destino e porta |
| `version` | `TLSv13` / `TLSv12` | Versão do TLS negociada |
| `cipher` | `TLS_AES_256_GCM_SHA384` / `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | Conjunto de cifras acordado |
| `server_name` | `www.example.com` / `-` | O SNI. Vazio na 2ª: sem nome, só o IP |
| `established` | `T` | O handshake completou nas duas |
| `issuer` | `CN=Proxy-Corp-CA,O=Empresa Exemplo` / `CN=R11,O=Lets Encrypt` | **O campo que denuncia a inspeção.** Emissor interno significa que o proxy quebrou e refez o TLS, logo o SOC vê o conteúdo. Emissor público significa que a sessão passou intacta — e aí só há metadados |

</details>

Na primeira linha o emissor é a CA interna: a sessão **foi inspecionada**. Na segunda o emissor é externo e o `server_name` (SNI, *Server Name Indication*) está vazio — sessão **não inspecionada e sem nome de destino**, exatamente o perfil que merece um segundo olhar.

FortiGate registrando um bloqueio dentro de sessão inspecionada:

```
date=2026-09-03 time=14:11:58 devname="FGT-BORDA-01" type="utm" subtype="webfilter" level="warning" srcip=10.10.20.45 dstip=203.0.113.77 srcport=52310 dstport=443 policyid=12 user="jsilva" service="HTTPS" hostname="cdn-update.example.com" url="/pkg/agent.bin" action="blocked" catdesc="Newly Observed Domain" ssl-inspection="deep-inspection" msg="URL belongs to a denied category"
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `date` | `2026-09-03` | Data local **do equipamento**, não UTC. Correlacionar com um log em UTC sem acertar o fuso desalinha a timeline |
| `time` | `14:11:58` | Hora local do equipamento |
| `devname` | `"FGT-BORDA-01"` | Nome do equipamento que gerou o log |
| `type` | `"utm"` | Categoria do log: `traffic` é sessão, `event` é evento do próprio aparelho, `utm` é inspeção de conteúdo |
| `subtype` | `"webfilter"` | Subcategoria: `forward` é tráfego que atravessa, `local` é destinado ao próprio firewall, `vpn` é túnel, `webfilter` e `ips` são inspeção |
| `level` | `"warning"` | Severidade atribuída pelo FortiOS (`notice`, `warning`, `alert`, `critical`). **Quem a escolhe é o fabricante**, não o seu SOC |
| `srcip` | `10.10.20.45` | IP de origem |
| `dstip` | `203.0.113.77` | IP de destino |
| `srcport` | `52310` | Porta de origem, efêmera e sorteada pelo cliente |
| `dstport` | `443` | Porta de destino — é ela que aponta o serviço |
| `policyid` | `12` | **Número da regra que decidiu.** Sem ele não se sabe por que o tráfego passou ou parou |
| `user` | `"jsilva"` | Conta autenticada — o que transforma "um IP" em "uma pessoa" |
| `service` | `"HTTPS"` | Nome do **objeto de serviço** do FortiGate, não a porta literal. Um objeto chamado `HTTPS` pode ter sido configurado noutra porta |
| `hostname` | `"cdn-update.example.com"` | Nome do host pedido, extraído do tráfego web |
| `url` | `"/pkg/agent.bin"` | URL pedida |
| `action` | `"blocked"` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |
| `catdesc` | `"Newly Observed Domain"` | Categoria de conteúdo atribuída ao destino |
| `inspection` | `"deep-inspection"` | Modo de inspeção aplicado (`flow` ou `proxy`) |
| `msg` | `"URL belongs to a denied category"` | Texto livre com a descrição legível. **Não use este campo em regras** — muda entre versões |

</details>

Campos-chave: `user` (identidade), `hostname` + `url` (só visíveis por causa da inspeção), `catdesc` (categoria) e `ssl-inspection=deep-inspection` (confirma que houve abertura do tráfego; `certificate-inspection` significa que só o SNI/certificado foi lido, sem abrir o conteúdo).

### O que a inspeção TLS quebra

| O que quebra | Por quê | Como aparece |
|---|---|---|
| **Certificate pinning** | O app só aceita um certificado específico, não a CA interna | Falha de conexão silenciosa; app "não abre" |
| **Apps móveis e agentes** | Muitos fazem pinning ou usam repositório de certificados próprio | Erro genérico de rede; sincronização parada |
| **mTLS** (TLS mútuo) | O servidor exige certificado do cliente, que o proxy não possui | Handshake falha com alerta de certificado |
| **Atualizadores e gestores de pacotes** | Validação estrita da cadeia | Instalação falha por "certificado não confiável" |
| **QUIC/HTTP3 (UDP 443)** | Muitos proxies não inspecionam; prática comum é bloquear UDP 443 para forçar o fallback a TCP | Tráfego some do log de proxy |

### Listas de não-inspeção (bypass)

Por privacidade e conformidade, categorias inteiras ficam de fora da inspeção — tipicamente **saúde, finanças/bancos, governo, jurídico e recursos humanos**. No Brasil isso conversa diretamente com a LGPD (Lei Geral de Proteção de Dados); na Europa, com o RGPD. A decisão é do jurídico e da segurança em conjunto, e o usuário deve ser avisado da existência da inspeção em política interna.

**Erro comum de analista júnior:** ver o emissor `CN=Proxy-Corp-CA` no `ssl.log` e abrir incidente de "ataque man-in-the-middle na rede". Numa empresa com inspeção TLS, esse é o comportamento **esperado**. O contrário também vale: tratar toda sessão não inspecionada como maliciosa, quando ela pode simplesmente cair numa categoria de bypass legítima. Antes de concluir, consulte qual é a política de inspeção do ambiente.

### Consultas úteis

SPL (Splunk) — procurando sessões TLS que fugiram da inspeção:

````spl
index=proxy sourcetype=zeek:ssl                       ```base: logs SSL do Zeek```
| search issuer!="CN=Proxy-Corp-CA*"                   ```tira o que foi inspecionado pela CA interna```
| stats count, dc(id.resp_h) AS destinos BY id.orig_h  ```agrupa por estação de origem```
| where count > 200                                    ```volume alto de sessões não inspecionadas```
| sort - count
````

KQL (Microsoft Sentinel) — beaconing de intervalo fixo no log de proxy:

```kql
ProxyLogs_CL                                          // tabela de logs de proxy
| where TimeGenerated > ago(24h)                      // janela de 24 horas
| where Action_s == "Allowed"                         // só o que passou
| summarize Requisicoes = count(),
            Intervalos = dcount(bin(TimeGenerated, 1m))
        by ClientIP_s, DestHost_s, User_s             // agrupa por origem, destino e usuário
| where Requisicoes > 500 and Intervalos > 400        // muitos acessos espalhados de forma regular
| order by Requisicoes desc
```

---

### Exercícios — Forward, reverse e transparent proxy, e inspeção TLS

1. **Leitura de log.** Na linha do Squid `1756900430.882 412 10.10.20.45 TCP_DENIED/403 3921 GET http://downloads.example.com/setup.exe maria.costa HIER_NONE/- text/html`, identifique: (a) o IP e o usuário, (b) se a requisição chegou ao servidor de destino, (c) por que o tamanho de 3921 bytes não é o tamanho do executável.

2. **Verdadeiro ou falso positivo?** O alerta diz: "Força bruta contra o portal — 4.000 falhas de login (HTTP 401) originadas de 203.0.113.10 em 10 minutos". Ao consultar a arquitetura, você descobre que 203.0.113.10 é o reverse proxy da empresa. O alerta é verdadeiro ou falso positivo? Qual campo do log resolve a dúvida?

3. **Próximo passo.** No `ssl.log` do Zeek você vê 1.440 conexões da estação 10.10.20.61 para 198.51.100.90:443, uma a cada 60 segundos, `server_name` vazio e emissor externo (não inspecionadas). Liste três passos de investigação em ordem, e diga qual técnica MITRE ATT&CK melhor descreve o padrão.

4. **Raciocínio de arquitetura.** Um usuário reclama que o aplicativo de banco no notebook corporativo parou de conectar depois de uma mudança na rede, mas o navegador acessa o mesmo banco normalmente. Qual é a causa mais provável e qual é a correção adequada?

5. **Cálculo.** Um forward proxy registra, para a estação 10.10.20.45, 1.440 requisições POST em 24 horas para `upload.example.com`, com `respsize` médio de 512 bytes e `reqsize` médio de 2.100.000 bytes. Quanto de dado saiu, aproximadamente, em gigabytes? Isso é mais compatível com navegação normal ou com exfiltração?

<details><summary>Ver gabarito</summary>

**1.** (a) IP `10.10.20.45`, usuária `maria.costa` — a autenticação no proxy é o que dá o nome. (b) **Não chegou**: o código é `TCP_DENIED/403` e a hierarquia é `HIER_NONE/-`, ou seja, o proxy não encaminhou para nenhum servidor de origem. (c) Os 3.921 bytes são a **página de bloqueio** devolvida pelo próprio proxy (note o `text/html` no final), não o arquivo pedido. Conclusão para o chamado: a política funcionou, mas resta descobrir **o que na estação** tentou buscar um executável em domínio não categorizado — verifique Sysmon Event ID 1 (criação de processo) e 3 (conexão de rede) no horário.

**2.** **Falso positivo quanto à origem** — o ataque pode ser real, mas o IP atribuído está errado. 203.0.113.10 é o reverse proxy; do ponto de vista do servidor de aplicação, *todo* tráfego vem dele. O campo que resolve é o **`X-Forwarded-For`** (ou `Forwarded`), que traz o IP real do cliente. Bloquear 203.0.113.10 tiraria o site do ar para todos. Atenção extra: o XFF pode ser forjado pelo cliente, então considere apenas o valor escrito pelo seu próprio proxy.

**3.** Padrão clássico de **beaconing**: intervalo rigidamente fixo (1.440 × 60s = 24h exatas), destino único, sem SNI. Passos: (i) identificar a estação e o usuário — cruzar 10.10.20.61 com o log de DHCP e com o evento **4624** do Windows Security para saber quem estava logado; (ii) verificar o destino 198.51.100.90 em fontes de reputação e checar a idade do domínio, além de conferir se ele está numa lista de bypass legítima (o que explicaria a ausência de inspeção); (iii) puxar telemetria de endpoint — Sysmon Event ID 3 para descobrir **qual processo** abriu essas conexões, e Event ID 1 para a linha de origem desse processo. Técnica MITRE: **T1071.001 — Application Layer Protocol: Web Protocols**, com o intervalo fixo remetendo a **T1029/T1573** conforme o caso. Não bloqueie antes de identificar o processo: sem isso você perde a chance de achar a persistência.

**4.** Causa mais provável: a rede passou a fazer **inspeção TLS** e o aplicativo do banco usa **certificate pinning** — ele só aceita o certificado original do banco e rejeita o emitido pela CA interna. O navegador funciona porque confia na CA interna instalada na máquina. Correção adequada: **incluir o domínio do banco na lista de não-inspeção** (bypass), decisão que, além de resolver o sintoma, é a esperada por privacidade e conformidade para categoria financeira. A correção errada seria pedir ao usuário para ignorar avisos de certificado ou desinstalar validações.

**5.** 1.440 × 2.100.000 bytes ≈ 3.024.000.000 bytes. Dividindo por 1.073.741.824 (1 GiB), dá **cerca de 2,8 GB de saída** em 24 horas, contra respostas minúsculas de 512 bytes. Navegação normal tem a proporção invertida: pouco enviado, muito recebido. Aqui o volume é quase todo **de saída**, em requisições regulares — perfil compatível com **exfiltração de dados (T1048 — Exfiltration Over Alternative Protocol)**. Próximo passo: identificar o processo na estação e acionar o time de resposta antes de qualquer bloqueio que alerte o operador.

</details>


## A sopa de siglas: SWG, CASB, DLP, ZTNA, SASE e SSE

Imagine um prédio corporativo. Na portaria há um porteiro que decide quem entra e sai (SWG). Há um fiscal que confere o que os funcionários levam para dentro do prédio de serviços de terceiros, como o Google Drive (CASB). Há um segurança na saída que abre a mochila para ver se ninguém está levando documento confidencial (DLP). E há um crachá inteligente que só abre a porta da sala específica que você precisa, e não o prédio inteiro (ZTNA). Quando você contrata tudo isso do mesmo fornecedor, na nuvem, num pacote só, você tem SASE ou SSE.

### O que cada sigla significa

| Sigla | Nome completo | O que faz, em uma frase |
|---|---|---|
| **SWG** | Secure Web Gateway | Proxy de saída para a internet: filtra por categoria, reputação, faz antivírus e inspeção TLS. |
| **CASB** | Cloud Access Security Broker | Enxerga e controla o uso de aplicações SaaS (Microsoft 365, Salesforce, Dropbox). |
| **DLP** | Data Loss Prevention | Procura dados sensíveis (CPF, cartão, contrato) saindo da empresa e bloqueia ou alerta. |
| **ZTNA** | Zero Trust Network Access | Substitui a VPN: dá acesso a uma aplicação específica, nunca à rede inteira. |
| **SSE** | Security Service Edge | O pacote SWG + CASB + DLP + ZTNA entregue como serviço na nuvem. |
| **SASE** | Secure Access Service Edge | SSE **mais** a parte de rede (SD-WAN, roteamento otimizado). |

Regra de bolso para nunca mais errar: **SASE = SSE + SD-WAN**. E SSE é o guarda-chuva que segura as outras quatro.

### CASB: inline vs API mode

Essa distinção cai em prova e cai no dia a dia do SOC.

- **Inline (proxy)**: o tráfego passa pelo produto em tempo real. Ele vê a requisição HTTPS acontecendo e pode **bloquear antes** do upload completar. Log tem `user`, `url`, `activity=Upload`, `action=block`. Limitação: só vê o que passa pelo proxy — se o usuário estiver fora do túnel, você não vê nada.
- **API mode (out-of-band)**: o produto se conecta via API ao tenant do SaaS (por exemplo, ao Microsoft 365) e faz varredura **depois** que o arquivo já subiu. Não bloqueia em tempo real, mas enxerga tudo, inclusive compartilhamento feito de casa, do celular, ou por um parceiro externo. Log tem `access_method=API` e chega com atraso de minutos a horas.

Erro comum de analista júnior: ver um alerta de DLP com atraso de 40 minutos e abrir incidente de "falha do proxy". Não é falha — é modo API, ele é assíncrono por natureza.

---

## Netskope

### O que é e como funciona

O Netskope é um SSE. Na máquina do usuário roda o **Netskope Client** (um agente). Ele faz o **steering**: decide qual tráfego é desviado para a nuvem do Netskope e qual segue direto. A configuração de steering costuma ter listas de exceção (bypass) por domínio, aplicação ou processo.

Componentes principais:

| Componente | Função |
|---|---|
| **NG-SWG** | Proxy de saída com inspeção TLS, categorias e antivírus. |
| **CASB inline** | Controle de atividade dentro do SaaS (Upload, Download, Share, Login). |
| **CASB API** | Varredura retroativa via API do tenant SaaS. |
| **Cloud Firewall** | Controle de portas e protocolos não-web (não só 80/443). |
| **NPA** | Netskope Private Access — o ZTNA da solução, substitui VPN. |
| **Skope IT** | Console de eventos e logs (Page Events, Application Events, Alerts). |

As políticas ficam em **Real-time Protection**, avaliadas de cima para baixo, primeira que casa vence.

### Fail-open vs fail-close

Quando o client não consegue falar com a nuvem do Netskope:

- **Fail-open**: o tráfego segue direto, sem inspeção. Usuário navega normal, mas você fica cego.
- **Fail-close**: o tráfego é bloqueado. É o modo seguro, e é o que gera o chamado clássico.

O que o usuário sente no fail-close: o `ping 8.8.8.8` funciona, o DNS resolve, mas **nada abre no navegador**. Ele jura que "a internet caiu", mas o problema é o agente de segurança em estado degradado. Sempre peça o status do client antes de culpar o link.

### Como aparece nos logs

```
timestamp=2026-09-03T14:22:07Z user=jsilva@empresa-exemplo.com.br device=NB-JSILVA-01
srcip=10.10.34.22 dstip=203.0.113.45 url=drive.example.com/upload
app=Cloud Storage Example activity=Upload object=contratos_2026.xlsx
traffic_type=CloudApp access_method=Client policy=DLP-Financeiro
action=block dlp_profile=CPF-Cartao dlp_incident_id=88213
category=Cloud Storage ccl=medium os=Windows 11 bytes=2148992
```

<details><summary>Ver legenda</summary>

| Campo | Significado |
|---|---|
| `access_method` | `Client` (inline pelo agente), `Tunnel` (IPsec/GRE) ou `API` (retroativo). |
| `activity` | Ação dentro do SaaS: Upload, Download, Share, Login, Delete. |
| `traffic_type` | `CloudApp` (SaaS conhecido) ou `Web` (navegação genérica). |
| `ccl` | Cloud Confidence Level — nota de risco da aplicação (poor a excellent). |
| `dlp_profile` | Qual regra de dado sensível disparou. |
| `action` | allow, block, alert, useralert (usuário pôde justificar e seguir). |

</details>

**O que o SOC N1 observa.** Normal: uploads para o storage corporativo aprovado, `action=allow`. Suspeito: mesmo usuário fazendo `activity=Upload` para uma aplicação com `ccl=poor` fora do horário, ou uma sequência de `Download` em massa do SaaS corporativo seguida de `Upload` para storage pessoal — padrão de exfiltração (MITRE **T1567.002**, Exfiltration to Cloud Storage).

**Erro comum de júnior:** confundir `action=useralert` com bloqueio. Não é. O usuário clicou em "continuar mesmo assim" e o dado saiu.

---

## Zscaler

### O que é e como funciona

Dois produtos distintos que os juniores misturam o tempo todo:

- **ZIA** (Zscaler Internet Access) — o SWG/CASB, tráfego **de dentro para a internet**.
- **ZPA** (Zscaler Private Access) — o ZTNA, acesso **do usuário para aplicações internas**, sem VPN.

O tráfego chega ao ZIA por três caminhos: o **Zscaler Client Connector** (agente na máquina), túnel **GRE** ou túnel **IPsec** saindo do firewall da filial. Os logs saem do tenant para o SIEM através do **NSS** (Nanolog Streaming Service), que envia em syslog num formato de campos definido por template.

### Como aparece nos logs

```
<134>1 2026-09-03T15:04:11Z zscaler-nss ZIA - - - user=maria.costa@empresa-exemplo.com.br
clienttranstime=142 dept=Financeiro location=Filial-SP-GRE
url=downloads.example.net/setup.exe urlcategory=Shareware_and_Freeware
urlsupercategory=Bandwidth_Loss appname=Generic_Browsing action=blocked
reason=Malware_Detected threatname=W32.Example.Trojan malwareclass=Virus
riskscore=92 reqsize=812 respsize=0 serverip=198.51.100.77 clientip=10.20.5.61
```

<details><summary>Ver legenda</summary>

| Campo | Significado |
|---|---|
| `location` | De onde o tráfego entrou (GRE/IPsec da filial ou Road Warrior via agente). |
| `urlcategory` / `urlsupercategory` | Categorização do destino, o filtro principal do SWG. |
| `action` | allowed, blocked, cautioned (aviso com opção de seguir). |
| `reason` | Por que o veredito: política, malware, DLP, sandbox. |
| `riskscore` | 0–100; acima de 80 trate como prioridade. |
| `respsize` | Bytes de resposta. `0` num bloqueio confirma que nada foi entregue. |

</details>

**O que o SOC N1 observa.** `action=blocked` com `respsize=0` é um bloqueio bem-sucedido: o payload não chegou. Se vier `action=allowed` para `.exe` de categoria Shareware, escale — verifique se o arquivo executou no endpoint (Sysmon Event ID 1).

---

## Symantec/Broadcom Blue Coat ProxySG

Produto tradicional, on-premises, ainda muito presente em banco e indústria. Grava o **access.log** no formato **ELFF** (Extended Log File Format), que começa com uma linha `#Fields:` declarando a ordem das colunas — sem ela, o log é ilegível. A categorização vem do **WebPulse**, o serviço de reputação em nuvem da Symantec.

```
#Fields: date time c-ip cs-username cs-host cs-uri-path sc-status s-action sc-bytes cs-categories
2026-09-03 16:11:02 10.30.7.19 admin.rodrigo cdn.example.org /js/loader.js 200 TCP_HIT 4821 "Technology"
2026-09-03 16:11:44 10.30.7.19 admin.rodrigo paste.example.net /raw/a91f 403 TCP_DENIED 0 "Suspicious;Uncategorized"
```

<details><summary>Ver legenda</summary>

| Campo | Significado |
|---|---|
| `c-ip` / `cs-username` | IP e usuário autenticado no proxy. |
| `sc-status` | Código HTTP devolvido ao cliente (`403` = negado pelo proxy). |
| `s-action` | Decisão do proxy: `TCP_HIT` (cache), `TCP_NC_MISS` (buscou na origem), `TCP_DENIED` (bloqueou), `TCP_TUNNELED` (CONNECT sem inspeção). |
| `cs-categories` | Categoria WebPulse; `Uncategorized` em domínio novo é forte indício de C2. |

</details>

**Erro comum de júnior:** somar bytes de linhas `TCP_HIT` para medir exfiltração. `TCP_HIT` foi servido do cache local — não saiu nada para a internet.

### Consultas úteis

```spl
index=proxy sourcetype=netskope action=block dlp_profile=*
| stats count values(object) as arquivos by user, app
| where count > 5
```

```kql
// Sentinel: uploads para storage de baixa confiança nas últimas 24h
NetskopeEvents
| where TimeGenerated > ago(24h)          // janela de análise
| where Activity == "Upload" and Ccl in ("poor","low")  // app mal avaliada
| summarize Total=sum(Bytes), Eventos=count() by User, App  // agrega por usuário
| where Total > 50000000                  // acima de ~50 MB, investigar
```

### Exercícios — SWG, CASB, DLP, ZTNA, SASE e os produtos de mercado

1. Um usuário abre chamado: "a internet caiu, mas o ping para 8.8.8.8 funciona e o WhatsApp Web não abre". Qual a hipótese mais provável e qual o próximo passo?
2. No log Netskope acima, o campo é `action=useralert`. O dado saiu da empresa? Justifique.
3. Um alerta de DLP do Netskope chega 45 minutos depois do upload, com `access_method=API`. Isso é falso positivo por atraso?
4. No access.log do ProxySG, você soma 1,2 GB de `sc-bytes` para o usuário jsilva e abre incidente de exfiltração. Que erro você pode ter cometido?
5. A empresa quer aposentar a VPN e dar acesso só ao servidor de RH para o time de RH. Qual sigla resolve, e por quê não é SWG?

<details><summary>Ver gabarito</summary>

1. **Netskope Client em fail-close.** O ICMP e o DNS passam, mas o tráfego web fica bloqueado porque o agente não consegue falar com a nuvem e o modo configurado é fail-close. Próximo passo: verificar o status do client na máquina (tunnel up/down) e a versão do agente; só depois olhar o link. Culpar a operadora primeiro é o erro clássico.

2. **Sim, o dado saiu.** `useralert` significa que a política mostrou um aviso e permitiu que o usuário justificasse e prosseguisse. Só `action=block` impede a transferência. Trate como incidente de dado e busque o `dlp_incident_id` para ver o conteúdo detectado.

3. **Não é falso positivo.** O modo API é assíncrono por desenho: o Netskope consulta o tenant SaaS via API e detecta **depois** que o arquivo subiu. Atraso é comportamento esperado. O que muda é a resposta: como não houve bloqueio, é preciso agir sobre o arquivo (remover compartilhamento, revogar link).

4. Você provavelmente somou linhas com `s-action=TCP_HIT`, que foram servidas do **cache do proxy** e não representam bytes enviados para a internet. Além disso, `sc-bytes` é o tráfego **do servidor para o cliente** (download). Para exfiltração, olhe os bytes de requisição do cliente e filtre por `TCP_NC_MISS` ou `TCP_TUNNELED`.

5. **ZTNA** (no Netskope, NPA; na Zscaler, ZPA). Ele publica **uma aplicação específica** para um grupo de usuários, sem colocar o dispositivo na rede interna — o oposto da VPN, que entrega uma sub-rede inteira. SWG não serve porque cuida do caminho **de dentro para a internet**, e aqui o fluxo é do usuário para uma aplicação **interna**.

</details>


## Logs de proxy na prática: lendo linha a linha

Um log de proxy é o extrato bancário da navegação da empresa. Assim como o extrato mostra data, valor, estabelecimento e se a compra foi aprovada ou negada, o log de proxy mostra quem navegou, para onde, quantos bytes trafegaram e se o acesso foi permitido ou bloqueado. Quem sabe ler esse extrato descobre quase tudo sobre um incidente.

### Squid access.log

O Squid é um proxy livre, muito usado em laboratório e em ambientes menores. O formato nativo é simples e sem cabeçalho, o que assusta no começo.

```
1725362410.482    312 10.10.20.45 TCP_MISS/200 18422 GET http://portal.example.com/index.html jsilva HIER_DIRECT/203.0.113.20 text/html
1725362488.117     44 10.10.20.45 TCP_DENIED/403 3894 GET http://jogos.example.com/ jsilva HIER_NONE/- text/html
1725362533.905   1180 10.10.20.45 TCP_MISS/200 4194304 GET http://cdn-update.example.com/setup.exe jsilva HIER_DIRECT/198.51.100.77 application/octet-stream
```

<details><summary>Ver legenda</summary>

| Posição | Campo | Significado |
|---|---|---|
| 1 | `1725362410.482` | Data em epoch Unix (segundos desde 1970) com milissegundos |
| 2 | `312` | Duração da requisição em milissegundos |
| 3 | `10.10.20.45` | IP interno do cliente (a estação do usuário) |
| 4 | `TCP_MISS/200` | Código do cache + código HTTP de resposta |
| 5 | `18422` | Bytes entregues ao cliente |
| 6 | `GET` | Método HTTP |
| 7 | `http://...` | URL completa (em HTTPS sem inspeção aparece só `host:443`) |
| 8 | `jsilva` | Usuário autenticado no proxy |
| 9 | `HIER_DIRECT/203.0.113.20` | Como o Squid buscou o objeto e o IP de destino real |
| 10 | `text/html` | Content-Type devolvido |

</details>

Os códigos de cache mais comuns: `TCP_MISS` (não estava em cache, buscou na internet), `TCP_HIT` (serviu do cache), `TCP_DENIED` (o proxy recusou antes de sair), `TCP_TUNNEL` (CONNECT de HTTPS repassado).

**O que o SOC N1 observa:** `TCP_DENIED/403` isolado é rotina — alguém clicou num banner. Dezenas de `TCP_DENIED` seguidos do mesmo IP, ou um `TCP_MISS/200` de 4 MB com `application/octet-stream`, merecem análise.

**Erro comum de analista júnior:** achar que `TCP_DENIED/403` significa "ameaça bloqueada". Significa apenas que a política negou; pode ser categoria "Jogos". O bloqueio de malware costuma vir com código próprio do produto, não com um 403 genérico.

### Blue Coat / Symantec ProxySG — formato ELFF

ELFF significa *Extended Log File Format* (formato estendido de arquivo de log). A grande vantagem é que os nomes dos campos vêm declarados numa linha `#Fields` no topo do arquivo.

```
#Fields: date time c-ip cs-username cs-host cs-uri-stem s-action sc-status sc-filter-result cs(User-Agent) sc-bytes cs-bytes cs-categories
2026-09-03 14:21:07 10.10.20.45 jsilva arquivos.example.com /doc/fatura.zip TCP_NC_MISS 200 OBSERVED "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" 512340 812 "Armazenamento Online"
2026-09-03 14:22:55 10.10.31.90 maria.costa apostas.example.com / TCP_DENIED 403 PROXIED "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" 1204 640 "Apostas"
```

<details><summary>Ver legenda</summary>

| Campo ELFF | Leitura em português |
|---|---|
| `c-ip` | IP do cliente |
| `cs-username` | usuário autenticado (client to server) |
| `cs-host` / `cs-uri-stem` | domínio e caminho pedidos |
| `s-action` | ação do proxy (`TCP_NC_MISS`, `TCP_DENIED`, `TCP_TUNNELED`) |
| `sc-status` | código HTTP devolvido ao cliente |
| `sc-filter-result` | `OBSERVED` (permitido) ou `PROXIED`/`DENIED` |
| `cs(User-Agent)` | identificação do navegador ou ferramenta |
| `sc-bytes` / `cs-bytes` | bytes baixados / bytes enviados |
| `cs-categories` | categoria atribuída ao site |

</details>

### Zscaler NSS

O NSS (*Nanolog Streaming Service*) exporta o log da nuvem Zscaler para o SIEM, geralmente em CSV ou key=value.

```
2026-09-03 14:31:02,jsilva@empresa-exemplo.com.br,10.10.20.45,203.0.113.44,cdn-update.example.com,/pacote/setup.exe,Blocked,Malware,"Sandbox: Malicious",4194304,1024,"python-requests/2.31.0",EXE,d2f1a9c47b3e5568aa10c9f4e7b21d3c9f0a5e6b7c8d9e0f1a2b3c4d5e6f7a8b
```

Campos na ordem: data/hora, usuário, IP interno, IP público de destino, host, caminho, ação (`Allowed`/`Blocked`), categoria de ameaça, motivo, bytes recebidos, bytes enviados, user-agent, tipo de arquivo e **hash SHA-256** do objeto. Esse hash é ouro: é ele que você joga no EDR e na base de reputação.

### Netskope

O Netskope junta proxy web com CASB (*Cloud Access Security Broker*, corretor de acesso a nuvem), então o log traz campos de aplicação em nuvem.

```json
{"timestamp":"2026-09-03T14:45:19Z","user":"maria.costa@empresa-exemplo.com.br","srcip":"10.10.31.90","dstip":"203.0.113.150","app":"Google Drive Pessoal","appcategory":"Cloud Storage","activity":"Upload","object":"base_clientes.xlsx","object_size":48211456,"action":"alert","policy":"DLP-Dados-Clientes","dlp_rule":"PII-BR-CPF","dlp_incident_id":"INC-77120","ccl":"medium","user_agent":"Mozilla/5.0"}
```

<details><summary>Ver legenda</summary>

| Campo | Para que serve na investigação |
|---|---|
| `app` / `appcategory` | qual serviço em nuvem e de que tipo |
| `activity` | `Login`, `Upload`, `Download`, `Share` — o verbo do que aconteceu |
| `object` / `object_size` | nome e tamanho do arquivo movimentado |
| `action` | `allow`, `alert`, `block`, `useralert` |
| `dlp_rule` | qual regra de DLP disparou (aqui, padrão de CPF) |
| `ccl` | *Cloud Confidence Level* — reputação da aplicação em nuvem |

</details>

## Seis cenários de investigação

### Cenário 1 — Usuário clicou em phishing

```
2026-09-03 09:12:44 10.10.20.45 jsilva login-portal.example.com /auth/verify TCP_NC_MISS 200 OBSERVED 8210 "Phishing"
2026-09-03 09:13:02 10.10.20.45 jsilva login-portal.example.com /files/anexo.exe TCP_NC_MISS 200 OBSERVED 2870144 "Phishing"
```

Raciocínio do N1: (1) confirmar o clique pelo horário e pelo `referer`; (2) ver se houve download — aqui houve, 2,8 MB de `.exe`; (3) pegar o hash do arquivo no log do proxy ou pedir ao Sysmon Event ID 1 (criação de processo) e Event ID 11 (criação de arquivo) na estação; (4) buscar o hash no EDR em toda a frota; (5) se executou, escalar para N2. Técnica MITRE relacionada: T1566.002 (*Phishing: Spearphishing Link*).

```spl
index=proxy sourcetype=bluecoat cs_categories="Phishing" sc_status=200
| stats values(cs_host) AS host values(cs_uri_stem) AS caminho sum(sc_bytes) AS bytes BY cs_username
| where bytes > 100000
```

```kql
// Sentinel: liga o acesso a phishing com download de executável na mesma estação
CommonSecurityLog
| where DeviceVendor == "Blue Coat" and DeviceCustomString1 == "Phishing"
| where RequestURL endswith ".exe" or RequestURL endswith ".zip"
| project TimeGenerated, SourceUserName, SourceIP, RequestURL, ReceivedBytes
```

### Cenário 2 — Executável vindo de domínio recém-registrado

Domínio criado há 3 dias entregando `.exe` é um dos sinais mais fortes que existem. Confira a idade do domínio no WHOIS e correlacione com a categoria "Newly Registered Domain" que SWGs modernos já atribuem.

```spl
index=proxy (url="*.exe" OR file_type=EXE) action=allowed
| lookup dominios_novos dominio AS dest_host OUTPUT dias_registro
| where dias_registro < 30
| table _time user src_ip dest_host url bytes_in file_hash
```

### Cenário 3 — Upload anormal para nuvem pessoal

O log Netskope acima mostra 48 MB de `base_clientes.xlsx` para Drive pessoal com regra de CPF disparada. Passos: confirmar se a conta é corporativa ou pessoal (`app` diz "Pessoal"), medir o volume dos últimos 7 dias do mesmo usuário, verificar se ele está em processo de desligamento e acionar o time de RH/jurídico. MITRE T1567.002 (*Exfiltration to Cloud Storage*).

```kql
NetskopeAlerts_CL
| where activity_s == "Upload" and appcategory_s == "Cloud Storage"
| summarize TotalMB = sum(object_size_d)/1024/1024, Arquivos = count() by user_s, bin(TimeGenerated, 1d)
| where TotalMB > 100
```

### Cenário 4 — Acesso repetido a categoria bloqueada

```
1725367001.220 12 10.10.20.45 TCP_DENIED/403 3894 GET http://proxy-livre.example.com/ jsilva HIER_NONE/- text/html
1725367014.880 11 10.10.20.45 TCP_DENIED/403 3894 GET http://tunel-web.example.com/ jsilva HIER_NONE/- text/html
1725367029.640 10 10.10.20.45 TCP_DENIED/403 3894 GET http://anon-browse.example.com/ jsilva HIER_NONE/- text/html
```

<details><summary>Ver legenda</summary>

| Campo | Valor nas três linhas | O que significa |
|---|---|---|
| *timestamp* | `1725367001.220`, `1725367014.880`, `1725367029.640` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos. **Cerca de 14 segundos entre cada tentativa** |
| duração | `12`, `11`, `10` | Milissegundos. Tão rápido porque a decisão é local: o proxy nem consultou a rede |
| cliente | `10.10.20.45` | Sempre a mesma estação |
| resultado/status | `TCP_DENIED/403` nas três | A política barrou todas |
| bytes | `3894` nas três | O mesmo tamanho: é a mesma página de bloqueio |
| método | `GET` | Pedido de leitura |
| URL | `proxy-livre.example.com`, `tunel-web.example.com`, `anon-browse.example.com` | **Três domínios diferentes, todos da mesma categoria.** Isso separa erro de clique de tentativa deliberada |
| usuário | `jsilva` | A mesma conta autenticada nas três — não há dúvida sobre quem foi |
| hierarquia/destino | `HIER_NONE/-` | Nada saiu para a Internet |
| tipo de conteúdo | `text/html` | A página de bloqueio devolvida |

</details>

Três domínios diferentes da categoria "Proxy Avoidance" em 30 segundos é tentativa deliberada de burlar o controle, não erro de clique. Ação: registrar, notificar o gestor e a segurança de RH. Se depois aparecer um `TCP_TUNNEL` permitido para um desses, houve bypass — vira incidente.

```spl
index=proxy action=blocked category IN ("Proxy Avoidance","Anonymizer")
| bin _time span=10m
| stats dc(dest_host) AS dominios count AS tentativas BY user _time
| where tentativas >= 5
```

### Cenário 5 — User-agent estranho

```
2026-09-03 03:14:08 10.10.31.90 - api-cdn.example.com /a/b.bin TCP_NC_MISS 200 OBSERVED "python-requests/2.31.0" 1048576
2026-09-03 03:14:39 10.10.31.90 - api-cdn.example.com /a/c.bin TCP_NC_MISS 200 OBSERVED "curl/8.4.0" 1048576
2026-09-03 03:15:10 10.10.31.90 - api-cdn.example.com /a/d.bin TCP_NC_MISS 200 OBSERVED "Mozilla/5.0 (Windows NT; WOW64) WindowsPowerShell/5.1.19041" 1048576
```

Navegador de gente não se chama `python-requests`. Em estação de usuário comum, `curl`, `python-requests` ou o user-agent do PowerShell (produzido por `Invoke-WebRequest`) às 3 da manhã indicam script ou malware. Correlacione com Sysmon Event ID 1 e Event ID 3 (conexão de rede) para saber qual processo abriu a conexão. MITRE T1105 (*Ingress Tool Transfer*).

```kql
// Defender: quem executou o processo que fez a conexão
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("powershell.exe","curl.exe","python.exe")
| where RemoteUrl != ""
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP
```

### Cenário 6 — IP direto e beaconing

```
1725370800.101 90 10.10.20.45 TCP_TUNNEL/200 512 CONNECT 192.0.2.66:443 jsilva HIER_DIRECT/192.0.2.66 -
1725371100.104 88 10.10.20.45 TCP_TUNNEL/200 516 CONNECT 192.0.2.66:443 jsilva HIER_DIRECT/192.0.2.66 -
1725371400.099 91 10.10.20.45 TCP_TUNNEL/200 510 CONNECT 192.0.2.66:443 jsilva HIER_DIRECT/192.0.2.66 -
```

Duas anomalias juntas: destino é IP puro, sem nome de domínio (navegador de gente quase sempre usa nome), e o intervalo é de exatamente 300 segundos, com bytes quase idênticos. Isso é *beaconing* — o padrão de um agente de comando e controle "batendo ponto". MITRE T1071.001 (*Application Layer Protocol: Web Protocols*).

```spl
index=proxy method=CONNECT
| rex field=dest "^(?<ip_puro>\d+\.\d+\.\d+\.\d+)$"
| where isnotnull(ip_puro)
| streamstats current=f last(_time) AS anterior BY src_ip, dest
| eval delta=_time-anterior
| stats count avg(delta) AS media stdev(delta) AS desvio BY src_ip dest
| where count > 10 AND desvio < 5
```

### Exercícios — Logs de proxy na prática e investigação no SOC

1. No Squid, qual a diferença prática entre `TCP_DENIED/403` e `TCP_MISS/200` para a triagem?
2. O log mostra `sc-bytes 2870144` e `cs-bytes 640`. Quem baixou o quê?
3. Alerta: `python-requests/2.31.0` acessando `api.pagamentos.example.com` a partir de `10.10.50.10`, servidor `svc_backup`, todo dia às 02:00. Verdadeiro ou falso positivo?
4. Você achou o download `.exe` no proxy mas não tem o hash. Qual o próximo passo?
5. Beaconing a cada 300 s com desvio de 2 s. Calcule quantas conexões em 24 horas.

<details><summary>Ver gabarito</summary>

1. `TCP_DENIED/403` = a política do proxy barrou antes de sair para a internet; nada trafegou, risco baixo, foco em comportamento do usuário. `TCP_MISS/200` = a requisição saiu e voltou com sucesso; aqui há conteúdo real entrando na rede, então avalie tamanho, Content-Type e reputação do destino.
2. `sc-bytes` é *server to client*: 2.870.144 bytes (cerca de 2,8 MB) desceram para a estação. `cs-bytes` é *client to server*: só 640 bytes subiram, típico de um GET. Portanto foi um **download**, não upload.
3. Provável **falso positivo**, mas confirme antes de fechar. É uma conta de serviço (`svc_backup`), num servidor, com horário fixo de janela de backup e destino interno de negócio — script legítimo usa mesmo `python-requests`. Confirme com o dono da aplicação e coloque em lista de exceção documentada. Se fosse a estação da `maria.costa`, seria verdadeiro positivo.
4. Peça o hash na ponta: Sysmon Event ID 11 registra a criação do arquivo e o EDR calcula SHA-256; alternativamente, o Event ID 1 traz `Hashes=` quando o binário é executado. Com o hash em mãos, faça busca retroativa na frota inteira e só então consulte reputação. Nunca baixe de novo o arquivo pela sua própria estação.
5. 24 h = 86.400 s. 86.400 ÷ 300 = **288 conexões por dia**, praticamente constantes. Regularidade é justamente o que denuncia automação: humano navega em rajadas irregulares.

</details>

## Mini-laboratório — Proxies: subir um Squid e ler os próprios logs

**Pré-requisitos:** Docker instalado, uma máquina Linux ou WSL, Wireshark opcional.

1. Suba o proxy:
   `docker run -d --name lab-squid -p 3128:3128 ubuntu/squid:latest`
2. Confirme que subiu: `docker ps` deve listar `lab-squid` com a porta 3128 mapeada.
3. Gere tráfego permitido: `curl -x http://127.0.0.1:3128 http://example.com/ -o /dev/null`
4. Acompanhe o log em tempo real: `docker exec -it lab-squid tail -f /var/log/squid/access.log`
   Observe a linha com `TCP_MISS/200` e o `text/html`.
5. Repita o mesmo `curl`. Agora deve aparecer `TCP_HIT` ou `TCP_REFRESH_HIT` — o objeto veio do cache.
6. Crie um bloqueio: entre no container com `docker exec -it lab-squid bash`, adicione ao `/etc/squid/squid.conf` uma ACL `acl bloqueados dstdomain .example.org` e `http_access deny bloqueados`, depois recarregue com `squid -k reconfigure`.
7. Teste: `curl -x http://127.0.0.1:3128 http://www.example.org/ -v`. O log deve trazer `TCP_DENIED/403`.
8. Teste o user-agent: `curl -x http://127.0.0.1:3128 -A "python-requests/2.31.0" http://example.com/`. Confira como o campo aparece se você ativar o formato `combined` no `logformat`.
9. Opcional: capture com `tcpdump -i lo -n port 3128 -w lab-proxy.pcap` e abra no Wireshark com o filtro `http.request` para ver o `CONNECT` e o `GET`.

**Critério de sucesso:** você consegue apontar no seu próprio `access.log` uma linha `TCP_MISS/200`, uma `TCP_HIT` e uma `TCP_DENIED/403`, e explicar cada um dos dez campos sem consultar a tabela.

## O que um SOC Level 1 realmente precisa saber

- 🟢 Ler os dez campos do Squid `access.log` e traduzir `TCP_MISS`, `TCP_HIT`, `TCP_DENIED` e `TCP_TUNNEL`.
- 🟢 Diferenciar bloqueio por categoria (política de uso) de bloqueio por ameaça (segurança) — a urgência é totalmente diferente.
- 🟢 Saber que `sc-bytes` é download e `cs-bytes` é upload, e usar isso para separar exfiltração de simples navegação.
- 🟢 Reconhecer user-agents que não são de navegador: `curl`, `python-requests`, `WindowsPowerShell`, `wget`.
- 🟢 Levar sempre estes cinco dados para o ticket: horário, usuário, IP interno, destino (host e IP) e ação do proxy.
- 🟡 Extrair o hash SHA-256 do log (Zscaler) ou do Sysmon Event ID 1/11 e buscá-lo no EDR em toda a frota.
- 🟡 Entender que em HTTPS sem inspeção você só vê `CONNECT host:443` e o volume — nunca a URL completa.
- 🟡 Identificar acesso a IP puro sem hostname e calcular intervalo entre conexões para suspeitar de beaconing.
- 🟡 Interpretar campos de CASB e DLP: `activity`, `app`, `dlp_rule`, `object_size`.
- 🔴 Escrever SPL/KQL com `streamstats` e `stdev` para caçar periodicidade de C2 sem depender de assinatura.
- 🔴 Correlacionar log de proxy com Zeek `ssl.log` (JA3, SNI) e Suricata EVE para confirmar um túnel malicioso.
- 🔴 Avaliar impacto de exceções de inspeção TLS: cada domínio na lista de bypass é um ponto cego permanente.

## Resumo em 10 linhas

1. O proxy é o intermediário obrigatório da navegação e, por isso, a melhor fonte de evidência web do SOC.
2. Forward protege o usuário saindo, reverse protege o servidor entrando, transparente age sem configuração no cliente.
3. Inspeção TLS é o que transforma um log cego (`CONNECT host:443`) num log rico com URL, arquivo e hash.
4. SWG, CASB, DLP e ZTNA convergem em SASE, mas o log continua sendo a matéria-prima da investigação.
5. No Squid, aprenda os dez campos; em Blue Coat, leia a linha `#Fields`; em Zscaler e Netskope, procure hash e regra de DLP.
6. Bloqueio de categoria é comportamento; bloqueio de ameaça é incidente — não trate os dois igual.
7. Volume assimétrico (muito upload) aponta exfiltração; volume de download com `.exe` aponta entrega de malware.
8. User-agent não humano, domínio recém-registrado e IP puro sem hostname são três gatilhos clássicos de triagem.
9. Beaconing se reconhece pela regularidade: mesmo destino, mesmo intervalo, mesmo tamanho, repetido por horas.
10. Toda conclusão de N1 precisa de correlação: proxy diz o quê e para onde; EDR, Sysmon e Zeek dizem quem e como.



---
