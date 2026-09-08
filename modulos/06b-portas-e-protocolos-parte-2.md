# Módulo 06b — Portas e Protocolos (Parte 2)

Por que este módulo importa para o SOC: as portas da parte 1 (DNS, HTTP, SSH) contam onde o tráfego vai. As portas desta parte contam **quem é você dentro da empresa** e **o que você acessa**. LDAP guarda o diretório de usuários, HTTPS carrega quase todo o tráfego moderno (inclusive o malicioso) e SMB é o protocolo que ransomware e movimento lateral mais amam. Um analista de SOC Nível 1 (N1) que sabe ler as portas 389, 443 e 445 já detecta a maioria dos incidentes reais de uma rede corporativa.

Índice do módulo:

- LDAP 389, HTTPS 443 e SMB 445
- Correio seguro, syslog, LDAPS e bancos de dados
- RDP, PostgreSQL, VNC, 8080 e as tabelas mestras

---

## Porta 389 — LDAP (Lightweight Directory Access Protocol)

Imagine a lista telefônica antiga do prédio: quem mora em cada apartamento, o telefone e o cargo. O **LDAP** é essa lista, só que da empresa inteira — e o **Active Directory (AD)**, o diretório da Microsoft, responde nessa porta.

**O que é.** Protocolo de consulta a diretório. Na porta **389/TCP** (e também 389/UDP para o serviço de localização de controlador de domínio, chamado CLDAP) o tráfego é **em texto claro**, sem criptografia. A versão cifrada é a 636 (LDAPS), tratada no próximo trecho.

**Como funciona.** O cliente abre a conexão, faz um **bind** (autenticação: usuário e senha, ou "anônimo", sem credencial) e depois envia **search** com um filtro. O servidor devolve os objetos: usuários, grupos, computadores, unidades organizacionais.

**Exemplo prático.** A estação `10.10.20.45` do usuário `jsilva` consulta o controlador de domínio `10.10.5.10` (`dc01.corp.local`) para descobrir de quais grupos o usuário faz parte. Isso é normal e acontece o dia inteiro.

**Como aparece nos logs.** Zeek (`conn.log`, campos separados por tabulação):

```
ts                    uid            id.orig_h    id.orig_p  id.resp_h   id.resp_p  proto  service  duration  orig_bytes  resp_bytes  conn_state
1756900112.481293     CmT4xz1a2b3c   10.10.20.45  49712      10.10.5.10  389        tcp    ldap     0.184     412         2890        SF
1756900140.902117     CkQ9pl4d5e6f   10.10.20.88  50331      10.10.5.10  389        tcp    ldap     91.740    184320      41287600    SF
```

<details><summary>Ver legenda</summary>

| Campo | 1ª linha (normal) / 2ª linha (suspeita) | O que significa |
|---|---|---|
| `ts` | `1756900112.481293` / `1756900140.902117` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos (aqui com microssegundos) |
| `uid` | `CmT4xz1a2b3c` / `CkQ9pl4d5e6f` | Identificador único de cada conexão |
| `id.orig_h` | `10.10.20.45` / `10.10.20.88` | Origem. São **estações diferentes** — a comparação é entre elas |
| `id.orig_p` | `49712` / `50331` | Porta de origem, efêmera |
| `id.resp_h` / `id.resp_p` | `10.10.5.10` / `389` | O mesmo controlador de domínio, na porta LDAP, nas duas |
| `proto` | `tcp` | Transporte |
| `service` | `ldap` | Protocolo identificado pela inspeção do conteúdo |
| `duration` | `0.184` / `91.740` | Duração em segundos. **Meio segundo é uma consulta; 91 segundos é uma varredura do diretório** |
| `orig_bytes` | `412` / `184320` | Payload enviado. A 2ª mandou 450 vezes mais pedidos |
| `resp_bytes` | `2890` / `41287600` | Payload devolvido: 2,8 KB contra **41 MB**. Isso é o diretório inteiro saindo — enumeração de AD |
| `conn_state` | `SF` | As duas completaram normalmente. O desfecho não denuncia nada: **o volume e a duração denunciam** |

</details>


Compare as duas linhas. A primeira é uma consulta comum: 0,18 segundo e 2,8 KB de resposta. A segunda durou **91 segundos** e o controlador devolveu **41 MB**. Isso não é um usuário consultando um grupo — é alguém **baixando o diretório inteiro**. É exatamente o rastro do **SharpHound**, o coletor do **BloodHound**, ferramenta que mapeia caminhos de ataque no AD (MITRE ATT&CK **T1087** – Account Discovery e **T1069** – Permission Groups Discovery).

**Riscos.**

| Risco | Por que importa |
|---|---|
| Texto claro | Credencial de bind simples trafega legível; quem captura o pacote lê a senha |
| Bind anônimo | Permite consultar o diretório sem nenhuma credencial |
| Enumeração em massa | Atacante lista todos os usuários, grupos e computadores em minutos |
| Insumo para outros ataques | A lista de usuários alimenta password spraying e Kerberoasting |

**O que o SOC N1 observa.**

- Normal: estações e servidores falando 389 com os controladores de domínio, sessões curtas, poucos KB.
- Suspeito: uma **única estação** consultando o controlador com sessão longa e dezenas de MB de resposta; uma máquina que nunca falou LDAP começando a falar; LDAP **saindo para a internet**.

**Erro comum de analista júnior:** ver "LDAP para o controlador de domínio" e fechar como normal sem olhar o **volume**. Em LDAP, o alerta quase nunca está na existência da conexão — está no tamanho e na duração dela.

Consulta em SPL (Splunk) para caçar a rajada:

```spl
index=zeek sourcetype=zeek:conn dest_port=389
| stats sum(resp_bytes) AS bytes_recebidos, count AS conexoes by src_ip, dest_ip
| eval mb=round(bytes_recebidos/1024/1024,2)
| where mb > 10
| sort - mb
```

Linha 1 filtra só LDAP. Linha 2 soma os bytes por par origem/destino. Linha 3 converte para MB. Linha 4 mantém quem passou de 10 MB. Linha 5 ordena do maior para o menor.

---

## Porta 443 — HTTPS (HTTP sobre TLS)

Analogia: um envelope lacrado dos Correios. Você não lê a carta, mas ainda vê o **destinatário no envelope**, o **carimbo**, o **peso** e **quantos envelopes** foram enviados por hora. É assim que o SOC trabalha com HTTPS.

**O que é.** Tráfego web protegido por **TLS (Transport Layer Security)**, o sucessor do SSL. Hoje é a porta mais usada da internet — e por isso também a preferida de atacantes: passa em qualquer firewall sem chamar atenção.

**Como funciona.** Antes de trocar dados, cliente e servidor fazem o **handshake**. No primeiro pacote (`Client Hello`) o cliente informa, **em texto claro**, o **SNI (Server Name Indication)** — o nome do site que quer acessar. O servidor responde com o **certificado**, também visível. Só depois tudo é cifrado.

**O que o SOC ainda vê mesmo com o tráfego cifrado.** Esta é a parte mais importante do trecho:

| Sinal visível | O que revela |
|---|---|
| SNI | O domínio pedido, mesmo sem descriptografar |
| Certificado (emissor, CN, validade) | Certificado autoassinado ou recém-emitido é suspeito |
| JA3 / JA3S | "Impressão digital" de como o cliente monta o handshake; identifica a biblioteca ou malware, não o site |
| Tamanho dos pacotes | Respostas minúsculas e repetitivas indicam batimento de comando e controle |
| Ritmo (beaconing) | Conexões em intervalos regulares — a marca do C2 (Command and Control) |
| IP e ASN de destino | Destino em provedor incomum para a empresa |

**Exemplo prático.** A estação `10.10.20.61` de `maria.costa` conecta a cada 60 segundos ao IP `203.0.113.77`, com SNI `cdn-update.example.com` e certificado autoassinado válido por 90 dias.

**Como aparece nos logs.** Zeek `ssl.log`:

```
ts                 id.orig_h     id.resp_h      id.resp_p  version  server_name              validation_status         ja3
1756901000.114     10.10.20.61   203.0.113.77   443        TLSv12   cdn-update.example.com   self signed certificate   a0e9f5d64349fb13191bc781f81f42e1
1756901060.207     10.10.20.61   203.0.113.77   443        TLSv12   cdn-update.example.com   self signed certificate   a0e9f5d64349fb13191bc781f81f42e1
1756901120.318     10.10.20.61   203.0.113.77   443        TLSv12   cdn-update.example.com   self signed certificate   a0e9f5d64349fb13191bc781f81f42e1
```

<details><summary>Ver legenda</summary>

| Campo | Valor nas três linhas | O que significa |
|---|---|---|
| `ts` | `1756901000.114`, `1756901060.207`, `1756901120.318` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos. **Exatamente 60 segundos entre cada uma** — é o batimento |
| `id.orig_h` | `10.10.20.61` | Sempre a mesma estação |
| `id.resp_h` / `id.resp_p` | `203.0.113.77` / `443` | Sempre o mesmo destino externo, em HTTPS |
| `version` | `TLSv12` | Versão do TLS negociada |
| `server_name` | `cdn-update.example.com` | O SNI pedido pelo cliente. Nome que imita CDN é disfarce comum |
| `validation_status` | `self signed certificate` | O certificado é autoassinado. **Contra um IP público isso quase nunca é legítimo** — CDN de verdade tem certificado válido |
| `ja3` | `a0e9f5d64349fb13191bc781f81f42e…` | Impressão digital do cliente TLS, **igual nas três**: é o mesmo binário a repetir. Procure este `ja3` na frota para achar as outras máquinas infectadas |

</details>


O mesmo evento em Palo Alto (log TRAFFIC, formato CSV):

```
1,2026/09/03 14:05:00,001801010101,TRAFFIC,end,2561,2026/09/03 14:05:00,10.10.20.61,203.0.113.77,0.0.0.0,0.0.0.0,regra-saida-web,corp\maria.costa,,ssl,vsys1,Trust,Untrust,ethernet1/2,ethernet1/1,Log-Padrao,2026/09/03 14:05:00,71234,1,51422,443,0,0,0x400053,tcp,allow,1842,912,930,14,,,,,,,,,0,,,,,,,,
```

<details><summary>Ver legenda</summary>

| Posição | Campo | Valor no exemplo | O que significa |
|---|---|---|---|
| 1, 6 | — | `1`, `2561` | Reservados pelo fabricante |
| 2 / 7 | Receive / Generated Time | `2026/09/03 14:05:00` | Quando o firewall recebeu e quando ocorreu |
| 3 | Serial Number | `001801010101` | Qual equipamento gerou |
| 4 / 5 | Type / Subtype | `TRAFFIC` / `end` | Log de sessão, no fim |
| 8 / 9 | Source / Destination Address | `10.10.20.61` / `203.0.113.77` | Origem interna e destino externo |
| 10 / 11 | NAT Source / Destination IP | `0.0.0.0` / `0.0.0.0` | **`0.0.0.0` significa "não houve NAT"**, e não o endereço zero. É o preenchimento que o PAN-OS usa quando o campo não se aplica |
| 12 | Rule Name | `regra-saida-web` | A regra que permitiu |
| 13 / 14 | Source / Destination User | `corp\maria.costa` / *(vazio)* | Usuário resolvido |
| 15 | Application | `ssl` | App-ID identificou TLS genérico |
| 16 | Virtual System | `vsys1` | Firewall virtual |
| 17 / 18 | Source / Destination Zone | `Trust` / `Untrust` | O sentido do tráfego |
| 19 / 20 | Inbound / Outbound Interface | `ethernet1/2` / `ethernet1/1` | Interfaces de entrada e saída |
| 21 / 22 | Log Action / — | `Log-Padrao` / `2026/09/03 14:05:00` | Perfil de log e campo reservado |
| 23 / 24 | Session ID / Repeat Count | `71234` / `1` | Sessão e contagem de repetições |
| 25 / 26 | Source / Destination Port | `51422` / `443` | Porta efêmera e porta de destino |
| 27 / 28 | NAT Source / Destination Port | `0` / `0` | Zero pelo mesmo motivo das posições 10 e 11: não houve tradução |
| 29 / 30 / 31 | Flags / Protocol / Action | `0x400053` / `tcp` / `allow` | Bits da sessão, protocolo e veredito |
| 32 / 33 / 34 / 35 | Bytes / Sent / Received / Packets | `1842` / `912` / `930` / `14` | Volume total, por direção, e pacotes |
| 36–52 | vários | `-` e `0` | **Campos vazios.** O PAN-OS emite a linha completa mesmo quando não tem o que pôr: contar vírgulas até ao fim é normal, e o vazio não é erro de coleta |

</details>

Campos-chave em ordem: origem `10.10.20.61`, destino `203.0.113.77`, aplicação `ssl`, usuário `corp\maria.costa`, porta destino `443`, ação `allow`, bytes totais `1842`, pacotes `14`. Repare que a aplicação foi identificada como `ssl` genérico, e não como `web-browsing` — outro indício de que não é navegação humana.

**O que o SOC N1 observa.** Normal: muitos destinos diferentes, tamanhos variados, certificados válidos de autoridades conhecidas, SNI de domínios do negócio. Suspeito: **um único destino**, intervalo regular, volume pequeno e constante, certificado autoassinado, SNI que não bate com o IP, JA3 raro no ambiente.

**Erro comum de analista júnior:** dizer "está cifrado, não dá para analisar" e fechar o caso. Metadados de TLS resolvem a maioria das investigações de C2 sem descriptografar nada.

---

## Porta 445 — SMB (Server Message Block)

Esta é a porta mais importante do módulo. Analogia: o armário de arquivos compartilhado do escritório, onde todo mundo pega e guarda pastas. Se alguém entra nesse armário com a chave errada, leva a empresa inteira.

**O que é.** Protocolo de compartilhamento de arquivos e impressoras do Windows, em **445/TCP**. Também transporta chamadas administrativas remotas.

**Como funciona.** O cliente autentica (normalmente via Kerberos ou NTLM), monta um **compartilhamento** e lê ou escreve arquivos. Existem compartilhamentos administrativos ocultos, criados pelo próprio Windows:

| Compartilhamento | O que é | Sinal para o SOC |
|---|---|---|
| `C$` | Raiz do disco C: | Acesso remoto ao disco inteiro — quase sempre administrativo ou malicioso |
| `ADMIN$` | Pasta `C:\Windows` | Usado por PsExec e Impacket para executar comandos remotos |
| `IPC$` | Canal de comunicação entre processos | Usado em enumeração; sessão nula é clássico de reconhecimento |
| `NETLOGON` / `SYSVOL` | Scripts e políticas do domínio | Acesso de estação é normal; escrita é grave |

**Riscos.** O **SMBv1**, versão antiga do protocolo, é vulnerável ao **EternalBlue (CVE-2017-0144)**, explorado pelo **WannaCry** em 2017 — o ransomware se espalhava sozinho pela rede via 445. SMBv1 deve estar desativado; se aparecer, é achado por si só. Além disso, 445 é a via de **movimento lateral** (MITRE **T1021.002** – SMB/Windows Admin Shares) e o caminho por onde ransomware **criptografa compartilhamentos inteiros**.

**Exemplo prático.** O servidor de arquivos `10.10.5.30` (`fs01.corp.local`) recebe, em dois minutos, 9.400 operações de escrita da estação `10.10.20.77`, sempre com a extensão `.locked`.

**Como aparece nos logs.** Windows Security no servidor de arquivos:

```
Event ID: 5140
Log Name: Security
Task Category: File Share
Descrição: Um objeto de compartilhamento de rede foi acessado.
  Assunto:
    Nome da Conta:   admin.rodrigo
    Domínio:         CORP
  Informações de Rede:
    Endereço de Origem:  10.10.20.77
    Porta de Origem:     51992
  Informações do Compartilhamento:
    Nome do Compartilhamento:  \\*\C$
    Caminho:                   \??\C:\
  Acesso Solicitado:  ReadData (ou ListDirectory) WriteData (ou AddFile)
```

```
Event ID: 5145
Log Name: Security
Descrição: Verificação de acesso detalhada em objeto de compartilhamento de rede.
  Nome da Conta:              admin.rodrigo
  Endereço de Origem:         10.10.20.77
  Nome do Compartilhamento:   \\*\FINANCEIRO
  Nome Relativo do Objeto:    orcamento_2026.xlsx.locked
  Acessos:                    WriteData (ou AddFile)  DELETE
```

Diferença essencial: o **5140** registra o **acesso ao compartilhamento** (uma vez por sessão) e o **5145** registra **cada arquivo** acessado dentro dele. Por isso o 5145 é o evento que denuncia ransomware: milhares de linhas por minuto, com DELETE e escrita de extensão nova.

Execução remota tipo PsExec deixa rastro em Windows Security e Sysmon:

```
Event ID: 4624
Tipo de Logon: 3          (logon pela rede — típico de SMB)
Conta: admin.rodrigo      Domínio: CORP
Endereço de Rede de Origem: 10.10.20.77
Pacote de Autenticação: NTLM
```

```
Event ID: 7            (Sysmon - Service Install equivalente em System 7045)
Nome do Serviço: PSEXESVC
Caminho da Imagem: %SystemRoot%\PSEXESVC.exe
```

Sequência a memorizar: **4624 tipo 3 com NTLM → acesso a ADMIN$ (5140) → instalação de serviço → 4688 de processo filho**. É a assinatura de movimento lateral.

**Por que 445 saindo para a internet é incidente imediato.** SMB nunca deve atravessar a borda. Se o firewall registra 445 de dentro para fora, há três hipóteses, todas ruins: exfiltração de arquivos, tentativa de captura de credencial NTLM por servidor externo, ou host já comprometido tentando se espalhar. Trate como **P1**, sem esperar mais evidência.

FortiGate (formato chave=valor) mostrando a tentativa bloqueada:

```
date=2026-09-03 time=14:22:10 devname="FGT-BORDA-01" devid="FG100E0000000001" logid="0000000013" type="traffic" subtype="forward" level="warning" srcip=10.10.20.77 srcport=52110 srcintf="port2" dstip=198.51.100.24 dstport=445 dstintf="port1" action="deny" policyid=98 service="SMB" proto=6 sentbyte=180 rcvdbyte=0 msg="violacao de politica de saida"
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `date` | `2026-09-03` | Data local **do equipamento**, não UTC. Correlacionar com um log em UTC sem acertar o fuso desalinha a timeline |
| `time` | `14:22:10` | Hora local do equipamento |
| `devname` | `"FGT-BORDA-01"` | Nome do equipamento que gerou o log |
| `devid` | `"FG100E0000000001"` | Número de série do equipamento — numa frota, é ele que identifica qual falou |
| `logid` | `"0000000013"` | Identificador do **tipo** de log. **É por ele que se filtra no SIEM**: o texto muda entre versões do FortiOS, o número não |
| `type` | `"traffic"` | Categoria do log: `traffic` é sessão, `event` é evento do próprio aparelho, `utm` é inspeção de conteúdo |
| `subtype` | `"forward"` | Subcategoria: `forward` é tráfego que atravessa, `local` é destinado ao próprio firewall, `vpn` é túnel, `webfilter` e `ips` são inspeção |
| `level` | `"warning"` | Severidade atribuída pelo FortiOS (`notice`, `warning`, `alert`, `critical`). **Quem a escolhe é o fabricante**, não o seu SOC |
| `srcip` | `10.10.20.77` | IP de origem |
| `srcport` | `52110` | Porta de origem, efêmera e sorteada pelo cliente |
| `srcintf` | `"port2"` | Interface por onde o tráfego **entrou** — dá o sentido, que o IP sozinho não dá |
| `dstip` | `198.51.100.24` | IP de destino |
| `dstport` | `445` | Porta de destino — é ela que aponta o serviço |
| `dstintf` | `"port1"` | Interface por onde o tráfego **saiu** |
| `action` | `"deny"` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |
| `policyid` | `98` | **Número da regra que decidiu.** Sem ele não se sabe por que o tráfego passou ou parou |
| `service` | `"SMB"` | Nome do **objeto de serviço** do FortiGate, não a porta literal. Um objeto chamado `HTTPS` pode ter sido configurado noutra porta |
| `proto` | `6` | Número do protocolo IP: **`6` é TCP, `17` é UDP, `1` é ICMP**. Vem em número, não em nome |
| `sentbyte` | `180` | Bytes enviados **pela origem**. O ponto de vista é o da origem, não do firewall |
| `rcvdbyte` | `0` | Bytes recebidos pela origem. **Comparar com `sentbyte` é o que revela exfiltração** |
| `msg` | `"violacao de politica de saida"` | Texto livre com a descrição legível. **Não use este campo em regras** — muda entre versões |

</details>

Campos: `srcip`/`dstip` origem e destino, `dstport=445`, `action="deny"` (bloqueado), `service="SMB"`, `proto=6` (TCP). Bloqueado não significa benigno — significa que **alguém de dentro tentou**.

**KQL (Microsoft Sentinel) para 445 saindo para fora:**

```kql
// Tráfego SMB da rede interna para IP público
CommonSecurityLog
| where DestinationPort == 445                       // porta SMB
| where not(ipv4_is_private(DestinationIP))          // destino fora da RFC1918
| summarize tentativas=count(), destinos=dcount(DestinationIP)
    by SourceIP, DeviceAction, bin(TimeGenerated, 5m)  // agrupa em janelas de 5 minutos
| order by tentativas desc
```

**O que o SOC N1 observa.** Normal: estações falando 445 com servidores de arquivos e controladores de domínio, leitura predominante. Suspeito: estação falando 445 com **outras estações** (não há motivo legítimo), acesso a `C$`/`ADMIN$` por conta que não é de administração, explosão de 5145 com extensão nova, SMBv1 negociado, 445 para a internet.

**Erro comum de analista júnior:** ver `admin.rodrigo` acessando `C$` e fechar como "é o administrador, é normal". A conta usada por um atacante **é sempre uma conta legítima roubada**. O que importa é a **origem** (a estação de onde partiu) e o **horário**.

### Exercícios — LDAP 389, HTTPS 443 e SMB 445

1. No `conn.log` da seção de LDAP, calcule quantos MB o host `10.10.20.88` recebeu do controlador de domínio e diga se isso é compatível com uma consulta de usuário comum.
2. Um alerta dispara: "TLS com certificado autoassinado". O SNI é `cdn-update.example.com`, o destino é `203.0.113.77` e há uma conexão a cada 60 segundos, sempre com cerca de 1,8 KB. Verdadeiro ou falso positivo? Justifique com dois indicadores.
3. O servidor `fs01.corp.local` gerou 9.400 eventos 5145 em dois minutos, todos da estação `10.10.20.77`, com escrita de arquivos terminados em `.locked`. Qual o próximo passo imediato da investigação?
4. Explique, em uma frase para um gestor não técnico, por que a porta 445 saindo para a internet é tratada como incidente P1.
5. Um analista afirma: "o tráfego é HTTPS, então não temos como investigar". Cite três metadados que continuam visíveis e o que cada um revela.

<details><summary>Ver gabarito</summary>

**1.** `resp_bytes = 41.287.600` bytes. Dividindo por 1.024 duas vezes: 41.287.600 / 1.048.576 ≈ **39,4 MB**, em 91,7 segundos. Uma consulta comum devolve poucos KB (a outra linha do log devolveu 2.890 bytes, cerca de 2,8 KB). Portanto **não é compatível**: 39 MB é o volume de quem baixou o diretório inteiro — comportamento de coletor tipo SharpHound (T1087/T1069). Próximo passo: identificar o processo na estação `10.10.20.88` via Sysmon Event ID 1 e verificar se a conta usada tem motivo para consultar o AD.

**2.** **Verdadeiro positivo, com alta suspeita.** Dois indicadores: (a) **periodicidade exata de 60 segundos** com volume quase idêntico — comportamento de máquina, não de pessoa navegando; (b) **certificado autoassinado** em um domínio que se apresenta como CDN, quando CDNs legítimas usam certificados de autoridades públicas. Reforça o caso o JA3 idêntico em todas as conexões e o Palo Alto classificar a aplicação como `ssl` genérico em vez de `web-browsing`. Ação: isolar a estação `10.10.20.61`, bloquear o IP e o domínio, e caçar o mesmo JA3 no restante da frota.

**3.** **Ransomware em execução.** O próximo passo imediato é **contenção**, não análise: isolar a estação `10.10.20.77` da rede (bloqueio na porta do switch ou isolamento pelo EDR) para parar a criptografia, e só então investigar. Em paralelo: verificar 4624 tipo 3 no servidor para saber qual conta foi usada, confirmar se `admin.rodrigo` teve a credencial comprometida, e acionar o processo de resposta a incidentes. Analisar antes de isolar custa arquivos.

**4.** "Compartilhamento de arquivos do Windows só faz sentido dentro da empresa. Se um computador nosso tenta enviar isso para fora, ou está mandando arquivos internos para um estranho, ou está tentando entregar as credenciais dos usuários — nos dois casos, precisa parar agora."

**5.** (a) **SNI** — revela o domínio pedido, mesmo sem descriptografar; (b) **certificado** (emissor, nome comum, validade) — revela se é autoassinado, recém-emitido ou não corresponde ao domínio; (c) **tamanho e ritmo dos pacotes** — revela beaconing de comando e controle. Também valem JA3/JA3S (identifica a biblioteca ou o malware que gerou o handshake) e o IP/ASN de destino.

</details>


## Correio seguro, syslog, LDAPS e bancos de dados

Este bloco fecha o grupo de portas que o analista N1 mais encontra em regras de firewall corporativo: o correio eletrônico protegido por criptografia, o transporte de logs, o diretório corporativo em versão segura e — o mais sensível de todos — os bancos de dados.

Para cada porta seguimos o mesmo formato de cinco itens: **o que é**, **como funciona**, **exemplo prático**, **como aparece nos logs** e **o que o SOC N1 observa**, terminando com o **erro comum de analista júnior**.

### Porta 465 — SMTPS (SMTP sobre TLS implícito)

**O que é.** SMTP significa *Simple Mail Transfer Protocol* (protocolo simples de transferência de correio) — é o protocolo que **envia** e-mail. A porta 465 é a versão "implícita": a criptografia TLS (*Transport Layer Security*, segurança da camada de transporte) começa antes de qualquer conversa.

**Analogia.** É como entrar num envelope lacrado **antes** de escrever a carta. Na porta 587 acontece o contrário: você começa a escrever no papel aberto e só depois pede o envelope.

**Como funciona.** O cliente abre TCP na 465, faz o *handshake* TLS imediatamente e só então envia os comandos `EHLO`, `AUTH`, `MAIL FROM`, `RCPT TO`, `DATA`.

**Exemplo prático.** O Outlook da estação `10.10.20.45` (usuária `maria.costa`) envia e-mail pelo servidor `smtp.empresa-exemplo.com.br` (198.51.100.25) na porta 465.

**Como aparece nos logs** (Palo Alto, CSV TRAFFIC resumido):

```
1,2026/09/03 09:12:44,014201005678,TRAFFIC,end,2561,2026/09/03 09:12:44,10.10.20.45,198.51.100.25,203.0.113.10,198.51.100.25,Regra-Saida-Email,corp\maria.costa,,smtp,vsys1,Trust,Untrust,ae1.20,ae1.10,Log-Panorama,2026/09/03 09:12:44,84512,1,51322,465,42115,465,0x400053,tcp,allow,18432,6120,12312,44,2026/09/03 09:12:12,12,any,0,7788112,0x0,10.10.0.0-10.255.255.255,US,0,26,18
```

<details><summary>Ver legenda</summary>

| Posição | Campo | Valor no exemplo | O que significa |
|---|---|---|---|
| 1, 6, 39, 44 | — | `1`, `2561`, `0`, `0` | Reservados pelo fabricante |
| 2 / 7 | Receive / Generated Time | `2026/09/03 09:12:44` | Quando o firewall recebeu e quando ocorreu |
| 3 | Serial Number | `014201005678` | Qual equipamento gerou |
| 4 / 5 | Type / Subtype | `TRAFFIC` / `end` | Log de sessão, no fim |
| 8 / 9 | Source / Destination Address | `10.10.20.45` / `198.51.100.25` | **Uma estação de usuário a falar direto com um servidor de correio externo** — é este par que levanta a questão |
| 10 / 11 | NAT Source / Destination IP | `203.0.113.10` / `198.51.100.25` | Endereço público de saída e destino |
| 12 | Rule Name | `Regra-Saida-Email` | A regra que permitiu |
| 13 / 14 | Source / Destination User | `corp\maria.costa` / *(vazio)* | Usuário resolvido |
| 15 | Application | `smtp` | **App-ID identificou SMTP inspecionando o conteúdo.** Se alguém tunelasse outra coisa na 465, o App-ID diria outro nome — é isso que o distingue de olhar só a porta |
| 16 | Virtual System | `vsys1` | Firewall virtual |
| 17 / 18 | Source / Destination Zone | `Trust` / `Untrust` | O sentido do tráfego |
| 19 / 20 | Inbound / Outbound Interface | `ae1.20` / `ae1.10` | Subinterfaces de *port-channel* |
| 21 | Log Action | `Log-Panorama` | O log é encaminhado para o Panorama (a consola central) |
| 22 | — | `2026/09/03 09:12:44` | Campo reservado |
| 23 / 24 | Session ID / Repeat Count | `84512` / `1` | Sessão e contagem |
| 25 / 26 | Source / Destination Port | `51322` / `465` | **465 é SMTPS** — submissão de e-mail com TLS |
| 27 / 28 | NAT Source / Destination Port | `42115` / `465` | Portas após tradução |
| 29 / 30 / 31 | Flags / Protocol / Action | `0x400053` / `tcp` / `allow` | Bits, protocolo e veredito |
| 32 / 33 / 34 / 35 | Bytes / Sent / Received / Packets | `18432` / `6120` / `12312` / `44` | Volume total, por direção, e pacotes |
| 36 / 37 | Start Time / Elapsed | `2026/09/03 09:12:12` / `12` | Início e duração em segundos |
| 38 | Category | `any` | Sem categoria de URL atribuída |
| 40 / 41 | Sequence Number / Action Flags | `7788112` / `0x0` | Sequencial do log e bits da ação |
| 42 / 43 | Source / Destination Location | `10.10.0.0-10.255.255.255` / `US` | Faixa interna na origem (IP privado não tem país) e país no destino |
| 45 / 46 | Packets Sent / Received | `26` / `18` | Pacotes em cada direção |

</details>


**O que o SOC N1 observa.**

| Normal | Suspeito |
|---|---|
| Estações falando 465 **só** com o servidor de e-mail corporativo | Estação falando 465 com dezenas de IPs externos diferentes |
| Volume por usuário compatível com trabalho | Milhares de sessões/hora saindo de um host só |
| Servidor de aplicação enviando notificação | Host de RH enviando e-mail direto para MX externo, sem passar pelo relay |

Muitas sessões 465/587 saindo de uma estação para destinos variados é padrão clássico de máquina com *malware* de spam. Em MITRE ATT&CK isso costuma ser mapeado como T1071.003 (Application Layer Protocol: Mail Protocols).

**Erro comum de júnior.** Achar que "465 é criptografado, então é seguro". Criptografia protege o conteúdo contra quem está no meio do caminho — não impede que a própria máquina esteja mandando spam ou exfiltrando dados por anexo.

### Porta 587 — SMTP submission

**O que é.** É a porta oficial para o **cliente autenticado** entregar mensagens ao servidor (RFC 6409). Usa STARTTLS: começa em texto claro e "sobe" para TLS.

**Como funciona.** Conecta em 587, o servidor anuncia `250-STARTTLS`, o cliente emite `STARTTLS`, o canal vira criptografado, e só então ocorre o `AUTH LOGIN`.

**Exemplo prático.** `svc_backup` em `10.10.30.12` envia relatório noturno pelo relay interno `10.10.5.25:587`.

**Como aparece nos logs** (FortiGate, key=value):

```
date=2026-09-03 time=02:05:11 devname="FGT-CORP-01" devid="FG100F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=10.10.30.12 srcport=49871 srcintf="port3" dstip=10.10.5.25 dstport=587 dstintf="port2" policyid=42 sessionid=88213 proto=6 action="accept" service="SMTPS" app="SMTP" duration=6 sentbyte=14820 rcvdbyte=2410 user="svc_backup"
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `date` | `2026-09-03` | Data local **do equipamento**, não UTC. Correlacionar com um log em UTC sem acertar o fuso desalinha a timeline |
| `time` | `02:05:11` | Hora local do equipamento |
| `devname` | `"FGT-CORP-01"` | Nome do equipamento que gerou o log |
| `devid` | `"FG100F0000000001"` | Número de série do equipamento — numa frota, é ele que identifica qual falou |
| `logid` | `"0000000013"` | Identificador do **tipo** de log. **É por ele que se filtra no SIEM**: o texto muda entre versões do FortiOS, o número não |
| `type` | `"traffic"` | Categoria do log: `traffic` é sessão, `event` é evento do próprio aparelho, `utm` é inspeção de conteúdo |
| `subtype` | `"forward"` | Subcategoria: `forward` é tráfego que atravessa, `local` é destinado ao próprio firewall, `vpn` é túnel, `webfilter` e `ips` são inspeção |
| `level` | `"notice"` | Severidade atribuída pelo FortiOS (`notice`, `warning`, `alert`, `critical`). **Quem a escolhe é o fabricante**, não o seu SOC |
| `srcip` | `10.10.30.12` | IP de origem |
| `srcport` | `49871` | Porta de origem, efêmera e sorteada pelo cliente |
| `srcintf` | `"port3"` | Interface por onde o tráfego **entrou** — dá o sentido, que o IP sozinho não dá |
| `dstip` | `10.10.5.25` | IP de destino |
| `dstport` | `587` | Porta de destino — é ela que aponta o serviço |
| `dstintf` | `"port2"` | Interface por onde o tráfego **saiu** |
| `policyid` | `42` | **Número da regra que decidiu.** Sem ele não se sabe por que o tráfego passou ou parou |
| `sessionid` | `88213` | Identificador da sessão na tabela de estado — casa o início e o fim da mesma conexão |
| `proto` | `6` | Número do protocolo IP: **`6` é TCP, `17` é UDP, `1` é ICMP**. Vem em número, não em nome |
| `action` | `"accept"` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |
| `service` | `"SMTPS"` | Nome do **objeto de serviço** do FortiGate, não a porta literal. Um objeto chamado `HTTPS` pode ter sido configurado noutra porta |
| `app` | `"SMTP"` | Aplicação identificada pelo controle de aplicação, por inspeção do conteúdo |
| `duration` | `6` | Duração da sessão em **segundos** |
| `sentbyte` | `14820` | Bytes enviados **pela origem**. O ponto de vista é o da origem, não do firewall |
| `rcvdbyte` | `2410` | Bytes recebidos pela origem. **Comparar com `sentbyte` é o que revela exfiltração** |
| `user` | `"svc_backup"` | Conta autenticada — o que transforma "um IP" em "uma pessoa" |

</details>

`proto=6` é TCP, `action="accept"` diz que a política 42 permitiu, `sentbyte`/`rcvdbyte` mostram o volume.

**O que o SOC N1 observa.** Normal: poucas origens, todas conhecidas, falando com o relay. Suspeito: 587 saindo direto para a internet burlando o relay, ou `sentbyte` gigantesco em horário fora do padrão.

**Erro comum de júnior.** Confundir 25, 465 e 587. Resumo: **25** é servidor-para-servidor, **465** é submissão com TLS implícito, **587** é submissão com STARTTLS.

### Porta 514 — Syslog

**O que é.** Syslog é o formato padrão de mensagem de log em rede. Por padrão roda em **UDP/514**.

**Analogia.** UDP é como jogar um bilhete pela janela: rápido, barato, mas ninguém confirma que chegou — e qualquer pessoa pode escrever um bilhete parecido e jogar também.

**Como funciona.** O dispositivo (firewall, switch, servidor Linux) monta a mensagem com *facility*, *severity*, *timestamp*, *hostname* e texto, e dispara para o coletor. Como é UDP, **não há garantia de entrega** e **não há autenticação** — a origem pode ser forjada (*spoofing*). Por isso ambientes maduros usam TCP/6514 com TLS ou, no mínimo, restringem por firewall quem pode falar 514 com o coletor.

**Por que centralizar log.** Se o log fica só na máquina, o atacante que ganha administrador apaga a evidência (MITRE T1070 — Indicator Removal). Centralizar cria uma cópia fora do alcance dele e permite correlação entre fontes. A construção dessa esteira de coleta é o assunto do **Módulo 11**; aqui interessa apenas reconhecer a porta e desconfiar do que chega por ela.

**Exemplo prático.** O firewall `10.10.1.1` envia para o coletor `10.10.60.10:514`.

**Como aparece nos logs** (syslog RFC 5424 recebido no coletor):

```
<134>1 2026-09-03T09:31:02.118Z fw-core-01.corp.local paloalto 8912 TRAFFIC - Sessao permitida de 10.10.20.45 para 198.51.100.25 porta 465 regra=Regra-Saida-Email
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `<134>` | PRI | `134 = 16 x 8 + 6`: facility 16 (local0), severidade 6 (informational) |
| `1` | VERSION | Formato RFC 5424 |
| `2026-09-03T09:31:02.118Z` | TIMESTAMP | ISO 8601 com milissegundos, em UTC |
| `fw-core-01.corp.local` | HOSTNAME | O firewall que gerou |
| `paloalto` | APP-NAME | A aplicação de origem |
| `8912` | PROCID | Identificador do processo no equipamento |
| `TRAFFIC` | MSGID | Tipo de log do Palo Alto: `TRAFFIC` é sessão, `THREAT` é detecção, `SYSTEM` é evento do próprio aparelho |
| `-` | STRUCTURED-DATA | Vazio |
| `Sessao permitida de 10.10.20.45 para 198.51.100.25 porta 465 regra=Regra-Saida-Email` | MSG | Texto livre com origem, destino, porta e regra. **Porta 465 é SMTPS** (submissão de e-mail com TLS) — sair de uma estação de usuário direto para fora, em vez de passar pelo servidor de correio da empresa, é o que merece atenção |

</details>


**O que o SOC N1 observa.** Normal: só as fontes cadastradas mandando 514 para o coletor. Suspeito: (1) uma fonte importante **para de enviar** — silêncio também é alerta; (2) uma estação de usuário aparece enviando syslog, o que pode ser tentativa de poluir o SIEM com eventos falsos.

**Erro comum de júnior.** Tratar todo campo de syslog como verdade absoluta. Em UDP/514 sem TLS, hostname e conteúdo podem ter sido forjados — sempre confirme com uma segunda fonte (log de firewall, EDR).

### Porta 636 — LDAPS

**O que é.** LDAPS é o LDAP (*Lightweight Directory Access Protocol*, protocolo leve de acesso a diretório) sobre TLS. Consulta o mesmo diretório da porta 389 — vista no trecho anterior — mas com o canal criptografado.

**Como funciona.** TLS implícito na 636; depois o `bind` (autenticação) e as consultas viajam cifrados, de modo que a senha do `bind` não trafega legível.

**Exemplo prático.** O portal em `10.10.40.20` valida logins contra o controlador de domínio `10.10.1.10:636`.

**Como aparece nos logs** (Zeek `ssl.log`, campos selecionados):

```
{"ts":"2026-09-03T09:40:15.220Z","uid":"CxYz19","id.orig_h":"10.10.40.20","id.orig_p":51902,"id.resp_h":"10.10.1.10","id.resp_p":636,"version":"TLSv12","cipher":"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","server_name":"dc01.corp.local","established":true}
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `ts` | `2026-09-03T09:40:15.220Z` | Instante do handshake. Aqui em formato ISO 8601 com `Z` de UTC, como o Zeek escreve quando configurado em JSON |
| `uid` | `CxYz19` | Identificador único da conexão |
| `id.orig_h` / `id.orig_p` | `10.10.40.20` / `51902` | Cliente e porta efêmera |
| `id.resp_h` / `id.resp_p` | `10.10.1.10` / `636` | Destino e porta: **636 é LDAPS**, o LDAP dentro de TLS |
| `version` | `TLSv12` | Versão do TLS negociada |
| `cipher` | `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` | Conjunto de cifras. `ECDHE` dá *forward secrecy* e `GCM` é modo autenticado — combinação saudável |
| `server_name` | `dc01.corp.local` | O SNI: o controlador de domínio que o cliente pediu |
| `established` | `true` | O handshake completou. Em JSON o Zeek usa booleano; no formato TSV o mesmo campo aparece como `T`/`F` |

</details>

**O que o SOC N1 observa.** Normal: servidores de aplicação conhecidos falando 636 com os controladores de domínio. Suspeito: estação comum abrindo LDAPS contra vários DCs — pode ser enumeração de diretório (T1087 — Account Discovery), padrão típico de ferramentas como BloodHound.

**Erro comum de júnior.** Concluir que, por estar criptografado, "não dá para investigar". Metadados bastam: quem, com quem, quantas conexões, em quanto tempo.

### Portas 993 e 995 — IMAPS e POP3S

**O que é.** IMAP (*Internet Message Access Protocol*) na 993 e POP3 (*Post Office Protocol v3*) na 995 são os protocolos de **leitura** de e-mail, ambos sobre TLS.

**Diferença prática.** IMAP mantém as mensagens no servidor e sincroniza pastas; POP3 tradicionalmente baixa e remove.

**Exemplo prático.** `jsilva`, em `10.10.20.77`, sincroniza a caixa com `mail.empresa-exemplo.com.br` (198.51.100.30) na 993.

**Como aparece nos logs** (Cisco ASA):

```
%ASA-6-302013: Built outbound TCP connection 774112 for outside:198.51.100.30/993 (198.51.100.30/993) to inside:10.10.20.77/50122 (203.0.113.10/50122)
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `%ASA` | `%ASA` | Etiqueta do produto: identifica a linha como vinda de um firewall ASA |
| severidade | `6` | Escala syslog do Cisco, de 0 (emergência) a 7 (depuração): `6` é **informational**. **Severidade baixa não quer dizer evento sem importância** — quem a escolhe é o fabricante, não o seu SOC |
| *message ID* | `302013` | Conexão TCP construída — entrou na tabela de estado. **É por este número que se escreve a regra no SIEM**: o texto da mensagem muda entre versões do software, o ID não |
| direção | `outbound` | **Quem iniciou**, não a direção dos bytes: `outbound` é de dentro para fora, `inbound` é de fora para dentro |
| id da conexão | `774112` | Número da conexão na tabela de estado. **É a chave para casar com o `302014`** que a encerra |
| lado remoto | `outside:198.51.100.30/993` | Interface, IP e porta do host **remoto**. Vem primeiro, logo depois do `for` — é isso que faz a linha parecer invertida |
| *(entre parênteses)* | `(198.51.100.30/993)` | O endereço **traduzido** desse lado. Igual ao real significa que não houve NAT nesta ponta |
| lado local | `inside:10.10.20.77/50122` | Interface, IP e porta do host **local**, antes da tradução |
| *(entre parênteses)* | `(203.0.113.10/50122)` | O endereço com que o host local saiu. **Este par — IP público mais porta — é o que desfaz o NAT** num pedido externo |
| — | — | **993 é IMAPS**, o IMAP dentro de TLS — o oposto do exemplo da porta 143. Aqui o pedido sai de dentro para fora, e o endereço entre parênteses do lado `inside` é o público com que ele saiu |

</details>


**O que o SOC N1 observa.** Suspeito: POP3S ativo onde a política manda usar só IMAPS ou Exchange; download volumoso de madrugada (possível cópia de caixa antes de desligamento — T1114, Email Collection); um mesmo usuário sincronizando de país incompatível.

**Erro comum de júnior.** Ignorar 993/995 por "ser só e-mail". Caixa de correio é um dos alvos mais valiosos numa exfiltração.

### Portas 1433, 1521 e 3306 — bancos de dados

| Porta | Produto | Protocolo | Observação para o SOC |
|---|---|---|---|
| 1433/TCP | Microsoft SQL Server | TDS | 1434/UDP é o SQL Browser; `xp_cmdshell` permite execução de comando no SO |
| 1521/TCP | Oracle Database | TNS Listener | Enumeração de SID/service name é reconhecimento clássico |
| 3306/TCP | MySQL / MariaDB | MySQL wire | Muito exposto por engano em nuvem |

**Como funciona.** A aplicação abre TCP na porta do banco, autentica e envia consultas SQL. Em SQL Server, a funcionalidade `xp_cmdshell` (quando habilitada) executa comandos do sistema operacional — é por isso que uma injeção de SQL bem-sucedida vira execução de comando (T1190 — Exploit Public-Facing Application). Banco exposto direto na internet é um dos achados mais graves de um N1.

**Padrão normal versus anômalo.**

| Cenário | Origem | Destino | Veredito |
|---|---|---|---|
| Aplicação → banco | `10.10.40.20` (app) | `10.10.50.30:1433` | Normal, esperado, alto volume |
| DBA com ferramenta | `10.10.20.9` (estação do DBA, na lista) | `10.10.50.30:1433` | Normal se dentro da janela e do grupo autorizado |
| **Estação de usuário → banco** | `10.10.20.45` (`maria.costa`, financeiro) | `10.10.50.30:1433` | **Anômalo** — investigar |
| Banco → internet | `10.10.50.30` | `203.0.113.77:443` | Muito suspeito: possível exfiltração |

**Como aparece nos logs** (FortiGate, o caso anômalo):

```
date=2026-09-03 time=14:02:53 devname="FGT-CORP-01" type="traffic" subtype="forward" level="warning" srcip=10.10.20.45 srcport=52210 srcintf="port3" dstip=10.10.50.30 dstport=1433 dstintf="port5" policyid=77 sessionid=99341 proto=6 action="accept" service="MS-SQL" duration=612 sentbyte=91230 rcvdbyte=48211904 user="maria.costa"
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `date` | `2026-09-03` | Data local **do equipamento**, não UTC. Correlacionar com um log em UTC sem acertar o fuso desalinha a timeline |
| `time` | `14:02:53` | Hora local do equipamento |
| `devname` | `"FGT-CORP-01"` | Nome do equipamento que gerou o log |
| `type` | `"traffic"` | Categoria do log: `traffic` é sessão, `event` é evento do próprio aparelho, `utm` é inspeção de conteúdo |
| `subtype` | `"forward"` | Subcategoria: `forward` é tráfego que atravessa, `local` é destinado ao próprio firewall, `vpn` é túnel, `webfilter` e `ips` são inspeção |
| `level` | `"warning"` | Severidade atribuída pelo FortiOS (`notice`, `warning`, `alert`, `critical`). **Quem a escolhe é o fabricante**, não o seu SOC |
| `srcip` | `10.10.20.45` | IP de origem |
| `srcport` | `52210` | Porta de origem, efêmera e sorteada pelo cliente |
| `srcintf` | `"port3"` | Interface por onde o tráfego **entrou** — dá o sentido, que o IP sozinho não dá |
| `dstip` | `10.10.50.30` | IP de destino |
| `dstport` | `1433` | Porta de destino — é ela que aponta o serviço |
| `dstintf` | `"port5"` | Interface por onde o tráfego **saiu** |
| `policyid` | `77` | **Número da regra que decidiu.** Sem ele não se sabe por que o tráfego passou ou parou |
| `sessionid` | `99341` | Identificador da sessão na tabela de estado — casa o início e o fim da mesma conexão |
| `proto` | `6` | Número do protocolo IP: **`6` é TCP, `17` é UDP, `1` é ICMP**. Vem em número, não em nome |
| `action` | `"accept"` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |
| `service` | `"MS-SQL"` | Nome do **objeto de serviço** do FortiGate, não a porta literal. Um objeto chamado `HTTPS` pode ter sido configurado noutra porta |
| `duration` | `612` | Duração da sessão em **segundos** |
| `sentbyte` | `91230` | Bytes enviados **pela origem**. O ponto de vista é o da origem, não do firewall |
| `rcvdbyte` | `48211904` | Bytes recebidos pela origem. **Comparar com `sentbyte` é o que revela exfiltração** |
| `user` | `"maria.costa"` | Conta autenticada — o que transforma "um IP" em "uma pessoa" |
| — | — | Compare `duration` com `sentbyte`/`rcvdbyte`: sessão longa a mover pouco é canal mantido aberto; sessão curta a mover muito é transferência |

</details>

O detonador aqui é `rcvdbyte=48211904`: cerca de 46 MB **vindos** do banco para uma estação de usuário comum, em 612 segundos. Isso tem cara de *dump* de base (T1005 — Data from Local System / T1213 — Data from Information Repositories).

**Query SPL (Splunk) — estações falando com bancos:**

```spl
index=firewall dest_port IN (1433,1521,3306) action=allowed
| search src_ip=10.10.20.0/24
| stats sum(bytes_in) AS bytes_recebidos, dc(dest_ip) AS bancos_distintos, values(user) AS usuarios BY src_ip
| where bytes_recebidos > 10000000
| sort - bytes_recebidos
```

Linha 1 filtra tráfego permitido para portas de banco; linha 2 restringe à faixa de estações de usuário (servidores ficam em outra faixa); linha 3 agrega bytes recebidos, quantos bancos distintos e quais usuários por origem; linha 4 mantém só acima de 10 MB; linha 5 ordena pelo maior volume.

**Query KQL (Microsoft Sentinel) — equivalente:**

```kql
CommonSecurityLog
| where DestinationPort in (1433, 1521, 3306) and DeviceAction == "accept"
| where ipv4_is_in_range(SourceIP, "10.10.20.0/24")
| summarize BytesIn = sum(ReceivedBytes), Bancos = dcount(DestinationIP) by SourceIP, SourceUserName, bin(TimeGenerated, 1h)
| where BytesIn > 10000000
| order by BytesIn desc
```

Cada linha espelha a lógica do SPL, com `bin(TimeGenerated, 1h)` agrupando por hora para revelar picos.

**Erro comum de júnior.** Fechar o alerta porque "o usuário é do financeiro, deve ser relatório". O caminho legítimo de um usuário de negócio ao dado é a **aplicação** ou o portal de BI — não o `sqlcmd` direto na porta 1433. Confirme o processo de origem no Sysmon Event ID 3 (conexão de rede) antes de concluir.

### Exercícios — Correio seguro, syslog, LDAPS e bancos de dados

1. Relacione porta e função, sem consultar as tabelas acima: 465, 514, 587, 636, 993, 995, 1433, 1521, 3306.
2. O coletor de logs `10.10.60.10` passou a receber mensagens syslog UDP/514 originadas de `10.10.20.45`, uma estação de usuário. As mensagens dizem "firewall fw-core-01 desligou regra de bloqueio". Alerta verdadeiro ou falso positivo? Qual o próximo passo?
3. Leia o log e diga o que investigar primeiro:

```
date=2026-09-03 time=03:41:07 devname="FGT-CORP-01" type="traffic" subtype="forward" srcip=10.10.50.30 srcport=44120 dstip=203.0.113.77 dstport=3306 action="accept" proto=6 sentbyte=302118400 rcvdbyte=18220 duration=1840
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `date` | `2026-09-03` | Data local **do equipamento**, não UTC. Correlacionar com um log em UTC sem acertar o fuso desalinha a timeline |
| `time` | `03:41:07` | Hora local do equipamento |
| `devname` | `"FGT-CORP-01"` | Nome do equipamento que gerou o log |
| `type` | `"traffic"` | Categoria do log: `traffic` é sessão, `event` é evento do próprio aparelho, `utm` é inspeção de conteúdo |
| `subtype` | `"forward"` | Subcategoria: `forward` é tráfego que atravessa, `local` é destinado ao próprio firewall, `vpn` é túnel, `webfilter` e `ips` são inspeção |
| `srcip` | `10.10.50.30` | IP de origem |
| `srcport` | `44120` | Porta de origem, efêmera e sorteada pelo cliente |
| `dstip` | `203.0.113.77` | IP de destino |
| `dstport` | `3306` | Porta de destino — é ela que aponta o serviço |
| `action` | `"accept"` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |
| `proto` | `6` | Número do protocolo IP: **`6` é TCP, `17` é UDP, `1` é ICMP**. Vem em número, não em nome |
| `sentbyte` | `302118400` | Bytes enviados **pela origem**. O ponto de vista é o da origem, não do firewall |
| `rcvdbyte` | `18220` | Bytes recebidos pela origem. **Comparar com `sentbyte` é o que revela exfiltração** |
| `duration` | `1840` | Duração da sessão em **segundos** |

</details>

4. Um analista abriu incidente porque `10.10.40.20` mantém 400 conexões simultâneas em `10.10.1.10:636`. Consultando o inventário, `10.10.40.20` é o portal de RH e `10.10.1.10` é o controlador de domínio `dc01.corp.local`. Verdadeiro ou falso positivo? Que evidência decide?
5. Calcule a taxa média do exemplo do banco anômalo (`rcvdbyte=48211904` em `duration=612`) em kilobytes por segundo e diga se o valor é compatível com uma consulta pontual de relatório.

<details><summary>Ver gabarito</summary>

**1.** 465 = SMTPS (envio com TLS implícito); 514 = syslog (UDP, transporte de log); 587 = SMTP submission com STARTTLS; 636 = LDAPS (diretório sobre TLS); 993 = IMAPS (leitura de e-mail, mantém no servidor); 995 = POP3S (leitura, tradicionalmente baixa e remove); 1433 = Microsoft SQL Server; 1521 = Oracle TNS Listener; 3306 = MySQL/MariaDB.

**2.** Alerta **verdadeiro** — merece investigação. Uma estação de usuário não é fonte legítima de syslog, e syslog UDP não autentica a origem: o conteúdo pode ser totalmente forjado para poluir o SIEM ou esconder eventos reais no meio do ruído. Próximo passo: confirmar com uma **segunda fonte** — o log do próprio `fw-core-01` diz que alguma regra mudou? Em paralelo, verificar no EDR/Sysmon qual processo em `10.10.20.45` abriu socket UDP para `10.10.60.10:514`, e restringir no firewall quem pode falar 514 com o coletor. Nunca aceite o campo hostname do syslog como prova.

**3.** É o **banco de dados falando para fora**: origem `10.10.50.30` (servidor de banco), destino público `203.0.113.77` na 3306, às 03:41, com `sentbyte=302118400` (cerca de 288 MB **enviados**) em 1840 segundos. Servidor de banco não deve iniciar conexão para a internet. Investigue nesta ordem: (a) processo responsável no host de banco (Sysmon Event ID 3 e Event ID 1 para o processo pai); (b) se há regra de firewall permitindo saída da faixa de servidores — provável falha de política; (c) contenção — bloquear a saída e preservar evidência. Hipótese principal: exfiltração de base (T1041 — Exfiltration Over C2 Channel, ou exfiltração por canal alternativo).

**4.** **Falso positivo** provável. Portal de RH autenticando usuários contra o controlador de domínio via LDAPS é exatamente o padrão esperado, e 400 sessões simultâneas em horário comercial é compatível com aplicação. A evidência que decide: comparar com a **linha de base** dos últimos 7 a 30 dias (o volume é típico para esse par origem-destino?) e confirmar no inventário que o serviço do portal é o dono da conexão. Se o volume fosse novo, ou se a origem fosse uma estação comum falando 636 com vários DCs, a leitura mudaria para possível enumeração de diretório (T1087).

**5.** 48.211.904 bytes ÷ 612 s ≈ 78.777 bytes/s ≈ **77 KB/s**, sustentados por mais de 10 minutos, totalizando cerca de 46 MB. Não é compatível com uma consulta pontual de relatório, que costuma ser um pico curto de poucos segundos e poucos megabytes. O perfil — fluxo constante e longo, vindo do banco para uma estação de usuário — é típico de leitura sequencial de tabelas, ou seja, cópia de base. Escale para o N2 com o log de firewall, o processo de origem e a lista de tabelas acessadas, se houver auditoria no SQL Server.

</details>


## Porta 3389 — RDP (Remote Desktop Protocol)

**O que é.** Imagine que você deixou uma cópia da chave da sua casa embaixo do tapete e colou um aviso na porta: "a chave está aqui". É mais ou menos isso que acontece quando a porta 3389 fica aberta para a internet. O RDP (Remote Desktop Protocol, ou Protocolo de Área de Trabalho Remota) permite que alguém veja e controle a tela de um computador Windows a distância, como se estivesse sentado na frente dele.

**Como funciona.** O cliente (mstsc.exe no Windows) abre uma conexão TCP na porta 3389 do servidor. Há negociação de TLS (Transport Layer Security, camada de segurança de transporte) e, depois, autenticação — idealmente com NLA (Network Level Authentication, autenticação em nível de rede), que exige credencial válida **antes** de mostrar qualquer tela. Autenticado o usuário, teclado e mouse vão de um lado e a imagem da tela volta do outro.

**Exemplo prático.** O analista `admin.rodrigo`, da estação `10.10.20.45`, abre uma sessão RDP no servidor `srv-app01.corp.local` (`10.10.50.12`). Legítimo. Já um endereço público `203.0.113.77` tentando 3389 no mesmo servidor não tem explicação boa.

**Como aparece nos logs.** Primeiro o firewall Palo Alto, no formato CSV do log TRAFFIC:

```
1,2026/09/03 02:11:47,014201001234,TRAFFIC,end,2561,2026/09/03 02:11:47,203.0.113.77,10.10.50.12,0.0.0.0,10.10.50.12,Permite-DMZ,,,ms-rdp,vsys1,Untrust,DMZ,ethernet1/1,ethernet1/2,Log-Padrao,2026/09/03 02:11:47,88213,1,51422,3389,0,3389,0x400053,tcp,allow,12480,6210,6270,66,2026/09/03 02:10:12,14,any,0,7712345,0x0,US,BR,0,33,33
```

<details><summary>Ver legenda</summary>

| Posição | Campo | Valor no exemplo | O que significa |
|---|---|---|---|
| 1, 6, 39, 44 | — | `1`, `2561`, `0`, `0` | Reservados pelo fabricante |
| 2 / 7 | Receive / Generated Time | `2026/09/03 02:11:47` | **02h11 da manhã** — o horário é metade do achado |
| 3 | Serial Number | `014201001234` | Qual equipamento gerou |
| 4 / 5 | Type / Subtype | `TRAFFIC` / `end` | Log de sessão, no fim |
| 8 / 9 | Source / Destination Address | `203.0.113.77` / `10.10.50.12` | **Origem externa, destino interno**: sessão de *entrada*, ao contrário dos exemplos anteriores |
| 10 / 11 | NAT Source / Destination IP | `0.0.0.0` / `10.10.50.12` | Sem NAT na origem; no destino, o IP interno após a tradução do publicado |
| 12 | Rule Name | `Permite-DMZ` | A regra que permitiu a entrada |
| 13 / 14 | Source / Destination User | `-` / `-` | **Sem usuário nos dois.** É esperado: o User-ID não conhece quem vem da Internet |
| 15 | Application | `ms-rdp` | App-ID identificou **RDP** — área de trabalho remota |
| 16 | Virtual System | `vsys1` | Firewall virtual |
| 17 / 18 | Source / Destination Zone | `Untrust` / `DMZ` | Da Internet para a DMZ |
| 19 / 20 | Inbound / Outbound Interface | `ethernet1/1` / `ethernet1/2` | Entrou pela interface externa, saiu pela da DMZ |
| 21 / 22 | Log Action / — | `Log-Padrao` / `2026/09/03 02:11:47` | Perfil de log e campo reservado |
| 23 / 24 | Session ID / Repeat Count | `88213` / `1` | Sessão e contagem |
| 25 / 26 | Source / Destination Port | `51422` / `3389` | **3389 é RDP.** Exposto à Internet, é dos vetores mais explorados |
| 27 / 28 | NAT Source / Destination Port | `0` / `3389` | Sem tradução na origem; a porta publicada no destino |
| 29 / 30 / 31 | Flags / Protocol / Action | `0x400053` / `tcp` / `allow` | Bits, protocolo e **`allow`: a sessão entrou** |
| 32 / 33 / 34 / 35 | Bytes / Sent / Received / Packets | `12480` / `6210` / `6270` / `66` | Volume equilibrado nos dois sentidos — houve conversa, não só tentativa |
| 36 / 37 | Start Time / Elapsed | `2026/09/03 02:10:12` / `14` | Início e duração em segundos |
| 38 | Category | `any` | Sem categoria atribuída |
| 40 / 41 | Sequence Number / Action Flags | `7712345` / `0x0` | Sequencial e bits da ação |
| 42 / 43 | Source / Destination Location | `US` / `BR` | **País de origem e de destino.** Aqui há país nos dois, porque a origem é um IP público |
| 45 / 46 | Packets Sent / Received | `33` / `33` | Pacotes em cada direção |

</details>


Agora o rastro no Windows. Logon bem-sucedido de RDP gera o evento **4624 com Logon Type 10** (RemoteInteractive):

```
EventID=4624
Account Name: jsilva
Account Domain: CORP
Logon Type: 10
Source Network Address: 203.0.113.77
Source Port: 51422
Logon Process: User32
Authentication Package: Negotiate
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `EventID` | `4624` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não. `4624` = logon **bem-sucedido** |
| `Account Name` | `jsilva` | A conta envolvida. Terminada em `$` é **conta de computador**, não de pessoa |
| `Account Domain` | `CORP` | Domínio da conta |
| `Logon Type` | `10` | **Como a sessão foi iniciada.** `10` = **RemoteInteractive** — RDP, área de trabalho remota |
| `Source Network Address` | `203.0.113.77` | **IP de origem.** Vazio ou `-` significa que a sessão foi local, e `::1`/`127.0.0.1` que veio da própria máquina |
| `Source Port` | `51422` | Porta de origem, efêmera |
| `Logon Process` | `User32` | Componente que processou o logon (`Kerberos`, `NtLmSsp`, `User32`, `Advapi`) |
| `Authentication Package` | `Negotiate` | Pacote que autenticou: `Kerberos`, `NTLM` ou `Negotiate` |

</details>

Falhas geram **4625** (An account failed to log on), com `Failure Reason` e `Status`/`Sub Status` — `0xC000006A` é senha errada e `0xC0000064` é usuário inexistente. Uma sequência de 4625 do mesmo IP com dezenas de nomes de usuário diferentes é **enumeração de contas**; dezenas de senhas para o mesmo usuário é **força bruta** (MITRE ATT&CK T1110). RDP como forma de movimentação lateral é T1021.001.

**O que o SOC N1 observa.**

| Situação | Leitura |
|---|---|
| 4624 tipo 10, origem RFC1918, horário comercial, usuário de TI | Normal |
| 4625 em rajada seguido de um 4624 tipo 10 | Força bruta bem-sucedida — escalar já |
| 3389 aceitando conexão de IP público | Exposição indevida da borda |
| RDP de estação para estação (10.10.20.x → 10.10.20.y) | Movimentação lateral, investigar |

RDP é o campeão de incidentes por um motivo simples: é a porta de entrada preferida de ransomware. O invasor faz força bruta ou compra a credencial pronta, entra pelo RDP, desativa o antivírus, apaga as cópias de sombra e cifra tudo. Some-se a isso o **BlueKeep** (CVE-2019-0708), falha crítica em versões antigas de RDP que permite execução remota de código **sem autenticação** — se você vê Windows 7 ou Server 2008 R2 com 3389 aberto, trate como crítico.

**Erro comum de analista júnior.** Ver 4625 e fechar como "usuário esqueceu a senha" sem olhar o `Source Network Address`. Senha esquecida vem da máquina do próprio usuário; força bruta vem de um IP que ninguém reconhece, muitas vezes de outro país.

## Porta 5432 — PostgreSQL

**O que é.** É a porta padrão do banco de dados PostgreSQL, um dos bancos de dados abertos mais usados do mundo. Pense num arquivo gigante com todas as fichas de clientes: quem chega na 5432 está pedindo para abrir esse arquivo.

**Como funciona.** O cliente abre TCP na 5432, envia uma mensagem de *startup* com usuário e nome do banco, e o servidor responde exigindo autenticação (`scram-sha-256`, `md5` ou, na pior configuração possível, `trust`, que não pede senha nenhuma). O tráfego só é cifrado se SSL/TLS estiver habilitado — não é o padrão automático em toda instalação.

**Exemplo prático.** A aplicação `10.10.60.20` conversa com o banco `db-fin01.corp.local` (`10.10.70.11`) na 5432 o dia inteiro. Isso é o normal. Uma estação de usuário `10.10.20.45` abrindo 5432 direto no banco não é.

**Como aparece nos logs.** Zeek, arquivo `conn.log` (campos separados por tabulação):

```
ts=1756869112.441  uid=CkT9aB2h1kQ  id.orig_h=10.10.20.45  id.orig_p=49812  id.resp_h=10.10.70.11  id.resp_p=5432  proto=tcp  service=postgresql  duration=612.338  orig_bytes=8412  resp_bytes=488213904  conn_state=SF
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `ts` | `1756869112.441` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos |
| `uid` | `CkT9aB2h1kQ` | Identificador único da conexão |
| `id.orig_h` / `id.orig_p` | `10.10.20.45` / `49812` | Quem iniciou: uma **estação de usuário** e sua porta efêmera |
| `id.resp_h` / `id.resp_p` | `10.10.70.11` / `5432` | Destino e porta: **5432 é PostgreSQL** |
| `proto` | `tcp` | Transporte |
| `service` | `postgresql` | Protocolo identificado pela inspeção do conteúdo |
| `duration` | `612.338` | Duração: pouco mais de 10 minutos com a conexão aberta |
| `orig_bytes` | `8412` | Payload enviado pelo cliente — 8 KB de consultas, ou seja, pouquíssimo comando |
| `resp_bytes` | `488213904` | Payload devolvido: **488 MB saindo do banco**. Pouco pedido e muita resposta é a assinatura de um `SELECT *` numa tabela inteira |
| `conn_state` | `SF` | Conexão normal, encerrada limpa — o desfecho é irrelevante aqui; o volume é que importa |

</details>


**O que o SOC N1 observa.** Normal: apenas os IPs das aplicações falando 5432, sempre para os mesmos bancos. Suspeito: origem nova, `resp_bytes` enorme, conexão fora do horário, ou qualquer 5432 cruzando a borda.

**Erro comum de analista júnior.** Achar que "é banco, então é tráfego de sistema" e ignorar. O que importa é **quem** está falando com o banco, não o fato de ser banco.

## Porta 5900 — VNC

**O que é.** VNC (Virtual Network Computing, computação em rede virtual) é o "primo mais velho e mais descuidado" do RDP: também mostra e controla a tela remota, mas em muitas instalações vai sem cifragem e, pior, **sem senha**.

**Como funciona.** TCP 5900 (a 5901, 5902 e seguintes correspondem aos displays :1, :2 etc.). O servidor anuncia a versão do protocolo RFB (Remote Framebuffer) e o tipo de segurança. O tipo de segurança **None** significa acesso livre a quem conectar.

**Exemplo prático.** Um totem de recepção com VNC ligado por um fornecedor em `10.10.90.31` e esquecido lá. Motores de busca de dispositivos varrem a internet inteira atrás exatamente disso.

**Como aparece nos logs.** Suricata, formato EVE JSON:

```json
{"timestamp":"2026-09-03T03:22:08.117+0000","event_type":"alert","src_ip":"198.51.100.42","src_port":44120,"dest_ip":"10.10.90.31","dest_port":5900,"proto":"TCP","alert":{"signature":"ET SCAN VNC Server Response","category":"Attempted Information Leak","severity":2}}
```

`src_ip` externo, `dest_port` 5900 e assinatura de varredura: alguém de fora encontrou um servidor VNC vivo. Se depois vier tráfego contínuo nessa mesma sessão, houve conexão de fato.

**O que o SOC N1 observa.** Qualquer 5900 vindo da internet é incidente. Internamente, VNC deve existir só onde a TI declarou.

**Erro comum de analista júnior.** Confundir 5900 com 5985/5986 (WinRM) ou tratar VNC como equivalente a RDP em risco — VNC costuma ser pior, porque frequentemente não há autenticação nenhuma.

## Porta 8080 — HTTP alternativo

**O que é.** É a "porta dos fundos" do HTTP (HyperText Transfer Protocol). Serve para três coisas no dia a dia corporativo: proxy de saída, console de administração de aplicação e aplicação interna que roda sem privilégio de porta baixa.

**Como funciona.** Fala HTTP puro, **sem cifragem**, igual à 80. Tudo que passa — inclusive credencial de console administrativo — pode ser lido por quem estiver no caminho.

**Exemplo prático.** Todas as estações usam `proxy.corp.local:8080` para navegar. Ao mesmo tempo, um console de gerenciamento em `10.10.80.15:8080` aceita login `admin` com senha padrão.

**Como aparece nos logs.** Squid, `access.log`:

```
1756871904.221   4413 10.10.20.45 TCP_MISS/200 918442 GET http://198.51.100.201:8080/update/pkg.bin - HIER_DIRECT/198.51.100.201 application/octet-stream
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| *timestamp* | `1756871904.221` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos |
| duração | `4413` | 4,4 segundos para atender — compatível com um download grande |
| cliente | `10.10.20.45` | A estação que pediu |
| resultado/status | `TCP_MISS/200` | Não estava em cache; buscou na origem e recebeu 200 OK |
| bytes | `918442` | 918 KB entregues ao cliente |
| método | `GET` | Pedido de leitura |
| URL | `http://198.51.100.201:8080/update/pkg.bin` | **Três sinais numa só URL**: HTTP em claro, destino por **IP e não por nome**, e porta 8080 — nenhuma atualização de fornecedor sério se parece com isto |
| hierarquia/destino | `HIER_DIRECT/198.51.100.201` | Foi direto ao endereço externo |
| tipo de conteúdo | `application/octet-stream` | MIME de **binário genérico**: o servidor não diz o que é. Combinado com `.bin`, é download de executável |

</details>


**O que o SOC N1 observa.** Normal: estações → proxy interno na 8080. Suspeito: estação → IP externo cru na 8080, especialmente baixando executável, ou console administrativo acessível de fora.

**Erro comum de analista júnior.** Tratar 8080 como "web, então é seguro". 8080 não é cifrada; para cifrado veja HTTPS 443 (coberto em outro trecho deste módulo).

## Tabela mestra de portas

| Porta | Serviço | Transporte | Cifrado | Sai para a internet? | Risco | O que investigar |
|---|---|---|---|---|---|---|
| 20/21 | FTP | TCP | Não | Não | Alto | Credencial em texto claro, upload em massa |
| 22 | SSH | TCP | Sim | Só com exceção | Médio | Força bruta, origem incomum, túnel |
| 23 | Telnet | TCP | Não | Nunca | Crítico | Tudo em texto claro; legado/IoT |
| 25 | SMTP | TCP | Opcional | Só relay oficial | Médio | Relay aberto, spam saindo |
| 53 | DNS | UDP/TCP | Não | Só resolvedor | Alto | Túnel DNS, domínio recém-criado |
| 67/68 | DHCP | UDP | Não | Nunca | Médio | Servidor DHCP não autorizado |
| 80 | HTTP | TCP | Não | Via proxy | Médio | Download de binário, C2 |
| 88 | Kerberos | TCP/UDP | Sim | Nunca | Alto | 4768/4769, Kerberoasting |
| 110 | POP3 | TCP | Não | Não | Médio | Senha em claro |
| 123 | NTP | UDP | Não | Só servidor NTP | Baixo | Amplificação, desvio de relógio |
| 135 | RPC Endpoint Mapper | TCP | Não | Nunca | Alto | Execução remota, Impacket |
| 137/138/139 | NetBIOS | UDP/TCP | Não | Nunca | Alto | Enumeração, Responder |
| 143 | IMAP | TCP | Não | Não | Médio | Senha em claro |
| 161/162 | SNMP | UDP | Não (v1/v2c) | Nunca | Alto | Community `public`, amplificação |
| 389 | LDAP | TCP/UDP | Não | Nunca | Alto | Enumeração de diretório |
| 443 | HTTPS | TCP | Sim | Sim | Médio | JA3, SNI, certificado |
| 445 | SMB | TCP | Parcial | Nunca | Crítico | Lateral, ransomware, PsExec |
| 465/587 | SMTPS/Submission | TCP | Sim | Sim | Baixo | Conta comprometida enviando |
| 514 | Syslog | UDP | Não | Nunca | Médio | Parada de envio de log |
| 636 | LDAPS | TCP | Sim | Nunca | Médio | Consulta massiva ao AD |
| 993 | IMAPS | TCP | Sim | Sim | Baixo | Login de país incomum |
| 995 | POP3S | TCP | Sim | Sim | Baixo | Coleta de caixa postal |
| 1433 | MS SQL Server | TCP | Opcional | Nunca | Alto | Força bruta `sa`, exfiltração |
| 1521 | Oracle | TCP | Opcional | Nunca | Alto | Acesso fora da aplicação |
| 3268 | Global Catalog | TCP | Não | Nunca | Alto | Enumeração ampla do AD |
| 3306 | MySQL/MariaDB | TCP | Opcional | Nunca | Alto | Força bruta, dump |
| 3389 | RDP | TCP | Sim (TLS) | Nunca | Crítico | 4624 tipo 10, 4625, BlueKeep |
| 5432 | PostgreSQL | TCP | Opcional | Nunca | Alto | Origem nova, volume de saída |
| 5900 | VNC | TCP | Geralmente não | Nunca | Crítico | Sem senha, exposto |
| 5985/5986 | WinRM | TCP | 5986 sim | Nunca | Alto | Execução remota, 4688 |
| 8080 | HTTP alternativo | TCP | Não | Só proxy | Médio | Console admin, download cru |
| 8443 | HTTPS alternativo | TCP | Sim | Só com exceção | Médio | Console admin exposto |

## Portas que nunca deveriam cruzar a borda

| Porta | Por que é alerta imediato |
|---|---|
| 445 (SMB) | Compartilhamento de arquivos e execução remota; caminho de ransomware e de PsExec/Impacket. Nunca há uso legítimo pela internet. |
| 139 (NetBIOS Session) | Versão antiga do SMB; mesma capacidade de acesso a arquivos, sem proteção moderna. |
| 137 (NetBIOS Name) | Entrega nomes de máquina e de domínio a quem perguntar — mapa pronto da rede interna. |
| 135 (RPC) | Ponto de partida da execução remota no Windows; expor equivale a oferecer o mecanismo de comando. |
| 3389 (RDP) | Controle total da máquina; alvo número um de força bruta e ransomware. |
| 23 (Telnet) | Sessão administrativa em texto claro; senha visível para qualquer um no caminho. |
| 21 (FTP) | Credencial e arquivos em texto claro; usado para exfiltração e para hospedar estágios de malware. |
| 1433 (MS SQL) | Banco de dados exposto = dados da empresa expostos; alvo histórico de força bruta na conta `sa`. |
| 3306 (MySQL) | Mesma lógica: acesso direto ao dado, sem passar pela aplicação. |
| 5900 (VNC) | Frequentemente sem senha; controle de tela livre para quem encontrar. |
| 5432 (PostgreSQL) | Banco exposto, com risco de dump completo das tabelas. |
| 161 (SNMP) | Revela inventário, interfaces e topologia; v1/v2c sem cifragem e ainda serve a ataques de amplificação. |

Consulta em Splunk (SPL) para caçar isso na borda:

````spl
index=firewall action=allow
| where NOT cidrmatch("10.0.0.0/8", src_ip)            ```comentário: origem fora da rede interna```
| search dest_port IN (445,139,137,135,3389,23,21,1433,3306,5900,5432,161)
| stats count values(dest_port) as portas by src_ip, dest_ip
| sort - count
````

Equivalente em KQL (Sentinel):

```kql
CommonSecurityLog
| where DeviceAction == "allow"                          // apenas o que passou
| where ipv4_is_private(SourceIP) == false               // origem pública
| where DestinationPort in (445,139,137,135,3389,23,21,1433,3306,5900,5432,161)
| summarize Tentativas=count() by SourceIP, DestinationIP, DestinationPort
| order by Tentativas desc
```

### Exercícios — RDP, PostgreSQL, VNC, 8080 e as tabelas mestras

1. Você recebe 240 eventos 4625 no servidor `srv-app01.corp.local` em 6 minutos, todos com `Source Network Address: 203.0.113.77` e nomes de usuário diferentes. Logo depois, um 4624 com Logon Type 10 para `maria.costa` do mesmo IP. Verdadeiro ou falso positivo? Qual o próximo passo?
2. No `conn.log` do Zeek, `10.10.20.45` conecta em `10.10.70.11:5432` com `resp_bytes=488213904` às 03h. É esperado? O que confirmar antes de escalar?
3. Um alerta Suricata mostra `dest_port 5900` com origem `198.51.100.42`. O gestor da área diz que "é o fornecedor acessando o totem". Como você fecha esse chamado?
4. Usando a tabela mestra, diga quais destas portas jamais deveriam aparecer em tráfego de entrada vindo da internet: 443, 445, 993, 3389, 8443, 161.
5. No Squid, `10.10.20.45` faz GET em `http://198.51.100.201:8080/update/pkg.bin`. Por que 8080 aqui é mais preocupante do que a mesma URL na 443?

<details><summary>Ver gabarito</summary>

1. **Verdadeiro positivo, prioridade máxima.** A rajada de 4625 com usuários variados é enumeração de contas; a rajada seguida de sucesso indica força bruta bem-sucedida (T1110) com sessão RDP interativa remota (Logon Type 10, T1021.001). Próximo passo: isolar o servidor da rede, bloquear `203.0.113.77` na borda, desabilitar/redefinir a conta `maria.costa`, coletar 4688 (criação de processo) e Sysmon Event ID 1 na janela após o 4624 para ver o que foi executado, e verificar por que a 3389 estava alcançável da internet.
2. **Não é esperado.** Uma estação de usuário não deve falar direto com o banco — quem fala é o servidor de aplicação. Somados os 488 MB devolvidos pelo banco e o horário (03h), o padrão é de exfiltração (T1030). Antes de escalar, confirme: (a) `10.10.20.45` é mesmo estação de usuário no inventário; (b) existe alguma exceção formal para ferramenta administrativa; (c) havia sessão de usuário ativa nessa máquina no horário (4624). Se as três respostas forem "não", escale como incidente.
3. **Não fecha só com a palavra do gestor.** Peça o registro formal da exceção (chamado, aprovação de segurança, janela de acesso). VNC exposto à internet costuma vir sem senha e sem cifragem. A recomendação correta é remover a exposição direta e colocar o acesso do fornecedor atrás de VPN com autenticação multifator. Enquanto isso não ocorre, documente como risco aceito com prazo — não como falso positivo.
4. **445, 3389 e 161** nunca devem aparecer em entrada vinda da internet. 443 e 8443 podem, para serviços publicados de forma controlada (8443 apenas com exceção justificada, porque costuma ser console administrativo). 993 é entrada legítima apenas se a empresa publica servidor IMAP próprio; no cenário típico, o correio é serviço em nuvem e o tráfego é de saída.
5. Porque na 8080 o conteúdo trafega **sem cifragem** e, principalmente, porque a requisição usa **IP cru, sem nome de domínio, em porta não padrão, baixando um binário**. Essa combinação é o padrão de download de estágio de malware (T1105). Na 443 o download também seria suspeito, mas a 8080 com IP puro elimina a hipótese de site legítimo de CDN e facilita a decisão. Próximo passo: bloquear o IP no proxy, extrair o hash do arquivo no endpoint e correlacionar com Sysmon Event ID 1 e 3 na estação.

</details>

## Mini-laboratório — Portas e protocolos na prática

**Objetivo.** Ver com os próprios olhos como uma varredura de portas e uma conexão de banco aparecem na rede e no log.

**Pré-requisitos.** VirtualBox com uma máquina Linux (Ubuntu Server), Docker instalado nela, `nmap`, `tcpdump` e Wireshark. Tudo em rede isolada *host-only* — jamais aponte varredura para endereço que não seja seu.

**Passo 1 — subir serviços.** Na VM Linux:

```bash
docker run -d --name lab-pg -e POSTGRES_PASSWORD=lab_senha_ficticia -p 5432:5432 postgres:16
docker run -d --name lab-web -p 8080:80 nginx:alpine
```

*Observe:* `docker ps` deve mostrar os dois contêineres com as portas 5432 e 8080 mapeadas.

**Passo 2 — capturar.** Em outro terminal da mesma VM:

```bash
sudo tcpdump -i any -w /tmp/lab-portas.pcap 'tcp port 5432 or tcp port 8080 or tcp port 3389'
```

**Passo 3 — varrer.** De uma terceira janela, contra a própria VM:

```bash
nmap -sS -sV -p 3389,5432,5900,8080 127.0.0.1
```

*Observe:* 5432 e 8080 devem aparecer `open` com o serviço identificado; 3389 e 5900 devem aparecer `closed` — exatamente o que você espera de um host que não roda RDP nem VNC.

**Passo 4 — gerar tráfego real.**

```bash
curl -s http://127.0.0.1:8080/ > /dev/null
```

**Passo 5 — analisar.** Pare o tcpdump com Ctrl+C e abra o arquivo no Wireshark. Aplique os filtros, um de cada vez:

```
tcp.port == 8080
tcp.flags.syn == 1 && tcp.flags.ack == 0
tcp.port == 5432
```

*Observe:* no primeiro filtro você vê a requisição HTTP legível em texto claro (clique com o botão direito → Follow → TCP Stream). No segundo, os SYN da varredura em sequência de portas — a assinatura visual de um port scan. No terceiro, o handshake do PostgreSQL.

**Critério de sucesso.** Você consegue (a) ler o conteúdo HTTP da 8080 em texto claro, (b) apontar no Wireshark a sequência de SYN da varredura e (c) explicar por que 3389 e 5900 fechadas são a resposta correta neste host.

## O que um SOC Level 1 realmente precisa saber

- 🟢 Porta sozinha não prova nada: o que decide é a tríade **origem, destino e direção** do tráfego.
- 🟢 Decore o núcleo: 22 SSH, 53 DNS, 80 HTTP, 443 HTTPS, 445 SMB, 3389 RDP, 389/636 LDAP/LDAPS, 88 Kerberos.
- 🟢 Protocolo sem cifragem (21, 23, 80, 110, 143, 161 v2c, 514, 8080) expõe credencial e conteúdo a quem estiver no caminho.
- 🟢 RDP exposto à internet é achado crítico por si só, mesmo sem nenhum alerta associado.
- 🟢 4624 Logon Type 10 é sessão RDP; 4625 em rajada é força bruta ou enumeração — sempre olhe o `Source Network Address`.
- 🟢 Banco de dados (1433, 3306, 5432, 1521) só conversa com servidor de aplicação. Estação falando com banco é investigação.
- 🟡 Volume grande de resposta (`resp_bytes` no Zeek) somado a horário estranho é o par clássico de exfiltração.
- 🟡 8080 é HTTP puro: proxy, console de administração e aplicação interna. Download de binário por IP cru na 8080 é estágio de malware.
- 🟡 VNC (5900) frequentemente vem sem senha; tratá-lo como "RDP mais leve" é subestimar o risco.
- 🟡 Aprenda a usar as duas tabelas deste módulo como checklist de triagem antes de escalar.
- 🔴 Serviço rodando em porta fora do padrão é comum tanto em aplicação legítima quanto em canal de comando e controle; só a App-ID do firewall ou o `service` do Zeek resolve.
- 🔴 BlueKeep (CVE-2019-0708) em sistemas antigos permite execução remota sem autenticação — priorize acima de qualquer outro achado de RDP.

## Resumo em 10 linhas

1. Porta é o número que identifica o serviço dentro de um endereço IP.
2. Existem portas conhecidas (0–1023), registradas (1024–49151) e dinâmicas (49152–65535).
3. TCP entrega com confirmação; UDP entrega rápido e sem garantia.
4. Serviços em texto claro — Telnet, FTP, HTTP, POP3, IMAP, SNMP v2c, syslog — expõem credencial e dado.
5. As versões cifradas correspondentes (SSH, HTTPS, IMAPS, LDAPS, 5986) são a recomendação padrão.
6. O ambiente Windows/Active Directory concentra risco em 88, 135, 137–139, 389, 445, 636 e 3389.
7. Bancos de dados (1433, 3306, 5432, 1521) nunca devem estar acessíveis pela internet.
8. RDP na 3389 é o vetor mais explorado por ransomware; monitore 4624 tipo 10 e 4625.
9. Doze portas nunca devem cruzar a borda: 445, 139, 137, 135, 3389, 23, 21, 1433, 3306, 5900, 5432 e 161.
10. Na triagem, pergunte sempre: quem falou, com quem, em qual porta, em qual direção e em qual horário.



---
