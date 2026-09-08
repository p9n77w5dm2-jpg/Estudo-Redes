# Módulo 16 — Laboratórios práticos: Wireshark e Linux para SOC

Ler sobre pacotes é como ler sobre natação: você entende a teoria, mas afunda na primeira piscina. Este módulo tira você da leitura e coloca a mão no teclado. Um analista de SOC (Security Operations Center, ou Centro de Operações de Segurança) Nível 1 que nunca abriu uma captura de pacotes vai tratar todo alerta de rede como uma caixa-preta — e vai fechar chamado como falso positivo por não conseguir provar o contrário. Montar um laboratório próprio é o que transforma "o SIEM disse que é malicioso" em "eu vi o pacote, o SNI e o certificado, e por isso classifico assim".

**Índice do módulo:**

- Montagem do laboratório caseiro e primeiros labs de Wireshark
- Labs de DNS e análise de captura maliciosa
- Linux essencial para SOC, brute force SSH e tcpdump

## Montagem do laboratório caseiro

### O que é um laboratório de análise

Pense numa cozinha experimental de restaurante: você testa receitas com fogo, faca e ingredientes estragados, mas isolada do salão onde os clientes comem. O laboratório de segurança é isso — máquinas virtuais onde você pode rodar tráfego suspeito, quebrar configurações e restaurar tudo em dois cliques, sem encostar na rede de casa ou da empresa.

### Requisitos realistas de hardware

Não é preciso servidor. É preciso memória RAM (Random Access Memory, memória de trabalho) e disco.

| Perfil | RAM total | Disco livre | O que roda simultaneamente |
|---|---|---|---|
| Mínimo | 8 GB | 120 GB SSD | 1 Windows cliente + 1 Ubuntu |
| Confortável | 16 GB | 250 GB SSD | Firewall + Controlador de Domínio + cliente Windows + Ubuntu |
| Ideal | 32 GB | 500 GB SSD | Tudo acima + Security Onion (sensor de rede) |

Regra prática de alocação: Windows Server como Controlador de Domínio pede 4 GB; Windows 10/11 cliente, 4 GB; Ubuntu servidor, 2 GB; pfSense/OPNsense como firewall, 2 GB; Security Onion **exige** 12 GB de RAM e 200 GB de disco para rodar com Suricata e Zeek juntos — abaixo disso a instalação falha ou o sensor descarta pacotes. Sempre deixe 4 GB para o sistema operacional do seu próprio computador (o host).

### Escolha do hipervisor

Hipervisor é o programa que cria e executa as máquinas virtuais (VMs).

| Hipervisor | Custo | Snapshot | Melhor para |
|---|---|---|---|
| VirtualBox | Gratuito, código aberto | Sim, ilimitado | Iniciante, Windows/Linux/macOS |
| VMware Workstation Player | Gratuito para uso pessoal | Limitado no Player | Quem já usa VMware no trabalho |
| Hyper-V | Incluso no Windows Pro | Sim ("checkpoints") | Quem não quer instalar nada extra |
| Proxmox VE | Gratuito, código aberto | Sim | Lab permanente em máquina dedicada |

Atenção a um detalhe que trava muita gente: no Windows, ativar o Hyper-V faz o VirtualBox e o VMware rodarem em modo degradado, porque o Hyper-V toma para si as instruções de virtualização do processador. Escolha um e desative o outro.

### Tipos de rede virtual — e qual usar

| Tipo | O que faz | Uso no lab de segurança |
|---|---|---|
| NAT | VM sai para a internet usando o IP do host; ninguém de fora alcança a VM | Só para baixar atualizações, antes de isolar |
| Bridge | VM entra na sua rede real como se fosse um computador físico | **Nunca** para VM de análise |
| Host-only | VM fala só com o host e com outras VMs; sem internet | Bom para o sensor e para acesso administrativo |
| Rede interna | VM fala só com outras VMs; nem o host enxerga | **Padrão do lab de malware e análise** |

A escolha correta para o laboratório de segurança é **rede interna** para o segmento onde roda a amostra suspeita, com um firewall virtual (pfSense) fazendo a única ponte controlada. Use NAT temporariamente para instalar e atualizar, depois troque para rede interna e tire o snapshot.

### Snapshots e higiene

Snapshot é uma fotografia do estado da VM (disco e memória) para a qual você pode voltar. Disciplina mínima:

1. Instale o sistema, atualize, instale as ferramentas.
2. Tire o snapshot chamado `base-limpa`.
3. Faça o laboratório.
4. Volte para `base-limpa` antes do próximo laboratório.

Regras de higiene inegociáveis:

- Nunca coloque a VM de análise em modo bridge na rede de casa ou da empresa.
- Nunca compartilhe pastas do host com a VM de análise, nem habilite área de transferência compartilhada.
- Nunca faça login em contas reais (e-mail corporativo, banco) dentro da VM de lab.
- Nunca use credenciais reais no lab: use `jsilva`, `maria.costa`, `admin.rodrigo`, `svc_backup` e domínio `corp.local`.
- Capturas com dados de produção não saem do ambiente autorizado.

### Topologia proposta

```
                       [ HOST FISICO ]  Windows/Linux + Wireshark
                              |
                       (adaptador host-only  192.168.56.0/24)
                              |
   +--------------------------+---------------------------+
   |                    LAB-MGMT (host-only)               |
   +--------------------------+---------------------------+
                              |
                  +-----------------------+
                  |  FW-LAB  (pfSense)    |
                  |  WAN: NAT (opcional)  |
                  |  LAN: 10.10.10.1/24   |
                  |  SPAN -> porta espelho|
                  +-----------+-----------+
                              |
        ============ LAB-INTERNA (rede interna) 10.10.10.0/24 ============
             |                    |                    |
    +----------------+   +----------------+   +------------------+
    | DC-LAB         |   | WS-CLIENTE01   |   | SRV-UBUNTU       |
    | Windows Server |   | Windows 11     |   | Ubuntu 22.04     |
    | AD DS + DNS    |   | membro dominio |   | SSH / web / DNS  |
    | 10.10.10.10    |   | 10.10.10.50    |   | 10.10.10.20      |
    +----------------+   +----------------+   +------------------+
                              |
                  +-----------------------+
                  |  SO-SENSOR            |
                  |  Security Onion       |
                  |  Zeek + Suricata      |
                  |  mgmt 192.168.56.20   |
                  |  mon  (modo promiscuo)|
                  +-----------------------+
```

A interface de monitoramento (`mon`) do sensor não recebe endereço IP: ela só escuta. É assim que um sensor de rede real funciona.

## LAB 1 — Primeira captura com Wireshark

**Objetivo:** capturar tráfego real, aplicar filtros de exibição e ler os campos essenciais de um pacote.

**Pré-requisitos:** VM `WS-CLIENTE01` ou `SRV-UBUNTU` ligada, Wireshark instalado, snapshot `base-limpa` tirado.

**Passos:**

1. Abra o Wireshark e escolha a interface da rede interna (a que mostra gráfico de atividade).
2. Inicie a captura (ícone da barbatana azul) e deixe rodar 60 segundos.
3. Na VM, gere tráfego previsível:

```bash
ping -c 4 10.10.10.10
curl -s http://10.10.10.20/index.html -o /dev/null
nslookup www.example.com 10.10.10.10
```

4. Pare a captura e salve como `lab01.pcapng`.
5. Aplique, um de cada vez, estes filtros de exibição na barra superior:

```
icmp
ip.addr == 10.10.10.20
tcp.port == 80
dns
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

6. Clique em um pacote ICMP e abra as camadas no painel do meio: Frame, Ethernet II, Internet Protocol, Internet Control Message Protocol.

**O que você deve observar:** o `ping` gera pacotes ICMP tipo 8 (Echo Request) e tipo 0 (Echo Reply). A consulta DNS aparece na porta 53/UDP. O `curl` abre uma conexão TCP na porta 80 e a coluna Info mostra `GET /index.html HTTP/1.1`. O filtro de SYN sem ACK lista exatamente uma linha por tentativa de conexão nova.

**Perguntas de verificação:**

1. Qual filtro mostra só as conexões novas iniciadas? → `tcp.flags.syn == 1 && tcp.flags.ack == 0`.
2. Qual é o tipo ICMP do Echo Reply? → Tipo 0 (o Request é tipo 8).
3. Por que `ip.addr == X` é diferente de `ip.src == X`? → `ip.addr` casa origem **ou** destino; `ip.src` só origem.

**Critério de sucesso:** você consegue, sem consultar nada, isolar todo o tráfego de um único host e listar suas tentativas de conexão.

**Erros comuns:** confundir filtro de captura (sintaxe BPF, ex. `host 10.10.10.20`) com filtro de exibição (sintaxe Wireshark, ex. `ip.addr == 10.10.10.20`); capturar na interface errada; esquecer que o Wireshark precisa de privilégio elevado para colocar a placa em modo promíscuo.

## LAB 2 — Three-way handshake e handshake TLS

**Objetivo:** identificar SYN, SYN-ACK e ACK, e localizar ClientHello, SNI e o certificado do servidor numa sessão TLS.

**Pré-requisitos:** LAB 1 concluído; acesso a um servidor HTTPS no lab ou via NAT temporário.

**Passos:**

1. Inicie a captura no Wireshark.
2. Gere uma sessão HTTPS:

```bash
curl -s https://www.example.com -o /dev/null
```

3. Pare a captura. Aplique o filtro do handshake TCP:

```
tcp.flags.syn == 1 || tcp.flags.fin == 1 || tcp.flags.reset == 1
```

4. Clique com o botão direito em um pacote da sessão → **Follow → TCP Stream** → feche a janela (isso cria o filtro `tcp.stream eq N`).
5. Agora filtre o handshake TLS (Transport Layer Security, o protocolo que cifra o HTTPS):

```
tls.handshake.type == 1
tls.handshake.extensions_server_name
tls.handshake.type == 11
```

6. No pacote do ClientHello, expanda `Transport Layer Security → Handshake Protocol: Client Hello → Extension: server_name` e leia o campo SNI (Server Name Indication).
7. No pacote de tipo 11 (Certificate), expanda até `subject` e `issuer` do certificado.

**O que você deve observar:** três pacotes na abertura — SYN (flags `0x002`), SYN-ACK (`0x012`), ACK (`0x010`) — e só depois o ClientHello. O SNI aparece **em texto claro**, mesmo em HTTPS: é por isso que o SOC consegue saber para qual site o usuário foi sem quebrar a criptografia. Em TLS 1.2 o certificado vem em claro; em TLS 1.3 ele já vai cifrado e o Wireshark não mostra o `subject`.

**Como aparece nos logs (Zeek `ssl.log`):**

```
#fields ts  uid  id.orig_h  id.orig_p  id.resp_h  id.resp_p  version  cipher  server_name  established  ja3
1725360012.481  CkAbc1  10.10.10.50  50122  203.0.113.45  443  TLSv12  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256  www.example.com  T  a0e9f5b2c7d31e4f6a8b0c2d4e6f8a1b
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `ts` | `1725360012.481` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos |
| `uid` | `CkAbc1` | Identificador único da conexão — cruza com o `conn.log` |
| `id.orig_h` / `id.orig_p` | `10.10.10.50` / `50122` | O cliente do laboratório e sua porta efêmera |
| `id.resp_h` / `id.resp_p` | `203.0.113.45` / `443` | O servidor e a porta |
| `version` | `TLSv12` | Versão do TLS negociada |
| `cipher` | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | Conjunto de cifras acordado |
| `server_name` | `www.example.com` | O SNI: o nome que o cliente pediu, visível mesmo com o tráfego cifrado |
| `established` | `T` | O handshake completou (`T`) ou foi interrompido (`F`) |
| `ja3` | `a0e9f5b2c7d31e4…` | Impressão digital do cliente TLS. **Compare o seu valor com o do exemplo**: como depende do programa que abriu a conexão, o `curl` e o navegador dão `ja3` diferentes |

</details>


**O que o SOC N1 observa:** normal é SNI coerente com o destino e handshake concluído (`established=T`). Suspeito é conexão TLS para IP puro sem SNI, SNI que não bate com o certificado, ou o mesmo JA3 saindo de dezenas de estações para destinos diferentes.

**Perguntas de verificação:**

1. Quais flags aparecem no SYN-ACK? → SYN e ACK, valor `0x012`.
2. O SNI é cifrado? → Não, em TLS 1.2 e 1.3 sem ECH o SNI trafega em claro.
3. Por que o certificado sumiu na captura? → A sessão negociou TLS 1.3, que cifra a mensagem Certificate.

**Critério de sucesso:** você localiza SYN/SYN-ACK/ACK, extrai o SNI e explica por que o certificado pode não estar visível.

**Erros comuns:** usar o filtro obsoleto `ssl` em vez de `tls`; achar que "porta 443" garante HTTPS; concluir "sem certificado = malicioso" quando é apenas TLS 1.3.

### Exercícios — Montagem do laboratório caseiro e primeiros labs de Wireshark

1. Você tem 16 GB de RAM e quer rodar DC-LAB (4 GB), WS-CLIENTE01 (4 GB), SRV-UBUNTU (2 GB) e Security Onion. É viável? Justifique com números.
2. Um estagiário configurou a VM de análise em modo bridge para "ter internet mais rápido". Liste dois riscos concretos e a correção.
3. Leia o log e diga se é normal ou suspeito:

```
1725361880.117  CmXy77  10.10.10.50  51944  198.51.100.77  443  -  -  -  F  6a1b3c9d0e2f4a7b8c5d1e3f9a0b2c4d
```

4. No Wireshark, qual único filtro lista todas as tentativas de conexão iniciadas pelo host `10.10.10.50`?
5. Um alerta diz "conexão HTTPS para domínio recém-registrado". Qual o próximo passo antes de escalar?

<details><summary>Ver gabarito</summary>

1. **Não com folga.** 4+4+2 = 10 GB, e o Security Onion exige 12 GB — total 22 GB, acima dos 16 GB, sem contar os ~4 GB do host. Solução: rodar o sensor em outro momento, reduzir o cliente Windows para 3 GB e desligar o DC durante labs que não usam Active Directory, ou usar apenas Zeek/Suricata isolados em vez da distribuição completa.

2. Riscos: (a) a amostra em análise alcança diretamente máquinas reais da rede doméstica ou corporativa e pode se propagar; (b) o tráfego de laboratório sai com IP da rede real, gerando alerta de segurança legítimo contra o próprio analista e possível bloqueio. Correção: mover o adaptador para **rede interna**, deixar o pfSense como única saída controlada e usar NAT apenas em janelas curtas de atualização, restaurando o snapshot depois.

3. **Suspeito.** O campo `established` está em `F`: o handshake TLS não completou. Além disso `server_name` está vazio (`-`), ou seja, conexão para IP puro sem SNI, e a versão/cifra não foram negociadas. Isso é padrão típico de beacon de canal de comando e controle testando um destino, ou de varredura. Ação do N1: verificar reputação de `198.51.100.77`, contar a frequência e a regularidade das tentativas (batimento cardíaco de beacon) e olhar o processo de origem em Sysmon Event ID 3.

4. `ip.src == 10.10.10.50 && tcp.flags.syn == 1 && tcp.flags.ack == 0`. Só SYN sem ACK identifica tentativa de abertura; incluir ACK traria também as respostas do servidor.

5. Antes de escalar, extrair o **SNI** do ClientHello e comparar com o `server_name` do `ssl.log` do Zeek; confirmar se o handshake foi estabelecido; identificar o processo de origem no endpoint (Sysmon Event ID 3, conexão de rede) e verificar se o domínio foi acessado por um único usuário ou por vários. Domínio recém-registrado sozinho não fecha o caso — muitos serviços legítimos rodam em domínios novos. O que decide é o conjunto: processo suspeito, ausência de referenciador e periodicidade da conexão.

</details>


## LAB 3 — DNS na prática: da consulta normal ao túnel disfarçado

O DNS (Domain Name System, ou Sistema de Nomes de Domínio) é a lista telefônica da internet: você sabe o nome ("padaria do bairro"), mas precisa do endereço da rua para chegar lá. O computador sabe `www.example.com`, mas só consegue conversar usando o endereço IP `203.0.113.25`. Quem faz essa tradução é o DNS.

Para o SOC (Security Operations Center, o centro de operações de segurança), o DNS é ouro: quase todo malware precisa resolver um nome antes de se comunicar com o servidor do atacante. Se o analista sabe ler DNS, ele vê o ataque antes do dado sair.

### Objetivo

Entender na prática como uma consulta DNS viaja pela rede, identificar cada tipo de registro, reconhecer o erro NXDOMAIN e medir o tamanho das consultas para reconhecer o padrão de um túnel DNS (técnica MITRE ATT&CK T1071.004 — Application Layer Protocol: DNS).

### Pré-requisitos

| Item | Detalhe |
|---|---|
| Máquina virtual | Linux (Ubuntu ou Kali) da montagem feita no primeiro laboratório deste módulo |
| Ferramentas | `dig`, `nslookup`, `tcpdump`, Wireshark |
| Instalação do dig | `sudo apt install dnsutils -y` |
| Rede | Acesso à internet e permissão de captura (`sudo`) |

### Passos numerados

1. Abra o Wireshark, selecione a interface de rede ativa e inicie a captura.
2. No filtro de exibição do Wireshark, digite `dns` e pressione Enter. Só o tráfego DNS aparecerá.
3. No terminal, consulte um registro **A** (endereço IPv4): `dig example.com A`
4. Consulte um registro **AAAA** (endereço IPv6): `dig example.com AAAA`
5. Consulte um registro **MX** (Mail Exchange, servidor de e-mail): `dig example.com MX`
6. Consulte um registro **TXT** (texto livre, usado para SPF e DKIM): `dig example.com TXT`
7. Consulte um registro **NS** (Name Server, servidor autoritativo): `dig example.com NS`
8. Consulte um registro **CNAME** (apelido que aponta para outro nome): `dig www.example.com CNAME`
9. Provoque um **NXDOMAIN** (domínio inexistente): `dig nao-existe-mesmo-9f3k.example.com`
10. Troque o resolvedor e compare: `dig @1.1.1.1 example.com` e depois `dig @8.8.8.8 example.com`. Compare o campo `Query time` de cada resposta.
11. Gere consultas com subdomínio longo, simulando o formato de um túnel: `dig aGVsbG8td29ybGQtdGVzdGUtZGUtbGFiLTAwMQ.tunel.example.com`. Repita 20 vezes trocando o texto do início.
12. Pare a captura e salve como `lab3-dns.pcapng`.

### O que observar

- Cada consulta usa a porta **UDP 53**. Um par consulta/resposta tem o mesmo **Transaction ID**.
- No painel do Wireshark, o campo `Flags` da resposta traz o **Reply code**: `No error (0)` para sucesso e `No such name (3)` para NXDOMAIN.
- O tamanho do nome consultado. Uma consulta normal (`example.com`) tem 20 a 40 bytes de nome. As consultas do passo 11 passam de 60 bytes — esse é o sinal do túnel.
- No `dig`, a seção `ANSWER SECTION` mostra o **TTL** (Time To Live), o tempo em segundos que a resposta pode ficar em cache.

### Como aparece nos logs

Zeek `dns.log` (o registro que o SOC mais usa para DNS):

```
#fields ts  uid  id.orig_h  id.orig_p  id.resp_h  id.resp_p  proto  query  qtype_name  rcode_name  answers
1757001102.114  CxT8k21  10.10.20.45  51422  10.10.0.53  53  udp  example.com  A  NOERROR  203.0.113.25
1757001133.870  CxT8k22  10.10.20.45  51890  10.10.0.53  53  udp  nao-existe-mesmo-9f3k.example.com  A  NXDOMAIN  -
1757001140.002  CxT8k23  10.10.20.45  52001  10.10.0.53  53  udp  aGVsbG8td29ybGQtdGVzdGUtZGUtbGFiLTAwMQ.tunel.example.com  TXT  NOERROR  "OK"
```

<details><summary>Ver legenda</summary>

| Campo | 1ª (normal) / 2ª (NXDOMAIN) / 3ª (túnel) | O que significa |
|---|---|---|
| `ts` | `1757001102.114` / `1757001133.870` / `1757001140.002` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos |
| `uid` | `CxT8k21` / `CxT8k22` / `CxT8k23` | Identificador único de cada consulta |
| `id.orig_h` / `id.orig_p` | `10.10.20.45` / `51422`, `51890`, `52001` | A estação e a porta efêmera de cada consulta |
| `id.resp_h` / `id.resp_p` | `10.10.0.53` / `53` | O resolvedor interno, na porta 53 |
| `proto` | `udp` | Consulta DNS sobre UDP |
| `query` | `example.com` / `nao-existe-mesmo-9f3k.example.com` / `aGVsbG8td29ybGQ…tunel.example.com` | O nome consultado. A 3ª tem o rótulo em **Base64** — decodificado dá texto legível, e é assim que se confirma tunelamento |
| `qtype_name` | `A` / `A` / `TXT` | Tipo de registro. O `TXT` da 3ª é o que transporta o dado |
| `rcode_name` | `NOERROR` / `NXDOMAIN` / `NOERROR` | Resultado. `NXDOMAIN` significa que o nome não existe |
| `answers` | `203.0.113.25` / `-` / `"OK"` | A resposta. Vazia no `NXDOMAIN`; na 3ª é a confirmação do servidor do túnel |

</details>


O mesmo evento em um firewall Palo Alto (log TRAFFIC em CSV, campos simplificados):

```
1,2026/09/03 10:32:20,001801000123,TRAFFIC,end,10.10.20.45,10.10.0.53,0.0.0.0,0.0.0.0,regra-dns-saida,jsilva,,dns,vsys1,Confianca,Servidores,ethernet1/2,ethernet1/3,Log-Padrao,52001,53,udp,allow,178,89,89,2
```

<details><summary>Ver legenda</summary>

| Posição no exemplo | Campo | Valor | O que significa |
|---|---|---|---|
| 1 | — | `1` | Reservado pelo fabricante |
| 2 | Receive Time | `2026/09/03 10:32:20` | Quando o firewall registrou |
| 3 | Serial Number | `001801000123` | Qual equipamento gerou |
| 4 / 5 | Type / Subtype | `TRAFFIC` / `end` | Log de sessão, no fim |
| 6 / 7 | Source / Destination Address | `10.10.20.45` / `10.10.0.53` | A estação do laboratório e **o servidor DNS interno** |
| 8 / 9 | NAT Source / Destination IP | `0.0.0.0` / `0.0.0.0` | Sem NAT: é tráfego interno |
| 10 | Rule Name | `regra-dns-saida` | A regra que permitiu a consulta |
| 11 / 12 | Source / Destination User | `jsilva` / `-` | Usuário resolvido |
| 13 | Application | `dns` | **App-ID identificou DNS inspecionando o conteúdo.** Se alguém tunelasse outra coisa na 53, o App-ID não diria `dns` |
| 14 | Virtual System | `vsys1` | Firewall virtual |
| 15 / 16 | Source / Destination Zone | `Confianca` / `Servidores` | Da zona de usuários para a de servidores |
| 17 / 18 | Inbound / Outbound Interface | `ethernet1/2` / `ethernet1/3` | Interfaces de entrada e saída |
| 19 | Log Action | `Log-Padrao` | Perfil de encaminhamento |
| 20 / 21 | Source / Destination Port | `52001` / `53` | Porta efêmera e **53, o DNS** |
| 22 / 23 | Protocol / Action | `udp` / `allow` | **`udp`**: o DNS usa UDP por padrão — e por isso não há handshake nem estado |
| 24 | Bytes | `178` | Total nos dois sentidos: uma consulta e uma resposta caberiam nisto |
| 25 / 26 | Bytes Sent / Received | `89` / `89` | Volume simétrico, típico de pergunta-e-resposta |
| 27 | Packets | `2` | **Dois pacotes**: a consulta e a resposta |
| — | — | — | **Recorte de 27 campos**; o formato completo tem mais de 46 |

</details>


### O que o SOC N1 observa

| Sinal | Normal | Suspeito |
|---|---|---|
| Volume de consultas por host | 50 a 500 por hora | Mais de 1.000 por hora para um único domínio pai |
| Tamanho médio do nome consultado | 15 a 40 caracteres | Acima de 50 caracteres, com aparência aleatória |
| Tipo de registro | A, AAAA, CNAME, MX | TXT e NULL em volume alto e repetido |
| Taxa de NXDOMAIN | Menos de 5% das consultas | Acima de 20% (indício de DGA — Domain Generation Algorithm) |
| Destino da consulta | Servidor DNS interno (`10.10.0.53`) | Estação falando direto com `203.0.113.90` na porta 53 |

Query SPL (Splunk) para caçar túnel DNS:

```spl
index=zeek sourcetype=zeek:dns
| eval tam_query=len(query)
| stats count avg(tam_query) as media_tamanho dc(query) as nomes_unicos by id.orig_h, parent_domain
| where count > 500 AND media_tamanho > 50
| sort - count
```

Linha a linha: filtra o log de DNS do Zeek; calcula o tamanho de cada nome consultado; agrupa por estação e domínio pai contando consultas, tamanho médio e nomes distintos; mantém só quem passou de 500 consultas com média acima de 50 caracteres; ordena do maior para o menor.

Query KQL (Microsoft Sentinel), equivalente:

```kql
DnsEvents
| where TimeGenerated > ago(24h)                       // últimas 24 horas
| extend TamNome = strlen(Name)                        // tamanho do nome consultado
| summarize Consultas=count(), Media=avg(TamNome)      // agrega por host de origem
    by ClientIP, Dominio=strcat_array(array_slice(split(Name,"."), -2, -1), ".")
| where Consultas > 500 and Media > 50                 // limiar de suspeita
| order by Consultas desc
```

### Verificação com gabarito

| Pergunta | Resposta esperada |
|---|---|
| Qual porta e protocolo de transporte a consulta usou? | UDP 53 |
| O que casa a resposta com a pergunta? | O Transaction ID, idêntico nos dois pacotes |
| Qual o rcode do domínio inexistente? | `No such name (3)`, exibido pelo Zeek como NXDOMAIN |
| Trocar o resolvedor mudou o endereço IP retornado? | Normalmente não; muda o `Query time` e o TTL restante |
| Qual o tamanho médio das consultas do passo 11? | Acima de 55 caracteres — padrão típico de tunelamento |

### Critério de sucesso

Você capturou pelo menos um par consulta/resposta de cada tipo de registro, identificou o NXDOMAIN na captura sem consultar o terminal, e conseguiu explicar em uma frase por que a média de tamanho do passo 11 é o indicador de túnel.

### Erros comuns

- Filtrar com `dns.port == 53` (filtro inválido). O correto é `dns` ou `udp.port == 53`.
- Esquecer que respostas grandes caem para **TCP 53**; se você filtrar só UDP, perde parte do tráfego.
- Confundir NXDOMAIN com "internet caiu". NXDOMAIN significa que o servidor respondeu corretamente que o nome não existe.

---

## LAB 4 — Analisar uma captura de tráfego malicioso pública

### Objetivo

Aplicar a metodologia de 10 passos apresentada no Módulo 12 sobre uma captura real de infecção, extrair os IOCs (Indicators of Compromise, indicadores de comprometimento) e escrever um mini-relatório no formato usado pelo SOC.

### Pré-requisitos

| Item | Detalhe |
|---|---|
| Fonte | `malware-traffic-analysis.net`, seção "Traffic Analysis Exercises" |
| Arquivo | Um `.pcap` dentro de ZIP protegido (a senha está publicada no próprio site) |
| Ambiente | Máquina virtual isolada, sem pasta compartilhada com o host |
| Ferramentas | Wireshark e, opcionalmente, Zeek para gerar os logs |

Cuidado importante: baixe e abra apenas dentro da máquina virtual de laboratório. O ZIP contém tráfego real de malware e, em alguns exercícios, o binário. Nunca execute o arquivo extraído.

### Passos numerados

1. Baixe o exercício e extraia o `.pcap` dentro da máquina virtual.
2. Abra no Wireshark e vá em `Statistics > Capture File Properties` para anotar a janela de tempo.
3. `Statistics > Endpoints`, aba IPv4: ordene por bytes e identifique a vítima (endereço RFC1918) e os destinos externos.
4. `Statistics > Conversations`: liste os pares vítima/servidor com maior volume e maior duração.
5. Filtre `dns` e anote todos os nomes consultados que não pertencem a domínios conhecidos.
6. Filtre `http.request` e colete `Host`, `URI` e `User-Agent` de cada requisição.
7. Filtre `tls.handshake.type == 1` (Client Hello) e leia o campo SNI (Server Name Indication) para ver o nome mesmo em tráfego cifrado.
8. `File > Export Objects > HTTP` para listar os arquivos transferidos; anote nome e tamanho, sem executar nada.
9. Identifique o padrão de beacon: conexões repetidas para o mesmo destino em intervalos regulares.
10. Consolide os IOCs e escreva o mini-relatório.

### O que observar

- O primeiro contato externo após a atividade do usuário (o "paciente zero" da linha do tempo).
- `User-Agent` estranho ou desatualizado, muitas vezes sem o nome do navegador.
- Domínio recém-registrado, com nome aleatório, resolvendo para IP em faixa de hospedagem barata.
- Regularidade: se o intervalo entre conexões é quase idêntico, é máquina falando, não pessoa.

### Como aparece nos logs

Suricata EVE JSON (alerta de IDS gerado sobre a mesma captura):

```json
{"timestamp":"2026-09-03T11:04:18.221000+0000","flow_id":1884320011,"event_type":"alert","src_ip":"10.10.20.45","src_port":49721,"dest_ip":"203.0.113.77","dest_port":80,"proto":"TCP","alert":{"signature_id":2036501,"rev":3,"signature":"ET MALWARE Win32/Generic CnC Checkin","category":"A Network Trojan was detected","severity":1},"http":{"hostname":"cdn-update.empresa-exemplo.com.br","url":"/api/v2/ping.php","http_user_agent":"Mozilla/4.0 (compatible; MSIE 6.0)","http_method":"POST","length":142}}
```

Campos: `src_ip` é a vítima; `dest_ip` e `dest_port` são o servidor de comando e controle; `signature` é o nome da regra; `severity: 1` é a mais alta; `http_user_agent` antigo demais para uma estação atual é sinal forte.

Sysmon Event ID 3 (Network connection detected) no endpoint, correlacionando o mesmo fluxo:

```
EventID: 3
UtcTime: 2026-09-03 11:04:18.198
Image: C:\Users\jsilva\AppData\Local\Temp\svhost.exe
User: CORP\jsilva
Protocol: tcp
SourceIp: 10.10.20.45
SourcePort: 49721
DestinationIp: 203.0.113.77
DestinationPort: 80
DestinationHostname: cdn-update.empresa-exemplo.com.br
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `EventID` | `3` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não. `3` = Sysmon **Network Connect** |
| `UtcTime` | `2026-09-03 11:04:18.198` | Instante do evento **em UTC**, o que dispensa converter fuso ao correlacionar |
| `Image` | `C:\Users\jsilva\AppData\Local\Temp\svhost.exe` | Caminho do executável (nomenclatura do Sysmon) |
| `User` | `CORP\jsilva` | Conta sob a qual o processo corre |
| `Protocol` | `tcp` | Protocolo de transporte da conexão |
| `SourceIp` | `10.10.20.45` | IP de origem da conexão |
| `SourcePort` | `49721` | Porta de origem |
| `DestinationIp` | `203.0.113.77` | IP de destino da conexão |
| `DestinationPort` | `80` | Porta de destino |
| `DestinationHostname` | `cdn-update.empresa-exemplo.com.br` | Nome do host de destino, quando o Sysmon consegue resolvê-lo |

</details>

O `Image` apontando para `AppData\Local\Temp` com nome imitando processo do sistema (`svhost.exe` em vez de `svchost.exe`) é o achado que fecha a história: o pacote na rede tem dono no endpoint.

### Formato do mini-relatório

Preencha exatamente esta estrutura:

```
RELATÓRIO DE ANÁLISE DE CAPTURA — SOC N1
----------------------------------------
1. Identificação
   Analista:
   Data/hora da análise:
   Arquivo analisado (nome e hash SHA-256):
   Janela de tempo da captura (início / fim):

2. Resumo executivo (3 linhas, sem jargão)

3. Host afetado
   IP:
   Hostname:
   Endereço MAC:
   Usuário associado:

4. Linha do tempo
   HH:MM:SS  evento observado
   HH:MM:SS  evento observado
   HH:MM:SS  evento observado

5. IOCs extraídos
   Domínios:
   Endereços IP:
   URLs:
   User-Agent:
   Arquivos (nome / tamanho / hash):

6. Técnicas MITRE ATT&CK identificadas
   Txxxx — nome da técnica — evidência

7. Avaliação
   Verdadeiro positivo / Falso positivo / Inconclusivo:
   Justificativa:

8. Recomendações
   Contenção:
   Bloqueios a solicitar:
   Escalonamento para N2 (sim/não e por quê):
```

### Verificação com gabarito

| Item | Como validar |
|---|---|
| Vítima corretamente identificada | É o único endereço RFC1918 com tráfego de saída em `Endpoints` |
| Domínio de comando e controle | Aparece em `dns.log` e no SNI, e não pertence a serviço conhecido |
| Beacon confirmado | Intervalos entre conexões com desvio pequeno (por exemplo, 60s ± 3s) |
| Técnicas MITRE | No mínimo T1071.001 (Web Protocols) e T1071.004 (DNS), quando houver túnel |

### Critério de sucesso

O mini-relatório está completo, todos os IOCs têm evidência apontando para um pacote específico da captura, e a seção 8 traz uma recomendação acionável (bloquear domínio no proxy, isolar a estação) em vez de "monitorar".

### Erros comuns

- Copiar o IP do servidor DNS interno como IOC. O `10.10.0.53` é infraestrutura da empresa, não indicador.
- Marcar todo domínio desconhecido como malicioso sem checar se é CDN ou serviço de telemetria legítimo.
- Escrever o relatório sem linha do tempo. Sem ordem dos eventos, o N2 não consegue continuar a investigação.
- Extrair o objeto HTTP e clicar duas vezes nele. Extrair é analisar; executar é se infectar.

### Exercícios — Labs de DNS e análise de captura maliciosa

1. Uma estação `10.10.20.45` gerou, em uma hora, 1.840 consultas DNS para subdomínios de `dados.empresa-exemplo.com.br`, todas do tipo TXT, com nome médio de 62 caracteres e rcode NOERROR. Calcule a taxa de consultas por minuto e diga qual técnica MITRE ATT&CK está em jogo.

2. Leia o log e diga o que aconteceu:
```
1757003001.221  10.10.20.88  10.10.0.53  53  udp  kj3n2lasd9x.example.com  A  NXDOMAIN  -
1757003001.480  10.10.20.88  10.10.0.53  53  udp  p0w9msdk22a.example.com  A  NXDOMAIN  -
1757003001.733  10.10.20.88  10.10.0.53  53  udp  zzq8vnmx01b.example.com  A  NOERROR  203.0.113.140
```

3. Este alerta é verdadeiro ou falso positivo? O Suricata disparou `ET MALWARE Win32/Generic CnC Checkin` para `10.10.20.45` indo a `203.0.113.77:80`. O Sysmon Event ID 3 do mesmo segundo mostra `Image: C:\Program Files\Empresa\Agente\agente-inventario.exe`, assinado, e o destino é o servidor de inventário documentado da empresa.

4. Na captura do LAB 4 você encontrou o domínio `cdn-update.empresa-exemplo.com.br` resolvendo para `203.0.113.77`, com POST a cada 60 segundos. Qual o próximo passo da investigação, antes de pedir bloqueio no firewall?

<details><summary>Ver gabarito</summary>

**1.** 1.840 ÷ 60 = aproximadamente **30,7 consultas por minuto**, ou uma a cada 2 segundos, de forma sustentada por uma hora. Nenhum uso humano de navegador produz isso para um único domínio pai. A combinação de volume alto, tipo TXT (que carrega texto arbitrário na resposta), nome longo e resposta sempre NOERROR indica **T1071.004 — Application Layer Protocol: DNS**, ou seja, tunelamento de dados sobre DNS. O detalhe que fecha o caso é o NOERROR: o domínio pai existe e tem servidor autoritativo respondendo, o que é exatamente a estrutura de um túnel.

**2.** É o padrão clássico de **DGA (Domain Generation Algorithm)**: o malware gera nomes pseudoaleatórios e tenta um atrás do outro até acertar o que o operador registrou. Os dois primeiros deram NXDOMAIN (nome não registrado) e o terceiro respondeu com `203.0.113.140` — esse é o servidor de comando e controle ativo. O intervalo de cerca de 250 milissegundos entre tentativas confirma automação. Ação: isolar `10.10.20.88` e tratar `203.0.113.140` como IOC.

**3.** **Falso positivo.** A assinatura casou por comportamento (POST periódico com User-Agent genérico), mas a evidência de endpoint contradiz: o processo é assinado, está em `Program Files` e não em pasta temporária, e o destino é infraestrutura documentada. O erro de analista júnior aqui é fechar o chamado só com o alerta de rede. O correto é registrar a justificativa, anexar o Sysmon como evidência e solicitar exceção ou ajuste da regra ao time responsável — sem isso, o mesmo alerta volta amanhã.

**4.** Antes de pedir bloqueio, faça duas checagens. Primeira: confirmar se o domínio é realmente externo e não um serviço interno mal nomeado — consulte o registro do domínio e o inventário de aplicações. Segunda: descobrir a **origem** no endpoint, correlacionando o Sysmon Event ID 3 pelo par IP/porta e horário para achar o `Image` responsável, e o Event ID 1 (Process Create) para ver quem foi o processo pai. Bloquear o domínio sem achar o processo apenas silencia o sintoma: o mesmo malware troca de domínio e volta. Só depois disso o pedido ao firewall e ao proxy vai acompanhado do que precisa ser removido da estação.

</details>


## LAB 5 — Linux essencial para o SOC

Pense no Linux como a cozinha de um restaurante: o cliente vê o prato pronto (o dashboard do SIEM), mas quem investiga de verdade precisa entrar na cozinha e olhar as panelas. No SOC Nível 1, 80% dos servidores, firewalls, proxies e sensores que geram os seus alertas são Linux. Saber cinco comandos bem usados vale mais do que decorar cinquenta.

**Pré-requisito:** a máquina virtual Ubuntu do laboratório caseiro montado no primeiro trecho deste módulo.

### 5.1 Navegação e leitura de arquivos

| Comando | Para que serve | Exemplo |
|---|---|---|
| `ls -lah` | lista arquivos com tamanho legível e ocultos | `ls -lah /var/log` |
| `cd` | muda de diretório | `cd /var/log` |
| `find` | procura arquivos por nome, dono ou data | `find /var/log -name "*.log" -mtime -1` |
| `cat` | imprime o arquivo inteiro | `cat /etc/hostname` |
| `less` | lê arquivo grande com rolagem (`/` busca, `q` sai) | `less /var/log/syslog` |
| `head -n 20` | primeiras 20 linhas | `head -n 20 access.log` |
| `tail -f` | acompanha o arquivo **ao vivo** | `tail -f /var/log/auth.log` |

`tail -f` é o comando mais usado em plantão: você deixa a janela aberta enquanto reproduz um teste e vê o log nascer.

```bash
$ ls -lah /var/log/auth.log
-rw-r----- 1 syslog adm 412K set  3 09:14 /var/log/auth.log
```

Leitura da saída: `-rw-r-----` = dono lê e escreve, grupo só lê, resto **nada**; dono `syslog`, grupo `adm`, 412 KB, alterado hoje às 09:14. Se você não está no grupo `adm`, precisa de `sudo`.

### 5.2 Busca com grep

`grep` é o "Ctrl+F" da linha de comando.

| Flag | Efeito |
|---|---|
| `-i` | ignora maiúsculas/minúsculas |
| `-v` | inverte: mostra o que **não** casa |
| `-c` | conta linhas que casaram |
| `-E` | regex estendida (`|`, `+`, `{}`) |
| `-r` | recursivo em diretórios |
| `-n` | mostra número da linha |

```bash
$ grep -c "Failed password" /var/log/auth.log
1873
$ grep -Ei "failed|invalid user" /var/log/auth.log | grep -v "192.168.10.25" | head -n 3
Sep  3 09:02:11 srv-web01 sshd[2211]: Failed password for invalid user admin from 203.0.113.45 port 51022 ssh2
Sep  3 09:02:12 srv-web01 sshd[2213]: Failed password for root from 203.0.113.45 port 51024 ssh2
Sep  3 09:02:14 srv-web01 sshd[2215]: Failed password for jsilva from 203.0.113.45 port 51026 ssh2
```

Regex básica que resolve o dia a dia: `^` início da linha, `$` fim, `.` qualquer caractere, `[0-9]{1,3}` de um a três dígitos, `\.` ponto literal.

### 5.3 Processamento de log: a cadeia clássica

| Comando | Papel |
|---|---|
| `cut -d' ' -f1` | corta por delimitador e escolhe o campo |
| `awk '{print $1}'` | mesma ideia, mas entende colunas e faz contas |
| `sed 's/a/b/'` | substitui texto |
| `sort` | ordena (`-n` numérico, `-r` decrescente) |
| `uniq -c` | conta repetições **de linhas já ordenadas** |
| `wc -l` | conta linhas |
| `tr` | troca ou apaga caracteres (`tr -s ' '` colapsa espaços) |

A cadeia que todo analista precisa saber de cor — top 10 endereços IP de um `access.log` de servidor web:

```bash
$ awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -nr | head -n 10
  48211 203.0.113.45
   1204 198.51.100.77
    883 10.10.20.14
    512 192.0.2.31
```

Lendo: `awk` pega a primeira coluna (o IP de origem), `sort` agrupa iguais lado a lado, `uniq -c` conta, `sort -nr` ordena do maior para o menor, `head` corta no top 10. Aqui `203.0.113.45` fez 40 vezes mais requisições que o segundo colocado — anomalia clara.

### 5.4 Rede, processos, usuários e logs

| Comando | O que responde |
|---|---|
| `ip a` | quais endereços IP a máquina tem |
| `ip r` | qual é o gateway padrão |
| `ss -tulpn` | quais portas estão abertas e qual processo escuta |
| `ping` / `traceroute` | há conectividade? por onde passa? |
| `dig example.com` | qual IP o DNS (Sistema de Nomes de Domínio) devolve |
| `curl -I https://example.com` | responde com quais cabeçalhos HTTP |
| `tcpdump` | captura pacotes no terminal |
| `ps aux` | todos os processos, com dono e uso de CPU |
| `top` | processos ao vivo, ordenados por CPU |
| `lsof -i :443` | qual processo está usando a porta 443 |
| `id jsilva` / `sudo -l` | grupos e privilégios do usuário |
| `journalctl -u ssh --since "1 hour ago"` | log de um serviço no systemd |

```bash
$ ss -tulpn
Netid State  Local Address:Port   Process
tcp   LISTEN 0.0.0.0:22           users:(("sshd",pid=812,fd=3))
tcp   LISTEN 127.0.0.1:3306       users:(("mysqld",pid=1140,fd=22))
tcp   LISTEN 0.0.0.0:4444         users:(("python3",pid=9911,fd=4))
```

**O que o N1 observa:** `sshd` na 22 e `mysqld` amarrado em `127.0.0.1` são normais. `python3` escutando em `0.0.0.0:4444` (aberto para toda a rede, porta clássica de shell reverso) é **suspeito** — escale imediatamente. Isso mapeia para MITRE ATT&CK T1571 (Non-Standard Port).

**Erro comum de júnior:** rodar `uniq -c` sem `sort` antes. `uniq` só compara linhas **adjacentes**, então a contagem sai errada e ninguém percebe.

---

## LAB 6 — Investigar brute force SSH

**Brute force** (força bruta) é o ladrão que testa mil chaves na mesma fechadura. No SSH (Secure Shell, acesso remoto por terminal, porta TCP 22), cada chave errada vira uma linha no `/var/log/auth.log`.

**Passo 1 — gerar as tentativas na SUA VM.** Do host, contra a VM Ubuntu do laboratório (IP `192.168.56.20`), digite a senha errada de propósito cinco vezes:

```bash
$ ssh usuario.inexistente@192.168.56.20
```

**Passo 2 — ver o rastro:**

```bash
$ sudo tail -n 5 /var/log/auth.log
Sep  3 09:02:11 srv-web01 sshd[2211]: Failed password for invalid user usuario.inexistente from 192.168.56.1 port 51022 ssh2
Sep  3 09:02:15 srv-web01 sshd[2211]: Connection closed by authenticating user root 203.0.113.45 port 51044 [preauth]
Sep  3 09:02:40 srv-web01 sshd[2260]: Accepted password for jsilva from 10.10.20.14 port 51190 ssh2
```

Campos: data e hora, host (`srv-web01`), serviço e PID (`sshd[2211]`), resultado (`Failed password` / `Accepted password`), usuário, IP de origem e porta de origem. `invalid user` significa que o usuário **nem existe** — sinal forte de varredura automatizada.

**Passo 3 — a cadeia que conta tentativas por IP:**

```bash
$ sudo grep "Failed password" /var/log/auth.log \
  | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' \
  | sort | uniq -c | sort -nr | head
   1841 203.0.113.45
      5 192.168.56.1
      2 10.10.20.14
```

O `awk` procura a palavra `from` e imprime o campo seguinte — assim funciona tanto para `invalid user` quanto para usuário existente, onde a posição da coluna muda.

**Regra de detecção proposta:** mais de 20 `Failed password` do mesmo IP de origem em 5 minutos, ou mais de 5 usuários distintos tentados pelo mesmo IP. E o gatilho de maior valor: **falhas seguidas de um `Accepted password` do mesmo IP** — isso é brute force **bem-sucedido** (MITRE T1110.001), incidente crítico.

```spl
index=linux sourcetype=linux_secure "Failed password"
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| bin _time span=5m
| stats count AS falhas, dc(user) AS usuarios_distintos BY _time, src_ip, host
| where falhas > 20 OR usuarios_distintos > 5
```

```kql
Syslog
| where SyslogMessage has "Failed password"                 // só falhas de autenticação
| extend src_ip = extract(@"from (\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
| summarize falhas = count() by src_ip, Computer, bin(TimeGenerated, 5m)
| where falhas > 20                                          // limiar de brute force
```

**Erro comum de júnior:** fechar o alerta porque "só teve falha, ninguém entrou". Sempre pesquise o mesmo IP de origem procurando `Accepted password` **depois** da rajada — e verifique se o IP é de scanner conhecido ou de um servidor interno comprometido.

---

## LAB 7 — tcpdump em servidor sem interface gráfica

Servidor de produção não tem Wireshark. Você captura com `tcpdump`, salva em arquivo e analisa na sua estação.

**Passo 1 — capturar 200 pacotes da porta 22 na interface `eth0`:**

```bash
$ sudo tcpdump -i eth0 -nn -s 0 -c 200 -w /tmp/ssh-brute.pcap 'tcp port 22'
tcpdump: listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
200 packets captured
```

Flags: `-i` interface, `-nn` não resolve nomes nem portas (mais rápido e sem consultas DNS acidentais), `-s 0` captura o pacote inteiro, `-c` para após N pacotes, `-w` grava em pcap. O filtro entre aspas é BPF (Berkeley Packet Filter) — **não** é filtro de exibição do Wireshark.

**Passo 2 — conferir sem sair do terminal:**

```bash
$ sudo tcpdump -nn -r /tmp/ssh-brute.pcap | head -n 3
09:02:11.114 IP 203.0.113.45.51022 > 10.10.20.5.22: Flags [S], seq 118, win 64240
09:02:11.115 IP 10.10.20.5.22 > 203.0.113.45.51022: Flags [S.], seq 90, ack 119
09:02:11.140 IP 203.0.113.45.51022 > 10.10.20.5.22: Flags [.], ack 1
```

Handshake TCP normal: `[S]` = SYN, `[S.]` = SYN-ACK, `[.]` = ACK.

**Passo 3 — transferir e abrir:**

```bash
$ scp jsilva@10.10.20.5:/tmp/ssh-brute.pcap ./
```

No Wireshark, use o filtro de exibição `tcp.port == 22 && tcp.flags.syn == 1 && tcp.flags.ack == 0` para ver só as aberturas de conexão. Dezenas de SYN do mesmo IP em segundos = brute force confirmado no nível de rede.

**Erro comum de júnior:** rodar `tcpdump` sem `-c` nem `-W`/`-C` num servidor de produção e encher o disco. Sempre limite a captura.

### Exercícios — Linux essencial para SOC, brute force SSH e tcpdump

1. Escreva a cadeia de comandos que devolve os 5 usuários mais tentados em falhas de SSH no `auth.log`.
2. `grep -c "Failed password" auth.log` devolve 3.400, mas a contagem por IP mostra 3.390 vindos de `10.10.20.99`, um servidor de backup interno. Verdadeiro ou falso positivo?
3. `ss -tulpn` mostra `tcp LISTEN 0.0.0.0:8080 users:(("nginx",pid=990))` num servidor web. Suspeito?
4. Após a rajada de `203.0.113.45` você encontra `Accepted password for svc_backup from 203.0.113.45`. Qual o próximo passo?

<details><summary>Ver gabarito</summary>

1. `sudo grep "Failed password" /var/log/auth.log | awk '{for(i=1;i<=NF;i++) if($i=="for") print $(i+1)}' | sed 's/invalid//' | grep -v '^user$' | sort | uniq -c | sort -nr | head -n 5`. O truque é o mesmo do LAB 6: ancorar na palavra-chave (`for`) em vez da posição fixa da coluna, porque `invalid user` desloca os campos.

2. **Provável falso positivo operacional, mas exige verificação.** Volume alto de um IP RFC1918 interno de backup costuma ser uma conta de serviço (`svc_backup`) com senha ou chave expirada tentando em laço. Confirme: o usuário é sempre o mesmo? O horário coincide com a janela de backup? Se sim, é problema de configuração — abra chamado para a equipe de infraestrutura em vez de tratar como ataque. Se os usuários variam, o servidor de backup pode estar comprometido e sendo usado para movimento lateral (T1110).

3. **Não é suspeito.** Porta 8080 é HTTP alternativo e o processo dono é o `nginx`, coerente com um servidor web. O que assustaria seria um processo incoerente com a função do servidor — `python3`, `nc` ou `bash` escutando numa porta alta e exposta em `0.0.0.0`.

4. **Escalar como incidente crítico imediatamente**, não fechar o ticket. Brute force bem-sucedido (T1110.001). Próximos passos do N1: (a) preservar evidência (`auth.log`, pcap); (b) listar tudo que `svc_backup` fez depois do login — `journalctl`, histórico de comandos, novos processos; (c) buscar o mesmo IP de origem nos logs de firewall e proxy procurando exfiltração; (d) acionar o N2 para conter o host e desabilitar a credencial.

</details>

---

## Mini-laboratório — Laboratórios práticos de Wireshark e Linux

**Pré-requisitos:** VirtualBox, uma VM Ubuntu Server (rede Host-Only, `192.168.56.20`), Wireshark no host, `tcpdump` na VM.

1. Na VM: `sudo apt install -y openssh-server tcpdump && sudo systemctl enable --now ssh`.
2. Na VM, deixe o log ao vivo numa janela: `sudo tail -f /var/log/auth.log`. **Observe:** nada até você agir.
3. Na VM, em outra janela, inicie a captura: `sudo tcpdump -i enp0s8 -nn -c 300 -w /tmp/lab.pcap 'tcp port 22'`.
4. Do host, erre a senha 8 vezes: `ssh usuario.inexistente@192.168.56.20`. **Observe:** cada erro gera um `Failed password ... from 192.168.56.1`.
5. Na VM, conte por IP: `sudo grep "Failed password" /var/log/auth.log | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq -c | sort -nr`.
6. Copie o pcap para o host (`scp`) e abra no Wireshark com `tcp.flags.syn == 1 && tcp.flags.ack == 0`.

**Critério de sucesso:** a contagem mostra `8 192.168.56.1`, o Wireshark exibe ao menos 8 SYN do host para a porta 22, e você consegue explicar em uma frase por que isso caracterizaria brute force se o IP fosse externo.

## O que um SOC Level 1 realmente precisa saber

- 🟢 Ler um pcap no Wireshark e aplicar filtros de exibição básicos (`ip.addr`, `tcp.port`, `dns`, `http.request`).
- 🟢 Diferenciar filtro de captura (BPF, no `tcpdump`) de filtro de exibição (no Wireshark) — sintaxes diferentes.
- 🟢 Reconhecer o handshake TCP (SYN, SYN-ACK, ACK) e o encerramento (FIN/RST) numa captura.
- 🟢 Usar `grep -i -v -c -E` e a cadeia `sort | uniq -c | sort -nr` para achar o top de qualquer campo de log.
- 🟢 Saber onde ficam os logs no Linux: `/var/log/auth.log`, `/var/log/syslog`, `journalctl -u <serviço>`.
- 🟢 Identificar brute force SSH no `auth.log` e, principalmente, checar se houve `Accepted password` depois.
- 🟡 Ler `ss -tulpn` e julgar se o processo que escuta a porta é coerente com a função do servidor.
- 🟡 Capturar com `tcpdump` limitando volume (`-c`, `-w`) e transferir o pcap com `scp`.
- 🟡 Traduzir uma detecção em regra de SIEM com limiar e janela de tempo (SPL ou KQL).
- 🟡 Analisar consultas DNS suspeitas numa captura: domínios longos, entropia alta, volume anormal de TXT.
- 🔴 Seguir um TCP Stream e correlacionar pcap com Zeek `conn.log` para reconstruir a sessão inteira.
- 🔴 Ajustar limiares para reduzir falso positivo sem criar ponto cego na detecção.

## Resumo em 10 linhas

1. Um laboratório caseiro com VirtualBox e duas VMs é suficiente para treinar tudo o que o SOC N1 faz.
2. Wireshark responde "o que exatamente passou no fio"; é a fonte de verdade quando o log é ambíguo.
3. Filtro de captura (BPF) reduz o que entra no arquivo; filtro de exibição só esconde o que já foi capturado.
4. DNS é o primeiro lugar onde malware se denuncia: domínio estranho, TXT em excesso, resolução sem tráfego depois.
5. No Linux, `tail -f` mostra o log nascendo e é o melhor amigo de quem reproduz um teste.
6. `grep` acha, `awk`/`cut` recortam, `sort | uniq -c | sort -nr` conta e ranqueia — essa cadeia resolve a maior parte da triagem.
7. `uniq -c` sem `sort` antes dá contagem errada; é o erro clássico de júnior.
8. Brute force SSH aparece como rajadas de `Failed password` no `auth.log`, com `invalid user` denunciando automação.
9. O alerta vira incidente crítico quando existe `Accepted password` do mesmo IP após as falhas (MITRE T1110.001).
10. Em servidor sem interface gráfica, capture com `tcpdump -w`, limite o volume, transfira por `scp` e analise no Wireshark.



---
