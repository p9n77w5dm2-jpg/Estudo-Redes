# Módulo 9 — VPN: túneis, IPsec, SSL VPN e investigação no SOC

## Por que este módulo importa para o SOC

A VPN é a porta da frente do trabalho remoto. É por ela que passam o notebook do comercial no aeroporto, a filial do Recife e o fornecedor que administra o firewall. Para o atacante, uma credencial de VPN válida vale mais do que qualquer exploit: ela dá acesso legítimo, autenticado e cifrado à rede interna — e o tráfego cifrado esconde o que ele faz depois. Um analista de SOC Nível 1 que entende túnel, autenticação e falha de negociação consegue separar em minutos um usuário que trocou de operadora de um atacante testando credenciais vazadas.

**Índice do módulo**

- O que é VPN, topologias e IPsec
- SSL VPN, split vs full tunnel e o processo de autenticação
- Troubleshooting de VPN e a ótica do SOC

---

## O que é uma VPN

### O malote lacrado

Imagine que você precisa enviar um documento sigiloso da sua empresa em São Paulo para a filial em Lisboa. O correio comum (a internet) é rápido, mas qualquer pessoa que manuseia o envelope pode abrir e ler. A solução é colocar o documento dentro de um **malote lacrado**, com fecho numerado e chave que só existe nas duas pontas. O carteiro continua carregando o malote pelas mesmas ruas públicas, mas não faz ideia do que há dentro — e se alguém tentar violar o lacre, o destinatário percebe.

VPN, sigla de **Virtual Private Network** (Rede Privada Virtual), é exatamente isso: um malote lacrado dentro da internet pública. O pacote original é embrulhado ("encapsulado") dentro de outro pacote, cifrado, e só é aberto no destino.

### O que a VPN garante

| Garantia | O que significa | Como é obtida |
|---|---|---|
| **Confidencialidade** | Quem intercepta vê bytes embaralhados | Cifragem simétrica (AES-256-GCM, ChaCha20) |
| **Integridade** | Se um bit for alterado no caminho, o destino descarta o pacote | Hash com chave (HMAC-SHA256, ou AEAD no GCM) |
| **Autenticação** | As duas pontas provam quem são antes de trocar dados | Pre-Shared Key (chave pré-compartilhada) ou certificado digital |
| **Anti-replay** | Um pacote capturado e reenviado é rejeitado | Número de sequência dentro do cabeçalho ESP |

### O que a VPN NÃO protege

Este é o ponto que mais confunde analista iniciante. A VPN protege o **caminho**, não as **pontas**.

- Se o notebook do usuário `jsilva` já está com um infostealer rodando, a VPN vai transportar o roubo de credenciais com toda a segurança criptográfica do mundo — direto para dentro da rede corporativa.
- A VPN não faz antivírus, não faz DLP, não valida se o usuário é realmente quem diz ser além do fator apresentado.
- Túnel cifrado significa que o IDS na borda **não vê** o conteúdo. Por isso a inspeção precisa acontecer *depois* do concentrador, onde o tráfego já saiu decifrado.

> Regra prática para o SOC: "cifrado" nunca é sinônimo de "confiável". Endpoint comprometido com VPN é comprometimento *com transporte garantido*.

---

## Topologias de VPN

### Remote Access (acesso remoto)

Um usuário individual, com um cliente instalado, cria um túnel até o concentrador da empresa. É o caso do home office.

```
   jsilva (casa)                 Internet                  Sede
  10.20.30.5 (Wi-Fi)                                 corp.local
  ┌──────────────┐                                ┌────────────────┐
  │  Notebook    │══════ túnel cifrado ══════════▶│  Concentrador  │
  │  Cliente VPN │   IP público 203.0.113.45      │  198.51.100.10 │
  └──────────────┘                                └───────┬────────┘
        IP virtual recebido: 10.99.10.37                  │
                                                  ┌───────▼────────┐
                                                  │ LAN 10.10.0.0/16│
                                                  │ DC, ERP, fileserver
                                                  └────────────────┘
```

Note o detalhe que mais gera dúvida: o notebook passa a ter **dois endereços** — o IP real da operadora (`203.0.113.45`) e o **IP virtual** entregue pelo pool da VPN (`10.99.10.37`). Nos logs internos você verá o IP virtual; nos logs do firewall de borda, o público.

### Site-to-Site (site a site)

Aqui não há cliente. Dois equipamentos (firewalls ou roteadores) mantêm um túnel permanente, e os usuários nem sabem que ele existe.

```
  Filial Recife                                    Matriz São Paulo
  LAN 172.16.20.0/24                               LAN 10.10.0.0/16
  ┌─────────────┐    túnel IPsec permanente    ┌─────────────┐
  │  FW-REC     │◀═══════════════════════════▶│  FW-SP      │
  │ 203.0.113.9 │                             │198.51.100.10│
  └─────────────┘                             └─────────────┘
```

### Hub-and-spoke vs full mesh

```
   HUB-AND-SPOKE                        FULL MESH
                                     
      [Filial A]                      [Filial A]─────[Filial B]
          │                                │  ╲     ╱   │
          │                                │   ╲   ╱    │
   [Filial B]──[MATRIZ]──[Filial C]        │    ╲ ╱     │
          │                                │     ╳      │
          │                                │    ╱ ╲     │
      [Filial D]                      [Filial D]─────[Filial C]

  n túneis para n filiais            n×(n-1)/2 túneis
  Tráfego A→B passa pela matriz      Tráfego A→B vai direto
  Fácil de inspecionar               Latência menor, visibilidade pior
```

| Critério | Hub-and-spoke | Full mesh |
|---|---|---|
| Túneis para 10 sites | 10 | 45 |
| Latência entre filiais | Maior (dois saltos) | Menor (direto) |
| Visibilidade para o SOC | Alta — tudo passa pelo hub | Baixa — tráfego lateral invisível ao hub |
| Custo operacional | Baixo | Alto |

**O que o SOC observa:** em ambiente hub-and-spoke, movimentação lateral entre filiais **tem** que aparecer no firewall da matriz. Se um host da filial A conversa com um da filial D e o hub não registrou nada, ou existe um túnel não documentado, ou alguém criou rota alternativa.

---

## IPsec em profundidade

**IPsec** (Internet Protocol Security) é um conjunto de protocolos que cifra e autentica pacotes na camada 3 (rede). Não é um protocolo só — é uma família.

### AH vs ESP

| | **AH** (Authentication Header, protocolo IP 51) | **ESP** (Encapsulating Security Payload, protocolo IP 50) |
|---|---|---|
| Cifra o conteúdo? | **Não** | **Sim** |
| Garante integridade? | Sim, inclusive de parte do cabeçalho IP | Sim, do payload |
| Sobrevive a NAT? | **Não** (o NAT altera o IP e quebra o hash) | Sim, com NAT-T |
| Uso no mundo real | Praticamente extinto | Padrão de fato |

Na prática, 99% do que você verá em produção é **ESP**. Se um log mostra AH, provavelmente é equipamento legado.

### Modo transporte vs modo túnel

```
Pacote original:       [ IP orig | TCP | dados ]

Modo TRANSPORTE:       [ IP orig | ESP | TCP | dados | ESP-trailer ]
                                        └── cifrado ──┘
                       Cabeçalho IP original preservado.
                       Uso: host-a-host dentro da mesma rede.

Modo TÚNEL:            [ IP novo | ESP | IP orig | TCP | dados | ESP-trailer ]
                                        └────── tudo cifrado ─────┘
                       Pacote inteiro vira payload de um pacote novo.
                       Uso: site-to-site e remote access. É o normal.
```

### IKE — como as pontas combinam as regras

Antes de trafegar dados, os dois lados precisam concordar em qual algoritmo usar e provar quem são. Esse é o trabalho do **IKE** (Internet Key Exchange).

**Fase 1** — cria um canal de controle seguro entre os gateways. O resultado é a **IKE SA** (Security Association, ou Associação de Segurança: o "contrato" com algoritmo, chave e prazo de validade).

**Fase 2** — dentro desse canal, negocia o túnel que realmente carregará os dados: a **IPsec SA**. Cada SA é unidirecional; um túnel completo tem no mínimo duas.

| | IKEv1 main mode | IKEv1 aggressive mode | IKEv2 |
|---|---|---|---|
| Mensagens na fase 1 | 6 | 3 | 4 |
| Identidade protegida | Sim | **Não** (vai em claro) | Sim |
| Suporte nativo a NAT-T | Extensão | Extensão | Nativo |
| Recomendação | Aceitável | Evitar | **Preferido** |

O *aggressive mode* expõe o identificador e um hash da PSK ainda em claro, o que permite ataque offline contra a chave. Se você vir aggressive mode habilitado num gateway de produção, isso é um achado para reportar.

### Diffie-Hellman

**Diffie-Hellman (DH)** é o mecanismo que permite às duas pontas chegarem à mesma chave secreta sem nunca enviá-la pela rede — como duas pessoas misturando tintas de cores públicas com uma cor secreta pessoal e chegando à mesma mistura final.

| Grupo DH | Tamanho / curva | Situação |
|---|---|---|
| 1, 2, 5 | 768 / 1024 / 1536 bits | **Obsoletos** — não usar |
| 14 | 2048 bits | Mínimo aceitável |
| 19, 20 | ECP 256 / 384 bits | Recomendado |
| 21 | ECP 521 bits | Recomendado |

### PSK vs certificado

- **PSK** (Pre-Shared Key): uma senha longa idêntica nos dois lados. Simples, mas não escala e não tem revogação — se vazar, todos os túneis que a usam estão comprometidos.
- **Certificado digital**: cada ponta tem seu par de chaves assinado por uma CA (Autoridade Certificadora). Escala, permite revogação e não expõe segredo compartilhado.

### NAT-T e as portas

ESP é um protocolo IP próprio (número 50), **não** tem portas. Roteadores NAT precisam de portas para montar a tabela de tradução — e por isso simplesmente derrubam ESP.

A solução é o **NAT-T** (NAT Traversal): o pacote ESP é embrulhado dentro de UDP 4500, ganhando portas e atravessando o NAT normalmente.

| Porta / protocolo | Função |
|---|---|
| **UDP 500** | IKE — negociação (fases 1 e 2) |
| **UDP 4500** | NAT-T — IKE e ESP encapsulados quando há NAT no caminho |
| **IP protocolo 50 (ESP)** | Dados cifrados, quando não há NAT |
| **IP protocolo 51 (AH)** | Legado |

A detecção de NAT acontece na própria fase 1: as pontas trocam hashes dos endereços que enxergam; se não baterem, há NAT no meio e a conversa migra de UDP 500 para UDP 4500.

### A negociação, passo a passo

1. Gateway A envia UDP 500 para B com suas **propostas** (cifra, hash, DH, tempo de vida).
2. B escolhe uma proposta compatível e responde. **Se nenhuma coincidir, morre aqui.**
3. Troca Diffie-Hellman: nasce a chave da fase 1.
4. Autenticação mútua (PSK ou certificado). **PSK diferente quebra aqui.**
5. Detecção de NAT → migração para UDP 4500 se necessário.
6. Fase 2: negocia cifra do túnel de dados e os *proxy IDs* (quais redes o túnel cobre).
7. IPsec SA estabelecida; ESP começa a fluir.

### Como aparece nos logs

Fase 1 e fase 2 completas, túnel de pé, no Cisco ASA:

```
%ASA-5-713119: Group = 203.0.113.9, IP = 203.0.113.9, PHASE 1 COMPLETED
%ASA-5-713049: Group = 203.0.113.9, IP = 203.0.113.9, Security negotiation complete for LAN-to-LAN group (FILIAL-RECIFE) Responder, Inbound SPI = 0x0a4b71c2, Outbound SPI = 0x77f31de9
%ASA-6-602303: IPSEC: An outbound remote access SA (SPI= 0x77F31DE9) between 198.51.100.10 and 203.0.113.9 (user= jsilva) has been created.
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `%ASA` | `%ASA` | Etiqueta do produto |
| severidade | `5` e `6` | `5` é notification, `6` é informational |
| *message ID* (1ª linha) | `713119` | **Fase 1 do IKE concluída**: o canal de controle do IPsec está de pé. É por este ID que se escreve a regra, não pelo texto |
| `Group` / `IP` | `203.0.113.9` | O par remoto do túnel. Em VPN site-a-site o grupo é o próprio IP do peer |
| *message ID* (2ª linha) | `713049` | Negociação de segurança concluída — a **fase 2**, que cria os canais de dados |
| `LAN-to-LAN group` | `(FILIAL-RECIFE)` | O nome do túnel na configuração. **É o que traduz um IP em "a filial do Recife"** |
| `Responder` | `Responder` | Quem foi **respondedor**, e não iniciador: o outro lado começou |
| `Inbound` / `Outbound SPI` | `0x0a4b71c2` / `0x77f31de9` | O **SPI** (*Security Parameter Index*) identifica cada canal de dados. **São dois, um por sentido** — e mudam a cada renegociação, por isso não servem como identificador de longo prazo |
| *message ID* (3ª linha) | `602303` | SA de IPsec criada. Confirma no plano de dados o que as duas primeiras negociaram |
| `(user= jsilva)` | `jsilva` | Utilizador associado à SA |

</details>


Erro 1 — **proposta não coincide** (FortiGate, formato key=value):

```
date=2026-09-03 time=09:14:22 devname="FW-SP" devid="FG100F0000000001" logid="0101037124" type="event" subtype="vpn" level="error" vd="root" eventtime=1772529262 logdesc="IPsec phase 1 error" msg="progress IPsec phase 1" action="negotiate" remip=203.0.113.9 locip=198.51.100.10 remport=500 locport=500 outintf="wan1" cookies="a1b2c3d4e5f60718/0000000000000000" user="N/A" group="N/A" xauthuser="N/A" xauthgroup="N/A" assignip=N/A vpntunnel="FILIAL-RECIFE" status="negotiate_error" reason="no SA proposal chosen" peer_notif="NOT-APPLICABLE"
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `date` | `2026-09-03` | Data local **do equipamento**, não UTC. Correlacionar com um log em UTC sem acertar o fuso desalinha a timeline |
| `time` | `09:14:22` | Hora local do equipamento |
| `devname` | `"FW-SP"` | Nome do equipamento que gerou o log |
| `devid` | `"FG100F0000000001"` | Número de série do equipamento — numa frota, é ele que identifica qual falou |
| `logid` | `"0101037124"` | Identificador do **tipo** de log. **É por ele que se filtra no SIEM**: o texto muda entre versões do FortiOS, o número não |
| `type` | `"event"` | Categoria do log: `traffic` é sessão, `event` é evento do próprio aparelho, `utm` é inspeção de conteúdo |
| `subtype` | `"vpn"` | Subcategoria: `forward` é tráfego que atravessa, `local` é destinado ao próprio firewall, `vpn` é túnel, `webfilter` e `ips` são inspeção |
| `level` | `"error"` | Severidade atribuída pelo FortiOS (`notice`, `warning`, `alert`, `critical`). **Quem a escolhe é o fabricante**, não o seu SOC |
| `vd` | `"root"` | *Virtual domain* (VDOM): qual firewall virtual atendeu |
| `eventtime` | `1772529262` | Instante do evento em epoch, com precisão de nanossegundos |
| `logdesc` | `"IPsec phase 1 error"` | Descrição do tipo de evento, em texto |
| `msg` | `"progress IPsec phase 1"` | Texto livre com a descrição legível. **Não use este campo em regras** — muda entre versões |
| `action` | `"negotiate"` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |
| `remip` | `203.0.113.9` | IP público **remoto** do outro lado do túnel — de onde o usuário ou o peer veio |
| `locip` | `198.51.100.10` | IP local do concentrador VPN |
| `remport` | `500` | Porta remota do túnel |
| `locport` | `500` | Porta local do túnel |
| `outintf` | `"wan1"` | Interface de saída do túnel |
| `cookies` | `"a1b2c3d4e5f60718/0000000000000000"` | Cookies do IKE, que identificam a negociação em curso |
| `user` | `"N/A"` | Conta autenticada — o que transforma "um IP" em "uma pessoa" |
| `group` | `"N/A"` | Grupo a que a conta pertence |
| `xauthuser` | `"N/A"` | Conta usada na autenticação estendida do IPsec |
| `xauthgroup` | `"N/A"` | Grupo da autenticação estendida |
| `assignip` | `N/A` | **O IP interno que a empresa emprestou** à máquina remota. Depois de o túnel subir, é este endereço que aparece no tráfego interno, e não o `remip` |
| `vpntunnel` | `"FILIAL-RECIFE"` | Nome do túnel na configuração — o que traduz um IP em "a filial tal" |
| `status` | `"negotiate_error"` | Estado da negociação |
| `reason` | `"no SA proposal chosen"` | **O campo que resolve o caso**: por que falhou ou por que terminou |
| `peer_notif` | `"NOT-APPLICABLE"` | Notificação enviada ao outro lado do túnel |
| — | — | `remip` é o IP público de quem se ligou; **`assignip` é o endereço interno que ele passou a usar**. Sem correlacionar os dois, o rastro do usuário desaparece ao entrar na rede |

</details>

`reason="no SA proposal chosen"` é literalmente "não achei uma proposta em comum". Alguém mexeu na cifra ou no grupo DH de um dos lados.

Erro 2 — **PSK diferente**:

```
%ASA-3-713048: Error processing payload: Payload ID: 1
%ASA-5-713904: Group = 203.0.113.9, IP = 203.0.113.9, All IKE SA proposals found unacceptable!
%ASA-3-713119: Group = 203.0.113.9, IP = 203.0.113.9, PHASE 1 FAILED
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `%ASA` | `%ASA` | Etiqueta do produto |
| severidade | `3` e `5` | **`3` é error** nas linhas 1 e 3, `5` é notification na 2ª. A subida de severidade acompanha a gravidade |
| *message ID* (1ª linha) | `713048` | Erro a processar *payload* do IKE. Sintoma, não causa |
| `Payload ID: 1` | `1` | Qual parte da mensagem falhou |
| *message ID* (2ª linha) | `713904` | **A causa real: nenhuma proposta de SA do IKE foi aceita.** Os dois lados não têm um conjunto comum de cifra, hash, grupo Diffie-Hellman e tempo de vida |
| *message ID* (3ª linha) | `713119` | **`PHASE 1 FAILED`** — o mesmo ID do exemplo anterior, onde dizia `COMPLETED`. **O ID não distingue sucesso de falha**; quem distingue é o texto e a severidade |
| `Group` / `IP` | `203.0.113.9` | O par remoto que tentou |
| — | — | Erro de **configuração**, não ataque: alguém mudou a proposta de um lado só. O caminho é comparar as duas configurações, não procurar comprometimento |

</details>

Em FortiGate o mesmo problema aparece como `reason="peer SA proposal not match local policy"` ou, mais claramente, uma falha de decriptação da mensagem de autenticação. A pista é a fase 1 falhar **depois** da troca DH.

Erro 3 — **fase 1 sobe, fase 2 não** (o clássico):

```
date=2026-09-03 time=09:31:07 devname="FW-SP" logid="0101037129" type="event" subtype="vpn" level="error" logdesc="IPsec phase 2 error" msg="progress IPsec phase 2" action="negotiate" remip=203.0.113.9 locip=198.51.100.10 outintf="wan1" cookies="a1b2c3d4e5f60718/9f8e7d6c5b4a3021" vpntunnel="FILIAL-RECIFE_p2" status="negotiate_error" reason="peer SA proposal not match local policy" srcaddr="10.10.0.0/255.255.0.0" dstaddr="172.16.20.0/255.255.255.0"
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `date` | `2026-09-03` | Data local **do equipamento**, não UTC. Correlacionar com um log em UTC sem acertar o fuso desalinha a timeline |
| `time` | `09:31:07` | Hora local do equipamento |
| `devname` | `"FW-SP"` | Nome do equipamento que gerou o log |
| `logid` | `"0101037129"` | Identificador do **tipo** de log. **É por ele que se filtra no SIEM**: o texto muda entre versões do FortiOS, o número não |
| `type` | `"event"` | Categoria do log: `traffic` é sessão, `event` é evento do próprio aparelho, `utm` é inspeção de conteúdo |
| `subtype` | `"vpn"` | Subcategoria: `forward` é tráfego que atravessa, `local` é destinado ao próprio firewall, `vpn` é túnel, `webfilter` e `ips` são inspeção |
| `level` | `"error"` | Severidade atribuída pelo FortiOS (`notice`, `warning`, `alert`, `critical`). **Quem a escolhe é o fabricante**, não o seu SOC |
| `logdesc` | `"IPsec phase 2 error"` | Descrição do tipo de evento, em texto |
| `msg` | `"progress IPsec phase 2"` | Texto livre com a descrição legível. **Não use este campo em regras** — muda entre versões |
| `action` | `"negotiate"` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |
| `remip` | `203.0.113.9` | IP público **remoto** do outro lado do túnel — de onde o usuário ou o peer veio |
| `locip` | `198.51.100.10` | IP local do concentrador VPN |
| `outintf` | `"wan1"` | Interface de saída do túnel |
| `cookies` | `"a1b2c3d4e5f60718/9f8e7d6c5b4a3021"` | Cookies do IKE, que identificam a negociação em curso |
| `vpntunnel` | `"FILIAL-RECIFE_p2"` | Nome do túnel na configuração — o que traduz um IP em "a filial tal" |
| `status` | `"negotiate_error"` | Estado da negociação |
| `reason` | `"peer SA proposal not match local policy"` | **O campo que resolve o caso**: por que falhou ou por que terminou |
| `srcaddr` | `"10.10.0.0/255.255.0.0"` | Objeto de endereço de origem na configuração |
| `dstaddr` | `"172.16.20.0/255.255.255.0"` | Objeto de endereço de destino na configuração |

</details>

Repare em `srcaddr` e `dstaddr`: são os *proxy IDs*. Se a matriz espera `10.10.0.0/16 ↔ 172.16.20.0/24` e a filial foi configurada com `10.10.5.0/24 ↔ 172.16.20.0/24`, a fase 1 sobe (os gateways se autenticam) e a fase 2 morre (as redes não batem). Fase 1 verde com fase 2 vermelha é quase sempre proxy ID divergente ou cifra da fase 2 diferente.

Visão do Zeek (`conn.log`) sobre o mesmo túnel:

```
#fields ts  uid  id.orig_h  id.orig_p  id.resp_h  id.resp_p  proto  service  duration  orig_bytes  resp_bytes  conn_state
1772529262.114  CpQ7xR2mNv9Lk  203.0.113.9  500  198.51.100.10  500  udp  ike  4.221  1840  1976  SF
1772529266.902  CvT4bZ8aHy1Wd  203.0.113.9  4500  198.51.100.10  4500  udp  -  3600.004  18442190  9931044  SF
```

<details><summary>Ver legenda</summary>

| Campo | 1ª linha (negociação) / 2ª linha (túnel) | O que significa |
|---|---|---|
| `ts` | `1772529262.114` / `1772529266.902` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos — o túnel sobe 4 segundos depois de a negociação terminar |
| `uid` | `CpQ7xR2mNv9Lk` / `CvT4bZ8aHy1Wd` | Identificador único de cada conexão |
| `id.orig_h` / `id.resp_h` | `203.0.113.9` → `198.51.100.10` | Os dois concentradores VPN, por IP público |
| `id.orig_p` / `id.resp_p` | `500`/`500` e `4500`/`4500` | As portas contam a história: **500/UDP é o IKE** (negociação de chaves) e **4500/UDP é o NAT-T**, o ESP encapsulado em UDP para atravessar NAT |
| `proto` | `udp` | O IPsec negocia e encapsula sobre UDP quando há NAT no caminho |
| `service` | `ike` / `-` | O Zeek reconhece o IKE; o túnel de dados aparece como `-` porque **o conteúdo está cifrado e ele não identifica nada lá dentro** |
| `duration` | `4.221` / `3600.004` | Negociação de 4 segundos; túnel de 1 hora — valor típico de vida de uma SA antes da renegociação |
| `orig_bytes` / `resp_bytes` | `1840`/`1976` e `18442190`/`9931044` | Payload em cada direção. A negociação troca poucos KB; o túnel moveu 18 MB e 9,9 MB |
| `conn_state` | `SF` | Ambas normais. Em UDP o Zeek usa `SF` para o fluxo que começou e terminou dentro da janela de observação — **não há handshake para confirmar** |

</details>

A primeira linha é a negociação (curta, poucos bytes, na 500). A segunda é o túnel de dados via NAT-T na 4500: longa duração e volume alto. `SF` significa conexão normal iniciada e finalizada.

### O que o SOC N1 observa

| Sinal | Normal | Suspeito |
|---|---|---|
| Falhas de fase 1 | Poucas, após janela de manutenção | Rajada de falhas de vários IPs de origem diferentes |
| Origem do peer site-to-site | Sempre o mesmo IP público documentado | IP novo tentando se autenticar como filial conhecida |
| Aggressive mode | Não deveria existir | Presente = superfície para quebra offline de PSK (MITRE **T1110** — Brute Force) |
| Volume no ESP/UDP 4500 | Compatível com o histórico do site | Salto súbito de saída = possível exfiltração (**T1048**) |
| Horário do túnel remote access | Horário comercial do usuário | Túnel de `jsilva` às 03h47 de um país onde ele não está (**T1133** — External Remote Services) |

### Erro comum de analista júnior

Ver `PHASE 1 COMPLETED` e concluir que "o túnel está funcionando". Fase 1 completa significa apenas que os gateways se cumprimentaram. Sem fase 2, nenhum pacote de usuário atravessa. Sempre confirme a existência da **IPsec SA** (fase 2) e, de preferência, contadores de bytes crescendo nos dois sentidos.

O segundo erro mais comum: tratar toda falha de fase 1 como ataque. Renovação de chave (*rekey*) mal sincronizada, queda de link da operadora e troca de IP dinâmico geram exatamente as mesmas mensagens. Correlacione com o histórico daquele peer antes de escalar.

---

### Exercícios — O que é VPN, topologias e IPsec

1. Uma rede tem 8 filiais em topologia full mesh. Quantos túneis existem? E se migrar para hub-and-spoke com a matriz como hub?

2. Leia o log e diga o que está errado:

```
%ASA-5-713119: Group = 203.0.113.9, IP = 203.0.113.9, PHASE 1 COMPLETED
%ASA-3-713061: Group = 203.0.113.9, IP = 203.0.113.9, Rejecting IPSec tunnel: no matching crypto map entry for remote proxy 172.16.99.0/255.255.255.0 local proxy 10.10.0.0/255.255.0.0
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `%ASA` | `%ASA` | Etiqueta do produto |
| severidade | `5` e `3` | Notification na 1ª linha, **error na 2ª** |
| *message ID* (1ª linha) | `713119` | `PHASE 1 COMPLETED` — **a autenticação funcionou**. É importante notar isto antes de ler a 2ª linha |
| *message ID* (2ª linha) | `713061` | Túnel IPsec rejeitado por não haver *crypto map* correspondente. **A fase 1 passou e a fase 2 falhou** |
| `remote proxy` | `172.16.99.0/255.255.255.0` | A rede que o **outro lado** quer alcançar |
| `local proxy` | `10.10.0.0/255.255.0.0` | A rede que **este lado** oferece |
| — | — | **É aqui que está o erro**: os dois lados têm de declarar exatamente as mesmas redes, espelhadas. O `172.16.99.0/24` não consta da configuração local. Máscara ou sub-rede diferente por um bit já basta para o túnel não fechar |

</details>

3. Um alerta dispara: "VPN IPsec — 47 falhas de fase 1 em 6 minutos, origem 198.51.100.77, gateway 198.51.100.10". O peer legítimo da filial Recife é `203.0.113.9`. Verdadeiro ou falso positivo? Qual o próximo passo?

4. O firewall da filial só permite saída em UDP 500 e ESP (protocolo 50). A filial está atrás de um roteador da operadora que faz NAT. O túnel nunca sobe. Explique a causa e a correção.

5. Escreva uma query SPL (Splunk) que liste os peers IPsec com mais erros de fase 1 nas últimas 24 horas, em logs FortiGate.

<details><summary>Ver gabarito</summary>

**1.** Full mesh: n×(n−1)/2 = 8×7/2 = **28 túneis**. Hub-and-spoke com a matriz como hub: cada filial mantém um túnel só com a matriz = **8 túneis**. A redução é grande, mas o custo é latência (tráfego entre filiais faz dois saltos) — e o ganho para o SOC é visibilidade total no hub.

**2.** A fase 1 completou, então autenticação e proposta do canal de controle estão corretas. O erro `no matching crypto map entry for remote proxy` é falha de **fase 2 por proxy ID divergente**: o peer está oferecendo `172.16.99.0/24`, mas a matriz espera outra rede (provavelmente `172.16.20.0/24`). Alguém trocou a sub-rede da filial de um lado só. Correção: alinhar as redes protegidas nos dois gateways — não é ataque, é erro de configuração.

**3.** Muito provavelmente **verdadeiro positivo de investigação**, ainda que não seja necessariamente comprometimento. O IP de origem `198.51.100.77` **não é** o peer documentado da filial, e 47 falhas em 6 minutos é padrão de tentativa automatizada contra o serviço IKE (MITRE T1110 sobre T1133). Próximos passos, nesta ordem: (a) confirmar se o modo aggressive está habilitado — se estiver, a PSK pode ter sido capturada para quebra offline; (b) verificar se houve alguma fase 1 **bem-sucedida** vinda daquele IP; (c) checar reputação e geolocalização do IP de origem; (d) bloquear a origem na borda e (e) se houve sucesso, tratar como incidente e planejar rotação da PSK. Se nenhuma tentativa teve sucesso e o IP é ruído de internet, documente e reduza a severidade — mas o bloqueio continua valendo.

**4.** Há NAT no caminho. ESP (protocolo IP 50) não possui portas, então o roteador NAT da operadora não consegue montar a tabela de tradução e descarta os pacotes. A negociação até começa em UDP 500, detecta o NAT e tenta migrar para **NAT-T em UDP 4500** — porta que o firewall da filial não libera. Correção: liberar **UDP 4500** de saída e garantir que NAT-T esteja habilitado nos dois gateways. Depois disso, o ESP viaja encapsulado em UDP e atravessa o NAT sem problema.

**5.** Query SPL:

```spl
index=firewall sourcetype=fortigate subtype=vpn level=error
| search logdesc="IPsec phase 1 error"
| eval peer=coalesce(remip, "desconhecido")
| stats count AS falhas, dc(vpntunnel) AS tuneis_afetados, values(reason) AS motivos, min(_time) AS primeira, max(_time) AS ultima BY peer
| eval primeira=strftime(primeira,"%Y-%m-%d %H:%M:%S"), ultima=strftime(ultima,"%Y-%m-%d %H:%M:%S")
| where falhas > 5
| sort - falhas
```

Linha a linha: a primeira filtra apenas eventos de VPN em nível de erro no índice de firewall; a segunda restringe a erros de fase 1 (deixando de fora ruído de fase 2); `eval peer` normaliza o IP remoto para uso como chave de agrupamento; o `stats` conta falhas por peer, mostra quantos túneis distintos foram afetados, os motivos textuais e a janela de tempo; os dois `strftime` deixam os horários legíveis; o `where` corta peers com uma ou duas falhas isoladas (rekey, oscilação de link); o `sort` traz os piores primeiro.

Equivalente em KQL (Microsoft Sentinel), assumindo os logs normalizados em `CommonSecurityLog`:

```kql
// Erros de fase 1 IPsec por peer nas últimas 24 horas
CommonSecurityLog
| where TimeGenerated > ago(24h)                       // janela de 24 horas
| where DeviceVendor == "Fortinet"                     // apenas FortiGate
| where DeviceEventClassID == "0101037124"             // logid de erro de fase 1
| summarize Falhas = count(),
            Motivos = make_set(Message, 5),
            Primeira = min(TimeGenerated),
            Ultima = max(TimeGenerated)
        by Peer = SourceIP                             // agrupa pelo IP do peer remoto
| where Falhas > 5                                     // descarta ruído isolado
| order by Falhas desc
```

</details>


## SSL VPN: a VPN que passa pela porta do site

Imagine que a empresa é um prédio com uma portaria física (o IPsec, visto no trecho anterior). Só que em muitos lugares — hotel, aeroporto, rede do cliente — a portaria física está fechada: o firewall do local bloqueia protocolos "estranhos". Então o funcionário entra por uma porta que **nunca** fica fechada em lugar nenhum: a porta 443, a mesma que todo mundo usa para abrir um site com cadeado. Essa é a ideia da SSL VPN.

**O que é:** SSL VPN (Virtual Private Network sobre SSL/TLS — Secure Sockets Layer / Transport Layer Security) é uma VPN que encapsula o tráfego dentro de uma sessão TLS, normalmente em TCP/443 ou UDP/443. Como o mundo inteiro libera 443, ela funciona praticamente de qualquer rede.

**Como funciona:** o cliente abre uma conexão TLS com o gateway VPN, valida o certificado, autentica o usuário (veremos o processo completo adiante) e a partir daí todo pacote IP do computador é colocado dentro desse túnel TLS. Uma interface virtual aparece no sistema operacional (por exemplo `tun0`, ou "TAP-Windows Adapter"), recebe um IP interno da empresa e passa a se comportar como se o notebook estivesse ligado por cabo no escritório.

### Client-based e clientless (portal)

| Modo | Como o usuário acessa | O que trafega | Uso típico |
|---|---|---|---|
| **Client-based** (full client) | Aplicativo instalado (GlobalProtect, FortiClient, AnyConnect, OpenVPN Connect, WatchGuard Mobile VPN) | Todo o tráfego IP: RDP, SMB, SSH, aplicações internas | Funcionário com máquina corporativa |
| **Clientless / portal** | Só o navegador, em `https://vpn.empresa-exemplo.com.br` | Apenas o que o portal publica: intranet web, RDP via HTML5, arquivos | Terceiro, fornecedor, máquina não gerenciada |

O modo clientless é mais cômodo, mas é **muito mais difícil de monitorar**: para o SOC, tudo sai do IP do próprio gateway, e não de um IP individual do pool.

### OpenVPN, derivados comerciais e WireGuard

O **OpenVPN** é a implementação livre mais usada de SSL VPN. Ele roda por padrão em **UDP/1194** (também aceita TCP/443) e usa a biblioteca OpenSSL. Um detalhe muito prático para o SOC N1: **vários appliances comerciais usam OpenVPN por baixo**, mesmo com nome próprio na interface. O WatchGuard Mobile VPN with SSL, por exemplo, é OpenVPN empacotado — o arquivo de configuração do cliente é um `.ovpn` comum, com diretivas conhecidas:

```text
# trecho de client.ovpn (fictício) — perfil da frota
client
dev tun
proto udp
remote vpn.empresa-exemplo.com.br 1194
redirect-gateway def1          # full tunnel: manda TODO o tráfego pelo túnel
auth-nocache                   # não guarda a senha em memória; pede de novo a cada reconexão
cipher AES-256-GCM
verb 3
```

Duas diretivas merecem atenção. `redirect-gateway def1` é o que transforma a conexão em **full tunnel**. E `auth-nocache` é ótimo para segurança (a credencial não fica em memória), mas gera um efeito colateral que o N1 vê o tempo todo: a cada queda de link o usuário recebe pedido de senha de novo, e uma sequência de reconexões parece "tentativa de brute force" no log do RADIUS quando na verdade é oscilação de Wi-Fi.

O **WireGuard** é a alternativa moderna: roda em UDP (porta configurável, comumente 51820), tem código muito menor, usa chaves públicas em vez de usuário/senha e reconecta praticamente instantâneo. Para o SOC, a diferença prática é que WireGuard **não tem sessão** no sentido clássico — ele não gera "login/logout" bonitinho, e a correlação precisa ser feita pelo IP do pool e pela chave pública do peer.

## Split tunnel vs full tunnel: o ponto cego do SOC

**Analogia:** full tunnel é o funcionário que, mesmo em casa, entra no ônibus da empresa para ir a qualquer lugar — até para comprar pão. Split tunnel é o funcionário que pega o ônibus da empresa só para ir ao escritório, e para o resto usa o carro dele, que a empresa não enxerga.

| Aspecto | Full tunnel | Split tunnel |
|---|---|---|
| Rotas empurradas | `0.0.0.0/0` (tudo) | Só as redes internas: `10.10.0.0/16`, `172.16.20.0/24` |
| Navegação na internet | Sai pelo proxy/firewall da empresa | Sai direto pelo provedor do usuário |
| Visibilidade do SOC | Total: DNS, HTTP, TLS, tudo logado | **Ponto cego**: nada do tráfego de internet aparece |
| Desempenho | Pior: tudo faz *hairpin* pelo datacenter; videoconferência sofre | Melhor: Teams e Zoom saem direto |
| Risco | Menor | Maior: máquina fica "com um pé em cada rede" |

O ponto que mais importa no dia a dia do N1: **com split tunnel, se um endpoint for infectado, o C2 (Command and Control — canal de comando do atacante) pode sair pela internet doméstica do usuário e não aparecer em nenhum log de firewall corporativo.** Nessa situação, a única fonte de verdade é a telemetria do endpoint (EDR, Sysmon) e o log do agente de proxy em nuvem (Netskope, Zscaler), quando existe. Muitas empresas resolvem isso com "split tunnel + agente de proxy em nuvem": o túnel só leva as redes internas, mas o tráfego de internet é inspecionado pelo agente local. Técnicas de exfiltração usando canal alternativo são mapeadas em MITRE ATT&CK como **T1090 (Proxy)** e **T1572 (Protocol Tunneling)**.

## O processo de autenticação, passo a passo — e o log de cada etapa

Sequência típica de uma conexão do usuário fictício `jsilva`, do IP público `203.0.113.45`, ao gateway `vpn.empresa-exemplo.com.br`:

| # | Etapa | Quem executa | Log gerado |
|---|---|---|---|
| 1 | Handshake TLS e envio das credenciais | Cliente → gateway VPN | Log do gateway (Palo Alto GlobalProtect, FortiGate `vpn` log, ASA `%ASA-6-`) |
| 2 | Gateway repassa a credencial | Gateway → RADIUS/NPS | Windows Event **6272** (concedido) / **6273** (negado) no NPS |
| 3 | Validação da senha | NPS → Active Directory / LDAP | **4776** (validação NTLM) ou **4768** (emissão de TGT Kerberos) no Domain Controller |
| 4 | Segundo fator | RADIUS → provedor de MFA | Log do provedor (Entra ID / Duo / Okta): "authentication succeeded, method: push" |
| 5 | Sessão criada | Gateway | **4624** (logon) se houver integração, + log de sessão do gateway |
| 6 | Atribuição de IP do pool | Gateway | Linha com `tunnel IP 10.60.14.37` |
| 7 | Rotas empurradas | Gateway | `push route 10.10.0.0/16` ou "assigned routes" |
| 8 | Verificação de postura / NAC | HIP check, FortiNAC, ISE | Log de HIP match / posture: antivírus atualizado, disco cifrado |

### Como isso aparece nos logs

```text
# 1) Cisco ASA — sessão SSL VPN estabelecida
%ASA-6-716001: Group <GRP-VPN-CORP> User <jsilva> IP <203.0.113.45> WebVPN session started.
%ASA-6-113039: Group <GRP-VPN-CORP> User <jsilva> IP <203.0.113.45> AnyConnect parent session started.
%ASA-6-302013: Built inbound TCP connection 88214 for outside:203.0.113.45/51022 (203.0.113.45/51022) to identity:198.51.100.10/443
```

`716001` = início de sessão SSL VPN; `302013` = conexão TCP construída — repare no destino `/443`, típico de SSL VPN. `Group` é o perfil que define split ou full tunnel.

```text
# 2) FortiGate (key=value) — evento de VPN SSL
date=2026-09-03 time=09:14:22 devname="FGT-BR-01" devid="FG100ETK00012345" logid="0101039947" type="event" subtype="vpn" level="notice" action="ssl-login-fail" user="jsilva" remip=203.0.113.45 group="N/A" reason="sslvpn_login_no_matching_policy" msg="SSL user failed to logged in"
date=2026-09-03 time=09:15:03 devname="FGT-BR-01" logid="0101039426" type="event" subtype="vpn" level="notice" action="tunnel-up" user="jsilva" remip=203.0.113.45 tunnelip=10.60.14.37 tunneltype="ssl-tunnel" duration=0 msg="SSL tunnel established"
```

`action` diz o resultado; `remip` é o IP público de origem; `tunnelip` é o **IP do pool** — anote sempre esse valor, é ele que aparecerá nos logs internos depois.

```text
# 3) Windows NPS (RADIUS) e Domain Controller
EventID=6272  Network Policy Server granted access to a user.
  Account Name: CORP\jsilva  Client Friendly Name: FGT-BR-01  Calling Station Identifier: 203.0.113.45
  Authentication Type: PEAP  Network Policy Name: NP-VPN-Colaboradores

EventID=4776  The computer attempted to validate the credentials for an account.
  Logon Account: jsilva   Source Workstation: FGT-BR-01   Error Code: 0x0

EventID=4768  A Kerberos authentication ticket (TGT) was requested.
  Account Name: jsilva@CORP.LOCAL   Client Address: ::ffff:10.60.14.37   Result Code: 0x0

EventID=4624  An account was successfully logged on.
  Account Name: jsilva   Logon Type: 3   Source Network Address: 10.60.14.37
```

Códigos úteis: `4776` com `Error Code: 0xC000006A` = senha errada; `0xC0000064` = usuário inexistente. Em `4768`, `Result Code: 0x12` = conta desabilitada ou bloqueada.

```text
# 4) Provedor de MFA (formato JSON simplificado, fictício)
{"timestamp":"2026-09-03T09:15:01Z","user":"jsilva@empresa-exemplo.com.br","application":"VPN-RADIUS","factor":"push","result":"success","device":"iPhone (pessoal)","ip":"203.0.113.45","country":"BR"}
```

### O que o SOC N1 observa

| Normal | Suspeito |
|---|---|
| `4776`/`6272` sucesso seguido de `tunnel-up` em segundos | Vários `6273`/`ssl-login-fail` e, no fim, um sucesso — possível *password spraying* (T1110.003) |
| MFA aprovado em 1 ou 2 tentativas | Rajada de pushes até o usuário aceitar — *MFA fatigue* (T1621) |
| IP de origem no Brasil, mesmo ASN de sempre | Sucesso no RADIUS **sem** evento correspondente de MFA — indica bypass ou caminho de autenticação alternativo |
| Um IP de pool por usuário | Mesmo usuário com dois `tunnelip` ativos e países diferentes — *impossible travel* |

### Consultas prontas

```spl
index=network sourcetype=fortigate subtype=vpn action=ssl-login-fail
| stats count AS falhas dc(user) AS usuarios values(user) AS lista by remip
| where falhas > 15 AND usuarios > 5
| sort - falhas
```

Linha 1 filtra só falhas de login SSL VPN. Linha 2 conta falhas e quantos usuários distintos vieram do mesmo IP. Linha 3 mantém apenas o padrão de spraying: muitas falhas espalhadas por muitas contas.

```kql
SigninLogs
| where AppDisplayName == "VPN-RADIUS"                 // só autenticação da VPN
| where ResultType == 0                                 // apenas sucessos
| summarize paises = make_set(Location), tentativas = count() by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(paises) > 1                        // mesmo usuário, país diferente na mesma hora
```

### Erro comum de analista júnior

Fechar o caso como falso positivo por ver "senha errada várias vezes, depois conectou" e concluir que foi o usuário digitando errado. Com `auth-nocache` isso é comum, sim — **mas só quando as falhas são da mesma conta e do mesmo IP**. Se as falhas envolvem contas diferentes vindas do mesmo IP público, é spraying, não dedo gordo. Outro erro clássico: investigar apenas o IP público (`remip`) e esquecer de pivotar para o `tunnelip`. Todo movimento lateral posterior aparecerá com o IP do pool, nunca com o IP público.

### Exercícios — SSL VPN, split vs full tunnel e o processo de autenticação

1. No log FortiGate acima, o usuário `jsilva` recebeu `tunnelip=10.60.14.37`. Trinta minutos depois, um `4624` com `Logon Type: 3` e origem `10.60.14.37` acessa o servidor de arquivos. Isso é normal? Qual o próximo passo?
2. Um alerta dispara: "15 falhas de login SSL VPN em 4 minutos, IP `203.0.113.45`". Ao abrir, você vê 15 eventos `ssl-login-fail` com `user="jsilva"` e um `tunnel-up` final para o mesmo usuário e IP. Verdadeiro ou falso positivo?
3. A empresa usa split tunnel. O EDR reporta que a estação de `maria.costa` contatou o domínio `atualiza-cdn.example.com` a cada 60 segundos. Você procura no log do firewall corporativo e não encontra nada. Por que, e onde procurar?
4. No NPS aparece `6272` (acesso concedido) para `admin.rodrigo` às 03:12, mas o log do provedor de MFA não tem nenhum registro desse horário. Qual a hipótese e qual a ação imediata do N1?
5. Calcule: o pool da VPN é `10.60.14.0/24`. Quantos endereços utilizáveis existem e quantos usuários simultâneos o gateway suporta nesse pool?

<details><summary>Ver gabarito</summary>

1. **É esperado, mas exige verificação.** Com full tunnel ou com rota interna empurrada, o usuário conectado navega pelos servidores internos usando o IP do pool. `Logon Type: 3` é logon de rede — normal para acesso a compartilhamento SMB. O próximo passo é confirmar que o `10.60.14.37` ainda estava atribuído a `jsilva` naquele minuto (pools são reciclados!) e verificar se o servidor acessado faz parte do escopo de trabalho dele. Pivotar sempre: IP público → IP do pool → usuário → recursos acessados.

2. **Provavelmente falso positivo — mas confirme dois pontos.** Todas as falhas são da **mesma conta** e do **mesmo IP**, terminando em sucesso: assinatura clássica de `auth-nocache` com Wi-Fi oscilando ou senha recém-trocada. Vira verdadeiro positivo se: (a) o mesmo IP tentar **outras contas**, ou (b) o MFA registrar aprovações repetidas que o usuário não reconheça. Confirme com o usuário por canal já conhecido, não pelo contato que veio no alerta.

3. **Porque em split tunnel o tráfego de internet não passa pela empresa.** A estação resolveu e contatou o domínio pelo provedor doméstico de `maria.costa`; o firewall corporativo nunca viu esse pacote. A batida a cada 60 segundos é *beaconing*, indício de C2 (T1071). Procure em: telemetria do EDR, Sysmon Event ID 3 (conexão de rede) e 22 (consulta DNS) na própria estação, e no log do agente de proxy em nuvem, se houver. Escale — isso não se resolve no N1.

4. **Hipótese: autenticação que não passou pelo MFA.** Pode ser política de rede do NPS que isenta um grupo, uma conta de serviço mal classificada, um método legado sem suporte a segundo fator, ou credencial válida usada por um atacante em caminho não coberto. Ação imediata do N1: registrar horário, IP de origem e política aplicada (`Network Policy Name` do evento 6272), verificar se `admin.rodrigo` reconhece a conexão e escalar para N2. Não desabilite conta administrativa por conta própria — siga o runbook.

5. **/24 = 256 endereços, 254 utilizáveis** (descontando rede `10.60.14.0` e broadcast `10.60.14.255`). Na prática o gateway consome um endereço para si (por exemplo `10.60.14.1`), então restam **253 sessões simultâneas**. Se a empresa tem 400 pessoas em home office, o pool esgota e usuários passam a receber erro de conexão — sintoma que chega ao SOC parecendo indisponibilidade ou ataque, mas é só dimensionamento.

</details>


## Troubleshooting de VPN: do sintoma à causa raiz

Imagine que a VPN (Virtual Private Network, ou "rede privada virtual") é uma ponte levadiça entre a casa do usuário e o castelo da empresa. Quando alguém liga dizendo "a VPN não funciona", isso pode significar coisas muito diferentes: a ponte não desce, desce e cai, desce mas leva para o lugar errado, ou desce e é lenta demais para atravessar. O trabalho do analista é descobrir **em que ponto da ponte** o problema acontece.

A regra de ouro do troubleshooting de VPN é: **teste de fora para dentro, na ordem das camadas**. Primeiro a internet do usuário, depois o alcance até o concentrador, depois a autenticação, depois o túnel, depois as rotas, depois o DNS (Domain Name System, o "catálogo de endereços" da internet) e só então a aplicação.

### Comandos de diagnóstico que você vai usar o tempo todo

| Objetivo | Windows | Linux |
|---|---|---|
| Ver IP, máscara, gateway, servidores DNS e sufixo | `ipconfig /all` | `ip a` e `resolvectl status` |
| Ver a tabela de rotas | `route print` ou `Get-NetRoute` | `ip r` |
| Testar porta TCP até o gateway VPN | `Test-NetConnection vpn.empresa-exemplo.com.br -Port 443` | `nc -vz vpn.empresa-exemplo.com.br 443` |
| Resolver um nome interno | `Resolve-DnsName srv-arquivos.corp.local` | `resolvectl query srv-arquivos.corp.local` |
| Ver conexões/portas abertas | `Get-NetTCPConnection` | `ss -tunap` |
| Estado do perfil VPN | `Get-VpnConnection -AllUserConnection` | `nmcli con show` |
| Limpar cache DNS | `ipconfig /flushdns` | `resolvectl flush-caches` |

O detalhe dos protocolos (IPsec, IKE) e da diferença entre split tunnel e full tunnel foi tratado nos trechos anteriores; aqui usamos esses conceitos apenas como causa possível.

### Sintoma 1 — "Não conecta de jeito nenhum"

**Causas prováveis:** internet do usuário fora do ar; UDP 500/4500 (IKE/IPsec) ou UDP 1194 (OpenVPN) bloqueados na rede visitada; certificado do gateway expirado; conta bloqueada ou senha expirada; relógio dessincronizado.

**Como confirmar:**

```powershell
# 1. A internet funciona? (usa IP público de documentação)
Test-NetConnection 203.0.113.10 -InformationLevel Detailed
# 2. O gateway VPN responde na porta TCP 443 (fallback SSL)?
Test-NetConnection vpn.empresa-exemplo.com.br -Port 443
# 3. O nome do gateway resolve?
Resolve-DnsName vpn.empresa-exemplo.com.br
# 4. Relógio do cliente (Kerberos tolera no máximo 5 minutos de desvio)
w32tm /query /status
```

Como o `Test-NetConnection` não testa UDP de forma confiável, para UDP 1194/500 use o log do cliente ou peça uma captura com `tcpdump -ni any udp port 1194` no lado do servidor.

**Como aparece nos logs** — FortiGate no formato chave=valor, negando o IKE de um hotel:

```
date=2026-09-03 time=09:12:44 devname="fgt-edge-01" devid="FG100E0000000001" logid="0101039426" type="event" subtype="vpn" level="error" vd="root" action="negotiate" remip=203.0.113.45 locip=198.51.100.7 remport=500 locport=500 outintf="wan1" cookies="N/A" user="jsilva" group="N/A" xauthuser="N/A" xauthgroup="N/A" assignip=N/A vpntunnel="SSLVPN-CORP" status="failure" reason="peer SA proposal not match local policy"
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `date` | `2026-09-03` | Data local **do equipamento**, não UTC. Correlacionar com um log em UTC sem acertar o fuso desalinha a timeline |
| `time` | `09:12:44` | Hora local do equipamento |
| `devname` | `"fgt-edge-01"` | Nome do equipamento que gerou o log |
| `devid` | `"FG100E0000000001"` | Número de série do equipamento — numa frota, é ele que identifica qual falou |
| `logid` | `"0101039426"` | Identificador do **tipo** de log. **É por ele que se filtra no SIEM**: o texto muda entre versões do FortiOS, o número não |
| `type` | `"event"` | Categoria do log: `traffic` é sessão, `event` é evento do próprio aparelho, `utm` é inspeção de conteúdo |
| `subtype` | `"vpn"` | Subcategoria: `forward` é tráfego que atravessa, `local` é destinado ao próprio firewall, `vpn` é túnel, `webfilter` e `ips` são inspeção |
| `level` | `"error"` | Severidade atribuída pelo FortiOS (`notice`, `warning`, `alert`, `critical`). **Quem a escolhe é o fabricante**, não o seu SOC |
| `vd` | `"root"` | *Virtual domain* (VDOM): qual firewall virtual atendeu |
| `action` | `"negotiate"` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |
| `remip` | `203.0.113.45` | IP público **remoto** do outro lado do túnel — de onde o usuário ou o peer veio |
| `locip` | `198.51.100.7` | IP local do concentrador VPN |
| `remport` | `500` | Porta remota do túnel |
| `locport` | `500` | Porta local do túnel |
| `outintf` | `"wan1"` | Interface de saída do túnel |
| `cookies` | `"N/A"` | Cookies do IKE, que identificam a negociação em curso |
| `user` | `"jsilva"` | Conta autenticada — o que transforma "um IP" em "uma pessoa" |
| `group` | `"N/A"` | Grupo a que a conta pertence |
| `xauthuser` | `"N/A"` | Conta usada na autenticação estendida do IPsec |
| `xauthgroup` | `"N/A"` | Grupo da autenticação estendida |
| `assignip` | `N/A` | **O IP interno que a empresa emprestou** à máquina remota. Depois de o túnel subir, é este endereço que aparece no tráfego interno, e não o `remip` |
| `vpntunnel` | `"SSLVPN-CORP"` | Nome do túnel na configuração — o que traduz um IP em "a filial tal" |
| `status` | `"failure"` | Estado da negociação |
| `reason` | `"peer SA proposal not match local policy"` | **O campo que resolve o caso**: por que falhou ou por que terminou |

</details>

Campos: `remip` é o IP público do usuário; `remport=500` mostra que é IKE; `status=failure` e `reason` explicam a negociação quebrada. Se o log **não existe**, o pacote nem chegou — aí o bloqueio é na rede do hotel, não no firewall da empresa.

Conta bloqueada aparece no Windows Security como 4625 com substatus específico:

```
EventID=4625  Account Name: jsilva  Account Domain: CORP
Failure Reason: Account locked out
Status: 0xC0000234   Sub Status: 0xC0000234
Logon Type: 3        Source Network Address: 203.0.113.45
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `EventID` | `4625` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não. `4625` = **falha** de logon |
| `Account Name` | `jsilva` | A conta envolvida. Terminada em `$` é **conta de computador**, não de pessoa |
| `Account Domain` | `CORP` | Domínio da conta |
| `Failure Reason` | `Account locked out` | Motivo da falha em texto — legível, mas **use o `Sub Status` na regra** |
| `Status` | `0xC0000234` | Código geral do resultado. `0xC0000234` = conta **bloqueada** |
| `Sub Status` | `0xC0000234` | **O código que diz a causa real** — o `Status` costuma ser genérico. `0xC0000234` = conta **bloqueada** |
| `Logon Type` | `3` | **Como a sessão foi iniciada.** `3` = **rede** — acesso a compartilhamento, RPC, WinRM. É o tipo que domina em movimento lateral |
| `Source Network Address` | `203.0.113.45` | **IP de origem.** Vazio ou `-` significa que a sessão foi local, e `::1`/`127.0.0.1` que veio da própria máquina |

</details>

Tabela de tradução rápida dos códigos de falha (4625/4776):

| Código | Significado | Ação do N1 |
|---|---|---|
| 0xC000006A | Senha errada | Verificar tentativas repetidas (força bruta) |
| 0xC0000234 | Conta bloqueada | Confirmar origem do bloqueio antes de desbloquear |
| 0xC0000071 | Senha expirada | Orientar troca; não é incidente |
| 0xC0000072 | Conta desabilitada | Uso de conta de desligado = investigar |
| 0xC0000064 | Usuário não existe | Enumeração de contas se em volume |

**Resolver:** desbloquear/renovar senha pelo processo padrão, renovar o certificado do gateway, ou instruir o usuário a usar TCP 443 (a maioria dos clientes faz fallback) quando UDP estiver bloqueado.

**Erro comum de analista júnior:** desbloquear a conta e fechar o chamado. O bloqueio pode ser o **sintoma de um ataque de password spraying** — sempre olhe quantos 4625 vieram, de quantos IPs e contra quantas contas.

### Sintoma 2 — "Conecta e cai a cada poucos minutos"

**Causas prováveis:** Wi-Fi instável; rekey do IKE falhando; NAT timeout do roteador doméstico derrubando a sessão UDP; sessão com limite de tempo na política; segundo login do mesmo usuário derrubando o primeiro.

**Como confirmar:** `ping -t 10.10.0.1` durante a queda, e no ASA:

```
%ASA-4-113019: Group = SSLVPN-CORP, Username = jsilva, IP = 203.0.113.45, Session disconnected. Session Type: SSL, Duration: 0h:03m:12s, Bytes xmt: 184320, Bytes rcv: 92160, Reason: Idle Timeout
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `%ASA` | `%ASA` | Etiqueta do produto: identifica a linha como vinda de um firewall ASA |
| severidade | `4` | Escala syslog do Cisco, de 0 (emergência) a 7 (depuração): `4` é **warning**. **Severidade baixa não quer dizer evento sem importância** — quem a escolhe é o fabricante, não o seu SOC |
| *message ID* | `113019` | Sessão de VPN de acesso remoto encerrada. **É por este número que se escreve a regra no SIEM**: o texto da mensagem muda entre versões do software, o ID não |
| `Group` | `SSLVPN-CORP` | O grupo de políticas aplicado à sessão |
| `Username` | `jsilva` | **A conta, e não só o IP.** É o que permite investigar por pessoa |
| `IP` | `203.0.113.45` | O endereço público de onde o usuário se ligou |
| `Session Type` | `SSL` | SSL VPN (portal ou cliente), em contraste com IPsec |
| `Duration` | `0h:03m:12s` | Quanto tempo a sessão durou |
| `Bytes xmt` / `rcv` | `184320` / `92160` | **Transmitidos e recebidos do ponto de vista do firewall**: `xmt` é o que o ASA enviou ao usuário. Confundir o sentido inverte a leitura de exfiltração |
| `Reason` | `Idle Timeout` | **O campo que resolve o caso.** `Idle Timeout` é inatividade; `User Requested` é o usuário a desligar; `Lost Service` é queda de rede; `Administrator Reset` é alguém a derrubar a sessão |

</details>


**Resolver:** ajustar keepalive/DPD (Dead Peer Detection), trocar UDP por TCP em redes com NAT agressivo, revisar timeout de sessão.

### Sintoma 3 — "Conecta, mas não abre o sistema interno"

**Causas prováveis:** rota não empurrada; conflito de sub-rede; política de firewall bloqueando; split tunnel mandando o tráfego pela internet.

**Como confirmar:**

```powershell
Get-NetRoute -AddressFamily IPv4 | Sort-Object RouteMetric | Format-Table -Auto
Test-NetConnection 10.20.5.40 -Port 445
```

Se a rota `10.20.0.0/16` não aparece apontando para a interface do adaptador virtual, ela não foi empurrada.

**O conflito de sub-rede** é o clássico: o roteador de casa usa `192.168.1.0/24` e a rede da empresa também usa `192.168.1.0/24`. O computador tem duas rotas idênticas e escolhe a local, então `192.168.1.50` da empresa nunca é alcançado.

```
Destino            Máscara           Gateway        Interface     Métrica
192.168.1.0        255.255.255.0     On-link        192.168.1.23      281   <- Wi-Fi de casa
192.168.1.0        255.255.255.0     On-link        10.99.0.14        26    <- VPN
```

**Resolver:** mudar a faixa do roteador doméstico para `192.168.77.0/24`. Não existe solução mágica no cliente.

**Erro comum de júnior:** achar que "ping falhou" significa firewall. Muitos hosts internos simplesmente bloqueiam ICMP echo (tipo 8); teste sempre a porta do serviço com `Test-NetConnection -Port`.

### Sintoma 4 — "O IP funciona, o nome não" (split-DNS)

O usuário abre `http://10.20.5.40` e funciona, mas `http://intranet.corp.local` dá erro. É DNS.

```powershell
ipconfig /all | Select-String "Sufixo|Servidores DNS"
Resolve-DnsName intranet.corp.local -Server 10.10.0.53
```

Se resolve apontando direto para o DNS interno mas falha sem `-Server`, o cliente está usando o DNS do provedor. Log do Zeek (`dns.log`), com campos separados por tabulação:

```
1756890123.442	CxT4uz1	10.99.0.14	54233	10.10.0.53	53	udp	31337	-	intranet.corp.local	1	C_INTERNET	1	A	3	NXDOMAIN	F	F	T	F	0	-	-	F
```

`rcode_name=NXDOMAIN` significa "nome não existe". Se o servidor consultado for público (por exemplo `203.0.113.53`), o vazamento de consulta de nome interno para fora é, além de falha, um problema de privacidade.

### Sintoma 5 — "Alguns sites travam no meio do carregamento" (MTU/MSS)

**Analogia:** o túnel é um cano mais estreito que a rua. O pacote de 1500 bytes não cabe depois de ganhar os cabeçalhos da VPN, e se o roteador não avisa ("ICMP tipo 3, código 4 — fragmentação necessária"), o pacote some. Resultado: conexão abre (pacotes pequenos passam), mas trava ao transferir dados grandes. Isso se chama **PMTUD black hole**.

```powershell
# Descobre o maior payload que passa sem fragmentar
ping 10.20.5.40 -f -l 1400
ping 10.20.5.40 -f -l 1372
netsh interface ipv4 show subinterfaces
```

Se 1372 passa e 1400 falha, a MTU útil é 1400 (1372 + 28 de cabeçalho IP/ICMP). **Resolver:** ajustar a MTU do adaptador virtual para 1400 e habilitar MSS clamping no gateway. No Wireshark, o filtro `icmp.type == 3 && icmp.code == 4` mostra os avisos; a ausência deles com retransmissões (`tcp.analysis.retransmission`) confirma o black hole.

### Sintoma 6 — Agente de segurança conflitando com o adaptador virtual

Clientes de proxy/SASE, antivírus com inspeção de rede e a VPN disputam o mesmo ponto da pilha. O sintoma típico é: `ping` funciona (ICMP), mas TCP não abre nada.

```powershell
Get-NetAdapter | Format-Table Name, InterfaceDescription, Status, LinkSpeed
Get-Service | Where-Object { $_.DisplayName -match 'VPN|Netskope|Zscaler' }
```

**Resolver:** ordem de bind das interfaces, exceção do adaptador virtual no agente, ou atualização de versão. Nunca desinstale o agente de segurança para "testar" sem aprovação.

## A ótica do SOC: a VPN como fonte de alerta

Para o SOC, a VPN é a porta da frente. Todo login remoto legítimo passa por ali — e todo atacante com credencial roubada também. O N1 raramente decide sozinho se é incidente; ele **enriquece** o alerta com contexto e classifica.

| Alerta | O que dispara | O que o N1 verifica |
|---|---|---|
| Viagem impossível | Dois logins distantes em pouco tempo | VPN corporativa no 2º IP? Fuso? MFA aprovado nos dois? |
| Login fora do horário | Fora da janela do perfil | Plantão, on-call, chamado aberto |
| País inesperado | Geo fora dos países aprovados | Viagem registrada no RH, VPN pessoal |
| Muitas falhas + 1 sucesso | Sequência 4625 seguida de 4624 | Nº de contas alvo, senha errada vs bloqueio |
| Conta de serviço na VPN | `svc_*` com logon interativo/remoto | Contas de serviço não usam VPN — quase sempre suspeito |
| Sessão muito longa | Ex.: > 18 horas contínuas | Tráfego constante? Automação? |
| Mesmo usuário, dois IPs | Sessões simultâneas | Celular + notebook vs credencial compartilhada |
| Origem em datacenter/Tor/proxy | ASN de hospedagem, nó de saída Tor | Usuário não usa VPS; forte indício de abuso |

Exemplo de sucesso após rajada de falhas (Windows Security, evento 4624 do tipo 3 = rede):

```
EventID=4624  Logon Type: 3
Account Name: maria.costa   Account Domain: CORP
Source Network Address: 198.51.100.212   Source Port: 51544
Logon Process: Kerberos   Authentication Package: Kerberos
Impersonation Level: Impersonation
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `EventID` | `4624` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não. `4624` = logon **bem-sucedido** |
| `Logon Type` | `3` | **Como a sessão foi iniciada.** `3` = **rede** — acesso a compartilhamento, RPC, WinRM. É o tipo que domina em movimento lateral |
| `Account Name` | `maria.costa` | A conta envolvida. Terminada em `$` é **conta de computador**, não de pessoa |
| `Account Domain` | `CORP` | Domínio da conta |
| `Source Network Address` | `198.51.100.212` | **IP de origem.** Vazio ou `-` significa que a sessão foi local, e `::1`/`127.0.0.1` que veio da própria máquina |
| `Source Port` | `51544` | Porta de origem, efêmera |
| `Logon Process` | `Kerberos` | Componente que processou o logon (`Kerberos`, `NtLmSsp`, `User32`, `Advapi`) |
| `Authentication Package` | `Kerberos` | Pacote que autenticou: `Kerberos`, `NTLM` ou `Negotiate` |
| `Impersonation Level` | `Impersonation` | Até onde o processo pode agir em nome do utilizador |

</details>

E o Netskope registrando origem em nó Tor:

```
timestamp=2026-09-03T02:14:07Z user=maria.costa@empresa-exemplo.com.br srcip=198.51.100.212 src_country=RO src_asn="AS64500 EXAMPLE-HOSTING" activity=Login category="Cloud Storage" app="Corp Drive" alert=yes alert_name="anomalous_location" access_method=Client action=allow
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `timestamp` | `2026-09-03T02:14:07Z` | Instante do evento conforme a plataforma que o gerou |
| `user` | `maria.costa@empresa-exemplo.com.br` | Conta autenticada — o que transforma "um IP" em "uma pessoa" |
| `srcip` | `198.51.100.212` | IP de origem |
| `src_country` | `RO` | País de origem por geolocalização |
| `src_asn` | `"AS64500 EXAMPLE-HOSTING"` | **ASN da origem**: o sistema autônomo, ou seja de quem é aquele bloco de IP. Mais estável que o IP para reconhecer infraestrutura |
| `activity` | `Login` | Ação do usuário classificada pela plataforma (`Upload`, `Login`, `Share`) |
| `category` | `"Cloud Storage"` | Categoria atribuída ao destino |
| `app` | `"Corp Drive"` | Aplicação identificada pelo controle de aplicação, por inspeção do conteúdo |
| `alert` | `yes` | Se o evento gerou alerta |
| `alert_name` | `"anomalous_location"` | Nome da política que gerou o alerta |
| `access_method` | `Client` | Como o tráfego foi capturado (`Client`, `Reverse Proxy`, `API`) |
| `action` | `allow` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |

</details>

`src_asn` de hospedagem + `src_country` fora do padrão + horário de madrugada formam três indicadores fracos que, somados, viram um alerta forte. Isso mapeia para MITRE ATT&CK **T1078** (Valid Accounts) e, quando há acesso pelo serviço remoto externo, **T1133** (External Remote Services).

### Consultas prontas

```spl
index=vpn sourcetype=cisco:asa "%ASA-6-113004" OR "%ASA-6-302013"
| rex field=_raw "Username = (?<user>[^,]+)"
| iplocation src_ip
| stats dc(Country) as paises, values(Country) as lista, dc(src_ip) as ips by user
| where paises > 1
```
Linha 1 filtra eventos de autenticação e conexão do ASA. Linha 2 extrai o usuário. Linha 3 geolocaliza. Linha 4 conta países e IPs distintos por usuário. Linha 5 mantém só quem apareceu em mais de um país.

```kql
SigninLogs
| where TimeGenerated > ago(24h)                       // janela de 24 horas
| where ResultType == 0                                // 0 = login bem-sucedido
| summarize Paises = dcount(Location),
            IPs = dcount(IPAddress),
            Primeiro = min(TimeGenerated),
            Ultimo = max(TimeGenerated)
        by UserPrincipalName                           // agrupa por usuário
| where Paises > 1 and datetime_diff('minute', Ultimo, Primeiro) < 120
```

**Erro comum de júnior:** fechar viagem impossível como falso positivo só porque "o MFA foi aprovado". MFA aprovado pode ser MFA fatigue — o usuário cansou de receber notificação e clicou em aprovar. Sempre confirme com a pessoa por um canal alternativo.

### Exercícios — Troubleshooting de VPN e a ótica do SOC

1. Um usuário conecta a VPN e o `route print` mostra duas rotas `192.168.1.0/255.255.255.0`, uma com métrica 281 na interface `192.168.1.23` e outra com métrica 26 na interface `10.99.0.14`. Ele não acessa o servidor `192.168.1.50` da empresa. Qual o problema e a única solução definitiva?
2. `ping 10.20.5.40 -f -l 1400` falha e `-l 1372` funciona. Qual a MTU útil do túnel e que sintoma o usuário relata?
3. Este alerta é verdadeiro ou falso positivo? `user=svc_backup` fez login via cliente VPN às 03:12, `src_country=BR`, `src_asn="AS64500 EXAMPLE-HOSTING"`, sessão de 22 minutos, seguida de acessos SMB a 14 servidores.
4. `Resolve-DnsName intranet.corp.local` falha, mas `Resolve-DnsName intranet.corp.local -Server 10.10.0.53` responde `10.20.5.40`. Qual o próximo passo?
5. 47 eventos 4625 com status 0xC000006A contra 47 contas diferentes vindos de `203.0.113.45` em 6 minutos, seguidos de um 4624 tipo 3 para `jsilva`. Qual a classificação e o próximo passo?

<details><summary>Ver gabarito</summary>

1. **Conflito de sub-rede.** A rede doméstica e a corporativa usam a mesma faixa `192.168.1.0/24`. Mesmo com métrica melhor na VPN, o comportamento fica ambíguo e o Windows tende a usar a rota on-link local para destinos da própria sub-rede. A única solução definitiva é **mudar a faixa do roteador doméstico** (por exemplo para `192.168.77.0/24`). Ajustar métrica ou desativar Wi-Fi são paliativos.

2. **MTU útil = 1400 bytes** (1372 de payload + 20 do cabeçalho IP + 8 do ICMP). O usuário relata que "alguns sites abrem e travam no meio", ou que arquivos grandes param em 90%: o handshake TCP passa (pacotes pequenos) e a transferência morre. Causa: PMTUD black hole, com o ICMP tipo 3 código 4 bloqueado no caminho. Correção: MTU 1400 no adaptador e MSS clamping no gateway.

3. **Verdadeiro positivo, prioridade alta.** Contas de serviço (`svc_`) não devem existir como usuário de VPN — elas rodam em servidores, não em estações. Somando: horário de madrugada, ASN de hospedagem (não é internet residencial) e enumeração de 14 servidores por SMB (porta 445), o padrão é credencial de serviço comprometida em movimentação lateral. Escalar imediatamente, mapeando T1078 (Valid Accounts). Não desabilite a conta sem aprovação, pois isso pode derrubar produção — mas peça contenção da sessão VPN.

4. **É split-DNS mal aplicado.** O cliente está usando o DNS do provedor em vez do DNS interno. Próximo passo: `ipconfig /all` para confirmar quais servidores DNS e qual sufixo (`corp.local`) foram entregues pelo túnel; se o DNS interno não aparece, o perfil VPN não está empurrando a configuração de DNS. Rodar `ipconfig /flushdns`, reconectar e, se persistir, escalar para a equipe de rede corrigir o perfil. Atenção adicional: consultas a `corp.local` saindo para DNS público são vazamento de informação interna.

5. **Password spraying, verdadeiro positivo crítico.** O padrão característico é **muitas contas, poucas tentativas por conta** (0xC000006A = senha incorreta), evitando bloqueio, seguido de **um sucesso**. O próximo passo é tratar `jsilva` como conta comprometida: verificar tudo que a sessão fez após o 4624 (acessos, 4768/4769 de Kerberos, 4688 de criação de processo), confirmar se houve MFA, isolar a sessão VPN e escalar para o N2. Técnica MITRE: T1110.003 (Password Spraying) seguida de T1078.

</details>

## Mini-laboratório — VPN: conflito de rota, MTU e leitura de log

**Objetivo:** reproduzir, num ambiente 100% gratuito, os três problemas mais comuns de VPN e observá-los no Wireshark.

**Pré-requisitos:** VirtualBox com uma VM Linux (Ubuntu Server ou Security Onion), Wireshark instalado no host, Docker opcional, acesso administrativo local. Nenhum equipamento pago é necessário.

**Passo 1 — Mapear o estado normal.** Na VM: `ip a`, `ip r`, `resolvectl status`. No Windows host: `ipconfig /all` e `route print`. Anote a interface padrão, o gateway e os servidores DNS. *Observar:* existe exatamente uma rota `0.0.0.0/0`.

**Passo 2 — Simular o conflito de sub-rede.** Adicione manualmente uma rota concorrente: `ip route add 192.168.1.0/24 dev lo metric 50` (na VM, sem afetar produção). Tente `ping 192.168.1.50`. *Observar:* o tráfego some no loopback. Remova com `ip route del 192.168.1.0/24 dev lo`. **Sucesso:** você viu que rota duplicada rouba o destino.

**Passo 3 — Reproduzir o problema de MTU.** Reduza a MTU: `ip link set dev enp0s3 mtu 1300`. Rode `ping -M do -s 1400 1.1.1.1` (deve falhar) e `ping -M do -s 1272 1.1.1.1` (deve funcionar). Baixe uma página grande com `curl -o /dev/null https://example.com`. *Observar:* no Wireshark, filtro `icmp.type == 3 && icmp.code == 4`. **Sucesso:** identificar o ponto exato onde o payload deixa de passar. Restaure com `mtu 1500`.

**Passo 4 — Ler DNS no Zeek.** Em Security Onion (ou com `zeek -r arquivo.pcap` sobre uma captura pública), abra `dns.log` e filtre por `rcode_name` diferente de NOERROR. *Observar:* correlacionar NXDOMAIN com o host que tentou resolver. **Sucesso:** explicar em uma frase por que o nome falhou.

**Passo 5 — Correlacionar autenticação.** Numa VM Windows de laboratório, erre a senha local 5 vezes e acerte na sexta. Abra o Event Viewer em Security e localize os 4625 e o 4624 final. *Observar:* os campos Logon Type, Status/Sub Status e Source Network Address. **Critério de sucesso do laboratório:** você consegue, olhando só os logs, contar a história "5 falhas por senha errada e 1 sucesso, do mesmo IP, em 90 segundos".

## O que um SOC Level 1 realmente precisa saber

- 🟢 VPN é um túnel criptografado que faz a máquina remota se comportar como se estivesse na rede interna; o cliente ganha um IP do pool corporativo.
- 🟢 Diferenciar split tunnel (só o tráfego corporativo entra no túnel) de full tunnel (tudo passa pela empresa) — muda completamente o que você vê nos logs.
- 🟢 Ler um log de autenticação: 4624 (sucesso), 4625 (falha) e os códigos 0xC000006A (senha errada), 0xC0000234 (bloqueada), 0xC0000071 (expirada).
- 🟢 A sequência "muitas falhas em muitas contas + um sucesso" é password spraying (T1110.003) até prova em contrário.
- 🟢 Conta de serviço (`svc_*`) conectando por VPN é anomalia por definição — escalar.
- 🟡 Viagem impossível exige contexto: fuso horário, VPN pessoal do usuário, celular corporativo e MFA aprovado não fecham o caso sozinhos.
- 🟡 Origem em ASN de datacenter, nó de saída Tor ou proxy residencial eleva a severidade mesmo com credencial válida (T1078, T1133).
- 🟡 Sintoma "conecta mas não acessa nada" é quase sempre rota, conflito de sub-rede ou DNS — não é criptografia.
- 🟡 Split-DNS quebrado faz nomes internos vazarem para DNS público: é falha operacional e de privacidade ao mesmo tempo.
- 🔴 MTU/MSS: travamento parcial em alguns destinos, com handshake OK, indica PMTUD black hole (ICMP tipo 3 código 4 bloqueado).
- 🔴 Relógio fora de sincronia acima de 5 minutos quebra Kerberos e códigos TOTP de MFA — verifique antes de abrir incidente de autenticação.
- 🔴 Correlacionar sessão VPN com o que aconteceu depois (4768/4769, 4688, tráfego SMB 445) é o que separa um chamado de suporte de um incidente real.

## Resumo em 10 linhas

1. VPN cria um túnel cifrado que estende a rede corporativa até o usuário remoto.
2. Existem VPNs site a site (escritório a escritório) e de acesso remoto (pessoa a empresa).
3. IPsec usa IKE em UDP 500/4500; SSL VPN usa TLS geralmente em TCP 443 e às vezes UDP 1194.
4. Split tunnel envia só o tráfego interno pelo túnel; full tunnel envia tudo e dá visibilidade total ao SOC.
5. Troubleshooting segue camadas: internet, alcance do gateway, autenticação, túnel, rota, DNS, aplicação.
6. Os problemas mais frequentes são rota não empurrada, conflito de sub-rede `192.168.1.0/24` e split-DNS quebrado.
7. Travamento só em alguns destinos, com conexão aberta, aponta para MTU/MSS e PMTUD black hole.
8. Certificado expirado, relógio dessincronizado, conta bloqueada e agente de segurança em conflito explicam a maioria das falhas de conexão.
9. Para o SOC, a VPN é a porta da frente: viagem impossível, país inesperado, conta de serviço, sessão longa e origem em datacenter/Tor são os alertas centrais.
10. O N1 enriquece com contexto (horário, geolocalização, ASN, MFA, histórico do usuário) e escala com evidência, nunca fecha alerta só porque "o login deu certo".



---
