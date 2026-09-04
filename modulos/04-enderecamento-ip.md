# Módulo 04 — Endereçamento IP para o SOC

## Por que este módulo importa para o SOC

Todo alerta que chega na sua fila tem, no mínimo, dois endereços IP: quem falou e com quem falou. Se você não souber ler esses dois números, você não consegue responder à pergunta mais básica de uma triagem: "isso é tráfego interno normal, ou é uma máquina da empresa conversando com a internet quando não deveria?". Um analista que confunde `10.10.5.20` com um endereço da internet escala um falso positivo. Um analista que não percebe que `169.254.x.x` significa "esta máquina não conseguiu pegar IP" perde uma pista de rede quebrada. Endereçamento IP não é decoreba: é a gramática de todo log de firewall, proxy, EDR e IDS que você vai ler pelo resto da carreira.

### Índice do módulo

- Binário, IPv4, classes, públicos vs privados, máscara e CIDR
- Rede, broadcast, hosts válidos e subnetting na prática
- IPv6, aplicação ao SOC e plano de endereçamento corporativo

## O que é um endereço IP e por que ele existe

**O que é.** Imagine o serviço de correios. Para uma carta chegar, ela precisa de um endereço: rua, número, cidade. Se duas casas na mesma rua tiverem o mesmo número, o carteiro se perde. O endereço IP (Internet Protocol, ou Protocolo de Internet) é exatamente isso para os dados: um número único dentro de uma rede, que diz onde entregar o pacote.

**Como funciona.** Cada dispositivo conectado — notebook, servidor, impressora, câmera, celular — recebe um endereço. Quando o notebook do usuário `jsilva` pede uma página web, o pacote sai carregando dois endereços: o de origem (o dele) e o de destino (o do servidor). O caminho de volta usa o endereço de origem. Sem isso, a resposta não sabe para onde voltar.

**Exemplo prático.** O notebook de `jsilva` tem `10.10.20.45`. O servidor de arquivos da `corp.local` tem `10.10.30.10`. Quando ele abre uma pasta compartilhada, o firewall registra a conversa entre esses dois números.

**Como aparece nos logs.** Firewall Cisco ASA, mensagem de sessão TCP criada:

```
%ASA-6-302013: Built outbound TCP connection 1284471 for OUTSIDE:203.0.113.45/443 (203.0.113.45/443) to INSIDE:10.10.20.45/51422 (198.51.100.7/51422)
```

Campos: `%ASA-6-302013` é a severidade 6 (informational) e o ID da mensagem "conexão TCP criada"; `outbound` é o sentido (de dentro para fora); `1284471` é o identificador da conexão; `OUTSIDE:203.0.113.45/443` é o destino (IP e porta 443, HTTPS); `INSIDE:10.10.20.45/51422` é a origem interna com porta alta aleatória; o `198.51.100.7` entre parênteses é o IP público depois da tradução NAT.

**O que o SOC N1 observa.** Normal: um host interno abrindo 443 para um destino externo. Suspeito: um host interno abrindo centenas de conexões por minuto para IPs externos diferentes, ou uma origem que deveria ser só de rede interna (um servidor de banco de dados) falando com a internet.

**Erro comum de analista júnior.** Achar que o IP de origem no log do firewall de borda é sempre o do usuário. Depois do NAT, todo mundo sai com o mesmo IP público. Para achar a máquina real, você precisa da linha de tradução ou do log do proxy, que costuma trazer o usuário.

## Binário sem trauma

**O que é.** Computadores só sabem dizer "tem corrente" ou "não tem corrente" — 1 ou 0. Um endereço IP, por baixo, é uma sequência de 32 desses zeros e uns. A notação `192.168.1.10` que você lê é só uma tradução amigável.

**Como funciona.** Cada octeto (grupo de 8 bits) tem posições com peso fixo. Guarde esta tabela; ela resolve 90% das contas:

| Posição | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
|---|---|---|---|---|---|---|---|---|
| Peso | 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |

Para converter **decimal → binário**, vá da esquerda para a direita perguntando "cabe?". Se cabe, escreve 1 e subtrai; se não cabe, escreve 0.

**Exemplo 1 — 192.** Cabe 128? Sim → 1, sobra 64. Cabe 64? Sim → 1, sobra 0. Todo o resto é 0. Resultado: `11000000`.

**Exemplo 2 — 168.** 128 cabe → 1, sobra 40. 64 não cabe → 0. 32 cabe → 1, sobra 8. 16 não → 0. 8 cabe → 1, sobra 0. Restante 0. Resultado: `10101000`.

**Exemplo 3 — 45.** 128 não → 0. 64 não → 0. 32 cabe → 1, sobra 13. 16 não → 0. 8 cabe → 1, sobra 5. 4 cabe → 1, sobra 1. 2 não → 0. 1 cabe → 1. Resultado: `00101101`.

**Exemplo 4 — binário → decimal, `11111100`.** Some os pesos das posições com 1: 128+64+32+16+8+4 = **252**. (Esse valor vai reaparecer como máscara `/30`.)

**Erro comum de analista júnior.** Confundir a ordem dos pesos e achar que o bit da direita vale 128. O bit mais à esquerda é o mais "caro"; o da direita vale 1.

## Formato IPv4 e octetos

Um endereço IPv4 tem 32 bits divididos em 4 octetos separados por ponto. Cada octeto vai de **0 a 255** (mínimo `00000000`, máximo `11111111` = 255). Portanto `10.10.300.5` é inválido: não existe 300 em 8 bits. Como o total é 32 bits, existem cerca de 4,29 bilhões de endereços — muito menos do que o mundo precisou, e é daí que nascem NAT, CGNAT e IPv6.

## Classes A, B, C, D e E — história e por que morreram

**O que foi.** No começo, o primeiro octeto definia automaticamente o tamanho da rede.

| Classe | 1º octeto | Máscara padrão | Uso |
|---|---|---|---|
| A | 1–126 | 255.0.0.0 (/8) | Redes gigantes |
| B | 128–191 | 255.255.0.0 (/16) | Redes médias |
| C | 192–223 | 255.255.255.0 (/24) | Redes pequenas |
| D | 224–239 | — | Multicast |
| E | 240–255 | — | Experimental/reservado |

**Por que morreram.** Uma empresa com 300 máquinas não cabia em uma classe C (254 hosts) e, ao pegar uma classe B, desperdiçava mais de 65 mil endereços. Em 1993 o CIDR (Classless Inter-Domain Routing, roteamento sem classes) acabou com isso: a máscara passou a ser explícita e de qualquer tamanho. Hoje "classe C" só sobrevive como gíria para `/24`.

**Erro comum de analista júnior.** Ver `172.20.5.10` e dizer "é classe B pública". As classes não dizem nada sobre ser público ou privado — quem diz isso são as faixas reservadas abaixo.

## Públicos, privados e as faixas especiais

**O que é.** Endereço público é roteável na internet e único no mundo. Endereço privado só vale dentro da sua rede — é o "ramal interno" da empresa.

| Faixa | Notação | Nome / RFC | O que significa no log |
|---|---|---|---|
| 10.0.0.0 – 10.255.255.255 | 10.0.0.0/8 | Privado (RFC 1918) | Rede interna |
| 172.16.0.0 – 172.31.255.255 | 172.16.0.0/12 | Privado (RFC 1918) | Rede interna |
| 192.168.0.0 – 192.168.255.255 | 192.168.0.0/16 | Privado (RFC 1918) | Rede interna, VPN, home office |
| 127.0.0.0 – 127.255.255.255 | 127.0.0.0/8 | Loopback | A máquina falando consigo mesma |
| 169.254.0.0 – 169.254.255.255 | 169.254.0.0/16 | APIPA / link-local | DHCP falhou |
| 100.64.0.0 – 100.127.255.255 | 100.64.0.0/10 | CGNAT (RFC 6598) | NAT do provedor |
| 224.0.0.0 – 239.255.255.255 | 224.0.0.0/4 | Multicast | Um para muitos |
| 255.255.255.255 | — | Broadcast limitado | Só na rede local |
| 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 | — | Documentação (RFC 5737) | Usado em exemplos e treinamento |

**Atenção:** `172.32.x.x` **não** é privado; a faixa privada para no `172.31`. É a pegadinha mais frequente em prova e em triagem.

**Exemplo prático.** A estação de `maria.costa` perdeu o servidor DHCP e assumiu `169.254.88.12`. Ela não navega, não autentica no domínio e some do inventário.

**Como aparece nos logs.** FortiGate, formato chave=valor:

```
date=2026-09-03 time=09:12:44 devname="FGT-BORDA-01" devid="FG100F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=10.10.20.45 srcport=51422 srcintf="port3" dstip=203.0.113.45 dstport=443 dstintf="port1" action="accept" policyid=17 service="HTTPS" trandisp="snat" transip=198.51.100.7 transport=51422 duration=32 sentbyte=8421 rcvdbyte=15302
```

Campos: `srcip`/`srcport` origem, `dstip`/`dstport` destino, `action=accept` a política permitiu, `policyid=17` qual regra decidiu, `trandisp=snat` houve tradução de origem, `transip` o IP público resultante, `sentbyte`/`rcvdbyte` volume trafegado.

**O que o SOC N1 observa.** Normal: `srcip` privado, `dstip` público, porta 443. Suspeito: `srcip` público chegando com destino privado sem passar por NAT/VPN (possível spoofing ou regra mal escrita); tráfego saindo com `dstip` em 10/8 na interface de internet; host com IP APIPA gerando alertas de autenticação falhando.

**Erro comum de analista júnior.** Tratar tráfego para `127.0.0.1` como "conexão externa suspeita". Loopback nunca sai da máquina. Já um processo estranho escutando em loopback (visível no Sysmon Event ID 3) merece olhar — mas o motivo é o processo, não o IP.

Sysmon, conexão de rede (Event ID 3):

```
EventID: 3
UtcTime: 2026-09-03 12:04:51.221
Image: C:\Users\jsilva\AppData\Local\Temp\updater.exe
User: CORP\jsilva
Protocol: tcp
SourceIp: 10.10.20.45
SourcePort: 49871
DestinationIp: 203.0.113.200
DestinationPort: 8443
DestinationHostname: cdn.empresa-exemplo.com.br
```

Campos: `Image` é o executável que abriu a conexão; `User` a conta; `DestinationPort: 8443` é HTTPS alternativo. Binário em `AppData\Local\Temp` falando com a internet é sinal clássico de execução suspeita (MITRE ATT&CK T1071 — Application Layer Protocol).

## Máscara de rede e notação CIDR

**O que é.** A máscara responde: "deste endereço, quanto é o nome do bairro e quanto é o número da casa?". A parte de rede é o bairro; a parte de host é a casa.

**Como funciona.** A máscara também tem 32 bits: todos os 1 à esquerda marcam a rede, todos os 0 à direita marcam os hosts. `/24` significa 24 bits de rede — ou seja, `255.255.255.0`. A wildcard é a máscara invertida (255 menos cada octeto) e aparece em ACLs Cisco e em regras de correlação.

| CIDR | Máscara decimal | Hosts utilizáveis | Wildcard |
|---|---|---|---|
| /8 | 255.0.0.0 | 16.777.214 | 0.255.255.255 |
| /9 | 255.128.0.0 | 8.388.606 | 0.127.255.255 |
| /10 | 255.192.0.0 | 4.194.302 | 0.63.255.255 |
| /11 | 255.224.0.0 | 2.097.150 | 0.31.255.255 |
| /12 | 255.240.0.0 | 1.048.574 | 0.15.255.255 |
| /13 | 255.248.0.0 | 524.286 | 0.7.255.255 |
| /14 | 255.252.0.0 | 262.142 | 0.3.255.255 |
| /15 | 255.254.0.0 | 131.070 | 0.1.255.255 |
| /16 | 255.255.0.0 | 65.534 | 0.0.255.255 |
| /17 | 255.255.128.0 | 32.766 | 0.0.127.255 |
| /18 | 255.255.192.0 | 16.382 | 0.0.63.255 |
| /19 | 255.255.224.0 | 8.190 | 0.0.31.255 |
| /20 | 255.255.240.0 | 4.094 | 0.0.15.255 |
| /21 | 255.255.248.0 | 2.046 | 0.0.7.255 |
| /22 | 255.255.252.0 | 1.022 | 0.0.3.255 |
| /23 | 255.255.254.0 | 510 | 0.0.1.255 |
| /24 | 255.255.255.0 | 254 | 0.0.0.255 |
| /25 | 255.255.255.128 | 126 | 0.0.0.127 |
| /26 | 255.255.255.192 | 62 | 0.0.0.63 |
| /27 | 255.255.255.224 | 30 | 0.0.0.31 |
| /28 | 255.255.255.240 | 14 | 0.0.0.15 |
| /29 | 255.255.255.248 | 6 | 0.0.0.7 |
| /30 | 255.255.255.252 | 2 | 0.0.0.3 |
| /31 | 255.255.255.254 | 2 (enlace ponto a ponto, RFC 3021) | 0.0.0.1 |
| /32 | 255.255.255.255 | 1 (host único) | 0.0.0.0 |

A conta geral: hosts utilizáveis = 2^(32 − prefixo) − 2, porque um endereço vira o da rede e outro o de broadcast. O `/31` é a exceção prevista na RFC 3021 para links ponto a ponto, e o `/32` identifica um host isolado.

**Exemplo prático.** A rede de estações é `10.10.20.0/24`: máscara `255.255.255.0`, hosts de `10.10.20.1` a `10.10.20.254`. O link entre dois roteadores é `10.255.0.0/30`: só dois endereços úteis, `.1` e `.2`.

**Como aparece nos logs.** Palo Alto, log TRAFFIC em CSV (campos abreviados):

```
1,2026/09/03 09:31:07,001801010001,TRAFFIC,end,2561,2026/09/03 09:31:07,10.10.20.45,203.0.113.45,198.51.100.7,203.0.113.45,Regra-Saida-Corp,corp\jsilva,,ssl,vsys1,Trust,Untrust,ae1.20,ae1.10,LOG-Default,2026/09/03 09:31:07,74213,1,51422,443,42311,443,0x400053,tcp,allow,18422,7311,11111,42
```

Campos na ordem: tipo `TRAFFIC`, subtipo `end` (sessão encerrada), IP de origem, IP de destino, origem após NAT, destino após NAT, nome da regra, usuário `corp\jsilva`, aplicação `ssl`, zonas `Trust`/`Untrust`, portas de origem e destino, protocolo `tcp` e ação `allow`.

**Consultas úteis.** SPL (Splunk), para achar tráfego privado saindo pela interface de internet:

```spl
index=firewall sourcetype=pan:traffic
| where cidrmatch("10.0.0.0/8", dest_ip) OR cidrmatch("172.16.0.0/12", dest_ip) OR cidrmatch("192.168.0.0/16", dest_ip)
| search dest_zone="Untrust"
| stats count values(dest_ip) as destinos by src_ip
| sort - count
```

Linha 1 seleciona os logs de tráfego do Palo Alto. Linha 2 testa se o destino cai em faixa privada. Linha 3 restringe à zona de internet. Linha 4 agrupa por origem. Linha 5 ordena pelos mais barulhentos.

KQL (Microsoft Sentinel), para listar hosts que caíram em APIPA:

```kql
DeviceNetworkInfo
// tabela do Defender for Endpoint com a configuração de rede de cada máquina
| mv-expand IPAddresses
// cada máquina pode ter vários IPs; expande em uma linha por IP
| extend ip = tostring(IPAddresses.IPAddress)
// extrai o endereço como texto
| where ipv4_is_in_range(ip, "169.254.0.0/16")
// filtra somente link-local (DHCP falhou)
| summarize ultimos = max(TimeGenerated) by DeviceName, ip
// mostra a última ocorrência por máquina
```

**O que o SOC N1 observa.** Normal: cada VLAN com o prefixo documentado no plano de endereçamento. Suspeito: host de servidores aparecendo com IP da faixa de convidados, ou um `/32` externo conversando com dezenas de hosts internos sequenciais (varredura).

**Erro comum de analista júnior.** Somar mal a máscara e concluir que `10.10.20.130` e `10.10.20.10` estão na mesma rede quando a máscara é `/25`. Não estão: `/25` corta o `/24` ao meio em `.0–.127` e `.128–.255`.

### Exercícios — Binário, IPv4, classes, públicos vs privados, máscara e CIDR

1. Converta para binário: `172.16.44.7`. Depois converta `11000000.10101000.00001010.00000001` para decimal.
2. Classifique cada endereço como privado, público, loopback, APIPA, CGNAT ou documentação: `172.32.10.5`, `100.90.4.7`, `169.254.10.2`, `192.0.2.55`, `10.200.3.9`.
3. Quantos hosts utilizáveis existem em um `/26`? E qual é a máscara decimal e a wildcard correspondentes?
4. Leia o log e diga se o alerta "conexão externa não autorizada" é verdadeiro ou falso positivo, e qual o próximo passo:

```
date=2026-09-03 time=14:07:19 devname="FGT-BORDA-01" type="traffic" subtype="forward" level="warning" srcip=10.10.30.10 srcport=44120 dstip=10.10.20.45 dstport=445 action="deny" policyid=0 service="SMB" msg="no matching policy"
```

5. Um servidor com IP `10.10.20.130/25` não consegue falar com `10.10.20.10`. A rede física está boa e o cabo está conectado. Qual é a causa mais provável e como você confirma?

<details><summary>Ver gabarito</summary>

**1.** `172` = 128+32+8+4 → `10101100`. `16` = 16 → `00010000`. `44` = 32+8+4 → `00101100`. `7` = 4+2+1 → `00000111`. Resultado: `10101100.00010000.00101100.00000111`. No sentido inverso: `11000000`=192, `10101000`=168, `00001010`=10, `00000001`=1 → `192.168.10.1`. A dica é sempre trabalhar octeto por octeto, nunca os 32 bits de uma vez.

**2.** `172.32.10.5` é **público** — a faixa privada da RFC 1918 termina em `172.31.255.255`, e essa é a pegadinha clássica. `100.90.4.7` é **CGNAT** (RFC 6598, `100.64.0.0/10`): tipicamente um cliente atrás do NAT do provedor, não um IP de datacenter. `169.254.10.2` é **APIPA**: DHCP falhou. `192.0.2.55` é **documentação** (RFC 5737) — se aparecer em tráfego real de produção, quase sempre é laboratório, simulação ou log sintético. `10.200.3.9` é **privado**.

**3.** `/26` deixa 6 bits para host: 2^6 − 2 = **62 hosts utilizáveis**. Máscara `255.255.255.192`, wildcard `0.0.0.63`. Confirme na tabela CIDR do módulo.

**4.** É **falso positivo** para "conexão externa": ambos os endereços são RFC 1918, ou seja, tráfego totalmente interno (leste-oeste). Mas não descarte o evento. Um servidor (`10.10.30.10`) tentando SMB na porta 445 contra uma estação de usuário (`10.10.20.45`) é o sentido invertido do normal — servidores não costumam iniciar SMB para desktops, e esse é um padrão associado a movimentação lateral (MITRE ATT&CK T1021.002 — SMB/Windows Admin Shares). `policyid=0` com `msg="no matching policy"` mostra que nenhuma regra permitia isso, então o firewall barrou. Próximo passo: verificar no servidor qual processo iniciou a conexão (Sysmon Event ID 3 ou 1), checar logons recentes nele (Windows Security 4624 tipo 3, e 4625 para falhas) e confirmar se houve varredura contra outros hosts da `10.10.20.0/24`.

**5.** Com `/25`, o `/24` é cortado em duas redes: `10.10.20.0/25` (hosts `.1` a `.126`) e `10.10.20.128/25` (hosts `.129` a `.254`). O servidor `.130` está na segunda; o `.10` está na primeira. Eles só se falam através de um roteador ou gateway, e o problema provável é gateway ausente, errado, ou uma ACL entre as duas metades. Confirme com `ipconfig /all` (ou `ip addr` no Linux) para ler máscara e gateway, teste `ping` no próprio gateway, e depois procure no firewall a política que trata `10.10.20.128/25` → `10.10.20.0/25`.

</details>


## Rede, broadcast, hosts válidos e gateway padrão

Imagine um prédio residencial. O prédio inteiro tem um nome ("Edifício Aurora") — esse é o **endereço de rede**. Existe um interfone que toca em todos os apartamentos ao mesmo tempo — esse é o **endereço de broadcast**. Os apartamentos onde as pessoas realmente moram são os **hosts válidos**. E a portaria, que é por onde tudo entra e sai do prédio, é o **gateway padrão**.

### O que é cada endereço

| Endereço | O que é | Pode ser dado a um computador? |
|---|---|---|
| Endereço de rede | Primeiro endereço do bloco; identifica a rede toda | Não |
| Primeiro host válido | Endereço de rede + 1 | Sim |
| Último host válido | Broadcast − 1 | Sim |
| Broadcast | Último endereço do bloco; fala com todos de uma vez | Não |
| Gateway padrão | Um host válido, normalmente o primeiro ou o último | Sim (é o roteador/firewall) |

O gateway padrão é o endereço do roteador ou firewall que a máquina usa para falar com quem está **fora** da própria rede. Sem gateway, o computador conversa apenas com vizinhos do mesmo bloco.

### Como funciona: o método binário

A máscara de sub-rede (já vista no trecho anterior sobre máscara e CIDR) separa o endereço em duas partes: **parte de rede** (bits 1 da máscara) e **parte de host** (bits 0).

1. Escreva o IP e a máscara em binário.
2. **Endereço de rede** = IP `AND` máscara (todos os bits de host viram 0).
3. **Broadcast** = endereço de rede com todos os bits de host em 1.
4. **Primeiro host** = rede + 1. **Último host** = broadcast − 1.
5. **Quantidade de hosts válidos** = 2^(bits de host) − 2.

### O atalho do bloco (256 menos o octeto)

Método rápido, usado no dia a dia do SOC (Security Operations Center, o centro de operações de segurança):

1. Olhe o **octeto interessante** — o último octeto da máscara que não é 0 nem 255.
2. **Tamanho do bloco = 256 − esse octeto.**
3. Some o bloco a partir de 0 até passar do octeto do IP. O múltiplo imediatamente **abaixo ou igual** é a rede.
4. **Broadcast** = próxima rede − 1.

| CIDR | Máscara | Octeto interessante | Bloco | Hosts válidos |
|---|---|---|---|---|
| /22 | 255.255.252.0 | 252 (3º) | 4 | 1022 |
| /24 | 255.255.255.0 | 255 (3º) | 1 | 254 |
| /26 | 255.255.255.192 | 192 (4º) | 64 | 62 |
| /28 | 255.255.255.240 | 240 (4º) | 16 | 14 |
| /30 | 255.255.255.252 | 252 (4º) | 4 | 2 |

## Cinco exercícios resolvidos

### Exercício A — 10.10.20.57/24

**Binário:** máscara 255.255.255.0 → os 8 bits do 4º octeto são de host. IP `AND` máscara zera o último octeto.
**Atalho:** 256 − 255 = bloco 1 no 3º octeto → a rede fecha no octeto 20.

- Rede: **10.10.20.0** — Broadcast: **10.10.20.255**
- Hosts: **10.10.20.1 a 10.10.20.254** (254 hosts)
- Gateway típico: 10.10.20.1

### Exercício B — 10.10.30.100/26

**Binário:** 100 = `01100100`. Máscara .192 = `11000000`. `AND` → `01000000` = 64.
**Atalho:** 256 − 192 = **64**. Blocos: 0, 64, 128, 192. O 100 cai no bloco de 64.

- Rede: **10.10.30.64** — Broadcast: **10.10.30.127**
- Hosts: **10.10.30.65 a 10.10.30.126** (62 hosts)

### Exercício C — 172.16.8.200/28

**Binário:** 200 = `11001000`. Máscara .240 = `11110000`. `AND` → `11000000` = 192. Bits de host em 1 → `11001111` = 207.
**Atalho:** 256 − 240 = **16**. Blocos: 0, 16, 32 … 192, 208. O 200 cai em 192.

- Rede: **172.16.8.192** — Broadcast: **172.16.8.207**
- Hosts: **172.16.8.193 a 172.16.8.206** (14 hosts)

### Exercício D — 192.168.100.9/30

**Binário:** 9 = `00001001`. Máscara .252 = `11111100`. `AND` → `00001000` = 8. Broadcast → `00001011` = 11.
**Atalho:** 256 − 252 = **4**. Blocos: 0, 4, 8, 12. O 9 cai em 8.

- Rede: **192.168.100.8** — Broadcast: **192.168.100.11**
- Hosts: **192.168.100.9 e 192.168.100.10** (2 hosts — o clássico enlace ponto a ponto entre roteadores)

### Exercício E — 10.50.14.37/22

Aqui o octeto interessante é o **terceiro**.
**Binário:** 3º octeto 14 = `00001110`. Máscara 252 = `11111100`. `AND` → `00001100` = 12.
**Atalho:** 256 − 252 = **4** no 3º octeto. Blocos: 0, 4, 8, 12, 16. O 14 cai em 12.

- Rede: **10.50.12.0** — Broadcast: **10.50.15.255**
- Hosts: **10.50.12.1 a 10.50.15.254** (1022 hosts)

## Como isso aparece nos logs

Saber a fronteira do bloco é o que permite dizer "esse IP é da minha rede" ou "esse IP não deveria estar aqui".

```
# Cisco ASA - sessão TCP permitida
%ASA-6-302013: Built outbound TCP connection 84512 for outside:203.0.113.45/443
(203.0.113.45/443) to inside:10.10.30.66/51224 (198.51.100.7/51224)
```

Campos: `302013` = conexão TCP criada; `outside`/`inside` = zonas do firewall; `10.10.30.66` é o host interno; `198.51.100.7` é o IP público após NAT (Network Address Translation, tradução de endereços). O host .66 está dentro de 10.10.30.64/26 — coerente com a VLAN de trabalho.

```
# FortiGate - key=value
date=2026-09-03 time=09:14:02 devname="FGT-CORP-01" type="traffic" subtype="forward"
srcip=10.10.30.127 dstip=10.10.30.255 srcport=138 dstport=138 proto=17
service="NETBIOS" action="deny" policyid=12 sentbyte=486 msg="violation"
```

`srcip=10.10.30.127` é o **broadcast** do bloco /26 — endereço que nunca deveria ser origem de tráfego. `dstip=10.10.30.255` é broadcast do /24. Origem em broadcast é sinal de host mal configurado ou de tentativa de amplificação.

```json
{"timestamp":"2026-09-03T09:20:11.442Z","event_type":"alert","src_ip":"10.10.30.66",
"dest_ip":"10.10.30.127","proto":"UDP","alert":{"signature":"ET SCAN Behavioral Unusual
Port 445 Broadcast","category":"Attempted Information Leak","severity":2}}
```

Suricata EVE JSON: `src_ip` interno varrendo o próprio bloco. Varredura interna dentro do /26 sugere descoberta lateral (MITRE ATT&CK **T1046 — Network Service Discovery**).

**O que o SOC N1 observa**

| Normal | Suspeito |
|---|---|
| Host fala com o gateway (.1 ou .254) | Host fala com **todos** os IPs do bloco em segundos |
| Broadcast só como destino, em protocolos como ARP e DHCP | Broadcast como **origem** |
| IP de origem dentro do bloco esperado da VLAN | IP de origem fora do bloco da VLAN (possível spoofing ou máquina não autorizada) |

**Erro comum de analista júnior:** tratar 10.10.30.127 como "só mais um host" porque termina em número comum. Em /26 ele é broadcast. Sempre confira o CIDR antes de julgar o endereço.

## Subnetting: dividir uma rede em N sub-redes

**O que é:** pegar um bloco grande e cortá-lo em pedaços menores, um por setor. Como dividir um andar de escritório em salas com paredes.

**Como funciona:** emprestar bits da parte de host. Para N sub-redes, empreste `b` bits onde 2^b ≥ N.

**Exemplo resolvido:** a rede 192.168.50.0/24 precisa de 4 sub-redes (RH, Financeiro, TI, Visitantes).
2^2 = 4 → empreste 2 bits → /26 → bloco 64.

| Sub-rede | Rede | Hosts válidos | Broadcast |
|---|---|---|---|
| RH | 192.168.50.0/26 | .1 – .62 | .63 |
| Financeiro | 192.168.50.64/26 | .65 – .126 | .127 |
| TI | 192.168.50.128/26 | .129 – .190 | .191 |
| Visitantes | 192.168.50.192/26 | .193 – .254 | .255 |

### VLSM — máscara de tamanho variável

**O que é:** VLSM (Variable Length Subnet Mask) é cortar sub-redes de tamanhos **diferentes**, conforme a necessidade real. Sala grande para quem tem muita gente, sala pequena para quem tem pouca.

**Regra:** atenda sempre do maior para o menor.

**Exemplo resolvido:** de 10.20.0.0/24, atender 100 hosts, 50 hosts, 20 hosts e um enlace de 2 hosts.

| Necessidade | Máscara | Bloco | Rede | Broadcast |
|---|---|---|---|---|
| 100 hosts | /25 (126) | 128 | 10.20.0.0/25 | 10.20.0.127 |
| 50 hosts | /26 (62) | 64 | 10.20.0.128/26 | 10.20.0.191 |
| 20 hosts | /27 (30) | 32 | 10.20.0.192/27 | 10.20.0.223 |
| 2 hosts | /30 (2) | 4 | 10.20.0.224/30 | 10.20.0.227 |

Sobra livre: 10.20.0.228 a 10.20.0.255.

### Supernetting e agregação de rotas

**O que é:** o contrário do subnetting — juntar blocos vizinhos em um só, para escrever menos regras.

**Exemplo resolvido:** 10.10.16.0/24, 10.10.17.0/24, 10.10.18.0/24 e 10.10.19.0/24.
Terceiro octeto: 16, 17, 18, 19 → os 6 primeiros bits são iguais (`000100`) → agregado **10.10.16.0/22** (16 a 19).

No SOC isso vira uma linha só de whitelist em vez de quatro. Cuidado: 10.10.20.0/24 **não** entra nesse /22 — o bloco seguinte começa em 10.10.20.0.

```spl
| tvindex=firewall sourcetype=pan:traffic
| where cidrmatch("10.10.16.0/22", src_ip)      // só origens do bloco agregado das filiais
| where NOT cidrmatch("10.0.0.0/8", dest_ip)    // destino fora da rede interna
| stats dc(dest_ip) AS destinos by src_ip       // conta destinos distintos por origem
| where destinos > 200                          // volume típico de varredura
```

```kql
// Sentinel/Defender — host que sai do bloco esperado da sua VLAN
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where ipv4_is_in_range(SourceIP, "10.10.30.64/26")   // bloco da VLAN de TI
| where not(ipv4_is_in_range(DestinationIP, "10.10.30.64/26"))
| summarize Destinos = dcount(DestinationIP) by SourceIP
| where Destinos > 50
```

### Exercícios — Rede, broadcast, hosts válidos e subnetting na prática

1. Calcule rede, broadcast, primeiro e último host de **172.16.45.130/27**, pelos dois métodos.
2. O firewall registrou origem **10.10.30.191** na VLAN 10.10.30.128/26. Isso é possível? Explique.
3. A qual sub-rede pertence **10.50.13.200** se a rede for **/22**?
4. Divida **192.168.80.0/24** em 8 sub-redes iguais e liste a 5ª.
5. Analise o log: alerta verdadeiro ou falso positivo? Qual o próximo passo?

```
# Palo Alto TRAFFIC (CSV, campos reduzidos)
2026-09-03 10:02:41,TRAFFIC,end,10.10.30.65,10.10.30.126,any,tcp,445,deny,VLAN-TI,VLAN-TI
2026-09-03 10:02:41,TRAFFIC,end,10.10.30.65,10.10.30.127,any,tcp,445,deny,VLAN-TI,VLAN-TI
```

<details><summary>Ver gabarito</summary>

**1.** Máscara /27 = 255.255.255.224. Binário: 130 = `10000010`, máscara `11100000`, `AND` → `10000000` = 128. Atalho: 256 − 224 = bloco **32** → 0, 32, 64, 96, **128**, 160. Rede **172.16.45.128**, broadcast **172.16.45.159**, hosts **.129 a .158** (30 hosts).

**2.** Não deveria acontecer. Em 10.10.30.128/26 (bloco 64), o intervalo vai de 128 a 191, então **.191 é o broadcast**. Broadcast como *origem* indica host mal configurado, pilha de rede quebrada ou spoofing. Próximo passo: identificar a porta do switch pela tabela MAC e isolar.

**3.** /22 → 256 − 252 = bloco **4** no 3º octeto: 0, 4, 8, **12**, 16. O octeto 13 cai no bloco de 12. Sub-rede **10.50.12.0/22**, broadcast 10.50.15.255. O IP é válido como host.

**4.** 8 sub-redes = 2^3 → empresta 3 bits → **/27**, bloco 32. Sequência: 0, 32, 64, 96, 128, 160, 192, 224. A 5ª é **192.168.80.128/27** — hosts .129 a .158, broadcast .159.

**5.** Alerta **verdadeiro** e de alta prioridade. O host .65 é o primeiro host válido de 10.10.30.64/26; ele está varrendo a porta **445 (SMB)** dentro do próprio bloco, inclusive contra **.127, que é o broadcast** — comportamento de varredura sequencial automatizada, não de uso legítimo por usuário. Isso é reconhecimento para movimento lateral (T1046, seguido de T1021.002 — SMB/Windows Admin Shares). Próximo passo: identificar o dono de 10.10.30.65 no inventário; correlacionar com Windows Security **4624 tipo 3** (logon de rede) e **4625** em massa nos servidores da VLAN; procurar Sysmon **Event ID 1** (criação de processo) e **Event ID 3** (conexão de rede) no host de origem; se confirmado, isolar a máquina e acionar resposta a incidentes. Falso positivo só se houver janela documentada de varredura de vulnerabilidades — verifique o scanner autorizado antes de fechar o caso.

</details>


## IPv6 — o endereçamento que já está ligado na sua rede (mesmo sem você saber)

Imagine que a numeração de telefones de um país inteiro foi criada nos anos 70 pensando em 4 bilhões de aparelhos. Deu certo por décadas — até que cada pessoa passou a ter celular, relógio, geladeira e carro conectados. Foi exatamente isso que aconteceu com o IPv4: 32 bits, cerca de 4,3 bilhões de endereços, esgotados. O IPv6 é a numeração nova, com **128 bits**, o que dá aproximadamente 340 undecilhões de endereços — na prática, inesgotável.

### Formato e regras de abreviação

O IPv6 é escrito em **hexadecimal** (0–9 e a–f), em 8 grupos de 4 dígitos separados por dois-pontos. Cada grupo representa 16 bits.

```
2001:0db8:0000:0000:0000:0000:0000:0001
```

Ninguém escreve assim. Existem duas regras de abreviação:

1. **Zeros à esquerda de cada grupo podem sumir**: `0db8` vira `db8`, `0000` vira `0`.
2. **Uma única sequência de grupos zerados pode virar `::`** — e só uma por endereço, senão fica ambíguo.

| Endereço completo | Abreviado | Observação |
|---|---|---|
| `2001:0db8:0000:0000:0000:0000:0000:0001` | `2001:db8::1` | ambas as regras aplicadas |
| `fe80:0000:0000:0000:0a2b:00ff:fe3c:4d5e` | `fe80::a2b:ff:fe3c:4d5e` | link-local típico |
| `0000:0000:0000:0000:0000:0000:0000:0001` | `::1` | loopback (o `127.0.0.1` do IPv6) |
| `2001:db8:0:1:0:0:0:ab` | `2001:db8:0:1::ab` | só o bloco maior de zeros vira `::` |

> Cuidado prático: `2001:db8::1` e `2001:0db8:0000:0000:0000:0000:0000:0001` são **o mesmo host**. Se o seu SIEM não normaliza, uma busca exata pode não trazer o evento.

### Tipos de endereço IPv6 que o N1 precisa reconhecer

| Prefixo | Nome | Equivalente mental no IPv4 | O que significa em uma investigação |
|---|---|---|---|
| `2000::/3` | Global Unicast | IP público | Roteável na Internet. Se o destino é `2000::/3`, saiu da empresa. |
| `fe80::/10` | Link-Local | `169.254.x.x` (APIPA) | Só vale dentro do mesmo segmento/VLAN. Nunca cruza roteador. |
| `fc00::/7` (na prática `fd00::/8`) | Unique Local (ULA) | RFC1918 (`10.x`, `192.168.x`) | Endereço interno privado. |
| `ff00::/8` | Multicast | broadcast/multicast | `ff02::1` = todos os nós do link; `ff02::2` = todos os roteadores. |
| `::1` | Loopback | `127.0.0.1` | Tráfego da própria máquina. |

**Prefixo /64 e EUI-64.** Quase toda sub-rede IPv6 é `/64`: os 64 primeiros bits identificam a rede, os 64 últimos identificam o host (chamado *interface ID*). O **EUI-64** é a receita antiga que gerava esse interface ID a partir do MAC da placa: pega o MAC de 48 bits, insere `ff:fe` no meio e inverte um bit. Resultado: o endereço IPv6 entrega o **fabricante da placa de rede**. Hoje o Windows usa por padrão endereços aleatórios (*privacy extensions*, RFC 4941), que trocam sozinhos — por isso um mesmo notebook pode aparecer com vários IPv6 no mesmo dia.

**SLAAC vs DHCPv6.** No IPv4 quase tudo é DHCP. No IPv6 existem dois caminhos:

- **SLAAC** (Stateless Address Autoconfiguration): o roteador anuncia o prefixo por **Router Advertisement (RA)** e o host monta o próprio endereço. Não há servidor guardando quem pegou o quê.
- **DHCPv6**: existe servidor e existe registro de concessão (*lease*).

Isso importa para o SOC: com SLAAC puro **não há log de lease** para dizer "às 14h32 o IPv6 X era o notebook da maria.costa". A atribuição vira trabalho de correlação com a tabela de vizinhança do switch.

**NDP no lugar do ARP.** O IPv6 não usa ARP. Usa o **NDP** (Neighbor Discovery Protocol), que roda sobre ICMPv6: Router Solicitation (tipo 133), Router Advertisement (134), Neighbor Solicitation (135), Neighbor Advertisement (136). Consequência direta: **bloquear ICMPv6 inteiro quebra a rede IPv6**.

**Dual-stack** é a máquina rodando IPv4 e IPv6 ao mesmo tempo — o padrão em Windows 10/11 e Linux moderno.

### Por que IPv6 é ponto cego do SOC

- **Está ligado por padrão** no Windows, e o sistema **prefere IPv6** quando os dois existem. O tráfego pode sair por IPv6 enquanto sua regra de detecção olha só IPv4.
- **Regra de firewall escrita só para IPv4**: um bloqueio de saída para `0.0.0.0/0` porta 445 não impede nada em IPv6 se não houver a regra `::/0` equivalente.
- **Rogue Router Advertisement**: qualquer máquina do segmento pode anunciar-se como roteador IPv6 e virar man-in-the-middle sem tocar em nada de IPv4. É o efeito que ferramentas como o Responder exploram — o rastro em log é RA vindo de um MAC/host que não é o gateway.
- **Túneis Teredo (UDP 3544) e 6to4 (protocolo IP 41)**: encapsulam IPv6 dentro de IPv4 e podem furar inspeção de proxy.

**Como aparece nos logs.** Zeek, `conn.log` (campos: timestamp, uid, IP e porta de origem, IP e porta de destino, protocolo, serviço, duração, bytes originados, bytes respondidos, estado da conexão):

```
#fields ts  uid  id.orig_h  id.orig_p  id.resp_h  id.resp_p  proto service duration orig_bytes resp_bytes conn_state
1756900412.118  CxT4a1  fd00:10:10:20::5a  49731  2001:db8:beef::10  443  tcp  ssl  312.44  184320  9822144  SF
1756900455.902  CzQ9k2  10.10.20.90  51222  203.0.113.44  3544  udp  -  62.10  8140  10420  SF
```

A primeira linha é tráfego IPv6 interno (ULA `fd00::/8`) para um destino global — saiu para a Internet. A segunda é UDP/3544: **Teredo**, IPv6 tunelado para fora.

Suricata EVE JSON de um Router Advertisement suspeito:

```json
{"timestamp":"2026-09-03T14:22:07.441+0000","event_type":"alert","src_ip":"fe80::a2b:ff:fe3c:4d5e","dest_ip":"ff02::1","proto":"IPV6-ICMP","icmp_type":134,"alert":{"signature":"ICMPv6 Router Advertisement from non-gateway host","category":"Potentially Bad Traffic","severity":2},"host":"sensor-dmz-01"}
```

`icmp_type 134` é RA; destino `ff02::1` é "todos os nós". Se a origem não for o gateway conhecido, é candidato a rogue RA.

**O que o SOC N1 observa.** *Normal*: RA vindo apenas dos MACs dos roteadores/firewalls; `fe80::` conversando só dentro do segmento; DNS AAAA resolvendo para destinos corporativos. *Suspeito*: RA de estação de usuário; tráfego UDP/3544 ou protocolo 41 saindo de desktop; host com dezenas de IPv6 globais diferentes em minutos.

**Erro comum de analista júnior:** ver `fe80::1` num alerta e escalar como "IP desconhecido na rede". Link-local existe em toda interface IPv6 e é normal. O oposto também é erro: descartar um alerta porque "o IP não parece com nada" — `2001:db8::` é público e sai da empresa.

## Aplicação ao SOC — por que o N1 precisa de subnetting todo dia

O N1 usa endereçamento e máscara (vistos nos trechos anteriores) para responder três perguntas em segundos:

1. **O IP é interno ou externo?** Define se é acesso de dentro para fora, de fora para dentro, ou lateral.
2. **É VLAN de servidor ou de usuário?** Um scan partindo de VLAN de usuário para VLAN de servidor é muito mais grave que o inverso.
3. **O scan ficou no mesmo segmento ou cruzou zonas?** Se cruzou, passou por firewall — e existe log de política para provar.

### Filtros por sub-rede nas quatro ferramentas

```spl
index=firewall sourcetype=pan:traffic
| where cidrmatch("10.10.20.0/24", src_ip)          /* origem: VLAN de usuários */
| where NOT cidrmatch("10.10.0.0/16", dest_ip)      /* destino fora do range corporativo */
| stats dc(dest_ip) AS destinos_unicos sum(bytes_out) AS bytes by src_ip user
| where destinos_unicos > 50                         /* muitos destinos = varredura */
```

```kql
// Sentinel / Defender — conexões de VLAN de usuário para VLAN de servidor
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where ipv4_is_in_range(SourceIP, "10.10.20.0/24")      // origem: usuários
| where ipv4_is_in_range(DestinationIP, "10.10.10.0/24") // destino: servidores
| summarize Portas = dcount(DestinationPort), Alvos = dcount(DestinationIP) by SourceIP
| where Portas > 20 or Alvos > 15                        // padrão de varredura
```

| Ferramenta | Filtro por sub-rede | Lê-se como |
|---|---|---|
| Wireshark | `ip.addr == 10.10.20.0/24` | qualquer ponta na VLAN de usuários |
| Wireshark (IPv6) | `ipv6.addr == fd00:10:10:20::/64` | mesmo conceito em IPv6 |
| tcpdump | `tcpdump -nn net 10.10.20.0/24 and not net 10.10.0.0/16` | sai da VLAN e do range corporativo |
| tcpdump (IPv6) | `tcpdump -nn ip6 and net fd00:10:10::/48` | só IPv6 interno |

## Plano de endereçamento corporativo — empresa-exemplo.com.br

| Zona / site | Sub-rede IPv4 | Máscara | Faixa de hosts | Gateway | Prefixo IPv6 | Uso |
|---|---|---|---|---|---|---|
| Matriz — Servidores | 10.10.10.0/24 | 255.255.255.0 | .1–.254 | 10.10.10.1 | fd00:10:10:10::/64 | AD, arquivos, ERP |
| Matriz — Usuários | 10.10.20.0/24 | 255.255.255.0 | .1–.254 | 10.10.20.1 | fd00:10:10:20::/64 | notebooks, desktops |
| Matriz — Gerência de rede | 10.10.30.0/26 | 255.255.255.192 | .1–.62 | 10.10.30.1 | fd00:10:10:30::/64 | switches, iLO, IDRAC |
| Matriz — Impressoras/IoT | 10.10.40.0/24 | 255.255.255.0 | .1–.254 | 10.10.40.1 | — | sem saída à Internet |
| Filial São Paulo | 10.20.0.0/22 | 255.255.252.0 | 10.20.0.1–10.20.3.254 | 10.20.0.1 | fd00:10:20::/48 | usuários + servidor local |
| Filial Recife | 10.30.0.0/24 | 255.255.255.0 | .1–.254 | 10.30.0.1 | fd00:10:30::/48 | usuários |
| Filial Lisboa | 10.40.0.0/24 | 255.255.255.0 | .1–.254 | 10.40.0.1 | fd00:10:40::/48 | usuários |
| DMZ | 172.16.1.0/25 | 255.255.255.128 | .1–.126 | 172.16.1.1 | 2001:db8:dmz::/64 | web, SMTP relay, proxy reverso |
| Cloud — VPC produção | 172.31.0.0/20 | 255.255.240.0 | 172.31.0.1–172.31.15.254 | 172.31.0.1 | 2001:db8:c10d::/56 | workloads |
| Pool VPN (SSL) | 192.168.100.0/24 | 255.255.255.0 | .1–.254 | 192.168.100.1 | — | acesso remoto |
| Bloco público NAT | 203.0.113.0/28 | 255.255.255.240 | .1–.14 | 203.0.113.1 | — | IPs de saída da empresa |

Regra de leitura rápida para o plantão: **10.10.x** = matriz; **10.20/30/40** = filiais; **172.16.1.x** = DMZ; **172.31.x** = cloud; **192.168.100.x** = VPN; **203.0.113.x** = nós, visto de fora.

### Exercícios — IPv6, aplicação ao SOC e plano de endereçamento corporativo

1. Abrevie ao máximo `2001:0db8:0000:0000:00a1:0000:0000:0042` e explique por que existe mais de uma resposta possível — e qual é a correta pela regra.
2. Classifique cada endereço (global unicast, link-local, ULA, multicast, loopback) e diga se ele pode cruzar um roteador: `fe80::1`, `fd00:10:10:20::9`, `2001:db8:beef::10`, `ff02::2`, `::1`.
3. Leia o log do FortiGate abaixo e diga em qual zona do plano estão origem e destino, e se o evento merece escalar:
```
date=2026-09-03 time=15:04:22 devname="FGT-MATRIZ-01" devid="FG100F0000000001" type="traffic" subtype="forward" level="warning" srcip=10.10.20.118 srcport=51544 srcintf="vlan20-users" dstip=10.10.10.25 dstport=445 dstintf="vlan10-srv" policyid=42 action="deny" service="SMB" sessionid=884120 srccountry="Reserved" user="jsilva"
```
4. Verdadeiro ou falso positivo? O alerta "host desconhecido comunicando na rede" disparou para `fe80::a2b:ff:fe3c:4d5e` conversando com `ff02::1` a partir do MAC do firewall de borda.
5. Um desktop da VLAN de usuários (`10.10.20.77`) mantém sessão UDP para `198.51.100.9:3544` por 40 minutos, 2 MB enviados. Qual é o próximo passo da investigação?

<details><summary>Ver gabarito</summary>

**1.** Resposta correta: `2001:db8::a1:0:0:42`. Os zeros à esquerda somem em todos os grupos e o `::` só pode ser usado **uma vez** — logo, aplica-se à maior sequência de grupos zerados, que é `0000:0000` no início (grupos 3 e 4). A sequência final `0000:0000` também tem 2 grupos; quando há empate, a convenção (RFC 5952) manda comprimir a **primeira** ocorrência. Escrever `2001:db8:0:0:a1::42` é válido mas não é a forma canônica; escrever `2001:db8::a1::42` está **errado** (dois `::`, ambíguo).

**2.** `fe80::1` = link-local, **não cruza roteador**. `fd00:10:10:20::9` = ULA (privado interno), cruza roteadores internos mas não é roteado na Internet. `2001:db8:beef::10` = global unicast (`2000::/3`), **cruza e sai para a Internet**. `ff02::2` = multicast de escopo link ("todos os roteadores"), não cruza roteador. `::1` = loopback, nunca sai da máquina.

**3.** Origem `10.10.20.118` = Matriz/Usuários; destino `10.10.10.25` = Matriz/Servidores. O tráfego **cruzou zonas** (interfaces `vlan20-users` → `vlan10-srv`), destino porta 445 (SMB), e `action="deny"` mostra que a política 42 bloqueou. Um deny isolado de SMB para um servidor de arquivos costuma ser ruído. O que decide o escalonamento é o **padrão**: repita a busca por `srcip=10.10.20.118` nas últimas 2 horas; se houver deny 445 para muitos `dstip` distintos, é varredura SMB / possível movimento lateral (MITRE T1021.002 e T1046) e escala. Um único deny, mesmo usuário, mesmo destino: registre e siga.

**4.** **Falso positivo.** `fe80::` é link-local — toda interface IPv6 tem um, sempre. O destino `ff02::1` é o multicast "todos os nós", usado pelo NDP/Router Advertisement. E a origem é o MAC do firewall de borda, ou seja, o roteador legítimo anunciando o prefixo. O caso seria verdadeiro se o RA (ICMPv6 tipo 134) viesse do MAC de uma estação de usuário — aí sim, suspeita de rogue RA.

**5.** UDP porta **3544 é Teredo**: túnel IPv6 dentro de IPv4, saindo direto para a Internet e escapando da inspeção do proxy. Próximos passos, nesta ordem: (a) confirmar o dono do host e o usuário logado (Windows Security EventID 4624, tipo de logon 2 ou 10); (b) verificar em Sysmon EventID 3 (network connection) qual processo abriu o socket e em EventID 1 a linha de comando pai; (c) checar se existe política de firewall bloqueando UDP/3544 de saída e por que não aplicou; (d) verificar se o host tem interface `Teredo Tunneling Pseudo-Interface` ativa; (e) escalar ao N2 se o processo não for um serviço conhecido, tratando como possível canal de comando e controle (MITRE T1572 — Protocol Tunneling).

</details>

## Mini-laboratório — endereçamento IP, máscara, subnetting e IPv6

**Pré-requisitos:** VirtualBox com uma VM Linux (Ubuntu Server ou Security Onion), Wireshark instalado no host, e a máquina Windows do próprio laboratório. Tudo gratuito. Faça o laboratório numa rede isolada (rede "Interna" do VirtualBox), nunca na rede de produção.

**Passo 1 — mapear seu próprio endereçamento.**
```
ipconfig /all
netsh interface ipv6 show address
```
No Linux: `ip -4 addr show` e `ip -6 addr show`. *O que observar:* anote IPv4, máscara, gateway e todos os IPv6. Você deve ver pelo menos um `fe80::` por interface.

**Passo 2 — calcular a sub-rede na mão.** Com o IPv4 e a máscara do passo 1, calcule endereço de rede, broadcast e faixa de hosts válidos. Confira com `ipcalc 10.10.20.118/24` (Linux) ou fazendo o AND bit a bit no papel.

**Passo 3 — capturar NDP e ARP lado a lado.**
```
sudo tcpdump -nn -i eth0 -w lab-ndp.pcap "arp or icmp6"
```
Em outro terminal, gere tráfego: `ping -c 3 10.10.20.1` e `ping6 -c 3 ff02::1%eth0`. *O que observar:* no Wireshark, filtre `arp` e depois `icmpv6.type == 135 || icmpv6.type == 136`. Compare: ARP request/reply em IPv4 e Neighbor Solicitation/Advertisement em IPv6 fazem o mesmo trabalho.

**Passo 4 — ver o Router Advertisement.** Filtro Wireshark: `icmpv6.type == 134`. Expanda o pacote e localize o campo *Prefix* — é ele que define o `/64` da sua rede. Anote o MAC de origem: esse é o **gateway legítimo**, sua linha de base para detectar rogue RA.

**Passo 5 — varredura controlada dentro do laboratório.**
```
nmap -sn 10.10.20.0/24
nmap -6 --script targets-ipv6-multicast-echo -e eth0
```
*O que observar:* na captura, o padrão de varredura — muitos destinos, poucos bytes, respostas ausentes. É exatamente essa assinatura que a query SPL do item anterior procura.

**Critério de sucesso:** você consegue (a) dizer de cor rede, broadcast e hosts da sua sub-rede; (b) mostrar no pcap um par NS/NA de IPv6 e explicar que substitui o ARP; (c) apontar o MAC do RA legítimo; (d) reconhecer visualmente o padrão de varredura na captura.

## O que um SOC Level 1 realmente precisa saber

- 🟢 Reconhecer de imediato se um IP é RFC1918 (`10/8`, `172.16/12`, `192.168/16`) ou público — é a primeira pergunta de toda investigação.
- 🟢 Ler máscara em notação decimal e em CIDR e saber que `/24` = 256 endereços, 254 hosts úteis.
- 🟢 Calcular endereço de rede, broadcast e faixa de hosts de uma `/24`, `/25` e `/26` sem calculadora.
- 🟢 Saber, olhando o plano de endereçamento da empresa, se um IP é servidor, usuário, DMZ, cloud ou VPN.
- 🟢 Identificar `127.0.0.1`/`::1` como loopback e `169.254.x.x`/`fe80::` como link-local — nenhum dos dois é "host misterioso".
- 🟢 Filtrar por sub-rede em Wireshark (`ip.addr == 10.10.20.0/24`), tcpdump (`net 10.10.20.0/24`), SPL (`cidrmatch`) e KQL (`ipv4_is_in_range`).
- 🟡 Distinguir tráfego que ficou no mesmo segmento de tráfego que cruzou zonas — e saber que só o segundo gera log de política no firewall.
- 🟡 Abreviar e expandir IPv6 corretamente, sabendo que `2001:db8::1` e a forma longa são o mesmo host na busca do SIEM.
- 🟡 Classificar IPv6 pelo prefixo: `2000::/3` sai para a Internet, `fd00::/8` é interno, `fe80::/10` é local, `ff00::/8` é multicast.
- 🟡 Suspeitar de UDP/3544 (Teredo) e protocolo IP 41 (6to4) saindo de estações de usuário.
- 🔴 Entender que SLAAC não gera log de lease e que atribuir um IPv6 a um usuário exige correlação com a tabela de vizinhança do switch e com logon do Windows (EventID 4624).
- 🔴 Reconhecer rogue Router Advertisement (ICMPv6 tipo 134 de origem que não é o gateway) como vetor de man-in-the-middle invisível ao IPv4.

## Resumo em 10 linhas

1. Todo endereço IPv4 é um número de 32 bits escrito em quatro octetos decimais; o binário é o que torna a máscara compreensível.
2. A máscara (ou o CIDR `/n`) divide o endereço em parte de rede e parte de host — é ela que define o tamanho do segmento.
3. Endereços privados (`10/8`, `172.16/12`, `192.168/16`) não existem na Internet; endereços públicos identificam a empresa vista de fora.
4. Em cada sub-rede, o primeiro endereço é a rede, o último é o broadcast, e o que sobra são os hosts válidos.
5. Subnetting é dividir um bloco grande em blocos menores para separar servidores, usuários, DMZ e gerência.
6. O IPv6 nasceu do esgotamento do IPv4: 128 bits em hexadecimal, com abreviação de zeros e um único `::` por endereço.
7. O prefixo diz tudo em IPv6: `2000::/3` é público, `fd00::/8` é interno, `fe80::/10` é link-local, `ff00::/8` é multicast, `::1` é loopback.
8. IPv6 usa NDP sobre ICMPv6 no lugar do ARP, atribui endereço por SLAAC ou DHCPv6, e vem ligado por padrão no Windows.
9. IPv6 é ponto cego do SOC quando a regra de firewall foi escrita só para IPv4 ou quando há túnel Teredo/6to4 saindo da rede.
10. O plano de endereçamento corporativo é a régua diária do N1: com ele, um IP no log vira uma zona, uma criticidade e um próximo passo.



---
