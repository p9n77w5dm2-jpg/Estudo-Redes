# Checklist de entrevista para SOC N1

Por que este módulo importa para o SOC: saber redes não basta se você não consegue explicar o que sabe em voz alta, sob pressão, para um entrevistador que tem 40 minutos para decidir se te contrata. Este módulo transforma o conteúdo técnico do curso em respostas faladas, curtas e seguras — do jeito que se responde numa entrevista real de SOC Nível 1.

Índice do módulo:

- O processo seletivo e perguntas de redes, OSI, TCP/IP e DNS
- Perguntas de portas, firewall, proxy, VPN, Windows/AD e Linux
- Perguntas de logs, SIEM, ameaças, processo e comportamentais
- Pegadinhas técnicas, cenários reais, simulado e cartão de revisão

## Como é o processo seletivo típico de um SOC

Pense no processo seletivo como um aeroporto: você passa por vários portões e em cada um checam uma coisa diferente. Nenhum portão sozinho reprova você por completo, mas todos somam.

| Etapa | Quem conduz | O que avaliam de verdade | Como se preparar |
|---|---|---|---|
| Triagem de RH (20 a 30 min) | Recrutador | Disponibilidade para turno/escala 24x7, inglês de leitura, pretensão salarial, motivação real | Ter uma apresentação de 90 segundos pronta e saber dizer por que SOC |
| Teste técnico (online, 30 a 60 min) | Plataforma automatizada | Fundamentos: portas, protocolos, OSI, leitura de log, noções de Windows/Linux | Treinar múltipla escolha e leitura rápida de log |
| Entrevista técnica (45 a 60 min) | Analista N2/N3 ou líder técnico | Se você entende o **porquê**, não só decorou | Explicar conceitos com analogia + exemplo prático |
| Entrevista de cenário | Coordenador do SOC | Raciocínio de investigação, priorização e honestidade ao dizer "não sei" | Ter um método fixo: o que vejo, o que valido, o que escalo |
| Cultural / fit | Gestor ou RH sênior | Trabalho em equipe, aguentar rotina de fila de alertas, comunicação escrita | Exemplos reais de colaboração e de erro assumido |

Regra de ouro: em entrevista de SOC, **resposta errada dita com convicção é pior do que "não sei, mas eu investigaria assim"**. O SOC vive de escalonamento honesto.

## As 15 perguntas clássicas de redes

### 1. Explique o modelo OSI

**Resposta ideal:** OSI, de Open Systems Interconnection (Interconexão de Sistemas Abertos), é um modelo didático em 7 camadas que separa as responsabilidades de uma comunicação em rede. É como os Correios: a camada 1 é a estrada, a 2 é o carteiro do bairro, a 3 é o CEP que leva a carta entre cidades, a 4 garante que a encomenda chegou inteira, e as camadas 5, 6 e 7 são o envelope, o idioma e a carta em si. Na prática, o SOC vive nas camadas 3 (IP), 4 (TCP/UDP, portas) e 7 (HTTP, DNS, SMB). Quando eu leio um alerta, eu já mapeio: IP de origem e destino é camada 3, porta é camada 4, e a URL ou a query DNS é camada 7.

**O que o entrevistador está avaliando:** se você sabe usar o modelo como ferramenta de diagnóstico, e não só recitar "Física, Enlace, Rede, Transporte, Sessão, Apresentação, Aplicação".

**Como se destacar:** cite onde cada ferramenta atua — firewall tradicional em 3 e 4, proxy web e WAF em 7, switch em 2, roteador em 3.

### 2. Diferença entre TCP e UDP

**Resposta ideal:** TCP, Transmission Control Protocol, é uma ligação telefônica: você disca, o outro atende, e os dois confirmam que estão se ouvindo. Ele garante entrega, ordem e retransmite o que se perdeu. UDP, User Datagram Protocol, é gritar do outro lado da rua: você fala e não sabe se ouviram. Não tem conexão nem confirmação, mas é muito mais rápido e leve. Por isso DNS, DHCP, NTP, streaming e VoIP usam UDP, enquanto HTTP, HTTPS, SSH e SMB usam TCP. Para o SOC isso importa porque UDP é fácil de forjar o IP de origem, então tráfego UDP suspeito exige mais cuidado antes de acusar a origem.

**O que o entrevistador está avaliando:** se você conecta a característica do protocolo ao impacto na investigação.

**Como se destacar:** mencione que UDP é o vetor preferido de amplificação em DDoS (DNS, NTP, memcached) justamente por não ter handshake.

### 3. Explique o three-way handshake

**Resposta ideal:** É o aperto de mão em três tempos que abre toda conexão TCP. O cliente manda um pacote com a flag SYN; o servidor responde SYN-ACK; o cliente fecha com ACK. Só depois disso os dados trafegam. Se a porta está fechada, o servidor responde RST-ACK. Se um firewall descarta silenciosamente, não vem resposta nenhuma e o cliente fica retransmitindo o SYN. Isso é ouro para o SOC: uma máquina mandando muitos SYN para portas diferentes e recebendo RST é varredura de portas.

**O que o entrevistador está avaliando:** domínio de flags TCP e capacidade de traduzir isso em detecção.

**Como se destacar:** cite o filtro de Wireshark `tcp.flags.syn==1 && tcp.flags.ack==0` e explique que o encerramento normal é FIN-ACK / FIN-ACK, não RST.

```
# Zeek conn.log (campos: ts, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto, service, duration, conn_state)
1725360012.114  10.10.20.55  49311  10.10.30.10  445   tcp  -  0.000112  S0
1725360012.118  10.10.20.55  49312  10.10.30.11  445   tcp  -  0.000109  REJ
1725360012.121  10.10.20.55  49313  10.10.30.12  3389  tcp  -  0.000131  S0
```

<details><summary>Ver legenda</summary>

| Campo | Valores nas três linhas | O que significa |
|---|---|---|
| `ts` | `1725360012.114`, `.118`, `.121` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos. **Três tentativas em 7 milissegundos** — velocidade de ferramenta, não de pessoa |
| `id.orig_h` | `10.10.20.55` | Sempre a mesma origem: é ela que está varrendo |
| `id.orig_p` | `49311`, `49312`, `49313` | Portas efêmeras **consecutivas** — assinatura de um processo abrindo conexões em série |
| `id.resp_h` | `10.10.30.10`, `.11`, `.12` | Destinos **sequenciais**: a ferramenta está percorrendo a faixa host a host |
| `id.resp_p` | `445`, `445`, `3389` | Portas de administração remota: SMB e RDP |
| `proto` | `tcp` | Transporte |
| `service` | `-` | Vazio nas três: **nenhuma sessão chegou a existir**, logo não houve conteúdo para o Zeek identificar |
| `duration` | `0.000112`, `0.000109`, `0.000131` | Frações de milissegundo — só o tempo do SYN e da resposta |
| `conn_state` | `S0`, `REJ`, `S0` | O campo-chave: `S0` = SYN enviado sem resposta (porta filtrada ou host inexistente); `REJ` = recusada com RST, **o que prova que aquele host existe e está ligado**; `SF` seria conexão completa |

</details>


**Erro comum de analista júnior:** ver `S0` e concluir "ataque bem-sucedido". `S0` normalmente indica exatamente o contrário: nada foi estabelecido.

### 4. O que acontece quando digito uma URL no navegador

**Resposta ideal:** Primeiro o navegador verifica o cache local e o arquivo hosts. Não achando, consulta o DNS para transformar o nome em endereço IP. Com o IP em mãos, monta um pacote e usa o gateway padrão se o destino estiver fora da rede local; se estiver dentro, usa ARP para descobrir o endereço MAC. Aí abre a conexão TCP na porta 443 com o three-way handshake, faz o handshake TLS trocando certificados, e só então envia o GET HTTP. O servidor responde, o navegador renderiza. Num ambiente corporativo, entre o navegador e a internet ainda tem proxy e firewall, e cada um desses passos gera log em um sistema diferente.

**O que o entrevistador está avaliando:** visão de ponta a ponta — esta é a pergunta que mais separa quem decorou de quem entendeu.

**Como se destacar:** encerre dizendo em qual log cada etapa aparece: DNS no Zeek `dns.log`, sessão no firewall, requisição no proxy, e negociação TLS no `ssl.log` com o campo SNI.

### 5. Para que serve o DNS e como funciona a resolução

**Resposta ideal:** DNS, Domain Name System (Sistema de Nomes de Domínio), é a lista telefônica da internet: traduz nomes como `intranet.corp.local` em endereços IP. A resolução é recursiva: o cliente pergunta ao servidor DNS interno; se ele não sabe e não tem em cache, ele pergunta a um servidor raiz, depois ao servidor do domínio de topo, depois ao servidor autoritativo do domínio, e devolve a resposta ao cliente guardando em cache pelo tempo do TTL. Para o SOC, DNS é a fonte de log mais valiosa que existe, porque quase todo malware precisa resolver um nome antes de falar com o servidor de comando e controle.

**O que o entrevistador está avaliando:** se você entende recursivo versus autoritativo e o valor do log de DNS.

**Como se destacar:** cite DNS tunneling (T1071.004) e diga o indicador: nomes longos, alta entropia, volume anormal de consultas TXT ou NULL para um mesmo domínio.

```json
{"timestamp":"2026-09-03T14:22:07.512Z","event_type":"dns","src_ip":"10.10.20.55","dest_ip":"10.10.10.5","proto":"UDP","dns":{"type":"query","rrname":"a7f3d9b2c1e8.tunnel.empresa-exemplo.com.br","rrtype":"TXT"}}
```

Log Suricata EVE JSON. `src_ip` é a estação, `dest_ip` é o DNS interno, `rrname` é o nome consultado e `rrtype` o tipo de registro. Subdomínio aleatório de 12 caracteres com consulta TXT repetida centenas de vezes é padrão clássico de exfiltração por DNS.

### 6. O que é um registro MX e um registro TXT

**Resposta ideal:** MX, Mail Exchanger, aponta qual servidor recebe o e-mail de um domínio, com um valor de prioridade — o menor número tenta primeiro. TXT é um registro de texto livre, usado hoje principalmente para SPF, DKIM e DMARC, que são os mecanismos que dizem quem pode enviar e-mail em nome do domínio. No SOC, quando investigo phishing, eu olho o MX para saber por onde o e-mail deveria entrar e o TXT com SPF para verificar se o remetente estava autorizado.

**O que o entrevistador está avaliando:** se você liga DNS a investigação de phishing, que é o alerta número um de qualquer SOC.

**Como se destacar:** diga que SPF sozinho não resolve, porque o cabeçalho `From` visível pode diferir do envelope validado pelo SPF — é por isso que existe o DMARC com alinhamento.

### 7. O que é um IP privado

**Resposta ideal:** É um endereço reservado pela RFC 1918 para uso dentro de redes internas e que não é roteável na internet. São três faixas: 10.0.0.0/8, 172.16.0.0/12 e 192.168.0.0/16. É como o número da sala dentro de um prédio: só faz sentido lá dentro. Numa investigação, se o IP de origem é privado, o atacante ou a vítima está dentro da rede; se é público, veio de fora.

**O que o entrevistador está avaliando:** memorização correta das faixas, que é pré-requisito de triagem.

**Como se destacar:** mencione também 169.254.0.0/16 (APIPA, indica falha de DHCP) e 127.0.0.0/8 (loopback), e as faixas de documentação 203.0.113.0/24, 198.51.100.0/24 e 192.0.2.0/24.

### 8. O que é NAT e por que ele complica a investigação

**Resposta ideal:** NAT, Network Address Translation, traduz endereços privados em um endereço público na saída para a internet. É como a recepção de um prédio: todo mundo sai com o endereço da rua na correspondência. O problema para o SOC é que centenas de estações saem com o mesmo IP público, então um alerta de fora só me dá o IP da empresa, não a máquina. Para chegar à estação eu preciso do log de NAT do firewall, correlacionando IP público, porta de origem traduzida, IP privado e o horário exato.

**O que o entrevistador está avaliando:** se você já pensou no problema prático de atribuir um evento a um usuário.

**Como se destacar:** insista no par **porta de origem + timestamp com fuso horário**, porque só o IP não identifica ninguém atrás de NAT.

```
%ASA-6-305011: Built dynamic TCP translation from inside:10.10.20.55/49877 to outside:203.0.113.44/61204
%ASA-6-302013: Built outbound TCP connection 88421 for outside:198.51.100.23/443 (198.51.100.23/443) to inside:10.10.20.55/49877 (203.0.113.44/61204)
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `%ASA` | `%ASA` | Etiqueta do produto: identifica a linha como vinda de um firewall ASA |
| severidade | `6` | Escala syslog do Cisco, de 0 (emergência) a 7 (depuração): `6` é **informational**. **Severidade baixa não quer dizer evento sem importância** — quem a escolhe é o fabricante, não o seu SOC |
| *message ID* | `305011` | Tradução dinâmica de NAT criada. **É por este número que se escreve a regra no SIEM**: o texto da mensagem muda entre versões do software, o ID não |
| `from` | `inside:10.10.20.55/49877` | **O endereço real**: interface, IP privado e porta de origem |
| `to` | `outside:203.0.113.44/61204` | **O endereço traduzido**: IP público e a porta que o ASA sorteou. Repare que **a porta também muda** (49877 → 61204) |
| *message ID* (2ª linha) | `302013` | Conexão TCP construída — o `305011` cria a tradução, o `302013` usa-a |
| id da conexão | `88421` | Número na tabela de estado |
| lado remoto | `outside:198.51.100.23/443` | O destino real da navegação |
| lado local | `inside:10.10.20.55/49877 (203.0.113.44/61204)` | O host local e, entre parênteses, o mesmo par traduzido da 1ª linha |
| — | — | **É este par de linhas que responde a "quem foi?"** quando chega uma denúncia sobre `203.0.113.44:61204`. Sem o `305011`, ou sem o parêntese do `302013`, o IP público não aponta para máquina nenhuma |

</details>


### 9. Para que serve o gateway padrão

**Resposta ideal:** É a saída do prédio. Quando a máquina quer falar com um IP que não está na sua própria rede, ela entrega o pacote ao gateway padrão, que é o roteador, e ele decide o caminho. A máquina descobre se o destino é local ou não comparando o IP de destino com sua máscara de sub-rede. Se o gateway está errado ou ausente, a máquina fala com vizinhos mas não sai para a internet.

**O que o entrevistador está avaliando:** entendimento de roteamento básico e de máscara de sub-rede.

**Como se destacar:** cite que gateway alterado sem motivo pode indicar ataque de homem no meio, e que o comando de verificação é `route print` no Windows ou `ip route` no Linux.

### 10. O que é uma VLAN

**Resposta ideal:** VLAN, Virtual Local Area Network, é uma rede local separada logicamente dentro do mesmo switch físico. É como dividir um galpão com paredes de drywall: mesma estrutura, ambientes isolados. Serve para separar setores — financeiro, servidores, visitantes — reduzindo o alcance de um ataque. Máquinas em VLANs diferentes só se falam passando por um roteador ou firewall, que é onde eu consigo aplicar regra e gerar log.

**O que o entrevistador está avaliando:** noção de segmentação como controle de segurança, não só de organização.

**Como se destacar:** relacione com movimentação lateral (T1021): boa segmentação transforma movimentação lateral em tráfego que atravessa o firewall e, portanto, vira log.

### 11. O que é uma DMZ

**Resposta ideal:** DMZ, DeMilitarized Zone (Zona Desmilitarizada), é a área intermediária onde ficam os servidores que precisam ser acessados pela internet — site, portal, servidor de e-mail de borda. É a recepção do prédio: o visitante entra ali, mas não passa para os andares internos. A regra é que a DMZ pode receber conexão da internet, mas não deve iniciar conexões para a rede interna. Se eu vejo um servidor da DMZ abrindo sessão SMB na porta 445 para um servidor interno, isso é alerta de alta prioridade.

**O que o entrevistador está avaliando:** entendimento do fluxo permitido e, principalmente, do fluxo proibido.

**Como se destacar:** dizer exatamente qual comportamento na DMZ te acorda de madrugada demonstra maturidade operacional.

### 12. O que é ARP e o que é ARP spoofing

**Resposta ideal:** ARP, Address Resolution Protocol, descobre o endereço MAC correspondente a um IP dentro da mesma rede local. A máquina grita "quem tem o IP 10.10.20.1?" e o dono responde com seu MAC. O problema é que o ARP não tem autenticação: qualquer um pode responder. No ARP spoofing, um equipamento malicioso responde se passando pelo gateway e passa a receber o tráfego dos vizinhos — é o clássico ataque de homem no meio, T1557.002 na matriz MITRE ATT&CK.

**O que o entrevistador está avaliando:** se você entende por que o ataque funciona, ou seja, a ausência de autenticação no protocolo.

**Como se destacar:** cite o rastro: o mesmo MAC associado a vários IPs na tabela ARP, visível com `arp -a`, e o controle de mitigação chamado Dynamic ARP Inspection no switch.

### 13. O que o TTL indica

**Resposta ideal:** TTL, Time To Live, é um contador no cabeçalho IP que diminui em um a cada roteador atravessado. Quando chega a zero, o pacote é descartado e o roteador devolve um ICMP tipo 11, que é o "tempo excedido" — é assim que o traceroute funciona. Serve para impedir que pacotes fiquem circulando para sempre. Como cada sistema começa com um valor padrão diferente — Windows em 128, Linux em 64, equipamentos de rede em 255 — dá para estimar o sistema operacional e a distância em saltos observando o TTL que chegou.

**O que o entrevistador está avaliando:** se você separa o TTL do IP do TTL do DNS, que são coisas diferentes.

**Como se destacar:** diga a diferença espontaneamente: no IP é contagem de saltos; no DNS é tempo em segundos de cache, e TTL de DNS muito baixo pode indicar fast flux.

### 14. Diferença entre IPv4 e IPv6

**Resposta ideal:** IPv4 usa 32 bits, escrito em quatro números decimais, e dá cerca de 4 bilhões de endereços, que acabaram — por isso existe NAT. IPv6 usa 128 bits, escrito em hexadecimal separado por dois-pontos, e o espaço é praticamente inesgotável, então cada dispositivo pode ter endereço público sem NAT. IPv6 tem autoconfiguração e não usa ARP, usa o protocolo de descoberta de vizinhos. Para o SOC o risco é ter IPv6 ativo por padrão nas estações sem estar monitorado: vira um caminho de tráfego sem visibilidade.

**O que o entrevistador está avaliando:** consciência de ponto cego de monitoramento.

**Como se destacar:** cite `fe80::/10` como link-local e mencione que ferramentas de ataque abusam de anúncio de roteador IPv6 em redes que só monitoram IPv4.

### 15. Você recebe um alerta e o IP de origem é 10.10.20.55. O que faz primeiro?

**Resposta ideal:** Primeiro eu classifico o endereço: é RFC 1918, então é uma máquina interna, e o incidente é dentro de casa. Em seguida eu identifico o ativo — quem é o dono, qual o setor, se é servidor ou estação — consultando o inventário. Depois eu monto a linha do tempo: o que essa máquina fez antes e depois do alerta, olhando DNS, proxy e firewall no mesmo intervalo. Só então eu decido se é falso positivo ou se escalo para o N2 com o resumo pronto.

**O que o entrevistador está avaliando:** método. Eles querem ouvir uma sequência, não uma ferramenta.

**Como se destacar:** termine dizendo que registraria tudo no ticket com horário em UTC, porque correlação entre fontes com fusos diferentes é a causa número um de erro de investigação.

### Exercícios — O processo seletivo e perguntas de redes, OSI, TCP/IP e DNS

1. Classifique cada endereço como privado, público de documentação, loopback ou APIPA: `172.16.4.9`, `203.0.113.7`, `169.254.10.2`, `192.168.100.5`, `127.0.0.1`.
2. Um pacote chega à sua estação com TTL 122. A origem provavelmente é Windows ou Linux, e quantos saltos ela percorreu?
3. Leia o log e diga se é varredura de portas ou conexão legítima, justificando pelo campo decisivo:

```
1725362201.004  10.10.20.77  51002  10.10.30.20  22    tcp  -  0.000098  REJ
1725362201.007  10.10.20.77  51003  10.10.30.20  23    tcp  -  0.000094  S0
1725362201.011  10.10.20.77  51004  10.10.30.20  3389  tcp  -  0.000101  REJ
```

4. Um alerta externo informa que o IP 203.0.113.44 da sua empresa contatou um domínio malicioso às 14h22. Qual informação você precisa obter e de qual log, para chegar à estação responsável?
5. Verdadeiro ou falso positivo: a estação `10.10.20.55` fez 400 consultas DNS do tipo TXT em 3 minutos para subdomínios diferentes de `empresa-exemplo.com.br`. Qual seu próximo passo?

<details><summary>Ver gabarito</summary>

1. `172.16.4.9` é privado (RFC 1918, faixa 172.16.0.0/12); `203.0.113.7` é público reservado para documentação (TEST-NET-3); `169.254.10.2` é APIPA, o que sugere falha de DHCP na máquina; `192.168.100.5` é privado; `127.0.0.1` é loopback, tráfego que nunca sai da própria máquina. Erro comum: tratar 172.16.x como público — a faixa privada vai de 172.16 até 172.31.

2. Provavelmente Windows, que parte de TTL 128, e percorreu 6 saltos (128 − 122). Se fosse Linux, que parte de 64, um TTL de 122 seria impossível numa entrega normal. Cuidado: alguns sistemas e balanceadores reescrevem o TTL, então isso é indício, não prova.

3. Varredura de portas. O campo decisivo é o `conn_state`: nenhuma sessão chegou a `SF` (conexão completa). São três portas administrativas distintas (22 SSH, 23 Telnet, 3389 RDP) no mesmo destino em 7 milissegundos — velocidade impossível para uso humano. Mapeia para T1046. Note que `REJ` significa que a porta respondeu com RST, ou seja, está fechada; `S0` na porta 23 indica filtragem silenciosa.

4. Você precisa da **porta de origem traduzida** e do **horário exato com fuso**. O log de NAT do firewall de borda (no Cisco ASA, a mensagem `%ASA-6-305011`) é o que amarra `203.0.113.44/porta` de volta ao IP privado da estação. Sem porta e sem timestamp preciso, dezenas de máquinas são candidatas e a atribuição é impossível.

5. Fortemente suspeito, tratar como verdadeiro positivo até prova em contrário. O padrão — volume alto, tipo TXT, subdomínios variáveis do mesmo domínio pai — é assinatura de DNS tunneling (T1071.004). Próximos passos: verificar a reputação do domínio pai, olhar no EDR qual processo originou as consultas (um `svchost.exe` legítimo ou um binário desconhecido em pasta de usuário), checar se outras estações fazem o mesmo, e escalar ao N2 com a linha do tempo pronta. Não bloqueie o domínio antes de confirmar que não é um serviço legítimo de segurança ou antivírus, que também usa TXT com volume alto.

</details>


## Bloco 3 — Portas, firewall, proxy e VPN

Este bloco cobre as perguntas de perímetro: portas conhecidas, filtragem, inspeção e acesso remoto. São perguntas que quase sempre caem depois das perguntas de OSI e TCP/IP (tratadas em outro trecho deste módulo). Cada pergunta traz a resposta ideal, o que o entrevistador quer medir e como você se destaca.

### 1) "Quais portas você sabe de cor e o que roda nelas?"

**Resposta ideal:** o entrevistador não espera 200 portas. Ele espera as que aparecem todo dia em log. Analogia: portas são como ramais de um prédio — o endereço IP é a rua e o número do prédio, a porta é o ramal do departamento que atende.

| Porta | Protocolo | Serviço | Observação para o SOC |
|---|---|---|---|
| 20/21 | TCP | FTP (File Transfer Protocol) | Texto claro, credencial visível |
| 22 | TCP | SSH (Secure Shell) | Administração Linux; força bruta é comum |
| 23 | TCP | Telnet | Texto claro; achou saindo? investigue |
| 25 | TCP | SMTP (Simple Mail Transfer Protocol) | Estação enviando na 25 = suspeita de spam bot |
| 53 | UDP/TCP | DNS (Domain Name System) | Exfiltração via DNS tunneling (T1071.004) |
| 67/68 | UDP | DHCP | Servidor DHCP não autorizado |
| 80 | TCP | HTTP | Deve passar pelo proxy |
| 88 | TCP/UDP | Kerberos | Autenticação no Active Directory |
| 110/143 | TCP | POP3 / IMAP | Correio legado sem TLS |
| 123 | UDP | NTP (Network Time Protocol) | Hora errada quebra Kerberos |
| 135 | TCP | RPC Endpoint Mapper | Movimentação lateral |
| 137-139 | TCP/UDP | NetBIOS | Legado; envenenamento por Responder |
| 161 | UDP | SNMP | Community string "public" ainda existe |
| 389 / 636 | TCP | LDAP / LDAPS | Consulta ao diretório |
| 443 | TCP | HTTPS | Onde 90% do malware se esconde |
| 445 | TCP | SMB (Server Message Block) | Compartilhamento de arquivos |
| 465/587 | TCP | SMTP com TLS / submissão | Envio legítimo de e-mail |
| 1194 | UDP | OpenVPN | Base de vários clientes VPN |
| 1433 / 3306 | TCP | MSSQL / MySQL | Banco exposto = incidente |
| 3389 | TCP | RDP (Remote Desktop Protocol) | Alvo número 1 de ransomware |
| 5985 / 5986 | TCP | WinRM HTTP / HTTPS | PowerShell remoto |

**O que o entrevistador está avaliando:** se você lê log sem precisar pesquisar cada número. Velocidade de triagem.

**Como se destacar:** cite a porta e o comportamento esperado. Exemplo: "445 é normal do notebook para o servidor de arquivos 10.20.5.10; não é normal do notebook para 203.0.113.45".

### 2) "Por que a porta 445 saindo para a internet é um problema?"

**Resposta ideal:** SMB é protocolo de rede local, feito para compartilhar arquivo e impressora dentro do escritório. Quando um host interno abre 445 para um IP público, três hipóteses ruins aparecem: tentativa de roubo de credencial (o Windows pode enviar o hash NTLM ao se autenticar num servidor SMB externo), exploração de vulnerabilidade estilo worm, ou exfiltração de arquivo. A regra prática: **445 nunca deve cruzar a borda**, nos dois sentidos.

```
# Palo Alto TRAFFIC (CSV, campos principais)
2026-09-03 14:22:07,014201007777,TRAFFIC,end,10.10.4.87,203.0.113.45,
0.0.0.0,0.0.0.0,Regra-Saida-Internet,CORP\jsilva,,ms-ds-smbv3,vsys1,
Trust,Untrust,ethernet1/2,ethernet1/1,Log-Forward,tcp,allow,
14820,4310,10510,62,445,54233,0,0x400053,...
```

<details><summary>Ver legenda</summary>

| Posição no exemplo | Campo | Valor | O que significa |
|---|---|---|---|
| 1 | Receive Time | `2026-09-03 14:22:07` | Quando o firewall registrou |
| 2 | Serial Number | `014201007777` | Qual equipamento gerou |
| 3 / 4 | Type / Subtype | `TRAFFIC` / `end` | Log de sessão, no fim |
| 5 / 6 | Source / Destination Address | `10.10.4.87` / `203.0.113.45` | **Origem interna e destino na Internet** — e é aí que está o problema |
| 7 / 8 | NAT Source / Destination IP | `0.0.0.0` / `0.0.0.0` | Sem NAT nesta sessão |
| 9 | Rule Name | `Regra-Saida-Internet` | A regra que permitiu |
| 10 / 11 | Source / Destination User | `CORP\jsilva` / `-` | Usuário resolvido |
| 12 | Application | `ms-ds-smbv3` | **O campo decisivo.** App-ID identificou **SMB versão 3** — protocolo de rede local, saindo para a Internet. Não existe motivo legítimo para isso |
| 13 | Virtual System | `vsys1` | Firewall virtual |
| 14 / 15 | Source / Destination Zone | `Trust` / `Untrust` | Confirma o sentido: de dentro para fora |
| 16 / 17 | Inbound / Outbound Interface | `ethernet1/2` / `ethernet1/1` | Interfaces de entrada e saída |
| 18 | Log Action | `Log-Forward` | Perfil de encaminhamento |
| 19 / 20 | Protocol / Action | `tcp` / `allow` | Protocolo e **`allow`: a sessão saiu**, a política não barrou |
| 21 | Bytes | `14820` | Total nos dois sentidos |
| 22 / 23 | Bytes Sent / Received | `4310` / `10510` | Volume em cada direção |
| 24 | Packets | `62` | Total de pacotes |
| 25 / 26 | Destination / Source Port | `445` / `54233` | **445 é SMB.** Neste recorte a porta de destino vem antes da de origem |
| 27 / 28 | NAT Port / Flags | `0` / `0x400053` | Sem tradução e os bits da sessão |
| 29 | *(truncado)* | `...` | O exemplo corta aqui; o formato completo tem mais de 46 campos |

</details>

Campos: origem `10.10.4.87`, destino `203.0.113.45`, usuário `CORP\jsilva`, aplicação `ms-ds-smbv3`, ação `allow`, porta destino `445`, porta origem `54233`, bytes enviados `4310`.

**O que o SOC N1 observa:** normal = 445 apenas entre estação e servidor interno. Suspeito = destino fora de RFC1918, ou muitos destinos internos diferentes na 445 em poucos minutos (varredura / movimentação lateral, T1021.002).

**Erro comum de júnior:** ver `action=allow` e concluir "o firewall liberou, então é permitido". Liberado não é o mesmo que legítimo — a regra pode estar errada.

### 3) "Diferença entre firewall stateful e stateless"

**Resposta ideal:** o stateless é o porteiro que olha só o crachá de cada pessoa, uma por vez, sem lembrar de nada. Ele decide por pacote: IP origem, IP destino, porta, protocolo. O stateful mantém uma **tabela de conexões**: sabe que a estação 10.10.4.87 iniciou a conexão para 198.51.100.30:443, então a resposta que volta é automaticamente permitida, sem precisar de regra de entrada.

```
%ASA-6-302013: Built outbound TCP connection 88214 for outside:198.51.100.30/443
 (198.51.100.30/443) to inside:10.10.4.87/51422 (203.0.113.10/51422)
%ASA-6-302014: Teardown TCP connection 88214 for outside:198.51.100.30/443
 to inside:10.10.4.87/51422 duration 0:02:11 bytes 24880 TCP FINs
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `%ASA` | `%ASA` | Etiqueta do produto: identifica a linha como vinda de um firewall ASA |
| severidade | `6` | Escala syslog do Cisco, de 0 (emergência) a 7 (depuração): `6` é **informational**. **Severidade baixa não quer dizer evento sem importância** — quem a escolhe é o fabricante, não o seu SOC |
| *message ID* | `302013` | Conexão TCP construída — entrou na tabela de estado. **É por este número que se escreve a regra no SIEM**: o texto da mensagem muda entre versões do software, o ID não |
| direção | `outbound` | **Quem iniciou**, não a direção dos bytes: `outbound` é de dentro para fora, `inbound` é de fora para dentro |
| id da conexão | `88214` | Número da conexão na tabela de estado. **É a chave para casar com o `302014`** que a encerra |
| lado remoto | `outside:198.51.100.30/443` | Interface, IP e porta do host **remoto**. Vem primeiro, logo depois do `for` — é isso que faz a linha parecer invertida |
| *(entre parênteses)* | `(198.51.100.30/443)` | O endereço **traduzido** desse lado. Igual ao real significa que não houve NAT nesta ponta |
| lado local | `inside:10.10.4.87/51422` | Interface, IP e porta do host **local**, antes da tradução |
| *(entre parênteses)* | `(203.0.113.10/51422)` | O endereço com que o host local saiu. **Este par — IP público mais porta — é o que desfaz o NAT** num pedido externo |
| *message ID* (2ª linha) | `302014` | Conexão TCP encerrada. **Contar `302013` e `302014` como dois eventos duplica a mesma sessão** no relatório |
| id da conexão | `88214` | O **mesmo** número da 1ª linha: é assim que se sabe que falam da mesma conexão |
| `duration` | `0:02:11` | Quanto tempo a conexão viveu, em `h:mm:ss` |
| `bytes` | `24880` | Total transferido na sessão. **Só existe no `302014`** — quando o `302013` é escrito, ainda não há o que contar |
| motivo | `TCP FINs` | Como terminou: `TCP FINs` é fim limpo nos dois sentidos; `TCP Reset-O` é RST vindo de fora (**O** de *Outside*); `TCP Reset-I` de dentro; `SYN Timeout` nunca completou; `Deny Terminate` a política cortou |

</details>


**Como se destacar:** diga que stateless ainda é usado em ACL de roteador e em regras de altíssimo volume, porque é barato em CPU.

### 4) "O que é um NGFW?"

**Resposta ideal:** NGFW (Next-Generation Firewall) é o firewall stateful mais identificação de **aplicação** (não confia só na porta), **identidade de usuário** (integra com o Active Directory), IPS embutido, filtro de URL e inspeção TLS. Exemplo: tráfego na porta 443 que o NGFW classifica como `bittorrent` em vez de `web-browsing`, mesmo estando na porta "de site".

**Erro comum de júnior:** achar que porta 443 significa navegação web.

### 5) "Como funciona um proxy e o que ele registra que o firewall não registra?"

**Resposta ideal:** o proxy é o despachante: em vez de você ir até o destino, você pede a ele e ele vai buscar. Por isso ele enxerga a **camada 7**: URL completa, método HTTP, User-Agent, categoria do site, tamanho da resposta e o usuário autenticado. O firewall vê IP, porta e bytes.

```
# Squid access.log
1756907231.482  312 10.10.4.87 TCP_MISS/200 41822 GET
http://arquivos.empresa-exemplo.com.br/relatorio.zip jsilva
DIRECT/198.51.100.77 application/zip

# Zscaler NSS (resumido)
2026-09-03 14:41:10 user=maria.costa@example.com action=blocked
url=hxxp://cdn-update.example-mal.test/panel.php urlcategory=Newly_Registered_Domains
reqmethod=POST reqsize=118 respsize=0 useragent=curl/8.4.0 clientip=10.10.7.22
```

<details><summary>Ver legenda</summary>

| Campo (Squid ou Zscaler) | Valor no exemplo | O que significa |
|---|---|---|
| Squid · *timestamp* | `1756907231.482` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos |
| Squid · duração | `312` | Milissegundos para atender |
| Squid · cliente | `10.10.4.87` | O IP de origem — o dado que o destino não vê |
| Squid · resultado/status | `TCP_MISS/200` | Buscou na origem e recebeu 200 OK |
| Squid · bytes | `41822` | 41 KB entregues |
| Squid · URL e usuário | `…/relatorio.zip` · `jsilva` | O recurso e a conta autenticada no proxy |
| Squid · hierarquia | `DIRECT/198.51.100.77` | Foi direto à origem |
| Zscaler · `action` | `blocked` | O veredito da política |
| Zscaler · `url` | `hxxp://cdn-update.example-mal.test/panel.php` | O destino. Escrito `hxxp` de propósito, para o link não ser clicável em relatório |
| Zscaler · `urlcategory` | `Newly_Registered_Domains` | **Domínio registrado há dias.** Infraestrutura de ataque é nova por natureza — é das categorias mais úteis para triagem |
| Zscaler · `reqmethod` / `reqsize` / `respsize` | `POST` · `118` · `0` | `POST` envia dados; 118 bytes subindo e **nada a descer** é o retrato de um beacon barrado |
| Zscaler · `useragent` | `curl/8.4.0` | **Ferramenta de linha de comando, não navegador.** Numa estação de usuário é anomalia por si só |
| Zscaler · `clientip` | `10.10.7.22` | A estação de origem |

</details>


**O que o SOC N1 observa:** normal = User-Agent de navegador conhecido e categoria de negócio. Suspeito = POST repetitivo para domínio novo, User-Agent de ferramenta (curl, python-requests, PowerShell).

### 6) "O que é inspeção TLS e o que ela quebra?"

**Resposta ideal:** TLS (Transport Layer Security) cifra o conteúdo. Na inspeção TLS o proxy/NGFW termina a sessão, abre, inspeciona e refaz a criptografia com um certificado da própria empresa — por isso a máquina precisa confiar na CA (Autoridade Certificadora) interna. Quebra: aplicações com **certificate pinning** (bancos, apps móveis), autenticação mútua por certificado (mTLS), e há dados sensíveis que por política ficam fora da inspeção (saúde, financeiro).

**Como se destacar:** mencione que quando o destino está na lista de "não inspecionar", o SOC perde visibilidade de conteúdo e precisa se apoiar em metadados TLS — JA3/JA4, SNI e certificado — via `ssl.log` do Zeek.

```
# Zeek ssl.log (campos selecionados)
ts=1756907512.331 id.orig_h=10.10.7.22 id.resp_h=203.0.113.88 id.resp_p=443
server_name=cdn-update.example-mal.test version=TLSv13
ja3=51c64c77e60f3980eea90869b68c58a8 validation_status="self signed certificate"
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `ts` | `1756907512.331` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos |
| `id.orig_h` | `10.10.7.22` | O cliente interno |
| `id.resp_h` / `id.resp_p` | `203.0.113.88` / `443` | Destino externo em HTTPS |
| `server_name` | `cdn-update.example-mal.test` | O SNI. **Visível mesmo sem inspeção de TLS** — é o que salva a investigação quando o destino está na lista de não-inspecionar |
| `version` | `TLSv13` | Versão do TLS negociada |
| `ja3` | `51c64c77e60f3980eea90869b68c58a8` | Impressão digital do cliente. Continua visível mesmo sem descriptografar |
| `validation_status` | `self signed certificate` | O certificado é autoassinado. Contra um destino de internet, com SNI de domínio recém-criado, é achado clássico |

</details>

Certificado autoassinado em destino de internet, com SNI de domínio novo, é achado clássico.

### 7) "Diferença entre IPsec VPN e SSL VPN"

**Resposta ideal:** IPsec (Internet Protocol Security) opera na camada 3, cifra o pacote IP inteiro e é o padrão para túnel **site a site** entre matriz e filial; usa IKE em UDP 500, NAT-T em UDP 4500 e os protocolos ESP/AH. SSL VPN (ou TLS VPN) roda sobre TLS na porta 443 e é o padrão para **usuário remoto**, porque atravessa qualquer rede de hotel ou 4G sem bloqueio.

**Erro comum de júnior:** confundir "VPN" com "anonimato". VPN corporativa é acesso, não anonimato.

### 8) "Split tunnel vs full tunnel"

**Resposta ideal:** no **full tunnel** todo o tráfego do usuário sobe pela VPN, inclusive a navegação — o SOC vê tudo, mas consome banda e concentrador. No **split tunnel** só o que é destinado à rede corporativa entra no túnel; o resto sai pela internet do usuário — melhor desempenho, **ponto cego** para o SOC, a menos que exista agente de proxy em nuvem no endpoint.

| Critério | Full tunnel | Split tunnel |
|---|---|---|
| Visibilidade do SOC | Alta | Baixa (só tráfego corporativo) |
| Consumo de link | Alto | Baixo |
| Risco de ponte para a internet | Menor | Maior |

**Como se destacar:** diga que em split tunnel a telemetria de EDR e o proxy em nuvem passam a ser sua fonte principal.

## Bloco 4 — Windows, Active Directory e Linux

### 9) "O que é o Active Directory e o que é um controlador de domínio?"

**Resposta ideal:** o Active Directory (AD) é a agenda e o cartório da empresa: guarda usuários, computadores, grupos e políticas. O **controlador de domínio (DC)** é o servidor que hospeda essa base e responde às autenticações. Um domínio de exemplo: `corp.local`, com DC em `10.10.1.10`. É onde nascem os eventos 4624, 4625, 4768 e 4769 que o SOC lê o dia inteiro.

### 10) "Como funciona o Kerberos?"

**Resposta ideal:** analogia do parque de diversões. Você mostra o documento na bilheteria e recebe uma **pulseira** (TGT — Ticket Granting Ticket, evento 4768). Para entrar em cada brinquedo você troca a pulseira por um **ingresso do brinquedo** (Service Ticket, evento 4769). Nenhuma senha circula de novo. Depende de relógio sincronizado (tolerância padrão de 5 minutos) e usa a porta 88.

```
EventID 4768  Account Name: jsilva  Service Name: krbtgt  Client Address: 10.10.4.87
              Ticket Encryption Type: 0x12  Result Code: 0x0
EventID 4769  Account Name: jsilva@CORP.LOCAL  Service Name: MSSQLSvc/db01.corp.local
              Ticket Encryption Type: 0x17  Client Address: 10.10.4.87
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `EventID` | `4768` / `4769` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não. `4768` = **TGT** do Kerberos pedido — nasce no controlador de domínio; `4769` = **ticket de serviço** do Kerberos pedido (o "crachá de sala") |
| `Account Name` | `jsilva` / `jsilva@CORP.LOCAL` | A conta envolvida. Terminada em `$` é **conta de computador**, não de pessoa |
| `Service Name` | `krbtgt` / `MSSQLSvc/db01.corp.local` | O serviço para o qual o ticket foi pedido. Terminado em `$` é uma conta de computador |
| `Client Address` | `10.10.4.87` | IP do cliente que pediu o ticket. Vem como `::ffff:10.10.10.50` — **é IPv4 embrulhado em notação IPv6**, não um endereço IPv6 |
| `Ticket Encryption Type` | `0x12` / `0x17` | **Cifra do ticket.** `0x12` = **AES256** — o normal num domínio moderno; `0x17` = **RC4** — fraco; pedido num domínio que usa AES pode indicar *Kerberoasting* |
| `Result Code` | `0x0` | **Código de resultado do Kerberos.** `0x0` = sucesso |

</details>

**O que o SOC N1 observa:** `Ticket Encryption Type 0x12` é AES256 (bom). `0x17` é RC4 — quando aparece em massa e para muitos serviços diferentes vindo de um único host, é indício de Kerberoasting (T1558.003). Erro comum: alertar em todo 4769 com RC4; muitos ambientes legados geram isso o tempo todo, o sinal está no **volume e na variedade de serviços**.

### 11) "O que é NTLM e por que o hash é perigoso?"

**Resposta ideal:** NTLM (NT LAN Manager) é o método antigo de autenticação, por desafio-resposta. O problema é que o **hash da senha funciona como a própria senha**: quem consegue o hash da memória autentica-se sem nunca descobrir o texto da senha. Aparece no evento 4776 (validação de credencial) e no 4624 com `Logon Process: NtLmSsp` e `Authentication Package: NTLM`.

### 12) "O que é pass-the-hash?"

**Resposta ideal:** é reusar o hash NTLM roubado para autenticar como o usuário em outra máquina (T1550.002). Ferramentas como Mimikatz e o conjunto Impacket são associadas à técnica — aqui o SOC N1 se preocupa apenas com o **rastro**: 4624 tipo 3 (rede) com NTLM, para uma conta administrativa, vindo de uma estação de usuário e não de um servidor de administração; muitas vezes seguido de criação de serviço (7045) e 4688 de processo incomum.

```
EventID 4624  Logon Type: 3  Account Name: admin.rodrigo
              Workstation Name: NB-JSILVA  Source Network Address: 10.10.4.87
              Logon Process: NtLmSsp  Authentication Package: NTLM
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `EventID` | `4624` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não. `4624` = logon **bem-sucedido** |
| `Logon Type` | `3` | **Como a sessão foi iniciada.** `3` = **rede** — acesso a compartilhamento, RPC, WinRM. É o tipo que domina em movimento lateral |
| `Account Name` | `admin.rodrigo` | A conta envolvida. Terminada em `$` é **conta de computador**, não de pessoa |
| `Workstation Name` | `NB-JSILVA` | Nome que a máquina de origem **declarou**. Vem do próprio cliente, logo é falsificável — trate como pista, não como identidade |
| `Source Network Address` | `10.10.4.87` | **IP de origem.** Vazio ou `-` significa que a sessão foi local, e `::1`/`127.0.0.1` que veio da própria máquina |
| `Logon Process` | `NtLmSsp` | Componente que processou o logon (`Kerberos`, `NtLmSsp`, `User32`, `Advapi`) |
| `Authentication Package` | `NTLM` | Pacote que autenticou: `Kerberos`, `NTLM` ou `Negotiate` |

</details>

```spl
index=windows EventCode=4624 Logon_Type=3 Authentication_Package=NTLM
| search Account_Name="admin*"                    ' foca contas administrativas
| stats dc(ComputerName) AS destinos values(ComputerName) BY Account_Name, src_ip
| where destinos > 3                              ' uma conta atingindo muitos hosts
```

```kql
SecurityEvent
| where EventID == 4624 and LogonType == 3 and AuthenticationPackageName == "NTLM"
| where TargetUserName startswith "admin"          // contas privilegiadas
| summarize destinos = dcount(Computer) by TargetUserName, IpAddress, bin(TimeGenerated, 1h)
| where destinos > 3                               // dispersão anormal
```

### 13) "O que é uma GPO?"

**Resposta ideal:** GPO (Group Policy Object) é a regra da casa aplicada automaticamente: define política de senha, firewall local, mapeamento de unidade, quem pode fazer logon local. Aplica-se a OU (Unidade Organizacional), site ou domínio. Para o SOC importa porque **alteração de GPO é vetor de persistência e distribuição em massa** — monitore o evento 5136 (objeto do diretório modificado) e mudanças na SYSVOL.

### 14) "Quais comandos Linux você usaria para investigar tentativas de login?"

**Resposta ideal:** o alvo é `/var/log/auth.log` (Debian/Ubuntu) ou `/var/log/secure` (RHEL), além do `journalctl`.

```bash
# 10 IPs com mais falhas de senha por SSH
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head
# logins aceitos, com método e IP
grep "Accepted" /var/log/auth.log
# via systemd, últimas 2 horas do serviço SSH
journalctl -u ssh --since "2 hours ago"
# quem está logado agora / histórico de sessões / falhas
who ; last -n 20 ; lastb -n 20
```

**O que o SOC N1 observa:** normal = poucas falhas seguidas de sucesso do mesmo usuário. Suspeito = centenas de `Failed password` de um IP e **depois** um `Accepted password` — força bruta bem-sucedida (T1110).

### 15) "Como você vê as conexões de rede abertas no Windows e no Linux?"

**Resposta ideal:**

| Objetivo | Windows | Linux |
|---|---|---|
| Conexões + PID | `netstat -ano` | `ss -tunap` |
| Só em escuta | `netstat -anob` (elevado) | `ss -ltnp` |
| Resolver PID em nome | `tasklist /fi "pid eq 4321"` | `ps -p 4321 -o pid,user,cmd` |
| Histórico (não ao vivo) | Sysmon Event ID 3 | Zeek `conn.log` |

```
# Sysmon Event ID 3 (Network connection detected)
Image: C:\Users\jsilva\AppData\Local\Temp\update.exe  User: CORP\jsilva
Protocol: tcp  SourceIp: 10.10.4.87  SourcePort: 51877
DestinationIp: 203.0.113.45  DestinationPort: 443  Initiated: true
```

**Erro comum de júnior:** rodar `netstat` e concluir "não tem nada, está limpo". O comando é uma foto do instante; malware com beacon periódico não aparece entre um batimento e outro. Use Sysmon 3 ou o `conn.log` do Zeek para ver o histórico.

### Exercícios — Perguntas de portas, firewall, proxy, VPN, Windows/AD e Linux

1. Na entrevista mostram este log e perguntam se é verdadeiro ou falso positivo:
   `TRAFFIC ... 10.10.4.87 -> 10.20.5.10 app=ms-ds-smbv3 dport=445 action=allow bytes=3.2MB`. Responda e justifique.
2. O proxy registra `clientip=10.10.7.22 useragent=python-requests/2.31 url=hxxp://api-status.example-mal.test/i.php method=POST` a cada 60 segundos, sempre com 118 bytes. Que hipótese você levanta e qual é o próximo passo?
3. Você recebe 4769 com `Ticket Encryption Type 0x17` para 12 nomes de serviço diferentes, todos em 90 segundos, originados de `10.10.4.87` com a conta `maria.costa`. Falso positivo ou investigação?
4. Um usuário reclama que o site do banco parou de abrir depois que entrou na VPN full tunnel. Qual a causa mais provável e o que você verifica?
5. Em `/var/log/auth.log` há 480 linhas `Failed password for invalid user admin from 198.51.100.14` e, ao final, `Accepted password for svc_backup from 198.51.100.14`. Qual a sua conclusão e a ação imediata?

<details><summary>Ver gabarito</summary>

1. **Falso positivo provável.** Destino `10.20.5.10` é RFC1918, ou seja, servidor interno — SMB dentro da rede é o uso normal do protocolo (cópia de arquivo, perfil, compartilhamento). O que tornaria isso suspeito seria destino público, ou o mesmo host falando 445 com dezenas de IPs internos em poucos minutos. Volume de 3,2 MB sozinho não é indicador.

2. **Hipótese: beacon de command and control (T1071.001).** As três marcas são o intervalo fixo de 60 segundos, o tamanho constante da requisição e o User-Agent de biblioteca (`python-requests`) numa estação de usuário. Próximo passo: verificar a categoria e a idade do domínio no proxy, buscar o mesmo destino em outros hosts, e pedir ao EDR o processo que originou a conexão (Sysmon Event ID 3 correlacionado por PID). Só então decidir bloqueio e isolamento.

3. **Investigar.** RC4 (`0x17`) isolado é comum em ambientes legados, mas 12 Service Principal Names distintos em 90 segundos a partir de um único host é o padrão de **Kerberoasting** (T1558.003) — pedir tickets em massa para depois tentar quebrá-los offline. Ação N1: preservar os eventos, listar quais serviços foram alvo, checar se `maria.costa` tem motivo de negócio para acessá-los e escalar ao N2.

4. **Inspeção TLS com certificate pinning.** Em full tunnel a navegação passa pelo proxy corporativo, que substitui o certificado; o app ou site do banco rejeita o certificado emitido pela CA interna. Verificação: confirmar se o domínio está na lista de exceção de inspeção e olhar o log do proxy procurando falha de handshake ou bloqueio por validação de certificado. Não é incidente de segurança, é ajuste de política.

5. **Força bruta bem-sucedida (T1110).** As 480 falhas com usuários inválidos e o sucesso final, do **mesmo IP**, indicam comprometimento da conta de serviço `svc_backup` — que ainda por cima não deveria aceitar autenticação por senha vinda da internet. Ação imediata: bloquear `198.51.100.14` na borda, encerrar as sessões da conta, acionar a rotação da credencial pelo time responsável (via cofre de segredos, nunca em texto), verificar `last`, chaves em `~/.ssh/authorized_keys` e tarefas agendadas criadas depois do horário do acesso, e escalar como incidente.

</details>


## Perguntas de logs, SIEM, ameaças, processo e comportamentais

Esta é a parte da entrevista em que o candidato deixa de recitar teoria e mostra se sabe **operar**. O entrevistador quer descobrir uma coisa simples: quando o alerta piscar às 3 da manhã, você vai saber o que olhar primeiro? Responda sempre com a mesma espinha: **o que é** → **como funciona** → **exemplo** → **como aparece no log** → **o que eu observaria**.

### 1. Qual a diferença entre evento, alerta e incidente?

Pense numa portaria de prédio. Cada pessoa que passa pela catraca é um **evento**. Quando o porteiro estranha alguém e liga para o interfone, isso é um **alerta**. Quando se confirma que o sujeito entrou no apartamento errado e levou algo, aí sim é um **incidente**.

| Termo | Definição | Volume típico/dia | Quem trata |
|---|---|---|---|
| Evento | Qualquer registro de atividade (log) | Milhões | Ninguém, fica indexado |
| Alerta | Evento que bateu numa regra de detecção | Dezenas a centenas | SOC N1 (triagem) |
| Incidente | Alerta confirmado com impacto real ou potencial | Poucos | N2 / resposta a incidentes |

**Como aparece nos logs** — um evento cru de autenticação bem-sucedida no Windows Security:

```
EventID=4624
Account Name: jsilva
Account Domain: CORP
Logon Type: 3
Source Network Address: 10.10.20.45
Logon Process: NtLmSsp
Authentication Package: NTLM
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `EventID` | `4624` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não. `4624` = logon **bem-sucedido** |
| `Account Name` | `jsilva` | A conta envolvida. Terminada em `$` é **conta de computador**, não de pessoa |
| `Account Domain` | `CORP` | Domínio da conta |
| `Logon Type` | `3` | **Como a sessão foi iniciada.** `3` = **rede** — acesso a compartilhamento, RPC, WinRM. É o tipo que domina em movimento lateral |
| `Source Network Address` | `10.10.20.45` | **IP de origem.** Vazio ou `-` significa que a sessão foi local, e `::1`/`127.0.0.1` que veio da própria máquina |
| `Logon Process` | `NtLmSsp` | Componente que processou o logon (`Kerberos`, `NtLmSsp`, `User32`, `Advapi`) |
| `Authentication Package` | `NTLM` | Pacote que autenticou: `Kerberos`, `NTLM` ou `Negotiate` |

</details>

Isso é só evento. Vira alerta se a regra disser "Logon Type 3 com NTLM vindo de fora da faixa de estações". Vira incidente se `jsilva` estiver de férias e a origem for uma máquina que ele nunca usou.

**Erro comum de júnior:** chamar tudo de "incidente" no ticket. Isso infla métrica, assusta gestão e queima credibilidade.

### 2. O que é um falso positivo e como você lida com ele?

**Falso positivo (FP)** é o alarme de incêndio que dispara com a fumaça da torrada. A regra funcionou, o comportamento é real, mas **não é malicioso**.

Fluxo correto: confirmar que é FP com evidência → documentar no ticket **por que** é FP → propor ajuste de regra (tuning) ou exceção documentada → nunca fechar em silêncio.

**Exemplo:** o scanner de vulnerabilidade `10.10.5.9` gera 800 alertas de port scan toda terça de madrugada.

```
Nov 12 02:14:03 fw01 date=2026-11-12 time=02:14:03 devname="fw01" type="traffic" subtype="forward" action="deny" srcip=10.10.5.9 dstip=10.10.20.45 dstport=445 proto=6 policyid=12 service="SMB" msg="scan detected"
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `date` | `2026-11-12` | Data local **do equipamento**, não UTC. Correlacionar com um log em UTC sem acertar o fuso desalinha a timeline |
| `time` | `02:14:03` | Hora local do equipamento |
| `devname` | `"fw01"` | Nome do equipamento que gerou o log |
| `type` | `"traffic"` | Categoria do log: `traffic` é sessão, `event` é evento do próprio aparelho, `utm` é inspeção de conteúdo |
| `subtype` | `"forward"` | Subcategoria: `forward` é tráfego que atravessa, `local` é destinado ao próprio firewall, `vpn` é túnel, `webfilter` e `ips` são inspeção |
| `action` | `"deny"` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |
| `srcip` | `10.10.5.9` | IP de origem |
| `dstip` | `10.10.20.45` | IP de destino |
| `dstport` | `445` | Porta de destino — é ela que aponta o serviço |
| `proto` | `6` | Número do protocolo IP: **`6` é TCP, `17` é UDP, `1` é ICMP**. Vem em número, não em nome |
| `policyid` | `12` | **Número da regra que decidiu.** Sem ele não se sabe por que o tráfego passou ou parou |
| `service` | `"SMB"` | Nome do **objeto de serviço** do FortiGate, não a porta literal. Um objeto chamado `HTTPS` pode ter sido configurado noutra porta |
| `msg` | `"scan detected"` | Texto livre com a descrição legível. **Não use este campo em regras** — muda entre versões |

</details>

**Erro comum de júnior:** fechar como FP porque "sempre foi FP". Ataque real muitas vezes se esconde exatamente no ruído que ninguém olha mais.

### 3. O que é IOC e o que é IOA?

**IOC (Indicator of Compromise / indicador de comprometimento)** é a pegada deixada: hash de arquivo, IP, domínio, chave de registro. É **passado**, é fato.
**IOA (Indicator of Attack / indicador de ataque)** é o comportamento: "processo do Word criou um processo de shell". É **presente**, é intenção.

IOC morre rápido (o atacante troca o IP em minutos). IOA sobrevive porque a técnica é mais cara de trocar.

```
Sysmon EventID=1
Image: C:\Windows\System32\cmd.exe
ParentImage: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
User: CORP\maria.costa
CommandLine: cmd.exe /c whoami
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `EventID` | `1` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não. `1` = Sysmon **Process Create** |
| `Image` | `C:\Windows\System32\cmd.exe` | Caminho do executável (nomenclatura do Sysmon) |
| `ParentImage` | `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE` | Caminho do processo **pai**. **É aqui que o Sysmon brilha**: Word ou Excel como pai de `powershell.exe` é sinal forte por si só |
| `User` | `CORP\maria.costa` | Conta sob a qual o processo corre |
| `CommandLine` | `cmd.exe /c whoami` | Linha de comando. `-enc` indica comando em Base64 e `-w hidden` janela oculta |

</details>

Esse é um IOA clássico — Word não deveria ser pai de `cmd.exe`.

### 4. Explique a Pirâmide da Dor

Modelo do David Bianco: quanto mais alto o indicador, mais **dói** para o atacante trocá-lo.

| Nível | Indicador | Dor para o atacante |
|---|---|---|
| 1 | Hash de arquivo | Trivial (muda 1 byte) |
| 2 | Endereço IP | Fácil |
| 3 | Domínio | Simples |
| 4 | Artefato de rede/host (User-Agent, mutex) | Irritante |
| 5 | Ferramenta (Mimikatz, Impacket) | Desafiador |
| 6 | TTP (táticas, técnicas e procedimentos) | **Muito difícil** |

Bloquear hash gera trabalho eterno. Detectar a TTP "dump de credenciais via acesso ao LSASS" pega qualquer ferramenta que faça aquilo.

### 5. O que é o MITRE ATT&CK e como você o usa na triagem?

É um catálogo público de comportamentos de atacantes, organizado em táticas (o objetivo) e técnicas (o modo). Na triagem serve para três coisas: **classificar** o alerta, **prever** o próximo passo e **preencher a lacuna** de visibilidade.

| Tática | Técnica | Código |
|---|---|---|
| Acesso inicial | Phishing | T1566 |
| Execução | Interpretador de comandos | T1059 |
| Acesso a credenciais | Força bruta / password spraying | T1110.003 |
| Comando e controle | Canal de C2 em protocolo de aplicação | T1071 |
| Exfiltração | Exfiltração por canal de C2 | T1041 |

Se o alerta é T1110.003, eu já sei que o passo seguinte do atacante costuma ser movimento lateral — e vou olhar 4624 Logon Type 3 nas horas seguintes.

### 6. Como você investiga um alerta de phishing do início ao fim?

1. **Preservar** o e-mail original (cabeçalhos completos, não print).
2. **Cabeçalhos**: SPF, DKIM e DMARC; conferir se `Return-Path` bate com o `From` exibido.
3. **Detonar** anexo/URL em sandbox — nunca clicar da estação de trabalho.
4. **Escopo**: quem mais recebeu o mesmo remetente/assunto?
5. **Clique**: alguém abriu o link? Olhar proxy.
6. **Pós-clique**: houve download, execução, autenticação no domínio falso?
7. **Contenção**: purgar da caixa, bloquear domínio, resetar senha se houve credencial digitada.

```
1731398400.221   482 10.10.20.45 TCP_MISS/200 15233 GET http://login-corp-acesso.example.com/auth - HIER_DIRECT/203.0.113.77 text/html "Mozilla/5.0"
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| *timestamp* | `1731398400.221` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos |
| duração | `482` | Milissegundos para atender |
| cliente | `10.10.20.45` | A estação — **é este registro que transforma "e-mail suspeito" em "o usuário clicou"** |
| resultado/status | `TCP_MISS/200` | A página de phishing carregou com sucesso |
| bytes | `15233` | 15 KB entregues: a página inteira, com o formulário |
| método | `GET` | Pedido de leitura |
| URL | `http://login-corp-acesso.example.com/auth` | O domínio imita portal de login corporativo, e `/auth` é a página de credenciais |
| usuário | `-` | Sem autenticação no proxy nesse pedido |
| hierarquia/destino | `HIER_DIRECT/203.0.113.77` | O IP do servidor de phishing |
| tipo de conteúdo | `text/html` / `"Mozilla/5.0"` | O MIME e, no fim, o *user-agent* do navegador — sinal de que foi uma pessoa, não um script |

</details>

Squid mostrando `10.10.20.45` acessando o domínio de phishing: passou de "e-mail suspeito" para "usuário clicou".

**Erro comum de júnior:** parar no "usuário não clicou" sem verificar os outros 40 destinatários.

### 7. Como você identifica beaconing?

Beacon é o malware ligando para casa em intervalos regulares — como um funcionário que sai para fumar exatamente de 5 em 5 minutos. Humano navega de forma irregular; máquina não.

Sinais: intervalo com baixa variação (jitter), tamanho de resposta quase constante, longa duração, destino sem reputação.

```
# SPL — Splunk: procura destinos com intervalo muito regular
index=network sourcetype=zeek:conn src_ip=10.10.20.45
| bin _time span=1m
| stats count by _time, id.resp_h
| stats avg(count) as media stdev(count) as desvio by id.resp_h
| eval razao=desvio/media
| where razao<0.15 AND media>3
```

```kql
// KQL — Sentinel: conexões repetidas ao mesmo destino com bytes constantes
CommonSecurityLog
| where DeviceVendor == "Palo Alto Networks"
| summarize conexoes=count(), bytesDistintos=dcount(SentBytes) by SourceIP, DestinationIP
| where conexoes > 200 and bytesDistintos < 5
```

### 8. Como detecta password spraying e por que a regra de brute force não pega?

Força bruta = muitas senhas contra **uma** conta. Password spraying = **uma** senha contra muitas contas. A regra clássica ("5 falhas na mesma conta em 5 minutos") nunca dispara, porque cada conta falha só uma ou duas vezes.

A detecção certa inverte o eixo: contar **contas distintas** falhando a partir da **mesma origem**.

```
EventID=4625  Account Name: maria.costa  Source Network Address: 203.0.113.50  Status: 0xC000006A
EventID=4625  Account Name: jsilva       Source Network Address: 203.0.113.50  Status: 0xC000006A
EventID=4625  Account Name: svc_backup   Source Network Address: 203.0.113.50  Status: 0xC000006A
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `EventID` | `4625` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não. `4625` = **falha** de logon |
| `Account Name` | `maria.costa` / `jsilva` / `svc_backup` | A conta envolvida. Terminada em `$` é **conta de computador**, não de pessoa |
| `Source Network Address` | `203.0.113.50` | **IP de origem.** Vazio ou `-` significa que a sessão foi local, e `::1`/`127.0.0.1` que veio da própria máquina |
| `Status` | `0xC000006A` | Código geral do resultado. `0xC000006A` = **senha errada** |

</details>

`0xC000006A` = senha errada. `0xC0000064` = usuário inexistente (sinal de enumeração).

```kql
// KQL — muitas contas distintas falhando da mesma origem em 30 min
SecurityEvent
| where EventID == 4625
| summarize contas=dcount(TargetUserName) by IpAddress, bin(TimeGenerated, 30m)
| where contas >= 10
```

O grande achado é o **4624 no meio dos 4625** — um sucesso significa que a senha fraca funcionou.

### 9. Sinais precoces de ransomware e o que você faz primeiro?

Antes da tela de resgate: apagamento de cópias de sombra, parada de serviços de backup/antivírus, pico de escritas em compartilhamento, renomeação em massa de arquivos, criação de conta administrativa nova.

**Primeiro passo: contenção da máquina** (isolar host na rede via EDR), preservar memória e disco, **não desligar** o equipamento (perde memória volátil), escalar imediatamente para N2 e acionar o plano de resposta.

**Erro comum de júnior:** reiniciar a máquina "para limpar". Isso destrói evidência e não interrompe o que já está criptografado.

### 10. Como você prioriza com 50 alertas na fila?

Critérios, nesta ordem: **criticidade do ativo** (controlador de domínio > notebook), **fase da cadeia de ataque** (C2 e exfiltração ganham de recon), **quantidade de hosts afetados**, **irreversibilidade** (dado saindo não volta) e **idade do alerta**. Explique que agrupa alertas duplicados do mesmo host num único ticket antes de contar a fila — 50 alertas costumam ser 6 casos.

### 11. O que você faz quando não sabe a resposta?

Resposta que passa: "digo que não sei, explico até onde consegui chegar, e mostro como eu buscaria." Cite a ordem real: playbook interno → documentação do fabricante → base de conhecimento do SOC → colega do turno → escalar antes do prazo estourar. Nunca chutar num ticket, porque a próxima pessoa lê aquilo como verdade.

### 12. Conte um erro que você cometeu

Escolha um erro **real, técnico e já corrigido**. Exemplo: "fechei como falso positivo um alerta de acesso ao LSASS porque a ferramenta era conhecida da equipe de TI; não confirmei com o dono do processo. Passei a exigir confirmação por escrito e escrevi essa regra no playbook." O entrevistador quer ver aprendizado e ausência de desculpa.

### 13. Por que você quer trabalhar em SOC?

Fuja de "gosto de segurança". Ancore em algo concreto: rotina investigativa, aprendizado acelerado em rede e sistemas, gosto por trabalhar com evidência, vontade de virar analista de resposta a incidentes ou caçador de ameaças. Mostre que entende que N1 é **volume e disciplina**, não filme de hacker.

### 14. Como você lida com turno noturno e pressão?

Fale de sistema, não de heroísmo: rotina de sono fixa mesmo na folga, checklist de passagem de turno, hidratação e pausas, e o hábito de escalar cedo em vez de segurar o problema. Sob pressão: seguir o playbook, registrar tudo, comunicar status parcial de hora em hora.

### 15. Como você documenta uma investigação?

Estrutura mínima: **resumo em uma linha** → linha do tempo em UTC → evidências com nome do campo e fonte do log → hipóteses testadas (inclusive as descartadas) → conclusão e classificação → ações tomadas → recomendação. Regra de ouro: escreva para o colega que vai ler daqui a seis meses sem você por perto.

### Use STAR nas comportamentais

**S**ituação (contexto em uma frase) → **T**arefa (o que era sua responsabilidade) → **A**ção (o que **você** fez, no singular) → **R**esultado (número, prazo, aprendizado). Prepare três histórias STAR: um erro, um conflito e uma entrega sob pressão. Elas cobrem 80% das perguntas comportamentais.

### Exercícios — Perguntas de logs, SIEM, ameaças, processo e comportamentais

1. Em 30 minutos, o IP `203.0.113.50` gerou 4625 contra 22 contas distintas, com no máximo 2 falhas por conta, e um único 4624 para `svc_backup`. Classifique o padrão e diga o próximo passo.
2. O host `10.10.20.45` conectou-se a `198.51.100.9` na porta 443 exatamente 288 vezes em 24 horas, sempre com resposta entre 512 e 540 bytes. Verdadeiro positivo ou falso positivo? Justifique.
3. Um analista fechou como falso positivo um Sysmon EventID 1 com `WINWORD.EXE` como pai de `powershell.exe`, alegando "macro de planilha da equipe financeira". O que faltou na análise?
4. Classifique cada indicador na Pirâmide da Dor: (a) hash SHA256 do binário; (b) o domínio `login-corp-acesso.example.com`; (c) a técnica "dump de credenciais do LSASS"; (d) o IP `203.0.113.77`.
5. Chegam simultaneamente: (a) port scan de fora bloqueado no firewall; (b) EDR detectando apagamento de cópias de sombra num servidor de arquivos; (c) 4625 isolado de `jsilva`. Ordene por prioridade e explique.

<details><summary>Ver gabarito</summary>

1. **Password spraying (T1110.003)**, não força bruta — o eixo é "muitas contas, poucas tentativas cada", vindo de uma origem única. A regra de brute force não dispara porque nenhuma conta chega ao limite de falhas. O ponto crítico é o **4624 de `svc_backup`**: o spray teve sucesso. Próximo passo: tratar como incidente, desabilitar ou resetar a senha de `svc_backup`, verificar o que essa conta acessou depois do logon bem-sucedido (4672, 4768/4769, acessos a compartilhamento) e bloquear `203.0.113.50` na borda.

2. Fortemente indicativo de **beaconing (verdadeiro positivo a investigar)**. 288 conexões em 24 horas é exatamente uma a cada 5 minutos — regularidade de máquina, não de pessoa. O tamanho de resposta quase constante reforça: tráfego de comando e controle costuma ter payload de tamanho fixo. Antes de escalar, descarte as causas legítimas com o mesmo perfil: agente de monitoramento, sincronização de antivírus, cliente de telemetria. Confirme a reputação do destino e o processo de origem no EDR.

3. Faltou **confirmar a hipótese com evidência**. Word como pai de PowerShell é IOA clássico de execução por macro maliciosa (T1566 seguido de T1059.001). Era preciso: identificar o arquivo aberto e sua origem (anexo de e-mail externo?), verificar a linha de comando completa do PowerShell, checar se houve conexão de rede subsequente (Sysmon EventID 3) e confirmar com o dono do processo de negócio. "É da equipe financeira" é suposição, não evidência.

4. (a) hash = nível 1, trivial de trocar; (d) IP = nível 2, fácil; (b) domínio = nível 3, simples; (c) dump de LSASS = nível 6, TTP — a mais dolorosa e a que vale construir detecção.

5. Ordem: **(b) → (c) → (a)**. O apagamento de cópias de sombra em servidor de arquivos é sinal precoce de ransomware, atinge ativo crítico e é irreversível — contenção imediata e escalada. O 4625 isolado de `jsilva` merece olhada rápida (senha errada acontece), mas só vira caso se repetir ou vier de origem estranha. O port scan bloqueado é ruído de internet: registrar e seguir. O critério dominante aqui é criticidade do ativo somada à irreversibilidade do dano.

</details>


## Pegadinhas técnicas — as 14 perguntas que derrubam candidatos

Entrevistador experiente não pergunta o que está no Google. Ele pergunta o que separa quem **decorou** de quem **entendeu**. Pense como um porteiro de prédio: qualquer um sabe dizer que o portão está fechado; poucos sabem dizer se o portão fechado significa que ninguém entrou.

| # | Pergunta capciosa | A armadilha | Resposta correta |
|---|---|---|---|
| 1 | O endereço MAC de origem muda ao longo do caminho? | O júnior confunde camada 2 com camada 3. | **Sim.** O MAC (Media Access Control, endereço físico da placa de rede) é reescrito a cada salto de roteador. O IP de origem permanece (salvo NAT). Por isso o MAC só serve para investigar dentro do **mesmo segmento de rede**. |
| 2 | A porta 443 sempre é HTTPS? | Porta é convenção, não contrato. | **Não.** Porta é só um número. Malware usa 443 para tráfego que não é HTTP nenhum (túnel proprietário, C2). O Zeek registra `service` real; se `id.resp_p=443` e `service` vier vazio ou diferente de `ssl`, isso é suspeito. |
| 3 | O ping funciona, então a rede está boa? | Confunde ICMP com serviço. | **Não.** ICMP (Internet Control Message Protocol) responde na camada 3. A aplicação pode estar morta, o firewall pode bloquear TCP 443 e liberar ICMP. Caso clássico: agente de proxy em *fail-close* — ping responde, TCP não fecha. |
| 4 | O firewall bloqueou, então estamos seguros? | Bloqueio é sinal, não conclusão. | **Não.** Um `deny` prova que **aquela** tentativa falhou. Pode haver 200 tentativas anteriores permitidas por outra regra, ou o mesmo host saindo por proxy. Bloqueio único é evento; bloqueio repetido é campanha. |
| 5 | O traceroute mostra o caminho de volta? | Assume simetria. | **Não.** Mostra apenas o caminho de ida. Roteamento na internet é frequentemente **assimétrico**. |
| 6 | O IP de origem no log é sempre a máquina real? | Ignora NAT e proxy. | **Não.** Atrás de NAT (Network Address Translation) ou proxy, o log da borda mostra o IP traduzido. É preciso o campo `X-Forwarded-For`, a tabela de NAT ou o log do proxy para chegar ao host real. |
| 7 | O DNS usa só UDP? | Decorou "DNS = UDP/53". | **Não.** UDP/53 para consultas normais; **TCP/53** para respostas grandes, transferência de zona (AXFR) e quando o bit TC (truncated) é setado. Ainda há DoT (TCP/853) e DoH (443). |
| 8 | Posso correlacionar logs usando o timestamp local de cada equipamento? | Ignora fuso e drift. | **Não.** Sem NTP (Network Time Protocol) sincronizado e normalização para UTC, a ordem dos eventos vira ficção. Primeira coisa a validar numa investigação. |
| 9 | Conta bloqueada significa ataque? | Confunde causa. | **Não necessariamente.** Senha antiga em celular, serviço mapeado com credencial vencida ou tarefa agendada geram lockout. Ataque tem assinatura: muitos **usuários diferentes** (password spray, T1110.003) ou muitos IPs. |
| 10 | Hash detectado pelo antivírus significa ameaça contida? | Confunde detecção com remediação. | **Não.** Ação `Detected` sem `Quarantined`/`Removed` significa arquivo ainda em disco. E o hash detectado pode ser o **estágio 2**; o dropper já rodou. |
| 11 | Certificado TLS válido significa site confiável? | Confunde criptografia com reputação. | **Não.** Certificado gratuito valida posse do domínio, não a intenção. A maioria do phishing moderno usa HTTPS com cadeado. |
| 12 | Tráfego cifrado significa que o SOC está cego? | Desiste cedo demais. | **Não.** Metadados continuam visíveis: SNI (Server Name Indication), JA3/JA3S, tamanho e cadência dos pacotes, volume, duração, geolocalização e reputação do destino. Beaconing se detecta sem abrir um byte de payload. |
| 13 | Se o Sysmon EventID 3 não aparece, não houve conexão? | Confia em telemetria incompleta. | **Não.** Sysmon só registra o que a configuração mandar; `NetworkConnect` é frequentemente filtrado por ruído. Ausência de log ≠ ausência de evento. |
| 14 | Um EventID 4624 com Logon Type 3 é sempre normal? | Decorou "tipo 3 = rede = normal". | **Depende.** Tipo 3 é acesso a compartilhamento, normal aos montes. Vira suspeito quando a conta é administrativa, a origem é uma estação (não servidor) e o `Logon Process` é `NtLmSsp` com NTLM onde deveria haver Kerberos — rastro típico de movimento lateral (T1021.002). |

---

## Cenários reais de entrevista

### Cenário 1 — O beacon "silencioso"

```
# Zeek conn.log (campos: ts, id.orig_h, id.resp_h, id.resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state)
1725364801.220 10.10.20.45 203.0.113.77 443 tcp ssl 1.02 512 340 SF
1725365101.418 10.10.20.45 203.0.113.77 443 tcp ssl 0.98 512 340 SF
1725365401.602 10.10.20.45 203.0.113.77 443 tcp ssl 1.05 512 344 SF
```

<details><summary>Ver legenda</summary>

| Campo | Valores nas três linhas | O que significa |
|---|---|---|
| `ts` | `1725364801.220`, `1725365101.418`, `1725365401.602` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos. Faça a subtração: **~300 segundos entre cada**, com variação de menos de 1 s |
| `id.orig_h` | `10.10.20.45` | Sempre a mesma estação |
| `id.resp_h` / `id.resp_p` | `203.0.113.77` / `443` | Sempre o mesmo destino externo, em HTTPS |
| `proto` / `service` | `tcp` / `ssl` | Transporte e serviço identificado |
| `duration` | `1.02`, `0.98`, `1.05` | Cerca de 1 segundo em cada — só o tempo de perguntar e sair |
| `orig_bytes` | `512` nas três | Payload enviado **idêntico**: o mesmo pedido a repetir |
| `resp_bytes` | `340`, `340`, `344` | Payload devolvido quase idêntico |
| `conn_state` | `SF` | Todas normais. É a **regularidade** que caracteriza o beacon, não o desfecho |

</details>

**Raciocínio esperado:** intervalo constante de ~300 s, bytes quase idênticos, duração curta. Isso é **beaconing** (T1071.001), não navegação humana. **Resposta modelo:** "Padrão periódico com baixo jitter e payload fixo. Verifico o SNI no `ssl.log`, a reputação de 203.0.113.77, o processo pai no Sysmon EventID 3 e escalo como possível C2." **Reprova quem:** diz "é HTTPS, é normal".

### Cenário 2 — Password spray

```
# Windows Security 4625 (falha de logon)
4625 | Account: jsilva      | Source: 198.51.100.30 | Sub Status: 0xC000006A | Logon Type 3
4625 | Account: maria.costa | Source: 198.51.100.30 | Sub Status: 0xC000006A | Logon Type 3
4625 | Account: svc_backup  | Source: 198.51.100.30 | Sub Status: 0xC000006A | Logon Type 3
```

**Raciocínio:** um IP, muitas contas, **uma ou duas** tentativas por conta. `0xC000006A` = senha errada (usuário existe). Isso é spray (T1110.003), não brute force. **Resposta modelo:** "Procuro um 4624 bem-sucedido do mesmo IP na janela; se houver, é comprometimento e escalo em P1." **Reprova quem:** trata cada 4625 como alerta isolado.

### Cenário 3 — Falso positivo de exfiltração

```
# Palo Alto TRAFFIC (CSV, campos-chave)
...,TRAFFIC,end,10.10.30.12,203.0.113.200,ssl,443,allow,"9843211","412",3600,...
```

<details><summary>Ver legenda</summary>

| Posição no exemplo | Campo | Valor | O que significa |
|---|---|---|---|
| 1 | *(truncado)* | `...` | O exemplo omite os primeiros campos de propósito, para focar no que importa |
| 2 / 3 | Type / Subtype | `TRAFFIC` / `end` | Log de sessão, no fim |
| 4 / 5 | Source / Destination Address | `10.10.30.12` / `203.0.113.200` | Origem interna e destino externo |
| 6 / 7 | Application / Destination Port | `ssl` / `443` | App-ID e HTTPS |
| 8 | Action | `allow` | A política permitiu |
| 9 | Bytes Sent | `"9843211"` | **9,8 GB a subir.** Vem entre aspas neste recorte; as aspas não fazem parte do valor |
| 10 | Bytes Received | `"412"` | 412 bytes a descer — a proporção que dispara o alerta |
| 11 | Elapsed Time | `3600` | Duração: **exatamente 1 hora**. Um número redondo assim costuma indicar processo agendado, não pessoa |
| 12 | *(truncado)* | `...` | O resto dos campos foi omitido |
| — | — | — | **Falta o essencial para decidir**: o campo `Rule Name`, o `Source User` e o `Destination Location`. Sem eles não se sabe se `203.0.113.200` é o backup corporativo — que é exatamente o ponto do cenário |

</details>

Upload de 9,8 GB. **Raciocínio:** antes de gritar exfiltração, checo destino (é backup corporativo?), usuário, horário e histórico. **Resposta modelo:** "Volume alto sozinho não é veredicto; comparo com a linha de base do host e do destino." **Reprova quem:** escala sem contexto — ou fecha como falso positivo sem verificar o destino.

### Cenário 4 — DNS tunneling

```
# Zeek dns.log
1725370010.11 10.10.20.88 8.8.8.8 udp a3f9c2e1b7d4.tunnel.example.com TXT NOERROR
1725370010.53 10.10.20.88 8.8.8.8 udp 9b2e7f01a4cc.tunnel.example.com TXT NOERROR
```

**Raciocínio:** subdomínios longos, aleatórios, tipo TXT, altíssima frequência sob um único domínio pai. É tunelamento (T1071.004). **Reprova quem:** ignora porque "DNS é infraestrutura, é ruído".

### Cenário 5 — Kerberoasting

```
# Windows Security 4769
Service Name: svc_backup | Ticket Encryption Type: 0x17 | Client: jsilva | Client Address: 10.10.20.45
```

**Raciocínio:** `0x17` é RC4 num ambiente que deveria usar AES (`0x12`). Muitos 4769 RC4 para contas de serviço, vindos de uma estação comum, é rastro de Kerberoasting (T1558.003). **Resposta modelo:** "Correlaciono com 4688 na origem e verifico se houve download de ferramenta."

### Cenário 6 — Proxy bloqueou, e agora?

```
# Squid access.log
1725371200.104 312 10.10.40.77 TCP_DENIED/403 0 CONNECT malicioso.example.com:443 - HIER_NONE/- -
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| *timestamp* | `1725371200.104` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos |
| duração | `312` | Milissegundos para atender |
| cliente | `10.10.40.77` | A estação que tentou |
| resultado/status | `TCP_DENIED/403` | A política barrou. **Prova a tentativa; não prova que a máquina está limpa** |
| bytes | `0` | **Zero bytes**: nada foi trocado com o destino |
| método | `CONNECT` | Pedido de túnel HTTPS |
| URL | `malicioso.example.com:443` | O destino pretendido, só host e porta |
| usuário | `-` | Sem autenticação nesse pedido |
| hierarquia/destino | `HIER_NONE/-` | Confirma que o proxy não encaminhou nada |
| tipo de conteúdo | `-` | Não houve conteúdo. **A pergunta que fica: houve `TCP_TUNNEL/200` para este domínio antes de a regra entrar?** |

</details>

**Raciocínio:** bloqueio prova tentativa, não impede. **Resposta modelo:** "Verifico se houve `TCP_TUNNEL/200` para o mesmo domínio antes da regra entrar, e se o host tentou outros destinos." **Reprova quem:** fecha o ticket com "bloqueado pelo proxy, sem impacto".

---

## Perguntas que você deve fazer ao entrevistador

| Pergunta | Por que te posiciona bem |
|---|---|
| "Quais fontes de log estão no SIEM hoje?" | Mostra que você pensa em cobertura, não em ferramenta. |
| "Como é o processo de escalação do N1 para o N2?" | Sinaliza que você entende o SOC como cadeia, não como herói solitário. |
| "Vocês trabalham com playbooks escritos?" | Demonstra maturidade de processo. |
| "Qual o volume médio de alertas por turno?" | Revela preocupação com fadiga de alerta e priorização. |
| "Existe plano de treinamento e trilha para N2?" | Mostra intenção de permanência. |
| "Como medem a qualidade do trabalho do N1?" | Você aceita ser medido — isso vale ouro. |

**Sem experiência formal?** Fale do laboratório caseiro com números: "montei Security Onion em VirtualBox com duas VMs, gerei tráfego com nmap contra uma máquina alvo minha, e reconstruí o scan pelo Suricata". Publique no GitHub: capturas `.pcap` anotadas, queries SPL e KQL comentadas, e um relatório de incidente fictício com linha do tempo. Um portfólio de 5 páginas vale mais que 3 certificações citadas de cor.

---

## Cartão de revisão de uma página

### Portas

| Porta | Serviço | Porta | Serviço |
|---|---|---|---|
| 21/22/23 | FTP / SSH / Telnet | 445 | SMB |
| 25/587/465 | SMTP / submissão / SMTPS | 3389 | RDP |
| 53 | DNS (UDP e TCP) | 389/636 | LDAP / LDAPS |
| 80/443 | HTTP / HTTPS | 88 | Kerberos |
| 135/139 | RPC / NetBIOS | 3306/1433/5432 | MySQL / MSSQL / PostgreSQL |

### EventIDs Windows

| ID | Significado | ID | Significado |
|---|---|---|---|
| 4624 | Logon com sucesso | 4720 | Conta criada |
| 4625 | Falha de logon | 4732 | Membro add em grupo local |
| 4634/4647 | Logoff | 4688 | Processo criado |
| 4768 | TGT solicitado (Kerberos) | 4776 | Validação NTLM |
| 4769 | Service Ticket solicitado | 1102 | Log de auditoria limpo |

### Flags TCP, tipos de logon e ICMP

| Flag | Uso | Logon Type | Significado | ICMP | Tipo/Código |
|---|---|---|---|---|---|
| SYN | Abre conexão | 2 | Console (local) | Echo Request | 8/0 |
| SYN-ACK | Aceita | 3 | Rede (SMB) | Echo Reply | 0/0 |
| ACK | Confirma | 4 | Batch | Dest. Unreachable | 3/x |
| FIN | Encerra normal | 5 | Serviço | Host Unreachable | 3/1 |
| RST | Corta abrupto | 7 | Unlock | Port Unreachable | 3/3 |
| PSH/URG | Entrega já | 10 | RDP | TTL Exceeded | 11/0 |

**Conceitos-chave:** MAC muda por salto, IP não · porta ≠ protocolo · ausência de log ≠ ausência de evento · UTC sempre · três perguntas de todo alerta: **quem, para onde, teve sucesso?**

---

### Exercícios — Pegadinhas técnicas, cenários reais, simulado e cartão de revisão

1. Um host 10.10.20.45 tem 96 conexões TCP/443 em 8 horas para 203.0.113.77, todas com 512 bytes de saída. Calcule o intervalo médio e diga o que isso indica.
2. Você vê 40 eventos 4625 com Sub Status `0xC0000064` vindos de 198.51.100.30 contra 40 contas distintas. Verdadeiro ou falso positivo? Justifique.
3. Escreva uma query SPL que encontre IPs com falhas contra mais de 10 contas distintas.
4. `%ASA-6-302013: Built inbound TCP connection for outside:203.0.113.55/44210 to inside:10.10.50.20/3389`. Qual o próximo passo?

<details><summary>Ver gabarito</summary>

1. 8 h = 28.800 s ÷ 96 = **300 s exatos**. Payload fixo e periodicidade rígida = **beaconing C2** (T1071.001). Próximo passo: SNI no `ssl.log`, reputação do destino e processo de origem via Sysmon EventID 3.
2. `0xC0000064` significa **usuário não existe**. Contra 40 contas distintas, isso é **enumeração de usuários**, não spray de senha — evento verdadeiro, mas com baixa chance de sucesso imediato. Não é falso positivo: registre e monitore se o mesmo IP passa a gerar `0xC000006A` (aí o atacante acertou nomes válidos).
**3.**
```spl
index=windows EventCode=4625 earliest=-1h
| stats dc(Account_Name) as contas values(Sub_Status) as status by Source_Network_Address
| where contas > 10
| sort - contas
```
`dc()` conta usuários distintos por IP; o `where` isola o comportamento de spray.
4. RDP **de entrada vinda da internet** (`outside` → `inside:3389`). Passos: confirmar se essa exposição é autorizada; buscar 4624/4625 Logon Type 10 no host 10.10.50.20 na mesma janela; se houver 4624 com sucesso de origem externa, escalar como acesso remoto não autorizado (T1133) e solicitar contenção.

</details>

## Mini-laboratório — Simulado de entrevista com evidência real

**Pré-requisitos:** VirtualBox, uma VM Ubuntu, Wireshark e tcpdump instalados. Tudo gratuito, tudo na sua máquina.

1. Na VM, capture 3 minutos: `sudo tcpdump -i any -w /tmp/lab-entrevista.pcap`.
2. Em outra aba, gere tráfego: `dig example.com`, `curl -I https://example.com`, `ping -c 4 example.com`.
3. Encerre a captura com Ctrl+C e abra o arquivo no Wireshark.
4. Aplique, um de cada vez, os filtros `dns`, `tcp.flags.syn==1 && tcp.flags.ack==0`, `icmp` e `tls.handshake.type==1`. **Observe:** no filtro TLS, o campo *server_name* (SNI) aparece em claro — é a prova de que tráfego cifrado ainda entrega metadados.
5. Conte quantos SYN sem ACK existem e explique em voz alta, como se fosse a entrevista, o que cada filtro provou.

**Critério de sucesso:** você consegue apontar na tela o SNI, o three-way handshake completo e a resposta DNS, e explicar cada um em menos de 30 segundos.

## O que um SOC Level 1 realmente precisa saber

- 🟢 Portas, EventIDs principais e flags TCP de cabeça — são a base de toda triagem.
- 🟢 Modelo OSI e TCP/IP com exemplo prático em cada camada, sem decoreba.
- 🟢 As três perguntas de todo alerta: quem, para onde, e houve sucesso.
- 🟢 Diferença entre bloqueado, detectado e contido — nunca confundir.
- 🟢 Normalizar tudo para UTC antes de correlacionar.
- 🟡 Ler log de firewall, proxy, DNS e autenticação sem precisar de tradução.
- 🟡 Escrever uma query SPL ou KQL simples com `stats`/`summarize` e contagem distinta.
- 🟡 Distinguir spray, brute force e enumeração pelos códigos de status.
- 🟡 Reconhecer beaconing por periodicidade e volume, mesmo em tráfego cifrado.
- 🔴 Correlacionar Kerberos (4768/4769) com criação de processo (4688) para movimento lateral.
- 🔴 Interpretar metadados TLS (SNI, JA3) quando o payload não está disponível.
- 🔴 Mapear achados para MITRE ATT&CK e escrever a escalação já no vocabulário do N2.

## Resumo em 10 linhas

1. A entrevista de SOC N1 testa raciocínio, não memória.
2. Pegadinhas existem para separar quem entendeu camada de quem decorou tabela.
3. MAC muda a cada salto; IP só muda com NAT.
4. Porta é convenção — 443 não garante HTTPS.
5. Bloqueio e detecção não são sinônimos de contenção.
6. Ausência de log nunca prova ausência de evento.
7. Sem UTC sincronizado, correlação é ficção.
8. Tráfego cifrado ainda entrega SNI, volume e cadência ao analista.
9. Cenários reais se resolvem com linha do tempo, linha de base e contexto do ativo.
10. Sem experiência, o laboratório caseiro documentado é a sua experiência.



---
