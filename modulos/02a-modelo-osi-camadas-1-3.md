# Módulo 02 — Modelo OSI: Camadas 1 a 3 na prática do SOC

## Por que este módulo importa para o SOC

Todo alerta que chega ao seu console — um bloqueio de firewall, um beacon de malware, uma tentativa de autenticação suspeita — acontece em algum lugar da pilha de rede. Se você não sabe em qual camada o evento nasceu, não sabe qual log consultar, qual equipe acionar nem o que perguntar. Um analista que domina as camadas 1 a 3 responde rápido a três perguntas que aparecem em quase toda investigação: **de onde veio**, **para onde ia** e **isso é rede quebrada ou é ataque?**. Este módulo constrói exatamente essa base.

### Índice do módulo

- Por que existe um modelo em camadas, encapsulamento e Camada 1 (Física)
- Camada 2 — Enlace
- Camada 3 — Rede

---

## Por que existe um modelo em camadas

**O que é.** O modelo OSI (Open Systems Interconnection, "interconexão de sistemas abertos") divide a comunicação em rede em 7 camadas independentes. Cada camada resolve um problema e entrega o resultado para a de cima.

**Analogia.** Pense em enviar uma encomenda. Você escreve a carta (conteúdo), coloca num envelope com o endereço do destinatário (endereço lógico), os Correios colocam numa saca do centro de distribuição de Campinas (endereço local do próximo salto) e um caminhão leva pela estrada (meio físico). O motorista não lê a carta. O carteiro não precisa saber que estrada foi usada. Cada um cuida do seu pedaço. Rede funciona igual.

**Por que isso importa no SOC.** Quando um usuário diz "a internet caiu", a resposta muda conforme a camada: cabo rompido (1), loop de switch (2), rota errada (3), firewall bloqueando (4), DNS quebrado (7). Camadas dão um mapa de triagem.

### As 7 camadas e a mnemônica

| # | Camada | Função em uma frase | PDU (unidade de dados) | Endereço usado |
|---|--------|---------------------|------------------------|----------------|
| 7 | Aplicação | O que o usuário usa (HTTP, DNS, SMTP) | Dados | URL, nome |
| 6 | Apresentação | Formato, criptografia, codificação (TLS) | Dados | — |
| 5 | Sessão | Abre, mantém e fecha conversas | Dados | — |
| 4 | Transporte | Entrega fim a fim, portas (TCP/UDP) | Segmento (TCP) / Datagrama (UDP) | Porta |
| 3 | Rede | Endereçamento lógico e roteamento (IP) | Pacote | IP |
| 2 | Enlace | Entrega dentro da mesma rede local | Quadro (frame) | MAC |
| 1 | Física | Bits virando sinal elétrico, luz ou rádio | Bit | — |

Mnemônica de baixo para cima (1 → 7): **F**ernando **E**ntrou **R**apidamente **T**razendo **S**eis **A**bacaxis **A**zedos — Física, Enlace, Rede, Transporte, Sessão, Apresentação, Aplicação.

> Atenção: na vida real usamos o modelo TCP/IP (4 camadas), mas o vocabulário OSI é o que aparece em SIEM, em documentação de firewall e em conversa com o time de redes. "Bloqueio em camada 7" e "problema de camada 2" são frases do dia a dia.

## Encapsulamento e desencapsulamento

**O que é.** Encapsulamento é o processo de cada camada adicionar seu próprio cabeçalho aos dados que vêm de cima, como envelopes dentro de envelopes. Desencapsulamento é o inverso, no destino: cada camada retira o seu envelope e entrega o miolo para a de cima.

**Como funciona.** O navegador de `jsilva` em `10.10.20.35` acessa `https://intranet.corp.local`. A requisição HTTP vira dados; o TCP acrescenta portas e número de sequência; o IP acrescenta origem e destino; a Ethernet acrescenta MACs e um CRC (Cyclic Redundancy Check, verificação cíclica de redundância) no fim.

```
+---------------------------------------------------------------+
| Quadro Ethernet (Camada 2)                                    |
| MAC dst 00:1A:2B:3C:4D:5E | MAC src 00:AA:BB:11:22:33 | 0x0800|
|  +----------------------------------------------------------+ |
|  | Cabeçalho IP (Camada 3)                                  | |
|  | src 10.10.20.35 -> dst 10.10.50.10 | TTL 128 | proto 6   | |
|  |  +-----------------------------------------------------+ | |
|  |  | Cabeçalho TCP (Camada 4)                            | | |
|  |  | porta origem 51422 -> porta destino 443 | flags PSH | | |
|  |  |  +------------------------------------------------+ | | |
|  |  |  | Dados HTTP (Camada 7)                          | | | |
|  |  |  | GET /rh/holerite HTTP/1.1                      | | | |
|  |  |  | Host: intranet.corp.local                      | | | |
|  |  |  +------------------------------------------------+ | | |
|  |  +-----------------------------------------------------+ | |
|  +----------------------------------------------------------+ |
| FCS / CRC (4 bytes)                                           |
+---------------------------------------------------------------+
```

**O que o SOC N1 observa.** Um sensor Zeek registra a mesma sessão em camadas diferentes: `conn.log` mostra IP e porta (camadas 3 e 4), `http.log` mostra a URI (camada 7). Correlacionar os dois pelo campo `uid` é a habilidade prática número um.

```
# Zeek conn.log — campos: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state
1757000412.512  CxT9a12Bk8   10.10.20.35  51422  10.10.50.10  443  tcp  ssl  12.804  1420  38210  SF
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `ts` | `1757000412.512` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos |
| `uid` | `CxT9a12Bk8` | Identificador único desta conexão. **É a chave da investigação**: o mesmo `uid` reaparece em `ssl.log`, `dns.log`, `http.log` e `files.log`, o que permite remontar a sessão inteira |
| `id.orig_h` | `10.10.20.35` | IP de origem — **camada 3** |
| `id.orig_p` | `51422` | Porta de origem, efêmera — **camada 4** |
| `id.resp_h` | `10.10.50.10` | IP de destino — **camada 3** |
| `id.resp_p` | `443` | Porta de destino: HTTPS — **camada 4** |
| `proto` | `tcp` | Protocolo de transporte |
| `service` | `ssl` | Serviço reconhecido pelo Zeek ao inspecionar o conteúdo: TLS, e não HTTP em claro |
| `duration` | `12.804` | Duração em segundos |
| `orig_bytes` | `1420` | Payload enviado pelo cliente (sem cabeçalhos) |
| `resp_bytes` | `38210` | Payload devolvido pelo servidor — proporção normal de navegação |
| `conn_state` | `SF` | Abriu com handshake completo e fechou com FIN. `S0` (resposta nenhuma) e `REJ` (recusada) são os estados que interessam em varredura |

</details>

**Erro comum de analista júnior.** Concluir "é HTTPS, então é seguro". A porta 443 diz apenas qual porta foi usada — malware usa 443 justamente porque quase ninguém bloqueia.

### MTU e fragmentação

**O que é.** MTU (Maximum Transmission Unit, unidade máxima de transmissão) é o maior tamanho de dados que cabe em um quadro. Em Ethernet o padrão é **1500 bytes**. Se um pacote IP é maior que a MTU do próximo enlace, ele é **fragmentado** em pedaços que o destino remonta.

**Exemplo prático.** Um túnel VPN adiciona cabeçalhos e reduz a MTU efetiva para cerca de 1400 bytes. O sintoma clássico: a página abre, mas o download trava. Ping pequeno funciona, ping grande com bit DF (Don't Fragment, não fragmentar) falha.

```
C:\> ping 10.10.50.10 -f -l 1472
Resposta de 10.10.50.10: bytes=1472 tempo=3ms TTL=126

C:\> ping 10.10.50.10 -f -l 1473
Pacote necessita ser fragmentado, mas o sinalizador DF está definido.
```

1472 bytes de dados + 20 de IP + 8 de ICMP = 1500. Esse teste descobre a MTU real do caminho.

**Relevância de segurança.** Fragmentação excessiva e sobreposta é técnica antiga de evasão de IDS, mapeada em MITRE ATT&CK como **T1027 (Obfuscated Files or Information)**. Suricata sinaliza isso sozinho — o analista só precisa reconhecer o alerta.

```json
{"timestamp":"2026-09-03T09:14:02.118+0000","event_type":"alert","src_ip":"203.0.113.77","dest_ip":"10.10.20.35","proto":"IPv4","alert":{"signature":"SURICATA IPv4 fragmentation overlap","category":"Generic Protocol Command Decode","severity":3}}
```

## Camada 1 — Física

**O que é.** A camada 1 transforma bits (0 e 1) em sinal que atravessa um meio: pulso elétrico no cobre, luz na fibra, onda de rádio no Wi-Fi. Ela não entende endereço nenhum — só existe sinal presente ou ausente, limpo ou sujo.

**Analogia.** É a estrada. Não importa o que o caminhão carrega; se há buraco na pista, tudo atrasa.

### Meios e equipamentos

| Meio | Uso típico | Alcance | Observação para o SOC |
|------|-----------|---------|-----------------------|
| UTP Cat5e | Estação de trabalho, 1 Gbps | 100 m | Cabo além de 100 m gera CRC e perda intermitente |
| UTP Cat6/6A | Uplink, 10 Gbps | 100 m (55 m no Cat6 a 10G) | Interferência de motor e reator causa erro |
| Fibra multimodo (MMF) | Dentro do datacenter | até ~550 m | Conector sujo derruba o link |
| Fibra monomodo (SMF) | Entre prédios, longa distância | dezenas de km | Corte de fibra = queda total de site |
| Wi-Fi (rádio) | Usuário móvel | dezenas de metros | Sujeito a interferência e jamming |

- **Hub:** equipamento antigo que repete o sinal para todas as portas. Não deve existir na rede; se aparecer, todo tráfego do segmento fica visível para qualquer máquina ligada nele.
- **Transceiver (SFP/SFP+):** módulo que converte sinal elétrico em óptico. Módulo com potência óptica caindo é causa frequente de flapping.

### Erros de CRC e flapping de porta

**O que é.** CRC é a soma de verificação no fim do quadro. Se o valor calculado não bate, o quadro chegou corrompido e é descartado. **Flapping** é a porta subindo e caindo repetidamente.

**Como aparece nos logs.**

```
Sep  3 09:22:41 sw-core-01 %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet1/0/14, changed state to down
Sep  3 09:22:44 sw-core-01 %LINK-3-UPDOWN: Interface GigabitEthernet1/0/14, changed state to up
Sep  3 09:22:59 sw-core-01 %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet1/0/14, changed state to down
```

```
sw-core-01# show interface GigabitEthernet1/0/14
GigabitEthernet1/0/14 is up, line protocol is up
  5 minute input rate 4120000 bits/sec
     18432 input errors, 17984 CRC, 448 frame, 0 overrun
     22 interface resets
```

- `input errors` / `CRC`: quadros corrompidos. Em rede saudável esse número fica praticamente em zero.
- `interface resets` crescendo: sinal instável, cabo, conector ou SFP.
- Três transições up/down em 20 segundos = flapping.

**O que o SOC N1 observa — normal vs suspeito.**

| Sinal | Provavelmente falha física | Merece investigação de segurança |
|-------|----------------------------|----------------------------------|
| Uma porta com CRC subindo | Cabo, patch panel, SFP | — |
| Link up/down em horário de manutenção | Troca de equipamento | — |
| Porta de sala de reunião subindo fora do expediente | Alguém plugou notebook | Sim — dispositivo não autorizado |
| Porta up seguida de MAC novo e DHCP para VLAN de servidores | Raro | Sim — possível tap ou equipamento rogue |

**Erro comum de analista júnior.** Fechar como "problema de rede" todo link up/down. A pergunta certa é: *houve mudança planejada?* Se não houve, o evento físico é o primeiro sinal de acesso não autorizado ao ambiente.

### Ataques físicos relevantes

- **Tap de rede:** dispositivo inserido no meio do cabo para copiar tráfego. Costuma causar uma queda breve do link no momento da instalação — daí a importância do log de link down.
- **Keylogger de hardware:** conector entre teclado e computador. Não gera tráfego; é detectado por inventário e inspeção visual, não por SIEM.
- **USB rogue:** dispositivo que se apresenta como teclado e injeta comandos — MITRE **T1200 (Hardware Additions)** e **T1091 (Replication Through Removable Media)**. Deixa rastro em Windows/Sysmon, não em camada 1.
- **Jamming de Wi-Fi:** ruído de rádio que derruba clientes. Aparece como queda simultânea de muitos clientes no mesmo ponto de acesso, sem erro de autenticação.

```
# Windows Security 4688 — criação de processo, logo após inserção de USB
EventID=4688 SubjectUserName=jsilva NewProcessName=C:\Windows\System32\cmd.exe
CreatorProcessName=C:\Windows\explorer.exe CommandLine="cmd.exe /q"
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `EventID` | `4688` | **O número do evento é o que se filtra**, não o texto da mensagem: o texto muda com o idioma e a versão do Windows, o número não. `4688` = **criação de processo** |
| `SubjectUserName` | `jsilva` | A conta que pediu a ação |
| `NewProcessName` | `C:\Windows\System32\cmd.exe` | Caminho do processo criado |
| `CreatorProcessName` | `C:\Windows\explorer.exe` | Caminho do processo pai |
| `CommandLine` | `"cmd.exe /q"` | Linha de comando. `-enc` indica comando em Base64 e `-w hidden` janela oculta |

</details>

O par "dispositivo HID novo" + 4688 fora do padrão do usuário é o indicador de USB rogue.

### Ferramentas e monitoramento

Zabbix e LibreNMS coletam via SNMP (Simple Network Management Protocol) os contadores `ifOperStatus`, `ifInErrors` e `ifOutDiscards`. É daí que sai o alerta de camada 1.

```
<134>1 2026-09-03T09:22:59.000Z zabbix-srv-01 zabbix - - [meta] Problem: Interface Gi1/0/14 on sw-core-01: Link down (severity: Warning, value: 2)
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `<134>` | PRI | `134 = 16 x 8 + 6`: facility 16 (local0), severidade 6 (informational) |
| `1` | VERSION | Formato RFC 5424 |
| `2026-09-03T09:22:59.000Z` | TIMESTAMP | ISO 8601 em UTC. Repare nos milissegundos zerados: o Zabbix agrega por segundo |
| `zabbix-srv-01` | HOSTNAME | **Quem enviou a mensagem é o servidor de monitorização, não o switch** — o switch é o *assunto*, não a origem |
| `zabbix` | APP-NAME | A aplicação que emitiu |
| `-` `-` | PROCID e MSGID | Vazios |
| `[meta]` | STRUCTURED-DATA | Presente mas sem pares: o Zabbix marca o bloco e não o preenche |
| `Problem: Interface Gi1/0/14 on sw-core-01: Link down` | MSG | O texto do alerta: qual interface, em qual equipamento, e o quê |
| `severity: Warning, value: 2` | MSG (fim) | **A severidade do Zabbix, que não é a do syslog.** São duas escalas diferentes na mesma linha — confundi-las é erro comum ao montar regras |

</details>

````spl
index=network sourcetype=cisco:ios ("LINK-3-UPDOWN" OR "LINEPROTO-5-UPDOWN")
| rex field=_raw "Interface (?<iface>\S+?),"          ``` extrai o nome da interface ```
| bucket _time span=10m                                ``` agrupa em janelas de 10 minutos ```
| stats count by host, iface, _time
| where count >= 4                                     ``` 4 transições em 10 min = flapping ```
````

```kql
// Sentinel — portas com flapping via Syslog de switches
Syslog
| where TimeGenerated > ago(24h)
| where SyslogMessage has_any ("LINK-3-UPDOWN", "LINEPROTO-5-UPDOWN")   // eventos de link
| extend Interface = extract(@"Interface (\S+?),", 1, SyslogMessage)     // isola a interface
| summarize Transicoes = count() by Computer, Interface, bin(TimeGenerated, 10m)
| where Transicoes >= 4                                                  // limiar de flapping
| order by Transicoes desc
```

### Exercícios — Por que existe um modelo em camadas, encapsulamento e Camada 1 (Física)

1. **Cálculo.** Um enlace tem MTU de 1400 bytes por causa de um túnel. Qual o maior valor de `-l` que funciona em `ping -f` nesse caminho? Mostre a conta.
2. **Leitura de log.** No `conn.log` do exemplo, quantos bytes o servidor devolveu e o que o estado `SF` indica sobre a conexão?
3. **Verdadeiro ou falso positivo?** Às 03:12 de um sábado, a porta `Gi1/0/22` do switch da recepção sobe, e dois minutos depois um novo MAC recebe IP `10.10.20.211`. Não há chamado de manutenção. Alerta verdadeiro ou ruído?
4. **Qual o próximo passo?** Uma interface acumula 17.984 erros de CRC em uma hora, mas o link nunca cai e nenhum usuário reclama. O que você faz e para quem escala?
5. **Camadas.** Classifique por camada OSI: (a) fibra rompida entre prédios; (b) pacote descartado por rota ausente; (c) alerta de fragmentação sobreposta no Suricata.

<details><summary>Ver gabarito</summary>

1. **1372 bytes.** A MTU de 1400 já inclui o cabeçalho IP (20 bytes) e o cabeçalho ICMP (8 bytes). Sobram 1400 − 28 = 1372 bytes de dados. Com 1373 o ping falha com "necessita ser fragmentado". Esse teste é a forma prática de descobrir a MTU real e explica a queixa clássica "abre a página mas o anexo não baixa".

2. **38.210 bytes** (`resp_bytes`) foram devolvidos pelo servidor `10.10.50.10`, contra 1.420 enviados pelo cliente — proporção normal para navegação. `SF` significa que a conexão completou o handshake e foi encerrada de forma limpa (FIN nos dois sentidos). Contraste: `S0` indica que a origem tentou abrir e nunca houve resposta — padrão típico de varredura de portas; `REJ` indica recusa ativa.

3. **Alerta verdadeiro, precisa investigação.** Evento físico fora da janela de manutenção, em área de acesso público (recepção), com MAC desconhecido obtendo endereçamento em VLAN de usuários. O caminho é: identificar o fabricante pelo OUI do MAC, confirmar com o inventário se o dispositivo é corporativo, checar a gravação de acesso do prédio no horário e, se não houver dono, isolar a porta. O erro seria fechar como "flapping de cabo" só porque a origem é camada 1 — a hora e a ausência de mudança planejada é que mudam a leitura.

4. **É falha física, não segurança — mas não se fecha sem ação.** CRC alto com link estável indica degradação: cabo excedendo 100 m, conector mal crimpado, patch cord danificado, interferência elétrica ou SFP com potência óptica baixa. O usuário não reclama porque o TCP retransmite e esconde o problema, ao custo de desempenho. Ação: registrar o contador atual de `show interface`, abrir chamado para a equipe de infraestrutura de redes com o número de porta e a taxa de erro por hora, e pedir substituição do cabo ou do transceiver. Documente para que não seja reaberto como incidente de segurança.

5. **(a) Camada 1** — meio físico rompido, sem sinal. **(b) Camada 3** — roteamento e endereçamento lógico IP. **(c) Camada 3** — a fragmentação é característica do cabeçalho IP; o Suricata inspeciona camadas superiores, mas o evento em si nasce na camada de rede.

</details>


## Camada 2 — Enlace (Data Link)

Imagine um prédio de escritórios. A Camada 1 (Física) é o cabo elétrico que chega em cada sala. A Camada 2 é o **contínuo interno do prédio**: o porteiro sabe que "a encomenda é para a sala 305" e entrega ali, sem precisar saber o endereço da rua. A Camada 2 entrega dados **dentro de uma mesma rede local** (LAN — *Local Area Network*), de placa de rede para placa de rede. Quem sai do prédio e vai para outra cidade é a Camada 3, tratada adiante.

**O que é:** a Camada de Enlace organiza os bits crus da Camada 1 em unidades com começo, meio e fim chamadas **quadros** (*frames*), coloca endereço de origem e destino, e detecta erros de transmissão.

**Como funciona:** cada placa de rede (NIC — *Network Interface Card*) tem um endereço físico chamado **MAC** (*Media Access Control*). O quadro Ethernet carrega o MAC de origem, o MAC de destino e os dados. Um **switch** lê esses MACs e decide por qual porta física repassar o quadro.

### Endereço MAC

**O que é:** o "número de série" da placa de rede. São 48 bits, escritos em 12 dígitos hexadecimais.

**Formato:** `00:1A:2B:3C:4D:5E` (Linux/Zeek), `00-1A-2B-3C-4D-5E` (Windows) ou `001a.2b3c.4d5e` (Cisco). Os **3 primeiros bytes** são o **OUI** (*Organizationally Unique Identifier*), atribuído ao fabricante — é assim que você descobre que um dispositivo é Dell, Apple, VMware ou um Raspberry Pi. Os 3 últimos bytes são o número de série da placa.

| Tipo | Exemplo | Significado |
|---|---|---|
| Unicast | `00:1A:2B:3C:4D:5E` | Um destinatário específico. Bit menos significativo do 1º byte = 0 |
| Multicast | `01:00:5E:00:00:FB` | Grupo de máquinas (mDNS). Bit menos significativo do 1º byte = 1 |
| Broadcast | `FF:FF:FF:FF:FF:FF` | Todas as máquinas do segmento |
| Localmente administrado | `02:...`, `06:...`, `0A:...`, `0E:...` | MAC alterado por software (VM, MAC randomization, spoofing) |

**Erro comum de analista júnior:** achar que um MAC iniciando por `00:0C:29` (VMware) ou `00:50:56` (VMware ESXi) prova que é servidor legítimo. MAC é trivialmente alterável por software — trate como pista, nunca como identidade confiável.

### Quadro Ethernet campo a campo

| Campo | Tamanho | Função |
|---|---|---|
| Preâmbulo + SFD | 8 bytes | Sincroniza o relógio do receptor; marca o início |
| MAC destino | 6 bytes | Para quem vai |
| MAC origem | 6 bytes | De quem veio |
| 802.1Q (opcional) | 4 bytes | Etiqueta de VLAN |
| EtherType | 2 bytes | O que vem dentro: `0x0800` = IPv4, `0x0806` = ARP, `0x86DD` = IPv6, `0x8100` = VLAN |
| Payload | 46–1500 bytes | Os dados (normalmente o pacote IP) |
| FCS | 4 bytes | *Frame Check Sequence* — CRC para detectar corrupção |

O limite de 1500 bytes de payload é a **MTU** (*Maximum Transmission Unit*) padrão. Guarde isso: problemas de MTU aparecem no SOC como "o site abre mas trava no meio do carregamento".

### Switch e tabela CAM

**Como funciona:** o switch aprende sozinho. Quando um quadro chega na porta `Gi1/0/12` com MAC de origem `00:1A:2B:3C:4D:5E`, ele anota na **tabela CAM** (*Content Addressable Memory*, também chamada tabela MAC): "esse MAC mora na porta 12, VLAN 20". Os próximos quadros destinados a ele saem só pela porta 12, em vez de inundar toda a rede.

**Exemplo prático:** `10.10.20.45` (notebook de `jsilva`) conversa com o servidor `10.10.30.10`. O switch já aprendeu ambos e faz a entrega ponto a ponto.

### ARP — traduzindo IP em MAC

**O que é:** ARP (*Address Resolution Protocol*) é a pergunta "quem tem o IP X? me diz o seu MAC". Analogia: gritar no corredor "quem é o dono do carro de placa ABC-1234?" e alguém levantar a mão.

**Como funciona:** o **ARP request** vai em broadcast (`FF:FF:FF:FF:FF:FF`) para toda a VLAN. Só o dono do IP responde com um **ARP reply** unicast. O resultado fica no **cache ARP** por alguns minutos. Existe ainda o **gratuitous ARP**: um anúncio não solicitado ("eu sou o `10.10.20.1`"), usado legitimamente em failover de cluster e ilegitimamente em ataques.

**O ponto fraco:** ARP não tem autenticação. Qualquer host pode responder por qualquer IP.

### VLAN 802.1Q, STP e 802.1X

- **VLAN** (*Virtual LAN*, padrão IEEE 802.1Q): divide um switch físico em várias redes lógicas. A etiqueta de 4 bytes carrega o **VLAN ID** (1–4094). Uma porta *access* pertence a uma VLAN; uma porta *trunk* transporta várias com etiqueta.
- **STP** (*Spanning Tree Protocol*, IEEE 802.1D/RSTP 802.1w): evita loops em redes com links redundantes, elegendo uma **root bridge** e bloqueando portas. Os switches conversam por quadros **BPDU** (*Bridge Protocol Data Unit*).
- **802.1X / NAC** (*Network Access Control*): exige autenticação antes de liberar a porta. O cliente (*supplicant*) fala EAP com o switch (*authenticator*), que consulta um servidor RADIUS. Sem credencial válida, a porta fica em VLAN de quarentena ou fechada.

### Ataques de Camada 2

| Ataque | O que faz | MITRE ATT&CK |
|---|---|---|
| ARP spoofing / poisoning | Envia ARP replies falsos para se pôr no meio do tráfego (AiTM) | T1557.002 |
| MAC flooding / CAM overflow | Satura a tabela CAM; o switch passa a inundar tudo e vira hub | T1040 (habilita sniffing) |
| VLAN hopping | Abusa de *double tagging* ou negociação DTP para alcançar outra VLAN | T1599 |
| STP root bridge attack | Anuncia BPDU com prioridade baixa para virar root e atrair tráfego | T1557 |
| Rogue DHCP | Servidor DHCP não autorizado entrega gateway/DNS controlado pelo atacante | T1557 |
| LLMNR/NBT-NS poisoning (Responder) | Responde a resoluções de nome falhas e captura hashes NetNTLM | T1557.001 |

Ferramentas ofensivas comuns nesse território: **Responder**, **Impacket** (`ntlmrelayx`), **Ettercap**, **Bettercap**, **Yersinia**. Aqui só descrevemos o **rastro** que deixam.

### Como aparece nos logs

Zeek gera um *notice* quando um mesmo IP aparece com MACs diferentes ou quando há inconsistência ARP (script `detect-arp-spoofing` / módulo ARP):

```
#fields ts      uid         note                      msg                                                                          sub                              src          dst         p  peer_descr  actions
1756890123.442  CH3f7a2Kx9  ARP::Cache_Inconsistency  IP 10.10.20.1 mapped to multiple MACs: 00:1a:2b:3c:4d:5e, 00:0c:29:aa:bb:cc  gateway impersonation suspected  10.10.20.87  10.10.20.1  -  worker-1    Notice::ACTION_LOG
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `ts` | `1756890123.442` | Instante do evento em epoch Unix (segundos desde 01/01/1970) com milissegundos |
| `uid` | `CH3f7a2Kx9` | Conexão que originou o notice, quando existe uma — permite voltar ao `conn.log` |
| `note` | `ARP::Cache_Inconsistency` | Tipo do notice. **É por este campo que se escreve a regra no SIEM**, não pelo texto da mensagem |
| `msg` | `IP 10.10.20.1 mapped to multiple MACs: ...` | Descrição legível; aqui lista os dois MAC que reivindicam o mesmo IP |
| `sub` | `gateway impersonation suspected` | Sub-mensagem, com o contexto que o script conseguiu juntar |
| `src` | `10.10.20.87` | Quem emitiu o ARP suspeito — o provável atacante |
| `dst` | `10.10.20.1` | IP que está sendo falsificado: o gateway |
| `p` | `-` | Porta envolvida. Vazia porque ARP não tem portas — vive na camada 2 |
| `peer_descr` | `worker-1` | Qual processo do cluster Zeek gerou o notice; útil quando há vários sensores |
| `actions` | `Notice::ACTION_LOG` | O que o Zeek fez com o notice: apenas registrou. Outras políticas enviam e-mail (`ACTION_EMAIL`) ou alarmam |

</details>


Suricata, com regra de ARP spoofing habilitada, produz EVE JSON:

```json
{"timestamp":"2026-09-03T09:14:02.118433+0000","flow_id":812774193302118,"in_iface":"eth1","event_type":"alert","src_ip":"10.10.20.87","dest_ip":"10.10.20.1","proto":"ARP","alert":{"action":"allowed","gid":1,"signature_id":2500101,"rev":3,"signature":"ET POLICY Possible ARP Spoofing - Gratuitous ARP for gateway from unexpected MAC","category":"Attempted Administrator Privilege Gain","severity":2},"ether":{"src_mac":"00:0c:29:aa:bb:cc","dest_mac":"ff:ff:ff:ff:ff:ff"},"vlan":[20]}
```

Campos-chave: `signature` diz o que a regra viu; `ether.src_mac` é o MAC do atacante; `ether.dest_mac` em `ff:ff:ff:ff:ff:ff` confirma broadcast (gratuitous ARP); `vlan` isola o segmento afetado.

Falha de 802.1X no switch Cisco, via syslog:

```
<174>1 2026-09-03T09:20:41.907Z sw-acesso-03.corp.local DOT1X - - - %DOT1X-5-FAIL: Authentication failed for client (0050.5687.19af) on Interface Gi1/0/24 AuditSessionID 0A0A1401000000AB
<174>1 2026-09-03T09:20:41.912Z sw-acesso-03.corp.local AUTHMGR - - - %AUTHMGR-5-SECURITY_VIOLATION: Security violation on the interface Gi1/0/24, new MAC address (0050.5687.19af) is seen
<174>1 2026-09-03T09:20:42.004Z sw-acesso-03.corp.local PM - - - %PM-4-ERR_DISABLE: psecure-violation error detected on Gi1/0/24, putting Gi1/0/24 in err-disable state
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `<174>` | PRI | `174 = 21 x 8 + 6`: **facility 21 (local5)**, severidade 6 (informational) |
| `1` | VERSION | Formato RFC 5424 |
| `2026-09-03T09:20:41.907Z` | TIMESTAMP | ISO 8601 em UTC. **As três mensagens cabem em 97 milissegundos** — é a proteção a reagir, não um humano |
| `sw-acesso-03.corp.local` | HOSTNAME | O switch de acesso que gerou tudo |
| `DOT1X`, `AUTHMGR`, `PM` | APP-NAME | O subsistema do IOS que falou: autenticação 802.1X, gestor de autenticação e *port manager* |
| `-` `-` `-` | PROCID, MSGID, STRUCTURED-DATA | Vazios: o IOS não os preenche |
| `%DOT1X-5-FAIL` | MSG · etiqueta Cisco | **A etiqueta tem três partes: `%FACILITY-SEVERIDADE-MNEMÓNICA`.** Aqui: subsistema `DOT1X`, severidade `5` (notification), mnemónica `FAIL`. É a mnemónica que se usa na regra do SIEM, porque o texto muda entre versões |
| `%AUTHMGR-5-SECURITY_VIOLATION` | MSG · etiqueta Cisco | Segunda mensagem: o port security viu um MAC que não esperava |
| `%PM-4-ERR_DISABLE` | MSG · etiqueta Cisco | Terceira: severidade **4 (warning)**, mais grave que as anteriores. `ERR_DISABLE` significa que **a porta foi desligada administrativamente** |
| `(0050.5687.19af)` | MSG · MAC | O MAC do cliente, na notação Cisco de três grupos de quatro dígitos (`aabb.ccdd.eeff`) |
| `Interface Gi1/0/24` | MSG · porta | A porta física — é o que se leva ao time local para ver o que está ligado ali |
| `AuditSessionID 0A0A1401000000AB` | MSG · sessão | Identificador da tentativa de autenticação; **liga as três mensagens à mesma sessão** |

</details>

Leitura: o cliente com MAC `0050.5687.19af` falhou no 802.1X na porta `Gi1/0/24`; o **port security** viu um MAC novo e a porta foi para `err-disable` (desligada administrativamente). Isso é a proteção funcionando.

### O que o SOC N1 observa

| Sinal | Normal | Suspeito |
|---|---|---|
| Gratuitous ARP | Poucos, em failover de cluster ou boot | Rajadas contínuas anunciando o IP do gateway |
| MACs por porta de switch | 1 a 3 (PC + telefone IP + VM) | Dezenas/centenas na mesma porta de acesso |
| Falha 802.1X | Isolada, após troca de notebook | Muitas falhas, mesma porta, MACs diferentes |
| BPDU em porta de acesso | Nenhuma | Qualquer uma → BPDU guard deve derrubar a porta |
| Ofertas DHCP | Só do IP do servidor autorizado | Oferta vinda de host de usuário |
| LLMNR/NBT-NS (UDP 5355 / 137) | Ruído baixo, resoluções que falham | Um host respondendo a *tudo* |

### Proteções e para que servem

| Proteção | Ataque que mitiga |
|---|---|
| Dynamic ARP Inspection (DAI) | ARP spoofing — valida ARP contra a base do DHCP snooping |
| Port security | MAC flooding — limita MACs por porta |
| DHCP snooping | Rogue DHCP — só portas *trusted* podem ofertar |
| BPDU guard / root guard | STP root bridge attack |
| Desativar DTP, mudar VLAN nativa | VLAN hopping |
| Desabilitar LLMNR e NBT-NS por GPO | Responder / NTLM relay |

### Consultas de caça

```spl
index=network sourcetype=suricata event_type=alert
| search alert.signature="*ARP Spoofing*" OR alert.signature="*Gratuitous ARP*"
| stats dc(ether.src_mac) as macs_distintos values(ether.src_mac) as macs count by dest_ip
| where macs_distintos > 1
```
Linha 1 filtra alertas do Suricata; linha 2 restringe às assinaturas de ARP; linha 3 conta quantos MACs diferentes reivindicaram o mesmo IP; linha 4 mantém só os casos com conflito real.

```kql
// Falhas de 802.1X e violações de port security por porta de switch
Syslog
| where TimeGenerated > ago(24h)                        // janela de 24 horas
| where SyslogMessage has_any ("%DOT1X-5-FAIL", "%AUTHMGR-5-SECURITY_VIOLATION")
| extend Porta = extract(@"Interface (\S+)", 1, SyslogMessage)   // extrai a interface
| extend Mac  = extract(@"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})", 1, SyslogMessage)
| summarize Tentativas = count(), MacsDistintos = dcount(Mac) by Computer, Porta
| where Tentativas > 5 or MacsDistintos > 2            // porta sob pressão
```

**Erro comum de analista júnior:** fechar como falso positivo todo alerta de ARP em ambiente com HSRP/VRRP ou cluster ativo-passivo. Antes de fechar, confirme que o MAC "novo" pertence ao par do cluster (OUI + inventário) e que houve janela de failover registrada. Outro erro clássico: ver `err-disable` e abrir a porta imediatamente, sem investigar por que houve violação.

### Exercícios — Camada 2 — Enlace

1. O MAC `02:42:AC:11:00:05` apareceu no inventário. Qual característica ele tem e por que isso importa numa investigação?
2. Um switch de acesso registra 214 MACs distintos aprendidos na porta `Gi1/0/18`, todos com OUIs aleatórios, em 40 segundos. Qual ataque é o mais provável e qual proteção deveria ter agido?
3. Analise o notice Zeek abaixo. É verdadeiro ou falso positivo? Justifique e diga o próximo passo.
```
1756891004.220	CkQ2p1	ARP::Cache_Inconsistency	IP 10.10.20.1 mapped to multiple MACs: 00:00:0c:07:ac:14, 00:1a:2b:3c:4d:5e	-	10.10.20.1	-	-	worker-1	Notice::ACTION_LOG
```
4. Um usuário reclama que a porta da sala 305 "morreu". O log do switch mostra `%PM-4-ERR_DISABLE: bpduguard error detected on Gi1/0/07`. O que aconteceu e qual o próximo passo do SOC N1?
5. Você vê rajadas de UDP/5355 e UDP/137 de `10.10.20.99` respondendo a nomes inexistentes como `\\srv-fnanceiro`. Que ferramenta e que técnica MITRE isso sugere, e qual a mitigação definitiva?

<details><summary>Ver gabarito</summary>

**1.** O segundo dígito hexadecimal do primeiro byte é `2` — isso liga o bit de "localmente administrado", ou seja, o MAC foi definido por software, não pelo fabricante. O prefixo `02:42:AC` é típico de contêineres Docker. Importa porque MAC atribuído localmente não serve para identificar hardware: pode ser um contêiner legítimo, uma VM ou um MAC forjado. Correlacione com switch port, DHCP e inventário antes de concluir.

**2.** **MAC flooding / CAM overflow** (habilita sniffing, T1040). Ao estourar a tabela CAM, o switch passa a inundar quadros por todas as portas da VLAN, permitindo captura de tráfego alheio. A proteção que deveria ter agido é **port security** com limite de MACs por porta e ação `restrict` ou `shutdown`. Verifique também se DAI e DHCP snooping estão ativos na VLAN.

**3.** Provavelmente **falso positivo**. O MAC `00:00:0c:07:ac:14` segue o padrão de **HSRP** da Cisco (`0000.0c07.acXX`, onde `XX` é o número do grupo — aqui grupo 20, coerente com a VLAN 20 do `10.10.20.1`). É esperado que o IP virtual do gateway apareça com o MAC virtual HSRP e, em momentos de transição, com o MAC físico do roteador ativo. **Próximo passo:** confirmar no inventário que `00:1a:2b:3c:4d:5e` pertence a um dos roteadores do par HSRP; se pertencer a um endpoint de usuário, o caso vira verdadeiro positivo de ARP spoofing e escala para contenção (isolar a porta, acionar rede).

**4.** Uma BPDU chegou numa porta de acesso, onde nenhum switch deveria existir. O **BPDU guard** derrubou a porta para `err-disable`, protegendo a topologia STP. Causa mais comum: usuário plugou um switch/roteador doméstico ou um dock com bridge. Causa maliciosa: tentativa de **STP root bridge attack**. **Próximo passo:** identificar fisicamente o que está ligado na `Gi1/0/07` (chamado com o time local), registrar o equipamento, e só então pedir ao time de rede o `shutdown`/`no shutdown` para reabilitar. Nunca reabilitar sem saber a causa.

**5.** Sugere **LLMNR/NBT-NS poisoning** com **Responder** — a máquina responde afirmativamente a qualquer nome que falhou no DNS (repare no erro de digitação `srv-fnanceiro`, típico de resolução falha), para capturar hashes NetNTLM. Técnica **T1557.001** (Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay). **Mitigação definitiva:** desabilitar LLMNR e NetBIOS over TCP/IP por GPO, exigir assinatura SMB e habilitar segmentação. Investigue em paralelo eventos **4624 tipo 3** e **4625** que possam indicar relay bem-sucedido a partir do host `10.10.20.99`.

</details>


## Camada 3 — Rede: entregando o pacote em qualquer lugar do mundo

Na Camada 2 (Enlace) vimos que um quadro só chega até o vizinho da mesma rede local. A Camada 3 é o que permite sair do prédio.

**Analogia:** imagine uma carta. O envelope tem o endereço completo — rua, número, cidade, país. Os Correios não entregam a carta em um salto: ela passa por várias agências, e cada agência olha o endereço de destino e decide para qual próxima agência mandar. Nenhuma agência sozinha conhece o caminho inteiro; cada uma só conhece o **próximo salto**. Isso é exatamente roteamento IP.

**O que é:** a Camada 3 (Rede) entrega pacotes entre redes diferentes, usando endereços lógicos (IP — Internet Protocol) que funcionam no mundo inteiro. A unidade de dados (PDU — Protocol Data Unit) aqui se chama **pacote**. O dispositivo típico é o **roteador** (e o firewall, que também roteia).

**Como funciona:** o roteador recebe o pacote, lê o IP de destino, consulta a **tabela de rotas** e reencaminha pela interface correta. O IP de origem e destino não mudam ao longo do caminho (exceto quando há NAT); o que muda a cada salto é o endereço MAC da Camada 2 e o campo TTL.

### O cabeçalho IPv4 — os campos que o SOC realmente usa

| Campo | Para que serve | Por que o SOC olha |
|---|---|---|
| Version | 4 (IPv4) ou 6 (IPv6) | Tráfego IPv6 inesperado pode escapar de regras feitas só para IPv4 |
| IHL / Total Length | Tamanho do cabeçalho e do pacote | Pacotes anormalmente grandes ou pequenos indicam túnel ou varredura |
| TTL (Time To Live) | Contador que diminui 1 a cada roteador | Revela distância e sistema operacional; valor estranho é indício de spoofing |
| Protocol | Qual protocolo vem dentro: 1=ICMP, 6=TCP, 17=UDP, 47=GRE, 50=ESP | Protocolo 47 ou 50 fora do padrão sugere tunelamento ou VPN não autorizada |
| Source / Destination IP | Quem falou com quem | Base de toda investigação |
| Flags / Fragment Offset | Fragmentação do pacote | Fragmentação excessiva é técnica clássica de evasão de IDS |

**Exemplo prático:** a estação `10.10.20.45` (usuário `jsilva`) acessa um servidor web em `203.0.113.80`. O pacote sai com TTL 128 (padrão do Windows). Ao chegar ao destino, chega com TTL 117 — ou seja, passou por 11 roteadores.

### TTL: o contador que evita pacotes eternos

**O que é:** o TTL impede que um pacote fique girando para sempre caso haja um laço de roteamento. Cada roteador subtrai 1; quando chega a zero, o roteador descarta o pacote e envia de volta um ICMP Time Exceeded (tipo 11).

Valores iniciais típicos: **Windows = 128**, **Linux/macOS = 64**, **equipamentos de rede Cisco = 255**.

**O que o SOC N1 observa:** se um host que diz ser Windows aparece com TTL chegando em 58, provavelmente o valor inicial era 64 (Linux) — o host pode não ser o que afirma, ou o pacote foi forjado.

**Erro comum de analista júnior:** concluir "é Linux" só pelo TTL. TTL pode ser alterado por firewall, proxy ou pelo próprio atacante. É indício, não prova.

### ICMP — o protocolo de recado da rede

**O que é:** ICMP (Internet Control Message Protocol) é como a rede reclama. Não transporta dados de aplicação; transporta avisos.

| Tipo/Código | Nome | Significado prático |
|---|---|---|
| 8 / 0 | Echo Request | O "ping" saindo |
| 0 / 0 | Echo Reply | A resposta do ping |
| 3 / 1 | Destination Unreachable — Host Unreachable | Não achei o host |
| 3 / 3 | Port Unreachable | Porta UDP fechada (o nmap usa isso) |
| 3 / 4 | Fragmentation Needed | Problema de MTU — causa clássica de "site abre, mas trava" |
| 11 / 0 | Time Exceeded | TTL chegou a zero — é o motor do traceroute |

**Ataque: ICMP tunneling (MITRE T1095 — Non-Application Layer Protocol).** O atacante esconde dados dentro do campo de dados do ping para exfiltrar informação sem usar HTTP nem DNS.

**Normal vs suspeito:** ping normal tem carga pequena (32 a 64 bytes), é esporádico e vai para poucos destinos. Suspeito é ICMP contínuo, por horas, para um único IP externo, com carga de centenas de bytes e volume assimétrico.

### Roteamento: tabela de rotas, rota default e métrica

**O que é:** a tabela de rotas é a lista de "para chegar nessa rede, mande por aqui". A regra é sempre **prefixo mais específico vence** — uma rota /24 ganha de uma /16, independente da métrica. A **métrica** só desempata entre rotas de mesmo tamanho de prefixo: quanto menor, melhor.

A **rota default** (`0.0.0.0/0`) é o "se eu não souber onde fica, mande para cá" — normalmente o firewall de borda.

```
C:\> route print -4

Destino de rede    Máscara de rede   Gateway          Interface     Métrica
0.0.0.0            0.0.0.0           10.10.20.1       10.10.20.45   25
10.10.20.0         255.255.255.0     Em vínculo       10.10.20.45   281
198.51.100.0       255.255.255.0     10.10.20.99      10.10.20.45   1
```

**O que o SOC N1 observa:** a terceira linha é uma **rota estática maliciosa** (MITRE T1565 — Data Manipulation). Alguém mandou o tráfego destinado a `198.51.100.0/24` passar por `10.10.20.99`, uma estação comum — clássico desvio para interceptar tráfego. Rota estática em endpoint de usuário quase nunca é legítima.

**Protocolos de roteamento, em resumo:**

- **OSPF (Open Shortest Path First):** usado **dentro** da empresa. Cada roteador anuncia aos vizinhos o que enxerga e todos calculam o caminho mais curto. Ataque: um roteador falso injeta rotas e atrai tráfego. Defesa: autenticação de vizinhança e interfaces passivas.
- **BGP (Border Gateway Protocol):** o protocolo **entre operadoras**, que faz a Internet funcionar. Ataque: **BGP hijack** — um operador anuncia que é dono de uma faixa que não é dele e o tráfego do mundo passa a ir para o lugar errado. O SOC N1 não corrige BGP, mas percebe: latência que dispara, traceroute passando por países estranhos, alerta de serviço externo de monitoramento de rotas.

### NAT e IPsec

**NAT (Network Address Translation):** traduz o IP privado (RFC1918: `10.x`, `172.16-31.x`, `192.168.x`) em um IP público na saída. **Impacto direto no SOC:** centenas de usuários saem com o mesmo IP público. Ao receber um alerta externo apontando `203.0.113.10`, você **não sabe quem foi** sem consultar o log de NAT do firewall (IP interno + porta de origem + horário exato).

**IPsec (Internet Protocol Security):** cifra o pacote na própria Camada 3. Usa ESP (protocolo 50), AH (protocolo 51) e negocia chaves via IKE (UDP 500 e UDP 4500). É a base das VPNs site-a-site. Tráfego ESP saindo de uma estação de usuário para um IP público desconhecido é altamente suspeito: pode ser um túnel não autorizado.

### Como aparece nos logs — decisão de roteamento e bloqueio

Log do FortiGate no formato chave=valor:

```
date=2026-09-03 time=10:42:17 devname="FGT-BORDA-01" devid="FG100F0000000001" logid="0000000013" type="traffic" subtype="forward" level="warning" srcip=10.10.20.45 srcport=51422 srcintf="port2" dstip=198.51.100.77 dstport=445 dstintf="port1" policyid=0 sessionid=884213 proto=6 action="deny" policytype="policy" service="SMB" msg="no matching policy" gatewayip=10.10.20.1 gatewayport=1
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `date` | `2026-09-03` | Data local **do equipamento**, não UTC. Correlacionar com um log em UTC sem acertar o fuso desalinha a timeline |
| `time` | `10:42:17` | Hora local do equipamento |
| `devname` | `"FGT-BORDA-01"` | Nome do equipamento que gerou o log |
| `devid` | `"FG100F0000000001"` | Número de série do equipamento — numa frota, é ele que identifica qual falou |
| `logid` | `"0000000013"` | Identificador do **tipo** de log. **É por ele que se filtra no SIEM**: o texto muda entre versões do FortiOS, o número não |
| `type` | `"traffic"` | Categoria do log: `traffic` é sessão, `event` é evento do próprio aparelho, `utm` é inspeção de conteúdo |
| `subtype` | `"forward"` | Subcategoria: `forward` é tráfego que atravessa, `local` é destinado ao próprio firewall, `vpn` é túnel, `webfilter` e `ips` são inspeção |
| `level` | `"warning"` | Severidade atribuída pelo FortiOS (`notice`, `warning`, `alert`, `critical`). **Quem a escolhe é o fabricante**, não o seu SOC |
| `srcip` | `10.10.20.45` | IP de origem |
| `srcport` | `51422` | Porta de origem, efêmera e sorteada pelo cliente |
| `srcintf` | `"port2"` | Interface por onde o tráfego **entrou** — dá o sentido, que o IP sozinho não dá |
| `dstip` | `198.51.100.77` | IP de destino |
| `dstport` | `445` | Porta de destino — é ela que aponta o serviço |
| `dstintf` | `"port1"` | Interface por onde o tráfego **saiu** |
| `policyid` | `0` | **Número da regra que decidiu.** Sem ele não se sabe por que o tráfego passou ou parou |
| `sessionid` | `884213` | Identificador da sessão na tabela de estado — casa o início e o fim da mesma conexão |
| `proto` | `6` | Número do protocolo IP: **`6` é TCP, `17` é UDP, `1` é ICMP**. Vem em número, não em nome |
| `action` | `"deny"` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |
| `policytype` | `"policy"` | Tipo de política: `policy` é a que atravessa o firewall, `local-in-policy` protege o próprio aparelho |
| `service` | `"SMB"` | Nome do **objeto de serviço** do FortiGate, não a porta literal. Um objeto chamado `HTTPS` pode ter sido configurado noutra porta |
| `msg` | `"no matching policy"` | Texto livre com a descrição legível. **Não use este campo em regras** — muda entre versões |
| `gatewayip` | `10.10.20.1` | Próximo salto escolhido pela tabela de rotas |
| `gatewayport` | `1` | Interface do próximo salto |
| — | — | `policyid=0` com `msg="no matching policy"` significa que **nenhuma regra escrita casou** — caiu na negação implícita do fim da lista. O `gatewayip` mostra a decisão de roteamento que já tinha sido tomada |

</details>

Campos que importam: `srcip`/`dstip` (quem para quem), `dstport=445` (SMB saindo para a Internet — nunca deve acontecer), `proto=6` (TCP), `srcintf`/`dstintf` (entrou pela LAN e tentou sair pela WAN — decisão de roteamento), `action=deny` com `policyid=0` e `msg="no matching policy"` (caiu na regra implícita de negação), `gatewayip` (o próximo salto escolhido pela tabela de rotas).

Log do Cisco ASA negando por rota inválida:

```
%ASA-4-106023: Deny tcp src inside:10.10.20.45/51422 dst outside:198.51.100.77/445 by access-group "inside_access_in"
%ASA-4-313005: No matching connection for ICMP error message: icmp src outside:203.0.113.9 dst inside:10.10.20.45 (type 11, code 0)
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `%ASA` | `%ASA` | Etiqueta do produto: identifica a linha como vinda de um firewall ASA |
| severidade | `4` | Escala syslog do Cisco, de 0 (emergência) a 7 (depuração): `4` é **warning**. **Severidade baixa não quer dizer evento sem importância** — quem a escolhe é o fabricante, não o seu SOC |
| *message ID* | `106023` | Pacote negado por lista de acesso. **É por este número que se escreve a regra no SIEM**: o texto da mensagem muda entre versões do software, o ID não |
| `src` | `inside:10.10.20.45/51422` | Interface, IP e porta de **origem**. Aqui a interface é o nome que o ASA dá à zona, e é ela que dá o sentido do tráfego |
| `dst` | `outside:198.51.100.77/445` | Interface, IP e porta de **destino** |
| `by access-group` | ``"inside_access_in"`` | **A lista de acesso que negou**, e a interface onde está aplicada. Sem este campo não se sabe qual regra corrigir |
| *message ID* (2ª linha) | `313005` | **Mensagem ICMP sem conexão correspondente.** O ASA é *stateful*: recebeu uma resposta de erro ICMP para uma sessão que não existe na sua tabela |
| `icmp src` / `dst` | `outside:203.0.113.9` / `inside:10.10.20.45` | Quem enviou o erro e a quem se destinava |
| `(type 11, code 0)` | `11` / `0` | **Tipo 11 é *Time Exceeded*** (o TTL zerou) e código 0 é em trânsito. É a resposta normal a um `traceroute` — ou um pacote forjado |

</details>

A segunda linha é um ICMP Time Exceeded chegando sem sessão correspondente — típico de resposta a traceroute ou de pacote forjado.

**Ataque: IP spoofing (MITRE T1036 — Masquerading).** O atacante forja o IP de origem. Indício forte: pacote com IP de origem **interno** chegando pela **interface externa**.

```
Sep  3 10:44:02 fw-borda-01 kernel: [ANTISPOOF] IN=eth0 OUT= SRC=10.10.20.15 DST=10.10.50.9 PROTO=TCP SPT=44311 DPT=3389 TTL=48 
```

Um IP `10.10.20.15` (interno) chegando na interface WAN (`eth0`) com TTL 48 é impossível de forma legítima: tráfego interno não sai e volta pela Internet, e o TTL baixo mostra que veio de longe.

### Ferramentas e o que o SOC observa

| Ferramenta | Uso no dia a dia do SOC |
|---|---|
| `ping` | Testa alcance na Camada 3 |
| `traceroute` / `tracert` | Mostra o caminho salto a salto (usa TTL crescente) |
| `route print` / `ip route` | Verifica rotas suspeitas no host |
| NetFlow / IPFIX | Quem falou com quem, quanto e por quanto tempo — sem ver o conteúdo |
| Zeek `conn.log` | Sessões completas com bytes e duração |
| Wireshark | Filtros `ip.ttl < 32`, `icmp.type == 8 && data.len > 64`, `ip.src == 10.10.20.45` |

**Indicadores de falha na Camada 3:** ping falha mas o cabo está bom (Camada 1 e 2 sanas); gateway inalcançável; assimetria de rota (pacote vai por um caminho e volta por outro, quebrando o firewall stateful); duplicidade de IP; MTU errada causando travamento em páginas grandes.

Consulta SPL (Splunk) para caçar ICMP anômalo:

```spl
index=firewall proto=1 action=allow
| stats sum(bytes) as total_bytes, count as pacotes, dc(dest_ip) as destinos by src_ip
| where total_bytes > 5000000 AND destinos < 3
| sort - total_bytes
```

Linha 1 filtra só ICMP permitido. Linha 2 agrega por origem somando bytes, contando pacotes e destinos distintos. Linha 3 mantém quem enviou muito volume para pouquíssimos destinos — assinatura de túnel ICMP. Linha 4 ordena pelo maior volume.

Consulta KQL (Microsoft Sentinel) para rota estática nova em endpoint:

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("route.exe", "netsh.exe")
| where ProcessCommandLine has_any ("add", "route")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

Linha 2 limita a 24 horas. Linha 3 procura os binários que alteram rotas. Linha 4 exige argumento de adição de rota. Linha 5 projeta os campos úteis. Linha 6 ordena do mais recente.

### Tabela resumo — Camadas 1 a 3

| Camada | PDU | Dispositivo | Protocolo típico | Ataque típico | Ferramenta |
|---|---|---|---|---|---|
| 1 — Física | Bit | Cabo, hub, transceiver, patch panel | Ethernet físico, RJ45, fibra | Grampo físico, rogue device, corte de cabo | Testador de cabo, `ethtool`, inventário de porta |
| 2 — Enlace | Quadro (frame) | Switch, placa de rede, access point | Ethernet, ARP, STP, VLAN 802.1Q | ARP spoofing, MAC flooding, VLAN hopping, rogue DHCP | Wireshark, `arp -a`, tabela MAC do switch |
| 3 — Rede | Pacote | Roteador, firewall (camada 3) | IP, ICMP, OSPF, BGP, IPsec | IP spoofing, ICMP tunneling, BGP hijack, rota maliciosa | `traceroute`, NetFlow, Zeek `conn.log`, log de firewall |

### Exercícios — Camada 3 — Rede

1. Um pacote chega ao seu servidor com TTL 117. O host de origem afirma ser um Windows 11. Quantos roteadores o pacote atravessou e isso é coerente?
2. Leia o log e diga se é verdadeiro ou falso positivo:
```
date=2026-09-03 time=02:14:55 devname="FGT-BORDA-01" type="traffic" subtype="forward" srcip=10.10.30.77 dstip=192.0.2.44 proto=1 action="accept" sentbyte=48211900 rcvdbyte=1204 duration=21600 service="PING"
```

<details><summary>Ver legenda</summary>

| Campo | Valor no exemplo | O que significa |
|---|---|---|
| `date` | `2026-09-03` | Data local **do equipamento**, não UTC. Correlacionar com um log em UTC sem acertar o fuso desalinha a timeline |
| `time` | `02:14:55` | Hora local do equipamento |
| `devname` | `"FGT-BORDA-01"` | Nome do equipamento que gerou o log |
| `type` | `"traffic"` | Categoria do log: `traffic` é sessão, `event` é evento do próprio aparelho, `utm` é inspeção de conteúdo |
| `subtype` | `"forward"` | Subcategoria: `forward` é tráfego que atravessa, `local` é destinado ao próprio firewall, `vpn` é túnel, `webfilter` e `ips` são inspeção |
| `srcip` | `10.10.30.77` | IP de origem |
| `dstip` | `192.0.2.44` | IP de destino |
| `proto` | `1` | Número do protocolo IP: **`6` é TCP, `17` é UDP, `1` é ICMP**. Vem em número, não em nome |
| `action` | `"accept"` | O veredito. `accept` permitiu, `deny` barrou, `close` encerrou normalmente, `timeout` expirou, `blocked` foi barrado pela inspeção |
| `sentbyte` | `48211900` | Bytes enviados **pela origem**. O ponto de vista é o da origem, não do firewall |
| `rcvdbyte` | `1204` | Bytes recebidos pela origem. **Comparar com `sentbyte` é o que revela exfiltração** |
| `duration` | `21600` | Duração da sessão em **segundos** |
| `service` | `"PING"` | Nome do **objeto de serviço** do FortiGate, não a porta literal. Um objeto chamado `HTTPS` pode ter sido configurado noutra porta |

</details>

3. Um usuário reclama que não acessa a intranet `10.10.50.20`. O `ping 10.10.50.20` falha, mas o `ping 10.10.20.1` (gateway) responde. Qual é o próximo passo da investigação?
4. Você recebe um alerta de abuso de um provedor externo dizendo que `203.0.113.10` fez varredura na Internet às 09:12. Esse é o IP público de saída da sua empresa. Qual é o próximo passo?
5. Em uma estação de `maria.costa` aparece a rota `172.16.9.0 255.255.255.0 10.10.20.99`. Verdadeiro ou falso positivo?

<details><summary>Ver gabarito</summary>

**1.** Windows inicia com TTL 128. 128 − 117 = **11 roteadores**. É coerente para um destino na Internet (o normal fica entre 8 e 20 saltos). Se o mesmo host aparecesse com TTL 57, o valor inicial seria 64 (Linux) e aí sim haveria contradição — indício de spoofing ou de que o "Windows" declarado não é o real. Lembre: TTL é indício, não prova, pois pode ser reescrito por proxy ou firewall.

**2.** **Verdadeiro positivo, prioridade alta.** `proto=1` é ICMP. A sessão durou 21600 segundos (6 horas) enviando 48 MB para um único IP externo, e recebendo apenas 1.204 bytes. Ping legítimo é curto e simétrico. Volume massivo, assimétrico, contínuo e de madrugada é a assinatura de **ICMP tunneling / exfiltração (T1095)**. Ação: isolar `10.10.30.77`, bloquear ICMP de saída para `192.0.2.44` e escalar para N2.

**3.** O gateway responde, então Camadas 1, 2 e a rota default estão funcionando. O próximo passo é verificar a **Camada 3 além do gateway**: rodar `tracert 10.10.50.20` para ver em qual salto o caminho morre, conferir a tabela de rotas do host com `route print`, e checar no firewall se há um `deny` para o par origem/destino. Se o traceroute morre no primeiro salto, o problema é roteamento ou regra de firewall — não é problema do cabo do usuário.

**4.** `203.0.113.10` é o IP pós-**NAT**: dezenas ou centenas de máquinas saem com ele. Você não pode responder "quem foi" só com esse dado. O próximo passo é consultar o **log de NAT do firewall** cruzando o horário exato (09:12, com a janela de fuso correta), a porta de origem informada pelo denunciante e o IP de destino, para traduzir de volta ao IP privado interno. Só depois disso se identifica a máquina e o usuário.

**5.** **Verdadeiro positivo provável.** Rota estática em estação de usuário final não é configuração normal — o padrão é apenas a rota default e a rede local. Direcionar `172.16.9.0/24` para `10.10.20.99` (outra estação, não um roteador) é forte indício de tentativa de interceptação de tráfego (T1565). Ação: verificar quem é `10.10.20.99`, procurar no EDR a execução de `route add` ou `netsh` na estação de `maria.costa`, e remover a rota após preservar a evidência.

</details>

## Mini-laboratório — Modelo OSI, Camadas 1 a 3

**Objetivo:** ver com os próprios olhos o quadro (Camada 2), o pacote (Camada 3) e o TTL diminuindo salto a salto.

**Pré-requisitos (tudo gratuito):** uma máquina com Wireshark instalado, terminal com `ping` e `tracert`/`traceroute`. Opcional: VirtualBox com uma VM Linux para o passo 5.

**Passo 1 — Capturar.** Abra o Wireshark, selecione a interface ativa e inicie a captura.

**Passo 2 — Gerar tráfego controlado.** No terminal:
```
ping -n 4 8.8.8.8
tracert -d -h 12 8.8.8.8
```
(No Linux/macOS: `ping -c 4 8.8.8.8` e `traceroute -n -m 12 8.8.8.8`.)

**Passo 3 — Isolar as camadas.** No filtro do Wireshark digite `icmp` e pressione Enter. Clique em um pacote e abra o painel do meio. Você verá três blocos empilhados: **Ethernet II** (Camada 2, com MAC de origem e destino), **Internet Protocol Version 4** (Camada 3, com IP de origem, destino, TTL e Protocol) e **Internet Control Message Protocol**. *Observe:* o MAC de destino é o do seu **gateway**, não o do Google — prova de que a Camada 2 só alcança o vizinho.

**Passo 4 — Ver o TTL trabalhando.** Aplique o filtro:
```
icmp.type == 11
```
Cada linha é um roteador dizendo "seu TTL zerou aqui". Clique em uma e leia o campo TTL dos pacotes de saída: 1, 2, 3... É assim que o traceroute funciona.

**Passo 5 — Comparar sistemas operacionais.** Se tiver a VM Linux, dê ping dela para o mesmo destino e compare o TTL inicial no Wireshark: 64 (Linux) contra 128 (Windows). Filtro útil: `ip.ttl < 65 && icmp`.

**Passo 6 — Ver a Camada 2 sem Camada 3.** Filtro `arp`. Esses quadros não têm cabeçalho IP nenhum — vivem só na rede local.

**Critério de sucesso:** você consegue apontar, em um único pacote, o MAC do gateway, o IP do destino final e o valor do TTL; e explicar por que o MAC muda a cada salto enquanto o IP não muda.

## O que um SOC Level 1 realmente precisa saber

- 🟢 **Essencial** — Encapsulamento: cada camada embrulha a de cima. Ao ler um log, saiba de qual camada aquele campo veio.
- 🟢 **Essencial** — Camada 2 endereça por MAC e só alcança a rede local; Camada 3 endereça por IP e atravessa o mundo. O MAC muda a cada salto, o IP não.
- 🟢 **Essencial** — Faixas privadas RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) nunca trafegam na Internet. IP privado chegando pela WAN é spoofing.
- 🟢 **Essencial** — TTL inicial: Windows 128, Linux/macOS 64, roteador Cisco 255. Serve para estimar distância e desconfiar de forjaria.
- 🟢 **Essencial** — Protocol number no cabeçalho IP: 1 ICMP, 6 TCP, 17 UDP, 47 GRE, 50 ESP. GRE ou ESP inesperados = possível túnel.
- 🟢 **Essencial** — NAT quebra a atribuição: um alerta sobre o IP público exige o log de NAT (IP interno, porta de origem, horário) para achar a máquina real.
- 🟡 **Importante** — A tabela de rotas escolhe pelo prefixo mais específico; a métrica só desempata entre prefixos iguais. Rota estática em endpoint de usuário é sinal de alerta.
- 🟡 **Importante** — ICMP normal é curto e simétrico. Volume alto, contínuo e assimétrico para um único destino é candidato a tunelamento (T1095).
- 🟡 **Importante** — Falha de Camada 1 (cabo, porta, SFP) e de Camada 2 (ARP, VLAN, MAC) parecem "internet caiu"; sempre suba a escada do modelo de baixo para cima antes de acusar a aplicação.
- 🟡 **Importante** — Um `deny` de firewall com "no matching policy" indica tráfego sem regra permissiva; o campo de gateway mostra a decisão de roteamento que foi tomada.
- 🔴 **Avançado** — OSPF (interno) e BGP (entre operadoras). BGP hijack se manifesta para o N1 como latência anômala e traceroute com saltos geograficamente impossíveis.
- 🔴 **Avançado** — Rota assimétrica quebra firewall stateful e gera falso positivo em massa; suspeite quando muitos alertas surgirem juntos após mudança de rede.

## Resumo em 10 linhas

1. O modelo OSI divide a comunicação em camadas para que cada problema tenha um lugar definido de investigação.
2. Encapsulamento: os dados descem embrulhados a cada camada e são desembrulhados no destino, na ordem inversa.
3. Camada 1 (Física) trata de bits, cabos, portas e sinal; falha aqui derruba tudo acima dela.
4. Camada 2 (Enlace) usa MAC e quadros, vive dentro da rede local e é território de ARP spoofing, MAC flooding e VLAN hopping.
5. Camada 3 (Rede) usa IP e pacotes, atravessa redes e é onde o roteador decide o próximo salto.
6. O cabeçalho IP entrega ao analista os campos que sustentam quase toda investigação: origem, destino, protocolo e TTL.
7. Roteamento segue o prefixo mais específico, cai na rota default quando não sabe, e a métrica só desempata.
8. ICMP explica falhas e alimenta o traceroute — e por isso mesmo é abusado como canal de exfiltração.
9. NAT esconde o host real e IPsec cifra o pacote: ambos mudam radicalmente o que você consegue ver no log.
10. Ataques de Camada 3 — IP spoofing, ICMP tunneling, BGP hijack, rota maliciosa — aparecem em firewall, NetFlow e traceroute antes de aparecerem no antivírus.



---
