# Módulo 10 — Active Directory para o SOC

## Por que este módulo importa para o SOC

Na maioria das empresas, o Active Directory (AD) é o "cartório" que decide quem é quem e quem pode o quê. Se o atacante domina o AD, ele domina todos os servidores, todas as estações e todos os dados — sem precisar explorar mais nenhuma falha. Por isso a esmagadora maioria dos incidentes graves passa, em algum momento, por uma autenticação estranha em um controlador de domínio. Um analista de SOC Nível 1 que entende a estrutura do AD consegue olhar um evento 4624 e dizer, em segundos, se aquilo é rotina ou o começo de um desastre.

**Índice do módulo:**

- Conceitos do Active Directory
- GPO, LDAP, Kerberos e NTLM
- Ataques comuns ao Active Directory
- Tabela mestra de EventIDs e caçada no SIEM

---

## O que é um serviço de diretório

**O que é.** Pense na lista telefônica antiga de uma cidade: nomes, endereços e telefones organizados por bairro, com um índice na frente. Um **serviço de diretório** é isso, só que para uma rede: um banco de dados hierárquico que guarda usuários, computadores, grupos e impressoras, e responde a perguntas do tipo "esse usuário existe?" e "ele pode entrar neste servidor?".

**Como funciona.** O AD (Active Directory, o serviço de diretório da Microsoft) guarda esses objetos em um arquivo de banco (`NTDS.dit`) dentro de servidores especiais e responde a consultas por LDAP (Lightweight Directory Access Protocol — protocolo leve de acesso a diretório) nas portas TCP 389 (texto), 636 (LDAPS, cifrado) e 3268/3269 (Global Catalog).

## Controlador de domínio (DC)

**O que é.** O **DC** (Domain Controller — controlador de domínio) é o servidor que guarda a cópia do diretório e valida logins. É o "cartório" propriamente dito.

**Exemplo prático.** Na `corp.local` fictícia existem dois: `DC01.corp.local` (10.10.10.10) e `DC02.corp.local` (10.10.10.11).

**Como aparece nos logs.** Um logon bem-sucedido do usuário `jsilva` visto no Windows Security do DC01:

```
EventID=4624
Log Name: Security
Source: Microsoft-Windows-Security-Auditing
Computer: DC01.corp.local
Account Name:  jsilva
Account Domain: CORP
Logon Type:  3
Logon Process: Kerberos
Authentication Package: Kerberos
Source Network Address: 10.20.30.55
Source Port:  49512
```

Campos: `Logon Type 3` = logon de rede (acesso a compartilhamento, LDAP, RPC); `Logon Type 2` = interativo no teclado; `10` = RDP. `Authentication Package` diz se foi Kerberos ou NTLM. `Source Network Address` é a origem real.

**O que o SOC N1 observa.** Normal: estações de usuário autenticando por Kerberos, tipo 3, o dia inteiro. Suspeito: `Logon Type 10` (RDP) direto em um DC vindo de uma estação comum, ou NTLM onde sempre houve Kerberos.

**Erro comum de júnior.** Achar que todo 4624 no DC é "alguém entrou no servidor". Tipo 3 é só validação de credencial — o usuário pode estar apenas abrindo uma pasta de rede.

## Domínio, árvore e floresta

**O que é.** Analogia: **domínio** é uma filial com regras próprias; **árvore** é o conjunto de filiais que compartilham o mesmo sobrenome DNS; **floresta** é o grupo empresarial inteiro, com um esquema (schema) e um catálogo comum. A floresta — não o domínio — é a fronteira real de segurança.

```
                    FLORESTA: corp.local
                    (Schema + Configuration comuns)
                             |
        +--------------------+--------------------+
        |                                         |
  DOMÍNIO RAIZ: corp.local            DOMÍNIO FILHO: br.corp.local
  DC01 (10.10.10.10)                  DC10 (10.30.10.10)
  DC02 (10.10.10.11)                  |
        |                             +-- OU=Usuarios-BR
        +-- OU=Sedes                  |     +-- maria.costa
        |     +-- OU=Lisboa           +-- OU=Servidores-BR
        |     |     +-- jsilva              +-- SRV-FILE01
        |     +-- OU=Porto
        +-- OU=Servidores
        |     +-- SRV-APP01
        +-- OU=Contas-Servico
        |     +-- svc_backup  (SPN: MSSQLSvc/SRV-APP01.corp.local:1433)
        +-- OU=TI-Admin
              +-- admin.rodrigo  (membro de Domain Admins)

   Confiança pai-filho: bidirecional e transitiva (automática)
   Confiança externa p/ parceiro.example.com: unidirecional, NÃO transitiva
```

## Relações de confiança (trusts)

**O que é.** Confiança é um acordo entre domínios: "eu aceito os crachás que você emite".

| Tipo | Direção | Transitiva? | Uso típico |
|---|---|---|---|
| Pai-filho | Bidirecional | Sim | Criada automaticamente dentro da floresta |
| Floresta (forest trust) | Uni ou bidirecional | Sim | Fusão/aquisição entre florestas |
| Externa (external) | Normalmente unidirecional | Não | Domínio legado ou parceiro |
| Realm | Uni ou bidirecional | Configurável | Kerberos não-Windows (Linux/MIT) |

**Unidirecional** = A confia em B, mas B não confia em A. **Transitiva** = se A confia em B e B confia em C, A confia em C. Toda confiança é caminho potencial de ataque lateral (MITRE **T1482 — Domain Trust Discovery**).

## Unidade Organizacional versus container

**OU** (Organizational Unit — unidade organizacional) é uma pasta na qual se pode aplicar GPO e delegar administração. **Container** (como o `CN=Users` padrão) parece pasta, mas **não aceita GPO**. Por isso contas criadas direto em `CN=Users` escapam das políticas de segurança — é achado clássico de auditoria.

## Objetos e identificadores

| Identificador | O que é | Exemplo fictício |
|---|---|---|
| DN (Distinguished Name) | Caminho completo no diretório | `CN=Joao Silva,OU=Lisboa,OU=Sedes,DC=corp,DC=local` |
| sAMAccountName | Nome de logon curto (legado, ≤20 chars) | `jsilva` |
| UPN (User Principal Name) | Logon em formato de e-mail | `jsilva@corp.local` |
| SID (Security Identifier) | Identidade binária única, usada nas permissões | `S-1-5-21-1004336348-1177238915-682003330-1108` |
| RID (Relative Identifier) | Últimos dígitos do SID | `1108`; **500** = Administrator, **512** = Domain Admins |
| GUID (objectGUID) | Identificador imutável do objeto | `a1b2c3d4-5e6f-4789-9abc-000000000001` |

Renomear o usuário muda o DN e o sAMAccountName, mas **nunca** o SID nem o GUID. Por isso o SOC deve pivotar investigações pelo SID, não pelo nome.

## Grupos

Existem dois **tipos**: **segurança** (concede permissão) e **distribuição** (só lista de e-mail, não dá acesso). E três **escopos**: **domain local** (permissões dentro do domínio), **global** (agrupa usuários do próprio domínio) e **universal** (atravessa a floresta, replica no Global Catalog).

### Grupos privilegiados críticos

| Grupo | Por que é perigoso |
|---|---|
| Domain Admins (RID 512) | Controle total do domínio e de todas as máquinas |
| Enterprise Admins (RID 519) | Controle de **todos** os domínios da floresta |
| Schema Admins (RID 518) | Altera o esquema — mudança irreversível e florestal |
| Account Operators | Cria/altera contas e pode entrar em DCs |
| Backup Operators | Lê qualquer arquivo, inclusive o `NTDS.dit` (todos os hashes) |
| DnsAdmins | Historicamente permitia carregar DLL no serviço DNS do DC |
| Server Operators | Manipula serviços no DC — caminho direto para SYSTEM |

**Como aparece nos logs.** Adição a grupo global de segurança:

```
EventID=4728
Log Name: Security
Computer: DC01.corp.local
Subject Account Name: admin.rodrigo
Member:  CN=svc_backup,OU=Contas-Servico,DC=corp,DC=local
Group Name: Domain Admins
Group Domain: CORP
```

`4728` = membro adicionado a grupo global; `4732` = grupo local; `4756` = universal.

**O que o SOC N1 observa.** Normal: mudanças em janela de manutenção, feitas por conta administrativa conhecida, com chamado aberto. Suspeito: conta de serviço entrando em Domain Admins às 03h12, sem chamado.

## Contas de serviço e SPN

**SPN** (Service Principal Name — nome principal de serviço) é a etiqueta que diz "o serviço SQL do host SRV-APP01 pertence à conta `svc_backup`". Kerberos usa o SPN para emitir tíquetes (evento **4769**). Conta de serviço com SPN e senha fraca é alvo de Kerberoasting (**T1558.003**) — o rastro é uma rajada de 4769 com `Ticket Encryption Type 0x17` (RC4) vinda de uma única estação.

## Global Catalog, FSMO, sites e sub-redes

O **Global Catalog (GC)** é um índice parcial de toda a floresta, servido nas portas 3268/3269 — é ele que responde "esse usuário existe em qualquer domínio?". Os papéis **FSMO** (Flexible Single Master Operations) são cinco funções que não podem ser feitas por dois DCs ao mesmo tempo: Schema Master e Domain Naming Master (por floresta), PDC Emulator, RID Master e Infrastructure Master (por domínio). Fora desses papéis, a replicação é **multimaster**: qualquer DC aceita escrita e propaga aos demais.

**Sites e sub-redes** dizem ao cliente qual DC está "perto" dele. Se a sub-rede `10.30.0.0/16` não estiver mapeada, a estação do Brasil pode autenticar em Lisboa — gerando logins que parecem geograficamente errados, mas são falso positivo de configuração.

## DNS integrado ao AD e registros SRV

Ligando ao Módulo 5 (DNS): o cliente não adivinha o DC — ele **pergunta ao DNS**. O registro **SRV** (Service) `_ldap._tcp.dc._msdcs.corp.local` devolve os controladores de domínio.

```
# Zeek dns.log
ts=1756880412.114  uid=CwXy3a  id.orig_h=10.20.30.55  id.orig_p=51833
id.resp_h=10.10.10.10  id.resp_p=53  proto=udp
query=_ldap._tcp.dc._msdcs.corp.local  qtype_name=SRV  rcode_name=NOERROR
answers=0,100,389,DC01.corp.local
```

Os campos da resposta SRV são: prioridade `0`, peso `100`, **porta 389**, alvo `DC01.corp.local`.

**O que o SOC N1 observa.** Normal: estações consultando SRV para os DCs internos. Suspeito: consulta a `_ldap._tcp.dc._msdcs` partindo de um servidor DMZ que nunca ingressou no domínio, ou resolução de nomes de DC via DNS público 203.0.113.53.

```kql
// Sentinel — logons NTLM em DCs nas últimas 24h (deveria ser Kerberos)
SecurityEvent
| where TimeGenerated > ago(24h)            // janela de busca
| where EventID == 4624                      // logon bem-sucedido
| where AuthenticationPackageName == "NTLM"  // pacote legado
| where Computer startswith "DC"             // apenas controladores
| summarize Tentativas=count() by Account, IpAddress, Computer
| order by Tentativas desc
```

```spl
index=wineventlog EventCode=4728 OR EventCode=4756
| eval grupo=coalesce('Group_Name',"desconhecido")
| search grupo IN ("Domain Admins","Enterprise Admins","Schema Admins")
| table _time, host, Account_Name, Member_Name, grupo
```

### Exercícios — Conceitos do Active Directory

1. Um objeto tem o SID `S-1-5-21-1004336348-1177238915-682003330-500`. Que conta é essa e por que o achado é relevante?
2. Um alerta dispara: "usuário `maria.costa` autenticou em `DC01.corp.local` (Lisboa) vindo de 10.30.44.20 (São Paulo)". Verdadeiro ou falso positivo?
3. A conta `svc_backup` aparece no evento 4728 sendo adicionada a `Domain Admins` por `admin.rodrigo` às 03h12. Qual o próximo passo da investigação?
4. Você encontra 30 contas de usuário em `CN=Users,DC=corp,DC=local` em vez de dentro de uma OU. Qual o risco de segurança?
5. Um servidor DMZ (192.0.2.40) consulta `_ldap._tcp.dc._msdcs.corp.local`. Qual hipótese testar primeiro?

<details><summary>Ver gabarito</summary>

1. O RID `500` identifica a conta **Administrator** interna do domínio — ela é a mesma mesmo que tenham renomeado a conta, pois o SID não muda. Qualquer uso dela merece atenção: em ambientes maduros ela deve estar desativada ou reservada para emergência.

2. Provavelmente **falso positivo de configuração**: a sub-rede `10.30.0.0/16` pode não estar mapeada ao site do Brasil, fazendo a estação escolher um DC de Lisboa. Valide o mapeamento de sites/sub-redes antes de escalar. Só vire suspeita se o IP de origem não pertencer à rede corporativa.

3. Correlacione três coisas: (a) existe chamado ou janela de mudança? (b) o `admin.rodrigo` tinha sessão legítima naquele horário — procure o 4624 correspondente e a estação de origem; (c) houve 4769 anterior para o SPN de `svc_backup` (indício de Kerberoasting, T1558.003). Se não houver chamado, trate como escalonamento de privilégio e escale para o N2 com pedido de remoção do grupo.

4. `CN=Users` é um **container**, não uma OU: não recebe GPO vinculada. Essas contas ficam fora de políticas de senha refinada, restrição de logon e configurações de segurança aplicadas por OU.

5. Hipótese primária: o servidor foi comprometido e o atacante está fazendo **descoberta de domínio** (T1482/T1018) para localizar os DCs, ou alguém ingressou indevidamente a máquina no domínio. Verifique se o host consta como objeto computador no AD, se houve 4624 de rede subsequente contra 10.10.10.10 e se há tráfego para as portas 389/445/88 nos logs de firewall.

</details>


## GPO — a régua de configuração do domínio

### O que é

Imagine um condomínio com 500 apartamentos. Em vez de o síndico ir de porta em porta pedindo que cada morador tranque a janela, ele publica um regulamento único no quadro de avisos e todos passam a obedecer. A **GPO** (Group Policy Object, ou Objeto de Política de Grupo) é esse regulamento: um pacote de configurações que o Active Directory empurra automaticamente para computadores e usuários do domínio.

Uma GPO pode definir papel de parede, tamanho mínimo de senha, regras de firewall, quais scripts rodam no logon e quais programas podem ser instalados. É poderosa exatamente por isso — e é por isso que o SOC precisa vigiá-la.

### Como funciona: a ordem LSDOU

As GPOs não são aplicadas em ordem aleatória. Elas seguem a sequência **LSDOU**:

| Ordem | Nível | Descrição |
|---|---|---|
| 1 | **L** — Local | Política gravada na própria máquina (`gpedit.msc`) |
| 2 | **S** — Site | Política ligada ao site do AD (agrupamento por rede física) |
| 3 | **D** — Domínio | Política ligada ao domínio inteiro (`corp.local`) |
| 4 | **OU** — Unidade Organizacional | Política ligada à OU, da mais alta para a mais profunda |

A regra de ouro: **quem aplica por último vence**. Se a política de domínio manda "senha mínima de 8 caracteres" e a política da OU `OU=TI,DC=corp,DC=local` manda "senha mínima de 14", quem vale na OU de TI é 14.

Três mecanismos ajustam esse comportamento:

- **Herança**: por padrão, uma OU filha herda tudo que veio de cima.
- **Bloqueio de herança** (*Block Inheritance*): a OU recusa políticas dos níveis superiores. Existe um contra-golpe legítimo: marcar a GPO como **Enforced** (antigo *No Override*), que atravessa o bloqueio e passa a vencer todas as outras.
- **Filtro de segurança** (*Security Filtering*): mesmo ligada à OU, a GPO só é aplicada a quem tiver permissão de *Read* + *Apply group policy*. É assim que se aplica uma política a um grupo específico, como `GG_Notebooks_Vendas`.

### Exemplo prático

Na `empresa-exemplo.com.br`, a estação `NB-VENDAS-042` (10.10.30.42) fica em `OU=Vendas,OU=Brasil,DC=empresa-exemplo,DC=com,DC=br`. O usuário `maria.costa` reclama que o mapeamento de unidade de rede sumiu. O analista pede que ela rode dois comandos:

```text
C:\> gpupdate /force
Atualizando a política...
A atualização da Política de Computador foi concluída com êxito.
A atualização da Política de Usuário foi concluída com êxito.

C:\> gpresult /h C:\Temp\gpo-maria.html
```

`gpupdate /force` reprocessa todas as GPOs imediatamente (sem esperar o ciclo padrão de 90 minutos + variação aleatória de até 30 minutos). `gpresult` mostra o **RSoP** (Resultant Set of Policy, ou conjunto de políticas resultante): quais GPOs venceram, quais foram negadas e por qual motivo — filtro de segurança, WMI ou link desabilitado.

### Como aparece nos logs

A modificação de uma GPO é registrada no controlador de domínio como alteração de objeto de diretório:

```text
EventID=5136
Log Name: Security
Source: Microsoft-Windows-Security-Auditing
Task Category: Directory Service Changes
Subject:
  Security ID:        EMPRESA\admin.rodrigo
  Account Name:       admin.rodrigo
  Logon ID:           0x3F8A21
Directory Service:
  Name:  empresa-exemplo.com.br
  Type:  Active Directory Domain Services
Object:
  DN:    CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=empresa-exemplo,DC=com,DC=br
  GUID:  {31B2F340-016D-11D2-945F-00C04FB984F9}
  Class: groupPolicyContainer
Attribute:
  LDAP Display Name: versionNumber
  Syntax (OID):      2.5.5.9
  Value:             131076
Operation:
  Type:              Value Written
  Correlation ID:    {a1c4e2f0-77b1-4d1e-9c33-5f2b7d904e11}
```

Campos que importam: **Subject / Account Name** diz quem alterou; **Object DN** identifica qual GPO (o GUID `{31B2F340-...}` é o da *Default Domain Policy* — GPO padrão do domínio); **Attribute / versionNumber** subindo indica que o conteúdo da política mudou de fato; **Operation Type** diz se foi escrita, adição ou remoção de valor.

### O que o SOC N1 observa

| Sinal | Normal | Suspeito |
|---|---|---|
| Autor do 5136 | Conta administrativa nominal, em janela de mudança | Conta de serviço (`svc_backup`), conta recém-criada ou fora do horário |
| GPO alvo | GPO de teste ou de departamento | *Default Domain Policy* ou *Default Domain Controllers Policy* |
| Atributo | `displayName`, `description` | `gPCMachineExtensionNames` (adiciona extensão de script/tarefa agendada) |
| Frequência | Uma ou duas edições isoladas | Rajada de 5136 seguida de 4688 em massa na frota |

O motivo do alerta crítico é direto: a GPO é o canal legítimo de distribuição em massa. Um atacante com direito de escrita em GPO cria uma tarefa agendada ou um script de logon e, no próximo ciclo de política, **toda a frota executa o payload**. É persistência (MITRE ATT&CK **T1484.001 — Domain Policy Modification**) e é o vetor clássico de detonação de ransomware em ambiente Windows.

**Erro comum de analista júnior**: fechar o 5136 como falso positivo só porque o autor está no grupo *Domain Admins*. A pergunta certa não é "essa conta pode?", é "essa conta **deveria** ter feito isso agora?". Sempre correlacione com um chamado de mudança.

---

## LDAP — a consulta ao catálogo do domínio

### O que é

O AD é uma agenda telefônica gigante da empresa. O **LDAP** (Lightweight Directory Access Protocol, ou Protocolo Leve de Acesso a Diretório) é o idioma que se usa para folhear essa agenda: perguntar "quem é o usuário jsilva?", "quais contas estão no grupo Domain Admins?", "quais computadores existem?".

### Como funciona

Toda conversa LDAP começa com um **bind** — o ato de se identificar:

| Tipo de bind | Descrição | Risco |
|---|---|---|
| Anônimo | Sem credencial nenhuma | Deveria estar desabilitado |
| Simples | Usuário e senha em claro no pacote | Alto se em porta 389 sem TLS |
| SASL / GSSAPI | Autenticação via Kerberos, com selo e cifra | Recomendado |

Depois do bind vem a busca, definida por uma **base de busca** (*Base DN*, onde começar a procurar) e um **filtro**. Filtros LDAP usam notação de prefixo, com o operador antes dos termos:

```text
# Todos os usuários habilitados cujo nome começa com "ma"
(&(objectClass=user)(objectCategory=person)(sAMAccountName=ma*))

# Membros diretos de um grupo
(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=local)

# Contas de serviço com SPN registrado (alvo típico de enumeração)
(&(objectClass=user)(servicePrincipalName=*))
```

`&` é E, `|` é OU, `!` é NÃO, `*` é curinga.

### Portas

| Porta | Protocolo | Escopo |
|---|---|---|
| 389/TCP | LDAP em claro (ou com StartTLS) | Domínio |
| 636/TCP | LDAPS — LDAP sobre TLS | Domínio |
| 3268/TCP | Catálogo Global em claro | Floresta inteira |
| 3269/TCP | Catálogo Global sobre TLS | Floresta inteira |

O Catálogo Global (*Global Catalog*) responde por toda a floresta, com um subconjunto dos atributos — por isso ferramentas de enumeração o adoram: uma consulta, visão completa.

### Como aparece nos logs

Rastro de rede de uma varredura de diretório visto no Zeek:

```text
#fields ts  uid  id.orig_h  id.orig_p  id.resp_h  id.resp_p  proto  service  duration  orig_bytes  resp_bytes  conn_state
1756900112.418  CJk2v1  10.10.30.42  49711  10.10.10.5  389  tcp  ldap  184.220  412885  38664201  SF
1756900297.004  CQm8x4  10.10.30.42  49733  10.10.10.5  3268 tcp  ldap  201.115  505110  51920334  SF
```

Leitura: `id.orig_h` 10.10.30.42 é uma **estação comum de vendas**, não um servidor; `id.resp_p` 389 e 3268 é consulta a domínio e a Catálogo Global; `duration` de 3 minutos com `resp_bytes` de ~38 MB e ~51 MB é volume de dados absurdo para uma estação — é o diretório inteiro sendo baixado. `conn_state=SF` significa conexão TCP normal, aberta e fechada corretamente (não é varredura de porta, é coleta bem-sucedida).

Esse é exatamente o padrão do **SharpHound**, coletor do **BloodHound**: poucas conexões LDAP, longas, com resposta enorme, partindo de um host que normalmente não consulta o diretório, seguidas de rajadas SMB/RPC para muitos hosts (coleta de sessões). Técnica **T1087 — Account Discovery** e **T1069 — Permission Groups Discovery**.

Query SPL para o padrão de volume:

```text
index=zeek sourcetype=zeek:conn service=ldap
| stats sum(resp_bytes) AS bytes_recebidos, dc(id.resp_h) AS dcs_consultados by id.orig_h
| where bytes_recebidos > 10000000
| eval mb=round(bytes_recebidos/1024/1024,1)
| table id.orig_h, mb, dcs_consultados
| sort - mb
```

Linha 1 filtra só conexões LDAP; linha 2 soma os bytes recebidos e conta quantos DCs cada origem consultou; linha 3 corta abaixo de 10 MB; linha 4 converte para megabytes legíveis; as duas últimas montam e ordenam a tabela.

**O que o SOC N1 observa**: LDAP saindo de servidores de aplicação e do servidor de RH é rotina. LDAP saindo de notebook de vendas às 22h, contra 389 **e** 3268, com dezenas de megabytes de resposta — abrir incidente e isolar.

**Erro comum de analista júnior**: contar conexões em vez de olhar bytes. O SharpHound faz poucas conexões; quem só alerta por "muitas conexões LDAP" não vê nada.

---

## Kerberos — o crachá com validade

### O que é

Você chega a um parque de diversões. Não paga em cada brinquedo: mostra o documento na bilheteria, recebe uma **pulseira do dia** e, em cada atração, troca a pulseira por uma **ficha daquele brinquedo**. Kerberos funciona assim, e a bilheteria confia em você porque conhece sua senha — que nunca é enviada pela rede.

### Os três atores

| Ator | Papel |
|---|---|
| Cliente | Usuário/máquina que quer acessar algo (`jsilva` em 10.10.30.42) |
| **KDC** (Key Distribution Center) | Roda no controlador de domínio; tem duas metades: **AS** (Authentication Service) emite a pulseira, **TGS** (Ticket Granting Service) emite as fichas |
| Serviço | O recurso final: `CIFS/fs01.corp.local`, `MSSQLSvc/sql01.corp.local:1433` |

### Passo a passo

1. **AS-REQ** — o cliente pede o TGT ao AS. Junto envia um carimbo de tempo cifrado com a chave derivada da senha do usuário. Isso é a **pré-autenticação**: prova que sabe a senha sem enviá-la. Se falhar, o KDC responde erro e nada é emitido.
2. **AS-REP** — o KDC devolve o **TGT** (Ticket Granting Ticket, a pulseira do dia), cifrado com a chave da conta `krbtgt`, válida tipicamente por 10 horas.
3. **TGS-REQ** — para acessar `\\fs01\financeiro`, o cliente apresenta o TGT ao TGS e pede a ficha do **SPN** (Service Principal Name, o nome do serviço) `CIFS/fs01.corp.local`.
4. **TGS-REP** — o TGS entrega o **ticket de serviço**, cifrado com a senha da conta que roda aquele serviço.
5. **AP-REQ** — o cliente apresenta o ticket direto ao servidor de arquivos, que o decifra com a própria chave e libera o acesso. O DC não participa desta etapa.

**Por que o relógio importa**: os tickets carregam carimbo de tempo, e a tolerância padrão do Windows é de **5 minutos**. Máquina com relógio fora do sincronismo simplesmente não autentica — erro `KRB_AP_ERR_SKEW`. Metade dos chamados de "não consigo logar" após restaurar uma VM é relógio.

**Criptografia**: os tipos aparecem no log como `Ticket Encryption Type`. `0x12` é AES256-CTS-HMAC-SHA1-96, `0x11` é AES128 e `0x17` é **RC4-HMAC**. Em domínio moderno, o normal é AES; RC4 em massa merece atenção porque é o tipo que ferramentas de extração de credencial costumam solicitar por ser mais fácil de quebrar offline (Kerberoasting, **T1558.003**).

### Como aparece nos logs

```text
EventID=4769
Log Name: Security
Task Category: Kerberos Service Ticket Operations
Account Information:
  Account Name:        jsilva@CORP.LOCAL
  Account Domain:      CORP.LOCAL
  Logon GUID:          {c81f77a2-2b6c-41e6-9a3a-9d5c1f0e77b2}
Service Information:
  Service Name:        MSSQLSvc/sql01.corp.local:1433
  Service ID:          CORP\svc_sql
Network Information:
  Client Address:      ::ffff:10.10.30.42
  Client Port:         51022
Additional Information:
  Ticket Options:      0x40810000
  Ticket Encryption Type: 0x17
  Failure Code:        0x0
```

`Ticket Encryption Type: 0x17` (RC4) para um SPN de serviço, partindo de estação de usuário comum, é a assinatura clássica de Kerberoasting.

### Tabela de eventos Kerberos e NTLM

| EventID | Significado | Leitura para o SOC |
|---|---|---|
| **4768** | TGT solicitado (AS-REQ/AS-REP) | Um por logon é normal; muitos por segundo com contas diferentes = pulverização de senha |
| **4769** | Ticket de serviço solicitado (TGS) | RC4 (`0x17`) para vários SPNs a partir de um host = Kerberoasting |
| **4771** | Falha de pré-autenticação | `0x18` = senha errada; `0x12` = conta desabilitada/bloqueada |
| **4776** | Validação de credencial NTLM pelo DC | `0xC000006A` senha errada, `0xC0000064` usuário inexistente |

Consulta KQL para Kerberoasting no Sentinel:

```kusto
// Eventos de ticket de serviço Kerberos nas últimas 24 horas
SecurityEvent
| where TimeGenerated > ago(24h) and EventID == 4769
// Apenas tickets RC4, que são os pedidos por ferramentas de extração
| where TicketEncryptionType == "0x17"
// Ignora contas de máquina, que terminam em "$" e usam RC4 legitimamente em casos antigos
| where AccountName !endswith "$"
// Conta quantos SPNs distintos cada origem pediu
| summarize SPNs=dcount(ServiceName), Amostra=make_set(ServiceName, 10) by AccountName, ClientAddress=IpAddress
// Pedir muitos SPNs diferentes em pouco tempo é o padrão do ataque
| where SPNs >= 5
```

**Erro comum de analista júnior**: tratar 4769 como "logon". 4769 é pedido de ticket — o usuário pode nunca ter acessado o serviço. Para logon efetivo, o evento é o 4624 no servidor de destino (detalhado no trecho de EventIDs deste módulo).

---

## NTLM — o desafio-resposta legado

### O que é

Kerberos é o crachá; **NTLM** (NT LAN Manager) é o interfone antigo do prédio: o porteiro faz uma pergunta que só o morador certo sabe responder.

### Passo a passo

1. **Negotiate** — o cliente diz ao servidor que quer autenticar com NTLM.
2. **Challenge** — o servidor devolve um número aleatório de 8 bytes, o *desafio* (*nonce*).
3. **Authenticate** — o cliente cifra o desafio usando o **hash** da senha e devolve a resposta. Se o servidor não for o dono da conta, ele repassa ao DC, que valida e registra o **4776**.

A senha nunca trafega. O problema é outro: **quem tem o hash não precisa da senha**. Como o cálculo usa o hash diretamente, roubá-lo da memória (Mimikatz) permite autenticar como a vítima — é o *Pass-the-Hash*, **T1550.002**.

**v1 vs v2**: o NTLMv1 usa DES e um desafio só do servidor — quebrável em tempo curto. O **NTLMv2** acrescenta um desafio do próprio cliente, carimbo de tempo e HMAC-MD5, e é o mínimo aceitável hoje. No log, o campo `Package Name` do 4624 mostra `NTLM V1` ou `NTLM V2`.

```text
EventID=4624
Logon Type:         3
Account Name:       jsilva
Workstation Name:   NB-VENDAS-042
Source Network Address: 10.10.30.42
Logon Process:      NtLmSsp
Authentication Package: NTLM
Package Name (NTLM only): NTLM V1
Key Length:         0
```

`Logon Type: 3` é logon de rede; `Authentication Package: NTLM` indica que Kerberos não foi usado; `NTLM V1` em 2026 é anomalia — pode indicar downgrade forçado ou coleta de credencial por ferramenta tipo Responder.

**Por que NTLM ainda existe**: acesso por endereço IP (`\\10.10.10.20\share`) não resolve SPN e cai em NTLM; aplicações antigas, appliances e máquinas fora do domínio dependem dele. Por isso não dá para simplesmente desligá-lo — dá para monitorá-lo.

**Erro comum de analista júnior**: ver `Account Name: ANONYMOUS LOGON` com `Logon Type: 3` e abrir incidente sempre. Esse par acontece em uso interno legítimo; o que qualifica o alerta é a **origem** ser externa ou incomum e vir acompanhada de enumeração.

### Exercícios — GPO, LDAP, Kerberos e NTLM

1. Uma GPO está ligada ao domínio `corp.local` definindo bloqueio de tela em 15 minutos. A OU `OU=Diretoria` tem *Block Inheritance* ativado e uma GPO própria com 60 minutos. A GPO de domínio está marcada como *Enforced*. Qual valor vale para um usuário da Diretoria?
2. Interprete: por que a conexão Zeek `10.10.30.42 → 10.10.10.5:3268`, com `duration=201` e `resp_bytes=51920334`, é mais preocupante do que 400 conexões curtas ao mesmo destino?
3. Verdadeiro ou falso positivo? Alerta "Kerberoasting" disparado por 12 eventos 4769 com `Ticket Encryption Type: 0x17`, `Account Name: SRV-APP01$`, `Client Address: 10.10.10.31` (servidor de aplicação), sempre para o mesmo SPN `MSSQLSvc/sql01.corp.local:1433`.
4. Um usuário relata "não consigo acessar nada" e o log do DC mostra apenas eventos 4771 com `Failure Code: 0x25`. Qual é a causa e qual o próximo passo?
5. Você recebe um 5136 alterando o atributo `gPCMachineExtensionNames` da *Default Domain Policy*, autor `svc_backup`, às 03h12. Qual é o próximo passo da investigação?

<details><summary>Ver gabarito</summary>

**1. Vale 15 minutos.** O *Block Inheritance* barra políticas dos níveis superiores, mas uma GPO marcada como **Enforced** atravessa o bloqueio e ainda vence a ordem normal do LSDOU. A regra "quem aplica por último vence" só se aplica entre GPOs não-Enforced. Comprove com `gpresult /h` na estação do usuário: a GPO da OU aparecerá como negada por *Enforced*.

**2. Porque o indicador é volume de resposta, não quantidade de conexões.** 51,9 MB vindos do Catálogo Global (3268) em 3 minutos significa que o diretório inteiro da floresta foi baixado por uma única sessão — comportamento de coletor tipo SharpHound. 400 conexões curtas com poucos KB cada são mais compatíveis com uma aplicação consultando usuários um a um. Um alerta baseado só em contagem de conexões perderia justamente o caso grave.

**3. Falso positivo.** Três sinais: (a) `SRV-APP01$` é conta de **máquina** (termina em `$`), não conta de usuário; (b) a origem é um servidor de aplicação que realmente precisa falar com o SQL Server; (c) o pedido é sempre para **um único SPN**. Kerberoasting se caracteriza por **muitos SPNs distintos** pedidos em curto intervalo, tipicamente por conta de usuário em estação. O uso de RC4 aqui provavelmente vem de configuração antiga da conta de serviço — vale abrir uma recomendação de hardening (migrar para AES), não um incidente.

**4. Relógio dessincronizado.** O código `0x25` no evento 4771 é `KRB_AP_ERR_SKEW`, diferença de tempo maior que a tolerância de 5 minutos. Note que não é senha errada (`0x18`). Próximo passo: verificar a hora da estação contra o DC (`w32tm /query /status` na máquina) e forçar ressincronismo com `w32tm /resync`. Causa frequente: VM restaurada de snapshot, BIOS com bateria fraca ou máquina que ficou muito tempo desligada.

**5. Tratar como incidente crítico, não como manutenção.** O atributo `gPCMachineExtensionNames` é alterado quando se **adiciona uma extensão** à GPO — scripts, tarefas agendadas, preferências — ou seja, algo novo passará a ser executado em toda a frota. A conta `svc_backup` é de serviço e não deveria editar GPO. Passos, nesta ordem: (a) confirmar se há chamado de mudança aprovado; (b) puxar os eventos 4768/4769/4624 da `svc_backup` para descobrir de qual host ela autenticou; (c) exportar a versão anterior da GPO do backup e comparar o conteúdo; (d) caçar 4688 (criação de processo) e Sysmon EventID 1 nas estações logo após o ciclo de política; (e) acionar a equipe de AD para reverter a GPO e rotacionar a senha da conta de serviço. Não espere confirmação de execução para escalar — o intervalo entre a edição e a aplicação em massa costuma ser de poucos minutos.

</details>


## Ataques comuns ao Active Directory

Pense no Active Directory (AD) como o porteiro de um prédio enorme. Ele guarda a lista de quem mora onde, quem tem chave de qual sala e quem pode abrir o cofre. Um atacante que entra no prédio raramente quebra a parede: ele prefere enganar o porteiro, copiar uma chave ou roubar o molho inteiro. Nesta seção você vai aprender a reconhecer, **pelo rastro em log**, cada uma dessas manobras.

Antes de tudo, uma regra de ouro para o analista de nível 1 (N1): quase todo ataque de AD é **abuso de função legítima**. O evento em si costuma ser normal. O que denuncia o ataque é o **contexto** — quem fez, de onde, com que frequência e em que horário.

### Mapa rápido dos ataques

| Ataque | Ideia em uma frase | EventID principal | Técnica MITRE ATT&CK |
|---|---|---|---|
| Kerberoasting | Pede o "ticket" de uma conta de serviço para quebrar a senha offline | 4769 | T1558.003 |
| AS-REP Roasting | Abusa de contas sem pré-autenticação Kerberos | 4768 | T1558.004 |
| Pass-the-Hash | Autentica com o hash da senha, sem saber a senha | 4624 tipo 3 (NTLM) | T1550.002 |
| Pass-the-Ticket | Reaproveita um ticket Kerberos roubado da memória | 4768/4769 ausentes | T1550.003 |
| Golden Ticket | Forja o bilhete mestre com o hash da conta krbtgt | 4769 sem 4768 | T1558.001 |
| Silver Ticket | Forja ticket de um único serviço | 4624 sem 4769 no DC | T1558.002 |
| DCSync | Finge ser controlador de domínio e pede a base de senhas | 4662 | T1003.006 |
| DCShadow | Registra um controlador de domínio falso e injeta mudanças | 4662 / 5137 | T1207 |
| Password spraying | Uma senha, muitas contas | 4625 / 4771 | T1110.003 |
| Brute force | Muitas senhas, uma conta | 4625 / 4740 | T1110.001 |
| LLMNR/NBT-NS poisoning | Responde "eu sou esse servidor" na rede local | 4776 / Sysmon 3 | T1557.001 |
| Abuso de delegação | Serviço age em nome de outro usuário | 4769 com flag de delegação | T1558.003 |
| Abuso de ACL/ACE | Permissão mal configurada vira caminho para Domain Admin | 4662 / 4738 | T1078.002 |
| Zerologon / PrintNightmare | Falhas de software no DC e no spooler | 5805 / 4688 | T1068 |

### Kerberoasting — pedindo a chave para quebrar em casa

**O que é.** Toda conta de serviço no AD tem um SPN (Service Principal Name, ou "nome principal de serviço" — o endereço do serviço, tipo `MSSQLSvc/sql01.corp.local:1433`). Qualquer usuário autenticado pode pedir um ticket para esse serviço. O ticket vem **criptografado com a senha da conta de serviço**. O atacante leva esse ticket para casa e tenta adivinhar a senha offline, sem gerar nenhum log a mais.

**Pré-requisito do atacante.** Apenas uma conta de domínio comum, válida. Nada de privilégio.

**Passo a passo conceitual.** (1) Consulta o diretório procurando contas de usuário que tenham SPN. (2) Solicita tickets de serviço (TGS) para vários desses SPNs de uma vez. (3) Extrai os tickets da memória. (4) Quebra offline com dicionário. Ferramentas: Rubeus, Impacket.

**Como aparece no log.** O EventID 4769 ("A Kerberos service ticket was requested") no controlador de domínio:

```
EventID=4769
Account Name:        jsilva@CORP.LOCAL
Service Name:        svc_backup
Service ID:          CORP\svc_backup
Client Address:      ::ffff:10.10.20.57
Ticket Options:      0x40810000
Ticket Encryption Type: 0x17
Failure Code:        0x0
```

Campo a campo: `Account Name` é quem pediu; `Service Name` é para qual serviço; `Client Address` é a estação de origem; `Ticket Encryption Type` é o algoritmo. **0x17 = RC4-HMAC**, um algoritmo antigo e fácil de quebrar; **0x12 = AES256**, o normal em domínios modernos.

**O que o SOC N1 observa.**

| Normal | Suspeito |
|---|---|
| 4769 com `0x12` (AES256) | 4769 com `0x17` (RC4) em ambiente que já usa AES |
| `Service Name` termina com `$` (conta de computador) | `Service Name` é conta de usuário (`svc_backup`, `svc_sql`) |
| 2 a 5 tickets por usuário/hora | 20+ SPNs distintos pedidos pelo mesmo usuário em menos de 2 minutos |

```spl
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17
| where NOT match(Service_Name, "\$$")            /* remove contas de máquina */
| bin _time span=5m                                /* agrupa em janelas de 5 min */
| stats dc(Service_Name) as spns values(Service_Name) by _time, Account_Name, Client_Address
| where spns >= 10                                 /* muitos SPNs = enumeração */
```

**Falso positivo típico.** Servidores antigos (SQL Server 2008, appliances) que só falam RC4; um scanner de vulnerabilidade autenticado; a própria ferramenta de auditoria da equipe de segurança. Sempre confirme se o `Client Address` pertence a um scanner conhecido.

**Contenção imediata.** Isolar a estação de origem da rede, forçar troca da senha das contas de serviço listadas (senha longa, 25+ caracteres) e marcar a conta que pediu para investigação de comprometimento.

### AS-REP Roasting — a porta sem tranca

**O que é.** Normalmente o Kerberos exige "pré-autenticação": você prova que sabe a senha antes de receber qualquer coisa. Algumas contas têm essa exigência desligada (flag `DONT_REQ_PREAUTH`), geralmente por compatibilidade com sistemas antigos. Nessas, qualquer pessoa pede e recebe um bloco cifrado com a senha do usuário — material pronto para quebra offline.

**Pré-requisito.** Nenhum. Basta alcançar o DC na porta 88/TCP e saber o nome de uma conta vulnerável.

**Como aparece no log.** EventID 4768 ("A Kerberos authentication ticket (TGT) was requested") com `Pre-Authentication Type: 0`:

```
EventID=4768
Account Name:            maria.costa
Service Name:            krbtgt/CORP.LOCAL
Client Address:          ::ffff:10.10.20.57
Ticket Encryption Type:  0x17
Pre-Authentication Type: 0
Result Code:             0x0
```

**O que o N1 observa.** `Pre-Authentication Type: 2` é o normal. **`0` é a exceção que interessa.** Vários 4768 com pré-autenticação 0, para contas diferentes, vindos do mesmo IP em segundos, é enumeração.

**Falso positivo.** Contas de integração legadas realmente configuradas assim há anos, sempre com o mesmo IP de origem. Compare com a linha de base.

**Contenção.** Reativar a pré-autenticação nas contas afetadas, resetar senhas e bloquear o host de origem.

### Pass-the-Hash e Pass-the-Ticket — usar a chave sem saber o segredo

**Pass-the-Hash (PtH).** O Windows guarda o hash NTLM (New Technology LAN Manager) da senha na memória. Quem tem privilégio de administrador local pode extraí-lo (Mimikatz, Impacket) e usá-lo diretamente para autenticar em outra máquina — **sem nunca descobrir a senha**.

**Como aparece.** EventID 4624 (logon com sucesso) do tipo 3 (rede), pacote NTLM, na máquina de destino:

```
EventID=4624
Logon Type:              3
Account Name:            admin.rodrigo
Authentication Package:  NTLM
Package Name (NTLM only):NTLM V2
Workstation Name:        WKS-FINANCE-04
Source Network Address:  10.10.20.57
Logon Process:           NtLmSsp
Key Length:              128
```

**O que o N1 observa.** Em domínio saudável, estação falando com estação usa **Kerberos**, não NTLM. Logon NTLM tipo 3 **entre duas estações de trabalho**, com conta administrativa, e **sem um 4768/4769 correspondente no DC** naquele minuto, é o padrão clássico de movimentação lateral. Correlacione ainda com Sysmon EventID 1 (criação de processo) mostrando `PsExec` ou serviço criado (EventID 7045).

**Pass-the-Ticket (PtT).** Mesma ideia, porém o atacante rouba um ticket Kerberos já emitido e o injeta em outra sessão. O sintoma é o **silêncio**: acesso bem-sucedido a um recurso sem o 4768/4769 que deveria precedê-lo, muitas vezes de um IP diferente do que originou o ticket.

**Falso positivo.** Aplicações antigas, scanners de vulnerabilidade e backups que autenticam por NTLM por projeto. Documente esses hosts em uma lista de exceção revisada.

**Contenção.** Isolar origem e destino, resetar a senha da conta duas vezes (para invalidar o hash em cache) e revisar quem é administrador local nas estações.

### Golden Ticket e Silver Ticket — falsificando o crachá

**Golden Ticket.** A conta `krbtgt` é o carimbo do domínio: tudo que ela assina o AD aceita. Com o hash dela, o atacante **fabrica um TGT** (Ticket Granting Ticket) para qualquer usuário, inclusive inexistente, com o privilégio que quiser.

**Pré-requisito.** Já ter sido Domain Admin ou ter feito DCSync antes. É pós-comprometimento total.

**Rastro em log.** Como o ticket é forjado offline, **não existe 4768**. Mas o uso gera 4769:

```
EventID=4769
Account Name:        backup_svc_adm@CORP.LOCAL      <-- conta que não existe no AD
Service Name:        cifs/fs01.corp.local
Client Address:      ::ffff:10.10.30.91
Ticket Options:      0x40810000
Ticket Encryption Type: 0x17
```

**Três sinais de altíssimo valor:** (1) 4769 sem 4768 anterior para a mesma conta; (2) nome de conta que **não existe** no diretório; (3) tempo de vida absurdo do ticket (o padrão da Microsoft é 10 horas; forjas comuns usam 10 anos).

**Silver Ticket.** Versão local: com o hash da conta do **serviço** (não do krbtgt), o atacante forja apenas o TGS daquele serviço. O DC nunca é consultado — por isso **não há 4769 no controlador de domínio**, só um 4624 no servidor-alvo. Comparar logs do servidor com os do DC é o único jeito de ver o buraco.

**Contenção.** Golden Ticket exige **resetar a senha do krbtgt duas vezes** (com intervalo de replicação entre as duas) — decisão de N3/engenharia, o N1 apenas escala com urgência máxima.

### DCSync e DCShadow — fingindo ser o próprio controlador

**DCSync.** Controladores de domínio replicam senhas entre si por um direito chamado `DS-Replication-Get-Changes-All`. Quem consegue esse direito pode **pedir a base inteira de hashes** como se fosse outro DC.

**Rastro — o mais confiável de todo o AD:** EventID 4662 ("An operation was performed on an object") com o GUID de replicação:

```
EventID=4662
Subject Account Name: jsilva
Object Server:        DS
Object Type:          %{19195a5b-6da0-11d0-afd3-00c04fd930c9}
Properties: Control Access
   {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}   <-- DS-Replication-Get-Changes-All
   {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}   <-- DS-Replication-Get-Changes
Access Mask:          0x100
```

```kql
// Sentinel / Defender for Identity
SecurityEvent
| where EventID == 4662                                   // operação em objeto do AD
| where Properties has "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"  // GUID de replicação
| where Account !endswith "$"                             // exclui contas de máquina
| where Computer !in (DomainControllersList)              // origem não é DC = crítico
| project TimeGenerated, Account, Computer, IpAddress, Properties
```

**Regra de ouro:** replicação só deve partir de **conta de computador de DC**. Se o `Subject Account Name` é um usuário comum, ou a origem é uma estação, é incidente crítico — praticamente sem falso positivo. As exceções conhecidas são Azure AD Connect / Entra Connect e ferramentas de backup do AD: mapeie essas contas.

**DCShadow.** O atacante **registra um servidor falso** como se fosse um novo DC e injeta alterações (por exemplo, adicionar SID de Domain Admin a uma conta) que se replicam sem passar pelos logs normais de alteração. Rastro: EventID 5137 (criação de objeto) e 4928/4929 no contexto de configuração, ou objeto `nTDSDSA` criado por conta que não é DC. Contenção: isolar o host, remover o objeto injetado e auditar mudanças recentes de grupo.

### Ataques de senha: spraying versus brute force

| | Password spraying | Brute force |
|---|---|---|
| Padrão | 1 senha × muitas contas | muitas senhas × 1 conta |
| Log | dezenas de 4625/4771 no mesmo instante, contas diferentes | dezenas de 4625 na mesma conta |
| Bloqueio | evita bloqueio (T1110.003) | costuma gerar 4740 (conta bloqueada) |
| Origem | IP único, frequentemente externo (VPN, OWA) | IP único |

```
EventID=4625  Account Name: jsilva        Status: 0xC000006A  Source: 203.0.113.45
EventID=4625  Account Name: maria.costa   Status: 0xC000006A  Source: 203.0.113.45
EventID=4625  Account Name: admin.rodrigo Status: 0xC000006A  Source: 203.0.113.45
EventID=4771  Account Name: svc_backup    Failure Code: 0x18  Client Address: 203.0.113.45
```

`0xC000006A` = senha errada. `0xC0000064` = usuário inexistente (indica enumeração). No Kerberos, EventID 4771 com `Failure Code 0x18` significa pré-autenticação falhou — senha errada.

**Falso positivo clássico.** Troca de senha recente com celular, tablet ou serviço de sincronização ainda usando a credencial antiga: gera rajada de 4625 na **mesma conta**, do **mesmo dispositivo**, com `0xC000006A`. Isso é falha de configuração, não ataque. O sinal de ataque é a **diversidade de contas** a partir de uma origem.

**Contenção.** Bloquear o IP de origem na borda, forçar MFA (autenticação multifator) e verificar se algum 4624 de sucesso veio do mesmo IP — se veio, já houve invasão.

### LLMNR/NBT-NS poisoning — o impostor da rede local

**O que é.** Quando o DNS (Domain Name System) falha em resolver um nome, o Windows grita na rede local via LLMNR (porta 5355/UDP) e NBT-NS (137/UDP): "alguém conhece o servidor `fileserv`?". Um atacante com Responder responde "sou eu" e captura o desafio-resposta NTLMv2 da vítima. É o equivalente a alguém no corredor dizendo "pode me entregar, eu sou do financeiro".

**Rastro.** Sysmon EventID 3 (conexão de rede) mostrando tráfego para 5355/UDP e 137/UDP concentrado em um host, e EventID 4776 no DC ("The computer attempted to validate the credentials") com nome de estação estranho:

```
EventID=4776
Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
Logon Account:          jsilva
Source Workstation:     WKS-FINANCE-04
Error Code:             0x0
```

**Contenção.** Desabilitar LLMNR e NBT-NS por política (isso é mitigação permanente), isolar o host que responde a tudo.

### Delegação, ACL e vulnerabilidades de software

**Delegação irrestrita (unconstrained).** Um servidor com essa configuração guarda o TGT de todo mundo que se conecta a ele. Se ele cair, todos caem junto — inclusive administradores. Sinal: 4769 com `Ticket Options` indicando delegação encaminhável, ou uma conta de computador acessando recursos "em nome de" contas privilegiadas. **Delegação restrita (constrained)** limita a serviços específicos; o abuso aparece como 4769 com campo `Transited Services` preenchido.

**Abuso de ACL/ACE.** Permissões herdadas mal configuradas (por exemplo, um grupo de helpdesk com `WriteDACL` sobre um grupo administrativo) formam caminhos que o BloodHound mapeia. Rastro: 4662 alterando `nTSecurityDescriptor`, 4738 (conta modificada), 5136 (objeto de diretório alterado).

**Zerologon e PrintNightmare** são **categorias de exploração de vulnerabilidade** (T1068), não abuso de função. Zerologon abusa do canal seguro Netlogon contra o próprio DC; procure EventID 5805/5723 e 4742 alterando a senha de uma conta de computador de DC. PrintNightmare abusa do serviço de spool de impressão; procure Sysmon EventID 1 com `spoolsv.exe` gerando processo filho anômalo e 4688 equivalente.

### Persistência: contas, grupos, GPO e o cpassword

| EventID | Significado | O que checar |
|---|---|---|
| 4720 | Conta de usuário criada | Fora do horário comercial, criador não é do RH/IT |
| 4728 | Membro adicionado a grupo global de segurança | Domain Admins, Enterprise Admins |
| 4732 | Membro adicionado a grupo local de segurança | Administrators local em servidor |
| 4756 | Membro adicionado a grupo universal | Enterprise Admins |
| 5136 | Objeto de diretório modificado | Alteração de GPO (Group Policy Object) |

Sequência clássica de persistência: 4720 (cria `svc_helpdesk2`) seguido, minutos depois, de 4728 adicionando a mesma conta a **Domain Admins**, tudo às 03h14, feito por uma conta que nunca cria usuários. Isso é escalação, não administração.

**GPO maliciosa.** O 5136 registra alteração em objetos do diretório, incluindo GPOs. Um atacante altera a política para rodar um script de logon em toda a frota. Sempre correlacione 5136 com a janela de mudança aprovada.

**O legado do cpassword.** As Group Policy Preferences (GPP) permitiam definir senha de administrador local direto na política. Essa senha ficava no compartilhamento **SYSVOL**, em arquivos XML (`Groups.xml`, `Services.xml`), no atributo `cpassword`, cifrada com uma chave **que a Microsoft publicou**. Qualquer usuário do domínio lê o SYSVOL. Corrigido em 2014 (MS14-025), mas os arquivos antigos **permanecem** em muitos domínios. Rastro de caça: acesso incomum a `\\corp.local\SYSVOL\...\Policies\` a partir de estação de usuário comum, visível em EventID 5145 (acesso a compartilhamento) ou no Zeek `smb_files.log`. Ação: varrer o SYSVOL, remover os XML com `cpassword` e adotar LAPS (Local Administrator Password Solution).

### Exercícios — Ataques comuns ao Active Directory

1. Em 4 minutos, o usuário `jsilva` (10.10.20.57) gerou 18 eventos 4769 para 18 SPNs distintos, todos com `Ticket Encryption Type: 0x17`, todos com `Failure Code: 0x0`. Qual ataque é e por que os eventos são de **sucesso**?
2. Um alerta dispara: 47 eventos 4625 com `Status: 0xC000006A`, todos para a conta `maria.costa`, todos vindos de 10.10.44.12, espalhados por 6 horas. Verdadeiro positivo ou falso positivo? Qual pergunta você faz primeiro?
3. Você encontra um 4769 para a conta `svcadmin_bkp@CORP.LOCAL` acessando `cifs/fs01.corp.local`, sem nenhum 4768 nos 10 minutos anteriores. A busca no diretório mostra que a conta **não existe**. Nomeie o ataque e a ação imediata.
4. Um 4662 registra `Properties: {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}` com `Subject Account Name: AZUREADCONNECT$` a partir do host `10.10.5.20`. Como decidir entre incidente crítico e operação normal?
5. Escreva em palavras a diferença de rastro entre Golden Ticket e Silver Ticket, do ponto de vista de **quais logs faltam**.

<details><summary>Ver gabarito</summary>

**1.** Kerberoasting (T1558.003). Os eventos são de **sucesso** porque pedir um ticket de serviço é uma operação legítima — qualquer usuário autenticado pode fazê-lo. O ataque acontece **depois**, offline, na quebra da senha; por isso nunca haverá evento de falha. Os três indicadores somados fecham o caso: volume (18 SPNs), janela curta (4 minutos) e RC4 (`0x17`) sendo solicitado deliberadamente por ser mais fácil de quebrar que AES256 (`0x12`). Próximo passo: verificar se os SPNs pertencem a contas de usuário (e não de máquina, que terminam em `$`) e isolar 10.10.20.57.

**2.** Provavelmente **falso positivo**. O padrão é brute force pelo formato (muitas falhas em uma conta), mas três detalhes empurram para credencial em cache: origem única e **interna**, uma única conta, e distribuição ao longo de 6 horas (ataque real é em rajada, não a cada poucos minutos). A primeira pergunta é: **`maria.costa` trocou a senha recentemente?** Em seguida, identifique o dispositivo 10.10.44.12 — celular, tablet, sessão RDP esquecida ou serviço mapeando unidade de rede com a senha antiga. Confirme também se houve 4740 (bloqueio) e se algum 4624 de sucesso veio dessa origem.

**3.** **Golden Ticket** (T1558.001). Dois indicadores independentes apontam para ticket forjado: uso de TGS (4769) sem a emissão do TGT (4768) que obrigatoriamente o precederia, e conta inexistente no diretório — o AD nunca emitiria bilhete para quem não existe, logo o bilhete foi fabricado offline com o hash do krbtgt. Verifique também o tempo de vida do ticket. Ação imediata: escalar como incidente crítico (P1), isolar 10.10.30.91 e o servidor `fs01`, e acionar N3 para o duplo reset da senha do krbtgt. O N1 **não** executa esse reset.

**4.** Não decida pelo EventID, decida pelo **ator e pela origem**. `AZUREADCONNECT$` é conta de computador (termina em `$`) e o Entra Connect/Azure AD Connect **legitimamente** usa direitos de replicação para sincronizar o diretório com a nuvem. Valide: (a) o host 10.10.5.20 é mesmo o servidor de sincronização inventariado? (b) o evento ocorre no ciclo habitual (a cada 30 minutos, por padrão)? Se sim, é normal e deve entrar na lista de exceção documentada. Se o mesmo GUID aparecesse com um usuário comum como `jsilva`, ou de uma estação de trabalho, seria DCSync (T1003.006) — incidente crítico.

**5.** No **Golden Ticket** falta o **4768** no controlador de domínio: o TGT foi forjado, então o DC nunca o emitiu, mas o 4769 aparece porque o atacante ainda pede tickets de serviço ao DC. No **Silver Ticket** falta o **4769** no DC: o TGS é forjado direto com o hash da conta de serviço e o controlador de domínio **nunca é consultado** — só existe o 4624 no servidor-alvo. Consequência prática: Golden Ticket é detectável olhando apenas o DC; Silver Ticket **exige correlacionar o log do servidor de destino com o log do DC**, procurando um logon que não tem ticket correspondente. Por isso é essencial coletar Security Log de servidores membros, não só dos controladores.

</details>


## Tabela mestra de EventIDs do Windows para o Active Directory

Pense no Windows como um prédio com câmeras em cada porta. Cada vez que alguém entra, sai, tenta entrar com a chave errada ou mexe no quadro de chaves da portaria, uma câmera grava um clipe. Esse clipe é o **evento de segurança**, e cada tipo de clipe tem um número: o **EventID**. O analista de SOC (Security Operations Center, o centro de operações de segurança) não decora tudo, mas precisa reconhecer de imediato os números que contam a história de um ataque ao Active Directory.

Os eventos ficam no log **Security** de cada máquina Windows. Os eventos de autenticação Kerberos e NTLM só existem no **Controlador de Domínio** (DC), porque é ele quem valida as credenciais. Já 4688 e 4624 aparecem também nas estações. Isso muda tudo na hora de escolher onde caçar.

### A tabela mestra

| ID | Nome | O que significa | Quando é suspeito |
|---|---|---|---|
| 4624 | Logon bem-sucedido | Alguém entrou com sucesso na máquina | Logon tipo 3 ou 10 de conta privilegiada vinda de estação comum; rajada de logons em muitos hosts |
| 4625 | Falha de logon | Credencial recusada | Muitas falhas para muitos usuários (spray) ou muitas para um usuário (força bruta) |
| 4634 | Logoff | Sessão encerrada | Isolado, quase nunca; útil para calcular duração da sessão |
| 4648 | Logon com credencial explícita | Alguém usou "executar como" outro usuário | Conta comum invocando conta de admin; rastro clássico de movimento lateral (T1078) |
| 4662 | Operação em objeto do AD | Acesso a um objeto do diretório com GUID de propriedade | GUID de replicação usado por conta que não é DC = DCSync (T1003.006) |
| 4672 | Privilégios especiais atribuídos ao logon | O logon recebeu direitos de administrador | Conta de serviço ou usuário comum recebendo privilégio de admin |
| 4688 | Novo processo criado | Um programa foi executado | Processos de descoberta e ferramentas de dump saindo de processo pai estranho |
| 4697 | Serviço instalado | Um serviço novo foi registrado | Serviço criado remotamente com nome aleatório (PsExec, Impacket) |
| 4720 | Conta de usuário criada | Novo usuário no domínio ou local | Criação fora do horário do time de identidade |
| 4726 | Conta de usuário excluída | Usuário removido | Exclusão logo após criação = tentativa de apagar rastro |
| 4728 | Membro adicionado a grupo global com segurança | Entrou em grupo global (ex.: Domain Admins) | Sempre revisar; fora de janela de mudança é incidente |
| 4732 | Membro adicionado a grupo local com segurança | Entrou em grupo local (ex.: Administrators) | Adição em servidor crítico sem chamado |
| 4738 | Conta de usuário alterada | Atributos do usuário mudaram | Ativação de "senha nunca expira" ou desativação de pré-autenticação |
| 4740 | Conta bloqueada | Bloqueio por excesso de erros | Vários bloqueios simultâneos = ataque ou senha antiga em serviço |
| 4756 | Membro adicionado a grupo universal com segurança | Entrou em grupo universal (ex.: Enterprise Admins) | Praticamente sempre digno de investigação |
| 4768 | TGT do Kerberos solicitado | Pedido do "crachá principal" (Ticket Granting Ticket) | Código de falha 0x18 (senha errada) em massa; TGT de IP incomum |
| 4769 | Ticket de serviço solicitado | Pedido de ticket para um serviço | Criptografia RC4 (0x17) em massa por um usuário = Kerberoasting (T1558.003) |
| 4771 | Pré-autenticação Kerberos falhou | Senha errada na etapa inicial | Volume alto = spray; 0x18 repetido por origem única |
| 4776 | Validação de credencial NTLM | O DC validou uma credencial NTLM | Erro 0xC000006A em massa; uso de NTLM onde o padrão é Kerberos |
| 5136 | Objeto do AD modificado | Um atributo do diretório mudou | Alteração em GPO, em ACL de objeto ou em `servicePrincipalName` |
| 5140 | Compartilhamento de rede acessado | Alguém abriu um share | Acesso a `ADMIN$`, `C$` ou `IPC$` de origem inesperada |
| 5145 | Verificação detalhada de acesso a share | Acesso a arquivo dentro do share | Leitura em massa do `SYSVOL` ou de pastas de backup |
| 7045 | Serviço instalado (log System) | Serviço registrado, visto no log System | Nome de serviço aleatório e binário em `C:\Windows\Temp` |
| 1102 | Log de auditoria limpo | Alguém apagou o log de segurança | Quase sempre incidente (T1070.001); só é normal com chamado formal |

### Os tipos de logon do 4624 (a tabela que você mais vai usar)

O 4624 sozinho não diz nada. O que importa é o campo **Logon Type**, que responde "por qual porta a pessoa entrou".

| Tipo | Nome | O que indica na prática |
|---|---|---|
| 2 | Interactive | Alguém digitou usuário e senha no teclado físico da máquina |
| 3 | Network | Acesso remoto a recurso de rede (share SMB, consulta ao DC). O mais comum de todos |
| 4 | Batch | Tarefa agendada rodando |
| 5 | Service | Um serviço do Windows iniciou com aquela conta |
| 7 | Unlock | A estação estava bloqueada e foi desbloqueada |
| 8 | NetworkCleartext | Senha trafegou em texto claro na rede (IIS básico, alguns apps antigos) |
| 9 | NewCredentials | `runas /netonly`; credencial diferente usada só para a rede |
| 10 | RemoteInteractive | RDP (Remote Desktop Protocol, área de trabalho remota) |
| 11 | CachedInteractive | Logon com credencial em cache, sem contato com o DC (notebook fora da rede) |

**Leitura rápida para o N1:** tipo 2 e 7 na estação do próprio usuário é rotina. Tipo 10 (RDP) para um servidor por uma conta que nunca usou RDP é suspeito. Tipo 9 é o rastro típico de ferramentas que injetam credencial. Tipo 8 nunca deveria existir em ambiente moderno.

### Como aparece no log real

```
An account was successfully logged on.

Subject:
    Security ID:        NULL SID
    Account Name:       -
Logon Type:            10
New Logon:
    Security ID:        CORP\admin.rodrigo
    Account Name:       admin.rodrigo
    Account Domain:     CORP.LOCAL
    Logon ID:           0x3E9A17
Network Information:
    Workstation Name:   WKS-VENDAS-042
    Source Network Address: 10.10.34.77
    Source Port:        51422
Detailed Authentication Information:
    Logon Process:      User32
    Authentication Package: Negotiate
EventID: 4624 | Computer: DC01.corp.local | Time: 2026-03-11 02:47:13
```

Campo a campo: `Logon Type 10` é RDP; `New Logon` é quem entrou; `Source Network Address` é de onde veio; `Workstation Name` é o nome da máquina de origem. O que salta aos olhos: uma conta de administrador entrando por RDP **no controlador de domínio**, às 02h47, partindo de uma estação de vendas. Nenhum desses três fatos, isolado, prova algo. Os três juntos são um incidente.

### Caça no SIEM — KQL (Sentinel e Defender)

```kql
// Kerberoasting: um usuário pede muitos tickets de serviço com RC4 (T1558.003)
SecurityEvent
| where EventID == 4769                       // ticket de serviço solicitado
| where TicketEncryptionType == "0x17"        // RC4, criptografia fraca e quebrável offline
| where ServiceName !endswith "$"             // ignora contas de máquina (ruído normal)
| summarize Servicos = dcount(ServiceName), Lista = make_set(ServiceName, 20)
    by TargetUserName, IpAddress, bin(TimeGenerated, 10m)
| where Servicos >= 8                         // muitos serviços diferentes em 10 min = anômalo
```

```kql
// Password spraying: uma origem erra a senha de MUITOS usuários diferentes
SecurityEvent
| where EventID in (4625, 4771)               // falha de logon e falha de pré-autenticação
| where Status in ("0xC000006A", "0x18")      // senha incorreta (não é usuário inexistente)
| summarize Vitimas = dcount(TargetUserName), Tentativas = count()
    by IpAddress, bin(TimeGenerated, 30m)
| where Vitimas >= 15 and Tentativas < Vitimas * 3   // poucas tentativas por conta = evita lockout
```

```kql
// DCSync: conta que não é DC pedindo replicação do diretório (T1003.006)
SecurityEvent
| where EventID == 4662
| where Properties has "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"  // GUID DS-Replication-Get-Changes
    or Properties has "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"   // GUID ...-Get-Changes-All
| where SubjectUserName !endswith "$"          // contas de máquina (DCs) replicam legitimamente
| project TimeGenerated, Computer, SubjectUserName, ObjectName
```

```kql
// Conta privilegiada logando fora do horário comercial
let Privilegiadas = dynamic(["admin.rodrigo","svc_backup","maria.costa.adm"]);
SecurityEvent
| where EventID == 4624 and LogonType in (3, 10)
| where TargetUserName in~ (Privilegiadas)
| extend Hora = datetime_part("Hour", TimeGenerated)
| where Hora < 7 or Hora > 20 or dayofweek(TimeGenerated) in (0d, 6d)
| project TimeGenerated, TargetUserName, LogonType, Computer, IpAddress
```

```kql
// Adição a grupo privilegiado (global, local e universal)
SecurityEvent
| where EventID in (4728, 4732, 4756)
| where TargetUserName has_any ("Domain Admins","Enterprise Admins","Administrators","Schema Admins")
| project TimeGenerated, Grupo = TargetUserName, MembroAdicionado = MemberName,
          QuemFez = SubjectUserName, Computer
```

Na tabela `IdentityLogonEvents` (Defender for Identity) o mesmo raciocínio fica mais curto, porque ela já correlaciona identidade e dispositivo:

```kql
IdentityLogonEvents
| where Timestamp > ago(24h)
| where LogonType == "Remote desktop"
| where AccountUpn has "adm"                   // convenção de nomes das contas privilegiadas
| summarize Destinos = dcount(DeviceName) by AccountUpn, IPAddress, bin(Timestamp, 1h)
| where Destinos >= 5                          // uma conta saltando por muitos hosts = lateral
```

### Caça no SIEM — SPL (Splunk)

```spl
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$"
| bin _time span=10m
| stats dc(Service_Name) as servicos values(Service_Name) as lista by _time, Account_Name, Client_Address
| where servicos >= 8
```

```spl
index=wineventlog (EventCode=4625 OR EventCode=4771) (Status=0xC000006A OR Failure_Code=0x18)
| bin _time span=30m
| stats dc(Account_Name) as vitimas count as tentativas by _time, Source_Network_Address
| where vitimas >= 15
| sort - vitimas
```

```spl
index=wineventlog EventCode=4662 Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*"
| search NOT Account_Name="*$"
| table _time, ComputerName, Account_Name, Object_Name
```

```spl
index=wineventlog EventCode=4624 (Logon_Type=3 OR Logon_Type=10)
    Account_Name IN ("admin.rodrigo","svc_backup")
| eval hora=strftime(_time,"%H")
| where hora < 7 OR hora > 20
| table _time, Account_Name, Logon_Type, ComputerName, Source_Network_Address
```

```spl
index=wineventlog (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
    Group_Name IN ("Domain Admins","Enterprise Admins","Administrators")
| table _time, Group_Name, Member_Name, Account_Name, ComputerName
```

**Erro comum de analista júnior:** contar 4625 sem separar o código de status. `0xC0000064` (usuário não existe) costuma ser erro de digitação ou scanner burro; `0xC000006A` (senha errada) é o que realmente indica spray. Outro erro clássico: alarmar com 4769 RC4 de contas terminadas em `$` — são contas de máquina, ruído normal.

### Checklist dos primeiros 15 minutos — suspeita de conta privilegiada comprometida

1. **Minutos 0–2 — Confirmar o escopo.** Liste todos os 4624 e 4625 daquela conta nas últimas 24h. Anote hosts de destino, IPs de origem e tipos de logon.
2. **Minutos 2–4 — Validar com o dono.** Contate o titular da conta por canal fora de banda (telefone, não e-mail da conta suspeita) e pergunte se a atividade é dele.
3. **Minutos 4–6 — Procurar persistência.** Busque 4720, 4728, 4732, 4756 e 4738 disparados por essa conta. Qualquer criação de usuário ou adição a grupo eleva o caso a incidente confirmado.
4. **Minutos 6–8 — Procurar dump de credencial.** Verifique 4662 com GUID de replicação, 4688 com processos suspeitos e 4697/7045 com serviços novos.
5. **Minutos 8–10 — Checar destruição de rastro.** Um único 1102 em qualquer DC nesse intervalo muda a resposta inteira: assuma comprometimento.
6. **Minutos 10–12 — Contenção proposta.** Escale para o N2 com a recomendação: resetar a senha **duas vezes** (invalida o Kerberos corretamente), desabilitar a conta e isolar os hosts de origem.
7. **Minutos 12–15 — Registrar.** Ticket com linha do tempo, EventIDs, IPs, hosts, contas afetadas e a técnica MITRE ATT&CK correspondente. Preserve os logs antes que a retenção os apague.

Regra de ouro: o N1 **não** reseta senha de administrador de domínio por conta própria. Ele coleta, correlaciona e escala com evidência pronta.

### Exercícios — Tabela mestra de EventIDs e caçada no SIEM

1. Um alerta traz 47 eventos 4771 com `Failure Code 0x18`, todos vindos de `10.10.34.77` em 25 minutos, atingindo 41 usuários distintos, no máximo 2 tentativas por usuário. Que ataque é esse e por que o atacante limitou as tentativas?
2. Você vê `4769` com `Ticket Encryption Type 0x17` para o serviço `MSSQLSvc/sql01.corp.local`, solicitado pela conta `WKS-042$`. Verdadeiro positivo de Kerberoasting ou falso positivo? Justifique.
3. O log abaixo apareceu no `DC01`. Qual é o próximo passo imediato da investigação?

```
EventID: 4662 | Computer: DC01.corp.local | 2026-03-11 03:12:44
Subject Account Name: jsilva
Object Type: domainDNS
Properties: Control Access {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}
Accesses: Control Access
```

4. Um 4624 mostra `Logon Type 11` para `maria.costa` no notebook `NB-1180` às 21h30. O time de service desk abriu um alerta. É incidente?
5. Ordene por prioridade de triagem, do mais grave para o menos grave: 4634, 1102, 4740, 4756.

<details><summary>Ver gabarito</summary>

1. **Password spraying** (T1110.003). O código `0x18` é senha incorreta, e o padrão "muitos usuários, poucas tentativas cada" é a assinatura da técnica. O atacante limita a 1–2 tentativas por conta justamente para ficar abaixo do limite da política de bloqueio de conta e evitar gerar 4740 em massa, que acenderia o alerta imediatamente. Próximo passo: verificar se houve algum 4624 bem-sucedido da mesma origem — é isso que separa "tentativa" de "comprometimento".

2. **Falso positivo.** A conta solicitante termina em `$`, ou seja, é uma **conta de máquina** (`WKS-042$`), e computadores pedem tickets de serviço o tempo todo como parte da operação normal do Kerberos. Kerberoasting é feito por conta de **usuário** pedindo muitos SPNs diferentes em curto intervalo. A regra correta precisa do filtro `ServiceName !endswith "$"` ou do lado do solicitante, conforme o campo disponível no seu SIEM. Um único ticket para um único serviço também não caracteriza a técnica.

3. **DCSync em andamento** (T1003.006). O GUID `1131f6ad-...` é o direito `DS-Replication-Get-Changes-All`, que permite pedir a replicação de segredos do diretório — na prática, extrair hashes de senha do domínio inteiro. A conta `jsilva` é um usuário comum, não um controlador de domínio, então não tem motivo legítimo para isso. Próximo passo imediato: tratar como comprometimento de domínio, escalar para o N2 e o responsável de identidade **agora**, levantar todos os 4624 e 4648 de `jsilva` nas últimas 72h para achar a máquina de origem, e verificar quem concedeu essa ACL (procure 5136 no objeto `domainDNS`). Não espere resposta do usuário para escalar.

4. **Não, é rotina.** `Logon Type 11` é logon com credencial em cache — típico de notebook ligado fora da rede corporativa, sem alcançar o controlador de domínio. É exatamente o que acontece quando alguém liga a máquina em casa antes de conectar a VPN. Vira relevante só se aparecer em um **servidor** dentro do datacenter, onde não deveria haver logon em cache.

5. **1102 → 4756 → 4740 → 4634.** O `1102` (log de auditoria limpo) é o mais grave: é destruição de evidência e quase nunca tem explicação inocente. `4756` adiciona alguém a grupo universal, o que pode significar `Enterprise Admins` — comprometimento total da floresta. `4740` (conta bloqueada) é frequentemente causado por senha antiga em serviço ou celular, então é médio. `4634` (logoff) é puramente informativo e sozinho não vale triagem.

</details>

## Mini-laboratório — Caçada de eventos do Active Directory

**Objetivo:** gerar e reconhecer, com as próprias mãos, os EventIDs 4624, 4625, 4771, 4720 e 4728 em um laboratório isolado.

**Pré-requisitos (tudo gratuito):**
- VirtualBox com uma VM Windows Server (imagem de avaliação de 180 dias da Microsoft) e uma VM Windows 10/11 de avaliação.
- Rede da VM configurada como **Rede Interna** no VirtualBox — sem saída para a internet.
- Wireshark instalado na estação.

**Passo 1 — Promover o domínio.** No servidor, com PowerShell como administrador:
```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName "corp.local" -InstallDNS
```
Após o reinício, você tem o `DC01.corp.local`. *Observar:* o log Security passa a receber centenas de eventos por minuto — essa é a linha de base.

**Passo 2 — Criar usuários de teste.**
```powershell
New-ADUser -Name "jsilva" -SamAccountName "jsilva" -Enabled $true `
  -AccountPassword (Read-Host -AsSecureString "Senha")
New-ADUser -Name "svc_backup" -SamAccountName "svc_backup" -Enabled $true `
  -AccountPassword (Read-Host -AsSecureString "Senha")
```
*Observar:* dois eventos **4720** no Visual de Eventos, em `Windows Logs > Security`.

**Passo 3 — Ligar a auditoria de linha de comando (para o 4688 ser útil).**
```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
```

**Passo 4 — Gerar logon bem-sucedido e falho.** Ingresse a estação no domínio, faça login como `jsilva` (gera **4624 tipo 2** na estação e **4768** no DC) e depois erre a senha três vezes de propósito (gera **4625** e **4771** com código `0x18` no DC).

**Passo 5 — Gerar logon de rede.** Da estação, acesse `\\DC01\NETLOGON` no Explorer. *Observar:* **4624 tipo 3** e **5140** no DC.

**Passo 6 — Gerar adição a grupo privilegiado.**
```powershell
Add-ADGroupMember -Identity "Domain Admins" -Members jsilva
```
*Observar:* **4728** no DC, com `Member Name` = `jsilva`. Remova em seguida com `Remove-ADGroupMember`.

**Passo 7 — Filtrar como um analista.** No Visualizador de Eventos, use *Filtrar Log Atual* com os IDs `4624,4625,4720,4728,4771` e exporte para `.evtx`. Como alternativa em linha de comando:
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625,4771} -MaxEvents 50 |
  Select-Object TimeCreated, Id, @{n='Msg';e={$_.Message.Split("`n")[0]}}
```

**Critério de sucesso:** você consegue apontar, no log exportado, qual evento corresponde a cada ação do laboratório, dizer o tipo de logon de cada 4624 e explicar por que o 4728 seria o alerta mais grave se aparecesse em produção.

## O que um SOC Level 1 realmente precisa saber

- 🟢 O Active Directory é a portaria única da empresa: quem controla o domínio controla tudo. Todo alerta que toca o DC sobe de prioridade.
- 🟢 **4624 sem olhar o Logon Type não significa nada.** Decore pelo menos 2 (teclado), 3 (rede), 10 (RDP) e 11 (cache).
- 🟢 4625 e 4771 são falhas: separe sempre pelo código de status. `0xC000006A` e `0x18` (senha errada) importam; `0xC0000064` (usuário inexistente) costuma ser ruído.
- 🟢 Muitos usuários com poucas falhas cada = **password spraying**. Um usuário com muitas falhas = força bruta. A diferença muda a resposta.
- 🟢 4720, 4728, 4732 e 4756 são mudanças de privilégio. Fora de janela de mudança aprovada, trate como incidente até prova em contrário.
- 🟢 **1102 (log de auditoria limpo) é escalonamento imediato.** Nunca engavete.
- 🟡 4769 com criptografia RC4 (`0x17`) em vários serviços num intervalo curto é a assinatura de **Kerberoasting**; ignore contas de máquina (terminadas em `$`).
- 🟡 4662 com os GUIDs de replicação, vindo de conta que não é controlador de domínio, é **DCSync** — comprometimento de domínio, não "alerta médio".
- 🟡 4697 e 7045 (serviço novo) com nome aleatório e binário em pasta temporária é o rastro típico de execução remota estilo PsExec/Impacket.
- 🟡 GPO, LDAP, Kerberos e NTLM já foram vistos nos trechos anteriores — aqui só importa saber em qual EventID cada um deixa marca.
- 🔴 Correlacionar 4648 + 4624 tipo 9 + 4672 na mesma janela é o padrão de movimento lateral com credencial roubada; monte a linha de tempo antes de escalar.
- 🔴 Resetar senha de conta privilegiada exige **dois resets** para invalidar tickets Kerberos; isso é decisão de N2, não do N1.

## Resumo em 10 linhas

1. O Active Directory concentra identidade, autenticação e política de toda a rede Windows.
2. Cada ação relevante vira um evento numerado no log Security; o DC é a fonte mais rica.
3. 4624 e 4625 contam quem entrou e quem falhou; o Logon Type diz por qual porta.
4. 4768, 4769 e 4771 são Kerberos; 4776 é NTLM; os códigos de erro separam ruído de ataque.
5. 4720, 4726, 4728, 4732, 4738 e 4756 registram mudanças de conta e de privilégio.
6. 4662 com GUID de replicação denuncia DCSync; 4697 e 7045 denunciam execução remota por serviço.
7. 5136, 5140 e 5145 mostram alterações no diretório e acesso a compartilhamentos.
8. 1102 significa log apagado — evidência sendo destruída, prioridade máxima.
9. Queries em KQL e SPL transformam esses IDs em detecções: spraying, Kerberoasting, DCSync, horário anômalo e mudança de grupo.
10. Na suspeita de conta privilegiada comprometida, o N1 tem 15 minutos para escopo, validação, busca de persistência e escalonamento documentado.



---
