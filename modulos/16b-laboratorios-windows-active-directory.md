# Laboratórios de Windows e Active Directory para o SOC

## Por que este módulo importa para o SOC

A maioria absoluta dos alertas que chegam à fila de um SOC (Security Operations Center, ou Centro de Operações de Segurança) Nível 1 nasce dentro de máquinas Windows e do Active Directory. É lá que o usuário faz login, é lá que o atacante rouba credenciais e é lá que ele se move de um computador para outro. Um analista que sabe ler rede mas não sabe abrir um Event Viewer fica cego na metade da investigação. Neste módulo você monta um laboratório real, gera atividade, e aprende a ver o rastro que ela deixa — primeiro no Windows puro, depois com Sysmon, depois em um domínio inteiro.

### Índice do módulo

- Windows essencial para SOC e Sysmon
- Montar o controlador de domínio e auditar autenticação
- Detectar password spraying, movimento lateral e ambientes prontos
- LAB 15 — Desafio final integrador

## LAB 8 — Windows essencial para SOC

### Objetivo

Ao final deste laboratório você consegue, sozinho e sem consultar ninguém: navegar no Event Viewer, filtrar por EventID, salvar uma consulta customizada, extrair as mesmas informações via PowerShell, usar as quatro ferramentas Sysinternals mais usadas na triagem e listar onde um programa malicioso costuma se esconder para sobreviver ao reboot.

### Pré-requisitos

- Uma máquina virtual Windows 10 ou Windows 11 (ou Windows Server 2019/2022), com snapshot tirado antes de começar.
- Conta com privilégio de administrador local nessa VM (usaremos `admin.rodrigo` como exemplo).
- Acesso à internet para baixar o pacote Sysinternals Suite.
- Nada disso em máquina de produção. Laboratório é laboratório.

### Passos numerados

1. **Abra o Event Viewer.** Tecle `Win+R`, digite `eventvwr.msc`, Enter. Pense no Event Viewer como o "livro de ocorrências da portaria" do computador: tudo que entra, sai ou dá errado fica registrado ali, separado por caderno.
2. **Conheça os cadernos principais.** Em `Windows Logs` você tem `Security` (autenticação e permissões), `System` (drivers, serviços, desligamentos) e `Application` (programas). O caderno mais importante para o SOC é o `Security`.
3. **Filtre por EventID.** Clique com o botão direito em `Security` → `Filter Current Log` → campo "All Event IDs" → digite `4624,4625,4688`. Você acabou de pedir só logons com sucesso, logons falhos e criação de processo.
4. **Salve a consulta.** Com o filtro aplicado, vá em `Action` → `Save Filter to Custom View`, nomeie `SOC - Triagem Basica` e salve. Ela passa a aparecer em `Custom Views` e você não precisa remontar o filtro nunca mais.
5. **Repita tudo via PowerShell.** Abra o PowerShell como administrador e rode os comandos da tabela da próxima seção, um a um, lendo a saída antes de passar ao seguinte.
6. **Instale a Sysinternals Suite.** Baixe do site oficial da Microsoft (`live.sysinternals.com` ou o pacote `SysinternalsSuite.zip` do Microsoft Learn), extraia em `C:\Tools\Sysinternals`.
7. **Abra as quatro ferramentas** — Process Explorer, Process Monitor, Autoruns e TCPView — e siga a seção "O que observar".
8. **Faça o inventário de persistência**, conferindo cada um dos cinco lugares listados adiante.

### PowerShell para investigação, com saída comentada

O comando mais importante da sua vida de analista é o `Get-WinEvent` com `FilterHashtable`. Ele é rápido porque filtra dentro do próprio serviço de log, e não em memória.

```powershell
# Últimos 20 logons com sucesso (4624) das últimas 24 horas
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    ID        = 4624
    StartTime = (Get-Date).AddHours(-24)
} -MaxEvents 20 | Select-Object TimeCreated, Id, @{
    N='Usuario'; E={$_.Properties[5].Value}
}, @{
    N='LogonType'; E={$_.Properties[8].Value}
}, @{
    N='IPOrigem'; E={$_.Properties[18].Value}
} | Format-Table -AutoSize
```

Saída típica (dados fictícios):

```text
TimeCreated          Id Usuario      LogonType IPOrigem
-----------          -- -------      --------- --------
03/09/2026 08:12:04 4624 jsilva               2 -
03/09/2026 08:31:47 4624 maria.costa          3 10.10.20.45
03/09/2026 09:02:11 4624 svc_backup           5 -
03/09/2026 09:14:55 4624 admin.rodrigo       10 10.10.30.8
```

Leitura: `LogonType 2` é logon interativo no teclado da máquina; `3` é acesso via rede (compartilhamento SMB, por exemplo); `5` é o serviço iniciando com a conta; `10` é RDP (Remote Desktop Protocol, área de trabalho remota). O campo `IPOrigem` com `-` significa logon local, sem rede envolvida.

| Comando | Para que serve na triagem | O que chama atenção |
|---|---|---|
| `Get-Process -Name svchost \| Select-Object Id,Path,Company` | Lista processos com caminho e fabricante | `svchost.exe` fora de `C:\Windows\System32` |
| `Get-Service \| Where-Object Status -eq 'Running'` | Serviços ativos | Serviço com nome aleatório, sem descrição |
| `Get-NetTCPConnection -State Established` | Conexões TCP abertas e o PID dono | Conexão para IP público a partir de processo de escritório |
| `Get-CimInstance Win32_Process \| Select ProcessId,Name,CommandLine` | Linha de comando completa | `powershell.exe -enc`, `rundll32` com URL |
| `Get-LocalUser \| Select Name,Enabled,LastLogon` | Contas locais | Conta nova habilitada que ninguém pediu |
| `Get-ScheduledTask \| Where State -eq 'Ready'` | Tarefas agendadas | Tarefa criada hoje, apontando para `%APPDATA%` |
| `Test-NetConnection 10.10.50.10 -Port 445` | Testa alcance e porta | Porta 445 aberta para estação, não para servidor |
| `Resolve-DnsName suspeito.example.com` | Resolve nome para IP | Domínio recém-criado, TTL muito baixo |
| `Get-FileHash C:\Users\jsilva\AppData\Roaming\upd.exe -Algorithm SHA256` | Hash para consulta em threat intel | Hash desconhecido por todos os fornecedores |

### O que observar nas ferramentas Sysinternals

| Ferramenta | Olhe primeiro | Sinal suspeito clássico |
|---|---|---|
| **Process Explorer** | Árvore de processos (pai → filho) e a coluna `Verified Signer` | `winword.exe` como pai de `cmd.exe` ou `powershell.exe` |
| **Process Monitor** | Filtros por `Operation is RegSetValue` e por `Path contains Run` | Escrita em chave de execução automática logo após abrir um anexo |
| **Autoruns** | Aba `Logon`, `Scheduled Tasks`, `Services`, `WMI`, com "Hide Microsoft entries" ligado | Entrada sem assinatura apontando para `%TEMP%` |
| **TCPView** | Coluna `Remote Address` e `Process` | Processo de usuário mantendo sessão TLS constante com IP 203.0.113.77 |

### Onde ficam os artefatos de persistência

| Mecanismo | Local exato | Técnica MITRE ATT&CK |
|---|---|---|
| Chaves Run | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` e a mesma em `HKLM` | T1547.001 |
| Pasta Startup | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` | T1547.001 |
| Tarefas agendadas | `C:\Windows\System32\Tasks` (EventID 4698 = tarefa criada) | T1053.005 |
| Serviços | `HKLM\SYSTEM\CurrentControlSet\Services` (EventID 7045 no log System) | T1543.003 |
| Assinatura WMI | Namespace `root\subscription` (`__EventFilter`, `CommandLineEventConsumer`) | T1546.003 |

### Como aparece nos logs

Criação de processo, EventID 4688 do log Security, com auditoria de linha de comando habilitada:

```text
EventID: 4688
Log Name: Security
Message: A new process has been created.
  Creator Subject:
    Account Name:       jsilva
    Account Domain:     CORP
  Process Information:
    New Process ID:     0x1a4c
    New Process Name:   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
    Token Elevation Type: %%1936
    Creator Process Name: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
    Process Command Line: powershell.exe -nop -w hidden -c IEX(...)
```

Campos que importam: `Creator Process Name` é o pai; `New Process Name` é o filho; `Process Command Line` só aparece se a política "Include command line in process creation events" estiver ativa — se estiver vazia no seu laboratório, ative antes de seguir.

### O que o SOC N1 observa

- **Normal:** `explorer.exe` gerando `chrome.exe`; `services.exe` gerando `svchost.exe`; PowerShell aberto por `explorer.exe` no horário comercial por um administrador conhecido.
- **Suspeito:** aplicativo Office como pai de shell; PowerShell com janela oculta; processo com nome de sistema rodando de fora de `System32`; conexão de saída iniciada por processo recém-criado.

### Erro comum de analista júnior

Concluir que um processo é malicioso só porque o nome parece estranho. O caminho, a assinatura digital, o processo pai e a linha de comando valem mais do que o nome. Igualmente comum: filtrar o Event Viewer por data e esquecer que ele usa o horário local da máquina, enquanto o SIEM (Security Information and Event Management, plataforma que centraliza logs) mostra UTC — três horas de diferença fazem o analista "não encontrar" um evento que está bem ali.

### Verificação com gabarito

Rode `Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 5`. Você deve ver cinco eventos com `Creator Process Name` preenchido. Em Autoruns, com entradas Microsoft ocultas, a lista deve ficar curta (tipicamente menos de 30 linhas numa VM limpa) e toda entrada restante deve ter fabricante identificado.

### Critério de sucesso

Consulta customizada salva e visível em `Custom Views`; os nove comandos PowerShell executados com saída compreendida; as quatro ferramentas Sysinternals abertas; os cinco locais de persistência inspecionados e documentados.

### Erros comuns

Executar o PowerShell sem elevação (o log Security não abre); usar `Get-EventLog`, que é legado e não lê os canais modernos; deixar o Autoruns com entradas Microsoft visíveis e se perder em milhares de linhas.

## LAB 9 — Instalar e ler o Sysmon

### Objetivo

Instalar o Sysmon (System Monitor, da suíte Sysinternals) com uma configuração pública reconhecida, gerar tráfego web normal e correlacionar, sozinho, um acesso HTTPS ao processo exato que o originou, usando os eventos 1, 3 e 22.

### Pré-requisitos

- A mesma VM do LAB 8, com o LAB 8 concluído.
- Privilégio de administrador e snapshot novo.
- Download do `Sysmon.zip` do site oficial Sysinternals e de uma configuração base pública reconhecida — o `sysmonconfig-export.xml` do projeto SwiftOnSecurity ou a configuração modular do Olaf Hartong (`sysmon-modular`).

### Passos numerados

1. Extraia o Sysmon em `C:\Tools\Sysmon` e coloque o XML de configuração na mesma pasta.
2. Instale, em PowerShell elevado: `.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml`.
3. Confirme o serviço: `Get-Service Sysmon64` deve retornar `Running`.
4. Confirme o canal de log: `Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational'`.
5. Gere atividade normal: abra o navegador e visite um site legítimo qualquer da sua organização de teste; abra o Bloco de Notas; rode `Resolve-DnsName www.example.com`.
6. Colete os três tipos de evento com o comando da próxima seção.
7. Correlacione: pegue o `ProcessGuid` do evento 22 (DNS) e procure o mesmo `ProcessGuid` nos eventos 1 (criação de processo) e 3 (conexão de rede).

```powershell
# Eventos 1, 3 e 22 do Sysmon nas últimas 2 horas
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'
    ID        = 1,3,22
    StartTime = (Get-Date).AddHours(-2)
} | Select-Object TimeCreated, Id, Message | Format-List
```

### Como aparece nos logs

```text
EventID: 22  (DNS query)
UtcTime: 2026-09-03 12:41:02.118
ProcessGuid: {a1b2c3d4-9f10-6659-2b00-000000000700}
ProcessId: 6712
QueryName: cdn.example.com
QueryStatus: 0
QueryResults: ::ffff:203.0.113.44;
Image: C:\Program Files\Google\Chrome\Application\chrome.exe

EventID: 3  (Network connection detected)
UtcTime: 2026-09-03 12:41:02.640
ProcessGuid: {a1b2c3d4-9f10-6659-2b00-000000000700}
Image: C:\Program Files\Google\Chrome\Application\chrome.exe
User: CORP\jsilva
Protocol: tcp
SourceIp: 10.10.20.45
SourcePort: 51344
DestinationIp: 203.0.113.44
DestinationPort: 443

EventID: 1  (Process Create)
UtcTime: 2026-09-03 12:39:58.002
ProcessGuid: {a1b2c3d4-9f10-6659-2b00-000000000700}
Image: C:\Program Files\Google\Chrome\Application\chrome.exe
CommandLine: "chrome.exe" --type=renderer
ParentImage: C:\Windows\explorer.exe
Hashes: SHA256=3F2B...C81A
```

O `ProcessGuid` é a cola que une os três: ele é único no tempo e na máquina, ao contrário do `ProcessId`, que o Windows reutiliza. Foi o `chrome.exe` (PID 6712), aberto pelo `explorer.exe`, que perguntou por `cdn.example.com`, recebeu 203.0.113.44 e abriu TCP 443 para lá.

### Query SPL e KQL equivalentes

```spl
index=win sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=22
| rex field=_raw "QueryName:\s(?<dominio>\S+)"          
| stats count values(Image) as processo by dominio, host   
| where count < 5                                          
```
Linha 1 seleciona só eventos DNS do Sysmon; linha 2 extrai o domínio consultado; linha 3 agrupa por domínio e host mostrando quem perguntou; linha 4 mantém só domínios raramente consultados, onde o incomum se destaca.

```kql
DeviceNetworkEvents
| where Timestamp > ago(2h)                        // janela de duas horas
| where RemotePort == 443                          // só HTTPS
| where InitiatingProcessFileName !in ("chrome.exe","msedge.exe")  // navegadores esperados fora
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl
```

### O que o SOC N1 observa

- **Normal:** evento 22 de navegador, seguido de evento 3 para o mesmo IP na porta 443, ambos com o mesmo `ProcessGuid`.
- **Suspeito:** evento 22 originado por `powershell.exe`, `rundll32.exe`, `mshta.exe` ou `certutil.exe`; evento 3 sem evento 22 anterior (conexão direta a IP, sem DNS — típico de canal de comando e controle, MITRE T1071).

### Erro comum de analista júnior

Correlacionar por `ProcessId` em vez de `ProcessGuid` e acusar o processo errado, porque o PID já tinha sido reciclado por outro programa. Outro deslize: instalar o Sysmon sem arquivo de configuração — o padrão registra pouquíssimo e o analista conclui, erradamente, que "o Sysmon não vê nada".

### Verificação com gabarito

`Get-Service Sysmon64` retorna `Running`; o canal `Microsoft-Windows-Sysmon/Operational` existe; ao buscar o `ProcessGuid` do seu evento 22, você encontra o evento 1 correspondente com `ParentImage` = `explorer.exe` e o evento 3 com `DestinationPort` 443.

### Critério de sucesso

Você escreve, em uma frase, a cadeia completa: "o usuário CORP\jsilva abriu o navegador pelo explorer.exe, o navegador consultou cdn.example.com, recebeu 203.0.113.44 e abriu conexão TCP 443 para esse endereço".

### Erros comuns

Rodar `Sysmon.exe` (32 bits) em sistema de 64 bits; esquecer `-accepteula` e travar na janela de licença; editar o XML e não aplicar com `Sysmon64.exe -c arquivo.xml`.

### Exercícios — Windows essencial para SOC e Sysmon

1. Um evento 4624 mostra `LogonType 10`, usuário `maria.costa`, `IPOrigem 203.0.113.90`. A política da empresa diz que RDP só é permitido a partir da rede interna. Verdadeiro ou falso positivo? Qual o próximo passo?
2. Você vê no Sysmon um evento 1 com `Image = C:\Users\jsilva\AppData\Local\Temp\upd.exe` e `ParentImage = C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE`. Liste três comandos PowerShell que você roda em seguida, e o que espera obter de cada um.
3. Uma máquina tem 47 eventos 4625 (logon falho) em 4 minutos, todos com o mesmo usuário `svc_backup` e origem 10.10.20.45. Outra tem 47 eventos 4625 em 4 minutos com 47 usuários diferentes e a mesma origem. Qual das duas é mais preocupante e por quê?
4. Escreva o `FilterHashtable` que retorna apenas eventos 7045 (serviço instalado) do log `System` nas últimas 72 horas.
5. Um evento Sysmon 3 aponta `DestinationIp 198.51.100.20`, porta 443, `Image = C:\Windows\System32\certutil.exe`, e não existe evento 22 anterior com o mesmo `ProcessGuid`. Explique o que isso sugere.

<details><summary>Ver gabarito</summary>

1. **Verdadeiro positivo até prova em contrário.** `LogonType 10` é RDP e `203.0.113.90` é endereço público, ou seja, RDP vindo da internet contra política. Próximo passo: confirmar se o RDP está exposto (firewall de borda), verificar se houve 4625 anteriores da mesma origem (força bruta que virou sucesso), checar o que a conta fez depois via 4688/Sysmon 1, e escalar para contenção. Nunca feche como falso positivo só porque o logon teve sucesso — sucesso é justamente o pior cenário.

2. Os três comandos: `Get-FileHash C:\Users\jsilva\AppData\Local\Temp\upd.exe -Algorithm SHA256` para obter o hash e consultar em threat intel; `Get-CimInstance Win32_Process | Where-Object {$_.Name -eq 'upd.exe'} | Select ProcessId,CommandLine` para ver a linha de comando completa e argumentos; `Get-NetTCPConnection -State Established | Where-Object OwningProcess -eq <PID>` para descobrir se ele já está falando com algum destino externo. Padrão Outlook gerando executável em `%TEMP%` é anexo malicioso executado pelo usuário (MITRE T1566.001).

3. **A segunda é mais preocupante.** Muitas falhas para *um* usuário costuma ser senha vencida, serviço com credencial desatualizada ou mapeamento de unidade quebrado — típico de `svc_backup`. Muitas falhas com *muitos usuários diferentes* a partir de uma única origem é o padrão clássico de password spraying (MITRE T1110.003): uma senha comum testada contra a lista inteira de contas. Confirme o `Status`/`Sub Status` do 4625 e busque um 4624 de sucesso vindo do mesmo 10.10.20.45.

**4.**
```powershell
   Get-WinEvent -FilterHashtable @{
       LogName   = 'System'
       ID        = 7045
       StartTime = (Get-Date).AddHours(-72)
   }
   ```
   Note que `AddHours(-72)` e `AddDays(-3)` são equivalentes; o importante é o `StartTime` ser um objeto de data, não texto.

5. Sugere download ou canal de comando e controle usando um binário legítimo do sistema (técnica conhecida como living-off-the-land). Dois sinais somados: `certutil.exe` é utilitário de certificados e não tem motivo para abrir HTTPS de saída para endereço externo; e a ausência de evento 22 indica conexão direta a IP, sem consulta DNS, o que remove o passo que a maioria dos programas legítimos faz. Ação do N1: coletar `ProcessGuid`, recuperar o evento 1 para ver a linha de comando e o processo pai, verificar no proxy ou firewall o volume trafegado para 198.51.100.20 e escalar ao N2 como possível T1105 (transferência de ferramenta) ou T1071.001.

</details>


## LAB 10 — Montar o controlador de domínio de laboratório

### O que é um controlador de domínio

Pense num condomínio grande. Existe uma portaria central que guarda a lista de moradores, sabe quem pode entrar em cada bloco e registra toda entrada e saída num livro. O **controlador de domínio** (em inglês *Domain Controller*, abreviado **DC**) é essa portaria da rede corporativa: ele guarda o **Active Directory** (**AD**, o "Diretório Ativo", banco de dados de usuários, computadores e grupos) e é quem decide se o crachá de alguém vale.

Para o SOC (**Security Operations Center**, o centro de operações de segurança), o DC é a fonte de log mais valiosa da rede Windows: quase toda autenticação passa por ele. Por isso você precisa ter um DC próprio para praticar antes de olhar um DC de produção.

### Passo 1 — Instalar o Windows Server em versão de avaliação

A Microsoft distribui o Windows Server em **versão de avaliação** (*evaluation*), gratuita por 180 dias, no Microsoft Evaluation Center. Baixe a imagem ISO do Windows Server 2022 (ou 2025) e crie uma máquina virtual:

| Item | Valor sugerido no laboratório |
|---|---|
| Memória RAM | 4 GB (mínimo 2 GB) |
| Disco | 60 GB |
| Processadores virtuais | 2 |
| Rede | Rede interna/host-only, sem NAT para a internet |
| Edição na instalação | Standard **Desktop Experience** (com interface gráfica) |
| Tipo de instalação | Personalizada: instalar apenas o Windows |

Na primeira inicialização o instalador pede a senha do usuário local **Administrator**. Use uma senha longa e exclusiva do laboratório — nunca reaproveite senha de trabalho.

Depois de entrar, configure o endereço fixo antes de promover o servidor. Em **Painel de Controle → Rede → Alterar configurações do adaptador → Propriedades → IPv4**:

```
Endereço IP.......: 10.10.10.10
Máscara...........: 255.255.255.0  (/24)
Gateway padrão....: 10.10.10.1
DNS preferencial..: 127.0.0.1
Nome do servidor..: DC01
```

Renomeie a máquina para `DC01` em **Sistema → Renomear este computador** e reinicie. O DNS apontando para si mesmo é obrigatório: o AD depende de DNS para tudo.

### Passo 2 — Adicionar a função AD DS

O **AD DS** (*Active Directory Domain Services*, Serviços de Domínio do Active Directory) é a função que transforma um servidor comum em controlador de domínio.

1. Abra o **Server Manager** → **Manage** → **Add Roles and Features**.
2. *Installation Type*: marque **Role-based or feature-based installation** → Next.
3. *Server Selection*: escolha `DC01` na lista → Next.
4. *Server Roles*: marque **Active Directory Domain Services**. Uma janela pede recursos adicionais — clique em **Add Features** → Next.
5. *Features*: não marque nada extra → Next → Next → **Install**.

### Passo 3 — Promover a controlador de domínio

Terminada a instalação, aparece a bandeira amarela de aviso no Server Manager com o link **Promote this server to a domain controller**. Clique nele.

| Tela do assistente | O que preencher |
|---|---|
| Deployment Configuration | **Add a new forest**. Root domain name: `corp.local` |
| Domain Controller Options | Functional level: **Windows Server 2016** (ou superior). Deixe **DNS server** e **Global Catalog (GC)** marcados. Defina a senha do **DSRM** (*Directory Services Restore Mode*, modo de restauração) |
| DNS Options | Ignore o aviso "delegation for this DNS server cannot be created" — é normal em floresta nova |
| Additional Options | NetBIOS name: `CORP` (preenchido sozinho) |
| Paths | Aceite os padrões (`C:\Windows\NTDS` e `C:\Windows\SYSVOL`) |
| Review / Prerequisites | Confira o resumo, aguarde a checagem e clique em **Install** |

O servidor reinicia sozinho. Ao voltar, o login já é `CORP\Administrator`. Você tem uma **floresta** nova chamada `corp.local` — floresta é o contêiner mais alto do AD, e nela existe o domínio `corp.local`.

### Passo 4 — Criar OUs, usuários e grupos fictícios

Abra **Active Directory Users and Computers** (`dsa.msc`). As **OUs** (*Organizational Units*, Unidades Organizacionais) são as pastas do domínio — servem para organizar objetos e para aplicar GPO. Clique com o botão direito em `corp.local` → **New → Organizational Unit**.

| OU | Objetos que vão dentro |
|---|---|
| `OU=Colaboradores` | jsilva, maria.costa |
| `OU=TI` | admin.rodrigo |
| `OU=Servicos` | svc_backup |
| `OU=Estacoes` | WKS01 (a estação cliente) |

Crie os usuários com **New → User**. Sugestão de dados fictícios:

| Usuário (sAMAccountName) | Nome exibido | Grupo |
|---|---|---|
| `jsilva` | João Silva | Domain Users |
| `maria.costa` | Maria Costa | RH-Leitura |
| `admin.rodrigo` | Rodrigo Admin | Domain Admins |
| `svc_backup` | Conta de Serviço Backup | Operadores-Backup |

Crie os grupos em **New → Group** (escopo *Global*, tipo *Security*) e adicione os membros pela aba **Members**. Nunca use senha real sua nas contas de laboratório.

### Passo 5 — Ingressar um cliente Windows no domínio

Na máquina virtual cliente (`WKS01`, Windows 10 ou 11), configure:

```
Endereço IP.......: 10.10.10.50
Máscara...........: 255.255.255.0
DNS preferencial..: 10.10.10.10   (o DC01 — obrigatório)
```

Depois vá em **Configurações → Sistema → Sobre → Renomear este PC (avançado) → Alterar → Domínio:** digite `corp.local`, informe as credenciais de `CORP\Administrator` e reinicie. Se a caixa recusar o domínio, o erro quase sempre é DNS apontando para o roteador em vez do DC.

**Erro comum de analista júnior:** apontar o DNS do cliente para `8.8.8.8` "porque funciona na internet". O AD publica seus serviços em registros SRV (`_ldap._tcp.dc._msdcs.corp.local`) que só existem no DNS do domínio; sem isso, o ingresso falha e a autenticação Kerberos nunca sobe.

## LAB 11 — Auditoria e eventos de autenticação

### O que é auditoria avançada

Por padrão, o Windows anota pouca coisa. A **Auditoria Avançada** (*Advanced Audit Policy Configuration*) é como trocar a câmera da portaria por um conjunto de câmeras específicas: uma para a porta, uma para a garagem, uma para o cofre. Você escolhe exatamente o que gravar, por subcategoria.

### Passo 1 — Ligar a auditoria por GPO

No DC01 abra **Group Policy Management** (`gpmc.msc`), clique com o botão direito em **Default Domain Policy** → **Edit**. Navegue até:

`Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Audit Policies`

| Categoria | Subcategoria | Marcar | Eventos que passa a gerar |
|---|---|---|---|
| Logon/Logoff | Audit Logon | Success e Failure | 4624, 4625 |
| Logon/Logoff | Audit Logoff | Success | 4634, 4647 |
| Logon/Logoff | Audit Account Lockout | Success e Failure | 4740 |
| Account Logon | Audit Kerberos Authentication Service | Success e Failure | 4768, 4771 |
| Account Logon | Audit Kerberos Service Ticket Operations | Success e Failure | 4769 |
| Account Logon | Audit Credential Validation | Success e Failure | 4776 |
| DS Access | Audit Directory Service Access | Success e Failure | 4662 |
| Detailed Tracking | Audit Process Creation | Success | 4688 |

Para o 4688 trazer a **linha de comando** completa, ative também:

`Computer Configuration → Policies → Administrative Templates → System → Audit Process Creation → Include command line in process creation events` → **Enabled**.

Aumente o tamanho do log de segurança em `Windows Settings → Security Settings → Event Log → Maximum security log size` para pelo menos **1.048.576 KB** (1 GB), senão o log gira e apaga a evidência.

Aplique com `gpupdate /force` no DC e no cliente, e confirme com `auditpol /get /category:*`.

### Passo 2 — Gerar logon correto e incorreto

No `WKS01`:

1. Faça logon como `CORP\jsilva` com a senha certa (gera 4624 no cliente, 4768 e 4769 no DC).
2. Bloqueie a tela e destrave errando a senha três vezes (gera 4625 no cliente, 4771 ou 4776 no DC).
3. Abra o Prompt de Comando e execute `whoami /groups` (gera 4688 com linha de comando).

### Passo 3 — Como aparece nos logs

Evento **4624** — logon com sucesso, visto no cliente:

```
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Event ID:      4624
Task Category: Logon
Computer:      WKS01.corp.local

An account was successfully logged on.

Subject:
    Security ID:        NULL SID
    Account Name:       -
New Logon:
    Security ID:        CORP\jsilva
    Account Name:       jsilva
    Account Domain:     CORP
    Logon ID:           0x3E9A41
Logon Type:             2
Logon Process:          User32
Authentication Package: Negotiate
Workstation Name:       WKS01
Source Network Address: 10.10.10.50
```

Evento **4625** — falha de logon, também no cliente:

```
Event ID:      4625
Computer:      WKS01.corp.local

An account failed to log on.

Account For Which Logon Failed:
    Account Name:   jsilva
    Account Domain: CORP
Failure Information:
    Failure Reason: Unknown user name or bad password.
    Status:         0xC000006D
    Sub Status:     0xC000006A
Logon Type:         2
Source Network Address: 10.10.10.50
```

Evento **4768** — o DC emitiu um **TGT** (*Ticket Granting Ticket*, o "crachá principal" do Kerberos):

```
Event ID:      4768
Computer:      DC01.corp.local

A Kerberos authentication ticket (TGT) was requested.

Account Name:        jsilva
Supplied Realm Name: CORP.LOCAL
Service Name:        krbtgt
Client Address:      ::ffff:10.10.10.50
Ticket Options:      0x40810010
Ticket Encryption:   0x12
Result Code:         0x0
```

Evento **4769** — pedido de ticket de serviço (o "crachá de sala"):

```
Event ID:      4769
Computer:      DC01.corp.local

A Kerberos service ticket was requested.

Account Name:      jsilva@CORP.LOCAL
Service Name:      WKS01$
Client Address:    ::ffff:10.10.10.50
Ticket Encryption: 0x12
Failure Code:      0x0
```

Evento **4776** — validação de credencial via **NTLM** (protocolo antigo, anterior ao Kerberos):

```
Event ID:      4776
Computer:      DC01.corp.local

The computer attempted to validate the credentials for an account.

Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
Logon Account:          jsilva
Source Workstation:     WKS01
Error Code:             0xC000006A
```

### Campos que o SOC N1 sempre lê

| Campo | Para que serve |
|---|---|
| Logon Type | 2 = teclado local, 3 = rede (compartilhamento), 10 = RDP (área de trabalho remota), 5 = serviço |
| Status / Sub Status (4625) | `0xC000006A` senha errada, `0xC0000064` usuário inexistente, `0xC0000234` conta bloqueada, `0xC0000072` conta desabilitada |
| Result/Failure Code (4768/4769) | `0x0` sucesso, `0x18` senha errada, `0x12` conta desabilitada ou expirada |
| Ticket Encryption (4769) | `0x12` = AES256 (normal); `0x17` = RC4 em ambiente AES pode indicar tentativa de Kerberoasting (MITRE **T1558.003**) |
| Source Network Address | De onde veio; um IP fora da faixa esperada muda tudo na investigação |

**Normal vs suspeito:** um 4625 isolado às 9h07 é dedo torto. Vinte 4625 do mesmo IP contra vinte contas diferentes em dois minutos é **password spraying** (**T1110.003**), tratado no próximo trecho. Muitos 4769 com `Ticket Encryption 0x17` pedidos pelo mesmo usuário contra vários serviços sugere Kerberoasting — ferramenta como Rubeus deixa exatamente esse rastro.

**Erro comum de analista júnior:** procurar o 4625 no controlador de domínio quando o logon foi interativo na estação. O 4624/4625 nasce na máquina onde a sessão acontece; no DC você vê o 4768/4771 (Kerberos) ou o 4776 (NTLM). Coletar só o DC deixa metade da história de fora.

### Passo 4 — Montar a timeline

Consulte o log com PowerShell no DC:

```powershell
# Últimos 50 eventos de autenticação do DC, do mais novo para o mais antigo
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4768,4769,4771,4776} -MaxEvents 50 |
    Select-Object TimeCreated, Id, @{n='Msg';e={$_.Message.Split("`n")[0]}} |
    Sort-Object TimeCreated
```

Consulta equivalente em **SPL** (Splunk):

```spl
index=wineventlog EventCode IN (4624,4625,4768,4769,4776) user="jsilva"
| eval origem=coalesce(Source_Network_Address, Client_Address)
| table _time host EventCode user origem Logon_Type Status
| sort _time
```

E em **KQL** (Microsoft Sentinel):

```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-09-03 09:00) .. datetime(2026-09-03 09:30))
| where EventID in (4624, 4625, 4768, 4769, 4776)      // eventos de autenticação
| where TargetUserName == "jsilva" or Account has "jsilva"
| project TimeGenerated, Computer, EventID, Account, IpAddress, LogonTypeName, Status
| sort by TimeGenerated asc                            // ordem cronológica = timeline
```

Timeline esperada do laboratório:

| Hora | Host | EventID | Leitura |
|---|---|---|---|
| 09:05:12 | WKS01 | 4625 | Falha, Sub Status 0xC000006A (senha errada) |
| 09:05:14 | DC01 | 4776 | NTLM recusado, erro 0xC000006A |
| 09:05:41 | WKS01 | 4624 | Sucesso, Logon Type 2, origem 10.10.10.50 |
| 09:05:41 | DC01 | 4768 | TGT emitido, Result Code 0x0 |
| 09:05:42 | DC01 | 4769 | Ticket de serviço para WKS01$ |
| 09:06:03 | WKS01 | 4688 | `whoami.exe /groups` iniciado por jsilva |

### Exercícios — Montar o controlador de domínio e auditar autenticação

1. Você promoveu o `DC01` mas o `WKS01` não consegue ingressar em `corp.local`. O `ping 10.10.10.10` responde. Qual a causa mais provável e qual comando confirma?
2. Leia: `4625, Logon Type 3, Sub Status 0xC0000064, Source Network Address 10.10.10.77`, repetido 14 vezes em 40 segundos contra 14 nomes diferentes. É verdadeiro ou falso positivo? Qual a técnica MITRE?
3. Um alerta dispara por `4769` com `Ticket Encryption 0x17` para o serviço `MSSQLSvc/sql01.corp.local`, solicitado por `svc_backup` às 03:00, dentro da janela do job de backup. Verdadeiro ou falso positivo? O que checar antes de decidir?
4. Você tem 4624 no cliente mas nenhum 4768 no DC para o mesmo usuário e horário. O que isso indica?
5. Qual subcategoria e qual política adicional precisam estar ligadas para o evento 4688 mostrar a linha de comando completa?

<details><summary>Ver gabarito</summary>

1. **DNS.** O ping funciona porque é IP puro, mas o ingresso no domínio depende dos registros SRV publicados no DNS do AD. O `WKS01` provavelmente está com DNS do roteador ou público. Confirme com `nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.local` — se não retornar `DC01.corp.local`, corrija o DNS preferencial do cliente para `10.10.10.10` e repita.

2. **Verdadeiro positivo.** O Sub Status `0xC0000064` significa "usuário não existe", e ver 14 nomes diferentes vindos do mesmo IP interno em 40 segundos é enumeração de contas seguida de **password spraying** — MITRE **T1110.003** (e T1087.002 para a enumeração). Logon Type 3 mostra que veio pela rede, não do teclado. Próximo passo: identificar o dono de `10.10.10.77` no inventário, isolar se não for ferramenta autorizada de varredura, e verificar se algum 4624 de sucesso saiu do mesmo IP depois.

3. **Provável falso positivo, mas não feche sem checar.** O `0x17` (RC4) é suspeito porque Kerberoasting (**T1558.003**) pede tickets nesse formato, porém contas de serviço antigas legitimamente ainda usam RC4. Cheque: (a) se `svc_backup` é a conta que roda o job de backup e se o horário bate com a janela agendada; (b) se houve **um** pedido ou dezenas de SPNs diferentes em sequência — Kerberoasting varre vários; (c) se a estação de origem é o servidor de backup e não uma estação de usuário; (d) se apareceu 4688 com ferramenta incomum no mesmo host. Um pedido único, no horário e da origem certa, é operação normal — vale abrir tarefa para migrar a conta para AES.

4. Indica que a autenticação **não foi Kerberos**. Casos: logon com conta local da máquina (não do domínio), logon por NTLM — nesse caso procure o **4776** no DC —, ou uso de credenciais em cache quando o DC está inacessível. Se for conta de domínio autenticando por NTLM de forma inesperada, investigue: ferramentas como Responder e Impacket costumam forçar NTLM, e o rastro é justamente 4776 sem 4768 correspondente.

5. Subcategoria **Detailed Tracking → Audit Process Creation** com Success marcado, mais a política administrativa **System → Audit Process Creation → Include command line in process creation events** definida como *Enabled*. Só a subcategoria gera o 4688, mas sem a segunda política o campo `Process Command Line` vem vazio — e é justamente ele que mostra os argumentos usados.

</details>


## LAB 12 — Detectar password spraying no laboratório

### O que é password spraying

Imagine um ladrão que, em vez de tentar mil chaves numa única porta (o que faz muito barulho e trava a fechadura), pega **uma única chave muito comum** e testa em **todas as portas do prédio**. Se um morador usa a fechadura padrão de fábrica, ele entra sem nunca disparar o alarme de "chave errada demais na mesma porta".

Isso é o **password spraying** (pulverização de senha): o atacante escolhe uma ou duas senhas prováveis e as testa contra **muitas contas diferentes**, mantendo poucas tentativas por conta para não estourar a política de bloqueio (*account lockout*). No MITRE ATT&CK é a técnica **T1110.003 — Brute Force: Password Spraying**.

A diferença essencial para o *brute force* clássico (T1110.001):

| Característica | Brute force clássico | Password spraying |
|---|---|---|
| Contas alvo | 1 ou poucas | Dezenas ou centenas |
| Senhas testadas por conta | Muitas | 1 a 3 |
| Dispara bloqueio de conta? | Quase sempre | Raramente |
| Assinatura no log | Muitos 4625 no **mesmo usuário** | Poucos 4625 por usuário, **mesma origem** |
| Detecção correta | Contar falhas por conta | Contar **contas distintas por IP de origem** |

### Como funciona no laboratório

Monte assim, usando as máquinas que você já criou nas partes anteriores deste módulo (o controlador de domínio e o cliente Windows):

- `DC01` — controlador de domínio do domínio `corp.local`, IP `10.10.10.10`
- `WS01` — estação Windows 10/11 no domínio, IP `10.10.10.50`
- Contas de teste criadas por você: `jsilva`, `maria.costa`, `admin.rodrigo`, `svc_backup`, `carlos.lima`, `ana.pereira`

**Passo 1 — garanta a auditoria ligada.** No `DC01`, em *Group Policy Management*, edite a *Default Domain Controllers Policy* e habilite, em **Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Logon/Logoff**, a subcategoria **Audit Logon** com **Failure** marcado. Rode `gpupdate /force`.

**Passo 2 — gere as falhas de forma controlada.** Não use ferramenta de ataque. Basta, a partir do `WS01`, tentar mapear um compartilhamento do `DC01` informando **senha errada** para cada uma das seis contas de teste, uma tentativa por conta:

```powershell
# Executar em WS01. Gera 1 falha de autenticacao por conta de teste.
# A senha e propositalmente invalida - nenhuma credencial real e usada.
'jsilva','maria.costa','admin.rodrigo','svc_backup','carlos.lima','ana.pereira' |
    ForEach-Object {
        # net use retorna erro 1326 (logon failure) - e exatamente o que queremos
        net use \\10.10.10.10\SYSVOL /user:corp\$_ "SenhaErradaDeLab!1" 2>$null
        net use \\10.10.10.10\SYSVOL /delete 2>$null
    }
```

Seis contas distintas, uma falha cada, todas vindas de `10.10.10.50` em menos de um minuto. É esse o padrão que você vai aprender a enxergar.

### Como aparece nos logs

No **DC01**, Event Viewer > Windows Logs > Security, EventID **4625 — An account failed to log on**:

```text
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Event ID:      4625
Task Category: Logon
Keywords:      Audit Failure
Computer:      DC01.corp.local

Account For Which Logon Failed:
    Security ID:        NULL SID
    Account Name:       maria.costa
    Account Domain:     CORP

Failure Information:
    Failure Reason:     Unknown user name or bad password.
    Status:             0xC000006D
    Sub Status:         0xC000006A

Logon Type:             3
Network Information:
    Workstation Name:   WS01
    Source Network Address: 10.10.10.50
    Source Port:        49722
```

Campos que importam para o N1:

| Campo | Significado | Uso na investigação |
|---|---|---|
| `Account Name` | Conta que falhou | Serve para contar **contas distintas** |
| `Logon Type 3` | Logon de rede (SMB, RPC, WinRM) | Spraying quase sempre é tipo 3 |
| `Status 0xC000006D` | Falha genérica de logon | Contexto |
| `Sub Status 0xC000006A` | **Senha errada, usuário existe** | Sinal forte: o atacante já enumerou contas válidas |
| `Sub Status 0xC0000064` | **Usuário não existe** | Sinal de enumeração às cegas |
| `Sub Status 0xC0000234` | Conta **bloqueada** | O spraying passou do limite |
| `Source Network Address` | IP de origem | Chave do agrupamento |

Se o Kerberos estiver em jogo (o normal em domínio), o mesmo ataque também gera **4771 — Kerberos pre-authentication failed** com `Failure Code 0x18` (senha incorreta) e **4776** no NTLM. Trate os três como a mesma família de evidência.

### Script PowerShell de análise (comentado linha a linha)

Execute no `DC01`:

```powershell
# ==== Deteccao de password spraying a partir do log de Seguranca ====

# 1) Janela de analise: ultimos 60 minutos. Spraying e um evento de rajada;
#    janelas curtas evitam somar falhas legitimas do dia inteiro.
$Janela = (Get-Date).AddMinutes(-60)

# 2) Limiar: a partir de quantas CONTAS DISTINTAS por IP consideramos suspeito.
#    Em laboratorio 3 e um bom valor; em producao calibre pelo baseline.
$LimiteContas = 3

# 3) Le apenas eventos 4625 (falha de logon) criados depois de $Janela.
#    FilterHashtable filtra no motor do log - muito mais rapido que Where-Object.
$Eventos = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = $Janela
} -ErrorAction SilentlyContinue

# 4) Converte cada evento em objeto simples com os 3 campos que interessam.
$Dados = foreach ($e in $Eventos) {
    # Transforma o XML do evento em objeto navegavel por nome de campo.
    $x = [xml]$e.ToXml()
    # Monta um dicionario nome -> valor com todos os Data do evento.
    $d = @{}
    foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }

    [pscustomobject]@{
        Hora     = $e.TimeCreated                 # quando falhou
        Conta    = $d['TargetUserName']           # conta alvo
        IPOrigem = $d['IpAddress']                # de onde veio
        SubStatus= $d['SubStatus']                # por que falhou
    }
}

# 5) Descarta ruido: logons locais do proprio host aparecem com '-' ou '::1'.
$Dados = $Dados | Where-Object { $_.IPOrigem -and $_.IPOrigem -notin '-','::1','127.0.0.1' }

# 6) Agrupa por IP de origem e calcula, para cada IP:
#    - quantas contas DISTINTAS falharam (o indicador de spraying)
#    - total de falhas e a lista de contas, para o relatorio do chamado
$Resultado = $Dados | Group-Object IPOrigem | ForEach-Object {
    $contas = $_.Group.Conta | Sort-Object -Unique
    [pscustomobject]@{
        IPOrigem        = $_.Name
        ContasDistintas = $contas.Count
        TotalFalhas     = $_.Count
        Primeira        = ($_.Group.Hora | Sort-Object)[0]
        Ultima          = ($_.Group.Hora | Sort-Object)[-1]
        Contas          = ($contas -join ', ')
    }
}

# 7) Mostra so o que passou do limiar, do pior para o menos grave.
$Resultado |
    Where-Object ContasDistintas -ge $LimiteContas |
    Sort-Object ContasDistintas -Descending |
    Format-Table -AutoSize
```

Saída esperada no laboratório:

```text
IPOrigem     ContasDistintas TotalFalhas Primeira            Ultima              Contas
--------     --------------- ----------- --------            ------              ------
10.10.10.50                6           6 03/09/2026 14:12:03 03/09/2026 14:12:41 admin.rodrigo, ana.pereira, carlos.lima, jsilva, maria.costa, svc_backup
```

A mesma lógica em **SPL (Splunk)** e **KQL (Microsoft Sentinel / Defender)**:

```spl
index=wineventlog EventCode=4625            /* so falhas de logon */
| search Logon_Type=3                        /* logon de rede */
| stats dc(Account_Name) AS contas           /* contas distintas por IP */
        count AS falhas
        values(Account_Name) AS lista
        min(_time) AS inicio max(_time) AS fim
        by Source_Network_Address
| where contas >= 5                          /* limiar calibravel */
| sort - contas
```

```kql
SecurityEvent
| where TimeGenerated > ago(1h)               // janela de 1 hora
| where EventID == 4625                       // falha de logon
| where LogonType == 3                        // logon de rede
| where IpAddress !in ("-", "::1", "127.0.0.1")  // descarta ruido local
| summarize ContasDistintas = dcount(TargetUserName),
            Falhas = count(),
            Contas = make_set(TargetUserName, 20)
        by IpAddress, bin(TimeGenerated, 15m)  // janelas de 15 min
| where ContasDistintas >= 5                   // limiar
| order by ContasDistintas desc
```

**O que o SOC N1 observa.** Normal: um usuário com 2 ou 3 falhas seguidas às 8h da manhã (voltou de férias, senha expirou), sempre da **mesma conta**. Suspeito: **muitas contas distintas, poucas falhas cada, mesma origem, intervalo curto** — e mais suspeito ainda se o `Sub Status` for `0xC000006A` (as contas existem) ou se logo depois vier um **4624 de sucesso** do mesmo IP: aí o spray acertou.

**Erro comum de analista júnior.** Ordenar o relatório por *total de falhas* e fechar o alerta porque "só teve 6 falhas, é pouco". A métrica de spraying não é o volume: é a **cardinalidade de contas por origem**. Seis falhas em seis contas diferentes é muito mais grave que sessenta falhas numa conta só.

## LAB 13 — Observar movimento lateral benigno

### O que é movimento lateral

Depois de entrar por uma porta, o ladrão anda pelos corredores usando as **chaves que já roubou**, sem arrombar mais nada. Isso é **lateral movement**: o atacante usa credenciais válidas para saltar de máquina em máquina. Como ele usa ferramentas administrativas legítimas (SMB, WMI, WinRM), o log não diz "ataque" — diz "administrador trabalhando". Aprender a diferença exige ver o rastro **benigno** primeiro. É por isso que este laboratório usa acesso **legítimo e autorizado** entre suas próprias máquinas.

### Como funciona no laboratório

Com `admin.rodrigo` (conta administrativa do seu laboratório), a partir de `WS01` (`10.10.10.50`) para `DC01` (`10.10.10.10`):

```powershell
# 1) Acesso a compartilhamento administrativo (SMB, porta TCP 445)
Get-ChildItem \\10.10.10.10\C$\Windows\Temp

# 2) PowerShell Remoting (WinRM, porta TCP 5985)
Invoke-Command -ComputerName DC01 -ScriptBlock { hostname; whoami }
```

### Como aparece nos logs

No **DC01** (o destino), três eventos formam a cadeia:

```text
Event ID: 4624  -  An account was successfully logged on
    Account Name:    admin.rodrigo
    Account Domain:  CORP
    Logon Type:      3                 <- logon de rede
    Logon Process:   Kerberos
    Authentication Package: Kerberos
    Workstation Name: WS01
    Source Network Address: 10.10.10.50
    Source Port: 51204
```

```text
Event ID: 5140  -  A network share object was accessed
    Account Name:      admin.rodrigo
    Source Address:    10.10.10.50
    Share Name:        \\*\C$          <- compartilhamento administrativo
    Share Path:        \??\C:\
    Access Mask:       0x1
```

```text
Event ID: 4688  -  A new process has been created
    Creator Subject Account Name: DC01$
    New Process Name: C:\Windows\System32\wsmprovhost.exe
    Parent Process Name: C:\Windows\System32\svchost.exe
    Token Elevation Type: %%1936 (TokenElevationTypeDefault)
    Creator Process ID: 0x2f4
```

| EventID | O que significa | Por que importa |
|---|---|---|
| 4624 tipo 3 | Logon de rede bem-sucedido | Diz **quem** entrou e **de onde** |
| 4672 | Privilégios especiais atribuídos ao logon | Marca que o logon é administrativo |
| 5140 | Acesso a compartilhamento de rede | `C$`, `ADMIN$`, `IPC$` = acesso administrativo |
| 5145 | Verificação detalhada de arquivo no share | Mostra o **arquivo** tocado |
| 4688 | Criação de processo | `wsmprovhost.exe` = PowerShell Remoting; `services.exe` criando serviço = padrão PsExec |

No Sysmon, o mesmo salto aparece como **Event ID 3 (Network connection)** de `WS01` para `10.10.10.10:445` e `:5985`, e **Event ID 1 (Process creation)** do processo remoto.

Do lado da rede, um firewall FortiGate registra o mesmo salto assim:

```text
date=2026-09-03 time=14:31:07 devname="FGT-CORP-01" devid="FG100F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=10.10.10.50 srcport=51204 srcintf="port3" dstip=10.10.10.10 dstport=445 dstintf="port2" proto=6 action="accept" policyid=12 service="SMB" duration=18 sentbyte=8421 rcvdbyte=15230 user="admin.rodrigo"
```

Campos: `srcip`/`dstip` são origem e destino, `dstport=445` é SMB, `proto=6` é TCP, `action=accept` significa que a política 12 permitiu, e `user` só aparece porque o firewall tem identidade integrada ao domínio.

**O que o SOC N1 observa.** Normal: `admin.rodrigo` acessando `C$` do `DC01` a partir do **desktop de sempre**, em horário comercial, com um único destino. Suspeito, com o **rastro idêntico**: a mesma conta partindo de uma estação de usuário comum, fora do horário, tocando **10 ou 20 hosts em poucos minutos** (padrão de PsExec ou Impacket), ou 4624 tipo 3 de uma conta de serviço como `svc_backup` que nunca deveria fazer logon interativo em estação. Ferramentas como PsExec e Impacket deixam ainda **7045 — A service was installed** no destino, com nome de serviço aleatório.

**Erro comum de analista júnior.** Concluir "é legítimo porque a conta é de administrador". Movimento lateral **sempre** parece legítimo no evento isolado — a evidência está no **conjunto**: quantos destinos, a partir de qual origem, em que horário, e se a origem é a habitual daquela conta.

## LAB 14 — Ambientes prontos e plataformas online

Montar tudo à mão ensina muito, mas consome tempo. Estes ambientes já vêm com tudo pronto.

| Ambiente | O que é | Requisitos aproximados | Bom para |
|---|---|---|---|
| **DetectionLab** | Laboratório automatizado (Vagrant/Packer) com DC, servidor de arquivos, Windows client, Splunk, Sysmon, osquery, Velociraptor e Zeek já integrados | 16 GB de RAM (32 GB confortável), 100 GB de disco, VirtualBox ou VMware + Vagrant | Ver telemetria de endpoint chegando num SIEM sem configurar nada |
| **GOAD (Game of Active Directory)** | Floresta AD vulnerável de propósito, com múltiplos domínios e relações de confiança, para praticar ataque e **detecção** de AD | 24 a 32 GB de RAM, ~120 GB de disco, VirtualBox/VMware/Proxmox + Vagrant + Ansible | Entender ataques de Kerberos e como aparecem em 4768/4769/4776 |
| **Splunk Attack Range** | Ambiente da Splunk que sobe o laboratório e **executa simulações** (Atomic Red Team, Caldera) gerando dados de ataque rotulados | 16 GB local, ou conta AWS/Azure (custo por hora) + Terraform | Treinar escrita de detecção com dado de ataque conhecido |
| **Security Onion** | Distribuição de monitoramento de rede: Suricata, Zeek, Elastic, Kibana e ferramentas de caça, numa ISO só | 16 GB de RAM e 200 GB de disco no modo standalone; 4 GB só para importar PCAP | Analisar tráfego e alertas de IDS de verdade |

Dica prática: se sua máquina tem 16 GB, comece por **Security Onion no modo de importação de PCAP** — ele roda leve e você aprende leitura de alerta sem subir cinco máquinas virtuais.

### Plataformas online

| Plataforma | Custo | Foco |
|---|---|---|
| **TryHackMe** | Gratuito com trilhas pagas baratas | Fundamentos guiados, trilha SOC Level 1 |
| **LetsDefend** | Gratuito limitado / assinatura | Simula a fila de alertas de um SOC real |
| **CyberDefenders** | Muitos desafios gratuitos | Blue team prático: PCAP, memória, logs |
| **Blue Team Labs Online** | Gratuito limitado / assinatura | Investigações completas com relatório |

**Ordem sugerida de estudo:** (1) TryHackMe para os fundamentos e vocabulário; (2) LetsDefend para acostumar com o ritmo de triagem de alertas; (3) CyberDefenders para desenvolver análise profunda de artefatos; (4) Blue Team Labs Online para praticar a investigação inteira e o relatório; (5) só então DetectionLab ou GOAD localmente, quando você já souber o que quer procurar nos logos que vai gerar.

### Exercícios — Detectar password spraying, movimento lateral e ambientes prontos

1. Numa hora, o `DC01` registrou: `10.10.10.50` com 40 eventos 4625 na conta `jsilva`; `10.10.10.77` com 8 eventos 4625 em 8 contas diferentes. Qual dos dois é password spraying e por quê? Qual seria classificado como T1110.001?

2. Leia o trecho de log e diga o que o `Sub Status` revela sobre o conhecimento prévio do atacante:

```text
Event ID: 4625  Account Name: ana.pereira  Logon Type: 3
Status: 0xC000006D   Sub Status: 0xC0000064
Source Network Address: 198.51.100.24
```

3. Alerta: "Logon administrativo de rede em DC01". Evidência: 4624 tipo 3 da conta `admin.rodrigo`, origem `10.10.10.50` (estação habitual dele), às 10h14 de terça, seguida de um único 5140 no share `C$`. Verdadeiro ou falso positivo? Justifique.

4. O alerta do exercício 3 mudou: a mesma conta `admin.rodrigo` gerou 4624 tipo 3 em **14 servidores** em 6 minutos, com 7045 em cada um, às 03h20 de domingo. Quais são os dois próximos passos da investigação?

5. Você tem 16 GB de RAM e quer treinar leitura de alertas de IDS a partir de capturas de tráfego, sem subir domínio. Qual ambiente da tabela escolher e em que modo?

<details><summary>Ver gabarito</summary>

**1.** O spraying é `10.10.10.77`: 8 contas distintas com pouquíssimas tentativas cada — cardinalidade alta de contas por origem, volume baixo por conta, exatamente o desenho de T1110.003. O `10.10.10.50`, com 40 falhas concentradas numa única conta (`jsilva`), é *brute force* clássico, **T1110.001** — e, se houver política de bloqueio, provavelmente já gerou um 4740 de conta bloqueada. Repare que o caso mais barulhento (40 eventos) é o menos furtivo; o perigoso é o discreto.

**2.** `Sub Status 0xC0000064` significa **"usuário não existe"**. Ou seja, o atacante ainda está **adivinhando nomes de conta** — está na fase de enumeração, não tem lista válida. Se o código fosse `0xC000006A` ("senha errada, usuário existe"), a leitura seria bem pior: ele já teria enumerado contas reais do domínio, provavelmente por LDAP ou por uma lista vazada, e estaria só testando senhas. A origem `198.51.100.24` é um IP externo, o que agrava: autenticação de domínio não deveria vir da internet — verifique se há serviço exposto (VPN, Exchange, RDP Gateway).

**3.** **Falso positivo** (mais precisamente: atividade legítima). Todos os sinais são de administração normal — conta administrativa esperada, origem que é a estação habitual daquele administrador, horário comercial, **um único destino** e **um único** acesso a share. Ação correta do N1: registrar a conclusão com a justificativa (conta + origem habitual + horário + baixo volume) e, se o alerta se repetir muito, propor ao N2 uma regra de supressão que contemple o par conta/origem — nunca suprimir a conta sozinha.

**4.** Agora é **incidente provável**. Próximos passos: (a) **conter e escopar** — levantar a lista completa dos 14 destinos, os nomes dos serviços instalados nos eventos **7045** (nome aleatório é assinatura típica de PsExec/Impacket) e os 4688/Sysmon ID 1 nos destinos para saber o que foi executado; (b) **investigar a origem** — no host `10.10.10.50`, procurar o 4624 **inicial** que deu acesso à conta `admin.rodrigo` (foi tipo 3 remoto? tipo 10 RDP? veio de fora?) e verificar sinais de roubo de credencial; em paralelo, acionar o N2 e o processo de resposta a incidentes para avaliar desabilitar a conta e isolar a estação. Horário fora do expediente e alta cardinalidade de destinos são os dois discriminadores que mudaram o veredito.

**5.** **Security Onion**, no **modo de importação de PCAP** (`so-import-pcap`). Ele não precisa dos 16 GB completos nesse modo — cerca de 4 GB bastam — porque não fica capturando tráfego ao vivo: você alimenta capturas e o Suricata e o Zeek as processam, entregando os alertas e os logs (`conn.log`, `dns.log`, `http.log`, `ssl.log`) já indexados para você investigar no Kibana. DetectionLab e GOAD ficariam apertados ou inviáveis com 16 GB e, além disso, focam em telemetria de endpoint e Active Directory, não em análise de tráfego.

</details>


## LAB 15 — Desafio final integrador

Chegamos ao último laboratório do módulo. Os anteriores treinaram peças isoladas: Windows essencial e Sysmon, o controlador de domínio e a auditoria de autenticação, a detecção de *password spraying* e movimento lateral. Agora vamos juntar tudo num único incidente, do jeito que ele realmente chega ao SOC — no meio do turno, mal explicado, com logs espalhados por seis produtos diferentes.

Pense num acidente de trânsito. Você não recebe o filme pronto: recebe a câmera do semáforo, o extrato do pedágio, o áudio do rádio da ambulância e o depoimento de quem passava. O trabalho do analista é colocar tudo em ordem cronológica até a história fazer sentido. É exatamente isso que este laboratório treina.

### O chamado como ele chega

```
TICKET: INC-2026-04412
Origem: usuário final (self-service portal)
Prioridade inicial: P3 (baixa)
Aberto em: 2026-04-14 09:12 UTC

Texto do usuário (jsilva):
"Abri uma fatura que veio por e-mail do fornecedor e o Excel piscou
e fechou sozinho. Depois disso a máquina ficou lenta. É vírus?"

Ativo declarado: WKS-FIN-014
```

Um P3 que parece nada. É assim que quase todo incidente grave começa.

### Regra de ouro antes de tocar em qualquer log

| Passo | O que fazer | Por que importa |
|---|---|---|
| 1 | Fixar **um único fuso**: UTC | Gateway em UTC, Windows em UTC-3, proxy em UTC+0 — misturar fusos inventa causalidade falsa |
| 2 | Anotar o *pivô* inicial | Aqui: usuário `jsilva`, host `WKS-FIN-014` |
| 3 | Expandir por **artefato**, não por palpite | Hash → IP → domínio → conta |
| 4 | Não conter antes de mapear | Isolar cedo demais cega você para o resto |

### Os logs do incidente

**1) Gateway de e-mail (formato key=value, appliance de e-mail)**

```
date=2026-04-14 time=08:41:07 devname="MAILGW-01" logid="0954023001"
type="email" subtype="delivery" msg_id="<4f2a91@fornecedor-cobranca.example>"
from="cobranca@fornecedor-cobranca.example" to="jsilva@empresa-exemplo.com.br"
subject="Fatura 88213 vencida - regularizar hoje" spf=fail dkim=none dmarc=fail
attachment="none" url_count=1 url="hxxp://cdn-docs-fatura[.]example/inv/88213.html"
action=deliver reason="policy_allow_low_score" score=3.9
```

Campos que importam: `spf=fail`, `dkim=none`, `dmarc=fail` (o remetente **não** provou ser quem diz), `action=deliver` (passou mesmo assim, porque a nota ficou abaixo do corte) e `url` (a isca não é anexo, é link — por isso `attachment="none"`).

**2) Proxy (Squid `access.log`, tempo em epoch)**

```
1776156094.221   842 10.10.24.14 TCP_MISS/200 3120 GET http://cdn-docs-fatura.example/inv/88213.html - HIER_DIRECT/203.0.113.77 text/html
1776156131.907  1633 10.10.24.14 TCP_MISS/200 421904 GET http://cdn-docs-fatura.example/inv/Fatura_88213.xlsm - HIER_DIRECT/203.0.113.77 application/vnd.ms-excel.sheet.macroEnabled.12
```

Leitura: epoch `1776156094` = **2026-04-14 08:41:34 UTC**; `1776156131` = **08:42:11 UTC**. Cliente `10.10.24.14`, código `TCP_MISS/200` (buscou na origem e recebeu 200 OK), 421904 bytes baixados, tipo MIME de planilha **com macro habilitada**.

**3) Sysmon — Event ID 1 (Process Create) e Event ID 3 (Network Connect)**

```
EventID=1 UtcTime=2026-04-14 08:43:02.117 Computer=WKS-FIN-014.corp.local
Image=C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE
ParentImage=C:\Windows\explorer.exe User=CORP\jsilva
ProcessGuid={a1b2-...-0091} ProcessId=6144

EventID=1 UtcTime=2026-04-14 08:43:19.884 Computer=WKS-FIN-014.corp.local
Image=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentImage=C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE
CommandLine="powershell.exe -nop -w hidden -enc <BASE64_OMITIDO>"
User=CORP\jsilva ParentProcessId=6144 ProcessId=7320
Hashes=SHA256=9F1C4A77E0B2D3558C6A0E41B7D2295E3A88C0F4D61B9E7205AA3C8D14E6F0B2

EventID=3 UtcTime=2026-04-14 08:43:41.502 Computer=WKS-FIN-014.corp.local
Image=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User=CORP\jsilva Protocol=tcp Initiated=true
SourceIp=10.10.24.14 SourcePort=51188
DestinationIp=198.51.100.42 DestinationPort=443
DestinationHostname=api-sync-cloud.example
```

O sinal forte não é o PowerShell existir — é **EXCEL.EXE ser pai de powershell.exe**. Planilha não abre terminal. Some-se `-w hidden` (janela oculta) e `-enc` (comando codificado) e você tem execução mascarada.

**4) Zeek `dns.log` (campos separados por TAB)**

```
#fields ts  uid  id.orig_h  id.orig_p  id.resp_h  id.resp_p  proto  query  qtype_name  rcode_name  answers
1776156215.331  CmT4x1  10.10.24.14  53122  10.10.1.10  53  udp  api-sync-cloud.example  A  NOERROR  198.51.100.42
1776156515.208  CmT4x2  10.10.24.14  53140  10.10.1.10  53  udp  api-sync-cloud.example  A  NOERROR  198.51.100.42
1776156815.774  CmT4x3  10.10.24.14  53177  10.10.1.10  53  udp  api-sync-cloud.example  A  NOERROR  198.51.100.42
```

Repare no intervalo: 08:43:35, 08:48:35, 08:53:35 — exatos **300 segundos**. Esse batimento regular chama-se *beaconing*: a máquina "liga para casa" no relógio. Gente não navega assim.

**5) Firewall (Palo Alto, TRAFFIC em CSV — colunas reduzidas para leitura)**

```
receive_time,type,src,dst,src_user,app,rule,session_end_reason,bytes_sent,bytes_received,dst_port,action
2026/04/14 08:43:41,TRAFFIC,10.10.24.14,198.51.100.42,corp\jsilva,ssl,Regra-Saida-Internet,tcp-fin,4210,3980,443,allow
2026/04/14 09:31:55,TRAFFIC,10.10.24.14,198.51.100.42,corp\jsilva,ssl,Regra-Saida-Internet,tcp-fin,88104,5120,443,allow
2026/04/14 10:07:12,TRAFFIC,10.10.9.31,198.51.100.42,corp\svc_backup,ssl,Regra-Saida-Servidores,tcp-fin,1264883910,74220,443,allow
```

A última linha é a que dói: **1.264.883.910 bytes enviados** (≈1,18 GB) de um **servidor**, com a conta `svc_backup`, para o mesmo IP do C2 (*command and control*, servidor de comando e controle). Saída muito maior que a entrada = exfiltração.

**6) Windows Security — autenticação e compartilhamento**

```
EventID=4625 (falha de logon) 2026-04-14 09:52:14 UTC  DC-CORP-01
Account Name: admin.rodrigo   Source Network Address: 10.10.24.14
Logon Type: 3   Status: 0xC000006A (senha incorreta)

EventID=4625 2026-04-14 09:52:16 UTC  DC-CORP-01
Account Name: svc_backup   Source Network Address: 10.10.24.14
Logon Type: 3   Status: 0xC000006A

EventID=4624 (logon com sucesso) 2026-04-14 09:53:02 UTC  SRV-FS-02 (10.10.9.31)
Account Name: svc_backup   Logon Type: 3
Source Network Address: 10.10.24.14   Authentication Package: NTLM

EventID=5140 (acesso a compartilhamento de rede) 2026-04-14 09:55:40 UTC  SRV-FS-02
Account Name: svc_backup   Share Name: \\*\Financeiro
Source Address: 10.10.24.14   Access: ReadData (ou ListDirectory)
```

`Logon Type: 3` = logon de rede (veio de outra máquina, não do teclado). NTLM numa rede com Kerberos disponível é bandeira amarela. E `5140` mostra qual pasta foi tocada.

### Sua tarefa

1. Montar a **timeline em UTC**, do e-mail à exfiltração.
2. Listar os **IOCs** (*indicators of compromise*, indicadores de comprometimento) separados por tipo.
3. Mapear as **técnicas MITRE ATT&CK** (código `Txxxx`).
4. Determinar **hosts e usuários afetados**.
5. Escrever o **relatório de escalonamento** no template do Módulo 11.

Não avance sem tentar. O gabarito abaixo só ensina depois da tentativa.

<details><summary>Ver gabarito</summary>

**Timeline (UTC)**

| Hora | Evento | Fonte |
|---|---|---|
| 08:41:07 | E-mail entregue a `jsilva`; SPF/DKIM/DMARC falham | Mail gateway |
| 08:41:34 | Acesso à página isca `cdn-docs-fatura.example` (203.0.113.77) | Squid |
| 08:42:11 | Download de `Fatura_88213.xlsm` (421.904 bytes) | Squid |
| 08:43:02 | EXCEL.EXE aberto por explorer.exe | Sysmon 1 |
| 08:43:19 | EXCEL.EXE gera `powershell.exe -nop -w hidden -enc` | Sysmon 1 |
| 08:43:41 | Primeira conexão 443 para 198.51.100.42 | Sysmon 3 / firewall |
| 08:43:35→08:53:35 | Beacon DNS a cada 300 s para `api-sync-cloud.example` | Zeek dns.log |
| 09:52:14–09:52:16 | Falhas 4625 para `admin.rodrigo` e `svc_backup` a partir de 10.10.24.14 | DC-CORP-01 |
| 09:53:02 | 4624 tipo 3 NTLM: `svc_backup` entra em SRV-FS-02 | SRV-FS-02 |
| 09:55:40 | 5140: acesso ao share `\\*\Financeiro` | SRV-FS-02 |
| 10:07:12 | ≈1,18 GB enviados de 10.10.9.31 para o C2 | Firewall |

**IOCs**

| Tipo | Valor |
|---|---|
| Remetente | `cobranca@fornecedor-cobranca.example` |
| URL | `hxxp://cdn-docs-fatura[.]example/inv/88213.html` e `/inv/Fatura_88213.xlsm` |
| Domínio C2 | `api-sync-cloud[.]example` |
| IP staging | `203.0.113.77` |
| IP C2 | `198.51.100.42` |
| SHA256 | `9F1C…F0B2` |
| Conta abusada | `CORP\svc_backup` |
| Hosts | WKS-FIN-014 (10.10.24.14), SRV-FS-02 (10.10.9.31) |

**MITRE ATT&CK**

| Fase | Técnica |
|---|---|
| Phishing com link | T1566.002 |
| Execução por macro / interação do usuário | T1204.002 |
| Interpretador PowerShell | T1059.001 |
| Ofuscação (`-enc`) | T1027 |
| C2 sobre canal cifrado/web | T1071.001 |
| Beacon com intervalo fixo | T1029 (agendamento) + T1071 |
| Uso de conta válida | T1078.002 |
| Movimento lateral por SMB/share admin | T1021.002 |
| Exfiltração pelo canal de C2 | T1041 |

**Afetados:** WKS-FIN-014 (paciente zero, `jsilva`), SRV-FS-02 (segundo host, via `svc_backup`), contas `jsilva` (comprometida) e `svc_backup` (abusada); `admin.rodrigo` só sofreu tentativa.

**Relatório de escalonamento (template do Módulo 11)**

```
[1] RESUMO EXECUTIVO
Comprometimento confirmado de WKS-FIN-014 via phishing com planilha com macro,
com C2 ativo e exfiltração de ~1,18 GB do file server SRV-FS-02 usando a conta
de serviço svc_backup. Severidade: P1 (Alta).

[2] JANELA DO INCIDENTE
2026-04-14 08:41 UTC a 10:07 UTC (em andamento na abertura).

[3] EVIDÊNCIAS-CHAVE
Sysmon 1 (EXCEL.EXE -> powershell.exe -enc), Sysmon 3 e Zeek dns.log
(beacon 300 s para api-sync-cloud.example), 4625/4624/5140 no domínio,
TRAFFIC do firewall com 1.264.883.910 bytes de saída.

[4] IOCS
Ver tabela de IOCs acima (7 artefatos).

[5] IMPACTO
Confidencialidade: dados do share \\*\Financeiro potencialmente exfiltrados.
Integridade e disponibilidade: sem evidência de alteração ou cifragem.

[6] AÇÕES JÁ EXECUTADAS PELO N1
Triagem, correlação multi-fonte, timeline e enriquecimento dos IOCs.
Nenhuma ação de contenção executada (fora do escopo do N1).

[7] RECOMENDAÇÕES AO N2/IR
Isolar WKS-FIN-014 e SRV-FS-02; bloquear 198.51.100.42, 203.0.113.77 e
os dois domínios; redefinir credenciais de jsilva e svc_backup;
coletar memória antes de desligar; revisar por que DMARC=fail foi entregue.

[8] CONTATO E HANDOVER
Analista N1, turno da manhã, ticket INC-2026-04412.
```

</details>

### Exercícios — LAB 15 — Desafio final integrador

1. **Cálculo.** O beacon roda a cada 300 s desde 08:43:35 UTC. Quantas conexões terão ocorrido às 10:07:12 UTC (inclusive) e por que esse número é útil no relatório?
2. **Leitura de log.** No firewall, a última linha traz `bytes_sent=1264883910` e `bytes_received=74220`. Converta para GB e explique o que a assimetria indica.
3. **Verdadeiro ou falso positivo?** Um alerta dispara: "PowerShell executado em WKS-FIN-014 às 08:43:19". Sozinho, isso é malicioso? Qual campo decide?
4. **Próximo passo.** Você confirmou 4624 tipo 3 com NTLM em SRV-FS-02 usando `svc_backup`. Qual é a próxima consulta e por quê?
5. **Escopo.** Como provar que nenhum terceiro host foi tocado?

<details><summary>Ver gabarito</summary>

1. De 08:43:35 a 10:07:12 há 5.017 segundos; 5.017 ÷ 300 = 16 intervalos completos, logo **17 conexões** (a inicial mais 16). Serve para provar persistência: um erro pontual não repete 17 vezes com desvio zero.
2. 1.264.883.910 ÷ 1.073.741.824 ≈ **1,18 GB** enviados contra ≈ 72 KB recebidos. Navegação normal recebe muito mais do que envia; a inversão é a assinatura clássica de exfiltração (T1041).
3. **Falso positivo isolado.** PowerShell é ferramenta legítima de administração. O que decide é o `ParentImage`: `EXCEL.EXE` como pai, somado a `-w hidden` e `-enc`, transforma o evento em verdadeiro positivo. Sem o campo pai, não escale.
4. Consultar **4768/4769** e demais **4624/4625** de `svc_backup` nas últimas 24 h em todos os DCs, além de **5140/5145** em SRV-FS-02. Objetivo: saber se a conta de serviço tocou outros servidores e quais pastas abriu. Conta de serviço tem comportamento previsível — qualquer desvio marca o alcance real do atacante.
5. Pivotando pelo IP de origem `10.10.24.14` e pela conta `svc_backup` em **todas** as fontes: 4624 em todos os hosts, Zeek `conn.log` para sessões SMB (porta 445) partindo dessa origem e TRAFFIC do firewall com destino ao C2. Só se declara escopo fechado quando as três fontes concordam.

</details>

## Mini-laboratório — Windows, Active Directory e a investigação ponta a ponta

**Pré-requisitos:** VirtualBox, uma VM Windows 10/11 de avaliação (WKS-LAB) e uma VM Windows Server como controlador de domínio `corp.local` (DC-LAB), Sysmon com uma configuração pública de referência, Wireshark e uma segunda VM Linux com Zeek (ou Security Onion). Rede em modo *Host-Only*, sem contato com a rede da empresa.

1. **Preparar a coleta.** No WKS-LAB, instale o Sysmon com a configuração escolhida. Verifique que o canal `Microsoft-Windows-Sysmon/Operational` está gerando eventos. *Observar:* Event ID 1 para cada processo iniciado.
2. **Ligar a auditoria no DC-LAB.** Em `Default Domain Controllers Policy`, habilite auditoria de logon de conta e de acesso a objetos. *Observar:* 4624 e 4625 aparecendo em `Security` a cada tentativa.
3. **Gerar cadeia pai-filho benigna.** No WKS-LAB, abra o Bloco de Notas a partir do Explorer e depois um `powershell.exe` a partir do menu Iniciar. *Observar:* nos dois eventos 1, o `ParentImage` é `explorer.exe` — este é o seu padrão de normalidade.
4. **Gerar autenticação de rede.** Do WKS-LAB, mapeie um compartilhamento do DC-LAB com uma conta de domínio, erre a senha duas vezes e acerte na terceira. *Observar:* dois 4625 com `0xC000006A`, depois um 4624 `Logon Type 3` e um 5140 com o nome do share.
5. **Capturar o tráfego.** Com o Wireshark no WKS-LAB, aplique o filtro `tcp.port == 445 || dns` durante o passo 4. *Observar:* a resolução de nome do DC seguida da sessão SMB.
6. **Correlacionar.** Exporte os eventos e monte uma mini-timeline em UTC juntando Sysmon, Security e a captura.

**Critério de sucesso:** você consegue, olhando só para os artefatos exportados, dizer qual conta autenticou, de qual origem, em que host e qual pasta foi acessada — sem depender da memória do que você fez.

## O que um SOC Level 1 realmente precisa saber

- 🟢 Ler um 4624 e identificar `Logon Type` (2 = console, 3 = rede, 10 = RDP) e o endereço de origem.
- 🟢 Ler um 4625 e traduzir o `Status`: `0xC000006A` é senha errada, `0xC0000064` é usuário inexistente — a diferença separa spraying de erro de digitação.
- 🟢 Saber que Sysmon Event ID 1 é criação de processo, 3 é conexão de rede e 22 é consulta DNS.
- 🟢 Sempre olhar o `ParentImage` antes de julgar um processo; o pai conta mais que o filho.
- 🟢 Converter tudo para UTC antes de montar qualquer timeline.
- 🟡 Reconhecer beacon por intervalo regular no `dns.log` do Zeek e por sessões curtas repetidas no firewall.
- 🟡 Identificar exfiltração pela assimetria `bytes_sent` ≫ `bytes_received`.
- 🟡 Desconfiar de NTLM em ambiente com Kerberos e de conta de serviço autenticando fora do horário e do host habituais.
- 🟡 Usar 5140/5145 para saber **qual** compartilhamento foi acessado, não apenas que houve logon.
- 🔴 Correlacionar 4768/4769 para reconstruir a trilha Kerberos do movimento lateral.
- 🔴 Reconhecer o rastro em log deixado por ferramentas como PsExec, Impacket ou BloodHound sem precisar executá-las.
- 🔴 Fechar escopo com três fontes independentes concordando antes de declarar o incidente contido.

## Resumo em 10 linhas

1. Windows e Active Directory são o centro de gravidade da maioria dos incidentes corporativos.
2. O log nativo do Windows responde "quem entrou"; o Sysmon responde "o que rodou".
3. `Logon Type` e código de `Status` são os dois campos que mais economizam tempo na triagem.
4. Relação pai-filho de processos é o detector barato mais eficaz contra macro maliciosa.
5. Password spraying aparece como muitos 4625 `0xC000006A` em muitas contas, poucas tentativas cada.
6. Movimento lateral aparece como 4624 tipo 3 seguido de 5140 num host onde a conta não costuma ir.
7. Conta de serviço tem comportamento previsível; desvio nela é sinal forte, não ruído.
8. C2 se denuncia pela regularidade; exfiltração, pelo volume assimétrico de saída.
9. Timeline em UTC é o produto principal do N1 — sem ela o N2 refaz todo o trabalho.
10. Escalar cedo, com evidência organizada, vale mais que investigar sozinho até ter certeza.



---
