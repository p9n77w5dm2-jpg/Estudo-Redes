# Redes para SOC Level 1

Curso completo de redes para quem quer trabalhar como analista N1 em um SOC
(Security Operations Center), escrito para quem **nunca estudou redes**.

**https://p9n77w5dm2-jpg.github.io/Estudo-Redes/**

21 módulos · 238 mil palavras · exercícios com gabarito · 15 laboratórios práticos · roadmap de 90 dias

---

## Como usar

| Modo | Como |
|---|---|
| Estudar do zero | Siga do Módulo 1 ao 18 na ordem, fazendo todos os laboratórios |
| Consulta rápida | Use a busca do site — ela procura em todos os módulos de uma vez |
| Revisão de plantão | Vá às seções "O que um SOC Level 1 realmente precisa saber" de cada módulo |

O site funciona **offline** depois da primeira visita. No celular, use
"Adicionar à tela de início" para abrir como aplicativo.

## Conteúdo

**Parte I — Fundamentos:** redes, LAN/WAN/VLAN/DMZ, modelo OSI camada a camada,
TCP/IP e packet flow completo, endereçamento IP e subnetting.

**Parte II — Serviços:** DNS (incluindo tunneling, DGA e fast flux) e as ~33 portas
e protocolos que aparecem todo dia num SOC.

**Parte III — Defesa e identidade:** firewalls (stateless, stateful, NGFW), proxies e
SASE, VPN, e Active Directory com os ataques clássicos (Kerberoasting, Pass-the-Hash,
Golden Ticket, DCSync).

**Parte IV — Operação:** logs e investigação, Wireshark, IDS/IPS/NDR/SIEM/EDR/XDR,
e as ameaças comuns com o rastro que cada uma deixa em log.

**Parte V — Prática e carreira:** mapa de conhecimentos, 15 laboratórios passo a passo,
checklist de entrevista e o plano de estudo de 90 dias.

Os módulos em markdown estão em [`modulos/`](modulos/), e o curso inteiro em um único
arquivo em [`Tutorial-Redes-SOC-Level-1.md`](Tutorial-Redes-SOC-Level-1.md).

## Sobre o conteúdo

- **Todos os dados são fictícios.** Domínios `example.com` / `corp.local`; IPs internos
  nas faixas RFC1918; IPs "públicos" apenas nas faixas de documentação RFC5737
  (`203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`).
- **Conteúdo estritamente defensivo.** Ferramentas ofensivas são nomeadas e o rastro
  que deixam em log é detalhado, mas não há payloads, comandos de exploração nem
  técnicas de evasão.
- Material de estudo pessoal, sem vínculo com qualquer empregador.
