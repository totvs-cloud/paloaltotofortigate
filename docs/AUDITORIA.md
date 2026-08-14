# Modelo do relatório de auditoria (Fase A)

O `fwaudit.py offline` gera `out/<data>/relatorio.md` (+ `.html`) com esta
estrutura. Evidência completa de cada check: `out/<data>/checks/<ID>.json`.

1. **Cabeçalho** — hostname, sha256/data do snapshot, versão PAN-OS, aviso de
   possível defasagem vs running-config.
2. **Sumário executivo** — contagem por severidade + tabela ID → check → itens.
3. **Inventário** — regras/NAT/zonas/objetos por vsys, rede (rotas, VPN,
   subinterfaces, EDLs, certs).
4. **Um bloco por check** (A01–A22), cada um com: severidade, classe
   FortiConverter coberta, resumo com número + consequência, tabela de evidência
   (até 30 linhas; resto no JSON).

## Como ler as severidades

| Sev | Significado | Tratamento |
|---|---|---|
| CRÍTICO | Falha provável na virada com impacto amplo (EDLs no topo, VIPs do Check_MK, rotas) | Pendência bloqueante da janela; dono + prazo |
| ALTO | Quebra funcional localizada ou cegueira operacional (User-ID, sem log, PSK, gerência) | Resolver antes do compare final |
| MÉDIO | Degrada postura/qualidade, não derruba tráfego (UTM, FQDN, nomes, certs) | Plano de remediação com data |
| BAIXO | Higiene (regras disabled) | Decidir migrar/descartar |
| INFO | Insumo de planejamento (mapas, contagens, de-para) | Anexar aos desenhos |

## As 11 classes de falha do FortiConverter (observadas na conversão TESP4)

FC-1 `logtraffic disable` em ~100% das policies · FC-2 zero UTM convertido ·
FC-3 App-ID cru/`service ALL` · FC-4 EDL vira objeto indefinido · FC-5 códigos
geo indefinidos · FC-6 grupos LDAP não resolvidos · FC-7 FQDN "incoming
interface failed" · FC-8 PSK exigem reset (e vazam no output) · FC-9 tunnel.N
indefinida em zona/rota · FC-10 sufixos silenciosos por conflito de nome ·
FC-11 regras disabled carregadas.

Cada check A01–A22 indica qual classe cobre; o compare C01–C12 verifica no FG
real se a classe foi remediada.
