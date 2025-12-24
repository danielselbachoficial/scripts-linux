**Exemplo 1: Auditoria Inicial**

`
sudo python3 ssh_auditor_v2.py --audit --verbose
`

---
**Saída:**

```bash
================================================================================

RELATÓRIO DE AUDITORIA SSH - ENTERPRISE EDITION

Data: 2025-12-24 19:00:00

Servidor: web-server-01

================================================================================



❌ TOTAL DE ISSUES: 13



────────────────────────────────────────────────────────────────────────────────

CATEGORIA: SSH_CONFIG

────────────────────────────────────────────────────────────────────────────────



🔴 [CRITICAL] missing

   parameter: PermitEmptyPasswords

   recommended: no

   comment: CIS 5.2.9: Senhas vazias são falha crítica



🟠 [HIGH] missing

   parameter: PubkeyAuthentication

   recommended: yes

   comment: CIS 5.2.7: Chaves públicas são o método recomendado
```
