📝 **Exemplos**

**Exemplo 1: Auditoria Inicial**

`bash
sudo python3 ssh_auditor_v2.py --audit --verbose
`

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
`


---

**Exemplo 2: Dry-Run**
`bash
sudo python3 ssh_auditor_v2.py --fix --dry-run
`



**Saída:**
```bash
[2025-12-24 19:05:00] [INFO] 🔍 MODO DRY-RUN ATIVADO

[2025-12-24 19:05:00] [INFO] Iniciando correção de configurações SSH...

[2025-12-24 19:05:00] [DEBUG] Atualizado: Ciphers = chacha20-poly1305@openssh.com,...

[2025-12-24 19:05:00] [DEBUG] Adicionado: PubkeyAuthentication = yes

[2025-12-24 19:05:00] [INFO] Dry-Run: 24 parâmetros seriam atualizados

[2025-12-24 19:05:00] [INFO] Dry-Run: 0 permissões seriam corrigidas
`


---

**Exemplo 3: Aplicação de Correções**



`bash
IMPORTANTE: Ter acesso alternativo ao servidor!

sudo python3 ssh_auditor_v2.py --fix
`



**Saída:**

```bash
[2025-12-24 19:10:00] [INFO] Iniciando correção de configurações SSH...

[2025-12-24 19:10:00] [INFO] Backup criado: /var/backups/ssh_auditor/sshd_config.bak_20251224_191000

[2025-12-24 19:10:00] [INFO] Configuração SSH atualizada

[2025-12-24 19:10:00] [INFO] ✅ Sintaxe do sshd_config válida

[2025-12-24 19:10:00] [INFO] Reiniciando serviço SSH...

[2025-12-24 19:10:02] [INFO] ✅ Serviço SSH reiniciado com sucesso

[2025-12-24 19:10:02] [INFO] ✅ PROCESSO CONCLUÍDO COM SUCESSO
`


---

**Exemplo 4: Criação de Usuário**

`bash
sudo python3 ssh_auditor_v2.py --create-user admin_backup
`



**Saída:**

```bash
[2025-12-24 19:15:00] [INFO] Usuário 'admin_backup' criado

[2025-12-24 19:15:00] [INFO] Senha definida para 'admin_backup'

[2025-12-24 19:15:00] [INFO] Usuário 'admin_backup' adicionado ao grupo 'sudo'



================================================================================

🔐 CREDENCIAIS DO NOVO USUÁRIO SUDO

================================================================================

Username: admin_backup

Password: K7#mR9@pL2$vN4&qW8

================================================================================

⚠️  ATENÇÃO: Salve esta senha AGORA. Ela não será exibida novamente.

================================================================================
`
