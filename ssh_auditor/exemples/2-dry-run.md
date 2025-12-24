**Exemplo 2: Dry-Run**
`
sudo python3 ssh_auditor_v2.py --fix --dry-run
`


---
**Saída:**
```bash
[2025-12-24 19:05:00] [INFO] 🔍 MODO DRY-RUN ATIVADO

[2025-12-24 19:05:00] [INFO] Iniciando correção de configurações SSH...

[2025-12-24 19:05:00] [DEBUG] Atualizado: Ciphers = chacha20-poly1305@openssh.com,...

[2025-12-24 19:05:00] [DEBUG] Adicionado: PubkeyAuthentication = yes

[2025-12-24 19:05:00] [INFO] Dry-Run: 24 parâmetros seriam atualizados

[2025-12-24 19:05:00] [INFO] Dry-Run: 0 permissões seriam corrigidas
```
