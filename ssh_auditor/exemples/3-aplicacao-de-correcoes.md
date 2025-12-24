**Exemplo 3: Aplicação de Correções**

IMPORTANTE: Ter acesso alternativo ao servidor!

`
sudo python3 ssh_auditor_v2.py --fix
`


---
**Saída:**

```bash
[2025-12-24 19:10:00] [INFO] Iniciando correção de configurações SSH...

[2025-12-24 19:10:00] [INFO] Backup criado: /var/backups/ssh_auditor/sshd_config.bak_20251224_191000

[2025-12-24 19:10:00] [INFO] Configuração SSH atualizada

[2025-12-24 19:10:00] [INFO] ✅ Sintaxe do sshd_config válida

[2025-12-24 19:10:00] [INFO] Reiniciando serviço SSH...

[2025-12-24 19:10:02] [INFO] ✅ Serviço SSH reiniciado com sucesso

[2025-12-24 19:10:02] [INFO] ✅ PROCESSO CONCLUÍDO COM SUCESSO
```
