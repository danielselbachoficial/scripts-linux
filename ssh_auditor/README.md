# SSH Auditor and Hardening Tool - Enterprise Edition

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/seu-usuario/ssh-auditor)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)
[![CIS Benchmark](https://img.shields.io/badge/CIS-5.2.x-red.svg)](https://www.cisecurity.org/)

Ferramenta profissional de auditoria e hardening de SSH para servidores Linux, com conformidade CIS Benchmark, NIST SP 800-123 e LGPD.

## 📋 Índice

- [Características](#-características)
- [Requisitos](#-requisitos)
- [Instalação](#-instalação)
- [Uso](#-uso)
  - [Menu Interativo](#menu-interativo)
  - [Linha de Comando](#linha-de-comando)
- [Funcionalidades](#-funcionalidades)
- [Conformidade](#-conformidade)
- [Exemplos](#-exemplos)
- [Troubleshooting](#-troubleshooting)
- [Contribuição](#-contribuição)
- [Licença](#-licença)

---

## 🚀 Características

### Auditoria Completa
- ✅ Verificação de 24+ parâmetros críticos do SSH
- ✅ Análise de permissões de arquivos e diretórios
- ✅ Validação de força de chaves de host (RSA 3072+ bits)
- ✅ Auditoria de `authorized_keys` de todos os usuários
- ✅ Verificação de status do Fail2ban

### Hardening Automatizado
- 🔒 Aplicação de configurações CIS Benchmark 5.2.x
- 🔒 Correção automática de permissões
- 🔒 Backup automático antes de alterações
- 🔒 Validação de sintaxe pré-restart
- 🔒 Rollback automático em caso de falha

### Recursos Avançados
- 🎯 Menu interativo intuitivo
- 🎯 Modo dry-run para simulação
- 🎯 Logging estruturado em JSON (SIEM-ready)
- 🎯 Suporte multi-distro (Debian/Ubuntu, RHEL/CentOS/Rocky, Alpine)
- 🎯 Criação de usuários sudo com senhas seguras
- 🎯 Instalação e configuração automática do Fail2ban

---

## 📦 Requisitos

### Sistema Operacional
- Debian 10+, Ubuntu 18.04+
- RHEL 7+, CentOS 7+, Rocky Linux 8+, AlmaLinux 8+
- Alpine Linux 3.12+

### Software
- Python 3.8 ou superior
- OpenSSH Server
- Privilégios de root/sudo

### Dependências Python
Todas as dependências são da biblioteca padrão do Python:
- `os`, `sys`, `subprocess`
- `logging`, `argparse`
- `shutil`, `datetime`
- `json`, `re`, `pwd`, `grp`
- `pathlib`, `typing`

---

## 🔧 Instalação

### Método 1: Clone do Repositório
```bash
# Clone o repositório
git clone https://github.com/seu-usuario/ssh-auditor.git
cd ssh-auditor

# Tornar executável
chmod +x ssh_auditor_v2.py

# Validar sintaxe
python3 -m py_compile ssh_auditor_v2.py && echo "✅ OK"
```

### Método 2: Download Direto

```bash
# Download do script:
wget https://raw.githubusercontent.com/seu-usuario/ssh-auditor/main/ssh_auditor_v2.py

# Tornar executável:
chmod +x ssh_auditor_v2.py
```

### Método 3: Instalação Global

```bash
Copiar para /usr/local/bin
sudo cp ssh_auditor_v2.py /usr/local/bin/ssh-auditor
sudo chmod +x /usr/local/bin/ssh-auditor

# Usar de qualquer lugar
sudo ssh-auditor
```

---

💻 **Uso**



**Menu Interativo**



**Inicie o menu interativo sem argumentos:**


`bash
sudo python3 ssh_auditor_v2.py
`



**Menu Principal:**

```bash
================================================================================

SSH AUDITOR AND HARDENING TOOL - ENTERPRISE EDITION v2.0

Servidor: meu-servidor

Distro: debian

================================================================================



MENU PRINCIPAL:



  [1] Auditoria de Segurança SSH

  [2] Simular Correções (Dry-Run)

  [3] Aplicar Correções (CUIDADO!)

  [4] Instalar/Configurar Fail2ban

  [5] Criar Usuário Sudo

  [6] Auditoria + Hardening Completo

  [7] Ver Logs de Auditoria

  [8] Ver Relatórios Salvos



  [0] Sair



--------------------------------------------------------------------------------

Escolha uma opção:
`

**Linha de Comando**

**Auditoria Básica**

`bash
sudo python3 ssh_auditor_v2.py --audit
`



**Simulação de Correções (Dry-Run)**

`bash
sudo python3 ssh_auditor_v2.py --fix --dry-run --verbose
`



**Aplicar Correções**

`bash
ATENÇÃO: Certifique-se de ter acesso alternativo ao servidor!

sudo python3 ssh_auditor_v2.py --fix --verbose
`

**Criar Usuário Sudo**

`bash
sudo python3 ssh_auditor_v2.py --create-user admin_backup
`



**Instalar Fail2ban**
`bash
sudo python3 ssh_auditor_v2.py --install-fail2ban
`

**Hardening**

`bash
sudo python3 ssh_auditor_v2.py --audit --fix --install-fail2ban --verbose
`

---

🛠️ **Funcionalidades**


1. **Auditoria de Segurança SSH**

**Verifica conformidade com CIS Benchmark 5.2.x:**

**Parâmetros Críticos:**
- PermitRootLogin → deve ser no
- PermitEmptyPasswords → deve ser no
- PasswordAuthentication → deve ser no (usar chaves SSH)
- PubkeyAuthentication → deve ser yes

**Parâmetros de Alta Prioridade:**
- Cifras criptográficas modernas (AEAD + CTR mode)
- MACs SHA-2 com Encrypt-then-MAC
- Algoritmos de troca de chaves pós-quânticos

**Parâmetros de Segurança:**
- MaxAuthTries → 3 tentativas
- LoginGraceTime → 60 segundos
- MaxStartups → 10:30:60 (proteção DoS)
- X11Forwarding → desabilitado
- AllowTcpForwarding → desabilitado


2. **Auditoria de Permissões**

**Verifica permissões de arquivos críticos:**

| Arquivo/Diretório | Permissões | Owner | Group |
|-------------------|------------|-------|-------|
| /etc/ssh/sshd_config | 0600 | root | root |
| /etc/ssh/ | 0755 | root | root |
| /etc/ssh/ssh_host__key | 0600 | root | root |
| /etc/ssh/ssh_host__key.pub | 0644 | root | root |
| ~/.ssh/authorized_keys | 0600 | user | user |


3. **Auditoria de Chaves de Host**

**Verifica força das chaves de host:**
- RSA: Mínimo 3072 bits (NIST SP 800-57)
- Ed25519: Recomendado (curva elíptica moderna)
- ECDSA: Aceito (256+ bits)


4. **Hardening Automatizado**

**Processo de Hardening:**
1. Backup automático do sshd_config
2. Aplicação de configurações CIS Benchmark
3. Validação de sintaxe (sshd -t)
4. Correção de permissões de arquivos
5. Restart do SSH com retry (3 tentativas)
6. Rollback automático em caso de falha



**Segurança do Processo:**
- ✅ Backup timestampado em /var/backups/ssh_auditor/
- ✅ Validação de sintaxe antes de restart
- ✅ Detecção de sessões SSH ativas
- ✅ Retry com backoff exponencial
- ✅ Restauração automática em caso de falha


5. **Gerenciamento de Usuários**

Criação de Usuário Sudo:
- Validação POSIX.1-2008 do username
- Geração de senha segura (20 caracteres)
- Adição automática ao grupo sudo/wheel
- Exibição única da senha (não logada)

**Requisitos de Senha:**
- Mínimo 20 caracteres
- Letras maiúsculas e minúsculas
- Números e símbolos
- Sem caracteres ambíguos (0, O, l, 1, I)


6. **Fail2ban**

**Configuração Automática:**
- Instalação via apt/yum
- Configuração de jail para SSH
- Parâmetros: 3 tentativas, 1h de ban, 10min de janela
- Habilitação e start automático

---

📊 **Conformidade**

**CIS Benchmark 5.2.x**

| Item CIS | Descrição | Status |
|----------|-----------|--------|
| 5.2.4 | LogLevel VERBOSE | ✅ |
| 5.2.5 | MaxAuthTries 3 | ✅ |
| 5.2.6 | X11Forwarding no | ✅ |
| 5.2.7 | PubkeyAuthentication yes | ✅ |
| 5.2.8 | PasswordAuthentication no | ✅ |
| 5.2.9 | PermitEmptyPasswords no | ✅ |
| 5.2.10 | PermitRootLogin no | ✅ |
| 5.2.11 | IgnoreRhosts yes | ✅ |
| 5.2.12 | HostbasedAuthentication no | ✅ |
| 5.2.13 | PermitUserEnvironment no | ✅ |
| 5.2.15 | Banner configurado | ✅ |
| 5.2.16 | LoginGraceTime 60 | ✅ |
| 5.2.17 | ClientAliveInterval 300 | ✅ |
| 5.2.18 | ClientAliveCountMax 0 | ✅ |
| 5.2.19 | UsePAM yes | ✅ |
| 5.2.21 | MaxStartups 10:30:60 | ✅ |
| 5.2.22 | MaxSessions 10 | ✅ |



**NIST SP 800-123**

- ✅ Autenticação forte (chaves públicas)
- ✅ Criptografia moderna (AES-GCM, ChaCha20-Poly1305)
- ✅ Logging detalhado para auditoria
- ✅ Proteção contra brute-force (Fail2ban)

**LGPD (Lei Geral de Proteção de Dados)**
- ✅ Art. 46: Medidas de segurança técnicas adequadas
- ✅ Art. 47: Boas práticas de governança
- ✅ Art. 48: Comunicação de incidentes (logging)

---

🔍 **Troubleshooting**

Problema: SSH não reinicia após correções

Sintoma:
`
❌ FALHA CRÍTICA: SSH não reiniciou corretamente
`

**Solução:**

1. **Verifique o status do SSH:**
   `bash
   sudo systemctl status sshd
   `

2. **Verifique logs do sistema:**

   `bash
   sudo journalctl -u sshd -n 50
   `

3. **Teste a configuração manualmente:**
   `bash
   sudo sshd -t -f /etc/ssh/sshd_config
   `

4. **Restaure o backup se necessário:**
   `bash
   sudo cp /var/backups/ssh_auditor/sshd_config.bak_TIMESTAMP /etc/ssh/sshd_config
   sudo systemctl restart sshd
   `
   
Problema: Bloqueio de acesso SSH



**Prevenção:**
- ✅ Sempre execute --dry-run primeiro
- ✅ Mantenha acesso alternativo (console/IPMI/KVM)
- ✅ Configure pelo menos 1 usuário com chave SSH antes de desabilitar senha
- ✅ Teste a chave SSH em nova sessão antes de fechar a atual



**Recuperação:**

1. **Acesse via console físico ou IPMI**

2. **Restaure o backup:**
   `bash
   sudo cp /var/backups/ssh_auditor/sshd_config.bak_TIMESTAMP /etc/ssh/sshd_config
   sudo systemctl restart sshd
   `

Problema: DeprecationWarning

**Sintoma:**
`
DeprecationWarning: datetime.datetime.utcnow() is deprecated

`
---



📂 **Estrutura de Arquivos**

`
ssh-auditor/
├── ssh_auditor_v2.py          # Script principal
├── README.md                  # Esta documentação
├── LICENSE                    # Licença MIT
├── CHANGELOG.md               # Histórico de versões

└── examples/                  # Exemplos de uso
    ├── basic_audit.sh
    ├── full_hardening.sh
    └── create_user.sh

`



****Arquivos Gerados****

`
/var/log/
├── ssh_auditor.log                    # Log estruturado JSON
└── ssh_audit_YYYYMMDD_HHMMSS.txt     # Relatórios de auditoria

/var/backups/ssh_auditor/
└── sshd_config.bak_YYYYMMDD_HHMMSS   # Backups do sshd_config

`

---



🤝 **Contribuição**
Contribuições são bem-vindas! Por favor, siga estas diretrizes:

****Como Contribuir:****

1. **Fork o repositório**

2. **Crie uma branch para sua feature:**

   `bash
   git checkout -b feature/nova-funcionalidade
   `

3. **Commit suas mudanças:**

   `bash
   git commit -m "Adiciona nova funcionalidade X"
   `

4. **Push para a branch:**
   `bash
   git push origin feature/nova-funcionalidade
   `
   
6. **Abra um Pull Request**

**Diretrizes de Código**
- Seguir PEP 8 (Python Style Guide)
- Adicionar docstrings para funções públicas
- Incluir testes para novas funcionalidades
- Atualizar documentação quando necessário



**Reportar Bugs**
Abra uma issue incluindo:
- Descrição detalhada do problema
- Passos para reproduzir
- Versão do Python e distribuição Linux
- Logs relevantes

---

📄 **Licença**
Este projeto está licenciado sob a Licença MIT - veja o arquivo LICENSE para detalhes.
`

**MIT License**

Copyright (c) 2025 Daniel Selbach Figueiró


Permission is hereby granted, free of charge, to any person obtaining a copy

of this software and associated documentation files (the "Software"), to deal

in the Software without restriction, including without limitation the rights

to use, copy, modify, merge, publish, distribute, sublicense, and/or sell

copies of the Software, and to permit persons to whom the Software is

furnished to do so, subject to the following conditions:


The above copyright notice and this permission notice shall be included in all

copies or substantial portions of the Software.


THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR

IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,

FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE

AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER

LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,

OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE

SOFTWARE.

`

---
👤 **Autor**
- Daniel Selbach Figueiró
- GitHub: @danielselbachoficial
- LinkedIn: [https://www.linkedin.com/in/danielselbachoficial/](https://www.linkedin.com/in/danielselbachoficial/)

---
🙏 **Agradecimentos**
- CIS Benchmarks - Padrões de segurança
- NIST - Guias de segurança
- OpenSSH - Implementação SSH
- Comunidade Python e Linux

---
📚 **Referências**
- CIS Benchmark for Linux
- NIST SP 800-123 - Guide to General Server Security
- NIST SP 800-57 - Key Management
- OpenSSH Security Best Practices
- LGPD - Lei Geral de Proteção de Dados

---
📊 **Status do Projeto**
!GitHub last commit
!GitHub issues
!GitHub pull requests
!GitHub stars

---
⚠️ **AVISO IMPORTANTE:**
Este script modifica configurações críticas de segurança do SSH. Sempre:

1. Execute em ambiente de teste primeiro
2. Mantenha acesso alternativo ao servidor
3. Execute --dry-run antes de aplicar correções
4. Faça backup manual do sshd_config
5. Teste em horário de baixo tráfego

Use por sua conta e risco. O autor não se responsabiliza por perda de acesso ou dados.

---
<div align="center">
Se este projeto foi útil, considere dar uma ⭐!
</div>
`
