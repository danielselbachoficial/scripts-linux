# Instalação segura do Netbox via Script Python

Um script de automação robusto para instalação e **hardening** do NetBox. Este instalador foi projetado para ambientes que exigem alta segurança e mínima intervenção manual.

## 🎯 Principais Funcionalidades

O script oferece um **Menu Interativo** com as seguintes opções:
- **Instalação Completa Automatizada:** Zero intervenção manual, ideal para deploys rápidos.
- **Instalação Passo a Passo:** Com confirmações em cada etapa para maior controle.
- **Security Hardening:** Aplicação imediata de protocolos de segurança rigorosos.
- **Backup/Restore:** Gestão simplificada de backups do banco de dados e arquivos.
- **Verificação de Sistema:** Monitoramento em tempo real do status de serviços e conectividade.

## 🔒 Segurança Implementada

A segurança é o pilar central deste instalador, dividida em três camadas:

### 1. Hardening de Rede

- **Firewall:** UFW pré-configurado para permitir apenas tráfego essencial (portas 80, 443 e SSH).
- **Fail2ban:** Proteção ativa contra ataques de força bruta.
- **SSL/TLS:** Criptografia ponta a ponta com certificados (autoassinados por padrão).

### 2. Hardening de Aplicação

- **PostgreSQL:** Configurado para aceitar apenas conexões locais.
- **Gerenciamento de Segredos:** * Senhas de 16 caracteres geradas automaticamente.
  - **SECRET_KEY** do Django com 100 caracteres hexadecimais.
- **Nginx Seguro:** Inclusão de headers de proteção (**X-Frame-Options**, **X-Content-Type-Options**) e protocolos TLS 1.2/1.3.

### 3. Hardening de Sistema

- **Permissões:** Aplicação do princípio do privilégio mínimo (Pastas em 755).
- **Auditoria:** Implementação do Auditd para logs detalhados de atividades.
- **Otimização:** Desativação de serviços desnecessários para reduzir a superfície de ataque.

## 📋 Pré-requisitos

Antes de iniciar, certifique-se de que seu sistema está atualizado e com as dependências Python instaladas:

```bash
sudo apt update && sudo apt install -y python3-pip
pip3 install colorama tqdm psycopg2-binary redis requests cryptography
```

## 🚀 Como Usar

Para executar o instalador, siga os comandos abaixo:
```bash
# 1. Baixar o script
wget https://seu-servidor/netbox_installer.py

# 2. Dar permissão de execução
chmod +x netbox_installer.py

# 3. Executar como root
sudo python3 netbox_installer.py
```

## 📊 Outputs Gerados

Ao final do processo, o script organiza os dados nos seguintes locais:

| Tipo de Dado                      | Caminho no Sistema              |
|-----------------------------------|---------------------------------|
| Log de Instalação                 | /var/log/netbox_installer.log   |
| Credenciais (JSON)                | /root/netbox_install_info.txt   |
| Diretório de Backups              | /var/backups/netbox/            |

> 🔐 **Importante:** O arquivo **netbox_install_info.txt** contém todas as senhas do PostgreSQL, Admin do Netbox e a Secret Key. Mantenha-o em local seguro!

## 🛡️ Vetores de Ataque Mitigados

| Ameaça                         | Técnica de Mitigação                           |
|--------------------------------|------------------------------------------------|
| SQL Injection                  | PostgreSQL com prepared statements             |
| Brute Force                    | Fail2ban ativo e monitorando logs              |
| Man-in-the-Middle              | SSL/TLS obrigatório em todas as conexões       |
| XSS / Clickjacking             | Headers de segurança injetados via Nginx       |
| Privilege Escalation           | Permissões de arquivos e diretórios restritas  |
| Information Disclosure         | DEBUG=False e erros verbosos desabilitados     |

## ⚠️ Observações Importantes
- **Acesso Root:** O script exige privilégios de superusuário para configurar serviços de sistema.
- **Certificado SSL:** Por padrão, o script gera um certificado autoassinado. Para ambientes de produção expostos à internet, recomenda-se a substituição pelo Let's Encrypt.
- **URL de Acesso:** Após a instalação, acesse via https://[IP_DO_SERVIDOR].
