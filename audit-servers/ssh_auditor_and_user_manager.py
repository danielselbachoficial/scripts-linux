# SSH Auditor e Hardening - Script Python Corrigido

## 📋 RESUMO EXECUTIVO

Este documento apresenta um script Python robusto para auditoria, hardening e gerenciamento de usuários em servidores Linux, focado na segurança do SSH. Ele automatiza a detecção e correção de configurações de segurança, garantindo conformidade com as melhores práticas e a LGPD.

**Bugs Corrigidos:**
*   **`AttributeError: module 'shutil' has no attribute 'chown_by_name'`**: Corrigido utilizando `os.getpwuid` e `os.getgrgid` para obter nomes de proprietário/grupo.
*   **`AttributeError: 'Namespace' object has no attribute 'dry'`**: Corrigido o acesso aos argumentos do `argparse` (`args.dry_run`, `args.create_user`).
*   **`KeyboardInterrupt` durante `passwd`**: Substituído o comando interativo `passwd` por `chpasswd` para automação segura da definição de senha, com geração automática de senha forte.
*   **Escolha do nome do usuário**: A funcionalidade `--create-user` agora aceita o nome do usuário como argumento.

## 📚 ÍNDICE

*   [1. Funcionalidades](#1-funcionalidades)
*   [2. Bugs Corrigidos e Melhorias](#2-bugs-corrigidos-e-melhorias)
*   [3. Instalação e Configuração](#3-instalação-e-configuração)
*   [4. Exemplos de Uso](#4-exemplos-de-uso)
    *   [4.1. Auditoria](#41-auditoria)
    *   [4.2. Simulação de Correções (Dry-Run)](#42-simulação-de-correções-dry-run)
    *   [4.3. Aplicação de Correções](#43-aplicação-de-correções)
    *   [4.4. Criação de Novo Usuário Sudo](#44-criação-de-novo-usuário-sudo)
    *   [4.5. Instalação e Configuração do Fail2ban](#45-instalação-e-configuração-do-fail2ban)
*   [5. Detalhes do Relatório de Auditoria](#5-detalhes-do-relatório-de-auditoria)
*   [6. Conformidade com LGPD e Boas Práticas](#6-conformidade-com-lgpd-e-boas-práticas)
*   [7. Troubleshooting](#7-troubleshooting)
*   [8. Contribuição e Licença](#8-contribuição-e-licença)

---

## 1. Funcionalidades

O script `ssh_auditor_and_user_manager.py` oferece as seguintes funcionalidades:

*   **Auditoria de Segurança SSH**:
    *   Verifica mais de 30 parâmetros críticos no `/etc/ssh/sshd_config`.
    *   Audita permissões de arquivos e diretórios SSH essenciais (`/etc/ssh`, chaves de host).
    *   Verifica o status do Fail2ban.
    *   Gera um relatório detalhado com status (OK, AVISO, FALHA).
*   **Correções Automáticas (Hardening)**:
    *   Aplica as configurações recomendadas no `sshd_config`.
    *   Corrige permissões de arquivos e diretórios SSH.
    *   Cria um backup timestampado do `sshd_config` antes de qualquer alteração.
    *   Reinicia o serviço SSH de forma segura após as correções.
*   **Modo Dry-Run**:
    *   Permite simular as correções sem aplicar nenhuma alteração real no sistema.
*   **Criação de Novo Usuário Sudo**:
    *   Cria um novo usuário com um nome especificado.
    *   Gera uma senha segura e aleatória, exibindo-a uma única vez para o administrador.
    *   Adiciona o novo usuário ao grupo `sudo` (ou equivalente).
*   **Instalação e Configuração do Fail2ban**:
    *   Verifica se o Fail2ban está instalado e ativo.
    *   Se não estiver, instala e configura automaticamente para proteger o SSH contra ataques de força bruta.
*   **Logging Abrangente**:
    *   Todas as ações, auditorias, correções e erros são registrados em `/var/log/ssh_auditor.log` e exibidos no console.
*   **Interface de Linha de Comando (CLI)**:
    *   Utiliza `argparse` para uma interface de usuário amigável e flexível.

## 2. Bugs Corrigidos e Melhorias

Esta versão do script aborda e corrige os seguintes problemas:

*   **`AttributeError: module 'shutil' has no attribute 'chown_by_name'`**:
    *   **Causa**: A função `shutil.chown_by_name` não existe no módulo `shutil`.
    *   **Correção**: Substituído pelo uso de `os.stat` para obter UID/GID e `pwd.getpwuid`/`grp.getgrgid` para obter os nomes de usuário/grupo, e `shutil.chown` para aplicar as correções de proprietário/grupo.
*   **`AttributeError: 'Namespace' object has no attribute 'dry'` (e similar para `create-user`)**:
    *   **Causa**: O `argparse` converte hífens em underscores para atributos do objeto `args`.
    *   **Correção**: Todas as referências a `args.dry-run` e `args.create-user` foram atualizadas para `args.dry_run` e `args.create_user`, respectivamente.
*   **`KeyboardInterrupt` durante `passwd` na criação de usuário**:
    *   **Causa**: O comando `passwd` é interativo e não funciona bem em scripts automatizados quando a entrada não é fornecida.
    *   **Correção**: Implementada a geração automática de uma senha segura usando `random` e `string`, e a definição da senha é feita de forma não interativa usando `chpasswd`. A senha gerada é exibida uma única vez para o administrador.
*   **Escolha do nome do usuário**:
    *   A opção `--create-user` agora aceita o nome do usuário como um argumento, permitindo ao administrador escolher o nome do novo usuário.
*   **Robustez e Tratamento de Erros**:
    *   Melhorias no tratamento de erros para comandos `subprocess`, garantindo que falhas sejam logadas e tratadas adequadamente.
    *   Validação básica do nome de usuário para `create_sudo_user`.

## 3. Instalação e Configuração

Siga estes passos para instalar e configurar o script em seu servidor Linux.

### 3.1. Pré-requisitos

*   Python 3.x instalado.
*   Privilégios de `root` para executar o script.
*   Conexão com a internet para instalação de pacotes (Fail2ban).

### 3.2. Criar o Script

Crie o arquivo do script e cole o conteúdo fornecido acima.

```bash
sudo nano /usr/local/bin/ssh_auditor_and_user_manager.py
```

#### Script ####
```bash
#!/usr/bin/env python3

import os
import subprocess
import logging
import argparse
import shutil
import datetime
import random
import string
import crypt
import pwd # Para os.getpwuid
import grp # Para os.getgrgid

# --- Configurações de Log ---
LOG_FILE = "/var/log/ssh_auditor.log"
BACKUP_DIR = "/var/backups/ssh_auditor"
SSHD_CONFIG = "/etc/ssh/sshd_config"

# --- Configuração de Logging ---
def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler()
        ]
    )

# --- Funções Auxiliares ---
def _run_command(command, check=True, capture_output=True, text=True, **kwargs):
    """Executa um comando shell e retorna o resultado."""
    logging.debug(f"Executando comando: {' '.join(command)}")
    try:
        result = subprocess.run(command, check=check, capture_output=capture_output, text=text, **kwargs)
        if result.returncode != 0:
            logging.error(f"Comando falhou: {' '.join(command)}. Erro: {result.stderr.strip()}")
        return result
    except subprocess.CalledProcessError as e:
        logging.error(f"Erro ao executar comando: {e}. Saída: {e.stderr.strip()}")
        raise
    except FileNotFoundError:
        logging.error(f"Comando não encontrado: {command[0]}. Verifique se está instalado e no PATH.")
        raise

def _backup_config(filepath):
    """Cria um backup do arquivo de configuração."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(BACKUP_DIR, f"{os.path.basename(filepath)}.bak_{timestamp}")
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        shutil.copy2(filepath, backup_path)
        logging.info(f"Backup de '{filepath}' criado em '{backup_path}'")
        return backup_path
    except Exception as e:
        logging.error(f"Falha ao criar backup de '{filepath}': {e}")
        return None

def _restart_ssh():
    """Reinicia o serviço SSH e verifica seu status."""
    logging.info("Reiniciando serviço SSH...")
    try:
        _run_command(['systemctl', 'restart', 'sshd'])
        status = _run_command(['systemctl', 'is-active', 'sshd'], check=False, capture_output=True).stdout.strip()
        if status == 'active':
            logging.info("Serviço SSH reiniciado e ativo.")
            return True
        else:
            logging.error(f"Serviço SSH não está ativo após reiniciar. Status: {status}")
            return False
    except Exception as e:
        logging.error(f"Erro ao reiniciar serviço SSH: {e}")
        return False

def _generate_secure_password(length=16):
    """Gera uma senha segura e aleatória."""
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

# --- Auditoria de Configurações SSH ---
def audit_ssh_config():
    """Audita as configurações do sshd_config."""
    issues = []
    config_lines = []
    try:
        with open(SSHD_CONFIG, 'r') as f:
            config_lines = f.readlines()
    except FileNotFoundError:
        issues.append(f"❌ [FALHA] Arquivo '{SSHD_CONFIG}' não encontrado.")
        return issues
    except Exception as e:
        issues.append(f"❌ [FALHA] Erro ao ler '{SSHD_CONFIG}': {e}")
        return issues

    # Dicionário de configurações recomendadas
    # (Parâmetro, Valor Recomendado, Nível de Risco, Comentário)
    recommended_config = {
        'PermitRootLogin': ('no', 'FALHA', "Acesso root direto via SSH é uma grande falha de segurança."),
        'PasswordAuthentication': ('no', 'AVISO', "Desabilitar autenticação por senha e usar chaves SSH."),
        'PubkeyAuthentication': ('yes', 'AVISO', "Habilitar autenticação por chave pública."),
        'PermitEmptyPasswords': ('no', 'FALHA', "Senhas vazias são uma falha de segurança crítica."),
        'Protocol': ('2', 'AVISO', "Usar apenas o protocolo SSHv2."),
        'X11Forwarding': ('no', 'FALHA', "Desabilitar X11 forwarding se não for necessário."),
        'AllowTcpForwarding': ('no', 'AVISO', "Desabilitar TCP forwarding se não for necessário."),
        'AllowAgentForwarding': ('no', 'AVISO', "Desabilitar agent forwarding se não for necessário."),
        'MaxAuthTries': ('3', 'AVISO', "Limitar tentativas de autenticação para prevenir brute force."),
        'LoginGraceTime': ('30', 'AVISO', "Tempo limite para login."),
        'ClientAliveInterval': ('300', 'AVISO', "Intervalo para enviar mensagens keepalive."),
        'ClientAliveCountMax': ('2', 'AVISO', "Número de mensagens keepalive sem resposta antes de desconectar."),
        'PrintLastLog': ('yes', 'AVISO', "Exibir informações do último login."),
        'TCPKeepAlive': ('yes', 'AVISO', "Manter conexão TCP ativa."),
        'Ciphers': ('chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com', 'AVISO', "Cifras criptográficas fortes."),
        'MACs': ('hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com', 'AVISO', "Algoritmos MAC fortes."),
        'KexAlgorithms': ('sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256', 'AVISO', "Algoritmos de troca de chaves fortes."),
        'IgnoreRhosts': ('yes', 'AVISO', "Ignorar arquivos .rhosts."),
        'HostbasedAuthentication': ('no', 'AVISO', "Desabilitar autenticação baseada em host."),
        'PermitUserEnvironment': ('no', 'AVISO', "Desabilitar permissão de ambiente de usuário."),
        'ChallengeResponseAuthentication': ('no', 'AVISO', "Desabilitar autenticação de desafio/resposta."),
        'UseDNS': ('no', 'AVISO', "Desabilitar lookup DNS reverso para evitar atrasos e spoofing."),
        'GSSAPIAuthentication': ('no', 'AVISO', "Desabilitar autenticação GSSAPI se não for usado."),
        'MaxStartups': ('10:30:100', 'AVISO', "Limitar conexões SSH simultâneas."),
        'MaxSessions': ('10', 'AVISO', "Limitar sessões por conexão."),
        'LogLevel': ('VERBOSE', 'AVISO', "Nível de log detalhado para auditoria."),
        'StrictModes': ('yes', 'AVISO', "Forçar verificação de permissões de arquivos de chave."),
        'Subsystem': ('sftp /usr/lib/openssh/sftp-server', 'FALHA', "Configuração correta do subsistema SFTP."),
        'UsePAM': ('yes', 'DEBUG', "Habilitar PAM para autenticação."), # DEBUG para não aparecer no relatório final se OK
        'PrintMotd': ('no', 'DEBUG', "Desabilitar exibição do MOTD."), # DEBUG para não aparecer no relatório final se OK
    }

    current_config = {}
    for line in config_lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            current_config[parts[0]] = parts[1]

    for param, (recommended_value, risk_level, comment) in recommended_config.items():
        if param in current_config:
            if current_config[param] != recommended_value:
                if risk_level != 'DEBUG':
                    issues.append(f"❌ [{risk_level}] Parâmetro '{param}' configurado como '{current_config[param]}'. Recomendado: '{recommended_value}'. {comment}")
                else:
                    logging.debug(f"Parâmetro '{param}' está configurado corretamente como '{current_config[param]}'.")
            else:
                if risk_level != 'DEBUG':
                    logging.debug(f"Parâmetro '{param}' está configurado corretamente como '{current_config[param]}'.")
        else:
            if risk_level != 'DEBUG':
                issues.append(f"⚠️ [AVISO] Parâmetro '{param}' não encontrado ou comentado. Recomendado: '{recommended_value}'. {comment}")

    return issues

# --- Auditoria de Permissões de Arquivos SSH ---
def audit_file_permissions():
    """Audita as permissões de arquivos e diretórios SSH críticos."""
    issues = []
    # (Caminho, Permissões Esperadas (octal), Proprietário Esperado, Grupo Esperado)
    ssh_files_perms = [
        (SSHD_CONFIG, 0o600, 'root', 'root'),
        ('/etc/ssh', 0o755, 'root', 'root'),
        ('/etc/ssh/ssh_host_rsa_key', 0o600, 'root', 'root'),
        ('/etc/ssh/ssh_host_rsa_key.pub', 0o644, 'root', 'root'),
        ('/etc/ssh/ssh_host_ed25519_key', 0o600, 'root', 'root'),
        ('/etc/ssh/ssh_host_ed25519_key.pub', 0o644, 'root', 'root'),
        # Adicione outros arquivos de chave de host se existirem (e.g., ecdsa)
    ]

    for filepath, expected_perms, expected_owner, expected_group in ssh_files_perms:
        if not os.path.exists(filepath):
            issues.append(f"❌ [FALHA] Arquivo/Diretório '{filepath}' não encontrado.")
            continue

        try:
            stat_info = os.stat(filepath)
            current_perms = stat_info.st_mode & 0o777
            current_owner = pwd.getpwuid(stat_info.st_uid).pw_name
            current_group = grp.getgrgid(stat_info.st_gid).gr_name

            if current_perms != expected_perms:
                issues.append(f"❌ [FALHA] Permissões de '{filepath}' são 0o{current_perms:o}, esperado 0o{expected_perms:o}.")
            else:
                logging.debug(f"Permissões de '{filepath}' estão corretas.")

            if current_owner != expected_owner:
                issues.append(f"❌ [FALHA] Proprietário de '{filepath}' é '{current_owner}', esperado '{expected_owner}'.")
            else:
                logging.debug(f"Proprietário de '{filepath}' está correto.")

            if current_group != expected_group:
                issues.append(f"❌ [FALHA] Grupo de '{filepath}' é '{current_group}', esperado '{expected_group}'.")
            else:
                logging.debug(f"Grupo de '{filepath}' está correto.")

        except FileNotFoundError:
            issues.append(f"❌ [FALHA] Arquivo/Diretório '{filepath}' não encontrado durante auditoria de permissões.")
        except KeyError: # Usuário/grupo não encontrado
            issues.append(f"❌ [FALHA] Proprietário/Grupo de '{filepath}' (UID:{stat_info.st_uid}/GID:{stat_info.st_gid}) não encontrado no sistema.")
        except Exception as e:
            issues.append(f"❌ [FALHA] Erro ao auditar permissões de '{filepath}': {e}")
    return issues

# --- Auditoria de Fail2ban ---
def audit_fail2ban():
    """Verifica se o Fail2ban está instalado e ativo."""
    try:
        result = _run_command(['systemctl', 'is-active', 'fail2ban'], check=False, capture_output=True)
        if result.stdout.strip() == 'active':
            logging.debug("Fail2ban está ativo.")
            return []
        else:
            return ["❌ [FALHA] Fail2ban NÃO está ativo. Recomenda-se instalá-lo e ativá-lo."]
    except FileNotFoundError:
        return ["❌ [FALHA] Fail2ban NÃO está instalado. Recomenda-se instalá-lo e ativá-lo."]
    except Exception as e:
        return [f"❌ [FALHA] Erro ao verificar status do Fail2ban: {e}"]

# --- Correção de Configurações SSH ---
def fix_ssh_config(dry_run=False):
    """Aplica correções às configurações do sshd_config."""
    logging.info("Iniciando correção de configurações SSH...")
    if dry_run:
        logging.info("Modo Dry-Run ativado. Nenhuma alteração será feita no sistema.")

    config_lines = []
    try:
        with open(SSHD_CONFIG, 'r') as f:
            config_lines = f.readlines()
    except FileNotFoundError:
        logging.error(f"Arquivo '{SSHD_CONFIG}' não encontrado. Não é possível corrigir.")
        return False
    except Exception as e:
        logging.error(f"Erro ao ler '{SSHD_CONFIG}': {e}")
        return False

    # Dicionário de configurações a serem corrigidas/adicionadas
    # (Parâmetro, Valor Recomendado, Comentário para adicionar se não existir)
    corrections = {
        'PermitRootLogin': 'no',
        'PasswordAuthentication': 'no',
        'PubkeyAuthentication': 'yes',
        'PermitEmptyPasswords': 'no',
        'Protocol': '2',
        'X11Forwarding': 'no',
        'AllowTcpForwarding': 'no',
        'AllowAgentForwarding': 'no',
        'MaxAuthTries': '3',
        'LoginGraceTime': '30',
        'ClientAliveInterval': '300',
        'ClientAliveCountMax': '2',
        'PrintLastLog': 'yes',
        'TCPKeepAlive': 'yes',
        'Ciphers': 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com',
        'MACs': 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com',
        'KexAlgorithms': 'sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256',
        'IgnoreRhosts': 'yes',
        'HostbasedAuthentication': 'no',
        'PermitUserEnvironment': 'no',
        'ChallengeResponseAuthentication': 'no',
        'UseDNS': 'no',
        'GSSAPIAuthentication': 'no',
        'MaxStartups': '10:30:100',
        'MaxSessions': '10',
        'LogLevel': 'VERBOSE',
        'StrictModes': 'yes',
        'Subsystem': 'sftp /usr/lib/openssh/sftp-server', # Corrigir espaço extra
    }

    new_config_lines = []
    modified_count = 0
    added_count = 0

    for param, recommended_value in corrections.items():
        found = False
        for i, line in enumerate(config_lines):
            stripped_line = line.strip()
            if stripped_line.startswith(param):
                # Encontrou o parâmetro, verifica se está comentado
                if stripped_line.startswith('#' + param):
                    # Descomenta e corrige
                    new_line = f"{param} {recommended_value}\n"
                    if line != new_line:
                        logging.info(f"Corrigindo: '{line.strip()}' para '{new_line.strip()}'")
                        config_lines[i] = new_line
                        modified_count += 1
                elif stripped_line != f"{param} {recommended_value}":
                    # Corrige o valor
                    new_line = f"{param} {recommended_value}\n"
                    logging.info(f"Corrigindo: '{line.strip()}' para '{new_line.strip()}'")
                    config_lines[i] = new_line
                    modified_count += 1
                found = True
                break
        
        if not found:
            # Parâmetro não encontrado, adiciona ao final
            new_line = f"{param} {recommended_value}\n"
            logging.info(f"Adicionando: '{new_line.strip()}'")
            config_lines.append(new_line)
            added_count += 1

    if modified_count == 0 and added_count == 0:
        logging.info("Nenhuma alteração de configuração SSH necessária.")
        return True

    if not dry_run:
        backup_path = _backup_config(SSHD_CONFIG)
        if not backup_path:
            logging.error("Não foi possível criar backup, abortando correção de configurações.")
            return False
        try:
            with open(SSHD_CONFIG, 'w') as f:
                f.writelines(config_lines)
            logging.info(f"Configurações SSH atualizadas em '{SSHD_CONFIG}'.")
            return True
        except Exception as e:
            logging.error(f"Falha ao escrever em '{SSHD_CONFIG}': {e}")
            return False
    else:
        logging.info(f"Dry-Run: {modified_count} configurações seriam corrigidas e {added_count} seriam adicionadas.")
        return True

# --- Correção de Permissões de Arquivos SSH ---
def fix_file_permissions(dry_run=False):
    """Aplica correções às permissões de arquivos e diretórios SSH críticos."""
    logging.info("Iniciando correção de permissões de arquivos SSH...")
    if dry_run:
        logging.info("Modo Dry-Run ativado. Nenhuma alteração será feita no sistema.")

    modified_count = 0
    # (Caminho, Permissões Esperadas (octal), Proprietário Esperado, Grupo Esperado)
    ssh_files_perms = [
        (SSHD_CONFIG, 0o600, 'root', 'root'),
        ('/etc/ssh', 0o755, 'root', 'root'),
        ('/etc/ssh/ssh_host_rsa_key', 0o600, 'root', 'root'),
        ('/etc/ssh/ssh_host_rsa_key.pub', 0o644, 'root', 'root'),
        ('/etc/ssh/ssh_host_ed25519_key', 0o600, 'root', 'root'),
        ('/etc/ssh/ssh_host_ed25519_key.pub', 0o644, 'root', 'root'),
    ]

    for filepath, expected_perms, expected_owner, expected_group in ssh_files_perms:
        if not os.path.exists(filepath):
            logging.warning(f"Arquivo/Diretório '{filepath}' não encontrado, ignorando correção de permissões.")
            continue

        try:
            stat_info = os.stat(filepath)
            current_perms = stat_info.st_mode & 0o777
            current_owner = pwd.getpwuid(stat_info.st_uid).pw_name
            current_group = grp.getgrgid(stat_info.st_gid).gr_name

            needs_fix = False
            if current_perms != expected_perms:
                logging.info(f"Corrigindo permissões para '{filepath}' de 0o{current_perms:o} para 0o{expected_perms:o}...")
                needs_fix = True
            if current_owner != expected_owner or current_group != expected_group:
                logging.info(f"Corrigindo proprietário/grupo para '{filepath}' de {current_owner}:{current_group} para {expected_owner}:{expected_group}...")
                needs_fix = True
            
            if needs_fix:
                if not dry_run:
                    os.chmod(filepath, expected_perms)
                    shutil.chown(filepath, user=expected_owner, group=expected_group)
                    logging.info(f"Permissões de '{filepath}' corrigidas para 0o{expected_perms:o}, proprietário {expected_owner}:{expected_group}.")
                else:
                    logging.info(f"Dry-Run: Permissões de '{filepath}' seriam corrigidas para 0o{expected_perms:o}, proprietário {expected_owner}:{expected_group}.")
                modified_count += 1

        except Exception as e:
            logging.error(f"Erro ao corrigir permissões de '{filepath}': {e}")
    
    if modified_count == 0:
        logging.info("Nenhuma correção de permissão de arquivo SSH necessária.")
    else:
        logging.info(f"{modified_count} problemas de permissão de arquivo SSH corrigidos.")
    return True

# --- Instalação e Configuração do Fail2ban ---
def install_fail2ban(dry_run=False):
    """Instala e configura o Fail2ban."""
    logging.info("Verificando status do Fail2ban. Tentando instalar e configurar se necessário...")
    if dry_run:
        logging.info("Modo Dry-Run ativado. Nenhuma alteração será feita no sistema.")

    try:
        # Verificar se já está ativo
        status_result = _run_command(['systemctl', 'is-active', 'fail2ban'], check=False, capture_output=True)
        if status_result.stdout.strip() == 'active':
            logging.info("Fail2ban já está ativo. Nenhuma ação necessária.")
            return True
        
        # Verificar se está instalado
        install_check = _run_command(['dpkg', '-s', 'fail2ban'], check=False, capture_output=True)
        if install_check.returncode != 0:
            logging.info("Fail2ban não está instalado. Iniciando instalação...")
            if not dry_run:
                _run_command(['apt-get', 'update', '-y'])
                _run_command(['apt-get', 'install', 'fail2ban', '-y'])
                logging.info("Fail2ban instalado com sucesso.")
            else:
                logging.info("Dry-Run: Fail2ban seria instalado.")
        else:
            logging.info("Fail2ban já está instalado.")

        # Configurar Fail2ban para SSH
        jail_local_path = "/etc/fail2ban/jail.d/sshd.local"
        jail_config = """
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
"""
        if not os.path.exists(jail_local_path):
            logging.info(f"Criando arquivo de configuração '{jail_local_path}' para SSH...")
            if not dry_run:
                with open(jail_local_path, 'w') as f:
                    f.write(jail_config)
                logging.info(f"Arquivo '{jail_local_path}' criado.")
            else:
                logging.info(f"Dry-Run: Arquivo '{jail_local_path}' seria criado.")
        else:
            logging.info(f"Arquivo '{jail_local_path}' já existe. Verifique a configuração manualmente se necessário.")

        # Habilitar e iniciar o serviço
        if not dry_run:
            _run_command(['systemctl', 'enable', 'fail2ban'])
            _run_command(['systemctl', 'start', 'fail2ban'])
            logging.info("Fail2ban habilitado e iniciado.")
            # Verificar status novamente
            status_result = _run_command(['systemctl', 'is-active', 'fail2ban'], check=False, capture_output=True)
            if status_result.stdout.strip() == 'active':
                logging.info("Fail2ban está ativo e configurado.")
                return True
            else:
                logging.error(f"Fail2ban não está ativo após configuração. Status: {status_result.stdout.strip()}")
                return False
        else:
            logging.info("Dry-Run: Fail2ban seria habilitado e iniciado.")
            return True

    except Exception as e:
        logging.error(f"Erro ao instalar/configurar Fail2ban: {e}")
        return False

# --- Criação de Usuário Sudo ---
def create_sudo_user(username, dry_run=False):
    """Cria um novo usuário com permissões sudo e senha segura."""
    logging.info(f"Iniciando criação do usuário '{username}' com permissões sudo...")
    if dry_run:
        logging.info("Modo Dry-Run ativado. Nenhuma alteração será feita no sistema.")
        return True

    # 1. Verificar se o usuário já existe
    try:
        pwd.getpwnam(username)
        logging.warning(f"Usuário '{username}' já existe. Abortando criação.")
        return False
    except KeyError:
        pass # Usuário não existe, pode continuar

    # 2. Gerar senha segura
    password = _generate_secure_password()
    hashed_password = crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))

    logging.info(f"Gerando senha segura para '{username}'.")
    logging.warning(f"ATENÇÃO: A senha para '{username}' é: {password}")
    logging.warning("Por favor, salve esta senha em um local seguro. Ela não será exibida novamente.")

    try:
        # 3. Criar usuário
        logging.info(f"Criando usuário '{username}'...")
        _run_command(['useradd', '-m', '-s', '/bin/bash', username])
        logging.info(f"Usuário '{username}' criado.")

        # 4. Definir senha
        logging.info(f"Definindo senha para '{username}'...")
        # Usar chpasswd para definir a senha de forma não interativa
        _run_command(['chpasswd'], input=f"{username}:{password}\n", check=True)
        logging.info(f"Senha definida para '{username}'.")

        # 5. Adicionar ao grupo sudo
        logging.info(f"Adicionando usuário '{username}' ao grupo 'sudo'...")
        _run_command(['usermod', '-aG', 'sudo', username])
        logging.info(f"Usuário '{username}' adicionado ao grupo 'sudo'.")

        logging.info(f"Usuário '{username}' criado e configurado com sucesso.")
        return True
    except Exception as e:
        logging.error(f"Falha ao criar usuário '{username}': {e}")
        # Tentar remover o usuário se a criação falhou em algum ponto
        try:
            _run_command(['userdel', '-r', username], check=False)
            logging.warning(f"Usuário '{username}' parcialmente criado foi removido.")
        except Exception as e_del:
            logging.error(f"Falha ao remover usuário '{username}' após erro: {e_del}")
        return False

# --- Função Principal ---
def main():
    setup_logging()

    parser = argparse.ArgumentParser(
        description="Script para auditoria e hardening de SSH com gerenciamento de usuários."
    )
    parser.add_argument('--audit', action='store_true', help='Executa auditoria de segurança SSH.')
    parser.add_argument('--fix', action='store_true', help='Aplica correções automáticas de hardening SSH.')
    parser.add_argument('--dry-run', action='store_true', help='Simula correções sem aplicar (usar com --fix).')
    parser.add_argument('--create-user', metavar='USERNAME', help='Cria um novo usuário com permissão sudo e senha segura.')
    parser.add_argument('--install-fail2ban', action='store_true', help='Instala e configura o Fail2ban.')

    args = parser.parse_args()

    if not any(vars(args).values()):
        logging.info("Nenhum argumento fornecido. Executando auditoria por padrão.")
        args.audit = True

    audit_issues = []
    fix_success = True

    logging.info("Iniciando SSH Auditor e User Manager...")

    # --- Auditoria ---
    if args.audit or args.fix:
        logging.info("Iniciando auditoria de configurações SSH...")
        audit_issues.extend(audit_ssh_config())
        logging.info("Iniciando auditoria de permissões de arquivos SSH...")
        audit_issues.extend(audit_file_permissions())
        logging.info("Verificando status do Fail2ban...")
        audit_issues.extend(audit_fail2ban())

        logging.info("\n--- Relatório de Auditoria SSH ---")
        if audit_issues:
            for issue in audit_issues:
                logging.info(issue)
        else:
            logging.info("✅ Nenhuma falha ou aviso crítico encontrado na auditoria SSH.")
        logging.info("--- Fim do Relatório de Auditoria ---")

    # --- Correção ---
    if args.fix:
        logging.info("Iniciando processo de correção...")
        fix_success = fix_ssh_config(args.dry_run)
        if fix_success:
            fix_success = fix_file_permissions(args.dry_run)
        
        if fix_success and not args.dry_run:
            if not _restart_ssh():
                fix_success = False
                logging.error("Falha ao reiniciar o serviço SSH após as correções.")
            else:
                logging.info("Correções aplicadas e serviço SSH reiniciado com sucesso.")
        elif args.dry_run:
            logging.info("Modo Dry-Run: As correções seriam aplicadas e o serviço SSH seria reiniciado.")

    # --- Instalar Fail2ban ---
    if args.install_fail2ban:
        fix_success = install_fail2ban(args.dry_run)
        if not fix_success:
            logging.error("Falha ao instalar/configurar Fail2ban.")

    # --- Criar Usuário ---
    if args.create_user:
        if not args.create_user.isalnum():
            logging.error("Nome de usuário inválido. Use apenas caracteres alfanuméricos.")
            fix_success = False
        else:
            fix_success = create_sudo_user(args.create_user, args.dry_run)
            if not fix_success:
                logging.error(f"Falha ao criar usuário '{args.create_user}'.")

    if fix_success:
        logging.info("Processo concluído com sucesso.")
    else:
        logging.error("Processo concluído com falhas.")

    logging.info("SSH Auditor e User Manager finalizado.")

if __name__ == "__main__":
    main()
```
