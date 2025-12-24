#!/usr/bin/env python3
"""
SSH Auditor and Hardening Tool - Enterprise Edition v1.0.0
Conformidade: CIS Benchmark 5.2.x, NIST SP 800-123, LGPD

ATENÇÃO: Este script modifica configurações críticas de SSH.
         Execute SEMPRE em ambiente de teste antes de produção.
         Mantenha acesso alternativo (console físico/IPMI/KVM) disponível.

Changelog v1.0.0:
- Menu interativo adicionado
- Correção de DeprecationWarning (datetime.utcnow)
- Parser robusto para continuação de linha
- Validação completa de sintaxe
- Logging estruturado JSON
"""

import os
import sys
import subprocess
import logging
import argparse
import shutil
import datetime
import random
import string
import json
import time
import re
import pwd
import grp
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# --- Configurações Globais ---
VERSION = "2.0.0-enterprise"
LOG_FILE = "/var/log/ssh_auditor.log"
BACKUP_DIR = "/var/backups/ssh_auditor"
SSHD_CONFIG = "/etc/ssh/sshd_config"
SSH_DIR = "/etc/ssh"

# Conformidade CIS Benchmark 5.2.x
CIS_COMPLIANT_CONFIG = {
    'PermitRootLogin': ('no', 'CRITICAL', "CIS 5.2.10: Root login direto é vetor de ataque primário"),
    'PasswordAuthentication': ('no', 'HIGH', "CIS 5.2.8: Autenticação por senha é vulnerável a brute-force"),
    'PubkeyAuthentication': ('yes', 'HIGH', "CIS 5.2.7: Chaves públicas são o método recomendado"),
    'PermitEmptyPasswords': ('no', 'CRITICAL', "CIS 5.2.9: Senhas vazias são falha crítica"),
    'X11Forwarding': ('no', 'MEDIUM', "CIS 5.2.6: X11 forwarding aumenta superfície de ataque"),
    'MaxAuthTries': ('3', 'MEDIUM', "CIS 5.2.5: Limitar tentativas de autenticação"),
    'IgnoreRhosts': ('yes', 'MEDIUM', "CIS 5.2.11: Ignorar arquivos .rhosts legados"),
    'HostbasedAuthentication': ('no', 'MEDIUM', "CIS 5.2.12: Desabilitar autenticação baseada em host"),
    'PermitUserEnvironment': ('no', 'MEDIUM', "CIS 5.2.13: Prevenir manipulação de ambiente"),
    'LoginGraceTime': ('60', 'LOW', "CIS 5.2.16: Timeout para login (60s padrão CIS)"),
    'ClientAliveInterval': ('300', 'LOW', "CIS 5.2.17: Keepalive a cada 5 minutos"),
    'ClientAliveCountMax': ('0', 'LOW', "CIS 5.2.18: Desconectar após timeout (0 = imediato)"),
    'LogLevel': ('VERBOSE', 'MEDIUM', "CIS 5.2.4: Logging detalhado para auditoria"),
    'MaxStartups': ('10:30:60', 'MEDIUM', "CIS 5.2.21: Limitar conexões simultâneas (DoS protection)"),
    'MaxSessions': ('10', 'LOW', "CIS 5.2.22: Limitar sessões por conexão"),
    'UsePAM': ('yes', 'LOW', "CIS 5.2.19: Habilitar PAM para autenticação centralizada"),
    'AllowTcpForwarding': ('no', 'MEDIUM', "Desabilitar TCP forwarding se não necessário"),
    'AllowAgentForwarding': ('no', 'MEDIUM', "Desabilitar agent forwarding se não necessário"),
    'PermitTunnel': ('no', 'MEDIUM', "Desabilitar tunneling se não necessário"),
    'Banner': ('/etc/issue.net', 'LOW', "CIS 5.2.15: Exibir banner legal"),
    'Ciphers': ('chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr', 'HIGH', "Cifras AEAD + CTR mode (FIPS 140-2 compatível)"),
    'MACs': ('hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256', 'HIGH', "MACs SHA-2 com Encrypt-then-MAC + fallback FIPS"),
    'KexAlgorithms': ('sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256', 'HIGH', "KEX pós-quântico + curvas elípticas + DH forte"),
}

# --- Configuração de Logging Estruturado ---
class JSONFormatter(logging.Formatter):
    """Formatter para logs estruturados em JSON (SIEM-ready)"""
    def format(self, record):
        log_data = {
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'level': record.levelname,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        if hasattr(record, 'event_type'):
            log_data['event_type'] = record.event_type
        if hasattr(record, 'details'):
            log_data['details'] = record.details
        return json.dumps(log_data)

def setup_logging(verbose: bool = False):
    """Configura logging dual: JSON para arquivo, human-readable para console"""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(JSONFormatter())
    file_handler.setLevel(logging.DEBUG)
    
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

def log_event(event_type: str, message: str, details: dict = None, level: str = 'INFO'):
    """Log estruturado para eventos de auditoria/hardening"""
    logger = logging.getLogger()
    log_level = getattr(logging, level.upper())
    
    extra = {'event_type': event_type}
    if details:
        extra['details'] = details
    
    logger.log(log_level, message, extra=extra)

# --- Funções Auxiliares ---
def run_command(command: List[str], check: bool = True, input_data: str = None, 
                timeout: int = 30) -> subprocess.CompletedProcess:
    """Executa comando com timeout e tratamento robusto de erros"""
    logging.debug(f"Executando: {' '.join(command)}")
    try:
        result = subprocess.run(
            command,
            check=check,
            capture_output=True,
            text=True,
            input=input_data,
            timeout=timeout
        )
        return result
    except subprocess.TimeoutExpired:
        logging.error(f"Timeout ao executar: {' '.join(command)}")
        raise
    except subprocess.CalledProcessError as e:
        logging.error(f"Comando falhou: {' '.join(command)}\nErro: {e.stderr.strip()}")
        if check:
            raise
        return e
    except FileNotFoundError:
        logging.error(f"Comando não encontrado: {command[0]}")
        raise

def detect_distro() -> str:
    """Detecta família da distribuição Linux"""
    try:
        with open('/etc/os-release', 'r') as f:
            content = f.read().lower()
            if any(x in content for x in ['debian', 'ubuntu']):
                return 'debian'
            elif any(x in content for x in ['rhel', 'centos', 'rocky', 'alma', 'fedora']):
                return 'rhel'
            elif 'alpine' in content:
                return 'alpine'
    except FileNotFoundError:
        pass
    
    if shutil.which('apt'):
        return 'debian'
    elif shutil.which('yum') or shutil.which('dnf'):
        return 'rhel'
    
    return 'unknown'

def get_sftp_server_path() -> str:
    """Retorna path correto do sftp-server baseado na distro"""
    distro = detect_distro()
    
    paths = {
        'debian': '/usr/lib/openssh/sftp-server',
        'rhel': '/usr/libexec/openssh/sftp-server',
        'alpine': '/usr/lib/ssh/sftp-server',
    }
    
    if distro in paths and os.path.exists(paths[distro]):
        return paths[distro]
    
    for path in paths.values():
        if os.path.exists(path):
            return path
    
    result = run_command(['which', 'sftp-server'], check=False)
    if result.returncode == 0:
        return result.stdout.strip()
    
    logging.warning("sftp-server não encontrado, usando path Debian como fallback")
    return paths['debian']

def backup_config(filepath: str) -> Optional[str]:
    """Cria backup timestampado do arquivo de configuração"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(BACKUP_DIR, f"{os.path.basename(filepath)}.bak_{timestamp}")
    
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        shutil.copy2(filepath, backup_path)
        
        log_event('backup_created', f"Backup criado: {backup_path}", {
            'original_file': filepath,
            'backup_file': backup_path
        })
        return backup_path
    except Exception as e:
        logging.error(f"Falha ao criar backup de '{filepath}': {e}")
        return None

def restore_backup(backup_path: str, original_path: str) -> bool:
    """Restaura arquivo de backup"""
    try:
        shutil.copy2(backup_path, original_path)
        log_event('backup_restored', f"Backup restaurado: {backup_path} -> {original_path}", {
            'backup_file': backup_path,
            'restored_to': original_path
        }, level='WARNING')
        return True
    except Exception as e:
        logging.error(f"Falha ao restaurar backup '{backup_path}': {e}")
        return False

def validate_sshd_config(config_path: str = SSHD_CONFIG) -> bool:
    """Valida sintaxe do sshd_config usando sshd -t"""
    logging.info(f"Validando sintaxe de '{config_path}'...")
    result = run_command(['sshd', '-t', '-f', config_path], check=False)
    
    if result.returncode == 0:
        logging.info("✅ Sintaxe do sshd_config válida")
        return True
    else:
        logging.error(f"❌ Sintaxe inválida no sshd_config:\n{result.stderr}")
        return False

def check_active_ssh_sessions() -> int:
    """Verifica número de sessões SSH ativas"""
    try:
        result = run_command(['who'], check=False)
        sessions = [line for line in result.stdout.split('\n') if 'pts/' in line]
        return len(sessions)
    except Exception:
        return 0

def restart_ssh_with_retry(max_retries: int = 3, retry_delay: int = 2) -> bool:
    """Reinicia SSH com retry e rollback automático em caso de falha"""
    logging.info("Reiniciando serviço SSH...")
    
    active_sessions = check_active_ssh_sessions()
    if active_sessions > 0:
        logging.warning(f"⚠️  ATENÇÃO: {active_sessions} sessão(ões) SSH ativa(s) detectada(s)")
        logging.warning("⚠️  O restart pode desconectar usuários ativos")
    
    try:
        run_command(['systemctl', 'restart', 'sshd'])
    except Exception as e:
        logging.error(f"Falha ao executar restart: {e}")
        return False
    
    for attempt in range(1, max_retries + 1):
        time.sleep(retry_delay * attempt)
        
        result = run_command(['systemctl', 'is-active', 'sshd'], check=False)
        status = result.stdout.strip()
        
        if status == 'active':
            log_event('ssh_restarted', "Serviço SSH reiniciado com sucesso", {
                'attempts': attempt,
                'status': status
            })
            return True
        
        logging.warning(f"Tentativa {attempt}/{max_retries}: SSH status = {status}")
    
    logging.error(f"❌ SSH não está ativo após {max_retries} tentativas")
    return False

def generate_secure_password(length: int = 20) -> str:
    """Gera senha segura com requisitos de complexidade"""
    letters = string.ascii_letters.replace('O', '').replace('l', '').replace('I', '')
    digits = string.digits.replace('0', '').replace('1', '')
    symbols = '!@#$%^&*()-_=+[]{}|;:,.<>?'
    
    password = [
        random.choice(string.ascii_uppercase.replace('O', '').replace('I', '')),
        random.choice(string.ascii_lowercase.replace('l', '')),
        random.choice(digits),
        random.choice(symbols)
    ]
    
    all_chars = letters + digits + symbols
    password.extend(random.choice(all_chars) for _ in range(length - 4))
    
    random.shuffle(password)
    return ''.join(password)

def validate_username(username: str) -> bool:
    """Valida username segundo POSIX.1-2008"""
    pattern = r'^[a-z_][a-z0-9_-]{0,31}$'
    return bool(re.match(pattern, username))

# --- Parser Robusto de sshd_config ---
class SSHDConfigParser:
    """Parser que suporta multilinhas e comentários"""
    
    def __init__(self, config_path: str = SSHD_CONFIG):
        self.config_path = config_path
        self.raw_lines = []
        self.config = {}
        self._parse()
    
    def _parse(self):
        """Parse do arquivo com suporte a continuação de linha"""
        try:
            with open(self.config_path, 'r') as f:
                self.raw_lines = f.readlines()
        except FileNotFoundError:
            logging.error(f"Arquivo '{self.config_path}' não encontrado")
            return
        
        current_line = ""
        for line in self.raw_lines:
            stripped = line.strip()
            
            if not stripped or stripped.startswith('#'):
                continue
            
            if '#' in stripped:
                stripped = stripped.split('#')[0].strip()
            
            # Continuação de linha (backslash)
            if stripped.endswith("\\"):
                current_line += stripped[:-1] + " "
                continue
            
            current_line += stripped
            
            parts = current_line.split(maxsplit=1)
            if len(parts) == 2:
                param, value = parts
                self.config[param] = value.strip()
            
            current_line = ""
    
    def get(self, param: str, default: str = None) -> Optional[str]:
        """Retorna valor do parâmetro"""
        return self.config.get(param, default)
    
    def has_param(self, param: str) -> bool:
        """Verifica se parâmetro existe"""
        return param in self.config
    
    def update_config(self, updates: Dict[str, str]) -> List[str]:
        """Atualiza configurações mantendo idempotência"""
        new_lines = []
        updated_params = set()
        
        for line in self.raw_lines:
            stripped = line.strip()
            
            if not stripped or stripped.startswith('#'):
                new_lines.append(line)
                continue
            
            parts = stripped.split(maxsplit=1)
            if len(parts) < 1:
                new_lines.append(line)
                continue
            
            param = parts[0]
            
            if param in updates:
                new_value = updates[param]
                new_lines.append(f"{param} {new_value}\n")
                updated_params.add(param)
                logging.debug(f"Atualizado: {param} = {new_value}")
            else:
                new_lines.append(line)
        
        for param, value in updates.items():
            if param not in updated_params:
                new_lines.append(f"{param} {value}\n")
                logging.debug(f"Adicionado: {param} = {value}")
        
        return new_lines

# --- Auditoria ---
def audit_ssh_config() -> List[Dict]:
    """Audita configurações SSH contra CIS Benchmark"""
    issues = []
    parser = SSHDConfigParser()
    
    sftp_path = get_sftp_server_path()
    config_to_check = CIS_COMPLIANT_CONFIG.copy()
    config_to_check['Subsystem'] = (f'sftp {sftp_path}', 'MEDIUM', "Configuração correta do subsistema SFTP")
    
    for param, (recommended, severity, comment) in config_to_check.items():
        current_value = parser.get(param)
        
        if current_value is None:
            issues.append({
                'type': 'missing',
                'severity': severity,
                'parameter': param,
                'recommended': recommended,
                'comment': comment
            })
        elif current_value != recommended:
            issues.append({
                'type': 'misconfigured',
                'severity': severity,
                'parameter': param,
                'current': current_value,
                'recommended': recommended,
                'comment': comment
            })
    
    return issues

def audit_file_permissions() -> List[Dict]:
    """Audita permissões de arquivos SSH críticos"""
    issues = []
    
    critical_files = [
        (SSHD_CONFIG, 0o600, 'root', 'root'),
        (SSH_DIR, 0o755, 'root', 'root'),
    ]
    
    for key_file in Path(SSH_DIR).glob('ssh_host_*_key'):
        critical_files.append((str(key_file), 0o600, 'root', 'root'))
        pub_key = f"{key_file}.pub"
        if os.path.exists(pub_key):
            critical_files.append((pub_key, 0o644, 'root', 'root'))
    
    for filepath, expected_perms, expected_owner, expected_group in critical_files:
        if not os.path.exists(filepath):
            issues.append({
                'type': 'missing_file',
                'severity': 'HIGH',
                'path': filepath,
                'comment': 'Arquivo crítico não encontrado'
            })
            continue
        
        try:
            stat_info = os.stat(filepath)
            current_perms = stat_info.st_mode & 0o777
            current_owner = pwd.getpwuid(stat_info.st_uid).pw_name
            current_group = grp.getgrgid(stat_info.st_gid).gr_name
            
            if current_perms != expected_perms:
                issues.append({
                    'type': 'wrong_permissions',
                    'severity': 'HIGH',
                    'path': filepath,
                    'current': f"0o{current_perms:o}",
                    'expected': f"0o{expected_perms:o}"
                })
            
            if current_owner != expected_owner or current_group != expected_group:
                issues.append({
                    'type': 'wrong_ownership',
                    'severity': 'HIGH',
                    'path': filepath,
                    'current': f"{current_owner}:{current_group}",
                    'expected': f"{expected_owner}:{expected_group}"
                })
        
        except Exception as e:
            issues.append({
                'type': 'audit_error',
                'severity': 'MEDIUM',
                'path': filepath,
                'error': str(e)
            })
    
    return issues

def audit_host_keys() -> List[Dict]:
    """Audita força das chaves de host SSH"""
    issues = []
    
    for key_file in Path(SSH_DIR).glob('ssh_host_*_key.pub'):
        try:
            result = run_command(['ssh-keygen', '-l', '-f', str(key_file)])
            output = result.stdout.strip()
            
            parts = output.split()
            if len(parts) < 1:
                continue
            
            key_size = int(parts[0])
            key_type = parts[-1].strip('()')
            
            if key_type == 'RSA' and key_size < 3072:
                issues.append({
                    'type': 'weak_host_key',
                    'severity': 'HIGH',
                    'path': str(key_file),
                    'key_type': key_type,
                    'key_size': key_size,
                    'comment': f"Chave RSA com {key_size} bits. NIST recomenda mínimo 3072 bits"
                })
        
        except Exception as e:
            logging.debug(f"Erro ao auditar chave {key_file}: {e}")
    
    return issues

def audit_authorized_keys() -> List[Dict]:
    """Audita permissões de authorized_keys de todos os usuários"""
    issues = []
    
    try:
        result = run_command(['getent', 'passwd'])
        users = []
        
        for line in result.stdout.split('\n'):
            if not line.strip():
                continue
            parts = line.split(':')
            if len(parts) >= 6:
                username = parts[0]
                home_dir = parts[5]
                users.append((username, home_dir))
        
        for username, home_dir in users:
            auth_keys_path = os.path.join(home_dir, '.ssh', 'authorized_keys')
            
            if not os.path.exists(auth_keys_path):
                continue
            
            try:
                stat_info = os.stat(auth_keys_path)
                current_perms = stat_info.st_mode & 0o777
                current_owner = pwd.getpwuid(stat_info.st_uid).pw_name
                
                if current_perms not in [0o600, 0o400]:
                    issues.append({
                        'type': 'insecure_authorized_keys',
                        'severity': 'CRITICAL',
                        'path': auth_keys_path,
                        'user': username,
                        'current_perms': f"0o{current_perms:o}",
                        'comment': 'authorized_keys deve ter permissões 0o600 ou 0o400'
                    })
                
                if current_owner != username:
                    issues.append({
                        'type': 'wrong_authorized_keys_owner',
                        'severity': 'CRITICAL',
                        'path': auth_keys_path,
                        'user': username,
                        'current_owner': current_owner,
                        'comment': f'authorized_keys deve pertencer a {username}'
                    })
            
            except Exception as e:
                logging.debug(f"Erro ao auditar {auth_keys_path}: {e}")
    
    except Exception as e:
        logging.error(f"Erro ao auditar authorized_keys: {e}")
    
    return issues

def audit_fail2ban() -> List[Dict]:
    """Verifica status do Fail2ban"""
    issues = []
    
    try:
        result = run_command(['systemctl', 'is-active', 'fail2ban'], check=False)
        if result.stdout.strip() != 'active':
            issues.append({
                'type': 'fail2ban_inactive',
                'severity': 'HIGH',
                'comment': 'Fail2ban não está ativo. Servidor vulnerável a brute-force'
            })
    except FileNotFoundError:
        issues.append({
            'type': 'fail2ban_missing',
            'severity': 'HIGH',
            'comment': 'Fail2ban não está instalado'
        })
    
    return issues

def generate_audit_report(all_issues: Dict[str, List[Dict]]) -> str:
    """Gera relatório de auditoria formatado"""
    report = []
    report.append("=" * 80)
    report.append("RELATÓRIO DE AUDITORIA SSH - ENTERPRISE EDITION")
    report.append(f"Data: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Servidor: {os.uname().nodename}")
    report.append("=" * 80)
    report.append("")
    
    total_issues = sum(len(issues) for issues in all_issues.values())
    
    if total_issues == 0:
        report.append("✅ NENHUMA FALHA DETECTADA")
        report.append("   Sistema em conformidade com CIS Benchmark")
    else:
        report.append(f"❌ TOTAL DE ISSUES: {total_issues}")
        report.append("")
        
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        
        for category, issues in all_issues.items():
            if not issues:
                continue
            
            report.append(f"\n{'─' * 80}")
            report.append(f"CATEGORIA: {category.upper()}")
            report.append(f"{'─' * 80}")
            
            sorted_issues = sorted(
                issues,
                key=lambda x: severity_order.index(x.get('severity', 'LOW'))
            )
            
            for issue in sorted_issues:
                severity = issue.get('severity', 'UNKNOWN')
                issue_type = issue.get('type', 'unknown')
                
                emoji = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡',
                    'LOW': '🔵'
                }.get(severity, '⚪')
                
                report.append(f"\n{emoji} [{severity}] {issue_type}")
                
                for key, value in issue.items():
                    if key not in ['type', 'severity']:
                        report.append(f"   {key}: {value}")
    
    report.append("\n" + "=" * 80)
    return "\n".join(report)

# --- Correções (Hardening) ---
def fix_ssh_config(dry_run: bool = False) -> bool:
    """Aplica correções no sshd_config"""
    logging.info("Iniciando correção de configurações SSH...")
    
    if dry_run:
        logging.info("🔍 MODO DRY-RUN: Simulação sem alterações reais")
    
    parser = SSHDConfigParser()
    
    sftp_path = get_sftp_server_path()
    updates = {param: value for param, (value, _, _) in CIS_COMPLIANT_CONFIG.items()}
    updates['Subsystem'] = f'sftp {sftp_path}'
    
    new_lines = parser.update_config(updates)
    
    if dry_run:
        logging.info(f"Dry-Run: {len(updates)} parâmetros seriam atualizados")
        return True
    
    backup_path = backup_config(SSHD_CONFIG)
    if not backup_path:
        logging.error("Não foi possível criar backup. Abortando correção.")
        return False
    
    try:
        with open(SSHD_CONFIG, 'w') as f:
            f.writelines(new_lines)
        
        log_event('config_updated', f"Configuração SSH atualizada", {
            'backup': backup_path,
            'parameters_updated': len(updates)
        })
    except Exception as e:
        logging.error(f"Falha ao escrever {SSHD_CONFIG}: {e}")
        return False
    
    if not validate_sshd_config():
        logging.error("❌ VALIDAÇÃO FALHOU: Restaurando backup...")
        restore_backup(backup_path, SSHD_CONFIG)
        return False
    
    return True

def fix_file_permissions(dry_run: bool = False) -> bool:
    """Corrige permissões de arquivos SSH"""
    logging.info("Iniciando correção de permissões...")
    
    if dry_run:
        logging.info("🔍 MODO DRY-RUN: Simulação sem alterações reais")
    
    issues = audit_file_permissions()
    fixed_count = 0
    
    for issue in issues:
        if issue['type'] == 'missing_file':
            logging.warning(f"Arquivo ausente: {issue['path']}")
            continue
        
        filepath = issue['path']
        
        try:
            if issue['type'] == 'wrong_permissions':
                expected_perms = int(issue['expected'], 8)
                if not dry_run:
                    os.chmod(filepath, expected_perms)
                logging.info(f"Corrigido: {filepath} -> {issue['expected']}")
                fixed_count += 1
            
            elif issue['type'] == 'wrong_ownership':
                owner, group = issue['expected'].split(':')
                if not dry_run:
                    shutil.chown(filepath, user=owner, group=group)
                logging.info(f"Corrigido: {filepath} -> {owner}:{group}")
                fixed_count += 1
        
        except Exception as e:
            logging.error(f"Erro ao corrigir {filepath}: {e}")
    
    if dry_run:
        logging.info(f"Dry-Run: {fixed_count} permissões seriam corrigidas")
    else:
        logging.info(f"✅ {fixed_count} permissões corrigidas")
    
    return True

def fix_authorized_keys(dry_run: bool = False) -> bool:
    """Corrige permissões de authorized_keys"""
    logging.info("Iniciando correção de authorized_keys...")
    
    if dry_run:
        logging.info("🔍 MODO DRY-RUN: Simulação sem alterações reais")
    
    issues = audit_authorized_keys()
    fixed_count = 0
    
    for issue in issues:
        filepath = issue['path']
        username = issue['user']
        
        try:
            if issue['type'] == 'insecure_authorized_keys':
                if not dry_run:
                    os.chmod(filepath, 0o600)
                logging.info(f"Corrigido: {filepath} -> 0o600")
                fixed_count += 1
            
            elif issue['type'] == 'wrong_authorized_keys_owner':
                if not dry_run:
                    shutil.chown(filepath, user=username, group=username)
                logging.info(f"Corrigido: {filepath} -> {username}:{username}")
                fixed_count += 1
        
        except Exception as e:
            logging.error(f"Erro ao corrigir {filepath}: {e}")
    
    if dry_run:
        logging.info(f"Dry-Run: {fixed_count} authorized_keys seriam corrigidos")
    else:
        logging.info(f"✅ {fixed_count} authorized_keys corrigidos")
    
    return True

# --- Fail2ban ---
def install_fail2ban(dry_run: bool = False) -> bool:
    """Instala e configura Fail2ban"""
    logging.info("Verificando Fail2ban...")
    
    if dry_run:
        logging.info("🔍 MODO DRY-RUN: Simulação sem alterações reais")
    
    try:
        result = run_command(['systemctl', 'is-active', 'fail2ban'], check=False)
        if result.stdout.strip() == 'active':
            logging.info("✅ Fail2ban já está ativo")
            return True
    except FileNotFoundError:
        pass
    
    distro = detect_distro()
    
    try:
        if distro == 'debian':
            if not dry_run:
                run_command(['apt-get', 'update', '-y'])
                run_command(['apt-get', 'install', 'fail2ban', '-y'])
            logging.info("Fail2ban instalado (Debian)")
        
        elif distro == 'rhel':
            if not dry_run:
                run_command(['yum', 'install', 'epel-release', '-y'])
                run_command(['yum', 'install', 'fail2ban', '-y'])
            logging.info("Fail2ban instalado (RHEL)")
        
        else:
            logging.warning(f"Distro '{distro}' não suportada para instalação automática")
            return False
    
    except Exception as e:
        logging.error(f"Erro ao instalar Fail2ban: {e}")
        return False
    
    jail_config = """[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
"""
    
    jail_path = "/etc/fail2ban/jail.d/sshd.local"
    
    if not dry_run:
        try:
            with open(jail_path, 'w') as f:
                f.write(jail_config)
            logging.info(f"Configuração criada: {jail_path}")
        except Exception as e:
            logging.error(f"Erro ao criar {jail_path}: {e}")
            return False
        
        run_command(['systemctl', 'enable', 'fail2ban'])
        run_command(['systemctl', 'start', 'fail2ban'])
        
        result = run_command(['systemctl', 'is-active', 'fail2ban'], check=False)
        if result.stdout.strip() == 'active':
            logging.info("✅ Fail2ban ativo e configurado")
            return True
        else:
            logging.error("❌ Fail2ban não está ativo após configuração")
            return False
    else:
        logging.info("Dry-Run: Fail2ban seria instalado e configurado")
        return True

# --- Gerenciamento de Usuários ---
def create_sudo_user(username: str, dry_run: bool = False) -> bool:
    """Cria usuário com permissões sudo e senha segura"""
    logging.info(f"Iniciando criação do usuário '{username}'...")
    
    if dry_run:
        logging.info("🔍 MODO DRY-RUN: Simulação sem alterações reais")
        return True
    
    if not validate_username(username):
        logging.error(f"Username inválido: '{username}'")
        logging.error("Formato válido: [a-z_][a-z0-9_-]{{0,31}}")
        return False
    
    try:
        pwd.getpwnam(username)
        logging.error(f"Usuário '{username}' já existe")
        return False
    except KeyError:
        pass
    
    password = generate_secure_password()
    
    try:
        run_command(['useradd', '-m', '-s', '/bin/bash', username])
        logging.info(f"Usuário '{username}' criado")
        
        run_command(['chpasswd'], input_data=f"{username}:{password}\n")
        logging.info(f"Senha definida para '{username}'")
        
        distro = detect_distro()
        sudo_group = 'sudo' if distro == 'debian' else 'wheel'
        
        run_command(['usermod', '-aG', sudo_group, username])
        logging.info(f"Usuário '{username}' adicionado ao grupo '{sudo_group}'")
        
        print("\n" + "=" * 80)
        print("🔐 CREDENCIAIS DO NOVO USUÁRIO SUDO")
        print("=" * 80)
        print(f"Username: {username}")
        print(f"Password: {password}")
        print("=" * 80)
        print("⚠️  ATENÇÃO: Salve esta senha AGORA. Ela não será exibida novamente.")
        print("=" * 80 + "\n")
        
        log_event('user_created', f"Usuário sudo criado: {username}", {
            'username': username,
            'sudo_group': sudo_group
        })
        
        return True
    
    except Exception as e:
        logging.error(f"Erro ao criar usuário '{username}': {e}")
        
        try:
            run_command(['userdel', '-r', username], check=False)
            logging.warning(f"Rollback: usuário '{username}' removido")
        except Exception:
            pass
        
        return False

# --- Menu Interativo ---
def interactive_menu():
    """Menu interativo para facilitar o uso do script"""
    
    def print_header():
        os.system('clear' if os.name == 'posix' else 'cls')
        print("=" * 80)
        print("SSH AUDITOR AND HARDENING TOOL - ENTERPRISE EDITION v1.0")
        print(f"Servidor: {os.uname().nodename}")
        print(f"Distro: {detect_distro()}")
        print("=" * 80)
        print()
    
    def print_menu():
        print("MENU PRINCIPAL:")
        print()
        print("  [1] Auditoria de Segurança SSH")
        print("  [2] Simular Correções (Dry-Run)")
        print("  [3] Aplicar Correções (CUIDADO!)")
        print("  [4] Instalar/Configurar Fail2ban")
        print("  [5] Criar Usuário Sudo")
        print("  [6] Auditoria + Hardening Completo")
        print("  [7] Ver Logs de Auditoria")
        print("  [8] Ver Relatórios Salvos")
        print()
        print("  [0] Sair")
        print()
        print("-" * 80)
    
    def wait_key():
        input("\nPressione ENTER para continuar...")
    
    def confirm_action(message):
        while True:
            response = input(f"\n{message} (s/n): ").lower().strip()
            if response in ['s', 'sim', 'y', 'yes']:
                return True
            elif response in ['n', 'nao', 'não', 'no']:
                return False
            print("Resposta inválida. Digite 's' para sim ou 'n' para não.")
    
    def run_audit():
        print_header()
        print("EXECUTANDO AUDITORIA DE SEGURANÇA SSH...")
        print("-" * 80)
        print()
        
        all_issues = {
            'ssh_config': audit_ssh_config(),
            'file_permissions': audit_file_permissions(),
            'host_keys': audit_host_keys(),
            'authorized_keys': audit_authorized_keys(),
            'fail2ban': audit_fail2ban()
        }
        
        report = generate_audit_report(all_issues)
        print(report)
        
        report_path = f"/var/log/ssh_audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(report_path, 'w') as f:
                f.write(report)
            print(f"\nRelatório salvo em: {report_path}")
        except Exception as e:
            logging.warning(f"Não foi possível salvar relatório: {e}")
        
        wait_key()
    
    def run_dry_run():
        print_header()
        print("SIMULAÇÃO DE CORREÇÕES (DRY-RUN)")
        print("-" * 80)
        print()
        
        logging.info("Modo Dry-Run ativado - nenhuma alteração será feita")
        print()
        
        fix_ssh_config(dry_run=True)
        fix_file_permissions(dry_run=True)
        fix_authorized_keys(dry_run=True)
        
        print()
        print("=" * 80)
        print("SIMULAÇÃO CONCLUÍDA")
        print("Nenhuma alteração foi aplicada ao sistema.")
        print("=" * 80)
        
        wait_key()
    
    def run_fix():
        print_header()
        print("APLICAR CORREÇÕES DE HARDENING")
        print("-" * 80)
        print()
        print("ATENÇÃO: Esta operação irá modificar configurações do SSH!")
        print()
        print("Recomendações antes de continuar:")
        print("  - Certifique-se de ter acesso alternativo ao servidor (console/IPMI)")
        print("  - Verifique se há pelo menos 1 usuário com chave SSH configurada")
        print("  - Backup do sshd_config será criado automaticamente")
        print()
        
        if not confirm_action("Deseja continuar com as correções?"):
            print("\nOperação cancelada pelo usuário.")
            wait_key()
            return
        
        print()
        print("Aplicando correções...")
        print("-" * 80)
        print()
        
        success = True
        
        if not fix_ssh_config(dry_run=False):
            logging.error("Falha ao corrigir configurações SSH")
            success = False
        
        if not fix_file_permissions(dry_run=False):
            logging.error("Falha ao corrigir permissões")
            success = False
        
        if not fix_authorized_keys(dry_run=False):
            logging.error("Falha ao corrigir authorized_keys")
            success = False
        
        if success:
            print()
            print("Reiniciando serviço SSH...")
            if not restart_ssh_with_retry():
                logging.error("FALHA CRÍTICA: SSH não reiniciou corretamente")
                print()
                print("ATENÇÃO: Verifique o serviço SSH manualmente!")
                print("Comando: systemctl status sshd")
                success = False
        
        print()
        print("=" * 80)
        if success:
            print("CORREÇÕES APLICADAS COM SUCESSO")
        else:
            print("CORREÇÕES CONCLUÍDAS COM FALHAS")
            print("Verifique os logs em: " + LOG_FILE)
        print("=" * 80)
        
        wait_key()
    
    def run_fail2ban():
        print_header()
        print("INSTALAR/CONFIGURAR FAIL2BAN")
        print("-" * 80)
        print()
        
        if install_fail2ban(dry_run=False):
            print()
            print("=" * 80)
            print("FAIL2BAN CONFIGURADO COM SUCESSO")
            print("=" * 80)
        else:
            print()
            print("=" * 80)
            print("FALHA AO CONFIGURAR FAIL2BAN")
            print("=" * 80)
        
        wait_key()
    
    def run_create_user():
        print_header()
        print("CRIAR USUÁRIO SUDO")
        print("-" * 80)
        print()
        
        username = input("Digite o nome do usuário (formato: [a-z_][a-z0-9_-]{0,31}): ").strip()
        
        if not username:
            print("\nOperação cancelada.")
            wait_key()
            return
        
        print()
        if create_sudo_user(username, dry_run=False):
            print()
            print("=" * 80)
            print("USUÁRIO CRIADO COM SUCESSO")
            print("=" * 80)
        else:
            print()
            print("=" * 80)
            print("FALHA AO CRIAR USUÁRIO")
            print("=" * 80)
        
        wait_key()
    
    def run_full_hardening():
        print_header()
        print("AUDITORIA + HARDENING COMPLETO")
        print("-" * 80)
        print()
        print("Esta operação irá:")
        print("  1. Executar auditoria completa")
        print("  2. Aplicar todas as correções de hardening")
        print("  3. Instalar e configurar Fail2ban")
        print()
        print("ATENÇÃO: Certifique-se de ter acesso alternativo ao servidor!")
        print()
        
        if not confirm_action("Deseja continuar?"):
            print("\nOperação cancelada pelo usuário.")
            wait_key()
            return
        
        print()
        print("Executando auditoria...")
        print("-" * 80)
        
        all_issues = {
            'ssh_config': audit_ssh_config(),
            'file_permissions': audit_file_permissions(),
            'host_keys': audit_host_keys(),
            'authorized_keys': audit_authorized_keys(),
            'fail2ban': audit_fail2ban()
        }
        
        report = generate_audit_report(all_issues)
        print(report)
        
        print()
        if not confirm_action("Deseja aplicar as correções?"):
            print("\nOperação cancelada pelo usuário.")
            wait_key()
            return
        
        print()
        print("Aplicando correções...")
        print("-" * 80)
        
        success = True
        
        if not fix_ssh_config(dry_run=False):
            success = False
        
        if not fix_file_permissions(dry_run=False):
            success = False
        
        if not fix_authorized_keys(dry_run=False):
            success = False
        
        if success:
            if not restart_ssh_with_retry():
                success = False
        
        print()
        print("Instalando Fail2ban...")
        if not install_fail2ban(dry_run=False):
            success = False
        
        print()
        print("=" * 80)
        if success:
            print("HARDENING COMPLETO APLICADO COM SUCESSO")
        else:
            print("HARDENING CONCLUÍDO COM FALHAS")
        print("=" * 80)
        
        wait_key()
    
    def view_logs():
        print_header()
        print("LOGS DE AUDITORIA")
        print("-" * 80)
        print()
        
        if not os.path.exists(LOG_FILE):
            print(f"Arquivo de log não encontrado: {LOG_FILE}")
            wait_key()
            return
        
        print(f"Exibindo últimas 30 linhas de: {LOG_FILE}")
        print()
        
        try:
            with open(LOG_FILE, 'r') as f:
                lines = f.readlines()
                for line in lines[-30:]:
                    try:
                        log_entry = json.loads(line)
                        timestamp = log_entry.get('timestamp', 'N/A')
                        level = log_entry.get('level', 'N/A')
                        message = log_entry.get('message', 'N/A')
                        print(f"[{timestamp}] [{level}] {message}")
                    except json.JSONDecodeError:
                        print(line.strip())
        except Exception as e:
            print(f"Erro ao ler logs: {e}")
        
        wait_key()
    
    def view_reports():
        print_header()
        print("RELATÓRIOS SALVOS")
        print("-" * 80)
        print()
        
        reports = sorted(Path('/var/log').glob('ssh_audit_*.txt'), reverse=True)
        
        if not reports:
            print("Nenhum relatório encontrado.")
            wait_key()
            return
        
        print(f"Encontrados {len(reports)} relatório(s):\n")
        
        for i, report in enumerate(reports[:10], 1):
            stat = report.stat()
            size = stat.st_size
            mtime = datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            print(f"  [{i}] {report.name}")
            print(f"      Data: {mtime} | Tamanho: {size} bytes")
            print()
        
        if len(reports) > 10:
            print(f"... e mais {len(reports) - 10} relatório(s)")
            print()
        
        choice = input("Digite o número do relatório para visualizar (ou ENTER para voltar): ").strip()
        
        if choice.isdigit() and 1 <= int(choice) <= min(10, len(reports)):
            print()
            print("=" * 80)
            with open(reports[int(choice) - 1], 'r') as f:
                print(f.read())
            print("=" * 80)
        
        wait_key()
    
    # Loop principal do menu
    while True:
        print_header()
        print_menu()
        
        choice = input("Escolha uma opção: ").strip()
        
        if choice == '1':
            run_audit()
        elif choice == '2':
            run_dry_run()
        elif choice == '3':
            run_fix()
        elif choice == '4':
            run_fail2ban()
        elif choice == '5':
            run_create_user()
        elif choice == '6':
            run_full_hardening()
        elif choice == '7':
            view_logs()
        elif choice == '8':
            view_reports()
        elif choice == '0':
            print()
            print("Encerrando...")
            sys.exit(0)
        else:
            print()
            print("Opção inválida. Tente novamente.")
            time.sleep(1)

# --- Main ---
def main():
    parser = argparse.ArgumentParser(
        description=f"SSH Auditor and Hardening Tool v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  %(prog)s                                  # Menu interativo
  %(prog)s --audit                          # Auditoria completa
  %(prog)s --fix --dry-run                  # Simular correções
  %(prog)s --fix                            # Aplicar correções
  %(prog)s --create-user admin_backup       # Criar usuário sudo
  %(prog)s --install-fail2ban               # Instalar Fail2ban
  %(prog)s --audit --fix --install-fail2ban # Auditoria + Hardening completo

ATENÇÃO: Execute sempre com --dry-run primeiro em produção!
        """
    )
    
    parser.add_argument('--audit', action='store_true',
                        help='Executar auditoria de segurança SSH')
    parser.add_argument('--fix', action='store_true',
                        help='Aplicar correções de hardening')
    parser.add_argument('--dry-run', action='store_true',
                        help='Simular correções sem aplicar (usar com --fix)')
    parser.add_argument('--create-user', metavar='USERNAME',
                        help='Criar novo usuário com permissões sudo')
    parser.add_argument('--install-fail2ban', action='store_true',
                        help='Instalar e configurar Fail2ban')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Modo verbose (debug)')
    parser.add_argument('--no-interactive', action='store_true',
                        help='Desabilitar menu interativo')
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {VERSION}')
    
    args = parser.parse_args()
    
    setup_logging(args.verbose)
    
    if os.geteuid() != 0:
        logging.error("❌ Este script requer privilégios de root")
        logging.error("   Execute com: sudo python3 ssh_auditor_v2.py")
        sys.exit(1)
    
    # Se nenhum argumento foi passado, iniciar menu interativo
    if not any([args.audit, args.fix, args.create_user, args.install_fail2ban, args.no_interactive]):
        interactive_menu()
        return
    
    logging.info(f"SSH Auditor and Hardening Tool v{VERSION}")
    logging.info(f"Distro detectada: {detect_distro()}")
    logging.info("=" * 80)
    
    success = True
    
    if args.audit or args.fix:
        logging.info("🔍 INICIANDO AUDITORIA...")
        
        all_issues = {
            'ssh_config': audit_ssh_config(),
            'file_permissions': audit_file_permissions(),
            'host_keys': audit_host_keys(),
            'authorized_keys': audit_authorized_keys(),
            'fail2ban': audit_fail2ban()
        }
        
        report = generate_audit_report(all_issues)
        print("\n" + report + "\n")
        
        report_path = f"/var/log/ssh_audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(report_path, 'w') as f:
                f.write(report)
            logging.info(f"📄 Relatório salvo em: {report_path}")
        except Exception as e:
            logging.warning(f"Não foi possível salvar relatório: {e}")
    
    if args.fix:
        logging.info("\n🔧 INICIANDO CORREÇÕES...")
        
        if args.dry_run:
            logging.info("🔍 MODO DRY-RUN ATIVADO")
        
        if not fix_ssh_config(args.dry_run):
            logging.error("❌ Falha ao corrigir configurações SSH")
            success = False
        
        if not fix_file_permissions(args.dry_run):
            logging.error("❌ Falha ao corrigir permissões")
            success = False
        
        if not fix_authorized_keys(args.dry_run):
            logging.error("❌ Falha ao corrigir authorized_keys")
            success = False
        
        if not args.dry_run and success:
            if not restart_ssh_with_retry():
                logging.error("❌ FALHA CRÍTICA: SSH não reiniciou corretamente")
                logging.error("   Verifique o serviço manualmente: systemctl status sshd")
                
                backups = sorted(Path(BACKUP_DIR).glob('sshd_config.bak_*'))
                if backups:
                    latest_backup = str(backups[-1])
                    logging.warning(f"⚠️  Tentando restaurar backup: {latest_backup}")
                    if restore_backup(latest_backup, SSHD_CONFIG):
                        logging.warning("   Backup restaurado. Tentando reiniciar novamente...")
                        restart_ssh_with_retry()
                
                success = False
    
    if args.install_fail2ban:
        logging.info("\n🛡️  CONFIGURANDO FAIL2BAN...")
        if not install_fail2ban(args.dry_run):
            logging.error("❌ Falha ao configurar Fail2ban")
            success = False
    
    if args.create_user:
        logging.info("\n👤 CRIANDO USUÁRIO SUDO...")
        if not create_sudo_user(args.create_user, args.dry_run):
            logging.error(f"❌ Falha ao criar usuário '{args.create_user}'")
            success = False
    
    logging.info("\n" + "=" * 80)
    if success:
        logging.info("✅ PROCESSO CONCLUÍDO COM SUCESSO")
    else:
        logging.error("❌ PROCESSO CONCLUÍDO COM FALHAS")
        logging.error("   Verifique os logs em: " + LOG_FILE)
    logging.info("=" * 80)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
