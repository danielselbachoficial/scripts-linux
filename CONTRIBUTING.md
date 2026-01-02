# 🤝 Contribuindo para o scripts-linux

Primeiramente, obrigado por dedicar seu tempo para contribuir! Este repositório visa ser uma caixa de ferramentas robusta para profissionais de infraestrutura (**Sysadmins, Analistas de NOC, Redes e Cybersec**).

Para manter a confiabilidade dos scripts, pedimos que siga estas diretrizes.

---

## 🛠️ Como posso contribuir?

### 1. Adicionando Novos Scripts
Se você tem um script de automação, hardening ou monitoramento:
* **Organização:** Coloque o script na categoria correta (`/services-noc`, `/security`, `/sysadmin`, etc).
* **Padronização:** Tente manter um estilo visual consistente (uso de cores para logs, barra de progresso para instalações longas).
* **Documentação:** Cada script novo deve vir acompanhado de um arquivo `.md` ou um cabeçalho detalhado explicando o que ele faz e as dependências.

### 2. Reportando Bugs ou Vulnerabilidades
Como este repositório lida com **Hardening e Segurança**:
* **Bugs de Funcionalidade:** Abra uma *Issue* detalhando o erro, a distribuição Linux e a versão do Python/Bash.
* **Vulnerabilidades de Segurança:** Se encontrar uma brecha em nossos scripts de hardening, por favor, envie um reporte privado ou abra uma *Issue* com a tag `security-critical`.

### 3. Melhorando o Hardening
Sugestões para melhorar regras de Firewall, Ciphers de TLS ou políticas de permissões são sempre bem-vindas.

---

## 📋 Padrões de Qualidade

Para garantir que os scripts sejam seguros para execução em ambientes de produção:

1.  **Privilégios:** Sempre verifique se o usuário tem permissão de `root` no início do script se ele for realizar alterações no sistema.
2.  **Idempotência:** O script deve ser seguro para ser executado mais de uma vez (verificar se um diretório já existe antes de criar, etc).
3.  **Tratamento de Erros:** Use blocos `try/except` (Python) ou verificações de `exit code` (Bash). Não deixe o script falhar silenciosamente.
4.  **Segurança de Dados:**
    * Nunca deixe senhas "hardcoded" no código.
    * Sempre gere segredos usando bibliotecas criptograficamente seguras (ex: `secrets` ou `cryptography` no Python).
    * Siga o padrão do repositório: salve credenciais geradas em `/root/` com permissões restritas.

---

## 🚀 Processo de Pull Request (PR)

1.  Faça um **Fork** do projeto.
2.  Crie uma branch para sua modificação: `git checkout -b feature/nome-do-script`.
3.  Faça o **Commit** de suas alterações: `git commit -m 'feat: adiciona script de hardening de kernel'`.
4.  Faça o **Push** para a branch: `git push origin feature/nome-do-script`.
5.  Abra um **Pull Request**.

---

## ⚖️ Licença
Ao contribuir para este repositório, você concorda que seu trabalho será licenciado sob a mesma [Licença MIT](LICENSE) do projeto.

---

**Dúvidas?** Sinta-se à vontade para abrir uma discussão no repositório!
