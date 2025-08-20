# Meus Scripts PowerShell

Este repositório contém uma coleção de scripts PowerShell para automação de tarefas de manutenção, segurança e verificação da saúde do sistema.

## Estrutura do Repositório

O repositório está organizado da seguinte forma:

- **Maintenance/**: Scripts para realizar manutenções periódicas no sistema.
- **Security/**: Scripts para aplicar configurações de segurança e mitigar vulnerabilidades.
- **SystemHealth/**: Scripts para monitorar e corrigir problemas de saúde do sistema.

## Scripts Disponíveis

### Maintenance

- `Manutenção periodica.ps1`: Script para realizar tarefas de manutenção de rotina.

### Security

- `GPO-CVE-2025-6558.ps1`: Script para aplicar uma GPO específica para mitigar a CVE-2025-6558.

### SystemHealth

- `Detect-SystemHealth.ps1`: Detecta e relata possíveis problemas de saúde do sistema.
- `Remediate-SystemHealth.ps1`: Tenta corrigir os problemas de saúde do sistema detectados.

## Como Usar

1. Clone este repositório:
   ```bash
   git clone <URL_DO_REPOSITORIO>
   ```
2. Navegue até o diretório do script desejado.
3. Execute o script no PowerShell:
   ```powershell
   .\<nome_do_script>.ps1
   ```

**Observação:** Alguns scripts podem exigir a execução com privilégios de administrador.

## Contribuições

Contribuições são bem-vindas! Sinta-se à vontade para abrir uma *issue* ou enviar um *pull request*.