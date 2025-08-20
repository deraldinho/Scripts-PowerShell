
# Documentação dos Scripts PowerShell

Esta documentação descreve os scripts PowerShell encontrados no diretório e seus subdiretórios.

## Maintenance

### Manutenção periodica.ps1

*   **Path:** `Maintenance\Manutenção periodica.ps1`
*   **Descrição:** Script de manutenção completo para o Windows. Realiza diagnóstico, limpeza, reparo avançado e otimização do sistema. Agora agenda o CHKDSK para a próxima reinicialização e detecta perfis de usuário de forma mais robusta. Pode enviar um relatório detalhado para o Slack.
*   **Parâmetros:**
    *   `WebhookUrl`: (Obrigatório) URL do Webhook do Slack para o envio de relatórios.
    *   `Destino`: Pasta para salvar os logs locais. O padrão é a Área de Trabalho.
    *   `SemReboot`: Impede a reinicialização automática no final da execução.
    *   `DryRun`: Simula as ações sem fazer alterações reais no sistema.
    *   `Disco`: A unidade de disco a ser verificada. O padrão é "C:".
    *   **Nota:** O script agora usa `[CmdletBinding()]` para funcionalidades avançadas de script. O uso de `-Force` para parar serviços ou reiniciar o computador é feito com mais cautela.
*   **Uso:**
    ```powershell
    .\Maintenance\Manutenção periodica.ps1 -WebhookUrl "https://hooks.slack.com/..."
    ```

## Security

### GPO-CVE-2025-6558.ps1

*   **Path:** `Security\GPO-CVE-2025-6558.ps1`
*   **Descrição:** Garante que o Google Chrome esteja atualizado. Compara a versão local com uma lista de versões críticas lida de um arquivo externo e inicia a atualização em segundo plano, se necessário. Envia um relatório para o Slack. Para maior segurança, considere armazenar o WebhookUrl usando o módulo SecretManagement do PowerShell.
*   **Parâmetros:**
    *   `SlackWebhookUrl`: URL do Webhook do Slack para receber relatórios.
    *   `CriticalVersionsFilePath`: Caminho para o arquivo de texto contendo as versões críticas do Chrome (uma versão por linha).
    *   `LogFilePath`: Caminho para o arquivo de log.
*   **Uso:**
    *   Este script foi projetado para ser executado em um ambiente de GPO (Política de Grupo).

## SystemHealth



### Detect-SystemHealth.ps1

*   **Path:** `SystemHealth\Detect-SystemHealth.ps1`
*   **Descrição:** Script de detecção para o Intune Proactive Remediations. Verifica a integridade dos arquivos do sistema e do repositório de componentes do Windows usando `DISM` e `SFC`. Agora utiliza `Write-Output` para melhor compatibilidade com o log do Intune.
*   **Uso:**
    *   Usado em conjunto com o Intune Proactive Remediations.

### Remediate-SystemHealth.ps1

*   **Path:** `SystemHealth\Remediate-SystemHealth.ps1`
*   **Descrição:** Script de correção para o Intune Proactive Remediations. Repara os arquivos do sistema e o repositório de componentes do Windows usando `DISM` e `SFC`. As mensagens de erro foram aprimoradas para incluir saída detalhada, facilitando a depuração.
*   **Uso:**
    *   Usado em conjunto com o Intune Proactive Remediations.

## Unsorted

### Sem título1.ps1

*   **Path:** `Unsorted\Sem título1.ps1`
*   **Descrição:** Outro script de manutenção do Windows. Realiza diagnóstico, limpeza e reparo. Envia relatórios para o Slack.
*   **Parâmetros:**
    *   `WebhookUrl`: (Obrigatório) URL do Webhook do Slack.
    *   `Destino`: Pasta para salvar os logs. O padrão é a Área de Trabalho.
    *   `Quiet`: Executa o script em modo silencioso.
    *   `SemReboot`: Impede a reinicialização automática.
    *   `DryRun`: Simula as ações.
    *   `ChkdskCompleto`: Executa o `CHKDSK` no modo completo.
    *   `Force`: Força a execução do script.
    *   `Disco`: A unidade de disco a ser verificada. O padrão é "C:".
*   **Uso:**
    ```powershell
    ".\Unsorted\Sem título1.ps1" -WebhookUrl "https://hooks.slack.com/..."
    ```

### Sem título2.ps1

*   **Path:** `Unsorted\Sem título2.ps1`
*   **Descrição:** Versão "zero-touch" e autônoma do script de manutenção. Possui uma URL de Webhook do Slack codificada.
*   **Uso:**
    ```powershell
    ".\Unsorted\Sem título2.ps1"
    ```
