## Plano de Implementação: Gerenciador de Backup de Configurações de Aplicativos

**Objetivo:** Criar um script PowerShell para automatizar o backup de configurações de aplicativos específicos, salvando-os em um local centralizado com timestamp.

**Fases:**

1.  **Definição de Aplicativos e Caminhos de Configuração:**
    *   Identificar uma lista inicial de aplicativos comuns (ex: Chrome, Firefox, VS Code, etc.).
    *   Pesquisar e mapear os caminhos padrão onde esses aplicativos armazenam suas configurações (AppData, ProgramData, etc.).
    *   Considerar a possibilidade de o usuário adicionar/remover aplicativos e seus caminhos via um arquivo de configuração.

2.  **Estrutura do Script:**
    *   **Parâmetros:**
        *   `CaminhoDestinoBackup`: Onde os backups serão salvos (obrigatório).
        *   `ListaAplicativos`: (Opcional) Caminho para um arquivo de texto/JSON com a lista de aplicativos e seus caminhos. Se não fornecido, usar uma lista padrão.
        *   `Compactar`: (Switch) Se deve compactar os backups em um arquivo ZIP.
        *   `ManterDias`: (Opcional) Número de dias para manter backups antigos.
    *   **Funções:**
        *   `Get-AppConfigPath`: Resolve o caminho completo da configuração de um aplicativo, considerando variáveis de ambiente e perfis de usuário.
        *   `Backup-AppConfig`: Realiza a cópia ou compactação dos arquivos de configuração.
        *   `Cleanup-OldBackups`: Remove backups mais antigos que `ManterDias`.
        *   `Write-BackupLog`: Função para registrar o status de cada backup (sucesso/falha, tamanho, etc.).

3.  **Implementação (Passos Detalhados):**
    *   **Inicialização:**
        *   Validar parâmetros de entrada.
        *   Criar o diretório de destino do backup se não existir.
    *   **Leitura da Lista de Aplicativos:**
        *   Se `ListaAplicativos` for fornecido, ler o arquivo.
        *   Caso contrário, usar uma lista interna de caminhos comuns.
    *   **Loop de Backup:**
        *   Para cada aplicativo na lista:
            *   Chamar `Get-AppConfigPath` para obter o caminho da configuração.
            *   Se o caminho existir, chamar `Backup-AppConfig`.
                *   Se `Compactar` for true, usar `Compress-Archive`.
                *   Caso contrário, usar `Copy-Item -Recurse`.
            *   Registrar o resultado com `Write-BackupLog`.
    *   **Limpeza:**
        *   Se `ManterDias` for fornecido, chamar `Cleanup-OldBackups`.

4.  **Testes:**
    *   Testar com diferentes aplicativos e caminhos.
    *   Testar com e sem compactação.
    *   Testar a funcionalidade de limpeza de backups antigos.
    *   Testar cenários de erro (caminhos inexistentes, permissões).

5.  **Documentação:**
    *   Adicionar comentários detalhados ao script.
    *   Atualizar o `README.md` do repositório com a descrição do script, uso e exemplos.
