<#
.SYNOPSIS
    Script de DETECÇÃO para Correções Proativas do Intune.
    Verifica a integridade dos arquivos de sistema e do repositório de componentes do Windows.

.DESCRIPTION
    1. Executa 'DISM /Online /Cleanup-Image /ScanHealth' para verificar o repositório.
    2. Executa 'SFC /verifyonly' para verificar os arquivos do sistema.
    3. Se qualquer um dos comandos indicar um problema (código de saída diferente de 0),
       o script retorna o código de saída 1 (indicando "Necessária Remediação").
    4. Se ambos os comandos forem concluídos com sucesso, o script retorna 0 (indicando "Compatível").

.NOTES
    Saída 1: Problema detectado, remediação necessária.
    Saída 0: Nenhum problema detectado.
#>

try {
    Write-Output "Iniciando script de detecção de integridade do sistema."
    $issueFound = $false

    # --- Passo 1: Verificar a imagem do Windows com DISM (sem reparar) ---
    Write-Output "Verificando o repositório de componentes com 'DISM /ScanHealth'..."
    $dismProcess = Start-Process -FilePath "DISM.exe" -ArgumentList "/Online /Cleanup-Image /ScanHealth" -Wait -PassThru -NoNewWindow

    if ($dismProcess.ExitCode -ne 0) {
        Write-Warning "DISM encontrou um problema. Código de saída: $($dismProcess.ExitCode)."
        $issueFound = $true
    } else {
        Write-Output "DISM não encontrou problemas."
    }

    # --- Passo 2: Verificar arquivos do sistema com SFC (sem reparar) ---
    Write-Output "Verificando arquivos do sistema com 'SFC /verifyonly'..."
    $sfcProcess = Start-Process -FilePath "SFC.exe" -ArgumentList "/verifyonly" -Wait -PassThru -NoNewWindow

    if ($sfcProcess.ExitCode -ne 0) {
        Write-Warning "SFC encontrou um problema de integridade. Código de saída: $($sfcProcess.ExitCode)."
        $issueFound = $true
    } else {
        Write-Output "SFC não encontrou problemas de integridade."
    }

    # --- Decisão Final ---
    if ($issueFound) {
        Write-Output "Resultado: Problema detectado. A remediação é necessária."
        exit 1 # Sinaliza ao Intune para executar o script de correção
    } else {
        Write-Output "Resultado: O sistema está íntegro. Nenhuma ação necessária."
        exit 0 # Sinaliza ao Intune que está tudo OK
    }
}
catch {
    Write-Error "Ocorreu um erro inesperado durante a detecção: $_"
    # Em caso de erro no script, assume-se que a remediação é necessária por precaução.
    exit 1
}