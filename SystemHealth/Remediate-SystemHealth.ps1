<#
.SYNOPSIS
    Script de CORREÇÃO para Correções Proativas do Intune.
    Repara a integridade dos arquivos de sistema e do repositório de componentes do Windows.

.DESCRIPTION
    1. Cria e utiliza um log de transcrição em C:\ProgramData\IntuneRemediations.
    2. Executa 'DISM.exe /Online /Cleanup-image /RestoreHealth' para reparar o repositório.
    3. Executa 'SFC.exe /scannow' para reparar os arquivos de sistema usando o repositório corrigido.
    4. O script lida com erros e garante que o log seja sempre salvo.
#>

# --- Configuração de Log ---
$logDir = "C:\ProgramData\IntuneRemediations"
$logFile = "SystemHealth-Repair-Log-$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss')).log"
$logPath = Join-Path -Path $logDir -ChildPath $logFile

# Garante que o diretório de log exista
if (-not (Test-Path -Path $logDir)) {
    try {
        New-Item -Path $logDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Error "Falha ao criar o diretório de log em '$logDir'."
        exit 1
    }
}

# --- Início da Remediação ---
try {
    Start-Transcript -Path $logPath -Append
    Write-Host "Iniciando remediação de integridade do sistema. Log salvo em: $logPath"

    # --- Passo 1: Reparar com DISM ---
    Write-Host "------------------------------------------------------------"
    Write-Host "Executando 'DISM /RestoreHealth'. Isso pode demorar vários minutos."
    $dismOutput = (DISM.exe /Online /Cleanup-image /RestoreHealth) *>&1
    
    if ($LASTEXITCODE -ne 0) {
        throw "O comando DISM falhou com o código de saída: $($LASTEXITCODE). Saída: `n$($dismOutput | Out-String)"
    } else {
        Write-Host "DISM concluído com sucesso."
    }

    # --- Passo 2: Reparar com SFC ---
    Write-Host "------------------------------------------------------------"
    Write-Host "Executando 'SFC /scannow'. Isso também pode demorar."
    $sfcOutput = (SFC.exe /scannow) *>&1

    if ($LASTEXITCODE -ne 0) {
        throw "O comando SFC falhou com o código de saída: $($LASTEXITCODE). Saída: `n$($sfcOutput | Out-String)"
    } else {
        Write-Host "SFC concluído com sucesso."
    }
    
    Write-Host "Remediação concluída com sucesso!"
}
catch {
    Write-Error "A remediação falhou. Verifique o log para detalhes. Erro: $_"
    exit 1 # Sinaliza ao Intune que a remediação falhou
}
finally {
    # Garante que o log de transcrição seja sempre parado e salvo
    if (Get-Transcript) {
        Stop-Transcript
    }
}

exit 0 # Sinaliza ao Intune que a remediação foi bem-sucedida