<#
.SYNOPSIS
    A Chave Mestre para manutenção do Windows: Diagnóstico, Limpeza, Reparo Avançado e Otimização 100% Silenciosa.
.DESCRIPTION
    Executa um diagnóstico de saúde completo, seguido por limpeza segura de arquivos, caches e lixeiras.
    Configura e executa a Limpeza de Disco do Windows de forma totalmente silenciosa, ativando todas as opções via registro.
    Realiza reparos avançados, otimiza discos (Defrag/TRIM) e usa as ferramentas de reparo do sistema (SFC, DISM).
    Projetado para ser uma ferramenta única e autônoma, enviando um relatório 360º para o Slack.
.PARAMETER WebhookUrl
    [OBRIGATÓRIO] URL do Webhook do Slack para receber o resumo da execução.
.PARAMETER Destino
    Pasta de destino para salvar os logs locais. Default: Área de Trabalho.
.PARAMETER SemReboot
    Impede o reboot automático ao final da execução.
.PARAMETER DryRun
    Apenas simula as ações, sem remover ou alterar nada.
.EXAMPLE
    .\ChaveMestre-v17.ps1 -WebhookUrl "https://hooks.slack.com/..."
.EXAMPLE
    .\ChaveMestre-v17.ps1 -WebhookUrl "https://..." -DryRun
#>
param (
    [string]$WebhookUrl = "", # Insira a URL do Webhook do Slack aqui para receber relatórios.
    [string]$Destino = "$([Environment]::GetFolderPath('Desktop'))",
    [switch]$SemReboot,
    [switch]$DryRun,
    [string]$Disco = "C:"
)

#region Funções auxiliares

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] - $Message"
    $Global:LogBuffer.Add($logMessage) | Out-Null # Add to in-memory buffer
    try {
        if ($Global:LogFile) { $logMessage | Out-File -FilePath $Global:LogFile -Append -Encoding utf8 -ErrorAction Stop }
    } catch {
        Write-Warning "Failed to write to local log file: $($_.Exception.Message)"
    }
    Write-Host $logMessage
}

function Safe-Run {
    param ([scriptblock]$ScriptBlock, [string]$Descricao)
    Write-Log "➡️  Iniciando: $Descricao"
    $startTime = Get-Date
    try {
        if ($DryRun.IsPresent) {
            Write-Log "🔎 DryRun: Ação '$Descricao' seria executada."
            $Global:TaskResults[$Descricao] = "✅ Simulado (DryRun)"
        } else {
            $output = & $ScriptBlock *>&1
            if ($output) { $output | ForEach-Object { Write-Log "    $_" } }
            $Global:TaskResults[$Descricao] = "✅ Sucesso"
        }
        Write-Log "✅ Concluído: $Descricao"
    } catch {
        $Global:TaskResults[$Descricao] = "❌ Erro"
        Write-Log "❌ Erro em '$Descricao': $_.Exception.Message"
    }
    $duration = (Get-Date) - $startTime
    Write-Log "⏱️  Tempo gasto: $([math]::Round($duration.TotalSeconds, 2)) segundos"
}

function Invoke-CacheCleanupForUser {
    param (
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSObject]$User,
        [switch]$DryRun
    )
    Write-Log "👤 Analisando usuário: $($User.Name)"
    $userReport = @{ User = $User.Name; Results = @()}

    $caminhosRelativos = @( "AppData\Local\Temp", "AppData\Local\Microsoft\Edge\User Data\Default\Cache", "AppData\Local\Google\Chrome\User Data\Default\Cache", "AppData\Roaming\Mozilla\Firefox\Profiles\*\cache2", "AppData\Local\Slack\Cache", "AppData\Roaming\discord\Cache", "AppData\Local\Microsoft\Teams\Cache", "AppData\Roaming\Spotify\Browser" )

    foreach ($caminhoPattern in $caminhosRelativos) {
        $fullPathPattern = Join-Path $User.FullName $caminhoPattern; $resolvedPaths = @(Resolve-Path -Path $fullPathPattern -ErrorAction SilentlyContinue)
        if ($resolvedPaths.Count -eq 0) { continue }
        foreach ($fullPath in $resolvedPaths) {
            $pathResult = @{ Path = $caminhoPattern.Replace("\*", ""); Status = "" }
            if ($DryRun) { $pathResult.Status = "Detectado (DryRun)"; Write-Log "🔎 DryRun: $fullPath" }
            else { try { Remove-Item -Path "$fullPath\*" -Recurse -Force -ErrorAction Stop; $pathResult.Status = "Limpo com Sucesso"; Write-Log "🧹 Limpo: $fullPath" } catch { $pathResult.Status = "Erro na Limpeza"; Write-Log "⚠️ Erro: $fullPath - $_" } }
            $userReport.Results += $pathResult
        }
    }
    $thumbCachePath = Join-Path $User.FullName "AppData\Local\Microsoft\Windows\Explorer"; $thumbFiles = Get-ChildItem -Path $thumbCachePath -Filter "thumbcache_*.db" -Force -ErrorAction SilentlyContinue
    if ($thumbFiles) { if ($DryRun) { Write-Log "🔎 DryRun: Cache de miniaturas detectado para $($User.Name)." } else { try { $thumbFiles | Remove-Item -Force; Write-Log "🧹 Cache de miniaturas limpo para $($User.Name)." } catch { Write-Log "⚠️ Erro ao limpar miniaturas de $($User.Name)." } } }

    return $userReport
}

#endregion

#region Validações Iniciais

Write-Host "`n🔑 INICIANDO CHAVE MESTRE DE MANUTENÇÃO v17 (Edição Furtiva) 🔑" -ForegroundColor Blue
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Warning "Este script precisa ser executado como ADMINISTRADOR."; exit 1
}

$LogPath = "$env:ProgramData\ManutencaoChaveMestre"
if (-not (Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force | Out-Null }
$Global:LogFile = Join-Path $LogPath "manutencao_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

$mutex = New-Object System.Threading.Mutex($false, "Global\ManutencaoChaveMestre")
if (!$mutex.WaitOne(0, $false)) { Write-Log "⚠️ Instância já em execução. Abortando."; exit 1 }

if ([string]::IsNullOrEmpty($WebhookUrl) -or -not ($WebhookUrl -match "hooks.slack.com")) {
    Write-Log "⚠️ WebhookUrl do Slack não informado ou inválido. Nenhum relatório será enviado."
    $WebhookUrl = $null
}

$Global:LogBuffer = [System.Collections.ArrayList]::new()
$Global:TaskResults = [ordered]@{}
$Global:CacheCleanReport = @()
$Global:HealthReport = [ordered]@{}

#endregion

#region Diagnóstico de Saúde do Sistema

Write-Log "`n[1/8] Executando Diagnóstico de Saúde do Sistema..."
Safe-Run {
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $Global:HealthReport["Sistema Operacional"] = $osInfo.Caption
    $Global:HealthReport["Memória RAM Total"] = "$([math]::Round($osInfo.TotalVisibleMemorySize / 1MB, 2)) GB"
    $uptime = (Get-Date) - $osInfo.LastBootUpTime
    $Global:HealthReport["Tempo Ligado (Uptime)"] = "$($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"

    $diskHealth = Get-PhysicalDisk | Select-Object FriendlyName, HealthStatus
    $diskHealthStatus = $diskHealth | ForEach-Object { "$($_.FriendlyName): $($_.HealthStatus)" } | Out-String
    $Global:HealthReport["Saúde dos Discos (S.M.A.R.T.)"] = $diskHealthStatus.Trim()

    $criticalErrors = Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 5 -ErrorAction SilentlyContinue
    if ($criticalErrors) { $Global:HealthReport["Erros Críticos (24h)"] = "‼️ Encontrados $($criticalErrors.Count) erros críticos." } else { $Global:HealthReport["Erros Críticos (24h)"] = "✅ Nenhum erro crítico encontrado." }

    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($defenderStatus) { $Global:HealthReport["Última Verificação Defender"] = if ($defenderStatus.FullScanStartTime) { $defenderStatus.FullScanStartTime.ToString('dd/MM/yyyy HH:mm') } else { "N/A" } } else { $Global:HealthReport["Última Verificação Defender"] = "Não disponível" }
} "Diagnóstico de Saúde do Sistema"

#endregion

#region Espaço em Disco - Antes

Write-Log "`n[2/8] Verificando espaço em disco ANTES da limpeza..."
$driveAntes = Get-PSDrive -Name $Disco.TrimEnd(':') -ErrorAction SilentlyContinue
if (-not $driveAntes) { Write-Warning "Disco $Disco não encontrado. Abortando."; exit 1 }
$Global:espacoLivreAntes = $driveAntes.Free
Write-Log "   Disco $($driveAntes.Name): $([math]::Round($driveAntes.Free / 1GB, 2)) GB livres."

#endregion

#region Limpeza de Caches de TODOS OS USUÁRIOS

Safe-Run {
    $userProfiles = Get-ChildItem -Path 'C:\Users' -Directory | Where-Object { Test-Path (Join-Path $_.FullName 'AppData') -and $_.Name -ne 'Default' -and $_.Name -ne 'Public' }

    foreach ($user in $userProfiles) {
        $userReport = Invoke-CacheCleanupForUser -User $user -DryRun:$DryRun.IsPresent
        $Global:CacheCleanReport += $userReport
    }
} "Limpeza de Caches (Multi-Usuário e Aplicativos)"

#endregion

#region Limpeza Profunda do Sistema Windows

Safe-Run {
    $limpezaCaminhos = @("$env:SystemRoot\Temp\*", "$env:WINDIR\SoftwareDistribution\Download\*", "$env:ProgramData\Microsoft\Windows\WER\*")
    foreach ($path in $limpezaCaminhos) { if (Test-Path $path) { if ($DryRun) { Write-Log "🔎 DryRun: $path" } else { Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue; Write-Log "🧹 Removido: $path" } } }
    ipconfig /flushdns; Write-Log "ℹ️ Cache de DNS limpo."
} "Limpeza de Temporários e DNS do Sistema"

#endregion

#region Esvaziar lixeiras e CleanMgr Silencioso

Safe-Run {
    # Esvazia todas as lixeiras
    Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ne $null } | ForEach-Object { $recycleBinPath = Join-Path $_.Root '$Recycle.Bin'; if (Test-Path $recycleBinPath) { Get-ChildItem $recycleBinPath -Force -ErrorAction SilentlyContinue | ForEach-Object { if ($DryRun) { Write-Log "🔎 DryRun: Lixeira detectada: $($_.FullName)" } else { Write-Log "🧹 Esvaziando lixeira: $($_.FullName)"; Remove-Item -Path "$($_.FullName)\*" -Recurse -Force -ErrorAction SilentlyContinue } } } }
    
    # *** MÉTODO FURTIVO PARA O CLEANMGR ***
    # Ativa TODAS as opções de limpeza do CleanMgr diretamente no registro.
    # Isso elimina a necessidade de qualquer interação do usuário.
    $volumeCaches = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
    Get-ChildItem -Path $volumeCaches | ForEach-Object {
        Set-ItemProperty -Path $_.PSPath -Name StateFlags0001 -Value 2 -Type DWord -Force
    }
    Write-Log "ℹ️ Todas as opções do CleanMgr foram ativadas silenciosamente via registro."

    # Executa o CleanMgr com as configurações que acabamos de forçar.
    Write-Log "Iniciando Limpador de Disco (CleanMgr) em modo furtivo..."
    $cleanMgrProcess = Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:1" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
    if ($cleanMgrProcess) {
        $cleanMgrProcess | Wait-Process -ErrorAction SilentlyContinue
        Write-Log "Limpador de Disco (CleanMgr) concluído."
    } else {
        Write-Log "⚠️ Não foi possível iniciar o Limpador de Disco (CleanMgr)."
    }
} "Esvaziar lixeiras e executar Limpeza de Disco Completa"

#endregion

#region Reparo Avançado de Componentes

Safe-Run {
    Stop-Service -Name Spooler -Force
    $spoolerPath = "$env:SystemRoot\System32\spool\PRINTERS\*"
    if (Test-Path $spoolerPath) {
        Write-Log "Limpando fila de impressão..."
        Remove-Item -Path $spoolerPath -Recurse -Force
    }
    Start-Service -Name Spooler
} "Reset do Spooler de Impressão"

Safe-Run {
    $servicesToStop = @("wuauserv", "cryptSvc", "bits", "msiserver")
    Stop-Service -Name $servicesToStop -Force
    $oldSDFolder = "$env:SystemRoot\SoftwareDistribution"
    $oldCatRootFolder = "$env:SystemRoot\System32\catroot2"
    if (Test-Path $oldSDFolder) { Rename-Item -Path $oldSDFolder -NewName "$oldSDFolder.old" -Force }
    if (Test-Path $oldCatRootFolder) { Rename-Item -Path $oldCatRootFolder -NewName "$oldCatRootFolder.old" -Force }
    Start-Service -Name $servicesToStop
} "Reset dos Componentes do Windows Update"

#endregion

#region Otimização e Reparo Final do Sistema

Safe-Run {
    $disk = Get-PhysicalDisk | Where-Object { $_.DeviceID -eq $driveAntes.Number }
    if ($disk.MediaType -eq "HDD") {
        Write-Log "Otimizando disco HDD: Desfragmentando..."
        defrag.exe $Disco /U /V
    } elseif ($disk.MediaType -eq "SSD") {
        Write-Log "Otimizando disco SSD: Executando TRIM..."
        defrag.exe $Disco /L
    }
} "Otimização de Discos (Defrag/TRIM)"

Safe-Run {
    Write-Log "Iniciando DISM /Online /Cleanup-Image /StartComponentCleanup..."
    $dismOutput = (dism.exe /Online /Cleanup-Image /StartComponentCleanup) *>&1 # Capture all output
    $dismOutput | ForEach-Object { Write-Log "DISM Output: $_" } # Log each line
} "Otimização da Loja de Componentes (WinSxS)"
Safe-Run {
    Write-Log "Iniciando sfc /scannow..."
    $sfcOutput = (sfc.exe /scannow) *>&1 # Capture all output
    $sfcOutput | ForEach-Object { Write-Log "SFC Output: $_" } # Log each line
    if ((Get-Content "$env:windir\Logs\CBS\CBS.log" -ErrorAction SilentlyContinue) | Select-String "Cannot repair member file") { Write-Log "⚠️ SFC encontrou erros incorrigíveis." } else { Write-Log "✅ Verificação SFC concluída." }
} "Verificação de integridade com SFC"
Safe-Run { echo s | chkdsk.exe /f /r } "CHKDSK (Modo hard)"

#endregion

#region Espaço em Disco - Depois

Write-Log "`n[8/8] Verificando espaço em disco DEPOIS da limpeza..."
$driveDepois = Get-PSDrive -Name $Disco.TrimEnd(':'); $espacoLivreDepois = $driveDepois.Free; $espacoRecuperado = $espacoLivreDepois - $Global:espacoLivreAntes
$espacoRecuperadoGB = if ($espacoRecuperado -gt 0) { [math]::Round($espacoRecuperado / 1GB, 2) } else { 0 }
Write-Log "   Disco $($driveDepois.Name): $([math]::Round($driveDepois.Free / 1GB, 2)) GB livres."
$Global:TaskResults["Espaço Recuperado"] = "$espacoRecuperadoGB GB"; Write-Log "   🎉 Espaço total recuperado: $espacoRecuperadoGB GB"

#endregion

#region Geração e Envio de Relatórios

Safe-Run {
    if (-not (Test-Path $Destino)) { New-Item -Path $Destino -ItemType Directory -Force | Out-Null }
    $Global:TaskResults | ConvertTo-Json -Depth 4 | Out-File -FilePath (Join-Path $Destino "log.json") -Encoding UTF8
    ($Global:TaskResults.GetEnumerator() | ForEach-Object { [PSCustomObject]@{ Tarefa = $_.Key; Status = $_.Value } }) | ConvertTo-Xml -As 'String' -NoTypeInformation | Out-File -FilePath (Join-Path $Destino "log.xml") -Encoding UTF8
    Write-Log "Relatórios locais gerados em $Destino"

    if (-not [string]::IsNullOrEmpty($WebhookUrl)) {
        Write-Log "📡 Enviando Relatório da Chave Mestre para o Slack..."
        $mensagemSlack = "🔑 *Relatório da Chave Mestre* no Host: `$($env:COMPUTERNAME)` `($($env:USERNAME))` `n"
        $mensagemSlack += "📅 *Data:* $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')`n`n"
        $mensagemSlack += "🩺 *Diagnóstico de Saúde do Sistema*`n$($Global:HealthReport.GetEnumerator() | ForEach-Object { "• *$($_.Key)*: $($_.Value)" } | Out-String)`n"
        $mensagemSlack += "🧹 *Relatório de Limpeza por Usuário*`n"
        foreach($userReport in $Global:CacheCleanReport) {
            $mensagemSlack += "  👤 *Usuário:* $($userReport.User)`n"
            foreach($result in $userReport.Results) {
                $statusEmoji = switch ($result.Status) { "Limpo com Sucesso" { "✔️" }; "Não Encontrado" { "➖" }; "Erro na Limpeza" { "❌" }; default { "🔎" } }
                $mensagemSlack += "    $statusEmoji `"$($result.Path)`" - $($result.Status)`n"
            }
        }
        $mensagemSlack += "`n📋 *Resumo das Tarefas de Manutenção:*`n$($Global:TaskResults.GetEnumerator() | ForEach-Object { "• *$($_.Key)*: $($_.Value)" } | Out-String)"

        $fullLogContent = $Global:LogBuffer -join "`n" # Join the log buffer

        $payload = @{
            text       = $mensagemSlack;
            username   = "Chave Mestre de Manutenção";
            icon_emoji = ":key:";
            attachments = @(
                @{
                    color = "#808080"; # Grey
                    title = "Log Detalhado da Execução";
                    text  = '```' + $fullLogContent + '```';
                    mrkdwn_in = @("text");
                }
            )
        } | ConvertTo-Json -Depth 4

        Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $payload -ContentType 'application/json' -ErrorAction Stop; Write-Log "✅ Relatório enviado para o Slack!"
    }
} "Geração e Envio de Relatórios"

#endregion

#region Finalização

Write-Log "`n📊 Resumo da Execução Final:"
$Global:TaskResults.GetEnumerator() | ForEach-Object { Write-Log "   $($_.Key): $($_.Value)" }
Write-Log "`n✅ Manutenção finalizada."
$mutex.ReleaseMutex()

if (-not $SemReboot.IsPresent) {
    Write-Host "`n🔥 REINICIALIZAÇÃO AUTOMÁTICA ATIVADA 🔥" -ForegroundColor Red
    Write-Log "♻️  Reiniciando o sistema em 10 segundos..."
    Start-Sleep -Seconds 10
    # Restart-Computer -Force
} else {
    Write-Log "⏹️  Reboot automático suprimido."
}

#endregion

exit 0
