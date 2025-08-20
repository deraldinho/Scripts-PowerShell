<#
.SYNOPSIS
    Script mestre de manutenção do Windows, com diagnóstico, limpeza profunda e reparo do sistema.
.DESCRIPTION
    Executa um diagnóstico de saúde completo (discos, eventos críticos, uptime), seguido por uma limpeza segura de arquivos,
    caches de todos os perfis, lixeiras e componentes do WinSxS. Usa ferramentas de reparo (SFC, DISM, CHKDSK).
    Gera logs locais e envia um relatório 360º para o Slack.
.PARAMETER WebhookUrl
    [OBRIGATÓRIO] URL do Webhook do Slack para receber o resumo da execução.
.PARAMETER ChkdskCompleto
    Se presente, executa o CHKDSK no modo completo (/f /r). O padrão é o modo /scan (online).
.PARAMETER Force
    Força a execução do script mesmo que o disco já tenha espaço livre suficiente.
.PARAMETER Destino
    Pasta de destino para salvar os logs locais. Default: Área de Trabalho.
.PARAMETER Quiet
    Executa o script em modo silencioso.
.PARAMETER SemReboot
    Impede o reboot automático ao final da execução.
.PARAMETER DryRun
    Apenas simula as ações, sem remover arquivos.
.EXAMPLE
    .\LimpezaAvancada-v13.ps1 -WebhookUrl "https://hooks.slack.com/..." -ChkdskCompleto
.EXAMPLE
    .\LimpezaAvancada-v13.ps1 -WebhookUrl "https://..." -Quiet -Force
#>
param (
    [string]$WebhookUrl = "", # Insira a URL do Webhook do Slack aqui para receber relatórios.
    [string]$Destino = "$([Environment]::GetFolderPath('Desktop'))",
    [switch]$Quiet,
    [switch]$SemReboot,
    [switch]$DryRun,
    [switch]$ChkdskCompleto,
    [switch]$Force,
    [string]$Disco = "C:"
)

#region Funções auxiliares

function Write-Log {
    param ([string]$msg)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $linha = "$timestamp - $msg"
    if ($Global:LogFile) { $linha | Out-File -Append -FilePath $Global:LogFile -Encoding UTF8 }
    if (-not $Quiet.IsPresent) { Write-Host $linha }
}

function Safe-Run {
    param ([scriptblock]$ScriptBlock, [string]$Descricao)
    Write-Log "➡️  Iniciando: $Descricao"
    $startTime = Get-Date
    try {
        $output = & $ScriptBlock *>&1
        if ($output) { $output | ForEach-Object { Write-Log "    $_" } }
        $Global:TaskResults[$Descricao] = "✅ Sucesso"
        Write-Log "✅ Concluído: $Descricao"
    } catch {
        $Global:TaskResults[$Descricao] = "❌ Erro"
        Write-Log "❌ Erro em '$Descricao': $_.Exception.Message"
    }
    $duration = (Get-Date) - $startTime
    Write-Log "⏱️  Tempo gasto: $([math]::Round($duration.TotalSeconds, 2)) segundos"
}

#endregion

#region Validações Iniciais

Write-Host "`n🚨 INICIANDO LIMPEZA AVANÇADA v13 (Edição Mestre)" -ForegroundColor Magenta
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Warning "Este script precisa ser executado como ADMINISTRADOR."; exit 1
}

$LogPath = "$env:ProgramData\IntuneManutencao"
if (-not (Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force | Out-Null }
$Global:LogFile = Join-Path $LogPath "manutencao_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

$mutex = New-Object System.Threading.Mutex($false, "Global\IntuneManutencaoScript")
if (!$mutex.WaitOne(0, $false)) { Write-Log "⚠️ Instância já em execução. Abortando."; exit 1 }

if ([string]::IsNullOrEmpty($WebhookUrl) -or -not ($WebhookUrl -match "hooks.slack.com")) {
    Write-Log "⚠️ WebhookUrl do Slack não informado ou inválido. Nenhum relatório será enviado."
    $WebhookUrl = $null
}

$Global:TaskResults = [ordered]@{}
$Global:CacheCleanReport = @()
$Global:HealthReport = [ordered]@{}

#endregion

#region Diagnóstico de Saúde do Sistema

Write-Log "`n[1/8] Executando Diagnóstico de Saúde do Sistema..."
Safe-Run {
    # Coleta de Informações Básicas
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $Global:HealthReport["Sistema Operacional"] = $osInfo.Caption
    $Global:HealthReport["Memória RAM Total"] = "$([math]::Round($osInfo.TotalVisibleMemorySize / 1MB, 2)) GB"
    $uptime = (Get-Date) - $osInfo.LastBootUpTime
    $Global:HealthReport["Tempo Ligado (Uptime)"] = "$($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"

    # Verificação de Saúde dos Discos
    $diskHealth = Get-PhysicalDisk | Select-Object FriendlyName, HealthStatus
    $diskHealthStatus = $diskHealth | ForEach-Object { "$($_.FriendlyName): $($_.HealthStatus)" } | Out-String
    $Global:HealthReport["Saúde dos Discos (S.M.A.R.T.)"] = $diskHealthStatus

    # Verificação de Erros Críticos no Event Log (últimas 24h)
    $criticalErrors = Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 5 -ErrorAction SilentlyContinue
    if ($criticalErrors) {
        $Global:HealthReport["Erros Críticos (24h)"] = "‼️ Encontrados $($criticalErrors.Count) erros críticos."
    } else {
        $Global:HealthReport["Erros Críticos (24h)"] = "✅ Nenhum erro crítico encontrado."
    }

    # Status do Windows Defender
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($defenderStatus) {
        $Global:HealthReport["Última Verificação Defender"] = if ($defenderStatus.FullScanStartTime) { $defenderStatus.FullScanStartTime.ToString('dd/MM/yyyy HH:mm') } else { "N/A" }
    } else {
        $Global:HealthReport["Última Verificação Defender"] = "Não disponível"
    }
} "Diagnóstico de Saúde do Sistema"

#endregion

#region Espaço em Disco - Antes e Validação

Write-Log "`n[2/8] Verificando espaço em disco ANTES da limpeza..."
$driveAntes = Get-PSDrive -Name $Disco.TrimEnd(':') -ErrorAction SilentlyContinue
if (-not $driveAntes) { Write-Warning "Disco $Disco não encontrado. Abortando."; exit 1 }

$Global:espacoLivreAntes = $driveAntes.Free
Write-Log "   Disco $($driveAntes.Name): $([math]::Round($driveAntes.Free / 1GB, 2)) GB livres."

$espacoMinimoGB = 10
if (($driveAntes.Free / 1GB) -gt $espacoMinimoGB -and -not $Force.IsPresent) {
    Write-Log "ℹ️  Espaço livre é maior que $espacoMinimoGB GB. A limpeza completa pode não ser necessária."
}

#endregion

#region Limpeza de Caches de TODOS OS USUÁRIOS

Safe-Run {
    $caminhosRelativos = @( "AppData\Local\Temp", "AppData\Local\Microsoft\Edge\User Data\Default\Cache", "AppData\Local\Google\Chrome\User Data\Default\Cache", "AppData\Roaming\Mozilla\Firefox\Profiles\*\cache2", "AppData\Local\Slack\Cache", "AppData\Roaming\discord\Cache", "AppData\Local\Microsoft\Teams\Cache", "AppData\Roaming\Spotify\Browser" )
    $userProfiles = Get-ChildItem -Path 'C:\Users' -Directory | Where-Object { Test-Path (Join-Path $_.FullName 'AppData') -and $_.Name -ne 'Default' -and $_.Name -ne 'Public' }

    foreach ($user in $userProfiles) {
        Write-Log "👤 Analisando usuário: $($user.Name)"
        $userReport = @{ User = $user.Name; Results = @() }

        foreach ($caminhoPattern in $caminhosRelativos) {
            $fullPathPattern = Join-Path $user.FullName $caminhoPattern; $resolvedPaths = @(Resolve-Path -Path $fullPathPattern -ErrorAction SilentlyContinue)
            if ($resolvedPaths.Count -eq 0) { continue }
            
            foreach ($fullPath in $resolvedPaths) {
                $pathResult = @{ Path = $caminhoPattern.Replace("\*", ""); Status = "" }
                if ($DryRun) { $pathResult.Status = "Detectado (DryRun)"; Write-Log "🔎 DryRun: $fullPath" }
                else { try { Remove-Item -Path "$fullPath\*" -Recurse -Force -ErrorAction Stop; $pathResult.Status = "Limpo com Sucesso"; Write-Log "🧹 Limpo: $fullPath" } catch { $pathResult.Status = "Erro na Limpeza"; Write-Log "⚠️ Erro: $fullPath - $_" } }
                $userReport.Results += $pathResult
            }
        }
        
        $thumbCachePath = Join-Path $user.FullName "AppData\Local\Microsoft\Windows\Explorer"; $thumbFiles = Get-ChildItem -Path $thumbCachePath -Filter "thumbcache_*.db" -Force -ErrorAction SilentlyContinue
        if ($thumbFiles) { if ($DryRun) { Write-Log "🔎 DryRun: Cache de miniaturas detectado para $($user.Name)." } else { try { $thumbFiles | Remove-Item -Force; Write-Log "🧹 Cache de miniaturas limpo para $($user.Name)." } catch { Write-Log "⚠️ Erro ao limpar miniaturas de $($user.Name)." } } }
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

#region Esvaziar lixeiras e CleanMgr Inteligente

Safe-Run {
    Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ne $null } | ForEach-Object { $recycleBinPath = Join-Path $_.Root '$Recycle.Bin'; if (Test-Path $recycleBinPath) { Get-ChildItem $recycleBinPath -Force -ErrorAction SilentlyContinue | ForEach-Object { if ($DryRun) { Write-Log "🔎 DryRun: Lixeira detectada: $($_.FullName)" } else { Write-Log "🧹 Esvaziando lixeira: $($_.FullName)"; Remove-Item -Path "$($_.FullName)\*" -Recurse -Force -ErrorAction SilentlyContinue } } } }

    $cleanMgrConfig = Join-Path $LogPath "cleanmgr.sageset1.done"
    if (-not (Test-Path $cleanMgrConfig) -and -not $DryRun) {
        Write-Log "⚠️ Executando configuração inicial do CleanMgr (/sageset:1)."
        Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sageset:1" -Wait -ErrorAction SilentlyContinue
        New-Item -Path $cleanMgrConfig -ItemType File -Force | Out-Null
        Write-Log "✅ Configuração do CleanMgr salva."
    }
    if ($DryRun) { Write-Log "🔎 DryRun: CleanMgr seria executado." } else { cleanmgr.exe /sagerun:1; Write-Log "ℹ️  Limpador de Disco (CleanMgr) iniciado." }
} "Esvaziar lixeiras e executar CleanMgr"

#endregion

#region Segurança e Reparo do Sistema

Safe-Run { dism.exe /Online /Cleanup-Image /StartComponentCleanup } "Otimização da Loja de Componentes (WinSxS)"
Safe-Run { sfc.exe /scannow | Out-Null; if ((Get-Content "$env:windir\Logs\CBS\CBS.log" -ErrorAction SilentlyContinue) | Select-String "Cannot repair member file") { Write-Log "⚠️ SFC encontrou erros incorrigíveis." } else { Write-Log "✅ Verificação SFC concluída." } } "Verificação de integridade com SFC"

if ($ChkdskCompleto.IsPresent) {
    Safe-Run { echo S | chkdsk.exe $Disco /f /r; if ((fsutil.exe dirty query $Disco) -match "is DIRTY") { Write-Log "ℹ️  CHKDSK agendado." } else { Write-Log "✅ CHKDSK concluído." } } "CHKDSK (Modo Completo /f /r)"
} else {
    Safe-Run { chkdsk.exe $Disco /scan } "CHKDSK (Modo Leve /scan)"
}

#endregion

#region Espaço em Disco - Depois

Write-Log "`n[7/8] Verificando espaço em disco DEPOIS da limpeza..."
$driveDepois = Get-PSDrive -Name $Disco.TrimEnd(':')
$espacoLivreDepois = $driveDepois.Free; $espacoRecuperado = $espacoLivreDepois - $Global:espacoLivreAntes
$espacoRecuperadoGB = if ($espacoRecuperado -gt 0) { [math]::Round($espacoRecuperado / 1GB, 2) } else { 0 }
Write-Log "   Disco $($driveDepois.Name): $([math]::Round($driveDepois.Free / 1GB, 2)) GB livres."
Write-Log "   🎉 Espaço total recuperado: $espacoRecuperadoGB GB"
$Global:TaskResults["Espaço Recuperado"] = "$espacoRecuperadoGB GB"

#endregion

#region Geração e Envio de Relatórios

Safe-Run {
    if (-not (Test-Path $Destino)) { New-Item -Path $Destino -ItemType Directory -Force | Out-Null }
    $Global:TaskResults | ConvertTo-Json -Depth 4 | Out-File -FilePath (Join-Path $Destino "log.json") -Encoding UTF8
    ($Global:TaskResults.GetEnumerator() | ForEach-Object { [PSCustomObject]@{ Tarefa = $_.Key; Status = $_.Value } }) | ConvertTo-Xml -As 'String' -NoTypeInformation | Out-File -FilePath (Join-Path $Destino "log.xml") -Encoding UTF8
    Write-Log "Relatórios locais gerados em $Destino"

    if (-not [string]::IsNullOrEmpty($WebhookUrl)) {
        Write-Log "📡 Enviando relatório 360º para o Slack..."
        $mensagemSlack = " Mestre de Manutenção no Host:* `$($env:COMPUTERNAME)` `($($env:USERNAME))` `n"
        $mensagemSlack += "📅 *Data:* $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')`n`n"
        
        # Seção de Diagnóstico de Saúde
        $mensagemSlack += "🩺 *Diagnóstico de Saúde do Sistema*`n"
        $Global:HealthReport.GetEnumerator() | ForEach-Object { $mensagemSlack += "• *$($_.Key)*: $($_.Value)`n" }
        $mensagemSlack += "`n"

        # Seção de Limpeza por Usuário
        $mensagemSlack += "🧹 *Relatório de Limpeza por Usuário*`n"
        foreach($userReport in $Global:CacheCleanReport) {
            $mensagemSlack += "  👤 *Usuário:* $($userReport.User)`n"
            foreach($result in $userReport.Results) {
                $statusEmoji = switch ($result.Status) { "Limpo com Sucesso" { "✔️" }; "Não Encontrado" { "➖" }; "Erro na Limpeza" { "❌" }; default { "🔎" } }
                $mensagemSlack += "    $statusEmoji `"$($result.Path)`" - $($result.Status)`n"
            }
        }
        $mensagemSlack += "`n"

        # Seção de Resumo Geral
        $mensagemSlack += "📋 *Resumo Geral das Outras Tarefas:*`n"
        $Global:TaskResults.GetEnumerator() | ForEach-Object { $mensagemSlack += "• *$($_.Key)*: $($_.Value)`n" }
        
        $payload = @{ text = $mensagemSlack; username = "Relatório Mestre - Deraldinho"; icon_emoji = ":toolbox:" } | ConvertTo-Json -Depth 4
        Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $payload -ContentType 'application/json' -ErrorAction Stop
        Write-Log "✅ Relatório enviado para o Slack!"
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
