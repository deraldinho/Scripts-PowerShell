<#
.SYNOPSIS
    A Chave Mestre de Manutenção - Edição Autônoma Definitiva.
.DESCRIPTION
    Versão 100% autônoma, "zero-touch". Executa um diagnóstico completo, limpeza profunda, reparos avançados
    e otimização de disco. Não requer NENHUM parâmetro de linha de comando. A URL do Webhook do Slack é
    uma constante interna. Execute e receba o relatório.
.NOTES
    Autor: Deraldo "Deraldinho" Palomino Filho
    Versão: 24 (Edição Autônoma Definitiva)
    DICA: Para garantir a acentuação correta, salve este arquivo .ps1 com a codificação "UTF-8".
.EXAMPLE
    # Simplesmente execute o script. Ele fará todo o resto.
    .\ChaveMestre-v24.ps1
#>

# --- Bloco principal de execução com tratamento de erro e liberação de Mutex ---
$mutex = New-Object System.Threading.Mutex($false, "Global\ManutencaoChaveMestreAutonoma")
if (!$mutex.WaitOne(0, $false)) {
    Write-Host "⚠️ Instância já em execução. Abortando."
    exit 1
}

try {
    #region Funções auxiliares

    function Write-Log {
        param ([string]$msg)
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $linha = "$timestamp - $msg"
        if ($Global:LogFile) { $linha | Out-File -Append -FilePath $Global:LogFile -Encoding UTF8 }
        Write-Host $linha
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
            $errorMessage = "$($_.Exception.Message) (Linha: $($_.InvocationInfo.ScriptLineNumber))"
            $Global:TaskResults[$Descricao] = "❌ Erro"
            Write-Log "❌ Erro em '$Descricao': $errorMessage"
        }
        $duration = (Get-Date) - $startTime
        Write-Log "⏱️  Tempo gasto: $([math]::Round($duration.TotalSeconds, 2)) segundos"
    }

    #endregion

    #region Validações e Configurações Iniciais

    Write-Host "`n👑 INICIANDO CHAVE MESTRE DE MANUTENÇÃO v24 (Edição Autônoma Definitiva) 👑" -ForegroundColor Green
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Write-Warning "Este script precisa ser executado como ADMINISTRADOR."; exit 1
    }

    # --- Configurações Fixas ---
    $WebhookUrl = "" # Insira a URL do Webhook do Slack aqui para receber relatórios.
    $LogPath = "$env:ProgramData\ManutencaoChaveMestre"
    $Destino = "$([Environment]::GetFolderPath('Desktop'))" # Salva relatórios na área de trabalho
    $Disco = "C:"

    if (-not (Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force | Out-Null }
    $Global:LogFile = Join-Path $LogPath "manutencao_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    
    $Global:TaskResults = [ordered]@{}
    $Global:CacheCleanReport = @()
    $Global:HealthReport = [ordered]@{}

    #endregion

    #region Diagnóstico de Saúde do Sistema
    Write-Log "`n[1/9] Executando Diagnóstico de Saúde do Sistema..."
    Safe-Run {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $Global:HealthReport["Sistema Operacional"] = $osInfo.Caption
        $Global:HealthReport["Memória RAM Total"] = "$([math]::Round($osInfo.TotalVisibleMemorySize / 1MB, 2)) GB"
        $uptime = (Get-Date) - $osInfo.LastBootUpTime
        $Global:HealthReport["Tempo Ligado (Uptime)"] = "$($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"
        $diskHealth = Get-PhysicalDisk | Select-Object FriendlyName, HealthStatus
        $diskHealthStatus = $diskHealth | ForEach-Object { "$($_.FriendlyName): $($_.HealthStatus)" } | Out-String
        $Global:HealthReport["Saúde dos Discos (S.M.A.R.T.)"] = $diskHealthStatus.Trim()
        if (Get-CimInstance -ClassName Win32_Battery) {
            powercfg /batteryreport /output "$LogPath\battery_report.html" /duration 1 | Out-Null
            $xmlReportPath = "$LogPath\battery_report.xml"; powercfg /batteryreport /xml /output $xmlReportPath | Out-Null
            if (Test-Path $xmlReportPath) {
                [xml]$xml = Get-Content $xmlReportPath
                $designCapacity = [double]$xml.BatteryReport.Battery.DesignCapacity
                $fullChargeCapacity = [double]$xml.BatteryReport.Battery.FullChargeCapacity
                $healthPercent = if ($designCapacity -gt 0) { [math]::Round(($fullChargeCapacity / $designCapacity) * 100) } else { 0 }
                $Global:HealthReport["Saúde da Bateria"] = "$healthPercent %"
            }
        } else { $Global:HealthReport["Saúde da Bateria"] = "N/A (Desktop)" }
        $unsignedDrivers = Get-WmiObject Win32_PnPSignedDriver | Where-Object { -not $_.IsSigned } | Select-Object -ExpandProperty DeviceName
        if ($unsignedDrivers) { $Global:HealthReport["Drivers não Assinados"] = ":warning: Encontrados: $($unsignedDrivers -join ', ')" } else { $Global:HealthReport["Drivers não Assinados"] = ":white_check_mark: Nenhum driver não assinado encontrado." }
        $criticalErrors = Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 5 -ErrorAction SilentlyContinue
        if ($criticalErrors) { $Global:HealthReport["Erros Críticos (24h)"] = ":warning: Encontrados $($criticalErrors.Count) erros críticos." } else { $Global:HealthReport["Erros Críticos (24h)"] = ":white_check_mark: Nenhum erro crítico encontrado." }
    } "Diagnóstico de Saúde do Sistema"
    #endregion
    
    #region Espaço em Disco - Antes
    Write-Log "`n[2/9] Verificando espaço em disco ANTES da limpeza..."
    $driveAntes = Get-PSDrive -Name $Disco.TrimEnd(':') -ErrorAction SilentlyContinue
    if (-not $driveAntes) { Write-Warning "Disco $Disco não encontrado. Abortando."; exit 1 }
    $Global:espacoLivreAntes = $driveAntes.Free
    Write-Log "   Disco $($driveAntes.Name): $([math]::Round($driveAntes.Free / 1GB, 2)) GB livres."
    #endregion

    #region Limpeza de Caches de TODOS OS USUÁRIOS
    Safe-Run {
        $caminhosRelativos = @( "AppData\Local\Temp", "AppData\Local\Microsoft\Edge\User Data\Default\Cache", "AppData\Local\Google\Chrome\User Data\Default\Cache", "AppData\Roaming\Mozilla\Firefox\Profiles\*\cache2", "AppData\Local\Slack\Cache", "AppData\Roaming\discord\Cache", "AppData\Local\Microsoft\Teams\Cache", "AppData\Roaming\Spotify\Browser" )
        $userProfiles = Get-ChildItem -Path 'C:\Users' -Directory | Where-Object { Test-Path (Join-Path $_.FullName 'AppData') -and $_.Name -ne 'Default' -and $_.Name -ne 'Public' }
        foreach ($user in $userProfiles) {
            Write-Log "👤 Analisando usuário: $($user.Name)"; $userReport = @{ User = $user.Name; Results = @() }
            foreach ($caminhoPattern in $caminhosRelativos) {
                $fullPathPattern = Join-Path $user.FullName $caminhoPattern; $resolvedPaths = @(Resolve-Path -Path $fullPathPattern -ErrorAction SilentlyContinue)
                if ($resolvedPaths.Count -eq 0) { continue }
                foreach ($fullPath in $resolvedPaths) {
                    $pathResult = @{ Path = $caminhoPattern.Replace("\*", ""); Status = "" }
                    try { Remove-Item -Path "$fullPath\*" -Recurse -Force -ErrorAction Stop; $pathResult.Status = "Limpo com Sucesso"; Write-Log "🧹 Limpo: $fullPath" } catch { $pathResult.Status = "Erro na Limpeza"; Write-Log "⚠️ Erro: $fullPath - $_" }
                    $userReport.Results += $pathResult
                }
            }
            $thumbCachePath = Join-Path $user.FullName "AppData\Local\Microsoft\Windows\Explorer"; $thumbFiles = Get-ChildItem -Path $thumbCachePath -Filter "thumbcache_*.db" -Force -ErrorAction SilentlyContinue
            if ($thumbFiles) { try { $thumbFiles | Remove-Item -Force; Write-Log "🧹 Cache de miniaturas limpo para $($user.Name)." } catch { Write-Log "⚠️ Erro ao limpar miniaturas de $($user.Name)." } }
            $Global:CacheCleanReport += $userReport
        }
    } "Limpeza de Caches (Multi-Usuário e Aplicativos)"
    #endregion

    #region Limpeza Profunda do Sistema
    Safe-Run {
        $limpezaCaminhos = @("$env:SystemRoot\Temp\*", "$env:WINDIR\SoftwareDistribution\Download\*", "$env:ProgramData\Microsoft\Windows\WER\*")
        foreach ($path in $limpezaCaminhos) { if (Test-Path $path) { Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue; Write-Log "🧹 Removido: $path" } }
        Clear-EventLog -LogName Application, System, Security -ErrorAction SilentlyContinue
        Write-Log "ℹ️ Logs de Eventos do Windows (Aplicação, Sistema, Segurança) limpos."
    } "Limpeza de Temporários e Logs de Eventos"
    #endregion
    
    #region Esvaziar lixeiras e CleanMgr Silencioso
    Safe-Run {
        Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ne $null } | ForEach-Object { $recycleBinPath = Join-Path $_.Root '$Recycle.Bin'; if (Test-Path $recycleBinPath) { Get-ChildItem $recycleBinPath -Force -ErrorAction SilentlyContinue | ForEach-Object { Write-Log "🧹 Esvaziando lixeira: $($_.FullName)"; Remove-Item -Path "$($_.FullName)\*" -Recurse -Force -ErrorAction SilentlyContinue } } }
        $volumeCaches = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
        Get-ChildItem -Path $volumeCaches | ForEach-Object { Set-ItemProperty -Path $_.PSPath -Name StateFlags0001 -Value 2 -Type DWord -Force }
        Write-Log "ℹ️ Todas as opções do CleanMgr foram ativadas silenciosamente via registro."
        cleanmgr.exe /sagerun:1; Write-Log "ℹ️  Limpador de Disco (CleanMgr) iniciado em modo furtivo."
    } "Esvaziar lixeiras e executar Limpeza de Disco Completa"
    #endregion

    #region Reparo Avançado de Componentes
    Safe-Run { Stop-Service -Name Spooler -Force; $spoolerPath = "$env:SystemRoot\System32\spool\PRINTERS\*"; if (Test-Path $spoolerPath) { Write-Log "Limpando fila de impressão..."; Remove-Item -Path $spoolerPath -Recurse -Force }; Start-Service -Name Spooler } "Reset do Spooler de Impressão"
    Safe-Run { $servicesToStop = @("wuauserv", "cryptSvc", "bits", "msiserver"); Stop-Service -Name $servicesToStop -Force; $oldSDFolder = "$env:SystemRoot\SoftwareDistribution"; $oldCatRootFolder = "$env:SystemRoot\System32\catroot2"; if (Test-Path $oldSDFolder) { Rename-Item -Path $oldSDFolder -NewName "$oldSDFolder.old" -Force }; if (Test-Path $oldCatRootFolder) { Rename-Item -Path $oldCatRootFolder -NewName "$oldCatRootFolder.old" -Force }; Start-Service -Name $servicesToStop } "Reset dos Componentes do Windows Update"
    Safe-Run { wsreset.exe -q; Get-AppXPackage -AllUsers | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction SilentlyContinue} } "Reset e Re-registro dos Aplicativos da Microsoft Store"
    #endregion

    #region Reparo de Rede e Otimização Final
    Safe-Run { netsh winsock reset | Out-Null; netsh int ip reset | Out-Null; ipconfig /flushdns; ipconfig /registerdns } "Reset e Renovação da Conectividade de Rede"
    Safe-Run { gpupdate /force | Out-Null } "Atualização Forçada de Políticas de Grupo (GPO)"
    Safe-Run { $disk = Get-PhysicalDisk | Where-Object { $_.DeviceID -eq $driveAntes.Number }; if ($disk.MediaType -eq "HDD") { Write-Log "Otimizando disco HDD: Desfragmentando..."; defrag.exe $Disco /U /V } elseif ($disk.MediaType -eq "SSD") { Write-Log "Otimizando disco SSD: Executando TRIM..."; defrag.exe $Disco /L } } "Otimização de Discos (Defrag/TRIM)"
    Safe-Run { dism.exe /Online /Cleanup-Image /StartComponentCleanup } "Otimização da Loja de Componentes (WinSxS)"
    Safe-Run { sfc.exe /scannow | Out-Null; if ((Get-Content "$env:windir\Logs\CBS\CBS.log" -ErrorAction SilentlyContinue) | Select-String "Cannot repair member file") { Write-Log "⚠️ SFC encontrou erros incorrigíveis." } else { Write-Log "✅ Verificação SFC concluída." } } "Verificação de integridade com SFC"
    Safe-Run { chkdsk.exe $Disco /scan } "CHKDSK (Modo Leve /scan)"
    #endregion
    
    #region Espaço em Disco - Depois
    Write-Log "`n[8/9] Verificando espaço em disco DEPOIS da limpeza..."
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
        $htmlHeader = "<style>body{font-family:sans-serif;background-color:#f4f4f4;} table{border-collapse:collapse;width:60%;margin:auto;} th,td{border:1px solid #ddd;padding:8px;text-align:left;} th{background-color:#4CAF50;color:white;}</style>"
        $Global:TaskResults.GetEnumerator() | Select-Object @{Name="Tarefa"; Expression={$_.Key}}, @{Name="Status"; Expression={$_.Value}} | ConvertTo-Html -Head $htmlHeader -Title "Relatório de Manutenção" | Out-File (Join-Path $Destino "relatorio.html") -Encoding UTF8
        Write-Log "Relatórios locais (JSON, XML, HTML) gerados em $Destino"
        if ($WebhookUrl) {
            Write-Log "📡 Enviando Relatório da Chave Mestre para o Slack..."
            $healthReportBlock = ($Global:HealthReport.GetEnumerator() | ForEach-Object { "• *$($_.Key)*: $($_.Value)" }) -join "`n"
            $cacheReportBlock = ""
            foreach($userReport in $Global:CacheCleanReport) {
                $cacheReportBlock += "  :bust_in_silhouette: *Usuário:* $($userReport.User)`n"
                foreach($result in $userReport.Results) {
                    $statusEmoji = switch ($result.Status) { "Limpo com Sucesso" { ":white_check_mark:" }; "Não Encontrado" { ":heavy_minus_sign:" }; "Erro na Limpeza" { ":x:" }; default { ":mag_right:" } }
                    $cacheReportBlock += "    $statusEmoji `"$($result.Path)`" - $($result.Status)`n"
                }
            }
            $tasksReportBlock = ($Global:TaskResults.GetEnumerator() | ForEach-Object { "• *$($_.Key)*: $($_.Value)" }) -join "`n"
            $mensagemSlack = @'
:crown: *Relatório da Chave Mestre Soberana* no Host: `{0}` (`{1}`)
:date: *Data:* {2}

:stethoscope: *Diagnóstico de Saúde do Sistema*
{3}

:broom: *Relatório de Limpeza por Usuário*
{4}
:clipboard: *Resumo das Tarefas de Manutenção:*
{5}
'@ -f $env:COMPUTERNAME, $env:USERNAME, (Get-Date -Format 'dd/MM/yyyy HH:mm:ss'), $healthReportBlock, $cacheReportBlock, $tasksReportBlock
            $payload = @{ text = $mensagemSlack; username = "Chave Mestre Soberana"; icon_emoji = ":crown:" } | ConvertTo-Json -Depth 5 -EscapeHandling 'Unicode'
            Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $payload -ContentType 'application/json' -ErrorAction Stop
            Write-Log "✅ Relatório enviado para o Slack!"
        }
    } "Geração e Envio de Relatórios"
    #endregion
}
finally {
    Write-Log "`n✅ Finalizando execução e liberando o mutex."
    $mutex.ReleaseMutex(); $mutex.Dispose()
}

#region Finalização Externa
# A reinicialização agora é controlada manualmente comentando/descomentando a linha abaixo.
# Por padrão, ela está desativada para segurança.
# Restart-Computer -Force

Write-Log "`n🏁 Script concluído."
exit 0
#endregion
