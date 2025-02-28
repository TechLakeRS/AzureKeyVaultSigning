using namespace System.Security.Cryptography.X509Certificates

function Initialize-AzureEnvironment {
    [CmdletBinding()]
    param()
    
    try {
        # Check if Az.Accounts module version 2.17.0 is installed
        $requiredVersion = "2.17.0"
        $module = Get-Module -ListAvailable -Name Az.Accounts | Where-Object { $_.Version -eq $requiredVersion }
        
        if (-not $module) {
            Write-Host "Az.Accounts module version $requiredVersion not found. Installing..." -ForegroundColor Yellow
            Install-Module -Name Az.Accounts -RequiredVersion $requiredVersion -Scope CurrentUser -Force -AllowClobber
        }
        
        # Import the specific version if it's not already loaded
        if (-not (Get-Module -Name Az.Accounts | Where-Object { $_.Version -eq $requiredVersion })) {
            Write-Host "Loading Az.Accounts module version $requiredVersion..." -ForegroundColor Yellow
            Import-Module Az.Accounts -RequiredVersion $requiredVersion
        }

        # Check if we have a valid context and token
        $context = Get-AzContext
        if ($context) {
            try {
                # Try to get a token to verify the connection is still valid
                $testToken = Get-AzAccessToken -ResourceUrl "https://vault.azure.net" -ErrorAction Stop
                Write-Host "Using existing Azure connection" -ForegroundColor Green
            }
            catch {
                Write-Host "Existing token is invalid. Reconnecting..." -ForegroundColor Yellow
                Disconnect-AzAccount -ErrorAction SilentlyContinue
                Connect-AzAccount
            }
        }
        else {
            Write-Host "No Azure context found. Connecting..." -ForegroundColor Yellow
            Connect-AzAccount
        }

        # Set the specific subscription context
        $subscriptionId = "ENTER_SUBSCRIPTION_ID"
        Write-Host "Setting subscription context..." -ForegroundColor Yellow
        Set-AzContext -Subscription $subscriptionId

        # Verify connection
        $context = Get-AzContext
        if (-not $context) {
            throw "Failed to establish Azure connection"
        }
        
        Write-Host "Azure environment initialized successfully." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to initialize Azure environment: $_"
        return $false
    }
}

function Write-SigningLog {
    param(
        [string]$Message
    )
    
    try {
        $logPath = "enter_path_to_log"
        $logFile = Join-Path $logPath "ScriptSigningLogs.log"
        
        # Create directory if it doesn't exist
        if (-not (Test-Path $logPath)) {
            New-Item -ItemType Directory -Path $logPath -Force | Out-Null
        }
        
        # Create log file if it doesn't exist
        if (-not (Test-Path $logFile)) {
            New-Item -ItemType File -Path $logFile -Force | Out-Null
        }
        
        # Get current user
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        
        # Format the log message with timestamp
        $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$currentUser|$Message"
        
        # Append to log file
        Add-Content -Path $logFile -Value $logMessage
    }
    catch {
        Write-Error "Failed to write to log file: $_"
    }
}

function Sign-Script {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    try {
        # Validate file extension
        $validExtensions = @('.ps1', '.psm1', '.psd1', '.vbs')
        $extension = [System.IO.Path]::GetExtension($FilePath)
        
        if ($extension -notin $validExtensions) {
            $errorMsg = "Invalid file type. Supported file types are: $($validExtensions -join ', ')"
            Write-SigningLog "ERROR: $errorMsg for file: $FilePath"
            throw $errorMsg
        }

        # Validate file exists
        if (-not (Test-Path $FilePath)) {
            $errorMsg = "File not found: $FilePath"
            Write-SigningLog "ERROR: $errorMsg"
            throw $errorMsg
        }

        # Initialize Azure environment
        if (-not (Initialize-AzureEnvironment)) {
            $errorMsg = "Failed to initialize Azure environment. Please check previous errors."
            Write-SigningLog "ERROR: $errorMsg"
            throw $errorMsg
        }
        
        Write-SigningLog "Starting to sign script: $FilePath"

        # Get Key Vault access token
        $token = Get-AzAccessToken -ResourceUrl "ENTER_KEYVAULT_URL"
        $headers = @{
            'Authorization' = "Bearer $($token.Token)"
            'Content-Type' = 'application/json'
        }
        
        # Fixed certificate and secret URIs
        $certUri = ""
        $secretUri = ""
        
        # Get the certificate with private key
        $secretResponse = Invoke-RestMethod -Uri $secretUri -Method GET -Headers $headers
        
        # Convert the PFX data
        $pfxBytes = [Convert]::FromBase64String($secretResponse.value)
        
        # Create certificate object with proper flags
        $cert = [X509Certificate2]::new(
            $pfxBytes,
            "" 
        )
        
        # Sign the file
        $signature = Set-AuthenticodeSignature -FilePath $FilePath -Certificate $cert -HashAlgorithm SHA256 -TimestampServer "http://timestamp.digicert.com"
        
        if ($signature.Status -ne "Valid") {
            $errorMsg = "Signature status is: $($signature.Status)"
            Write-SigningLog "ERROR: $errorMsg for file: $FilePath"
            throw $errorMsg
        }
        
        # Log successful signing
        Write-SigningLog "Successfully signed script: $FilePath with certificate: $($cert.Subject)"
        Write-Host "Successfully signed file: $FilePath" -ForegroundColor Green
        Write-Host "Signature details:" -ForegroundColor Green
        Write-Host "Status: $($signature.Status)" -ForegroundColor Green
        Write-Host "Path: $($signature.Path)" -ForegroundColor Green
        Write-Host "SignerCertificate: $($signature.SignerCertificate.Subject)" -ForegroundColor Green
        
        return $signature
    }
    catch {
    $errorMsg = "Error during script signing: $_"
    Write-SigningLog "ERROR: $errorMsg"
    Write-Error $errorMsg
    if ($_.Exception.InnerException) {
        $innerMsg = "Inner exception: $($_.Exception.InnerException.Message)"
        Write-SigningLog "ERROR: $innerMsg"
        Write-Error $innerMsg
    }

    throw
} finally {
    if ($null -ne $cert) {
        $cert.Dispose()
        Write-SigningLog "Certificate disposed"
    }
 }
}

# Export only the Sign-Script function
Export-ModuleMember -Function Sign-Script
