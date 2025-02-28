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


# SIG # Begin signature block
# MIInjQYJKoZIhvcNAQcCoIInfjCCJ3oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC9vF/NkE8EyLff
# zGL3WJKBuw5nmC6XpvKrKt0tImoyA6CCIaQwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggauMIIElqADAgECAhAHNje3JFR82Ees/ShmKl5bMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yMjAzMjMwMDAwMDBaFw0zNzAzMjIyMzU5NTlaMGMx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMy
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcg
# Q0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDGhjUGSbPBPXJJUVXH
# JQPE8pE3qZdRodbSg9GeTKJtoLDMg/la9hGhRBVCX6SI82j6ffOciQt/nR+eDzMf
# UBMLJnOWbfhXqAJ9/UO0hNoR8XOxs+4rgISKIhjf69o9xBd/qxkrPkLcZ47qUT3w
# 1lbU5ygt69OxtXXnHwZljZQp09nsad/ZkIdGAHvbREGJ3HxqV3rwN3mfXazL6IRk
# tFLydkf3YYMZ3V+0VAshaG43IbtArF+y3kp9zvU5EmfvDqVjbOSmxR3NNg1c1eYb
# qMFkdECnwHLFuk4fsbVYTXn+149zk6wsOeKlSNbwsDETqVcplicu9Yemj052FVUm
# cJgmf6AaRyBD40NjgHt1biclkJg6OBGz9vae5jtb7IHeIhTZgirHkr+g3uM+onP6
# 5x9abJTyUpURK1h0QCirc0PO30qhHGs4xSnzyqqWc0Jon7ZGs506o9UD4L/wojzK
# QtwYSH8UNM/STKvvmz3+DrhkKvp1KCRB7UK/BZxmSVJQ9FHzNklNiyDSLFc1eSuo
# 80VgvCONWPfcYd6T/jnA+bIwpUzX6ZhKWD7TA4j+s4/TXkt2ElGTyYwMO1uKIqjB
# Jgj5FBASA31fI7tk42PgpuE+9sJ0sj8eCXbsq11GdeJgo1gJASgADoRU7s7pXche
# MBK9Rp6103a50g5rmQzSM7TNsQIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB
# /wIBADAdBgNVHQ4EFgQUuhbZbU2FL3MpdpovdYxqII+eyG8wHwYDVR0jBBgwFoAU
# 7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoG
# CCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDig
# NqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZI
# hvcNAQELBQADggIBAH1ZjsCTtm+YqUQiAX5m1tghQuGwGC4QTRPPMFPOvxj7x1Bd
# 4ksp+3CKDaopafxpwc8dB+k+YMjYC+VcW9dth/qEICU0MWfNthKWb8RQTGIdDAiC
# qBa9qVbPFXONASIlzpVpP0d3+3J0FNf/q0+KLHqrhc1DX+1gtqpPkWaeLJ7giqzl
# /Yy8ZCaHbJK9nXzQcAp876i8dU+6WvepELJd6f8oVInw1YpxdmXazPByoyP6wCeC
# RK6ZJxurJB4mwbfeKuv2nrF5mYGjVoarCkXJ38SNoOeY+/umnXKvxMfBwWpx2cYT
# gAnEtp/Nh4cku0+jSbl3ZpHxcpzpSwJSpzd+k1OsOx0ISQ+UzTl63f8lY5knLD0/
# a6fxZsNBzU+2QJshIUDQtxMkzdwdeDrknq3lNHGS1yZr5Dhzq6YBT70/O3itTK37
# xJV77QpfMzmHQXh6OOmc4d0j/R0o08f56PGYX/sr2H7yRp11LB4nLCbbbxV7HhmL
# NriT1ObyF5lZynDwN7+YAN8gFk8n+2BnFqFmut1VwDophrCYoCvtlUG3OtUVmDG0
# YgkPCr2B2RP+v6TR81fZvAT6gt4y3wSJ8ADNXcL50CN/AAvkdgIm2fBldkKmKYcJ
# RyvmfxqkhQ/8mJb2VVQrH4D6wPIOK+XW+6kvRBVK5xMOHds3OBqhK/bt1nz8MIIG
# vDCCBKSgAwIBAgIQC65mvFq6f5WHxvnpBOMzBDANBgkqhkiG9w0BAQsFADBjMQsw
# CQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRp
# Z2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENB
# MB4XDTI0MDkyNjAwMDAwMFoXDTM1MTEyNTIzNTk1OVowQjELMAkGA1UEBhMCVVMx
# ETAPBgNVBAoTCERpZ2lDZXJ0MSAwHgYDVQQDExdEaWdpQ2VydCBUaW1lc3RhbXAg
# MjAyNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL5qc5/2lSGrljC6
# W23mWaO16P2RHxjEiDtqmeOlwf0KMCBDEr4IxHRGd7+L660x5XltSVhhK64zi9Ce
# C9B6lUdXM0s71EOcRe8+CEJp+3R2O8oo76EO7o5tLuslxdr9Qq82aKcpA9O//X6Q
# E+AcaU/byaCagLD/GLoUb35SfWHh43rOH3bpLEx7pZ7avVnpUVmPvkxT8c2a2yC0
# WMp8hMu60tZR0ChaV76Nhnj37DEYTX9ReNZ8hIOYe4jl7/r419CvEYVIrH6sN00y
# x49boUuumF9i2T8UuKGn9966fR5X6kgXj3o5WHhHVO+NBikDO0mlUh902wS/Eeh8
# F/UFaRp1z5SnROHwSJ+QQRZ1fisD8UTVDSupWJNstVkiqLq+ISTdEjJKGjVfIcsg
# A4l9cbk8Smlzddh4EfvFrpVNnes4c16Jidj5XiPVdsn5n10jxmGpxoMc6iPkoaDh
# i6JjHd5ibfdp5uzIXp4P0wXkgNs+CO/CacBqU0R4k+8h6gYldp4FCMgrXdKWfM4N
# 0u25OEAuEa3JyidxW48jwBqIJqImd93NRxvd1aepSeNeREXAu2xUDEW8aqzFQDYm
# r9ZONuc2MhTMizchNULpUEoA6Vva7b1XCB+1rxvbKmLqfY/M/SdV6mwWTyeVy5Z/
# JkvMFpnQy5wR14GJcv6dQ4aEKOX5AgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMC
# B4AwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAE
# GTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3Mp
# dpovdYxqII+eyG8wHQYDVR0OBBYEFJ9XLAN3DigVkGalY17uT5IfdqBbMFoGA1Ud
# HwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUF
# BwEBBIGDMIGAMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20w
# WAYIKwYBBQUHMAKGTGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZI
# hvcNAQELBQADggIBAD2tHh92mVvjOIQSR9lDkfYR25tOCB3RKE/P09x7gUsmXqt4
# 0ouRl3lj+8QioVYq3igpwrPvBmZdrlWBb0HvqT00nFSXgmUrDKNSQqGTdpjHsPy+
# LaalTW0qVjvUBhcHzBMutB6HzeledbDCzFzUy34VarPnvIWrqVogK0qM8gJhh/+q
# DEAIdO/KkYesLyTVOoJ4eTq7gj9UFAL1UruJKlTnCVaM2UeUUW/8z3fvjxhN6hdT
# 98Vr2FYlCS7Mbb4Hv5swO+aAXxWUm3WpByXtgVQxiBlTVYzqfLDbe9PpBKDBfk+r
# abTFDZXoUke7zPgtd7/fvWTlCs30VAGEsshJmLbJ6ZbQ/xll/HjO9JbNVekBv2Tg
# em+mLptR7yIrpaidRJXrI+UzB6vAlk/8a1u7cIqV0yef4uaZFORNekUgQHTqddms
# PCEIYQP7xGxZBIhdmm4bhYsVA6G2WgNFYagLDBzpmk9104WQzYuVNsxyoVLObhx3
# RugaEGru+SojW4dHPoWrUhftNpFC5H7QEY7MhKRyrBe7ucykW7eaCuWBsBb4HOKR
# FVDcrZgdwaSIqMDiCLg4D+TPVgKx2EgEdeoHNHT9l3ZDBD+XgbF+23/zBjeCtxz+
# dL/9NWR6P2eZRi7zcEO1xwcdcqJsyz/JceENc2Sg8h3KeFUCS7tpFk7CrDqkMIIH
# MzCCBRugAwIBAgIQZgybEpoKbCFVCTjdVKDtLTANBgkqhkiG9w0BAQsFADBTMQsw
# CQYDVQQGEwJFVTEpMCcGA1UECgwgRVVST1BFQU4gU1lTVEVNIE9GIENFTlRSQUwg
# QkFOS1MxGTAXBgNVBAMMEEVTQ0ItUEtJIFJPT1QgQ0EwIBgPMjAxMTA3MjIxMDQ2
# MzVaFw0yNjA3MjIxMDQ2MzVaMFUxCzAJBgNVBAYTAkVVMSkwJwYDVQQKDCBFVVJP
# UEVBTiBTWVNURU0gT0YgQ0VOVFJBTCBCQU5LUzEbMBkGA1UEAwwSRVNDQi1QS0kg
# T05MSU5FIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0m/LhkKz
# QSfOJdqFphnmA/mj3zuy8eZ8LuT4VgmPHV0pSivWaCCY0KLYXdhJTF7s9pJvGLca
# QTJeGID4inupwfB/P4pbKveBl3OEBkjGjMXNXlfk75WMapThdtGkPBI7XpI8buVl
# rdyPOMEN51PRviJqv4vj6awv6CiUGySXT+8UeJynOQ/DmLcmJ8NeVaPCmUnzATc2
# WLtYGjL3sStuxKzGQNwnXFwGYSGsmpH29c3E8Ucn4dxs15iBEct4JfYnW6THW8oK
# fXDYR4jEVMaTENH1GOJSmYMEfmDcLxLs3k8ZlnwTwQGJj7BC985LKsznURi7QlP5
# X6YVMad9+2/UZI0RiNTiug9cWiWjNvII5xB59XrBStEFb4X9iZigC2hOYD8bRe8T
# PdhPbhHqsN6KlwrpCph98t9RhmguUoT6RSg46HYZm+aqBqf2HrEDvkq7k7pp59dm
# cPrO8kkJS7mD1G0B/LWQ62OqpL6ASLCW+UmKEixUcROV/qPFemb3QKexdBx68axX
# exuUodhpjG5PSlkeB95nXoiRle3U6UpeTet4wifMm2REdR14MQ/SfMuVB0O+nsi+
# SWky/xSccVFz5g2IrRu+EXSxZ8lr32A1HtWxxR8mi2v9Lsodsf60Pq+bp9rd5fWe
# pqbbEA1BVs7VDfFA5pJPRGpEAwIXZLvcb7kCAwEAAaOCAf0wggH5MA8GA1UdEwEB
# /wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBTkWd5EJLakPINDNyiw
# yKSuJi09AzAfBgNVHSMEGDAWgBTVhR1pY5coyVnm0WcHzVS83AJ+6jA8BgNVHSAE
# NTAzMDEGBFUdIAAwKTAnBggrBgEFBQcCARYbaHR0cDovL3BraS5lc2NiLmV1L3Bv
# bGljaWVzMD8GCCsGAQUFBwEBBDMwMTAvBggrBgEFBQcwAoYjaHR0cDovL3BraS5l
# c2NiLmV1L2NlcnRzL3Jvb3RDQS5jcnQwggEVBgNVHR8EggEMMIIBCDCCAQSgggEA
# oIH9hiJodHRwOi8vcGtpLmVzY2IuZXUvY3Jscy9yb290Q0EuY3JshoGObGRhcDov
# L2xkYXAtcGtpLmVzY2IuZXUvQ049RVNDQi1QS0klMjBSb290JTIwQ0EsT1U9UEtJ
# LE9VPUVTQ0ItUEtJLE89RVNDQixDPUVVP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxp
# c3Q/YmFzZT9vYmplY3RjbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludIYmaHR0cDov
# L2lhbS1jcmwuZXNjYi5ldS9lc2NiL3Jvb3RDQS5jcmyGHmh0dHA6Ly9lc2NicGtp
# L2NybHMvcm9vdENBLmNybDANBgkqhkiG9w0BAQsFAAOCAgEANKj8sGwW5pc+iKwA
# KrVTTKaAq/8kJrFq05p+hncEokBnivD0PdVz+NycTcufpkaz/Mv7Pldtf2/7pUSN
# FDlVTauu7nXz2G4c53uHqSatNOCTLw/L9Nx74/uh9iUTYW3OlON6qnKY0oeyPyID
# nwbqVlfS5W0GL5sChEUhIbsU8EduTaEsC9Yo3KfaIn77W9S3UxdF7bH3I6Fc01wh
# 1ELoG2clRYvDEMAHtROxKDHgFz9oIZN8MKwzcIqIWijspMzd6JYdpI2U3U+3lFpL
# BwWJPixFcIkZzoRukbgV6cgFS82oqdMe5ye35T36nsg8BYuxZivGMwfwC36HkoSa
# n5KyfFnXcpiFpndmw5kQNu7hgpkcoEuxVjTl4PTWXHdKmTmpl3+9jsKKmTL7Ol7Z
# v37qCcPnOyvfV2y7cOu+kxGZR+dJ4Uso7/S/bkZRd+OUo9qW2fRf3Q02tWfZ0EO4
# qn78soBe6FMS40lRLXoyIDdVsy4Whf33TGoLB4YLfl5MyjEuXTIe+PgWqQKlt1JM
# Gxm4PSF2rvasBXGeVQmd5Xln4Pj0TTYONJG830ybAMqX/1WRP2b6F9/sRB793IqU
# tXQcywf+pU2E36FMwxCYET259d6cm5IyZ7qkHtc2wQIK+qTBbKmw8WZPUKGZxz4i
# RIzXQcBw+KhcoaVEcra6SjC3VVwwggdmMIIFTqADAgECAhBuEy7ZziR69mVmBTcP
# 7a7OMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNVBAYTAkVVMSkwJwYDVQQKDCBFVVJP
# UEVBTiBTWVNURU0gT0YgQ0VOVFJBTCBCQU5LUzEbMBkGA1UEAwwSRVNDQi1QS0kg
# T05MSU5FIENBMB4XDTIzMTEyODE1MjAyM1oXDTI2MDcyMjEwNDYzNVowgYAxCzAJ
# BgNVBAYTAkJFMSkwJwYDVQQKDCBFVVJPUEVBTiBTWVNURU0gT0YgQ0VOVFJBTCBC
# QU5LUzEmMCQGA1UECwwdTmF0aW9uYWwgQmFuayBvZiBCZWxnaXVtIChCRSkxHjAc
# BgNVBAMMFU5CQiBEaWdpdGFsIFdvcmtwbGFjZTCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBALM003OjqGQSRvtt/zMJfPePoEg+z6b5xwKWdZgTALtJaJV9
# Q78Wv2ust0i3NkPNiFiTow1yymp6KAR5W9AcgnfV1Tljn7BrxoKUErcoNLDlNoCg
# Ch22E+mgC5fq+/RbfY5uc/wz2UbVoZ+ssg0+gUhpgNazvAEkVsjiCexK6U2FzoLL
# IlUMjelnYzJQCvQGNm+95m3RSm4CfIu5k3pL8+JPxhpb9lQGF/r4uRalTRZqFkt1
# BIpo10FOJklEmwJNHfmBErYDUWk4IQY3XR/jlj1Tb3QSjHCeq7sAYY1z4XfAICBg
# VpWYBWkEHr1SrAyt5JcScIFlDF7yx9lbUlnHB/UCAwEAAaOCAwQwggMAMCIGA1Ud
# EQQbMBmBF2RpZ2l0YWx3b3JrcGxhY2VAbmJiLmJlMA4GA1UdDwEB/wQEAwIHgDAW
# BgNVHSUBAf8EDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUXdB63ft2T/3SQwRb1ndJ
# w+kIBwQwHwYDVR0jBBgwFoAU5FneRCS2pDyDQzcosMikriYtPQMwQQYDVR0gBDow
# ODA2BgkEAH8ACgECBAMwKTAnBggrBgEFBQcCARYbaHR0cDovL3BraS5lc2NiLmV1
# L3BvbGljaWVzMIHcBggrBgEFBQcBAQSBzzCBzDAvBggrBgEFBQcwAoYjaHR0cDov
# L3BraS5lc2NiLmV1L2NlcnRzL3Jvb3RDQS5jcnQwLgYIKwYBBQUHMAKGImh0dHA6
# Ly9wa2kuZXNjYi5ldS9jZXJ0cy9zdWJDQS5jcnQwHwYIKwYBBQUHMAGGE2h0dHA6
# Ly9vY3NwLWVzY2Jwa2kwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLXBraS5lc2Ni
# LmV1MCMGCCsGAQUFBzABhhdodHRwOi8vaWFtLW9jc3AuZXNjYi5ldTAcBggEAH8A
# CgEDAgQQQkFOQ08gREUgRVNQQcORQTAbBggEAH8ACgEDAwQPVkFURVMtUTI4MDI0
# NzJHMIIBEwYDVR0fBIIBCjCCAQYwggECoIH/oIH8hh1odHRwOi8vZXNjYnBraS9j
# cmxzL3N1YkNBLmNybIYhaHR0cDovL3BraS5lc2NiLmV1L2NybHMvc3ViQ0EuY3Js
# hoGQbGRhcDovL2xkYXAtcGtpLmVzY2IuZXUvQ049RVNDQi1QS0klMjBPTkxJTkUl
# MjBDQSxPVT1QS0ksT1U9RVNDQi1QS0ksTz1FU0NCLEM9RVU/Y2VydGlmaWNhdGVS
# ZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdGNsYXNzPWNSTERpc3RyaWJ1dGlvblBv
# aW50hiVodHRwOi8vaWFtLWNybC5lc2NiLmV1L2VzY2Ivc3ViQ0EuY3JsMA0GCSqG
# SIb3DQEBCwUAA4ICAQAP1aH0XkPy1W+Tm5bzszcJVxkcJGD20CVxn+bhvPz+oGSW
# AVid7z0LJ67HIdQ89JjRjQMycUMg1VWInsCScm2e3UobHqaSR7LfTz+GY06G1Zqa
# umHc1Np+V6NwukzHpFeLCwqX1uzAoinJqNI6lBdfny9AEqhdZ4mArvhn2v+V+Vqa
# 8/jSgsPnFYrsoOTjzPaz1QPPfwswoDi407KA5HMAxnuiQPlNtCgoBaAeJrRpVv4b
# hw/JWTdiRTBlsLps8CzSVUxSm+n5/VT9ONS+JkUcHQ6xUEzujVNOYHLhRrlo1Yyw
# BNG8gu+nPvsDdchfdUldFoNlW6JOa0NYJCdhEeSpmkTjFsV4YPGUo7W4JtxemNZA
# +WA64EwIY3nFlN4xAy14c/IjYmjz3R1OK6GvO7HDZp5Iw4nx348qaef2bt0LQ9Vn
# YfRy8s6E1xw3oahQFqAzTaQoeTzLrd5wxrMNdNaGjaNQoXLMvc+wQfDu6cYRjA/i
# dOfGPSXFDivv6bI+f2sHGvuDvq2YNPyZfOOcw66aqGBxMxXrXOdWm1zIsNtv3Gb1
# 68MJqfsjVGyIymcxdL1cArHX6G8v3EqKn2cSGdr1atAvM4V5uflfLh2lcE8MIoCj
# TD3+oTLolSV/MopGnID7EDnRYSt/NRX12uC5pVsYey2Ec8GTIAmSpweNgI/xezGC
# BT8wggU7AgEBMGkwVTELMAkGA1UEBhMCRVUxKTAnBgNVBAoMIEVVUk9QRUFOIFNZ
# U1RFTSBPRiBDRU5UUkFMIEJBTktTMRswGQYDVQQDDBJFU0NCLVBLSSBPTkxJTkUg
# Q0ECEG4TLtnOJHr2ZWYFNw/trs4wDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGC
# NwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgtJ1pGwNI
# YSLOxiB/JyU7rY8J9esDdtHiHPdP0blATPgwDQYJKoZIhvcNAQEBBQAEggEAINUc
# DXFqa7fXlPHFujkpnR8Dp1r4DU2JMESp+9gbtqpg0ZqiKn7M128C6mpF5ogy5HJc
# V7Qhan7RDaszM92Yupt9gXZ1AzSV9XnaKaHb0oZmUf03ZhbPokMrBn/tjumRqlsx
# KYy3roy9gX3ZZ2FHWf4SaNkrQb9lVjygI2WQblQH+QDY2V08TBrgTSYCNMXSYPbE
# P48efy/azmLEuPTiEd1qB5CsBvOY5UqSXJ3+Jc9yoO1KybQORLCUM9VRGZ6wMgdT
# R/nWq9M735llEpcUWs7U/B9luTS0WX4V8zAY+7yUcIgl/+t1x8o4T4XrhcBWDTQr
# w6sWABwQMuXaqw4UDKGCAyAwggMcBgkqhkiG9w0BCQYxggMNMIIDCQIBATB3MGMx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMy
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcg
# Q0ECEAuuZrxaun+Vh8b56QTjMwQwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNTAyMTcxMzA4NTVaMC8G
# CSqGSIb3DQEJBDEiBCDEe7q+y9DI8lEbX/Kf0yTmm0i21cT7GU4Aj7QyV850CjAN
# BgkqhkiG9w0BAQEFAASCAgC5WCm1Fdr3MUYOc39vpgP5CXiccNcZ2lbGlt/N9Gv2
# +2VXRJ5bCzr0lrG3tN8lijtfwSzv8hunmgMVDijCCaJ82PsMiBkxBv5dlXIDLf5y
# eizc8pQtnDZwXI9xcCw+y7ErcS648VV8nv9ZU4k4WygZmMIuIJzcKolnvqc6d1ho
# bc7bX3gsl2ZrnPLFSE/Ax2HcwxX87nklYu8ousR3OnkcLOI5/r3i+upbiNfIQ96v
# tgvaHbvqlFzv07FBTjU8x8R/DmSqdBIVmF1gxpj6MFrctO2SQEO1bDOSi4DsYDyp
# 57io4XJIloSJA78UM03Py9TifoUVOMRNcKVJoKhPU3caLYkAQ+L8C322qZivf0aV
# 59VJtxBNoiYh6Dm9j9npXrYKMtmNjCaFQXzkUkn8x4t9C1Y0GOfCltvDny+sr2xH
# nRNhft8LnYFOYRBghTOS3nMsYgx9jCNggKGDrjTpMEkjs+6A4h3YKOcb5yXpldOb
# pkWtpqFotigr397uvxsuDhwZXP74knc1RyXdI2PPU/cOb0TyOKtvnrI9ZOi/BGPs
# Io22jQbW4sAECJ1qpJzeIjcNWk50DeQi9epgVShhf61NtT/D+/PKz6X7eGc+13Bl
# EhJX3oRYwUDURrc2pJfVHkOe+vYSkgGtOghhSfrxExH8KNcVnAyHlWwgO03BqnAL
# xQ==
# SIG # End signature block
