<#
.SYNOPSIS
    Create a TPM/CNG-backed certificate for Entra ID application authentication.

.DESCRIPTION
    Creates a self-signed RSA certificate in the Windows certificate store with
    the properties Entra ID (Azure AD) application certificate auth requires:

      * a non-exportable private key (the key never leaves the device);
      * a CNG / NCrypt key -- by default in the TPM via the Microsoft Platform
        Crypto Provider, so signing happens on the chip;
      * Digital Signature key usage.

    The script exports only the PUBLIC certificate (.cer) for upload to the app
    registration. The private key is never exported.

    This is a standalone utility; it has no dependency on any particular project
    and can be copied and used as-is.

.PARAMETER Subject
    Certificate subject. A bare name is accepted and prefixed with "CN="
    automatically (e.g. "my-app" becomes "CN=my-app"). Required unless -List is
    used.

.PARAMETER List
    List existing certificates in the selected Location\Store instead of creating
    one. Nothing is created (unless -ExportPath is also given, see below). Use with
    -Location and -Store to choose which store to inspect.

.PARAMETER Thumbprint
    In -List mode, restrict output to the certificate with this thumbprint
    (spaces are ignored, case-insensitive). Required alongside -ExportPath when the
    store holds more than one certificate, to pick which one to export.

.PARAMETER Provider
    CNG Key Storage Provider. Default: "Microsoft Platform Crypto Provider"
    (TPM-backed, requires a usable TPM). Use "Microsoft Software Key Storage
    Provider" on machines without a TPM -- still a CNG/NCrypt key, just
    software-backed.

.PARAMETER Location
    Certificate store location: "CurrentUser" (default) or "LocalMachine".
    LocalMachine requires an elevated shell.

.PARAMETER Store
    Logical store name. Default: "My" (Personal).

.PARAMETER KeyLength
    RSA key length in bits. Default: 2048.

.PARAMETER ValidYears
    Certificate lifetime in years. Default: 2.

.PARAMETER ExportPath
    Path for the exported public .cer (DER). May be a file path or a directory;
    if a directory is given, the file is placed inside it, named after the
    certificate CN. Defaults to a file named after the subject CN in the current
    directory. In -List mode, supplying -ExportPath exports the selected
    certificate's public key rather than listing.

.EXAMPLE
    .\New-TPMEntraCertificate.ps1 -Subject my-service-app

.EXAMPLE
    .\New-TPMEntraCertificate.ps1 -Subject my-app -Provider "Microsoft Software Key Storage Provider"

.EXAMPLE
    .\New-TPMEntraCertificate.ps1 -Subject prod-app -Location LocalMachine -ValidYears 1

.EXAMPLE
    .\New-TPMEntraCertificate.ps1 -List

.EXAMPLE
    .\New-TPMEntraCertificate.ps1 -List -Location LocalMachine -Store My

.EXAMPLE
    .\New-TPMEntraCertificate.ps1 -List -Thumbprint <thumbprint> -ExportPath $HOME\Desktop

.NOTES
    Version: 1.2.0
#>
[CmdletBinding(DefaultParameterSetName = "Create")]
param(
    [Parameter(Mandatory, ParameterSetName = "Create", Position = 0)]
    [string]$Subject,

    [Parameter(Mandatory, ParameterSetName = "List")]
    [switch]$List,

    [Parameter(ParameterSetName = "List")]
    [string]$Thumbprint,

    [Parameter(ParameterSetName = "Create")]
    [string]$Provider = "Microsoft Platform Crypto Provider",

    [ValidateSet("CurrentUser", "LocalMachine")]
    [string]$Location = "CurrentUser",

    [string]$Store = "My",

    [Parameter(ParameterSetName = "Create")]
    [int]$KeyLength = 2048,

    [Parameter(ParameterSetName = "Create")]
    [int]$ValidYears = 2,

    [Parameter(ParameterSetName = "Create")]
    [Parameter(ParameterSetName = "List")]
    [string]$ExportPath
)

$ScriptVersion = "1.2.0"
$ErrorActionPreference = "Stop"

function ConvertTo-SafeFileName {
    <#
    .SYNOPSIS
        Turn a certificate CN into a filesystem-safe base file name.
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )
    return ($Name -replace "^CN=", "") -replace "[^\w.-]", "_"
}

function Get-CertCommonName {
    <#
    .SYNOPSIS
        Extract the CN value from a certificate's subject, falling back to the
        thumbprint when no CN is present.
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    $match = [regex]::Match($Certificate.Subject, "CN=([^,]+)")
    if ($match.Success) {
        return $match.Groups[1].Value.Trim()
    }
    return $Certificate.Thumbprint
}

function Resolve-ExportFilePath {
    <#
    .SYNOPSIS
        Resolve a user-supplied export path to a concrete .cer file path.

    .DESCRIPTION
        Empty path defaults to <Cn>.cer in the current directory. An existing
        directory receives a file named after the CN. Throws if the target's
        parent directory does not exist (Export-Certificate will not create it),
        so a bad path fails before any certificate is created.
    #>
    [OutputType([string])]
    param(
        [AllowEmptyString()]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Cn
    )

    if (-not $Path) {
        $Path = Join-Path (Get-Location) "$Cn.cer"
    }
    elseif (Test-Path -Path $Path -PathType Container) {
        $Path = Join-Path $Path "$Cn.cer"
    }

    $dir = Split-Path -Path $Path -Parent
    if ($dir -and -not (Test-Path -Path $dir -PathType Container)) {
        throw "Export directory does not exist: $dir"
    }

    return $Path
}

# -List: inspect an existing store. Read-only unless -ExportPath is supplied, in
# which case the selected certificate's public key is exported instead of listed.
if ($List) {
    $storePath = "Cert:\$Location\$Store"
    Write-Host "New-TPMEntraCertificate.ps1 v$ScriptVersion"

    $certs = @(Get-ChildItem -Path $storePath)

    if ($Thumbprint) {
        $wanted = ($Thumbprint -replace "\s", "").ToUpperInvariant()
        $certs = @($certs | Where-Object { $_.Thumbprint -eq $wanted })
    }

    $certs = @($certs | Sort-Object -Property NotAfter)

    if (-not $certs) {
        if ($Thumbprint) {
            throw "No certificate with thumbprint '$Thumbprint' in ${storePath}."
        }
        Write-Host "Certificates in ${storePath}:`n"
        Write-Host "  (no certificates found)"
        return
    }

    # Export request: -ExportPath given in list mode. Requires an unambiguous target.
    if ($ExportPath) {
        if ($certs.Count -gt 1) {
            throw ("Multiple certificates match in ${storePath}; " +
                "specify -Thumbprint to choose which one to export.")
        }
        $target = $certs[0]
        $cn = ConvertTo-SafeFileName -Name (Get-CertCommonName -Certificate $target)
        $resolved = Resolve-ExportFilePath -Path $ExportPath -Cn $cn

        Export-Certificate -Cert $target -FilePath $resolved -Type CERT | Out-Null

        Write-Host "Exported public certificate:"
        Write-Host "  Subject     : $($target.Subject)"
        Write-Host "  Thumbprint  : $($target.Thumbprint)"
        Write-Host "  Public cert : $resolved"
        return
    }

    Write-Host "Certificates in ${storePath}:`n"
    $certs |
        Select-Object Subject,
            Thumbprint,
            @{ Name = "NotBefore"; Expression = { $_.NotBefore.ToString("yyyy-MM-dd") } },
            @{ Name = "NotAfter"; Expression = { $_.NotAfter.ToString("yyyy-MM-dd") } },
            @{ Name = "HasPrivateKey"; Expression = { $_.HasPrivateKey } } |
        Format-Table -AutoSize

    return
}

# Accept a bare name as well as a full "CN=..." distinguished name.
if ($Subject -notmatch "=") {
    $Subject = "CN=$Subject"
}

# Resolve the export path BEFORE creating the cert, so a bad path fails early
# rather than leaving an orphaned cert in the store with no exported .cer.
$cn = ConvertTo-SafeFileName -Name $Subject
$ExportPath = Resolve-ExportFilePath -Path $ExportPath -Cn $cn

Write-Host "New-TPMEntraCertificate.ps1 v$ScriptVersion"
Write-Host "Creating certificate '$Subject' (provider: $Provider, store: $Location\$Store)..."

$certParams = @{
    Subject           = $Subject
    CertStoreLocation = "Cert:\$Location\$Store"
    KeyAlgorithm      = "RSA"
    KeyLength         = $KeyLength
    Provider          = $Provider
    KeyExportPolicy   = "NonExportable"
    Type              = "Custom"
    KeyUsage          = "DigitalSignature"
    NotAfter          = (Get-Date).AddYears($ValidYears)
}
$cert = New-SelfSignedCertificate @certParams

$exportParams = @{
    Cert     = $cert
    FilePath = $ExportPath
    Type     = "CERT"
}
Export-Certificate @exportParams | Out-Null

Write-Host @"

Certificate created.
  Subject     : $($cert.Subject)
  Thumbprint  : $($cert.Thumbprint)
  Store       : Cert:\$Location\$Store
  Provider    : $Provider
  Public cert : $ExportPath

Next steps for Entra application certificate auth:
  1. Upload the public cert to the app registration:
     Entra ID > App registrations > <app> > Certificates & secrets > Certificates.
  2. Authenticate with the thumbprint above. The private key stays on this device.
"@
