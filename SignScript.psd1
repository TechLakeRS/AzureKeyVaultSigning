@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'SignScript.psm1'

    # Version number of this module.
    ModuleVersion = '1.0.0'

    # Supported PSEditions
    CompatiblePSEditions = @('Desktop', 'Core')

    # ID used to uniquely identify this module
    GUID = '12345678-1234-5678-1234-567812345678'  # You should generate a new GUID

    # Author of this module
    Author = 'Riyadh Sarker'

    # Company or vendor of this module
    CompanyName = 'TECHLAKE'

    # Copyright statement for this module
    Copyright = '(c) 2025 TECHLAKE. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'Module for signing PowerShell and VBScript files using Azure Key Vault certificate'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @(
        @{
            ModuleName = 'Az.Accounts'
            RequiredVersion = '2.17.0'
        }
    )

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry
    FunctionsToExport = @('Sign-Script')

    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            # Tags applied to this module
            Tags = @('CodeSigning', 'Azure', 'KeyVault', 'Security', 'NBB')

            # A URL to the main website for this project.
            ProjectUri = ''  # Add your project URI if applicable

            # ReleaseNotes of this module
            ReleaseNotes = 'Initial release of SignScript module'
        }
    }
}