<#
.SYNOPSIS
    Powershell NPS Radius Module. 
.DESCRIPTION
    Cmdlets for netsh nps commands.
    Minimum requirements are: Powershell v5.1.
.EXAMPLE
    Import-Module .\NPS-Radius.psm1
.NOTES
    Authors: Eryniox - 2024
    Date:    May 2024
.LINK
    http://
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSProvideDefaultParameterValue", "Version")]
[version]$Version = "1.00"

enum NPSRadiusState {
    <# Specify a list of distinct values #>
    Enabled = 1
    Disabled = 2
}

enum NPSRadiusSetState {
    <# Specify a list of distinct values #>
    ENABLE = 1
    DISABLE = 2
}

enum NPSRadiusCRPType {
    <# Specify a list of distinct values #>
    Condition
    Profile
}

class NPSRadiusCRPTypeAttribute {
    # CRP = Connection request policy configuration
    # Properties
    [string] $Name
    [int]    $IdInt
    # $Id = 0x1006
    # "0x" + [System.Convert]::ToString($Id,16)
    [string] $Type

    hidden $_Id = $($this | Add-Member -MemberType ScriptProperty -Name 'Id' -Value { # get
            $("0x" + [System.Convert]::ToString($this.IdInt,16))
        } -SecondValue { # set
            param ( $arg ); try { $this.IdInt = [int]$arg } catch {}
        }
    )

    hidden [void] Init ([string] $String) {
        $array = $String -split '[\t\f\cK ]{3,}'
        $this.Init($array[0], $array[1], ($array[2..99] -join ' '))
    }
    hidden [void] Init ([string] $Name, [string] $Id, [string] $Type) {
        $this.Name = ("" + $Name).Trim()
        $this.Id = ("" + $Id).Trim()
        $this.Type = ("" + $Type).Trim()
    }

    NPSRadiusCRPTypeAttribute () {}
    NPSRadiusCRPTypeAttribute ([string] $String) {
        $this.Init($String)
    }
    NPSRadiusCRPTypeAttribute ([string] $Name, [string] $Id, [string] $Type) {
        $this.Init($Name, $Id, $Type)
    }
}

class NPSCRPStaticAttributes {
    # netsh nps show crpconditionattributes
    # netsh nps show crpprofileattributes
    # Properties
    static [hashtable] $ConditionAttributes
    static [hashtable] $ProfileAttributes
    static [hashtable] $Attributes = @{}
    hidden static [array] $ValidStrings = @(
        "Connection request policy profile attributes:",
        "Connection request policy condition attributes:",
        "Network policy condition attributes:",
        "Network policy profile attributes:"
    )

    static hidden [hashtable] CreateStaticAttributes ([array] $String) {
        $NewHash = @{} ; $Current = "Begin"
        foreach ($line in $String) {
            if ($line.Trim() -like "" -or $null -eq $line) { continue }
            if ($line.Trim() -in [NPSCRPStaticAttributes]::ValidStrings) {
                $Current = "BeginHeader"
            } elseif  ($line.Trim() -like "Ok.") {
                Break
            } elseif ($Current -like "Begin*" -and $line.Trim() -like "Name*Id*Type") {
                $Current = "Header"
            } elseif ($Current -like "Header" -and $line.Trim() -like "--------*") {
                $Current = "DataNext"
            } elseif ($Current -like "DataNext") {
                $Current = "Data"
            }
            if ($Current -notlike "Data") { continue }
            $TypeObj = [NPSRadiusCRPTypeAttribute]::new($line)
            $NewHash[$TypeObj.Id] = $TypeObj
        }
        Return ($NewHash)
    }
    static [void] CreateStaticConditionAttributes ([array] $String) {
        if (($String[0..2] -join "").Trim() -notlike "Connection request policy condition attributes:*") {
            Throw "Not a valid string."
        }
        [NPSCRPStaticAttributes]::ConditionAttributes = [NPSCRPStaticAttributes]::CreateStaticAttributes($String)
    }
    static [void] CreateStaticProfileAttributes ([array] $String) {
        if (($String[0..2] -join "").Trim() -notlike "Connection request policy profile attributes:*") {
            Throw "Not a valid string."
        }
        [NPSCRPStaticAttributes]::ProfileAttributes = [NPSCRPStaticAttributes]::CreateStaticAttributes($String)
    }
    static [void] AddStaticAttributes ([array] $String) {
        $StringCheck = ($String[0..2] -join "").Trim()
        $StringBool = $false
        foreach ($ValidString in [NPSCRPStaticAttributes]::ValidStrings) {
            if ($StringCheck -like ($ValidString + "*")) {
                $StringBool = $true
                Break
            }
        }
        if (-not $StringBool) { Throw "Not a valid string." }
        $NewHash = [NPSCRPStaticAttributes]::CreateStaticAttributes($String)
        foreach ($Key in $NewHash.Keys) {
            if (-not [NPSCRPStaticAttributes]::Attributes.ContainsKey($Key)) {
                [NPSCRPStaticAttributes]::Attributes[$Key] = $NewHash[$Key]
            }
        }
    }
}

class NPSRadiusCRPAttribute : NPSRadiusCRPTypeAttribute {
    # CRP = Connection request policy configuration
    # Extra Properties
    [string] $ValueString
    [psobject] $ValueObject
    [string] $TypeName
    [psobject] $TypeObj
    [NPSRadiusCRPType] $AttributeType

    hidden [void] Init ([string] $Name, [string] $Id, [string] $Value) {
        $this.Name = ("" + $Name).Trim()
        $this.Id = ("" + $Id).Trim()
        $this.Value = ("" + $Value).Trim()
    }

    hidden $_Value = $($this | Add-Member -MemberType ScriptProperty -Name 'Value' -Value { # get
            if ($this.ValueObject) { Return $this.ValueObject }
            Return $this.ValueString
        } -SecondValue { # set
            param ( $arg )
            if ($arg -is [string]) {
                $this.ValueString = $arg
                $this.ValueObject = $null
            } else {
                $this.ValueObject = $arg
                $this.ValueString = $null
            }
        }
    )

    NPSRadiusCRPAttribute () {}
    NPSRadiusCRPAttribute ([string] $String) {
        $this.Init($String)
    }
    NPSRadiusCRPAttribute ([string] $Name, [string] $Id, [string] $Value) {
        $this.Init($Name, $Id, $Value)
    }

    SetTypeAttributes ([NPSRadiusCRPType] $Type) {
        $this.TypeObj = [NPSCRPStaticAttributes]::Attributes[$this.Id]
        if (-not $this.TypeObj) { Return }
        $this.TypeName = $this.TypeObj.Name
        $this.Type = $this.TypeObj.Type
        $this.AttributeType = $Type
    }
}

class NPSProfileMSFilter {
    # MS-Filter*0x102f
    $IPFilterType = "IPFILTER_IPV4INFILTER"
    $Action = "DENY"
    [ipaddress] $Address
    [ipaddress] $Mask
    $Protocol = 0
    $SourcePort = 0
    $DestinationPort = 0

    hidden $_netid = $($this | Add-Member -MemberType ScriptProperty -Name 'netid' -Value { # get
            Return ($this.Address.Address -band $this.Mask.Address)
        } -SecondValue { # set . don't care about the set
            param ( $arg )}
    )

    NPSProfileMSFilter () {}
}

class NPSRadiusNPAttribute : NPSRadiusCRPAttribute {

    hidden [void] Init ([string] $String) {
        $array = $String -split '[\t\f\cK ]{3,}'
        $this.Init($array[0], $array[1], ($array[2..99] -join ' '))
    }

    hidden [void] Init ([int] $ExtraType, [array] $ExtraFilters) {
        if ($ExtraType -ne 4) { Return }
        $array = $ExtraFilters[0] -split '[\t\f\cK ]{3,}'
        $this.Name = ("" + $array[0]).Trim()
        $this.Id = ("" + $array[1]).Trim()
        $NPSProfileMSFilter = [NPSProfileMSFilter]::new()
        $FilterArray = $ExtraFilters[2] -split 'Action:'
        $NPSProfileMSFilter.IPFilterType = $FilterArray[0].Trim()
        $NPSProfileMSFilter.Action = $FilterArray[1].Trim()
        $Count = 4
        foreach ($line in $ExtraFilters[4..99]) {
            switch ($Count) {
                4 { $NPSProfileMSFilter.Address = [ipaddress]::Parse(($line -split ':')[1].Trim()) }
                5 { $NPSProfileMSFilter.Mask = [ipaddress]::Parse(($line -split ':')[1].Trim()) }
                6 { $NPSProfileMSFilter.Protocol = [int]($line -split ':')[1].Trim() }
                7 { $NPSProfileMSFilter.SourcePort = [int]($line -split ':')[1].Trim() }
                8 { $NPSProfileMSFilter.DestinationPort = [int]($line -split ':')[1].Trim() }
                Default {}
            }
            $Count++
        }
        $this.Value = $NPSProfileMSFilter
    }

    NPSRadiusNPAttribute () {}
    NPSRadiusNPAttribute ([string] $String) : base($String) {}

    NPSRadiusNPAttribute ([string] $Name, [string] $Id, [string] $Value) : base($Name, $Id, $Value) {}
    NPSRadiusNPAttribute ([int] $ExtraType, [array] $ExtraFilters) {
        $this.Init($ExtraType, $ExtraFilters)
    }
}

class NPSRadiusPolicyConfiguration {
    # CRP = Connection request policy configuration
        # netsh nps show crp        
    # NP = Network policy configuration
        # netsh nps show np

    # Properties
    [string]            $Name
    [NPSRadiusState]    $State
    [int]               ${Processing Order} = 1000000
    [int]               ${Policy Source}
    [System.Collections.Generic.List[System.Object]] $ConditionAttributes = @()
    [System.Collections.Generic.List[System.Object]] $ProfileAttributes = @()
    
    # Constructor
    NPSRadiusPolicyConfiguration () {}
}

class NPSRadiusCRPArray {
    # CRP = Connection request policy configuration
    # netsh nps show crp
    # Properties
    [System.Collections.Generic.List[System.Object]] $NPSRadiusCRPArray = @()

    hidden [NPSRadiusPolicyConfiguration] CreateOneConfiguration ([array] $String) {
        $Current = "Begin"; $CurrentType = "StringData"
        $NPSRadiusPolicyConfiguration = [NPSRadiusPolicyConfiguration]::new()
        foreach ($line in $String) {
            if ($line.Trim() -like "" -or $null -eq $line) { continue }
            if ($line.Trim() -like "Condition attributes:" ) {
                $Current = "BeginHeader"; $CurrentType = "Condition"
            } elseif ($line.Trim() -like "Profile attributes:" ) {
                $Current = "BeginHeader"; $CurrentType = "Profile"
            } elseif ($Current -like "Begin*" -and $line.Trim() -like "Name*Id*Value") {
                $Current = "Header"
            } elseif (($Current -like "Header" -or $Current -like "Begin" )-and $line.Trim() -like "--------*") {
                $Current = "DataNext"
            }  elseif ($Current -like "DataNext") {
                $Current = "Data"
            }

            if ($Current -notlike "Data") { continue }
            if ($CurrentType -like "StringData") {
                $Key, $Value = $line -split '= ', 2 | ForEach-Object { ("" + $_).Trim()}
                # Write-Host ("Key: " + $Key + " - " + "Value: " + $Value.ToString())
                $NPSRadiusPolicyConfiguration.$Key = $Value.ToString()
                #$NPSRadiusPolicyConfiguration.State = ("Enabled").ToString()

            } else {
                $NPSRadiusCRPAttribute = [NPSRadiusCRPAttribute]::new($line)
                $NPSRadiusCRPAttribute.SetTypeAttributes($CurrentType)
                if ($CurrentType -eq "Condition") {
                    $NPSRadiusPolicyConfiguration.ConditionAttributes.Add($NPSRadiusCRPAttribute)
                } elseif ($CurrentType -eq "Profile") {
                    $NPSRadiusPolicyConfiguration.ProfileAttributes.Add($NPSRadiusCRPAttribute)
                }
            }
        }
        Return $NPSRadiusPolicyConfiguration
    }
    hidden [void] CreateAllConfigurations ([array] $String) {
        $Current = "Begin"; $CurrentProfile = @()
        foreach ($line in $String) {
            if ($line.Trim() -like "" -or $null -eq $line) { continue }
            if ($line.Trim() -like "Connection request policy configuration:" ) {
                $Current = "BeginHeader"
            } elseif ($line.Trim() -like "Ok.") {
                $Current = "End"
            } else {
                $Current = "Data"
                $CurrentProfile += $line
                # Write-Host ("Count: " + $CurrentProfile.Count + " " + $line)
            }

            if ($CurrentProfile.Count -gt 0 -and ($Current -like "End" -or $Current -like "BeginHeader")) {
                $null = $this.NPSRadiusCRPArray.Add($this.CreateOneConfiguration($CurrentProfile))
                $CurrentProfile = @()
            }
            if ($Current -like "End") { Break }
        }
        if ($CurrentProfile.Count -gt 0) {
            $null = $this.NPSRadiusCRPArray.Add($this.CreateOneConfiguration($CurrentProfile))
            $CurrentProfile = @()
        }
    }
    NPSRadiusCRPArray ([array] $String) {
        if (($String[0..2] -join "").Trim() -notlike "Connection request policy configuration:*") {
            Throw "Not a valid string."
        }
        $this.CreateAllConfigurations($String)
    }
}

class NPSRadiusNPArray {
    # NP = Network policy configuration
        # netsh nps show np
    # Properties
    [System.Collections.Generic.List[System.Object]] $NPSRadiusNPArray = @()

    hidden [NPSRadiusPolicyConfiguration] CreateOneConfiguration ([array] $String) {
        $Current = "Begin"; $CurrentType = "StringData"; $ExtraFilters = @(); $ExtraType = 0
        $NPSRadiusPolicyConfiguration = [NPSRadiusPolicyConfiguration]::new()
        foreach ($line in $String) {
            if ($line.Trim() -like "" -or $null -eq $line) { continue }
            if ($line.Trim() -like "Condition attributes:" ) {
                $Current = "BeginHeader"; $CurrentType = "Condition"
            } elseif ($line.Trim() -like "Profile attributes:" ) {
                $Current = "BeginHeader"; $CurrentType = "Profile"
            } elseif ($Current -like "Begin*" -and $line.Trim() -like "Name*Id*Value") {
                $Current = "Header"
            } elseif (($Current -like "Header" -or $Current -like "Begin" )-and $line.Trim() -like "--------*") {
                $Current = "DataNext"
            }  elseif ($Current -like "DataNext") {
                $Current = "Data"
            }

            if ($Current -notlike "Data") { continue }
            if ($CurrentType -like "StringData") {
                $Key, $Value = $line -split '= ', 2 | ForEach-Object { ("" + $_).Trim()}
                # Write-Host ("Key: " + $Key + " - " + "Value: " + $Value.ToString())
                $NPSRadiusPolicyConfiguration.$Key = $Value.ToString()
            } else {
                if ($line.Trim() -like "MS-Filter*0x102f" -or $ExtraType -ne 0) {
                    $ExtraFilters += $line
                    if ($line.Trim() -like "MS-Filter*0x102f") {
                        $ExtraType = 1
                    } elseif ($line.Trim() -like "================*") {
                        $ExtraType = 2
                    } elseif ($line.Trim() -like "----------------*" -and $ExtraType -eq 2) {
                        $ExtraType = 4
                    } elseif ($line.Trim() -like "----------------*" -and $ExtraType -eq 4) {
                        $NPSRadiusNPAttribute = [NPSRadiusNPAttribute]::new($ExtraType, $ExtraFilters)
                        $NPSRadiusNPAttribute.SetTypeAttributes($CurrentType)
                        if ($CurrentType -eq "Condition") {
                            $NPSRadiusPolicyConfiguration.ConditionAttributes.Add($NPSRadiusNPAttribute)
                        } elseif ($CurrentType -eq "Profile") {
                            $NPSRadiusPolicyConfiguration.ProfileAttributes.Add($NPSRadiusNPAttribute)
                        }
                        $ExtraType = 0
                    }

                } else {
                    $NPSRadiusNPAttribute = [NPSRadiusNPAttribute]::new($line)
                    $NPSRadiusNPAttribute.SetTypeAttributes($CurrentType)
                    if ($CurrentType -eq "Condition") {
                        $NPSRadiusPolicyConfiguration.ConditionAttributes.Add($NPSRadiusNPAttribute)
                    } elseif ($CurrentType -eq "Profile") {
                        $NPSRadiusPolicyConfiguration.ProfileAttributes.Add($NPSRadiusNPAttribute)
                    }
                }
            }
        }
        Return $NPSRadiusPolicyConfiguration
    }
    hidden [void] CreateAllConfigurations ([array] $String) {
        $Current = "Begin"; $CurrentProfile = @()
        foreach ($line in $String) {
            if ($line.Trim() -like "" -or $null -eq $line) { continue }
            if ($line.Trim() -like "Network policy configuration:" ) {
                $Current = "BeginHeader"
            } elseif ($line.Trim() -like "Ok.") {
                $Current = "End"
            } else {
                $Current = "Data"
                $CurrentProfile += $line
                # Write-Host ("Count: " + $CurrentProfile.Count + " " + $line)
            }

            if ($CurrentProfile.Count -gt 0 -and ($Current -like "End" -or $Current -like "BeginHeader")) {
                $null = $this.NPSRadiusNPArray.Add($this.CreateOneConfiguration($CurrentProfile))
                $CurrentProfile = @()
            }
            if ($Current -like "End") { Break }
        }
        if ($CurrentProfile.Count -gt 0) {
            $null = $this.NPSRadiusNPArray.Add($this.CreateOneConfiguration($CurrentProfile))
            $CurrentProfile = @()
        }
    }
    NPSRadiusNPArray ([array] $String) {
        if (($String[0..2] -join "").Trim() -notlike "Network policy configuration:*") {
            Throw "Not a valid string."
        }
        $this.CreateAllConfigurations($String)
    }
}

class NPSRadiusBuildArguments {
    #Properties
    [string] $Name
    [ValidateSet("crp", "np")]
    [string] $Type
    [array]  $ConditionAttributes
    [array]  $ProfileAttributes

    static [array] $BuildStart = @("nps", "set")
    # $BuildParams = @("nps", "set", "crp") # $BuildParams += @("name", "=", $Name)

    #Methods
    [string] GetArguments () {
        $BuildParams = [NPSRadiusBuildArguments]::BuildStart
        $BuildParams += $this.Type
        $NameCheck = '"' + ($this.Name -replace '^"|"$') + '"'
        $BuildParams += @("name", "=", $NameCheck)
        foreach ($CPRCondition in $this.ConditionAttributes) {
            $BuildParams += @("conditionid", "=", ('"' + $CPRCondition.Id + '"'), "conditiondata", "=", $CPRCondition.Value)
        }
        foreach ($CPRProfile in $this.ProfileAttributes) {
            $BuildParams += @("profileid", "=", ('"' + $CPRProfile.Id + '"'), "profiledata", "=", $CPRProfile.Value)
        }
        Return ($BuildParams -join " ")
    }
}

function Add-NPSCRPStaticAttributes {
    param (
        [Parameter(Mandatory=$false)]
        [array] $Profiles,
        [Parameter(Mandatory=$false)]
        [array] $Conditions
    )
    If ($Profiles) {
        [NPSCRPStaticAttributes]::AddStaticAttributes($Profiles)    
    }
    If ($Conditions) {
        [NPSCRPStaticAttributes]::AddStaticAttributes($Conditions)
    }
    # [NPSCRPStaticAttributes]::AddStaticAttributes($crpConditions)    
}

function Get-NPSCRPStaticAttributes {
    param (
        [Parameter(Mandatory=$true)]
        [string] $AttributeId
    )
    try {
        Return ([NPSCRPStaticAttributes]::Attributes[$AttributeId])
    }
    catch {}
}

function New-NPSRadiusCRPArray {
    param (
        [Parameter(Mandatory=$true)]
        [array] $crp
    )
    Return ([NPSRadiusCRPArray]::new($crp))
}

function New-NPSRadiusNPArray {
    param (
        [Parameter(Mandatory=$true)]
        [array] $np
    )
    Return ([NPSRadiusNPArray]::new($np))
}

function ConvertTo-NPSRadiusSetState {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateRange([int32] 1, [int32] 2)]
        [int32] $StateValue
    )
    Return ([NPSRadiusSetState]$StateValue)
}

function Get-NPSRadiusBuildArguments {
    param (
        [Parameter(Mandatory=$true)]
        [string] $Name,
        [Parameter(Mandatory=$true)]
        [ValidateSet("crp", "np")]
        [string] $Type,
        [Parameter(Mandatory=$true)]
        [array]  $ConditionAttributes,
        [Parameter(Mandatory=$true)]
        [array]  $ProfileAttributes
    )
    $NPSRadiusBuildArguments = [NPSRadiusBuildArguments]::new()
    $NPSRadiusBuildArguments.Name = $Name
    $NPSRadiusBuildArguments.Type = $Type
    $NPSRadiusBuildArguments.ConditionAttributes = $ConditionAttributes
    $NPSRadiusBuildArguments.ProfileAttributes = $ProfileAttributes
    Return ($NPSRadiusBuildArguments.GetArguments())
}

# Example usage:
# [array]$crpConditions = netsh nps show crpconditionattributes
# [array]$crpProfiles = netsh nps show crpprofileattributes
# [array]$npConditions = netsh nps show npconditionattributes
# [array]$npProfiles = netsh nps show npprofileattributes
# Add-NPSCRPStaticAttributes -Conditions $crpConditions -Profiles $crpProfiles
# Add-NPSCRPStaticAttributes -Conditions $npConditions -Profiles $npProfiles

# [array]$np = netsh nps show np
# [array]$crp = netsh nps show crp
# $CRPObj = New-NPSRadiusCRPArray -crp $crp
# $Name = "Name of crp to change"
# $CPRToChange = $CRPObj.NPSRadiusCRPArray | Where-Object { $_.Name -like $Name }
# Get-NPSRadiusBuildArguments -Name $Name -Type "crp" -ConditionAttributes $CPRToChange.ConditionAttributes -ProfileAttributes $CPRToChange.ProfileAttributes

Export-ModuleMember -Function Add-NPSCRPStaticAttributes, Get-NPSCRPStaticAttributes,
                                New-NPSRadiusCRPArray, New-NPSRadiusNPArray,
                                ConvertTo-NPSRadiusSetState, Get-NPSRadiusBuildArguments
# Exporting needed functions
