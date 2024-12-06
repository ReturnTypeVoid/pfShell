<#
.SYNOPSIS
    Analyse pfSense configuration exported in XML format for potential security issues and generate reports.

.DESCRIPTION
    This script processes a pfSense XML configuration export file and evaluates filter rules and SNMP configurations 
    against defined security criteria. It categorises rules into High, Medium, and Low severity levels and outputs the results 
    to the console or optionally to Excel reports.

.PARAMETER XmlPath
    Mandatory parameter specifying the path to the pfSense XML configuration export file.

.PARAMETER Report
    Optional switch to enable the generation of Excel reports for the analysed data.

.NOTES
    Author: Reece Alqotaibi [ReturnTypeVoid]
    Created: 03/12/2024
    Version: 1.0
    URL: https://github.com/ReturnTypeVoid/pfShell
    License: Creative Commons Attribution-NonCommercial 4.0 International License

    Licensing terms:
    - You are free to fork, edit, and share this work, provided credit is given to the author.
    - The work cannot be integrated into commercial products or sold as part of any product.
    - The work may be used in commercial services, such as penetration testing, provided that:
        - It is properly referenced in reports or documentation.
        - The work is not resold or directly monetised as a standalone offering.
    - Non-commercial services and personal projects are fully permitted.

.EXAMPLE
    # Analyse the pfSense configuration file and output results to the console.
    Invoke-PfShell -XmlPath "C:\Path\To\Config.xml"

.EXAMPLE
    # Analyse the pfSense configuration file and generate Excel reports.
    Invoke-PfShell -XmlPath "C:\Path\To\Config.xml" -Report

#>

function Invoke-PfShell {
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Path to the full pfSense XML export")]
        [string]$XmlPath,

        [Parameter(Mandatory = $false, HelpMessage = "Generate Excel report")]
        [switch]$Report
    )

    # Ensure ImportExcel module is available
    function Ensure-ImportExcel {
        if (-not (Get-Module -Name ImportExcel -ListAvailable)) {
            Write-Host "The ImportExcel module is not installed. Installing it now..." -ForegroundColor Yellow
            try {
                Install-Module -Name ImportExcel -Force -Scope CurrentUser -ErrorAction Stop
                Write-Host "ImportExcel module installed successfully." -ForegroundColor Green
            } catch {
                Write-Error "Failed to install the ImportExcel module. Please install it manually using 'Install-Module -Name ImportExcel'."
                throw $_
            }
    }

    # Import the module
    Import-Module -Name ImportExcel -Force -ErrorAction Stop
}

# Call the function to ensure ImportExcel is ready
Ensure-ImportExcel
    $OutputParentDirectory = "."
    # Ensure the XML path is valid
    if (-not (Test-Path $XmlPath)) {
        throw "The specified XML path '$XmlPath' does not exist."
    }

    # Load the XML content
    $xmlContent = [xml](Get-Content -Path $XmlPath)

    # Get the hostname from the XML
    $hostname = $xmlContent.pfsense.system.hostname
    if (-not $hostname) {
        throw "Hostname not found in the XML file."
    }


    # Initialize arrays for categorized rules
    $highCriteria1 = @()
    $highCriteria2 = @()
    $mediumCriteria1 = @()
    $mediumCriteria2 = @()
    $mediumCriteria3 = @()
    $mediumCriteria4 = @()
    $mediumCriteria5 = @()
    $mediumCriteria6 = @()
    $lowCriteria1 = @()
    $lowCriteria2 = @()

    # Helper functions
    function Get-Address {
        param ([System.Xml.XmlElement]$Node)
        if ($null -ne $Node.address) {
            return $Node.address
        } else {
            return "*"
        }
    }

    function Get-Port {
        param ([System.Xml.XmlElement]$Node)
        if ($null -ne $Node.port) {
            return $Node.port
        } else {
            return "*"
        }
    }

    function Test-SecureCommunityString {
        param ([string]$CommunityString)
        $hasLowerCase = $false
        $hasUpperCase = $false
        $hasDigit = $false
        $hasSpecial = $false
        $hasMinLength = $false

        $hasMinLength = $CommunityString.Length -ge 16

        foreach ($char in $CommunityString.ToCharArray()) {
            if ($char -cmatch '[a-z]') { $hasLowerCase = $true }
            if ($char -cmatch '[A-Z]') { $hasUpperCase = $true }
            if ($char -cmatch '\d') { $hasDigit = $true }
            if ($char -cmatch '\W') { $hasSpecial = $true }
        }

        return $hasLowerCase -and $hasUpperCase -and $hasDigit -and $hasSpecial -and $hasMinLength
    }

    function Write-Excel {
        param (
            [object[]]$Data,
            [string]$Severity,
            [string]$Criteria
        )

        # Create the output folder using the hostname
        $outputFolder = Join-Path -Path $OutputParentDirectory -ChildPath "pfShell - $hostname"
        if (-not (Test-Path $outputFolder)) {
            New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
        }

        $filePath = Join-Path -Path $outputFolder -ChildPath "pfAnalysis-$Severity.xlsx"

        if ($Data.Count -gt 0) {
            $Data | Export-Excel -Path $filePath -WorksheetName $Criteria -Append -AutoSize
        }
    }

    function Write-Console {
        param (
            [object[]]$Data,
            [string]$Color = 'White'  # Default color is White
        )

        # Format the table output
        $formatted = $Data | Format-Table -AutoSize | Out-String

        # Write to the console with color
        Write-Host $formatted -ForegroundColor $Color

    }

    # Extract rules from XML
    $rules = $xmlContent.pfsense.filter.rule
    foreach ($rule in $rules) {
        $filterRule = [PSCustomObject]@{
            Type               = $rule.type
            Interface          = $rule.interface
            IPProtocol         = $rule.ipprotocol
            Protocol           = $rule.protocol
            SourceAddress      = Get-Address $rule.source
            SourcePort         = Get-Port $rule.source
            DestinationAddress = Get-Address $rule.destination
            DestinationPort    = Get-Port $rule.destination
            Description        = if ($rule.descr.'#cdata-section') { $rule.descr.'#cdata-section'.Trim() } else { "No Description" }
        }

        # High severity criteria
        if ($filterRule.DestinationAddress -eq "*" -and $filterRule.DestinationPort -eq "*") {
            $highCriteria1 += $filterRule
        }
        if ($filterRule.SourceAddress -eq "*" -and $filterRule.DestinationAddress -eq "*" -and $filterRule.SourcePort -eq "*") {
            $highCriteria2 += $filterRule
        }

        # Medium severity criteria
        if ($filterRule.SourceAddress -eq "*" -and $filterRule.DestinationAddress -ne "*" -and $filterRule.DestinationPort -ne "*") {
            $mediumCriteria1 += $filterRule
        }
        if ($filterRule.DestinationAddress -eq "*" -and $filterRule.SourceAddress -ne "*" -and $filterRule.SourcePort -ne "*") {
            $mediumCriteria2 += $filterRule
        }
        if ($filterRule.DestinationPort -eq "*" -and $filterRule.SourceAddress -ne "*" -and $filterRule.DestinationAddress -ne "*") {
            $mediumCriteria3 += $filterRule
        }
        if ($filterRule.DestinationPort -match '^(\d+)-(\d+)$') {
            $startPort = [int]$Matches[1]
            $endPort = [int]$Matches[2]
            if (($endPort - $startPort) -ge 1000) {
                $mediumCriteria4 += $filterRule
            }
        }

        # Low severity criteria
        if ($filterRule.Type -eq "reject") {
            $lowCriteria1 += $filterRule
        }
    }

    # Process SNMP Configuration
    $snmpdNode = $xmlContent.pfsense.snmpd
    if ($null -ne $snmpdNode.enable) {
        $snmpdObject = [PSCustomObject]@{
            SysLocation  = $snmpdNode.syslocation -as [string]
            SysContact   = $snmpdNode.syscontact -as [string]
            ROCommunity  = $snmpdNode.rocommunity -as [string]
            PollPort     = $snmpdNode.pollport -as [string]
        }

        if ($snmpdObject.ROCommunity -eq "public" -or -not (Test-SecureCommunityString $snmpdObject.ROCommunity)) {
            $mediumCriteria5 += $snmpdObject
        } elseif ($snmpdObject.ROCommunity -ne "public" -and (Test-SecureCommunityString $snmpdObject.ROCommunity)) {
            $lowCriteria2 += $snmpdObject
        }
    }

    # Output High Severity
    if ($highCriteria1.Count -gt 0 -or $highCriteria2.Count -gt 0) {
        Write-Console "##########################################################################################################################################" -Color Red
        Write-Console "###                                                            High Severity                                                           ###" -Color Red
        Write-Console "##########################################################################################################################################" -Color Red

        if ($highCriteria1.Count -gt 0) {
            Write-Console "*********************************************************************************" -Color Red
            Write-Console "*          Rule Allows Packets To Any Destination On Any Service/Port           *" -Color Red
            Write-Console "*********************************************************************************" -Color Red
            Write-Console -Data $highCriteria1
        }

        if ($highCriteria2.Count -gt 0) {
            Write-Console "*********************************************************************************" -Color Red
            Write-Console "*        Rule Allows Any Source, Any Destination, Multiple Service/Ports        *" -Color Red
            Write-Console "*********************************************************************************" -Color Red
            Write-Console -Data $highCriteria2
        }
    }

    # Output Medium Severity
    if ($mediumCriteria1.Count -gt 0 -or $mediumCriteria2.Count -gt 0 -or $mediumCriteria3.Count -gt 0 -or $mediumCriteria4.Count -gt 0) {
        Write-Console "##########################################################################################################################################" -Color Yellow
        Write-Console "###                                                         Medium Severity                                                            ###" -Color Yellow
        Write-Console "##########################################################################################################################################" -Color Yellow

        if ($mediumCriteria1.Count -gt 0) {
            Write-Console "************************************************************" -Color Yellow
            Write-Console "*            Rule Allows Packets From Any Source           *"-Color Yellow
            Write-Console "************************************************************" -Color Yellow
            Write-Console -Data $mediumCriteria1
        }

        if ($mediumCriteria2.Count -gt 0) {
            Write-Console "************************************************************" -Color Yellow
            Write-Console "*         Rule Allows Packets To Any Destination           *" -Color Yellow
            Write-Console "************************************************************" -Color Yellow
            Write-Console -Data $mediumCriteria2
        }

        if ($mediumCriteria3.Count -gt 0) {
            Write-Console "************************************************************" -Color Yellow
            Write-Console "*          Rule Allows Packets To Any Service/Port         *" -Color Yellow
            Write-Console "************************************************************" -Color Yellow
            Write-Console -Data $mediumCriteria3
        }

        if ($mediumCriteria4.Count -gt 0) {
            Write-Console "************************************************************" -Color Yellow
            Write-Console "*      Rule Allows Packets To Large Service/Port Range     *" -Color Yellow
            Write-Console "************************************************************" -Color Yellow
            Write-Console -Data $mediumCriteria4
        }

        if ($mediumCriteria5.Count -gt 0) {
            Write-Console "************************************************************" -Color Yellow
            Write-Console "*     SNMP Enabled with default/weak community string      *" -Color Yellow
            Write-Console "************************************************************" -Color Yellow
            Write-Console -Data $mediumCriteria5
        }

        if ($mediumCriteria6.Count -gt 0) {
            Write-Console "************************************************************" -Color Yellow
            Write-Console "*     Alias Has Excessive Ports In Port/Service Group      *" -Color Yellow
            Write-Console "************************************************************" -Color Yellow
            Write-Console -Data $mediumCriteria6
        }
    }

    # Output Low Severity
    if ($lowCriteria1.Count -gt 0 -or $lowCriteria2.Count -gt 0) {
        Write-Console "##########################################################################################################################################" -Color Cyan
        Write-Console "###                                                             Low Severity                                                           ###" -Color Cyan
        Write-Console "##########################################################################################################################################" -Color Cyan

        if($lowCriteria1.Count -gt 0) {
            Write-Console "**************************************************" -Color Cyan
            Write-Console "*            Reject Rule Identified              *" -Color Cyan
            Write-Console "**************************************************" -Color Cyan
            Write-Console -Data $lowCriteria1
        }

        if($lowCriteria2.Count -gt 0) {
            Write-Console "**************************************************" -Color Cyan
            Write-Console "*          SNMP < Version 3 Detected             *" -Color Cyan
            Write-Console "**************************************************" -Color Cyan
            Write-Console -Data $lowCriteria2
        }
    }

    if($Report) {
        # Output High Severity
        Write-Excel -Data $highCriteria1 -Severity "High" -Criteria "Rule Allows Packets To Any Destination On Any Service/Port"
        Write-Excel -Data $highCriteria2 -Severity "High" -Criteria "Rule Allows Any Source, Any Destination, Multiple Service/Ports"

        # Output Medium Severity
        Write-Excel -Data $mediumCriteria1 -Severity "Medium" -Criteria "Rule Allows Packets From Any Source"
        Write-Excel -Data $mediumCriteria2 -Severity "Medium" -Criteria "Rule Allows Packets To Any Destination"
        Write-Excel -Data $mediumCriteria3 -Severity "Medium" -Criteria "Rule Allows Packets To Any Service/Port"
        Write-Excel -Data $mediumCriteria4 -Severity "Medium" -Criteria "Rule Allows Packets To Large Service/Port Range"
        Write-Excel -Data $mediumCriteria5 -Severity "Medium" -Criteria "SNMP Enabled with Default/Weak Community String"

        # Output Low Severity
        Write-Excel -Data $lowCriteria1 -Severity "Low" -Criteria "Reject Rule Identified"
        Write-Excel -Data $lowCriteria2 -Severity "Low" -Criteria "SNMP < Version 3 Detected"
    }

}

Export-ModuleMember -Function Invoke-PfShell