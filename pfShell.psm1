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
        
    
    
    $highCriteria1 = @()
    $highCriteria2 = @()
    $mediumCriteria1 = @()
    $mediumCriteria2 = @()
    $mediumCriteria3 = @()
    $mediumCriteria4 = @()
    $mediumCriteria5 = @()
    $lowCriteria1 = @()
    $lowCriteria2 = @()
    
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
    
        # Sanitise worksheet name: shorten and remove invalid characters
        $sanitisedCriteria = ($Criteria -replace '[\\/\*\[\]\:\?]', '').Substring(0, [math]::Min($Criteria.Length, 31))
    
        $filePath = Join-Path -Path $outputFolder -ChildPath "pfAnalysis-$Severity.xlsx"
    
        if ($Data.Count -gt 0) {
            try {
                $Data | Export-Excel -Path $filePath -WorksheetName $sanitisedCriteria -Append -AutoSize
            } catch {
                Write-Error "Failed to write to Excel. Error: $_"
            }
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
    
    function Find-FilterRuleStartLine {
        param (
            [string]$XmlPath
        )
    
        # Load the XML content
        [xml]$xmlContent = Get-Content -Path $XmlPath
    
        # Get the <filter> node directly under <pfsense>
        $filterNode = $xmlContent.SelectSingleNode('/pfsense/filter')
    
        if (-not $filterNode) {
            return $null  # Return $null if no <filter> section is found
        }
    
        # Load the file lines
        $lines = Get-Content -Path $XmlPath
    
        # Search for the first occurrence of the <filter> tag
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i].Trim() -match '^<filter>$') {
                return $i + 1  # Return the line number (1-based index)
            }
        }
    
        return $null  # Return $null if the <filter> section is not found
    }

    # Define custom objects for source and destination
    class Source {
        [string]$Value
        [string]$Port
    }
    
    class Destination {
        [string]$Address
        [string]$Network
        [string]$Port
    }
    
    # Function to parse the source
    function Parse-Source {
        param (
            [Parameter(Mandatory = $true)]
            [System.Xml.XmlElement]$ruleNode
        )
    
        $source = New-Object Source
    
        $protocol = if ($ruleNode.protocol) { $ruleNode.protocol.ToUpper() } else { "ANY" }
    
        # Check if <not> exists in the source node
        $isNot = $ruleNode.source.SelectSingleNode('not')
    
        if ($ruleNode.source.address) {
            $source.Value = if ($isNot) { "!$($ruleNode.source.address)" } else { $ruleNode.source.address }
        }
        elseif ($ruleNode.source.network) {
            $source.Value = if ($isNot) { "!$($ruleNode.source.network)" } else { $ruleNode.source.network }
        }
        else {
            $source.Value = "ANY"
        }
    
        if ($ruleNode.source.port) {
            $source.Port = "${protocol}: $($ruleNode.source.port)"
        }
        else {
            $source.Port = "ANY"
        }
    
        return $source
    }
    
    
    # Function to parse the destination
    function Parse-Destination {
        param (
            [Parameter(Mandatory = $true)]
            [System.Xml.XmlElement]$ruleNode
        )
    
        $destination = New-Object Destination
    
        $protocol = if ($ruleNode.protocol) { $ruleNode.protocol.ToUpper() } else { "ANY" }
    
        # Check if <not> exists in the destination node
        $isNot = $ruleNode.destination.SelectSingleNode('not')
    
        if ($ruleNode.destination.address) {
            $destination.Address = if ($isNot) { "!$($ruleNode.destination.address)" } else { $ruleNode.destination.address }
        }
        elseif ($ruleNode.destination.network) {
            $destination.Network = if ($isNot) { "!$($ruleNode.destination.network)" } else { $ruleNode.destination.network }
        }
        else {
            $destination.Address = "ANY"
        }
    
        if ($ruleNode.destination.port) {
            $destination.Port = "${protocol}: $($ruleNode.destination.port)"
        }
        else {
            $destination.Port = "ANY"
        }
    
        return $destination
    }
    
    
    
    # Function to parse the descr field
    function Parse-Descr {
        param (
            [Parameter(Mandatory=$true)]
            [System.Xml.XmlElement]$ruleNode
        )
    
        # Handle the descr field as CDATA and clean it up
        $descr = if ($ruleNode.descr) { $ruleNode.descr.InnerText.Trim() } else { "No description available" }
        $maxLength = 50  # Set a max length if you need
        $descr = if ($descr.Length -gt $maxLength) { $descr.Substring(0, $maxLength) + "..." } else { $descr }
    
        return $descr
    }
    
    # Function to build a rule object from parsed data
    function Build-RuleObject {
        param (
            [Parameter(Mandatory = $true)]
            [System.Xml.XmlElement]$ruleNode,
            [Parameter(Mandatory = $true)]
            [Source]$source,
            [Parameter(Mandatory = $true)]
            [Destination]$destination,
            [Parameter(Mandatory = $true)]
            [string]$descr,
            [Parameter(Mandatory = $true)]
            [int]$lineNo
        )
    
        # Combine address and network to display the destination appropriately
        $destinationFormatted = if ($destination.Address) {
            $destination.Address
        }
        elseif ($destination.Network) {
            $destination.Network
        }
        else {
            "ANY"
        }
    
        # Create the psCustomObject for the rule
        $rule = [psCustomObject]@{
            LineNo           = $lineNo
            Type             = $ruleNode.type
            Interface        = $ruleNode.interface
            IPProtocol       = $ruleNode.ipprotocol
            Source           = $source.Value
            SourcePort       = $source.Port
            Destination      = $destinationFormatted
            DestinationPort  = $destination.Port
            Descr            = $descr
        }
    
        return $rule
    }
    
    
    
    # Function to process all rules and output the results
    function Process-Rules {
        param (
            [Parameter(Mandatory = $true)]
            [xml]$xmlContent,
            [string]$XmlPath
        )
    
        $rules = @()
        $filterStartLine = Find-FilterRuleStartLine -XmlPath $XmlPath
        
        # Create a new XML document and set the <filter> node as the root
        $tempXmlDoc = New-Object System.Xml.XmlDocument
        $xmlDeclaration = $tempXmlDoc.CreateXmlDeclaration("1.0", "UTF-8", $null)
        $tempXmlDoc.AppendChild($xmlDeclaration) | Out-Null

        # Clone the <filter> node and append it as the document's root
        $filterNode = $xmlContent.pfsense.filter
        $importedFilterNode = $tempXmlDoc.ImportNode($filterNode, $true)
        $tempXmlDoc.AppendChild($importedFilterNode) | Out-Null

        # Save to the temporary file
        $tempPath = ".\temp.xml"
        $tempXmlDoc.Save($tempPath)

        # Read the temporary file line-by-line
        $lines = Get-Content -Path $tempPath
    
        # Keep track of the current line number within the temporary file
        $currentLineNumber = 0
    
        # Load the temporary XML for processing
        [xml]$tempXml = Get-Content -Path $tempPath
    
        # Iterate over each <rule> node in the temporary XML
        foreach ($ruleNode in $tempXml.filter.rule) {
            $ruleFound = $false
    
            # Get the trimmed OuterXml of the rule
            $ruleString = $ruleNode.OuterXml.Trim()
    
            # Search for the start of the rule in the lines
            for ($i = $currentLineNumber; $i -lt $lines.Count; $i++) {
                if ($lines[$i].Trim() -like "<rule*") {
                    $currentLineNumber = $i + 1  # Adjust for 1-based index
                    $ruleFound = $true
                    break
                }
            }

            # If the rule was found, calculate the line number relative to the original XML
            $lineNo = if ($ruleFound) { $filterStartLine + $currentLineNumber + -2} else { 0 }
    
            # Parse source, destination, and description
            $source = Parse-Source -ruleNode $ruleNode
            $destination = Parse-Destination -ruleNode $ruleNode
            $descr = Parse-Descr -ruleNode $ruleNode
    
            # Build the rule object with the line number
            $rule = Build-RuleObject -ruleNode $ruleNode -source $source -destination $destination -descr $descr -lineNo $lineNo
    
            # Add the rule object to the array of rules
            $rules += $rule
        }
    
        # Clean up the temporary file
        Remove-Item -Path $tempPath -Force

        return $rules
    }    
    
    # Main code to load XML and process rules
    $rules = Process-Rules -xmlContent $xmlContent -XmlPath $XmlPath
    foreach($filterRule in $rules) {
         # High severity criteria
         if ($filterRule.Destination -eq "ANY" -and $filterRule.DestinationPort -eq "ANY" -and $filterRule.source -ne "ANY") {
            $highCriteria1 += $filterRule
        }
        if ($filterRule.Source -eq "ANY" -and $filterRule.Destination -eq "ANY" -and $filterRule.destinationPort -eq "ANY") {
            $highCriteria2 += $filterRule
        }
    
        # Medium severity criteria
        if ($filterRule.Source -eq "ANY" -and $filterRule.Destination -ne "ANY" -and $filterRule.DestinationPort -ne "ANY") {
            $mediumCriteria1 += $filterRule
        }
        if ($filterRule.Destination -eq "ANY" -and $filterRule.Source -ne "ANY" -and $filterRule.SourcePort -ne "ANY") {
            $mediumCriteria2 += $filterRule
        }
        if ($filterRule.DestinationPort -eq "ANY" -and $filterRule.Source -ne "ANY" -and $filterRule.Destination -ne "ANY") {
            $mediumCriteria3 += $filterRule
        }
    
        if ($filterRule.DestinationPort -match '^\s*\D*(\d+)-(\d+)\s*$') {
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
        Write-Console "*     Alias Has Excessive Ports In Port/Service Group      *" -Color Yellow
        Write-Console "************************************************************" -Color Yellow
        Write-Console -Data $mediumCriteria5
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
}
    
    if($Report) {
        # Output High Severity
        Write-Excel -Data $highCriteria1 -Severity "High" -Criteria "AnyDestAnyPort"
        Write-Excel -Data $highCriteria2 -Severity "High" -Criteria "AnySrcDestMultiPorts"
    
        # Output Medium Severity
        Write-Excel -Data $mediumCriteria1 -Severity "Medium" -Criteria "AnySrcSpecDestPort"
        Write-Excel -Data $mediumCriteria2 -Severity "Medium" -Criteria "AnyDestSpecSrcPort"
        Write-Excel -Data $mediumCriteria3 -Severity "Medium" -Criteria "AnyPortSpecSrcDest"
        Write-Excel -Data $mediumCriteria4 -Severity "Medium" -Criteria "LargePortRange"
        Write-Excel -Data $mediumCriteria5 -Severity "Medium" -Criteria "ExcessivePortsAlias"
    
    
        # Output Low Severity
        # Output Low Severity
        Write-Excel -Data $lowCriteria1 -Severity "Low" -Criteria "RejectRule"
        Write-Excel -Data $lowCriteria2 -Severity "Low" -Criteria "SNMPv2Detected"
    }

}

Export-ModuleMember -Function Invoke-PfShell