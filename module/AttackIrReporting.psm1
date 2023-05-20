<#
.Description
This module aims to generate in an automated way the core documents assembling the available information from the MITRE ATT&CK(r) framework without the need to sift through the online resources. This can be done whenever a set of ATT&CK(r) (Sub-)Techniques are identified during the report writing as a deliverable for an incident response engagement. The module provides functions to generate recommendations, a CTID ATT&CK(r) FLow, an ATT&CK(r) NAvigator Layer and Sightings.
.SYNOPSIS
Powershell module to help generate documents to complement IR Reporting.
#>

$file_json_helper_attack_list = (get-location).path + "\helper_attack_list.json"
$file_json_helper_attack_array = (get-location).path + "\helper_attack_array.json"

function Get-ATTACKEnterpriseJSON {
    <#
    .Description
    This function fetches the latest available ATT&CK(r) STIX JSON file from Github. A verificatin is performed whether the file already exists or not. No option is implemented to fetch a previous version of the file.
    .PARAMETER Force
    Using this parameter will allow you to force a download of the ATT&CK(r) STIX JSON file from Github.
    .PARAMETER Version
    Using this parameter will allow you to select the version of the ATT&CK(r) STIX JSON file from Github.
    .LINK
    https://github.com/nightly-nessie/attack-ir-reporting
    .EXAMPLE
    # Fetch the latest available ATT&CK(r) STIX JSON file from Github.
    PS> Get-ATTACKEnterpriseJSON -Force
    .EXAMPLE
    # Fetch a specficic verision of the ATT&CK(r) STIX JSON file from Github.
    PS> Get-ATTACKEnterpriseJSON -Version 11.0
    .INPUTS
    None, objects cannot be pipe to New-ATTACKRecommendations.
    .OUTPUTS
    helper_enterprise_attack.json.
    .SYNOPSIS
    This function fetches the latest available ATT&CK(r) STIX JSON file from Github.
    #>
    [CmdletBinding(DefaultParametersetName='None')]
    Param(
        [Switch]$Force,
        [string]$Version
    )
    if ($Version) {
        $url_json_helper_enterprise_attack_version = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-" + [string]$version + ".json")
        $url_json_helper_enterprise_attack = $url_json_helper_enterprise_attack_version
    }
    else {
    $url_json_helper_enterprise_attack_latest = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    $url_json_helper_enterprise_attack = $url_json_helper_enterprise_attack_latest
    }
    Write-Host `u{2139} "The ATT&CK`u{00AE} JSON STIX file is required to continue. It will be downloaded if not already present in the folder"
    $file_json_helper_enterprise_attack = (get-location).path + "\helper_enterprise_attack.json"
    if ((-not(Test-Path -Path $file_json_helper_enterprise_attack -PathType Leaf)) -or ($Force.IsPresent) -or ($Version)) {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $url_json_helper_enterprise_attack -OutFile $file_json_helper_enterprise_attack
        Write-Host $url_json_helper_enterprise_attack + "has been downloaded."
        $array_obj_complete_attack = (Get-Content $file_json_helper_enterprise_attack -Raw) | ConvertFrom-Json
    }
    else {
    $array_obj_complete_attack = (Get-Content $file_json_helper_enterprise_attack -Raw) | ConvertFrom-Json
    $file_json_helper_enterprise_attack_property_modified = Get-Date ($array_obj_complete_attack.objects.Modified[0]) -UFormat "%F"
    $file_json_helper_enterprise_attack_property_version = $array_obj_complete_attack.objects.x_mitre_version[0]
    Write-Host `u{2139} "The local ATT&CK`u{00AE} JSON STIX file was present already and was last modified on" $($file_json_helper_enterprise_attack_property_modified)". It serves MITRE ATT&CK`u{00AE} version"$($file_json_helper_enterprise_attack_property_version)
    Write-Host `u{2139} "Consider running 'Get-ATTACKEnterpriseJSON -Force' to fetch the latest version or run 'Get-ATTACKEnterpriseJSON -Version 11.0' for a specific version. The current file is not overwritten."
    }
    Set-Variable -Name "file_json_helper_enterprise_attack" -value $file_json_helper_enterprise_attack -scope Global
    Set-Variable -Name "array_obj_complete_attack" -value $array_obj_complete_attack -scope Global
}

function Get-CISControlsJSON {
    Write-Host `u{2139} "The CIS Controls ATT&CK`u{00AE} mapping JSON STIX file is required to continue. It will be silently downloaded if not already present in the folder"
    $file_json_helper_cis_controls_mapping = (get-location).path + "\helper_cis_controls_mapping.json"
    if (-not(Test-Path -Path $file_json_helper_cis_controls_mapping -PathType Leaf)) {
        $url_json_helper_cis_controls_mapping = "https://raw.githubusercontent.com/nightly-nessie/attack-cis-controls/main/cis-controls-8-enterprise-attack-12.json"
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $url_json_helper_cis_controls_mapping -OutFile $file_json_helper_cis_controls_mapping
    }
    $array_obj_complete_cis_controls_mapping = (Get-Content $file_json_helper_cis_controls_mapping -Raw) | ConvertFrom-Json
    Set-Variable -Name "array_obj_complete_cis_controls_mapping" -value $array_obj_complete_cis_controls_mapping -scope Global
}

function Get-NISTControlsJSON {
    Write-Host `u{2139} "The NIST 800-53 Rev 5 Controls ATT&CK`u{00AE} mapping JSON STIX file is required to continue. It will be silently downloaded if not already present in the folder"
    $file_json_helper_nist_mapping = (get-location).path + "\helper_nist_attack_mapping.json"
    if (-not(Test-Path -Path $file_json_helper_nist_mapping -PathType Leaf)) {
        $url_json_helper_nist_mapping = "https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/main/frameworks/attack_10_1/nist800_53_r5/stix/nist800-53-r5-enterprise-attack.json"
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $url_json_helper_nist_mapping -OutFile $file_json_helper_nist_mapping
    }
    $array_obj_complete_nist_mapping = (Get-Content $file_json_helper_nist_mapping -Raw) | ConvertFrom-Json
    Set-Variable -Name "array_obj_complete_nist_mapping" -value $array_obj_complete_nist_mapping -scope Global
}

function Get-OSSEMJSON {
    Write-Host `u{2139} "The OSSEM ATT&CK`u{00AE} mapping JSON file is required to continue. It will be silently downloaded if not already present in the folder"
    $file_json_helper_ossem_mapping_array = (get-location).path + "\helper_ossem_attack_mapping.json"
    if (-not(Test-Path -Path $file_json_helper_ossem_mapping_array)) {
        $url_json_helper_ossem_mapping = "https://raw.githubusercontent.com/OTRF/OSSEM-DM/main/use-cases/mitre_attack/techniques_to_events_mapping.json"
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $url_json_helper_ossem_mapping -OutFile $file_json_helper_ossem_mapping_array
    }
    $array_obj_complete_ossem_mapping = (Get-Content $file_json_helper_ossem_mapping_array -Raw) | ConvertFrom-Json
    Set-Variable -Name "array_obj_complete_ossem_mapping" -value $array_obj_complete_ossem_mapping -scope Global
}

function Get-AtomicRedTeamJSON {
    Write-Host `u{2139} "The Red Canary Atomic Red Team tests mapping JSON file is required to continue. It will be silently downloaded if not already present in the folder"
    $file_json_helper_atomicred_mapping_array = (get-location).path + "\helper_atomicred_attack_mapping.json"
    if (-not(Test-Path -Path $file_json_helper_atomicred_mapping_array)) {
        $url_json_helper_atomicred_mapping = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/Attack-Navigator-Layers/art-navigator-layer.json"
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $url_json_helper_atomicred_mapping -OutFile $file_json_helper_atomicred_mapping_array
    }
    $array_obj_complete_atomicred_mapping = (Get-Content $file_json_helper_atomicred_mapping_array -Raw) | ConvertFrom-Json
    Set-Variable -Name "array_obj_complete_atomicred_mapping" -value $array_obj_complete_atomicred_mapping -scope Global
}

function Set-AttackEmpty {
    [Environment]::NewLine
    Write-Host `u{26A0} -Foregroundcolor DarkRed "No helper file" $($file_json_helper_attack_array)", "$($file_json_helper_attack_list)", ATT&CK`u{00AE} Navigator Layer, nor CISA Decider Export file containing the identified ATT&CK`u{00AE} Techniques is applied. Manual input is required."
    do {
        $list_obj_attack_techniques = Read-Host `u{2328} " Give a single or a semicolon seperated list of ATT&CK`u{00AE} IDs (for example: T1566.002;T1018;T1033)"
        $isValid = ($list_obj_attack_techniques -match '^T\d{4}(?:\.\d{3})?(?:;T\d{4}(?:\.\d{3})?)*$')
        if ($isValid -eq $false) {
            Write-Host `u{26A0} -Foregroundcolor DarkRed "Invalid input. Try again."
        }
        else {
            $list_obj_selected_attack_techniques = $list_obj_attack_techniques.ToString() -split ";" | Select-Object -Property @{Name='attack_id';Expression={$_}}
            $list_obj_complete_techniques = (($array_obj_complete_attack.objects | Where-Object {$_.x_mitre_deprecated -ne $true} | Where-Object {$_.revoked -ne $true} | Where-Object {$_.type -eq "attack-pattern"}).external_references | Where-Object{($_.source_name -eq "mitre-attack")}).external_id | Select-Object -Property @{Name='attack_id';Expression={$_}}
            if ($list_obj_selected_attack_techniques.count -eq 1)
            {
                $query_technique_exists = $list_obj_selected_attack_techniques.attack_id -in $list_obj_complete_techniques.attack_id
                if ($query_technique_exists -eq $false) {
                    Write-Host `u{26A0} -Foregroundcolor DarkRed $list_obj_selected_attack_techniques.attack_id "does not exist in the current ATT&CK Enterprise JSON. Please verify your input."
                    $isValid = $false
                }
            }
            else {
                $count_techniques=0..($list_obj_selected_attack_techniques.count-1)
                $list_counter = 1
                do {
                    foreach($instance in $count_techniques) {
                        $query_technique_exists = $list_obj_selected_attack_techniques.attack_id[$instance] -in $list_obj_complete_techniques.attack_id
                        if ($query_technique_exists -eq $false) {
                            Write-Host `u{26A0} -Foregroundcolor DarkRed $list_obj_selected_attack_techniques.attack_id[$instance] "does not exist in the current ATT&CK Enterprise JSON. Please verify your input."
                            $isValid = $false
                        }
                    $list_counter++
                    }
                }
                while ($list_counter -le $list_obj_selected_attack_techniques.count)
            }
        }
    }
    until ($isValid -eq $true)
    $list_obj_selected_attack_techniques = $list_obj_attack_techniques.ToString() -split ";" | Select-Object -Property @{Name='attack_id';Expression={$_}}
    Set-Variable -Name "list_obj_selected_attack_techniques" -value $list_obj_selected_attack_techniques -scope global
    Set-Variable -Name "switch_attack_tactic_generation" -value "MANUAL" -scope global
    $InputFile = "NoInput"
    Set-Variable -Name "InputFile" -value $InputFile -scope global
}

function Set-AttackList {
    if ($file_json_helper_attack_list){
        $obj_array_helper_attack_list = (Get-Content -Raw $file_json_helper_attack_list | ConvertFrom-Json)
        Write-Host `u{2705} -Foregroundcolor Green "A helper file" $($file_json_helper_attack_list) "containing identified ATT&CK`u{00AE} Techniques is found in the directory and will be used. It contains the following Techniques:" $($obj_array_helper_attack_list.techniques.attack_id -join ", ")
        $source_attacklist = Read-Host `u{2328} " Do you want to proceed with these techniques ([Y]/N)"
        if ((-not($source_attacklist)) -or ($source_attacklist -eq "Y")) {
            $list_obj_selected_attack_techniques = $obj_array_helper_attack_list.techniques | Select-Object -Property @{Name='attack_id';Expression={$_.attack_id}}
            Set-Variable -Name "list_obj_selected_attack_techniques" -value $list_obj_selected_attack_techniques -scope global
            Set-Variable -Name "switch_attack_tactic_generation" -value "MANUAL" -scope global
            $InputFile = "HelperInput"
            Set-Variable -Name "InputFile" -value $InputFile -scope global
        }
        else{
            Set-AttackEmpty
        }
    }
    else{
        Set-AttackEmpty
    }
}

function Set-AttackArray {
    $array_obj_complete_navigator_objects = (Get-Content -Raw $file_json_helper_attack_array | ConvertFrom-Json)
    $array_obj_sorted_navigator_objects = $array_obj_complete_navigator_objects.techniques | Sort-Object -Property attack_id
    Write-Host `u{2705} -Foregroundcolor Green "A source file" $($file_json_helper_attack_array) "containing identified ATT&CK`u{00AE} Techniques is found and will be used. It contains the following Techniques:" $($array_obj_complete_navigator_objects.techniques.attack_id -join ", ")
    $source_attacklist = Read-Host `u{2328} " Do you want to proceed with these techniques ([Y]/N)"
    if ((-not($source_attacklist)) -or ($source_attacklist -eq "Y")) {
        Set-Variable -Name "array_obj_sorted_navigator_objects" -value $array_obj_sorted_navigator_objects -scope global
        $InputFile = "HelperInput"
        Set-Variable -Name "InputFile" -value $InputFile -scope global
    }
    elseif (Test-Path -Path $file_json_helper_attack_list -PathType Leaf){
        Set-AttackList
    }
    else{
        Set-AttackEmpty
    }
}

function Get-AttackNavigatorLayer {
    $condition_multiple_tactics = ""
    $attack_navigator_layer = (Get-Content $file_json_attack_navigator_layer -Raw) | ConvertFrom-Json
    $attack_navigator_array = $attack_navigator_layer.techniques | Where-Object {$_.color -ne ""} | Select-Object TechniqueId,tactic 
    $attack_techniques_navigator_list = (($attack_navigator_array | Sort-Object TechniqueID -Unique).TechniqueId -join ", ")
    Write-Host `u{2705} -Foregroundcolor Green "An ATT&CK`u{00AE} Navigator Layer source file containing identified ATT&CK`u{00AE} Techniques was provided and will be used. It contains the following Techniques:" $($attack_techniques_navigator_list)
    $source_navigator = Read-Host `u{2328} " Do you want to proceed with these techniques ([Y]/N)"
    if ((-not($source_navigator)) -or ($source_navigator -eq "Y")) {
        $array_obj_selected_techniques = $attack_navigator_array | Group-Object -Property techniqueID | ForEach-Object {
            [PSCustomObject]@{
                attack_id = ($_.Group | Select-Object -First 1).techniqueID
                tactics = ($_.Group).tactic
            }
        }
        foreach($a in $array_obj_selected_techniques){
            if ($a.tactics.count -gt 1){
                $condition_multiple_tactics = "MULTIPLE"
            }
            else{
            }
        }
        if ($condition_multiple_tactics -eq "MULTIPLE") {
            $list_obj_selected_attack_techniques = $attack_navigator_array | Select-Object -Property @{Name='attack_id';Expression={$_.TechniqueID}}
            Set-Variable -Name "list_obj_selected_attack_techniques" -value $list_obj_selected_attack_techniques -scope global
            Set-Variable -Name "switch_attack_tactic_generation" -value "MANUAL" -scope global
        }
        else{
            $list_obj_selected_attack_techniques = $attack_navigator_array | Select-Object -Property @{Name='attack_id';Expression={$_.TechniqueID}}
            Set-Variable -Name "list_obj_selected_attack_techniques" -value $list_obj_selected_attack_techniques -scope global
            Set-Variable -Name "array_obj_selected_techniques" -value $array_obj_selected_techniques -scope global
            Set-Variable -Name "switch_attack_tactic_generation" -value "AUTO" -scope global
        }
    }
    else{
        if (Test-Path -Path $file_json_helper_attack_list -PathType Leaf){
            Set-AttackList
        }
        else{
            Set-AttackEmpty
        }
        
    }
}

function Get-DeciderExportJSON {
    [Environment]::NewLine
    $decider_export = (Get-Content $file_json_decider_export -Raw) | ConvertFrom-Json
    $decider_export_array = $decider_export.entries | Select-Object index,tacticName
    $decider_export_techniques_list = (($decider_export_array | Sort-Object index -Unique).index -join ", ")
    Write-Host `u{2705} -Foregroundcolor Green "A CISA Decider Export file containing identified ATT&CK`u{00AE} Techniques was provided and will be used. It contains the following Techniques:" $($decider_export_techniques_list)
    $source_decider = Read-Host `u{2328} " Do you want to proceed with these techniques ([Y]/N)"
    if ((-not($source_decider)) -or ($source_decider -eq "Y")) {
        $array_obj_selected_techniques = $decider_export_array | Group-Object -Property index | ForEach-Object {
            [PSCustomObject]@{
                attack_id = ($_.Group | Select-Object -First 1).index
                tactics = ($_.Group).tacticName -Replace(" ","-")
            }
        }
        foreach($a in $array_obj_selected_techniques){
            if ($a.tactics.count -gt 1){
                $condition_multiple_tactics = "MULTIPLE"
            }
            else{
            }
        }
        if ($condition_multiple_tactics -eq "MULTIPLE") {
            $list_obj_selected_attack_techniques = $decider_export_array | Select-Object -Property @{Name='attack_id';Expression={$_.index}}
            Set-Variable -Name "list_obj_selected_attack_techniques" -value $list_obj_selected_attack_techniques -scope global
            Set-Variable -Name "switch_attack_tactic_generation" -value "MANUAL" -scope global
        }
        else{
            $list_obj_selected_attack_techniques = $decider_export_array | Select-Object -Property @{Name='attack_id';Expression={$_.index}}
            Set-Variable -Name "list_obj_selected_attack_techniques" -value $list_obj_selected_attack_techniques -scope global
            Set-Variable -Name "array_obj_selected_techniques" -value $array_obj_selected_techniques -scope global
            Set-Variable -Name "switch_attack_tactic_generation" -value "AUTO" -scope global
        }
    }
    else{
        if (Test-Path -Path $file_json_helper_attack_list -PathType Leaf){
            Set-AttackList
        }
        else{
            Set-AttackEmpty
        }
    }
}

function Test-FileInputStructure ($InputFile){
    switch ($InputFile)
    {
        "NavigatorLayer" {
            # Verification if the provided Navigator Layer has a layer attribute, assuming this would indicate a correct file. If that's not the case, moving over to verifying an existing helper list file or manual input.
            $file_json_attack_navigator_layer = (get-location).path + "\" + $NavigatorFile
            Set-Variable -Name "file_json_attack_navigator_layer" -value $file_json_attack_navigator_layer -scope global
            [Environment]::NewLine
            if (Test-Path -Path $file_json_attack_navigator_layer -PathType Leaf) {
                $file_json_attack_navigator_layer_property_version = ((Get-Content $file_json_attack_navigator_layer -Raw) | ConvertFrom-Json).versions.layer
                if ($file_json_attack_navigator_layer_property_version) {
                    Get-AttackNavigatorLayer
                    $file_json_attack_navigator_layer_property_name = ((Get-Content $file_json_attack_navigator_layer -Raw) | ConvertFrom-Json).name
                    Set-Variable -Name "file_json_attack_navigator_layer_property_name" -value $file_json_attack_navigator_layer_property_name -scope global

                }
                else{
                    [Environment]::NewLine
                    Write-Host `u{26A0} -Foregroundcolor DarkRed "The provided file has not been identified as a Navigator Layer file."
                    $file_json_attack_navigator_layer_property_name = $null
                    [Environment]::NewLine
                    if (Test-Path -Path $file_json_helper_attack_list -PathType Leaf){
                        Set-AttackList
                    }
                    else{
                        Set-AttackEmpty
                    }
                }
            }
            elseif (Test-Path -Path $file_json_helper_attack_list -PathType Leaf){
                Set-AttackList
            }
            else{
                Set-AttackEmpty
            }
        }
        "DeciderExport" {
            # Verification if the provided Decider Export has a versions attribute, assuming this would indicate a correct file. If that's not the case, moving over to manual input.
            $file_json_decider_export = (get-location).path + "\" + $DeciderFile
            Set-Variable -Name "file_json_decider_export" -value $file_json_decider_export -scope global
            [Environment]::NewLine
            if (Test-Path -Path $file_json_decider_export -PathType Leaf) {
                $file_json_decider_export_property_version = ((Get-Content $file_json_decider_export -Raw) | ConvertFrom-Json).version
                if ($file_json_decider_export_property_version) {
                    Get-DeciderExportJSON
                    $file_json_decider_export_property_name = ((Get-Content $file_json_decider_export -Raw) | ConvertFrom-Json).title
                    Set-Variable -Name "file_json_decider_export_property_name" -value $file_json_decider_export_property_name -scope global
                }
                else{
                    [Environment]::NewLine
                    Write-Host `u{26A0} -Foregroundcolor DarkRed "The provided file has not been identified as a Decider Export file."
                    $file_json_decider_export_property_name = $null
                    [Environment]::NewLine
                    if (Test-Path -Path $file_json_helper_attack_list -PathType Leaf){
                        Set-AttackList
                    }
                    else{
                        Set-AttackEmpty
                    }
                }
            }
            elseif (Test-Path -Path $file_json_helper_attack_list -PathType Leaf){
                Set-AttackList
            }
            else{
                Set-AttackEmpty
            }
        }
        "NoInput" {
            if (Test-Path -Path $file_json_helper_attack_list -PathType Leaf){
                Set-AttackList
            }
            else{
                Set-AttackEmpty
            }
        }
    }
}
function Test-FileInputPropertyName ($InputFile) {
    function New-DocumentPrefix {
        [Environment]::NewLine
        $query_doc_name = Read-Host `u{2328} " Do you want to add a name or case(number) to the documents/flow (Y/[N])"
        if ((-not($query_doc_name)) -or ($query_doc_name -eq "N")) {
            $file_prefix = $null
            $flow_name_content = "Untitled Document"
            $file_prefix_content = $flow_name_content
        }
        elseif ($query_doc_name -eq "Y") {
            $file_prefix_content = Read-Host `u{2328} " Please provide a name or case(number)"
            $flow_name_content = $file_prefix_content
            $file_prefix = $file_prefix_content.Replace(" ","_")
            $file_prefix = $file_prefix+"_"
        }
        else {
            $file_prefix = $null
            $flow_name_content = "Untitled Document"
            $file_prefix_content = $flow_name_content
        }
        Set-Variable -Name "file_prefix" -value $file_prefix -scope global
        Set-Variable -Name "flow_name_content" -value $flow_name_content -scope global
        Set-Variable -Name "file_prefix_content" -value $file_prefix_content -scope global
    }
    switch ($InputFile)
    {
        "NavigatorLayer" {
            # Verification if the navigator layer or decider export was given a name. By default, an exported navigator layer will be called layer if it was not changed. A decider export will have untitled-date-time. Either way, it will be proposed to use the name to prepend the generated files with.
            if ($file_json_attack_navigator_layer_property_name){
                [Environment]::NewLine
                $query_doc_name = Read-Host `u{2328} " Do you want to add"$($file_json_attack_navigator_layer_property_name)"as the document prefix/flow name ([Y]/N)"
                if ((-not($query_doc_name)) -or ($query_doc_name -eq "Y")) {
                    $file_prefix_content = $file_json_attack_navigator_layer_property_name
                    $flow_name_content = $file_prefix_content
                    $file_prefix = $file_prefix_content.Replace(" ","_")
                    $file_prefix = $file_prefix+"_"
                }
                else {
                    New-DocumentPrefix
                }
            }
            else {
                New-DocumentPrefix
            }
        }
        "DeciderExport" {
            if ($file_json_decider_export_property_name){
                [Environment]::NewLine
                $query_doc_name = Read-Host `u{2328} " Do you want to add"$($file_json_decider_export_property_name)"as the document prefix/flow name ([Y]/N)"
                if ((-not($query_doc_name)) -or ($query_doc_name -eq "Y")) {
                    $file_prefix_content = $file_json_decider_export_property_name
                    $flow_name_content = $file_prefix_content
                    $file_prefix = $file_prefix_content.Replace(" ","_")
                    $file_prefix = $file_prefix+"_"
                }
                else {
                    New-DocumentPrefix
                }
            }
            else {
                New-DocumentPrefix
            }
        }
        "HelperInput" {
            if (Test-Path -Path $file_json_helper_attack_list -PathType Leaf){
                $file_json_helper_attack_list_property_name = ((Get-Content $file_json_helper_attack_list -Raw) | ConvertFrom-Json).name
                [Environment]::NewLine
                $query_doc_name = Read-Host `u{2328} " Do you want to add"$($file_json_helper_attack_list_property_name)"as the document prefix/flow name ([Y]/N)"
                if ((-not($query_doc_name)) -or ($query_doc_name -eq "Y")) {
                    $file_prefix_content = $file_json_helper_attack_list_property_name
                    $flow_name_content = $file_prefix_content
                    $file_prefix = $file_prefix_content.Replace(" ","_")
                    $file_prefix = $file_prefix+"_"
                }
                else {
                    New-DocumentPrefix
                }
            }
            elseif (Test-Path -Path $file_json_helper_attack_array -PathType Leaf){
                $file_json_helper_attack_array_property_name = ((Get-Content $file_json_helper_attack_array -Raw) | ConvertFrom-Json).name
                [Environment]::NewLine
                $query_doc_name = Read-Host `u{2328} " Do you want to add"$($file_json_helper_attack_array_property_name)"as the document prefix/flow name ([Y]/N)"
                if ((-not($query_doc_name)) -or ($query_doc_name -eq "Y")) {
                    $file_prefix_content = $file_json_helper_attack_list_property_name
                    $flow_name_content = $file_prefix_content
                    $file_prefix = $file_prefix_content.Replace(" ","_")
                    $file_prefix = $file_prefix+"_"
                }
                else {
                    New-DocumentPrefix
                }
            }
            else {
                New-DocumentPrefix
            }
        }
        "NoInput" {
            New-DocumentPrefix
        }
    }
    Set-Variable -Name "file_prefix" -value $file_prefix -scope global
    Set-Variable -Name "flow_name_content" -value $flow_name_content -scope global
    Set-Variable -Name "file_prefix_content" -value $file_prefix_content -scope global
}

function New-NavigatorLayerObjects {
    # Create lookup list, ease of retrieval of multiple attack-pattern ids associated with technique ids
    $array_obj_complete_mapping_external_id_attack_pattern = $array_obj_complete_attack.objects | Where-Object {$_.type -eq "attack-pattern"} | Select-Object -Property @{Name='id';Expression={ $_.id}} -ExpandProperty external_references| Where-Object{($_.source_name -eq "mitre-attack")} | Select-Object external_id, id
    $array_obj_filtered_mapping_external_id_attack_pattern = $array_obj_complete_mapping_external_id_attack_pattern | Where-Object {$_.external_id -In $list_obj_selected_attack_techniques.attack_id}
    $array_obj_sorted_mapping_external_id_attack_pattern = $array_obj_filtered_mapping_external_id_attack_pattern | Sort-Object -Property external_id
    [System.Collections.ArrayList]$array_obj_complete_navigator_objects =@()
    foreach ($obj_navigator_objects_property_external_id in $array_obj_sorted_mapping_external_id_attack_pattern) {
        $obj_filtered_attack_attack_pattern = $array_obj_complete_attack.objects | Where-Object {$_.type -eq "attack-pattern"} | Where-Object {$_.id -eq $obj_navigator_objects_property_external_id.id}
        $obj_navigator_objects_property_name = $obj_filtered_attack_attack_pattern.name
        if($obj_filtered_attack_attack_pattern.kill_chain_phases.phase_name.count -eq 1) {
            [System.Collections.ArrayList]$obj_navigator_objects_property_tactics =@()
            $obj_navigator_objects_property_tactics.Add($obj_filtered_attack_attack_pattern.kill_chain_phases.phase_name) | out-null
        }
        else{
            [System.Collections.ArrayList]$obj_navigator_objects_property_tactics =@()
            for ($count=0; $count -lt $obj_filtered_attack_attack_pattern.kill_chain_phases.phase_name.count; $count=$count+1) {
            $obj_navigator_objects_property_tactics.Add($obj_filtered_attack_attack_pattern.kill_chain_phases.phase_name[$count]) | out-null
            }
        }
        $obj_navigator_objects_property_external_references = $obj_filtered_attack_attack_pattern.external_references | Where-Object{$_.source_name -eq "mitre-attack"}
        $obj_navigator_objects_property_attack_id = $obj_navigator_objects_property_external_references.external_id
        $array_row = "" | Select-Object attack_id,attack_name,attack_tactics
        $array_row.attack_id = $obj_navigator_objects_property_attack_id
        $array_row.attack_name = $obj_navigator_objects_property_name
        $array_row.attack_tactics = $obj_navigator_objects_property_tactics
        $array_obj_complete_navigator_objects += $array_row
    }
    $array_obj_sorted_navigator_objects = $array_obj_complete_navigator_objects | Sort-Object -Property attack_id
    Set-Variable -Name "array_obj_sorted_navigator_objects" -value $array_obj_sorted_navigator_objects -scope global
}

function New-ATTACKRecommendations {
<#
.Description
This function generates in an automated way DOCX/TXT documents presenting the collected information across the ATT&CK(r) knowledge base enabling the analysts to add complementary recommendations. It will present the options to generate CIS Control and/or NIST 500-53 Rev 5 Mappings to the mitigations and it will generate OSSEM-DB information to the detections.
.PARAMETER NavigatorFile
A JSON Navigator Layer can be given as the source of the identified ATT&CK (Sub-)Techniques/Tactic Pairs.
.PARAMETER DeciderFile
A JSON exported Decider file can be given as the source of the identified ATT&CK (Sub-)Techniques/Tactic Pairs.
.EXAMPLE
# No parameters provided, the function will verify if any helper file is available and will provide the possibility to provide manual input.
PS> New-ATTACKRecommendations
.EXAMPLE
# Providing a ATT&CK Navigator Layer JSON file. The function will verify if it has the layer field. If chosen not to continue with the proposed identified (Sub-)Techniques from the file, it will use available helper file generated by a previous execution of the functions New-ATTACKRecommendations and/or New-CTIDATTACKFlow. It will present the option to generate identified assets as well.
PS> New-ATTACKRecommendations -NavigatorFile navigator_layer.json
.EXAMPLE
# Providing a Decider Export JSON file. The function will verify if it has the version field. If chosen not to continue with the proposed identified (Sub-)Techniques from the file, it will use available helper file generated by a previous execution of the functions New-ATTACKRecommendations and/or New-CTIDATTACKFlow. It will present the option to generate identified assets as well.
PS> New-ATTACKRecommendations -DeciderFile untitled-2023-04-19_19-10-48.json
.INPUTS
None, objects cannot be pipe to New-ATTACKRecommendations.
.OUTPUTS
introduction.docx|txt, eventually with a prefix.
recommendations.docx|txt, eventually with a prefix.
mitigations.docx|txt, eventually with a prefix.
detections.docx|txt, eventually with a prefix.
validations.docx|txt, eventually with a prefix.
helper_attack_list.json.
.SYNOPSIS
Generating assembled documents with MITRE ATT&CK(r) knowledge base information.
#>
param (
    [string]$NavigatorFile,
    [string]$DeciderFile
)

# Starting
Clear-Host
Write-Host -ForegroundColor Blue `u{1F6E0} "This function will construct a collection of word DOCX files or simple TXT files covering MITRE ATT&CK`u{00AE} information with regards to Mitigations and Detections based on identified ATT&CK (Sub-)Techniques. It also indicates the CIS Controls covered if the mitigations would have been implemented."
if ($NavigatorFile -and $DeciderFile){
    [Environment]::NewLine
    Write-Host `u{26A0} -Foregroundcolor DarkRed "Please only use one single input."
    [Environment]::NewLine
    Exit
}
elseif($NavigatorFile){
    $InputFile = "NavigatorLayer"
}
elseif($DeciderFile){
    $InputFile = "DeciderExport"
}else {
    $InputFile = "NoInput"
}

# Pull the ATT&CK(r) JSON STIX 2.1 if required, to allow the lookup and assembly of the array based on the input for the (Sub-)Techniques
Get-ATTACKEnterpriseJSON

# Pull Mitigations CIS Controls mapping JSON
Get-CISControlsJSON

# Pull NIST Controls mapping JSON
Get-NISTControlsJSON

# Pull OSSEM DM mapping JSON
Get-OSSEMJSON

# Pull Atomic Red Team mapping JSON
Get-AtomicRedTeamJSON

# Verification Navigator Layer or Decider Export 'structure'
Test-FileInputStructure $InputFile

# Verification Navigator Layer or Decider Export Name
Test-FileInputPropertyName $InputFile

# Create lookup list for ease of retrieval of multiple attack-pattern ids associated with technique ids
$array_obj_complete_mapping_external_id_attack_pattern = $array_obj_complete_attack.objects | Where-Object {$_.type -eq "attack-pattern"} | Select-Object -Property @{Name='id';Expression={ $_.id}} -ExpandProperty external_references| Where-Object{($_.source_name -eq "mitre-attack")} | Select-Object external_id, id
$array_obj_filtered_mapping_external_id_attack_pattern = $array_obj_complete_mapping_external_id_attack_pattern | Where-Object {$_.external_id -In $list_obj_selected_attack_techniques.attack_id}
$array_obj_sorted_mapping_external_id_attack_pattern = $array_obj_filtered_mapping_external_id_attack_pattern | Sort-Object -Property external_id

# Generate the introduction array for the identified techniques
$array_obj_complete_introduction =@()
foreach ($attack_id in $array_obj_sorted_mapping_external_id_attack_pattern) {
    $obj_filtered_attack_attack_pattern = $array_obj_complete_attack.objects | Where-Object {$_.type -eq "attack-pattern"} | Where-Object {$_.id -eq $attack_id.id}
    $content_introduction_attack_name = $obj_filtered_attack_attack_pattern.name
    if ($obj_filtered_attack_attack_pattern.kill_chain_phases.phase_name.count -eq 1) {
        [System.Collections.ArrayList]$array_obj_complete_attack_tactics =@()
        $array_obj_complete_attack_tactics.Add($obj_filtered_attack_attack_pattern.kill_chain_phases.phase_name) | out-null
    }
    else{
        [System.Collections.ArrayList]$array_obj_complete_attack_tactics =@()
        for ($i=0; $i -lt $obj_filtered_attack_attack_pattern.kill_chain_phases.phase_name.count; $i=$i+1) {
        $array_obj_complete_attack_tactics.Add($obj_filtered_attack_attack_pattern.kill_chain_phases.phase_name[$i]) | out-null
        }
    }
    $content_introduction_attack_description = $obj_filtered_attack_attack_pattern.description
    $obj_filtered_attack_attack_pattern_property_external_references = $obj_filtered_attack_attack_pattern.external_references | Where-Object{$_.source_name -eq "mitre-attack"}
    $content_introduction_attack_url = $obj_filtered_attack_attack_pattern_property_external_references.url
    $obj_filtered_attack_attack_pattern_property_external_id = $obj_filtered_attack_attack_pattern_property_external_references.external_id
    $array_row = "" | Select-Object attack_title,attack_ref,attack_description
    $array_row.attack_title = $obj_filtered_attack_attack_pattern_property_external_id + ": " + $content_introduction_attack_name
    $array_row.attack_ref = "ATT&CK`u{00AE} Tactic: " + ($array_obj_complete_attack_tactics -join ", ") + "`n" + "ATT&CK`u{00AE} URL: " + $content_introduction_attack_url
    $array_row.attack_description = $content_introduction_attack_description
    $array_obj_complete_introduction += $array_row
}

$content_introduction_intro = "This annex describes the possible mitigations, controls and eventually detections to implement to avoid a similar incident from happening again. The identified adversary TTPs (Techniques, Procedures and Tactics) are the result from the investigation conducted by CPIRT.
The information presented stems from the common library for adversarial TTPs, the MITRE ATT&CK`u{00AE} Framework [https://attack.mitre.org/].
The different techniques are listed, explained, and linked with the adversary tactics. Tactics are the goals an adversary wants to achieve. 
Next, based on these techniques, possible mitigations are listed, each with a description and relation with both the MITRE ATT&CK`u{00AE} Techniques and CIS Controls.
Some environments do not allow or struggle implementing the presented mitigations/controls. To cover these gaps, detections should be put in place. Coverage of the possible detections against the identified Techniques also includes the platform (IaaS, Containers, Linux, Windows ...) and the collection layer (Network, Host ...) to deploy the detection. Some detections may not be relevant for the environment as the platform may not be in use. The indication of the platform makes it straightforward to disregard those irrelevant detections."
$content_introduction_techniques = "According to the MITRE ATT&CK`u{00AE} Framework 'Techniques' represent 'how' an adversary achieves a tactical goal (tactic) by performing an action. For example, an adversary may dump credentials to achieve credential access. Below are the identified MITRE ATT&CK`u{00AE} Techniques listed which provide insight in the actions performed by perpetrators during this incident. Depending on the available information and artefacts, this may not be an exhaustive list but should provide a very reasonable starting point to understand the techniques used and the follow up mitigations/controls to implement. Assure you have put detections in place where mitigations/controls were not implemented or are insufficient."

# Verification whether office is installed on the system, if it is not, generate simplified txt files
try {
    New-Object -ComObject Word.Application | Out-Null
    $file_word_introduction = (get-location).path + "\"+$file_prefix+"introduction.docx"
    [Environment]::NewLine
    Write-Host `u{2139} -Foregroundcolor Green $($file_word_introduction) "is being generated."
    [ref]$SaveFormat = "microsoft.office.interop.word.WdSaveFormat" -as [type]
    $word = New-Object -ComObject Word.Application
    $word.Visible = $False
    $doc = $word.Documents.Add()
    $selection = $word.Selection
    $selection.Style = "Normal"
    $selection.TypeText($content_introduction_intro)
    $selection.TypeParagraph()
    $selection.Style = "Heading 1"
    $selection.TypeText("Techniques")
    $selection.TypeParagraph()
    $selection.Style = "Normal"
    $selection.TypeText($content_introduction_techniques)
    $selection.TypeParagraph()
    foreach ($attack in $array_obj_complete_introduction) {
        $selection.Style = "Heading 2"
        $selection.TypeText($attack.attack_title)
        $selection.TypeParagraph()
        $selection.Style = "Normal"
        $selection.TypeText($attack.attack_ref)
        $selection.TypeParagraph()
        $attack_description = $attack.attack_description -replace '\(Citation:.*\)', ''
        $attack_description = $attack_description -replace "\r?\n\r?\n", "`n"
        $selection.TypeText($attack_description)
        $selection.TypeParagraph()
        }
    $doc.saveas([ref] $file_word_introduction, [ref]$SaveFormat::wdFormatDocumentDefault)
    $doc.close()
    $word.quit()
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($doc) | Out-Null
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null
    Remove-Variable doc,word
    [gc]::collect()
    [gc]::WaitForPendingFinalizers()
}
catch {
    $file_txt_introduction = (get-location).path + "\"+$file_prefix+"introduction.txt"
    Write-Host `u{2139} -Foregroundcolor Green "Office doesn't seem to be installed. Generating a simplified txt file."
    Write-Host `u{2139} -Foregroundcolor Green $($file_txt_introduction) "is being generated."
    $content_technique = ""
    foreach ($attack in $array_obj_complete_introduction) {
        $content_technique +=  [Environment]::NewLine
        $content_technique += ($attack.attack_title)
        $content_technique += [Environment]::NewLine
        $content_technique += ($attack.attack_ref)
        $content_technique += [Environment]::NewLine
        $content_attack_description = $attack.attack_description -replace '\(Citation:.*\)', ''
        $content_attack_description = $content_attack_description -replace "\r?\n\r?\n", "`n"
        $content_technique += ($content_attack_description)
        $content_technique += [Environment]::NewLine
        $content_technique += "#################"
        $content_technique += [Environment]::NewLine
        }
    $file_txt_introduction_content = $content_introduction_intro + [Environment]::NewLine + $content_introduction_techniques + [Environment]::NewLine + $content_technique
    Set-Content -Path $file_txt_introduction -Value $file_txt_introduction_content
}
Write-Host `u{2705} -Foregroundcolor Green "Done."

# Generate complete list of mitigation objects
[Environment]::NewLine
Write-Host `u{2139} -Foregroundcolor Green "Preparing Mitigation mappings to CIS Controls`u{00AE} v8 and NIST 800-53 Rev 5 Controls. This might take a while."
$array_obj_complete_attack_mitigations = $array_obj_complete_attack.objects | Where-Object{ $_.relationship_type -eq "mitigates"}

# Filter out the technique selection from the mitigations and generate an array with the relevant information, and a prioritisation list
$array_obj_filtered_attack_mitigations = $array_obj_complete_attack_mitigations | Where-Object{$_.target_ref -In $array_obj_filtered_mapping_external_id_attack_pattern.id} | Where-Object{$_.x_mitre_deprecated -ne $true}
$array_obj_complete_mitigations =@()
$array_obj_filtered_cis_controls_prio =@()
foreach ($mitigation in $array_obj_filtered_attack_mitigations) {
    $obj_course_of_action_property_guid = $mitigation.source_ref
    $obj_mitigation = $array_obj_complete_attack.objects | Where-Object{ $_.type -eq "course-of-action"} | Where-Object{$_.id -eq $obj_course_of_action_property_guid}
    if ($obj_mitigation.x_mitre_deprecated -eq $true) {
    }
    else{
        $obj_course_of_action_property_guid = $mitigation.source_ref
        $obj_mitigation_property_description = $mitigation.description
        $obj_mitigation_attack_pattern = $array_obj_filtered_mapping_external_id_attack_pattern | Where-Object{ $_.id -eq $mitigation.target_ref}
        $mitigation_component_block = $array_obj_complete_attack.objects | Where-Object{ $_.type -eq "course-of-action"} | Where-Object{$_.id -eq $obj_course_of_action_property_guid}
        $obj_mitigation_property_id = $mitigation_component_block.external_references | Where-Object{ $_.source_name -eq "mitre-attack"}
        $array_obj_filtered_cis_controls_mapping = $array_obj_complete_cis_controls_mapping.objects | Where-Object{$_.target_ref -eq $mitigation.source_ref}
        $array_obj_complete_cis_control_content =@()
        foreach ($mapping in $array_obj_filtered_cis_controls_mapping){
            $obj_complete_cis_control = $array_obj_complete_cis_controls_mapping.objects | Where-Object{ $_.type -eq "course-of-action"} | Where-Object{$_.id -eq $mapping.source_ref}
            $content_cis_controls = $obj_complete_cis_control.external_references.external_id + " " + $obj_complete_cis_control.name
            $array_obj_complete_cis_control_content += $content_cis_controls
            }
        foreach ($mapping in $array_obj_filtered_cis_controls_mapping){
            $obj_complete_cis_control = $array_obj_complete_cis_controls_mapping.objects | Where-Object{ $_.type -eq "course-of-action"} | Where-Object{$_.id -eq $mapping.source_ref}
            $array_row = "" | Select-Object cis_control_id,cis_control_name,cis_control_ig
            $array_row.cis_control_id = $obj_complete_cis_control.external_references.external_id
            $array_row.cis_control_name = $obj_complete_cis_control.name
            $array_row.cis_control_ig = $obj_complete_cis_control.x_cis_ig
            $array_obj_filtered_cis_controls_prio += $array_row
            }
        $query_content_cis_controls = [string]::IsNullOrEmpty($array_obj_complete_cis_control_content)
        if ($query_content_cis_controls -eq $false) {
            $content_cis_controls_body = $array_obj_complete_cis_control_content -join "`n"
        }
        else {
            $content_cis_controls_body = "There is no CIS Control`u{00AE} mapped with this Mitigation."
        }
        $nist_coas = $array_obj_complete_nist_mapping.objects | Where-Object{ $_.relationship_type -eq "mitigates"} | Where-Object{$_.target_ref -eq $mitigation.target_ref}
        $nist_control_array =@()
            foreach ($c in $nist_coas){
                $nist_coa_block = $array_obj_complete_nist_mapping.objects | Where-Object{ $_.type -eq "course-of-action"} | Where-Object{ $_.id -eq $c.source_ref}
                $nist_control_id = $nist_coa_block.external_references.external_id
                $nist_control_name = $nist_coa_block.name
                $nist_string = $nist_control_id + " " + $nist_control_name
                $nist_control_array += $nist_string
            }
        $nist_control_array = $nist_control_array | Sort-Object
        $nist_control_body = $nist_control_array -join "`n"
        $array_row = "" | Select-Object name,external_id,url,description,cis_control,nist_control,attack_id
        $array_row.name = $mitigation_component_block.name
        $array_row.external_id = $obj_mitigation_property_id.external_id
        $array_row.url = $obj_mitigation_property_id.url
        $array_row.description = $obj_mitigation_property_description
        $array_row.attack_id = $obj_mitigation_attack_pattern.external_id
        $array_row.cis_control = $content_cis_controls_body
        $array_row.nist_control = $nist_control_body
        $array_obj_complete_mitigations += $array_row
        }
    }
$array_obj_sorted_mitigations = $array_obj_complete_mitigations |  Sort-Object -Property external_id
$array_obj_complete_cis_controls_prio = $array_obj_filtered_cis_controls_prio | Group-Object -Property cis_control_id | ForEach-Object {
    [PSCustomObject]@{
        cis_control_id = $_.Name
        cis_control_name = ($_.Group | Select-Object -First 1).cis_control_name
        cis_control_ig = ($_.Group | Select-Object -First 1).cis_control_ig
        cis_control_count = ($_.Group | Measure-Object).Count
    }
} | Sort-Object -Property @{expression = 'cis_control_ig';Descending = $false}, @{expression = 'cis_control_count';Descending = $true},  @{expression = 'cis_control_id';Descending = $false}

# Verification whether office is installed on the system, if it is not, generate simplified txt files
try {
    New-Object -ComObject Word.Application | Out-Null
    $file_word_mitigations = (get-location).path + "\"+$file_prefix+"mitigations.docx"
    [ref]$SaveFormat = "microsoft.office.interop.word.WdSaveFormat" -as [type]

    # Request whether the output should include the CIS Controls, the NIST 800-53 Controls, both or neither. Add the prioritisaion list as required.
    $query_cis_controls_mapping = Read-Host `u{2328} " Do you want to generate the CIS Controls`u{00AE} v8 mapping? ([Y]/N)"
    if ((-not($query_cis_controls_mapping)) -or ($query_cis_controls_mapping -eq "Y")) {
        $query_nist_controls_mapping = Read-Host `u{2328} " Do you want to generate the NIST 800-53 Rev 5 Controls mapping? (Y/[N])"
        if ((-not($query_nist_controls_mapping)) -or ($query_nist_controls_mapping -eq "N")) {
            $switch_control_mapping_selection = "CX"
        }
        else {
            $switch_control_mapping_selection = "CN"
        }
    }
    else {
        $query_nist_controls_mapping = Read-Host `u{2328} " Do you want to generate the NIST 800-53 Rev 5 Controls mapping? (Y/[N])"
        if ((-not($query_nist_controls_mapping)) -or ($query_nist_controls_mapping -eq "N")) {
            $switch_control_mapping_selection = "XX"
        }
        else {
            $switch_control_mapping_selection = "XN"
        }
    }
    switch ($switch_control_mapping_selection)
    {
        "CN" {
                Write-Host `u{2139} -Foregroundcolor Green "Both CIS Controls`u{00AE} v8 and NIST 800-53 Rev 5 Controls are being generated."
                $var_table_columns = 3
                $var_table_lines_row = 4
                $var_table_rows = (($array_obj_sorted_mitigations.Count+1)*($var_table_lines_row))
                $word = New-Object -ComObject Word.Application
                $word.Visible = $False
                $doc = $word.Documents.Add()
                $selection = $word.Selection
                $selection.Style = "Heading 1"
                $selection.TypeText("Mitigations/Controls")
                $selection.TypeParagraph()
                $selection.Style = "Normal"
                $selection.TypeText("Mitigations represent security concepts and classes of technologies that can be used to prevent (Sub)-Techniques from being successfully executed.")
                $selection.TypeParagraph()
                $selection.Style = "Heading 2"
                $selection.TypeText("Mitigations Resume")
                $selection.TypeParagraph()
                Foreach($mitigation in $array_obj_sorted_mitigations) {
                    $resume_description = "`u{2022} " + $mitigation.description + [Environment]::NewLine
                    $resume_description = $resume_description -replace '\(Citation:.*\)', ''
                    $resume_description = $resume_description -replace "\r?\n\r?\n", "`n"
                    $selection.TypeText($resume_description)
                }
                $selection.EndKey(6) | Out-Null
                $selection.InsertNewPage()
                $selection.Style = "Heading 2"
                $selection.TypeText("Mitigations overview")
                $selection.TypeParagraph()
                $selection.Style = "Normal"
                $selection.TypeText("The mitigations listed below are mapped with the CIS Controls`u{00AE} v8 and the NIST 800-53 Rev 5 Controls. This mapping demonstrates which Controls are supported with the implementation of the corresponding Mitigations.")
                $range = $selection.Range()
                $selection.Tables.Add($range,$var_table_rows,$var_table_columns) | Out-Null
                $table_mitigations = $selection.Tables.item(1)
                $table_mitigations.Cell(1,1).Range.Font.Bold=$True
                $table_mitigations.Cell(1,1).Range.Text = "Mitigation ID: Name"
                $table_mitigations.Cell(1,2).Range.Font.Bold=$True
                $table_mitigations.Cell(1,2).Range.Text = "Mitigation URL"
                $table_mitigations.Cell(1,3).Range.Font.Bold=$True
                $table_mitigations.Cell(1,3).Range.Text = "Covered ATT&CK`u{00AE} Technique"
                $table_mitigations.Cell(2,3).Merge($table_mitigations.Cell(2,1))
                $table_mitigations.Cell(2,1).Range.Font.Bold=$True
                $table_mitigations.Cell(2,1).Range.Text = "Description"
                $table_mitigations.Cell(3,3).Merge($table_mitigations.Cell(3,1))
                $table_mitigations.Cell(3,1).Range.Font.Bold=$True
                $table_mitigations.Cell(3,1).Range.Text = "CIS Controls`u{00AE} v8"
                $table_mitigations.Cell(4,3).Merge($table_mitigations.Cell(4,1))
                $table_mitigations.Cell(4,1).Range.Font.Bold=$True
                $table_mitigations.Cell(4,1).Range.Text = "NIST 800-53 Rev 5 Controls"
                Foreach($mitigation in $array_obj_sorted_mitigations) {
                    $table_mitigations.Range.Style = "Table Grid"
                    $table_mitigations.Cell(($var_table_lines_row+1),1).Range.Font.Bold=$True
                    $table_mitigations.Cell(($var_table_lines_row+1),1).Range.Text = $mitigation.external_id + ": " + $mitigation.name
                    $table_mitigations.Cell(($var_table_lines_row+1),2).Range.Text = $mitigation.url
                    $table_mitigations.Cell(($var_table_lines_row+1),2).Range.Hyperlinks.Add($table_mitigations.Cell(($var_table_lines_row+1),2).Range, $mitigation.url, "", "", $mitigation.external_id) | Out-Null
                    $table_mitigations.Cell(($var_table_lines_row+1),3).Range.Text = $mitigation.attack_id
                    $content_generated_url = $mitigation.attack_id.Replace(".","/")
                    $table_mitigations.Cell(($var_table_lines_row+1),3).Range.Hyperlinks.Add($table_mitigations.Cell(($var_table_lines_row+1),3).Range, "https://attack.mitre.org/techniques/" + $content_generated_url, "", "", $mitigation.attack_id) | Out-Null
                    $table_mitigations.Cell(($var_table_lines_row+2),3).Merge($table_mitigations.Cell(($var_table_lines_row+2),1))
                    $content_mitigation_description = $mitigation.description -replace '\(Citation:.*\)', ''
                    $content_mitigation_description = $content_mitigation_description -replace "\r?\n\r?\n", "`n"
                    $table_mitigations.Cell(($var_table_lines_row+2),1).Range.Text = $content_mitigation_description
                    $table_mitigations.Cell(($var_table_lines_row+3),3).Merge($table_mitigations.Cell(($var_table_lines_row+3),1))
                    $table_mitigations.Cell(($var_table_lines_row+3),1).Range.Text = $mitigation.cis_control
                    $table_mitigations.Cell(($var_table_lines_row+4),3).Merge($table_mitigations.Cell(($var_table_lines_row+4),1))
                    $table_mitigations.Cell(($var_table_lines_row+4),1).Range.Text = $mitigation.nist_control
                    $var_table_lines_row = $var_table_lines_row+4
                }
                $selection.EndKey(6) | Out-Null
                $selection.InsertNewPage()
                $selection.Style = "Heading 2"
                $selection.TypeText("CIS Controls`u{00AE} Implementation Priority Guideline")
                $selection.TypeParagraph()
                $selection.Style = "Normal"
                $selection.TypeText("Below list presents a possible implementation priority, based on the lowest implementation groups where the CIS Control`u{00AE} is associated with and the weight of that specific CIS Control`u{00AE} in the mapping with the identified ATT&CK (Sub-)Techniques and their associated Mitigations.")
                $var_table_columns = 4
                $var_table_rows = ($array_obj_complete_cis_controls_prio.count + 1)
                $range = $selection.Range()
                $selection.Tables.Add($range,$var_table_rows,$var_table_columns) | Out-Null
                $table_cis_controls_prio = $selection.Tables.item(1)
                $table_cis_controls_prio.Cell(1,1).Range.Font.Bold=$True
                $table_cis_controls_prio.Cell(1,1).Range.Text = "Control`u{00AE} ID"
                $table_cis_controls_prio.Cell(1,2).Range.Font.Bold=$True
                $table_cis_controls_prio.Cell(1,2).Range.Text = "Control`u{00AE} Description"
                $table_cis_controls_prio.Cell(1,3).Range.Font.Bold=$True
                $table_cis_controls_prio.Cell(1,3).Range.Text = "IG"
                $table_cis_controls_prio.Cell(1,4).Range.Font.Bold=$True
                $table_cis_controls_prio.Cell(1,4).Range.Text = "Relative Weight"
                $Line_start = 2
                Foreach($mitigation in $array_obj_complete_cis_controls_prio) {
                    $table_cis_controls_prio.Range.Style = "Table Grid"
                    $table_cis_controls_prio.Cell(($Line_start),1).Range.Font.Bold=$True
                    $table_cis_controls_prio.Cell(($Line_start),1).Range.Text = $mitigation.cis_control_id
                    $table_cis_controls_prio.Cell(($Line_start),2).Range.Text = $mitigation.cis_control_name
                    $table_cis_controls_prio.Cell(($Line_start),3).Range.Text = $mitigation.cis_control_ig
                    $table_cis_controls_prio.Cell(($Line_start),4).Range.Text = [string]$mitigation.cis_control_count
                    $Line_start = $Line_start + 1
                }
        }
        "CX" {
                    Write-Host `u{2139} -Foregroundcolor Green "Only CIS Controls`u{00AE} v8 are being generated."
                    $var_table_columns = 3
                    $var_table_lines_row = 3
                    $var_table_rows = (($array_obj_sorted_mitigations.Count+1)*($var_table_lines_row))
                    $word = New-Object -ComObject Word.Application
                    $word.Visible = $False
                    $doc = $word.Documents.Add()
                    $selection = $word.Selection
                    $selection.Style = "Heading 1"
                    $selection.TypeText("Mitigations/Controls")
                    $selection.TypeParagraph()
                    $selection.Style = "Normal"
                    $selection.TypeText("Mitigations represent security concepts and classes of technologies that can be used to prevent (Sub)-Techniques from being successfully executed.")
                    $selection.TypeParagraph()
                    $selection.Style = "Heading 2"
                    $selection.TypeText("Mitigations Resume")
                    $selection.TypeParagraph()
                    Foreach($mitigation in $array_obj_sorted_mitigations) {
                        $resume_description = "`u{2022} " + $mitigation.description + [Environment]::NewLine
                        $resume_description = $resume_description -replace '\(Citation:.*\)', ''
                        $resume_description = $resume_description -replace "\r?\n\r?\n", "`n"
                        $selection.TypeText($resume_description)
                    }
                    $selection.EndKey(6) | Out-Null
                    $selection.InsertNewPage()
                    $selection.Style = "Heading 2"
                    $selection.TypeText("Mitigations overview")
                    $selection.TypeParagraph()
                    $selection.Style = "Normal"
                    $selection.TypeText("The mitigations listed below are mapped with the CIS Controls`u{00AE} v8. This mapping demonstrates which Controls are supported with the implementation of the corresponding Mitigations.")
                    $range = $selection.Range()
                    $selection.Tables.Add($range,$var_table_rows,$var_table_columns) | Out-Null
                    $table_mitigations = $selection.Tables.item(1)
                    $table_mitigations.Cell(1,1).Range.Font.Bold=$True
                    $table_mitigations.Cell(1,1).Range.Text = "Mitigation ID: Name"
                    $table_mitigations.Cell(1,2).Range.Font.Bold=$True
                    $table_mitigations.Cell(1,2).Range.Text = "Mitigation URL"
                    $table_mitigations.Cell(1,3).Range.Font.Bold=$True
                    $table_mitigations.Cell(1,3).Range.Text = "Covered ATT&CK`u{00AE} Technique"
                    $table_mitigations.Cell(2,3).Merge($table_mitigations.Cell(2,1))
                    $table_mitigations.Cell(2,1).Range.Font.Bold=$True
                    $table_mitigations.Cell(2,1).Range.Text = "Description"
                    $table_mitigations.Cell(3,3).Merge($table_mitigations.Cell(3,1))
                    $table_mitigations.Cell(3,1).Range.Font.Bold=$True
                    $table_mitigations.Cell(3,1).Range.Text = "CIS Controls`u{00AE} v8"
                    Foreach($mitigation in $array_obj_sorted_mitigations) {
                        $table_mitigations.Range.Style = "Table Grid"
                        $table_mitigations.Cell(($var_table_lines_row+1),1).Range.Font.Bold=$True
                        $table_mitigations.Cell(($var_table_lines_row+1),1).Range.Text = $mitigation.external_id + ": " + $mitigation.name
                        $table_mitigations.Cell(($var_table_lines_row+1),2).Range.Text = $mitigation.url
                        $table_mitigations.Cell(($var_table_lines_row+1),2).Range.Hyperlinks.Add($table_mitigations.Cell(($var_table_lines_row+1),2).Range, $mitigation.url, "", "", $mitigation.external_id) | Out-Null
                        $table_mitigations.Cell(($var_table_lines_row+1),3).Range.Text = $mitigation.attack_id
                        $content_generated_url = $mitigation.attack_id.Replace(".","/")
                        $table_mitigations.Cell(($var_table_lines_row+1),3).Range.Hyperlinks.Add($table_mitigations.Cell(($var_table_lines_row+1),3).Range, "https://attack.mitre.org/techniques/" + $content_generated_url, "", "", $mitigation.attack_id) | Out-Null
                        $table_mitigations.Cell(($var_table_lines_row+2),3).Merge($table_mitigations.Cell(($var_table_lines_row+2),1))
                        $content_mitigation_description = $mitigation.description -replace '\(Citation:.*\)', ''
                        $content_mitigation_description = $content_mitigation_description -replace "\r?\n\r?\n", "`n"
                        $table_mitigations.Cell(($var_table_lines_row+2),1).Range.Text = $content_mitigation_description 
                        $table_mitigations.Cell(($var_table_lines_row+3),3).Merge($table_mitigations.Cell(($var_table_lines_row+3),1))
                        $table_mitigations.Cell(($var_table_lines_row+3),1).Range.Text = $mitigation.cis_control
                        $var_table_lines_row = $var_table_lines_row+3
                    }
                    $selection.EndKey(6) | Out-Null
                    $selection.InsertNewPage()
                    $selection.Style = "Heading 2"
                    $selection.TypeText("CIS Controls`u{00AE} Implementation Priority Guideline")
                    $selection.TypeParagraph()
                    $selection.Style = "Normal"
                    $selection.TypeText("Below list presents a possible implementation priority, based on the lowest implementation groups where the CIS Control`u{00AE} is associated with and the weight of that specific CIS Control`u{00AE} in the mapping with the identified ATT&CK (Sub-)Techniques and their associated Mitigations.")
                    $var_table_columns = 4
                    $var_table_rows = ($array_obj_complete_cis_controls_prio.count + 1)
                    $range = $selection.Range()
                    $selection.Tables.Add($range,$var_table_rows,$var_table_columns) | Out-Null
                    $table_cis_controls_prio = $selection.Tables.item(1)
                    $table_cis_controls_prio.Cell(1,1).Range.Font.Bold=$True
                    $table_cis_controls_prio.Cell(1,1).Range.Text = "Control`u{00AE} ID"
                    $table_cis_controls_prio.Cell(1,2).Range.Font.Bold=$True
                    $table_cis_controls_prio.Cell(1,2).Range.Text = "Control`u{00AE} Description"
                    $table_cis_controls_prio.Cell(1,3).Range.Font.Bold=$True
                    $table_cis_controls_prio.Cell(1,3).Range.Text = "IG"
                    $table_cis_controls_prio.Cell(1,4).Range.Font.Bold=$True
                    $table_cis_controls_prio.Cell(1,4).Range.Text = "Relative Weight"
                    $Line_start = 2
                    Foreach($mitigation in $array_obj_complete_cis_controls_prio) {
                        $table_cis_controls_prio.Range.Style = "Table Grid"
                        $table_cis_controls_prio.Cell(($Line_start),1).Range.Font.Bold=$True
                        $table_cis_controls_prio.Cell(($Line_start),1).Range.Text = $mitigation.cis_control_id
                        $table_cis_controls_prio.Cell(($Line_start),2).Range.Text = $mitigation.cis_control_name
                        $table_cis_controls_prio.Cell(($Line_start),3).Range.Text = $mitigation.cis_control_ig
                        $table_cis_controls_prio.Cell(($Line_start),4).Range.Text = [string]$mitigation.cis_control_count
                        $Line_start = $Line_start + 1
                    }
        }
        "XX" {
                    Write-Host `u{2139} -Foregroundcolor Green "None of the CIS Controls`u{00AE} v8 nor NIST 800-53 Rev 5 Controls are being generated."
                    $var_table_columns = 3
                    $var_table_lines_row = 2
                    $var_table_rows = (($array_obj_sorted_mitigations.Count+1)*($var_table_lines_row))
                    $word = New-Object -ComObject Word.Application
                    $word.Visible = $False
                    $doc = $word.Documents.Add()
                    $selection = $word.Selection
                    $selection.Style = "Heading 1"
                    $selection.TypeText("Mitigations")
                    $selection.TypeParagraph()
                    $selection.Style = "Normal"
                    $selection.TypeText("Mitigations represent security concepts and classes of technologies that can be used to prevent (Sub)-Techniques from being successfully executed.")
                    $selection.TypeParagraph()
                    $selection.Style = "Heading 2"
                    $selection.TypeText("Mitigations Resume")
                    $selection.TypeParagraph()
                    Foreach($mitigation in $array_obj_sorted_mitigations) {
                        $resume_description = "`u{2022} " + $mitigation.description + [Environment]::NewLine
                        $resume_description = $resume_description -replace '\(Citation:.*\)', ''
                        $resume_description = $resume_description -replace "\r?\n\r?\n", "`n"
                        $selection.TypeText($resume_description)
                    }
                    $selection.EndKey(6) | Out-Null
                    $selection.InsertNewPage()
                    $selection.Style = "Heading 2"
                    $selection.TypeText("Mitigations overview")
                    $selection.TypeParagraph()
                    $range = $selection.Range()
                    $selection.Tables.Add($range,$var_table_rows,$var_table_columns) | Out-Null
                    $table_mitigations = $selection.Tables.item(1)
                    $table_mitigations.Cell(1,1).Range.Font.Bold=$True
                    $table_mitigations.Cell(1,1).Range.Text = "Mitigation ID: Name"
                    $table_mitigations.Cell(1,2).Range.Font.Bold=$True
                    $table_mitigations.Cell(1,2).Range.Text = "Mitigation URL"
                    $table_mitigations.Cell(1,3).Range.Font.Bold=$True
                    $table_mitigations.Cell(1,3).Range.Text = "Covered ATT&CK`u{00AE} Technique"
                    $table_mitigations.Cell(2,3).Merge($table_mitigations.Cell(2,1))
                    $table_mitigations.Cell(2,1).Range.Font.Bold=$True
                    $table_mitigations.Cell(2,1).Range.Text = "Description"
                    Foreach($mitigation in $array_obj_sorted_mitigations) {
                        $table_mitigations.Range.Style = "Table Grid"
                        $table_mitigations.Cell(($var_table_lines_row+1),1).Range.Font.Bold=$True
                        $table_mitigations.Cell(($var_table_lines_row+1),1).Range.Text = $mitigation.external_id + ": " + $mitigation.name
                        $table_mitigations.Cell(($var_table_lines_row+1),2).Range.Text = $mitigation.url
                        $table_mitigations.Cell(($var_table_lines_row+1),2).Range.Hyperlinks.Add($table_mitigations.Cell(($var_table_lines_row+1),2).Range, $mitigation.url, "", "", $mitigation.external_id) | Out-Null
                        $table_mitigations.Cell(($var_table_lines_row+1),3).Range.Text = $mitigation.attack_id
                        $content_generated_url = $mitigation.attack_id.Replace(".","/")
                        $table_mitigations.Cell(($var_table_lines_row+1),3).Range.Hyperlinks.Add($table_mitigations.Cell(($var_table_lines_row+1),3).Range, "https://attack.mitre.org/techniques/" + $content_generated_url, "", "", $mitigation.attack_id) | Out-Null
                        $table_mitigations.Cell(($var_table_lines_row+2),3).Merge($table_mitigations.Cell(($var_table_lines_row+2),1))
                        $content_mitigation_description = $mitigation.description -replace '\(Citation:.*\)', ''
                        $content_mitigation_description = $content_mitigation_description -replace "\r?\n\r?\n", "`n"
                        $table_mitigations.Cell(($var_table_lines_row+2),1).Range.Text = $content_mitigation_description
                        $var_table_lines_row = $var_table_lines_row+2
                    }
        }
        "XN" {
                    Write-Host `u{2139} -Foregroundcolor Green "Only NIST 800-53 Rev 5 Controls are being generated."
                    $var_table_columns = 3
                    $var_table_lines_row = 3
                    $var_table_rows = (($array_obj_sorted_mitigations.Count+1)*($var_table_lines_row))
                    $word = New-Object -ComObject Word.Application
                    $word.Visible = $False
                    $doc = $word.Documents.Add()
                    $selection = $word.Selection
                    $selection.Style = "Heading 1"
                    $selection.TypeText("Mitigations/Controls")
                    $selection.TypeParagraph()
                    $selection.Style = "Normal"
                    $selection.TypeText("Mitigations represent security concepts and classes of technologies that can be used to prevent (Sub)-Techniques from being successfully executed. The mitigations listed below are mapped with the NIST 800-53 Rev 5 Controls. This mapping demonstrates which Controls are supported with the implementation of the corresponding Mitigations.")
                    $selection.TypeParagraph()
                    $selection.Style = "Heading 2"
                    $selection.TypeText("Mitigations Resume")
                    $selection.TypeParagraph()
                    Foreach($mitigation in $array_obj_sorted_mitigations) {
                        $resume_description = "`u{2022} " + $mitigation.description + [Environment]::NewLine
                        $resume_description = $resume_description -replace '\(Citation:.*\)', ''
                        $resume_description = $resume_description -replace "\r?\n\r?\n", "`n"
                        $selection.TypeText($resume_description)
                    }
                    $selection.EndKey(6) | Out-Null
                    $selection.InsertNewPage()
                    $selection.Style = "Heading 2"
                    $selection.TypeText("Mitigations overview")
                    $selection.TypeParagraph()
                    $selection.Style = "Normal"
                    $selection.TypeText("The mitigations listed below are mapped with the NIST 800-53 Rev 5 Controls. This mapping demonstrates which Controls are supported with the implementation of the corresponding Mitigations.")
                    $range = $selection.Range()
                    $selection.Tables.Add($range,$var_table_rows,$var_table_columns) | Out-Null
                    $table_mitigations = $selection.Tables.item(1)
                    $table_mitigations.Cell(1,1).Range.Font.Bold=$True
                    $table_mitigations.Cell(1,1).Range.Text = "Mitigation ID: Name"
                    $table_mitigations.Cell(1,2).Range.Font.Bold=$True
                    $table_mitigations.Cell(1,2).Range.Text = "Mitigation URL"
                    $table_mitigations.Cell(1,3).Range.Font.Bold=$True
                    $table_mitigations.Cell(1,3).Range.Text = "Covered ATT&CK`u{00AE} Technique"
                    $table_mitigations.Cell(2,3).Merge($table_mitigations.Cell(2,1))
                    $table_mitigations.Cell(2,1).Range.Font.Bold=$True
                    $table_mitigations.Cell(2,1).Range.Text = "Description"
                    $table_mitigations.Cell(3,3).Merge($table_mitigations.Cell(3,1))
                    $table_mitigations.Cell(3,1).Range.Font.Bold=$True
                    $table_mitigations.Cell(3,1).Range.Text = "NIST 800-53 Rev 5 Controls"
                    Foreach($mitigation in $array_obj_sorted_mitigations) {
                        $table_mitigations.Range.Style = "Table Grid"
                        $table_mitigations.Cell(($var_table_lines_row+1),1).Range.Font.Bold=$True
                        $table_mitigations.Cell(($var_table_lines_row+1),1).Range.Text = $mitigation.external_id + ": " + $mitigation.name
                        $table_mitigations.Cell(($var_table_lines_row+1),2).Range.Text = $mitigation.url
                        $table_mitigations.Cell(($var_table_lines_row+1),2).Range.Hyperlinks.Add($table_mitigations.Cell(($var_table_lines_row+1),2).Range, $mitigation.url, "", "", $mitigation.external_id) | Out-Null
                        $table_mitigations.Cell(($var_table_lines_row+1),3).Range.Text = $mitigation.attack_id
                        $content_generated_url = $mitigation.attack_id.Replace(".","/")
                        $table_mitigations.Cell(($var_table_lines_row+1),3).Range.Hyperlinks.Add($table_mitigations.Cell(($var_table_lines_row+1),3).Range, "https://attack.mitre.org/techniques/" + $content_generated_url, "", "", $mitigation.attack_id) | Out-Null
                        $table_mitigations.Cell(($var_table_lines_row+2),3).Merge($table_mitigations.Cell(($var_table_lines_row+2),1))
                        $content_mitigation_description = $mitigation.description -replace '\(Citation:.*\)', ''
                        $content_mitigation_description = $content_mitigation_description -replace "\r?\n\r?\n", "`n"
                        $table_mitigations.Cell(($var_table_lines_row+2),1).Range.Text = $content_mitigation_description
                        $table_mitigations.Cell(($var_table_lines_row+3),3).Merge($table_mitigations.Cell(($var_table_lines_row+3),1))
                        $table_mitigations.Cell(($var_table_lines_row+3),1).Range.Text = $mitigation.nist_control
                        $var_table_lines_row = $var_table_lines_row+3
                    }
        }    
    }
    Write-Host `u{2139} -Foregroundcolor Green $($file_word_mitigations) "is being generated."
    $doc.saveas([ref] $file_word_mitigations, [ref]$SaveFormat::wdFormatDocumentDefault)
    $doc.close()
    $word.quit()
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($doc) | Out-Null
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($range) | Out-Null
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($table_mitigations) | Out-Null
    if($null -ne $table_cis_controls_prio) {
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($table_cis_controls_prio) | Out-Null
        Remove-Variable doc,word,range,table_mitigations,table_cis_controls_prio
    }
    else{
        Remove-Variable doc,word,range,table_mitigations
    }
    [gc]::collect()
    [gc]::WaitForPendingFinalizers()
}
catch {
    $file_txt_mitigations = (get-location).path + "\"+$file_prefix+"mitigations.txt"
    Write-Host `u{2139} -Foregroundcolor Green "Office doesn't seem to be installed. Generating a simplified txt file, only containing the resume of the mitigations."
    Write-Host `u{2139} -Foregroundcolor Green $($file_txt_mitigations) "is being generated."
    $content_mitigations_intro = "Mitigations represent security concepts and classes of technologies that can be used to prevent (Sub)-Techniques from being successfully executed." + [Environment]::NewLine + "Mitigations Resume"
    $content_mitigations_description = ""
    Foreach($mitigation in $array_obj_sorted_mitigations) {
        $content_mitigations_description +=  [Environment]::NewLine
        $resume_description = "`u{2022} " + $mitigation.description + [Environment]::NewLine
        $resume_description = $resume_description -replace '\(Citation:.*\)', ''
        $resume_description = $resume_description -replace "\r?\n\r?\n", "`n"
        $content_mitigations_description += ($resume_description)
    }
    $txt_content = $content_mitigations_intro + [Environment]::NewLine + $mitigations_content
    Set-Content -Path $file_txt_mitigations -Value $txt_content
}

Write-Host `u{2705} -Foregroundcolor Green "Done."
[Environment]::NewLine

# Create complete list of Detection objects
$array_obj_complete_detections = $array_obj_complete_attack.objects | Where-Object{ $_.relationship_type -eq "detects"} | Where-Object{$_.x_mitre_deprecated -ne $true}

# Filter out the Technique selection from the Detections
$array_obj_filtered_detections = $array_obj_complete_detections | Where-Object{$_.target_ref -In $array_obj_filtered_mapping_external_id_attack_pattern.id}
$array_obj_filtered_mitigations_detections =@()
foreach ($detection in $array_obj_filtered_detections) {
    $obj_detection_property_guid = $detection.source_ref
    $obj_detection_property_description = $detection.description
    $attack_detection_attack_pattern = $array_obj_filtered_mapping_external_id_attack_pattern | Where-Object{ $_.id -eq $detection.target_ref}
    $detection_component_block = $array_obj_complete_attack.objects | Where-Object{ $_.type -eq "x-mitre-data-component"} | Where-Object{$_.id -eq $obj_detection_property_guid}
    $detection_data_source = $detection_component_block.x_mitre_data_source_ref
    $detection_data_source_block = $array_obj_complete_attack.objects | Where-Object{ $_.type -eq "x-mitre-data-source"} | Where-Object{$_.id -eq $detection_data_source}
    $detection_data_source_block_id = $detection_data_source_block.external_references | Where-Object{ $_.source_name -eq "mitre-attack"}
    $array_row = "" | Select-Object name,external_id,url,description,platforms,collection_layers,attack_id
    $array_row.name = $detection_component_block.name
    $array_row.external_id = $detection_data_source_block_id.external_id
    $array_row.url = $detection_data_source_block_id.url.Replace("-","")
    # Some urls to the sources are wrong in the JSON file and contain -, https://github.com/mitre-attack/attack-stix-data/issues/31
    $array_row.description = $obj_detection_property_description
    $array_row.platforms = $detection_data_source_block.x_mitre_platforms
    $array_row.collection_layers = $detection_data_source_block.x_mitre_collection_layers
    $array_row.attack_id = $attack_detection_attack_pattern.external_id
    $array_obj_filtered_mitigations_detections += $array_row
}
$array_obj_sorted_detections = $array_obj_filtered_mitigations_detections | Sort-Object -Property @{expression = 'external_id';Descending = $false},  @{expression = 'name';Descending = $false}, @{expression = 'attack_id';Descending = $false}
$content_detections_intro = "Detections are based on data sources and their components associated with the identified (Sub-)Techniques required to create detections where the mitigations/controls prove to be impossible to implement or inadequate.`n
The table includes the mapping with the Open Source Security Events Metadata Detection Model (OSSEM-DM). It facilitates the detection of adversary techniques.`n
The provided information may help or drive the development of detection rules for adversary actions mapped to the MITRE ATT&CK knowledge base."
$array_obj_condensed_detections = $array_obj_sorted_detections | Group-Object -Property external_id,name | ForEach-Object {
    [PSCustomObject]@{
        name = ($_.Group | Select-Object -First 1).name
        external_id = ($_.Group | Select-Object -First 1).external_id
        url = ($_.Group | Select-Object -First 1).url
        attack_id = ($_.Group).attack_id
        platforms = ($_.Group | Select-Object -First 1).platforms
        collection_layers = ($_.Group | Select-Object -First 1).collection_layers
        description = ($_.Group).description
        combined_attack = ($_.Group | Select-Object -First 1).attack_id
    }
}

# Verification whether office is installed on the system, if it is not, generate simplified txt files
try {
    New-Object -ComObject Word.Application | Out-Null
    $file_word_detections = (get-location).path + "\"+$file_prefix+"detections.docx"
    Write-Host `u{2139} -Foregroundcolor Green $($file_word_detections) "is being generated."
    [ref]$SaveFormat = "microsoft.office.interop.word.WdSaveFormat" -as [type]
    $word = New-Object -ComObject Word.Application
    $word.Visible = $False
    $doc = $word.Documents.Add()
    $selection = $word.Selection
    $selection.Style = "Heading 1"
    $selection.TypeText("Detections")
    $selection.TypeParagraph()
    $selection.Style = "Normal"
    $selection.TypeText($content_detections_intro)
    $selection.TypeParagraph()
    $var_table_columns = 3
    $var_table_rows = 8
    $range = $selection.Range()
    $selection.Tables.Add($range,$var_table_rows,$var_table_columns) | Out-Null
    $table_detections = $selection.Tables.item(1)
    $table_detections.Range.Style = "Table Grid"
    $table_detections.Cell(1,1).Range.Font.Bold=$True
    $table_detections.Cell(1,1).Range.Text = "Detection ID: Name"
    $table_detections.Cell(1,2).Range.Font.Bold=$True
    $table_detections.Cell(1,2).Range.Text = "Detection URL"
    $table_detections.Cell(1,3).Range.Font.Bold=$True
    $table_detections.Cell(1,3).Range.Text = "Covered ATT&CK`u{00AE} Technique"
    $table_detections.Cell(2,1).Range.Font.Bold=$True
    $table_detections.Cell(2,1).Range.Text = "Platforms"
    $table_detections.Cell(2,3).Merge($table_detections.Cell(2,2))
    $table_detections.Cell(2,2).Range.Font.Bold=$True
    $table_detections.Cell(2,2).Range.Text = "Collection Layers"
    $table_detections.Cell(3,3).Merge($table_detections.Cell(3,1))
    $table_detections.Cell(3,1).Range.Font.Bold=$True
    $table_detections.Cell(3,1).Range.Text = "Description"
    $table_detections.Cell(4,3).Merge($table_detections.Cell(4,1))
    $table_detections.Cell(5,3).Merge($table_detections.Cell(5,1))
    $table_detections.Cell(5,1).Range.Font.Bold=$True
    $table_detections.Cell(5,1).Range.Text = "Source - Relationship - Target"
    $table_detections.Cell(6,3).Merge($table_detections.Cell(6,1))
    $table_detections.Cell(6,1).Range.Font.Bold=$True
    $table_detections.Cell(6,1).Range.Text = "Log Source/Channel"
    $table_detections.Cell(7,3).Merge($table_detections.Cell(7,1))
    $table_detections.Cell(7,1).Range.Font.Bold=$True
    $table_detections.Cell(7,1).Range.Text = "EventID - Event Name | Defender Advanced Hunting Schema/ActionType filter"
    $table_detections.Cell(8,3).Merge($table_detections.Cell(8,1))
    $table_detections.Cell(8,1).Range.Font.Bold=$True
    $table_detections.Cell(8,1).Range.Text = "Platform/Audit Category/Audit Subcategory : Filter"
    $selection.EndKey(6) | Out-Null
    $selection.TypeParagraph()
    Foreach($t in $array_obj_condensed_detections) {
        $selection.InsertNewPage()
        $var_table_columns = 3
        $var_table_rows = 3
        $range = $selection.Range()
        $selection.Tables.Add($range,$var_table_rows,$var_table_columns) | Out-Null
        $table_detections = $selection.Tables.item(1)
        $table_detections.Range.Style = "Table Grid"
        $table_detections.Cell(1,1).Range.Font.Bold=$True
        $table_detections.Cell(1,1).Range.Text = $t.external_id + ": " + $t.name
        $table_detections.Cell(1,2).Range.Text = $t.url
        $table_detections.Cell(1,2).Range.Hyperlinks.Add($table_detections.Cell(1,2).Range, $t.url, "", "", $t.external_id) | Out-Null
        $table_detections.Cell(1,3).Range.Text = $t.attack_id -join ", "
        $platform_list = $t.platforms -join ", "
        $table_detections.Cell(2,1).Range.Text = $platform_list
        $table_detections.Cell(2,3).Merge($table_detections.Cell(2,2))
        $collection_layers_list = $t.collection_layers -join ", "
        $table_detections.Cell(2,2).Range.Text = $collection_layers_list
        $table_detections.Cell(3,3).Merge($table_detections.Cell(3,1))
        $description = $t.description -replace '\(Citation:.*\)', '' | Sort-Object -Unique
        $description = $description -join "`n"
        $table_detections.Cell(3,1).Range.Text = $description
        $selection.EndKey(6) | Out-Null
        $array_obj_filtered_ossem_data = $array_obj_complete_ossem_mapping | Where-Object {$_.technique_id -eq $t.combined_attack} | Where-Object {$_.data_component -eq $t.name}
        $var_ossem_elements = $array_obj_filtered_ossem_data.count
        $var_table_columns = 1
        if($var_ossem_elements -eq 0) {
            $var_table_rows = 2
            $range = $selection.Range()
            $selection.Tables.Add($range,$var_table_rows,$var_table_columns) | Out-Null
            $table_ossem = $selection.Tables.item(1)
            $table_ossem.Range.Style = "Table Grid"
            $table_ossem.Cell(1,1).Range.Text = ""
            $table_ossem.Cell(2,1).Range.Font.Bold=$True
            $table_ossem.Cell(2,1).Range.Text = "No OSSEM DM Information available."
            $selection.EndKey(6) | Out-Null
        }
        else {
            $var_table_rows = 5*$var_ossem_elements
            $range = $selection.Range()
            $selection.Tables.Add($range,$var_table_rows,$var_table_columns) | Out-Null
            $table_ossem = $selection.Tables.item(1)
            $table_ossem.Range.Style = "Table Grid"
            $x = 1
            foreach($j in $array_obj_filtered_ossem_data) {
                $table_ossem.Cell($x,1).Range.Text = ""
                $table_ossem.Cell($x+1,1).Range.Font.Bold=$True
                $table_ossem.Cell($x+1,1).Range.Text = "Source - Relationship - Target: " + $j.name
                if($j.log_source -eq "sysmon" -OR $j.log_source -eq "Microsoft Defender for Endpoint") {
                    $table_ossem.Cell($x+2,1).Range.Text = "Log Source: " + $j.log_source
                }
                else{ 
                    $table_ossem.Cell($x+2,1).Range.Text = "Log Source/Channel: " + $j.log_source  + "/" + ($j.channel -replace '^[^_]*\/','')
                }
                if($j.log_source -eq "Microsoft Defender for Endpoint") {
                    $table_ossem.Cell($x+3,1).Range.Text = "Defender Advanced Hunting Schema/ActionType filter: " + $j.event_id + "/" + $j.filter_in.ActionType
                }
                else{ 
                    $table_ossem.Cell($x+3,1).Range.Text = "EventID - Event Name: " + $j.event_id + " - " + $j.event_name
                }
                if([string]$j.audit_sub_category -eq "NaN"){
                    if([string]$j.audit_category -eq "NaN") {
                        $table_ossem.Cell($x+4,1).Range.Text = "Platform: " + $j.event_platform
                    }
                    else {
                        if([string]$j.filter_in -eq "NaN") {
                            $table_ossem.Cell($x+4,1).Range.Text = "Platform/Audit Category: " + $j.event_platform + "/" + $j.audit_category
                        }
                        else{
                            $obj_ossem_filter = ($j.filter_in | ConvertTo-Csv -UseQuotes Never) -join "/"
                            $table_ossem.Cell($x+4,1).Range.Text = "Platform/Audit Category : Fiter: " + $j.event_platform + "/" + $j.audit_category + " : " + $obj_ossem_filter
                        }
                    }
                }
                else {
                    if([string]$j.filter_in -eq "NaN") {
                        $table_ossem.Cell($x+4,1).Range.Text = "Platform/Audit Category/Audit Subcategory: " + $j.event_platform + "/" + $j.audit_category + "/" + $j.audit_sub_category
                    }
                    else{
                        $obj_ossem_filter = ($j.filter_in | ConvertTo-Csv -UseQuotes Never) -join "/"
                        $table_ossem.Cell($x+4,1).Range.Text = "Platform/Audit Category/Audit Subcategory : Filter:`n" + $j.event_platform + "/" + $j.audit_category + "/" + $j.audit_sub_category + " : " + $obj_ossem_filter
                    }
                }
                $x = $x + 5
                $selection.EndKey(6) | Out-Null
            }
        }
    }
    $doc.saveas([ref] $file_word_detections, [ref]$SaveFormat::wdFormatDocumentDefault)
    $doc.close()
    $word.quit()
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($doc) | Out-Null
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($range) | Out-Null
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($table_detections) | Out-Null
    Remove-Variable doc,word,range,table_detections
    [gc]::collect()
    [gc]::WaitForPendingFinalizers()
}
catch {
    $file_txt_detections = (get-location).path + "\"+$file_prefix+"detections.txt"
    Write-Host `u{2139} -Foregroundcolor Green "Office doesn't seem to be installed. Generating a simplified txt file, only containing the resume of the detections."
    Write-Host `u{2139} -Foregroundcolor Green $($file_txt_detections) "is being generated."
    $content_detections_description = ""
    Foreach($mitigation in $array_obj_sorted_detections) {
        $content_detections_description +=  [Environment]::NewLine
        $resume_description = "`u{2022} " + $mitigation.description + [Environment]::NewLine
        $resume_description = $resume_description -replace '\(Citation:.*\)', ''
        $resume_description = $resume_description -replace "\r?\n\r?\n", "`n"
        $content_detections_description += ($resume_description)
    }
    $txt_content = $content_detections_intro + [Environment]::NewLine + [Environment]::NewLine + "Detections Resume" + [Environment]::NewLine + $content_detections_description
    Set-Content -Path $file_txt_detections -Value $txt_content
}
Write-Host `u{2705} -Foregroundcolor Green "Done."

# Generate the validation array for the identified techniques
$array_obj_complete_validation =@()
$array_obj_complete_validation = $array_obj_complete_atomicred_mapping.techniques | Where-Object {$_.techniqueID -in $list_obj_selected_attack_techniques.attack_id}
$content_validation_intro = "Validations may be conducted in three ways. Atomic testing, Micro Emulation Plans and full blown scenario based testing (BAS and the likes). This annex maps the identified (Sub-)Techniques against the library of available focused tests from Red Canary Atomic Red Team and is therefore an avenue to the first approach of security validation. Pay attention to additional information on their website (https://atomicredteam.io/learn-more/) to have an understanding of the caveats and limitations. Red Canary also addresses the coverage of the library against the MITRE ATT&CK`u{00AE} knowledge base (https://atomicredteam.io/coverage/#atomic-analytics). The score is a reflection of the quantity of tests per (Sub)-Technique."

# Verification whether office is installed on the system, if it is not, generate simplified txt files
try {
    New-Object -ComObject Word.Application | Out-Null
    $file_word_validation = (get-location).path + "\"+$file_prefix+"validations.docx"
    [Environment]::NewLine
    Write-Host `u{2139} -Foregroundcolor Green $($file_word_validation) "is being generated."
    [ref]$SaveFormat = "microsoft.office.interop.word.WdSaveFormat" -as [type]
    $word = New-Object -ComObject Word.Application
    $word.Visible = $False
    $doc = $word.Documents.Add()
    $selection = $word.Selection
    $selection.Style = "Normal"
    $selection.TypeText($content_validation_intro)
    $selection.TypeParagraph()
    $var_table_columns = 2
    $var_table_rows = ($array_obj_complete_validation.count+1)
    $range = $selection.Range()
    $selection.Tables.Add($range,$var_table_rows,$var_table_columns) | Out-Null
    $table_validation = $selection.Tables.item(1)
    $table_validation.Range.Style = "Table Grid"
    $table_validation.Cell(1,1).Range.Font.Bold=$True
    $table_validation.Cell(1,1).Range.Text = "Atomic Red Team test URL"
    $table_validation.Cell(1,2).Range.Font.Bold=$True
    $table_validation.Cell(1,2).Range.Text = "Score"
    $var_table_lines_row = 1
    Foreach($validation in $array_obj_complete_validation) {
        $table_validation.Range.Style = "Table Grid"
        $table_validation.Cell(($var_table_lines_row+1),1).Range.Text = $validation.links.url
        $table_validation.Cell(($var_table_lines_row+1),1).Range.Hyperlinks.Add($table_validation.Cell(($var_table_lines_row+1),1).Range, $validation.links.url, "", "", "Atomic Red Team test for " + $validation.techniqueID) | Out-Null
        $table_validation.Cell(($var_table_lines_row+1),2).Range.Text = [string]$validation.score
        $var_table_lines_row = $var_table_lines_row+1
    }
    $doc.saveas([ref] $file_word_validation, [ref]$SaveFormat::wdFormatDocumentDefault)
    $doc.close()
    $word.quit()
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($doc) | Out-Null
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null
    Remove-Variable doc,word
    [gc]::collect()
    [gc]::WaitForPendingFinalizers()
}
catch {
    $file_txt_validation = (get-location).path + "\"+$file_prefix+"validations.txt"
    Write-Host `u{2139} -Foregroundcolor Green "Office doesn't seem to be installed. Generating a simplified txt file."
    Write-Host `u{2139} -Foregroundcolor Green $($file_txt_validation) "is being generated."
    $content_technique = ""
    foreach ($attack in $array_obj_complete_validation) {
        $content_technique +=  [Environment]::NewLine
        $content_technique += ($attack.techniqueID)
        $content_technique += [Environment]::NewLine
        $content_technique += ($attack.links.url)
        $content_technique += [Environment]::NewLine
        $content_technique += "#################"
        $content_technique += [Environment]::NewLine
        }
    $file_txt_validation_content = $content_validation_intro + [Environment]::NewLine + $content_validation_techniques + [Environment]::NewLine + $content_technique
    Set-Content -Path $file_txt_validation -Value $file_txt_validation_content
}
Write-Host `u{2705} -Foregroundcolor Green "Done."

# Create helper_attack_list.json
[System.Collections.ArrayList]$array_obj_filtered_attack_id =@()
foreach ($attack_id in $array_obj_sorted_mapping_external_id_attack_pattern) {
    $obj_filtered_attack_attack_pattern = $array_obj_complete_attack.objects | Where-Object {$_.type -eq "attack-pattern"} | Where-Object {$_.id -eq $attack_id.id}
    $obj_filtered_attack_attack_pattern_property_external_references = $obj_filtered_attack_attack_pattern.external_references | Where-Object{$_.source_name -eq "mitre-attack"}
    $obj_filtered_attack_attack_pattern_property_external_id = $obj_filtered_attack_attack_pattern_property_external_references.external_id
    $array_row = "" | Select-Object attack_id
    $array_row.attack_id = $obj_filtered_attack_attack_pattern_property_external_id
    $array_obj_filtered_attack_id += $array_row
}
$array_obj_sorted_attack_id = $array_obj_filtered_attack_id | Sort-Object -Property attack_id
$obj_helper_list_attack_id_template_header =@"
{
    "name": "$file_prefix_content",
    "techniques": []
}
"@

$obj_complete_helper_list_attack_id = $obj_helper_list_attack_id_template_header | ConvertFrom-Json
$obj_complete_helper_list_attack_id.techniques += $array_obj_sorted_attack_id
$obj_complete_helper_list_attack_id | ConvertTo-Json | Out-File $file_json_helper_attack_list -Encoding UTF8

# Closing
[Environment]::NewLine
Write-Host `u{2139} -Foregroundcolor Green $($file_json_helper_attack_list) "has been generated. The file will be used by the functions New-CTIDATTACKFlow and/or New-ATTACKNvigatorLayer"
Write-Host `u{2705} -Foregroundcolor Green "Done."
[Environment]::NewLine
}

function New-CTIDATTACKFlow {
<#
.Description
This function generates in an automated manner a baseline CTID ATT&CK(r) FLow Builder file including the provided and retained ATT&CK(r) (Sub-)Techniques/Tactic pairs. It will use available helper file generated by the functions New-ATTACKRecommendations and/or New-CTIDATTACKFlow. It will present the option to generate identified assets as well.
.PARAMETER NavigatorFile
A JSON Navigator Layer can be given as the source of the identified ATT&CK (Sub-)Techniques/Tactic Pairs.
.PARAMETER DeciderFile
A JSON exported Decider file can be given as the source of the identified ATT&CK (Sub-)Techniques/Tactic Pairs.
.EXAMPLE
# No parameters provided, the function will verify if any helper file is available and will provide the possibility to provide manual input.
PS> New-CTIDATTACKFlow
.EXAMPLE
# Providing a ATT&CK Navigator Layer JSON file. The function will verify if it has the layer field. If chosen not to continue with the proposed identified (Sub-)Techniques from the file, it will use available helper file generated by the functions New-ATTACKRecommendations and/or New-CTIDATTACKFlow. It will present the option to generate identified assets as well.
PS> New-CTIDATTACKFlow -NavigatorFile navigator_layer.json
.EXAMPLE
# Providing a Decider Export JSON file. The function will verify if it has the version field. If chosen not to continue with the proposed identified (Sub-)Techniques from the file, it will use available helper file generated by the functions New-ATTACKRecommendations and/or New-CTIDATTACKFlow. It will present the option to generate identified assets as well.
PS> New-CTIDATTACKFlow -DeciderFile untitled-2023-04-19_19-10-48.json
.INPUTS
None, objects cannot be pipe to New-CTIDATTACKFlow.
.OUTPUTS
ctid_attack_flow.afb, eventually with a prefix.
helper_attack_array.json.
.SYNOPSIS
Generating a headstart AFB ATT&CK(r) Flow Builder file including Actions and possibly Assets enabling the analysts to visualise the flow of events.
#>
param (
    [string]$NavigatorFile,
    [string]$DeciderFile
)

# Starting
Clear-Host
Write-Host -ForegroundColor Blue `u{1F6E0} "This function will construct a head-start CTID ATT&CK`u{00AE} Flow v2 afb file based on the selected (Sub-)Techniques / Tactic pairs."
if ($NavigatorFile -and $DeciderFile){
    [Environment]::NewLine
    Write-Host `u{26A0} -Foregroundcolor DarkRed "Please only use one single input."
    [Environment]::NewLine
    Exit
}
elseif($NavigatorFile){
    $InputFile = "NavigatorLayer"
}
elseif($DeciderFile){
    $InputFile = "DeciderExport"
}else {
    $InputFile = "NoInput"
}

# Pull the ATT&CK(r) JSON STIX 2.1 if required, to allow the lookup and assembly of the array based on the input for the (Sub-)Techniques
Get-ATTACKEnterpriseJSON

# Verification Navigator Layer or Decider Export 'structure'
Test-FileInputStructure $InputFile

# Verification Navigator Layer or Decider Export Name
Test-FileInputPropertyName $InputFile

# Create lookup list for ease of retrieval of multiple attack-pattern ids associated with technique ids
$array_obj_complete_mapping_external_id_attack_pattern = $array_obj_complete_attack.objects | Where-Object {$_.type -eq "attack-pattern"} | Select-Object -Property @{Name='id';Expression={ $_.id}} -ExpandProperty external_references| Where-Object{($_.source_name -eq "mitre-attack")} | Select-Object external_id, id
$array_obj_filtered_mapping_external_id_attack_pattern = $array_obj_complete_mapping_external_id_attack_pattern | Where-Object {$_.external_id -In $list_obj_selected_attack_techniques.attack_id}
$array_obj_sorted_mapping_external_id_attack_pattern = $array_obj_filtered_mapping_external_id_attack_pattern | Sort-Object -Property external_id

# Switch according to single ATT&CK (Sub-)Technique to Tactic pairing.
switch ($switch_attack_tactic_generation)
{
	"AUTO" {
        [System.Collections.ArrayList]$array_obj_complete_flow_objects=@()
        foreach ($obj_flow_objects_property_external_id in $array_obj_sorted_mapping_external_id_attack_pattern) {
            [System.Collections.ArrayList]$obj_flow_objects_tactics =@()
            $obj_list_tactics = $array_obj_selected_techniques |Where-Object{$_.attack_id -eq $obj_flow_objects_property_external_id.external_id} | Select-Object tactics
            $obj_flow_objects_tactics.Add($obj_list_tactics.tactics) | Out-Null
            $obj_filtered_attack_attack_pattern = $array_obj_complete_attack.objects | Where-Object {$_.type -eq "attack-pattern"} | Where-Object {$_.id -eq $obj_flow_objects_property_external_id.id}
            $obj_flow_objects_property_name = $obj_filtered_attack_attack_pattern.name
            $obj_flow_objects_property_GUID = [System.Collections.Generic.List[string]]::new()
            $obj_flow_objects_children_property_GUID = New-GUID
            $obj_flow_objects_property_GUID.Add($obj_flow_objects_children_property_GUID) | out-null
            $obj_flow_objects_property_external_references = $obj_filtered_attack_attack_pattern.external_references | Where-Object{$_.source_name -eq "mitre-attack"}
            $obj_flow_objects_property_external_id = $obj_flow_objects_property_external_references.external_id
            $array_row = "" | Select-Object attack_id,attack_name,attack_tactics,attack_GUID
            $array_row.attack_id = $obj_flow_objects_property_external_id
            $array_row.attack_name = $obj_flow_objects_property_name
            $array_row.attack_tactics = $obj_flow_objects_tactics
            $array_row.attack_GUID = $obj_flow_objects_property_GUID
            $array_obj_complete_flow_objects+= $array_row
        }
        $switch_pair_remove = "NONE"
	}
	"MANUAL" {
        [System.Collections.ArrayList]$array_obj_complete_flow_objects=@()
        foreach ($obj_flow_objects_property_external_id in $array_obj_sorted_mapping_external_id_attack_pattern) {
            $obj_filtered_attack_attack_pattern = $array_obj_complete_attack.objects | Where-Object {$_.type -eq "attack-pattern"} | Where-Object {$_.id -eq $obj_flow_objects_property_external_id.id}
            $obj_flow_objects_property_name = $obj_filtered_attack_attack_pattern.name
            if ($obj_filtered_attack_attack_pattern.kill_chain_phases.phase_name.count -eq 1) {
                [System.Collections.ArrayList]$obj_flow_objects_tactics =@()
                $obj_flow_objects_tactics.Add($obj_filtered_attack_attack_pattern.kill_chain_phases.phase_name) | out-null
            }
            else{
                [System.Collections.ArrayList]$obj_flow_objects_tactics =@()
                for ($count=0; $count -lt $obj_filtered_attack_attack_pattern.kill_chain_phases.phase_name.count; $count=$count+1) {
                $obj_flow_objects_tactics.Add($obj_filtered_attack_attack_pattern.kill_chain_phases.phase_name[$count]) | out-null
                }
            }
            $obj_flow_objects_property_GUID = [System.Collections.Generic.List[string]]::new()
            for ($count=0; $count -lt $obj_filtered_attack_attack_pattern.kill_chain_phases.phase_name.count; $count=$count+1) {
                $obj_flow_objects_children_property_GUID = New-GUID
                $obj_flow_objects_property_GUID.Add($obj_flow_objects_children_property_GUID) | out-null
            }
            $obj_flow_objects_property_external_references = $obj_filtered_attack_attack_pattern.external_references | Where-Object{$_.source_name -eq "mitre-attack"}
            $obj_flow_objects_property_external_id = $obj_flow_objects_property_external_references.external_id
            $array_row = "" | Select-Object attack_id,attack_name,attack_tactics,attack_GUID
            $array_row.attack_id = $obj_flow_objects_property_external_id
            $array_row.attack_name = $obj_flow_objects_property_name
            $array_row.attack_tactics = $obj_flow_objects_tactics
            $array_row.attack_GUID = $obj_flow_objects_property_GUID
            $array_obj_complete_flow_objects+= $array_row
            $switch_pair_remove = "QUERY"
        }
	}
}

$file_flow_afb = (get-location).path + "\"+$file_prefix+"ctid_attack_flow.afb"
# Flow afb formatting variables
$var_obj_flow_property_GUID = New-GUID
$var_obj_flow_property_background_colour = "#ffffff"
$var_obj_flow_property_grid_colour = "#f5f5f5"
$var_obj_flow_objects_property_anchor_markers_colour = "#fb6fa5"
$var_obj_flow_objects_property_anchor_hover_colour = "rgba(200, 88, 135, 0.25)"
$var_obj_flow_objects_property_box_colour = "#fefefe"
$current_time = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')

# Flow afb required blocks
$obj_flow_template_header = @"
{"version":"2.0.1","id":"$var_obj_flow_property_GUID","schema":{"page_template":"flow","templates":[{"id":"@__builtin__page","type":7,"role":0,"grid":[10,10],"properties":{"name":{"type":2,"value":"Untitled Document","is_primary":true}},"style":{"grid_color":"$var_obj_flow_property_grid_colour","background_color":"$var_obj_flow_property_background_colour","drop_shadow":{"color":"rgba(0,0,0,.4)","offset":[3,3]}}},{"id":"@__builtin__anchor","type":0,"role":0,"radius":10,"line_templates":{"0":"@__builtin__line_horizontal_elbow","1":"@__builtin__line_vertical_elbow"},"style":{"color":"$var_obj_flow_objects_property_anchor_hover_colour"}},{"id":"@__builtin__line_handle","type":4,"role":0,"style":{"radius":6,"fill_color":"#fedb22","stroke_color":"#fefefe","stroke_width":1.5}},{"id":"@__builtin__line_source","type":3,"role":12288,"style":{"radius":6,"fill_color":"#fedb22","stroke_color":"#141414","stroke_width":1.5}},{"id":"@__builtin__line_target","type":3,"role":16384,"style":{"radius":6,"fill_color":"#fedb22","stroke_color":"#141414","stroke_width":1.5}},{"id":"@__builtin__line_horizontal_elbow","namespace":"horizontal_elbow","type":5,"role":8192,"hitbox_width":20,"line_handle_template":"@__builtin__line_handle","line_ending_template":{"source":"@__builtin__line_source","target":"@__builtin__line_target"},"style":{"width":5,"cap_size":16,"color":"#646464","select_color":"#646464"}},{"id":"@__builtin__line_vertical_elbow","namespace":"vertical_elbow","type":6,"role":8192,"hitbox_width":20,"line_handle_template":"@__builtin__line_handle","line_ending_template":{"source":"@__builtin__line_source","target":"@__builtin__line_target"},"style":{"width":5,"cap_size":16,"color":"#646464","select_color":"#646464"}},{"id":"flow","type":7,"role":4096,"grid":[10,10],"properties":{"name":{"type":2,"value":"Untitled Document","is_primary":true},"description":{"type":2},"author":{"type":6,"form":{"name":{"type":2,"is_primary":true},"identity_class":{"type":4,"options":{"type":5,"form":{"type":2},"value":[["individual","Individual"],["group","Group"],["system","System"],["organization","Organization"],["class","Class"],["unknown","Unknown"]]}},"contact_information":{"type":2}}},"scope":{"type":4,"options":{"type":5,"form":{"type":2},"value":[["incident","Incident"],["campaign","Campaign"],["threat-actor","Threat Actor"],["malware","Malware"],["other","Other"]]},"value":"incident"},"external_references":{"type":5,"form":{"type":6,"form":{"source_name":{"type":2,"is_primary":true,"is_required":true},"description":{"type":2},"url":{"type":2}}}},"created":{"type":3,"value":"$current_time","is_visible":false}},"style":{"grid_color":"$var_obj_flow_property_grid_colour","background_color":"$var_obj_flow_property_background_colour","drop_shadow":{"color":"rgba(0,0,0,.4)","offset":[3,3]}}},{"id":"true_anchor","type":0,"role":0,"radius":10,"line_templates":{"0":"@__builtin__line_horizontal_elbow","1":"@__builtin__line_vertical_elbow"},"style":{"color":"rgba(255, 255, 255, 0.25)"}},{"id":"false_anchor","type":0,"role":0,"radius":10,"line_templates":{"0":"@__builtin__line_horizontal_elbow","1":"@__builtin__line_vertical_elbow"},"style":{"color":"rgba(255, 255, 255, 0.25)"}},{"id":"action","namespace":"attack_flow.action","type":2,"role":4096,"properties":{"name":{"type":2,"is_primary":true,"is_required":true},"tactic_id":{"type":2},"tactic_ref":{"type":2},"technique_id":{"type":2},"technique_ref":{"type":2},"description":{"type":2},"confidence":{"type":4,"options":{"type":5,"form":{"type":6,"form":{"text":{"type":2,"is_primary":true},"value":{"type":0}}},"value":[["speculative",{"text":"Speculative","value":0}],["very-doubtful",{"text":"Very Doubtful","value":10}],["doubtful",{"text":"Doubtful","value":30}],["even-odds",{"text":"Even Odds","value":50}],["probable",{"text":"Probable","value":70}],["very-probable",{"text":"Very Probable","value":90}],["certain",{"text":"Certain","value":100}]]},"value":null},"execution_start":{"type":3},"execution_end":{"type":3}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#637bc9","stroke_color":"#708ce6","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"asset","namespace":"attack_flow.asset","type":2,"role":4096,"properties":{"name":{"type":2,"is_primary":true,"is_required":true},"description":{"type":2}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#c26130","stroke_color":"#e57339","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"condition","namespace":"attack_flow.condition","type":1,"role":4096,"properties":{"description":{"type":2,"is_primary":true,"is_required":true},"pattern":{"type":2},"pattern_type":{"type":2},"pattern_version":{"type":2},"date":{"type":3}},"branches":[{"text":"True","anchor_template":"true_anchor"},{"text":"False","anchor_template":"false_anchor"}],"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#2a9642","stroke_color":"#32b34e","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"branch":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","vertical_padding":12,"horizontal_padding":30},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"or","namespace":"attack_flow.OR_operator","type":8,"role":4096,"properties":{"operator":{"type":2,"value":"OR","is_primary":true,"is_visible":false,"is_editable":false}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"fill_color":"#c94040","stroke_color":"#dd5050","text":{"font":{"family":"Inter","size":"14pt","weight":800},"color":"#d8d8d8","line_height":24},"border_radius":13,"select_outline":{"color":"#e6d845","padding":4,"border_radius":19},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"vertical_padding":18,"horizontal_padding":35}},{"id":"and","namespace":"attack_flow.AND_operator","type":8,"role":4096,"properties":{"operator":{"type":2,"value":"AND","is_primary":true,"is_visible":false,"is_editable":false}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"fill_color":"#c94040","stroke_color":"#dd5050","text":{"font":{"family":"Inter","size":"14pt","weight":800},"color":"#d8d8d8","line_height":24},"border_radius":13,"select_outline":{"color":"#e6d845","padding":4,"border_radius":19},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"vertical_padding":18,"horizontal_padding":35}},{"id":"attack_pattern","namespace":"stix_object.attack_pattern","type":2,"role":4096,"properties":{"name":{"type":2,"is_primary":true,"is_required":true},"description":{"type":2},"aliases":{"type":5,"form":{"type":2}},"kill_chain_phases":{"type":5,"form":{"type":2}}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"campaign","namespace":"stix_object.campaign","type":2,"role":4096,"properties":{"name":{"type":2,"is_primary":true,"is_required":true},"description":{"type":2},"aliases":{"type":5,"form":{"type":2}},"first_seen":{"type":3},"last_seen":{"type":3},"objective":{"type":2}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"course_of_action","namespace":"stix_object.course_of_action","type":2,"role":4096,"properties":{"name":{"type":2,"is_primary":true,"is_required":true},"description":{"type":2},"action_type":{"type":2},"os_execution_envs":{"type":5,"form":{"type":2}},"action_bin":{"type":2}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"grouping","namespace":"stix_object.grouping","type":2,"role":4096,"properties":{"name":{"type":2,"is_primary":true},"description":{"type":2},"context":{"type":2,"is_required":true}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"identity","namespace":"stix_object.identity","type":2,"role":4096,"properties":{"name":{"type":2,"is_required":true,"is_primary":true},"description":{"type":2},"roles":{"type":5,"form":{"type":2}},"identity_class":{"type":2,"is_required":true},"sectors":{"type":5,"form":{"type":2}},"contact_information":{"type":2}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"indicator","namespace":"stix_object.indicator","type":2,"role":4096,"properties":{"name":{"type":2,"is_primary":true},"description":{"type":2},"indicator_types":{"type":5,"form":{"type":2,"is_required":true}},"pattern":{"type":2,"is_required":true},"pattern_type":{"type":2,"is_required":true},"patter_version":{"type":2},"valid_from":{"type":3,"is_required":true},"valid_until":{"type":3},"kill_chain_phases":{"type":5,"form":{"type":2}}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"infrastructure","namespace":"stix_object.infrastructure","type":2,"role":4096,"properties":{"name":{"type":2,"is_primary":true,"is_required":true},"description":{"type":2},"infrastructure_types":{"type":5,"form":{"type":2,"is_required":true}},"aliases":{"type":5,"form":{"type":2}},"kill_chain_phases":{"type":5,"form":{"type":2}},"first_seen":{"type":3},"last_seen":{"type":3}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"intrusion_set","namespace":"stix_object.intrusion_set","type":2,"role":4096,"properties":{"name":{"type":2,"is_primary":true,"is_required":true},"description":{"type":2},"aliases":{"type":5,"form":{"type":2,"is_required":true}},"first_seen":{"type":3},"last_seen":{"type":3},"goals":{"type":5,"form":{"type":2}},"resource_level":{"type":2},"primary_motivation":{"type":2},"secondary_motivations":{"type":5,"form":{"type":2}}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"location","namespace":"stix_object.location","type":2,"role":4096,"properties":{"name":{"type":2,"is_primary":true},"description":{"type":2},"latitude":{"type":1,"min":-90,"max":90},"longitude":{"type":1,"min":-180,"max":180},"precision":{"type":1},"region":{"type":2},"country":{"type":2},"administrative_area":{"type":2},"city":{"type":2},"street_address":{"type":2},"postal_code":{"type":2}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"malware","namespace":"stix_object.malware","type":2,"role":4096,"properties":{"name":{"type":2,"is_primary":true},"description":{"type":2},"malware_types":{"type":5,"form":{"type":2,"is_required":true}},"is_family":{"type":4,"options":{"type":5,"form":{"type":2},"value":[["true","True"],["false","False"]]},"is_required":true},"aliases":{"type":5,"form":{"type":2}},"kill_chain_phases":{"type":5,"form":{"type":2}},"first_seen":{"type":3},"last_seen":{"type":3},"os_execution_envs":{"type":5,"form":{"type":2}},"architecture_execution_envs":{"type":5,"form":{"type":2}},"implementation_languages":{"type":5,"form":{"type":2}},"capabilities":{"type":5,"form":{"type":2}}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"malware_analysis","namespace":"stix_object.malware_analysis","type":2,"role":4096,"properties":{"product":{"type":2,"is_primary":true,"is_required":true},"version":{"type":2},"configuration_version":{"type":2},"modules":{"type":5,"form":{"type":2}},"analysis_engine_version":{"type":2},"analysis_definition_version":{"type":2},"submitted":{"type":3},"analysis_started":{"type":3},"analysis_ended":{"type":3},"av_result":{"type":2}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"note","namespace":"stix_object.note","type":2,"role":4096,"properties":{"abstract":{"type":2,"is_primary":true},"content":{"type":2,"is_required":true},"authors":{"type":5,"form":{"type":2}}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"observed_data","namespace":"stix_object.observed_data","type":2,"role":4096,"properties":{"first_observed":{"type":3,"is_required":true},"last_observed":{"type":3,"is_required":true},"number_observed":{"type":0,"min":0,"is_required":true}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"opinion","namespace":"stix_object.opinion","type":2,"role":4096,"properties":{"explanation":{"type":2,"is_primary":true},"authors":{"type":5,"form":{"type":2}},"opinion":{"type":2,"is_required":true}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"report","namespace":"stix_object.report","type":2,"role":4096,"properties":{"name":{"type":2,"is_primary":true,"is_required":true},"description":{"type":2},"report_types":{"type":5,"form":{"type":2,"is_required":true}},"published":{"type":3,"is_required":true}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"threat_actor","namespace":"stix_object.threat_actor","type":2,"role":4096,"properties":{"name":{"type":2,"is_primary":true,"is_required":true},"description":{"type":2},"threat_actor_types":{"type":5,"form":{"type":2,"is_required":true}},"aliases":{"type":5,"form":{"type":2}},"first_seen":{"type":3},"last_seen":{"type":3},"roles":{"type":5,"form":{"type":2}},"goals":{"type":5,"form":{"type":2}},"sophistication":{"type":2},"resource_level":{"type":2},"primary_motivation":{"type":2},"secondary_motivations":{"type":5,"form":{"type":2}},"personal_motivations":{"type":5,"form":{"type":2}}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"tool","namespace":"stix_object.tool","type":2,"role":4096,"properties":{"name":{"type":2,"is_primary":true,"is_required":true},"description":{"type":2},"tool_types":{"type":5,"form":{"type":2,"is_required":true}},"aliases":{"type":5,"form":{"type":2}},"kill_chain_phases":{"type":5,"form":{"type":2}},"tool_version":{"type":2}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"vulnerability","namespace":"stix_object.vulnerability","type":2,"role":4096,"properties":{"name":{"type":2,"is_primary":true,"is_required":true},"description":{"type":2}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"artifact","namespace":"stix_observable.artifact","type":2,"role":4096,"properties":{"mime_type":{"type":2},"payload_bin":{"type":2},"url":{"type":2},"hashes":{"type":2},"encryption_algorithm":{"type":2},"decryption_key":{"type":2}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"autonomous_system","namespace":"stix_observable.autonomous_system","type":2,"role":4096,"properties":{"number":{"type":2,"is_primary":true,"is_required":true},"name":{"type":2},"rir":{"type":2}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"directory","namespace":"stix_observable.directory","type":2,"role":4096,"properties":{"path":{"type":2,"is_primary":true,"is_required":true},"path_enc":{"type":2},"ctime":{"type":3},"mtime":{"type":3},"atime":{"type":3}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"domain_name","namespace":"stix_observable.domain_name","type":2,"role":4096,"properties":{"value":{"type":2,"is_required":true}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"email_address","namespace":"stix_observable.email_address","type":2,"role":4096,"properties":{"value":{"type":2,"is_required":true},"display_name":{"type":2}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"email_message","namespace":"stix_observable.email_message","type":2,"role":4096,"properties":{"is_multipart":{"type":4,"options":{"type":5,"form":{"type":2},"value":[["true","True"],["false","False"]]},"is_required":true},"date":{"type":2},"content_type":{"type":2},"message_id":{"type":2},"subject":{"type":2,"is_primary":true},"received_lines":{"type":2},"additional_header_fields":{"type":2},"body":{"type":2},"body_multipart":{"type":2}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"file","namespace":"stix_observable.file","type":2,"role":4096,"properties":{"hashes":{"type":2},"size":{"type":2},"name":{"type":2,"is_primary":true},"name_enc":{"type":2},"magic_number_hex":{"type":2},"mime_type":{"type":2},"ctime":{"type":3},"mtime":{"type":3},"atime":{"type":3}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"ipv4_addr","namespace":"stix_observable.ipv4_addr","type":2,"role":4096,"properties":{"value":{"type":2,"is_required":true}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"ipv6_addr","namespace":"stix_observable.ipv6_addr","type":2,"role":4096,"properties":{"value":{"type":2,"is_required":true}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"mac_addr","namespace":"stix_observable.mac_addr","type":2,"role":4096,"properties":{"value":{"type":2,"is_required":true}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"mutex","namespace":"stix_observable.mutex","type":2,"role":4096,"properties":{"name":{"type":2,"is_required":true}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"network_traffic","namespace":"stix_observable.network_traffic","type":2,"role":4096,"properties":{"start":{"type":3},"end":{"type":3},"is_active":{"type":4,"options":{"type":5,"form":{"type":2},"value":[["true","True"],["false","False"]]}},"src_port":{"type":0,"min":0,"max":65535},"dst_port":{"type":0,"min":0,"max":65535},"protocols":{"type":5,"form":{"type":2,"is_required":true}},"src_byte_count":{"type":0,"min":0},"dst_byte_count":{"type":0,"min":0},"src_packets":{"type":0,"min":0},"dst_packets":{"type":0,"min":0},"ipfix":{"type":2}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"process","namespace":"stix_observable.process","type":2,"role":4096,"properties":{"is_hidden":{"type":4,"options":{"type":5,"form":{"type":2},"value":[["true","True"],["false","False"]]}},"pid":{"type":0,"min":0},"created_time":{"type":3},"cwd":{"type":2},"command_line":{"type":2,"is_required":true},"environment_variables":{"type":2}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"software","namespace":"stix_observable.software","type":2,"role":4096,"properties":{"name":{"type":2,"is_primary":true,"is_required":true},"cpe":{"type":2},"languages":{"type":5,"form":{"type":2}},"vendor":{"type":2},"version":{"type":2}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"url","namespace":"stix_observable.url","type":2,"role":4096,"properties":{"value":{"type":2,"is_required":true}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"user_account","namespace":"stix_observable.user_account","type":2,"role":4096,"properties":{"user_id":{"type":2},"credential":{"type":2},"account_login":{"type":2},"account_type":{"type":2},"display_name":{"type":2,"is_primary":true,"is_required":true},"is_service_account":{"type":4,"options":{"type":5,"form":{"type":2},"value":[["true","True"],["false","False"]]}},"is_privileged":{"type":4,"options":{"type":5,"form":{"type":2},"value":[["true","True"],["false","False"]]}},"can_escalate_privs":{"type":4,"options":{"type":5,"form":{"type":2},"value":[["true","True"],["false","False"]]}},"is_disabled":{"type":4,"options":{"type":5,"form":{"type":2},"value":[["true","True"],["false","False"]]}},"account_created":{"type":3},"account_expires":{"type":3},"credential_last_changed":{"type":3},"account_first_login":{"type":3},"account_last_login":{"type":3}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"windows_registry_key","namespace":"stix_observable.windows_registry_key","type":2,"role":4096,"properties":{"key":{"type":2,"is_primary":true},"values":{"type":5,"form":{"type":2}},"modified_time":{"type":3},"number_of_subkeys":{"type":0,"min":0}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}},{"id":"x509_certificate","namespace":"stix_observable.x509_certificate","type":2,"role":4096,"properties":{"subject":{"type":2,"is_primary":true,"is_required":true},"is_self_signed":{"type":4,"options":{"type":5,"form":{"type":2},"value":[["true","True"],["false","False"]]}},"hashes":{"type":2},"version":{"type":2},"serial_number":{"type":2},"signature_algorithm":{"type":2},"issuer":{"type":2},"validity_not_before":{"type":3},"validity_not_after":{"type":3},"subject_public_key_algorithm":{"type":2},"subject_public_key_modulus":{"type":2},"subject_public_key_exponent":{"type":0,"min":0}},"anchor_template":"@__builtin__anchor","style":{"max_width":320,"head":{"fill_color":"#737373","stroke_color":"#8c8c8c","one_title":{"title":{"font":{"family":"Inter","size":"10.5pt","weight":800},"color":"#d8d8d8"}},"two_title":{"title":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#d8d8d8","padding":8},"subtitle":{"font":{"family":"Inter","size":"13pt","weight":800},"color":"#d8d8d8","line_height":23}},"vertical_padding":14},"body":{"fill_color":"$var_obj_flow_objects_property_box_colour","stroke_color":"#383838","field_name":{"font":{"family":"Inter","size":"8pt","weight":600},"color":"#b3b3b3","padding":12},"field_value":{"font":{"family":"Inter","size":"10.5pt"},"color":"#bfbfbf","line_height":20,"padding":22},"vertical_padding":18},"select_outline":{"color":"#e6d845","padding":4,"border_radius":9},"anchor_markers":{"color":"$var_obj_flow_objects_property_anchor_markers_colour","size":3},"border_radius":5,"horizontal_padding":20}}]},
"@

# Initializing and clearing variables
$obj_flow_objects_actions_content = ""
$obj_flow_action_child_definition = ""
$obj_flow_action_child_header = ""
$obj_flow_objects_actions_child_content = ""

# Location variables
$var_x_pos = -290
$var_y_pos = -170

# Switch if (Sub-)Technique/Tactic pairs need handling/verification.
switch ($switch_pair_remove)
{
	"QUERY" {
        [Environment]::NewLine
        Write-Host `u{2139} "Multiple pairings with different Tactics have been identified for at least one (Sub-)Technique. Please validate the relevant pairs"
        [System.Collections.ArrayList]$array_obj_complete_flow_objects_remove_attack =@()

        # Requesting confirmation to add the (Sub-)Technique / Tactic pairs; removing those unwanted
        # This will generate an error if all Tactics are removed from the (Sub-)Technique / Tactics pairs. Hence why a counter is presented.
        $range_techniques=0..($array_obj_complete_flow_objects.attack_id.count-1)
        $count_techniques = $array_obj_complete_flow_objects.attack_id.count
        [Environment]::NewLine
        Write-Host `u{2139} "Number of (Sub-)Techniques to be treated:" $count_techniques
        foreach ($technique in $range_techniques) {
            if ($array_obj_complete_flow_objects[$technique].attack_tactics.count -eq 1) {
                [Environment]::NewLine
                $count_techniques = $count_techniques -1
                Write-Host `u{2139} -Foregroundcolor DarkMagenta $($array_obj_complete_flow_objects[$technique].attack_id) $($array_obj_complete_flow_objects[$technique].attack_name) "is only paired with a single Tactic:" $($array_obj_complete_flow_objects[$technique].attack_tactics)
                Write-Host `u{2139} -Foregroundcolor DarkMagenta "This Technique/Tactic Pair" $($array_obj_complete_flow_objects[$technique].attack_id)"/"$($array_obj_complete_flow_objects[$technique].attack_tactics) "will be added to the CTID Flow file."
                Write-Host `u{2139} "Number of (Sub-)Techniques left:" $count_techniques
            }
            else {
                $count = 0
                $range_tactics=0..($array_obj_complete_flow_objects[$technique].attack_tactics.count-1)
                [Environment]::NewLine
                $count_techniques = $count_techniques -1
                Write-Host `u{2139} -Foregroundcolor DarkBlue $($array_obj_complete_flow_objects[$technique].attack_id) $($array_obj_complete_flow_objects[$technique].attack_name) "is paired with multiple Tactics ("(($array_obj_complete_flow_objects[$technique].attack_tactics).count)"):"(($array_obj_complete_flow_objects[$technique].attack_tactics) -join "; ")
                foreach ($o in $range_tactics) {
                    $query_confirm_pair = Read-Host `u{2328} " ("($o+1)"/"($range_tactics[-1]+1)") Adding this Technique/Tactic Pair" $($array_obj_complete_flow_objects[$technique].attack_id)"/"$($array_obj_complete_flow_objects[$technique].attack_tactics[$count]) "to the CTID Flow file ([Y]/N)"
                    if ((-not($query_confirm_pair)) -or ($query_confirm_pair -eq "Y")) {
                        Write-Host `u{2139} -Foregroundcolor Green "Adding" $($array_obj_complete_flow_objects[$technique].attack_id)"/"$($array_obj_complete_flow_objects[$technique].attack_tactics[$count])
                        $count = $count+1
                    }
                    elseif ($query_confirm_pair -eq "N") {
                        Write-Host `u{2139} -Foregroundcolor DarkRed "Skipping" $($array_obj_complete_flow_objects[$technique].attack_id)"/"$($array_obj_complete_flow_objects[$technique].attack_tactics[$count])
                        $array_obj_complete_flow_objects[$technique].attack_GUID.remove($array_obj_complete_flow_objects[$technique].attack_GUID[$count]) | out-null
                        $array_obj_complete_flow_objects[$technique].attack_tactics.remove($array_obj_complete_flow_objects[$technique].attack_tactics[$count]) | out-null
                    }
                    else {
                        Write-Host `u{2139} -Foregroundcolor DarkRed "Invalid input. Skipping" $($array_obj_complete_flow_objects[$technique].attack_id)"/"$($array_obj_complete_flow_objects[$technique].attack_tactics[$count])
                        $array_obj_complete_flow_objects[$technique].attack_GUID.remove($array_obj_complete_flow_objects[$technique].attack_GUID[$count]) | out-null
                        $array_obj_complete_flow_objects[$technique].attack_tactics.remove($array_obj_complete_flow_objects[$technique].attack_tactics[$count]) | out-null
                    }
                }
                Write-Host `u{2139} "Number of (Sub-)Techniques left:" $count_techniques
            }
        }

        # Removing unwanted (Sub-)Techniques altogether if they only had one Tactic associated and are not required.
        foreach ($instance in $array_obj_complete_flow_objects_remove_attack) {
            $array_obj_complete_flow_objects_remove_index = ($array_obj_complete_flow_objects| where-object {$_.attack_id -eq $instance})
            $array_obj_complete_flow_objects.Remove($array_obj_complete_flow_objects_remove_index) | out-null
        }
	}
	"NONE" {
        [Environment]::NewLine
        Write-Host `u{2139} -Foregroundcolor DarkMagenta "Following pairs are added automatically to the CTID Flow File"
        foreach ($instance in $array_obj_complete_flow_objects) {
            Write-Host `u{2139} -Foregroundcolor DarkMagenta $instance.attack_id"/"$instance.attack_tactics
        }
	}
}

# Generating the Action objects for the Flow file
$range_techniques=0..($array_obj_complete_flow_objects.attack_id.count-1)
foreach ($technique in $range_techniques) {
    if ($array_obj_complete_flow_objects[$technique].attack_tactics.count -eq 1) {
            $obj_flow_action_child_header_GUID = $array_obj_complete_flow_objects[$technique].attack_GUID
            $obj_list_flow_objects_action_child_GUID= @()
            $obj_list_flow_objects_action_child_GUID = New-Object -TypeName 'System.Collections.ArrayList'
            $count=0
                for ($count=1; $count -le 12; $count=$count+1) {
                    $obj_action_child_GUID = New-GUID
                    $obj_list_flow_objects_action_child_GUID.Add($obj_action_child_GUID) | out-null
                }   
            $attack_flow_action_child_GUID_group = $obj_list_flow_objects_action_child_GUID -join '","'
            $obj_flow_action_child_header = @"
{"id":"$obj_flow_action_child_header_GUID","x":$var_x_pos,"y":$var_y_pos,"attrs":256,"template":"action","children":["$attack_flow_action_child_GUID_group"],"properties":[["name","$($array_obj_complete_flow_objects[$technique].attack_name)"],["tactic_id",null],["tactic_ref","$($array_obj_complete_flow_objects[$technique].attack_tactics)"],["technique_id","$($array_obj_complete_flow_objects[$technique].attack_id)"],["technique_ref",null],["description","DESCRIPTION_PLACEHOLDER"],["confidence","62814720b26c68ab20bbb6669a1ec919"],["execution_start",null],["execution_end",null]]},
"@
            $obj_flow_action_child_definition = @"
{"id":"$($obj_list_flow_objects_action_child_GUID[0])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":1},{"id":"$($obj_list_flow_objects_action_child_GUID[1])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":1},{"id":"$($obj_list_flow_objects_action_child_GUID[2])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":1},{"id":"$($obj_list_flow_objects_action_child_GUID[3])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":0},{"id":"$($obj_list_flow_objects_action_child_GUID[4])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":0},{"id":"$($obj_list_flow_objects_action_child_GUID[5])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":0},{"id":"$($obj_list_flow_objects_action_child_GUID[6])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":1},{"id":"$($obj_list_flow_objects_action_child_GUID[7])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":1},{"id":"$($obj_list_flow_objects_action_child_GUID[8])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":1},{"id":"$($obj_list_flow_objects_action_child_GUID[9])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":0},{"id":"$($obj_list_flow_objects_action_child_GUID[10])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":0},{"id":"$($obj_list_flow_objects_action_child_GUID[11])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":0}
"@
            $obj_flow_objects_actions_child_content = $obj_flow_action_child_header + $obj_flow_action_child_definition
            $obj_flow_objects_actions_content += $obj_flow_objects_actions_child_content
            $var_x_pos = $var_x_pos + 100
            $var_y_pos = $var_y_pos + 50       
    }
    else {
            $range_tactics=0..($array_obj_complete_flow_objects[$technique].attack_tactics.count-1)
            foreach ($o in $range_tactics) {
                    $obj_flow_action_child_header_GUID = $array_obj_complete_flow_objects[$technique].attack_GUID[$o]
                    $obj_list_flow_objects_action_child_GUID= @()
                    $obj_list_flow_objects_action_child_GUID = New-Object -TypeName 'System.Collections.ArrayList'
                    $count=0
                        for ($count=1; $count -le 12; $count=$count+1) {
                            $obj_action_child_GUID = New-GUID
                            $obj_list_flow_objects_action_child_GUID.Add($obj_action_child_GUID) | out-null
                        }
                    $attack_flow_action_child_GUID_group = $obj_list_flow_objects_action_child_GUID -join '","'
                    $obj_flow_action_child_header = @"
{"id":"$obj_flow_action_child_header_GUID","x":$var_x_pos,"y":$var_y_pos,"attrs":256,"template":"action","children":["$attack_flow_action_child_GUID_group"],"properties":[["name","$($array_obj_complete_flow_objects[$technique].attack_name)"],["tactic_id",null],["tactic_ref","$($array_obj_complete_flow_objects[$technique].attack_tactics[$o])"],["technique_id","$($array_obj_complete_flow_objects[$technique].attack_id)"],["technique_ref",null],["description","DESCRIPTION_PLACEHOLDER"],["confidence","62814720b26c68ab20bbb6669a1ec919"],["execution_start",null],["execution_end",null]]},
"@
                    $obj_flow_action_child_definition = @"
{"id":"$($obj_list_flow_objects_action_child_GUID[0])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":1},{"id":"$($obj_list_flow_objects_action_child_GUID[1])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":1},{"id":"$($obj_list_flow_objects_action_child_GUID[2])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":1},{"id":"$($obj_list_flow_objects_action_child_GUID[3])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":0},{"id":"$($obj_list_flow_objects_action_child_GUID[4])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":0},{"id":"$($obj_list_flow_objects_action_child_GUID[5])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":0},{"id":"$($obj_list_flow_objects_action_child_GUID[6])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":1},{"id":"$($obj_list_flow_objects_action_child_GUID[7])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":1},{"id":"$($obj_list_flow_objects_action_child_GUID[8])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":1},{"id":"$($obj_list_flow_objects_action_child_GUID[9])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":0},{"id":"$($obj_list_flow_objects_action_child_GUID[10])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":0},{"id":"$($obj_list_flow_objects_action_child_GUID[11])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":0}
"@
                    $obj_flow_objects_actions_child_content = $obj_flow_action_child_header + $obj_flow_action_child_definition
                    $obj_flow_objects_actions_content += $obj_flow_objects_actions_child_content
                    $var_x_pos = $var_x_pos + 100
                    $var_y_pos = $var_y_pos + 50       
                    $count = $count+1
            }
    }
}
[Environment]::NewLine
Write-Host `u{2139} "Actions generated."

# Request the user whether Asset objects for the Flow file should be generated, if so requesting input for the asset names. No checks on the provided list is performed.
[Environment]::NewLine
$query_assets = Read-Host `u{2328} " Do you need Assets to be generated ([Y]/N)"
if ((-not($query_assets)) -or ($query_assets -eq "Y")) {
    $obj_list_assets = Read-Host `u{2328} " Give a single or a semicolon seperated list of asset names to generate (for example: SYSTEM01;SRV-EXCH-01;Obsolete Device)"
    $obj_array_assets = $obj_list_assets.ToString() -split ";" | Select-Object -Property @{Name='asset';Expression={$_}}
    $asset_flow_object_child_GUID_list= @()
    $asset_flow_object_child_GUID_list = New-Object -TypeName 'System.Collections.ArrayList'
    $count_asset=1..($obj_array_assets.count)
    foreach ($instance in $count_asset) {
        $Objects_GUID = New-GUID
        $asset_flow_object_child_GUID_list.Add($Objects_GUID) | out-null
    }
    $obj_flow_objects_asset_content = ""
    $asset_flow_action_children_definition = ""
    $asset_flow_action_children_header = ""
    $asset_flow_action_complete = ""
    $var_x_pos = 100
    $var_y_pos = -300
    $count_guid = 0
    $range_techniques=0..(($obj_array_assets.count)-1)
    foreach ($technique in $range_techniques) {
            $obj_flow_action_child_header_GUID = $asset_flow_object_child_GUID_list[$count_guid]
            $obj_list_flow_objects_asset_child_GUID= @()
            $obj_list_flow_objects_asset_child_GUID = New-Object -TypeName 'System.Collections.ArrayList'
            $count=0
                for ($count=1; $count -le 12; $count=$count+1) {
                    $obj_action_child_GUID = New-GUID
                    $obj_list_flow_objects_asset_child_GUID.Add($obj_action_child_GUID) | out-null
                }   
            $asset_flow_action_child_GUID_group = $obj_list_flow_objects_asset_child_GUID -join '","'
            $asset_flow_action_children_header = @"
{"id":"$obj_flow_action_child_header_GUID","x":$var_x_pos,"y":$var_y_pos,"attrs":256,"template":"asset","children":["$asset_flow_action_child_GUID_group"],"properties":[["name","$($obj_array_assets[$technique].asset)"],["description","DESCRIPTION_PLACEHOLDER"]]},
"@
            $asset_flow_action_children_definition = @"
{"id":"$($obj_list_flow_objects_asset_child_GUID[0])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":1},{"id":"$($obj_list_flow_objects_asset_child_GUID[1])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":1},{"id":"$($obj_list_flow_objects_asset_child_GUID[2])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":1},{"id":"$($obj_list_flow_objects_asset_child_GUID[3])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":0},{"id":"$($obj_list_flow_objects_asset_child_GUID[4])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":0},{"id":"$($obj_list_flow_objects_asset_child_GUID[5])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":0},{"id":"$($obj_list_flow_objects_asset_child_GUID[6])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":1},{"id":"$($obj_list_flow_objects_asset_child_GUID[7])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":1},{"id":"$($obj_list_flow_objects_asset_child_GUID[8])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":1},{"id":"$($obj_list_flow_objects_asset_child_GUID[9])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":0},{"id":"$($obj_list_flow_objects_asset_child_GUID[10])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":0},{"id":"$($obj_list_flow_objects_asset_child_GUID[11])","x":0,"y":0,"attrs":0,"template":"@__builtin__anchor","children":[],"properties":[],"angle":0}
"@
            $asset_flow_action_complete = $asset_flow_action_children_header + $asset_flow_action_children_definition
            $obj_flow_objects_asset_content += $asset_flow_action_complete
            $var_x_pos = $var_x_pos + 100
            $var_y_pos = $var_y_pos + 50       
            $count_guid = $count_guid+1
    }   

}
elseif ($query_assets -eq "N") {
    Write-Host `u{2139} -Foregroundcolor DarkRed "Skipping adding assets."
    $obj_array_assets = $null
}
else {
    Write-Host `u{2139} -Foregroundcolor DarkRed "Skipping adding assets."
    $obj_array_assets = $null
}

# Correcting the instances where the seperation between two JSON objects is missing
$obj_flow_objects_actions_content = $obj_flow_objects_actions_content.Replace("}{","},{")

# Generating the appropriate list of object GUID when Asset objects will be present or not
if ($obj_array_assets.count -eq 0) {
    $obj_list_flow_property_GUID = $array_obj_complete_flow_objects.attack_GUID -join '","'
 }
else {
    $obj_flow_objects_asset_content = $obj_flow_objects_asset_content.Replace("}{","},{")
    $obj_list_flow_property_GUID = (($array_obj_complete_flow_objects.attack_GUID -join '","'), ($asset_flow_object_child_GUID_list.Guid -join '","')) -join '","'
}

# Generating the JSON "objects" object. This object refers to "children", the Actions and Assets. Author Name and Contact Information are prefilled.
$obj_flow_objects_header = @"
"objects":[{"id":"$var_obj_flow_property_GUID","x":-290,"y":-170,"attrs":0,"template":"flow","children":["$obj_list_flow_property_GUID"],"properties":[["name","$flow_name_content"],["description",null],["author",[["name","CPIRT"],["identity_class","db0f6f37ebeb6ea09489124345af2a45"],["contact_information","emergency-response@checkpoint.com"]]],["scope","3e072748feb6ecd1b1ba397704e009c0"],["external_references",[]],["created","$current_time"]]},
"@

# Defining the default afb footer
$obj_flow_template_footer = @"
],"location":{"x":-0.5,"y":-0.5,"k":1}}
"@

# Generating the complete flow file
if ($obj_array_assets.count -eq 0) {
    $obj_flow_template_header + $obj_flow_objects_header + $obj_flow_objects_actions_content + $obj_flow_template_footer | Out-File $file_flow_afb -Encoding UTF8
}
else {
    $obj_flow_objects_asset_prepend =","
    $obj_flow_template_header + $obj_flow_objects_header + $obj_flow_objects_actions_content + $obj_flow_objects_asset_prepend + $obj_flow_objects_asset_content + $obj_flow_template_footer | Out-File $file_flow_afb -Encoding UTF8
}

# Closing
[Environment]::NewLine
Write-Host `u{2705} -Foregroundcolor Green "All done."$($file_flow_afb) "has been generated. The file can be used with https://center-for-threat-informed-defense.github.io/attack-flow/ui/"

# Convert the flow to a locally saved JSON file for other uses (Navigator, Sightings)
$array_obj_complete_flow_techniques = $array_obj_complete_flow_objects | Select-Object attack_id,attack_name,attack_tactics

$obj_helper_array_attack_template_header =@"
{
    "name": "$file_prefix_content",
    "techniques": []
}
"@

$obj_complete_helper_array_attack = $obj_helper_array_attack_template_header | ConvertFrom-Json
$obj_complete_helper_array_attack.techniques += $array_obj_complete_flow_techniques
$obj_complete_helper_array_attack | ConvertTo-Json -Depth 3 | Out-File $file_json_helper_attack_array -Encoding UTF8
Write-Host `u{2139} -Foregroundcolor Green $($file_json_helper_attack_array) "has been generated. The file will be used by the functions New-ATTACKSighting and New-ATTACKNavigatorLayer"
}

function New-ATTACKNavigatorLayer {
<#
.Description
This function generates in an automated manner an ATT&CK(r) Navigator Layer including the provided and retained ATT&CK(r) (Sub-)Techniques/Tactic pairs. It will use available helper files generated by the functions New-ATTACKRecommendations and/or New-CTIDATTACKFlow. As a last resort, if these are not present, it will request manual input.
.EXAMPLE
# No parameters are to be provided, the function will verify if any helper file is available and will provide the possibility to provide manual input.
PS> New-ATTACKNavigatorLayer
.INPUTS
None, objects cannot be pipe to New-ATTACKNavigatorLayer.
.OUTPUTS
navigator_layer.json, eventually with a prefix.
.SYNOPSIS
Generating a JSON ATT&CK(r) Navigator Layer from the identified (Sub-)Techniques/Tactic pairs leveraging the use of Navigator Layers in the different use cases.
#>

$var_obj_layer_technique_property_colour = "#c41a9f"
$var_obj_layer_tactic_property_colour = "#c41a9f"

# Starting
Clear-Host
Write-Host  -ForegroundColor Blue `u{1F6E0} "This function will generate an ATT&CK`u{00AE} Navigator Layer based on the previously selected (Sub-)Techniques / Tactic pairs from New-CTIDATTACKFlow, the previously selected (Sub-)Techniques from New-ATTACKRecommendations or based on maunal input."
[Environment]::NewLine

Get-ATTACKEnterpriseJSON

if (Test-Path -Path $file_json_helper_attack_array -PathType Leaf) {
    Set-AttackArray
}
elseif (Test-Path -Path $file_json_helper_attack_list -PathType Leaf) {
    Set-AttackList
}
else{
    $InputFile = "NoInput"
    Test-FileInputStructure $InputFile
    New-NavigatorLayerObjects
}

Test-FileInputPropertyName $InputFile

# Verify if multiple tactic pairings for a given (Sub-)Technique is present and generate accordingly
[System.Collections.ArrayList]$array_obj_navigator_techniques =@()
$range_navigator_objects=$array_obj_sorted_navigator_objects.count
for($instance_object=0; $instance_object -lt $range_navigator_objects; $instance_object=$instance_object+1) {
    if ($array_obj_sorted_navigator_objects[$instance_object].attack_tactics.count -eq 1) {
        $array_row = "" | Select-Object techniqueID,tactic,color
        $array_row.techniqueID = $array_obj_sorted_navigator_objects[$instance_object].attack_id
        $array_row.tactic = [string]$array_obj_sorted_navigator_objects[$instance_object].attack_tactics
        $array_row.color = $var_obj_layer_technique_property_colour
        $array_obj_navigator_techniques += $array_row
    }
    else {
        $range_navigator_objects_tactics=0..($array_obj_sorted_navigator_objects[$instance_object].attack_tactics.count-1)
        foreach ($instance_tactic in $range_navigator_objects_tactics) {
            $array_row = "" | Select-Object techniqueID,tactic,color
            $array_row.techniqueID = $array_obj_sorted_navigator_objects[$instance_object].attack_id
            $array_row.tactic = [string]$array_obj_sorted_navigator_objects[$instance_object].attack_tactics[$instance_tactic]
            $array_row.color = $var_obj_layer_technique_property_colour
            $array_obj_navigator_techniques += $array_row
        }
    }
}

# Define the layer header
$obj_navigator_template_header =@"
{
    "name": "",
    "versions": {
        "attack": "12",
        "navigator": "4.8.0",
        "layer": "4.4"
    },
    "domain": "enterprise-attack",
    "description": "",
    "filters": {
        "platforms": [
            "Linux",
            "macOS",
            "Windows",
            "Network",
            "PRE",
            "Containers",
            "Office 365",
            "SaaS",
            "Google Workspace",
            "IaaS",
            "Azure AD"
        ]
    },
    "sorting": 0,
    "layout": {
        "layout": "side",
        "aggregateFunction": "average",
        "showID": true,
        "showName": true,
        "showAggregateScores": false,
        "countUnscored": false
    },
    "hideDisabled": false,
    "techniques": [],
    "gradient": {
        "colors": [
            "#ff6666ff",
            "#ffe766ff",
            "#8ec843ff"
        ],
        "minValue": 0,
        "maxValue": 100
    },
    "legendItems": [],
    "metadata": [],
    "links": [],
    "showTacticRowBackground": true,
    "tacticRowBackground": "#c41a9f",
    "selectTechniquesAcrossTactics": false,
    "selectSubtechniquesWithParent": false
}
"@

# Generating the Navigator Layer file.
$obj_complete_navigator_layer = $obj_navigator_template_header | ConvertFrom-Json
$obj_complete_navigator_layer.techniques += $array_obj_navigator_techniques
$obj_complete_navigator_layer.tacticRowBackground = $var_obj_layer_tactic_property_colour
$obj_complete_navigator_layer.name = $file_prefix_content
$file_navigator_layer_json = (get-location).path + "\"+$file_prefix+"navigator_layer.json"
($obj_complete_navigator_layer | ConvertTo-Json) | Out-File $file_navigator_layer_json -Encoding UTF8

# Closing
[Environment]::NewLine
Write-Host `u{2705} -Foregroundcolor Green "All done." $($file_navigator_layer_json) "has been generated. This file can be uploaded and used with https://mitre-attack.github.io/attack-navigator/."
}

function New-ATTACKSighting {
<#
.Description
This script generates in an semi-automated way a Sighting. It will use available helper files generated by the functions New-ATTACKRecommendations and/or New-CTIDATTACKFlow. As a last resort, if these are not present, it will request manual input. In all cases, additional information is requested, such as start date, victim country, victim sector, the detection source, the platform, and the privilege level. It will also present the option to provide the used software.
.EXAMPLE
# No parameters are to be provided, the function will verify if any helper file is available and will provide the possibility to provide manual input.
PS> New-ATTACKSighting
.INPUTS
None, objects cannot be pipe to New-CTIDATTACKFlow.
.OUTPUTS
GUID_sighting.json with a fresh GUID upon each execution.
.SYNOPSIS
Generating JSON Direct Technique/Software Sightings from the identified (Sub-)Techniques providing a means to exchange this information with MITRE (or other entities).
#>

$format = "yyyy-MM-dd'T'HH:mm:ss'Z'"
[System.Globalization.CultureInfo]$provider = [System.Globalization.CultureInfo]::InvariantCulture
[ref]$parsedDate = get-date

Clear-Host
Write-Host -ForegroundColor Blue `u{1F6E0} "This function will construct Human Validated Sightings of MITRE ATT&CK`u{00AE} (Sub-)Techniques and optionally Software Sightings."

Get-ATTACKEnterpriseJSON

if (Test-Path -Path $file_json_helper_attack_array -PathType Leaf) {
    Set-AttackArray
}
elseif (Test-Path -Path $file_json_helper_attack_list -PathType Leaf) {
    Set-AttackList
}
else{
    $InputFile = "NoInput"
    Test-FileInputStructure $InputFile
}

[Environment]::NewLine
do {
    $Sighting_Start = Read-Host `u{2139} "Please provide the start time for the sightings.`n`u{2328}  Please use RFC 3339 timestamps in UTC time [2022-12-22T12:03:23Z]"
    $isValid = [DateTime]::TryParseExact($Sighting_Start, $format,$provider,[System.Globalization.DateTimeStyles]::None,$parseddate)
    if ($isValid -eq $false) {
        Write-Host `u{26A0} -Foregroundcolor DarkRed "Invalid input. Try again."
    }
}
until ($isValid -eq $true)
[Environment]::NewLine
[System.Collections.ArrayList]$sightings_techniques_array =@()
$sightings_techniques_array += $list_obj_selected_attack_techniques.attack_id

$detectionList = "host_based","network_based","cloud_based"
do {
    $detectionSource = Read-Host `u{2328} " Define the detection source [host_based, network_based, cloud_based]"
        $result = $detectionSource -in $detectionList
        if ($result -eq $false) {
            Write-Host `u{26A0} -Foregroundcolor DarkRed $detectionSource "is not in the list. Verify your input please."
            $isValid = $false
        }
        else {
            $isValid = $true
        }
}
until ($isValid -eq $true)

$NAICSList = @{11="Agriculture, Forestry, Fishing and Hunting";21="Mining, Quarrying, and Oil and Gas Extraction";22="Utilities";23="Construction";31="Manufacturing";32="Manufacturing";33="Manufacturing";42="Wholesale Trade";44="Retail Trade";45="Retail Trade";48="Transportation and Warehousing";49="Transportation and Warehousing";51="Information";52="Finance and Insurance";53="Real Estate and Rental and Leasing";54="Professional, Scientific, and Technical Services";55="Management of Companies and Enterprises";56="Administrative and Support and Waste Management and Remediation Services";61="Educational Services";62="Health Care and Social Assistance";71="Arts, Entertainment, and Recreation";72="Accommodation and Food Services";81="Other Services (except Public Administration)";92="Public Administration"}
do {
    $victimSector = Read-Host `u{2328} " Provide the victim sector NAICS code, first 2 digits only [eg 22]"
        $result = $victimSector -in $NAICSList.Keys
        if ($result -eq $false) {
            Write-Host `u{26A0} -Foregroundcolor DarkRed $victimSector "is not in the NAICS list. Verify your input please."
            $NAICSTable = $NAICSList.GetEnumerator() | Sort-Object key | Format-Table -AutoSize
            Write-Host "Refer to the following list:"
            $NAICSTable
            $isValid = $false
        }
        else {
            $VictimSectorName = $NAICSList.[int32]$victimSector
            Write-Host `u{2705} -Foregroundcolor Green "You selected the following sector:" $victimSectorName
            $isValid = $true
        }
}
until ($isValid -eq $true)

$ISOCountryList = @{"AF"="The Islamic Republic of Afghanistan";"AX"="Åland";"AL"="The Republic of Albania";"DZ"="The People's Democratic Republic of Algeria";"AS"="The Territory of American Samoa";"AD"="The Principality of Andorra";"AO"="The Republic of Angola";"AI"="Anguilla";"AQ"="All land and ice shelves south of the 60th parallel south";"AG"="Antigua and Barbuda";"AR"="The Argentine Republic";"AM"="The Republic of Armenia";"AW"="Aruba";"AU"="The Commonwealth of Australia";"AT"="The Republic of Austria";"AZ"="The Republic of Azerbaijan";"BS"="The Commonwealth of The Bahamas";"BH"="The Kingdom of Bahrain";"BD"="The People's Republic of Bangladesh";"BB"="Barbados";"BY"="The Republic of Belarus";"BE"="The Kingdom of Belgium";"BZ"="Belize";"BJ"="The Republic of Benin";"BM"="Bermuda";"BT"="The Kingdom of Bhutan";"BO"="The Plurinational State of Bolivia";"BQ"="Bonaire, Sint Eustatius and Saba";"BA"="Bosnia and Herzegovina";"BW"="The Republic of Botswana";"BV"="Bouvet Island";"BR"="The Federative Republic of Brazil";"IO"="The British Indian Ocean Territory";"BN"="The Nation of Brunei, the Abode of Peace";"BG"="The Republic of Bulgaria";"BF"="Burkina Faso";"BI"="The Republic of Burundi";"CV"="The Republic of Cabo Verde";"KH"="The Kingdom of Cambodia";"CM"="The Republic of Cameroon";"CA"="Canada";"KY"="The Cayman Islands";"CF"="The Central African Republic";"TD"="The Republic of Chad";"CL"="The Republic of Chile";"CN"="The People's Republic of China";"CX"="The Territory of Christmas Island";"CC"="The Territory of Cocos (Keeling) Islands";"CO"="The Republic of Colombia";"KM"="The Union of the Comoros";"CD"="The Democratic Republic of the Congo";"CG"="The Republic of the Congo";"CK"="The Cook Islands";"CR"="The Republic of Costa Rica";"CI"="The Republic of Côte d'Ivoire";"HR"="The Republic of Croatia";"CU"="The Republic of Cuba";"CW"="The Country of Curaçao";"CY"="The Republic of Cyprus";"CZ"="The Czech Republic";"DK"="The Kingdom of Denmark";"DJ"="The Republic of Djibouti";"DM"="The Commonwealth of Dominica";"DO"="The Dominican Republic";"EC"="The Republic of Ecuador";"EG"="The Arab Republic of Egypt";"SV"="The Republic of El Salvador";"GQ"="The Republic of Equatorial Guinea";"ER"="The State of Eritrea";"EE"="The Republic of Estonia";"SZ"="The Kingdom of Eswatini";"ET"="The Federal Democratic Republic of Ethiopia";"FK"="The Falkland Islands";"FO"="The Faroe Islands";"FJ"="The Republic of Fiji";"FI"="The Republic of Finland";"FR"="The French Republic";"GF"="Guyane";"PF"="French Polynesia";"TF"="The French Southern and Antarctic Lands";"GA"="The Gabonese Republic";"GM"="The Republic of The Gambia";"GE"="Georgia";"DE"="The Federal Republic of Germany";"GH"="The Republic of Ghana";"GI"="Gibraltar";"GR"="The Hellenic Republic";"GL"="Kalaallit Nunaat";"GD"="Grenada";"GP"="Guadeloupe";"GU"="The Territory of Guam";"GT"="The Republic of Guatemala";"GG"="The Bailiwick of Guernsey";"GN"="The Republic of Guinea";"GW"="The Republic of Guinea-Bissau";"GY"="The Co-operative Republic of Guyana";"HT"="The Republic of Haiti";"HM"="The Territory of Heard Island and McDonald Islands";"VA"="The Holy See";"HN"="The Republic of Honduras";"HK"="The Hong Kong Special Administrative Region of China[10]";"HU"="Hungary";"IS"="Iceland";"IN"="The Republic of India";"ID"="The Republic of Indonesia";"IR"="The Islamic Republic of Iran";"IQ"="The Republic of Iraq";"IE"="Ireland";"IM"="The Isle of Man";"IL"="The State of Israel";"IT"="The Italian Republic";"JM"="Jamaica";"JP"="Japan";"JE"="The Bailiwick of Jersey";"JO"="The Hashemite Kingdom of Jordan";"KZ"="The Republic of Kazakhstan";"KE"="The Republic of Kenya";"KI"="The Republic of Kiribati";"KP"="The Democratic People's Republic of Korea";"KR"="The Republic of Korea";"KW"="The State of Kuwait";"KG"="The Kyrgyz Republic";"LA"="The Lao People's Democratic Republic";"LV"="The Republic of Latvia";"LB"="The Lebanese Republic";"LS"="The Kingdom of Lesotho";"LR"="The Republic of Liberia";"LY"="The State of Libya";"LI"="The Principality of Liechtenstein";"LT"="The Republic of Lithuania";"LU"="The Grand Duchy of Luxembourg";"MO"="The Macao Special Administrative Region of China[11]";"MK"="The Republic of North Macedonia[12]";"MG"="The Republic of Madagascar";"MW"="The Republic of Malawi";"MY"="Malaysia";"MV"="The Republic of Maldives";"ML"="The Republic of Mali";"MT"="The Republic of Malta";"MH"="The Republic of the Marshall Islands";"MQ"="Martinique";"MR"="The Islamic Republic of Mauritania";"MU"="The Republic of Mauritius";"YT"="The Department of Mayotte";"MX"="The United Mexican States";"FM"="The Federated States of Micronesia";"MD"="The Republic of Moldova";"MC"="The Principality of Monaco";"MN"="Mongolia";"ME"="Montenegro";"MS"="Montserrat";"MA"="The Kingdom of Morocco";"MZ"="The Republic of Mozambique";"MM"="The Republic of the Union of Myanmar";"NA"="The Republic of Namibia";"NR"="The Republic of Nauru";"NP"="The Federal Democratic Republic of Nepal";"NL"="The Kingdom of the Netherlands";"NC"="New Caledonia";"NZ"="New Zealand";"NI"="The Republic of Nicaragua";"NE"="The Republic of the Niger";"NG"="The Federal Republic of Nigeria";"NU"="Niue";"NF"="The Territory of Norfolk Island";"MP"="The Commonwealth of the Northern Mariana Islands";"NO"="The Kingdom of Norway";"OM"="The Sultanate of Oman";"PK"="The Islamic Republic of Pakistan";"PW"="The Republic of Palau";"PS"="The State of Palestine";"PA"="The Republic of Panamá";"PG"="The Independent State of Papua New Guinea";"PY"="The Republic of Paraguay";"PE"="The Republic of Perú";"PH"="The Republic of the Philippines";"PN"="The Pitcairn, Henderson, Ducie and Oeno Islands";"PL"="The Republic of Poland";"PT"="The Portuguese Republic";"PR"="The Commonwealth of Puerto Rico";"QA"="The State of Qatar";"RE"="Réunion";"RO"="Romania";"RU"="The Russian Federation";"RW"="The Republic of Rwanda";"BL"="The Collectivity of Saint-Barthélemy";"SH"="Saint Helena, Ascension and Tristan da Cunha";"KN"="Saint Kitts and Nevis";"LC"="Saint Lucia";"MF"="The Collectivity of Saint-Martin";"PM"="The Overseas Collectivity of Saint-Pierre and Miquelon";"VC"="Saint Vincent and the Grenadines";"WS"="The Independent State of Samoa";"SM"="The Republic of San Marino";"ST"="The Democratic Republic of São Tomé and Príncipe";"SA"="The Kingdom of Saudi Arabia";"SN"="The Republic of Senegal";"RS"="The Republic of Serbia";"SC"="The Republic of Seychelles";"SL"="The Republic of Sierra Leone";"SG"="The Republic of Singapore";"SX"="Sint Maarten";"SK"="The Slovak Republic";"SI"="The Republic of Slovenia";"SB"="The Solomon Islands";"SO"="The Federal Republic of Somalia";"ZA"="The Republic of South Africa";"GS"="South Georgia and the South Sandwich Islands";"SS"="The Republic of South Sudan";"ES"="The Kingdom of Spain";"LK"="The Democratic Socialist Republic of Sri Lanka";"SD"="The Republic of the Sudan";"SR"="The Republic of Suriname";"SJ"="Svalbard and Jan Mayen";"SE"="The Kingdom of Sweden";"CH"="The Swiss Confederation";"SY"="The Syrian Arab Republic";"TW"="The Republic of China";"TJ"="The Republic of Tajikistan";"TZ"="The United Republic of Tanzania";"TH"="The Kingdom of Thailand";"TL"="The Democratic Republic of Timor-Leste";"TG"="The Togolese Republic";"TK"="Tokelau";"TO"="The Kingdom of Tonga";"TT"="The Republic of Trinidad and Tobago";"TN"="The Republic of Tunisia";"TR"="The Republic of Türkiye";"TM"="Turkmenistan";"TC"="The Turks and Caicos Islands";"TV"="Tuvalu";"UG"="The Republic of Uganda";"UA"="Ukraine";"AE"="The United Arab Emirates";"GB"="The United Kingdom of Great Britain and Northern Ireland";"UM"="Baker Island, Howland Island, Jarvis Island, Johnston Atoll, Kingman Reef, Midway Atoll, Navassa Island, Palmyra Atoll, and Wake Island";"US"="The United States of America";"UY"="The Oriental Republic of Uruguay";"UZ"="The Republic of Uzbekistan";"VU"="The Republic of Vanuatu";"VE"="The Bolivarian Republic of Venezuela";"VN"="The Socialist Republic of Viet Nam";"VG"="The Virgin Islands";"VI"="The Virgin Islands of the United States";"WF"="The Territory of the Wallis and Futuna Islands";"EH"="The Sahrawi Arab Democratic Republic";"YE"="The Republic of Yemen";"ZM"="The Republic of Zambia";"ZW"="The Republic of Zimbabwe"}
do {
    $victimCountry = Read-Host `u{2328} " Provide the victim ISO 3166-1 alpha-2 country code [eg BE]"
        $result = $victimCountry -in $ISOCountryList.Keys
        if ($result -eq $false) {
            Write-Host `u{26A0} -Foregroundcolor DarkRed $victimCountry "is not in the ISO Country list. Verify your input please."
            $isValid = $false
        }
        else {
            $VictimCountryName = $ISOCountryList.$victimCountry
            Write-Host `u{2705} -Foregroundcolor Green "You selected the following country:" $victimCountryName
            $isValid = $true
        }
}
until ($isValid -eq $true)

$platformList = "windows","macos","nix","other"
do {
    $victimPlatformenv = Read-Host `u{2328} " Define the platform [windows, macos, nix, other]"
        $result = $victimPlatformenv -in $platformList
        if ($result -eq $false) {
            Write-Host `u{26A0} -Foregroundcolor DarkRed $victimPlatformenv "is not in the list. Verify your input please."
            $isValid = $false
        }
        else {
            $isValid = $true
        }
}
until ($isValid -eq $true)

$privilegeList = "system","admin","user","none"
do {
    $victimPrivilegelevel = Read-Host `u{2328} " Provide the privilege level [system, admin, user, none]"
        $result = $victimPrivilegelevel -in $privilegeList
        if ($result -eq $false) {
            Write-Host `u{26A0} -Foregroundcolor DarkRed $victimPrivilegelevel "is not in the list. Verify your input please."
            $isValid = $false
        }
        else {
            $isValid = $true
        }
}
until ($isValid -eq $true)

$sightingSoftware = Read-Host `u{2328} " Provide the malicious software name that was observed. This should be an exact name from the list https://attack.mitre.org/software/. Simply tap enter if not applicable."
if (-not($sightingSoftware)) {
    $sightingSoftware = "NaN"
}

$sightingVersion = "2.0"
$sightings_id = New-GUID
$detectionType = "human_validated"
$file_sighting_json = (get-location).path + "\" + [string]$sightings_id.Guid + "_sighting.json"

[System.Collections.ArrayList]$sightings_array_json =@()
$row = "" | Select-Object version,id,start_time,tid,detection_type,detection_source,sector,country,platform,privilege_level,software_name
$row.version = $sightingVersion
$row.id = $sightings_id.Guid
$row.start_time = $Sighting_Start
$row.tid = $sightings_techniques_array
$row.detection_type = $detectionType
$row.detection_source = $detectionSource
$row.sector = $victimSector
$row.country = $victimCountry
$row.platform = $victimPlatformenv
$row.privilege_level = $victimPrivilegelevel
$row.software_name = $sightingSoftware
$sightings_array_json += $row
[Environment]::NewLine
Write-Host `u{2705} -Foregroundcolor Green "Done." $($file_sighting_json) "has been generated."
Write-Host `u{2139} "Verify https://github.com/center-for-threat-informed-defense/sightings_ecosystem/blob/main/data/data_model.md for specific information."
($sightings_array_json | ConvertTo-Json) | Out-File $file_sighting_json -Encoding UTF8
}

Export-ModuleMember -Function 'New-ATTACKRecommendations','New-CTIDATTACKFlow','Get-ATTACKEnterpriseJSON','New-ATTACKNavigatorLayer','New-ATTACKSighting'
