#---------------------------------------------------------#
#  File:         Select-Reviewer.ps1                      #
#  Author:       Codey Funston [s222250824@deakin.edu.au] #
#                                                         #
#  Description:  Based on repository preferences, selects #
#                a reviewer, or whole team if no matches. #
#---------------------------------------------------------#

<#
.SYNOPSIS
    Selects reviewer for pull-request based on current repository.

.DESCRIPTION
    By using a provided JSON repository preferences document this script 
    selects the corresponding team member for pull-request review. If 
    there are no matches, the team member is set to the team lead for
    them to manually assign the pull-reqeust.

.PARAMETER Path
    File path to JSON preferences document.

.INPUTS
    [string] - Path to JSON file.

.OUTPUTS
    [string] - Reviewer's email address.

.EXAMPLE
    $reviewer = .\Select-Reviewer.ps1 -Path ..\data\PR_Preferences.json
#>

param (
    [string]$Path
)

$reviewer = $null
$thisRepo = $env:REPO

try {
    $data = Get-Content -Raw $Path | ConvertFrom-Json -AsHashtable
    $preferences = $data["preferences"]
    $teamLead = $data["teamLead"]
}
catch {
    Write-Error "Failed to read or parse prefences JSON."
    exit 1
}

foreach ($member in $preferences.Keys) {
    if ($preferences[$member] -contains $thisRepo) {
        $reviewer = $member
        break
    }
}

if ($null -eq $reviewer) {
    $reviewer = $teamLead
}

Write-Output $reviewer