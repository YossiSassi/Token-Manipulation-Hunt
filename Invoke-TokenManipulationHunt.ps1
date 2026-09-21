<#
.SYNOPSIS
Hunt for Token Manipulation behavior with Sysmon & Security Events evidence.

.DESCRIPTION
Hunt for Token Manipulation behavior with Sysmon & Security Events evidence. Correlates Event IDs 1,10 and 4688 (enrichment), 4703 (optional enrichment).

.PARAMETER LookBackMinutes
How far back to fetch evidence/events. More minutes = Longer query time. Defaults to 120 seconds.

.PARAMETER CorrelationSeconds
The time window to correlate between the events. Unless process is suspended/split payload, usually very few seconds. Defaults to 120 seconds.

.PARAMETER MinimumConfidence
The minimal suspicious score to filter results as output. Ranging between 0 to 100. Default is 60. Lower confidence value might produce False-Positives, yet uncover some other behavior.

.NOTES
Version: 1.0
Comments welcome to yossis@protonmail.com (1nTh35h311)
#>
param(
    [int]$LookbackMinutes = 120, 
    [int]$CorrelationSeconds = 120, 
    [int]$MinimumConfidence = 60
)

$StartTime = (Get-Date).AddMinutes(-$LookbackMinutes)
$SysmonLog = 'Microsoft-Windows-Sysmon/Operational'


# ============================================================
# Helpers
# ============================================================

function Get-EventDataMap {
    param(
        [Parameter(Mandatory)]
        $Event
    )

    [xml]$Xml = $Event.ToXml()

    $Map = @{}

    foreach ($Item in @($Xml.Event.EventData.Data)) {

        $Name = [string]$Item.Name

        if (-not [string]::IsNullOrWhiteSpace($Name)) {
            $Map[$Name] = [string]$Item.'#text'
        }
    }

    return $Map
}


function Convert-Pid {
    param($Value)

    if (
        [string]::IsNullOrWhiteSpace([string]$Value) -or
        $Value -eq '-'
    ) {
        return $null
    }

    try {

        $Text = ([string]$Value).Trim()

        if ($Text -match '^0x[0-9a-fA-F]+$') {
            return [Convert]::ToInt64(
                $Text.Substring(2),
                16
            )
        }

        return [int64]$Text
    }
    catch {
        return $null
    }
}


function Join-Account {
    param(
        $Domain,
        $User
    )

    if (
        [string]::IsNullOrWhiteSpace($User) -or
        $User -eq '-'
    ) {
        return $null
    }

    if (
        [string]::IsNullOrWhiteSpace($Domain) -or
        $Domain -eq '-'
    ) {
        return $User
    }

    return "$Domain\$User"
}


function Test-ServiceIdentity {
    param($User)

    if ([string]::IsNullOrWhiteSpace($User)) {
        return $false
    }

    return (
        $User -ieq 'NT AUTHORITY\SYSTEM' -or
        $User -ieq 'NT AUTHORITY\LOCAL SERVICE' -or
        $User -ieq 'NT AUTHORITY\NETWORK SERVICE'
    )
}


function Test-SystemIdentity {
    param($User)

    if ([string]::IsNullOrWhiteSpace($User)) {
        return $false
    }

    return (
        $User -ieq 'NT AUTHORITY\SYSTEM' -or
        $User -match '\\SYSTEM$'
    )
}


# ============================================================
# Sysmon EID 1
# ============================================================

Write-Host "[*] Reading Sysmon Event ID 1..." -ForegroundColor Cyan

$SysmonProcesses = @(
    Get-WinEvent -FilterHashtable @{
        LogName   = $SysmonLog
        Id        = 1
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue |
    ForEach-Object {

        $D = Get-EventDataMap $_

        [PSCustomObject]@{
            Time              = $_.TimeCreated

            ProcessGuid       = $D.ProcessGuid
            ProcessId         = Convert-Pid $D.ProcessId
            Image             = $D.Image
            CommandLine       = $D.CommandLine
            User              = $D.User
            IntegrityLevel    = $D.IntegrityLevel
            LogonId           = $D.LogonId

            ParentProcessGuid = $D.ParentProcessGuid
            ParentProcessId   = Convert-Pid $D.ParentProcessId
            ParentImage       = $D.ParentImage
            ParentCommandLine = $D.ParentCommandLine
            ParentUser        = $D.ParentUser
        }
    }
)


# ============================================================
# Sysmon EID 10
# ============================================================

Write-Host "[*] Reading Sysmon Event ID 10..." -ForegroundColor Cyan

$ProcessAccess = @(
    Get-WinEvent -FilterHashtable @{
        LogName   = $SysmonLog
        Id        = 10
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue |
    ForEach-Object {

        $D = Get-EventDataMap $_

        [PSCustomObject]@{
            Time              = $_.TimeCreated

            SourceProcessGuid = $D.SourceProcessGUID
            SourceProcessId   = Convert-Pid $D.SourceProcessId
            SourceImage       = $D.SourceImage
            SourceUser        = $D.SourceUser

            TargetProcessGuid = $D.TargetProcessGUID
            TargetProcessId   = Convert-Pid $D.TargetProcessId
            TargetImage       = $D.TargetImage
            TargetUser        = $D.TargetUser

            GrantedAccess     = $D.GrantedAccess
            CallTrace         = $D.CallTrace
        }
    }
)


# ============================================================
# Security 4688
# Used as enrichment only
# ============================================================

Write-Host "[*] Reading Security Event ID 4688..." -ForegroundColor Cyan

$Security4688 = @(
    Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4688
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue |
    ForEach-Object {

        $D = Get-EventDataMap $_

        [PSCustomObject]@{
            Time =
                $_.TimeCreated

            CreatorPid =
                Convert-Pid $D.ProcessId

            CreatorImage =
                $D.ParentProcessName

            CreatorUser =
                Join-Account `
                    $D.SubjectDomainName `
                    $D.SubjectUserName

            CreatorSid =
                $D.SubjectUserSid

            NewPid =
                Convert-Pid $D.NewProcessId

            NewProcess =
                $D.NewProcessName

            CommandLine =
                $D.CommandLine

            TargetUser =
                Join-Account `
                    $D.TargetDomainName `
                    $D.TargetUserName

            TargetSid =
                $D.TargetUserSid
        }
    }
)


# ============================================================
# Security 4703
# Optional enrichment
# ============================================================

$Security4703 = @(
    Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4703
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue |
    ForEach-Object {

        $D = Get-EventDataMap $_

        [PSCustomObject]@{
            Time =
                $_.TimeCreated

            ProcessId =
                Convert-Pid $D.ProcessId

            ProcessName =
                $D.ProcessName

            EnabledPrivileges =
                $D.EnabledPrivilegeList

            SubjectUser =
                Join-Account `
                    $D.SubjectDomainName `
                    $D.SubjectUserName
        }
    }
)


# ============================================================
# Main hunt:
#
# START FROM THE SYSTEM CHILD, NOT FROM 4688.
# ============================================================

Write-Host "[*] Correlating privileged children..." -ForegroundColor Cyan

$Results = @()


$SystemChildren = @(
    $SysmonProcesses |
    Where-Object {

        $_.IntegrityLevel -match '^System$' -and

        (
            Test-SystemIdentity `
                -User $_.User
        )
    }
)


foreach ($Child in $SystemChildren) {


    # ========================================================
    # 1. Resolve the direct parent from Sysmon EID 1
    # ========================================================

    $DirectParent = $null


    # Prefer ProcessGuid

    if (
        -not [string]::IsNullOrWhiteSpace(
            $Child.ParentProcessGuid
        )
    ) {

        $DirectParent =
            $SysmonProcesses |
            Where-Object {

                $_.ProcessGuid -eq
                    $Child.ParentProcessGuid -and

                $_.Time -le
                    $Child.Time
            } |
            Sort-Object Time -Descending |
            Select-Object -First 1
    }


    # Fall back to PID

    if (
        -not $DirectParent -and
        $Child.ParentProcessId
    ) {

        $DirectParent =
            $SysmonProcesses |
            Where-Object {

                $_.ProcessId -eq
                    $Child.ParentProcessId -and

                $_.Time -le
                    $Child.Time
            } |
            Sort-Object Time -Descending |
            Select-Object -First 1
    }


    # ========================================================
    # 2. Find 4688 for resulting child
    # ========================================================

    $Create4688 =
        $Security4688 |
        Where-Object {

            $_.NewPid -eq
                $Child.ProcessId -and

            [math]::Abs(
                ($_.Time - $Child.Time).TotalSeconds
            ) -le 10
        } |
        Sort-Object Time |
        Select-Object -First 1


    # ========================================================
    # 3. DIRECT PARENT-CHILD CASE
    #
    # Example:
    #
    # PowerShell (user)
    #       ->
    # cmd.exe (SYSTEM)
    #
    # DirectParent is therefore our first manipulator candidate.
    # ========================================================

    $DirectParentIsUserProcess =
        (
            $DirectParent -and
            -not (
                Test-ServiceIdentity `
                    -User $DirectParent.User
            )
        )


    # ========================================================
    # 4. Look for EID 10 originating from DIRECT PARENT
    #
    # This is the key missing logic.
    #
    # Parent:
    #   powershell.exe / normal user
    #
    # Event 10:
    #   powershell.exe -> winlogon.exe
    #
    # Child:
    #   cmd.exe / SYSTEM
    # ========================================================

    $DirectParentAccess = $null


    if ($DirectParentIsUserProcess) {

        $DirectParentAccess =
            $ProcessAccess |
            Where-Object {

                (
                    $_.SourceProcessGuid -and
                    $DirectParent.ProcessGuid -and
                    $_.SourceProcessGuid -eq
                        $DirectParent.ProcessGuid
                ) -or 
		(
                    $_.SourceProcessId -eq
                        $DirectParent.ProcessId
                )
            } |
            Where-Object {

                $_.Time -ge
                    $Child.Time.AddSeconds(
                        -$CorrelationSeconds
                    ) -and

                $_.Time -le
                    $Child.Time.AddSeconds(5)
            } |
            Where-Object {

                # Donor should be SYSTEM context
                (
                    Test-SystemIdentity `
                        -User $_.TargetUser
                )
            } |
            Sort-Object Time -Descending |
            Select-Object -First 1
    }


    # ========================================================
    # 5. DONOR-PARENT CASE
    #
    # Example:
    #
    # PowerShell -> winlogon
    #
    # Child reports:
    # ParentPID = winlogon
    #
    # Find some non-service process that accessed this parent.
    # ========================================================

    $DonorParentAccess = $null


    $DonorParentAccess =
        $ProcessAccess |
        Where-Object {

            $_.TargetProcessId -eq
                $Child.ParentProcessId
        } |
        Where-Object {

            $_.Time -ge
                $Child.Time.AddSeconds(
                    -$CorrelationSeconds
                ) -and

            $_.Time -le
                $Child.Time.AddSeconds(5)
        } |
        Where-Object {

            -not (
                Test-ServiceIdentity `
                    -User $_.SourceUser
            )
        } |
        Sort-Object Time -Descending |
        Select-Object -First 1


    # ========================================================
    # 6. Determine relationship
    # ========================================================

    $Relationship = $null
    $ManipulatorPID = $null
    $ManipulatorImage = $null
    $ManipulatorUser = $null
    $ManipulatorCommandLine = $null
    $ManipulatorGuid = $null

    $TokenSourcePID = $null
    $TokenSourceImage = $null
    $TokenSourceUser = $null
    $TokenSourceGuid = $null

    $GrantedAccess = $null
    $AccessTime = $null


    # --------------------------------------------------------
    # CASE A - DIRECT PARENT MANIPULATOR
    # --------------------------------------------------------

    if (
        $DirectParentIsUserProcess -and
        $DirectParentAccess
    ) {

        $Relationship =
            'Direct Parent-Child Token Manipulation'

        $ManipulatorPID =
            $DirectParent.ProcessId

        $ManipulatorImage =
            $DirectParent.Image

        $ManipulatorUser =
            $DirectParent.User

        $ManipulatorCommandLine =
            $DirectParent.CommandLine

        $ManipulatorGuid =
            $DirectParent.ProcessGuid


        $TokenSourcePID =
            $DirectParentAccess.TargetProcessId

        $TokenSourceImage =
            $DirectParentAccess.TargetImage

        $TokenSourceUser =
            $DirectParentAccess.TargetUser

        $TokenSourceGuid =
            $DirectParentAccess.TargetProcessGuid


        $GrantedAccess =
            $DirectParentAccess.GrantedAccess

        $AccessTime =
            $DirectParentAccess.Time
    }


    # --------------------------------------------------------
    # CASE B - TOKEN DONOR REPORTED AS CHILD PARENT
    # --------------------------------------------------------

    elseif ($DonorParentAccess) {

        $Relationship =
            'Token Donor Reported As Child Parent'

        $ManipulatorPID =
            $DonorParentAccess.SourceProcessId

        $ManipulatorImage =
            $DonorParentAccess.SourceImage

        $ManipulatorUser =
            $DonorParentAccess.SourceUser

        $ManipulatorGuid =
            $DonorParentAccess.SourceProcessGuid


        # Resolve manipulator command line

        $ManipulatorEvent =
            $SysmonProcesses |
            Where-Object {

                (
                    $_.ProcessGuid -eq
                        $ManipulatorGuid
                ) -or
                (
                    $_.ProcessId -eq
                        $ManipulatorPID
                )
            } |
            Where-Object {
                $_.Time -le $AccessTime
            } |
            Sort-Object Time -Descending |
            Select-Object -First 1


        if ($ManipulatorEvent) {

            $ManipulatorImage =
                $ManipulatorEvent.Image

            $ManipulatorUser =
                $ManipulatorEvent.User

            $ManipulatorCommandLine =
                $ManipulatorEvent.CommandLine
        }


        $TokenSourcePID =
            $DonorParentAccess.TargetProcessId

        $TokenSourceImage =
            $DonorParentAccess.TargetImage

        $TokenSourceUser =
            $DonorParentAccess.TargetUser

        $TokenSourceGuid =
            $DonorParentAccess.TargetProcessGuid

        $GrantedAccess =
            $DonorParentAccess.GrantedAccess

        $AccessTime =
            $DonorParentAccess.Time
    }


    # --------------------------------------------------------
    # CASE C - DIRECT PARENT WITHOUT EID 10
    #
    # Keep as lower-confidence candidate if:
    #
    # regular-user parent
    #       ->
    # SYSTEM child
    #
    # This is useful if EID 10 filtering missed the donor access.
    # --------------------------------------------------------

    elseif ($DirectParentIsUserProcess) {

        $Relationship =
            'Direct Parent-Child SYSTEM Identity Transition'

        $ManipulatorPID =
            $DirectParent.ProcessId

        $ManipulatorImage =
            $DirectParent.Image

        $ManipulatorUser =
            $DirectParent.User

        $ManipulatorCommandLine =
            $DirectParent.CommandLine

        $ManipulatorGuid =
            $DirectParent.ProcessGuid
    }


    else {
        continue
    }


    # ========================================================
    # 7. Validate manipulator really differs from SYSTEM child
    # ========================================================

    if (
        Test-ServiceIdentity `
            -User $ManipulatorUser
    ) {
        continue
    }


    # ========================================================
    # 8. Optional 4703 correlation
    # ========================================================

    $PrivilegeChange = $null


    if ($ManipulatorPID) {

        $PrivilegeChange =
            $Security4703 |
            Where-Object {

                $_.ProcessId -eq
                    $ManipulatorPID -and

                $_.Time -ge
                    $Child.Time.AddSeconds(-120) -and

                $_.Time -le
                    $Child.Time.AddSeconds(5)
            } |
            Where-Object {

                $_.EnabledPrivileges -match
                    'SeDebugPrivilege|SeAssignPrimaryTokenPrivilege|SeImpersonatePrivilege|SeIncreaseQuotaPrivilege'
            } |
            Sort-Object Time -Descending |
            Select-Object -First 1
    }


    # ========================================================
    # 9. Confidence
    # ========================================================

    $Score = 50

    $Reasons = @(
        'Sysmon shows SYSTEM child created from non-service process context'
    )


    if (
        $Relationship -eq
        'Direct Parent-Child Token Manipulation'
    ) {

        $Score += 30

        $Reasons +=
            'Direct parent is regular-user process and accessed SYSTEM token donor before creating child'
    }


    if (
        $Relationship -eq
        'Token Donor Reported As Child Parent'
    ) {

        $Score += 30

        $Reasons +=
            'Non-service manipulator accessed SYSTEM process that is reported as privileged child parent'
    }


    if (
        $Create4688 -and
        $Create4688.TargetSid -eq
            'S-1-5-18'
    ) {

        $Score += 10

        $Reasons +=
            'Security 4688 confirms target identity is SYSTEM'
    }


    if (
        $Create4688 -and
        $Create4688.CreatorSid -notin @(
            'S-1-5-18',
            'S-1-5-19',
            'S-1-5-20'
        )
    ) {

        $Score += 5

        $Reasons +=
            'Security 4688 initiating identity is non-service account'
    }


    if ($PrivilegeChange) {

        $Score += 10

        $Reasons +=
            'Manipulator enabled token-related privilege'
    }


    if ($Score -gt 100) {
        $Score = 100
    }


    if ($Score -lt $MinimumConfidence) {
        continue
    }


    # ========================================================
    # 10. Output
    # ========================================================

    $Results += [PSCustomObject]@{

        Time =
            $Child.Time

        ConfidenceScore =
            $Score

        Relationship =
            $Relationship


        ManipulatorPID =
            $ManipulatorPID

        ManipulatorImage =
            $ManipulatorImage

        ManipulatorUser =
            $ManipulatorUser

        ManipulatorCommandLine =
            $ManipulatorCommandLine

        ManipulatorProcessGuid =
            $ManipulatorGuid


        TokenSourcePID =
            $TokenSourcePID

        TokenSourceImage =
            $TokenSourceImage

        TokenSourceUser =
            $TokenSourceUser

        TokenSourceProcessGuid =
            $TokenSourceGuid

        GrantedAccess =
            $GrantedAccess


        NewProcessPID =
            $Child.ProcessId

        NewProcessGuid =
            $Child.ProcessGuid

        NewProcessImage =
            $Child.Image

        NewProcessCommandLine =
            $Child.CommandLine

        NewProcessUser =
            $Child.User

        NewProcessIntegrity =
            $Child.IntegrityLevel


        ReportedParentPID =
            $Child.ParentProcessId

        ReportedParentImage =
            $Child.ParentImage

        ReportedParentUser =
            $Child.ParentUser

        ReportedParentGuid =
            $Child.ParentProcessGuid


        AccessTime =
            $AccessTime


        Security4688CreatorPID =
            if ($Create4688) {
                $Create4688.CreatorPid
            }
            else {
                $null
            }

        Security4688CreatorUser =
            if ($Create4688) {
                $Create4688.CreatorUser
            }
            else {
                $null
            }

        Security4688TargetUser =
            if ($Create4688) {
                $Create4688.TargetUser
            }
            else {
                $null
            }


        EnabledPrivileges =
            if ($PrivilegeChange) {
                $PrivilegeChange.EnabledPrivileges
            }
            else {
                $null
            }


        DetectionReasons =
            ($Reasons -join '; ')
    }
}

# ============================================================
# Display Results
# ============================================================

Write-Host
Write-Host "[x] Detection complete." -ForegroundColor Green
Write-Host "[x] Matching events: $($Results.Count)" -ForegroundColor Green
Write-Host

if ($Results)
    {
        $Results | Sort-Object ConfidenceScore, Time -Descending | Out-GridView
        $Results | Sort-Object ConfidenceScore, Time -Descending | where ConfidenceScore -ge 50| select Time, ConfidenceScore, ManipulatorUser, NewProcessUser, ManipulatorImage, NewProcessImage, TokenSourceImage, ReportedParentImage, ManipulatorCommandLine, NewProcessCommandLine, ReportedParentPID, ManipulatorPID, NewProcessPID, NewProcessIntegrity, DetectionReasons | Format-List
    }
else
    {
        "[!] No correlation results found."
    }