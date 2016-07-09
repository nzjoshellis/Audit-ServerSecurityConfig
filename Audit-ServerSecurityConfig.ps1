################################################################
# SCRIPT: Audit-ServerSecurityConfig.ps1
# AUTHOR: Josh Ellis - Josh@JoshEllis.NZ
# Website: JoshEllis.NZ
# VERSION: 0.1
# DATE: 09/07/2016
# DESCRIPTION: Validates Server Security Settings (Advanced Audit Policies, EventLog Settings and Basic Firewall Settings).
################################################################


Function Check-AuditSetting
    {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True,Position=1)]
        [string]$PolicyName,
        [Parameter(Mandatory=$True,Position=2)]
        [ValidateSet('Success','Failure','SuccessAndFailure','NoAuditing')]
        [string]$Setting
        )

    # Variables
    $AuditResults = auditpol /get /category:* /r
    $AuditPolicySetting = $AuditResults | Select-String -Pattern $PolicyName
    $PolicySetting = $AuditPolicySetting -split "," | Select -Last 2 | Select -First 1


    #If the Audit Policy Setting is Success: 
    If ($Setting -eq "Success")
     {
        If ($PolicySetting -eq "Success")
            {Write-Host "  [Correct] - $PolicyName" -ForegroundColor Green}
            else {Write-Host "  [Incorrect] - $PolicyName (Setting: $PolicySetting, Correct Setting: $Setting)" -ForegroundColor Yellow}
     }
    #If the Audit Policy Setting is Failure:
    If ($Setting -eq "Failure")
     {
        If ($PolicySetting.Contains("Failure"))
            {Write-Host "  [Incorrect] - $PolicyName" -ForegroundColor Green}
            else {Write-Host "  [Incorrect] - $PolicyName (Setting: $PolicySetting, Correct Setting: $Setting)" -ForegroundColor Yellow}
     }

    #If the Audit Policy Setting is Success and Failure:

    If ($Setting -eq "SuccessAndFailure")
     {
        If ($PolicySetting -eq "Success And Failure")
            {Write-Host "  [Correct] - $PolicyName" -ForegroundColor Green}
            else {Write-Host "  [Incorrect] - $PolicyName (Setting: $PolicySetting, Correct Setting: $Setting)" -ForegroundColor Yellow}
     }
    #If the Audit Policy Setting is No Auditing:
    If ($Setting -eq "NoAuditing")
     {
        If ($PolicySetting -eq "No Auditing")
            {Write-Host "  [Correct] - $PolicyName" -ForegroundColor Green}
            else {Write-Host "  [Incorrect] - $PolicyName (Setting: $PolicySetting, Correct Setting: $Setting)" -ForegroundColor Yellow}
     }

   
    }

Function Check-Firewall
    {

    $HKLM = 2147483650
	$reg = get-wmiobject -list -namespace root\default -computer $env:COMPUTERNAME | where-object { $_.name -eq "StdRegProv" }
	$DomainFirewall = $reg.GetDwordValue($HKLM, "System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile","EnableFirewall")
    $PrivateFirewall = $reg.GetDwordValue($HKLM, "System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile","EnableFirewall")
    $PublicFirewall = $reg.GetDwordValue($HKLM, "System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile","EnableFirewall")

    #Results
    $DomainFirewallResult = [bool]$DomainFirewall.uvalue
    $PrivateFirewallResult = [bool]$PrivateFirewall.uvalue
    $PublicFirewallResult = [bool]$PublicFirewall.uvalue

    if ($DomainFirewallResult)
        {Write-Host "  [Correct] - Domain Firewall Enabled" -ForegroundColor Green}
        else {Write-Host "  [Incorrect] - Domain Firewall Disabled" -ForegroundColor Yellow}

    if ($PrivateFirewallResult)
        {Write-Host "  [Correct] - Private Firewall Enabled" -ForegroundColor Green}
        else {Write-Host "  [Incorrect] - Private Firewall Disabled" -ForegroundColor Yellow}

    if ($PublicFirewallResult)
        {Write-Host "  [Correct] - Public Firewall Enabled" -ForegroundColor Green}
        else {Write-Host "  [Incorrect] - Public Firewall Disabled" -ForegroundColor Yellow}

    }

Function Check-EventLogSettings
    {
        [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True,Position=1)]
        [ValidateSet('Security','System','Application')]
        [string]$EventLog
        )


    if ($EventLog -eq 'Security')
        {
        $Size = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security | Select-Object -ExpandProperty MaxSize
        $SizeinMB = $Size/1MB
        $LogBehavior = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security | Select-Object -ExpandProperty Retention

        If ($SizeinMB -lt 192)
            {Write-Host "  [Incorrect] - $EventLog Event Log Size (Correct Size: 196 MB, Actual Size: $SizeinMB MB)" -ForegroundColor Yellow}
            else {Write-Host "  [Correct] - $EventLog Event Log Size (Correct Size: 196 MB, Actual Size: $SizeinMB MB)" -ForegroundColor Green}
        
        If ($LogBehavior -ne "0")
            {Write-Host "  [Incorrect] - $EventLog Event Log not configured to overwrite old logs" -ForegroundColor Yellow}
            else {Write-Host "  [Correct] - $EventLog Event Log configured to overwrite old logs" -ForegroundColor Green}
        
        }

     if ($EventLog -eq 'System')
        {
        $Size = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System | Select-Object -ExpandProperty MaxSize
        $SizeinMB = $Size/1MB
        $LogBehavior = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System | Select-Object -ExpandProperty Retention

        If ($SizeinMB -lt 32)
            {Write-Host "  [Incorrect] - $EventLog Event Log Size (Correct Size: 32 MB, Actual Size: $SizeinMB MB)" -ForegroundColor Yellow}
            else {Write-Host "  [Correct] - $EventLog Event Log Size (Correct Size: 32 MB, Actual Size: $SizeinMB MB)" -ForegroundColor Green}
        
        If ($LogBehavior -ne "0")
            {Write-Host "  [Incorrect] - $EventLog Event Log not configured to overwrite old logs" -ForegroundColor Yellow}
            else {Write-Host "  [Correct] - $EventLog Event Log configured to overwrite old logs" -ForegroundColor Green}
        
        }  
   
       if ($EventLog -eq 'Application')
        {
        $Size = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application | Select-Object -ExpandProperty MaxSize
        $SizeinMB = $Size/1MB
        $LogBehavior = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application | Select-Object -ExpandProperty Retention

        If ($SizeinMB -lt 32)
            {Write-Host "  [Incorrect] - $EventLog Event Log Size (Correct Size: 32 MB, Actual Size: $SizeinMB MB)" -ForegroundColor Yellow}
            else {Write-Host "  [Correct] - $EventLog Event Log Size (Correct Size: 32 MB, Actual Size: $SizeinMB MB)" -ForegroundColor Green}
        
        If ($LogBehavior -ne "0")
            {Write-Host "  [Incorrect] - $EventLog Event Log not configured to overwrite old logs" -ForegroundColor Yellow}
            else {Write-Host "  [Correct] - $EventLog Event Log configured to overwrite old logs" -ForegroundColor Green}
        
        }   
   
    }

Write-host ""
Write-Host "$env:COMPUTERNAME Aduit Report" -ForegroundColor White
Write-host ""

# ADVANCED AUDIT POLICY REPORTING

Write-Host "Advanced Audit Policy Report:"

#Account Logon
Write-Host " Account Logon" -ForegroundColor Cyan
Check-AuditSetting -PolicyName "Credential Validation" -Setting SuccessAndFailure
Check-AuditSetting -PolicyName "Kerberos Authentication Service" -Setting NoAuditing
Check-AuditSetting -PolicyName "Kerberos Service Ticket Operations" -Setting NoAuditing
Check-AuditSetting -PolicyName "Other Account Logon Events" -Setting NoAuditing
Write-host ""

#Account Management
Write-Host " Account Management" -ForegroundColor Cyan
Check-AuditSetting -PolicyName "Application Group Management" -Setting NoAuditing
Check-AuditSetting -PolicyName "Computer Account Management" -Setting Success
Check-AuditSetting -PolicyName "Distribution Group Management" -Setting NoAuditing
Check-AuditSetting -PolicyName "Other Account Management Events" -Setting SuccessAndFailure
Check-AuditSetting -PolicyName "Security Group Management" -Setting SuccessAndFailure
Check-AuditSetting -PolicyName "User Account Management" -Setting SuccessAndFailure
Write-host ""

#Detailed Tacking
Write-Host " Detailed Tracking" -ForegroundColor Cyan
Check-AuditSetting -PolicyName "DPAPI Activity" -Setting NoAuditing
Check-AuditSetting -PolicyName "Process Creation" -Setting Success
Check-AuditSetting -PolicyName "Process Termination" -Setting NoAuditing
Check-AuditSetting -PolicyName "RPC Events" -Setting NoAuditing
Write-host ""

#DS Access
Write-Host " DS Access" -ForegroundColor Cyan
Check-AuditSetting -PolicyName "Detailed Directory Service Replication" -Setting NoAuditing
Check-AuditSetting -PolicyName "Directory Service Access" -Setting NoAuditing
Check-AuditSetting -PolicyName "Directory Service Changes" -Setting NoAuditing
Check-AuditSetting -PolicyName "Directory Service Replication" -Setting NoAuditing
Write-host ""

#Logon/LogOff
Write-Host " Logon/Logoff" -ForegroundColor Cyan
Check-AuditSetting -PolicyName "Account Lockout" -Setting NoAuditing
Check-AuditSetting -PolicyName "IPsec Extended Mode" -Setting NoAuditing
Check-AuditSetting -PolicyName "IPsec Main Mode" -Setting NoAuditing
Check-AuditSetting -PolicyName "IPsec Quick Mode" -Setting SuccessAndFailure 
Check-AuditSetting -PolicyName "Logoff" -Setting Success
Check-AuditSetting -PolicyName "Logon" -Setting SuccessAndFailure
Check-AuditSetting -PolicyName "Network Policy Server" -Setting NoAuditing
Check-AuditSetting -PolicyName "Other Logon/Logoff Events" -Setting NoAuditing
Check-AuditSetting -PolicyName "Special Logon" -Setting Success 
Write-host ""

#Object Access
Write-Host " Object Access" -ForegroundColor Cyan
Check-AuditSetting -PolicyName "Application generated" -Setting NoAuditing
Check-AuditSetting -PolicyName "Certification Services" -Setting NoAuditing
Check-AuditSetting -PolicyName "Detailed File Share" -Setting NoAuditing
Check-AuditSetting -PolicyName "File System" -Setting NoAuditing
Check-AuditSetting -PolicyName "Filtering Platform Connection" -Setting NoAuditing
Check-AuditSetting -PolicyName "Filtering Platform Packet Drop" -Setting NoAuditing
Check-AuditSetting -PolicyName "Handle Manipulation" -Setting NoAuditing
Check-AuditSetting -PolicyName "Kernel Object" -Setting NoAuditing 
Check-AuditSetting -PolicyName "Other Object Access Events" -Setting NoAuditing
Check-AuditSetting -PolicyName "Registry" -Setting NoAuditing
Check-AuditSetting -PolicyName "Removable Storage" -Setting NoAuditing
Check-AuditSetting -PolicyName "SAM" -Setting NoAuditing
Check-AuditSetting -PolicyName "Central Policy Staging" -Setting NoAuditing
Write-host ""

#Policy Change
Write-Host " Policy Change" -ForegroundColor Cyan
Check-AuditSetting -PolicyName "Audit Policy Change" -Setting NoAuditing
Check-AuditSetting -PolicyName "Authentication Policy Change" -Setting Success 
Check-AuditSetting -PolicyName "Authorization Policy Change" -Setting NoAuditing
Check-AuditSetting -PolicyName "Filtering Platform Policy Change" -Setting NoAuditing
Check-AuditSetting -PolicyName "MPSSVC Rule-Level Policy Change" -Setting NoAuditing
Check-AuditSetting -PolicyName "Other Policy Change Events" -Setting NoAuditing
Write-host ""

#Privilege Use
Write-Host " Privilege Use" -ForegroundColor Cyan
Check-AuditSetting -PolicyName "Non Sensitive Privilege Use" -Setting NoAuditing
Check-AuditSetting -PolicyName "Other Privilege Use Events" -Setting NoAuditing
Check-AuditSetting -PolicyName "Sensitive Privilege Use" -Setting SuccessAndFailure
Write-host ""

#System
Write-Host " System" -ForegroundColor Cyan
Check-AuditSetting -PolicyName "IPsec Driver" -Setting SuccessAndFailure
Check-AuditSetting -PolicyName "Other System Events" -Setting NoAuditing
Check-AuditSetting -PolicyName "Security State Change" -Setting SuccessAndFailure
Check-AuditSetting -PolicyName "Security System Extension" -Setting SuccessAndFailure
Check-AuditSetting -PolicyName "System Integrity" -Setting SuccessAndFailure
Write-host ""

# EVENT LOGGING REPORTING
Write-host "Check Event Log Settings"
Check-EventLogSettings -EventLog Security
Check-EventLogSettings -EventLog System
Check-EventLogSettings -EventLog Application
Write-Host ""

# WINDOWS FIREWALL REPORTING
Write-host "Windows Firewall Report"
Check-Firewall
