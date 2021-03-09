<#
"-------------------------------------------------------------------"
"             PowerShell Auditing Script  'aka Phase-1'             "
"-------------------------------------------------------------------"
 SYNOPSIS: this script will document your PC's current profile and take a few unproblematic steps to harden its configuration
 DESCRIPTION: the most successful enterprises maintain proper documentation of their systems/infastructure and is crucial in the event of an incident.
 Unfortunately, garnering this documentation has proven itself to be particularly time consuming and is prone to human error.
 This script intends to ease the burden of auditing through automation.

 **FIXME FIX OTHER DEPENDENCIES W/O ADDING BAD RULES (ie SQl SRV)
 **TODO LIST POTENTIAL BEACONS
 **FIXME THIS DOESNT WORK ON ALL VERSIONS OF WINDOWS

 CONTACT: please refer any questions or comments regarding this script to @kogatana-x

#>
<#--------------------------------
  Addressing Script Prerequisites:
---------------------------------#>
#Elevates permissions in new window, if needed
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
  Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit
}

#Dump output to file
$dir = $PSScriptRoot
$SN = $env:computername
$FP= "$dir\"+$SN+"-Phase-1 Audit Transcript_$(get-date -Format yyyy-mm-dd_hhmmtt).txt"

$ExecutionPolicy = Get-ExecutionPolicy
Set-ExecutionPolicy Unrestricted -force

#THINGS THAT ARE UNLIKELY TO BE USEFUL IN PRODUCTION>>
##Ensuring regular password changes, without password reusage is key to preventing sustained unwanted access to accounts
 ## net user Administrator 'tmp-123!A@3de/FFd7g_'
##Adding backup administrative accounts are crucial in the event of a breach, and the malicious agent revokes your usual access --
## It would be best to change `backup` to whatever your username is 
  net user backup SecPass123@ /add
  net localgroup Administrators backup /add
  net group Administrators backup /add
  
##Using a Least-privilege access model, disabling the guest account is a good way to restrict unattributed and unauthorized access into the system
  net user Guest /active:no

<#---------------------
  Function Definitions:
----------------------#>
 #Does the spacing math for the headers

 #Deals with the space math for the header function
 function space{
   Param([int]$len,[String]$str)
   for($i=1;$i -le $len/2; $i++){
     $str+=" "
   }
   return $str
 }
 #Displays a header
 function header{
   #.EXAMPLE Write-Host (header "TEST")
   Param([String]$wrd)
   $len= 64 - $wrd.Length
   $str=""
   $xdash="----------------------------------------------------------------"

   $str=space $len $str
   $str+=$wrd
   Write-Host $xdash
   Write-Host $str
   Write-Host $xdash
 }
# Set Standard/Static Firewall Rules
 $network_addr = "172.20.240.0/22,127.0.0.1/8" #CHANGEME
 function fwset-standard{
   #Allow all connections from within your network, and allow loopback traffic
    netsh advfirewall firewall add rule name="LB" action=allow remoteip=127.0.0.1/8 dir=in
    netsh advfirewall firewall add rule name="LB" action=allow remoteip=127.0.0.1/8 dir=in

   #Allow internet (through firefox) out
    netsh advfirewall firewall add rule name="FOX_OUT_TCP" dir=out action=allow protocol=tcp remoteport=80,443 program=%ProgramFiles%\Mozilla*\firefox.exe
    netsh advfirewall firewall add rule name="FOX_OUT_UDP" dir=out action=allow protocol=udp remoteport=53 program=%ProgramFiles%\Mozilla*\firefox.exe

    #Block commonly exploited ports that are rarely used in a `small` commerical setting
     #  RPC,SSH (for Windows),SMB, etc
     netsh advfirewall firewall add rule name="BAD-PORTS" action=deny dir=in localport=135,5985,445,20,21,22
     netsh advfirewall firewall add rule name="BAD-PORTS" action=deny dir=out remoteport=135,5985,445,20,21,22

    #Turn on the firewall and block all connections by default
    netsh advfirewall set allprofiles state on
    netsh advfirewall set allprofiles firewallpolicy blockinbound, blockoutbound
  }
 #Set System Dependent/Dynamic Firewall Rules
 function fwset{
   #Sets Listening Email Service Firewall Rules
   $processes = (Get-NetTCPConnection | ? {($_.State -eq "Listen") -and ($_.RemoteAddress -eq "0.0.0.0") -and ($_.Port -in 25,110,143,465,587,993,995)} | Select OwningProcess,LocalPort)
   foreach ($process in $processes){netsh advfirewall firewall add rule name=$_.LocalPort dir=in action=allow protocol=tcp remoteport=$_.LocalPort program=(wmic process where processid=$_.OwningProcess get executablepath)}

   #Sets Listening WebApp Service Firewall Rules
   $processes = (Get-NetTCPConnection | ? {($_.State -eq "Listen") -and ($_.RemoteAddress -eq "0.0.0.0") -and ($_.Port -in 80,443)} | Select LocalPort)
   foreach ($process in $processes){netsh advfirewall firewall add rule name=$_.LocalPort dir=in action=allow protocol=tcp remoteport=$_.LocalPort}

   #Sets AD/DNS Rules - UDP
   $processes = (Get-NetUDPEndpoint | ? {($_.LocalAddress -eq "0.0.0.0") -and ($_.Port -in 53,88,389)} | Select LocalPort,OwningProcess)
   foreach ($process in $processes){netsh advfirewall firewall add rule name=$_.LocalPort dir=in action=allow protocol=udp remoteport=$_.LocalPort remoteip=network_addr program=(wmic proceess where processid=$_.OwningProcess get executablepath)}
   foreach ($process in $processes){netsh advfirewall firewall add rule name=$_.LocalPort dir=out action=allow protocol=udp remoteport=$_.LocalPort remoteip=network_addrprogram=(wmic proceess where processid=$_.OwningProcess get executablepath)}

   #Sets AD/DNS Rules - TCP
   $processes = (Get-NetTCPConnection | ? {($_.State -eq "Listen") -and ($_.RemoteAddress -eq "0.0.0.0") -and ($_.Port -in 53,88,389)} | Select LocalPort)
   foreach ($process in $processes){netsh advfirewall firewall add rule name=$_.LocalPort dir=in action=allow protocol=tcp remoteport=$_.LocalPort remoteip=$network_addr program=(wmic proceess where processid=$_.OwningProcess get executablepath)}
   foreach ($process in $processes){netsh advfirewall firewall add rule name=$_.LocalPort dir=out action=allow protocol=tcp remoteport=$_.LocalPort remoteip=$network_addr program=(wmic proceess where processid=$_.OwningProcess get executablepath)}

   fwset-standard #call static rules defined above
 }

<#---------------------
      Start Script:
 ----------------------#>
 Start-Transcript -Path $FP -NoClobber

  #GATHER OS SERVER INFO >>
  Write-Host (header "OS/Server Information")
  $OS =Get-WmiObject -class Win32_OperatingSystem -computername "."
  Get-WmiObject Win32_OperatingSystem | FL PSComputerName,Organization,Name,Version,ServicePackMajorVersion,OSArchitecture,WindowsDirectory | Out-Host

  #------------------------------------------------------------------
  #GATHER GROUP INFO (DC & non-DC)>>
  Write-Host (header "Members by Group")
  $server = "$env:COMPUTERNAME"
  $computer = [ADSI]"WinNT://$server,computer"
  $computer.psbase.children | where { $_.psbase.schemaClassName -eq 'group' } | foreach { #psbase fixes XML parsing garbage errors
    write-host $_.name
    write-host "------"
    $group =[ADSI]$_.psbase.Path
    $group.psbase.Invoke("Members") | foreach {$_."GetType".Invoke().InvokeMember("Name", 'GetProperty', $null, $_, $null) | Format-list}
    write-host
  }
  #GATHER USERS & INFO >>
  Write-Host (header "Non-Disabled Local Users")
  Get-WmiObject -Class Win32_UserAccount -Filter {LocalAccount='True' and Disabled='False'} | Select-Object Caption, AccountType, Domain, PasswordRequired, SID, SIDType | Out-Host

  Write-Host (header "Domain Users")
  Get-WmiObject -Class Win32_UserAccount -Filter {LocalAccount='False' and Disabled='False'} | Select-Object Caption, AccountType, Domain, PasswordRequired, SID, SIDType | Out-Host

  #QUERY SESSIONS >>
  Write-Host (header "Users Logged In")
  $SN = $env:computername
  Get-WmiObject Win32_LoggedOnUser -ComputerName $SN | Select Antecedent,PSComputerName -Unique | Format-List | Out-Host

  #------------------------------------------------------------------

  <#LIST CURRENT PWD POLICIES >>
  Write-Host (header "Current Password Policies")
    Write Host " Local Policy"
    Write-Host "_______________________"
    net accounts | Out-Host

    Write Host " Domain Policy"
    Write-Host "_______________________"
    Write-Host
    net accounts /domain | Out-Host
  #>

  #------------------------------------------------------------------

  #LIST RUNNING SERIVCES >> #FIXME for some reason this works as a standalone, but will not appear in the transcript? (too big??)
  Write-Host (header "Running Services")
  Get-Service | where status -eq 'running' | select servicename, starttype, servicetype

  #LIST ALL SERVICES RUNNING UNDER A NON-NT AUTH ACCT
  Write-host (header "Non-Standard Account Services Running")
  Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\* | Where-Object {($_.ObjectName -notlike 'NT Authority\*') -and ($_.ObjectName -ne $null) -and ($_.ObjectName -ne "LocalSystem")}


  #------------------------------------------------------------------

  #LIST RUNNING PROCESSES >>
  Write-Host (header "Running Proccesses")
  Get-Process | Select StartTime,ID,Path | Format-Table

  #LIST INSTALLED PROGRAMS >>
  Write-Host (header "Installed Programs")
  Get-ItemProperty 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | Select InstallDate,Publisher,DisplayName

  #------------------------------------------------------------------
  #AUDIT NETWORK CONNECTIONS >>
  write-host (header "Listening Network Connections")
  netstat -abno
  #TODO FIND THE POTENTIAL BADDIES

  #AUDIT FW RULES >>
  netsh advfirewall firewall delete rule name=all
  netsh firewall set logging C:\Apps\app_log.txt 32767 ENABLE ENABLE
  fwset

  write-host (header "Firewall Rules Set")
  write-host "The Following Rules have been created:"
  write-host "______________________________________"
  $f=New-object -comObject HNetCfg.FwPolicy2;$f.rules | where {$_.action -eq "1"} | select servicename,applicationname,localports,remoteports,remoteaddresses | format-table
  $f=New-object -comObject HNetCfg.FwPolicy2;$f.rules | where {$_.action -eq "0"} | select servicename,applicationname,localports,remoteports,remoteaddresses | format-table


  #------------------------------------------------------------------


  #PERSISTANT SCH TASKS >>
  Write-Host (header "Persistant Scheduled Tasks")
  Get-ScheduledTask | Where Triggers -like "MSFT_TaskRegistrationTrigger"

  #AUDIT PATH VARIABLE >>
  write-host (header "Please Inspect the Path Variable:")
  echo $env:Path.split(';')

  #AUDIT HOST FILE >>
  Write-Host (Header "Host File: Ensure there are no contents")
  type C:\Windows\system32\drivers\etc\hosts

  #AUDIT RUN KEYS >> FIXME This doesnt actually list the contents of the registry booooo for some machines which is weird af
  write-host (header "Please Inspect the Following Values")
  Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
  Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue
  Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" -ErrorAction SilentlyContinue
  Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices" -ErrorAction SilentlyContinue
  Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
  Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue
  Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" -ErrorAction SilentlyContinue
  Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices" -ErrorAction SilentlyContinue

  #AUDIT DNS CACHE >>
  Write-Host (header "Please Inspect the DNS Cache:")
  ipconfig /displaydns

  #------------------------------------------------------------------

  <#---------------------
      Begin Hardening:
   ----------------------#>

  #DISABLE UNNECCESSARY SMB & RDP CONNECTIONS TO PREVENT PIVOTING >>
  reg add HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters /v SMB1 /t REG_DWORD /d 0 /f
  reg add “hklm\system\currentcontrolset\control\Terminal Server” /v fDenyTSConnections /t REG_DWORD /d 1 /f
  reg add hklm\system\currentcontrolset\control /v DisableRemoteScmEndpoints /t REG_DWORD /d 1 /f
  reg add hklm\system\currentcontrolset\control\lsa /v RestrictAnonymous /t REG_DWORD /d 1 /f

  #DELETE UNNECCESSARY SCHEDULED TASKS >>
  schtasks /delete /TN * /F

  #REMOVE ACCESSIBILITY FEATURES
    #NOTE: This is not advisable in general, but is particularly useful in competitive cyber security enviornments
  $pathlist= "C:\Windows\System32\osk.exe", "C:\Windows\System32\Magnify.exe", "C:\Windows\System32\Narrator.exe", "C:\Windows\System32\DisplaySwitch.exe", "C:\Windows\System32\AtBroker.exe", "C:\windows\system32\sethc.exe"
  foreach ($path in $pathlist){
    takeown /F $path /A
    icacls $path /grant Administrators:F
    Remove-item $pathlist
  }

  #PREFETCH >>
  reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 3 /f
  reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Prefetcher" /v MaxPrefetchFiles /t REG_DWORD /d 8192 /f
  Enable-MMAgent -OperationAPI #if it doesn’t work try Enable-MMAgent -ApplicationLaunchPrefetching
  net start sysmain

  #MISC HARDENING >>
  reg add "HKLM\Software\Microsoft\Windows Script Host\Settings" /v "Enabled" /t REG_DWORD /d "0" /f  #disable Windows Script Host (.vbs **)
  reg add HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /v "AutoShareWks" /t REG_DWORD /d "0" /f #disable admin shares
  reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" /v "AutoAdminLogon" /t REG_DWORD /d "0" /f #disable auto login for administrators
  Disable-WindowsOptionalFeature -online -FeatureName internet-explorer-optional-amd64 #disable IE
  wevtutil.exe sI Microsoft-Windows-WMI-Activity/Trace /e:true #enable WMI event tracing

#------------------------------------------------------------------

  Write-Host (header "Summary of Actions Taken")
  Write-Host "1.) Active user's password has been changed"
  Write-Host "2.) Temporary backdoor, backup, successfully created"
  Write-Host "3.) Guest Account has been sucessfully disabled"
  Write-Host "4.) SMB & RDP have been successfully hardened"
  Write-Host "5.) Firewall has been properly configured; logs are located in: C:\Apps\app_log.txt"
  Write-Host "6.) Scheduled Tasks have been successfully removed; however, please review the list of potentially persistant tasks that may remain or left backdoors"
  Write-Host "7.) Prefetch has been successfully enabled. (Prefetch is quite useful in memory forensics in the even of an incident, but requires an external tool to take advantage of the prefetch files)"
  Write-Host "#.) Other odds and ends have been additionally hardened (e.g. remediating potential backdoored services, disabling anon & auto login, etc.)"
  Write-Host "_"
  Write-Host "Audit Complete >> REMEMBER TO CHANGE YOUR PASSWORD!"
  Write-Host
  Write-Host "**DISCLAIMER: this is not comprehensive and you will have to secure your individual services, this is only a general system audit**"


  Set-ExecutionPolicy $ExecutionPolicy -force
  Stop-Transcript

  pause
