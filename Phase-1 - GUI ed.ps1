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
 **TODO summary list needs to go in a scrollable textbox on Panel2
 **FIXME admin rights dont work with this gui apparently
 ~~FIXME audit output can honestly just go and writhe in shrewd darkness over in the transcript file~~

 CONTACT: please refer any questions or comments regarding this script to <AA>

#>

<#--------------------------------
  Addressing Script Prerequisites:
---------------------------------#>
#Elevates permissions in new window, if needed
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
  Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit
}

function p1GUI {
  <#---------------------
    Main Script Function Definitions:
  ----------------------#>
   $summaryStr=""
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

  #ACTION------------------------------------------------------------------
   #Set System Firewall Rules
   function fwset{
      $network_addr = "172.20.240.0/22,127.0.0.1/8" #CHANGEME
      netsh advfirewall firewall delete rule name=all

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

      #Allow all connections from within your network, and allow loopback traffic
      netsh advfirewall firewall add rule name="LB" action=allow remoteip=127.0.0.1/8 dir=in
      netsh advfirewall firewall add rule name="LB" action=allow remoteip=127.0.0.1/8 dir=in

      #Allow internet (through firefox) out
      netsh advfirewall firewall add rule name="FOX_OUT_TCP" dir=out action=allow protocol=tcp remoteport=80,443 program=%ProgramFiles%\Mozilla*\firefox.exe
      netsh advfirewall firewall add rule name="FOX_OUT_UDP" dir=out action=allow protocol=udp remoteport=53 program=%ProgramFiles%\Mozilla*\firefox.exe

      #Block commonly exploited ports that are rarely used in a small commerical setting
      #  RPC,SSH (for Windows),SMB, etc
      netsh advfirewall firewall add rule name="BAD-PORTS" action=deny dir=in localport=135,5985,445,20,21,22
      netsh advfirewall firewall add rule name="BAD-PORTS" action=deny dir=out remoteport=135,5985,445,20,21,22

      #Turn on the firewall and block all connections by default
      netsh advfirewall set allprofiles state on
      netsh advfirewall set allprofiles firewallpolicy blockinbound, blockoutbound

      #log
      netsh firewall set logging C:\Apps\app_log.txt 32767 ENABLE ENABLE

      write-host (header "Firewall Rules Set")
      write-host "The Following Rules Have Been Created:"
      write-host "______________________________________"
      $f=New-object -comObject HNetCfg.FwPolicy2;$f.rules | where {$_.action -eq "1"} | select servicename,applicationname,localports,remoteports,remoteaddresses | format-table
      $f=New-object -comObject HNetCfg.FwPolicy2;$f.rules | where {$_.action -eq "0"} | select servicename,applicationname,localports,remoteports,remoteaddresses | format-table

      $summaryStr+= "Firewall has been properly configured; `r`n       >>>logs are located in: C:\Apps\app_log.txt`r`n"
   }
   #Adds a Backdoor, changes password
   function useradd{
    net user Administrator 'tmp-123!A@3de/FFd7g_'
    net user poop SecPass123@ /add
    net user p00p SecPass123@ /add /domain
    net localgroup Administrators poop /add
    net group Administrators p00p /add
    net group Administrators poop /add
    net user Guest /active:no
    $summaryStr+= "Active user's password has been changed`r`n"
    $summaryStr+= "Temporary backdoor, poop, successfully created`r`n"
    $summaryStr+= "Guest Account has been sucessfully disabled`r`n"
   }
   #SMB & RDP
   function smb_rdp{
     #DISABLE UNNECCESSARY SMB & RDP CONNECTIONS TO PREVENT PIVOTING >>
     reg add HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters /v SMB1 /t REG_DWORD /d 0 /f
     reg add “hklm\system\currentcontrolset\control\Terminal Server” /v fDenyTSConnections /t REG_DWORD /d 1 /f
     reg add hklm\system\currentcontrolset\control /v DisableRemoteScmEndpoints /t REG_DWORD /d 1 /f
     reg add hklm\system\currentcontrolset\control\lsa /v RestrictAnonymous /t REG_DWORD /d 1 /f

     $summaryStr+= "SMB & RDP have been successfully hardened`r`n"
   }
   #MISC REG EDITS
   function miscedit{
     reg add "HKLM\Software\Microsoft\Windows Script Host\Settings" /v "Enabled" /t REG_DWORD /d "0" /f  #disable Windows Script Host (.vbs **)
     reg add HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /v "AutoShareWks" /t REG_DWORD /d "0" /f #disable admin shares
     reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" /v "AutoAdminLogon" /t REG_DWORD /d "0" /f #disable auto login for administrators
     Disable-WindowsOptionalFeature -online -FeatureName internet-explorer-optional-amd64 #disable IE
     wevtutil.exe sI Microsoft-Windows-WMI-Activity/Trace /e:true #enable WMI event tracing
     $summaryStr+="Windows Script Host has been disabled`r`n"
     $summaryStr+="Network Shares have been disabled`r`n"
     $summaryStr+="Automatic Login has been disabled`r`n"
     $summaryStr+="Optional Feature Internet Explorer has been removed`r`n"
   }
   #SCH TASK DELETE
   function schtasks{
     #DELETE UNNECCESSARY SCHEDULED TASKS >>
     schtasks /delete /TN * /F
     $summaryStr+= "Scheduled Tasks have been successfully removed;`r`n however, please review the list of potentially persistant tasks that may remain or left backdoors`r`n"
   }
   #RM ACCESSIBILITY FEATURES
   function accessibility{
     #RM ACCESSIBILITY FEATURES
       #NOTE: This is not advisable for enviornments that need to accomodate individuals with disibility
     $pathlist= "C:\Windows\System32\osk.exe", "C:\Windows\System32\Magnify.exe", "C:\Windows\System32\Narrator.exe", "C:\Windows\System32\DisplaySwitch.exe", "C:\Windows\System32\AtBroker.exe", "C:\windows\system32\sethc.exe"
     foreach ($path in $pathlist){
       takeown /F $path /A
       icacls $path /grant Administrators:F
       Remove-item $pathlist
     }
     $summaryStr+="Accessibility Features have been removed `r`n(Sticky Keys Backdoor Risk, Eliminated)`r`n"
    }
   #ENABLE PREFETCH >>
   function prefetch{
     #PREFETCH >>
     reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 3 /f
     reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Prefetcher" /v MaxPrefetchFiles /t REG_DWORD /d 8192 /f
     Enable-MMAgent -OperationAPI #if it doesn’t work try Enable-MMAgent -ApplicationLaunchPrefetching
     net start sysmain
     $summaryStr+= "Prefetch has been successfully enabled.`r`n (Note: Prefect still requires an external tool to take advantage of the prefetch files)`r`n"
    }

  #AUDIT-------------------------------------------------------------------
   #GATHER OS SERVER INFO >>
   function osinfo{
    Write-Host (header "OS/Server Information")
    $OS =Get-WmiObject -class Win32_OperatingSystem -computername "."
    Get-WmiObject Win32_OperatingSystem | FL PSComputerName,Organization,Name,Version,ServicePackMajorVersion,OSArchitecture,WindowsDirectory | Out-Host
   }
   #GATHER GROUP INFO >>
   function userinfo{
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
   }
   #LIST CURRENT PWD POLICIES >>
   function pwdpol{
      Write-Host (header "Current Password Policies")
      Write Host " Local Policy"
      Write-Host "_______________________"
      net accounts | Out-Host

      Write Host " Domain Policy"
      Write-Host "_______________________"
      Write-Host
      net accounts /domain | Out-Host
   }
   #SERVICE/PROC INFO >>
   function services{
    #LIST RUNNING SERIVCES >> #FIXME for some reason this works as a standalone, but will not appear in the transcript? (too big??)
    Write-Host (header "Running Services")
    Get-Service | where status -eq 'running' | select servicename, starttype, servicetype

    #LIST ALL SERVICES RUNNING UNDER A NON-NT AUTH ACCT
    Write-host (header "Non-Standard Account Services Running")
    Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\* | Where-Object {($_.ObjectName -notlike 'NT Authority\*') -and ($_.ObjectName -ne $null) -and ($_.ObjectName -ne "LocalSystem")}

    #LIST RUNNING PROCESSES >>
    Write-Host (header "Running Proccesses")
    Get-Process | Select StartTime,ID,Path | Format-Table

    #LIST INSTALLED PROGRAMS >>
    Write-Host (header "Installed Programs")
    Get-ItemProperty 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | Select InstallDate,Publisher,DisplayName

   }
   #AUDIT NETWORK CONNECTIONS >>
   function network{
    write-host (header "Listening Network Connections")
    netstat -abno
    #TODO FIND THE POTENTIAL BADDIES
   }
   #AUDIT MISC >>
   function misc{
    #PERSISTANT SCH TASKS >>
    Write-Host (header "Persistant Scheduled Tasks")
    Get-ScheduledTask | Where Triggers -like "MSFT_TaskRegistrationTrigger"

    #AUDIT PATH VARIABLE >>
    write-host (header "Please Inspect the Path Variable:")
    echo $env:Path.split(';')

    #AUDIT HOST FILE >>
    Write-Host (Header "Host File: Ensure there are no contents")
    type C:\Windows\system32\drivers\etc\hosts

    #AUDIT DNS CACHE >>
    Write-Host (header "Please Inspect the DNS Cache:")
    ipconfig /displaydns
   }
   #AUDIT REGISTRY >>
   function reg{
    #AUDIT RUN KEYS >> FIXME This doesnt actually list the contents of the registry booooo for some machines which is weird af
    write-host (header "Please Inspect the Following Values")
    Get-ChildItem "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
    Get-ChildItem "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Userinit" -ErrorAction SilentlyContinue
    Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
    Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue
    Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" -ErrorAction SilentlyContinue
    Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices" -ErrorAction SilentlyContinue
    Get-ChildItem "HKLM:\System\CurrentControlSet\Control\Session Manager\subsystems" -ErrorAction SilentlyContinue
    Get-ChildItem "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -ErrorAction SilentlyContinue
    Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
    Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue
    Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" -ErrorAction SilentlyContinue
    Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices" -ErrorAction SilentlyContinue
   }

  #SUMMARY------------------------------------------------------------------
  function summary{ #FIXME
    Write-Host (header "Summary of Actions Taken")
    Write-Host $summaryStr
    Write-Host "Audit Complete >> REMEMBER TO CHANGE YOUR PASSWORD!"
    Write-Host
    Write-Host "**DISCLAIMER: this is not comprehensive, so you will have to secure your individual services, this is only a general system audit**"
  }


  <#---------------------
        START GUI:
  ----------------------#>

  #IMPORT MOD >>
	[void][reflection.assembly]::Load('System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
	[void][reflection.assembly]::Load('System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
	[System.Windows.Forms.Application]::EnableVisualStyles()

	#OBJ INIT>>
	$formPhase1WindowsAudit = New-Object 'System.Windows.Forms.Form'
	$Harden = New-Object 'System.Windows.Forms.Label'
	$labelAudit = New-Object 'System.Windows.Forms.Label'
	$checkedlistbox2 = New-Object 'System.Windows.Forms.CheckedListBox'
	$checkedlistbox1 = New-Object 'System.Windows.Forms.CheckedListBox'
	$splitcontainer1 = New-Object 'System.Windows.Forms.SplitContainer'
	$buttonSubmit = New-Object 'System.Windows.Forms.Button'
	$labelConfigureOutput = New-Object 'System.Windows.Forms.Label'
	$InitialFormWindowState = New-Object 'System.Windows.Forms.FormWindowState'
	$outputStr = "Phase-1 Windows Audit Script >>`r`n"

  function Update-ListBox {
		  param(
			[Parameter(Mandatory = $true)]
			[ValidateNotNull()]
			[System.Windows.Forms.ListBox]
			$ListBox,
			[Parameter(Mandatory = $true)]
			[ValidateNotNull()]
			$Items,
			[Parameter(Mandatory = $false)]
			[string]
			$DisplayMember,
			[switch]
			$Append
		)
		  if (-not $Append){$listBox.Items.Clear()}
		  if ($Items -is [System.Windows.Forms.ListBox+ObjectCollection]){
			$listBox.Items.AddRange($Items)
		}
		  elseif ($Items -is [Array]){
			$listBox.BeginUpdate()
			foreach ($obj in $Items){
				$listBox.Items.Add($obj)
			}
			$listBox.EndUpdate()
		}
		  else{$listBox.Items.Add($Items)}
		  $listBox.DisplayMember = $DisplayMember
	  }
	#Select All Functions >>
	$checkedlistbox2.Add_Click({
	    if ($This.SelectedItem -eq 'Select All') {
	      $checkedlistbox2.SetItemChecked(0,$True)
	        for ($i=1;$i -lt $checkedlistbox2.Items.count;$i++) {
	            $checkedlistbox2.SetItemchecked($i,$True)
	        }
	    }
	  })
  $checkedlistbox1.Add_Click({
    if ($This.SelectedItem -eq 'Select All') {
      $checkedlistbox1.SetItemChecked(0,$True)
        for ($i=1;$i -lt $checkedlistbox1.Items.count;$i++) {
            $checkedlistbox1.SetItemchecked($i,$True)
        }
    }
  })
	$buttonSubmit_Click={
    #Dump output to file
    $dir = $PSScriptRoot
    $SN = $env:computername
    $FP= "$dir\"+$SN+"-Phase-1 Audit Transcript_$(get-date -Format yyyy-mm-dd_hhmmtt).txt"

    $ExecutionPolicy = Get-ExecutionPolicy
    Set-ExecutionPolicy Unrestricted -force
    Start-Transcript -Path $FP -NoClobber

    if($checkedlistbox1.GetItemCheckState(1) -eq 'Checked'){osinfo}
    if($checkedlistbox1.GetItemCheckState(2) -eq 'Checked'){userinfo}
    if($checkedlistbox1.GetItemCheckState(3) -eq 'Checked'){pwdpol}
    if($checkedlistbox1.GetItemCheckState(4) -eq 'Checked'){services}
    if($checkedlistbox1.GetItemCheckState(5) -eq 'Checked'){network}
    if($checkedlistbox1.GetItemCheckState(6) -eq 'Checked'){reg}
    if($checkedlistbox1.GetItemCheckState(7) -eq 'Checked'){misc}
    <#--------------------------------------------------------
    if($checkedlistbox2.GetItemCheckState(1) -eq 'Checked'){fwset}
    if($checkedlistbox2.GetItemCheckState(2) -eq 'Checked'){smb_rdp}
    if($checkedlistbox2.GetItemCheckState(3) -eq 'Checked'){useradd}
    if($checkedlistbox2.GetItemCheckState(4) -eq 'Checked'){schtasks}
    if($checkedlistbox2.GetItemCheckState(5) -eq 'Checked'){accessibility}
    if($checkedlistbox2.GetItemCheckState(6) -eq 'Checked'){prefetch}
    if($checkedlistbox2.GetItemCheckState(7) -eq 'Checked'){miscedit} #>
    summary
    Stop-Transcript
    $buttonSubmit.Visible=$False
  }
	$Panel2_Paint=[System.Windows.Forms.PaintEventHandler]{
	 #Event Argument: $_ = [System.Windows.Forms.PaintEventArgs]
		#TODO: IDK DO SOMETHING W OUTPUT MAYBE
	 }

  $Form_StateCorrection_Load={
		 #Correct the initial state of the form to prevent the .Net maximized form issue
		 $formPhase1WindowsAudit.WindowState = $InitialFormWindowState
	 }
	$Form_Cleanup_FormClosed={
		#Remove all event handlers from the controls
		try
		{
			$checkedlistbox2.remove_SelectedIndexChanged($checkedlistbox2_SelectedIndexChanged)
			$checkedlistbox1.remove_SelectedIndexChanged($checkedlistbox1_SelectedIndexChanged)
			$formPhase1WindowsAudit.remove_Load($formPhase1WindowsAudit_Load)
			$buttonSubmit.remove_Click($buttonSubmit_Click)
			$checkbox1.remove_CheckedChanged($checkbox1_CheckedChanged)
			$formPhase1WindowsAudit.remove_Load($Form_StateCorrection_Load)
			$formPhase1WindowsAudit.remove_FormClosed($Form_Cleanup_FormClosed)
		}
		catch { Out-Null <# Prevent PSScriptAnalyzer warning #> }
	}
	$formPhase1WindowsAudit.SuspendLayout()
	$splitcontainer1.BeginInit()
	$splitcontainer1.SuspendLayout()


	# OBJ formPhase1WindowsAudit >>
	$formPhase1WindowsAudit.Controls.Add($Harden)
	$formPhase1WindowsAudit.Controls.Add($labelAudit)
	$formPhase1WindowsAudit.Controls.Add($checkedlistbox2)
	$formPhase1WindowsAudit.Controls.Add($checkedlistbox1)
	$formPhase1WindowsAudit.Controls.Add($splitcontainer1)
	$formPhase1WindowsAudit.AutoScaleDimensions = New-Object System.Drawing.SizeF(6, 13)
	$formPhase1WindowsAudit.AutoScaleMode = 'Font'
	$formPhase1WindowsAudit.BackColor = [System.Drawing.SystemColors]::ActiveCaption
	$formPhase1WindowsAudit.ClientSize = New-Object System.Drawing.Size(420, 426)
	$formPhase1WindowsAudit.Name = 'formPhase1WindowsAudit'
	$formPhase1WindowsAudit.Text = 'Phase-1 Windows Audit'
	$formPhase1WindowsAudit.add_Load($formPhase1WindowsAudit_Load)

	#OBJ labelHarden >>
	$Harden.AutoSize = $True
	$Harden.BackColor = [System.Drawing.SystemColors]::ControlLightLight
	$Harden.Location = New-Object System.Drawing.Point(31, 205)
	$Harden.Name = 'Harden'
	$Harden.Size = New-Object System.Drawing.Size(42, 13)
	$Harden.TabIndex = 6
	$Harden.Text = 'Harden'

	# OBJ labelAudit >>
	$labelAudit.AutoSize = $True
	$labelAudit.BackColor = [System.Drawing.SystemColors]::ControlLightLight
	$labelAudit.Location = New-Object System.Drawing.Point(31, 46)
	$labelAudit.Name = 'labelAudit'
	$labelAudit.Size = New-Object System.Drawing.Size(31, 13)
	$labelAudit.TabIndex = 5
	$labelAudit.Text = 'Audit'

	#OBJ checkedlistbox2
	$checkedlistbox2.FormattingEnabled = $True
  [void]$checkedlistbox2.Items.Add('Select All')
	[void]$checkedlistbox2.Items.Add('Firewall Configuration')
	[void]$checkedlistbox2.Items.Add('Services')
	[void]$checkedlistbox2.Items.Add('Users & Groups')
	[void]$checkedlistbox2.Items.Add('Scheduled Tasks')
  [void]$checkedlistbox2.Items.Add('Accessibility Features')
	[void]$checkedlistbox2.Items.Add('Prefetch')
	[void]$checkedlistbox2.Items.Add('Misc Items')
	$checkedlistbox2.Location = New-Object System.Drawing.Point(29, 223)
	$checkedlistbox2.Name = 'checkedlistbox2'
	$checkedlistbox2.Size = New-Object System.Drawing.Size(137, 109)
	$checkedlistbox2.TabIndex = 4
	$checkedlistbox2.add_SelectedIndexChanged($checkedlistbox2_SelectedIndexChanged)

	#OBJ checkedlistbox1 >>
	$checkedlistbox1.FormattingEnabled = $True
  [void]$checkedlistbox1.Items.Add('Select All')
	[void]$checkedlistbox1.Items.Add('OS Information')
	[void]$checkedlistbox1.Items.Add('Users & Groups')
	[void]$checkedlistbox1.Items.Add('Domain Policies')
	[void]$checkedlistbox1.Items.Add('Services & Processes')
	[void]$checkedlistbox1.Items.Add('Network Connections')
	[void]$checkedlistbox1.Items.Add('Registry Values')
	[void]$checkedlistbox1.Items.Add('Misc Items')
	$checkedlistbox1.Location = New-Object System.Drawing.Point(29, 64)
	$checkedlistbox1.Name = 'checkedlistbox1'
	$checkedlistbox1.Size = New-Object System.Drawing.Size(137, 124)
	$checkedlistbox1.TabIndex = 2
	$checkedlistbox1.add_SelectedIndexChanged($checkedlistbox1_SelectedIndexChanged)

	#OBJ splitcontainer1 >>
	$splitcontainer1.Location = New-Object System.Drawing.Point(8, 12)
	$splitcontainer1.Name = 'splitcontainer1'
	$splitcontainer1.Panel1.BackColor = [System.Drawing.SystemColors]::ControlLightLight
	[void]$splitcontainer1.Panel1.Controls.Add($labelConfigureOutput)
	[void]$splitcontainer1.Panel1.Controls.Add($checkbox1)
	[void]$splitcontainer1.Panel1.Controls.Add($buttonSubmit)
	$splitcontainer1.Panel2.BackColor = [System.Drawing.SystemColors]::ControlLightLight
	$splitcontainer1.Size = New-Object System.Drawing.Size(404, 407)
	$splitcontainer1.SplitterDistance = 163
	$splitcontainer1.TabIndex = 9

	#OBJ buttonSubmit >>
	$buttonSubmit.BackColor = [System.Drawing.Color]::AliceBlue
	$buttonSubmit.FlatStyle = 'Popup'
	$buttonSubmit.Font = [System.Drawing.Font]::new('Microsoft Sans Serif', '8.25')
	$buttonSubmit.ForeColor = [System.Drawing.SystemColors]::ActiveCaptionText
	$buttonSubmit.Location = New-Object System.Drawing.Point(47, 370)
	$buttonSubmit.Name = 'buttonSubmit'
	$buttonSubmit.Size = New-Object System.Drawing.Size(61, 22)
	$buttonSubmit.TabIndex = 3
	$buttonSubmit.Text = 'Submit'
	$buttonSubmit.UseVisualStyleBackColor = $False
	$buttonSubmit.add_Click($buttonSubmit_Click)

  # OBJ labelConfigureOutput >>
	$labelConfigureOutput.AutoSize = $True
	$labelConfigureOutput.Font = [System.Drawing.Font]::new('Microsoft Sans Serif', '8.25', [System.Drawing.FontStyle]'Bold')
	$labelConfigureOutput.Location = New-Object System.Drawing.Point(5, 8)
	$labelConfigureOutput.Name = 'labelConfigureOutput'
	$labelConfigureOutput.Size = New-Object System.Drawing.Size(103, 13)
	$labelConfigureOutput.TabIndex = 9
	$labelConfigureOutput.Text = 'Configure Output'
	$splitcontainer1.EndInit()
	$splitcontainer1.ResumeLayout()
	$formPhase1WindowsAudit.ResumeLayout()


	$InitialFormWindowState = $formPhase1WindowsAudit.WindowState
	$formPhase1WindowsAudit.add_Load($Form_StateCorrection_Load)
	$formPhase1WindowsAudit.add_FormClosed($Form_Cleanup_FormClosed)
	return $formPhase1WindowsAudit.ShowDialog()

}

p1GUI | Out-Null
