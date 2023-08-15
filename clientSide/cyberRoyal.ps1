#########################################
##       Royal TS meets CyberArk       ##
##          www.gravitir.ch            ##
#########################################
#         ClientSide Script             #
#########################################

# to start and debug directly from PowerShell the following params can be used
param([String]$username, [String]$settingsFile, [Boolean]$debugAuthPrompt, [Boolean]$debugOn)

# settings via webserver, leave empty if none or enter URL to the json settings like "https://WebHost/ScriptData/cyberRoyalSettings.json" 
# or use Custom Field 1 in the DynamicFolder Options in RoyalTS
$webSettingsUrl = "$CustomField1$"

# enable or disable (not recommended) SSL/TLS certificate validation callback in PowerShell (.NET) for the web calls
$psCertValidation = $false

# settings locally, webSettingsUrl will replace this entries!
$localSettings = @"
{
    "cyberRoyalMode": "list",
    "listMode": "listALL",
    "listUrl": "https://YOUR-WEBHOST/ScriptData/cyberRoyalSafeAccountList.json",
    "listPermissionUrl": "https://YOUR-WEBHOST/ScriptData/cyberRoyalPermissionList.json",
    "listAdGroupSafeRegex": "CN=.*?(SafeName),OU=.*",
    "pvwaUrl": "https://YOUR-PVWA/PasswordVault",
    "pvwaAuthMethod": "LDAP",
	"pvwaAuthRetries": 3,
    "usernameFromEnv": 0,
    "pvwaSafeSearch": "",
    "pvwaSavedFilter": "Favorites",
    "pvwaAdditionalProperties": [ "location", "FQDN" ],
    "psmRdpAddress": "YOUR-PSM",
    "psmSshAddress": "YOUR-PSMP",
    "safeFilter": ".*",
    "excludeAccounts": [ "guest", "player" ],
    "excludeEmptyFolders": 1,
    "connectionDescription": "location",
    "folderCreation": "safeName",
    "folderAccountParameter": "Location",
    "enableNLA": 0,
    "rdpResizeMode": "SmartSizing",
    "rdpAuthenticationLevel": 2,
    "useWebPluginWin": "f008c2f0-5fb3-4c5e-a8eb-8072c1183088",
    "platformMappings": {
        "UnixSSH": {
            "connections": [ {
                "type": "SSH",
                "components": ["PSMP-SSH"]
            },
            {
                "type": "SFTP",
                "components": ["PSMP-SFTP"]
            },
            {
                "type": "RDP",
                "components": ["PSM-WinSCP"]
            }
            ]
        },
        "WinDomain": {
            "psmRemoteMachine": 1,
            "connections": [ {
                "type": "RDP",
                "components": ["PSM-RDP"]
            }]
        },
        "WinServerLocal": {
            "namePrefix": "Local - ",
            "namePostfix": "",
            "psmRemoteMachine": 0,
            "color":  "#FF0000",
            "connections": [ {
                "type": "RDP",
                "components": ["PSM-RDP"]
            }]
        }
    }
}
"@


#########################################
#           Powershell Settings         #
#########################################
if ((Get-Host).Version.Major -gt 5) { $pwsh7 = $true } else { $pwsh7 = $false }
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
if ($psCertValidation) { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } } else { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null }

if ($debugOn) { 
	$stopWatch = [system.diagnostics.stopwatch]::StartNew() 
	$debugNrAccounts = 0
	$debugNrServerConnections = 0
}
else {
	$ErrorActionPreference = "Stop"
	$ProgressPreference = "SilentlyContinue"
}

#########################################
#              Functions                #
#########################################

function Write-Debug($message) {
	if ($debugOn) { Write-Host $stopWatch.Elapsed + $message }
}

function Invoke-ErrorMessage($type, $message) {
	Add-Type -AssemblyName System.Windows.Forms
	Add-Type -AssemblyName System.Drawing
	$form = New-Object System.Windows.Forms.Form
	$form.Text = $type
	$form.Size = New-Object System.Drawing.Size(320, 200)
	$form.StartPosition = 'CenterScreen'
	$submit = New-Object System.Windows.Forms.Button
	$submit.Location = New-Object System.Drawing.Point(200, 120)
	$submit.Size = New-Object System.Drawing.Size(80, 25)
	$submit.Text = 'OK'
	$submit.DialogResult = [System.Windows.Forms.DialogResult]::OK
	$form.AcceptButton = $submit
	$form.Controls.Add($submit)

	$textLabel = New-Object System.Windows.Forms.Label
	$textLabel.Text = $message
	$textLabel.AutoSize = $false
	$textLabel.MaximumSize = New-Object System.Drawing.Size(280, 0)
	$textLabel.Dock = [System.Windows.Forms.DockStyle]::Fill
	$textLabel.TextAlign = [System.Drawing.ContentAlignment]::TopLeft
	$textLabel.UseCompatibleTextRendering = $true

	$form.Controls.Add($textLabel)
	$form.Add_Shown({ $submit.Select() })

	# add top and activate windows on load
	$form.Add_Load({ $form.Topmost = $true; $form.Activate() })
	$result = $form.ShowDialog()
	
	# end dynamic folder
	Write-Host "{}"
	exit
}

function Invoke-GetCredentialsUi($username, $message) {
	Add-Type -AssemblyName System.Windows.Forms
	Add-Type -AssemblyName System.Drawing
	$form = New-Object System.Windows.Forms.Form
	$form.Text = 'CyberArk Login'
	$form.Size = New-Object System.Drawing.Size(320, 200)
	$form.StartPosition = 'CenterScreen'
	$submit = New-Object System.Windows.Forms.Button
	$submit.Location = New-Object System.Drawing.Point(200, 120)
	$submit.Size = New-Object System.Drawing.Size(80, 25)
	$submit.Text = 'OK'
	$submit.DialogResult = [System.Windows.Forms.DialogResult]::OK
	$form.AcceptButton = $submit
	$form.Controls.Add($submit)
	
	$textLabel = New-Object System.Windows.Forms.Label
	$textLabel.Location = New-Object System.Drawing.Point(10, 10)
	$textLabel.Size = New-Object System.Drawing.Size(240, 20)
	$textLabel.Text = $message
	$form.Controls.Add($textLabel)
	
	$usernameLabel = New-Object System.Windows.Forms.Label
	$usernameLabel.Location = New-Object System.Drawing.Point(10, 40)
	$usernameLabel.Size = New-Object System.Drawing.Size(70, 20)
	$usernameLabel.Text = 'Username:'
	$form.Controls.Add($usernameLabel)
	$usernameBox = New-Object System.Windows.Forms.TextBox
	$usernameBox.Location = New-Object System.Drawing.Point(80, 40)
	$usernameBox.Size = New-Object System.Drawing.Size(200, 20)
	$form.Controls.Add($usernameBox)
	
	$passwordLabel = New-Object System.Windows.Forms.Label
	$passwordLabel.Location = New-Object System.Drawing.Point(10, 80)
	$passwordLabel.Size = New-Object System.Drawing.Size(70, 20)
	$passwordLabel.Text = 'Password:'
	$form.Controls.Add($passwordLabel)
	$passwordBox = New-Object System.Windows.Forms.TextBox
	$passwordBox.Location = New-Object System.Drawing.Point(80, 80)
	$passwordBox.Size = New-Object System.Drawing.Size(200, 20)
	$passwordBox.PasswordChar = '*'
	$form.Controls.Add($passwordBox)
	
	# add top and activate windows on load
	$form.Add_Load({ $form.Topmost = $true; $form.Activate() })

	if ([string]::isNullOrEmpty($username)) {
		$form.Add_Shown({ $usernameBox.Select() })
	}
	else {
		$usernameBox.Text = $username
		$form.Add_Shown({ $passwordBox.Select() })
	}
	$result = $form.ShowDialog()
	
	if ([string]::isNullOrEmpty($passwordBox.Text) -or [string]::isNullOrEmpty($usernameBox.Text) -or $result -ne [System.Windows.Forms.DialogResult]::OK) { 
		Invoke-ErrorMessage "Error" "No credentials provided"
	}
	else {
		$password = ConvertTo-SecureString $passwordBox.Text -AsPlainText -Force
		return New-Object System.Management.Automation.PSCredential ($usernameBox.Text, $password)
	}
}

function Invoke-GetOtpUi() {
	Add-Type -AssemblyName System.Windows.Forms
	Add-Type -AssemblyName System.Drawing
	$form = New-Object System.Windows.Forms.Form
	$form.Text = 'CyberArk OTP'
	$form.Size = New-Object System.Drawing.Size(320, 120)
	$form.StartPosition = 'CenterScreen'
	$submit = New-Object System.Windows.Forms.Button
	$submit.Location = New-Object System.Drawing.Point(200, 40)
	$submit.Size = New-Object System.Drawing.Size(80, 25)
	$submit.Text = 'OK'
	$submit.DialogResult = [System.Windows.Forms.DialogResult]::OK
	$form.AcceptButton = $submit
	$form.Controls.Add($submit)
	
	$textLabel = New-Object System.Windows.Forms.Label
	$textLabel.Location = New-Object System.Drawing.Point(10, 10)
	$textLabel.Size = New-Object System.Drawing.Size(240, 20)
	$textLabel.Text = 'Please enter your CyberArk OTP'
	$form.Controls.Add($textLabel)
	
	$otpLabel = New-Object System.Windows.Forms.Label
	$otpLabel.Location = New-Object System.Drawing.Point(10, 40)
	$otpLabel.Size = New-Object System.Drawing.Size(40, 20)
	$otpLabel.Text = 'OTP:'
	$form.Controls.Add($otpLabel)
	
	$otpBox = New-Object System.Windows.Forms.TextBox
	$otpBox.Location = New-Object System.Drawing.Point(60, 40)
	$otpBox.Size = New-Object System.Drawing.Size(100, 20)
	$otpBox.PasswordChar = '*'
	$form.Controls.Add($otpBox)
	
	# add top and activate windows on load
	$form.Add_Load({ $form.Topmost = $true; $form.Activate() })
	
	$form.Add_Shown({ $otpBox.Select() })
	$result = $form.ShowDialog()
	
	if ([string]::isNullOrEmpty($otpBox.Text) -or $result -ne [System.Windows.Forms.DialogResult]::OK) { 
		Invoke-ErrorMessage "Error" "No OTP provided"
	}
	else {
		return $otpBox.Text
	}
}

function Invoke-Logon() {
	Write-Debug "invoke PVWA logon"
	$global:header = @{}
	$global:header.Add("Content-type", "application/json") 
	$logonURL = $pvwaUrl + "/api/auth/" + $settings.pvwaAuthMethod + "/Logon"

	$logonData = @{ 
		username          = $caCredentials.GetNetworkCredential().UserName; 
		password          = $caCredentials.GetNetworkCredential().Password; 
		concurrentSession = $true; 
	} | ConvertTo-Json 

	try {
		$logonDataEnc = [System.Text.Encoding]::UTF8.GetBytes($logonData)
		$logonResult = $( Invoke-WebRequest -Uri $logonURL -Headers $global:header -Method Post -UseBasicParsing -Body $logonDataEnc -SessionVariable webSession ).content | ConvertFrom-Json 
	} 
	catch {
		if (![string]::isNullOrEmpty($_.ErrorDetails.Message) ) {
			$message = $_.ErrorDetails.Message | ConvertFrom-Json
		}
		else {
			Invoke-ErrorMessage "Error" $_ 		
		}

		# "ErrorCode":"PASWS013E" - "ErrorMessage":"Authentication failure for User []."
		# "ErrorCode":"PASWS268E" - "ErrorMessage":"Your user [] has been suspended. Contact your system administrator."
		switch ($message.ErrorCode) {
			# RADIUS Challenge
			"ITATS542I" { 
				$cookies = $_.Exception.Response.Cookies
				foreach ($cookie in $cookies) {
					$webSession.Cookies.Add($cookie)
				}	
				$logonData = @{ 
					username          = $caCredentials.GetNetworkCredential().UserName; 
					password          = Invoke-GetOtpUi; 
					concurrentSession = $true; 
				} | ConvertTo-Json 
				$logonDataEnc = [System.Text.Encoding]::UTF8.GetBytes($logonData)
				try {
					$logonResult = $( Invoke-WebRequest -Uri $logonURL -Method Post -ContentType "application/json" -UseBasicParsing -TimeoutSec 30 -Body $logonDataEnc -WebSession $webSession ).content | ConvertFrom-Json  
				}
				catch {
					Invoke-ErrorMessage "Error" $_
				}
				# $logonResult = Invoke-RestMethod -Method Post -Uri $logonURL -ContentType "application/json" -Body $logonDataEnc -UseBasicParsing -TimeoutSec 30 -WebSession $webSession

			}
			"PASWS013E" {
				if ($logonRetries -lt $logonRetriesLimit) {
					$logonRetries++
					$message = "Logon failed! Please try again"
					$caCredentials = Invoke-GetCredentialPrompt($message)
					Invoke-Logon
				}
				else {
					Invoke-ErrorMessage "Error" "Logon failed after $logonRetries retries"
				}
			}
			Default {
				Invoke-ErrorMessage "Error" "$( $message.ErrorCode): $( $message.ErrorMessage)" 		
			}
		}
	}
	if ($logonResult) {
		$global:header.Add("Authorization" , $logonResult)
	}
}
function Invoke-Logoff() {
	try { Invoke-WebRequest -Uri $( $pvwaUrl + "/api/auth/Logoff") -Headers $global:header -UseBasicParsing -Method Post | Out-Null } catch { }
}

function Get-PvwaSafeDetails() {
	if ([string]::IsNullOrEmpty($settings.pvwaSafeSearch)) { 
		Write-Debug "get all accessable PVWA safes"
		$safeURL = $pvwaUrl + "/api/Safes?limit=10000&includeAccounts=false&extendedDetails=false" 
	}
	else { 
		Write-Debug "get PVWA safes with safe search $($settings.pvwaSafeSearch)"
		$safeURL = $pvwaUrl + "/api/Safes?limit=10000&search=$($settings.pvwaSafeSearch)" 
	}
	try {
		$safesList = $( Invoke-WebRequest -Uri $safeURL -Headers $global:header -Method Get -UseBasicParsing).content | ConvertFrom-Json
		$safes = New-Object System.Collections.ArrayList
		foreach ($safe in $safesList.value) {
			$safes.Add($safe) | Out-Null
		}
	}
 catch {
		Invoke-ErrorMessage "Error" $_
	}
	return $safes
}

function Get-PermissionListSafeNames($listUrl) {
	Write-Debug "get permissionsList from $listUrl"
	try { $jsonFileData = Invoke-WebRequest -Uri $listUrl -Method GET -UseBasicParsing -ContentType 'application/json; charset=utf-8' } catch { Invoke-ErrorMessage "Error" "Error getting List from URL $listUrl" }
	$safePermissionList = $jsonFileData.Content | Foreach-Object { $_ -replace "\xEF\xBB\xBF", "" } | ConvertFrom-Json
	$safeNames = New-Object System.Collections.ArrayList
	foreach ($safePermission in $safePermissionList.users) {
		if ($safePermission.username -eq $global:caUser) {
			$safeNames = $safePermission.permissions
		}
	}
	if ($safeNames.Count -lt 1) { Invoke-ErrorMessage "Info" "No safe permissions for user $global:caUser in PermissionList found" }

	return $safeNames
}

function Get-AdGroupSafeNames() {
	Write-Debug "get adGroups from user $global:caUser"
	$userGroups = (New-Object System.DirectoryServices.DirectorySearcher("(&(objectCategory=User)(samAccountName=$( $global:caUser )))")).FindOne().GetDirectoryEntry()
	$groups = $userGroups.memberOf
	Write-Debug "fetched $global:caUser member groups $groups"
	$safeNames = New-Object System.Collections.ArrayList
	foreach ($group in $groups) {
		$match = [regex]::Match($group, $settings.listAdGroupSafeRegex)
		if ($match.Success) {
			$safeName = $match.Groups[1].ToString()
			$safeNames.Add($safeName) | Out-Null
		}
	}

	return $safeNames
}

function Get-PvwaAccountsFromList($listUrl) {
	Write-Debug "get accountsList from $listUrl"
	# get the prepared data file and remove BOM (thanks to .NET, IIS) if necessary
	try { $jsonFileData = Invoke-WebRequest -Uri $listUrl -Method GET -UseBasicParsing -ContentType 'application/json; charset=utf-8' } catch { Invoke-ErrorMessage "Error" "Error getting List from URL $listUrl" }
	Write-Debug "fetched json file length: $( $jsonFileData.RawContentLength)"
	
	[PSCustomObject]$safesAndAccounts = $jsonFileData.Content | Foreach-Object { $_ -replace "\xEF\xBB\xBF", "" } | ConvertFrom-Json
	return $safesAndAccounts
}

function Get-PvwaAccountsFromSafes($safeDetails) {
	Write-Debug "get accounts from PVWA safes"
	$safesAndAccounts = [System.Collections.SortedList]::new()
	foreach ($safe in $safeDetails) {
		if (![string]::IsNullOrEmpty($settings.safeFilter) -and !([regex]::Match( $safe.SafeName, $settings.safeFilter ).Success )) { continue } 
		$accountURL = $pvwaUrl + "/api/Accounts?limit=1000&filter=safeName eq $($safe.SafeName)"
		try { $accountsResult = $( Invoke-WebRequest -Uri $accountURL -Headers $global:header -Method Get).content | ConvertFrom-Json } catch { Invoke-ErrorMessage "Error" $_ }
		if ($null -ne $accountsResult.value -and $accountsResult.value.Length -gt 0) {
			$safeEntry = @{ "SafeName" = $safe.SafeName; "Description" = $safe.Description; "Accounts" = New-Object System.Collections.ArrayList }
			foreach ($account in $accountsResult.value) {
				$accountEntry = @{ "userName" = $account.userName; "address" = $account.address ; "platformId" = $account.platformId; "remoteMachines" = $account.remoteMachinesAccess.remoteMachines }
				foreach ($property in $settings.pvwaAdditionalProperties) {
					$accountEntry += @{$property = $account.platformAccountProperties.$property }
				}
				$safeEntry.Accounts.Add($accountEntry) | Out-Null
				$accountEntriesCount++
			}
			$safesAndAccounts.Add($safe.SafeName, $safeEntry) | Out-Null
		}
	}
	Write-Debug "retrieved $accountEntriesCount accounts from PVWA"
	return $safesAndAccounts
}

function Get-PvwaAccountsFromSavedFilter($savedFilter) {
	Write-Debug "get accounts from PVWA saved Filter $savedFilter"
	$safesAndAccounts = [System.Collections.SortedList]::new()
	$accountURL = $pvwaUrl + "/api/Accounts?savedFilter=$savedFilter"
	try { $accountsResult = $(Invoke-WebRequest -Uri $accountURL -Headers $global:header -Method Get).content | ConvertFrom-Json } catch { Invoke-ErrorMessage "Error" "Error getting accounts from PVWA" }
	if ($null -ne $accountsResult.value -and $accountsResult.value.Length -gt 0) {
		$safes = $accountsResult.value.safeName | Select-Object -Unique
		foreach ($safe in $safes) {
			if (![string]::IsNullOrEmpty($settings.safeFilter) -and !([regex]::Match( $safe, $settings.safeFilter ).Success )) { continue } 
			$safeURL = $pvwaUrl + "/api/Safes/$safe"
			try { $safeResult = $(Invoke-WebRequest -Uri $safeURL -Headers $global:header -Method Get).content | ConvertFrom-Json } catch { Invoke-ErrorMessage "Error" "Error getting safes from PVWA" }
			$safeEntry = @{ "SafeName" = $safe; "Description" = $($safeResult.description); "Accounts" = New-Object System.Collections.ArrayList }
			foreach ($account in $accountsResult.value) {
				if ($account.safeName -eq $safe) {
					$accountEntry = @{ "userName" = $account.userName; "address" = $account.address ; "platformId" = $account.platformId; "remoteMachines" = $account.remoteMachinesAccess.remoteMachines }
					foreach ($property in $settings.pvwaAdditionalProperties) {
						$accountEntry += @{$property = $account.platformAccountProperties.$property }
					}
					$safeEntry.Accounts.Add($accountEntry) | Out-Null
					$accountEntriesCount++
				}
			}
			$safesAndAccounts.Add($safe, $safeEntry) | Out-Null
		}
	}
	return $safesAndAccounts
}

function Get-ConnectionRDP($acc, $plat, $comp) {
	$entry = @{ }
	$entry.Properties = @{ }
	$entry.Type = "RemoteDesktopConnection"
	$entry.Username = $global:caUser
	if ($plat.psmRemoteMachine) { $entry.Properties.StartProgram = "psm /u " + $acc.userName + "@" + $acc.address + " /a " + $acc.target + " /c " + $comp }
	else { $entry.Properties.StartProgram = "psm /u " + $acc.userName + " /a " + $acc.target + " /c " + $comp }
	return $entry
}

function Get-ConnectionSSH($acc, $plat, $comp) {
	$entry = @{ }
	$entry.Type = "TerminalConnection"
	$entry.TerminalConnectionType = "SSH"
	$entry.UserName = $global:caUser + "@" + $acc.userName + "@" + $acc.target
	return $entry
}

function Get-ConnectionSFTP($acc, $plat, $comp) {
	$entry = @{ }
	$entry.Type = "FileTransferConnection"
	$entry.FileTransferConnectionType = "SFTP"
	$entry.CredentialMode = 4
	$entry.CredentialName = $global:caUser + "@" + $acc.userName + "@" + $acc.target
	return $entry
}

function Get-ConnectionWEB($acc, $plat, $comp) {
	$entry = @{ }
	$entry.Properties = @{ }
	$entry.Type = "WebConnection"
	if (![string]::isNullOrEmpty( $plat.webProtocol )) { $webProtocol = $plat.webProtocol } else { $webProtocol = "https" }
	if (![string]::isNullOrEmpty( $plat.webOverwriteUri )) {  
		$entry.URL = "$( $webProtocol )://" + $plat.webOverwriteUri
	} 
	else {     
		$entry.URL = "$( $webProtocol )://" + $acc.target
	}
	# Entry Properties
	$entry.Properties.ShowToolbar = $true
	$entry.Properties.IgnoreCertificateErrors = $true
	$entry.Properties.UseDedicatedEngine = $true
	# AutoFill Implementations
	if (![string]::isNullOrEmpty($plat.webInputObject)) { 
		$fillUser = $acc.userName
		$fillMappings = @( @{ Element = $plat.webInputObject; Action = "Fill"; Value = $fillUser } )
		$entry.AutoFillElements = $fillMappings
		$entry.AutoFillDelay = 1000
	}
	# Use Win WebPlugin ID instead of global config
	if (![string]::isNullOrEmpty( $settings.useWebPluginWin )) {
		$entry.Properties.UseGlobalPlugInWin = $false
		$entry.Properties.PlugInWin = $settings.useWebPluginWin
	}
	return $entry
}

function Get-ConnectionEntry($accountDetail, $safeDetails, $platformSetting, $connectionType, $component) {
	# create connection entry for different connection types
	switch ($connectionType) {
		"SSH" {
			$entry = Get-ConnectionSSH $accountDetail $platformSetting $component 
			if ([string]::isNullOrEmpty( $platformSetting.replacePsmp )) { $entry.ComputerName = $settings.psmSshAddress } else { $entry.ComputerName = $platformSetting.replacePsmp }
		}
		"SFTP" {
			$entry = Get-ConnectionSFTP $accountDetail $platformSetting $component
			if ([string]::isNullOrEmpty( $platformSetting.replacePsmp )) { $entry.ComputerName = $settings.psmSshAddress } else { $entry.ComputerName = $platformSetting.replacePsmp }
		}
		"RDP" {
			$entry = Get-ConnectionRDP $accountDetail $platformSetting $component
			if ([string]::isNullOrEmpty( $platformSetting.replacePsm )) { $entry.ComputerName = $settings.psmRdpAddress } else { $entry.ComputerName = $platformSetting.replacePsm }
			if ([string]::isNullOrEmpty( $settings.rdpResizeMode )) { $entry.ResizeMode = "SmartSizing" } else { $entry.ResizeMode = $settings.rdpResizeMode }
			if ([string]::isNullOrEmpty( $settings.rdpAuthenticationLevel )) { $entry.Properties.AuthenticationLevel = 0 } else { $entry.Properties.AuthenticationLevel = $settings.rdpAuthenticationLevel }
			if ($platformSetting.drivesRedirection) { $entry.Properties.RedirectDrives = "true" } else { $entry.Properties.RedirectDrives = "false" } 
			if ($settings.enableNLA) { $entry.NLA = "true" } else { $entry.NLA = "false" }
		}
		"WEB" { $entry = Get-ConnectionWEB $accountDetail $platformSetting $component }
	}

	# add standard connection entry values and naming
	if (![string]::isNullOrEmpty( $platformSetting.connectionNaming )) { $naming = $platformSetting.connectionNaming } else { $naming = $settings.connectionNaming }
	switch ($naming) {
		"named" { $name = $accountDetail.userName + "@" + $accountDetail.address + " - " + $accountDetail.target } 
		"simple" { $name = $accountDetail.userName + "@" + $accountDetail.target }
		"target" { $name = $accountDetail.target }
		Default { $name = $accountDetail.userName + "@" + $accountDetail.target }
	}

	$componentName = $component.Replace("PSM-RDP", "").Replace("PSMP-SSH", "").Replace("PSMP-SFTP", "")
	if (![string]::isNullOrEmpty( $componentName)) { $componentName = " - " + $componentName }

	$entry.Name = $platformSetting.namePrefix + $name + $componentName + $platformSetting.namePostfix

	# account description
	$connectionDescriptionProperty = $settings.connectionDescription
	if ([string]::isNullOrEmpty( $connectionDescriptionProperty )) {
		$entry.Description = $safeDetails.Value.Description
	}
	else {
		$entry.Description = $accountDetail.$connectionDescriptionProperty
	}

	# add standard connection entry values and naming
	if ([string]::isNullOrEmpty( $platformSetting.color )) { $entry.ColorFromParent = $true } else { $entry.color = $platformSetting.color }
	if (![string]::isNullOrEmpty( $platformSetting.replaceName )) { $entry.Name = $platformSetting.replaceName }
	if (![string]::isNullOrEmpty($platformSetting.replaceRegex )) { $entry.Name = $entry.Name -replace $platformSetting.replaceRegex }

	return $entry
}

function Invoke-GetCredentialPrompt($message) {
	if (![string]::IsNullOrEmpty($global:caUser)) {
		if ([string]::isNullOrEmpty($message)) { $message = "Please enter your CyberArk Password" }
		if ($pwsh7) {
			$caCredentials = Invoke-GetCredentialsUi $global:caUser $message
		}
		else {
			$caCredentials = Get-Credential -UserName $global:caUser -Message $message
		}
	}
	else {
		if ([string]::isNullOrEmpty($message)) { $message = "Please enter your CyberArk Username and Password" }
		if ($pwsh7) {
			$caCredentials = Invoke-GetCredentialsUi $global:caUser $message
		}
		else {
			$caCredentials = Get-Credential -Message $message
		}
		$global:caUser = $caCredentials.UserName
	}
	if (!$caCredentials) {
		Invoke-ErrorMessage "Error" "No credentials provided"
	}
	return $caCredentials
}


#########################################
#               Variables               #
#########################################
# RoyalTS user context or credential will fill the following $variables$ if defined during script execution
$global:caUser = @'
$EffectiveUsername$
'@

$caPass = @'
$EffectivePassword$
'@

# get settings from web if available
if (![string]::IsNullOrEmpty($settingsFile)) {
	# debug as started from console directly
	if (Test-Path $settingsFile) {
		Write-Host -ForegroundColor Cyan "apply settings from file $settingsFile"
		$settings = Get-Content $settingsFile | ConvertFrom-Json
	}
	else {
		Write-Error "settings file not found" -ErrorAction Stop
	}
}
elseif (![string]::isNullOrEmpty($webSettingsUrl)) {
	try {
		$webSettings = Invoke-WebRequest -Uri $webSettingsUrl -Method Get -UseBasicParsing -ContentType "application/json; charset=utf-8"
		$settings = $webSettings | ConvertFrom-Json
	}
	catch {
		Invoke-ErrorMessage "Error" "Could not get settings from provided URL"
	}
}
else {
	$settings = $localSettings | ConvertFrom-Json
}

# used variables
$pvwaUrl = $settings.pvwaUrl
$logonRetries = 0
if ($settings.pvwaAuthRetries) { $logonRetriesLimit = $settings.pvwaAuthRetries } else { $logonRetriesLimit = 3 }

#########################################
#                MAIN                   #
#########################################

# check when and how credentials are required
if ($settings.cyberRoyalMode -eq "pvwa" -or $settings.listMode -eq "pvwaRBAC") { $pvwaLoginRequired = $true } else { $pvwaLoginRequired = $false }
if ($settings.usernameFromEnv) { $global:caUser = $env:username }
if (![string]::IsNullOrEmpty($username)) { $global:caUser = $username }
if ($pvwaLoginRequired) {
	if (![string]::IsNullOrEmpty($global:caUser) -and ![string]::IsNullOrEmpty($caPass)) {
		[securestring]$secStringPassword = ConvertTo-SecureString $caPass -AsPlainText -Force
		[pscredential]$caCredentials = New-Object System.Management.Automation.PSCredential ($global:caUser, $secStringPassword)
	}
	else {
		$caCredentials = Invoke-GetCredentialPrompt
	}
}

# switch cyberRoyal mode - set the users "permissive" safes to apply account connections
switch ($settings.cyberRoyalMode) {
	"list" {
		switch ($settings.listMode) {
			"adGroupRBAC" { 
				$safes = Get-AdGroupSafeNames
				Write-Debug "fetched adGroup safes: $( $safes.Count )" 
			}
			"pvwaRBAC" { 
				Invoke-Logon
				$safesDetails = Get-PvwaSafeDetails
				$safes = $safesDetails.SafeName
				Write-Debug "fetched PVWA safes: $( $safes.Count )" 
			}
			"listRBAC" { 
				$safes = Get-PermissionListSafeNames($settings.listPermissionUrl)
				Write-Debug "fetched PermissionList safes: $( $safes.Count )" 
			}
			"listALL" { 
				$skipSafesMatching = $true
				Write-Debug "applying all accounts from list" 
			}
		}
		[PSCustomObject]$safesAndAccounts = Get-PvwaAccountsFromList($settings.listUrl)
	}
	"pvwa" {
		Invoke-Logon
		# Get PVWA safes details and accounts
		if ([string]::IsNullOrEmpty($settings.pvwaSavedFilter)) {
			$safesDetails = Get-PvwaSafeDetails
			$safes = $safesDetails.SafeName
			$safesAndAccountsSortedList = Get-PvwaAccountsFromSafes($safesDetails)
		}
		else {
			$safesAndAccountsSortedList = Get-PvwaAccountsFromSavedFilter($settings.pvwaSavedFilter)
			$safes = $safesAndAccountsSortedList.Keys
		}
		# Convert SortedList to PSCustomObject List
		[PSCustomObject]$safesAndAccounts = $safesAndAccountsSortedList | ConvertTo-Json -Depth 100 | ConvertFrom-Json
	}
}

# prepare RoyalJSON response
$response = @{
	Objects = New-Object System.Collections.ArrayList
}
$objects = New-Object System.Collections.ArrayList
$folders = New-Object System.Collections.ArrayList

# safes as List
# safesAndAccounts as PSCustomObject List
Write-Debug "looping through safes and accounts to create royalJSON connection entries" 
foreach ($safe in $safesAndAccounts.PsObject.Properties) {
	# match safe or continue
	if ( !$skipSafesMatching -and !($safes.Contains( $safe.Name )) ) { continue }

	# match safeFilter or continue
	if (![string]::IsNullOrEmpty($settings.safeFilter) -and !([regex]::Match( $safe.Name, $settings.safeFilter ).Success )) { continue } 
	if (![string]::IsNullOrEmpty($settings.folderCreation)) {
		[pscustomobject]$folder = @{
			Name            = ""
			Type            = "Folder"
			ColorFromParent = $true
		}

		switch ($settings.folderCreation) {
			"safeName" { $folder.Name = $safe.Name; $folder.Description = $safe.Value.Description }
			"safeName-Description" { $folder.Name = $safe.Name + ' - ' + $safe.Value.Description; $folder.Description = $safe.Value.Description }
			"safeDescription" { $folder.Name = $safe.Value.Description; $folder.Description = "Safe: " + $safe.Name }
			"safeDescription-Name" { $folder.Name = $safe.Value.Description + ' - ' + $safe.Name; $folder.Description = $safe.Value.Description }
			Default { $folder.Name = $safe.Name }
		}
	}

	foreach ($account in $safe.Value.Accounts) {

		$accountPlatform = $account.platformId

		if (!$settings.platformMappings.$accountPlatform) { continue }
		if (![string]::IsNullOrEmpty($settings.excludeAccounts) -and $settings.excludeAccounts.Contains( $account.userName)) { continue }
		if ($debugOn) { $debugNrAccounts++ }

		# create connections for every configured connection component
		if ($null -eq $account.remoteMachines) {
			Add-Member -InputObject $account -NotePropertyName 'target' -NotePropertyValue $account.address
			$royalPlatform = $settings.platformMappings.$accountPlatform

			# continue if remote machines are required for the connection component but none provided
			if ($royalPlatform.psmRemoteMachine) { continue }
						
			foreach ($connection in $royalPlatform.connections) {
				foreach ($component in $connection.components) { 
					$connectionEntry = Get-ConnectionEntry $account $safe $royalPlatform $connection.Type $component

					$objects.Add( $connectionEntry ) | Out-Null 
					if ($debugOn) { $debugNrServerConnections++ }
				}
			}
		}
		# create connections for each remoteMachine and every configured connection component
		else {
			$remoteMachines = $account.remoteMachines.split(';', [System.StringSplitOptions]::RemoveEmptyEntries) | Sort-Object
			foreach ($remoteMachine in $remoteMachines) {
				Add-Member -InputObject $account -NotePropertyName 'target' -NotePropertyValue $remoteMachine -Force
				$royalPlatform = $settings.platformMappings.$accountPlatform
				foreach ($connection in $royalPlatform.connections) {
					foreach ($component in $connection.components) { 
						$connectionEntry = Get-ConnectionEntry $account $safe $royalPlatform $connection.Type $component

						$objects.Add( $connectionEntry ) | Out-Null 
						if ($debugOn) { $debugNrServerConnections++ }
					}
				}
			}
		}

	}
	
	# if folders are created
	if (![string]::IsNullOrEmpty($settings.folderCreation)) {
		if (!$settings.excludeEmptyFolders -and $objects.Count -gt 0) {
			$folder.Objects = $objects
			$folders.Add($folder) | Out-Null
			$objects = New-Object System.Collections.ArrayList
		}
		else {
			# no folder as it would be empty
			Write-Debug "skip $($folder.Name) as it would be empty" 
		}
	}
}

if ([string]::IsNullOrEmpty($settings.folderCreation) -and $objects.Length -gt 0) {
	[array]$sortedDirectObjects = $objects | Sort-Object -Property { $_.Name }
	$response.Objects = $sortedDirectObjects
}
else {
	[array]$sortedFolderObjects = $folders | Sort-Object -Property { $_.Name }
	$response.Objects = $sortedFolderObjects
}

# send RoyalJSON response
$jsonResponse = $response | ConvertTo-Json -Depth 100

if ($debugOn) { 
	Write-Debug "created $debugNrServerConnections server connections" 
	Out-File -FilePath "dataRoyalJson.json" -Encoding UTF8 -InputObject $jsonResponse
	$safesAndAccounts | ConvertTo-Json -Depth 100 | Out-File -FilePath "dataSafeAndAccounts.json" -Encoding UTF8
}
else {
	Write-Host $jsonResponse
}

# logoff if required
if ($pvwaLoginRequired) { Invoke-Logoff }
Write-Debug "finished"