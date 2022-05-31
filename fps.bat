REG ADD "HKEY_CURRENT_USER\System\GameConfigStore" /F /V "GameDVR_Enabled" /T REG_DWORD /d 0 
REG ADD "HKEY_CURRENT_USER\System\GameConfigStore" /F /V "GameDVR_FSEBehaviorMode" /T REG_DWORD /d 2 
REG ADD "HKEY_CURRENT_USER\System\GameConfigStore" /F /V "GameDVR_HonorUserFSEBehaviorMode" /T REG_DWORD /d 0 
REG ADD "HKEY_CURRENT_USER\System\GameConfigStore" /F /V "GameDVR_DXGIHonorFSEWindowsCompatible" /T REG_DWORD /d 0 
REG ADD "HKEY_CURRENT_USER\System\GameConfigStore" /F /V "GameDVR_EFSEFeatureFlags" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "AllowCommercialDataPipeline" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "AllowDesktopAnalyticsProcessing" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "AllowDeviceNameInTelemetry" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "AllowTelemetry" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "AllowUpdateComplianceProcessing" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "AllowWUfBCloudProcessing" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "DisableEnterpriseAuthProxy" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "MicrosoftEdgeDataOptIn" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "DisableTelemetryOptInChangeNotification" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "DisableTelemetryOptInSettingsUx" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "DisableDiagnosticDataViewer" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "EnableConfigFlighting" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "DoNotShowFeedbackNotifications" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "LimitEnhancedDiagnosticDataWindowsAnalytics" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /F /V "EnableSmartScreen" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\FileHistory" /F /V "Disabled" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FindMyDevice" /F /V "AllowFindMyDevice" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Settings\FindMyDevice" /F /V "LocationSyncEnabled" /T REG_DWORD /d 0 
Reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /F /V "Value" /T REG_SZ /d "Deny" 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /F /V "DisableLocation" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /F /V "DisableLocationScripting" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /F /V "DisableSensors" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /F /V "DisableWindowsLocationProvider" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Maps" /F /V "AutoDownloadAndUpdateMapData" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Maps" /F /V "AllowUntriggeredNetworkTrafficOnSettingsPage" /T REG_DWORD /d 0 
Reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /F /V "Value" /T REG_SZ /d "Deny" 
Reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /F /V "Value" /T REG_SZ /d "Deny" 
Reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /F /V "Value" /T REG_SZ /d "Deny" 
Reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /F /V "Value" /T REG_SZ /d "Deny" 
Reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /F /V "Value" /T REG_SZ /d "Deny" 
Reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /v "Value" /t REG_SZ /d "Deny" /f 
Reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" /v "Value" /t REG_SZ /d "Deny" /f 
Reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /v "Value" /t REG_SZ /d "Deny" /f 
Reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" /v "Value" /t REG_SZ /d "Deny" /f 
Reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" /v "Value" /t REG_SZ /d "Deny" /f 
Reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /v "Value" /t REG_SZ /d "Deny" /f 
Reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /v "Value" /t REG_SZ /d "Deny" /f 
Reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /v "Value" /t REG_SZ /d "Deny" /f 
Reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /v "Value" /t REG_SZ /d "Deny" /f 
Reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953062741}" /v "Value" /t REG_SZ /d "Deny" /f 
Reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /v "Value" /t REG_SZ /d "Deny" /f 
Reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /F /V "Value" /T REG_SZ /d "Deny" 
Reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /F /V "Value" /T REG_SZ /d "Deny" 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Messaging" /F /V "AllowMessageSync" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /F /V "NoActiveHelp" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /F /V "DisableWebSearch" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /F /V "DisableRemovableDriveIndexing" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /F /V "AllowCortanaAboveLock" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /F /V "AllowCloudSearch" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /F /V "AllowSearchToUseLocation" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /F /V "ConnectedSearchUseWeb" /T REG_DWORD /d 0 
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /F /V "SafeSearchMode" /T REG_DWORD /d 0 
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /F /V "IsDeviceSearchHistoryEnabled" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Speech" /F /V "AllowSpeechModelUpdate" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableApplicationSettingSync" /T REG_DWORD /d 2 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableAppSyncSettingSync" /T REG_DWORD /d 2 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableWebBrowserSettingSync" /T REG_DWORD /d 2 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableDesktopThemeSettingSync" /T REG_DWORD /d 2 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableSettingSync" /T REG_DWORD /d 2 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableSyncOnPaidNetwork" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableWindowsSettingSync" /T REG_DWORD /d 2 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableCredentialsSettingSync" /T REG_DWORD /d 2 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisablePersonalizationSettingSync" /T REG_DWORD /d 2 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableStartLayoutSettingSync" /T REG_DWORD /d 2 
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314563Enabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\TabletPC" /F /V "TurnOffTouchInput" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\TabletPC" /F /V "TurnOffPanning" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" /F /V "AllowLinguisticDataCollection" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /F /V "AllowWindowsInkWorkspace" /T REG_DWORD /d 0  
rmdir C:\Windows\system32\adminrightstest >NUL 2>&1 
SC CONFIG Winmgmt start= auto >NUL 2>&1  
SC CONFIG TrustedInstaller start= demand >NUL 2>&1 
SC CONFIG AppInfo start= demand >NUL 2>&1 
SC CONFIG DeviceInstall start= demand >NUL 2>&1 
SC START Winmgmt >NUL 2>&1 
SC START TrustedInstaller >NUL 2>&1 
SC START AppInfo >NUL 2>&1 
SC START DeviceInstall >NUL 2>&1 
SC START Dhcp >NUL 2>&1 
wmic process where name="javaw.exe" CALL setpriority "realtime" 
wmic process where name="svchost.exe" CALL setpriority "realtime" 
PowerShell "get-process svchost | %% { $_.ProcessorAffinity=2 }" 
PowerShell "get-process svchost | foreach { $_.ProcessorAffinity=2 }" 
PowerShell "get-process winlogon | %% { $_.ProcessorAffinity=2 }" 
PowerShell "get-process winlogon | foreach { $_.ProcessorAffinity=2 }" 
PowerShell "get-process dwm | %% { $_.ProcessorAffinity=2 }" 
PowerShell "get-process dwm | foreach { $_.ProcessorAffinity=2 }" 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableConnectionRateLimiting" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableDCA" /t REG_DWORD /d "" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUBHDetect" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableRSS" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableTCPA" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableWsd" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "IRPStackSize" /t REG_DWORD /d "0000001e" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxFreeTcbs" /t REG_DWORD /d "65535" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxHashTableSize" /t REG_DWORD /d "00010000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SizReqBuf" /t REG_DWORD /d "51319" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SynAttackProtect" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "4" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpAckFrequency" /t REG_DWORD /d "00000005" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "StrictTimeWaitSeqCheck" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableIPSourceRouting" /t REG_DWORD /d "00000008" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "KeepAliveInterval" /t REG_DWORD /d "000003e8" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpCreateAndConnectTcbRateLimitDepth" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPInitalRtt" /t REG_DWORD /d "00046325" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "00000002" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpNumConnections" /t REG_DWORD /d "de7a" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "00000042d" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpFinWait2Delay" /t REG_DWORD /d "00000042d" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPDelAckTicks" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "IPAutoconfigurationEnabled" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "38" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "DisableTaskOffload" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "EnableConnectionRateLimiting" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "EnableDCA" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "EnablePMTUBHDetect" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "EnablePMTUDiscovery" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "EnableRSS" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "EnableTCPA" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "EnableWsd" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "IRPStackSize" /t REG_DWORD /d "0000001e" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "MaxFreeTcbs" /t REG_DWORD /d "65535" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "MaxHashTableSize" /t REG_DWORD /d "00010000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "MaxUserPort" /t REG_DWORD /d "65534" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "SackOpts" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "SizReqBuf" /t REG_DWORD /d "51319" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "SynAttackProtect" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPNoDelay" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "Tcp1323Opts" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "5" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpAckFrequency" /t REG_DWORD /d "00000004" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "StrictTimeWaitSeqCheck" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "DisableIPSourceRouting" /t REG_DWORD /d "00000008" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "KeepAliveInterval" /t REG_DWORD /d "000003e8" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpCreateAndConnectTcbRateLimitDepth" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "IPAutoconfigurationEnabled" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPInitalRtt" /t REG_DWORD /d "00046325" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpMaxDupAcks" /t REG_DWORD /d "00000002" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpNumConnections" /t REG_DWORD /d "de7a" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpTimedWaitDelay" /t REG_DWORD /d "00000042d" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpFinWait2Delay" /t REG_DWORD /d "00000042d" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPDelAckTicks" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "DefaultTTL" /t REG_DWORD /d "38" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "239" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "240" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "1740" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "1741" /f 
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "10" /f 
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "10" /f 
Reg.exe add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "10" /f 
Reg.exe add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "10" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "10" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "10" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "ffffffff" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d "000f0000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableBucketSize" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableSize" /t REG_DWORD /d "00000180" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheEntryTtlLimit" /t REG_DWORD /d "0000FA00" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxSOACacheEntryTtlLimit" /t REG_DWORD /d "0000012D" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeCacheTime" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NetFailureCacheTime" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeSOACacheTime" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters\OCMsetup" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters\Security" /v "SecureDSCommunication" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters\setup" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Setup" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "80" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "170372" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "HiberbootEnabled" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "MaxOutstandingSends" /t REG_DWORD /d "1073741824" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d "4294967295" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" /v "ServiceTypeBestEffort" /t REG_DWORD /d "99" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" /v "ServiceTypeControlledLoad" /t REG_DWORD /d "99" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" /v "ServiceTypeGuaranteed" /t REG_DWORD /d "99" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" /v "ServiceTypeNetworkControl" /t REG_DWORD /d "99" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" /v "ServiceTypeQualitative" /t REG_DWORD /d "99" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingNonConforming" /v "ServiceTypeBestEffort" /t REG_DWORD /d "99" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingNonConforming" /v "ServiceTypeControlledLoad" /t REG_DWORD /d "99" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingNonConforming" /v "ServiceTypeGuaranteed" /t REG_DWORD /d "99" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingNonConforming" /v "ServiceTypeNetworkControl" /t REG_DWORD /d "99" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingNonConforming" /v "ServiceTypeQualitative" /t REG_DWORD /d "99" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeNonConforming" /t REG_DWORD /d "7" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeBestEffort" /t REG_DWORD /d "7" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeControlledLoad" /t REG_DWORD /d "7" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeGuaranteed" /t REG_DWORD /d "7" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeNetworkControl" /t REG_DWORD /d "7" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeQualitative" /t REG_DWORD /d "7" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "50" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "170372" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v "EnableBITSMaxBandwidth" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\NetCache" /v "PeerCachingLatencyThreshold" /t REG_DWORD /d "268435456" /f 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\PeerDist\Service" /v "Enable" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "UpdateSecurityLevel" /t REG_DWORD /d "598" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "RegistrationTtl" /t REG_DWORD /d "1117034098" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Network Connections" /v "NC_AllowNetBridge_NLA" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Network Connections" /v "NC_AllowAdvancedTCPIPConfig" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SizReqBuf" /t REG_DWORD /d "53819" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SynAttackProtect" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "23" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpAckFrequency" /t REG_DWORD /d "00000008" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "StrictTimeWaitSeqCheck" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableIPSourceRouting" /t REG_DWORD /d "00000008" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "KeepAliveInterval" /t REG_DWORD /d "000003e8" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpCreateAndConnectTcbRateLimitDepth" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPInitalRtt" /t REG_DWORD /d "00049697" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "00000002" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpNumConnections" /t REG_DWORD /d "de7a" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "00000076d" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpFinWait2Delay" /t REG_DWORD /d "00000076d" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPDelAckTicks" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "IPAutoconfigurationEnabled" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "33" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MTU" /t REG_DWORD /d "420" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MSS" /t REG_DWORD /d "412" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "DisableTaskOffload" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "SizReqBuf" /t REG_DWORD /d "53819" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "SynAttackProtect" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPNoDelay" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "Tcp1323Opts" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "23" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpAckFrequency" /t REG_DWORD /d "00000008" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "StrictTimeWaitSeqCheck" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "DisableIPSourceRouting" /t REG_DWORD /d "00000008" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "KeepAliveInterval" /t REG_DWORD /d "000003e8" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpCreateAndConnectTcbRateLimitDepth" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPInitalRtt" /t REG_DWORD /d "00049697" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpMaxDupAcks" /t REG_DWORD /d "00000002" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpNumConnections" /t REG_DWORD /d "de7a" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpTimedWaitDelay" /t REG_DWORD /d "00000076d" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpFinWait2Delay" /t REG_DWORD /d "00000076d" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPDelAckTicks" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "IPAutoconfigurationEnabled" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "DefaultTTL" /t REG_DWORD /d "33" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "MTU" /t REG_DWORD /d "420" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "MSS" /t REG_DWORD /d "412" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "191" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "192" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "214" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "215" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "FastCopyReceiveThreshold" /t REG_DWORD /d "2048" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "FastSendDatagramThreshold" /t REG_DWORD /d "2048" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "PriorityBoost" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DefaultSendWindow" /t REG_DWORD /d "415029" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DefaultReceiveWindow" /t REG_DWORD /d "415029" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MaxFastCopyTransmit" /t REG_DWORD /d "296" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MaxFastTransmit" /t REG_DWORD /d "100" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "TransmitWorker" /t REG_DWORD /d "50" /f 
reg.exe add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile /v NoLazyMode /t REG_DWORD /d 1 /f 
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup /v SendTelemetryData /t REG_DWORD /d 0 /f 
reg.exe add HKLM\SYSTEM\CurrentControlSet\services\NvTelemetryContainer /v Start /t REG_DWORD /d 4 /f 
reg.exe add HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client /v OptInOrOutPreference /t REG_DWORD /d 0 /f  
reg.exe add HKLM\SOFTWARE\Microsoft\Direct3D /v DisableVidMemVBs /t REG_DWORD /d 0 /f           
reg.exe add HKLM\SOFTWARE\Microsoft\Direct3D /v FlipNoVsync /t REG_DWORD /d 1 /f               
reg.exe add HKLM\SOFTWARE\Microsoft\Direct3DDrivers /v SoftwareOnly /t REG_DWORD /d 0 /f       
reg.exe add HKLM\SOFTWARE\Microsoft\Direct3D /v MMX Fast Path /t REG_DWORD /d 1 /f             
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers /v TdrLevel /t REG_DWORD /d 0 /f             
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers /v TdrDebugMode /t REG_DWORD /d 0 /f         
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v EnergyEstimationEnabled /t REG_DWORD /d 0 /f        
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v CsEnabled /t REG_DWORD /d 0 /f      
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v PerfCalculateActualUtilization /t REG_DWORD /d 0 /f                 
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v SleepReliabilityDetailedDiagnostics /t REG_DWORD /d 0 /f            
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v EventProcessorEnabled /t REG_DWORD /d 0 /f          
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v QosManagesIdleProcessors /t REG_DWORD /d 0 /f       
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v DisableVsyncLatencyUpdate /t REG_DWORD /d 1 /f   
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v DisableSensorWatchdog /t REG_DWORD /d 1 /f          
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v ExitLatencyCheckEnabled /t REG_DWORD /d 0 /f        
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling /v PowerThrottlingOff /t REG_DWORD /d 1 /f             
reg.exe add HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism /v MagnetismUpdateIntervalInMilliseconds /t REG_DWORD /d 1 /f           
reg.exe add HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed /v CursorUpdateInterval /t REG_DWORD /d 1 /f               
reg.exe add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability /v TimeStampInterval /t REG_DWORD /d 0 /f               
reg.exe add HKCU\Software\Microsoft\Windows\DWM /v CompositionPolicy /t REG_DWORD /d 0 /f      
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\amdlog /v Start /t REG_DWORD /d 4 /f        
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000 /v DisableDMACopy /t REG_DWORD /d 1 /f     
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000 /v StutterMode /t REG_DWORD /d 0 /f        
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000 /v EnableUlps /t REG_DWORD /d 0 /f         
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000 /v PP_SclkDeepSleepDisable /t REG_DWORD /d 1 /f            
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000 /v PP_ThermalAutoThrottlingEnable /t REG_DWORD /d 0 /f     
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000 /v DisableDrmdmaPowerGating /t REG_DWORD /d 1 /f           
reg.exe add HKLM\Software\Microsoft\Windows Nt\CurrentVersion\Multimedia\SystemProfilE\Tasks\Games /v GPU Priority /t REG_DWORD /d 8 /f        
reg.exe add HKLM\Software\Microsoft\Windows Nt\CurrentVersion\Multimedia\SystemProfilE\Tasks\Games /v Priority /t REG_DWORD /d 6 /f 
reg.exe add HKLM\Software\Microsoft\Windows Nt\CurrentVersion\Multimedia\SystemProfilE\Tasks\Games /v Scheduling Category /t REG_SZ /d High /f                 
reg.exe add HKLM\Software\Microsoft\Windows Nt\CurrentVersion\Multimedia\SystemProfilE\Tasks\Games /v SFIO Priority /t REG_SZ /d High /f       
reg.exe add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games /v Latency Sensitive /t REG_SZ /d True /f   
reg.exe add HKLM\SYSTEM\ControlSet001\Services\camsvc /v Start /t REG_DWORD /d 2 /f            
reg.exe add HKLM\SYSTEM\ControlSet001\Services\TapiSrv /v Start /t REG_DWORD /d 4 /f          
reg.exe add HKLM\SYSTEM\ControlSet001\Services\FontCache3.0.0.0 /v Start /t REG_DWORD /d 4 /f  
reg.exe add HKLM\SYSTEM\ControlSet001\Services\WpcMonSvc /v Start /t REG_DWORD /d 4 /f         
reg.exe add HKLM\SYSTEM\ControlSet001\Services\SEMgrSvc /v Start /t REG_DWORD /d 4 /f          
reg.exe add HKLM\SYSTEM\ControlSet001\Services\PNRPsvc /v Start /t REG_DWORD /d 4 /f           
reg.exe add HKLM\SYSTEM\ControlSet001\Services\LanmanWorkstation /v Start /t REG_DWORD /d 2 /f                 
reg.exe add HKLM\SYSTEM\ControlSet001\Services\WEPHOSTSVC /v Start /t REG_DWORD /d 4 /f        
reg.exe add HKLM\SYSTEM\ControlSet001\Services\p2psvc /v Start /t REG_DWORD /d 4 /f            
reg.exe add HKLM\SYSTEM\ControlSet001\Services\p2pimsvc /v Start /t REG_DWORD /d 4 /f          
reg.exe add HKLM\SYSTEM\ControlSet001\Services\PhoneSvc /v Start /t REG_DWORD /d 4 /f          
reg.exe add HKLM\SYSTEM\ControlSet001\Services\Wecsvc /v Start /t REG_DWORD /d 4 /f           
reg.exe add HKLM\SYSTEM\ControlSet001\Services\RmSvc /v Start /t REG_DWORD /d 4 /f             
reg.exe add HKLM\SYSTEM\ControlSet001\Services\SensorDataService /v Start /t REG_DWORD /d 4 /f                 
reg.exe add HKLM\SYSTEM\ControlSet001\Services\SensrSvc /v Start /t REG_DWORD /d 4 /f          
reg.exe add HKLM\SYSTEM\ControlSet001\Services\perceptionsimulation /v Start /t REG_DWORD /d 4 /f              
reg.exe add HKLM\SYSTEM\ControlSet001\Services\StiSvc /v Start /t REG_DWORD /d 4 /f            
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc /v Start /t REG_DWORD /d 2 /f      
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc /v Start /t REG_DWORD /d 2 /f              
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc /v Start /t REG_DWORD /d 2 /f           
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\UnistoreSvc /v Start /t REG_DWORD /d 2 /f   
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc /v Start /t REG_DWORD /d 2 /f            
reg.exe add HKLM\SYSTEM\ControlSet001\Services\WMPNetworkSvc /v Start /t REG_DWORD /d 4 /f     
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\CaptureService /v Start /t REG_DWORD /d 4 /f                
reg.exe add HKLM\SYSTEM\ControlSet001\Services\autotimesvc /v Start /t REG_DWORD /d 4 /f       
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\MessagingService /v Start /t REG_DWORD /d 4 /f              
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\CDPUserSvc /v Start /t REG_DWORD /d 4 /f    
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc /v Start /t REG_DWORD /d 4 /f         
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\BcastDVRUserService /v Start /t REG_DWORD /d 4 /f           
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\UserDataSvc /v Start /t REG_DWORD /d 4 /f   
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc /v Start /t REG_DWORD /d 2 /f    
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\cbdhsvc /v Start /t REG_DWORD /d 2 /f       
reg.exe add HKLM\SYSTEM\ControlSet001\Services\edgeupdatem /v Start /t REG_DWORD /d 4 /f >nul 2>&1             
reg.exe add HKLM\SYSTEM\ControlSet001\Services\MicrosoftEdgeElevationService /v Start /t REG_DWORD /d 4 /f >nul 2>&1           
reg.exe add HKLM\SYSTEM\ControlSet001\Services\ALG /v Start /t REG_DWORD /d 4 /f               
reg.exe add HKLM\SYSTEM\ControlSet001\Services\QWAVE /v Start /t REG_DWORD /d 4 /f             
reg.exe add HKLM\SYSTEM\ControlSet001\Services\IpxlatCfgSvc /v Start /t REG_DWORD /d 4 /f      
reg.exe add HKLM\SYSTEM\ControlSet001\Services\icssvc /v Start /t REG_DWORD /d 4 /f            
reg.exe add HKLM\SYSTEM\ControlSet001\Services\DusmSvc /v Start /t REG_DWORD /d 4 /f           
reg.exe add HKLM\SYSTEM\ControlSet001\Services\MapsBroker /v Start /t REG_DWORD /d 4 /f        
reg.exe add HKLM\SYSTEM\ControlSet001\Services\edgeupdate /v Start /t REG_DWORD /d 4 /f >nul 2>&1              
reg.exe add HKLM\SYSTEM\ControlSet001\Services\SensorService /v Start /t REG_DWORD /d 4 /f     
reg.exe add HKLM\SYSTEM\ControlSet001\Services\shpamsvc /v Start /t REG_DWORD /d 4 /f          
reg.exe add HKLM\SYSTEM\ControlSet001\Services\svsvc /v Start /t REG_DWORD /d 4 /f            
reg.exe add HKLM\SYSTEM\ControlSet001\Services\SysMain /v Start /t REG_DWORD /d 4 /f           
reg.exe add HKLM\SYSTEM\ControlSet001\Services\MSiSCSI /v Start /t REG_DWORD /d 4 /f           
reg.exe add HKLM\SYSTEM\ControlSet001\Services\Netlogon /v Start /t REG_DWORD /d 4 /f          
reg.exe add HKLM\SYSTEM\ControlSet001\Services\CscService /v Start /t REG_DWORD /d 4 /f        
reg.exe add HKLM\SYSTEM\ControlSet001\Services\ssh-agent /v Start /t REG_DWORD /d 4 /f         
reg.exe add HKLM\SYSTEM\ControlSet001\Services\AppReadiness /v Start /t REG_DWORD /d 4 /f      
reg.exe add HKLM\SYSTEM\ControlSet001\Services\tzautoupdate /v Start /t REG_DWORD /d 4 /f      
reg.exe add HKLM\SYSTEM\ControlSet001\Services\NfsClnt /v Start /t REG_DWORD /d 4 /f            
reg.exe add HKLM\SYSTEM\ControlSet001\Services\wisvc /v Start /t REG_DWORD /d 4 /f             
reg.exe add HKLM\SYSTEM\ControlSet001\Services\defragsvc /v Start /t REG_DWORD /d 2 /f         
reg.exe add HKLM\SYSTEM\ControlSet001\Services\VaultSvc /v Start /t REG_DWORD /d 2 /f          
reg.exe add HKLM\SYSTEM\ControlSet001\Services\SharedRealitySvc /v Start /t REG_DWORD /d 4 /f  
reg.exe add HKLM\SYSTEM\ControlSet001\Services\RetailDemo /v Start /t REG_DWORD /d 4 /f        
reg.exe add HKLM\SYSTEM\ControlSet001\Services\lltdsvc /v Start /t REG_DWORD /d 4 /f           
reg.exe add HKLM\SYSTEM\ControlSet001\Services\TrkWks /v Start /t REG_DWORD /d 4 /f             
reg.exe add HKLM\SYSTEM\ControlSet001\Services\AppIDSvc /v Start /t REG_DWORD /d 4 /f          
reg.exe add HKLM\SYSTEM\ControlSet001\Services\CryptSvc /v Start /t REG_DWORD /d 4 /f          
reg.exe add HKCU\SOFTWARE\Microsoft\InputPersonalization /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f                 
reg.exe add HKCU\SOFTWARE\Microsoft\InputPersonalization /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f                
reg.exe add HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore /v   HarvestContacts /t REG_DWORD /d 0 /f            
reg.exe add HKLM\SOFTWARE\Policies\Google\Chrome /v MetricsReportingEnabled /t REG_DWORD /d 0 /f               
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports /v PreventHandwritingErrorReports /t REG_DWORD /d 1 /f            
reg.exe add HKCU\Control Panel\International\User Profile /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f   
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors /v DisableLocation /t REG_DWORD /d 1 /f                
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors /v DisableLocationScripting /t REG_DWORD /d 1 /f       
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors /v DisableSensors /t REG_DWORD /d 1 /f                 
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors /v DisableWindowsLocationProvider /t REG_DWORD /d 1 /f                 
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\lfsvc /v Start /t REG_DWORD /d 4 /f         
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration /v Status /t REG_DWORD /d 0 /f  
reg.exe add HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions /v SensorPermissionState /t REG_DWORD /d 0 /f                 
reg.exe add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides /v SensorPermissionState /t REG_DWORD /d 0 /f   
reg.exe add HKLM\SYSTEM\ControlSet001\Services\DiagTrack /v Start /t REG_DWORD /d 4 /f         
reg.exe add HKLM\SYSTEM\ControlSet001\Services\diagsvc /v Start /t REG_DWORD /d 4 /f           
reg.exe add HKLM\SYSTEM\ControlSet001\Services\DPS /v Start /t REG_DWORD /d 4 /f               
reg.exe add HKLM\SYSTEM\ControlSet001\Services\WdiServiceHost /v Start /t REG_DWORD /d 4 /f    
reg.exe add HKLM\SYSTEM\ControlSet001\Services\WdiSystemHost /v Start /t REG_DWORD /d 4 /f     
reg.exe add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection /v AllowTelemetry /t REG_DWORD /d 00000000 /f               
reg.exe add HKLM\Software\Policies\Microsoft\Windows\DataCollection /v AllowTelemetry /t REG_DWORD /d 00000000 /f              
reg.exe add HKLM\SYSTEM\ControlSet001\Services\dmwappushsvc /v Start /t REG_DWORD /d 4 /f      
reg.exe add HKLM\SYSTEM\ControlSet001\Services\diagnosticshub.standardcollector.service /v Start /t REG_DWORD /d 4 /f          
reg.exe add HKLM\SYSTEM\ControlSet001\Services\TroubleshootingSvc /v Start /t REG_DWORD /d 4 /f                
reg.exe add HKLM\SYSTEM\ControlSet001\Services\DsSvc /v Start /t REG_DWORD /d 4 /f              
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat /v AITEnable /t REG_DWORD /d 0 /f               
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice /v Start /t REG_DWORD /d 4 /f              
reg.exe add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo /v Enabled /t REG_DWORD /d 0 /f     
reg.exe add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo /v Enabled /t REG_DWORD /d 0 /f     
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f             
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat /v DisableInventory /t REG_DWORD /d 1 /f        
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows /v CEIPEnable /t REG_DWORD /d 0 /f              
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\SQMClient /v CorporateSQMURL /t REG_SZ /d 0.0.0.0 /f 
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent /v DisableSoftLanding /t REG_DWORD /d 1 /f   
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0 /v NoActiveHelp /t REG_DWORD /d 1 /f        
reg.exe add HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener /v Start /t REG_DWORD /d 0 /f       
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener /v Start /t REG_DWORD /d 0 /f   
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger /v Start /t REG_DWORD /d 0 /f       
reg.exe add HKCU\SOFTWARE\Microsoft\Siuf\Rules /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f    
reg.exe add HKCU\SOFTWARE\Microsoft\Siuf\Rules /v PeriodInNanoSeconds /t REG_DWORD /d 0 /f      
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f     
reg.exe add HKCU\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0 /v NoExplicitFeedback /t REG_DWORD /d 1 /f  
reg.exe add HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences /v UsageTracking /t REG_DWORD /d 0 /f              
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer /v NoUseStoreOpenWith /t REG_DWORD /d 1 /f       
reg.exe add HKLM\SYSTEM\ControlSet001\Services\FrameServer /v Start /t REG_DWORD /d 4 /f       
reg.exe add HKCU\System\GameConfigStore /v GameDVR_FSEBehaviorMode /t REG_DWORD /d 2 /f        
reg.exe add HKCU\System\GameConfigStore /v GameDVR_HonorUserFSEBehaviorMode /t REG_DWORD /d 0 /f               
reg.exe add HKCU\System\GameConfigStore /v GameDVR_DXGIHonorFSEWindowsCompatible /t REG_DWORD /d 1 /f          
reg.exe add HKCU\System\GameConfigStore /v GameDVR_EFSEFeatureFlags /t REG_DWORD /d 0 /f        
reg.exe add HKLM\SYSTEM\ControlSet001\Control\PriorityControl /v Win32PrioritySeparation /t REG_DWORD /d fff55555 /f                 
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management /v FeatureSettingsOverride /t REG_DWORD /d 3 /f            
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f        
reg.exe add HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters /v EnablePrefetcher /t REG_DWORD /d 0 /f    
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters /v EnablePrefetcher /t REG_DWORD /d 0 /f                
reg.exe add HKLM\SYSTEM\ControlSet001\Control\Power /v HibernateEnabled /t REG_DWORD /d 0 /f   
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v HibernateEnabled /t REG_DWORD /d 0 /f                
reg.exe add HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVt\Channels\Microsoft-Windows-Superfetch/Main /v Enabled /t REG_DWORD /d 0 /f   
reg.exe add HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVt\Channels\Microsoft-Windows-Superfetch/PfApLog /v Enabled /t REG_DWORD /d 0 /f                
reg.exe add HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVt\Channels\Microsoft-Windows-Superfetch/StoreLog /v Enabled /t REG_DWORD /d 0 /f               
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management /v ClearPageFileAtShutdown /t REG_DWORD /d 0 /f             
reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled /v Value /t REG_SZ /d Deny /f    
reg.exe add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions /v CpuPriorityClass /t REG_DWORD /d 4 /f      
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers /v HwSchedMode /t REG_DWORD /d 2 /f          
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management /v LargeSystemCache /t REG_DWORD /d 1 /f   
reg.exe add HKCU\Control Panel\Mouse /v MouseHoverTime /t REG_SZ /d 0 /f       
reg.exe add HKCU\Control Panel\Mouse /v MouseSensitivity /t REG_SZ /d 10 /f     
reg.exe add HKU\.DEFAULT\Control Panel\Mouse /v MouseThreshold1 /t REG_SZ /d 0 /f              
reg.exe add HKU\.DEFAULT\Control Panel\Mouse /v MouseThreshold2 /t REG_SZ /d 0 /f              
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\mouhid\Parameters /v TreatAbsolutePointerAsAbsolute /t REG_DWORD /d 1 /f    
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\mouhid\Parameters /v TreatAbsoluteAsRelative /t REG_DWORD /d 0 /f          
reg.exe add HKCU\Control Panel\Mouse /v SmoothMouseXCurve /t REG_BINARY /d 000000000000000000a0000000000000004001000000000000800200000000000000050000000000 /f                 
reg.exe add HKCU\Control Panel\Mouse /v SmoothMouseYCurve /t REG_BINARY /d 000000000000000066a6020000000000cd4c050000000000a0990a00000000003833150000000000 /f                 
reg.exe add HKLM\SYSTEM\CurrentControlSet\Servicesmouclass\Parameters /v MouseDataQueueSize /t REG_DWORD /d 16 /f              
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters /v KeyboardDataQueueSize /t REG_DWORD /d 16 /f          
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management /v EnableCfg /t REG_DWORD /d 0 /f          
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management /v FeatureSettings /t REG_DWORD /d 1 /f                
reg.exe add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile /v NoLazyMode /t REG_DWORD /d 0 /f       
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\amdlog /v Start /t REG_DWORD /d 3 /f                  
reg.exe add HKLM\SYSTEM\ControlSet001\Services\TapiSrv /v Start /t REG_DWORD /d 3 /f           
reg.exe add HKLM\SYSTEM\ControlSet001\Services\FontCache3.0.0.0 /v Start /t REG_DWORD /d 3 /f   
reg.exe add HKLM\SYSTEM\ControlSet001\Services\WpcMonSvc /v Start /t REG_DWORD /d 3 /f         
reg.exe add HKLM\SYSTEM\ControlSet001\Services\SEMgrSvc /v Start /t REG_DWORD /d 2 /f          
reg.exe add HKLM\SYSTEM\ControlSet001\Services\PNRPsvc /v Start /t REG_DWORD /d 3 /f           
reg.exe add HKLM\SYSTEM\ControlSet001\Services\WEPHOSTSVC /v Start /t REG_DWORD /d 3 /f        
reg.exe add HKLM\SYSTEM\ControlSet001\Services\p2psvc /v Start /t REG_DWORD /d 3 /f            
reg.exe add HKLM\SYSTEM\ControlSet001\Services\p2pimsvc /v Start /t REG_DWORD /d 3 /f          
reg.exe add HKLM\SYSTEM\ControlSet001\Services\PhoneSvc /v Start /t REG_DWORD /d 3 /f 
reg.exe add HKLM\SYSTEM\ControlSet001\Services\Wecsvc /v Start /t REG_DWORD /d 3 /f            
reg.exe add HKLM\SYSTEM\ControlSet001\Services\RmSvc /v Start /t REG_DWORD /d 3 /f             
reg.exe add HKLM\SYSTEM\ControlSet001\Services\SensorDataService /v Start /t REG_DWORD /d 3 /f                 
reg.exe add HKLM\SYSTEM\ControlSet001\Services\SensrSvc /v Start /t REG_DWORD /d 3 /f          
reg.exe add HKLM\SYSTEM\ControlSet001\Services\perceptionsimulation /v Start /t REG_DWORD /d 3 /f              
reg.exe add HKLM\SYSTEM\ControlSet001\Services\StiSvc /v Start /t REG_DWORD /d 3 /f             
reg.exe add HKLM\SYSTEM\ControlSet001\Services\OneSyncSvc /v Start /t REG_DWORD /d 2 /f        
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc /v Start /t REG_DWORD /d 3 /f              
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc /v Start /t REG_DWORD /d 3 /f           
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\UnistoreSvc /v Start /t REG_DWORD /d 3 /f   
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc /v Start /t REG_DWORD /d 3 /f            
reg.exe add HKLM\SYSTEM\ControlSet001\Services\WMPNetworkSvc /v Start /t REG_DWORD /d 3  
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\CaptureService /v Start /t REG_DWORD /d 3 /f                
reg.exe add HKLM\SYSTEM\ControlSet001\Services\autotimesvc /v Start /t REG_DWORD /d 3 /f       
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\MessagingService /v Start /t REG_DWORD /d 3 /f              
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\CDPUserSvc /v Start /t REG_DWORD /d 2 /f     
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc /v Start /t REG_DWORD /d 3 /f        
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\BcastDVRUserService /v Start /t REG_DWORD /d 3 /f          
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\UserDataSvc /v Start /t REG_DWORD /d 3 /f   
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc /v Start /t REG_DWORD /d 3 /f    
reg.exe add HKLM\SYSTEM\ControlSet001\Services\edgeupdatem /v Start /t REG_DWORD /d 3 /f       
reg.exe add HKLM\SYSTEM\ControlSet001\Services\MicrosoftEdgeElevationService /v Start /t REG_DWORD /d 3 /f     
reg.exe add HKLM\SYSTEM\ControlSet001\Services\ALG /v Start /t REG_DWORD /d 3 /f                
reg.exe add HKLM\SYSTEM\ControlSet001\Services\IpxlatCfgSvc /v Start /t REG_DWORD /d 3 /f      
reg.exe add HKLM\SYSTEM\ControlSet001\Services\icssvc /v Start /t REG_DWORD /d 3 /f            
reg.exe add HKLM\SYSTEM\ControlSet001\Services\DusmSvc /v Start /t REG_DWORD /d 2 /f           
reg.exe add HKLM\SYSTEM\ControlSet001\Services\MapsBroker /v Start /t REG_DWORD /d 2 /f        
reg.exe add HKLM\SYSTEM\ControlSet001\Services\SensorService /v Start /t REG_DWORD /d 3 /f     
reg.exe add HKLM\SYSTEM\ControlSet001\Services\svsvc /v Start /t REG_DWORD /d 3 /f             
reg.exe add HKLM\SYSTEM\ControlSet001\Services\MSiSCSI /v Start /t REG_DWORD /d 3 /f           
reg.exe add HKLM\SYSTEM\ControlSet001\Services\Netlogon /v Start /t REG_DWORD /d 3 /f          
reg.exe add HKLM\SYSTEM\ControlSet001\Services\CscService /v Start /t REG_DWORD /d 3 /f        
reg.exe add HKLM\SYSTEM\ControlSet001\Services\AppReadiness /v Start /t REG_DWORD /d 3 /f      
reg.exe add HKLM\SYSTEM\ControlSet001\Services\wisvc /v Start /t REG_DWORD /d 3 /f             
reg.exe add HKLM\SYSTEM\ControlSet001\Services\lltdsvc /v Start /t REG_DWORD /d 3 /f           
reg.exe add HKLM\SYSTEM\ControlSet001\Services\TrkWks /v Start /t REG_DWORD /d 2 /f            
reg.exe add HKLM\SYSTEM\ControlSet001\Services\AppIDSvc /v Start /t REG_DWORD /d 3 /f          
reg.exe add HKLM\SYSTEM\ControlSet001\Services\CryptSvc /v Start /t REG_DWORD /d 2 /f          
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors /v DisableLocation /t REG_DWORD /d 0 /f                
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors /v DisableLocationScripting /t REG_DWORD /d 0 /f       
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors /v DisableSensors /t REG_DWORD /d 0 /f                 
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors /v DisableWindowsLocationProvider /t REG_DWORD /d 0 /f                 
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\lfsvc /v Start /t REG_DWORD /d 3 /f         
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration /v Status /t REG_DWORD /d 1 /f  
reg.exe add HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions /v SensorPermissionState /t REG_DWORD /d 1 /f                 
reg.exe add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides /v SensorPermissionState /t REG_DWORD /d 1 /f   
reg.exe add HKLM\SYSTEM\ControlSet001\Services\DiagTrack /v Start /t REG_DWORD /d 3 /f         
reg.exe add HKLM\SYSTEM\ControlSet001\Services\diagsvc /v Start /t REG_DWORD /d 3 /f           
reg.exe add HKLM\SYSTEM\ControlSet001\Services\dmwappushsvc /v Start /t REG_DWORD /d 3 /f      
reg.exe add HKLM\SYSTEM\ControlSet001\Services\diagnosticshub.standardcollector.service /v Start /t REG_DWORD /d 3 /f          
reg.exe add HKLM\SYSTEM\ControlSet001\Services\TroubleshootingSvc /v Start /t REG_DWORD /d 3 /f                
reg.exe add HKLM\SYSTEM\ControlSet001\Services\DsSvc /v Start /t REG_DWORD /d 3 /f             
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice /v Start /t REG_DWORD /d 3 /f              
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer /v NoUseStoreOpenWith /t REG_DWORD /d 0 /f       
reg.exe add HKLM\SYSTEM\ControlSet001\Services\FrameServer /v Start /t REG_DWORD /d 3 /f       
reg.exe add HKCU\System\GameConfigStore /v GameDVR_Enabled /t REG_DWORD /d 1 /f                
reg.exe add HKLM\Software\Policies\Microsoft\Windows /v AllowGameDVR /t REG_DWORD /d 1 /f      
reg.exe add HKLM\SYSTEM\ControlSet001\Control\PriorityControl /v Win32PrioritySeparation /t REG_DWORD /d 28 /f                 
reg.exe add HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters /v EnablePrefetcher /t REG_DWORD /d 1 /f    
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters /v EnablePrefetcher /t REG_DWORD /d 1 /f                
reg.exe add HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVt\Channels\Microsoft-Windows-Superfetch/Main /v Enabled /t REG_DWORD /d 1 /f    
reg.exe add HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVt\Channels\Microsoft-Windows-Superfetch/PfApLog /v Enabled /t REG_DWORD /d 1 /f                
reg.exe add HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVt\Channels\Microsoft-Windows-Superfetch/StoreLog /v Enabled /t REG_DWORD /d 1 /f               
reg.exe add HKLM\SYSTEM\CurrentControlSet\Servicesmouclass\Parameters /v MouseDataQueueSize /t REG_DWORD /d 100 /f             
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters /v KeyboardDataQueueSize /t REG_DWORD /d 100 /f          
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management /v FeatureSettingsOverride /t REG_DWORD /d 2 /f            
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management /v FeatureSettingsOverrideMask /t REG_DWORD /d 2 /f 
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Application Name" /t REG_SZ /d "fortniteclient-win64-shipping.exe" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "DSCP value" /t REG_SZ /d "46" /f 
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Local IP" /t REG_SZ /d "*" /f 
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Local IP Prefix Length" /t REG_SZ /d "*" /f 
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Local Port" /t REG_SZ /d "*" /f 
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Protocol" /t REG_SZ /d "UDP" /f 
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Remote IP" /t REG_SZ /d "*" /f 
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Remote IP Prefix Length" /t REG_SZ /d "*" /f 
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Remote Port" /t REG_SZ /d "*" /f 
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "throttle Rate" /t REG_SZ /d "-1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "version" /t REG_SZ /d "1.0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c" /v "ValueMax" /t REG_DWORD /d "100" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ValueMax" /t REG_DWORD /d "100" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "VsyncIdleTimeout" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\Intel\GMM" /v "DedicatedSegmentSize" /t REG_DWORD /d "1298" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "2" /f 
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f 
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "2" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBoottrace" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f  
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMftZoneReservation" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisable8dot3NameCreation" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "DontVerifyRandomDrivers" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisableLastAccessUpdate" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "ContigFileAllocSize" /t REG_DWORD /d "64" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "5000" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1000" /f  
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "4000" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_SZ /d "150000" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "FpsAll" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "GameFluidity" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "FpsStatusGames" /t REG_DWORD /d "16" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "FpsStatusGamesAll" /t REG_DWORD /d "4" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "2" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Affinity" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Background Only" /t REG_SZ /d "False" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Clock Rate" /t REG_DWORD /d "10000" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "GPU Priority" /t REG_DWORD /d "8" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Priority" /t REG_DWORD /d "2" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Scheduling Category" /t REG_SZ /d "High" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "SFIO Priority" /t REG_SZ /d "High" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Latency Sensitive" /t REG_SZ /d "True" /f 
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "CPUPriority" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d "Off" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d "Highly Restricted" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d "Restricted" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d "Normal" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Application DSCP Marking Request" /t REG_SZ /d "Ignored" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Application DSCP Marking Request" /t REG_SZ /d "Allowed" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\QoS" /v "Do not use NLA" /t REG_SZ /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableUserTOSSetting" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "CorpLocationProbeTimeout" /t REG_DWORD /d "30" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "LdapTimeoutMs" /t REG_DWORD /d "5000" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "ShowDomainEndpointInterfaces" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "EnableNoGatewayLocationDetection" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "MinimumInternetHopCount" /t REG_DWORD /d "2" /f   
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\NVAPI" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f    
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "TimeStampInterval" /t REG_DWORD /d "0" /f    
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Diagnostics\Performance" /F /V "DisableDiagnosticTracing" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /F /V "EventProcessorEnabled" /T REG_DWORD /d 0  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /F /V "MonitorLatencyTolerance" /T REG_DWORD /d 0  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /F /V "MonitorRefreshLatencyTolerance" /T REG_DWORD /d 0  
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop" /F /V "MenuShowDelay" /T REG_SZ /d 0  
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /F /V "MouseSensitivity" /T REG_SZ /d 0  
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /F /V "SmoothMouseXCurve" /T REG_BINARY /d 0000000000000000C0CC0C0000000000809919000000000040662600000000000033330000000000  
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /F /V "SmoothMouseYCurve" /T REG_BINARY /d 0000000000000000000038000000000000007000000000000000A800000000000000E00000000000  
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /F /V "MouseSpeed" /T REG_SZ /d 0  
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /F /V "MouseThreshold1" /T REG_SZ /d 0  
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /F /V "MouseThreshold2" /T REG_SZ /d 0  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "ConvertibleSlateMode" /t REG_DWORD /d "0" /f  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "40" /f  
REG ADD "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Update" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f  
REG ADD "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Update" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f  
REG ADD "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Update\ExcludeWUDriversInQualityUpdate" /v "value" /t REG_DWORD /d "1" /f      
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "3" /f   
reg add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "0" /f reg add "HKCU\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d "2" /f   
reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9012038010020000" /f   
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f   
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShellState" /t REG_BINARY /d "240000003E28000000000000000000000000000001000000130000000000000072000000" /f   
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "1" /f   
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "0" /f   
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f   
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f  
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogEnable" /t REG_DWORD /d "0" /f reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogLevel" /t REG_DWORD /d "0" /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f   
reg add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f   
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" /v "CorporateSQMURL" /t REG_SZ /d "0.0.0.0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "16" /f reg add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "16" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "0" /f    
for /f %%a in ('wmic PATH Win32_PnPEntity GET DeviceID ^| findstr /l "USB\VID_"') do (  
C:\Windows\SetACL.exe -on "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" -ot reg -actn setowner -ownr "n:Administrators"  
C:\Windows\SetACL.exe -on "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" -ot reg -actn ace -ace "n:Administrators;p:full"  
reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v SelectiveSuspendOn /t REG_DWORD /d 00000000 /f  
reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v SelectiveSuspendEnabled /t REG_BINARY /d 00 /f  
reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v EnhancedPowerManagementEnabled /t REG_DWORD /d 00000000 /f  
reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v AllowIdleIrpInD3 /t REG_DWORD /d 00000000 /f  
)  
for /f %%a in ('wmic PATH Win32_USBHub GET DeviceID ^| findstr /l "USB\ROOT_HUB"') do (  
C:\Windows\SetACL.exe -on "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters\WDF" -ot reg -actn setowner -ownr "n:Administrators"  
reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 00000000 /f  
)    
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 3 /f reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f    
netsh interface teredo set state disabled  
netsh interface 6to4 set state disabled  
netsh winsock reset  
netsh int isatap set state disable  
netsh int ip set global taskoffload=disabled  
netsh int ip set global neighborcachelimit=4096  
netsh int tcp set global timestamps=disabled  
netsh int tcp set heuristics disabled  
netsh int tcp set global autotuninglevel=disable  
netsh int tcp set global chimney=disabled  
netsh int tcp set global ecncapability=disabled  
netsh int tcp set global rss=enabled  
netsh int tcp set global rsc=disabled  
netsh int tcp set global dca=enabled  
netsh int tcp set global netdma=enabled  
netsh int tcp set global nonsackrttresiliency=disabled  
netsh int tcp set security mpp=disabled  
netsh int tcp set security profiles=disabled  
netsh int ip set global icmpredirects=disabled  
netsh int tcp set security mpp=disabled profiles=disabled  
netsh int ip set global multicastforwarding=disabled  
PowerShell Disable-NetAdapterLso -Name "*"  
powershell "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction SilentlyContinue}"  
powershell "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterLso -Name $adapter.Name -ErrorAction SilentlyContinue}"   
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "32" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "8760" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "8760" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_SZ /d "ffffffff" /f      
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Application Name" /t REG_SZ /d "fortniteclient-win64-shipping.exe" /f   
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "DSCP value" /t REG_SZ /d "46" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Local IP" /t REG_SZ /d "*" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Local IP Prefix Length" /t REG_SZ /d "*" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Local Port" /t REG_SZ /d "*" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Protocol" /t REG_SZ /d "UDP" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Remote IP" /t REG_SZ /d "*" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Remote IP Prefix Length" /t REG_SZ /d "*" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Remote Port" /t REG_SZ /d "*" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "throttle Rate" /t REG_SZ /d "-1" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "version" /t REG_SZ /d "1.0" /f  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\pci\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\rt640x64\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\storahci\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\USBXHCI\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\pci\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f 