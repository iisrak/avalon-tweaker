bcdedit /deletevalue allowedinmemorysettings    
bcdedit /deletevalue avoidlowmemory    
bcdedit /deletevalue bootems    
bcdedit /deletevalue bootlog     
bcdedit /deletevalue bootmenupolicy    
bcdedit /deletevalue bootux    
bcdedit /deletevalue configaccesspolicy    
bcdedit /deletevalue configflags    
bcdedit /deletevalue debug    
bcdedit /deletevalue disabledynamictick     
bcdedit /deletevalue disableelamdrivers     
bcdedit /deletevalue ems    
bcdedit /deletevalue extendedinput     
bcdedit /deletevalue firstmegabytepolicy    
bcdedit /deletevalue forcefipscrypto    
bcdedit /deletevalue forcelegacyplatform    
bcdedit /deletevalue graphicsmodedisabled    
bcdedit /deletevalue halbreakpoint    
bcdedit /deletevalue highestmode     
bcdedit /deletevalue hypervisorlaunchtype    
bcdedit /deletevalue integrityservices    
bcdedit /deletevalue isolatedcontext    
bcdedit /deletevalue nointegritychecks    
bcdedit /deletevalue nolowmem     
bcdedit /deletevalue noumex     
bcdedit /deletevalue nx    
bcdedit /deletevalue onecpu    
bcdedit /deletevalue pae    
bcdedit /deletevalue perfmem    
bcdedit /deletevalue quietboot     
bcdedit /deletevalue sos     
bcdedit /deletevalue testsigning    
bcdedit /deletevalue tpmbootentropy    
bcdedit /deletevalue tscsyncpolicy    
bcdedit /deletevalue usephysicaldestination    
bcdedit /deletevalue useplatformclock    
bcdedit /deletevalue useplatformtick     
bcdedit /deletevalue vm    
bcdedit /deletevalue vsmlaunchtype    
bcdedit /deletevalue useplatformclock    
bcdedit /deletevalue useplatformclock    
bcdedit /set disabledynamictick yes    
bcdedit /set useplatformtick yes    
bcdedit /timeout 0    
bcdedit /set nx optout    
bcdedit /set bootux disabled    
bcdedit /set bootmenupolicy standard    
bcdedit /set hypervisorlaunchtype off    
bcdedit /set tpmbootentropy ForceDisable    
bcdedit /set quietboot yes    
bcdedit /set {globalsettings} custom:16000067 true    
bcdedit /set {globalsettings} custom:16000069 true    
bcdedit /set {globalsettings} custom:16000068 true    
bcdedit /set highestmode Yes     
bcdedit /set onecpu No     
bcdedit /set forcefipscrypto No