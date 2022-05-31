del *.log /a /s /q /f
/s /f /q c:\windows\temp\*.*
rd /s /q c:\windows\temp
md c:\windows\temp
del /s /f /q C:\WINDOWS\Prefetch
del /s /f /q %temp%\*.*
rd /s /q %temp%
md %temp%
deltree /y c:\windows\tempor~1
deltree /y c:\windows\temp
deltree /y c:\windows\tmp
deltree /y c:\windows\ff*.tmp
deltree /y c:\windows\history
deltree /y c:\windows\cookies
deltree /y c:\windows\recent
deltree /y c:\windows\spool\printers
del c:\WIN386.SWP 
FOR /F "tokens=1, 2 * " %%V IN ('bcdedit') DO SET adminTest=%%V
IF (%adminTest%)==(Access) goto noAdmin
for /F " tokens=*" %%G in ('wevtutil.exe el') DO (call :do_clear "%%G")
RD /S /Q %temp%
MKDIR %temp%
takeown /f "%temp%" /r /d y
takeown /f "C:\Windows\Temp" /r /d y
RD /S /Q C:\Windows\Temp
MKDIR C:\Windows\Temp
takeown /f "C:\Windows\Temp" /r /d y
takeown /f %temp% /r /d y
del /f /s /q %systemdrive%\*.tmp
del /f /s /q %systemdrive%\*._mp
del /f /s /q %systemdrive%\*.log
del /f /s /q %systemdrive%\*.gid
del /f /s /q %systemdrive%\*.chk
del /f /s /q %systemdrive%\*.old
del /f /s /q %systemdrive%\recycled\*.*
del /f /s /q %windir%\*.bak
del /f /s /q %windir%\prefetch\*.*
rd /s /q %windir%\temp & md %windir%\temp
del /f /q %userprofile%\cookies\*.*
del /f /q %userprofile%\recent\*.*
del /f /s /q “%userprofile%\Local Settings\Temporary Internet Files\*.*”
del /f /s /q “%userprofile%\Local Settings\Temp\*.*”
del /f /s /q “%userprofile%\recent\*.*”
takeown /f %LocalAppData%\Microsoft\Windows\Explorer\ /r /d y
takeown /f %%G\AppData\Local\Temp\ /r /d y
takeown /f %SystemRoot%\TEMP\ /r /d y
takeown /f %systemdrive%\$Recycle.bin\ /r /d y
takeown /f C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Code Cache\ /r /d y
takeown /f C:\Users\%USERNAME%\AppData\Local\Fortnitegame\saved\ /r /d y
takeown /f C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\Default\Code Cache\ /r /d y
del /q /s %systemdrive%\$Recycle.bin\*
for /d %%x in (%systemdrive%\$Recycle.bin\*) do @rd /s /q "%%x"
powershell.exe Remove-Item -Path $env:TEMP -Recurse -Force -ErrorAction SilentlyContinue
erase /F /S /Q "%SystemRoot%\TEMP*.*"
for /D %%G in ("%SystemRoot%\TEMP*") do RD /S /Q "%%G"
for /D %%G in ("%SystemDrive%\Users*") do erase /F /S /Q "%%G\AppData\Local\Temp*.*"
for /D %%G in ("%SystemDrive%\Users*") do RD /S /Q "%%G\AppData\Local\Temp\" 
set BraveDir=C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Code Cache\Js
del /s /Q /f "%BraveDir%"
rd /s /q "%BraveDir%"
set AppleDir=C:\ProgramData\Apple\Installer Cache
del /s /Q /f "%AppleDir%"
rd /s /q "%AppleDir%"
tasklist /fi "ImageName eq chrome.exe" /fo csv 2>NUL | find /I "chrome.exe">NUL
set ChromeDir=C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\Default\Code Cache\Js
del /s /Q /f "%ChromeDir%"> nul
rd /s /q "%ChromeDir%"> nul
set FortDir=C:\Users\%USERNAME%\AppData\Local\Fortnitegame\saved\Logs
del /s /Q /f "%FortDir%"> nul
rd /s /q "%FortDir%"> nul
set EpicDir=C:\Users\%USERNAME%\AppData\Local\EpicGamesLauncher\Saved\Logs
del /s /Q /f "%EpicDir%"> nul
rd /s /q "%EpicDir%"> nul
set EbicDir=C:\Users\%USERNAME%\AppData\Local\EpicGamesLauncher\Saved\Crashes
del /s /Q /f "%EbicDir%"> nul
rd /s /q "%EbicDir%"> nul
cd/  
Invoke-Command COMPUTERNAME -command{Stop-Process -ProcessName Explorer}  
Invoke-Command COMPUTERNAME -command{Start-Process -ProcessName Explorer}  
powershell Start explorer.exe   
rd /s /q C:\Windows\SoftwareDistribution  
md C:\Windows\SoftwareDistribution
takeown /f %systemdrive%\$Recycle.bin\ /r /d y 