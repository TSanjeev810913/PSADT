Add Registry Key

```
Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Olinda_0' -Name 'NoRemove' -Value '1' -Type Dword

Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Olinda_0' -Name 'NoModify' -Value '1'   -Type Dword![image](https://github.com/user-attachments/assets/29f83cbe-2fb0-4658-843f-57a18d7bf5a0)
```
Add Reg Key for All users
```
Remove-RegistryKey -Key "HKCU\Software\Test" -SID $UserProfile.SID -Recurse
Remove-RegistryKey -Key "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Merck\eCore\Software\$MerckPackageName"
```
Kill Task
```
Stop-Process -Name msedge -Force
taskkill /IM Olinda.exe /F![image](https://github.com/user-attachments/assets/a7440f90-c778-4dc2-af1a-386e235b5887)
```
Start Sleep
`
Start-Sleep -Seconds 120
`
Executing EXE in PSADT
```
$EXENAME_I = "Embedded_Box_PC_3000_1.17.0.exe"
$EXEPARAM_I = "/s /noreboot /l=`"C:\Core\Log\WATERSEmpower_eLACEBIOSUpdate_117_1000_Install.LOG`""

Execute-Process -Path "$EXENAME_I" -Parameters "$EXEPARAM_I" -WindowStyle 'Hidden' -IgnoreExitCodes '3,2'
```
Import Registry
```
REGEDIT.exe /s "$dirFiles\LIMS_DEV_SQL.reg" 
REGEDIT.exe /s "$dirFiles\ODBC Data Sources.reg"
```
To check whether a system is 32 or 64 bit
```
If (Test-Path "$ENV:PROCESSOR_ARCHITECTURE -eq 'x86'")
            {
            Write-Log -Message "Detected 32-bit OS Architecture" -Severity 1 -Source $deployAppScriptFriendlyName
            Execute-MSI -Action 'Install' -Path "$MSINAME_X86"
            Remove-File -Path "$env:public\desktop\BIOVIA Draw 2021.lnk"
            }
        else
            {
            Write-Log -Message "Detected 64-bit OS Architecture" -Severity 1 -Source $deployAppScriptFriendlyName
            #Execute-MSI -Action 'Install' -Path "$MSINAME_X64"
            Execute-MSI -Action 'Install' -Path "$MSINAME_X86"
            Remove-File -Path "$env:public\desktop\BIOVIA Draw 2021.lnk"
            }
```
TO Check if it’s a server or a client
```
$RegCheck = Get-RegistryKey -Key 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Value 'InstallationType'

        if($RegCheck -eq 'Server') { }
```
To Get Installed App name(PSADT)
```
if (Get-InstalledApplication -Name 'SoftMax Pro 7.1.2 GxP')
```
Import Trust Cert 
```
Import-Certificate "$dirFiles\data\drivers\BeckmanTrust.cer" -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
```
REMOVE CERTIFICATE
```
Get-ChildItem Cert:\LocalMachine\TrustedPublisher | Where-Object { $_.Subject -match 'Agrident GmbH' } | Remove-Item
```
Install Driver
```
Execute-Process -Path "$dirFiles\data\DPInst_64.exe" -Parameters "/A /SW /SE /PATH `"$dirFiles\data\drivers"` -WindowStyle Hidden 
```
Uninstall Driver
```
Execute-Process -Path "$dirFiles\prerequisites\drivers\DPInst_64.exe" -Parameters "/U `"C:\Windows\System32\DriverStore\FileRepository\thermo-cdc-acm.inf_amd64_ff5924ef39de2ce3\thermo-cdc-acm.inf`" /S /d" -WindowStyle Hidden![image](https://github.com/user-attachments/assets/b2621168-ffc1-495b-b19f-10794d428e87)
```
To Startup/Execute any file after restart
```
Copy-File -Path "$dirFiles\PhoenixLicense.bat" -Destination "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\PhoenixLicense.bat" 
```
Install FONTS through PS
```
Source = "$dirSupportFiles\*"
        $dest = (New-Object -ComObject Shell.Application).NameSpace(0x14)

        Get-ChildItem -Path $Source -Include '*.ttf' -Recurse | Foreach {
        $dest.CopyHere($_.FullName,0x10)
        }
```
SETTING PERMISSIONS
```
$acl_to_modify = "C:\LabWare-8\APP"
Invoke-Expression -Command:'icacls.exe $acl_to_modify /grant "AHLIMS-DEV-USERS:(OI)(CI)(R,X)"'
```
#setting permission(use this for full permissions)
```
$acl_to_modify = "$envProgramFiles\MODA_US_GLOBAL\Master Client Files - UAT"
Invoke-Expression -Command:'icacls.exe $acl_to_modify /grant "Users:(OI)(CI)F"'![image](https://github.com/user-attachments/assets/dcdd23b3-06ed-46d0-a13b-f8db9c163299)
```
To Copy a File or Folder to all User %Appdata%(This is extract example)
```
$sourcepath="C:\Core\Install\Pkg\Files\Atlassian.zip"
        
        $users=Get-ChildItem -Path "C:\Users\" -Directory
        $arguments2= "X `"$sourcepath`" -y -O`"$destinationfolder`""
        foreach ($user in $users)
        {
            $destinationfolder=Join-Path -Path $user.FullName -ChildPath "AppData\Local"
            Start-Process -FilePath $7zPath -ArgumentList $arguments2 -Wait -WindowStyle Hidden
            #Copy-Item -Path $sourcepath -Destination $destinationfolder -Recurse -Force
        }
```
A different approact for file permission
```
Setting Folder permissions
& icacls "${env:ProgramFiles(x86)}\tibco_6_8_1\studio\4.0\eclipse\configuration\config.ini" /inheritance:e

Execute-Process -Path "cacls" -Parameters "`"$envSystemDrive\Oracle`" /E /T /C /G `"Users`":R" -WindowStyle 'Hidden'
```
7-ZIP Extraction
```
$sourcepath="$dirFiles\SIMU3D_CHEVILLOT.zip"
        
$extractPath="$envSystemDrive\FAGORCNC\Configuration\"
       
$7zPath="$dirFiles\7-zip\7z.exe"

$arguments= "X `"$zipPath`" -y -O`"$extractPath`""

Start-Process -FilePath $7zPath -ArgumentList $arguments -Wait -WindowStyle Hidden![image](https://github.com/user-attachments/assets/2e945271-4877-48ac-9376-f06798849e08)
```
NSTALL FONT
```
Copy-File -Path "$dirSupportFiles\Fonts\*.ttf" -Destination "$envWinDir\fonts\"
Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts' -Name 'Embosser MS (TrueType)' -Value 'EmbosserMS.ttf' -Type String![image](https://github.com/user-attachments/assets/69fe4b95-4573-4e5e-b5be-9e5c3f0c3950)
```
MOUNT ISO to a SPECIFIC DRIVELETTER:
```
$driveletter = "E:"
        $MountResult = Mount-DiskImage -ImagePath "$dirFiles\aspenONE_V14_ENG.iso" -NoDriveLetter
        $MountDriveletter = $MountResult | Get-Volume | Select-Object -ExpandProperty "DriveLetter"
        $volInfo = $MountResult | Get-Volume
        mountvol $driveletter
```
```
Dismount-DiskImage -ImagePath "Path to ISO"
```
MESSAGE PROMPT
```
Show-InstallationPrompt -Message 'In order for the Installation to complete, you must restart your computer. Please save your work and restart your machine.' -ButtonRightText 'OK' -Icon Information -NoWait![image](https://github.com/user-attachments/assets/4b4bebba-35e1-4ec3-a47c-eff4eb870530)
```
EXECUTE PS inside PSADT
```
Execute-Process -Path "$envSystemDrive\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -Parameters "-ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File `"$envSystemDrive\SoftMax Pro GxP Components\Examples\ClientInstall.ps1`"
```





