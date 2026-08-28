@ECHO OFF
@SET "config=%~dp0..\etc\ssh\ssh_config"
@ICACLS "%config%" /inheritance:r >NUL
@ICACLS "%config%" /remove:g "*S-1-5-11" "*S-1-5-32-545" "*S-1-1-0" >NUL
@ICACLS "%config%" /grant:r "*S-1-5-11:R" "*S-1-5-18:F" "*S-1-5-32-544:F" >NUL
@"%~dp0..\usr\bin\ssh.exe" %*
