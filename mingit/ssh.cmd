@ECHO OFF
@SET "config=%~dp0..\etc\ssh\ssh_config"
@ICACLS "%config%" /inheritance:r >NUL
@IF ERRORLEVEL 1 @EXIT /B 1
@ICACLS "%config%" /remove:g "*S-1-5-11" "*S-1-5-32-545" "*S-1-1-0" >NUL
@IF ERRORLEVEL 1 @EXIT /B 1
@ICACLS "%config%" /grant:r "%USERNAME%:F" "*S-1-5-18:F" "*S-1-5-32-544:F" >NUL
@IF ERRORLEVEL 1 @EXIT /B 1
@"%~dp0..\usr\bin\ssh.exe" %*
