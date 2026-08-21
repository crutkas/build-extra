@REM This script is intended to be run after installation of Git for Windows
@REM (including the portable version)

@REM If run manually, it should be run via
@REM   git-bash.exe --no-needs-console --hide --no-cd --command=post-install.bat
@REM to hide the console.

@REM Change to the directory in which this script lives.
@REM https://technet.microsoft.com/en-us/library/bb490909.aspx says:
@REM <percent>~dpI Expands <percent>I to a drive letter and path only.
@REM <percent>~fI Expands <percent>I to a fully qualified path name.
@FOR /F "delims=" %%D IN ("%~dp0") DO @CD %%~fD

@SET /A "version=0" & FOR /F "tokens=2 delims=[]" %%i IN ('"VER"') DO @(
	@FOR /F "tokens=2 delims=. " %%v IN ("%%~i") DO @(
		@SET /A "version=%%~v + 0"
	)
)

@REM If this is a 32-bit Git for Windows, adjust the DLL address ranges.
@REM We cannot use %PROCESSOR_ARCHITECTURE% for this test because it is
@REM allowed to install a 32-bit Git for Windows into a 64-bit system.
@IF EXIST mingw32\bin\git.exe @(
	@REM We need to rebase just to make sure that it still works even with
	@REM 32-bit Windows 10
	@IF %version% GEQ 10 @(
		@REM We copy `rebase.exe` because it links to `msys-2.0.dll`
		@REM (and @REM thus prevents modifying it). It is okay to
		@REM execute `rebase.exe`, though, because the DLL base address
		@REM problems only really show when other processes are
		@REM `fork()`ed and `rebase.exe` does no such thing.
		@IF NOT EXIST bin\rebase.exe @(
			@IF NOT EXIST bin @MKDIR bin
			@COPY usr\bin\rebase.exe bin\rebase.exe
		)
		@IF NOT EXIST bin\msys-2.0.dll @(
			@COPY usr\bin\msys-2.0.dll bin\msys-2.0.dll
		)
		@bin\rebase.exe -b 0x64000000 usr\bin\msys-2.0.dll
	)

	usr\bin\dash.exe -c '/usr/bin/dash usr/bin/rebaseall -p'
)

@IF EXIST clangarm64\bin\busybox.exe @IF EXIST clangarm64\bin\busybox-shim.exe @IF EXIST etc\arm64-busybox-aliases.txt @(
	@SET "busybox_alias_failed="
	@FOR /F "usebackq delims=" %%P IN ("etc\arm64-busybox-aliases.txt") DO @(
		@DEL /F /Q "usr\bin\%%P" 2>NUL
		@IF "%GFW_ARM64_BUSYBOX_FORCE_COPY%" == "1" @(
			@COPY /Y "clangarm64\bin\busybox-shim.exe" "usr\bin\%%P" >NUL || @SET "busybox_alias_failed=1"
		) ELSE @(
			@MKLINK /H "usr\bin\%%P" "clangarm64\bin\busybox-shim.exe" >NUL 2>&1 || @COPY /Y "clangarm64\bin\busybox-shim.exe" "usr\bin\%%P" >NUL || @SET "busybox_alias_failed=1"
		)
	)
)
@echo "running post-install"
@REM Run the post-install scripts
@IF EXIST usr\bin\bash.exe (
	@usr\bin\bash.exe --norc -c "export PATH=/usr/bin:$PATH; export SYSCONFDIR=/etc; for p in $(export LC_COLLATE=C; echo /etc/post-install/*.post); do test -e \"$p\" && . \"$p\"; done"
) ELSE (
	@bin\bash.exe --norc -c "export PATH=/usr/bin:$PATH; export SYSCONFDIR=/etc; for p in $(export LC_COLLATE=C; echo /etc/post-install/*.post); do test -e \"$p\" && . \"$p\"; done"
)

@REM Win32 OpenSSH rejects system configuration writable by other users.
@IF NOT EXIST clangarm64\bin\git.exe @GOTO cleanup
@IF EXIST unins000.exe @GOTO cleanup
@IF NOT EXIST etc\ssh\ssh_config @GOTO cleanup
@ICACLS etc\ssh\ssh_config /inheritance:r >NUL
@IF ERRORLEVEL 1 @EXIT /B 1
@ICACLS etc\ssh\ssh_config /remove:g "*S-1-5-11" "*S-1-5-32-545" "*S-1-1-0" >NUL
@IF ERRORLEVEL 1 @EXIT /B 1
@ICACLS etc\ssh\ssh_config /grant:r "*S-1-5-11:R" "*S-1-5-18:F" "*S-1-5-32-544:F" >NUL
@IF ERRORLEVEL 1 @EXIT /B 1

:cleanup
@REM Unset environment variables set by this script
@SET "version="

@IF DEFINED busybox_alias_failed @(
	@DEL post-install.bat
	@EXIT /B 1
)

@REM Remove this script
@DEL post-install.bat
