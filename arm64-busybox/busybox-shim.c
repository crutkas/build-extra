#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>

static WCHAR module_path[32768];

static __declspec(noinline) void zero_memory(void *buffer, SIZE_T size)
{
	volatile BYTE *p = buffer;

	while (size--)
		*p++ = 0;
}

static void fail(const char *message)
{
	DWORD written;
	HANDLE stderr_handle = GetStdHandle(STD_ERROR_HANDLE);

	WriteFile(stderr_handle, message, (DWORD)lstrlenA(message), &written, NULL);
	ExitProcess(126);
}

static WCHAR *find_last_separator(WCHAR *path)
{
	WCHAR *last = NULL;

	for (; *path; path++)
		if (*path == L'\\' || *path == L'/')
			last = path;
	return last;
}

static WCHAR *skip_program_name(WCHAR *command_line)
{
	if (*command_line == L'"') {
		command_line++;
		while (*command_line && *command_line != L'"')
			command_line++;
		if (*command_line == L'"')
			command_line++;
	} else {
		while (*command_line && *command_line != L' ' &&
		       *command_line != L'\t')
			command_line++;
	}
	return command_line;
}

void WINAPI wWinMainCRTStartup(void)
{
	static const WCHAR suffix[] = L"\\clangarm64\\bin\\busybox.exe";
	WCHAR applet[64], *separator, *remainder;
	WCHAR *child_command_line;
	DWORD module_length, exit_code = 126;
	SIZE_T command_length;
	STARTUPINFOW startup;
	PROCESS_INFORMATION process;
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limits;
	HANDLE job = NULL;
	int i;

	module_length = GetModuleFileNameW(NULL, module_path,
					  ARRAYSIZE(module_path));
	if (!module_length || module_length >= ARRAYSIZE(module_path))
		fail("busybox-shim: could not determine the executable path\n");

	separator = find_last_separator(module_path);
	if (!separator || lstrlenW(separator + 1) >= ARRAYSIZE(applet))
		fail("busybox-shim: invalid executable path\n");
	lstrcpyW(applet, separator + 1);

	*separator = L'\0';
	separator = find_last_separator(module_path);
	if (!separator)
		fail("busybox-shim: invalid usr/bin path\n");
	*separator = L'\0';
	separator = find_last_separator(module_path);
	if (!separator)
		fail("busybox-shim: invalid installation root\n");
	*separator = L'\0';
	if (lstrlenW(module_path) + ARRAYSIZE(suffix) >=
	    ARRAYSIZE(module_path))
		fail("busybox-shim: installation path is too long\n");
	lstrcatW(module_path, suffix);

	remainder = skip_program_name(GetCommandLineW());
	command_length = lstrlenW(applet) + lstrlenW(remainder) + 4;
	child_command_line = HeapAlloc(GetProcessHeap(), 0,
				       command_length * sizeof(WCHAR));
	if (!child_command_line)
		fail("busybox-shim: out of memory\n");
	child_command_line[0] = L'"';
	lstrcpyW(child_command_line + 1, applet);
	i = lstrlenW(child_command_line);
	child_command_line[i++] = L'"';
	lstrcpyW(child_command_line + i, remainder);

	zero_memory(&startup, sizeof(startup));
	zero_memory(&process, sizeof(process));
	zero_memory(&job_limits, sizeof(job_limits));
	startup.cb = sizeof(startup);
	startup.dwFlags = STARTF_USESTDHANDLES;
	startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);

	if (!CreateProcessW(module_path, child_command_line, NULL, NULL, TRUE,
			    CREATE_SUSPENDED, NULL, NULL, &startup, &process))
		fail("busybox-shim: could not start busybox.exe\n");

	job = CreateJobObjectW(NULL, NULL);
	if (job) {
		job_limits.BasicLimitInformation.LimitFlags =
			JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
		if (!SetInformationJobObject(job,
					    JobObjectExtendedLimitInformation,
					    &job_limits, sizeof(job_limits)) ||
		    !AssignProcessToJobObject(job, process.hProcess)) {
			CloseHandle(job);
			job = NULL;
		}
	}

	if (ResumeThread(process.hThread) == (DWORD)-1) {
		TerminateProcess(process.hProcess, 126);
		fail("busybox-shim: could not resume busybox.exe\n");
	}
	CloseHandle(process.hThread);
	WaitForSingleObject(process.hProcess, INFINITE);
	GetExitCodeProcess(process.hProcess, &exit_code);
	CloseHandle(process.hProcess);
	if (job)
		CloseHandle(job);
	HeapFree(GetProcessHeap(), 0, child_command_line);
	ExitProcess(exit_code);
}
