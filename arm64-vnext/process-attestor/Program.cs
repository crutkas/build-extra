using System.ComponentModel;
using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Arm64VNext.ProcessAttestor;

internal static class Program
{
    private const string Epoch = "2026-08-31-v1";
    private const ushort MachineUnknown = 0x0000;
    private const ushort MachineI386 = 0x014c;
    private const ushort MachineAmd64 = 0x8664;
    private const ushort MachineArm64 = 0xaa64;
    private const ushort MachineArm64Ec = 0xa641;
    private const ushort MachineArm64X = 0xa64e;
    private const uint CreateSuspended = 0x00000004;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint OpenExisting = 3;
    private const uint FileFlagSequentialScan = 0x08000000;
    private const uint Th32csSnapModule = 0x00000008;
    private const uint Th32csSnapModule32 = 0x00000010;
    private const uint WaitObject0 = 0x00000000;
    private const uint WaitTimeout = 0x00000102;
    private const uint WaitFailed = 0xffffffff;
    private const uint StillActive = 259;
    private const int ErrorBadLength = 24;
    private const int ErrorNoMoreFiles = 18;
    private const int ProcessMachineTypeInfo = 9;

    private static string SourceRevisionId =>
        Assembly.GetExecutingAssembly()
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .Single(attribute => attribute.Key == "SourceRevisionId")
            .Value ?? "";

    public static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--build-info")
        {
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                schema = "arm64-vnext-process-attestor-build-info-v1",
                epoch = Epoch,
                source_revision_id = SourceRevisionId,
                process_architecture = RuntimeInformation.ProcessArchitecture.ToString()
            }, JsonOptions));
            return 0;
        }
        if (args.Length == 1 && args[0] == "--self-test-wait")
            return RunWaitSelfTest();
        if (args.Length == 2 && args[0] == "--probe"
            && int.TryParse(args[1], out var milliseconds))
        {
            Thread.Sleep(milliseconds);
            return 0;
        }

        var allowNonNative = args.Length > 0 && args[0] == "--allow-non-native";
        var commandIndex = allowNonNative ? 1 : 0;
        if (args.Length <= commandIndex)
        {
            Console.Error.WriteLine(
                "usage: process-attestor [--allow-non-native] <image> [arguments...]");
            return 64;
        }

        try
        {
            var evidence = Attest(args[commandIndex], args[(commandIndex + 1)..]);
            Console.WriteLine(JsonSerializer.Serialize(evidence, JsonOptions));
            return evidence.NativeArm64 || allowNonNative ? 0 : 2;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(JsonSerializer.Serialize(new
            {
                schema = "arm64-vnext-process-attestation-error-v1",
                epoch = Epoch,
                source_revision_id = SourceRevisionId,
                error = error.Message
            }, JsonOptions));
            return 1;
        }
    }

    private static Attestation Attest(string requestedImage, string[] arguments)
    {
        var startedAt = DateTimeOffset.UtcNow;
        var fullRequestedImage = Path.GetFullPath(requestedImage);
        using var requested = HeldFile.Open(fullRequestedImage);
        var commandLine = QuoteWindowsArgument(fullRequestedImage);
        if (arguments.Length > 0)
            commandLine += " " + string.Join(" ", arguments.Select(QuoteWindowsArgument));

        var startup = new StartupInfo { Cb = Marshal.SizeOf<StartupInfo>() };
        if (!CreateProcessW(
                fullRequestedImage,
                new StringBuilder(commandLine),
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                CreateSuspended | CreateUnicodeEnvironment,
                IntPtr.Zero,
                Path.GetDirectoryName(fullRequestedImage),
                ref startup,
                out var process))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessW failed");
        }

        var modules = new Dictionary<string, HeldFile>(StringComparer.OrdinalIgnoreCase);
        var observedSnapshotPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var suspendedAt = DateTimeOffset.UtcNow;
            var exactImagePath = QueryImagePath(process.Process);
            using var exactImage = HeldFile.Open(exactImagePath);
            if (requested.Identity != exactImage.Identity)
                throw new InvalidOperationException(
                    "requested path and created process image file IDs differ");
            IsWow64Process2Checked(
                process.Process,
                out var wowProcessMachine,
                out var wowNativeMachine);
            var machineInfo = GetMachineInformation(process.Process);
            var moduleObservationErrors = new List<string>();

            if (ResumeThread(process.Thread) == uint.MaxValue)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "ResumeThread failed");
            var resumedAt = DateTimeOffset.UtcNow;

            WaitForChild(
                process.Process,
                () => SampleModules(
                    process.Process,
                    process.ProcessId,
                    modules,
                    observedSnapshotPaths,
                    moduleObservationErrors));
            if (moduleObservationErrors.Count > 0)
                throw new InvalidOperationException(
                    "module observation failed: "
                    + string.Join("; ", moduleObservationErrors));
            if (!GetExitCodeProcess(process.Process, out var exitCode))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetExitCodeProcess failed");
            if (exitCode == StillActive)
                throw new InvalidOperationException(
                    "process signaled but GetExitCodeProcess returned STILL_ACTIVE");
            requested.VerifyStable();
            exactImage.VerifyStable();
            foreach (var module in modules.Values)
                module.VerifyStable();
            if (modules.Count == 0)
                throw new InvalidOperationException(
                    "no loaded module was captured through a stable handle");

            var endedAt = DateTimeOffset.UtcNow;
            var nativeArm64 = exactImage.PeMachine == MachineArm64
                && machineInfo.ProcessMachine == MachineArm64;
            return new Attestation
            {
                Schema = "arm64-vnext-process-attestation-v2",
                Epoch = Epoch,
                SourceRevisionId = SourceRevisionId,
                StartedAt = startedAt,
                SuspendedAt = suspendedAt,
                ResumedAt = resumedAt,
                EndedAt = endedAt,
                DurationMilliseconds = (endedAt - startedAt).TotalMilliseconds,
                ParentProcessId = Environment.ProcessId,
                ChildProcessId = (int)process.ProcessId,
                Relation = "CreateProcessW child created suspended by this attestor",
                RequestedImage = requested.Evidence,
                ExactChildImage = exactImage.Evidence,
                IsWow64Process2 = new Wow64Evidence(
                    Hex(wowProcessMachine),
                    Hex(wowNativeMachine),
                    wowProcessMachine == MachineUnknown
                        ? "processMachine 0 is expected for native processes and cannot distinguish pure AMD64 here"
                        : "nonzero processMachine identifies an emulated process"),
                ProcessMachineTypeInfo = new MachineInformationEvidence(
                    Hex(machineInfo.ProcessMachine),
                    machineInfo.MachineAttributes),
                Classification = Classify(exactImage.PeMachine, machineInfo.ProcessMachine),
                NativeArm64 = nativeArm64,
                ExitCode = exitCode,
                Modules = modules.Values
                    .Select(module => module.Evidence)
                    .OrderBy(module => module.FinalPath, StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                ModuleObservationErrors = moduleObservationErrors.ToArray(),
                FileIdentityContract = new FileIdentityContract(
                    "CreateFileW GENERIC_READ with FILE_SHARE_READ only; write and delete sharing denied",
                    "SHA-256 and PE Machine read through duplicated handles; file ID, final path, size, timestamp, and hash rechecked after exit",
                    "Windows can change bytes through existing writable handles opened before the attestor denied new write/delete sharing"),
                DescendantObservation = new DescendantEvidence(
                    false,
                    "Only the directly created child is suspended and sampled.",
                    new[]
                    {
                        "Descendants are not intercepted or created suspended.",
                        "A descendant that starts and exits between samples may not be observed.",
                        "Module snapshots are point-in-time observations of the direct child only."
                    })
            };
        }
        finally
        {
            try
            {
                EnsureTerminated(process.Process);
            }
            finally
            {
                foreach (var module in modules.Values)
                    module.Dispose();
                CloseHandle(process.Thread);
                CloseHandle(process.Process);
            }
        }
    }

    private static string Classify(ushort peMachine, ushort liveMachine)
    {
        if (peMachine == MachineArm64 && liveMachine == MachineArm64)
            return "native-arm64";
        if (peMachine is MachineArm64Ec or MachineArm64X)
            return "excluded-arm64ec-or-arm64x";
        if (peMachine == MachineAmd64)
            return "excluded-amd64-or-unclassified-hybrid";
        if (peMachine == MachineI386)
            return "emulated-x86";
        return "not-native-arm64";
    }

    private static void SampleModules(
        IntPtr process,
        uint processId,
        Dictionary<string, HeldFile> modules,
        HashSet<string> observedSnapshotPaths,
        List<string> errors)
    {
        IntPtr snapshot = new(-1);
        for (var attempt = 0; attempt < 5; attempt++)
        {
            snapshot = CreateToolhelp32Snapshot(
                Th32csSnapModule | Th32csSnapModule32,
                processId);
            if (snapshot != new IntPtr(-1) || Marshal.GetLastWin32Error() != ErrorBadLength)
                break;
        }
        if (snapshot == new IntPtr(-1))
        {
            if (HasExited(process))
                return;
            errors.Add(
                new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "CreateToolhelp32Snapshot failed").Message);
            return;
        }
        try
        {
            var entry = new ModuleEntry32
            {
                DwSize = (uint)Marshal.SizeOf<ModuleEntry32>()
            };
            if (!Module32FirstW(snapshot, ref entry))
            {
                var error = Marshal.GetLastWin32Error();
                if (error != ErrorNoMoreFiles && !HasExited(process))
                    errors.Add(new Win32Exception(error, "Module32FirstW failed").Message);
                return;
            }
            do
            {
                var snapshotPath = entry.SzExePath;
                if (!string.IsNullOrEmpty(snapshotPath))
                {
                    var normalizedSnapshotPath = NormalizePath(snapshotPath);
                    if (observedSnapshotPaths.Contains(normalizedSnapshotPath))
                    {
                        entry.DwSize = (uint)Marshal.SizeOf<ModuleEntry32>();
                        continue;
                    }
                    try
                    {
                        var mappedPath = QueryMappedPath(process, entry.BaseAddress);
                        var held = HeldFile.Open(mappedPath);
                        var normalizedMappedPath = NormalizePath(mappedPath);
                        if (!string.Equals(
                                held.NormalizedFinalPath,
                                normalizedMappedPath,
                                StringComparison.OrdinalIgnoreCase))
                        {
                            held.Dispose();
                            throw new InvalidOperationException(
                                $"{snapshotPath}: mapped path and held-handle path differ");
                        }
                        if (modules.TryGetValue(held.NormalizedFinalPath, out var existing))
                        {
                            if (existing.Identity != held.Identity || existing.Sha256 != held.Sha256)
                            {
                                held.Dispose();
                                throw new InvalidOperationException(
                                    $"{snapshotPath}: module identity changed between snapshots");
                            }
                            held.Dispose();
                            observedSnapshotPaths.Add(normalizedSnapshotPath);
                        }
                        else
                        {
                            held.SnapshotPath = snapshotPath;
                            held.MappedPath = mappedPath;
                            modules.Add(held.NormalizedFinalPath, held);
                            observedSnapshotPaths.Add(normalizedSnapshotPath);
                        }
                    }
                    catch (Win32Exception error)
                    {
                        if (HasExited(process))
                            return;
                        errors.Add($"{snapshotPath}: {error.Message}");
                    }
                    catch (IOException error)
                    {
                        if (HasExited(process))
                            return;
                        errors.Add($"{snapshotPath}: {error.Message}");
                    }
                }
                entry.DwSize = (uint)Marshal.SizeOf<ModuleEntry32>();
            }
            while (Module32NextW(snapshot, ref entry));

            var nextError = Marshal.GetLastWin32Error();
            if (
                nextError != 0
                && nextError != ErrorNoMoreFiles
                && !HasExited(process))
                errors.Add(
                    new Win32Exception(nextError, "Module32NextW failed").Message);
        }
        finally
        {
            CloseHandle(snapshot);
        }
    }

    private static bool HasExited(IntPtr process) =>
        InterpretWaitStatus(WaitForSingleObject(process, 0)) == WaitState.Exited;

    private enum WaitState
    {
        Exited,
        TimedOut
    }

    private static WaitState InterpretWaitStatus(uint status)
    {
        return status switch
        {
            WaitObject0 => WaitState.Exited,
            WaitTimeout => WaitState.TimedOut,
            WaitFailed => throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "WaitForSingleObject failed"),
            _ => throw new InvalidOperationException(
                $"WaitForSingleObject returned unexpected status 0x{status:X8}")
        };
    }

    private static void WaitForChild(IntPtr process, Action onTimeout)
    {
        while (true)
        {
            switch (InterpretWaitStatus(WaitForSingleObject(process, 25)))
            {
                case WaitState.Exited:
                    return;
                case WaitState.TimedOut:
                    onTimeout();
                    break;
            }
        }
    }

    private static void EnsureTerminated(
        IntPtr process,
        Func<IntPtr, uint, uint>? wait = null,
        Func<IntPtr, uint, bool>? terminate = null)
    {
        wait ??= WaitForSingleObject;
        terminate ??= TerminateProcess;
        Exception? initialWaitError = null;
        try
        {
            if (InterpretWaitStatus(wait(process, 0)) == WaitState.Exited)
                return;
        }
        catch (Exception error) when (
            error is Win32Exception or InvalidOperationException)
        {
            initialWaitError = error;
        }

        var terminated = terminate(process, 1);
        var terminateError = terminated
            ? null
            : new Win32Exception(Marshal.GetLastWin32Error(), "child cleanup failed");
        var finalState = InterpretWaitStatus(wait(process, 5000));
        if (finalState != WaitState.Exited)
            throw new TimeoutException("terminated child did not exit within five seconds");
        if (initialWaitError is not null)
            throw new InvalidOperationException(
                "initial child state query failed after guaranteed cleanup",
                initialWaitError);
        if (terminateError is not null)
            throw terminateError;
    }

    private static int RunWaitSelfTest()
    {
        var controls = new List<object>();
        try
        {
            CleanupFailureControl(
                "wait-failed-cleanup",
                WaitFailed,
                typeof(InvalidOperationException),
                controls);
            CleanupFailureControl(
                "unexpected-wait-status-cleanup",
                7,
                typeof(InvalidOperationException),
                controls);

            var waits = new Queue<uint>(new[] { WaitTimeout, WaitObject0 });
            var terminateCalls = 0;
            EnsureTerminated(
                IntPtr.Zero,
                (_, _) => waits.Dequeue(),
                (_, _) =>
                {
                    terminateCalls++;
                    return true;
                });
            if (terminateCalls != 1 || waits.Count != 0)
                throw new InvalidOperationException("active child cleanup control failed");
            controls.Add(new { name = "active-child-terminated-and-waited", pass = true });

            terminateCalls = 0;
            EnsureTerminated(
                IntPtr.Zero,
                (_, _) => WaitObject0,
                (_, _) =>
                {
                    terminateCalls++;
                    return true;
                });
            if (terminateCalls != 0)
                throw new InvalidOperationException("exited child was terminated");
            controls.Add(new { name = "exited-child-not-terminated", pass = true });

            Console.WriteLine(JsonSerializer.Serialize(new
            {
                schema = "arm64-vnext-process-attestor-wait-self-test-v1",
                epoch = Epoch,
                source_revision_id = SourceRevisionId,
                pass = true,
                controls
            }, JsonOptions));
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(JsonSerializer.Serialize(new
            {
                schema = "arm64-vnext-process-attestor-wait-self-test-v1",
                epoch = Epoch,
                source_revision_id = SourceRevisionId,
                pass = false,
                controls,
                error = error.Message
            }, JsonOptions));
            return 1;
        }
    }

    private static void CleanupFailureControl(
        string name,
        uint firstStatus,
        Type expectedException,
        List<object> controls)
    {
        var waits = new Queue<uint>(new[] { firstStatus, WaitObject0 });
        var terminateCalls = 0;
        try
        {
            EnsureTerminated(
                IntPtr.Zero,
                (_, _) => waits.Dequeue(),
                (_, _) =>
                {
                    terminateCalls++;
                    return true;
                });
            throw new InvalidOperationException($"{name}: cleanup did not fail closed");
        }
        catch (Exception error) when (error.GetType() == expectedException)
        {
            if (terminateCalls != 1 || waits.Count != 0)
                throw new InvalidOperationException(
                    $"{name}: child was not terminated and waited");
            controls.Add(new { name, pass = true });
        }
    }

    private static ProcessMachineInformation GetMachineInformation(IntPtr process)
    {
        var size = Marshal.SizeOf<ProcessMachineInformation>();
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (!GetProcessInformation(process, ProcessMachineTypeInfo, buffer, (uint)size))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetProcessInformation failed");
            return Marshal.PtrToStructure<ProcessMachineInformation>(buffer);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static void IsWow64Process2Checked(
        IntPtr process,
        out ushort processMachine,
        out ushort nativeMachine)
    {
        if (!IsWow64Process2(process, out processMachine, out nativeMachine))
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "IsWow64Process2 failed");
    }

    private static string QueryImagePath(IntPtr process)
    {
        var capacity = 32768;
        var buffer = new StringBuilder(capacity);
        if (!QueryFullProcessImageNameW(process, 0, buffer, ref capacity))
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "QueryFullProcessImageNameW failed");
        return buffer.ToString();
    }

    private static string QueryMappedPath(IntPtr process, IntPtr baseAddress)
    {
        var buffer = new StringBuilder(32768);
        var length = GetMappedFileNameW(process, baseAddress, buffer, buffer.Capacity);
        if (length == 0)
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "GetMappedFileNameW failed");
        return DevicePathToDosPath(buffer.ToString());
    }

    private static string DevicePathToDosPath(string path)
    {
        if (!path.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
            return path;
        var target = new StringBuilder(32768);
        foreach (var drive in DriveInfo.GetDrives())
        {
            var driveName = drive.Name[..2];
            target.Clear();
            if (QueryDosDeviceW(driveName, target, target.Capacity) == 0)
                continue;
            var device = target.ToString();
            if (path.StartsWith(device, StringComparison.OrdinalIgnoreCase))
                return driveName + path[device.Length..];
        }
        throw new InvalidOperationException($"cannot map device path to DOS path: {path}");
    }

    private static string NormalizePath(string path)
    {
        var full = path.StartsWith(@"\\?\")
            ? path[4..]
            : Path.GetFullPath(path);
        return full.TrimEnd(Path.DirectorySeparatorChar).ToUpperInvariant();
    }

    private static string QuoteWindowsArgument(string argument)
    {
        if (argument.Length > 0
            && !argument.Any(character => char.IsWhiteSpace(character) || character == '"'))
            return argument;
        var result = new StringBuilder("\"");
        var backslashes = 0;
        foreach (var character in argument)
        {
            if (character == '\\')
            {
                backslashes++;
                continue;
            }
            if (character == '"')
            {
                result.Append('\\', backslashes * 2 + 1).Append('"');
                backslashes = 0;
                continue;
            }
            result.Append('\\', backslashes).Append(character);
            backslashes = 0;
        }
        return result.Append('\\', backslashes * 2).Append('"').ToString();
    }

    private static string Hex(ushort value) => $"0x{value:X4}";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = true
    };

    private sealed class HeldFile : IDisposable
    {
        private readonly SafeFileHandle handle;
        private readonly ByHandleFileInformation initialInformation;

        private HeldFile(
            string requestedPath,
            SafeFileHandle handle,
            string finalPath,
            ByHandleFileInformation information,
            string sha256,
            ushort peMachine)
        {
            RequestedPath = requestedPath;
            this.handle = handle;
            FinalPath = finalPath;
            NormalizedFinalPath = NormalizePath(finalPath);
            initialInformation = information;
            Identity = FileIdentity.From(information);
            Sha256 = sha256;
            PeMachine = peMachine;
        }

        public string RequestedPath { get; }
        public string FinalPath { get; }
        public string NormalizedFinalPath { get; }
        public string? SnapshotPath { get; set; }
        public string? MappedPath { get; set; }
        public FileIdentity Identity { get; }
        public string Sha256 { get; }
        public ushort PeMachine { get; }
        public StableFileEvidence Evidence => new(
            RequestedPath,
            FinalPath,
            SnapshotPath,
            MappedPath,
            Identity,
            Sha256,
            Hex(PeMachine),
            initialInformation.FileSize);

        public static HeldFile Open(string path)
        {
            var requestedPath = Path.GetFullPath(path);
            var handle = CreateFileW(
                requestedPath,
                GenericRead,
                FileShareRead,
                IntPtr.Zero,
                OpenExisting,
                FileFlagSequentialScan,
                IntPtr.Zero);
            if (handle.IsInvalid)
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    $"{requestedPath}: CreateFileW failed");
            try
            {
                var information = GetInformation(handle);
                var finalPath = GetFinalPath(handle);
                var sha256 = Hash(handle);
                var peMachine = ReadPeMachine(handle, requestedPath);
                return new HeldFile(
                    requestedPath,
                    handle,
                    finalPath,
                    information,
                    sha256,
                    peMachine);
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        public void VerifyStable()
        {
            var currentInformation = GetInformation(handle);
            if (FileIdentity.From(currentInformation) != Identity
                || currentInformation.FileSize != initialInformation.FileSize
                || !currentInformation.LastWriteTime.Equals(
                    initialInformation.LastWriteTime))
            {
                throw new InvalidOperationException(
                    $"{RequestedPath}: held file identity changed");
            }
            if (!string.Equals(
                    NormalizePath(GetFinalPath(handle)),
                    NormalizedFinalPath,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"{RequestedPath}: held file final path changed");
            }
            if (Hash(handle) != Sha256)
                throw new InvalidOperationException($"{RequestedPath}: held file hash changed");
        }

        public void Dispose() => handle.Dispose();

        private static ByHandleFileInformation GetInformation(SafeFileHandle handle)
        {
            if (!GetFileInformationByHandle(handle, out var information))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetFileInformationByHandle failed");
            return information;
        }

        private static string GetFinalPath(SafeFileHandle handle)
        {
            var buffer = new StringBuilder(32768);
            var length = GetFinalPathNameByHandleW(
                handle,
                buffer,
                (uint)buffer.Capacity,
                0);
            if (length == 0 || length >= buffer.Capacity)
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetFinalPathNameByHandleW failed");
            return buffer.ToString();
        }

        private static string Hash(SafeFileHandle handle)
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[64 * 1024];
            long offset = 0;
            while (true)
            {
                var read = RandomAccess.Read(handle, buffer, offset);
                if (read == 0)
                    break;
                hash.AppendData(buffer.AsSpan(0, read));
                offset += read;
            }
            return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
        }

        private static ushort ReadPeMachine(SafeFileHandle handle, string path)
        {
            var dosHeader = ReadAt(handle, 0, 64);
            if (BinaryPrimitives.ReadUInt16LittleEndian(dosHeader) != 0x5a4d)
                throw new InvalidDataException($"{path}: missing DOS signature");
            var peOffset = BinaryPrimitives.ReadUInt32LittleEndian(
                dosHeader.AsSpan(0x3c, 4));
            var peHeader = ReadAt(handle, peOffset, 6);
            if (BinaryPrimitives.ReadUInt32LittleEndian(peHeader) != 0x00004550)
                throw new InvalidDataException($"{path}: missing PE signature");
            return BinaryPrimitives.ReadUInt16LittleEndian(peHeader.AsSpan(4, 2));
        }

        private static byte[] ReadAt(
            SafeFileHandle handle,
            long offset,
            int count)
        {
            var result = new byte[count];
            var total = 0;
            while (total < count)
            {
                var read = RandomAccess.Read(
                    handle,
                    result.AsSpan(total),
                    offset + total);
                if (read == 0)
                    throw new EndOfStreamException("unexpected end of file");
                total += read;
            }
            return result;
        }
    }

    private sealed class Attestation
    {
        public required string Schema { get; init; }
        public required string Epoch { get; init; }
        public required string SourceRevisionId { get; init; }
        public DateTimeOffset StartedAt { get; init; }
        public DateTimeOffset SuspendedAt { get; init; }
        public DateTimeOffset ResumedAt { get; init; }
        public DateTimeOffset EndedAt { get; init; }
        public double DurationMilliseconds { get; init; }
        public int ParentProcessId { get; init; }
        public int ChildProcessId { get; init; }
        public required string Relation { get; init; }
        public required StableFileEvidence RequestedImage { get; init; }
        public required StableFileEvidence ExactChildImage { get; init; }
        public required Wow64Evidence IsWow64Process2 { get; init; }
        public required MachineInformationEvidence ProcessMachineTypeInfo { get; init; }
        public required string Classification { get; init; }
        public bool NativeArm64 { get; init; }
        public uint ExitCode { get; init; }
        public required StableFileEvidence[] Modules { get; init; }
        public required string[] ModuleObservationErrors { get; init; }
        public required FileIdentityContract FileIdentityContract { get; init; }
        public required DescendantEvidence DescendantObservation { get; init; }
    }

    private sealed record StableFileEvidence(
        string RequestedPath,
        string FinalPath,
        string? SnapshotPath,
        string? MappedPath,
        FileIdentity FileId,
        string Sha256,
        string PeMachine,
        ulong Size);
    private sealed record FileIdentity(uint VolumeSerialNumber, ulong FileIndex)
    {
        public static FileIdentity From(ByHandleFileInformation information) =>
            new(
                information.VolumeSerialNumber,
                ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow);
    }
    private sealed record Wow64Evidence(
        string ProcessMachine,
        string NativeMachine,
        string Interpretation);
    private sealed record MachineInformationEvidence(
        string ProcessMachine,
        uint MachineAttributes);
    private sealed record FileIdentityContract(
        string HandleSharing,
        string Verification,
        string KernelLimitation);
    private sealed record DescendantEvidence(
        bool Complete,
        string Scope,
        string[] Limitations);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int Cb;
        public string? Reserved;
        public string? Desktop;
        public string? Title;
        public int X;
        public int Y;
        public int XSize;
        public int YSize;
        public int XCountChars;
        public int YCountChars;
        public int FillAttribute;
        public int Flags;
        public short ShowWindow;
        public short Reserved2;
        public IntPtr Reserved2Pointer;
        public IntPtr StdInput;
        public IntPtr StdOutput;
        public IntPtr StdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr Process;
        public IntPtr Thread;
        public uint ProcessId;
        public uint ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessMachineInformation
    {
        public ushort ProcessMachine;
        public ushort Reserved;
        public uint MachineAttributes;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ModuleEntry32
    {
        public uint DwSize;
        public uint ModuleId;
        public uint ProcessId;
        public uint GlobalUsage;
        public uint ProcessUsage;
        public IntPtr BaseAddress;
        public uint BaseSize;
        public IntPtr ModuleHandle;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string SzModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string SzExePath;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime : IEquatable<FileTime>
    {
        public uint Low;
        public uint High;
        public readonly bool Equals(FileTime other) => Low == other.Low && High == other.High;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public FileTime CreationTime;
        public FileTime LastAccessTime;
        public FileTime LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
        public readonly ulong FileSize => ((ulong)FileSizeHigh << 32) | FileSizeLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessW(
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string? currentDirectory,
        ref StartupInfo startupInfo,
        out ProcessInformation processInformation);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle file,
        StringBuilder filePath,
        uint filePathSize,
        uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(
        IntPtr process,
        uint flags,
        StringBuilder imageName,
        ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWow64Process2(
        IntPtr process,
        out ushort processMachine,
        out ushort nativeMachine);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessInformation(
        IntPtr process,
        int processInformationClass,
        IntPtr processInformation,
        uint processInformationSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Module32FirstW(
        IntPtr snapshot,
        ref ModuleEntry32 entry);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Module32NextW(
        IntPtr snapshot,
        ref ModuleEntry32 entry);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetMappedFileNameW(
        IntPtr process,
        IntPtr address,
        StringBuilder fileName,
        int size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDeviceW(
        string deviceName,
        StringBuilder targetPath,
        int max);
}
