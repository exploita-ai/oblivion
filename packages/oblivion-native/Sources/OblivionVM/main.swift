import Darwin
import Dispatch
import Foundation
import Virtualization
import RuntimeLifetime

struct RuntimeConfig: Decodable {
    struct Disk: Decodable {
        let path: String
        let readOnly: Bool
    }

    let version: Int
    let backend: String
    let kernel: String
    let initrd: String?
    let commandLine: String
    let disks: [Disk]
    let cpuCount: Int
    let memoryMiB: UInt64
    let controlSocket: String
    let controlPort: UInt32
    let network: Bool
    let serialStdio: Bool
}

enum RuntimeError: String, Error {
    case invalidArguments = "invalid_arguments"
    case unsupportedArchitecture = "apple_silicon_required"
    case virtualizationUnavailable = "virtualization_unavailable"
    case nestedUnavailable = "nested_virtualization_unavailable"
    case invalidConfiguration = "invalid_runtime_configuration"
    case invalidControlDirectory = "private_control_directory_required"
    case socketInUse = "runtime_socket_in_use"
    case socketFailed = "control_socket_failed"
    case lockFailed = "runtime_already_running"
}

func report(_ event: String) {
    // Events contain identifiers only. Subprocess or guest output never enters them.
    diagnosticWrite(Data(("{\"event\":\"" + event + "\"}\n").utf8), to: STDERR_FILENO)
}

func diagnosticWrite(_ data: Data, to descriptor: Int32) {
    // Debug PTYs may be nonblocking. Foundation writeData raises an exception
    // on EAGAIN; optional console output must never terminate a running VM.
    data.withUnsafeBytes { bytes in
        var offset = 0
        while offset < bytes.count {
            let written = Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
            if written < 0 && errno == EINTR { continue }
            if written <= 0 { return }
            offset += written
        }
    }
}

func requireHost() throws {
    #if !arch(arm64)
    throw RuntimeError.unsupportedArchitecture
    #else
    guard VZVirtualMachine.isSupported else { throw RuntimeError.virtualizationUnavailable }
    guard VZGenericPlatformConfiguration.isNestedVirtualizationSupported else {
        throw RuntimeError.nestedUnavailable
    }
    #endif
}

final class StreamBridge {
    let local: Int32
    let connection: VZVirtioSocketConnection
    private let group = DispatchGroup()
    var onClose: (() -> Void)?

    init(local: Int32, connection: VZVirtioSocketConnection) {
        self.local = local
        self.connection = connection
    }

    func start() {
        copy(from: local, to: connection.fileDescriptor)
        copy(from: connection.fileDescriptor, to: local)
        group.notify(queue: .main) {
            Darwin.close(self.local)
            self.onClose?()
        }
    }

    private func copy(from source: Int32, to destination: Int32) {
        group.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            defer {
                Darwin.shutdown(destination, SHUT_WR)
                self.group.leave()
            }
            var buffer = [UInt8](repeating: 0, count: 65536)
            defer { _ = buffer.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
            while true {
                let length = Darwin.read(source, &buffer, buffer.count)
                if length < 0 && errno == EINTR { continue }
                if length <= 0 { return }
                var offset = 0
                while offset < length {
                    let written = buffer.withUnsafeBytes {
                        Darwin.write(destination, $0.baseAddress!.advanced(by: offset), length - offset)
                    }
                    if written < 0 && errno == EINTR { continue }
                    if written <= 0 {
                        Darwin.shutdown(source, SHUT_RDWR)
                        return
                    }
                    offset += written
                }
            }
        }
    }

    func close() {
        Darwin.shutdown(local, SHUT_RDWR)
        Darwin.shutdown(connection.fileDescriptor, SHUT_RDWR)
    }
}

final class Runtime: NSObject, VZVirtualMachineDelegate {
    let config: RuntimeConfig
    let machine: VZVirtualMachine
    private var listener: Int32 = -1
    private var lock: Int32 = -1
    private var ownsSocket = false
    private var acceptSource: DispatchSourceRead?
    private var signals: [DispatchSourceSignal] = []
    private var bridges: [UUID: StreamBridge] = [:]
    private var stopping = false
    private var lifetimeRevoked = false
    private let lifetime: SupervisorLifetime
    private let consolePipe: Pipe
    private var serialTail = Data()

    init(config: RuntimeConfig, lifetime: SupervisorLifetime) throws {
        try requireHost()
        guard config.version == 1, config.controlPort > 1024,
              config.memoryMiB <= UInt64.max / 1048576,
              !config.disks.isEmpty,
              !config.kernel.isEmpty,
              !config.commandLine.contains("\0") else {
            throw RuntimeError.invalidConfiguration
        }
        let backend = config.commandLine.split(separator: " ").filter { $0.hasPrefix("oblivion.runtime-backend=") }
        guard config.backend == "apple-vz", backend == ["oblivion.runtime-backend=apple-vz"] else {
            throw RuntimeError.invalidConfiguration
        }
        let settings = VZVirtualMachineConfiguration()
        let boot = VZLinuxBootLoader(kernelURL: URL(fileURLWithPath: config.kernel))
        boot.initialRamdiskURL = config.initrd.map { URL(fileURLWithPath: $0) }
        boot.commandLine = config.commandLine
        settings.bootLoader = boot
        settings.cpuCount = config.cpuCount
        settings.memorySize = config.memoryMiB * 1048576
        let platform = VZGenericPlatformConfiguration()
        platform.isNestedVirtualizationEnabled = true
        settings.platform = platform
        settings.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
        settings.memoryBalloonDevices = [VZVirtioTraditionalMemoryBalloonDeviceConfiguration()]
        settings.socketDevices = [VZVirtioSocketDeviceConfiguration()]
        settings.storageDevices = try config.disks.map { disk in
            let attachment = try VZDiskImageStorageDeviceAttachment(
                url: URL(fileURLWithPath: disk.path),
                readOnly: disk.readOnly,
                // Explicit cached I/O avoids VZ guest memory corruption seen
                // with uncached/automatic disk access on Apple Silicon.
                // Keep durable flushes: https://github.com/apple/container/pull/1041
                cachingMode: .cached,
                synchronizationMode: .full
            )
            return VZVirtioBlockDeviceConfiguration(attachment: attachment)
        }
        if config.network {
            let ethernet = VZVirtioNetworkDeviceConfiguration()
            ethernet.attachment = VZNATNetworkDeviceAttachment()
            settings.networkDevices = [ethernet]
        }
        let pipe = Pipe()
        self.consolePipe = pipe
        let serial = VZVirtioConsoleDeviceSerialPortConfiguration()
        serial.attachment = VZFileHandleSerialPortAttachment(
            fileHandleForReading: config.serialStdio ? .standardInput : FileHandle(forReadingAtPath: "/dev/null")!,
            fileHandleForWriting: pipe.fileHandleForWriting
        )
        settings.serialPorts = [serial]
        try settings.validate()
        self.config = config
        self.lifetime = lifetime
        self.machine = VZVirtualMachine(configuration: settings)
        super.init()
        machine.delegate = self
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let bytes = handle.availableData
            guard !bytes.isEmpty else { return }
            DispatchQueue.main.async { self?.observeSerial(bytes) }
        }
    }

    func start() throws {
        try lifetime.check()
        lifetime.monitor(queue: .main) { [weak self] in self?.supervisorLost() }
        try listen()
        for number in [SIGINT, SIGTERM, SIGHUP] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
            source.setEventHandler { self.stop() }
            source.resume()
            signals.append(source)
        }
        signal(SIGPIPE, SIG_IGN)
        machine.start { result in
            switch result {
            case .success:
                self.acceptSource?.resume()
                report("runtime_started")
            case .failure:
                self.finish(code: 1, event: "runtime_start_failed")
            }
        }
    }

    private func listen() throws {
        let path = config.controlSocket
        guard path.hasPrefix("/"), path.utf8.count < 104 else {
            throw RuntimeError.invalidConfiguration
        }
        let parent = URL(fileURLWithPath: path).deletingLastPathComponent().path
        var info = stat()
        guard lstat(parent, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == getuid(), info.st_mode & 0o077 == 0 else {
            throw RuntimeError.invalidControlDirectory
        }
        lock = Darwin.open(path + ".lock", O_RDWR | O_CREAT | O_NOFOLLOW, 0o600)
        guard lock >= 0, flock(lock, LOCK_EX | LOCK_NB) == 0 else { throw RuntimeError.lockFailed }
        // Leave stale sockets for explicit recovery. A live process may own the endpoint.
        if lstat(path, &info) == 0 {
            // The exclusive runtime lock excludes another Oblivion owner.
            // Only an owned socket whose listener is gone may be recovered.
            guard info.st_mode & S_IFMT == S_IFSOCK, info.st_uid == getuid() else {
                throw RuntimeError.socketInUse
            }
            let probe = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
            guard probe >= 0 else { throw RuntimeError.socketFailed }
            var address = sockaddr_un()
            address.sun_family = sa_family_t(AF_UNIX)
            _ = path.withCString { pointer in
                withUnsafeMutablePointer(to: &address.sun_path) {
                    $0.withMemoryRebound(to: CChar.self, capacity: 104) { strcpy($0, pointer) }
                }
            }
            let connected = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(probe, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            let failure = errno
            Darwin.close(probe)
            guard connected != 0 && failure == ECONNREFUSED && unlink(path) == 0 else {
                throw RuntimeError.socketInUse
            }
        } else if errno != ENOENT { throw RuntimeError.socketFailed }
        listener = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard listener >= 0 else { throw RuntimeError.socketFailed }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &address.sun_path) { bytes in
            path.utf8CString.withUnsafeBytes { value in bytes.copyBytes(from: value) }
        }
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bound == 0 else { throw RuntimeError.socketFailed }
        ownsSocket = true
        guard chmod(path, 0o600) == 0, Darwin.listen(listener, 16) == 0,
              fcntl(listener, F_SETFL, O_NONBLOCK) == 0 else {
            throw RuntimeError.socketFailed
        }
        let source = DispatchSource.makeReadSource(fileDescriptor: listener, queue: .main)
        source.setEventHandler { self.accept() }
        acceptSource = source
    }

    private func accept() {
        while true {
            let fd = Darwin.accept(listener, nil, nil)
            if fd < 0 { return }
            var uid = uid_t()
            var gid = gid_t()
            guard !stopping, getpeereid(fd, &uid, &gid) == 0, uid == getuid(),
                  bridges.count < 64,
                  let device = machine.socketDevices.first as? VZVirtioSocketDevice else {
                Darwin.close(fd)
                continue
            }
            var noSignal: Int32 = 1
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
            device.connect(toPort: config.controlPort) { result in
                switch result {
                case .success(let connection):
                    guard !self.stopping else {
                        Darwin.close(fd)
                        return
                    }
                    let id = UUID()
                    guard fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK) == 0,
                          fcntl(connection.fileDescriptor, F_SETFL, fcntl(connection.fileDescriptor, F_GETFL) & ~O_NONBLOCK) == 0 else {
                        Darwin.close(fd)
                        return
                    }
                    let bridge = StreamBridge(local: fd, connection: connection)
                    self.bridges[id] = bridge
                    bridge.onClose = { self.bridges.removeValue(forKey: id) }
                    bridge.start()
                case .failure:
                    Darwin.close(fd)
                }
            }
        }
    }

    private func observeSerial(_ bytes: Data) {
        if config.serialStdio { diagnosticWrite(bytes, to: STDOUT_FILENO) }
        serialTail.append(bytes)
        let memoryFailure = [
            "BUG: Bad rss-counter state",
            "BUG: corrupted stack end",
            "Internal error: Oops",
        ].contains { serialTail.range(of: Data($0.utf8)) != nil }
        if memoryFailure || serialTail.range(of: Data("Kernel panic - not syncing".utf8)) != nil {
            guard !stopping else { return }
            stopping = true
            acceptSource?.cancel()
            // An Oops can leave the kernel running with corrupted memory. It
            // must not continue accepting Safe requests until an eventual panic.
            report(memoryFailure ? "runtime_kernel_memory_failure" : "runtime_kernel_panic")
            machine.stop { _ in self.finish(code: 1, event: "runtime_failed") }
            return
        }
        // Detect markers split across chunks without retaining boot output.
        if serialTail.count > 128 { serialTail.removeFirst(serialTail.count - 128) }
    }

    private func supervisorLost() {
        guard !lifetimeRevoked else { return }
        lifetimeRevoked = true
        stopping = true
        acceptSource?.cancel()
        bridges.values.forEach { $0.close() }
        report("supervisor_lifetime_lost")
        // This VM belongs to this helper instance. A lost supervisor is a
        // failure path, not a successful archive lock or graceful user exit.
        machine.stop { _ in self.finish(code: 1, event: "runtime_supervisor_lost") }
    }

    private func stop() {
        guard !stopping else { return }
        stopping = true
        acceptSource?.cancel()
        // The launcher asks the controller to lock Safes before stopping the runtime.
        // This signal remains an emergency path when that launcher disappears.
        do {
            try machine.requestStop()
            report("runtime_stopping")
        } catch {
            forceStop()
            return
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 45) {
            self.forceStop()
        }
    }

    private func forceStop() {
        report("runtime_shutdown_timeout")
        machine.stop { _ in self.finish(code: 1, event: "runtime_forced_stop") }
    }

    private func finish(code: Int32, event: String) -> Never {
        lifetime.cancel()
        consolePipe.fileHandleForReading.readabilityHandler = nil
        bridges.values.forEach { $0.close() }
        if listener >= 0 { Darwin.close(listener) }
        if ownsSocket { unlink(config.controlSocket) }
        if lock >= 0 { Darwin.close(lock) }
        report(event)
        Darwin.exit(code)
    }

    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        finish(code: lifetimeRevoked ? 1 : 0, event: lifetimeRevoked ? "runtime_supervisor_lost" : "runtime_stopped")
    }

    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        finish(code: 1, event: "runtime_failed")
    }

    deinit {
        if listener >= 0 { Darwin.close(listener) }
        if ownsSocket { unlink(config.controlSocket) }
        if lock >= 0 { Darwin.close(lock) }
    }
}

func main() throws {
    let args = Array(CommandLine.arguments.dropFirst())
    if args == ["pick-files"] {
        try MainActor.assumeIsolated { try pickFiles() }
        return
    }
    if args == ["capabilities"] {
        #if arch(arm64)
        let nested = VZGenericPlatformConfiguration.isNestedVirtualizationSupported
        #else
        let nested = false
        #endif
        let response: [String: Any] = [
            "version": 1,
            "backend": "apple-vz",
            "virtualization": VZVirtualMachine.isSupported,
            "nested": nested,
            "supported": VZVirtualMachine.isSupported && nested,
        ]
        FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: response, options: [.sortedKeys]))
        FileHandle.standardOutput.write(Data([10]))
        return
    }
    guard args.count == 5, args[0] == "run", args[1] == "--config",
          args[3] == "--lifetime-fd", args[4] == "3" else {
        throw RuntimeError.invalidArguments
    }
    let lifetime = try SupervisorLifetime(taking: 3)
    try requireHost()
    let config = try JSONDecoder().decode(RuntimeConfig.self, from: Data(contentsOf: URL(fileURLWithPath: args[2])))
    let runtime = try Runtime(config: config, lifetime: lifetime)
    try runtime.start()
    withExtendedLifetime(runtime) { dispatchMain() }
}

umask(0o077)
var dumpLimit = rlimit(rlim_cur: 0, rlim_max: 0)
guard setrlimit(RLIMIT_CORE, &dumpLimit) == 0 else {
    report("core_dump_protection_failed")
    Darwin.exit(1)
}
do {
    try main()
} catch let error as SupervisorLifetimeFailure {
    report(error.rawValue)
    Darwin.exit(1)
} catch let error as RuntimeError {
    report(error.rawValue)
    Darwin.exit(1)
} catch let error as FilePickerFailure {
    report(error.rawValue)
    Darwin.exit(1)
} catch {
    report("runtime_configuration_failed")
    Darwin.exit(1)
}
