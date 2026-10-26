import AppKit
import Virtualization

// Development-only host. No directory sharing, audio or Mac disk passthrough.
// Clipboard text crosses only on an explicit copy/paste shortcut through the
// configured, host-key-verified SSH connection; there is no clipboard polling.
@MainActor
final class Laboratory: NSObject, NSApplicationDelegate, NSWindowDelegate, @preconcurrency VZVirtualMachineDelegate {
    var machine: VZVirtualMachine?
    var window: NSWindow?
    var terminationPending = false
    let serialInput = Pipe()
    let serialOutput = Pipe()
    var clipboardMonitor: Any?
    var clipboardBusy = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        clipboardMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
            guard let self, self.window?.isKeyWindow == true,
                  event.modifierFlags.contains(.command) || event.modifierFlags.contains(.control),
                  let key = event.charactersIgnoringModifiers?.lowercased(), ["c", "v"].contains(key),
                  ProcessInfo.processInfo.environment["OBLIVION_CLIPBOARD_HOST"] != nil else { return event }
            self.transferClipboard(copy: key == "c")
            return nil
        }
        start()
    }

    func transferClipboard(copy: Bool) {
        guard !clipboardBusy else { return }
        let environment = ProcessInfo.processInfo.environment
        guard let host = environment["OBLIVION_CLIPBOARD_HOST"],
              let identity = environment["OBLIVION_CLIPBOARD_IDENTITY"],
              let knownHosts = environment["OBLIVION_CLIPBOARD_KNOWN_HOSTS"] else { NSSound.beep(); return }
        let input = copy ? Data() : Data((NSPasteboard.general.string(forType: .string) ?? "").utf8)
        guard input.count <= 256 * 1024 else { NSSound.beep(); return }
        clipboardBusy = true
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
        process.arguments = ["-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=3",
            "-o", "ServerAliveInterval=2", "-o", "ServerAliveCountMax=2", "-o", "UserKnownHostsFile=\(knownHosts)",
            "-i", identity, host,
            "sudo -n -u oblivion-manager /usr/bin/oblivion-manager --clipboard-client " + (copy ? "copy" : "paste")]
        let incoming = Pipe()
        let outgoing = Pipe()
        process.standardInput = incoming
        process.standardOutput = outgoing
        process.standardError = FileHandle.nullDevice
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try process.run()
                let timeout = DispatchWorkItem { if process.isRunning { process.terminate() } }
                DispatchQueue.global().asyncAfter(deadline: .now() + 8, execute: timeout)
                incoming.fileHandleForWriting.write(input)
                try? incoming.fileHandleForWriting.close()
                let output = outgoing.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                timeout.cancel()
                Task { @MainActor in
                    self.clipboardBusy = false
                    guard process.terminationStatus == 0, output.count <= 256 * 1024 else { NSSound.beep(); return }
                    if copy, let value = String(data: output, encoding: .utf8), !value.isEmpty {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(value, forType: .string)
                    }
                }
            } catch {
                Task { @MainActor in self.clipboardBusy = false; NSSound.beep() }
            }
        }
    }

    func applicationDidBecomeActive(_ notification: Notification) {
        guard let window, let view = window.contentView else { return }
        window.makeKeyAndOrderFront(nil)
        window.makeFirstResponder(view)
    }

    func windowDidBecomeKey(_ notification: Notification) {
        guard let window, let view = window.contentView else { return }
        window.makeFirstResponder(view)
    }

    func start() {
        FileHandle.standardError.write(Data("Oblivion lab: configuring ARM64 VM\n".utf8))
        do {
            let arguments = Array(CommandLine.arguments.dropFirst())
            guard arguments.count >= 3 else {
                throw Failure.message("Usage: OblivionLab --usb writable-image efi-store OR kernel initrd root-image [kernel-command-line]")
            }
            guard VZGenericPlatformConfiguration.isNestedVirtualizationSupported else {
                throw Failure.message("Nested virtualization is unavailable on this Mac.")
            }
            let configuration = VZVirtualMachineConfiguration()
            let platform = VZGenericPlatformConfiguration()
            platform.isNestedVirtualizationEnabled = true
            configuration.platform = platform
            configuration.cpuCount = 4
            configuration.memorySize = 6 * 1024 * 1024 * 1024
            if arguments[0] == "--usb" || arguments[0] == "--live" {
                if arguments[0] == "--live" {
                    guard arguments.count >= 4 else { throw Failure.message("--live requires USB, kernel and initrd") }
                    let boot = VZLinuxBootLoader(kernelURL: URL(fileURLWithPath: arguments[2]))
                    boot.initialRamdiskURL = URL(fileURLWithPath: arguments[3])
                    boot.commandLine = "boot=live live-media-offset=0 nopersistence noeject nonetworking ip=off ipv6.disable=1 pstore.backend=none efi_pstore.pstore_disable=1 systemd.mask=systemd-pstore.service systemd.getty_auto=no console=hvc0 console=tty1 loglevel=5"
                    configuration.bootLoader = boot
                } else {
                    let boot = VZEFIBootLoader()
                    let store = URL(fileURLWithPath: arguments[2])
                    boot.variableStore = FileManager.default.fileExists(atPath: store.path)
                        ? VZEFIVariableStore(url: store)
                        : try VZEFIVariableStore(creatingVariableStoreAt: store)
                    configuration.bootLoader = boot
                }
                let usb = VZXHCIControllerConfiguration()
                usb.usbDevices = [VZUSBMassStorageDeviceConfiguration(attachment:
                    try VZDiskImageStorageDeviceAttachment(url: URL(fileURLWithPath: arguments[1]), readOnly: false))]
                // Explicit synthetic USB fixtures for import/export testing.
                for path in arguments.dropFirst(arguments[0] == "--live" ? 4 : 3) {
                    usb.usbDevices.append(VZUSBMassStorageDeviceConfiguration(attachment:
                        try VZDiskImageStorageDeviceAttachment(url: URL(fileURLWithPath: path), readOnly: false)))
                }
                configuration.usbControllers = [usb]
                let uplink = VZVirtioNetworkDeviceConfiguration()
                // Reuse the lab's network identity across software updates so
                // its verified diagnostic SSH endpoint keeps the same lease.
                if let address = ProcessInfo.processInfo.environment["OBLIVION_MAC_ADDRESS"] {
                    guard let mac = VZMACAddress(string: address) else { throw Failure.message("Invalid laboratory MAC address") }
                    uplink.macAddress = mac
                }
                uplink.attachment = VZNATNetworkDeviceAttachment()
                configuration.networkDevices = [uplink]
            } else {
                let boot = VZLinuxBootLoader(kernelURL: URL(fileURLWithPath: arguments[0]))
                boot.initialRamdiskURL = URL(fileURLWithPath: arguments[1])
                boot.commandLine = arguments.count > 3 ? arguments[3] : "console=hvc0 console=tty0 root=/dev/vda rootfstype=squashfs ro panic=0 systemd.getty_auto=no"
                configuration.bootLoader = boot
                configuration.storageDevices = [VZVirtioBlockDeviceConfiguration(attachment:
                    try VZDiskImageStorageDeviceAttachment(url: URL(fileURLWithPath: arguments[2]), readOnly: true))]
            }
            let display = VZVirtioGraphicsDeviceConfiguration()
            display.scanouts = [VZVirtioGraphicsScanoutConfiguration(widthInPixels: 1280, heightInPixels: 800)]
            configuration.graphicsDevices = [display]
            configuration.keyboards = [VZUSBKeyboardConfiguration()]
            configuration.pointingDevices = [VZUSBScreenCoordinatePointingDeviceConfiguration()]
            configuration.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
            let serial = VZVirtioConsoleDeviceSerialPortConfiguration()
            serialOutput.fileHandleForReading.readabilityHandler = { handle in
                let bytes = handle.availableData
                if !bytes.isEmpty { FileHandle.standardOutput.write(bytes) }
            }
            serial.attachment = VZFileHandleSerialPortAttachment(fileHandleForReading: serialInput.fileHandleForReading, fileHandleForWriting: serialOutput.fileHandleForWriting)
            configuration.serialPorts = [serial]
            try configuration.validate()
            let machine = VZVirtualMachine(configuration: configuration)
            machine.delegate = self
            self.machine = machine
            let view = VZVirtualMachineView()
            view.virtualMachine = machine
            view.capturesSystemKeys = true
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1280, height: 800), styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
            self.window = window
            window.delegate = self
            window.title = "Oblivion · ARM64 Laboratory"
            window.contentView = view
            window.center()
            window.makeKeyAndOrderFront(nil)
            window.makeFirstResponder(view)
            NSApp.activate(ignoringOtherApps: true)
            machine.start { result in
                switch result {
                case .success:
                    window.makeKeyAndOrderFront(nil)
                    window.makeFirstResponder(view)
                    FileHandle.standardError.write(Data("Oblivion lab: VM started; active=\(NSApp.isActive) keyWindow=\(window.isKeyWindow) inputFocused=\(window.firstResponder === view)\n".utf8))
                case .failure(let error): self.fail(error)
                }
            }
        } catch { fail(error) }
    }

    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        if terminationPending { NSApp.reply(toApplicationShouldTerminate: true); return }
        NSApp.terminate(nil)
    }
    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) { fail(error) }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let machine, machine.canRequestStop else { return .terminateNow }
        if terminationPending { return .terminateLater }
        do {
            try machine.requestStop()
            terminationPending = true
            return .terminateLater
        }
        catch { return .terminateNow }
    }
    func fail(_ error: Error) {
        FileHandle.standardError.write(Data("Oblivion lab: \(error)\n".utf8))
        if terminationPending { NSApp.reply(toApplicationShouldTerminate: true); return }
        NSApp.terminate(nil)
    }
}

enum Failure: Error { case message(String) }
@main
struct Main {
    @MainActor static func main() {
        let application = NSApplication.shared
        let laboratory = Laboratory()
        application.setActivationPolicy(.regular)
        application.delegate = laboratory
        withExtendedLifetime(laboratory) { application.run() }
    }
}
