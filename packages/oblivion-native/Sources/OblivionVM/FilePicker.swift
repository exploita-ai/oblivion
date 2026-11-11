import AppKit
import Darwin
import Dispatch
import Foundation
import RuntimeLifetime

enum FilePickerFailure: String, Error {
    case unavailable = "file_picker_unavailable"
    case output = "file_picker_output_failed"
}

private let maximumPaths = 128
private let maximumPathBytes = 64 * 1024

@MainActor
func pickFiles() throws {
    // Bun passes stdin as a Unix stream. Reuse the exact owner check used
    // for the VM helper and handle an already revoked request before AppKit.
    let owner: SupervisorLifetime
    do {
        owner = try SupervisorLifetime(taking: STDIN_FILENO)
    } catch SupervisorLifetimeFailure.lost {
        try writePaths([])
        return
    }
    let application = NSApplication.shared
    guard application.setActivationPolicy(.accessory) else { throw FilePickerFailure.unavailable }
    let picker = FilesPalette(owner: owner)
    picker.show(application)
    withExtendedLifetime(picker) { application.run() }
    throw FilePickerFailure.unavailable
}

private func writePaths(_ paths: [String]) throws {
    struct Selection: Encodable { let paths: [String] }
    do {
        var response = try JSONEncoder().encode(Selection(paths: paths))
        response.append(10)
        _ = signal(SIGPIPE, SIG_IGN)
        try FileHandle.standardOutput.write(contentsOf: response)
    } catch {
        throw FilePickerFailure.output
    }
}

private func localPaths(_ urls: [URL]) -> [String]? {
    guard (1...maximumPaths).contains(urls.count) else { return nil }
    var paths: [String] = []
    var bytes = 0
    for url in urls {
        guard url.isFileURL, url.baseURL == nil, !(url as NSURL).isFileReferenceURL(),
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.user == nil, components.password == nil, components.port == nil,
              components.query == nil, components.fragment == nil else { return nil }
        let host = components.percentEncodedHost ?? ""
        guard host.isEmpty || host.lowercased() == "localhost" else { return nil }
        let encoded = components.percentEncodedPath
        guard encoded.utf8.count <= 3 * (maximumPathBytes - bytes),
              !encoded.lowercased().contains("%2f"),
              let path = encoded.removingPercentEncoding, path.hasPrefix("/"),
              !path.hasPrefix("//"), !path.utf8.contains(0) else { return nil }
        bytes += path.utf8.count
        guard bytes <= maximumPathBytes else { return nil }
        paths.append(path)
    }
    return paths
}

@MainActor
private final class FilesPalette: NSObject, NSWindowDelegate {
    private let window = NSWindow(
        contentRect: NSRect(x: 0, y: 0, width: 420, height: 155),
        styleMask: [.titled, .closable], backing: .buffered, defer: false
    )
    private let message = NSTextField(wrappingLabelWithString: "Review the selection in Oblivion before copying.")
    private let owner: SupervisorLifetime
    private var chooser: NSOpenPanel?
    private var finished = false

    init(owner: SupervisorLifetime) {
        self.owner = owner
        super.init()
        window.title = "Oblivion Files"
        window.isReleasedWhenClosed = false
        window.delegate = self
        let drop = FileDropView()
        drop.choose = { [weak self] urls in self?.choose(urls) ?? false }
        drop.invalid = { [weak self] in self?.invalidSelection() }
        window.contentView = drop

        let title = NSTextField(labelWithString: "Drop files or folders here")
        title.font = .systemFont(ofSize: 16, weight: .semibold)
        message.textColor = .secondaryLabelColor
        message.alignment = .center
        let cancel = NSButton(title: "Cancel", target: self, action: #selector(cancelSelection))
        cancel.keyEquivalent = "\u{1b}"
        let browse = NSButton(title: "Choose files…", target: self, action: #selector(browseFiles))
        browse.keyEquivalent = "\r"
        let buttons = NSStackView(views: [cancel, browse])
        buttons.spacing = 8
        let layout = NSStackView(views: [title, message, buttons])
        layout.orientation = .vertical
        layout.alignment = .centerX
        layout.spacing = 12
        layout.translatesAutoresizingMaskIntoConstraints = false
        drop.addSubview(layout)
        NSLayoutConstraint.activate([
            layout.centerXAnchor.constraint(equalTo: drop.centerXAnchor),
            layout.centerYAnchor.constraint(equalTo: drop.centerYAnchor),
            message.widthAnchor.constraint(lessThanOrEqualTo: drop.widthAnchor, constant: -36),
        ])
    }

    func show(_ application: NSApplication) {
        owner.monitor(queue: .main) { [weak self] in self?.finish([]) }
        window.center()
        window.makeKeyAndOrderFront(nil)
        application.activate()
    }

    @objc private func browseFiles() {
        guard chooser == nil, !finished else { return }
        let panel = NSOpenPanel()
        panel.title = "Choose files or folders"
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.canCreateDirectories = false
        panel.allowsMultipleSelection = true
        panel.resolvesAliases = false
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser
        chooser = panel
        panel.beginSheetModal(for: window) { [weak self] result in
            guard let self else { return }
            self.chooser = nil
            if result == .OK {
                _ = self.choose(panel.urls)
            } else {
                self.finish([])
            }
        }
    }

    private func choose(_ urls: [URL]) -> Bool {
        guard !finished, chooser == nil, let paths = localPaths(urls) else {
            invalidSelection()
            return false
        }
        // Let AppKit acknowledge the drop before closing the palette process.
        DispatchQueue.main.async { [weak self] in self?.finish(paths) }
        return true
    }

    private func invalidSelection() {
        message.stringValue = "Choose up to 128 local files or folders, with at most 64 KiB of paths."
    }

    @objc private func cancelSelection() { finish([]) }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        finish([])
        return false
    }

    private func finish(_ paths: [String]) {
        guard !finished else { return }
        finished = true
        owner.cancel()
        chooser?.cancel(nil)
        window.orderOut(nil)
        do {
            try writePaths((try? owner.check()) == nil ? [] : paths)
            Darwin.exit(0)
        } catch let error as FilePickerFailure {
            report(error.rawValue)
            Darwin.exit(1)
        } catch {
            report(FilePickerFailure.unavailable.rawValue)
            Darwin.exit(1)
        }
    }
}

@MainActor
private final class FileDropView: NSView {
    var choose: (([URL]) -> Bool)?
    var invalid: (() -> Void)?

    init() {
        super.init(frame: .zero)
        registerForDraggedTypes([.fileURL])
    }

    required init?(coder: NSCoder) { nil }

    override func draggingEntered(_ sender: NSDraggingInfo) -> NSDragOperation {
        sender.draggingSourceOperationMask.contains(.copy) ? .copy : []
    }

    override func performDragOperation(_ sender: NSDraggingInfo) -> Bool {
        guard sender.draggingSourceOperationMask.contains(.copy),
              let items = sender.draggingPasteboard.pasteboardItems,
              (1...maximumPaths).contains(items.count) else {
            invalid?()
            return false
        }
        var urls: [URL] = []
        var encodedBytes = 0
        for item in items {
            guard let value = item.string(forType: .fileURL),
                  value.utf8.count <= 3 * maximumPathBytes + 32 * maximumPaths - encodedBytes,
                  let url = URL(string: value, encodingInvalidCharacters: false) else {
                invalid?()
                return false
            }
            encodedBytes += value.utf8.count
            urls.append(url)
        }
        return choose?(urls) ?? false
    }
}
