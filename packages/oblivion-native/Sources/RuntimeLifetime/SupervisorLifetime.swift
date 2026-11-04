import Darwin
import Dispatch
import Foundation

public enum SupervisorLifetimeFailure: String, Error {
    case required = "supervisor_lifetime_required"
    case lost = "supervisor_lifetime_lost"
}

public final class SupervisorLifetime {
    private let handle: FileHandle
    private var source: DispatchSourceRead?

    public init(taking descriptor: Int32) throws {
        let flags = fcntl(descriptor, F_GETFD)
        guard flags >= 0 else { throw SupervisorLifetimeFailure.required }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        guard fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) == 0 else {
            throw SupervisorLifetimeFailure.required
        }
        var kind: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        var address = sockaddr_storage()
        var addressLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let local = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(descriptor, $0, &addressLength)
            }
        }
        guard getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &kind, &length) == 0,
              kind == SOCK_STREAM, local == 0, address.ss_family == AF_UNIX else {
            throw SupervisorLifetimeFailure.required
        }
        self.handle = handle
        try check()
    }

    public func check() throws {
        var byte: UInt8 = 0
        while true {
            let received = recv(handle.fileDescriptor, &byte, 1, MSG_PEEK | MSG_DONTWAIT)
            if received >= 0 { throw SupervisorLifetimeFailure.lost }
            if errno == EINTR { continue }
            if errno == EAGAIN || errno == EWOULDBLOCK { return }
            throw SupervisorLifetimeFailure.lost
        }
    }

    public func monitor(queue: DispatchQueue, lost: @escaping () -> Void) {
        let source = DispatchSource.makeReadSource(fileDescriptor: handle.fileDescriptor, queue: queue)
        source.setEventHandler { [weak self] in
            guard let self else { return }
            do { try self.check() }
            catch {
                self.cancel()
                lost()
            }
        }
        self.source = source
        source.resume()
    }

    public func cancel() {
        source?.cancel()
        source = nil
    }

    deinit { source?.cancel() }
}
