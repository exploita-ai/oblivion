import Darwin
import Dispatch
import RuntimeLifetime
import XCTest

final class SupervisorLifetimeTests: XCTestCase {
    private func endpoints() throws -> (Int32, Int32) {
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else {
            throw SupervisorLifetimeFailure.required
        }
        return (pair[0], pair[1])
    }

    func testEOFAndUnexpectedDataRevokeTheEndpoint() throws {
        let (parent, child) = try endpoints()
        let lifetime = try SupervisorLifetime(taking: child)
        XCTAssertNoThrow(try lifetime.check())
        close(parent)
        XCTAssertThrowsError(try lifetime.check()) { error in
            XCTAssertEqual(error as? SupervisorLifetimeFailure, .lost)
        }
        let (writer, other) = try endpoints()
        defer { close(writer) }
        let second = try SupervisorLifetime(taking: other)
        var byte: UInt8 = 1
        XCTAssertEqual(write(writer, &byte, 1), 1)
        XCTAssertThrowsError(try second.check())
    }

    func testChildExecCannotInheritTheLifetimeEndpoint() throws {
        let (parent, child) = try endpoints()
        defer { close(parent) }
        XCTAssertEqual(fcntl(child, F_SETFD, 0), 0)
        let lifetime = try SupervisorLifetime(taking: child)
        XCTAssertNotEqual(fcntl(child, F_GETFD) & FD_CLOEXEC, 0)
        XCTAssertNoThrow(try lifetime.check())
    }

    func testReadSourceNotifiesOnSupervisorLoss() throws {
        let (parent, child) = try endpoints()
        let lifetime = try SupervisorLifetime(taking: child)
        let lost = expectation(description: "supervisor socket closed")
        lifetime.monitor(queue: DispatchQueue(label: "lifetime-test")) { lost.fulfill() }
        close(parent)
        wait(for: [lost], timeout: 2)
        lifetime.cancel()
    }
    func testInheritedCapabilityMustBeAStreamSocket() throws {
        var pair: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_DGRAM, 0, &pair), 0)
        defer { close(pair[0]) }
        XCTAssertThrowsError(try SupervisorLifetime(taking: pair[1])) { error in
            XCTAssertEqual(error as? SupervisorLifetimeFailure, .required)
        }
    }

}
