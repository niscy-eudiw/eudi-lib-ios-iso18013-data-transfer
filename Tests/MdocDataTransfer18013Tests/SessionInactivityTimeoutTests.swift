import Foundation
import Testing
import os
@testable import MdocDataTransfer18013

struct SessionInactivityTimeoutTests {
    @Test func defaultDeadlineExpiresAt300SecondsWithoutActivity() {
        let clock = TimeoutTestClock()
        let timer = clock.makeTimer()
        let owner = NSObject()
        timer.observe(owner) { notify in clock.recordExpiry(); return notify }
        clock.advance(299)
        #expect(timer.check())
        #expect(clock.expirations == 0)
        clock.advance(1)
        clock.deliver()
        #expect(clock.expirations == 1)
        #expect(!timer.check())
        clock.deliver()
        #expect(clock.expirations == 1)
    }

    @Test func activityExtendsDeadlineAndCancelledCallbacksCannotExpireIt() {
        let clock = TimeoutTestClock()
        let timer = clock.makeTimer()
        let owner = NSObject()
        timer.observe(owner) { notify in clock.recordExpiry(); return notify }
        clock.advance(200)
        timer.activity()
        clock.advance(100)
        clock.deliver() // Delivers the cancelled initial callback deliberately.
        #expect(timer.check())
        #expect(clock.expirations == 0)
        clock.advance(200)
        clock.deliver()
        #expect(clock.expirations == 1)
    }

    @Test func lateActivityCannotReviveExpiredSessionBeforeTimerDelivery() {
        let clock = TimeoutTestClock()
        let timer = clock.makeTimer()
        let owner = NSObject()
        timer.observe(owner) { notify in clock.recordExpiry(); return notify }
        clock.advance(301)
        timer.activity()
        #expect(clock.expirations == 1)
        #expect(!timer.check())
    }

    @Test func oldGenerationCannotExpireRestartedTimer() {
        let clock = TimeoutTestClock()
        let timer = clock.makeTimer()
        let owner = NSObject()
        timer.observe(owner) { notify in clock.recordExpiry(); return notify }
        clock.advance(100)
        timer.cancel()
        timer.observe(owner) { notify in clock.recordExpiry(); return notify }
        clock.advance(200)
        clock.deliver()
        #expect(clock.expirations == 0)
        clock.advance(100)
        clock.deliver()
        #expect(clock.expirations == 1)
    }
}

/// Delivers even cancelled scheduled actions, so tests exercise generation checks.
final class TimeoutTestClock: @unchecked Sendable {
    private struct State {
        var now: TimeInterval = 0
        var actions: [(TimeInterval, SessionInactivityTimeout.Action)] = []
        var expirations = 0
    }
    private let state = OSAllocatedUnfairLock(initialState: State())
    var now: TimeInterval { state.withLock { $0.now } }
    var expirations: Int { state.withLock { $0.expirations } }
    func recordExpiry() { state.withLock { $0.expirations += 1 } }
    func advance(_ seconds: TimeInterval) { state.withLock { $0.now += seconds } }
    func makeTimer() -> SessionInactivityTimeout {
        SessionInactivityTimeout(clock: { self.now }, schedule: { delay, action in
            self.state.withLock { $0.actions.append(($0.now + delay, action)) }
            return {}
        })
    }
    func deliver() {
        let actions = state.withLock { state in
            let due = state.actions.filter { $0.0 <= state.now }
            state.actions.removeAll { $0.0 <= state.now }
            return due.map(\.1)
        }
        let invoke = { for action in actions { action() } }
        if Thread.isMainThread { invoke() } else { DispatchQueue.main.sync(execute: invoke) }
    }
}
