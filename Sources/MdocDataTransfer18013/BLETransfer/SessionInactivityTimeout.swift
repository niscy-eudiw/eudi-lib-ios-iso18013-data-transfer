import Foundation
import MdocDataModel18013
import os

/// One monotonic inactivity deadline per engagement, shared by both BLE roles.
final class SessionInactivityTimeout: @unchecked Sendable {
    typealias Action = @Sendable () -> Void
    typealias Scheduler = @Sendable (TimeInterval, @escaping Action) -> Action
    typealias Observer = @Sendable (Bool) -> Bool
    static let defaultInterval: TimeInterval = 300
    private static let origin = ContinuousClock.now
    private static func monotonicTime() -> TimeInterval {
        let elapsed = origin.duration(to: ContinuousClock.now).components
        return Double(elapsed.seconds) + Double(elapsed.attoseconds) / 1e18
    }
    private struct Key: Hashable {
        let area: ObjectIdentifier
        let id: String
        let index: Int
    }
    private final class WeakTimer: @unchecked Sendable {
        weak var value: SessionInactivityTimeout?
        init(_ value: SessionInactivityTimeout) { self.value = value }
    }
    private static let timers = OSAllocatedUnfairLock(initialState: [Key: WeakTimer]())

    static func shared(for key: CoseKeyPrivate) -> SessionInactivityTimeout {
        timers.withLock { entries in
            entries = entries.filter { $0.value.value != nil }
            let identifier = Key(area: ObjectIdentifier(key.secureArea), id: key.privateKeyId, index: key.index)
            if let timer = entries[identifier]?.value { return timer }
            let timer = SessionInactivityTimeout()
            entries[identifier] = WeakTimer(timer)
            return timer
        }
    }

    private let lock = NSRecursiveLock()
    private let interval: TimeInterval
    private let clock: @Sendable () -> TimeInterval
    private let schedule: Scheduler
    private var deadline: TimeInterval?
    private var generation = UUID()
    private var cancellation: Action?
    private var observers: [(ObjectIdentifier, Observer)] = []

    init(interval: TimeInterval = defaultInterval,
         clock: @escaping @Sendable () -> TimeInterval = { SessionInactivityTimeout.monotonicTime() },
         schedule: @escaping Scheduler = { delay, action in
             let task = Task {
                 do { try await Task.sleep(for: .seconds(delay)) } catch { return }
                 guard !Task.isCancelled else { return }
                 await MainActor.run { action() }
             }
             return { task.cancel() }
         }) {
        precondition(interval.isFinite && interval > 0)
        self.interval = interval
        self.clock = clock
        self.schedule = schedule
    }

    func observe(_ owner: AnyObject, onExpiry: @escaping Observer) {
        lock.withLock {
            let id = ObjectIdentifier(owner)
            if !observers.contains(where: { $0.0 == id }) { observers.append((id, onExpiry)) }
            if deadline == nil { deadline = clock() + interval; arm() }
        }
    }

    /// Check expiry at event admission too, in case delivery of the timer was delayed.
    @discardableResult func check() -> Bool {
        let result: (Bool, UUID?) = lock.withLock {
            guard let deadline else { return (false, nil) }
            return clock() < deadline ? (true, nil) : (false, generation)
        }
        if let token = result.1 { fire(token) }
        return result.0
    }

    /// Only complete requests and trusted outbound progress refresh the deadline.
    func activity() {
        guard check() else { return }
        lock.withLock {
            guard let deadline, clock() < deadline else { return }
            self.deadline = clock() + interval
            arm()
        }
    }

    func cancel() {
        lock.withLock {
            generation = UUID()
            deadline = nil
            cancellation?()
            cancellation = nil
            observers.removeAll()
        }
    }

    /// End the entire engagement, including an idle sibling BLE role.
    func end() {
        let callbacks = lock.withLock {
            let callbacks = observers.map(\.1)
            cancel()
            return callbacks
        }
        for callback in callbacks { _ = callback(false) }
    }

    private func arm() {
        cancellation?()
        generation = UUID()
        let token = generation
        cancellation = schedule(max(0, deadline! - clock())) { [weak self] in self?.fire(token) }
    }

    private func fire(_ token: UUID) {
        let callbacks: [Observer] = lock.withLock {
            guard token == generation, let deadline else { return [] }
            guard clock() >= deadline else { arm(); return [] }
            let callbacks = observers.map(\.1)
            cancel()
            return callbacks
        }
        var notified = false
        for callback in callbacks { notified = callback(!notified) || notified }
    }

    deinit { cancellation?() }
}
