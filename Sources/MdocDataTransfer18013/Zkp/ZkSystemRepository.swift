import Foundation
import MdocDataModel18013

/// A repository of ZkSystem implementations.
public class ZkSystemRepository {
    private var systems: [any ZkSystemProtocol] = []
    
    public init() {}
    
    /// Registers a new ZkSystem into the repository.
    ///
    /// - Parameter zkSystem: The ZkSystem implementation to add.
    /// - Returns: This repository instance for method chaining
    @discardableResult
    public func add(_ zkSystem: any ZkSystemProtocol) -> ZkSystemRepository {
        systems.append(zkSystem)
        return self
    }
    
    /// Looks up a registered ZkSystem by name.
    ///
    /// - Parameter zkSystemName: The name of the system to find.
    /// - Returns: The matching ZkSystem, or nil if not found.
    public func lookup(_ zkSystemName: String) -> (any ZkSystemProtocol)? {
        return systems.first { $0.name == zkSystemName }
    }
    
    /// Returns a list of all ZkSystemSpec from each ZkSystem implementation.
    ///
    /// - Returns: A list of ZkSystemSpec.
    public func getAllZkSystemSpecs() -> [ZkSystemSpec] {
        return systems.flatMap { $0.systemSpecs }
    }
}
