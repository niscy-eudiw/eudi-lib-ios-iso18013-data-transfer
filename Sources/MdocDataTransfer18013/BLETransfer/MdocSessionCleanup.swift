import Foundation
import MdocDataModel18013
import MdocSecurity18013

/// Detach session state synchronously, then delete only the captured ephemeral key.
/// Advertising pauses are deliberately separate from session termination.
@discardableResult
func clearMdocSession(_ delegate: (any MdocOfflineDelegate)?, engagement capturedEngagement: DeviceEngagement? = nil) -> Task<Void, Never>? {
    let engagement = capturedEngagement ?? delegate?.deviceEngagement
    let key = engagement?.privateKey
    engagement?.invalidateSession()
    let currentKey = delegate?.deviceEngagement?.privateKey
    let ownsCurrentSession = capturedEngagement == nil ||
        (key?.privateKeyId == currentKey?.privateKeyId && key?.index == currentKey?.index &&
         key.map { ObjectIdentifier($0.secureArea) } == currentKey.map { ObjectIdentifier($0.secureArea) })
    if ownsCurrentSession {
        delegate?.sessionEncryption?.invalidate()
        delegate?.sessionEncryption = nil
        delegate?.deviceEngagement = nil
        delegate?.deviceRequest = nil
        delegate?.qrCodePayload = nil
        delegate?.deviceResponseBytes = nil
    }
    guard let key else { return nil }
    return Task { await deleteMdocSessionKey(key) }
}

func deleteMdocSessionKey(_ key: CoseKeyPrivate) async {
    do {
        try await key.secureArea.deleteKeyBatch(id: key.privateKeyId, startIndex: key.index, batchSize: 1)
        try await key.secureArea.deleteKeyInfo(id: key.privateKeyId)
    } catch {
        logger.error("Failed to delete terminated engagement key: \(error)")
    }
}
