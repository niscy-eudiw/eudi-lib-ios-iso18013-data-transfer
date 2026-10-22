import Foundation
import SwiftCBOR
import X509
import MdocDataModel18013
import MdocSecurity18013

extension MdocHelpers {
    /// Check every supplied signature using the caller's configured reader trust policy.
    /// A request-wide signature covers every DocRequest, including unsigned individual entries.
    static func readerAuthenticationResults(for request: DeviceRequest, transcript: SessionTranscript,
                                             trustValidator: any CertificateTrustValidator) async
        -> (documents: [DocType: ReaderAuthenticationResult], all: [ReaderAuthenticationResult]) {
        let authentication = MdocReaderAuthentication(transcript: transcript)
        var all: [ReaderAuthenticationResult] = []
        for (raw, auth) in zip(request.readerAuthAllRawCBOR ?? [], request.readerAuthAll ?? []) {
            let certificates = auth.x5chain.map { Data($0) }
            let result = await readerAuthenticationResult(raw: raw, certificates: certificates) {
                try await authentication.validateReaderAuthAll(readerAuthCBOR: raw, readerAuthX5c: certificates,
                    deviceRequest: request, trustValidator: trustValidator)
            }
            all.append(result)
        }
        var byDocType: [DocType: [ReaderAuthenticationResult]] = [:]
        for document in request.docRequests {
            var results = all
            if let raw = document.readerAuthRawCBOR, let items = document.itemsRequestRawData {
                let result = await readerAuthenticationResult(raw: raw, certificates: document.readerCertificates) {
                    try await authentication.validateReaderAuth(readerAuthCBOR: raw, readerAuthX5c: document.readerCertificates,
                        itemsRequestRawData: items, trustValidator: trustValidator)
                }
                results.append(result)
            } else if all.isEmpty {
                results.append(.init(isValidated: false, validationMessage: "Reader authentication not present in request"))
            }
            // Repeated document types must not overwrite an earlier failed/absent authentication.
            byDocType[document.itemsRequest.docType, default: []].append(contentsOf: results)
        }
        return (byDocType.mapValues(combineReaderAuthenticationResults), all)
    }

    private static func readerAuthenticationResult(raw: CBOR, certificates: [Data],
        validate: () async throws -> (Bool, String?)) async -> ReaderAuthenticationResult {
        let name = certificates.first.flatMap { try? X509.Certificate(derEncoded: Array($0)) }
            .map { getCN(from: $0.subject.description) }
        do {
            let (valid, message) = try await validate()
            return .init(isValidated: valid, certificateIssuer: name, validationMessage: message,
                authBytes: Data(raw.encode()), certificateChain: certificates)
        } catch {
            return .init(isValidated: false, certificateIssuer: name,
                validationMessage: "Reader auth validation failed: \(error.localizedDescription)",
                authBytes: Data(raw.encode()), certificateChain: certificates)
        }
    }

    private static func combineReaderAuthenticationResults(_ results: [ReaderAuthenticationResult]) -> ReaderAuthenticationResult {
        guard let first = results.first else { return .init(isValidated: false) }
        if results.count == 1 { return first }
        let valid = results.allSatisfy { $0.isValidated }
        let sameIdentity = first.certificateChain?.first.map { leaf in
            results.allSatisfy { $0.certificateChain?.first == leaf }
        } ?? false
        let bytes = results.compactMap(\.authBytes)
        return .init(isValidated: valid,
            certificateIssuer: valid && sameIdentity ? first.certificateIssuer : nil,
            validationMessage: valid ? nil : results.first(where: { !$0.isValidated })?.validationMessage,
            legalName: valid && sameIdentity ? first.legalName : nil,
            authBytes: bytes.isEmpty ? nil : Data(CBOR.array(bytes.map { .byteString(Array($0)) }).encode()),
            certificateChain: valid && sameIdentity ? first.certificateChain : nil)
    }
}
