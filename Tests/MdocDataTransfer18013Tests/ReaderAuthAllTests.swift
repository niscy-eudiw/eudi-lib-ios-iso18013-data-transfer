import Foundation
import CryptoKit
import Testing
import X509
import SwiftCBOR
import MdocDataModel18013
import MdocSecurity18013
@testable import MdocDataTransfer18013

struct ReaderAuthAllTests {
    @Test func readerAuthAllOnlyAuthenticatesEveryRequestedDocument() async throws {
        let fixture = try await Fixture()
        let signer = try Signer(name: "Reader All")
        let request = try fixture.request(signers: [signer])
        let result = try await fixture.decode(request, trusted: [signer.certificate]).get()
        #expect(result.readerAuthResults.count == 2)
        #expect(result.readerAuthResults.values.allSatisfy { $0.isValidated })
        #expect(result.defaultReaderAuthResult?.certificateIssuer == "Reader All")
    }

    @Test func everySignerMustValidateAndMultipleIdentitiesAreExposed() async throws {
        let fixture = try await Fixture()
        let first = try Signer(name: "First Reader")
        let second = try Signer(name: "Second Reader")
        let result = try await fixture.decode(try fixture.request(signers: [first, second]), trusted: [first.certificate, second.certificate]).get()
        #expect(result.readerAuthAllResults.count == 2)
        #expect(result.readerAuthAllResults.allSatisfy { $0.isValidated })
        #expect(result.readerAuthResults.values.allSatisfy { $0.isValidated })
        #expect(result.defaultReaderAuthResult == nil)
    }

    @Test(arguments: [false, true])
    func invalidOrUntrustedSecondSignatureCannotBeIgnored(_ invalid: Bool) async throws {
        let fixture = try await Fixture()
        let first = try Signer(name: "Trusted Reader")
        let second = try Signer(name: "Other Reader")
        var request = try fixture.request(signers: [first, second])
        if invalid {
            request["readerAuthAll"] = .array([try first.sign(fixture.payload()), try second.sign(fixture.payload(), tampered: true)])
        }
        let trusted: Set<Data> = invalid ? [first.certificate, second.certificate] : [first.certificate]
        let result = try await fixture.decode(request, trusted: trusted).get()
        #expect(result.readerAuthAllResults[0].isValidated)
        #expect(!result.readerAuthAllResults[1].isValidated)
        #expect(result.readerAuthResults.values.allSatisfy { !$0.isValidated && $0.authBytes != nil })
        #expect(result.defaultReaderAuthResult == nil)
    }

    @Test(arguments: [false, true])
    func mixedLegacyAndAllCannotHideEitherFailedSignature(_ invalidAll: Bool) async throws {
        let fixture = try await Fixture()
        let signer = try Signer(name: "Reader")
        var request = try fixture.request(signers: [signer])
        let legacyPayload = CBOR.array([.utf8String("ReaderAuthentication"), fixture.session.sessionTranscript.toCBOR(options: CBOROptions()), fixture.items[0]]).taggedEncoded.encode()
        guard case var .array(documents) = request["docRequests"] else { return }
        documents[0]["readerAuth"] = try signer.sign(legacyPayload, tampered: !invalidAll)
        request["docRequests"] = .array(documents)
        request["readerAuthAll"] = .array([try signer.sign(fixture.payload(), tampered: invalidAll)])
        let result = try await fixture.decode(request, trusted: [signer.certificate]).get()
        #expect(result.readerAuthResults["mdl"]?.isValidated == false)
        #expect(result.readerAuthResults["pid"]?.isValidated == !invalidAll)
        #expect(result.defaultReaderAuthResult == nil)
    }

    @Test(arguments: [false, true])
    func legacyAndUnsignedRequestsKeepTheirMeaning(_ signed: Bool) async throws {
        let fixture = try await Fixture()
        let signer = try Signer(name: "Legacy Reader")
        let documents: [CBOR] = try fixture.items.map { item in
            var doc: CBOR = .map([.utf8String("itemsRequest"): item])
            if signed {
                let payload = CBOR.array([.utf8String("ReaderAuthentication"), fixture.session.sessionTranscript.toCBOR(options: CBOROptions()), item]).taggedEncoded.encode()
                doc["readerAuth"] = try signer.sign(payload)
            }
            return doc
        }
        let request = CBOR.map([.utf8String("version"): .utf8String("1.0"), .utf8String("docRequests"): .array(documents)])
        let result = try await fixture.decode(request, trusted: [signer.certificate]).get()
        #expect(result.readerAuthAllResults.isEmpty)
        #expect(result.readerAuthResults.values.allSatisfy { $0.isValidated == signed })
        if signed { #expect(result.defaultReaderAuthResult?.certificateIssuer == "Legacy Reader") }
        else { #expect(result.readerAuthResults.values.allSatisfy { $0.authBytes == nil }) }
    }

    @Test func noncanonicalDeviceInfoIsVerifiedUsingOriginalBytes() async throws {
        let fixture = try await Fixture()
        let signer = try Signer(name: "Reader")
        let info = CBOR.tagged(.encodedCBORDataItem, .byteString([0xbf,0x61,0x78,0x18,0x01,0xff]))
        let result = try await fixture.decode(try fixture.request(signers: [signer], info: info), trusted: [signer.certificate]).get()
        #expect(result.readerAuthResults.values.allSatisfy { $0.isValidated })
    }

    @Test(arguments: [0,1,2,3])
    func tamperingWithSignedRequestOrTranscriptFails(_ variant: Int) async throws {
        let fixture = try await Fixture()
        let signer = try Signer(name: "Reader")
        let info = CBOR.map([.utf8String("x"): .unsignedInt(1)]).taggedEncoded
        var request = try fixture.request(signers: [signer], info: info)
        switch variant {
        case 0:
            request["docRequests"] = .array(fixture.items.reversed().map { .map([.utf8String("itemsRequest"): $0]) })
        case 1:
            request["deviceRequestInfo"] = CBOR.map([.utf8String("x"): .unsignedInt(2)]).taggedEncoded
        case 2:
            let replacement: CBOR = .map([.utf8String("docType"): .utf8String("mdl"),
                .utf8String("nameSpaces"): .map([.utf8String("namespace"): .map([.utf8String("portrait"): .boolean(false)])])])
            request["docRequests"] = .array([.map([.utf8String("itemsRequest"): replacement.taggedEncoded]),
                .map([.utf8String("itemsRequest"): fixture.items[1]])])
        default:
            request["readerAuthAll"] = .array([try signer.sign(fixture.payload(info: info, transcript: SessionTranscript(handOver: .utf8String("other session"))))])
        }
        let result = try await fixture.decode(request, trusted: [signer.certificate]).get()
        #expect(result.readerAuthResults.values.allSatisfy { !$0.isValidated })
    }

    @Test func protectedCertificateHeaderIsSupported() async throws {
        let fixture = try await Fixture()
        let signer = try Signer(name: "Protected Reader")
        let result = try await fixture.decode(try fixture.request(signers: [signer], protectedChain: true), trusted: [signer.certificate]).get()
        #expect(result.readerAuthResults.values.allSatisfy { $0.isValidated })
    }

    @Test func attachedPayloadCannotPassDetachedReaderAuthentication() async throws {
        let fixture = try await Fixture()
        let signer = try Signer(name: "Reader")
        var request = try fixture.request(signers: [signer])
        guard case var .array(fields) = try signer.sign(fixture.payload()) else { return }
        fields[2] = .byteString([0])
        request["readerAuthAll"] = .array([.array(fields)])
        let result = try await fixture.decode(request, trusted: [signer.certificate]).get()
        #expect(result.readerAuthResults.values.allSatisfy { !$0.isValidated })
    }

    @Test(arguments: [false, true])
    func repeatedDocumentTypesCannotOverwriteAnUnsignedRequest(_ useAll: Bool) async throws {
        let fixture = try await Fixture()
        let signer = try Signer(name: "Reader")
        let items = [fixture.items[0], fixture.items[0]]
        let legacyPayload = CBOR.array([.utf8String("ReaderAuthentication"), fixture.session.sessionTranscript.toCBOR(options: CBOROptions()), items[1]]).taggedEncoded.encode()
        let documents: [CBOR] = [.map([.utf8String("itemsRequest"): items[0]]),
            .map([.utf8String("itemsRequest"): items[1], .utf8String("readerAuth"): try signer.sign(legacyPayload)])]
        var request: CBOR = .map([.utf8String("version"): .utf8String(useAll ? "1.1" : "1.0"), .utf8String("docRequests"): .array(documents)])
        if useAll { request["readerAuthAll"] = .array([try signer.sign(fixture.payload(items: items))]) }
        let result = try await fixture.decode(request, trusted: [signer.certificate]).get()
        #expect(result.readerAuthResults.count == 1)
        #expect(result.readerAuthResults["mdl"]?.isValidated == useAll)
        #expect(result.defaultReaderAuthResult?.isValidated == useAll)
    }

    @Test(arguments: [0,1,2])
    func malformedAuthAllFailsInsteadOfBecomingUnsigned(_ variant: Int) async throws {
        let fixture = try await Fixture()
        let signer = try Signer(name: "Reader")
        var request = try fixture.request(signers: [signer])
        request["readerAuthAll"] = [CBOR.map([:]), .array([]), .array([.array([])])][variant]
        if case .success = await fixture.decode(request, trusted: [signer.certificate]) { Issue.record("Malformed authentication accepted") }
    }

    struct Signer {
        let key = P256.Signing.PrivateKey()
        let certificate: Data
        init(name: String) throws {
            let privateKey = Certificate.PrivateKey(key)
            let dn = try DistinguishedName { CommonName(name) }
            let cert = try Certificate(version: .v3, serialNumber: .init(), publicKey: privateKey.publicKey,
                notValidBefore: Date() - 60, notValidAfter: Date() + 3600, issuer: dn, subject: dn,
                extensions: Certificate.Extensions {}, issuerPrivateKey: privateKey)
            certificate = Data(try cert.serializeAsPEM().derBytes)
        }
        func sign(_ payload: [UInt8], protectedChain: Bool = false, tampered: Bool = false) throws -> CBOR {
            var header: CBOR = .map([1: .negativeInt(6)])
            if protectedChain { header[33] = .byteString(Array(certificate)) }
            let protectedBytes = header.encode()
            let input: CBOR = .array([.utf8String("Signature1"), .byteString(protectedBytes), .byteString([]), .byteString(payload)])
            var signature = Array(try key.signature(for: Data(input.encode())).rawRepresentation)
            if tampered { signature[0] ^= 1 }
            return .array([.byteString(protectedBytes), protectedChain ? .map([:]) : .map([33: .byteString(Array(certificate))]),
                .null, .byteString(signature)])
        }
    }

    struct Fixture {
        let engagement: DeviceEngagement
        let session: SessionEncryption
        let readerKey: CoseKey
        let incomingKey: SymmetricKey
        let items: [CBOR]
        init() async throws {
            let area = SoftwareSecureArea.create(storage: ReaderAuthKeyStorage())
            var device = try #require(DeviceEngagement(supportsCentralClientMode: false, supportsPeripheralServerMode: true, readerAuthAllSupport: true))
            try await device.makePrivateKey(secureArea: area, keyOptions: .init(curve: .P256))
            let reader = P256.KeyAgreement.PrivateKey()
            readerKey = CoseKey(crv: .P256, x963Representation: reader.publicKey.x963Representation)
            let establishment = try SessionEstablishment(cbor: .map([.utf8String("eReaderKey"): readerKey.toCBOR(options: CBOROptions()).taggedEncoded,
                .utf8String("data"): .byteString([])]))
            session = try #require(SessionEncryption(se: establishment, de: device, handOver: .null, authenticationContext: ThreadSafeAuthContext()))
            var deviceKey = try #require(device.privateKey)
            let devicePublic = try await deviceKey.key
            let secret = try reader.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: devicePublic.x963Representation))
            incomingKey = secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: session.sessionTranscriptBytes,
                sharedInfo: Data("SKReader".utf8), outputByteCount: 32)
            engagement = device
            items = ["mdl", "pid"].map { docType in
                CBOR.map([.utf8String("docType"): .utf8String(docType),
                    .utf8String("nameSpaces"): .map([.utf8String("namespace"): .map([.utf8String("family_name"): .boolean(false)])])]).taggedEncoded
            }
        }
        func payload(items: [CBOR]? = nil, info: CBOR? = nil, transcript: SessionTranscript? = nil) -> [UInt8] {
            CBOR.array([.utf8String("ReaderAuthenticationAll"), (transcript ?? session.sessionTranscript).toCBOR(options: CBOROptions()),
                .array(items ?? self.items), info ?? .null]).taggedEncoded.encode()
        }
        func request(signers: [Signer], info: CBOR? = nil, protectedChain: Bool = false) throws -> CBOR {
            var request: CBOR = .map([.utf8String("version"): .utf8String("1.1"),
                .utf8String("docRequests"): .array(items.map { .map([.utf8String("itemsRequest"): $0]) }),
                .utf8String("readerAuthAll"): .array(try signers.map { try $0.sign(payload(info: info), protectedChain: protectedChain) })])
            if let info { request["deviceRequestInfo"] = info }
            return request
        }
        func decode(_ request: CBOR, trusted: Set<Data>) async -> Result<UserRequestInfo, Error> {
            do {
                let nonce = try AES.GCM.Nonce(data: Data([0,0,0,0,0,0,0,0,0,0,0,1]))
                let box = try AES.GCM.seal(Data(request.encode()), using: incomingKey, nonce: nonce)
                let ciphertext = Array(try #require(box.combined).dropFirst(12))
                let establishment: CBOR = .map([.utf8String("eReaderKey"): readerKey.toCBOR(options: CBOROptions()).taggedEncoded,
                    .utf8String("data"): .byteString(ciphertext)])
                let result = await MdocHelpers.decodeRequestAndInformUser(deviceEngagement: engagement, docs: [:], docMetadata: [:],
                    trustValidator: ReaderAuthTrust(trusted: trusted), requestData: Data(establishment.encode()), privateKeyObjects: [:],
                    dauthMethod: .deviceSignature, unlockData: [:], readerKeyRawData: nil, handOver: .null, authenticationContext: ThreadSafeAuthContext())
                return result.map(\.userRequestInfo)
            } catch { return .failure(error) }
        }
    }
}

private struct ReaderAuthTrust: CertificateTrustValidator {
    var docType: String? = "reader-context"
    let trusted: Set<Data>
    func createCertTrustPath(chain: [Data]) async -> [Data]? { chain }
    func validateCertTrustPath(chain: [Data]) async -> (Bool, String?) {
        let accepted = chain.first.map { trusted.contains($0) } == true && docType == "reader-context"
        return (accepted, accepted ? nil : "Reader certificate is untrusted")
    }
}

private actor ReaderAuthKeyStorage: SecureKeyStorage {
    var info: [String: [String: Data]] = [:]
    var keys: [String: [Int: [String: Data]]] = [:]
    func readKeyInfo(id: String) async throws -> [String: Data] { info[id] ?? [:] }
    func readKeyData(id: String, index: Int, authenticationContext: ThreadSafeAuthContext) async throws -> [String: Data] { keys[id]?[index] ?? [:] }
    func writeKeyInfo(id: String, dict: [String: Data]) async throws { info[id] = dict }
    func writeKeyDataBatch(id: String, startIndex: Int, dicts: [[String: Data]], keyOptions: KeyOptions?) async throws {
        for (offset, dict) in dicts.enumerated() { keys[id, default: [:]][startIndex + offset] = dict }
    }
    func deleteKeyBatch(id: String, startIndex: Int, batchSize: Int) async throws {
        for index in startIndex..<(startIndex + batchSize) { keys[id]?[index] = nil }
    }
    func deleteKeyInfo(id: String) async throws { info[id] = nil }
}
