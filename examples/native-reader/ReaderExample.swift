import Foundation

protocol ExampleTransport {
    func exchange(_ message: Data) throws -> Data
    func send(_ message: Data) throws
}

protocol ExamplePdp {
    func permit(authzenRequestJson: String) -> Bool
}

final class LongTermReaderSigner: ReaderAuthSigner {
    func signEs256(data: Data) throws -> Data {
        // Return raw r || s with the host's long-term key, not a DER signature or session key.
        fatalError("Implement with the host's protected ReaderAuth key")
    }
}

// deviceEngagement is raw CBOR. handover is 0xf6 for QR or nfcHandoverCbor's output for NFC.
func presentMdl(
    deviceEngagement: Data,
    handover: Data,
    transport: ExampleTransport,
    pdp: ExamplePdp,
    leafReaderCertificateDer: Data,
    clock: () -> Int64
) throws -> [VerifiedDocument] {
    let reader = try Reader.startWithRole(
        deviceEngagement: deviceEngagement,
        handover: handover,
        mdocIssuerRole: "pid-provider"
    )
    let auth = ReaderAuth(x5cDer: [leafReaderCertificateDer], signer: LongTermReaderSigner())
    let document = RequestedDocument(
        docType: "org.iso.18013.5.1.mDL",
        namespaces: [
            RequestedNamespace(
                namespace: "org.iso.18013.5.1",
                elements: [
                    RequestedElement(identifier: "given_name", intentToRetain: false),
                    RequestedElement(identifier: "family_name", intentToRetain: false),
                ]
            )
        ],
        readerAuth: auth
    )

    let establishment = try reader.establishmentMessageFromDocuments(documents: [document])
    let sessionData = try transport.exchange(establishment)
    // Sample after holder consent/transport, immediately before validity verification.
    let verified = try reader.openResponse(
        sessionData: sessionData,
        now: clock(),
        acceptedDocTypes: ["org.iso.18013.5.1.mDL"]
    )

    // Cryptographic validity is not a trust decision. Withhold every element until each permit.
    let permitted = verified.filter { pdp.permit(authzenRequestJson: $0.authzenRequestJson) }
    try transport.send(reader.terminationMessage())
    return permitted
}
