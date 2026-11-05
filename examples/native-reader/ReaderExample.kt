import uniffi.siros_verifier_core_ffi.Reader
import uniffi.siros_verifier_core_ffi.ReaderAuth
import uniffi.siros_verifier_core_ffi.ReaderAuthSigner
import uniffi.siros_verifier_core_ffi.RequestedDocument
import uniffi.siros_verifier_core_ffi.RequestedElement
import uniffi.siros_verifier_core_ffi.RequestedNamespace
import uniffi.siros_verifier_core_ffi.VerifiedDocument

/** Host interfaces only; no application or transport implementation is implied. */
interface ExampleTransport {
    fun exchange(message: ByteArray): ByteArray
    fun send(message: ByteArray)
}

interface ExamplePdp {
    fun permit(authzenRequestJson: String): Boolean
}

fun signWithLongTermP256ReaderKey(data: ByteArray): ByteArray {
    // Return raw r || s with the host's long-term key, not a DER signature or session key.
    TODO("Implement with the host's protected ReaderAuth key")
}

// deviceEngagement is raw CBOR. handover is 0xf6 for QR or nfcHandoverCbor's output for NFC.
fun presentMdl(
    deviceEngagement: ByteArray,
    handover: ByteArray,
    transport: ExampleTransport,
    pdp: ExamplePdp,
    leafReaderCertificateDer: ByteArray,
    clock: () -> Long,
): List<VerifiedDocument> {
    val reader = Reader.startWithRole(deviceEngagement, handover, "pid-provider")
    val auth = ReaderAuth(
        listOf(leafReaderCertificateDer),
        object : ReaderAuthSigner {
            override fun signEs256(data: ByteArray): ByteArray = signWithLongTermP256ReaderKey(data)
        },
    )
    val document = RequestedDocument(
        "org.iso.18013.5.1.mDL",
        listOf(
            RequestedNamespace(
                "org.iso.18013.5.1",
                listOf(
                    RequestedElement("given_name", false),
                    RequestedElement("family_name", false),
                ),
            ),
        ),
        auth,
    )

    val establishment = reader.establishmentMessageFromDocuments(listOf(document))
    val sessionData = transport.exchange(establishment)
    // Sample after holder consent/transport, immediately before validity verification.
    val verified = reader.openResponse(sessionData, clock(), listOf("org.iso.18013.5.1.mDL"))

    // Cryptographic validity is not a trust decision. Withhold every element until each permit.
    val permitted = verified.filter { pdp.permit(it.authzenRequestJson) }
    transport.send(reader.terminationMessage())
    return permitted
}
