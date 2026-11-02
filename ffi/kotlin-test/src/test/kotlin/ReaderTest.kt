import org.json.JSONObject
import uniffi.siros_verifier_core_ffi.FfiException
import uniffi.siros_verifier_core_ffi.Reader
import uniffi.siros_verifier_core_ffi.ReaderAuth
import uniffi.siros_verifier_core_ffi.ReaderAuthSigner
import uniffi.siros_verifier_core_ffi.RequestedDocument
import uniffi.siros_verifier_core_ffi.RequestedElement
import uniffi.siros_verifier_core_ffi.RequestedNamespace
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertContentEquals
import kotlin.test.assertTrue

/** ISO/IEC 18013-5 Annex D.5 vectors, driven through the generated bindings and the native library. */
class ReaderTest {
    private val v = JSONObject(javaClass.getResource("/iso18013_annex_d5.json")!!.readText())

    private fun hex(k: String) = v.getString(k).chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun hexOf(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun reader() = Reader.startWithKeyForVectors(
        hexOf(v.getJSONObject("ereader").getString("d")), hex("device_engagement"), hex("handover"),
    )

    private fun specRequest(): ByteArray {
        val ct = extractData(hex("session_establishment"))
        val iv = ByteArray(12).also { it[11] = 1 }
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, javax.crypto.spec.SecretKeySpec(hex("sk_reader"), "AES"), javax.crypto.spec.GCMParameterSpec(128, iv))
        return cipher.doFinal(ct)
    }

    @Test
    fun specResponseVerifiesThroughKotlin() {
        val docs = reader().openResponse(hex("session_data"), 1_610_000_000L, listOf("org.iso.18013.5.1.mDL"))
        assertEquals(1, docs.size)
        val d = docs[0]
        assertEquals("org.iso.18013.5.1.mDL", d.docType)
        assertTrue(d.elements.any { it.identifier == "family_name" })
        assertEquals(1, d.issuerX5c.size)
        val req = JSONObject(d.authzenRequestJson)
        assertEquals("x5c", req.getJSONObject("resource").getString("type"))
        assertTrue(req.getJSONObject("subject").getString("id").startsWith("x509_hash:"))
    }

    @Test
    fun establishmentMessageMatchesTheSpecByteForByte() {
        // decrypt the spec's request with the spec's SKReader (JCA, independent of the Rust code), re-send it through the library
        val est = hex("session_establishment")
        val plain = specRequest()
        assertContentEquals(est, reader().establishmentMessage(plain))
    }

    @Test
    fun rejectionsArriveAsTypedExceptionsWithStableCodes() {
        val e = assertFailsWith<FfiException.Rejected> {
            reader().openResponse(hex("session_data"), 1_610_000_000L, listOf("eu.europa.ec.eudi.pid.1"))
        }
        assertEquals("policy", e.code)
        val bad = assertFailsWith<FfiException.Rejected> { Reader.start(byteArrayOf(0xa0.toByte()), byteArrayOf(0xf6.toByte())) }
        assertTrue(bad.code in setOf("malformed", "policy"))
    }

    @Test
    fun terminationIsNotAFailure() {
        val e = assertFailsWith<FfiException.SessionOver> { reader().openResponse(hexOf("a16673746174757314"), 0, emptyList()) }
        assertEquals(20uL, e.status)
    }

    @Test
    fun aSecondEstablishmentIsRefused() {
        val r = reader()
        r.establishmentMessage(byteArrayOf(0xa0.toByte()))
        assertFailsWith<FfiException.Rejected> { r.establishmentMessage(byteArrayOf(0xa0.toByte())) }
    }

    @Test
    fun hostReaderAuthSignerMatchesTheSpecAndVerifiesWithJca() {
        val spec = specRequest()
        val signature = spec.copyOfRange(spec.size - 64, spec.size)
        val certificate = certificate(spec)
        val signer = ReplaySigner(signature)
        val auth = ReaderAuth(listOf(certificate.encoded), signer)
        val elements = listOf(
            "family_name" to true,
            "document_number" to true,
            "driving_privileges" to true,
            "issue_date" to true,
            "expiry_date" to true,
            "portrait" to false,
        ).map { (identifier, retain) -> RequestedElement(identifier, retain) }
        val document = RequestedDocument(
            "org.iso.18013.5.1.mDL",
            listOf(RequestedNamespace("org.iso.18013.5.1", elements)),
            auth,
        )
        val built = reader().buildDeviceRequest(listOf(document))
        assertContentEquals(spec, built)

        val signingInput = signer.signingInput!!
        assertEquals(775, signingInput.size)
        val verifier = java.security.Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(certificate.publicKey)
        verifier.update(signingInput)
        assertTrue(verifier.verify(rawSignatureToDer(signature)))
    }

    private class ReplaySigner(private val signature: ByteArray) : ReaderAuthSigner {
        var signingInput: ByteArray? = null
        override fun signEs256(`data`: ByteArray): ByteArray {
            signingInput = data
            return signature
        }
    }

    private fun certificate(request: ByteArray): X509Certificate {
        val factory = CertificateFactory.getInstance("X.509")
        for (offset in 0 until request.size - 4) {
            if (request[offset] != 0x30.toByte() || request[offset + 1] != 0x82.toByte()) continue
            try {
                return factory.generateCertificate(ByteArrayInputStream(request, offset, request.size - offset)) as X509Certificate
            } catch (_: java.security.cert.CertificateException) {
                // Not the certificate's DER SEQUENCE; keep looking.
            }
        }
        error("no X.509 certificate in DeviceRequest")
    }

    private fun rawSignatureToDer(signature: ByteArray): ByteArray {
        fun integer(value: ByteArray): ByteArray {
            val unsigned = value.dropWhile { it == 0.toByte() }.ifEmpty { listOf(0.toByte()) }.toByteArray()
            val needsZero = unsigned[0].toInt() and 0x80 != 0
            val content = if (needsZero) byteArrayOf(0) + unsigned else unsigned
            return byteArrayOf(0x02, content.size.toByte()) + content
        }
        val body = integer(signature.copyOfRange(0, 32)) + integer(signature.copyOfRange(32, 64))
        return byteArrayOf(0x30, body.size.toByte()) + body
    }

    /** { "eReaderKey": ..., "data": bstr } -> the data bytes (minimal CBOR walk for this one shape). */
    private fun extractData(b: ByteArray): ByteArray {
        val key = "data".toByteArray()
        outer@ for (i in 0 until b.size - key.size) {
            for (j in key.indices) if (b[i + j] != key[j]) continue@outer
            var p = i + key.size
            val head = b[p].toInt() and 0xff
            assertEquals(0x59, head, "bstr with 2-byte length")
            val len = ((b[p + 1].toInt() and 0xff) shl 8) or (b[p + 2].toInt() and 0xff)
            return b.copyOfRange(p + 3, p + 3 + len)
        }
        error("no data member")
    }
}
