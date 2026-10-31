import org.json.JSONObject
import uniffi.siros_verifier_core_ffi.FfiException
import uniffi.siros_verifier_core_ffi.Reader
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
        val ct = extractData(est)
        val iv = ByteArray(12).also { it[11] = 1 }
        val c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        c.init(javax.crypto.Cipher.DECRYPT_MODE, javax.crypto.spec.SecretKeySpec(hex("sk_reader"), "AES"), javax.crypto.spec.GCMParameterSpec(128, iv))
        val plain = c.doFinal(ct)
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
