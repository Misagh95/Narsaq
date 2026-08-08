package dev.narsaq.speedtester.build

import dev.narsaq.speedtester.model.ConfigType
import dev.narsaq.speedtester.model.ParsedConfig
import dev.narsaq.speedtester.parse.ConfigParser
import dev.narsaq.speedtester.util.AntiFilterDefaults
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class ConfigRebuilderAntiFilterTest {

    private val af = ConfigRebuilder.AntiFilter(
        fragmentJson = AntiFilterDefaults.FRAGMENT_JSON,
        cipherSuites = AntiFilterDefaults.CIPHER_SUITES,
        fingerprintUnsafe = true
    )

    private fun parse(link: String): ParsedConfig {
        val parsed = ConfigParser.parse(link)
        assertTrue("config should parse", parsed.isNotEmpty())
        return parsed.first()
    }

    // ─── VLESS: fm (FinalMask) + cs (cipher suites) + fp=unsafe land in the query ───
    // These are the exact keys the PattNG client reads from share links,
    // mirroring the cf-optimizor tool.

    @Test
    fun `vless gets fm cs and fp in query`() {
        val cfg = parse("vless://uuid@original.example:443?encryption=none&security=tls&sni=real.example#label")
        val rebuilt = ConfigRebuilder.rebuild(cfg, "1.2.3.4", antiFilter = af)
        assertNotNull(rebuilt)
        assertTrue(rebuilt!!.startsWith("vless://uuid@1.2.3.4:443"))
        assertTrue("fm (FinalMask) missing", rebuilt.contains("fm="))
        assertTrue("cs (cipher suites) missing", rebuilt.contains("cs="))
        assertTrue("fp=unsafe missing", rebuilt.contains("fp=unsafe"))
        // original params preserved
        assertTrue("encryption lost", rebuilt.contains("encryption=none"))
        assertTrue("sni lost", rebuilt.contains("sni=real.example"))
    }

    // ─── Trojan: same keys as VLESS ───

    @Test
    fun `trojan gets fm cs and fp in query`() {
        val cfg = parse("trojan://password@original.example:443?security=tls&sni=real.example#label")
        val rebuilt = ConfigRebuilder.rebuild(cfg, "5.6.7.8", antiFilter = af)
        assertNotNull(rebuilt)
        assertTrue(rebuilt!!.startsWith("trojan://password@5.6.7.8:443"))
        assertTrue("fm missing", rebuilt.contains("fm="))
        assertTrue("cs missing", rebuilt.contains("cs="))
        assertTrue("sni lost", rebuilt.contains("sni=real.example"))
    }

    // ─── VMess: cf-optimizor passes it through — only the IP is swapped ───

    @Test
    fun `vmess is passed through with only ip swapped`() {
        val base64 = android.util.Base64.encodeToString(
            """{"v":"2","ps":"t","add":"original.example","port":"443","id":"uuid","aid":"0","scy":"auto","net":"ws","type":"none","host":"h","path":"/p","tls":"tls","sni":"real.example"}"""
                .toByteArray(Charsets.UTF_8),
            android.util.Base64.NO_WRAP
        )
        val cfg = parse("vmess://$base64#label")
        val rebuilt = ConfigRebuilder.rebuild(cfg, "9.9.9.9", antiFilter = af)
        assertNotNull(rebuilt)
        assertTrue(rebuilt!!.startsWith("vmess://"))

        val payload = rebuilt.substringAfter("://").substringBefore('#')
        val decoded = String(
            android.util.Base64.decode(payload, android.util.Base64.DEFAULT),
            Charsets.UTF_8
        )
        assertTrue("add not replaced", decoded.contains("\"add\":\"9.9.9.9\""))
        assertFalse("fragment must not be injected into vmess", decoded.contains("\"fragment\":"))
        assertFalse("cipherSuites must not be injected into vmess", decoded.contains("\"cipherSuites\":"))
        assertFalse("fp must not be injected into vmess", decoded.contains("\"fp\":"))
    }

    // ─── Shadowsocks: pass-through, anti-filter must NOT be injected ───

    @Test
    fun `shadowsocks is passed through without anti filter`() {
        val cfg = parse("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@original.example:8388#label")
        val rebuilt = ConfigRebuilder.rebuild(cfg, "1.1.1.1", antiFilter = af)
        assertNotNull(rebuilt)
        assertTrue(rebuilt!!.startsWith("ss://"))
        assertTrue("ip not replaced", rebuilt.contains("@1.1.1.1:8388"))
        assertFalse("fm must not be injected into ss", rebuilt.contains("fm="))
        assertFalse("cs must not be injected into ss", rebuilt.contains("cs="))
        assertFalse("fp must not be injected into ss", rebuilt.contains("fp="))
    }

    // ─── Without anti-filter: query untouched ───

    @Test
    fun `vless without anti filter keeps query as is`() {
        val cfg = parse("vless://uuid@original.example:443?encryption=none&security=tls&sni=real.example#label")
        val rebuilt = ConfigRebuilder.rebuild(cfg, "1.2.3.4")
        assertNotNull(rebuilt)
        assertEquals("vless://uuid@1.2.3.4:443?encryption=none&security=tls&sni=real.example#label", rebuilt)
    }
}
