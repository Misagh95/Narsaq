package dev.narsaq.speedtester.parse

import dev.narsaq.speedtester.model.ConfigType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class ConfigParserTest {

    @Test
    fun `skips comments and blank lines`() {
        val parsed = ConfigParser.parse("\n# comment\nexample.com\n")

        assertEquals(1, parsed.size)
        assertEquals("example.com", parsed.single().host)
        assertEquals(listOf(443), parsed.single().ports)
    }

    @Test
    fun `parses and deduplicates up to three plain ports`() {
        val item = ConfigParser.parse("example.com:443,8443,443").single()

        assertTrue(item.isValid)
        assertEquals(listOf(443, 8443), item.ports)
    }

    @Test
    fun `rejects invalid explicit uri port instead of defaulting`() {
        val item = ConfigParser.parse("vless://id@example.com:99999").single()

        assertFalse(item.isValid)
        assertEquals(ConfigType.INVALID, item.type)
    }

    @Test
    fun `defaults missing uri port to 443`() {
        val item = ConfigParser.parse("trojan://password@example.com").single()

        assertTrue(item.isValid)
        assertEquals(listOf(443), item.ports)
    }

    @Test
    fun `rejects protocol uri without credentials`() {
        val item = ConfigParser.parse("vless://example.com:443").single()

        assertFalse(item.isValid)
    }

    @Test
    fun `accepts compressed ipv6 and rejects malformed ipv6`() {
        val valid = ConfigParser.parse("[2001:db8::1]:443").single()
        val invalid = ConfigParser.parse("[1:2:3]:443").single()

        assertTrue(valid.isValid)
        assertFalse(invalid.isValid)
    }

    @Test
    fun `rejects more than three ports`() {
        val item = ConfigParser.parse("example.com:80,443,8443,2053").single()

        assertFalse(item.isValid)
    }
}
