package dev.narsaq.speedtester.parse

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class IpParserTest {

    @Test
    fun `parses plain ipv4 lines`() {
        assertEquals(listOf("1.2.3.4"), IpParser.parse("1.2.3.4"))
    }

    @Test
    fun `parses ipv4 with port`() {
        assertEquals(listOf("1.2.3.4"), IpParser.parse("1.2.3.4:443"))
    }

    @Test
    fun `parses bracketed ipv6 with port`() {
        assertEquals(
            listOf("2606:4700::1"),
            IpParser.parse("[2606:4700::1]:443")
        )
    }

    @Test
    fun `parses bare ipv6`() {
        assertEquals(
            listOf("2606:4700::1"),
            IpParser.parse("2606:4700::1")
        )
    }

    @Test
    fun `parses mixed list and dedupes`() {
        val ips = IpParser.parse("1.2.3.4\n1.2.3.4\n2606:4700::1")
        assertEquals(listOf("1.2.3.4", "2606:4700::1"), ips)
    }

    @Test
    fun `rejects garbage and hostnames`() {
        assertTrue(IpParser.parse("not-an-ip").isEmpty())
        assertTrue(IpParser.parse("example.com").isEmpty())
    }
}
