package dev.narsaq.speedtester.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CloudflareRangesTest {

    @Test
    fun `neighbors stay inside the same cloudflare range`() {
        val neighbors = CloudflareRanges.neighborsOf("188.114.97.6", 20)

        assertEquals(20, neighbors.size)
        assertTrue(neighbors.all { it.startsWith("188.114.") })
        assertFalse(neighbors.contains("188.114.97.6"))
    }

    @Test
    fun `neighbors exclude network boundary`() {
        val neighbors = CloudflareRanges.neighborsOf("103.21.244.1", 4)

        assertFalse(neighbors.contains("103.21.244.0"))
        assertEquals(neighbors.distinct().size, neighbors.size)
    }

    @Test
    fun `invalid seed produces no neighbors`() {
        assertTrue(CloudflareRanges.neighborsOf("1.1.1.1", 10).isEmpty())
        assertTrue(CloudflareRanges.neighborsOf("bad-ip", 10).isEmpty())
    }

    @Test
    fun `ipv6 generation stays inside cloudflare v6 ranges`() {
        val ips = CloudflareRanges.generateRandomIpsV6(100)

        assertEquals(100, ips.size)
        assertEquals(ips.distinct().size, ips.size)
        assertTrue(ips.all { ip ->
            ip.startsWith("2400:cb00:") ||
                ip.startsWith("2606:4700:") ||
                ip.startsWith("2803:f800:") ||
                ip.startsWith("2405:b500:") ||
                ip.startsWith("2405:8100:") ||
                ip.startsWith("2a06:98c") ||
                ip.startsWith("2c0f:f248:")
        })
    }

    @Test
    fun `custom v4 cidr generation stays inside the cidr`() {
        val ips = CloudflareRanges.generateFromCustomRanges("103.21.244.0/24", 50)

        assertTrue(ips.isNotEmpty())
        assertTrue(ips.size <= 50)
        assertTrue(ips.all { it.startsWith("103.21.244.") })
        assertEquals(ips.distinct().size, ips.size)
    }

    @Test
    fun `custom mixed v4 and v6 ranges produce both families`() {
        val ips = CloudflareRanges.generateFromCustomRanges(
            "103.21.244.0/24\n2606:4700::/32",
            40
        )

        assertTrue(ips.any { it.contains('.') })
        assertTrue(ips.any { it.contains(':') })
        assertTrue(ips.size <= 40)
    }

    @Test
    fun `custom bare ips and port lines are included`() {
        val ips = CloudflareRanges.generateFromCustomRanges(
            "1.2.3.4:443\n1.2.3.5\n[2606:4700::1]:443",
            10
        )

        assertTrue(ips.contains("1.2.3.4"))
        assertTrue(ips.contains("1.2.3.5"))
        assertTrue(ips.contains("2606:4700::1"))
    }

    @Test
    fun `custom ranges with garbage only return nothing`() {
        assertTrue(CloudflareRanges.generateFromCustomRanges("not-an-ip\ngarbage", 10).isEmpty())
    }
}
