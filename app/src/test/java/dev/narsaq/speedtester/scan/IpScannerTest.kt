package dev.narsaq.speedtester.scan

import org.junit.Assert.assertEquals
import org.junit.Test

class IpScannerTest {

    @Test
    fun `scan result quality excellent`() {
        val result = ScanResult(
            ip = "1.1.1.1",
            port = 443,
            tcpLatencyMs = 50,
            tlsLatencyMs = 55,
            lossRate = 5f,
            verified = true
        )
        assertEquals("Excellent", result.quality)
    }

    @Test
    fun `scan result quality good`() {
        val result = ScanResult(
            ip = "1.1.1.2",
            port = 443,
            tcpLatencyMs = 150,
            tlsLatencyMs = 160,
            lossRate = 10f,
            verified = true
        )
        assertEquals("Good", result.quality)
    }

    @Test
    fun `scan result quality fair`() {
        val result = ScanResult(
            ip = "1.1.1.3",
            port = 443,
            tcpLatencyMs = 300,
            tlsLatencyMs = 310,
            lossRate = 20f,
            verified = true
        )
        assertEquals("Fair", result.quality)
    }

    @Test
    fun `scan result quality slow by latency`() {
        val result = ScanResult(
            ip = "1.1.1.4",
            port = 443,
            tcpLatencyMs = 500,
            tlsLatencyMs = 510,
            lossRate = 1f,
            verified = true
        )
        assertEquals("Slow", result.quality)
    }

    @Test
    fun `scan result quality slow by loss rate`() {
        val result = ScanResult(
            ip = "1.1.1.5",
            port = 443,
            tcpLatencyMs = 80,
            tlsLatencyMs = 90,
            lossRate = 60f,
            verified = true
        )
        assertEquals("Slow", result.quality)
    }

    @Test
    fun `scan result quality slow by high loss rate`() {
        val result = ScanResult(
            ip = "1.1.1.6",
            port = 443,
            tcpLatencyMs = 100,
            tlsLatencyMs = 110,
            lossRate = 50f,
            verified = true
        )
        assertEquals("Slow", result.quality)
    }

    @Test
    fun `scan result total latency uses tls when available`() {
        val result = ScanResult(
            ip = "1.1.1.7",
            port = 443,
            tcpLatencyMs = 100,
            tlsLatencyMs = 80,
            lossRate = 0f
        )
        assertEquals(80L, result.totalLatencyMs)
    }

    @Test
    fun `scan result total latency falls back to tcp`() {
        val result = ScanResult(
            ip = "1.1.1.8",
            port = 443,
            tcpLatencyMs = 120,
            tlsLatencyMs = null,
            lossRate = 0f
        )
        assertEquals(120L, result.totalLatencyMs)
    }
}
