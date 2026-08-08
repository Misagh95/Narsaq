package dev.narsaq.speedtester.data

import dev.narsaq.speedtester.scan.ScanResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/**
 * Round-trip tests for the JSON persistence layer: ScanResult ↔ entity and
 * save/reload across a store instance.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class PersistenceStoreTest {

    private fun sampleScan() = ScanResult(
        ip = "104.16.0.1",
        port = 443,
        tcpLatencyMs = 12,
        tlsLatencyMs = 8,
        httpValid = true,
        verified = true,
        asn = "13335",
        isp = "Cloudflare, Inc.",
        country = "US",
        city = "San Francisco",
        colo = "SFO"
    )

    @Test
    fun `scan result round-trips through JSON without losing fields`() {
        val src = sampleScan()
        val entity = ScanResultEntity.fromScanResult(src, batchId = 42)
        val back = entity.toScanResult()

        assertEquals(src.ip, back.ip)
        assertEquals(src.port, back.port)
        assertEquals(src.tcpLatencyMs, back.tcpLatencyMs)
        assertEquals(src.tlsLatencyMs, back.tlsLatencyMs)
        assertEquals(src.httpValid, back.httpValid)
        assertEquals(src.verified, back.verified)
        assertEquals(src.asn, back.asn)
        assertEquals(src.isp, back.isp)
        assertEquals(src.country, back.country)
        assertEquals(src.city, back.city)
        assertEquals(src.country, back.country)
        assertEquals(src.colo, back.colo)
    }

    @Test
    fun `store saves and reloads the latest scan batch`() {
        val ctx = RuntimeEnvironment.getApplication()
        val store = PersistenceStore(ctx)

        // Save batch A, then batch B — only B should be restored (newest wins).
        val a = ScanResultEntity.fromScanResult(sampleScan().copy(ip = "1.1.1.1"), batchId = 1)
        val b = ScanResultEntity.fromScanResult(sampleScan().copy(ip = "104.16.1.1"), batchId = 2)
        store.saveScanResults(listOf(a))
        store.saveScanResults(listOf(b))

        val latest = store.latestScanResults()
        assertEquals("newest batch must win", 1, latest.size)
        assertEquals("104.16.1.1", latest.single().ip)
    }

    @Test
    fun `store is empty before anything is saved`() {
        val store = PersistenceStore(RuntimeEnvironment.getApplication())
        assertTrue(store.latestScanResults().isEmpty())
        assertTrue(store.latestBuiltConfigs().isEmpty())
    }
}