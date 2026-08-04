package dev.narsaq.speedtester.scan

import android.os.SystemClock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.net.InetSocketAddress
import java.net.Socket

data class ScanResult(
    val ip: String,
    val port: Int,
    val latencyMs: Long
)

data class ScanProgress(
    val total: Int,
    val done: Int,
    val found: Int
)

class IpScanner {

    companion object {
        const val DEFAULT_PORT = 443
        const val DEFAULT_COUNT = 200
        const val DEFAULT_TIMEOUT_MS = 3000
        const val DEFAULT_CONCURRENCY = 30
    }

    suspend fun scan(
        port: Int = DEFAULT_PORT,
        count: Int = DEFAULT_COUNT,
        timeoutMs: Int = DEFAULT_TIMEOUT_MS,
        concurrency: Int = DEFAULT_CONCURRENCY,
        onProgress: (ScanProgress) -> Unit = {}
    ): List<ScanResult> = coroutineScope {

        val ips = CloudflareRanges.generateRandomIps(count)
        val semaphore = Semaphore(concurrency)
        val results = java.util.concurrent.ConcurrentLinkedQueue<ScanResult>()
        val doneCount = java.util.concurrent.atomic.AtomicInteger(0)

        val deferred = ips.map { ip ->
            async(Dispatchers.IO) {
                semaphore.withPermit {
                    currentCoroutineContext().ensureActive()

                    val latency = testIp(ip, port, timeoutMs)
                    if (latency != null) {
                        results.add(ScanResult(ip, port, latency))
                    }

                    val done = doneCount.incrementAndGet()
                    onProgress(
                        ScanProgress(
                            total = ips.size,
                            done = done,
                            found = results.size
                        )
                    )
                }
            }
        }

        deferred.awaitAll()

        results.sortedBy { it.latencyMs }
    }

    private fun testIp(ip: String, port: Int, timeoutMs: Int): Long? {
        val start = SystemClock.elapsedRealtime()
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(ip, port), timeoutMs)
                SystemClock.elapsedRealtime() - start
            }
        } catch (e: Exception) {
            null
        }
    }
}