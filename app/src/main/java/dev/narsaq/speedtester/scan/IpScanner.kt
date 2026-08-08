package dev.narsaq.speedtester.scan

import android.os.SystemClock
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import kotlin.math.sqrt

data class ScanResult(
    val ip: String,
    val port: Int,
    val tcpLatencyMs: Long,
    val tlsLatencyMs: Long? = null,
    val httpValid: Boolean? = null,
    val verified: Boolean = false,
    val asn: String = "",
    val isp: String = "",
    val country: String = "",
    val city: String = "",
    val flaggedDomestic: Boolean = false,
    val lossRate: Float? = null,
    val avgLatencyMs: Long? = null,
    val jitterMs: Long? = null,
    val throughputMbps: Float? = null,
    val colo: String = ""
) {
    val totalLatencyMs: Long
        get() = tlsLatencyMs ?: tcpLatencyMs

    val quality: String
        get() = when {
            totalLatencyMs < 100 && (lossRate == null || lossRate < 10) -> "Excellent"
            totalLatencyMs < 200 && (lossRate == null || lossRate < 25) -> "Good"
            totalLatencyMs < 350 && (lossRate == null || lossRate < 50) -> "Fair"
            else -> "Slow"
        }

    val isCloudflare: Boolean
        get() = asn == "AS13335" || isp.contains("Cloudflare", ignoreCase = true)
}

data class ScanProgress(
    val done: Int,
    val found: Int,
    val total: Int,
    val phase: String
)

class IpScanner {

    companion object {
        val CLOUDFLARE_HTTPS_PORTS = listOf(443, 2053, 2083, 2087, 2096, 8443)
        val CLOUDFLARE_HTTP_PORTS = listOf(80, 8080, 8880, 2052, 2082, 2086, 2095)

        const val DEFAULT_COUNT = 1000
        const val DEFAULT_TIMEOUT_MS = 3000
        const val CONCURRENCY_PHASE1 = 80
        const val CONCURRENCY_PHASE2 = 25
        const val VERIFY_TOP_COUNT = 50
        const val VERIFY_SAMPLES = 3
        const val LOSS_TEST_SAMPLES = 10

        // Payload sample for the data-flow check (trace can succeed while the
        // IP is unable to carry real traffic).
        const val DOWNLOAD_SAMPLE_BYTES = 64 * 1024

        // Payload size used for the throughput (Mbps) measurement.
        const val SPEED_SAMPLE_BYTES = 512 * 1024

        // How many top endpoints get the post-scan speed test.
        const val SPEED_TEST_COUNT = 10

        // Rotating SNI reduces the chance of deep-packet inspection blackholing.
        val SNI_HOSTNAMES = listOf(
            "speed.cloudflare.com",
            "www.cloudflare.com",
            "cloudflare.com",
            "1.1.1.1.cdn.cloudflare.net"
        )
    }

    private data class TlsProbe(val latencyMs: Long?, val colo: String?)

    /**
     * 5-phase scan:
     * 1. TCP connect test on all IP:port pairs
     * 2. TLS handshake test on top candidates
     * 3. Multi-sample verification of top results
     * 4. Packet loss testing (+ avg latency & jitter)
     * 5. Throughput speed test (Mbps) on the best endpoints
     *
     * Custom CIDR/IP ranges are merged with the built-in Cloudflare pool when
     * provided. IPv6 (Cloudflare v6 ranges) is scanned in addition to IPv4
     * when enabled.
     */
    suspend fun scan(
        ports: List<Int> = CLOUDFLARE_HTTPS_PORTS.take(1),
        count: Int = DEFAULT_COUNT,
        timeoutMs: Int = DEFAULT_TIMEOUT_MS,
        enableTls: Boolean = true,
        enableVerify: Boolean = true,
        neighborScan: Boolean = false,
        enableV6: Boolean = false,
        customRanges: String = "",
        speedTest: Boolean = true,
        onProgress: (ScanProgress) -> Unit = {}
    ): List<ScanResult> {
        if (ports.isEmpty()) return emptyList()
        val neighborBudget = if (neighborScan) minOf(count / 3, 100) else 0
        val randomCount = (count - neighborBudget).coerceAtLeast(1)

        val scope = ArrayList<String>(randomCount * 2)
        if (customRanges.isNotBlank()) {
            // User-provided ranges get half the budget, merged with Cloudflare.
            scope += CloudflareRanges.generateFromCustomRanges(
                customRanges,
                maxOf(randomCount / 2, 1)
            )
        }
        scope += CloudflareRanges.generateRandomIps(randomCount)
        if (enableV6) {
            // Extra v6 probes, never more than the requested count.
            scope += CloudflareRanges.generateRandomIpsV6(
                minOf(randomCount, maxOf(randomCount / 3, 50))
            )
        }
        val scopeIps = scope.distinct()
        if (scopeIps.isEmpty()) return emptyList()

        val phase1Total = scopeIps.size * ports.size
        val initialResults = runPhase1(scopeIps, ports, timeoutMs) { done, found ->
            onProgress(ScanProgress(done, found, phase1Total, "TCP Test"))
        }

        if (initialResults.isEmpty()) return emptyList()

        val neighborIps = if (neighborBudget > 0) {
            val seeds = initialResults.sortedBy { it.tcpLatencyMs }
                .map { it.ip }.distinct().take(5)
            CloudflareRanges.neighborsOf(seeds, neighborBudget)
                .filterNot { it in scopeIps }
        } else {
            emptyList()
        }
        val neighborResults = if (neighborIps.isNotEmpty()) {
            runPhase1(neighborIps, ports, timeoutMs) { done, found ->
                onProgress(
                    ScanProgress(
                        done = scopeIps.size * ports.size + done,
                        found = initialResults.size + found,
                        total = (scopeIps.size + neighborIps.size) * ports.size,
                        phase = "Neighbor Test"
                    )
                )
            }
        } else {
            emptyList()
        }
        val phase1Results = (initialResults + neighborResults)
            .distinctBy { it.ip to it.port }

        val sortedPhase1 = phase1Results.sortedBy { it.tcpLatencyMs }

        val phase2Results = if (enableTls) {
            val topForTls = sortedPhase1.take(VERIFY_TOP_COUNT)
            runPhase2(topForTls, timeoutMs) { done, found ->
                onProgress(ScanProgress(done, found, topForTls.size, "TLS Test"))
            }
        } else {
            sortedPhase1
        }

        if (phase2Results.isEmpty()) return phase1Results

        val sortedPhase2 = if (enableTls) {
            phase2Results.sortedBy { it.tlsLatencyMs ?: it.tcpLatencyMs }
        } else {
            phase2Results
        }

        val phase3Results = if (enableTls && enableVerify) {
            val candidates = sortedPhase2.take(VERIFY_TOP_COUNT / 2)
            runPhase3(candidates, timeoutMs, VERIFY_SAMPLES) { done, found ->
                onProgress(ScanProgress(done, found, candidates.size, "Verify"))
            }
        } else {
            phase2Results
        }

        if (phase3Results.isEmpty()) return phase2Results

        val lossCandidates = phase3Results.take(25)
        val phase4Results = runPhase4(lossCandidates, timeoutMs) { done, found ->
            onProgress(ScanProgress(done, found, lossCandidates.size, "Loss Test"))
        }

        if (phase4Results.isEmpty()) return phase3Results

        val finalResults = if (speedTest) {
            val speedCandidates = phase4Results.take(SPEED_TEST_COUNT)
            val speedResults = runPhase5(speedCandidates, timeoutMs) { done, found ->
                onProgress(ScanProgress(done, found, speedCandidates.size, "Speed Test"))
            }
            phase4Results.map { result ->
                speedResults.firstOrNull {
                    it.ip == result.ip && it.port == result.port
                } ?: result
            }
        } else {
            phase4Results
        }

        return finalResults.sortedBy { it.totalLatencyMs }
    }

    private suspend fun runPhase1(
        ips: List<String>,
        ports: List<Int>,
        timeoutMs: Int,
        onProgress: (done: Int, found: Int) -> Unit
    ): List<ScanResult> = coroutineScope {
        val semaphore = Semaphore(CONCURRENCY_PHASE1)
        val results = java.util.concurrent.ConcurrentLinkedQueue<ScanResult>()
        val doneCount = java.util.concurrent.atomic.AtomicInteger(0)

        val jobs = ips.flatMap { ip ->
            ports.map { port ->
                async(Dispatchers.IO) {
                    semaphore.withPermit {
                        currentCoroutineContext().ensureActive()
                        val latency = tcpConnect(ip, port, timeoutMs)
                        if (latency != null) {
                            results.add(ScanResult(ip = ip, port = port, tcpLatencyMs = latency))
                        }
                        val done = doneCount.incrementAndGet()
                        onProgress(done, results.size)
                    }
                }
            }
        }

        jobs.awaitAll()
        results.toList()
    }

    private suspend fun runPhase2(
        candidates: List<ScanResult>,
        timeoutMs: Int,
        onProgress: (done: Int, found: Int) -> Unit
    ): List<ScanResult> = coroutineScope {
        val semaphore = Semaphore(CONCURRENCY_PHASE2)
        val results = java.util.concurrent.ConcurrentLinkedQueue<ScanResult>()
        val doneCount = java.util.concurrent.atomic.AtomicInteger(0)

        val jobs = candidates.map { candidate ->
            async(Dispatchers.IO) {
                semaphore.withPermit {
                    currentCoroutineContext().ensureActive()

                    val probe = tlsHttpProbe(candidate.ip, candidate.port, timeoutMs)
                    if (probe.latencyMs != null) {
                        results.add(
                            candidate.copy(
                                tlsLatencyMs = probe.latencyMs,
                                httpValid = true,
                                verified = true,
                                colo = probe.colo.orEmpty()
                            )
                        )
                    }
                    onProgress(doneCount.incrementAndGet(), results.size)
                }
            }
        }

        jobs.awaitAll()
        results.toList()
    }

    private suspend fun runPhase3(
        candidates: List<ScanResult>,
        timeoutMs: Int,
        samples: Int,
        onProgress: (done: Int, found: Int) -> Unit
    ): List<ScanResult> = coroutineScope {
        val semaphore = Semaphore(CONCURRENCY_PHASE2)
        val results = java.util.concurrent.ConcurrentLinkedQueue<ScanResult>()
        val doneCount = java.util.concurrent.atomic.AtomicInteger(0)

        val jobs = candidates.map { candidate ->
            async(Dispatchers.IO) {
                semaphore.withPermit {
                    currentCoroutineContext().ensureActive()

                    val latencies = ArrayList<Long>(samples)
                    var colo = ""
                    for (i in 0 until samples) {
                        currentCoroutineContext().ensureActive()
                        val probe = tlsHttpProbe(candidate.ip, candidate.port, timeoutMs)
                        probe.latencyMs?.let { latencies.add(it) }
                        if (!probe.colo.isNullOrBlank()) colo = probe.colo
                    }

                    if (latencies.size >= (samples + 1) / 2) {
                        latencies.sort()
                        val downloadOk = tlsDownloadProbe(candidate.ip, candidate.port, timeoutMs)
                        if (downloadOk) {
                            results.add(
                                candidate.copy(
                                    tlsLatencyMs = latencies[latencies.size / 2],
                                    httpValid = true,
                                    verified = true,
                                    colo = colo
                                )
                            )
                        }
                    }
                    onProgress(doneCount.incrementAndGet(), results.size)
                }
            }
        }

        jobs.awaitAll()
        results.toList()
    }

    // Phase 4: Packet loss test + latency jitter measurement
    private suspend fun runPhase4(
        candidates: List<ScanResult>,
        timeoutMs: Int,
        onProgress: (done: Int, found: Int) -> Unit
    ): List<ScanResult> = coroutineScope {
        val semaphore = Semaphore(15)
        val results = java.util.concurrent.ConcurrentLinkedQueue<ScanResult>()
        val doneCount = java.util.concurrent.atomic.AtomicInteger(0)

        val jobs = candidates.map { candidate ->
            async(Dispatchers.IO) {
                semaphore.withPermit {
                    currentCoroutineContext().ensureActive()

                    var lost = 0
                    val successSamples = ArrayList<Long>(LOSS_TEST_SAMPLES)
                    for (i in 0 until LOSS_TEST_SAMPLES) {
                        currentCoroutineContext().ensureActive()
                        val lat = tcpConnect(candidate.ip, candidate.port, timeoutMs / 2)
                        if (lat == null) {
                            lost++
                        } else {
                            successSamples += lat
                        }
                    }

                    if (successSamples.isNotEmpty()) {
                        val lossRate = (lost * 100.0 / (lost + successSamples.size)).toFloat()
                        val avg = successSamples.average().toLong()
                        val variance = successSamples
                            .map { val d = it - avg; d * d }
                            .average() ?: 0.0
                        val jitter = sqrt(variance).toLong()
                        results.add(
                            candidate.copy(
                                lossRate = lossRate,
                                avgLatencyMs = avg,
                                jitterMs = jitter
                            )
                        )
                    }
                    onProgress(doneCount.incrementAndGet(), results.size)
                }
            }
        }

        jobs.awaitAll()
        results.toList()
    }

    // Phase 5: Throughput speed test (Mbps) on the best endpoints
    private suspend fun runPhase5(
        candidates: List<ScanResult>,
        timeoutMs: Int,
        onProgress: (done: Int, found: Int) -> Unit
    ): List<ScanResult> = coroutineScope {
        val semaphore = Semaphore(8)
        val results = java.util.concurrent.ConcurrentLinkedQueue<ScanResult>()
        val doneCount = java.util.concurrent.atomic.AtomicInteger(0)

        val jobs = candidates.map { candidate ->
            async(Dispatchers.IO) {
                semaphore.withPermit {
                    currentCoroutineContext().ensureActive()
                    val mbps = tlsDownloadMbps(candidate.ip, candidate.port, timeoutMs)
                    if (mbps != null) {
                        results.add(candidate.copy(throughputMbps = mbps))
                    }
                    onProgress(doneCount.incrementAndGet(), results.size)
                }
            }
        }

        jobs.awaitAll()
        results.toList()
    }

    private fun tcpConnect(ip: String, port: Int, timeoutMs: Int): Long? {
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

    private fun tlsHttpProbe(ip: String, port: Int, timeoutMs: Int): TlsProbe {
        for (sni in SNI_HOSTNAMES) {
            val probe = tlsHttpProbeOnce(ip, port, sni, timeoutMs)
            if (probe.latencyMs != null) return probe
        }
        return TlsProbe(null, null)
    }

    private fun tlsHttpProbeOnce(ip: String, port: Int, sniHost: String, timeoutMs: Int): TlsProbe {
        val start = SystemClock.elapsedRealtime()
        var rawSocket: Socket? = null
        var sslSocket: SSLSocket? = null

        return try {
            // Budget split: TCP gets 1/4, TLS handshake gets 1/2, leaving 1/4
            // for the HTTP GET+response. Without this, on DPI-throttled networks
            // the TLS handshake can consume the whole timeout and produce
            // false-positive failures.
            val dialTimeoutMs = maxOf(timeoutMs / 4, minOf(2000, timeoutMs))
            val handshakeTimeoutMs = maxOf(timeoutMs / 2, minOf(3000, timeoutMs))

            rawSocket = Socket()
            rawSocket.connect(InetSocketAddress(ip, port), dialTimeoutMs)
            rawSocket.soTimeout = handshakeTimeoutMs

            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            sslSocket = factory.createSocket(rawSocket, sniHost, port, true) as SSLSocket
            sslSocket.soTimeout = handshakeTimeoutMs
            sslSocket.startHandshake()

            val request = "GET /cdn-cgi/trace HTTP/1.1\r\n" +
                "Host: $sniHost\r\n" +
                "User-Agent: Narsaq/1.0\r\n" +
                "Accept: */*\r\n" +
                "Connection: close\r\n\r\n"
            sslSocket.getOutputStream().apply {
                write(request.toByteArray(Charsets.US_ASCII))
                flush()
            }

            val remaining = (timeoutMs - (SystemClock.elapsedRealtime() - start))
                .coerceAtLeast(500)
                .toInt()
            sslSocket.soTimeout = remaining

            val response = readHttpResponse(sslSocket.getInputStream())
            // A real Cloudflare edge must return 200 with a colo identifier.
            val colo = response?.let { parseColo(it) }
            if (colo == null) return TlsProbe(null, null)

            // Idle-hold stability check: on Iranian ISPs, DPI often allows the
            // initial trace GET but RSTs the connection shortly after. An idle
            // hold catches this before the IP is marked healthy.
            if (!tlsStabilityProbe(ip, port, sniHost, timeoutMs)) {
                return TlsProbe(null, null)
            }

            TlsProbe(SystemClock.elapsedRealtime() - start, colo)
        } catch (e: Exception) {
            TlsProbe(null, null)
        } finally {
            try { sslSocket?.close() } catch (_: Exception) {}
            try { rawSocket?.close() } catch (_: Exception) {}
        }
    }

    // Idle-hold check on a TLS connection to detect DPI systems that RST
    // connections after the initial handshake. Returns true if the connection
    // survived the idle period.
    private fun tlsStabilityProbe(ip: String, port: Int, sniHost: String, timeoutMs: Int): Boolean {
        var rawSocket: Socket? = null
        var sslSocket: SSLSocket? = null

        return try {
            val dialTimeoutMs = maxOf(timeoutMs / 4, minOf(2000, timeoutMs))
            val handshakeTimeoutMs = maxOf(timeoutMs / 2, minOf(3000, timeoutMs))

            rawSocket = Socket()
            rawSocket.connect(InetSocketAddress(ip, port), dialTimeoutMs)
            rawSocket.soTimeout = handshakeTimeoutMs

            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            sslSocket = factory.createSocket(rawSocket, sniHost, port, true) as SSLSocket
            sslSocket.soTimeout = handshakeTimeoutMs
            sslSocket.startHandshake()

            val idleHoldMs = minOf(1500L, maxOf(500L, timeoutMs / 2L)).toInt()
            sslSocket.soTimeout = idleHoldMs
            val buf = ByteArray(1)
            try {
                // Timeout here is EXPECTED (server doesn't send data while idle).
                // EOF (-1) or any error (RST) means the connection was killed.
                sslSocket.getInputStream().read(buf) != -1
            } catch (e: java.net.SocketTimeoutException) {
                true
            }
        } catch (e: Exception) {
            false
        } finally {
            try { sslSocket?.close() } catch (_: Exception) {}
            try { rawSocket?.close() } catch (_: Exception) {}
        }
    }

    private fun parseColo(response: String): String? {
        // /cdn-cgi/trace returns a line like "colo=FRA"
        val lines = response.split("\r\n", "\n")
        for (line in lines) {
            if (line.startsWith("colo=")) {
                val value = line.substringAfter('=').trim()
                return value.ifEmpty { null }
            }
        }
        return null
    }

    // Downloads a small payload through the candidate IP. On Iranian ISPs,
    // /cdn-cgi/trace often succeeds while actual data transfer fails — this
    // catches IPs that are reachable but cannot carry traffic.
    private fun tlsDownloadProbe(ip: String, port: Int, timeoutMs: Int): Boolean {
        var rawSocket: Socket? = null
        var sslSocket: SSLSocket? = null

        return try {
            val dialTimeoutMs = maxOf(timeoutMs / 4, minOf(2000, timeoutMs))
            val handshakeTimeoutMs = maxOf(timeoutMs / 2, minOf(3000, timeoutMs))
            val sni = "speed.cloudflare.com"

            rawSocket = Socket()
            rawSocket.connect(InetSocketAddress(ip, port), dialTimeoutMs)
            rawSocket.soTimeout = handshakeTimeoutMs

            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            sslSocket = factory.createSocket(rawSocket, sni, port, true) as SSLSocket
            sslSocket.soTimeout = handshakeTimeoutMs
            sslSocket.startHandshake()

            val request = "GET /__down?bytes=$DOWNLOAD_SAMPLE_BYTES HTTP/1.1\r\n" +
                "Host: $sni\r\n" +
                "User-Agent: Narsaq/1.0\r\n" +
                "Accept: */*\r\n" +
                "Connection: close\r\n\r\n"
            sslSocket.getOutputStream().apply {
                write(request.toByteArray(Charsets.US_ASCII))
                flush()
            }

            sslSocket.soTimeout = timeoutMs
            val input = sslSocket.getInputStream()
            val buffer = ByteArray(8192)
            var total = 0
            var statusOk = false
            val head = StringBuilder()
            var headerDone = false
            while (total < DOWNLOAD_SAMPLE_BYTES * 2) {
                val n = input.read(buffer)
                if (n < 0) break
                if (!headerDone) {
                    head.append(String(buffer, 0, n, Charsets.ISO_8859_1))
                    val end = head.indexOf("\r\n\r\n")
                    if (end >= 0) {
                        headerDone = true
                        if (!head.startsWith("HTTP/1.1 200") && !head.contains(" 200 ")) break
                        statusOk = true
                        // Count any body bytes already buffered past the terminator.
                        total = head.length - (end + 4)
                    }
                } else {
                    total += n
                }
            }
            statusOk && total >= DOWNLOAD_SAMPLE_BYTES
        } catch (e: Exception) {
            false
        } finally {
            try { sslSocket?.close() } catch (_: Exception) {}
            try { rawSocket?.close() } catch (_: Exception) {}
        }
    }

    // Measures real download throughput through the candidate IP and returns
    // it in Mbps (null if the endpoint cannot carry the sample payload).
    private fun tlsDownloadMbps(ip: String, port: Int, timeoutMs: Int): Float? {
        var rawSocket: Socket? = null
        var sslSocket: SSLSocket? = null

        return try {
            val dialTimeoutMs = maxOf(timeoutMs / 4, minOf(2000, timeoutMs))
            val handshakeTimeoutMs = maxOf(timeoutMs / 2, minOf(3000, timeoutMs))
            val sni = "speed.cloudflare.com"

            rawSocket = Socket()
            rawSocket.connect(InetSocketAddress(ip, port), dialTimeoutMs)
            rawSocket.soTimeout = handshakeTimeoutMs

            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            sslSocket = factory.createSocket(rawSocket, sni, port, true) as SSLSocket
            sslSocket.soTimeout = handshakeTimeoutMs
            sslSocket.startHandshake()

            val request = "GET /__down?bytes=$SPEED_SAMPLE_BYTES HTTP/1.1\r\n" +
                "Host: $sni\r\n" +
                "User-Agent: Narsaq/1.0\r\n" +
                "Accept: */*\r\n" +
                "Connection: close\r\n\r\n"
            sslSocket.getOutputStream().apply {
                write(request.toByteArray(Charsets.US_ASCII))
                flush()
            }

            sslSocket.soTimeout = timeoutMs
            val input = sslSocket.getInputStream()
            val buffer = ByteArray(8192)
            var total = 0
            var statusOk = false
            val head = StringBuilder()
            var headerDone = false
            var bodyStart = 0L
            while (total < SPEED_SAMPLE_BYTES * 2) {
                val n = input.read(buffer)
                if (n < 0) break
                if (!headerDone) {
                    head.append(String(buffer, 0, n, Charsets.ISO_8859_1))
                    val end = head.indexOf("\r\n\r\n")
                    if (end >= 0) {
                        headerDone = true
                        if (!head.startsWith("HTTP/1.1 200") && !head.contains(" 200 ")) break
                        statusOk = true
                        total = head.length - (end + 4)
                        // Start the throughput clock once the body begins.
                        bodyStart = SystemClock.elapsedRealtime()
                    }
                } else {
                    total += n
                }
            }

            if (!statusOk || bodyStart <= 0) return null
            val elapsedMs = SystemClock.elapsedRealtime() - bodyStart
            if (total < SPEED_SAMPLE_BYTES || elapsedMs <= 0) return null

            // bits / seconds / 1_000_000 → Mbps
            ((total * 8.0 / 1_000_000) / (elapsedMs / 1000.0)).toFloat()
        } catch (e: Exception) {
            null
        } finally {
            try { sslSocket?.close() } catch (_: Exception) {}
            try { rawSocket?.close() } catch (_: Exception) {}
        }
    }

    private fun readHttpResponse(input: java.io.InputStream, maxBytes: Int = 4096): String? {
        val buffer = ByteArray(512)
        val sb = StringBuilder()
        var total = 0
        try {
            while (total < maxBytes) {
                val n = input.read(buffer)
                if (n < 0) break
                sb.append(String(buffer, 0, n, Charsets.ISO_8859_1))
                total += n
                // Keep reading past the header terminator so the /cdn-cgi/trace
                // body (which carries colo=) is fully captured.
                if (sb.contains("colo=")) break
                if (n < buffer.size) break
            }
        } catch (e: Exception) {
            return null
        }
        return if (sb.isEmpty()) null else sb.toString()
    }
}
