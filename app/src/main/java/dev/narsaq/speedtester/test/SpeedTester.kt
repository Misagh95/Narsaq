package dev.narsaq.speedtester.test

import android.os.SystemClock
import dev.narsaq.speedtester.build.ConfigRebuilder
import dev.narsaq.speedtester.model.CandidateHit
import dev.narsaq.speedtester.model.ItemStatus
import dev.narsaq.speedtester.model.ParsedConfig
import dev.narsaq.speedtester.model.PortDetail
import dev.narsaq.speedtester.model.UiItem
import dev.narsaq.speedtester.protocol.EndpointValidator
import dev.narsaq.speedtester.protocol.ProtocolResult
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

class SpeedTester {

    private val validator = EndpointValidator()

    suspend fun runTests(
        configs: List<ParsedConfig>,
        candidateIps: List<String>,
        onStart: (UiItem) -> Unit,
        onDone: (UiItem) -> Unit
    ): List<UiItem> = coroutineScope {
        val socketSemaphore = Semaphore(SpeedTestConfig.CONCURRENCY)

        val deferred = configs.map { cfg ->
            async(Dispatchers.Default) {
                currentCoroutineContext().ensureActive()
                onStart(UiItem.waiting(cfg).copy(status = ItemStatus.TESTING))
                val result = testOne(cfg, candidateIps, socketSemaphore)
                currentCoroutineContext().ensureActive()
                onDone(result)
                result
            }
        }

        deferred.awaitAll()
    }

    private suspend fun testOne(
        cfg: ParsedConfig,
        candidateIps: List<String>,
        socketSemaphore: Semaphore
    ): UiItem = coroutineScope {
        if (!cfg.isValid || candidateIps.isEmpty()) {
            return@coroutineScope UiItem.waiting(cfg).copy(status = ItemStatus.FAILED)
        }

        val ports = cfg.ports.distinct()
        val probes = ArrayList<kotlinx.coroutines.Deferred<Probe>>(ports.size * candidateIps.size)

        for (port in ports) {
            for (ip in candidateIps) {
                probes += async(Dispatchers.IO) {
                    socketSemaphore.withPermit {
                        currentCoroutineContext().ensureActive()
                        Probe(
                            ip = ip,
                            port = port,
                            latencyMs = testPort(ip, port)
                        )
                    }
                }
            }
        }

        val probeResults = probes.awaitAll()

        val successes = probeResults
            .filter { it.latencyMs != null }
            .sortedWith(
                compareBy<Probe> { it.latencyMs ?: Long.MAX_VALUE }
                    .thenBy { it.port }
                    .thenBy { it.ip }
            )

        val topCandidates = validateTopCandidates(
            cfg = cfg,
            successes = successes
        )

        val portDetails = ports.map { port ->
            val bestForPort = successes
                .filter { it.port == port }
                .minByOrNull { it.latencyMs ?: Long.MAX_VALUE }

            PortDetail(
                port = port,
                reachable = bestForPort != null,
                latencyMs = bestForPort?.latencyMs,
                bestIp = bestForPort?.ip
            )
        }

        val best = topCandidates.firstOrNull { it.protocolOk } ?: topCandidates.firstOrNull()

        UiItem(
            id = cfg.id,
            raw = cfg.raw,
            type = cfg.type,
            host = cfg.host,
            ports = cfg.ports,
            sni = cfg.sni,
            path = cfg.path,
            valid = true,
            status = if (topCandidates.isNotEmpty()) ItemStatus.PASSED else ItemStatus.FAILED,
            bestLatencyMs = best?.latencyMs,
            portDetails = portDetails,
            bestIp = best?.ip,
            finalConfig = best?.finalConfig,
            topCandidates = topCandidates
        )
    }

    /**
     * Ranks the TCP successes by latency, then runs the end-to-end protocol
     * probe (real VLESS/Trojan handshake through the endpoint) on the fastest
     * candidates. Candidates that definitively fail the tunnel test are ranked
     * last; the remaining (unprobed) successes stay ranked after them so the
     * result list keeps its previous size.
     */
    private suspend fun validateTopCandidates(
        cfg: ParsedConfig,
        successes: List<Probe>
    ): List<CandidateHit> {
        if (successes.isEmpty()) return emptyList()

        val top = successes.take(SpeedTestConfig.PROTOCOL_VERIFY_TOP)

        val probed = coroutineScope {
            val semaphore = Semaphore(SpeedTestConfig.PROTOCOL_CONCURRENCY)
            top.map { probe ->
                async(Dispatchers.IO) {
                    semaphore.withPermit {
                        currentCoroutineContext().ensureActive()
                        val result = validator.probe(
                            cfg = cfg,
                            raw = cfg.raw,
                            ip = probe.ip,
                            port = probe.port,
                            timeoutMs = SpeedTestConfig.CONNECT_TIMEOUT_MS
                        )
                        TcpCandidate(
                            rank = 0,
                            probe = probe,
                            result = result
                        )
                    }
                }
            }.awaitAll()
        }

        val remaining = successes.drop(SpeedTestConfig.PROTOCOL_VERIFY_TOP)
            .map { probe ->
                TcpCandidate(
                    rank = 0,
                    probe = probe,
                    result = ProtocolResult(verified = false, ok = true)
                )
            }

        return (probed + remaining)
            .sortedWith(
                compareBy<TcpCandidate> { rankOf(it.result) }
                    .thenBy { it.probe.latencyMs ?: Long.MAX_VALUE }
                    .thenBy { it.probe.port }
                    .thenBy { it.probe.ip }
            )
            .take(SpeedTestConfig.TOP_RESULTS_PER_CONFIG)
            .mapIndexed { index, candidate ->
                candidate.copy(rank = index + 1).toHit(cfg)
            }
    }

    private fun rankOf(result: ProtocolResult): Int = when {
        result.verified && result.ok -> 0
        !result.verified -> 1
        else -> 2
    }

    private data class TcpCandidate(
        val rank: Int,
        val probe: Probe,
        val result: ProtocolResult
    ) {
        fun toHit(cfg: ParsedConfig): CandidateHit {
            val config = ConfigRebuilder.rebuild(
                config = cfg,
                newIp = probe.ip,
                newPort = probe.port,
                rank = rank
            ) ?: cfg.raw
            return CandidateHit(
                rank = rank,
                ip = probe.ip,
                port = probe.port,
                latencyMs = probe.latencyMs ?: Long.MAX_VALUE,
                finalConfig = config,
                protocolVerified = result.verified,
                protocolOk = result.ok,
                ttfbMs = result.ttfbMs,
                throughputMbps = result.throughputMbps
            )
        }
    }

    private fun testPort(ip: String, port: Int): Long? {
        val start = SystemClock.elapsedRealtime()
        return try {
            Socket().use { socket ->
                socket.connect(
                    InetSocketAddress(ip, port),
                    SpeedTestConfig.CONNECT_TIMEOUT_MS
                )
                SystemClock.elapsedRealtime() - start
            }
        } catch (e: Exception) {
            null
        }
    }

    private data class Probe(
        val ip: String,
        val port: Int,
        val latencyMs: Long?
    )
}
