package dev.narsaq.speedtester

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.narsaq.speedtester.data.PersistenceStore
import dev.narsaq.speedtester.data.ScanResultEntity
import dev.narsaq.speedtester.scan.IpScanner
import dev.narsaq.speedtester.scan.ScanResult
import dev.narsaq.speedtester.util.AsnLookup
import dev.narsaq.speedtester.util.FlagUtil
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

enum class ScanPhase { IDLE, SCANNING, ASN_LOOKUP, DONE, CANCELLED }

data class ScanState(
    val phase: ScanPhase = ScanPhase.IDLE,
    val total: Int = 0,
    val done: Int = 0,
    val found: Int = 0,
    val currentPhase: String = "",
    val results: List<ScanResult> = emptyList()
) {
    val progressPercent: Int
        get() = if (total > 0) (done * 100 / total) else 0
}

class ScanViewModel(app: Application) : AndroidViewModel(app) {

    private val scanner = IpScanner()
    private val store = PersistenceStore(app)
    private var scanJob: Job? = null

    private val _state = MutableStateFlow(ScanState())
    val state: StateFlow<ScanState> = _state.asStateFlow()

    init {
        // Restore the last scan session so results survive app restarts.
        viewModelScope.launch(Dispatchers.IO) {
            val saved = store.latestScanResults()
            if (saved.isEmpty()) return@launch
            val results = saved.map { it.toScanResult() }
            _state.update {
                ScanState(
                    phase = ScanPhase.DONE,
                    total = results.size,
                    done = results.size,
                    found = results.size,
                    currentPhase = "Done",
                    results = results
                )
            }
        }
    }

    fun startScan(
        ports: List<Int> = IpScanner.CLOUDFLARE_HTTPS_PORTS.take(1),
        count: Int = IpScanner.DEFAULT_COUNT,
        timeoutMs: Int = IpScanner.DEFAULT_TIMEOUT_MS,
        enableTls: Boolean = true,
        enableVerify: Boolean = true,
        neighborScan: Boolean = false,
        enableV6: Boolean = false,
        customRanges: String = "",
        speedTest: Boolean = true
    ) {
        if (scanJob?.isActive == true) return

        _state.update {
            ScanState(
                phase = ScanPhase.SCANNING,
                total = count * ports.size,
                currentPhase = "Starting..."
            )
        }

        scanJob = viewModelScope.launch {
            try {
                val results = scanner.scan(
                    ports = ports,
                    count = count,
                    timeoutMs = timeoutMs,
                    enableTls = enableTls,
                    enableVerify = enableVerify,
                    neighborScan = neighborScan,
                    enableV6 = enableV6,
                    customRanges = customRanges,
                    speedTest = speedTest,
                    onProgress = { progress ->
                        _state.update { st ->
                            st.copy(
                                total = progress.total,
                                done = progress.done,
                                found = progress.found,
                                currentPhase = progress.phase
                            )
                        }
                    }
                )

                // ─── ASN lookup for top results ───
                _state.update {
                    it.copy(
                        phase = ScanPhase.ASN_LOOKUP,
                        results = results,
                        currentPhase = "ASN Lookup"
                    )
                }

                val infoMap = AsnLookup.lookupAll(
                    ips = results.map { it.ip }.distinct(),
                    concurrency = 8
                )

                val enriched = results.map { result ->
                    val info = infoMap[result.ip]
                    if (info == null) result else result.copy(
                        asn = info.asn,
                        isp = info.isp,
                        country = info.country,
                        city = info.city,
                        flaggedDomestic = info.isFlaggedDomestic
                    )
                }

                _state.update {
                    val cleanResults = enriched.filter { result -> !result.flaggedDomestic }
                    it.copy(
                        phase = ScanPhase.DONE,
                        results = cleanResults,
                        found = cleanResults.size,
                        currentPhase = "Done"
                    )
                }
                persistResults()
            } catch (e: kotlinx.coroutines.CancellationException) {
                _state.update {
                    it.copy(
                        phase = ScanPhase.CANCELLED,
                        currentPhase = "Cancelled"
                    )
                }
            }
        }
    }

    fun cancelScan() {
        scanJob?.cancel()
    }

    fun reset() {
        scanJob?.cancel()
        _state.update { ScanState() }
    }

    fun getCleanIpsText(limit: Int = Int.MAX_VALUE): String {
        // exclude flagged domestic IPs from the export; results are already
        // sorted by quality so taking the first N picks the best N
        return _state.value.results
            .filter { !it.flaggedDomestic }
            .take(limit)
            .joinToString("\n") { result ->
                val ip = if (':' in result.ip) "[${result.ip}]" else result.ip
                "$ip:${result.port}"
            }
    }

    fun getCleanIpsList(limit: Int = Int.MAX_VALUE): List<String> {
        return _state.value.results
            .filter { !it.flaggedDomestic }
            .take(limit)
            .map { it.ip }
    }

    fun getScanReportText(): String {
        return _state.value.results
            .filter { !it.flaggedDomestic }
            .joinToString("\n") { result ->
                val loss = result.lossRate?.let { "%.0f%%".format(it) } ?: "N/A"
                val jitter = result.jitterMs?.let { "±${it}ms" } ?: "N/A"
                val speed = result.throughputMbps?.let { "%.1f Mbps".format(it) } ?: "N/A"
                val flag = if (result.isCloudflare) {
                    ""
                } else {
                    FlagUtil.countryFlag(result.country)
                }
                val location = buildString {
                    if (result.country.isNotBlank()) append(result.country)
                    if (flag.isNotEmpty()) {
                        if (isNotEmpty()) append(" ")
                        append(flag)
                    }
                    if (result.city.isNotBlank()) {
                        if (isNotEmpty()) append("/")
                        append(result.city)
                    }
                }
                val ip = if (':' in result.ip) "[${result.ip}]" else result.ip
                "${ip}:${result.port} | ${result.totalLatencyMs}ms | Loss: $loss | " +
                    "Jitter: $jitter | Speed: $speed" +
                    (if (result.colo.isNotBlank()) " | Colo: ${result.colo}" else "") +
                    " | ASN: ${result.asn.ifBlank { "N/A" }} | ISP: ${result.isp.ifBlank { "N/A" }} | $location"
            }
    }

    fun getCleanIpsList(): List<String> {
        return _state.value.results
            .filter { !it.flaggedDomestic }
            .map { it.ip }
    }

    /** Saves the completed scan to the store (newest batch wins). */
    private suspend fun persistResults() {
        val results = _state.value.results
        if (results.isEmpty()) return
        val rows = results.map { ScanResultEntity.fromScanResult(it, System.currentTimeMillis()) }
        withContext(Dispatchers.IO) {
            store.saveScanResults(rows)
        }
    }
}
