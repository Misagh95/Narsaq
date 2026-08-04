package dev.narsaq.speedtester

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.narsaq.speedtester.scan.IpScanner
import dev.narsaq.speedtester.scan.ScanResult
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

enum class ScanPhase { IDLE, SCANNING, DONE, CANCELLED }

data class ScanState(
    val phase: ScanPhase = ScanPhase.IDLE,
    val total: Int = 0,
    val done: Int = 0,
    val found: Int = 0,
    val results: List<ScanResult> = emptyList()
) {
    val progressPercent: Int
        get() = if (total > 0) (done * 100 / total) else 0
}

class ScanViewModel : ViewModel() {

    private val scanner = IpScanner()
    private var scanJob: Job? = null

    private val _state = MutableStateFlow(ScanState())
    val state: StateFlow<ScanState> = _state.asStateFlow()

    fun startScan(
        port: Int = IpScanner.DEFAULT_PORT,
        count: Int = IpScanner.DEFAULT_COUNT,
        timeoutMs: Int = IpScanner.DEFAULT_TIMEOUT_MS
    ) {
        if (scanJob?.isActive == true) return

        _state.update {
            ScanState(
                phase = ScanPhase.SCANNING,
                total = count
            )
        }

        scanJob = viewModelScope.launch {
            try {
                val results = scanner.scan(
                    port = port,
                    count = count,
                    timeoutMs = timeoutMs,
                    onProgress = { progress ->
                        _state.update { st ->
                            st.copy(
                                done = progress.done,
                                found = progress.found
                            )
                        }
                    }
                )

                _state.update {
                    it.copy(
                        phase = ScanPhase.DONE,
                        results = results,
                        found = results.size
                    )
                }
            } catch (e: kotlinx.coroutines.CancellationException) {
                _state.update { it.copy(phase = ScanPhase.CANCELLED) }
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

    fun getCleanIpsText(): String {
        return _state.value.results.joinToString("\n") { result -> result.ip }
    }

    fun getCleanIpsList(): List<String> {
        return _state.value.results.map { result -> result.ip }
    }
}