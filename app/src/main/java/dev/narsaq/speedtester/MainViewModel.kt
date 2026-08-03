package dev.narsaq.speedtester

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.narsaq.speedtester.build.ConfigRebuilder
import dev.narsaq.speedtester.model.BuiltResult
import dev.narsaq.speedtester.model.ItemStatus
import dev.narsaq.speedtester.model.ParsedConfig
import dev.narsaq.speedtester.model.UiItem
import dev.narsaq.speedtester.parse.ConfigParser
import dev.narsaq.speedtester.parse.IpParser
import dev.narsaq.speedtester.test.SpeedTester
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

enum class Phase { IDLE, TESTING, DONE, CANCELLED }

enum class UiEvent { NO_VALID_CONFIGS, NO_VALID_IPS, RETEST_EMPTY }

data class TesterState(
    val phase: Phase = Phase.IDLE,
    val totalCount: Int = 0,
    val doneCount: Int = 0,
    val items: List<UiItem> = emptyList()
) {
    val passedItems: List<UiItem>
        get() = items
            .filter { it.status == ItemStatus.PASSED }
            .sortedWith(
                compareBy<UiItem> { it.bestLatencyMs ?: Long.MAX_VALUE }
                    .thenBy { it.bestIp ?: it.host }
            )

    val failedItems: List<UiItem>
        get() = items.filter { it.status == ItemStatus.FAILED || !it.valid }

    val isTerminal: Boolean
        get() = phase == Phase.DONE || phase == Phase.CANCELLED
}

class MainViewModel : ViewModel() {

    data class AntiFilterSettings(
        val fragmentJson: String = "",
        val cipherSuites: String = "",
        val fingerprintUnsafe: Boolean = true
    )

    private val tester = SpeedTester()
    private var testJob: Job? = null
    private var parsedConfigs: List<ParsedConfig> = emptyList()
    private var candidateIps: List<String> = emptyList()
    private var antiFilter: AntiFilterSettings? = null

    private val _state = MutableStateFlow(TesterState())
    val state: StateFlow<TesterState> = _state.asStateFlow()

    private val _events = MutableSharedFlow<UiEvent>(extraBufferCapacity = 16)
    val events: SharedFlow<UiEvent> = _events.asSharedFlow()

    fun startBuild(
        configText: String,
        ipText: String,
        antiFilterSettings: AntiFilterSettings? = null
    ) {
        if (testJob?.isActive == true) return

        antiFilter = antiFilterSettings

        _state.update {
            it.copy(
                phase = Phase.TESTING,
                totalCount = 0,
                doneCount = 0,
                items = emptyList()
            )
        }

        testJob = viewModelScope.launch {
            val configs = withContext(Dispatchers.Default) {
                ConfigParser.parse(configText)
            }
            val ips = withContext(Dispatchers.Default) {
                IpParser.parse(ipText)
            }

            if (configs.isEmpty()) {
                _state.update { it.copy(phase = Phase.IDLE) }
                _events.emit(UiEvent.NO_VALID_CONFIGS)
                return@launch
            }

            if (ips.isEmpty()) {
                _state.update { it.copy(phase = Phase.IDLE) }
                _events.emit(UiEvent.NO_VALID_IPS)
                return@launch
            }

            parsedConfigs = configs
            candidateIps = ips
            runEngine(configs, ips, keepPassed = false)
        }
    }

    fun retestAll() {
        val configs = parsedConfigs
        val ips = candidateIps
        if (configs.isEmpty() || ips.isEmpty() || testJob?.isActive == true) return
        _state.update { it.copy(phase = Phase.TESTING) }
        testJob = viewModelScope.launch {
            runEngine(configs, ips, keepPassed = false)
        }
    }

    fun retestFailed() {
        if (testJob?.isActive == true) return
        val failedIds = _state.value.failedItems.map { it.id }.toSet()
        if (failedIds.isEmpty()) {
            _events.tryEmit(UiEvent.RETEST_EMPTY)
            return
        }
        val subset = parsedConfigs.filter { it.id in failedIds }
        if (subset.isEmpty() || candidateIps.isEmpty()) {
            _events.tryEmit(UiEvent.RETEST_EMPTY)
            return
        }
        _state.update { it.copy(phase = Phase.TESTING) }
        testJob = viewModelScope.launch {
            runEngine(subset, candidateIps, keepPassed = true)
        }
    }

    fun cancelTest() {
        testJob?.cancel()
    }

    fun reset() {
        testJob?.cancel()
        parsedConfigs = emptyList()
        candidateIps = emptyList()
        antiFilter = null
        _state.update { TesterState() }
    }

    fun buildFinalConfigs(): List<BuiltResult> {
        val passed = _state.value.passedItems
        val af = antiFilter

        return passed.flatMap { item ->
            val original = parsedConfigs.find { it.id == item.id }
                ?: return@flatMap emptyList()

            item.topCandidates.map { hit ->
                val rebuilt = ConfigRebuilder.rebuild(
                    config = original,
                    newIp = hit.ip,
                    newPort = hit.port,
                    rank = hit.rank,
                    antiFilter = af?.let {
                        ConfigRebuilder.AntiFilter(
                            fragmentJson = it.fragmentJson,
                            cipherSuites = it.cipherSuites,
                            fingerprintUnsafe = it.fingerprintUnsafe
                        )
                    }
                ) ?: hit.finalConfig

                BuiltResult(
                    rank = hit.rank,
                    originalConfig = original,
                    bestIp = hit.ip,
                    bestPort = hit.port,
                    latencyMs = hit.latencyMs,
                    finalConfig = rebuilt
                )
            }
        }
    }

    private suspend fun runEngine(
        configs: List<ParsedConfig>,
        ips: List<String>,
        keepPassed: Boolean
    ) {
        val prevPassed: Map<Long, UiItem> = if (keepPassed) {
            _state.value.items
                .filter { it.status == ItemStatus.PASSED }
                .associateBy { it.id }
        } else {
            emptyMap()
        }

        val initial: List<UiItem> = configs.map { cfg ->
            when {
                prevPassed.containsKey(cfg.id) -> prevPassed.getValue(cfg.id)
                cfg.isValid -> UiItem.waiting(cfg)
                else -> UiItem.waiting(cfg).copy(status = ItemStatus.FAILED)
            }
        }

        _state.update {
            it.copy(
                totalCount = initial.size,
                doneCount = initial.count { x ->
                    x.status == ItemStatus.PASSED || x.status == ItemStatus.FAILED
                },
                items = initial
            )
        }

        val toTest = configs.filter { cfg ->
            cfg.isValid && !prevPassed.containsKey(cfg.id)
        }

        if (toTest.isEmpty()) {
            _state.update { it.copy(phase = Phase.DONE) }
            return
        }

        try {
            tester.runTests(
                configs = toTest,
                candidateIps = ips,
                onStart = { item ->
                    _state.update { st ->
                        st.copy(
                            items = st.items.map {
                                if (it.id == item.id) item else it
                            }
                        )
                    }
                },
                onDone = { item ->
                    _state.update { st ->
                        st.copy(
                            doneCount = st.doneCount + 1,
                            items = st.items.map {
                                if (it.id == item.id) item else it
                            }
                        )
                    }
                }
            )
            _state.update { it.copy(phase = Phase.DONE) }
        } catch (e: CancellationException) {
            _state.update { st ->
                st.copy(
                    phase = Phase.CANCELLED,
                    items = st.items.map {
                        if (it.status == ItemStatus.TESTING ||
                            it.status == ItemStatus.WAITING
                        ) {
                            it.copy(
                                status = ItemStatus.FAILED,
                                bestLatencyMs = null,
                                portDetails = emptyList(),
                                bestIp = null,
                                finalConfig = null,
                                topCandidates = emptyList()
                            )
                        } else {
                            it
                        }
                    }
                )
            }
        }
    }
}