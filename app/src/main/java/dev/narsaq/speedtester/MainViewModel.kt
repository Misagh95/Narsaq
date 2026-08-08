package dev.narsaq.speedtester

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.narsaq.speedtester.build.ConfigRebuilder
import dev.narsaq.speedtester.data.BuiltConfigEntity
import dev.narsaq.speedtester.data.PersistenceStore
import dev.narsaq.speedtester.model.BuiltResult
import dev.narsaq.speedtester.model.CandidateHit
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

class MainViewModel(app: Application) : AndroidViewModel(app) {

    data class AntiFilterSettings(
        val fragmentJson: String = "",
        val cipherSuites: String = "",
        val fingerprintUnsafe: Boolean = true
    )

    private val tester: SpeedTester = SpeedTester()
    private val store = PersistenceStore(app)
    private var testJob: Job? = null
    private var parsedConfigs: List<ParsedConfig> = emptyList()
    private var candidateIps: List<String> = emptyList()
    private var antiFilter: AntiFilterSettings? = null

    private val _state = MutableStateFlow(TesterState())
    val state: StateFlow<TesterState> = _state.asStateFlow()

    private val _events = MutableSharedFlow<UiEvent>(extraBufferCapacity = 16)
    val events: SharedFlow<UiEvent> = _events.asSharedFlow()

    init {
        // Restore the last build session so results survive app restarts.
        viewModelScope.launch(Dispatchers.IO) {
            val saved = store.latestBuiltConfigs()
            if (saved.isEmpty()) return@launch
            val restored = restoreItems(saved)
            if (restored.isEmpty()) return@launch
            parsedConfigs = restored.map { it.originalConfig }
            _state.update {
                TesterState(
                    phase = Phase.DONE,
                    totalCount = restored.size,
                    doneCount = restored.size,
                    items = restored.map { it.uiItem }
                )
            }
        }
    }

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

    /** True when the PattNG anti-filter (fragment + cipher suites) is applied. */
    fun isAntiFilterActive(): Boolean = antiFilter != null

    /**
     * Applies (or removes) the PattNG anti-filter on every passed config and
     * re-persists the batch. Fragment/cipher-suite values come from
     * [AntiFilterDefaults] — the same ones the cf-optimizor web tool injects.
     */
    fun setAntiFilter(enabled: Boolean) {
        antiFilter = if (enabled) {
            AntiFilterSettings(
                fragmentJson = dev.narsaq.speedtester.util.AntiFilterDefaults.FRAGMENT_JSON,
                cipherSuites = dev.narsaq.speedtester.util.AntiFilterDefaults.CIPHER_SUITES,
                fingerprintUnsafe = true
            )
        } else {
            null
        }

        val af = antiFilter?.let {
            ConfigRebuilder.AntiFilter(
                fragmentJson = it.fragmentJson,
                cipherSuites = it.cipherSuites,
                fingerprintUnsafe = it.fingerprintUnsafe
            )
        }

        _state.update { st ->
            st.copy(
                items = st.items.map { item ->
                    if (item.status != ItemStatus.PASSED) return@map item
                    val original = parsedConfigs.find { it.id == item.id }
                        ?: return@map item
                    val candidates = item.topCandidates.map { hit ->
                        val rebuilt = ConfigRebuilder.rebuild(
                            config = original,
                            newIp = hit.ip,
                            newPort = hit.port,
                            rank = hit.rank,
                            antiFilter = af
                        ) ?: hit.finalConfig
                        hit.copy(finalConfig = rebuilt)
                    }
                    item.copy(
                        topCandidates = candidates,
                        finalConfig = candidates.firstOrNull { it.protocolOk }?.finalConfig
                            ?: candidates.firstOrNull()?.finalConfig
                    )
                }
            )
        }
        viewModelScope.launch { persistResults() }
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

            item.topCandidates
                .map { hit ->
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
                        finalConfig = rebuilt,
                        protocolVerified = hit.protocolVerified,
                        protocolOk = hit.protocolOk,
                        ttfbMs = hit.ttfbMs,
                        throughputMbps = hit.throughputMbps
                    )
                }
        }
    }

    /** Best (rank-1) rebuilt config per passed result, in latency order. */
    fun bestConfigs(): List<BuiltResult> {
        val seen = HashSet<Long>()
        return buildFinalConfigs().filter { seen.add(it.originalConfig.id) }
    }

    /** Best rebuilt config for a single item, or null if none. */
    fun bestConfigFor(item: UiItem): String? {
        val rebuilt = buildFinalConfigs()
            .firstOrNull { it.originalConfig.id == item.id }
            ?.finalConfig
        return rebuilt?.takeIf { it.isNotBlank() } ?: item.finalConfig
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
            persistResults()
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

    // ─── Persistence (Room) ─────────────────────────────────────────────────

    /** A restored build session: original config + its UI item. */
    private data class RestoredBuild(
        val originalConfig: ParsedConfig,
        val uiItem: UiItem
    )

    /** Saves the completed build (ranked final configs) to the store. */
    private suspend fun persistResults() {
        val results = buildFinalConfigs()
        if (results.isEmpty()) return
        val rows = results.map { r ->
            BuiltConfigEntity(
                batchId = System.currentTimeMillis(),
                configId = r.originalConfig.id,
                rank = r.rank,
                rawConfig = r.originalConfig.raw,
                host = r.originalConfig.host,
                bestIp = r.bestIp,
                bestPort = r.bestPort,
                latencyMs = r.latencyMs,
                finalConfig = r.finalConfig,
                protocolVerified = r.protocolVerified,
                protocolOk = r.protocolOk,
                ttfbMs = r.ttfbMs,
                throughputMbps = r.throughputMbps
            )
        }
        withContext(Dispatchers.IO) {
            store.saveBuiltConfigs(rows)
        }
    }

    /** Rebuilds UI items from persisted rows (grouped by original config). */
    private fun restoreItems(rows: List<BuiltConfigEntity>): List<RestoredBuild> {
        val byConfig = rows.groupBy { it.configId }
        val restored = ArrayList<RestoredBuild>(byConfig.size)

        for ((configId, configRows) in byConfig) {
            val ranked = configRows.sortedBy { it.rank }
            val first = ranked.first()

            val original = ConfigParser.parse(first.rawConfig)
                .firstOrNull { it.id == configId }
                ?: ParsedConfig(
                    id = configId,
                    raw = first.rawConfig,
                    type = dev.narsaq.speedtester.model.ConfigType.INVALID,
                    host = first.host,
                    ports = listOf(first.bestPort),
                    sni = null,
                    path = null
                )

            val candidates = ranked.map { r ->
                CandidateHit(
                    rank = r.rank,
                    ip = r.bestIp,
                    port = r.bestPort,
                    latencyMs = r.latencyMs,
                    finalConfig = r.finalConfig,
                    protocolVerified = r.protocolVerified,
                    protocolOk = r.protocolOk,
                    ttfbMs = r.ttfbMs,
                    throughputMbps = r.throughputMbps
                )
            }

            val best = candidates.firstOrNull { it.protocolOk } ?: candidates.firstOrNull()
            val uiItem = UiItem(
                id = original.id,
                raw = original.raw,
                type = original.type,
                host = original.host,
                ports = original.ports,
                sni = original.sni,
                path = original.path,
                valid = original.isValid,
                status = if (original.isValid) ItemStatus.PASSED else ItemStatus.FAILED,
                bestLatencyMs = best?.latencyMs,
                portDetails = emptyList(),
                bestIp = best?.ip,
                finalConfig = best?.finalConfig,
                topCandidates = candidates
            )
            restored += RestoredBuild(originalConfig = original, uiItem = uiItem)
        }

        return restored.sortedBy { it.uiItem.bestLatencyMs ?: Long.MAX_VALUE }
    }
}
