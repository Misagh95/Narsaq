package dev.narsaq.speedtester.model

enum class ConfigType {
    VLESS, VMESS, SHADOWSOCKS, TROJAN, PLAIN, INVALID
}

enum class ItemStatus {
    WAITING, TESTING, PASSED, FAILED
}

data class PortDetail(
    val port: Int,
    val reachable: Boolean?,
    val latencyMs: Long?,
    val bestIp: String? = null
)

data class CandidateHit(
    val rank: Int,
    val ip: String,
    val port: Int,
    val latencyMs: Long,
    val finalConfig: String,
    val protocolVerified: Boolean = false,
    val protocolOk: Boolean = true,
    val ttfbMs: Long? = null,
    val throughputMbps: Float? = null
)

data class ParsedConfig(
    val id: Long,
    val raw: String,
    val type: ConfigType,
    val host: String,
    val ports: List<Int>,
    val sni: String?,
    val path: String?
) {
    val isValid: Boolean
        get() = type != ConfigType.INVALID && host.isNotBlank() && ports.isNotEmpty()
}

data class UiItem(
    val id: Long,
    val raw: String,
    val type: ConfigType,
    val host: String,
    val ports: List<Int>,
    val sni: String?,
    val path: String?,
    val valid: Boolean,
    val status: ItemStatus,
    val bestLatencyMs: Long?,
    val portDetails: List<PortDetail>,
    val bestIp: String? = null,
    val finalConfig: String? = null,
    val topCandidates: List<CandidateHit> = emptyList()
) {
    val bestPort: Int?
        get() = topCandidates.firstOrNull()?.port
            ?: portDetails.firstOrNull { d ->
                d.reachable == true &&
                    d.latencyMs != null &&
                    d.latencyMs == bestLatencyMs &&
                    d.bestIp == bestIp
            }?.port

    companion object {
        fun waiting(cfg: ParsedConfig): UiItem = UiItem(
            id = cfg.id,
            raw = cfg.raw,
            type = cfg.type,
            host = cfg.host,
            ports = cfg.ports,
            sni = cfg.sni,
            path = cfg.path,
            valid = cfg.isValid,
            status = ItemStatus.WAITING,
            bestLatencyMs = null,
            portDetails = emptyList(),
            bestIp = null,
            finalConfig = null,
            topCandidates = emptyList()
        )
    }
}

data class BuiltResult(
    val rank: Int,
    val originalConfig: ParsedConfig,
    val bestIp: String,
    val bestPort: Int,
    val latencyMs: Long,
    val finalConfig: String,
    val protocolVerified: Boolean = false,
    val protocolOk: Boolean = true,
    val ttfbMs: Long? = null,
    val throughputMbps: Float? = null
)
