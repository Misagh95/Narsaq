package dev.narsaq.speedtester.data

import org.json.JSONObject

/**
 * Serializable DTO for one built-config row: one final rebuilt config per
 * (config, rank). [batchId] groups the rows of a single build run
 * (a timestamp); only the newest batch is restored on app start.
 */
data class BuiltConfigEntity(
    val batchId: Long,
    val configId: Long,
    val rank: Int,
    val rawConfig: String,
    val host: String,
    val bestIp: String,
    val bestPort: Int,
    val latencyMs: Long,
    val finalConfig: String,
    val protocolVerified: Boolean,
    val protocolOk: Boolean,
    val ttfbMs: Long?,
    val throughputMbps: Float?
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("batchId", batchId)
        put("configId", configId)
        put("rank", rank)
        put("rawConfig", rawConfig)
        put("host", host)
        put("bestIp", bestIp)
        put("bestPort", bestPort)
        put("latencyMs", latencyMs)
        put("finalConfig", finalConfig)
        put("protocolVerified", protocolVerified)
        put("protocolOk", protocolOk)
        put("ttfbMs", ttfbMs ?: JSONObject.NULL)
        put("throughputMbps", throughputMbps ?: JSONObject.NULL)
    }

    companion object {
        fun fromJson(obj: JSONObject): BuiltConfigEntity = BuiltConfigEntity(
            batchId = obj.getLong("batchId"),
            configId = obj.getLong("configId"),
            rank = obj.getInt("rank"),
            rawConfig = obj.getString("rawConfig"),
            host = obj.getString("host"),
            bestIp = obj.getString("bestIp"),
            bestPort = obj.getInt("bestPort"),
            latencyMs = obj.getLong("latencyMs"),
            finalConfig = obj.getString("finalConfig"),
            protocolVerified = obj.getBoolean("protocolVerified"),
            protocolOk = obj.getBoolean("protocolOk"),
            ttfbMs = if (obj.isNull("ttfbMs")) null else obj.getLong("ttfbMs"),
            throughputMbps = if (obj.isNull("throughputMbps")) null else obj.getDouble("throughputMbps").toFloat()
        )
    }
}
