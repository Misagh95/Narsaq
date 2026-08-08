package dev.narsaq.speedtester.data

import dev.narsaq.speedtester.scan.ScanResult
import org.json.JSONObject

/**
 * Serializable DTO for one scan result row. Persisted as JSON in
 * SharedPreferences (org.json ships with the Android SDK — no extra
 * dependency needed). [batchId] groups the rows of a single scan run
 * (a timestamp); only the newest batch is restored on app start.
 */
data class ScanResultEntity(
    val batchId: Long,
    val ip: String,
    val port: Int,
    val tcpLatencyMs: Long,
    val tlsLatencyMs: Long?,
    val httpValid: Boolean?,
    val verified: Boolean,
    val asn: String,
    val isp: String,
    val country: String,
    val city: String,
    val flaggedDomestic: Boolean,
    val lossRate: Float?,
    val avgLatencyMs: Long?,
    val jitterMs: Long?,
    val throughputMbps: Float?,
    val colo: String
) {
    fun toScanResult(): ScanResult = ScanResult(
        ip = ip,
        port = port,
        tcpLatencyMs = tcpLatencyMs,
        tlsLatencyMs = tlsLatencyMs,
        httpValid = httpValid,
        verified = verified,
        asn = asn,
        isp = isp,
        country = country,
        city = city,
        flaggedDomestic = flaggedDomestic,
        lossRate = lossRate,
        avgLatencyMs = avgLatencyMs,
        jitterMs = jitterMs,
        throughputMbps = throughputMbps,
        colo = colo
    )

    fun toJson(): JSONObject = JSONObject().apply {
        put("batchId", batchId)
        put("ip", ip)
        put("port", port)
        put("tcpLatencyMs", tcpLatencyMs)
        put("tlsLatencyMs", tlsLatencyMs ?: JSONObject.NULL)
        put("httpValid", httpValid ?: JSONObject.NULL)
        put("verified", verified)
        put("asn", asn)
        put("isp", isp)
        put("country", country)
        put("city", city)
        put("flaggedDomestic", flaggedDomestic)
        put("lossRate", lossRate ?: JSONObject.NULL)
        put("avgLatencyMs", avgLatencyMs ?: JSONObject.NULL)
        put("jitterMs", jitterMs ?: JSONObject.NULL)
        put("throughputMbps", throughputMbps ?: JSONObject.NULL)
        put("colo", colo)
    }

    companion object {
        fun fromScanResult(result: ScanResult, batchId: Long): ScanResultEntity =
            ScanResultEntity(
                batchId = batchId,
                ip = result.ip,
                port = result.port,
                tcpLatencyMs = result.tcpLatencyMs,
                tlsLatencyMs = result.tlsLatencyMs,
                httpValid = result.httpValid,
                verified = result.verified,
                asn = result.asn,
                isp = result.isp,
                country = result.country,
                city = result.city,
                flaggedDomestic = result.flaggedDomestic,
                lossRate = result.lossRate,
                avgLatencyMs = result.avgLatencyMs,
                jitterMs = result.jitterMs,
                throughputMbps = result.throughputMbps,
                colo = result.colo
            )

        fun fromJson(obj: JSONObject): ScanResultEntity = ScanResultEntity(
            batchId = obj.getLong("batchId"),
            ip = obj.getString("ip"),
            port = obj.getInt("port"),
            tcpLatencyMs = obj.getLong("tcpLatencyMs"),
            tlsLatencyMs = obj.optLong("tlsLatencyMs", -1L).takeIf { it >= 0 },
            httpValid = if (obj.isNull("httpValid")) null else obj.getBoolean("httpValid"),
            verified = obj.getBoolean("verified"),
            asn = obj.getString("asn"),
            isp = obj.getString("isp"),
            country = obj.getString("country"),
            city = obj.getString("city"),
            flaggedDomestic = obj.getBoolean("flaggedDomestic"),
            lossRate = if (obj.isNull("lossRate")) null else obj.getDouble("lossRate").toFloat(),
            avgLatencyMs = if (obj.isNull("avgLatencyMs")) null else obj.getLong("avgLatencyMs"),
            jitterMs = if (obj.isNull("jitterMs")) null else obj.getLong("jitterMs"),
            throughputMbps = if (obj.isNull("throughputMbps")) null else obj.getDouble("throughputMbps").toFloat(),
            colo = obj.getString("colo")
        )
    }
}
