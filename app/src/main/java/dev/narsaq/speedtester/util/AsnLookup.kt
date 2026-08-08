package dev.narsaq.speedtester.util

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.ConcurrentHashMap

/**
 * Lightweight ISP/ASN lookup via ipinfo.io (free tier, no key needed for basic fields).
 * Results are cached in-memory for the lifetime of the process to avoid repeat calls.
 */
object AsnLookup {

    data class IpInfo(
        val ip: String,
        val org: String,
        val country: String,
        val city: String
    ) {
        val asn: String get() = org.substringBefore(' ').takeIf { it.startsWith("AS") } ?: ""
        val isp: String get() = if (asn.isNotBlank()) org.substringAfter(' ').trim() else org
        val isCloudflare: Boolean get() = asn == "AS13335" || isp.contains("Cloudflare", ignoreCase = true)
        val isFlaggedDomestic: Boolean get() = DOMESTIC_ASNS.contains(asn) || (country == "IR" && !isCloudflare)
    }

    private val cache = ConcurrentHashMap<String, IpInfo>()
    private const val TIMEOUT_MS = 4000

    private val DOMESTIC_ASNS = setOf(
        "AS48159", "AS16322", "AS49100", "AS43754", "AS44244",
        "AS197207", "AS25184", "AS12880", "AS48434", "AS47262",
        "AS57218", "AS44285"
    )

    suspend fun lookup(ip: String): IpInfo? {
        cache[ip]?.let { return it }
        return withContext(Dispatchers.IO) {
            val info = tryIpInfo(ip) ?: tryIpWhoIs(ip)
            if (info != null) cache[ip] = info
            info
        }
    }

    private fun tryIpInfo(ip: String): IpInfo? {
        return try {
            val url = URL("https://ipinfo.io/$ip/json")
            val conn = url.openConnection() as HttpURLConnection
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS
            conn.setRequestProperty("Accept", "application/json")
            conn.setRequestProperty("User-Agent", "Narsaq/1.0")
            val body = conn.inputStream.bufferedReader().use { it.readText() }
            conn.disconnect()
            val json = JSONObject(body)
            IpInfo(
                ip = ip,
                org = json.optString("org", ""),
                country = json.optString("country", ""),
                city = json.optString("city", "")
            ).takeIf { it.org.isNotBlank() || it.country.isNotBlank() }
        } catch (e: Exception) {
            null
        }
    }

    private fun tryIpWhoIs(ip: String): IpInfo? {
        return try {
            val url = URL("https://ipwho.is/$ip")
            val conn = url.openConnection() as HttpURLConnection
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS
            conn.setRequestProperty("Accept", "application/json")
            conn.setRequestProperty("User-Agent", "Narsaq/1.0")
            val body = conn.inputStream.bufferedReader().use { it.readText() }
            conn.disconnect()
            val json = JSONObject(body)
            if (!json.optBoolean("success", true)) return null
            val connection = json.optJSONObject("connection")
            val asn = connection?.optString("asn", "") ?: ""
            val orgName = connection?.optString("org", "") ?: ""
            val org = if (asn.isNotBlank()) "AS$asn $orgName" else orgName
            IpInfo(
                ip = ip,
                org = org,
                country = json.optString("country_code", ""),
                city = json.optString("city", "")
            ).takeIf { it.org.isNotBlank() || it.country.isNotBlank() }
        } catch (e: Exception) {
            null
        }
    }

    suspend fun lookupAll(
        ips: List<String>,
        concurrency: Int = 8,
        onEach: (IpInfo) -> Unit = {}
    ): Map<String, IpInfo> = coroutineScope {
        val semaphore = Semaphore(concurrency)
        ips.map { ip ->
            async(Dispatchers.IO) {
                semaphore.withPermit {
                    lookup(ip)?.also { onEach(it) }
                }
            }
        }.awaitAll()
        ips.mapNotNull { ip -> cache[ip]?.let { ip to it } }.toMap()
    }

    fun getCached(ip: String): IpInfo? = cache[ip]
    fun clearCache() = cache.clear()
}