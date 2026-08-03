package dev.narsaq.speedtester.build

import android.net.Uri
import android.util.Base64
import dev.narsaq.speedtester.model.ConfigType
import dev.narsaq.speedtester.model.ParsedConfig
import org.json.JSONObject
import java.net.URLEncoder

object ConfigRebuilder {

    data class AntiFilter(
        val fragmentJson: String = "",
        val cipherSuites: String = "",
        val fingerprintUnsafe: Boolean = true
    )

    fun rebuild(
        config: ParsedConfig,
        newIp: String,
        newPort: Int? = null,
        rank: Int? = null,
        antiFilter: AntiFilter? = null
    ): String? {
        return try {
            when (config.type) {
                ConfigType.VLESS -> rebuildVless(config, newIp, newPort, rank, antiFilter)
                ConfigType.TROJAN -> rebuildTrojan(config, newIp, newPort, rank, antiFilter)
                ConfigType.VMESS -> rebuildVmess(config, newIp, newPort, rank, antiFilter)
                ConfigType.SHADOWSOCKS -> rebuildShadowsocks(config, newIp, newPort, rank)
                ConfigType.PLAIN -> rebuildPlain(newIp, newPort ?: config.ports.firstOrNull())
                ConfigType.INVALID -> null
            }
        } catch (e: Exception) {
            null
        }
    }

    // ─── VLESS ───

    private fun rebuildVless(
        config: ParsedConfig,
        newIp: String,
        newPort: Int?,
        rank: Int?,
        antiFilter: AntiFilter?
    ): String {
        val uri = Uri.parse(config.raw)
        val userInfo = uri.userInfo ?: return config.raw
        val port = newPort ?: config.ports.firstOrNull() ?: 443
        var query = uri.encodedQuery ?: ""

        if (antiFilter != null) {
            query = applyAntiFilterToQuery(query, antiFilter)
        }

        val qPart = if (query.isNotBlank()) "?$query" else ""
        val fragment = buildFragment(uri.fragment, rank)
        return "vless://$userInfo@${formatIp(newIp)}:$port$qPart$fragment"
    }

    // ─── Trojan ───

    private fun rebuildTrojan(
        config: ParsedConfig,
        newIp: String,
        newPort: Int?,
        rank: Int?,
        antiFilter: AntiFilter?
    ): String {
        val uri = Uri.parse(config.raw)
        val password = uri.userInfo ?: return config.raw
        val port = newPort ?: config.ports.firstOrNull() ?: 443
        var query = uri.encodedQuery ?: ""

        if (antiFilter != null) {
            query = applyAntiFilterToQuery(query, antiFilter)
        }

        val qPart = if (query.isNotBlank()) "?$query" else ""
        val fragment = buildFragment(uri.fragment, rank)
        return "trojan://$password@${formatIp(newIp)}:$port$qPart$fragment"
    }

    // ─── VMess ───

    private fun rebuildVmess(
        config: ParsedConfig,
        newIp: String,
        newPort: Int?,
        rank: Int?,
        antiFilter: AntiFilter?
    ): String {
        val raw = config.raw
        val payload = raw.substringAfter("://").substringBefore('#').trim()
        val json = decodeBase64(payload) ?: return raw
        val obj = JSONObject(json)

        obj.put("add", newIp)
        if (newPort != null) {
            obj.put("port", newPort.toString())
        }

        if (antiFilter != null) {
            if (antiFilter.fingerprintUnsafe) {
                obj.put("fp", "unsafe")
            }
            if (antiFilter.fragmentJson.isNotBlank()) {
                obj.put("fragment", antiFilter.fragmentJson)
            }
            if (antiFilter.cipherSuites.isNotBlank()) {
                obj.put("cipherSuites", antiFilter.cipherSuites)
            }
        }

        val oldPs = obj.optString("ps", "")
        if (rank != null) {
            obj.put("ps", renameLabel(oldPs, rank))
        }

        val encoded = Base64.encodeToString(
            obj.toString().toByteArray(Charsets.UTF_8),
            Base64.NO_WRAP
        )

        val originalFrag = if ('#' in raw) Uri.decode(raw.substringAfter('#')) else ""
        val fragment = buildFragment(originalFrag, rank)
        return "vmess://$encoded$fragment"
    }

    // ─── Shadowsocks ───

    private fun rebuildShadowsocks(
        config: ParsedConfig,
        newIp: String,
        newPort: Int?,
        rank: Int?
    ): String {
        val rawBody = config.raw.substringAfter("://")

        val bodyWithoutFrag: String
        val fragmentRaw: String
        if ('#' in rawBody) {
            bodyWithoutFrag = rawBody.substringBefore('#')
            fragmentRaw = Uri.decode(rawBody.substringAfter('#'))
        } else {
            bodyWithoutFrag = rawBody
            fragmentRaw = ""
        }

        val serverPart: String
        val queryPart: String
        if ('?' in bodyWithoutFrag) {
            serverPart = bodyWithoutFrag.substringBefore('?')
            queryPart = "?" + bodyWithoutFrag.substringAfter('?')
        } else {
            serverPart = bodyWithoutFrag
            queryPart = ""
        }

        val credentialPart = if ('@' in serverPart) {
            serverPart.substringBeforeLast('@')
        } else {
            val decoded = decodeBase64(serverPart) ?: return config.raw
            if ('@' !in decoded) return config.raw
            val credentials = decoded.substringBeforeLast('@')
            Base64.encodeToString(
                credentials.toByteArray(Charsets.UTF_8),
                Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING
            )
        }

        val port = newPort ?: config.ports.firstOrNull() ?: 443
        val fragment = buildFragment(fragmentRaw, rank)
        return "ss://$credentialPart@${formatIp(newIp)}:$port$queryPart$fragment"
    }

    // ─── Plain ───

    private fun rebuildPlain(newIp: String, port: Int?): String {
        return if (port != null) "$newIp:$port" else newIp
    }

    // ─── Anti-Filter Query Helper ───

    private fun applyAntiFilterToQuery(originalQuery: String, af: AntiFilter): String {
        val params = LinkedHashMap<String, String>()

        if (originalQuery.isNotBlank()) {
            for (param in originalQuery.split("&")) {
                val parts = param.split("=", limit = 2)
                if (parts.size == 2) {
                    params[parts[0]] = parts[1]
                }
            }
        }

        if (af.fingerprintUnsafe) {
            params["fp"] = "unsafe"
        }

        if (af.fragmentJson.isNotBlank()) {
            params["fragment"] = Uri.encode(af.fragmentJson)
        }

        if (af.cipherSuites.isNotBlank()) {
            params["cipherSuites"] = Uri.encode(af.cipherSuites)
        }

        return params.entries.joinToString("&") { "${it.key}=${it.value}" }
    }

    // ─── Helpers ───

    private fun formatIp(ip: String): String {
        return if (':' in ip) "[$ip]" else ip
    }

    private fun buildFragment(original: String?, rank: Int?): String {
        val name = when {
            original.isNullOrBlank() && rank == null -> ""
            rank == null -> original.orEmpty()
            else -> renameLabel(original.orEmpty(), rank)
        }
        return if (name.isBlank()) "" else "#${Uri.encode(name)}"
    }

    private fun renameLabel(label: String, rank: Int): String {
        val trimmed = label.trim()
        if (trimmed.isEmpty()) return rank.toString()
        val pattern = Regex("""^(.*?)(\d+)(\s*-\s*.*)?$""")
        val match = pattern.matchEntire(trimmed)
        return if (match != null) {
            val prefix = match.groupValues[1]
            val suffix = match.groupValues[3]
            "$prefix$rank$suffix"
        } else {
            "$trimmed $rank"
        }
    }

    private fun decodeBase64(input: String): String? {
        val cleaned = input.replace("\n", "").replace("\r", "").trim()
        if (cleaned.isEmpty()) return null
        val padded = when (cleaned.length % 4) {
            2 -> "$cleaned=="
            3 -> "$cleaned="
            else -> cleaned
        }
        val flags = listOf(
            Base64.DEFAULT or Base64.NO_PADDING,
            Base64.URL_SAFE or Base64.NO_PADDING
        )
        for (flag in flags) {
            try {
                return String(Base64.decode(padded, flag), Charsets.UTF_8)
            } catch (_: IllegalArgumentException) {
            }
        }
        return null
    }
}