package dev.narsaq.speedtester.parse

import android.net.Uri
import android.util.Base64
import dev.narsaq.speedtester.model.ConfigType
import dev.narsaq.speedtester.model.ParsedConfig
import org.json.JSONObject
import java.util.Locale

object ConfigParser {

    const val DEFAULT_PORT = 443
    private const val MAX_PORTS = 3
    private const val MAX_HOST_LENGTH = 253

    private val hostRegex = Regex(
        "^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$"
    )

    fun parse(text: String): List<ParsedConfig> {
        val out = ArrayList<ParsedConfig>()
        var id = 0L
        for (line in text.lineSequence()) {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue
            out += parseLine(trimmed, id++)
        }
        return out
    }

    private fun parseLine(line: String, id: Long): ParsedConfig {
        return when {
            line.startsWith("vless://", true) -> parseBasicUri(id, line, ConfigType.VLESS)
            line.startsWith("trojan://", true) -> parseBasicUri(id, line, ConfigType.TROJAN)
            line.startsWith("vmess://", true) -> parseVmess(id, line)
            line.startsWith("ss://", true) -> parseShadowsocks(id, line)
            else -> parsePlain(id, line)
        }
    }

    private fun invalid(id: Long, raw: String): ParsedConfig =
        ParsedConfig(id, raw, ConfigType.INVALID, "", emptyList(), null, null)

    private fun parseBasicUri(id: Long, line: String, type: ConfigType): ParsedConfig {
        return try {
            val uri = Uri.parse(line)
            val host = uri.host
            if (host.isNullOrBlank() || !isHost(host) || uri.userInfo.isNullOrBlank()) {
                return invalid(id, line)
            }
            val port = parseUriPort(uri, DEFAULT_PORT) ?: return invalid(id, line)
            val sni = uri.getQueryParameter("sni")?.takeIf { it.isNotBlank() }
                ?: uri.getQueryParameter("host")?.takeIf { it.isNotBlank() }
            val path = uri.getQueryParameter("path")?.takeIf { it.isNotBlank() }
            ParsedConfig(id, line, type, host, listOf(port), sni, path)
        } catch (e: Exception) {
            invalid(id, line)
        }
    }

    private fun parseVmess(id: Long, line: String): ParsedConfig {
        return try {
            val payload = line.substringAfter("://").substringBefore('#').trim()
            val json = decodeBase64Loose(payload) ?: return invalid(id, line)
            val obj = JSONObject(json)
            val host = obj.optString("add").ifBlank { obj.optString("host") }.trim()
            if (!isHost(host) || obj.optString("id").isBlank()) {
                return invalid(id, line)
            }
            val port = if (obj.has("port")) parsePortValue(obj.opt("port")) else DEFAULT_PORT
            if (port == null) return invalid(id, line)
            val sni = obj.optString("sni").ifBlank { obj.optString("host") }
                .takeIf { it.isNotBlank() }
            val path = obj.optString("path").takeIf { it.isNotBlank() }
            ParsedConfig(id, line, ConfigType.VMESS, host, listOf(port), sni, path)
        } catch (e: Exception) {
            invalid(id, line)
        }
    }

    private fun parseShadowsocks(id: Long, line: String): ParsedConfig {
        return try {
            val body = line.substringAfter("://").substringBefore('#').substringBefore('?')
            val hostPort = if (body.contains('@')) {
                if (body.substringBeforeLast('@').isBlank()) return invalid(id, line)
                body.substringAfterLast('@')
            } else {
                val decoded = decodeBase64Loose(body.substringBefore('/'))
                    ?: return invalid(id, line)
                if (!decoded.substringBeforeLast('@', "").contains(':')) {
                    return invalid(id, line)
                }
                decoded.substringAfterLast('@')
            }
            val (host, port) = splitHostPort(hostPort)
            if (!isHost(host) || port != null && port !in 1..65535) {
                return invalid(id, line)
            }
            ParsedConfig(
                id, line, ConfigType.SHADOWSOCKS,
                host, listOf(port ?: DEFAULT_PORT), null, null
            )
        } catch (e: Exception) {
            invalid(id, line)
        }
    }

    private fun parsePlain(id: Long, line: String): ParsedConfig {
        return try {
            val lower = line.lowercase(Locale.ROOT)
            if (lower.startsWith("http://") || lower.startsWith("https://")) {
                val uri = Uri.parse(line)
                val host = uri.host
                if (host.isNullOrBlank() || !isHost(host)) return invalid(id, line)
                val port = parseUriPort(
                    uri,
                    if (lower.startsWith("https")) 443 else 80
                ) ?: return invalid(id, line)
                return ParsedConfig(id, line, ConfigType.PLAIN, host, listOf(port), host, null)
            }
            if (line.startsWith("[")) {
                val close = line.indexOf(']')
                if (close < 0) return invalid(id, line)
                val host = line.substring(1, close)
                val ports = parsePortsTail(line.substring(close + 1))
                    ?: return invalid(id, line)
                if (!isIpv6(host)) return invalid(id, line)
                return ParsedConfig(id, line, ConfigType.PLAIN, host, ports, null, null)
            }
            val colons = line.count { it == ':' }
            when {
                colons == 0 -> {
                    if (!isHostname(line)) return invalid(id, line)
                    ParsedConfig(id, line, ConfigType.PLAIN, line, listOf(DEFAULT_PORT), null, null)
                }
                colons >= 2 -> {
                    if (!isIpv6(line)) return invalid(id, line)
                    ParsedConfig(id, line, ConfigType.PLAIN, line, listOf(DEFAULT_PORT), null, null)
                }
                else -> {
                    val host = line.substringBefore(':')
                    val ports = parsePortsTail(
                        line.substring(line.indexOf(':'))
                    ) ?: return invalid(id, line)
                    if (!isHostname(host)) return invalid(id, line)
                    ParsedConfig(id, line, ConfigType.PLAIN, host, ports, null, null)
                }
            }
        } catch (e: Exception) {
            invalid(id, line)
        }
    }

    private fun parsePortsTail(tail: String): List<Int>? {
        if (tail.isEmpty()) return listOf(DEFAULT_PORT)
        if (!tail.startsWith(":")) return null
        val parts = tail.substring(1).split(',')
        if (parts.isEmpty() || parts.size > MAX_PORTS) return null
        val ports = ArrayList<Int>()
        for (part in parts) {
            val v = part.trim().toIntOrNull() ?: return null
            if (v !in 1..65535) return null
            if (v !in ports) ports += v
        }
        return ports
    }

    private fun splitHostPort(s: String): Pair<String, Int?> {
        val str = s.trim()
        if (str.startsWith("[")) {
            val close = str.indexOf(']')
            if (close < 0) return "" to null
            val host = str.substring(1, close)
            val rest = str.substring(close + 1)
            val port = if (rest.startsWith(":")) rest.substring(1).toIntOrNull() else null
            return host to port
        }
        val idx = str.lastIndexOf(':')
        if (idx < 0) return str to null
        val port = str.substring(idx + 1).toIntOrNull() ?: return "" to null
        return str.substring(0, idx) to port
    }

    private fun parsePortValue(value: Any?): Int? = when (value) {
        is Number -> value.toInt().takeIf { it in 1..65535 }
        is String -> value.trim().toIntOrNull()?.takeIf { it in 1..65535 }
        else -> null
    }

    private fun decodeBase64Loose(input: String): String? {
        val cleaned = input.replace("\n", "").replace("\r", "").trim()
        if (cleaned.isEmpty()) return null
        val padded = when (cleaned.length % 4) {
            2 -> "$cleaned=="
            3 -> "$cleaned="
            else -> cleaned
        }
        val flagOptions = listOf(
            Base64.DEFAULT or Base64.NO_PADDING,
            Base64.URL_SAFE or Base64.NO_PADDING
        )
        for (flags in flagOptions) {
            try {
                return String(Base64.decode(padded, flags), Charsets.UTF_8)
            } catch (e: IllegalArgumentException) {
                // try next flag set
            }
        }
        return null
    }

    private fun isHostname(s: String): Boolean =
        s.length in 1..MAX_HOST_LENGTH && hostRegex.matches(s)

    private fun isHost(s: String): Boolean = isHostname(s) || isIpv6(s)

    private fun isIpv6(s: String): Boolean {
        if (!s.contains(':') || s.any { it !in "0123456789abcdefABCDEF:" }) return false
        val doubleColonCount = "::".toRegex().findAll(s).count()
        if (doubleColonCount > 1 || s.contains(":::")) return false
        val groups = s.split(':').filter { it.isNotEmpty() }
        if (groups.any { it.length > 4 }) return false
        return if (doubleColonCount == 1) groups.size < 8 else groups.size == 8
    }

    private fun parseUriPort(uri: Uri, defaultPort: Int): Int? {
        val authority = uri.encodedAuthority ?: return null
        val hostPort = authority.substringAfterLast('@')
        val portText = if (hostPort.startsWith("[")) {
            val close = hostPort.indexOf(']')
            if (close < 0) return null
            val suffix = hostPort.substring(close + 1)
            if (suffix.isEmpty()) return defaultPort
            if (!suffix.startsWith(':')) return null
            suffix.substring(1)
        } else {
            val colon = hostPort.lastIndexOf(':')
            if (colon < 0) return defaultPort
            hostPort.substring(colon + 1)
        }
        return portText.toIntOrNull()?.takeIf { it in 1..65535 }
    }
}