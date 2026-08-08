package dev.narsaq.speedtester.util

import android.net.Uri
import android.util.Base64
import dev.narsaq.speedtester.model.BuiltResult
import dev.narsaq.speedtester.model.ConfigType
import org.json.JSONArray
import org.json.JSONObject

/**
 * Converts a list of BuiltResult into three export formats:
 *  - Base64 subscription (v2ray-compatible, one link per line, base64-encoded)
 *  - Sing-box JSON (outbounds array)
 *  - Clash YAML (proxies block)
 */
object ConfigPackager {

    // ─── Base64 Subscription ─────────────────────────────────────────────────

    fun buildBase64Subscription(results: List<BuiltResult>): String {
        val lines = results.joinToString("\n") { it.finalConfig.trim() }
        return Base64.encodeToString(lines.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
    }

    // ─── Sing-box JSON ────────────────────────────────────────────────────────

    fun buildSingboxJson(results: List<BuiltResult>): String {
        val outbounds = JSONArray()
        for (r in results) {
            val obj = toSingboxOutbound(r) ?: continue
            outbounds.put(obj)
        }
        val root = JSONObject()
        root.put("outbounds", outbounds)
        return root.toString(2)
    }

    private fun toSingboxOutbound(r: BuiltResult): JSONObject? {
        return try {
            when (r.originalConfig.type) {
                ConfigType.VLESS   -> singboxVless(r)
                ConfigType.TROJAN  -> singboxTrojan(r)
                ConfigType.VMESS   -> singboxVmess(r)
                ConfigType.SHADOWSOCKS -> singboxShadowsocks(r)
                else -> null
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun singboxVless(r: BuiltResult): JSONObject {
        val uri = Uri.parse(r.finalConfig)
        val q = QueryParams(uri.encodedQuery)
        val obj = JSONObject()
        obj.put("type", "vless")
        obj.put("tag", tagName(r))
        obj.put("server", r.bestIp)
        obj.put("server_port", r.bestPort)
        obj.put("uuid", uri.userInfo ?: "")
        val flow = q["flow"]?.let { Uri.decode(it) }
        if (!flow.isNullOrBlank()) obj.put("flow", flow)
        val transport = buildTransport(q)
        if (transport != null) obj.put("transport", transport)
        obj.put("tls", buildTls(q, r.originalConfig.sni))
        return obj
    }

    private fun singboxTrojan(r: BuiltResult): JSONObject {
        val uri = Uri.parse(r.finalConfig)
        val q = QueryParams(uri.encodedQuery)
        val obj = JSONObject()
        obj.put("type", "trojan")
        obj.put("tag", tagName(r))
        obj.put("server", r.bestIp)
        obj.put("server_port", r.bestPort)
        obj.put("password", uri.userInfo ?: "")
        val flow = q["flow"]?.let { Uri.decode(it) }
        if (!flow.isNullOrBlank()) obj.put("flow", flow)
        val transport = buildTransport(q)
        if (transport != null) obj.put("transport", transport)
        obj.put("tls", buildTls(q, r.originalConfig.sni))
        return obj
    }

    private fun singboxVmess(r: BuiltResult): JSONObject {
        val raw = r.finalConfig
        val payload = raw.substringAfter("://").substringBefore('#').trim()
        val json = decodeBase64(payload) ?: return JSONObject()
        val v = JSONObject(json)

        val obj = JSONObject()
        obj.put("type", "vmess")
        obj.put("tag", tagName(r))
        obj.put("server", r.bestIp)
        obj.put("server_port", r.bestPort)
        obj.put("uuid", v.optString("id", ""))
        obj.put("security", v.optString("scy", "auto"))
        obj.put("alter_id", v.optInt("aid", 0))

        val net = v.optString("net", "tcp")
        val transport = buildVmessTransport(v, net)
        if (transport != null) obj.put("transport", transport)

        val tls = v.optString("tls", "")
        if (tls == "tls" || tls == "reality") {
            val tlsObj = JSONObject()
            tlsObj.put("enabled", true)
            val sni = v.optString("sni", "").ifBlank { v.optString("host", "") }
            if (sni.isNotBlank()) tlsObj.put("server_name", sni)
            obj.put("tls", tlsObj)
        }
        return obj
    }

    private fun singboxShadowsocks(r: BuiltResult): JSONObject {
        val uri = Uri.parse(r.finalConfig)
        val q = QueryParams(uri.encodedQuery)
        // credentials are base64(method:password) before @
        val userInfo = uri.userInfo ?: ""
        val decoded = decodeBase64(userInfo) ?: userInfo
        val method = decoded.substringBefore(':')
        val password = decoded.substringAfter(':')

        val obj = JSONObject()
        obj.put("type", "shadowsocks")
        obj.put("tag", tagName(r))
        obj.put("server", r.bestIp)
        obj.put("server_port", r.bestPort)
        obj.put("method", method)
        obj.put("password", password)

        val plugin = parseSsPlugin(q)
        if (plugin != null) {
            obj.put("plugin", plugin.singboxName)
            obj.put("plugin_opts", plugin.optsJoined)
        }
        return obj
    }

    private fun buildTransport(q: QueryParams): JSONObject? {
        return when (q["type"] ?: q["net"] ?: "tcp") {
            "ws" -> {
                val t = JSONObject()
                t.put("type", "ws")
                val path = q["path"]?.let { Uri.decode(it) }
                if (!path.isNullOrBlank()) t.put("path", path)
                val host = q["host"]?.let { Uri.decode(it) }
                if (!host.isNullOrBlank()) {
                    val headers = JSONObject()
                    headers.put("Host", host)
                    t.put("headers", headers)
                }
                t
            }
            "grpc" -> {
                val t = JSONObject()
                t.put("type", "grpc")
                val svcName = q["serviceName"]?.let { Uri.decode(it) }
                if (!svcName.isNullOrBlank()) t.put("service_name", svcName)
                t
            }
            "httpupgrade", "xhttp", "splithttp" -> {
                val t = JSONObject()
                t.put("type", "httpupgrade")
                val path = q["path"]?.let { Uri.decode(it) }
                if (!path.isNullOrBlank()) t.put("path", path)
                val host = q["host"]?.let { Uri.decode(it) }
                if (!host.isNullOrBlank()) t.put("host", host)
                t
            }
            else -> null
        }
    }

    private fun buildVmessTransport(v: JSONObject, net: String): JSONObject? {
        return when (net) {
            "ws" -> {
                val t = JSONObject()
                t.put("type", "ws")
                val path = v.optString("path", "")
                if (path.isNotBlank()) t.put("path", path)
                val host = v.optString("host", "")
                if (host.isNotBlank()) {
                    val headers = JSONObject()
                    headers.put("Host", host)
                    t.put("headers", headers)
                }
                t
            }
            "grpc" -> {
                val t = JSONObject()
                t.put("type", "grpc")
                val svcName = v.optString("path", "")
                if (svcName.isNotBlank()) t.put("service_name", svcName)
                t
            }
            else -> null
        }
    }

    private fun buildTls(q: QueryParams, fallbackSni: String?): JSONObject {
        val obj = JSONObject()
        val security = q["security"] ?: ""
        obj.put("enabled", security == "tls" || security == "reality")
        val sni = (q["sni"] ?: q["host"] ?: fallbackSni ?: "").let { Uri.decode(it) }
        if (sni.isNotBlank()) obj.put("server_name", sni)
        val fp = q["fp"]?.let { Uri.decode(it) }
        if (!fp.isNullOrBlank()) {
            obj.put("utls", JSONObject().apply { put("enabled", true); put("fingerprint", fp) })
        }
        if (security == "reality") {
            val reality = JSONObject()
            reality.put("enabled", true)
            val pbk = (q["pbk"] ?: q["publicKey"] ?: q["public_key"])?.let { Uri.decode(it) }
            if (!pbk.isNullOrBlank()) reality.put("public_key", pbk)
            val sid = (q["sid"] ?: q["shortId"] ?: q["short_id"])?.let { Uri.decode(it) }
            if (!sid.isNullOrBlank()) reality.put("short_id", sid)
            val spx = q["spx"]?.let { Uri.decode(it) }
            if (!spx.isNullOrBlank()) reality.put("spider_x", spx)
            val handshake = q["handshake"]?.let { Uri.decode(it) }?.takeIf { it.isNotBlank() }
                ?: sni.takeIf { it.isNotBlank() }
            if (!handshake.isNullOrBlank()) {
                reality.put(
                    "handshake",
                    JSONObject().apply {
                        put("server", handshake)
                        put("server_port", 443)
                    }
                )
            }
            obj.put("reality", reality)
        }
        return obj
    }

    // ─── Clash YAML ──────────────────────────────────────────────────────────

    fun buildClashYaml(results: List<BuiltResult>): String {
        val sb = StringBuilder()
        sb.appendLine("proxies:")
        for (r in results) {
            val block = toClashProxy(r) ?: continue
            for (line in block.lines()) {
                sb.appendLine("  $line")
            }
        }
        return sb.toString()
    }

    private fun toClashProxy(r: BuiltResult): String? {
        return try {
            when (r.originalConfig.type) {
                ConfigType.VLESS        -> clashVless(r)
                ConfigType.TROJAN       -> clashTrojan(r)
                ConfigType.VMESS        -> clashVmess(r)
                ConfigType.SHADOWSOCKS  -> clashShadowsocks(r)
                else -> null
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun clashVless(r: BuiltResult): String {
        val uri = Uri.parse(r.finalConfig)
        val q = QueryParams(uri.encodedQuery)
        val name = clashProxyName(r)
        val network = q["type"] ?: "tcp"
        val sni = (q["sni"] ?: q["host"] ?: r.originalConfig.sni ?: "").let { Uri.decode(it) }
        val sb = StringBuilder()
        sb.appendLine("- name: \"$name\"")
        sb.appendLine("  type: vless")
        sb.appendLine("  server: ${r.bestIp}")
        sb.appendLine("  port: ${r.bestPort}")
        sb.appendLine("  uuid: ${uri.userInfo ?: ""}")
        sb.appendLine("  network: $network")
        sb.appendLine("  tls: ${q["security"] == "tls" || q["security"] == "reality"}")
        if (sni.isNotBlank()) sb.appendLine("  servername: $sni")
        val fp = q["fp"]?.let { Uri.decode(it) }
        if (!fp.isNullOrBlank()) sb.appendLine("  client-fingerprint: $fp")
        val flow = q["flow"]?.let { Uri.decode(it) }
        if (!flow.isNullOrBlank()) sb.appendLine("  flow: $flow")
        if (q["security"] == "reality") appendClashRealityOpts(sb, q)
        appendClashWsOpts(sb, q, network)
        appendClashGrpcOpts(sb, q, network)
        sb.append("  udp: true")
        return sb.toString()
    }

    private fun clashTrojan(r: BuiltResult): String {
        val uri = Uri.parse(r.finalConfig)
        val q = QueryParams(uri.encodedQuery)
        val name = clashProxyName(r)
        val network = q["type"] ?: "tcp"
        val sni = (q["sni"] ?: q["host"] ?: r.originalConfig.sni ?: "").let { Uri.decode(it) }
        val sb = StringBuilder()
        sb.appendLine("- name: \"$name\"")
        sb.appendLine("  type: trojan")
        sb.appendLine("  server: ${r.bestIp}")
        sb.appendLine("  port: ${r.bestPort}")
        sb.appendLine("  password: ${uri.userInfo ?: ""}")
        sb.appendLine("  network: $network")
        if (sni.isNotBlank()) sb.appendLine("  sni: $sni")
        val fp = q["fp"]?.let { Uri.decode(it) }
        if (!fp.isNullOrBlank()) sb.appendLine("  client-fingerprint: $fp")
        if (q["security"] == "reality") appendClashRealityOpts(sb, q)
        appendClashWsOpts(sb, q, network)
        appendClashGrpcOpts(sb, q, network)
        sb.append("  udp: true")
        return sb.toString()
    }

    private fun clashVmess(r: BuiltResult): String {
        val raw = r.finalConfig
        val payload = raw.substringAfter("://").substringBefore('#').trim()
        val json = decodeBase64(payload) ?: return ""
        val v = JSONObject(json)

        val name = clashProxyName(r)
        val net = v.optString("net", "tcp")
        val tls = v.optString("tls", "")
        val sni = v.optString("sni", "").ifBlank { v.optString("host", "") }

        val sb = StringBuilder()
        sb.appendLine("- name: \"$name\"")
        sb.appendLine("  type: vmess")
        sb.appendLine("  server: ${r.bestIp}")
        sb.appendLine("  port: ${r.bestPort}")
        sb.appendLine("  uuid: ${v.optString("id", "")}")
        sb.appendLine("  alterId: ${v.optInt("aid", 0)}")
        sb.appendLine("  cipher: ${v.optString("scy", "auto")}")
        sb.appendLine("  network: $net")
        sb.appendLine("  tls: ${tls == "tls"}")
        if (sni.isNotBlank()) sb.appendLine("  servername: $sni")
        if (net == "ws") {
            sb.appendLine("  ws-opts:")
            val path = v.optString("path", "/")
            sb.appendLine("    path: \"$path\"")
            val host = v.optString("host", "")
            if (host.isNotBlank()) {
                sb.appendLine("    headers:")
                sb.appendLine("      Host: $host")
            }
        }
        if (net == "grpc") {
            sb.appendLine("  grpc-opts:")
            sb.appendLine("    grpc-service-name: \"${v.optString("path", "")}\"")
        }
        sb.append("  udp: true")
        return sb.toString()
    }

    private fun clashShadowsocks(r: BuiltResult): String {
        val uri = Uri.parse(r.finalConfig)
        val q = QueryParams(uri.encodedQuery)
        val userInfo = uri.userInfo ?: ""
        val decoded = decodeBase64(userInfo) ?: userInfo
        val method = decoded.substringBefore(':')
        val password = decoded.substringAfter(':')
        val name = clashProxyName(r)
        val sb = StringBuilder()
        sb.appendLine("- name: \"$name\"")
        sb.appendLine("  type: ss")
        sb.appendLine("  server: ${r.bestIp}")
        sb.appendLine("  port: ${r.bestPort}")
        sb.appendLine("  cipher: $method")
        sb.appendLine("  password: \"$password\"")
        appendClashSsPlugin(sb, parseSsPlugin(q))
        sb.append("  udp: true")
        return sb.toString()
    }

    private fun appendClashWsOpts(sb: StringBuilder, q: QueryParams, network: String) {
        if (network != "ws") return
        val path = q["path"]?.let { Uri.decode(it) } ?: "/"
        val host = q["host"]?.let { Uri.decode(it) } ?: ""
        sb.appendLine("  ws-opts:")
        sb.appendLine("    path: \"$path\"")
        if (host.isNotBlank()) {
            sb.appendLine("    headers:")
            sb.appendLine("      Host: $host")
        }
    }

    private fun appendClashGrpcOpts(sb: StringBuilder, q: QueryParams, network: String) {
        if (network != "grpc") return
        val svcName = q["serviceName"]?.let { Uri.decode(it) } ?: ""
        sb.appendLine("  grpc-opts:")
        sb.appendLine("    grpc-service-name: \"$svcName\"")
    }

    // ─── Reality / SS plugin helpers ──────────────────────────────────────────

    private fun appendClashRealityOpts(sb: StringBuilder, q: QueryParams) {
        val pbk = (q["pbk"] ?: q["publicKey"] ?: q["public_key"])?.let { Uri.decode(it) }
        val sid = (q["sid"] ?: q["shortId"] ?: q["short_id"])?.let { Uri.decode(it) }
        if (pbk.isNullOrBlank() && sid.isNullOrBlank()) return
        sb.appendLine("  reality-opts:")
        if (!pbk.isNullOrBlank()) sb.appendLine("    public-key: \"$pbk\"")
        if (!sid.isNullOrBlank()) sb.appendLine("    short-id: \"$sid\"")
    }

    private data class SsPlugin(
        val name: String,
        val opts: List<Pair<String, String>>
    ) {
        val singboxName: String
            get() = when (name) {
                "obfs-local", "simple-obfs" -> "obfs"
                else -> name
            }

        val optsJoined: String
            get() = opts.joinToString(";") { (k, v) -> if (v.isEmpty()) k else "$k=$v" }

        fun has(key: String): Boolean = opts.any { it.first == key }

        fun opt(key: String): String? =
            opts.firstOrNull { it.first == key }?.second?.takeIf { it.isNotBlank() }
    }

    private fun parseSsPlugin(q: QueryParams): SsPlugin? {
        val raw = q["plugin"]?.let { Uri.decode(it) }?.trim() ?: return null
        if (raw.isEmpty()) return null
        val parts = raw.split(';')
        val name = parts.firstOrNull()?.trim().orEmpty()
        if (name.isEmpty()) return null
        val opts = parts.drop(1).mapNotNull { token ->
            val t = token.trim()
            if (t.isEmpty()) return@mapNotNull null
            val kv = t.split('=', limit = 2)
            if (kv.size == 2) kv[0] to kv[1] else t to ""
        }
        return SsPlugin(name, opts)
    }

    private fun appendClashSsPlugin(sb: StringBuilder, plugin: SsPlugin?) {
        if (plugin == null) return
        when (plugin.singboxName) {
            "obfs" -> {
                sb.appendLine("  plugin: obfs")
                sb.appendLine("  plugin-opts:")
                val mode = plugin.opt("obfs") ?: "http"
                sb.appendLine("    mode: $mode")
                val host = plugin.opt("obfs-host")
                if (host != null) sb.appendLine("    host: \"$host\"")
            }

            "v2ray-plugin" -> {
                sb.appendLine("  plugin: v2ray-plugin")
                sb.appendLine("  plugin-opts:")
                val mode = when (plugin.opt("mode")) {
                    "http2" -> "http2"
                    "quic" -> "quic"
                    else -> "websocket"
                }
                sb.appendLine("    mode: $mode")
                val host = plugin.opt("host")
                if (host != null) sb.appendLine("    host: \"$host\"")
                val path = plugin.opt("path")
                if (path != null) sb.appendLine("    path: \"$path\"")
                if (plugin.has("tls")) sb.appendLine("    tls: true")
            }

            else -> sb.appendLine("  plugin: ${plugin.name}")
        }
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private fun tagName(r: BuiltResult): String {
        val frag = r.finalConfig.substringAfter('#', "")
        val decoded = if (frag.isNotBlank()) Uri.decode(frag) else ""
        return decoded.ifBlank { "narsaq-${r.rank}-${r.bestIp}" }
    }

    private fun clashProxyName(r: BuiltResult) = tagName(r)

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
            } catch (_: IllegalArgumentException) { }
        }
        return null
    }

    /** Minimal query string parser that URL-decodes keys but keeps values encoded
     *  (so callers can choose to decode or not). */
    private class QueryParams(encoded: String?) {
        private val map = LinkedHashMap<String, String>()
        init {
            encoded?.split("&")?.forEach { part ->
                val idx = part.indexOf('=')
                if (idx > 0) {
                    val key = Uri.decode(part.substring(0, idx))
                    val value = part.substring(idx + 1)
                    map[key] = value
                }
            }
        }
        operator fun get(key: String): String? = map[key]
    }
}
