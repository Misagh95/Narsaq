package dev.narsaq.speedtester.protocol

import dev.narsaq.speedtester.model.ConfigType
import dev.narsaq.speedtester.model.ParsedConfig
import java.net.URLDecoder

/**
 * Pure-Kotlin implementations of the VLESS / Trojan / WebSocket protocol
 * pieces needed to end-to-end validate a rebuilt share link against a
 * candidate endpoint — no external Xray binary required.
 *
 * The byte-level builders here are kept free of Android dependencies so the
 * protocol logic can be unit tested on the JVM.
 */
object ProtocolCore {

    data class ProtocolSpec(
        val type: ConfigType,
        val credential: String,   // VLESS uuid or Trojan hex password
        val network: String,      // "tcp" | "ws"
        val security: String,     // "" | "tls" | "reality"
        val sni: String?,
        val wsHost: String?,
        val wsPath: String,
        val flow: String?,
        val targetHost: String
    ) {
        val supportsE2E: Boolean
            get() = (type == ConfigType.VLESS || type == ConfigType.TROJAN) &&
                (network == "tcp" || network == "ws") &&
                flow.isNullOrBlank()
    }

    /** Extracts the fields needed for an end-to-end probe from a share link. */
    fun parse(raw: String, cfg: ParsedConfig): ProtocolSpec? {
        if (cfg.type != ConfigType.VLESS && cfg.type != ConfigType.TROJAN) return null
        val body = raw.substringBefore('#').substringAfter("://")
        val qIndex = body.indexOf('?')
        val params = if (qIndex >= 0) parseQuery(body.substring(qIndex + 1)) else emptyMap()

        val userInfo = body.substringBefore('@').takeIf { '@' in body } ?: return null
        if (userInfo.isBlank()) return null

        val network = (params["type"] ?: params["net"] ?: "tcp").lowercase()
        val security = (params["security"] ?: "").lowercase()
        val sni = params["sni"]?.takeIf { it.isNotBlank() }
        val wsHost = if (network == "ws") params["host"]?.takeIf { it.isNotBlank() } else null
        val path = params["path"]?.takeIf { it.isNotBlank() } ?: "/"
        val flow = params["flow"]?.takeIf { it.isNotBlank() }

        return ProtocolSpec(
            type = cfg.type,
            credential = userInfo,
            network = network,
            security = security,
            sni = sni,
            wsHost = wsHost,
            wsPath = path,
            flow = flow,
            targetHost = cfg.host
        )
    }

    private fun parseQuery(query: String): Map<String, String> {
        val map = HashMap<String, String>()
        for (part in query.split("&")) {
            if (part.isEmpty()) continue
            val idx = part.indexOf('=')
            if (idx < 0) continue
            val key = URLDecoder.decode(part.substring(0, idx), "UTF-8")
            val value = URLDecoder.decode(part.substring(idx + 1), "UTF-8")
            map[key] = value
        }
        return map
    }

    // ─── VLESS ───────────────────────────────────────────────────────────────

    object Vless {
        const val ATYP_IPV4: Byte = 1
        const val ATYP_DOMAIN: Byte = 2
        const val ATYP_IPV6: Byte = 3

        /** 16 raw bytes of a UUID string (dashes are optional). */
        fun uuidToBytes(uuid: String): ByteArray? {
            val hex = uuid.replace("-", "")
            if (hex.length != 32) return null
            val out = ByteArray(16)
            for (i in 0 until 16) {
                val v = hex.substring(i * 2, i * 2 + 2).toIntOrNull(16) ?: return null
                out[i] = v.toByte()
            }
            return out
        }

        /**
         * VLESS request header followed by the inner payload.
         * version(0) + uuid(16) + addons(0) + command(1=tcp) + port(2 BE) +
         * addressType(1) + address + payload
         */
        fun requestHeader(
            uuid: ByteArray,
            port: Int,
            addressType: Byte,
            address: ByteArray,
            innerPayload: ByteArray
        ): ByteArray {
            val head = ByteArray(1 + 16 + 1 + 1 + 2 + 1 + address.size)
            var i = 0
            head[i++] = 0                     // version
            uuid.copyInto(head, i)
            i += 16
            head[i++] = 0                     // addons length
            head[i++] = 1                     // command: tcp
            head[i++] = (port ushr 8).toByte()
            head[i++] = port.toByte()
            head[i++] = addressType
            address.copyInto(head, i)
            return head + innerPayload
        }

        /**
         * Server response header: version(0) + addons length(0). Some servers
         * skip the header and stream the inner HTTP response directly, so a
         * leading "HTTP/" is also accepted as success.
         */
        fun isSuccess(header: ByteArray): Boolean {
            if (header.size < 2) return false
            val h0 = header[0].toInt()
            val h1 = header[1].toInt()
            if (h0 == 0 && h1 == 0) return true
            if (h0 == 'H'.code && h1 == 'T'.code) return true
            return false
        }
    }

    // ─── Trojan ──────────────────────────────────────────────────────────────

    object Trojan {
        fun request(passwordHex: String, targetHost: String, targetPort: Int): ByteArray {
            val sb = StringBuilder()
            sb.append(passwordHex).append("\r\n")
            sb.append("CONNECT $targetHost:$targetPort HTTP/1.1\r\n")
            sb.append("Host: $targetHost:$targetPort\r\n\r\n")
            return sb.toString().toByteArray(Charsets.US_ASCII)
        }

        fun isSuccess(responseHead: String): Boolean =
            responseHead.startsWith("HTTP/1.1 200") || responseHead.startsWith("HTTP/1.0 200")
    }

    // ─── WebSocket framing ───────────────────────────────────────────────────

    object Ws {
        const val OP_CONT = 0x0
        const val OP_TEXT = 0x1
        const val OP_BINARY = 0x2
        const val OP_CLOSE = 0x8
        const val OP_PING = 0x9
        const val OP_PONG = 0xA

        fun handshakeRequest(path: String, host: String, key: String): ByteArray {
            val p = if (path.startsWith("/")) path else "/$path"
            return ("GET $p HTTP/1.1\r\n" +
                "Host: $host\r\n" +
                "Upgrade: websocket\r\n" +
                "Connection: Upgrade\r\n" +
                "Sec-WebSocket-Key: $key\r\n" +
                "Sec-WebSocket-Version: 13\r\n" +
                "\r\n").toByteArray(Charsets.US_ASCII)
        }

        fun isUpgraded(response: String): Boolean =
            response.startsWith("HTTP/1.1 101") || response.startsWith("HTTP/1.0 101")

        /** Encodes a FIN+binary client frame with the given 4-byte mask. */
        fun encodeClientFrame(payload: ByteArray, mask: ByteArray): ByteArray {
            require(mask.size == 4) { "mask must be 4 bytes" }
            val len = payload.size
            val headerLen = when {
                len < 126 -> 2
                len < 65536 -> 4
                else -> 10
            }
            val out = ByteArray(headerLen + 4 + len)
            var i = 0
            out[i++] = (0x80 or OP_BINARY).toByte()   // FIN + binary
            if (len < 126) {
                out[i++] = (0x80 or len).toByte()
            } else if (len < 65536) {
                out[i++] = (0x80 or 126).toByte()
                out[i++] = (len ushr 8).toByte()
                out[i++] = len.toByte()
            } else {
                out[i++] = (0x80 or 127).toByte()
                for (shift in 56 downTo 0 step 8) {
                    out[i++] = (len.toLong() ushr shift).toByte()
                }
            }
            mask.copyInto(out, i)
            i += 4
            for (j in payload.indices) {
                out[i + j] = (payload[j].toInt() xor mask[j % 4].toInt()).toByte()
            }
            return out
        }

        /**
         * Decodes the payload length of a frame from its length byte and any
         * extended length bytes. Returns -1 when the encoding is invalid.
         */
        fun decodeFrameLength(lengthByte: Int, extended: ByteArray): Long {
            val b = lengthByte and 0x7F
            return when {
                b < 126 -> b.toLong()
                b == 126 && extended.size >= 2 ->
                    (((extended[0].toInt() and 0xFF) shl 8) or (extended[1].toInt() and 0xFF)).toLong()
                b == 127 && extended.size >= 8 -> {
                    var v = 0L
                    for (i in 0 until 8) v = (v shl 8) or (extended[i].toInt() and 0xFF).toLong()
                    v
                }
                else -> -1
            }
        }
    }

    // ─── Inner HTTP ──────────────────────────────────────────────────────────

    object Http {
        fun parseStatus(head: String): Int? {
            val line = head.substringBefore("\r\n")
            val match = Regex("""^HTTP/1\.[01] (\d{3})""").find(line) ?: return null
            return match.groupValues[1].toIntOrNull()
        }
    }
}
