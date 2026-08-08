package dev.narsaq.speedtester.protocol

import android.os.SystemClock
import android.util.Base64
import dev.narsaq.speedtester.model.ConfigType
import dev.narsaq.speedtester.model.ParsedConfig
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.SecureRandom
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import kotlinx.coroutines.CancellationException

data class ProtocolResult(
    val verified: Boolean,
    val ok: Boolean,
    val ttfbMs: Long? = null,
    val throughputMbps: Float? = null,
    val innerStatus: Int? = null
)

/**
 * End-to-end validator: connects to a candidate endpoint and actually speaks
 * the config's protocol (VLESS or Trojan, over TCP or WebSocket, with or
 * without TLS), then tunnels a small HTTP download through the connection to
 * measure TTFB and throughput. This proves the endpoint really carries the
 * config's traffic, not just that its TCP/TLS port is open.
 */
class EndpointValidator {

    companion object {
        const val E2E_DOWNLOAD_BYTES = 64 * 1024
        const val MAX_READ_BYTES = E2E_DOWNLOAD_BYTES * 3
        private const val MAX_FRAME = 8 * 1024 * 1024
    }

    private val random = SecureRandom()

    fun probe(
        cfg: ParsedConfig,
        raw: String,
        ip: String,
        port: Int,
        timeoutMs: Int
    ): ProtocolResult {
        val spec = ProtocolCore.parse(raw, cfg)
            ?: return ProtocolResult(verified = false, ok = true)
        if (!spec.supportsE2E) return ProtocolResult(verified = false, ok = true)
        return try {
            probeSpec(spec, ip, port, timeoutMs)
        } catch (e: CancellationException) {
            throw e
        } catch (e: SocketTimeoutException) {
            // The handshake timed out — inconclusive, not a definitive
            // protocol rejection (a slow-but-valid endpoint must not be
            // excluded just because it answered late).
            ProtocolResult(verified = false, ok = true)
        } catch (e: Exception) {
            // The endpoint did not complete the protocol exchange.
            ProtocolResult(verified = true, ok = false)
        }
    }

    private fun probeSpec(
        spec: ProtocolCore.ProtocolSpec,
        ip: String,
        port: Int,
        timeoutMs: Int
    ): ProtocolResult {
        var rawSocket: Socket? = null
        var sslSocket: SSLSocket? = null

        return try {
            val dialTimeout = minOf(timeoutMs, 3000)
            rawSocket = Socket()
            rawSocket.connect(InetSocketAddress(ip, port), dialTimeout)
            rawSocket.soTimeout = timeoutMs

            val isTls = spec.security == "tls" || spec.security == "reality"
            if (isTls) {
                val sni = spec.sni ?: spec.targetHost
                val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
                sslSocket = factory.createSocket(rawSocket, sni, port, true) as SSLSocket
                sslSocket.soTimeout = timeoutMs
                sslSocket.startHandshake()
            }
            val socket: Socket = sslSocket ?: rawSocket
            val input = socket.getInputStream()
            val output = socket.getOutputStream()
            val ws = spec.network == "ws"

            // 1. WebSocket upgrade when the transport is ws.
            if (ws) {
                val key = randomKey()
                val host = spec.wsHost ?: spec.sni ?: spec.targetHost
                output.write(ProtocolCore.Ws.handshakeRequest(spec.wsPath, host, key))
                output.flush()
                val upgradeHead = readUntilHeader(input)
                if (upgradeHead == null || !ProtocolCore.Ws.isUpgraded(upgradeHead)) {
                    return ProtocolResult(verified = true, ok = false)
                }
            }

            // 2. Protocol handshake. VLESS carries the inner request in the
            //    same write; Trojan must first establish CONNECT and only then
            //    tunnel the inner request.
            val inner = buildInnerRequest(spec.targetHost)
            val reader = TunnelReader(input, ws)
            val start = SystemClock.elapsedRealtime()

            val handshakePayload = when (spec.type) {
                ConfigType.VLESS -> {
                    val uuid = ProtocolCore.Vless.uuidToBytes(spec.credential)
                        ?: return ProtocolResult(verified = true, ok = false)
                    val (atyp, addr) = targetAddress(spec.targetHost)
                    ProtocolCore.Vless.requestHeader(uuid, 443, atyp, addr, inner)
                }

                ConfigType.TROJAN -> ProtocolCore.Trojan.request(
                    spec.credential,
                    spec.targetHost,
                    443
                )

                else -> return ProtocolResult(verified = false, ok = true)
            }
            writePayload(output, ws, handshakePayload)

            val ttfbMs: Long
            val firstChunk: ByteArray
            when (spec.type) {
                ConfigType.VLESS -> {
                    firstChunk = reader.readUpTo(4096)
                        ?: return ProtocolResult(verified = true, ok = false)
                    ttfbMs = SystemClock.elapsedRealtime() - start
                    if (!ProtocolCore.Vless.isSuccess(firstChunk)) {
                        return ProtocolResult(verified = true, ok = false)
                    }
                }

                ConfigType.TROJAN -> {
                    val connectHead = reader.readUntilHeader()
                        ?: return ProtocolResult(verified = true, ok = false)
                    if (!ProtocolCore.Trojan.isSuccess(connectHead)) {
                        return ProtocolResult(verified = true, ok = false)
                    }
                    // Tunnel is up — send the inner HTTP request and time it.
                    val t2 = SystemClock.elapsedRealtime()
                    writePayload(output, ws, inner)
                    firstChunk = reader.readUpTo(4096)
                        ?: return ProtocolResult(verified = true, ok = true, ttfbMs = SystemClock.elapsedRealtime() - t2)
                    ttfbMs = SystemClock.elapsedRealtime() - t2
                    if (firstChunk.isEmpty()) {
                        // The CONNECT succeeded but no inner response arrived —
                        // the tunnel still works, just no download score.
                        return ProtocolResult(verified = true, ok = true, ttfbMs = ttfbMs)
                    }
                }

                else -> return ProtocolResult(verified = false, ok = true)
            }

            // 3. Inner HTTP status + short download score through the tunnel.
            val head = String(firstChunk, Charsets.ISO_8859_1)
            val headerEnd = head.indexOf("\r\n\r\n")
            // VLESS servers prepend a 2-byte response header (version +
            // addons length) before the inner HTTP response — strip it so
            // the status line actually parses.
            val status = ProtocolCore.Http.parseStatus(
                if (spec.type == ConfigType.VLESS && firstChunk.size >= 2 &&
                    firstChunk[0] == 0.toByte() && firstChunk[1] == 0.toByte()
                ) {
                    String(firstChunk, 2, firstChunk.size - 2, Charsets.ISO_8859_1)
                } else {
                    head
                }
            )
            var total = if (headerEnd >= 0) firstChunk.size - (headerEnd + 4) else firstChunk.size
            val bodyStart = SystemClock.elapsedRealtime()
            val buf = ByteArray(8192)
            try {
                while (total < E2E_DOWNLOAD_BYTES && total < MAX_READ_BYTES) {
                    val n = reader.read(buf, 0, minOf(buf.size, MAX_READ_BYTES - total))
                    if (n < 0) break
                    total += n
                }
            } catch (e: SocketTimeoutException) {
                // Partial body is fine — the tunnel already validated.
            }
            val bodyElapsedMs = SystemClock.elapsedRealtime() - bodyStart
            val mbps = if (total > 4096 && bodyElapsedMs > 0) {
                ((total * 8.0 / 1_000_000) / (bodyElapsedMs / 1000.0)).toFloat()
            } else {
                null
            }

            ProtocolResult(
                verified = true,
                ok = true,
                ttfbMs = ttfbMs,
                throughputMbps = mbps,
                innerStatus = status
            )
        } finally {
            try { sslSocket?.close() } catch (_: Exception) {}
            try { rawSocket?.close() } catch (_: Exception) {}
        }
    }

    private fun writePayload(output: java.io.OutputStream, ws: Boolean, payload: ByteArray) {
        if (ws) {
            output.write(ProtocolCore.Ws.encodeClientFrame(payload, randomMask()))
        } else {
            output.write(payload)
        }
        output.flush()
    }

    private fun buildInnerRequest(targetHost: String): ByteArray {
        return ("GET /__down?bytes=$E2E_DOWNLOAD_BYTES HTTP/1.1\r\n" +
            "Host: $targetHost\r\n" +
            "User-Agent: Narsaq/1.0\r\n" +
            "Accept: */*\r\n" +
            "Connection: close\r\n\r\n").toByteArray(Charsets.US_ASCII)
    }

    /** VLESS address type + address bytes for the inner target. */
    private fun targetAddress(host: String): Pair<Byte, ByteArray> {
        val octets = host.split(".")
        if (octets.size == 4 && octets.all {
                it.isNotEmpty() && it.length <= 3 && it.all(Char::isDigit) && it.toInt() in 0..255
            }
        ) {
            return ProtocolCore.Vless.ATYP_IPV4 to ByteArray(4) { octets[it].toInt().toByte() }
        }
        if (host.contains(':')) {
            try {
                val addr = java.net.InetAddress.getByName(host).address
                if (addr.size == 16) return ProtocolCore.Vless.ATYP_IPV6 to addr
            } catch (_: Exception) {
            }
        }
        val bytes = host.toByteArray(Charsets.US_ASCII)
        val len = minOf(bytes.size, 255)
        return ProtocolCore.Vless.ATYP_DOMAIN to (byteArrayOf(len.toByte()) + bytes.copyOf(len))
    }

    private fun randomKey(): String {
        val raw = ByteArray(16)
        random.nextBytes(raw)
        return Base64.encodeToString(raw, Base64.NO_WRAP or Base64.NO_PADDING)
    }

    private fun randomMask(): ByteArray {
        val mask = ByteArray(4)
        random.nextBytes(mask)
        return mask
    }

    private fun readUntilHeader(input: InputStream, max: Int = 4096): String? {
        val buffer = ByteArray(512)
        val sb = StringBuilder()
        while (sb.length < max) {
            val n = input.read(buffer)
            if (n < 0) break
            sb.append(String(buffer, 0, n, Charsets.ISO_8859_1))
            if (sb.contains("\r\n\r\n")) break
        }
        return if (sb.isEmpty()) null else sb.toString()
    }

    /**
     * Stream reader that transparently unwraps WebSocket frames (or passes the
     * raw TCP stream through when the transport is plain).
     */
    private class TunnelReader(private val input: InputStream, private val ws: Boolean) {

        private var buffered = ByteArray(0)
        private var pos = 0

        fun read(buf: ByteArray, off: Int, len: Int): Int {
            if (!ws) return input.read(buf, off, len)
            while (true) {
                if (pos < buffered.size) {
                    val n = minOf(len, buffered.size - pos)
                    System.arraycopy(buffered, pos, buf, off, n)
                    pos += n
                    return n
                }
                buffered = readNextPayload() ?: return -1
                pos = 0
                if (buffered.isEmpty()) continue
            }
        }

        fun readUpTo(maxBytes: Int): ByteArray? {
            val out = ByteArrayOutputStream()
            val buf = ByteArray(4096)
            while (out.size() < maxBytes) {
                val n = read(buf, 0, minOf(buf.size, maxBytes - out.size()))
                if (n < 0) break
                out.write(buf, 0, n)
            }
            return out.toByteArray()
        }

        /** Reads until `\r\n\r\n` through the tunnel (e.g. the Trojan CONNECT response). */
        fun readUntilHeader(max: Int = 4096): String? {
            val sb = StringBuilder()
            val buf = ByteArray(512)
            while (sb.length < max) {
                val n = read(buf, 0, minOf(buf.size, max - sb.length))
                if (n < 0) break
                sb.append(String(buf, 0, n, Charsets.ISO_8859_1))
                if (sb.contains("\r\n\r\n")) break
            }
            return if (sb.isEmpty()) null else sb.toString()
        }

        private fun readNextPayload(): ByteArray? {
            while (true) {
                val b0 = input.read()
                if (b0 < 0) return null
                val opcode = b0 and 0x0F
                if (opcode == ProtocolCore.Ws.OP_CLOSE) return null

                val b1 = input.read()
                if (b1 < 0) return null
                val masked = (b1 and 0x80) != 0
                val len = when (b1 and 0x7F) {
                    126 -> {
                        val ext = ByteArray(2)
                        if (!readFully(ext)) return null
                        ProtocolCore.Ws.decodeFrameLength(b1, ext)
                    }

                    127 -> {
                        val ext = ByteArray(8)
                        if (!readFully(ext)) return null
                        ProtocolCore.Ws.decodeFrameLength(b1, ext)
                    }

                    else -> ProtocolCore.Ws.decodeFrameLength(b1, ByteArray(0))
                }
                if (len < 0 || len > MAX_FRAME) return null

                val mask = if (masked) {
                    val m = ByteArray(4)
                    if (!readFully(m)) return null
                    m
                } else {
                    null
                }
                val payload = ByteArray(len.toInt())
                if (!readFully(payload)) return null
                if (mask != null) {
                    for (i in payload.indices) {
                        payload[i] = (payload[i].toInt() xor mask[i % 4].toInt()).toByte()
                    }
                }
                if (opcode == ProtocolCore.Ws.OP_PING || opcode == ProtocolCore.Ws.OP_PONG) {
                    continue
                }
                return payload
            }
        }

        private fun readFully(buf: ByteArray): Boolean {
            var off = 0
            while (off < buf.size) {
                val n = input.read(buf, off, buf.size - off)
                if (n < 0) return false
                off += n
            }
            return true
        }
    }
}
