package dev.narsaq.speedtester.protocol

import dev.narsaq.speedtester.model.ConfigType
import dev.narsaq.speedtester.model.ParsedConfig
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowSystemClock
import java.io.DataInputStream
import java.io.OutputStream
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.time.Duration
import java.util.Base64

/**
 * End-to-end tests for [EndpointValidator]: a real server socket on localhost
 * speaks the actual wire protocol (VLESS header, Trojan CONNECT, WebSocket
 * upgrade + masking) and the validator must complete the exchange and report
 * TTFB + throughput — not just a TCP/TLS reachability ping.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class EndpointValidatorTest {

    private val validator = EndpointValidator()
    private val servers = ArrayList<ServerSocket>()

    @Before
    fun setUp() {
        servers.clear()
    }

    @After
    fun tearDown() {
        servers.forEach { runCatching { it.close() } }
    }

    // ─── Fixtures ───────────────────────────────────────────────────────────

    private val UUID = "00112233-4455-6677-8899-aabbccddeeff"

    private fun vlessTcpConfig(): ParsedConfig = ParsedConfig(
        id = 1,
        raw = "vless://$UUID@example.com:443?type=tcp#test",
        type = ConfigType.VLESS,
        host = "example.com",
        ports = listOf(443),
        sni = null,
        path = null
    )

    private fun vlessWsConfig(): ParsedConfig = ParsedConfig(
        id = 2,
        raw = "vless://$UUID@example.com:443?type=ws&path=%2Fws#test",
        type = ConfigType.VLESS,
        host = "example.com",
        ports = listOf(443),
        sni = null,
        path = "/ws"
    )

    private fun trojanConfig(): ParsedConfig = ParsedConfig(
        id = 3,
        raw = "trojan://my-password@example.com:443#test",
        type = ConfigType.TROJAN,
        host = "example.com",
        ports = listOf(443),
        sni = null,
        path = null
    )

    private val E2E_BODY_BYTES = EndpointValidator.E2E_DOWNLOAD_BYTES

    /** Starts a one-shot fake server on localhost and returns its port. */
    private fun fakeServer(handler: (Socket) -> Unit): Int {
        val server = ServerSocket(0)
        servers += server
        Thread {
            try {
                val sock = server.accept()
                sock.soTimeout = 8000
                handler(sock)
                sock.close()
            } catch (_: Exception) {
            }
        }.apply { isDaemon = true }.start()
        return server.localPort
    }

    private fun http200Head(): ByteArray {
        return ("HTTP/1.1 200 OK\r\n" +
            "Content-Length: $E2E_BODY_BYTES\r\n" +
            "Connection: close\r\n" +
            "\r\n").toByteArray(Charsets.ISO_8859_1)
    }

    /** Body bytes for the download. */
    private fun http200BodyBytes(): ByteArray =
        ByteArray(E2E_BODY_BYTES) { 'A'.code.toByte() }

    /**
     * Streams the body in chunks with small pauses. The pause keeps the
     * download window open long enough for the shadow clock to advance,
     * so the probe observes a non-zero elapsed time (throughput).
     */
    private fun writeBodyChunked(out: OutputStream) {
        val chunk = ByteArray(8 * 1024) { 'A'.code.toByte() }
        var sent = 0
        while (sent < E2E_BODY_BYTES) {
            val n = minOf(chunk.size, E2E_BODY_BYTES - sent)
            out.write(chunk, 0, n)
            out.flush()
            sent += n
            Thread.sleep(15)
        }
    }

    /**
     * Robolectric freezes SystemClock.elapsedRealtime() unless advanced
     * explicitly. The probe measures throughput between two clock reads, so
     * advance the shadow clock on a background thread while the download is
     * in flight (the fake server pauses between head and body to open that
     * window).
     */
    private fun advanceClockWhileDownloading() {
        Thread {
            try {
                Thread.sleep(80)
                ShadowSystemClock.advanceBy(Duration.ofMillis(400))
            } catch (_: InterruptedException) {
            }
        }.apply { isDaemon = true }.start()
    }

    /** Reads the VLESS request header (version..address) off the wire. */
    private fun readVlessHeader(input: DataInputStream) {
        assertEquals(0, input.read())               // version
        input.readFully(ByteArray(16))              // uuid
        assertEquals(0, input.read())               // addons length
        assertEquals(1, input.read())               // command: tcp
        input.readFully(ByteArray(2))               // port BE
        val atyp = input.read()
        when (atyp) {
            1 -> input.readFully(ByteArray(4))
            2 -> input.readFully(ByteArray(input.read()))
            3 -> input.readFully(ByteArray(16))
            else -> throw IllegalStateException("unexpected atyp=$atyp")
        }
    }

    /** Consumes the inner HTTP GET request (up to the blank line). */
    private fun consumeInnerRequest(input: DataInputStream) {
        val buf = ByteArray(512)
        val sb = StringBuilder()
        while (!sb.contains("\r\n\r\n")) {
            val n = input.read(buf)
            if (n < 0) break
            sb.append(String(buf, 0, n, Charsets.ISO_8859_1))
        }
    }

    // ─── VLESS over plain TCP ───────────────────────────────────────────────

    @Test
    fun `vless tcp probe completes full exchange with ttfb and throughput`() {
        val port = fakeServer { sock ->
            val input = DataInputStream(sock.getInputStream())
            readVlessHeader(input)
            consumeInnerRequest(input)
            val out = sock.getOutputStream()
            out.write(byteArrayOf(0, 0)) // VLESS response header
            out.write(http200Head())
            out.flush()
            writeBodyChunked(out)
        }
        advanceClockWhileDownloading()

        val result = validator.probe(vlessTcpConfig(), vlessTcpConfig().raw, "127.0.0.1", port, 5000)

        assertTrue("endpoint must verify", result.verified)
        assertTrue("protocol must succeed", result.ok)
        assertNotNull("ttfb must be measured", result.ttfbMs)
        assertNotNull("throughput must be measured", result.throughputMbps)
        assertEquals(200, result.innerStatus)
    }

    @Test
    fun `vless tcp probe fails when server sends garbage`() {
        val port = fakeServer { sock ->
            val input = DataInputStream(sock.getInputStream())
            readVlessHeader(input)
            consumeInnerRequest(input)
            // Wrong response header: nonzero version is a protocol error.
            sock.getOutputStream().write(byteArrayOf(9, 9, 1, 2, 3))
            sock.getOutputStream().flush()
        }

        val result = validator.probe(vlessTcpConfig(), vlessTcpConfig().raw, "127.0.0.1", port, 5000)

        assertTrue(result.verified)
        assertFalse("garbage response must fail", result.ok)
    }

    @Test
    fun `vless tcp probe fails when server closes without responding`() {
        val port = fakeServer { sock ->
            DataInputStream(sock.getInputStream()).readFully(ByteArray(2))
            // close without any response
        }

        val result = validator.probe(vlessTcpConfig(), vlessTcpConfig().raw, "127.0.0.1", port, 5000)

        assertTrue(result.verified)
        assertFalse("closed connection must fail", result.ok)
    }

    @Test
    fun `vless tcp probe reports inconclusive on timeout`() {
        val port = fakeServer { sock ->
            // Accept but never respond — the probe must time out.
            Thread.sleep(5000)
        }

        val result = validator.probe(vlessTcpConfig(), vlessTcpConfig().raw, "127.0.0.1", port, 700)

        assertFalse("timeout is not a definitive rejection", result.verified)
        assertTrue("timeout must not mark endpoint failed", result.ok)
    }

    // ─── Trojan over plain TCP ──────────────────────────────────────────────

    @Test
    fun `trojan probe completes CONNECT and inner download`() {
        val port = fakeServer { sock ->
            val input = DataInputStream(sock.getInputStream())
            // Trojan request: password line + CONNECT header + blank line.
            val sb = StringBuilder()
            val buf = ByteArray(512)
            while (!sb.contains("\r\n\r\n")) {
                val n = input.read(buf)
                if (n < 0) break
                sb.append(String(buf, 0, n, Charsets.ISO_8859_1))
            }
            assertTrue(sb.startsWith("my-password\r\n"))
            assertTrue(sb.contains("CONNECT example.com:443 HTTP/1.1"))

            val out = sock.getOutputStream()
            out.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(Charsets.ISO_8859_1))
            out.flush()

            consumeInnerRequest(input)
            out.write(http200Head())
            out.flush()
            writeBodyChunked(out)
        }
        advanceClockWhileDownloading()

        val result = validator.probe(trojanConfig(), trojanConfig().raw, "127.0.0.1", port, 5000)

        assertTrue("trojan endpoint must verify", result.verified)
        assertTrue("trojan protocol must succeed", result.ok)
        assertNotNull(result.ttfbMs)
        assertNotNull(result.throughputMbps)
        assertEquals(200, result.innerStatus)
    }

    @Test
    fun `trojan probe fails when CONNECT is rejected`() {
        val port = fakeServer { sock ->
            val input = DataInputStream(sock.getInputStream())
            val buf = ByteArray(512)
            val sb = StringBuilder()
            while (!sb.contains("\r\n\r\n")) {
                val n = input.read(buf)
                if (n < 0) break
                sb.append(String(buf, 0, n, Charsets.ISO_8859_1))
            }
            sock.getOutputStream().write(
                "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.ISO_8859_1)
            )
            sock.getOutputStream().flush()
        }

        val result = validator.probe(trojanConfig(), trojanConfig().raw, "127.0.0.1", port, 5000)

        assertTrue(result.verified)
        assertFalse("rejected CONNECT must fail", result.ok)
    }

    // ─── VLESS over WebSocket ───────────────────────────────────────────────

    private fun wsHandshakeResponse(input: DataInputStream, out: OutputStream) {
        val sb = StringBuilder()
        val buf = ByteArray(512)
        var key = ""
        while (!sb.contains("\r\n\r\n")) {
            val n = input.read(buf)
            if (n < 0) break
            sb.append(String(buf, 0, n, Charsets.ISO_8859_1))
        }
        for (line in sb.lines()) {
            if (line.startsWith("Sec-WebSocket-Key:", true)) {
                key = line.substringAfter(':').trim()
            }
        }
        val accept = Base64.getEncoder().encodeToString(
            MessageDigest.getInstance("SHA-1").digest(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").toByteArray(Charsets.US_ASCII)
            )
        )
        out.write(
            ("HTTP/1.1 101 Switching Protocols\r\n" +
                "Upgrade: websocket\r\n" +
                "Connection: Upgrade\r\n" +
                "Sec-WebSocket-Accept: $accept\r\n\r\n").toByteArray(Charsets.ISO_8859_1)
        )
        out.flush()
    }

    /** Reads one client frame (must be masked) and returns the unmasked payload. */
    private fun readClientFrame(input: DataInputStream): ByteArray {
        val b0 = input.read()
        val b1 = input.read()
        val len = when (b1 and 0x7F) {
            126 -> {
                val ext = ByteArray(2)
                input.readFully(ext)
                ((ext[0].toInt() and 0xFF) shl 8) or (ext[1].toInt() and 0xFF)
            }
            127 -> {
                val ext = ByteArray(8)
                input.readFully(ext)
                var v = 0L
                for (i in 0 until 8) v = (v shl 8) or (ext[i].toInt() and 0xFF).toLong()
                v.toInt()
            }
            else -> b1 and 0x7F
        }
        val mask = ByteArray(4)
        input.readFully(mask)
        val payload = ByteArray(len)
        input.readFully(payload)
        for (i in payload.indices) {
            payload[i] = (payload[i].toInt() xor mask[i % 4].toInt()).toByte()
        }
        return payload
    }

    /** Writes one unmasked server binary frame (FIN + opcode 2). */
    private fun writeServerFrame(out: OutputStream, payload: ByteArray) {
        out.write(0x82)
        when {
            payload.size < 126 -> out.write(payload.size)
            payload.size < 65536 -> {
                out.write(126)
                out.write((payload.size ushr 8) and 0xFF)
                out.write(payload.size and 0xFF)
            }
            else -> {
                out.write(127)
                var v = payload.size.toLong()
                for (shift in 56 downTo 0 step 8) {
                    out.write(((v ushr shift) and 0xFF).toInt())
                }
            }
        }
        out.write(payload)
        out.flush()
    }

    @Test
    fun `vless ws probe completes upgrade and tunneled download`() {
        val port = fakeServer { sock ->
            val input = DataInputStream(sock.getInputStream())
            val out = sock.getOutputStream()
            wsHandshakeResponse(input, out)

            // Client sends the VLESS header + inner request inside a masked frame.
            val frame = readClientFrame(input)
            // VLESS header layout: version(1) uuid(16) addons(1) cmd(1)
            // port(2) atyp(1) then the target address.
            assertEquals(0, frame[0].toInt())                 // version
            assertEquals(1, frame[18].toInt())                // command: tcp
            assertEquals(2, frame[21].toInt())                // atyp: domain
            val addrLen = frame[22].toInt()
            val addr = String(frame, 23, addrLen, Charsets.US_ASCII)
            assertEquals("example.com", addr)
            // Payload after the address: inner HTTP GET.
            val innerOffset = 23 + addrLen
            val inner = String(frame, innerOffset, frame.size - innerOffset, Charsets.ISO_8859_1)
            assertTrue(inner.startsWith("GET /__down"))

            // Server replies: VLESS response header + HTTP head in one frame,
            // then the body in follow-up (unmasked) frames.
            writeServerFrame(out, byteArrayOf(0, 0) + http200Head())
            // Body: several frames so the download window stays open.
            val chunk = ByteArray(8 * 1024) { 'A'.code.toByte() }
            var sent = 0
            while (sent < E2E_BODY_BYTES) {
                val n = minOf(chunk.size, E2E_BODY_BYTES - sent)
                writeServerFrame(out, chunk.copyOf(n))
                sent += n
                Thread.sleep(15)
            }
        }
        advanceClockWhileDownloading()

        val result = validator.probe(vlessWsConfig(), vlessWsConfig().raw, "127.0.0.1", port, 5000)

        assertTrue("ws endpoint must verify", result.verified)
        assertTrue("ws protocol must succeed", result.ok)
        assertNotNull(result.ttfbMs)
        assertNotNull(result.throughputMbps)
        assertEquals(200, result.innerStatus)
    }

    @Test
    fun `ws upgrade rejection fails the probe`() {
        val port = fakeServer { sock ->
            val input = DataInputStream(sock.getInputStream())
            val buf = ByteArray(512)
            val sb = StringBuilder()
            while (!sb.contains("\r\n\r\n")) {
                val n = input.read(buf)
                if (n < 0) break
                sb.append(String(buf, 0, n, Charsets.ISO_8859_1))
            }
            sock.getOutputStream().write("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.ISO_8859_1))
            sock.getOutputStream().flush()
        }

        val result = validator.probe(vlessWsConfig(), vlessWsConfig().raw, "127.0.0.1", port, 5000)

        assertTrue(result.verified)
        assertFalse("failed upgrade must fail", result.ok)
    }
}
