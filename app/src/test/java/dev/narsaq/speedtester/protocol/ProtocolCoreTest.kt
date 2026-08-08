package dev.narsaq.speedtester.protocol

import dev.narsaq.speedtester.model.ConfigType
import dev.narsaq.speedtester.model.ParsedConfig
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtocolCoreTest {

    // ─── Spec parsing ────────────────────────────────────────────────────────

    @Test
    fun `parses vless ws config into a probe spec`() {
        val raw = "vless://00112233-4455-6677-8899-aabbccddeeff@worker.example.com:443" +
            "?type=ws&security=tls&sni=worker.example.com&path=%2Fws&host=worker.example.com#label"
        val cfg = ParsedConfig(1, raw, ConfigType.VLESS, "worker.example.com", listOf(443), "worker.example.com", "/ws")

        val spec = ProtocolCore.parse(raw, cfg)

        assertNotNull(spec)
        spec?.let {
            assertEquals("00112233-4455-6677-8899-aabbccddeeff", it.credential)
            assertEquals("ws", it.network)
            assertEquals("tls", it.security)
            assertEquals("worker.example.com", it.sni)
            assertEquals("worker.example.com", it.wsHost)
            assertEquals("/ws", it.wsPath)
            assertTrue(it.supportsE2E)
        }
    }

    @Test
    fun `grpc transport is not e2e supported`() {
        val raw = "vless://uuid@worker.example.com:443?type=grpc&serviceName=x"
        val cfg = ParsedConfig(1, raw, ConfigType.VLESS, "worker.example.com", listOf(443), null, null)
        val spec = ProtocolCore.parse(raw, cfg)
        assertNotNull(spec)
        assertFalse(spec!!.supportsE2E)
    }

    @Test
    fun `vmess configs are not probed`() {
        val raw = "vmess://AQIDBAUGBwgJCgsMDQ4PEA=="
        val cfg = ParsedConfig(1, raw, ConfigType.VMESS, "1.2.3.4", listOf(443), null, null)
        assertNull(ProtocolCore.parse(raw, cfg))
    }

    @Test
    fun `flowed configs are not e2e supported`() {
        val raw = "vless://uuid@worker.example.com:443?type=tcp&security=reality&flow=xtls-rprx-vision"
        val cfg = ParsedConfig(1, raw, ConfigType.VLESS, "worker.example.com", listOf(443), null, null)
        val spec = ProtocolCore.parse(raw, cfg)
        assertNotNull(spec)
        assertFalse(spec!!.supportsE2E)
    }

    // ─── VLESS ───────────────────────────────────────────────────────────────

    @Test
    fun `uuid converts to 16 raw bytes`() {
        val bytes = ProtocolCore.Vless.uuidToBytes("00112233-4455-6677-8899-aabbccddeeff")
        val expected = byteArrayOf(
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88.toByte(), 0x99.toByte(), 0xAA.toByte(), 0xBB.toByte(),
            0xCC.toByte(), 0xDD.toByte(), 0xEE.toByte(), 0xFF.toByte()
        )
        assertArrayEquals(expected, bytes)
    }

    @Test
    fun `uuid with wrong length is rejected`() {
        assertNull(ProtocolCore.Vless.uuidToBytes("not-a-uuid"))
    }

    @Test
    fun `vless request header has exact bytes`() {
        val uuid = ByteArray(16) { it.toByte() }
        val addr = "example.com".toByteArray(Charsets.US_ASCII)
        val payload = "GET / HTTP/1.1\r\n\r\n".toByteArray(Charsets.US_ASCII)
        val req = ProtocolCore.Vless.requestHeader(
            uuid = uuid,
            port = 443,
            addressType = ProtocolCore.Vless.ATYP_DOMAIN,
            address = byteArrayOf(addr.size.toByte()) + addr,
            innerPayload = payload
        )

        assertEquals(0, req[0].toInt())                     // version
        assertArrayEquals(uuid, req.copyOfRange(1, 17))     // uuid
        assertEquals(0, req[17].toInt())                    // addons
        assertEquals(1, req[18].toInt())                    // command tcp
        assertEquals(0x01, req[19].toInt())                 // port hi
        assertEquals(0xBB.toByte(), req[20])                // port lo (443)
        assertEquals(2, req[21].toInt())                    // atyp domain
        assertEquals(addr.size, req[22].toInt())            // domain length
        assertArrayEquals(addr, req.copyOfRange(23, 23 + addr.size))
        assertArrayEquals(payload, req.copyOfRange(23 + addr.size, req.size))
    }

    @Test
    fun `vless success requires zero version and addons`() {
        assertTrue(ProtocolCore.Vless.isSuccess(byteArrayOf(0, 0)))
        assertFalse(ProtocolCore.Vless.isSuccess(byteArrayOf(0, 1)))
        assertFalse(ProtocolCore.Vless.isSuccess(byteArrayOf(0)))
    }

    // ─── Trojan ──────────────────────────────────────────────────────────────

    @Test
    fun `trojan request contains hex password and connect line`() {
        val req = String(
            ProtocolCore.Trojan.request("a1b2c3d4", "worker.example.com", 443),
            Charsets.US_ASCII
        )
        assertTrue(req.startsWith("a1b2c3d4\r\n"))
        assertTrue(req.contains("CONNECT worker.example.com:443 HTTP/1.1\r\n"))
        assertTrue(req.contains("Host: worker.example.com:443\r\n\r\n"))
    }

    @Test
    fun `trojan success requires 200 response`() {
        assertTrue(ProtocolCore.Trojan.isSuccess("HTTP/1.1 200 Connection Established\r\n\r\n"))
        assertFalse(ProtocolCore.Trojan.isSuccess("HTTP/1.1 404 Not Found\r\n\r\n"))
    }

    // ─── WebSocket ───────────────────────────────────────────────────────────

    @Test
    fun `ws handshake request has upgrade headers`() {
        val req = String(
            ProtocolCore.Ws.handshakeRequest("/ws", "worker.example.com", "dGhlIHNhbXBsZSBub25jZQ=="),
            Charsets.US_ASCII
        )
        assertTrue(req.startsWith("GET /ws HTTP/1.1\r\n"))
        assertTrue(req.contains("Host: worker.example.com\r\n"))
        assertTrue(req.contains("Upgrade: websocket\r\n"))
        assertTrue(req.contains("Connection: Upgrade\r\n"))
        assertTrue(req.contains("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"))
        assertTrue(req.contains("Sec-WebSocket-Version: 13\r\n"))
    }

    @Test
    fun `ws handshake path gets leading slash`() {
        val req = String(ProtocolCore.Ws.handshakeRequest("ws", "h", "k"), Charsets.US_ASCII)
        assertTrue(req.startsWith("GET /ws HTTP/1.1"))
    }

    @Test
    fun `ws upgrade detection`() {
        assertTrue(ProtocolCore.Ws.isUpgraded("HTTP/1.1 101 Switching Protocols\r\n\r\n"))
        assertFalse(ProtocolCore.Ws.isUpgraded("HTTP/1.1 200 OK\r\n\r\n"))
    }

    @Test
    fun `ws client frame round trips with masking`() {
        val payload = "hello vless over ws".toByteArray(Charsets.UTF_8)
        val mask = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        val frame = ProtocolCore.Ws.encodeClientFrame(payload, mask)

        assertEquals(0x82.toByte(), frame[0])                       // FIN + binary
        assertEquals((0x80 or payload.size).toByte(), frame[1])     // masked + len
        assertArrayEquals(mask, frame.copyOfRange(2, 6))

        val decoded = ByteArray(payload.size)
        for (i in payload.indices) {
            decoded[i] = (frame[6 + i].toInt() xor mask[i % 4].toInt()).toByte()
        }
        assertArrayEquals(payload, decoded)
    }

    @Test
    fun `ws extended 16-bit length uses decode helper`() {
        val payload = ByteArray(200)
        val frame = ProtocolCore.Ws.encodeClientFrame(payload, byteArrayOf(0, 0, 0, 0))
        // header: b0 + b1(0x80|126) + 2 length bytes + 4 mask
        assertEquals(126, frame[1].toInt() and 0x7F)
        val len = ProtocolCore.Ws.decodeFrameLength(
            frame[1].toInt(),
            byteArrayOf(frame[2], frame[3])
        )
        assertEquals(200L, len)
    }

    @Test
    fun `ws 64-bit length decodes correctly`() {
        val ext = byteArrayOf(0, 0, 0, 0, 0, 1, 0, 0) // 65536
        assertEquals(65536L, ProtocolCore.Ws.decodeFrameLength(0xFF, ext))
    }

    // ─── Inner HTTP ──────────────────────────────────────────────────────────

    @Test
    fun `http status parses from response head`() {
        assertEquals(200, ProtocolCore.Http.parseStatus("HTTP/1.1 200 OK\r\nServer: x"))
        assertEquals(404, ProtocolCore.Http.parseStatus("HTTP/1.1 404 Not Found\r\n"))
        assertNull(ProtocolCore.Http.parseStatus("garbage"))
    }
}
