package dev.narsaq.speedtester.scan

import java.math.BigInteger

object CloudflareRanges {

    val IPV4_CIDRS = listOf(
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "108.162.192.0/18",
        "131.0.72.0/22",
        "141.101.64.0/18",
        "162.158.0.0/15",
        "172.64.0.0/13",
        "173.245.48.0/20",
        "188.114.96.0/20",
        "190.93.240.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17"
    )

    // Cloudflare's published IPv6 ranges (https://www.cloudflare.com/ips-v6/)
    val IPV6_CIDRS = listOf(
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32"
    )

    data class CidrBlock(
        val base: Long,
        val size: Long
    )

    private data class V6Block(
        val network: ByteArray,
        val prefix: Int,
        val size: BigInteger
    )

    // ─── IPv4 helpers ────────────────────────────────────────────────────────

    private fun parseCidr(cidr: String): CidrBlock {
        val parts = cidr.split("/")
        val ip = parts[0]
        val prefix = parts[1].toInt()
        val octets = ip.split(".")
        val ipLong = (octets[0].toLong() shl 24) or
            (octets[1].toLong() shl 16) or
            (octets[2].toLong() shl 8) or
            octets[3].toLong()
        val size = 1L shl (32 - prefix)
        return CidrBlock(ipLong, size)
    }

    private fun longToIp(ip: Long): String {
        return "${(ip shr 24) and 0xFF}.${(ip shr 16) and 0xFF}.${(ip shr 8) and 0xFF}.${ip and 0xFF}"
    }

    private fun ipToLong(ip: String): Long? {
        val octets = ip.split(".")
        if (octets.size != 4) return null
        val values = octets.map { it.toLongOrNull() ?: return null }
        if (values.any { it !in 0..255 }) return null
        return (values[0] shl 24) or (values[1] shl 16) or
            (values[2] shl 8) or values[3]
    }

    fun neighborsOf(ip: String, count: Int): List<String> {
        if (count <= 0) return emptyList()
        val value = ipToLong(ip) ?: return emptyList()
        val block = IPV4_CIDRS.map { parseCidr(it) }
            .firstOrNull { value >= it.base && value < it.base + it.size }
            ?: return emptyList()
        val firstUsable = block.base + 1
        val lastUsable = block.base + block.size - 2
        val neighbors = LinkedHashSet<Long>(count)
        var distance = 1L
        while (neighbors.size < count &&
            (value - distance >= firstUsable || value + distance <= lastUsable)
        ) {
            if (value + distance <= lastUsable) neighbors.add(value + distance)
            if (neighbors.size < count && value - distance >= firstUsable) {
                neighbors.add(value - distance)
            }
            distance++
        }
        return neighbors.map { longToIp(it) }
    }

    fun neighborsOf(seeds: List<String>, count: Int): List<String> {
        if (seeds.isEmpty() || count <= 0) return emptyList()
        val seen = LinkedHashSet<String>(count)
        val candidates = seeds.distinct().map { neighborsOf(it, count) }
        for (index in 0 until count) {
            for (neighbors in candidates) {
                neighbors.getOrNull(index)?.let { seen.add(it) }
                if (seen.size == count) break
            }
            if (seen.size == count) break
        }
        return seen.toList()
    }

    fun generateRandomIps(count: Int): List<String> {
        val blocks = IPV4_CIDRS.map { parseCidr(it) }
        val totalSize = blocks.sumOf { it.size }
        val seen = LinkedHashSet<Long>(count * 2)
        val random = java.util.Random()
        val maxAttempts = count * 8

        var attempts = 0
        while (seen.size < count && attempts < maxAttempts) {
            attempts++
            var r = (random.nextDouble() * totalSize).toLong()
            var selectedBlock: CidrBlock? = null
            for (block in blocks) {
                if (r < block.size) {
                    selectedBlock = block
                    break
                }
                r -= block.size
            }
            if (selectedBlock == null) continue

            val offset = (random.nextDouble() * (selectedBlock.size - 2)).toLong() + 1
            val ip = selectedBlock.base + offset
            seen.add(ip)
        }

        return seen.map { longToIp(it) }
    }

    // ─── IPv6 generation ─────────────────────────────────────────────────────

    /**
     * Generates [count] random IPv6 addresses inside Cloudflare's published
     * IPv6 ranges, using size-weighted sampling (larger ranges picked more
     * often), mirroring SenPaiScanner's MahsaNG-style sampling.
     */
    fun generateRandomIpsV6(count: Int): List<String> {
        if (count <= 0) return emptyList()
        val blocks = IPV6_CIDRS.mapNotNull { parseCidrV6(it) }
        if (blocks.isEmpty()) return emptyList()
        val totalSize = blocks.sumOf { it.size }
        val seen = LinkedHashSet<String>(count * 2)
        val random = java.util.Random()
        val maxAttempts = count * 8

        var attempts = 0
        while (seen.size < count && attempts < maxAttempts) {
            attempts++
            var r = random.nextDouble() * totalSize.toDouble()
            var selectedBlock: V6Block? = null
            for (block in blocks) {
                if (r < block.size.toDouble()) {
                    selectedBlock = block
                    break
                }
                r -= block.size.toDouble()
            }
            if (selectedBlock == null) continue
            seen.add(formatIpv6(randomV6In(selectedBlock, random)))
        }

        return seen.toList()
    }

    // ─── Custom CIDR / IP list support ───────────────────────────────────────

    /**
     * Generates up to [count] unique random addresses from user-provided
     * ranges: plain IPs, IPv4/IPv6 CIDRs, `ip:port` lines and `[v6]:port`
     * lines (one per line). Every listed range is represented.
     */
    fun generateFromCustomRanges(text: String, count: Int): List<String> {
        if (count <= 0) return emptyList()
        val v4Blocks = ArrayList<CidrBlock>()
        val v6Blocks = ArrayList<V6Block>()
        val directIps = LinkedHashSet<String>()
        val random = java.util.Random()

        for (rawLine in text.lineSequence()) {
            val line = rawLine.substringBefore('#').trim()
            if (line.isBlank()) continue
            val token = line.split(Regex("""\s+""")).firstOrNull()?.trim().orEmpty()
            if (token.isBlank()) continue

            when {
                // [v6] or [v6]:port
                token.startsWith("[") -> {
                    val close = token.indexOf(']')
                    if (close < 0) continue
                    val addr = token.substring(1, close).trim()
                    if (isIpv6(addr)) directIps.add(addr)
                }

                // CIDR: v4 or v6
                token.contains("/") -> {
                    val parts = token.split("/")
                    if (parts.size != 2) continue
                    val prefix = parts[1].trim().toIntOrNull() ?: continue
                    val addrPart = parts[0].trim()
                    if (addrPart.contains(':')) {
                        if (prefix in 0..128) {
                            parseIpv6Bytes(addrPart)?.let {
                                v6Blocks += V6Block(
                                    it,
                                    prefix,
                                    BigInteger.ONE.shiftLeft(128 - prefix)
                                )
                            }
                        }
                    } else {
                        if (prefix in 0..32) {
                            ipToLong(addrPart)?.let { base ->
                                val masked = base and (-1L shl (32 - prefix))
                                v4Blocks += CidrBlock(masked, 1L shl (32 - prefix))
                            }
                        }
                    }
                }

                // v4 possibly with a port: 1.2.3.4 or 1.2.3.4:443
                token.count { it == ':' } == 1 -> {
                    val right = token.substringAfter(':')
                    val ip = if (right.isNotEmpty() && right.all { it.isDigit() }) {
                        token.substringBefore(':')
                    } else {
                        token
                    }
                    ipToLong(ip)?.let { v4Blocks += CidrBlock(it, 1) }
                }

                else -> {
                    if (token.contains(':')) {
                        if (isIpv6(token)) directIps.add(token)
                    } else {
                        ipToLong(token)?.let { v4Blocks += CidrBlock(it, 1) }
                    }
                }
            }
        }

        if (v4Blocks.isEmpty() && v6Blocks.isEmpty()) {
            return directIps.take(count)
        }

        val seen = LinkedHashSet<String>(count * 2)
        directIps.forEach { if (seen.size < count) seen.add(it) }

        val blocks = ArrayList<Any>(v4Blocks.size + v6Blocks.size).apply {
            addAll(v4Blocks)
            addAll(v6Blocks)
        }

        val maxAttempts = count * 10 + directIps.size * 2
        var attempts = 0
        while (seen.size < count && attempts < maxAttempts) {
            attempts++
            for (block in blocks) {
                if (seen.size >= count) break
                val ip = when (block) {
                    is CidrBlock -> longToIp(randomV4In(block, random))
                    is V6Block -> formatIpv6(randomV6In(block, random))
                    else -> continue
                }
                seen.add(ip)
            }
        }

        return seen.take(count).toList()
    }

    private fun randomV4In(block: CidrBlock, random: java.util.Random): Long {
        if (block.size <= 2) return block.base
        val offset = (random.nextDouble() * (block.size - 2)).toLong() + 1
        return block.base + offset
    }

    // ─── IPv6 helpers ────────────────────────────────────────────────────────

    private fun parseCidrV6(cidr: String): V6Block? {
        val parts = cidr.split("/")
        if (parts.size != 2) return null
        val prefix = parts[1].trim().toIntOrNull() ?: return null
        if (prefix !in 0..128) return null
        val network = parseIpv6Bytes(parts[0].trim()) ?: return null
        return V6Block(network, prefix, BigInteger.ONE.shiftLeft(128 - prefix))
    }

    private fun randomV6In(block: V6Block, random: java.util.Random): ByteArray {
        val out = block.network.clone()
        val randomBytes = ByteArray(16)
        random.nextBytes(randomBytes)
        val firstRandomByte = block.prefix / 8
        val bitOffset = block.prefix % 8
        for (i in firstRandomByte until 16) {
            if (i == firstRandomByte && bitOffset > 0) {
                // Keep the top `bitOffset` bits of this byte (network part)
                // and randomize the remaining low bits (host part).
                val keep = (0xFF shl (8 - bitOffset)) and 0xFF
                out[i] = (
                    (out[i].toInt() and keep) or
                        (randomBytes[i].toInt() and keep.inv())
                    ).toByte()
            } else {
                out[i] = randomBytes[i]
            }
        }
        return out
    }

    private fun isIpv6(s: String): Boolean {
        if (s.isBlank() || !s.contains(':')) return false
        if (s.any { it !in "0123456789abcdefABCDEF:" }) return false
        val doubleColonCount = "::".toRegex().findAll(s).count()
        if (doubleColonCount > 1 || s.contains(":::")) return false
        val groups = s.split(':').filter { it.isNotEmpty() }
        if (groups.any { it.length > 4 }) return false
        return if (doubleColonCount == 1) groups.size < 8 else groups.size == 8
    }

    /** Parses an IPv6 address (with optional `::` compression) into 16 bytes. */
    private fun parseIpv6Bytes(address: String): ByteArray? {
        val s = address.trim()
        if (s.isEmpty()) return null
        val hasDoubleColon = s.contains("::")
        if (!hasDoubleColon && s.count { it == ':' } != 7) return null

        val parts = if (hasDoubleColon) s.split("::", limit = 2) else listOf(s)
        val leftGroups = ArrayList<Int>()
        val rightGroups = ArrayList<Int>()

        fun parseGroups(raw: String, into: MutableList<Int>): Boolean {
            if (raw.isEmpty()) return true
            for (g in raw.split(':')) {
                if (g.isEmpty() || g.length > 4) return false
                val v = g.toIntOrNull(16) ?: return false
                into.add(v)
            }
            return true
        }

        if (!parseGroups(parts[0], leftGroups)) return null
        if (hasDoubleColon && !parseGroups(parts[1], rightGroups)) return null
        // Without `::` exactly 8 groups are required; with `::` the total must be < 8.
        if (hasDoubleColon && leftGroups.size + rightGroups.size >= 8) return null

        val out = ByteArray(16)
        var idx = 0
        for (v in leftGroups) {
            out[idx++] = (v shr 8).toByte()
            out[idx++] = v.toByte()
        }
        if (hasDoubleColon) {
            idx += (8 - leftGroups.size - rightGroups.size) * 2
        }
        for (v in rightGroups) {
            out[idx++] = (v shr 8).toByte()
            out[idx++] = v.toByte()
        }
        return out
    }

    /** Renders 16 bytes as a canonical IPv6 string with longest zero-run `::` compression. */
    private fun formatIpv6(bytes: ByteArray): String {
        val groups = IntArray(8) { i ->
            ((bytes[i * 2].toInt() and 0xFF) shl 8) or (bytes[i * 2 + 1].toInt() and 0xFF)
        }

        var bestStart = -1
        var bestLen = 0
        var i = 0
        while (i < 8) {
            if (groups[i] == 0) {
                var j = i
                while (j < 8 && groups[j] == 0) j++
                if (j - i > bestLen) {
                    bestLen = j - i
                    bestStart = i
                }
                i = j
            } else {
                i++
            }
        }

        val sb = StringBuilder()
        if (bestLen >= 2) {
            for (k in 0 until bestStart) {
                if (k > 0) sb.append(':')
                sb.append(groups[k].toString(16))
            }
            sb.append("::")
            for (k in bestStart + bestLen until 8) {
                if (k > bestStart + bestLen) sb.append(':')
                sb.append(groups[k].toString(16))
            }
        } else {
            for (k in 0 until 8) {
                if (k > 0) sb.append(':')
                sb.append(groups[k].toString(16))
            }
        }
        return sb.toString()
    }
}
