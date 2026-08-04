package dev.narsaq.speedtester.scan

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

    data class CidrBlock(
        val base: Long,
        val size: Long
    )

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
}