package dev.narsaq.speedtester.parse

object IpParser {

    fun parse(text: String): List<String> {
        val out = ArrayList<String>()
        val seen = LinkedHashSet<String>()

        for (rawLine in text.lineSequence()) {
            val candidate = normalize(rawLine) ?: continue
            if (!isValidIp(candidate)) continue
            if (seen.add(candidate)) {
                out += candidate
            }
        }

        return out
    }

    private fun isValidIp(candidate: String): Boolean =
        isIpv4(candidate) || isIpv6(candidate)

    private fun isIpv4(s: String): Boolean {
        val octets = s.split('.')
        if (octets.size != 4) return false
        return octets.all { octet ->
            octet.isNotEmpty() &&
                octet.length <= 3 &&
                octet.all { it.isDigit() } &&
                octet.toInt() in 0..255
        }
    }

    private fun isIpv6(s: String): Boolean {
        if (!s.contains(':') || s.any { it !in "0123456789abcdefABCDEF:" }) return false
        val doubleColonCount = "::".toRegex().findAll(s).count()
        if (doubleColonCount > 1 || s.contains(":::")) return false
        val groups = s.split(':').filter { it.isNotEmpty() }
        if (groups.any { it.length > 4 }) return false
        return if (doubleColonCount == 1) groups.size < 8 else groups.size == 8
    }

    private fun normalize(rawLine: String): String? {
        val line = rawLine.substringBefore('#').trim()
        if (line.isBlank()) return null

        val token = line.split(Regex("""\s+""")).firstOrNull()?.trim().orEmpty()
        if (token.isBlank()) return null

        return when {
            token.startsWith("[") && token.contains("]") -> {
                token.substringAfter('[').substringBefore(']').trim().takeIf { it.isNotBlank() }
            }

            token.count { it == ':' } == 1 -> {
                val right = token.substringAfter(':')
                if (right.all { it.isDigit() }) token.substringBefore(':').trim() else token
            }

            else -> token
        }
    }
}
