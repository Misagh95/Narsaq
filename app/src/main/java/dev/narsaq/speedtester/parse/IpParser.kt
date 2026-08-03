package dev.narsaq.speedtester.parse

import android.util.Patterns

object IpParser {

    fun parse(text: String): List<String> {
        val out = ArrayList<String>()
        val seen = LinkedHashSet<String>()

        for (rawLine in text.lineSequence()) {
            val candidate = normalize(rawLine) ?: continue
            if (!Patterns.IP_ADDRESS.matcher(candidate).matches()) continue
            if (seen.add(candidate)) {
                out += candidate
            }
        }

        return out
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