package dev.narsaq.speedtester.util

object FlagUtil {

    /** Converts an ISO 3166-1 alpha-2 country code to its flag emoji. */
    fun countryFlag(countryCode: String): String {
        val code = countryCode.trim().uppercase()
        if (code.length != 2 || code.any { it !in 'A'..'Z' }) return ""
        val first = 0x1F1E6 + (code[0] - 'A')
        val second = 0x1F1E6 + (code[1] - 'A')
        return buildString {
            appendCodePoint(first)
            appendCodePoint(second)
        }
    }
}
