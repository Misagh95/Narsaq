package dev.narsaq.speedtester.util

/**
 * Default anti-filter values for the PattNG fix (fragment + cipher suites).
 * These are the values the cf-optimizor tool injects into every config —
 * applying them in-app saves the user from pasting them per config.
 */
object AntiFilterDefaults {

    val FRAGMENT_JSON: String =
        """{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["5","94", "1"], "delays": ["0"], "maxSplit": "0"}},{"type": "fragment", "settings": {"packets": "1-1", "lengths": ["109", "1"], "delays": ["1"], "maxSplit": "355"}}]}"""

    val CIPHER_SUITES: String =
        "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:" +
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:" +
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:" +
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:" +
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:" +
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:" +
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
}
