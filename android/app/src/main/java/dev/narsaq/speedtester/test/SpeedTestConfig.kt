package dev.narsaq.speedtester.test

object SpeedTestConfig {
    const val CONNECT_TIMEOUT_MS = 5_000
    const val CONCURRENCY = 20
    const val TOP_RESULTS_PER_CONFIG = 10

    // How many TCP-fastest candidates get the end-to-end protocol probe
    // (VLESS/Trojan handshake through the endpoint), and their parallelism.
    // Every slot shown in the result list gets verified.
    const val PROTOCOL_VERIFY_TOP = 10
    const val PROTOCOL_CONCURRENCY = 5
}
