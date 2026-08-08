package dev.narsaq.speedtester.data

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * JSON (org.json) persistence of the last scan + last build session, stored in
 * SharedPreferences. Chosen over Room because org.json and SharedPreferences
 * ship with the Android SDK — no extra compile/runtime dependency and no
 * network fetch, which matters on machines without Google Maven access.
 *
 * Only the newest batch is kept: each save atomically replaces the previous
 * batch, so the store stays bounded.
 */
class PersistenceStore(context: Context) {

    private val prefs = context.applicationContext
        .getSharedPreferences("narsaq_state", Context.MODE_PRIVATE)

    // ─── Scan results ───────────────────────────────────────────────────────

    private var scanBatch: Long = 0
    private var scanRows: List<ScanResultEntity> = emptyList()

    /** Returns the most recent scan batch, or an empty list if none. */
    fun latestScanResults(): List<ScanResultEntity> {
        refreshScanCache()
        return if (scanBatch == 0L) emptyList() else scanRows
    }

    /** Replaces the stored scan batch with [rows] (prunes older batches). */
    fun saveScanResults(rows: List<ScanResultEntity>) {
        if (rows.isEmpty()) return
        val batchId = System.currentTimeMillis()
        val root = JSONObject().apply {
            put(KEY_SCAN_BATCH, batchId)
            put(KEY_SCAN_ROWS, JSONArray().apply {
                rows.forEach { put(it.toJson()) }
            })
        }
        prefs.edit().putString(KEY_SCAN, root.toString()).apply()
        scanBatch = batchId
        scanRows = rows
    }

    private fun refreshScanCache() {
        val raw = prefs.getString(KEY_SCAN, "{}") ?: "{}"
        val root = runCatching { JSONObject(raw) }.getOrElse { JSONObject() }
        val batch = root.optLong(KEY_SCAN_BATCH, 0L)
        val rowsJson = root.optJSONArray(KEY_SCAN_ROWS)
        val rows = if (rowsJson == null) emptyList() else buildList {
            for (i in 0 until rowsJson.length()) {
                val obj = rowsJson.optJSONObject(i) ?: continue
                add(ScanResultEntity.fromJson(obj))
            }
        }
        scanBatch = batch
        scanRows = rows
    }

    // ─── Built configs ──────────────────────────────────────────────────────

    private var buildBatch: Long = 0
    private var buildRows: List<BuiltConfigEntity> = emptyList()

    /** Returns the most recent build batch (rank-ordered), or empty. */
    fun latestBuiltConfigs(): List<BuiltConfigEntity> {
        refreshBuildCache()
        return if (buildBatch == 0L) emptyList() else buildRows.sortedBy { it.rank }
    }

    /** Replaces the stored build batch with [rows] (prunes older batches). */
    fun saveBuiltConfigs(rows: List<BuiltConfigEntity>) {
        if (rows.isEmpty()) return
        val batchId = System.currentTimeMillis()
        val root = JSONObject().apply {
            put(KEY_BUILD_BATCH, batchId)
            put(KEY_BUILD_ROWS, JSONArray().apply {
                rows.forEach { put(it.toJson()) }
            })
        }
        prefs.edit().putString(KEY_BUILD, root.toString()).apply()
        buildBatch = batchId
        buildRows = rows
    }

    private fun refreshBuildCache() {
        val raw = prefs.getString(KEY_BUILD, "{}") ?: "{}"
        val root = runCatching { JSONObject(raw) }.getOrElse { JSONObject() }
        val batch = root.optLong(KEY_BUILD_BATCH, 0L)
        val rowsJson = root.optJSONArray(KEY_BUILD_ROWS)
        val rows = if (rowsJson == null) emptyList() else buildList {
            for (i in 0 until rowsJson.length()) {
                val obj = rowsJson.optJSONObject(i) ?: continue
                add(BuiltConfigEntity.fromJson(obj))
            }
        }
        buildBatch = batch
        buildRows = rows
    }

    companion object {
        private const val KEY_SCAN = "scan"
        private const val KEY_SCAN_BATCH = "batchId"
        private const val KEY_SCAN_ROWS = "rows"
        private const val KEY_BUILD = "build"
        private const val KEY_BUILD_BATCH = "batchId"
        private const val KEY_BUILD_ROWS = "rows"
    }
}