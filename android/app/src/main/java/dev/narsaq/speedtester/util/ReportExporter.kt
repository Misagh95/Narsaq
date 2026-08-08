package dev.narsaq.speedtester.util

import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import dev.narsaq.speedtester.R
import dev.narsaq.speedtester.model.BuiltResult
import dev.narsaq.speedtester.model.ItemStatus
import dev.narsaq.speedtester.model.UiItem
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object ReportExporter {

    enum class ExportFormat {
        TXT, BASE64, SINGBOX, CLASH
    }

    sealed class ExportOutcome {
        data class Ok(val displayPath: String) : ExportOutcome()
        object Error : ExportOutcome()
    }

    fun buildReport(context: Context, items: List<UiItem>): String {
        val date = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date())
        val passed = items
            .filter { it.status == ItemStatus.PASSED }
            .sortedWith(
                compareBy<UiItem> { it.bestLatencyMs ?: Long.MAX_VALUE }
                    .thenBy { it.host }
            )
        val failed = items.filter { it.status != ItemStatus.PASSED }

        val sb = StringBuilder()
        sb.appendLine(context.getString(R.string.report_title, date))
        sb.appendLine(context.getString(R.string.report_servers, items.size))
        sb.appendLine()

        passed.forEachIndexed { index, item ->
            val hostPort = buildString {
                append(item.host.ifBlank { "?" })
                append(':')
                append(item.bestPort ?: item.ports.firstOrNull() ?: 0)
            }
            val latency = item.bestLatencyMs ?: 0L
            val typeLabel = context.getString(item.type.labelRes())
            sb.appendLine(context.getString(R.string.report_line_no_speed, index + 1, hostPort, latency, typeLabel))
        }

        if (failed.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine(context.getString(R.string.report_header_failed))
            failed.forEach { item ->
                val ports = item.ports.joinToString(",")
                sb.appendLine("${item.host.ifBlank { item.raw.take(60) }}:$ports")
            }
        }
        return sb.toString()
    }

    fun buildFormattedContent(
        context: Context,
        format: ExportFormat,
        items: List<UiItem>,
        builtResults: List<BuiltResult>
    ): String = when (format) {
        ExportFormat.TXT -> buildReportText(builtResults, items, context)
        ExportFormat.BASE64 -> ConfigPackager.buildBase64Subscription(builtResults)
        ExportFormat.SINGBOX -> ConfigPackager.buildSingboxJson(builtResults)
        ExportFormat.CLASH -> ConfigPackager.buildClashYaml(builtResults)
    }

    private fun buildReportText(
        results: List<BuiltResult>,
        items: List<UiItem>,
        context: Context
    ): String {
        if (results.isEmpty()) return buildReport(context, items)
        // Clean output: one rebuilt config per line, no headers or comments.
        return results.joinToString("\n") { it.finalConfig.trim() }
    }

    fun export(context: Context, text: String, format: ExportFormat = ExportFormat.TXT): ExportOutcome {
        val stamp = SimpleDateFormat("yyyy-MM-dd_HH-mm-ss", Locale.US).format(Date())
        val (name, mime) = when (format) {
            ExportFormat.TXT     -> "narsaq_report_$stamp.txt"     to "text/plain"
            ExportFormat.BASE64  -> "narsaq_sub_$stamp.txt"        to "text/plain"
            ExportFormat.SINGBOX -> "narsaq_singbox_$stamp.json"   to "application/json"
            ExportFormat.CLASH   -> "narsaq_clash_$stamp.yaml"     to "text/yaml"
        }
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            var insertedUri: android.net.Uri? = null
            try {
                val values = ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, name)
                    put(MediaStore.Downloads.MIME_TYPE, mime)
                    put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                    put(MediaStore.Downloads.IS_PENDING, 1)
                }
                val uri = context.contentResolver.insert(
                    MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                    values
                ) ?: throw IllegalStateException("Unable to create report")
                insertedUri = uri
                context.contentResolver.openOutputStream(uri)?.use {
                    it.write(text.toByteArray(Charsets.UTF_8))
                } ?: throw IllegalStateException("Unable to open report")
                context.contentResolver.update(uri, ContentValues().apply {
                    put(MediaStore.Downloads.IS_PENDING, 0)
                }, null, null)
                ExportOutcome.Ok("Download/$name")
            } catch (e: Exception) {
                insertedUri?.let { context.contentResolver.delete(it, null, null) }
                ExportOutcome.Error
            }
        } else {
            try {
                val dir = Environment.getExternalStoragePublicDirectory(
                    Environment.DIRECTORY_DOWNLOADS
                )
                if (!dir.exists() && !dir.mkdirs()) return ExportOutcome.Error
                val file = File(dir, name)
                file.writeText(text, Charsets.UTF_8)
                ExportOutcome.Ok(file.absolutePath)
            } catch (e: Exception) {
                ExportOutcome.Error
            }
        }
    }

    private fun dev.narsaq.speedtester.model.ConfigType.labelRes(): Int = when (this) {
        dev.narsaq.speedtester.model.ConfigType.VLESS -> R.string.type_vless
        dev.narsaq.speedtester.model.ConfigType.VMESS -> R.string.type_vmess
        dev.narsaq.speedtester.model.ConfigType.SHADOWSOCKS -> R.string.type_ss
        dev.narsaq.speedtester.model.ConfigType.TROJAN -> R.string.type_trojan
        dev.narsaq.speedtester.model.ConfigType.PLAIN -> R.string.type_plain
        dev.narsaq.speedtester.model.ConfigType.INVALID -> R.string.type_invalid
    }
}
