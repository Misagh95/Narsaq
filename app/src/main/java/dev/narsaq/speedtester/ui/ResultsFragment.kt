package dev.narsaq.speedtester.ui

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.LinearLayoutManager
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import dev.narsaq.speedtester.MainActivity
import dev.narsaq.speedtester.MainViewModel
import dev.narsaq.speedtester.Phase
import dev.narsaq.speedtester.R
import dev.narsaq.speedtester.TesterState
import dev.narsaq.speedtester.UiEvent
import dev.narsaq.speedtester.databinding.FragmentResultsBinding
import dev.narsaq.speedtester.model.UiItem
import dev.narsaq.speedtester.util.ReportExporter
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class ResultsFragment : Fragment(R.layout.fragment_results) {

    private enum class Filter { ALL, PASSED, FAILED }

    private var _binding: FragmentResultsBinding? = null
    private val binding get() = _binding!!
    private val viewModel: MainViewModel by activityViewModels()
    private var filter: Filter = Filter.ALL
    private val adapter = ResultsAdapter { item -> showDetail(item) }

    private val storagePermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) {
                doExport()
            } else {
                val currentBinding = _binding ?: return@registerForActivityResult
                Snackbar.make(
                    currentBinding.root,
                    R.string.storage_permission_denied,
                    Snackbar.LENGTH_SHORT
                ).show()
            }
        }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        _binding = FragmentResultsBinding.bind(view)

        binding.rvResults.layoutManager = LinearLayoutManager(requireContext())
        binding.rvResults.adapter = adapter

        binding.btnBack.setOnClickListener { viewModel.reset() }
        binding.btnLanguage.setOnClickListener { (activity as? MainActivity)?.toggleLanguage() }
        binding.btnTheme.setOnClickListener { (activity as? MainActivity)?.toggleTheme() }

        binding.filterGroup.addOnButtonCheckedListener { _, checkedId, isChecked ->
            if (!isChecked) return@addOnButtonCheckedListener
            filter = when (checkedId) {
                R.id.chipPassed -> Filter.PASSED
                R.id.chipFailed -> Filter.FAILED
                else -> Filter.ALL
            }
            render(viewModel.state.value)
        }

        binding.btnCancel.setOnClickListener { viewModel.cancelTest() }
        binding.btnRetestAll.setOnClickListener { viewModel.retestAll() }
        binding.btnRetestFailed.setOnClickListener { viewModel.retestFailed() }
        binding.btnExport.setOnClickListener { startExport() }
        binding.btnCopy.setOnClickListener { copyReport() }
        binding.btnShare.setOnClickListener { shareReport() }

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.state.collect { render(it) }
            }
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.events.collect { event ->
                    if (event == UiEvent.RETEST_EMPTY) {
                        Toast.makeText(
                            requireContext(),
                            R.string.retest_empty,
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        refreshThemeIcon()
    }

    private fun refreshThemeIcon() {
        val main = activity as? MainActivity ?: return
        binding.btnTheme.setImageResource(
            if (main.isNightModeActive()) R.drawable.ic_light else R.drawable.ic_dark
        )
    }

    private fun render(state: TesterState) {
        binding.progressBar.max = state.totalCount.coerceAtLeast(1)
        binding.progressBar.progress = state.doneCount.coerceAtMost(state.totalCount)
        binding.tvProgressText.text =
            getString(R.string.progress_text, state.doneCount, state.totalCount)

        binding.tvStatus.setText(
            when (state.phase) {
                Phase.TESTING -> R.string.status_testing
                Phase.DONE -> R.string.status_done
                Phase.CANCELLED -> R.string.status_cancelled
                Phase.IDLE -> R.string.app_name
            }
        )

        binding.btnCancel.visibility =
            if (state.phase == Phase.TESTING) View.VISIBLE else View.GONE

        binding.btnRetestAll.visibility =
            if (state.isTerminal && state.totalCount > 0) View.VISIBLE else View.GONE

        binding.btnRetestFailed.visibility =
            if (state.isTerminal && state.failedItems.isNotEmpty()) View.VISIBLE else View.GONE

        val hasResults = state.isTerminal && state.totalCount > 0
        binding.btnExport.visibility = if (hasResults) View.VISIBLE else View.GONE
        binding.btnCopy.visibility = if (hasResults) View.VISIBLE else View.GONE
        binding.btnShare.visibility = if (hasResults) View.VISIBLE else View.GONE

        val rows = buildRows(state)
        adapter.submitList(rows)

        if (rows.isEmpty()) {
            binding.emptyState.visibility = View.VISIBLE
            if (state.phase == Phase.DONE && state.passedItems.isEmpty()) {
                binding.tvEmptyTitle.setText(R.string.all_failed)
                binding.tvEmptyBody.setText(R.string.empty_results_body)
                binding.ivEmptyIcon.setImageResource(R.drawable.ic_cloud_off)
            } else {
                binding.tvEmptyTitle.setText(R.string.empty_results_title)
                binding.tvEmptyBody.setText(R.string.empty_results_body)
                binding.ivEmptyIcon.setImageResource(R.drawable.ic_speed)
            }
        } else {
            binding.emptyState.visibility = View.GONE
        }
    }

    private fun buildRows(state: TesterState): List<ResultsAdapter.Row> {
        if (state.phase == Phase.TESTING) {
            return state.items.map { ResultsAdapter.Row.Item(it, 0) }
        }

        val passed = state.passedItems.mapIndexed { index, item ->
            ResultsAdapter.Row.Item(item, index + 1)
        }

        val failed = state.failedItems.map { ResultsAdapter.Row.Item(it, 0) }

        return when (filter) {
            Filter.PASSED -> passed
            Filter.FAILED -> failed
            Filter.ALL -> if (failed.isEmpty()) {
                passed
            } else {
                passed +
                    ResultsAdapter.Row.Header(getString(R.string.report_header_failed)) +
                    failed
            }
        }
    }

    private fun showDetail(item: UiItem) {
        val built = viewModel.buildFinalConfigs()
            .filter { it.originalConfig.id == item.id }

        val lines = StringBuilder()

        lines.appendLine("Original Host: ${item.host}")
        if (item.sni != null) lines.appendLine(getString(R.string.detail_sni, item.sni))
        if (item.path != null) lines.appendLine(getString(R.string.detail_path, item.path))
        lines.appendLine()

        if (built.isNotEmpty()) {
            lines.appendLine("Top Results:")
            lines.appendLine()

            for (r in built) {
                lines.appendLine("${r.rank}) ${r.bestIp}:${r.bestPort} — ${r.latencyMs} ms")
                lines.appendLine(r.finalConfig)
                lines.appendLine()
            }
        } else {
            if (!item.bestIp.isNullOrBlank()) {
                lines.appendLine("Best IP: ${item.bestIp}")
            }
            if (item.bestPort != null) {
                lines.appendLine("Best Port: ${item.bestPort}")
            }
            if (item.bestLatencyMs != null) {
                lines.appendLine("Latency: ${item.bestLatencyMs} ms")
            }
            if (!item.finalConfig.isNullOrBlank()) {
                lines.appendLine()
                lines.appendLine("Final Config:")
                lines.appendLine(item.finalConfig)
            }
            lines.appendLine()
        }

        if (item.portDetails.isNotEmpty()) {
            lines.appendLine(getString(R.string.detail_ports_header))
            for (p in item.portDetails) {
                if (p.reachable == true) {
                    val ipInfo = p.bestIp?.let { " | $it" } ?: ""
                    lines.appendLine("• ${p.port} -> ${p.latencyMs ?: 0L} ms$ipInfo")
                } else {
                    lines.appendLine(getString(R.string.port_fail, p.port))
                }
            }
        }

        if (!item.valid) {
            lines.appendLine()
            lines.append(getString(R.string.invalid_config))
        }

        MaterialAlertDialogBuilder(requireContext())
            .setTitle(getString(R.string.detail_title))
            .setMessage(lines.toString())
            .setPositiveButton(R.string.ok, null)
            .show()
    }

    private fun buildReportText(): String {
        val results = viewModel.buildFinalConfigs()
        if (results.isEmpty()) {
            return ReportExporter.buildReport(requireContext(), viewModel.state.value.items)
        }

        val sb = StringBuilder()
        sb.appendLine("# Narsaq — Best Configs")
        sb.appendLine("# Total: ${results.size}")
        sb.appendLine(
            "# Generated: ${
                SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())
            }"
        )
        sb.appendLine()

        for (r in results) {
            sb.appendLine(r.finalConfig)
        }

        sb.appendLine()
        sb.appendLine("# ── Latency Report ──")
        for (r in results) {
            sb.appendLine(
                "# cfg=${r.originalConfig.id} rank=${r.rank} ${r.bestIp}:${r.bestPort} — ${r.latencyMs}ms"
            )
        }

        return sb.toString()
    }

    private fun startExport() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            val permission = Manifest.permission.WRITE_EXTERNAL_STORAGE
            if (
                ContextCompat.checkSelfPermission(requireContext(), permission) !=
                PackageManager.PERMISSION_GRANTED
            ) {
                storagePermission.launch(permission)
                return
            }
        }
        doExport()
    }

    private fun doExport() {
        val currentBinding = _binding ?: return
        val currentContext = context ?: return

        when (val outcome = ReportExporter.export(currentContext, buildReportText())) {
            is ReportExporter.ExportOutcome.Ok -> {
                Snackbar.make(
                    currentBinding.root,
                    getString(R.string.export_ok, outcome.displayPath),
                    Snackbar.LENGTH_LONG
                ).show()
                shareReport()
            }

            ReportExporter.ExportOutcome.Error -> {
                Snackbar.make(
                    currentBinding.root,
                    R.string.export_failed,
                    Snackbar.LENGTH_SHORT
                ).show()
            }
        }
    }

    private fun copyReport() {
        val cm = requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText(getString(R.string.app_name), buildReportText()))
        Snackbar.make(binding.root, R.string.copied, Snackbar.LENGTH_SHORT).show()
    }

    private fun shareReport() {
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, buildReportText())
            putExtra(Intent.EXTRA_SUBJECT, getString(R.string.app_name))
        }
        startActivity(Intent.createChooser(send, getString(R.string.share_title)))
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}