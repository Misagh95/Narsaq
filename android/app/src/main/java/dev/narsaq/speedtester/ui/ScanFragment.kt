package dev.narsaq.speedtester.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import dev.narsaq.speedtester.MainActivity
import dev.narsaq.speedtester.R
import dev.narsaq.speedtester.ScanPhase
import dev.narsaq.speedtester.ScanState
import dev.narsaq.speedtester.ScanViewModel
import dev.narsaq.speedtester.databinding.FragmentScanBinding
import dev.narsaq.speedtester.scan.IpScanner
import dev.narsaq.speedtester.scan.ScanResult
import dev.narsaq.speedtester.util.FlagUtil
import kotlinx.coroutines.launch

class ScanFragment : Fragment(R.layout.fragment_scan) {

    private var _binding: FragmentScanBinding? = null
    private val binding get() = _binding!!
    private val scanVm: ScanViewModel by activityViewModels()

    /** Selected IP limit for the scan→build transfer; null = all clean IPs. */
    private var selectedIpLimit: Int? = null

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        _binding = FragmentScanBinding.bind(view)

        binding.btnLanguage.setOnClickListener {
            (activity as? MainActivity)?.toggleLanguage()
        }
        binding.btnTheme.setOnClickListener {
            (activity as? MainActivity)?.toggleTheme()
            refreshThemeIcon()
        }

        binding.cardGuideWorker.setOnClickListener { showWorkerGuide() }
        binding.cardGuideBot.setOnClickListener { showBotGuide() }
        binding.cardGuidePanels.setOnClickListener { showPanelsGuide() }

        binding.btnStartScan.setOnClickListener {
            val portText = binding.etPort.text?.toString()?.trim().orEmpty()
            val ports = parsePortsInput(portText)
            val count = binding.etCount.text?.toString()?.toIntOrNull() ?: 1000
            val timeout = (binding.etTimeout.text?.toString()?.toIntOrNull() ?: 3) * 1000
            val enableTls = binding.switchTls.isChecked
            val enableVerify = binding.switchVerify.isChecked
            val neighborScan = binding.switchNeighborScan.isChecked
            val enableV6 = binding.switchIpv6.isChecked
            val customRanges = binding.etCustomRanges.text?.toString().orEmpty()
            val speedTest = binding.switchSpeedTest.isChecked

            scanVm.startScan(
                ports = ports,
                count = count,
                timeoutMs = timeout,
                enableTls = enableTls,
                enableVerify = enableVerify,
                neighborScan = neighborScan,
                enableV6 = enableV6,
                customRanges = customRanges,
                speedTest = speedTest
            )
        }

        binding.btnCancelScan.setOnClickListener { scanVm.cancelScan() }

        binding.selectCountText.setOnClickListener {
            showIpCountPicker()
        }

        binding.btnCopyIps.setOnClickListener {
            val text = scanVm.getScanReportText()
            if (text.isBlank()) {
                Toast.makeText(requireContext(), R.string.scan_no_ips_copy, Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            val cm = requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("Clean IPs", text))
            Snackbar.make(binding.root, R.string.scan_report_copied, Snackbar.LENGTH_SHORT).show()
        }

        binding.btnGoToBuild.setOnClickListener {
            val limit = selectedIpLimit
            val text = if (limit == null) scanVm.getCleanIpsText() else scanVm.getCleanIpsText(limit)
            if (text.isBlank()) {
                Toast.makeText(requireContext(), R.string.scan_no_ips_copy, Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            (activity as? MainActivity)?.goToBuildWithIps(text)
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                scanVm.state.collect { state -> render(state) }
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

    private fun parsePortsInput(text: String): List<Int> {
        if (text.isBlank()) return listOf(443)
        val ports = text.split(",", " ", ";")
            .mapNotNull { it.trim().toIntOrNull() }
            .filter { it in 1..65535 }
            .distinct()
        return if (ports.isEmpty()) listOf(443) else ports
    }

    private fun showWorkerGuide() {
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.scan_guide_worker_title)
            .setMessage(R.string.scan_guide_worker_body)
            .setPositiveButton(R.string.ok, null)
            .setNeutralButton(R.string.scan_open_cloudflare) { _, _ ->
                openUrl("https://dash.cloudflare.com/")
            }
            .show()
    }

    private fun showBotGuide() {
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.scan_guide_bot_title)
            .setMessage(R.string.scan_guide_bot_body)
            .setPositiveButton(R.string.ok, null)
            .setNeutralButton(R.string.scan_open_bot) { _, _ ->
                openUrl("https://t.me/CloudBPBot")
            }
            .show()
    }

    private fun showPanelsGuide() {
        val panels = arrayOf(
            "BPB Worker Panel",
            "EdgeTunnel (cmliu)",
            "Zeus Panel",
            "Nahan Panel",
            "Nova Proxy"
        )
        val urls = arrayOf(
            "https://github.com/bia-pain-bache/BPB-Worker-Panel",
            "https://github.com/cmliu/edgetunnel",
            "https://github.com/IR-NETLIFY/zeus",
            "https://github.com/itsyebekhe/nahan",
            "https://github.com/IRNova/Nova-Proxy"
        )
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.scan_guide_panels_title)
            .setItems(panels) { _, which -> openUrl(urls[which]) }
            .setPositiveButton(R.string.ok, null)
            .show()
    }

    private fun openUrl(url: String) {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
        } catch (e: Exception) {
            Toast.makeText(requireContext(), R.string.scan_cannot_open, Toast.LENGTH_SHORT).show()
        }
    }

    private fun render(state: ScanState) {
        when (state.phase) {
            ScanPhase.IDLE -> {
                binding.progressScan.visibility = View.GONE
                binding.btnStartScan.isEnabled = true
                binding.btnCancelScan.visibility = View.GONE
                binding.cardResults.visibility = View.GONE
                binding.cardReady.visibility = View.GONE
                binding.heroPill.visibility = View.GONE
                binding.heroStats.visibility = View.GONE
                binding.tvScanStatus.setText(R.string.scan_status_idle)
            }

            ScanPhase.SCANNING -> {
                binding.progressScan.visibility = View.VISIBLE
                binding.progressScan.progress = state.progressPercent
                binding.btnStartScan.isEnabled = false
                binding.btnCancelScan.visibility = View.VISIBLE
                binding.cardResults.visibility = View.GONE
                binding.cardReady.visibility = View.GONE
                binding.heroPill.visibility = View.VISIBLE
                binding.tvHeroPillText.setText(R.string.cd_status_scanning)
                binding.heroStats.visibility = View.VISIBLE
                binding.tvStat1Value.text = state.done.toString()
                binding.tvStat2Value.text = state.found.toString()
                binding.tvStat3Value.text = bestLatencyText(state)
                binding.tvScanStatus.text =
                    "${state.currentPhase} ${state.done}/${state.total} | ${getString(R.string.filter_passed)}: ${state.found}"
            }

            ScanPhase.ASN_LOOKUP -> {
                binding.progressScan.visibility = View.VISIBLE
                binding.progressScan.progress = 0
                binding.btnStartScan.isEnabled = false
                binding.btnCancelScan.visibility = View.VISIBLE
                binding.cardResults.visibility = if (state.results.isNotEmpty()) View.VISIBLE else View.GONE
                binding.cardReady.visibility = if (state.results.isNotEmpty()) View.VISIBLE else View.GONE
                binding.heroPill.visibility = View.VISIBLE
                binding.tvHeroPillText.setText(R.string.scan_status_asn)
                binding.heroStats.visibility = View.VISIBLE
                binding.tvStat1Value.text = state.total.toString()
                binding.tvStat2Value.text = state.found.toString()
                binding.tvStat3Value.text = bestLatencyText(state)
                binding.tvReadyTitle.text = getString(R.string.scan_ready_title, state.results.size)
                binding.tvScanStatus.text = getString(R.string.scan_status_asn)
                renderResults(state)
            }

            ScanPhase.DONE -> {
                binding.progressScan.visibility = View.GONE
                binding.btnStartScan.isEnabled = true
                binding.btnCancelScan.visibility = View.GONE
                binding.tvScanStatus.text =
                    getString(R.string.scan_status_done, state.found)

                binding.heroPill.visibility = View.VISIBLE
                binding.tvHeroPillText.text = getString(R.string.scan_complete_pill, state.found)
                binding.heroStats.visibility = View.VISIBLE
                binding.tvStat1Value.text = state.total.toString()
                binding.tvStat2Value.text = state.found.toString()
                binding.tvStat3Value.text = bestLatencyText(state)

                binding.cardResults.visibility = View.VISIBLE
                binding.cardReady.visibility = if (state.results.isNotEmpty()) View.VISIBLE else View.GONE
                binding.tvReadyTitle.text = getString(R.string.scan_ready_title, state.results.size)
                renderResults(state)
            }

            ScanPhase.CANCELLED -> {
                binding.progressScan.visibility = View.GONE
                binding.btnStartScan.isEnabled = true
                binding.btnCancelScan.visibility = View.GONE
                binding.cardReady.visibility = View.GONE
                binding.heroPill.visibility = View.GONE
                binding.heroStats.visibility = View.GONE
                binding.tvScanStatus.setText(R.string.scan_status_cancelled)
            }
        }
    }

    private fun showIpCountPicker() {
        val options = listOf(10, 50, 100)
        val labels = options.map { it.toString() } + getString(R.string.scan_ip_count_all)
        val current = selectedIpLimit
        val checked = if (current == null) options.size else options.indexOf(current)

        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.scan_ip_count_dialog_title)
            .setSingleChoiceItems(labels.toTypedArray(), checked) { dialog, which ->
                selectedIpLimit = if (which == options.size) null else options[which]
                updateIpCountLabel()
                dialog.dismiss()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun updateIpCountLabel() {
        val limit = selectedIpLimit
        binding.selectCountText.text = if (limit == null) {
            getString(R.string.scan_ip_count_all)
        } else {
            getString(R.string.scan_ip_count_pick, limit)
        }
    }

    private fun bestLatencyText(state: ScanState): String {
        val best = state.results
            .filter { !it.flaggedDomestic }
            .minOfOrNull { it.tcpLatencyMs }
        return if (best == null) "—" else getString(R.string.latency_ms, best)
    }

    private fun formatEndpoint(result: ScanResult): String {
        val ip = if (':' in result.ip) "[${result.ip}]" else result.ip
        return "$ip:${result.port}"
    }

    private fun renderResults(state: ScanState) {
        if (state.results.isEmpty()) {
            binding.tvResultsTitle.setText(R.string.scan_no_results)
            binding.tvResultsList.setText(R.string.scan_no_results_hint)
            return
        }
        binding.tvResultsTitle.text = getString(R.string.scan_results_found, state.results.filter { !it.flaggedDomestic }.size)
        binding.tvResultsList.text = state.results
            .filter { !it.flaggedDomestic }
            .mapIndexed { index, result ->
                val verified = if (result.verified) " ✓" else ""
                val tls = if (result.tlsLatencyMs != null) " | TLS: ${result.tlsLatencyMs}ms" else ""
                val asn = result.asn.ifBlank { "?" }
                val loss = result.lossRate?.let { "%.0f%%".format(it) } ?: "N/A"
                val jitter = result.jitterMs?.let { "±${it}ms" } ?: "N/A"
                val speed = result.throughputMbps?.let { "%.1f Mbps".format(it) } ?: "N/A"
                val colo = result.colo.ifBlank { "?" }
                val country = result.country.ifBlank { "?" }
                val flag = if (result.isCloudflare) {
                    ""
                } else {
                    FlagUtil.countryFlag(result.country)
                }
                val countryText = if (flag.isEmpty()) country else "$country $flag"
                "${index + 1}. ${formatEndpoint(result)} — ${result.tcpLatencyMs}ms$tls (${result.quality.lowercase()})$verified\n" +
                    "   Loss: $loss | Jitter: $jitter | Speed: $speed | Colo: $colo\n" +
                    "   ASN: $asn | Country: $countryText"
            }.joinToString("\n")
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
