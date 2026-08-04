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
import kotlinx.coroutines.launch

class ScanFragment : Fragment(R.layout.fragment_scan) {

    private var _binding: FragmentScanBinding? = null
    private val binding get() = _binding!!
    private val scanVm: ScanViewModel by activityViewModels()

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        _binding = FragmentScanBinding.bind(view)

        // ─── Hero ───
        binding.btnLanguage.setOnClickListener {
            (activity as? MainActivity)?.toggleLanguage()
        }
        binding.btnTheme.setOnClickListener {
            (activity as? MainActivity)?.toggleTheme()
        }

        // ─── Guide Cards ───
        binding.cardGuideWorker.setOnClickListener { showWorkerGuide() }
        binding.cardGuideBot.setOnClickListener { showBotGuide() }
        binding.cardGuidePanels.setOnClickListener { showPanelsGuide() }

        // ─── Scan ───
        binding.btnStartScan.setOnClickListener {
            val port = binding.etPort.text?.toString()?.toIntOrNull() ?: 443
            val count = binding.etCount.text?.toString()?.toIntOrNull() ?: 200
            val timeout = (binding.etTimeout.text?.toString()?.toIntOrNull() ?: 3) * 1000
            scanVm.startScan(port, count, timeout)
        }

        binding.btnCancelScan.setOnClickListener {
            scanVm.cancelScan()
        }

        binding.btnCopyIps.setOnClickListener {
            val text = scanVm.getCleanIpsText()
            if (text.isBlank()) {
                Toast.makeText(requireContext(), "No IPs to copy", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            val cm =
                requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("Clean IPs", text))
            Snackbar.make(binding.root, "IPs copied!", Snackbar.LENGTH_SHORT).show()
        }

        binding.btnGoToBuild.setOnClickListener {
            (activity as? MainActivity)?.goToBuildWithIps(scanVm.getCleanIpsText())
        }

        // ─── State ───
        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                scanVm.state.collect { state -> render(state) }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        val main = activity as? MainActivity ?: return
        binding.btnTheme.setImageResource(
            if (main.isNightModeActive()) R.drawable.ic_light else R.drawable.ic_dark
        )
    }

    // ─── Guide Dialogs ───

    private fun showWorkerGuide() {
        MaterialAlertDialogBuilder(requireContext())
            .setTitle("☁️ Create Cloudflare Worker")
            .setMessage(
                """
Step 1: Create API Token
• Go to Cloudflare Dashboard
• Profile → API Tokens → Create Token
• Permissions needed:
  - Workers Scripts / Edit
  - Workers KV Storage / Edit
  - D1 / Edit
  - Workers Routes / Edit
  - Account Settings / Read

Step 2: Verify Email
• Your Cloudflare email must be verified
• Visit Workers & Pages at least once

Step 3: Deploy Panel
• Use one of the panel projects
• Or use the Telegram bot for auto setup

⚠️ After creating the panel, if you see "There is nothing here yet", wait 1-2 minutes and refresh.
                """.trimIndent()
            )
            .setPositiveButton("OK", null)
            .setNeutralButton("Open Cloudflare") { _, _ ->
                openUrl("https://dash.cloudflare.com/")
            }
            .show()
    }

    private fun showBotGuide() {
        MaterialAlertDialogBuilder(requireContext())
            .setTitle("🤖 Auto Setup Bot")
            .setMessage(
                """
Use these Telegram bots to automatically deploy your Worker panel:

• Enter your Cloudflare API Token
• Choose panel type (BPB, EdgeTunnel, etc.)
• Bot deploys everything automatically
• You get your config link instantly

This is the easiest way to get started!
                """.trimIndent()
            )
            .setPositiveButton("OK", null)
            .setNeutralButton("Open Telegram") { _, _ ->
                openUrl("https://t.me/ArchiveTell")
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
            .setTitle("📋 Panel Projects")
            .setItems(panels) { _, which ->
                openUrl(urls[which])
            }
            .setPositiveButton("Close", null)
            .show()
    }

    private fun openUrl(url: String) {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
        } catch (e: Exception) {
            Toast.makeText(requireContext(), "Cannot open link", Toast.LENGTH_SHORT).show()
        }
    }

    // ─── Render ───

    private fun render(state: ScanState) {
        when (state.phase) {
            ScanPhase.IDLE -> {
                binding.progressScan.visibility = View.GONE
                binding.btnStartScan.isEnabled = true
                binding.btnCancelScan.visibility = View.GONE
                binding.cardResults.visibility = View.GONE
                binding.tvScanStatus.text = "Scan Cloudflare IPs to find clean ones"
            }

            ScanPhase.SCANNING -> {
                binding.progressScan.visibility = View.VISIBLE
                binding.progressScan.progress = state.progressPercent
                binding.btnStartScan.isEnabled = false
                binding.btnCancelScan.visibility = View.VISIBLE
                binding.cardResults.visibility = View.GONE
                binding.tvScanStatus.text =
                    "Scanning... ${state.done}/${state.total} | Found: ${state.found}"
            }

            ScanPhase.DONE -> {
                binding.progressScan.visibility = View.GONE
                binding.btnStartScan.isEnabled = true
                binding.btnCancelScan.visibility = View.GONE
                binding.tvScanStatus.text = "Done! Found ${state.results.size} clean IPs"

                binding.cardResults.visibility = View.VISIBLE
                if (state.results.isNotEmpty()) {
                    binding.tvResultsTitle.text = "✅ ${state.results.size} Clean IPs Found"
                    binding.tvResultsList.text = state.results.mapIndexed { index, result ->
                        "${index + 1}. ${result.ip} — ${result.latencyMs}ms"
                    }.joinToString("\n")
                } else {
                    binding.tvResultsTitle.text = "⚠️ No clean IPs found"
                    binding.tvResultsList.text = "Try increasing timeout or IP count"
                }
            }

            ScanPhase.CANCELLED -> {
                binding.progressScan.visibility = View.GONE
                binding.btnStartScan.isEnabled = true
                binding.btnCancelScan.visibility = View.GONE
                binding.tvScanStatus.text = "Scan cancelled"
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}