package dev.narsaq.speedtester.ui

import android.content.ClipboardManager
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Bundle
import android.view.View
import android.widget.Toast
import com.google.android.material.textfield.TextInputEditText
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.widget.doAfterTextChanged
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import dev.narsaq.speedtester.MainActivity
import dev.narsaq.speedtester.MainViewModel
import dev.narsaq.speedtester.R
import dev.narsaq.speedtester.UiEvent
import dev.narsaq.speedtester.databinding.FragmentInputBinding
import kotlinx.coroutines.launch

class InputFragment : Fragment(R.layout.fragment_input) {

    private enum class FileTarget { CONFIGS, IPS }

    private var _binding: FragmentInputBinding? = null
    private val binding get() = _binding!!
    private val viewModel: MainViewModel by activityViewModels()

    private var fileTarget: FileTarget = FileTarget.CONFIGS

    private val pickFile =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri == null) return@registerForActivityResult
            val currentContext = context ?: return@registerForActivityResult
            try {
                val text = currentContext.contentResolver.openInputStream(uri)?.use { stream ->
                    stream.bufferedReader(Charsets.UTF_8).readText().take(2_000_000)
                }.orEmpty()
                if (text.isBlank()) {
                    Toast.makeText(currentContext, R.string.file_read_error, Toast.LENGTH_SHORT)
                        .show()
                    return@registerForActivityResult
                }
                when (fileTarget) {
                    FileTarget.CONFIGS -> _binding?.etConfigs?.setText(text)
                    FileTarget.IPS -> _binding?.etIps?.setText(text)
                }
            } catch (e: Exception) {
                Toast.makeText(currentContext, R.string.file_read_error, Toast.LENGTH_SHORT).show()
            }
        }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        _binding = FragmentInputBinding.bind(view)

        // ─── Hero ───
        binding.hero.btnLanguage.setOnClickListener {
            (activity as? MainActivity)?.toggleLanguage()
        }
        binding.hero.btnTheme.setOnClickListener {
            (activity as? MainActivity)?.toggleTheme()
        }

        // ─── Configs ───
        binding.etConfigs.doAfterTextChanged {
            updateCounts()
            updateStartState()
        }

        binding.btnPasteConfigs.setOnClickListener { pasteInto(binding.etConfigs) }
        binding.btnFileConfigs.setOnClickListener {
            fileTarget = FileTarget.CONFIGS
            pickFile.launch(arrayOf("text/plain", "application/octet-stream", "*/*"))
        }
        binding.btnClearConfigs.setOnClickListener { binding.etConfigs.setText("") }

        // ─── IPs ───
        binding.etIps.doAfterTextChanged {
            updateCounts()
            updateStartState()
        }

        binding.btnPasteIps.setOnClickListener { pasteInto(binding.etIps) }
        binding.btnFileIps.setOnClickListener {
            fileTarget = FileTarget.IPS
            pickFile.launch(arrayOf("text/plain", "application/octet-stream", "*/*"))
        }
        binding.btnClearIps.setOnClickListener { binding.etIps.setText("") }

        // ─── Anti-Filter Section ───
        setupAntiFilter()

        // ─── Start ───
        binding.btnStart.setOnClickListener {
            val configText = binding.etConfigs.text?.toString().orEmpty()
            val ipText = binding.etIps.text?.toString().orEmpty()

            when {
                configText.isBlank() -> {
                    Toast.makeText(requireContext(), "Enter configs first", Toast.LENGTH_SHORT)
                        .show()
                }

                ipText.isBlank() -> {
                    Toast.makeText(requireContext(), "Enter IPs first", Toast.LENGTH_SHORT).show()
                }

                !isOnline() -> {
                    Toast.makeText(requireContext(), R.string.offline_error, Toast.LENGTH_LONG)
                        .show()
                }

                else -> {
                    val antiFilter = if (binding.switchAntiFilter.isChecked) {
                        MainViewModel.AntiFilterSettings(
                            fragmentJson = binding.etFragment.text?.toString()?.trim().orEmpty(),
                            cipherSuites = binding.etCipherSuites.text?.toString()?.trim().orEmpty(),
                            fingerprintUnsafe = true
                        )
                    } else {
                        null
                    }
                    viewModel.startBuild(configText, ipText, antiFilter)
                }
            }
        }

        updateCounts()
        updateStartState()

        // ─── Events ───
        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.events.collect { event ->
                    when (event) {
                        UiEvent.NO_VALID_CONFIGS -> {
                            Toast.makeText(
                                requireContext(),
                                R.string.no_valid_configs,
                                Toast.LENGTH_SHORT
                            ).show()
                        }

                        UiEvent.NO_VALID_IPS -> {
                            Toast.makeText(
                                requireContext(),
                                "No valid IPs found",
                                Toast.LENGTH_SHORT
                            ).show()
                        }

                        UiEvent.RETEST_EMPTY -> Unit
                    }
                }
            }
        }
    }

    private fun setupAntiFilter() {
        // پیش‌فرض‌ها
        binding.etFragment.setText(DEFAULT_FRAGMENT_JSON)
        binding.etCipherSuites.setText(DEFAULT_CIPHER_SUITES)

        // نمایش/مخفی کردن جزئیات
        binding.switchAntiFilter.setOnCheckedChangeListener { _, isChecked ->
            binding.antiFilterDetails.visibility = if (isChecked) View.VISIBLE else View.GONE
        }

        // ریست به پیش‌فرض
        binding.btnResetDefaults.setOnClickListener {
            binding.etFragment.setText(DEFAULT_FRAGMENT_JSON)
            binding.etCipherSuites.setText(DEFAULT_CIPHER_SUITES)
            Toast.makeText(requireContext(), "Reset to defaults", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onResume() {
        super.onResume()
        refreshThemeIcon()
    }

    private fun refreshThemeIcon() {
        val main = activity as? MainActivity ?: return
        binding.hero.btnTheme.setImageResource(
            if (main.isNightModeActive()) R.drawable.ic_light else R.drawable.ic_dark
        )
    }

    private fun updateCounts() {
        val configCount = binding.etConfigs.text
            ?.lineSequence()?.count { it.isNotBlank() } ?: 0
        val ipCount = binding.etIps.text
            ?.lineSequence()?.count { it.isNotBlank() } ?: 0
        binding.tvConfigCount.text = getString(R.string.lines_count, configCount)
        binding.tvIpCount.text = getString(R.string.lines_count, ipCount)
    }

    private fun updateStartState() {
        binding.btnStart.isEnabled =
            !binding.etConfigs.text.isNullOrBlank() && !binding.etIps.text.isNullOrBlank()
    }

    private fun pasteInto(target: TextInputEditText) {
        val cm = requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val text = cm.primaryClip
            ?.takeIf { it.itemCount > 0 }
            ?.getItemAt(0)
            ?.coerceToText(requireContext())
            ?.toString()
        if (text.isNullOrBlank()) {
            Toast.makeText(requireContext(), R.string.clipboard_empty, Toast.LENGTH_SHORT).show()
        } else {
            target.setText(text)
        }
    }

    private fun isOnline(): Boolean = try {
        val cm = requireContext().getSystemService(Context.CONNECTIVITY_SERVICE)
            as ConnectivityManager
        val net = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(net) ?: return false
        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    } catch (e: Exception) {
        true
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    companion object {
        private val DEFAULT_FRAGMENT_JSON = """{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["5","94", "1"], "delays": ["0"], "maxSplit": "0"}},{"type": "fragment", "settings": {"packets": "1-1", "lengths": ["109", "1"], "delays": ["1"], "maxSplit": "355"}}]}""".trimIndent()

        private const val DEFAULT_CIPHER_SUITES =
            "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:" +
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:" +
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:" +
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:" +
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:" +
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:" +
                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
    }
}