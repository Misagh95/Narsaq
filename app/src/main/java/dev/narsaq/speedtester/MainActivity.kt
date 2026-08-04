package dev.narsaq.speedtester

import android.content.res.Configuration
import android.os.Bundle
import androidx.activity.OnBackPressedCallback
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import dev.narsaq.speedtester.databinding.ActivityMainBinding
import dev.narsaq.speedtester.ui.InputFragment
import dev.narsaq.speedtester.ui.ResultsFragment
import dev.narsaq.speedtester.ui.ScanFragment
import dev.narsaq.speedtester.util.NightModeStore
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    private val viewModel: MainViewModel by viewModels()
    private var lastScannedIps: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        NightModeStore.apply(applicationContext)
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        if (savedInstanceState == null) {
            showScan()
        }

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.state.collect { state ->
                    when (state.phase) {
                        Phase.TESTING,
                        Phase.DONE,
                        Phase.CANCELLED -> showResultsIfNeeded()

                        Phase.IDLE -> {
                            // فقط اگر الان روی نتایج هستیم برگرد به ورودی
                            if (currentIsResults()) {
                                showInputIfNeeded(lastScannedIps)
                            }
                        }
                    }
                }
            }
        }

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                when {
                    currentIsResults() -> {
                        viewModel.reset()
                        showInputIfNeeded(lastScannedIps)
                    }

                    currentIsInput() -> {
                        showScanIfNeeded()
                    }

                    else -> {
                        isEnabled = false
                        onBackPressedDispatcher.onBackPressed()
                    }
                }
            }
        })
    }

    fun toggleLanguage() {
        val isFa = resources.configuration.locales.get(0).language == "fa"
        AppCompatDelegate.setApplicationLocales(
            LocaleListCompat.forLanguageTags(if (isFa) "en" else "fa")
        )
    }

    fun toggleTheme() {
        NightModeStore.toggle(applicationContext)
    }

    fun isNightModeActive(): Boolean =
        (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) ==
            Configuration.UI_MODE_NIGHT_YES

    /**
     * از ScanFragment صدا زده می‌شود.
     * IPهای تمیز را به صفحه Build می‌فرستد.
     */
    fun goToBuildWithIps(ipsText: String) {
        lastScannedIps = ipsText
        if (supportFragmentManager.isStateSaved) return

        supportFragmentManager.beginTransaction()
            .replace(
                R.id.fragmentContainer,
                InputFragment.newInstance(initialIps = ipsText),
                TAG_INPUT
            )
            .commit()
    }

    fun goToScan() {
        showScanIfNeeded()
    }

    private fun currentIsResults(): Boolean =
        supportFragmentManager.findFragmentById(R.id.fragmentContainer) is ResultsFragment

    private fun currentIsInput(): Boolean =
        supportFragmentManager.findFragmentById(R.id.fragmentContainer) is InputFragment

    private fun currentIsScan(): Boolean =
        supportFragmentManager.findFragmentById(R.id.fragmentContainer) is ScanFragment

    private fun showScan() {
        supportFragmentManager.beginTransaction()
            .replace(R.id.fragmentContainer, ScanFragment(), TAG_SCAN)
            .commit()
    }

    private fun showScanIfNeeded() {
        if (currentIsScan()) return
        if (supportFragmentManager.isStateSaved) return
        showScan()
    }

    private fun showInputIfNeeded(initialIps: String = "") {
        val current = supportFragmentManager.findFragmentById(R.id.fragmentContainer)
        if (current is InputFragment) return
        if (supportFragmentManager.isStateSaved) return

        supportFragmentManager.beginTransaction()
            .replace(
                R.id.fragmentContainer,
                InputFragment.newInstance(initialIps = initialIps),
                TAG_INPUT
            )
            .commit()
    }

    private fun showResultsIfNeeded() {
        if (currentIsResults()) return
        if (supportFragmentManager.isStateSaved) return

        supportFragmentManager.beginTransaction()
            .replace(R.id.fragmentContainer, ResultsFragment(), TAG_RESULTS)
            .commit()
    }

    companion object {
        private const val TAG_SCAN = "scan"
        private const val TAG_INPUT = "input"
        private const val TAG_RESULTS = "results"
    }
}