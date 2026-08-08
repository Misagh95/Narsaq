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
import com.google.android.material.bottomnavigation.BottomNavigationView
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

    /**
     * Guards against re-entrancy: setting `selectedItemId` fires the
     * item-selected listener synchronously, and the showXIfNeeded helpers
     * re-set the id while their fragment transaction is still pending
     * (commits are async). Without a guard this recurses forever and the app
     * dies with a StackOverflowError on startup.
     */
    private var navSyncing = false

    override fun onCreate(savedInstanceState: Bundle?) {
        NightModeStore.apply(applicationContext)
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.bottomNav.setOnItemSelectedListener { item ->
            if (navSyncing) {
                true
            } else {
                when (item.itemId) {
                    R.id.nav_input -> { showInputIfNeeded(lastScannedIps); true }
                    R.id.nav_scanner -> { showScanIfNeeded(); true }
                    R.id.nav_results -> { showResultsIfNeeded(); true }
                    else -> false
                }
            }
        }

        if (savedInstanceState == null) {
            binding.bottomNav.selectedItemId = R.id.nav_scanner
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
    NightModeStore.toggle(this)
}

    fun isNightModeActive(): Boolean =
    NightModeStore.isNightEnabled(this)

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
        selectNavItem(R.id.nav_input)
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
        selectNavItem(R.id.nav_scanner)
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
        selectNavItem(R.id.nav_input)
    }

    private fun showResultsIfNeeded() {
        if (currentIsResults()) return
        if (supportFragmentManager.isStateSaved) return

        supportFragmentManager.beginTransaction()
            .replace(R.id.fragmentContainer, ResultsFragment(), TAG_RESULTS)
            .commit()
        selectNavItem(R.id.nav_results)
    }

    /**
     * Programmatically selects a bottom-nav item without re-entering the
     * item-selected listener (the listener ignores events while syncing).
     */
    private fun selectNavItem(itemId: Int) {
        if (navSyncing) return
        navSyncing = true
        try {
            binding.bottomNav.selectedItemId = itemId
        } finally {
            navSyncing = false
        }
    }

    companion object {
        private const val TAG_SCAN = "scan"
        private const val TAG_INPUT = "input"
        private const val TAG_RESULTS = "results"
    }
}
