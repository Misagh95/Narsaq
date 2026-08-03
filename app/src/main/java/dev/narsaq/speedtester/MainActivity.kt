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
import dev.narsaq.speedtester.util.NightModeStore
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        NightModeStore.apply(applicationContext)
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        if (savedInstanceState == null) {
            showInput()
        }

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.state.collect { state ->
                    if (state.phase == Phase.IDLE) showInputIfNeeded() else showResultsIfNeeded()
                }
            }
        }

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (currentIsResults()) {
                    viewModel.reset()
                } else {
                    isEnabled = false
                    onBackPressedDispatcher.onBackPressed()
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

    private fun currentIsResults(): Boolean =
        supportFragmentManager.findFragmentById(R.id.fragmentContainer) is ResultsFragment

    private fun showInput() {
        supportFragmentManager.beginTransaction()
            .replace(R.id.fragmentContainer, InputFragment(), TAG_INPUT)
            .commit()
    }

    private fun showInputIfNeeded() {
        if (supportFragmentManager.findFragmentById(R.id.fragmentContainer) is InputFragment) return
        if (supportFragmentManager.isStateSaved) return
        showInput()
    }

    private fun showResultsIfNeeded() {
        if (supportFragmentManager.findFragmentById(R.id.fragmentContainer) is ResultsFragment) return
        if (supportFragmentManager.isStateSaved) return
        supportFragmentManager.beginTransaction()
            .replace(R.id.fragmentContainer, ResultsFragment(), TAG_RESULTS)
            .commit()
    }

    companion object {
        private const val TAG_INPUT = "input"
        private const val TAG_RESULTS = "results"
    }
}
