package dev.narsaq.speedtester.util

import android.content.Context
import androidx.appcompat.app.AppCompatDelegate

object NightModeStore {

    private const val PREFS = "narsaq_prefs"
    private const val KEY_NIGHT = "night_mode"

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun getSavedMode(context: Context): Int {
        return prefs(context).getInt(
            KEY_NIGHT,
            AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
        )
    }

    fun isNightEnabled(context: Context): Boolean {
        return when (getSavedMode(context)) {
            AppCompatDelegate.MODE_NIGHT_YES -> true
            AppCompatDelegate.MODE_NIGHT_NO -> false
            else -> {
                val mask = android.content.res.Configuration.UI_MODE_NIGHT_MASK
                val yes = android.content.res.Configuration.UI_MODE_NIGHT_YES
                (context.resources.configuration.uiMode and mask) == yes
            }
        }
    }

    fun apply(context: Context) {
        AppCompatDelegate.setDefaultNightMode(getSavedMode(context))
    }

    fun setMode(context: Context, mode: Int) {
        prefs(context).edit().putInt(KEY_NIGHT, mode).apply()
        AppCompatDelegate.setDefaultNightMode(mode)
    }

    fun toggle(context: Context) {
        val next = if (isNightEnabled(context)) {
            AppCompatDelegate.MODE_NIGHT_NO
        } else {
            AppCompatDelegate.MODE_NIGHT_YES
        }
        setMode(context, next)
    }
}