package dev.narsaq.speedtester.util

import android.content.Context
import androidx.appcompat.app.AppCompatDelegate

object NightModeStore {

    private const val PREFS = "narsaq_prefs"
    private const val KEY_NIGHT = "night_mode"

    fun isNightUi(context: Context): Boolean {
        val mask = android.content.res.Configuration.UI_MODE_NIGHT_MASK
        val yes = android.content.res.Configuration.UI_MODE_NIGHT_YES
        return (context.resources.configuration.uiMode and mask) == yes
    }

    fun apply(context: Context) {
        val mode = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getInt(KEY_NIGHT, AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM)
        AppCompatDelegate.setDefaultNightMode(mode)
    }

    fun toggle(context: Context) {
        val next = if (isNightUi(context)) {
            AppCompatDelegate.MODE_NIGHT_NO
        } else {
            AppCompatDelegate.MODE_NIGHT_YES
        }
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putInt(KEY_NIGHT, next)
            .apply()
        AppCompatDelegate.setDefaultNightMode(next)
    }
}
