package com.txlite.android.core

import android.content.Context

data class PerAppConfig(
    val mode: String = MODE_ALL,
    val packages: Set<String> = emptySet(),
) {
    companion object {
        const val MODE_ALL = "all"
        const val MODE_BYPASS = "bypass"
        const val MODE_ONLY = "only"
    }
}

object PerAppPrefs {
    private const val PREFS_NAME = "txlite_per_app"
    private const val KEY_MODE = "mode"
    private const val KEY_PACKAGES = "packages"

    fun load(context: Context): PerAppConfig {
        val sp = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val mode = sp.getString(KEY_MODE, PerAppConfig.MODE_ALL) ?: PerAppConfig.MODE_ALL
        val pkgs = sp.getStringSet(KEY_PACKAGES, emptySet())?.toSet() ?: emptySet()
        return PerAppConfig(
            mode = if (mode in setOf(PerAppConfig.MODE_ALL, PerAppConfig.MODE_BYPASS, PerAppConfig.MODE_ONLY)) mode else PerAppConfig.MODE_ALL,
            packages = pkgs,
        )
    }

    fun save(context: Context, cfg: PerAppConfig) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_MODE, cfg.mode)
            .putStringSet(KEY_PACKAGES, cfg.packages)
            .apply()
    }
}
