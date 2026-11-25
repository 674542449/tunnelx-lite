package com.txlite.android

import android.app.Application
import com.txlite.android.core.CoreBridge
import java.io.File

class TxliteApp : Application() {
    override fun onCreate() {
        super.onCreate()
        val dataDir = File(filesDir, "txlite").apply { mkdirs() }.absolutePath
        CoreBridge.ensureInit(dataDir)
    }
}
