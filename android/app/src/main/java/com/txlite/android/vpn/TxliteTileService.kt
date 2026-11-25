package com.txlite.android.vpn

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.txlite.android.core.CoreBridge
import com.txlite.android.ui.MainActivity

class TxliteTileService : TileService() {

    companion object {
        fun requestRefresh(context: Context) {
            runCatching {
                requestListeningState(context, ComponentName(context, TxliteTileService::class.java))
            }
        }
    }

    override fun onStartListening() {
        super.onStartListening()
        syncTile()
    }

    override fun onClick() {
        super.onClick()
        val cur = TxliteVpnService.state.value
        if (cur.running || cur.connecting) {
            TxliteVpnService.stop(applicationContext)
            syncTile()
            return
        }
        if (VpnService.prepare(applicationContext) != null) {
            // Need interactive VPN consent dialog: open MainActivity.
            val intent = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                val pi = android.app.PendingIntent.getActivity(
                    this,
                    2,
                    intent,
                    android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE,
                )
                startActivityAndCollapse(pi)
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(intent)
            }
            return
        }
        val st = runCatching { CoreBridge.status() }.getOrNull()
        val id = st?.selectedId?.ifBlank {
            runCatching { CoreBridge.servers().firstOrNull()?.id }.getOrNull().orEmpty()
        }.orEmpty()
        if (id.isNotEmpty()) {
            TxliteVpnService.start(applicationContext, id)
        }
        syncTile()
    }

    private fun syncTile() {
        val tile = qsTile ?: return
        val cur = TxliteVpnService.state.value
        tile.state = when {
            cur.running -> Tile.STATE_ACTIVE
            cur.connecting -> Tile.STATE_UNAVAILABLE
            else -> Tile.STATE_INACTIVE
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = when {
                cur.running -> "已连接"
                cur.connecting -> "连接中"
                else -> "未连接"
            }
        }
        tile.updateTile()
    }
}
