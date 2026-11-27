package com.txlite.android.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.txlite.android.R
import com.txlite.android.core.CoreBridge
import com.txlite.android.core.PerAppConfig
import com.txlite.android.core.PerAppPrefs
import com.txlite.android.core.formatBytes
import com.txlite.android.ui.MainActivity
import hev.htproxy.TProxyService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.File

data class VpnRuntimeEvent(
    val running: Boolean = false,
    val connecting: Boolean = false,
    val lastError: String = "",
)

class TxliteVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.txlite.android.vpn.START"
        const val ACTION_STOP = "com.txlite.android.vpn.STOP"
        const val EXTRA_NODE_ID = "node_id"

        private const val CHANNEL_ID = "txlite_vpn_channel"
        private const val NOTIF_ID = 1001

        private val _state = MutableStateFlow(VpnRuntimeEvent())
        val state: StateFlow<VpnRuntimeEvent> = _state

        fun start(context: Context, nodeId: String) {
            val intent = Intent(context, TxliteVpnService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_NODE_ID, nodeId)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            val intent = Intent(context, TxliteVpnService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tunPfd: ParcelFileDescriptor? = null
    private var workJob: Job? = null
    private var notifJob: Job? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpnSession()
                return START_NOT_STICKY
            }
            ACTION_START -> {
                val nodeId = intent.getStringExtra(EXTRA_NODE_ID).orEmpty()
                if (nodeId.isNotEmpty()) {
                    startVpnSession(nodeId)
                }
            }
        }
        return START_STICKY
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            val channel = NotificationChannel(
                CHANNEL_ID,
                "txlite VPN 连接状态",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "显示当前节点连接状态与实时传输速率"
                setShowBadge(false)
            }
            nm.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(title: String, content: String): Notification {
        ensureChannel()
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, TxliteVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_vpn_tile)
            .setContentTitle(title)
            .setContentText(content)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(openIntent)
            .addAction(0, "断开连接", stopIntent)
            .build()
    }

    private fun promoteForeground(title: String, content: String) {
        val notif = buildNotification(title, content)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, notif)
        }
    }

    private fun collectPhysicalDnsServers(): List<String> {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return emptyList()
        val active = cm.activeNetwork ?: return emptyList()
        val lp = cm.getLinkProperties(active) ?: return emptyList()
        return extractDns(lp)
    }

    private fun extractDns(lp: LinkProperties): List<String> {
        return lp.dnsServers
            .mapNotNull { it.hostAddress }
            .filter { addr ->
                addr.isNotBlank() &&
                    !addr.startsWith("127.") &&
                    addr != "::1" &&
                    !addr.startsWith("198.18.") &&
                    !addr.startsWith("fd01:198:18:")
            }
            .distinct()
    }

    private fun startVpnSession(nodeId: String) {
        promoteForeground("txlite 正在连接", "建立加密隧道与虚拟网卡…")
        workJob?.cancel()
        workJob = scope.launch {
            _state.value = VpnRuntimeEvent(running = false, connecting = true, lastError = "")
            try {
                // Clean any previous session cleanly before establishing a new one.
                tearDownTunnelOnly()
                runCatching { CoreBridge.disconnect() }

                val dnsList = collectPhysicalDnsServers()
                CoreBridge.connect(nodeId, dnsList)

                val pfd = establishTun()
                    ?: throw IllegalStateException("系统未授予 VPN 虚拟网卡权限")
                tunPfd = pfd

                val cfgFile = writeHevConfig()
                val ok = TProxyService.TProxyStartService(cfgFile.absolutePath, pfd.fd)
                if (!ok) {
                    throw IllegalStateException("TUN 网络栈启动失败")
                }

                registerNetworkWatcher()
                _state.value = VpnRuntimeEvent(running = true, connecting = false, lastError = "")
                TxliteTileService.requestRefresh(applicationContext)
                startNotificationTicker()
            } catch (e: Throwable) {
                tearDownTunnelOnly()
                runCatching { CoreBridge.disconnect() }
                _state.value = VpnRuntimeEvent(
                    running = false,
                    connecting = false,
                    lastError = e.message ?: "连接失败",
                )
                TxliteTileService.requestRefresh(applicationContext)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private fun establishTun(): ParcelFileDescriptor? {
        val perApp = PerAppPrefs.load(applicationContext)
        val builder = Builder()
            .setSession("txlite")
            .setMtu(8500)
            .addAddress("198.18.77.1", 30)
            .addRoute("0.0.0.0", 0)
            .addAddress("fd01:198:18::1", 126)
            .addRoute("::", 0)
            .addDnsServer("1.1.1.1")
            .addDnsServer("8.8.8.8")

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        when (perApp.mode) {
            PerAppConfig.MODE_ONLY -> {
                val allowed = perApp.packages.filter { it != packageName }
                if (allowed.isEmpty()) {
                    // Fallback to standard all-except-self when no app was picked.
                    runCatching { builder.addDisallowedApplication(packageName) }
                } else {
                    for (pkg in allowed) {
                        runCatching { builder.addAllowedApplication(pkg) }
                    }
                }
            }
            PerAppConfig.MODE_BYPASS -> {
                runCatching { builder.addDisallowedApplication(packageName) }
                for (pkg in perApp.packages) {
                    if (pkg != packageName) {
                        runCatching { builder.addDisallowedApplication(pkg) }
                    }
                }
            }
            else -> {
                // Always exclude txlite itself so tunnel & direct CN dials never loop.
                runCatching { builder.addDisallowedApplication(packageName) }
            }
        }
        return builder.establish()
    }

    private fun writeHevConfig(): File {
        val file = File(cacheDir, "hev-socks5-tunnel.yml")
        val yaml = """
            tunnel:
              mtu: 8500
              ipv4: 198.18.77.1
              ipv6: 'fd01:198:18::1'
            socks5:
              port: ${CoreBridge.SOCKS_PORT}
              address: '${CoreBridge.SOCKS_HOST}'
              udp: 'udp'
            misc:
              tcp-buffer-size: 131072
              udp-recv-buffer-size: 524288
              connect-timeout: 10000
              tcp-read-write-timeout: 300000
              udp-read-write-timeout: 60000
              log-level: warn
        """.trimIndent() + "\n"
        file.writeText(yaml, Charsets.UTF_8)
        return file
    }

    private fun registerNetworkWatcher() {
        unregisterNetworkWatcher()
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        var lastNetHandle: Long? = null
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val handle = network.networkHandle
                if (lastNetHandle != null && lastNetHandle != handle) {
                    // Wi-Fi <-> 5G 切换时主动触发 TXPulse 无缝连接迁移
                    CoreBridge.migrateNetwork()
                }
                lastNetHandle = handle
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                val dns = extractDns(linkProperties)
                if (dns.isNotEmpty()) {
                    CoreBridge.updateDns(dns)
                }
            }
        }
        runCatching {
            cm.registerDefaultNetworkCallback(cb)
            networkCallback = cb
        }
    }

    private fun unregisterNetworkWatcher() {
        val cb = networkCallback ?: return
        networkCallback = null
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        runCatching { cm.unregisterNetworkCallback(cb) }
    }

    private fun startNotificationTicker() {
        notifJob?.cancel()
        notifJob = scope.launch {
            val nm = getSystemService(NotificationManager::class.java)
            while (isActive && _state.value.running) {
                runCatching {
                    val st = CoreBridge.status()
                    val modeText = if (st.proxyMode == "global") "全局单 IPv4" else "绕过大陆"
                    val proto = st.activeTransport.uppercase()
                    val title = "${st.nodeName.ifBlank { "txlite" }} · $proto · $modeText"
                    val text = "↑ ${formatBytes(st.uploadRate)}/s   ↓ ${formatBytes(st.downloadRate)}/s"
                    nm.notify(NOTIF_ID, buildNotification(title, text))
                }
                delay(1500L)
            }
        }
    }

    private fun tearDownTunnelOnly() {
        notifJob?.cancel()
        notifJob = null
        unregisterNetworkWatcher()
        runCatching {
            if (TProxyService.TProxyIsRunning()) {
                TProxyService.TProxyStopService()
            }
        }
        runCatching { tunPfd?.close() }
        tunPfd = null
    }

    private fun stopVpnSession() {
        workJob?.cancel()
        CoreBridge.cancelConnect()
        scope.launch {
            tearDownTunnelOnly()
            runCatching { CoreBridge.disconnect() }
            _state.value = VpnRuntimeEvent(running = false, connecting = false, lastError = "")
            TxliteTileService.requestRefresh(applicationContext)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    override fun onRevoke() {
        stopVpnSession()
        super.onRevoke()
    }

    override fun onDestroy() {
        tearDownTunnelOnly()
        runCatching { CoreBridge.disconnect() }
        _state.value = VpnRuntimeEvent(running = false, connecting = false, lastError = "")
        scope.cancel()
        super.onDestroy()
    }
}
