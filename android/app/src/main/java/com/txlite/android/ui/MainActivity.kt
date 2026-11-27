package com.txlite.android.ui

import android.Manifest
import android.content.ClipboardManager
import android.content.ClipData
import android.content.Context
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.ui.res.painterResource
import com.txlite.android.R
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.txlite.android.core.CoreBridge
import com.txlite.android.core.EngineStatus
import com.txlite.android.core.ProbeResultItem
import com.txlite.android.core.ServerItem
import com.txlite.android.core.SiteCheckEntry
import com.txlite.android.core.SiteCheckReport
import com.txlite.android.vpn.TxliteVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private val LightColors = lightColorScheme(
    primary = Color(0xFF2563EB),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFDBEAFE),
    onPrimaryContainer = Color(0xFF1E3A8A),
    secondary = Color(0xFF059669),
    secondaryContainer = Color(0xFFD1FAE5),
    onSecondaryContainer = Color(0xFF065F46),
    error = Color(0xFFDC2626),
    errorContainer = Color(0xFFFEE2E2),
    onErrorContainer = Color(0xFF991B1B),
    background = Color(0xFFF4F6FA),
    surface = Color(0xFFFFFFFF),
    surfaceVariant = Color(0xFFEEF2F8),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF4F86F7),
    onPrimary = Color(0xFF0A192F),
    primaryContainer = Color(0xFF1E3354),
    onPrimaryContainer = Color(0xFFDBEAFE),
    secondary = Color(0xFF34D399),
    secondaryContainer = Color(0xFF064E3B),
    onSecondaryContainer = Color(0xFFD1FAE5),
    error = Color(0xFFF87171),
    errorContainer = Color(0xFF450A0A),
    onErrorContainer = Color(0xFFFECACA),
    background = Color(0xFF0F1218),
    surface = Color(0xFF181D27),
    surfaceVariant = Color(0xFF202634),
)

class MainActivity : ComponentActivity() {

    private var pendingConnectId: String? = null
    private var onQrResult: ((String) -> Unit)? = null
    private var onToastMessage: ((String) -> Unit)? = null

    private val vpnConsentLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val id = pendingConnectId
        pendingConnectId = null
        if (result.resultCode == RESULT_OK && !id.isNullOrEmpty()) {
            TxliteVpnService.start(applicationContext, id)
        } else {
            onToastMessage?.invoke("未授予 VPN 权限，无法启动接管")
        }
    }

    private val notifPermLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* optional notification permission */ }

    private val qrLauncher = registerForActivityResult(ScanContract()) { result ->
        val text = result.contents
        if (!text.isNullOrBlank()) {
            onQrResult?.invoke(text)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        setContent {
            val colors = if (isSystemInDarkTheme()) DarkColors else LightColors
            MaterialTheme(colorScheme = colors) {
                TxliteRootApp(
                    onStartVpn = { nodeId -> requestStartVpn(nodeId) },
                    onStopVpn = { TxliteVpnService.stop(applicationContext) },
                    onLaunchQr = { callback ->
                        onQrResult = callback
                        val opts = ScanOptions().apply {
                            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                            setPrompt("对准服务器面板生成的 txlite:// 或 txpulse:// 二维码")
                            setBeepEnabled(false)
                            setOrientationLocked(false)
                        }
                        qrLauncher.launch(opts)
                    },
                    onBindToast = { fn -> onToastMessage = fn },
                )
            }
        }
    }

    private fun requestStartVpn(nodeId: String) {
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            pendingConnectId = nodeId
            vpnConsentLauncher.launch(prepareIntent)
        } else {
            TxliteVpnService.start(applicationContext, nodeId)
        }
    }
}

@Composable
private fun TxliteRootApp(
    onStartVpn: (String) -> Unit,
    onStopVpn: () -> Unit,
    onLaunchQr: ((String) -> Unit) -> Unit,
    onBindToast: ((String) -> Unit) -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    val vpnEvent by TxliteVpnService.state.collectAsState()

    var activeTab by remember { mutableIntStateOf(0) }
    var status by remember { mutableStateOf(EngineStatus()) }
    var servers by remember { mutableStateOf<List<ServerItem>>(emptyList()) }
    var selectedId by remember { mutableStateOf("") }
    var probes by remember { mutableStateOf<Map<String, ProbeResultItem>>(emptyMap()) }
    var probingIds by remember { mutableStateOf<Set<String>>(emptySet()) }
    var busy by remember { mutableStateOf(false) }

    // Split-routing & IP check state
    var checkReport by remember { mutableStateOf<SiteCheckReport?>(null) }
    var customChecks by remember { mutableStateOf<List<SiteCheckEntry>>(emptyList()) }
    var checkBusy by remember { mutableStateOf(false) }

    fun showMessage(msg: String) {
        scope.launch {
            snackbar.currentSnackbarData?.dismiss()
            snackbar.showSnackbar(msg)
        }
    }

    LaunchedEffect(Unit) {
        onBindToast { showMessage(it) }
    }

    LaunchedEffect(vpnEvent.lastError) {
        if (vpnEvent.lastError.isNotBlank()) {
            showMessage("连接失败：${vpnEvent.lastError}")
        }
    }

    suspend fun refreshState() {
        val pair = withContext(Dispatchers.IO) {
            runCatching { CoreBridge.status() to CoreBridge.servers() }.getOrNull()
        } ?: return
        status = pair.first
        servers = pair.second
        if (servers.none { it.id == selectedId }) {
            selectedId = status.selectedId.takeIf { id -> servers.any { it.id == id } }
                ?: servers.firstOrNull()?.id.orEmpty()
        }
    }

    LaunchedEffect(Unit) {
        while (true) {
            refreshState()
            delay(1000L)
        }
    }

    fun importText(text: String) {
        if (text.isBlank()) {
            showMessage("内容为空，未找到 txlite:// 或 txpulse:// 链接")
            return
        }
        scope.launch {
            busy = true
            try {
                val res = withContext(Dispatchers.IO) { CoreBridge.importLinks(text) }
                refreshState()
                val msg = "导入成功：新增 ${res.added} 个" + if (res.updated > 0) "，更新 ${res.updated} 个" else ""
                showMessage(msg)
            } catch (e: Throwable) {
                showMessage(e.message ?: "导入失败")
            } finally {
                busy = false
            }
        }
    }

    fun copyToClipboard(label: String, value: String) {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText(label, value))
    }

    fun readClipboard(): String {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        return cm.primaryClip?.getItemAt(0)?.coerceToText(context)?.toString().orEmpty()
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbar) },
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    selected = activeTab == 0,
                    onClick = { activeTab = 0 },
                    icon = { Icon(painterResource(R.drawable.ic_tab_nodes), contentDescription = "节点") },
                    label = { Text("节点") },
                )
                NavigationBarItem(
                    selected = activeTab == 1,
                    onClick = { activeTab = 1 },
                    icon = { Icon(painterResource(R.drawable.ic_tab_check), contentDescription = "分流检测") },
                    label = { Text("分流检测") },
                )
                NavigationBarItem(
                    selected = activeTab == 2,
                    onClick = { activeTab = 2 },
                    icon = { Icon(painterResource(R.drawable.ic_tab_apps), contentDescription = "分应用") },
                    label = { Text("分应用") },
                )
                NavigationBarItem(
                    selected = activeTab == 3,
                    onClick = { activeTab = 3 },
                    icon = { Icon(Icons.Rounded.Settings, contentDescription = "设置") },
                    label = { Text("设置") },
                )
            }
        },
    ) { innerPadding ->
        Box(modifier = Modifier.padding(innerPadding)) {
            when (activeTab) {
                0 -> NodesScreen(
                    status = status,
                    vpnEvent = vpnEvent,
                    servers = servers,
                    selectedId = selectedId,
                    probes = probes,
                    probingIds = probingIds,
                    busy = busy,
                    onSelect = { id ->
                        selectedId = id
                        scope.launch(Dispatchers.IO) { runCatching { CoreBridge.selectServer(id) } }
                    },
                    onToggleConnect = {
                        if (vpnEvent.running || vpnEvent.connecting || status.connected) {
                            onStopVpn()
                        } else if (selectedId.isNotEmpty()) {
                            scope.launch {
                                withContext(Dispatchers.IO) { runCatching { CoreBridge.selectServer(selectedId) } }
                                onStartVpn(selectedId)
                            }
                        } else {
                            showMessage("请先导入并选择一个节点")
                        }
                    },
                    onSwitchMode = { nextMode ->
                        scope.launch {
                            try {
                                withContext(Dispatchers.IO) {
                                    CoreBridge.saveProxyMode(nextMode, status.directDomains.joinToString("\n"))
                                }
                                refreshState()
                                val label = if (nextMode == "global") "全局代理（单 IPv4）" else "绕过大陆"
                                showMessage("已切换为「$label」" + if (status.connected) "，旧连接已重置" else "")
                            } catch (e: Throwable) {
                                showMessage(e.message ?: "切换失败")
                            }
                        }
                    },
                    onScanQr = { onLaunchQr { scanned -> importText(scanned) } },
                    onImportClipboard = { importText(readClipboard()) },
                    onImportManual = { text -> importText(text) },
                    onProbeOne = { id ->
                        scope.launch {
                            probingIds = probingIds + id
                            val item = withContext(Dispatchers.IO) {
                                runCatching { ProbeResultItem(id, CoreBridge.probe(id)) }
                                    .getOrElse { ProbeResultItem(id, -1L, it.message ?: "失败") }
                            }
                            probes = probes + (id to item)
                            probingIds = probingIds - id
                        }
                    },
                    onProbeAll = {
                        scope.launch {
                            probingIds = servers.map { it.id }.toSet()
                            val list = withContext(Dispatchers.IO) { runCatching { CoreBridge.probeAll() }.getOrDefault(emptyList()) }
                            probes = probes + list.associateBy { it.id }
                            probingIds = emptySet()
                            val ok = list.count { it.error.isEmpty() && it.ms > 0 }
                            showMessage("测速完成：$ok / ${list.size} 个可用")
                        }
                    },
                    onCopyLink = { id ->
                        scope.launch {
                            runCatching { withContext(Dispatchers.IO) { CoreBridge.shareLink(id) } }
                                .onSuccess {
                                    copyToClipboard("txlite", it)
                                    showMessage("已复制分享链接")
                                }
                                .onFailure { showMessage(it.message ?: "复制失败") }
                        }
                    },
                    onRename = { id, newName ->
                        scope.launch {
                            runCatching { withContext(Dispatchers.IO) { CoreBridge.rename(id, newName) } }
                                .onSuccess {
                                    refreshState()
                                    showMessage("已重命名")
                                }
                                .onFailure { showMessage(it.message ?: "重命名失败") }
                        }
                    },
                    onRemove = { id ->
                        scope.launch {
                            runCatching { withContext(Dispatchers.IO) { CoreBridge.remove(id) } }
                                .onSuccess {
                                    probes = probes - id
                                    refreshState()
                                    showMessage("已删除节点")
                                }
                                .onFailure { showMessage(it.message ?: "删除失败") }
                        }
                    },
                )

                1 -> CheckScreen(
                    status = status,
                    report = checkReport,
                    customItems = customChecks,
                    busy = checkBusy,
                    onRunAll = {
                        scope.launch {
                            checkBusy = true
                            try {
                                checkReport = withContext(Dispatchers.IO) { CoreBridge.checkSites() }
                                showMessage("常见网站分流与出口 IP 检测完成")
                            } catch (e: Throwable) {
                                showMessage(e.message ?: "检测失败")
                            } finally {
                                checkBusy = false
                            }
                        }
                    },
                    onCheckCustom = { raw ->
                        scope.launch {
                            checkBusy = true
                            try {
                                val item = withContext(Dispatchers.IO) { CoreBridge.checkDomain(raw) }
                                customChecks = (listOf(item) + customChecks.filterNot { it.domain == item.domain }).take(12)
                                val dir = if (item.route == "direct") "直连" else "代理"
                                showMessage("${item.domain} → $dir（${item.rule}）")
                            } catch (e: Throwable) {
                                showMessage(e.message ?: "域名检测失败")
                            } finally {
                                checkBusy = false
                            }
                        }
                    },
                )

                2 -> AppsScreen(
                    connected = vpnEvent.running || status.connected,
                    onSaved = { msg -> showMessage(msg) },
                )

                3 -> SettingsScreen(
                    status = status,
                    connected = vpnEvent.running || vpnEvent.connecting || status.connected,
                    onSaveTransport = { t ->
                        scope.launch {
                            runCatching { withContext(Dispatchers.IO) { CoreBridge.saveTransport(t) } }
                                .onSuccess {
                                    refreshState()
                                    showMessage("传输模式已保存，下次连接生效")
                                }
                                .onFailure { showMessage(it.message ?: "保存失败") }
                        }
                    },
                    onSaveDirectDomains = { domains ->
                        scope.launch {
                            runCatching { withContext(Dispatchers.IO) { CoreBridge.saveProxyMode(status.proxyMode, domains) } }
                                .onSuccess {
                                    refreshState()
                                    showMessage("直连例外已保存" + if (status.connected) "并立即生效" else "")
                                }
                                .onFailure { showMessage(it.message ?: "保存失败") }
                        }
                    },
                    onUpdateRules = {
                        scope.launch {
                            showMessage("正在下载最新 MetaCubeX 分流规则…")
                            runCatching { withContext(Dispatchers.IO) { CoreBridge.updateRoutingRules() } }
                                .onSuccess {
                                    refreshState()
                                    showMessage("分流规则已更新")
                                }
                                .onFailure { showMessage(it.message ?: "规则更新失败") }
                        }
                    },
                    onSaveDns = { enabled, domestic, remote ->
                        scope.launch {
                            runCatching { withContext(Dispatchers.IO) { CoreBridge.saveDns(enabled, domestic, remote) } }
                                .onSuccess {
                                    refreshState()
                                    showMessage("防污染 DNS 配置已保存" + if (status.connected) "并立即生效" else "")
                                }
                                .onFailure { showMessage(it.message ?: "DNS 保存失败") }
                        }
                    },
                )
            }
        }
    }
}
