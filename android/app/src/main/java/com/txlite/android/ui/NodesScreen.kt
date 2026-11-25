package com.txlite.android.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.ContentPaste
import androidx.compose.material.icons.rounded.MoreVert
import androidx.compose.material.icons.rounded.PowerSettingsNew
import androidx.compose.material.icons.rounded.QrCodeScanner
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.txlite.android.core.EngineStatus
import com.txlite.android.core.ProbeResultItem
import com.txlite.android.core.ServerItem
import com.txlite.android.core.formatBytes
import com.txlite.android.vpn.VpnRuntimeEvent

@Composable
fun NodesScreen(
    status: EngineStatus,
    vpnEvent: VpnRuntimeEvent,
    servers: List<ServerItem>,
    selectedId: String,
    probes: Map<String, ProbeResultItem>,
    probingIds: Set<String>,
    busy: Boolean,
    onSelect: (String) -> Unit,
    onToggleConnect: () -> Unit,
    onSwitchMode: (String) -> Unit,
    onScanQr: () -> Unit,
    onImportClipboard: () -> Unit,
    onImportManual: (String) -> Unit,
    onProbeOne: (String) -> Unit,
    onProbeAll: () -> Unit,
    onCopyLink: (String) -> Unit,
    onRename: (String, String) -> Unit,
    onRemove: (String) -> Unit,
) {
    var showManualDialog by remember { mutableStateOf(false) }
    var manualText by remember { mutableStateOf("") }
    var renameTarget by remember { mutableStateOf<ServerItem?>(null) }
    var renameText by remember { mutableStateOf("") }

    val isConnected = vpnEvent.running || status.connected
    val isConnecting = vpnEvent.connecting || status.connectionState == "connecting"
    val activeNode = servers.find { it.id == (if (isConnected || isConnecting) status.nodeId else selectedId) }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // Header
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column {
                    Text(
                        text = "txlite",
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold,
                    )
                    Text(
                        text = "${status.version} · 入口支持 IPv4/IPv6 · 落地仅 IPv4",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Surface(
                    shape = RoundedCornerShape(999.dp),
                    color = if (isConnected) MaterialTheme.colorScheme.secondaryContainer else MaterialTheme.colorScheme.surfaceVariant,
                ) {
                    val protoText = when {
                        isConnected && status.activeTransport == "vision" -> "VISION"
                        isConnected && status.activeTransport == "h2" -> "H2"
                        isConnected -> "TCP"
                        status.transportPreference == "h2" -> "H2"
                        else -> "VISION/TCP"
                    }
                    Text(
                        text = protoText,
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = if (isConnected) MaterialTheme.colorScheme.onSecondaryContainer else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        // Hero Connect + Mode Card
        item {
            Card(
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                            Box(
                                modifier = Modifier
                                    .size(10.dp)
                                    .clip(CircleShape)
                                    .background(
                                        when {
                                            isConnected -> Color(0xFF10B981)
                                            isConnecting -> Color(0xFFF59E0B)
                                            else -> MaterialTheme.colorScheme.outline
                                        }
                                    )
                            )
                            Spacer(Modifier.width(8.dp))
                            Column {
                                Text(
                                    text = when {
                                        isConnecting -> "正在建立安全隧道…"
                                        isConnected -> "已接管 · ${if (status.proxyMode == "global") "全局单 IPv4" else "绕过大陆"}"
                                        else -> "未连接"
                                    },
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.SemiBold,
                                )
                                Text(
                                    text = activeNode?.let { "${it.name} (${it.host}:${it.port})" } ?: "未选择服务器节点",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                        }
                    }

                    // Live telemetry strip
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(12.dp))
                            .background(MaterialTheme.colorScheme.surfaceVariant)
                            .padding(horizontal = 12.dp, vertical = 10.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Column {
                            Text("实时上传", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Text(
                                "${formatBytes(if (isConnected) status.uploadRate else 0)}/s",
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.SemiBold,
                                style = MaterialTheme.typography.bodyMedium,
                            )
                        }
                        Column {
                            Text("实时下载", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Text(
                                "${formatBytes(if (isConnected) status.downloadRate else 0)}/s",
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.SemiBold,
                                style = MaterialTheme.typography.bodyMedium,
                            )
                        }
                        Column(horizontalAlignment = Alignment.End) {
                            Text("累计流量", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Text(
                                formatBytes(if (isConnected) status.upload + status.download else 0),
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.SemiBold,
                                style = MaterialTheme.typography.bodyMedium,
                            )
                        }
                    }

                    // Orthogonal live-switchable routing mode
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(12.dp))
                            .background(MaterialTheme.colorScheme.surfaceVariant)
                            .padding(4.dp),
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        val modes = listOf("bypass_cn" to "绕过大陆（国内直连）", "global" to "全局代理（单 IPv4）")
                        modes.forEach { (key, label) ->
                            val selected = status.proxyMode == key
                            Surface(
                                modifier = Modifier
                                    .weight(1f)
                                    .clip(RoundedCornerShape(9.dp))
                                    .clickable(enabled = !isConnecting) {
                                        if (!selected) onSwitchMode(key)
                                    },
                                color = if (selected) MaterialTheme.colorScheme.surface else Color.Transparent,
                                tonalElevation = if (selected) 2.dp else 0.dp,
                            ) {
                                Text(
                                    text = label,
                                    modifier = Modifier.padding(vertical = 8.dp, horizontal = 6.dp),
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
                                    color = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                        }
                    }

                    // Main connect / disconnect CTA
                    Button(
                        onClick = onToggleConnect,
                        enabled = !busy && (isConnected || isConnecting || selectedId.isNotEmpty()),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(48.dp),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (isConnected || isConnecting) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
                        ),
                    ) {
                        Icon(Icons.Rounded.PowerSettingsNew, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = when {
                                isConnecting -> "取消连接"
                                isConnected -> "断开 VPN 连接"
                                else -> "一键连接 VPN"
                            },
                            fontWeight = FontWeight.SemiBold,
                        )
                    }
                }
            }
        }

        // Import & Probe action row
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                FilledTonalButton(
                    onClick = onScanQr,
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 10.dp),
                ) {
                    Icon(Icons.Rounded.QrCodeScanner, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("扫码", maxLines = 1)
                }
                FilledTonalButton(
                    onClick = onImportClipboard,
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 10.dp),
                ) {
                    Icon(Icons.Rounded.ContentPaste, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("剪贴板", maxLines = 1)
                }
                OutlinedButton(
                    onClick = { showManualDialog = true },
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 10.dp),
                ) {
                    Icon(Icons.Rounded.Add, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("手动", maxLines = 1)
                }
                OutlinedButton(
                    onClick = onProbeAll,
                    enabled = servers.isNotEmpty() && probingIds.isEmpty(),
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 10.dp),
                ) {
                    Icon(Icons.Rounded.Speed, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("测速", maxLines = 1)
                }
            }
        }

        item {
            Text(
                text = "服务器节点 (${servers.size})",
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        if (servers.isEmpty()) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text("还没有导入服务器", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        Text(
                            "点击上方「扫码」扫描服务端面板二维码，或复制 txlite:// 分享链接后点「剪贴板」即可一键导入。",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        } else {
            items(servers, key = { it.id }) { srv ->
                val isSelected = srv.id == selectedId
                val isLiveNode = isConnected && status.nodeId == srv.id
                val probe = probes[srv.id]
                val probing = srv.id in probingIds
                var menuOpen by remember { mutableStateOf(false) }

                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onSelect(srv.id) },
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = if (isSelected) MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.45f)
                        else MaterialTheme.colorScheme.surface
                    ),
                    border = BorderStroke(
                        width = if (isSelected || isLiveNode) 1.5.dp else 1.dp,
                        color = if (isLiveNode) MaterialTheme.colorScheme.secondary
                        else if (isSelected) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.outlineVariant,
                    ),
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(start = 14.dp, top = 12.dp, bottom = 12.dp, end = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                if (isLiveNode) {
                                    Box(
                                        modifier = Modifier
                                            .size(8.dp)
                                            .clip(CircleShape)
                                            .background(Color(0xFF10B981))
                                    )
                                }
                                Text(
                                    text = srv.name,
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.SemiBold,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                Text(
                                    text = "${srv.host}:${srv.port}",
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                    modifier = Modifier.weight(1f, fill = false),
                                )
                                Surface(
                                    shape = RoundedCornerShape(6.dp),
                                    color = MaterialTheme.colorScheme.surfaceVariant,
                                ) {
                                    Text(
                                        text = srv.family,
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                            }
                        }

                        // Latency pill
                        val latencyText = when {
                            probing -> "测速中"
                            probe == null -> "—"
                            probe.error.isNotEmpty() -> "超时"
                            else -> "${probe.ms} ms"
                        }
                        val latencyColor = when {
                            probing || probe == null -> MaterialTheme.colorScheme.onSurfaceVariant
                            probe.error.isNotEmpty() || probe.ms >= 450 -> MaterialTheme.colorScheme.error
                            probe.ms < 180 -> MaterialTheme.colorScheme.secondary
                            else -> Color(0xFFD97706)
                        }
                        Text(
                            text = latencyText,
                            style = MaterialTheme.typography.labelMedium,
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.SemiBold,
                            color = latencyColor,
                            modifier = Modifier.padding(horizontal = 6.dp),
                        )

                        Box {
                            IconButton(onClick = { menuOpen = true }) {
                                Icon(Icons.Rounded.MoreVert, contentDescription = "节点操作")
                            }
                            DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                                DropdownMenuItem(
                                    text = { Text("测试延迟") },
                                    onClick = { menuOpen = false; onProbeOne(srv.id) },
                                )
                                DropdownMenuItem(
                                    text = { Text("复制分享链接") },
                                    onClick = { menuOpen = false; onCopyLink(srv.id) },
                                )
                                DropdownMenuItem(
                                    text = { Text("重命名") },
                                    onClick = {
                                        menuOpen = false
                                        renameTarget = srv
                                        renameText = srv.name
                                    },
                                )
                                DropdownMenuItem(
                                    text = { Text("删除节点", color = MaterialTheme.colorScheme.error) },
                                    onClick = { menuOpen = false; onRemove(srv.id) },
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    if (showManualDialog) {
        AlertDialog(
            onDismissRequest = { showManualDialog = false },
            title = { Text("添加分享链接") },
            text = {
                OutlinedTextField(
                    value = manualText,
                    onValueChange = { manualText = it },
                    label = { Text("txlite:// 分享链接（可多行）") },
                    minLines = 3,
                    maxLines = 6,
                    modifier = Modifier.fillMaxWidth(),
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    val v = manualText
                    manualText = ""
                    showManualDialog = false
                    onImportManual(v)
                }) { Text("导入") }
            },
            dismissButton = {
                TextButton(onClick = { showManualDialog = false }) { Text("取消") }
            },
        )
    }

    renameTarget?.let { srv ->
        AlertDialog(
            onDismissRequest = { renameTarget = null },
            title = { Text("重命名节点") },
            text = {
                OutlinedTextField(
                    value = renameText,
                    onValueChange = { renameText = it },
                    label = { Text("节点名称") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    val name = renameText.trim()
                    renameTarget = null
                    if (name.isNotEmpty()) onRename(srv.id, name)
                }) { Text("保存") }
            },
            dismissButton = {
                TextButton(onClick = { renameTarget = null }) { Text("取消") }
            },
        )
    }
}
