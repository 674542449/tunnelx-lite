package com.txlite.android.ui

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.txlite.android.core.PerAppConfig
import com.txlite.android.core.PerAppPrefs
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private data class InstalledAppEntry(
    val label: String,
    val pkg: String,
    val isSystem: Boolean,
)

@Composable
fun AppsScreen(
    connected: Boolean,
    onSaved: (String) -> Unit,
) {
    val context = LocalContext.current
    var cfg by remember { mutableStateOf(PerAppPrefs.load(context)) }
    var apps by remember { mutableStateOf<List<InstalledAppEntry>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var query by remember { mutableStateOf("") }
    var showSystem by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        loading = true
        apps = withContext(Dispatchers.IO) {
            val pm = context.packageManager
            val selfPkg = context.packageName
            @Suppress("DEPRECATION")
            val installed = pm.getInstalledApplications(PackageManager.GET_META_DATA)
            installed
                .filter { it.packageName != selfPkg }
                .map { info ->
                    val label = runCatching { pm.getApplicationLabel(info).toString() }.getOrDefault(info.packageName)
                    val sys = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                    InstalledAppEntry(label = label, pkg = info.packageName, isSystem = sys)
                }
                .sortedWith(compareBy<InstalledAppEntry> { it.isSystem }.thenBy { it.label.lowercase() })
        }
        loading = false
    }

    fun persist(next: PerAppConfig, toast: String? = null) {
        cfg = next
        PerAppPrefs.save(context, next)
        if (toast != null) {
            onSaved(toast + if (connected) "（请重新连接 VPN 生效）" else "")
        }
    }

    val visibleApps = remember(apps, query, showSystem, cfg.packages) {
        val q = query.trim().lowercase()
        apps.filter { app ->
            (showSystem || !app.isSystem || app.pkg in cfg.packages) &&
                (q.isEmpty() || app.label.lowercase().contains(q) || app.pkg.lowercase().contains(q))
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        item {
            Column {
                Text("分应用代理", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                Text(
                    "控制哪些应用经过 VPN 虚拟网卡（txlite 自身已自动排除防环路）",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        item {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                val modes = listOf(
                    PerAppConfig.MODE_ALL to "全部接管",
                    PerAppConfig.MODE_BYPASS to "绕过所选",
                    PerAppConfig.MODE_ONLY to "仅代理所选",
                )
                modes.forEach { (m, label) ->
                    FilterChip(
                        selected = cfg.mode == m,
                        onClick = { persist(cfg.copy(mode = m), "分应用模式已切换为「$label」") },
                        label = { Text(label) },
                    )
                }
            }
        }

        if (cfg.mode == PerAppConfig.MODE_ALL) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                ) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text("当前为「全部接管」模式", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                        Text(
                            "本机除 txlite 外的所有应用流量都将进入 VPN，并按「绕过大陆」或「全局代理」规则处理。如需让银行/国内 App 直接不经 VPN，可切换上方「绕过所选」并勾选对应应用。",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        } else {
            item {
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    placeholder = { Text("搜索应用名称或包名") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }

            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Switch(checked = showSystem, onCheckedChange = { showSystem = it })
                        Text("显示系统应用", style = MaterialTheme.typography.bodySmall)
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("已选 ${cfg.packages.size}", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                        if (cfg.packages.isNotEmpty()) {
                            TextButton(onClick = { persist(cfg.copy(packages = emptySet()), "已清空所选应用") }) {
                                Text("清空")
                            }
                        }
                    }
                }
            }

            if (loading) {
                item { LinearProgressIndicator(modifier = Modifier.fillMaxWidth()) }
            } else {
                items(visibleApps, key = { it.pkg }) { app ->
                    val checked = app.pkg in cfg.packages
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                val next = if (checked) cfg.packages - app.pkg else cfg.packages + app.pkg
                                persist(cfg.copy(packages = next))
                            },
                        shape = RoundedCornerShape(12.dp),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 12.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Checkbox(
                                checked = checked,
                                onCheckedChange = { isChecked ->
                                    val next = if (isChecked) cfg.packages + app.pkg else cfg.packages - app.pkg
                                    persist(cfg.copy(packages = next))
                                },
                            )
                            Column(modifier = Modifier.weight(1f)) {
                                Text(app.label, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                Text(app.pkg, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }
                        }
                    }
                }
            }
        }
    }
}
