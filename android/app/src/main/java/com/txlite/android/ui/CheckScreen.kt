package com.txlite.android.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.txlite.android.core.EngineStatus
import com.txlite.android.core.SiteCheckEntry
import com.txlite.android.core.SiteCheckReport

@Composable
fun CheckScreen(
    status: EngineStatus,
    report: SiteCheckReport?,
    customItems: List<SiteCheckEntry>,
    busy: Boolean,
    onRunAll: () -> Unit,
    onCheckCustom: (String) -> Unit,
) {
    var category by remember { mutableStateOf("all") }
    var customInput by remember { mutableStateOf("") }

    val allItems = remember(report, customItems) {
        customItems + (report?.items ?: emptyList())
    }
    val filtered = remember(allItems, category) {
        allItems.filter { category == "all" || it.category == category || it.category == "custom" }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("分流与 IP 出口检查", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                    Text(
                        "实测本机直连 IPv4、节点落地 IPv4 与 19 个常见站分流",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Button(onClick = onRunAll, enabled = !busy) {
                    Icon(Icons.Rounded.Refresh, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text(if (busy) "检测中" else "一键检测")
                }
            }
        }

        if (busy) {
            item {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
        }

        // Exit IP 2x2 Summary Cards
        item {
            val ex = report?.exit
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    SummaryCard(
                        title = "本机直连 IPv4",
                        value = when {
                            ex == null -> "未检测"
                            ex.directIp.isNotEmpty() -> ex.directIp
                            else -> ex.directError.ifBlank { "获取失败" }
                        },
                        highlight = ex?.directIp?.isNotEmpty() == true,
                        mono = true,
                        modifier = Modifier.weight(1f),
                    )
                    SummaryCard(
                        title = "节点落地 IPv4",
                        value = when {
                            report == null -> "未检测"
                            !report.connected -> "未连接节点"
                            ex?.proxyIp?.isNotEmpty() == true -> ex.proxyIp
                            else -> ex?.proxyError?.ifBlank { "获取失败" } ?: "获取失败"
                        },
                        highlight = report?.connected == true && ex?.proxyIp?.isNotEmpty() == true,
                        mono = true,
                        modifier = Modifier.weight(1f),
                    )
                }
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    val v6Warn = report?.connected == true && ex?.proxyIpv6Blocked == false
                    SummaryCard(
                        title = "IPv6 落地防护",
                        value = when {
                            report == null || !report.connected -> "仅 IPv4 落地"
                            ex?.proxyIpv6Blocked == true -> "仅 IPv4（已阻断）"
                            else -> "旧服务端未阻断 IPv6"
                        },
                        highlight = report?.connected == true && ex?.proxyIpv6Blocked == true,
                        warn = v6Warn,
                        mono = false,
                        modifier = Modifier.weight(1f),
                    )
                    val directCount = allItems.count { it.route == "direct" }
                    val proxyCount = allItems.count { it.route == "proxy" }
                    val modeName = if ((report?.proxyMode ?: status.proxyMode) == "global") "全局" else "绕过大陆"
                    SummaryCard(
                        title = "分流汇总",
                        value = if (allItems.isEmpty()) "待检测" else "$modeName · 直连 $directCount / 代理 $proxyCount",
                        highlight = allItems.isNotEmpty(),
                        mono = false,
                        modifier = Modifier.weight(1f),
                    )
                }
            }
        }

        // Custom Domain Checker
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedTextField(
                    value = customInput,
                    onValueChange = { customInput = it },
                    placeholder = { Text("输入任意域名检查，如 cip.cc / netflix.com") },
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                )
                Button(
                    onClick = {
                        val v = customInput.trim()
                        if (v.isNotEmpty()) {
                            customInput = ""
                            onCheckCustom(v)
                        }
                    },
                    enabled = !busy && customInput.isNotBlank(),
                ) {
                    Icon(Icons.Rounded.Search, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("检查")
                }
            }
        }

        // Category filter chips
        item {
            LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                val cats = listOf("all" to "全部", "ip" to "测 IP 站点", "cn" to "国内常见", "global" to "海外常见")
                items(cats) { (key, label) ->
                    FilterChip(
                        selected = category == key,
                        onClick = { category = key },
                        label = { Text(label) },
                    )
                }
            }
        }

        if (filtered.isEmpty()) {
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
                        Text("点击「一键检测」开始实测", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        Text(
                            "支持检查当前是否只暴露唯一节点 IPv4，以及国内外常见网站实际走直连还是走节点。",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        } else {
            items(filtered, key = { "${it.category}:${it.domain}:${it.url}" }) { item ->
                SiteResultCard(item)
            }
        }
    }
}

@Composable
private fun SummaryCard(
    title: String,
    value: String,
    highlight: Boolean = false,
    warn: Boolean = false,
    mono: Boolean = false,
    modifier: Modifier = Modifier,
) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(title, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(
                text = value,
                style = MaterialTheme.typography.bodyMedium,
                fontFamily = if (mono) FontFamily.Monospace else FontFamily.Default,
                fontWeight = FontWeight.SemiBold,
                color = when {
                    warn -> MaterialTheme.colorScheme.error
                    highlight -> MaterialTheme.colorScheme.secondary
                    else -> MaterialTheme.colorScheme.onSurface
                },
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
private fun SiteResultCard(item: SiteCheckEntry) {
    val isLeak = item.verifiedIp && item.route == "proxy" && item.exitKind == "direct"
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        border = BorderStroke(
            width = if (isLeak) 1.5.dp else 1.dp,
            color = if (isLeak) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.outlineVariant,
        ),
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(item.name, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(item.domain, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                val statusText = when {
                    item.preview -> "规则预览"
                    item.ok -> "${item.latencyMs} ms"
                    else -> item.error.ifBlank { "失败" }
                }
                val statusColor = when {
                    item.preview -> MaterialTheme.colorScheme.onSurfaceVariant
                    !item.ok || item.latencyMs >= 700 -> MaterialTheme.colorScheme.error
                    item.latencyMs < 250 -> MaterialTheme.colorScheme.secondary
                    else -> Color(0xFFD97706)
                }
                Text(
                    text = statusText,
                    style = MaterialTheme.typography.labelMedium,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.SemiBold,
                    color = statusColor,
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                    Surface(
                        shape = RoundedCornerShape(999.dp),
                        color = if (item.route == "direct") MaterialTheme.colorScheme.secondaryContainer else MaterialTheme.colorScheme.primaryContainer,
                    ) {
                        Text(
                            text = if (item.route == "direct") "直连" else "代理",
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = if (item.route == "direct") MaterialTheme.colorScheme.onSecondaryContainer else MaterialTheme.colorScheme.onPrimaryContainer,
                        )
                    }
                    Text(item.rule, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }

                if (item.exitIp.isNotEmpty()) {
                    Row(horizontalArrangement = Arrangement.spacedBy(4.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text(item.exitIp, style = MaterialTheme.typography.labelSmall, fontFamily = FontFamily.Monospace)
                        val tag = when {
                            isLeak -> "分流异常"
                            item.exitKind == "proxy" -> if (item.verifiedIp) "实测节点" else "节点"
                            item.exitKind == "direct" -> if (item.verifiedIp) "实测本机" else "本机"
                            item.verifiedIp -> "实测"
                            else -> ""
                        }
                        if (tag.isNotEmpty()) {
                            Surface(
                                shape = RoundedCornerShape(6.dp),
                                color = when {
                                    isLeak -> MaterialTheme.colorScheme.errorContainer
                                    item.exitKind == "proxy" -> MaterialTheme.colorScheme.primaryContainer
                                    else -> MaterialTheme.colorScheme.secondaryContainer
                                },
                            ) {
                                Text(
                                    text = tag,
                                    modifier = Modifier.padding(horizontal = 5.dp, vertical = 1.dp),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = when {
                                        isLeak -> MaterialTheme.colorScheme.onErrorContainer
                                        item.exitKind == "proxy" -> MaterialTheme.colorScheme.onPrimaryContainer
                                        else -> MaterialTheme.colorScheme.onSecondaryContainer
                                    },
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
