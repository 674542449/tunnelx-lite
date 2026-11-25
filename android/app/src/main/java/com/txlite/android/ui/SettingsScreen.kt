package com.txlite.android.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.txlite.android.core.EngineStatus

@Composable
fun SettingsScreen(
    status: EngineStatus,
    connected: Boolean,
    onSaveTransport: (String) -> Unit,
    onSaveDirectDomains: (String) -> Unit,
    onUpdateRules: () -> Unit,
    onSaveDns: (Boolean, String, String) -> Unit,
) {
    var hydrated by remember { mutableStateOf(false) }
    var domainsText by remember { mutableStateOf("") }
    var dnsEnabled by remember { mutableStateOf(true) }
    var domesticDns by remember { mutableStateOf("") }
    var remoteDns by remember { mutableStateOf("") }

    LaunchedEffect(status.directDomains, status.dnsOverride, status.domesticDns, status.remoteDns) {
        if (!hydrated) {
            domainsText = status.directDomains.joinToString("\n")
            dnsEnabled = status.dnsOverride
            domesticDns = status.domesticDns.joinToString("\n")
            remoteDns = status.remoteDns.joinToString("\n")
            hydrated = true
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item {
            Column {
                Text("代理设置", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                Text(
                    "配置 TCP 传输协议、直连例外、防污染分流 DNS 与规则更新",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        // Transport Card
        item {
            SettingsCard(
                title = "TCP 传输模式",
                desc = "断开连接后可切换（默认推荐 Vision 零拷贝直连）",
            ) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(
                        selected = status.transportPreference != "h2",
                        enabled = !connected,
                        onClick = { onSaveTransport("tcp") },
                        label = { Text("TCP 直连 + Vision（推荐）") },
                    )
                    FilterChip(
                        selected = status.transportPreference == "h2",
                        enabled = !connected,
                        onClick = { onSaveTransport("h2") },
                        label = { Text("HTTP/2 并发") },
                    )
                }
                Text(
                    "采用 XTLS Vision 思想：内层 TLS 1.3 建连后剥离外层加密并配合服务端 Linux splice 零拷贝直通，大幅提升下载与高清视频吞吐。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        // Direct Exceptions & Rules Card
        item {
            SettingsCard(
                title = "直连例外与分流规则",
                desc = "填写的域名 / IP / CIDR 始终直连（修改后立即生效）",
            ) {
                OutlinedTextField(
                    value = domainsText,
                    onValueChange = { domainsText = it },
                    placeholder = { Text("每行一条，例如：\ncorp.example.com\n10.20.0.0/16") },
                    minLines = 3,
                    maxLines = 6,
                    modifier = Modifier.fillMaxWidth(),
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Button(
                        onClick = { onSaveDirectDomains(domainsText) },
                        modifier = Modifier.weight(1f),
                    ) { Text("保存例外") }
                    OutlinedButton(
                        onClick = onUpdateRules,
                        modifier = Modifier.weight(1f),
                    ) { Text("更新分流规则") }
                }
                HorizontalDivider()
                Text(
                    text = "当前规则：${status.ruleMeta.domains} 条域名 · ${status.ruleMeta.ipPrefixes} 段 IP（MetaCubeX meta-rules-dat）",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        // Anti-Pollution Split DNS Card
        item {
            SettingsCard(
                title = "防污染 DNS 覆写",
                desc = "国内域名走加密阿里 / 腾讯 DoH，海外走加密隧道远端 DNS",
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("启用国内加密 DoH 覆写", style = MaterialTheme.typography.bodyMedium)
                    Switch(checked = dnsEnabled, onCheckedChange = { dnsEnabled = it })
                }

                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    FilterChip(
                        selected = false,
                        onClick = {
                            dnsEnabled = true
                            domesticDns = "https://223.5.5.5/dns-query\nhttps://223.6.6.6/dns-query\nhttps://1.12.12.12/dns-query"
                        },
                        label = { Text("阿里+腾讯") },
                    )
                    FilterChip(
                        selected = false,
                        onClick = {
                            dnsEnabled = true
                            domesticDns = "https://223.5.5.5/dns-query\nhttps://223.6.6.6/dns-query"
                        },
                        label = { Text("仅阿里云") },
                    )
                    FilterChip(
                        selected = false,
                        onClick = {
                            dnsEnabled = true
                            domesticDns = "https://1.12.12.12/dns-query\nhttps://120.53.53.53/dns-query"
                        },
                        label = { Text("仅腾讯") },
                    )
                }

                OutlinedTextField(
                    value = domesticDns,
                    onValueChange = { domesticDns = it },
                    enabled = dnsEnabled,
                    label = { Text("国内分流 DNS（留空用默认 DoH）") },
                    placeholder = { Text("https://223.5.5.5/dns-query") },
                    minLines = 2,
                    maxLines = 4,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = remoteDns,
                    onValueChange = { remoteDns = it },
                    label = { Text("海外远端 DNS（留空用 1.1.1.1 / 8.8.8.8）") },
                    placeholder = { Text("1.1.1.1:53\n8.8.8.8:53") },
                    minLines = 2,
                    maxLines = 4,
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(
                    onClick = { onSaveDns(dnsEnabled, domesticDns, remoteDns) },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("保存 DNS 设置") }
            }
        }

        // About Card
        item {
            SettingsCard(
                title = "关于 txlite Android",
                desc = "内核与桌面版同源，免 Root 整机接管",
            ) {
                Text("版本：${status.version} (arm64-v8a)", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                Text("网络架构：入口支持 IPv4 / IPv6，落地仅限 IPv4；TLS 1.3 + ECH + XTLS Vision + hev-socks5-tunnel (lwIP)", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun SettingsCard(
    title: String,
    desc: String,
    content: @Composable () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Column {
                Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(desc, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            content()
        }
    }
}
