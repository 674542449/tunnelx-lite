package com.txlite.android.core

data class ServerItem(
    val id: String,
    val name: String,
    val host: String,
    val port: Int,
    val family: String,
    val protocol: String = "txlite",
    val hop: String = "",
)

data class ProbeResultItem(
    val id: String,
    val ms: Long,
    val error: String = "",
)

data class RuleMeta(
    val source: String = "builtin",
    val updatedAt: Long = 0,
    val domains: Int = 0,
    val ipPrefixes: Int = 0,
)

data class EngineStatus(
    val version: String = "v0.6.0",
    val connected: Boolean = false,
    val connectionState: String = "disconnected",
    val connectionStage: String = "disconnected",
    val nodeId: String = "",
    val nodeName: String = "",
    val selectedId: String = "",
    val proxyMode: String = "bypass_cn",
    val directDomains: List<String> = emptyList(),
    val transportPreference: String = "tcp",
    val activeTransport: String = "tcp",
    val dnsOverride: Boolean = true,
    val domesticDns: List<String> = emptyList(),
    val remoteDns: List<String> = emptyList(),
    val upload: Long = 0,
    val download: Long = 0,
    val uploadRate: Long = 0,
    val downloadRate: Long = 0,
    val activeConnections: Long = 0,
    val ruleMeta: RuleMeta = RuleMeta(),
)

data class ExitIpSummary(
    val directIp: String = "",
    val directError: String = "",
    val proxyIp: String = "",
    val proxyError: String = "",
    val proxyIpv6: String = "",
    val proxyIpv6Blocked: Boolean = false,
)

data class SiteCheckEntry(
    val name: String,
    val category: String,
    val domain: String,
    val url: String,
    val route: String,
    val rule: String,
    val exitIp: String = "",
    val exitKind: String = "",
    val verifiedIp: Boolean = false,
    val status: Int = 0,
    val latencyMs: Long = 0,
    val ok: Boolean = false,
    val preview: Boolean = false,
    val error: String = "",
)

data class SiteCheckReport(
    val checkedAt: Long = 0,
    val connected: Boolean = false,
    val nodeName: String = "",
    val proxyMode: String = "bypass_cn",
    val tunActive: Boolean = false,
    val exit: ExitIpSummary = ExitIpSummary(),
    val items: List<SiteCheckEntry> = emptyList(),
)

data class ImportResult(
    val added: Int,
    val updated: Int,
)

fun formatBytes(raw: Long): String {
    var value = raw.coerceAtLeast(0L).toDouble()
    val units = arrayOf("B", "KB", "MB", "GB", "TB")
    var i = 0
    while (value >= 1024.0 && i < units.lastIndex) {
        value /= 1024.0
        i++
    }
    return if (i == 0) "${value.toLong()} B" else String.format("%.1f %s", value, units[i])
}
