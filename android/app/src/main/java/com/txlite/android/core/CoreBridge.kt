package com.txlite.android.core

import org.json.JSONArray
import org.json.JSONObject

object CoreBridge {
    const val SOCKS_HOST = "127.0.0.1"
    const val SOCKS_PORT = 10808
    const val HTTP_PORT = 10809

    @Volatile
    private var initialized = false

    init {
        System.loadLibrary("txlitecore")
    }

    @JvmStatic
    private external fun nativeInit(dataDir: ByteArray, socksAddr: ByteArray, httpAddr: ByteArray): ByteArray

    @JvmStatic
    private external fun nativeCall(action: ByteArray, payload: ByteArray): ByteArray

    @Synchronized
    fun ensureInit(dataDir: String) {
        if (initialized) return
        val raw = nativeInit(
            dataDir.toByteArray(Charsets.UTF_8),
            "$SOCKS_HOST:$SOCKS_PORT".toByteArray(Charsets.UTF_8),
            "$SOCKS_HOST:$HTTP_PORT".toByteArray(Charsets.UTF_8),
        )
        val json = JSONObject(raw.toString(Charsets.UTF_8))
        if (!json.optBoolean("ok", false)) {
            throw IllegalStateException(json.optString("error", "txlite 内核初始化失败"))
        }
        initialized = true
    }

    private fun invoke(action: String, payload: JSONObject? = null): JSONObject {
        val reqBytes = (payload?.toString() ?: "").toByteArray(Charsets.UTF_8)
        val raw = nativeCall(action.toByteArray(Charsets.UTF_8), reqBytes)
        val resp = JSONObject(raw.toString(Charsets.UTF_8))
        if (!resp.optBoolean("ok", false)) {
            throw IllegalStateException(resp.optString("error", "操作失败"))
        }
        return resp
    }

    fun status(): EngineStatus {
        val d = invoke("status").optJSONObject("data") ?: JSONObject()
        val pref = d.optJSONObject("preferences") ?: JSONObject()
        val rules = d.optJSONObject("routing_rules") ?: JSONObject()
        return EngineStatus(
            version = d.optString("version", "v0.6.1"),
            connected = d.optBoolean("connected", false),
            connectionState = d.optString("connection_state", "disconnected"),
            connectionStage = d.optString("connection_stage", "disconnected"),
            nodeId = d.optString("node_id", ""),
            nodeName = d.optString("node_name", ""),
            selectedId = pref.optString("selected_id", ""),
            proxyMode = if (pref.optString("proxy_mode") == "global") "global" else "bypass_cn",
            directDomains = jsonStringList(pref.optJSONArray("direct_domains")),
            transportPreference = if (d.optString("transport_preference") == "h2") "h2" else "tcp",
            activeTransport = d.optString("transport", d.optString("transport_preference", "tcp")),
            dnsOverride = d.optBoolean("dns_override", true),
            domesticDns = jsonStringList(d.optJSONArray("domestic_dns")),
            remoteDns = jsonStringList(d.optJSONArray("remote_dns")),
            upload = d.optLong("upload", 0L),
            download = d.optLong("download", 0L),
            uploadRate = d.optLong("upload_rate", 0L),
            downloadRate = d.optLong("download_rate", 0L),
            activeConnections = d.optLong("active", 0L),
            ruleMeta = RuleMeta(
                source = rules.optString("source", "builtin"),
                updatedAt = rules.optLong("updated_at", 0L),
                domains = rules.optInt("domains", 0),
                ipPrefixes = rules.optInt("ip_prefixes", 0),
            ),
        )
    }

    fun servers(): List<ServerItem> {
        val arr = invoke("servers").optJSONArray("data") ?: return emptyList()
        val list = ArrayList<ServerItem>(arr.length())
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            list.add(
                ServerItem(
                    id = o.optString("id"),
                    name = o.optString("name"),
                    host = o.optString("host"),
                    port = o.optInt("port"),
                    family = o.optString("family"),
                    protocol = o.optString("protocol", "txlite"),
                    hop = o.optString("hop", ""),
                )
            )
        }
        return list
    }

    fun importLinks(text: String): ImportResult {
        val d = invoke("import", JSONObject().put("text", text)).optJSONObject("data") ?: JSONObject()
        return ImportResult(d.optInt("added", 0), d.optInt("updated", 0))
    }

    fun rename(id: String, name: String) {
        invoke("rename", JSONObject().put("id", id).put("name", name))
    }

    fun remove(id: String) {
        invoke("remove", JSONObject().put("id", id))
    }

    fun shareLink(id: String): String {
        val d = invoke("share_link", JSONObject().put("id", id)).optJSONObject("data") ?: JSONObject()
        return d.optString("link", "")
    }

    fun selectServer(id: String) {
        invoke("select", JSONObject().put("id", id))
    }

    fun connect(id: String, dnsServers: List<String>) {
        val dnsArr = JSONArray()
        dnsServers.forEach { dnsArr.put(it) }
        invoke("connect", JSONObject().put("id", id).put("dns_servers", dnsArr))
    }

    fun disconnect() {
        invoke("disconnect")
    }

    fun cancelConnect() {
        runCatching { invoke("cancel") }
    }

    fun updateDns(dnsServers: List<String>) {
        val dnsArr = JSONArray()
        dnsServers.forEach { dnsArr.put(it) }
        runCatching { invoke("update_dns", JSONObject().put("dns_servers", dnsArr)) }
    }

    fun migrateNetwork() {
        runCatching { invoke("migrate_network") }
    }

    fun probe(id: String): Long {
        val d = invoke("probe", JSONObject().put("id", id)).optJSONObject("data") ?: JSONObject()
        return d.optLong("ms", -1L)
    }

    fun probeAll(): List<ProbeResultItem> {
        val arr = invoke("probe_all").optJSONArray("data") ?: return emptyList()
        val list = ArrayList<ProbeResultItem>(arr.length())
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            list.add(
                ProbeResultItem(
                    id = o.optString("id"),
                    ms = o.optLong("ms", -1L),
                    error = o.optString("error", ""),
                )
            )
        }
        return list
    }

    fun saveProxyMode(mode: String, directDomains: String) {
        invoke("save_mode", JSONObject().put("mode", mode).put("direct_domains", directDomains))
    }

    fun saveDns(enabled: Boolean, domestic: String, remote: String) {
        invoke("save_dns", JSONObject().put("enabled", enabled).put("domestic", domestic).put("remote", remote))
    }

    fun saveTransport(transport: String) {
        invoke("save_transport", JSONObject().put("transport", transport))
    }

    fun updateRoutingRules() {
        invoke("update_rules")
    }

    fun checkSites(): SiteCheckReport {
        val d = invoke("check_sites").optJSONObject("data") ?: JSONObject()
        val ex = d.optJSONObject("exit") ?: JSONObject()
        val arr = d.optJSONArray("items") ?: JSONArray()
        val items = ArrayList<SiteCheckEntry>(arr.length())
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            items.add(parseSiteEntry(o))
        }
        return SiteCheckReport(
            checkedAt = d.optLong("checked_at", 0L),
            connected = d.optBoolean("connected", false),
            nodeName = d.optString("node_name", ""),
            proxyMode = d.optString("proxy_mode", "bypass_cn"),
            tunActive = d.optBoolean("tun_active", false),
            exit = ExitIpSummary(
                directIp = ex.optString("direct_ip", ""),
                directError = ex.optString("direct_error", ""),
                proxyIp = ex.optString("proxy_ip", ""),
                proxyError = ex.optString("proxy_error", ""),
                proxyIpv6 = ex.optString("proxy_ipv6", ""),
                proxyIpv6Blocked = ex.optBoolean("proxy_ipv6_blocked", false),
            ),
            items = items,
        )
    }

    fun checkDomain(domain: String): SiteCheckEntry {
        val o = invoke("check_domain", JSONObject().put("domain", domain)).optJSONObject("data") ?: JSONObject()
        return parseSiteEntry(o)
    }

    private fun parseSiteEntry(o: JSONObject): SiteCheckEntry = SiteCheckEntry(
        name = o.optString("name", ""),
        category = o.optString("category", "custom"),
        domain = o.optString("domain", ""),
        url = o.optString("url", ""),
        route = o.optString("route", "proxy"),
        rule = o.optString("rule", ""),
        exitIp = o.optString("exit_ip", ""),
        exitKind = o.optString("exit_kind", ""),
        verifiedIp = o.optBoolean("verified_ip", false),
        status = o.optInt("status", 0),
        latencyMs = o.optLong("latency_ms", 0L),
        ok = o.optBoolean("ok", false),
        preview = o.optBoolean("preview", false),
        error = o.optString("error", ""),
    )

    private fun jsonStringList(arr: JSONArray?): List<String> {
        if (arr == null) return emptyList()
        val out = ArrayList<String>(arr.length())
        for (i in 0 until arr.length()) {
            val s = arr.optString(i)
            if (s.isNotEmpty()) out.add(s)
        }
        return out
    }
}
