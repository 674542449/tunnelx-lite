'use strict';

const $ = id => document.getElementById(id);
const bridge = () => {
  const b = window.go?.main?.App;
  if (!b) throw Error('客户端正在初始化，请稍候');
  return b;
};

let status = {};
let servers = [];
let selected = '';
let probes = new Map();
let busy = false;
let refreshing = false;
let menuFor = '';
let activeView = 'nodes';
let logFilter = 'all';
let logEntries = [];
let lastTableSignature = '';
let settingsHydrated = false;
let lastSavedDomains = '';
let lastSavedTransport = 'tcp';
let checkReport = null;
let customCheckItems = [];
let checkCat = 'all';
let checkBusy = false;

const stages = {
  restoring_proxy: '恢复代理中',
  verifying_tls: '建立安全连接',
  authenticating: '验证密钥中',
  starting_proxy: '启动本地代理',
  checking_tun_network: '检测 IPv6 出口',
  starting_tun: '配置 TUN 网卡',
  reconnecting: '网络变化重连中',
  cancelling: '正在取消',
};

const modeNames = { bypass_cn: '绕过大陆', global: '全局代理' };
const transportNames = { tcp: 'TCP 直连 + Vision 零拷贝', h2: 'TCP 多路复用 (H2)' };

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

function bytes(n) {
  n = Math.max(0, Number(n) || 0);
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(i ? 1 : 0) + ' ' + u[i];
}

function errText(e) {
  const t = String(e?.message || e || '操作失败');
  return /context canceled|context deadline exceeded/i.test(t) ? '已取消' : t;
}

const connected = () => status.connected === true || ['connected', 'degraded'].includes(status.connection_state);
const connecting = () => status.connection_state === 'connecting';

function toast(text, kind = '') {
  const host = $('toast-host');
  const t = el('div', text, 'toast' + (kind ? ' ' + kind : ''));
  host.append(t);
  setTimeout(() => t.remove(), 3200);
}

function log(text, kind = '') {
  const entry = { time: new Date().toLocaleTimeString('zh-CN', { hour12: false }), text, kind };
  logEntries.push(entry);
  if (logEntries.length > 400) logEntries.shift();
  if (kind === 'err' && activeView !== 'logs') $('nav-log-dot').hidden = false;
  if (logFilter === 'all' || logFilter === kind) appendLogLine(entry);
}

function appendLogLine(entry) {
  const row = el('div', undefined, 'log-line' + (entry.kind ? ' ' + entry.kind : ''));
  row.append(el('span', entry.time, 'log-time'), el('span', entry.text, 'log-msg'));
  const box = $('log');
  box.append(row);
  while (box.childNodes.length > 400) box.firstChild.remove();
  box.scrollTop = box.scrollHeight;
}

function renderLogs() {
  const box = $('log');
  box.replaceChildren();
  for (const e of logEntries) {
    if (logFilter === 'all' || logFilter === e.kind) appendLogLine(e);
  }
}

function switchView(view) {
  activeView = view;
  for (const btn of document.querySelectorAll('.nav-item')) {
    const on = btn.dataset.view === view;
    btn.classList.toggle('active', on);
    btn.setAttribute('aria-selected', String(on));
  }
  for (const panel of document.querySelectorAll('.view')) {
    panel.hidden = panel.id !== 'view-' + view;
  }
  if (view === 'logs') $('nav-log-dot').hidden = true;
  if (view === 'settings') hydrateSettings(true);
}

async function task(label, fn) {
  if (busy) return;
  busy = true;
  render();
  try {
    await fn();
  } catch (e) {
    const t = errText(e);
    if (t !== '已取消') {
      log(label + '失败：' + t, 'err');
      toast(label + '失败：' + t, 'err');
    }
  } finally {
    busy = false;
    await refresh();
  }
}

async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    status = await bridge().Status();
    servers = await bridge().Servers();
  } catch {
    return;
  } finally {
    refreshing = false;
  }
  if (!servers.some(s => s.id === selected)) {
    selected = status.preferences?.selected_id || servers[0]?.id || '';
  }
  render();
}

function makeIconBtn(title, cls, svgPath, onClick) {
  const b = el('button', undefined, 'icon-btn' + (cls ? ' ' + cls : ''));
  b.type = 'button';
  b.title = title;
  b.setAttribute('aria-label', title);
  b.innerHTML = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + svgPath + '</svg>';
  b.onclick = ev => { ev.stopPropagation(); onClick(); };
  return b;
}

function renderTable(active) {
  const filter = $('filter').value.trim().toLowerCase();
  const shown = servers.filter(s => !filter || (s.name + ' ' + s.host + ':' + s.port).toLowerCase().includes(filter));
  const sig = JSON.stringify({
    active,
    selected,
    filter,
    on: connected(),
    nodeId: status.node_id || '',
    servers: shown.map(s => [s.id, s.name, s.host, s.port, s.family, s.protocol || 'txlite', s.hop || '']),
    probes: shown.map(s => { const p = probes.get(s.id); return p ? [p.busy, p.ms, p.error] : null; }),
  });
  if (sig === lastTableSignature) return;
  lastTableSignature = sig;

  $('empty').hidden = servers.length > 0;
  const rows = shown.map(s => {
    const tr = el('tr');
    tr.dataset.id = s.id;
    const isConnectedNode = connected() && status.node_id === s.id;
    if (s.id === selected) tr.classList.add('sel');
    if (s.id === active || isConnectedNode) tr.classList.add('active');

    const statusTd = el('td', undefined, 'col-status');
    if (isConnectedNode) {
      statusTd.append(el('span', '●', 'active-dot'));
      statusTd.title = '当前已连接';
    } else if (s.id === active) {
      statusTd.append(el('span', '✓', 'active-dot'));
      statusTd.title = '当前活动节点';
    }

    const nameTd = el('td', undefined, 'col-name');
    nameTd.append(el('span', s.name, 'node-title'));
    nameTd.title = s.name;

    const hostTd = el('td', s.host + ':' + s.port, 'col-host mono host-cell');
    hostTd.title = s.host + ':' + s.port;

    const famTd = el('td', undefined, 'col-fam');
    const isPulse = s.protocol === 'txpulse';
    const protoEl = el('span', isPulse ? 'TXPulse' : 'Vision', 'proto-pill ' + (isPulse ? 'txpulse' : 'txlite'));
    protoEl.title = isPulse
      ? ('自研类 Hy2 UDP 协议 · 自签证书固定' + (s.hop ? ' · 端口跳跃 ' + s.hop : ''))
      : 'TCP Vision / H2 (TLS 1.3 + ECH)';
    famTd.append(protoEl, el('span', s.family, 'fam-pill'));

    const msTd = el('td', undefined, 'col-ms');
    const p = probes.get(s.id);
    if (p?.busy) {
      msTd.append(el('span', '测速中…', 'ms-badge ms-busy'));
    } else if (p?.error) {
      const b = el('span', p.error, 'ms-badge ms-bad');
      b.title = p.error;
      msTd.append(b);
    } else if (p?.ms !== undefined) {
      const cls = p.ms < 180 ? 'ms-good' : p.ms < 450 ? 'ms-warm' : 'ms-bad';
      msTd.append(el('span', p.ms + ' ms', 'ms-badge mono ' + cls));
    } else {
      msTd.append(el('span', '—', 'host-cell'));
    }

    const opsTd = el('td', undefined, 'col-ops');
    const ops = el('div', undefined, 'row-ops');
    ops.append(
      makeIconBtn('测试延迟', '', '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>', () => probe(s.id)),
      makeIconBtn('复制分享链接', '', '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>', () => command('copy', s.id)),
      makeIconBtn('重命名', '', '<path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/>', () => command('rename', s.id)),
      makeIconBtn('删除', 'danger', '<polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/>', () => command('remove', s.id)),
    );
    opsTd.append(ops);

    tr.append(statusTd, nameTd, hostTd, famTd, msTd, opsTd);
    return tr;
  });
  $('rows').replaceChildren(...rows);
}

function render() {
  const pref = status.preferences || {};
  const active = pref.selected_id || '';
  const on = connected();
  const going = connecting();
  const tunEnabled = pref.tun_enabled === true || status.tun_enabled === true;
  const tunActive = status.tun_active === true;
  const mode = pref.proxy_mode === 'global' ? 'global' : 'bypass_cn';
  const tun = status.tun || {};

  $('brand-version').textContent = status.version || 'v0.6.0';
  $('nav-node-count').textContent = String(servers.length);
  $('header-node-count').textContent = servers.length + ' 个节点';

  renderTable(active);

  // Sidebar status & connect control
  const state = status.connection_state || 'disconnected';
  $('state-dot').className = 'dot ' + state;
  $('state-text').textContent = going
    ? (stages[status.connection_stage] || '正在连接')
    : state === 'degraded' ? '连接异常'
    : on ? '已连接' : '未连接';

  const currentNode = servers.find(s => s.id === (on || going ? status.node_id : (selected || active)));
  $('active-node-name').textContent = currentNode ? currentNode.name : '未选择节点';
  $('active-node-name').title = currentNode ? currentNode.name + ' (' + currentNode.host + ':' + currentNode.port + ')' : '';

  $('connect-label').textContent = on ? '断开连接' : going ? '连接中…' : '立即连接';
  $('connect-btn').classList.toggle('on', on);
  $('connect-btn').disabled = busy || going || (!on && !selected);
  $('cancel-btn').hidden = !going;
  $('probe-all').disabled = busy || !servers.length;

  // Transport chip
  const tpref = status.transport_preference === 'h2' ? 'h2' : 'tcp';
  const chip = $('transport-chip');
  if (on) {
    const actual = status.transport === 'txpulse' ? 'txpulse'
      : status.transport === 'vision' ? 'vision'
      : status.transport === 'h2' ? 'h2' : 'tcp';
    chip.textContent = actual === 'txpulse' ? 'TXPULSE' : actual === 'vision' ? 'VISION' : actual === 'tcp' ? 'TCP' : 'H2';
    chip.className = 'transport-chip ' + actual;
    if (actual === 'txpulse') {
      const ps = status.pulse_stats || {};
      const detail = ps.srtt_ms ? (' · RTT ' + ps.srtt_ms + 'ms · 丢包 ' + (Number(ps.loss_rate || 0) * 100).toFixed(1) + '% · HyBBR ' + (ps.pacing_mbps || 0) + ' Mbps') : '';
      chip.title = '当前使用 TXPulse 自研抗丢包 UDP 协议（自签证书指纹固定 + 自适应 HyBBR）' + detail;
    } else {
      chip.title = actual === 'vision'
        ? '当前使用 TCP 直连 + Vision 零拷贝直通（TLS 1.3 内层直连，无双重加密）'
        : actual === 'tcp'
        ? '当前使用 TCP 直连多通道（更新服务端至 v0.5.0 可启用 Vision 零拷贝）'
        : (tpref === 'tcp' ? '服务端为旧版，当前自动兼容 HTTP/2（更新服务端可启用 Vision 极速直连）' : '当前使用 TCP HTTP/2 多路复用');
    }
  } else if (currentNode && currentNode.protocol === 'txpulse') {
    chip.textContent = 'TXPULSE';
    chip.className = 'transport-chip txpulse';
    chip.title = '所选节点使用 TXPulse 自研类 Hy2 UDP 协议（自签证书指纹固定 + 自适应 HyBBR）';
  } else {
    chip.textContent = tpref === 'h2' ? 'H2' : 'TCP';
    chip.className = 'transport-chip';
    chip.title = '传输模式：' + (transportNames[tpref] || tpref);
  }

  // Orthogonal routing mode segmented control (hot-switchable while connected!)
  for (const btn of document.querySelectorAll('.seg-btn')) {
    const isSel = btn.dataset.mode === mode;
    btn.classList.toggle('active', isSel);
    btn.setAttribute('aria-checked', String(isSel));
    btn.disabled = busy || going;
  }
  $('mode-live-hint').textContent = on ? '已实时生效' : '支持实时切换';

  // Independent TUN toggle
  const tunToggle = $('tun-toggle');
  tunToggle.checked = tunEnabled;
  tunToggle.disabled = busy || on || going;
  const tunSub = $('tun-sub');
  if (tunActive) {
    tunSub.textContent = mode === 'global'
      ? '已接管 · 全局单 IPv4'
      : '已接管 · 国内直连 (IPv4 落地)';
    tunSub.className = 'tun-sub ok';
  } else if (tunEnabled && tun.supported && !tun.elevated) {
    tunSub.textContent = '需管理员权限运行';
    tunSub.className = 'tun-sub warn';
  } else if (tunEnabled && tun.supported && !tun.assets_ready) {
    tunSub.textContent = '缺少 TUN 组件';
    tunSub.className = 'tun-sub warn';
  } else if (on) {
    tunSub.textContent = '断开后可切换';
    tunSub.className = 'tun-sub';
  } else {
    tunSub.textContent = tunEnabled
      ? (mode === 'global' ? '下次连接全网单 IP 接管' : '下次连接启用（国内直连）')
      : '接管全部 TCP/UDP（按规则分流）';
    tunSub.className = 'tun-sub';
  }

  // Telemetry
  $('speed-up').textContent = bytes(on ? status.upload_rate : 0) + '/s';
  $('speed-down').textContent = bytes(on ? status.download_rate : 0) + '/s';

  const taken = status.system_proxy_taken === true;
  const tunProxyConflict = status.tun_proxy_conflict || '';
  const proxyOn = status.system_proxy === true && !taken;
  const captureEl = $('metric-capture');
  if (taken && tunActive) {
    captureEl.textContent = 'TUN 运行中（检测到外部系统代理）';
    captureEl.className = 'metric-value warn';
  } else if (taken) {
    captureEl.textContent = '系统代理被其他程序占用';
    captureEl.className = 'metric-value warn';
  } else if (tunActive) {
    captureEl.textContent = 'TUN 虚拟网卡 · ' + modeNames[mode];
    captureEl.className = 'metric-value ok';
  } else if (proxyOn) {
    captureEl.textContent = 'Windows 系统代理 · ' + modeNames[mode];
    captureEl.className = 'metric-value ok';
  } else {
    captureEl.textContent = '未接管（' + (tunEnabled ? 'TUN + ' : '') + modeNames[mode] + '）';
    captureEl.className = 'metric-value';
  }

  $('metric-traffic').textContent = '↑ ' + bytes(on ? status.upload : 0) + ' · ↓ ' + bytes(on ? status.download : 0);
  $('metric-active').textContent = String(on ? (status.active || 0) : 0);
  if (status.socks && status.http) {
    $('metric-ports').textContent = 'SOCKS ' + status.socks.split(':').pop() + ' · HTTP ' + status.http.split(':').pop();
  }

  // Banner
  const warningParts = [];
  if (status.startup_warning) warningParts.push(status.startup_warning);
  if (status.proxy_recovery_error) warningParts.push(status.proxy_recovery_error);
  if (taken && tunActive) {
    warningParts.push('检测到 Windows 系统代理被其他程序开启' + (tunProxyConflict ? '（' + tunProxyConflict + '）' : '') + '，浏览器等应用可能会绕过 TUN 虚拟网卡。');
  } else if (taken) {
    warningParts.push('Windows 系统代理已被其他软件接管，部分应用可能未经过 txlite。');
  }
  const warning = warningParts.join(' ');
  $('banner-text').textContent = warning;
  $('banner').hidden = !warning;
  $('banner-recover').hidden = !status.proxy_recovery_error && (!taken || tunActive);

  hydrateSettings(false);
  renderCheckView();
}

const checkCatLabels = { ip: '测 IP', cn: '国内', global: '海外', custom: '自定义' };

function renderCheckView() {
  const btn = $('btn-check-sites');
  if (!btn) return;
  btn.disabled = checkBusy;
  $('btn-check-label').textContent = checkBusy ? '检测中…' : '一键检测全部';
  $('btn-check-custom').disabled = checkBusy;
  $('empty-check-start').disabled = checkBusy;
  $('check-progress').hidden = !checkBusy;

  const r = checkReport;
  const directEl = $('chk-direct-ip');
  const proxyEl = $('chk-proxy-ip');
  const ipv6El = $('chk-ipv6-guard');
  const sumEl = $('chk-summary');

  if (r) {
    const exit = r.exit || {};
    if (exit.direct_ip) {
      directEl.textContent = exit.direct_ip;
      directEl.className = 'metric-value mono selectable ok';
    } else {
      directEl.textContent = exit.direct_error || '获取失败';
      directEl.className = 'metric-value warn';
    }
    if (!r.connected) {
      proxyEl.textContent = '未连接节点';
      proxyEl.className = 'metric-value';
      ipv6El.textContent = '连接后检测';
      ipv6El.className = 'metric-value';
    } else {
      if (exit.proxy_ip) {
        proxyEl.textContent = exit.proxy_ip;
        proxyEl.className = 'metric-value mono selectable ok';
      } else {
        proxyEl.textContent = exit.proxy_error || '获取失败';
        proxyEl.className = 'metric-value warn';
      }
      if (exit.proxy_ipv6_blocked) {
        ipv6El.textContent = '仅 IPv4 落地（已阻断）';
        ipv6El.className = 'metric-value ok';
      } else {
        ipv6El.textContent = exit.proxy_ipv6 ? ('检测到 IPv6：' + exit.proxy_ipv6) : '旧服务端允许 IPv6（建议升级）';
        ipv6El.className = 'metric-value warn';
      }
    }
  }

  const allItems = [...customCheckItems, ...(r?.items || [])];
  if (allItems.length > 0) {
    const directCnt = allItems.filter(i => i.route === 'direct').length;
    const proxyCnt = allItems.filter(i => i.route === 'proxy').length;
    const modeTxt = modeNames[(r?.proxy_mode || status.preferences?.proxy_mode) === 'global' ? 'global' : 'bypass_cn'];
    sumEl.textContent = modeTxt + ' · 直连 ' + directCnt + ' / 代理 ' + proxyCnt;
    sumEl.className = 'metric-value ok';
  }

  const shown = allItems.filter(i => checkCat === 'all' || i.category === checkCat || i.category === 'custom');
  $('check-empty').hidden = allItems.length > 0;
  const rows = shown.map(item => {
    const tr = el('tr');

    const siteTh = el('th');
    siteTh.scope = 'row';
    const wrap = el('span', undefined, 'site-name-wrap');
    wrap.append(
      el('span', item.name, 'site-name-text'),
      el('span', checkCatLabels[item.category] || item.category, 'cat-tag'),
    );
    siteTh.append(wrap);
    siteTh.title = item.name + ' (' + item.url + ')';

    const domTd = el('td', item.domain, 'mono host-cell');
    domTd.title = item.domain;

    const routeTd = el('td');
    const rwrap = el('span', undefined, 'route-cell');
    rwrap.append(
      el('span', item.route === 'direct' ? '直连' : '代理', 'route-pill ' + (item.route === 'direct' ? 'direct' : 'proxy')),
      el('span', item.rule || '', 'route-rule'),
    );
    routeTd.append(rwrap);
    routeTd.title = (item.route === 'direct' ? '直连' : '代理') + ' · ' + (item.rule || '');

    const ipTd = el('td');
    if (item.exit_ip) {
      const ipWrap = el('span', undefined, 'ip-cell');
      ipWrap.append(el('span', item.exit_ip, 'mono'));
      let tagText = '';
      let tagCls = '';
      if (item.verified_ip && item.route === 'proxy' && item.exit_kind === 'direct') {
        tagText = '分流异常';
        tagCls = 'warn';
      } else if (item.exit_kind === 'proxy') {
        tagText = item.verified_ip ? '实测节点' : '节点 IP';
        tagCls = 'node';
      } else if (item.exit_kind === 'direct') {
        tagText = item.verified_ip ? '实测本机' : '本机 IP';
        tagCls = 'local';
      } else if (item.verified_ip) {
        tagText = '实测返回';
        tagCls = 'node';
      }
      if (tagText) ipWrap.append(el('span', tagText, 'ip-tag ' + tagCls));
      ipTd.append(ipWrap);
      ipTd.title = item.exit_ip + (tagText ? ' (' + tagText + ')' : '');
    } else {
      ipTd.append(el('span', item.preview ? '未连接' : '—', 'host-cell'));
    }

    const stTd = el('td', undefined, 'chk-cell-status');
    if (item.preview) {
      stTd.append(el('span', '规则预览', 'ms-badge ms-busy'));
    } else if (item.ok) {
      const cls = item.latency_ms < 250 ? 'ms-good' : item.latency_ms < 700 ? 'ms-warm' : 'ms-bad';
      const badge = el('span', item.latency_ms + ' ms', 'ms-badge mono ' + cls);
      badge.title = 'HTTP ' + item.status + ' · ' + item.latency_ms + ' ms';
      stTd.append(badge);
    } else {
      const badge = el('span', item.error || '失败', 'ms-badge ms-bad');
      badge.title = item.error || '访问失败';
      stTd.append(badge);
    }

    tr.append(siteTh, domTd, routeTd, ipTd, stTd);
    return tr;
  });
  $('check-rows').replaceChildren(...rows);
}

async function runSiteCheck() {
  if (checkBusy) return;
  checkBusy = true;
  renderCheckView();
  log('正在执行常见网站分流与出口 IP 检测…');
  try {
    checkReport = await bridge().CheckSites();
    const ex = checkReport.exit || {};
    const parts = [];
    if (ex.direct_ip) parts.push('本机直连 IPv4：' + ex.direct_ip);
    if (checkReport.connected && ex.proxy_ip) parts.push('节点落地 IPv4：' + ex.proxy_ip);
    if (checkReport.connected) parts.push(ex.proxy_ipv6_blocked ? 'IPv6 已阻断（仅 IPv4 落地）' : '警告：服务端未阻断 IPv6');
    const summary = '分流检测完成' + (parts.length ? '（' + parts.join('，') + '）' : '');
    log(summary, 'ok');
    toast('常见网站分流检测完成', 'ok');
  } catch (e) {
    const t = errText(e);
    log('分流检测失败：' + t, 'err');
    toast('分流检测失败：' + t, 'err');
  } finally {
    checkBusy = false;
    renderCheckView();
  }
}

async function runCustomDomainCheck(raw) {
  const val = raw.trim();
  if (!val || checkBusy) return;
  checkBusy = true;
  renderCheckView();
  try {
    const item = await bridge().CheckDomain(val);
    customCheckItems = [item, ...customCheckItems.filter(x => x.domain !== item.domain)].slice(0, 12);
    $('check-custom-input').value = '';
    const msg = item.domain + ' → ' + (item.route === 'direct' ? '直连' : '代理') + '（' + item.rule + (item.exit_ip ? '，出口 ' + item.exit_ip : '') + '）';
    log('自定义域名检测：' + msg, 'ok');
    toast(msg, 'ok');
  } catch (e) {
    const t = errText(e);
    log('域名检测失败：' + t, 'err');
    toast(t, 'err');
  } finally {
    checkBusy = false;
    renderCheckView();
  }
}

function hydrateSettings(force) {
  const pref = status.preferences || {};
  const rules = status.routing_rules || {};
  const tun = status.tun || {};
  const on = connected();
  const going = connecting();

  const domainsStr = (pref.direct_domains || []).join('\n');
  const tpref = status.transport_preference === 'h2' ? 'h2' : 'tcp';

  if (force || !settingsHydrated) {
    $('set-domains').value = domainsStr;
    $('set-transport').value = tpref;
    $('set-dns-override').checked = status.dns_override !== false;
    $('set-domestic-dns').value = (status.domestic_dns || []).join('\n');
    $('set-remote-dns').value = (status.remote_dns || []).join('\n');
    lastSavedDomains = domainsStr;
    lastSavedTransport = tpref;
    settingsHydrated = true;
  }

  $('set-domains').disabled = busy || going;
  $('save-exceptions').disabled = busy || going;
  $('set-dns-override').disabled = busy || going;
  $('set-domestic-dns').disabled = busy || going || !$('set-dns-override').checked;
  $('set-remote-dns').disabled = busy || going;
  $('save-dns').disabled = busy || going;
  $('set-transport').disabled = busy || on || going;
  $('save-transport').disabled = busy || on || going;
  $('btn-update-rules').disabled = busy;
  $('btn-recover-proxy').disabled = busy || on || going;

  $('rule-info-text').textContent =
    '当前规则：' + Number(rules.domains || 0).toLocaleString() + ' 条域名 · ' +
    Number(rules.ip_prefixes || 0).toLocaleString() + ' 段 IP · ' +
    (rules.source === 'updated'
      ? '更新于 ' + new Date(rules.updated_at * 1000).toLocaleString('zh-CN')
      : '随版本内置') +
    '（MetaCubeX meta-rules-dat）';

  $('info-ports').textContent = status.socks ? ('SOCKS5 ' + status.socks + '  /  HTTP ' + status.http) : '—';
  $('info-tun').textContent = !tun.supported
    ? '当前系统不支持'
    : !tun.assets_ready
    ? (tun.error || '缺少 TUN 组件')
    : tun.elevated ? '已具备管理员权限（可直接启用）' : '当前为普通权限（启用 TUN 需以管理员身份运行）';
  $('info-datadir').textContent = status.data_directory || '—';
  $('info-version').textContent = status.version || '—';
  updateThemeButtons();
}

// Theme management following modern-web-guidance (dark-mode & dark-mode-toggle)
const darkMql = window.matchMedia('(prefers-color-scheme: dark)');

function getStoredTheme() {
  try {
    const v = localStorage.getItem('txlite.theme');
    return v === 'light' || v === 'dark' ? v : 'system';
  } catch {
    return 'system';
  }
}

function updateThemeButtons() {
  const current = getStoredTheme();
  const sysLabel = '跟随系统（当前' + (darkMql.matches ? '深色' : '浅色') + '）';
  $('theme-system-btn').textContent = sysLabel;
  for (const btn of document.querySelectorAll('.theme-btn')) {
    const on = btn.dataset.themeChoice === current;
    btn.classList.toggle('active', on);
    btn.setAttribute('aria-checked', String(on));
  }
}

function applyTheme(choice) {
  const meta = document.querySelector('meta[name="color-scheme"]');
  if (choice === 'light' || choice === 'dark') {
    if (meta) meta.content = choice;
    try { localStorage.setItem('txlite.theme', choice); } catch {}
  } else {
    if (meta) meta.content = 'light dark';
    try { localStorage.removeItem('txlite.theme'); } catch {}
    choice = 'system';
  }
  updateThemeButtons();
  try { bridge().SetTheme(choice).catch(() => {}); } catch {}
}

darkMql.addEventListener('change', updateThemeButtons);
window.addEventListener('storage', e => {
  if (e.key === 'txlite.theme') applyTheme(getStoredTheme());
});

// Actions
async function connectTo(id) {
  if (connected()) {
    if (status.node_id === id) return;
    await bridge().Disconnect();
  }
  await bridge().SavePreferences(id);
  const name = servers.find(s => s.id === id)?.name || '';
  const pref = status.preferences || {};
  const modeLabel = modeNames[pref.proxy_mode === 'global' ? 'global' : 'bypass_cn'];
  const tunEnabled = pref.tun_enabled === true || status.tun_enabled === true;
  log('正在连接 ' + name + ' …');
  const watch = setInterval(refresh, 350);
  try {
    await bridge().Connect(id);
    const tunHint = tunEnabled
      ? (pref.proxy_mode === 'global'
        ? 'TUN + 全局代理：全网统一单 IP 出口'
        : 'TUN + 绕过大陆：国内站点直连，全网单 IP 请切「全局代理」')
      : (modeLabel + '，已设置系统代理');
    const msg = '已连接 ' + name + '（' + tunHint + '）';
    log(msg, 'ok');
    toast('已连接 ' + name, 'ok');
  } finally {
    clearInterval(watch);
  }
}

async function probe(id) {
  probes.set(id, { busy: true });
  render();
  try {
    const ms = await bridge().Probe(id);
    probes.set(id, { ms });
  } catch (e) {
    probes.set(id, { error: errText(e) });
  }
  render();
}

async function importText(text) {
  const r = text === undefined ? await bridge().ImportClipboard() : await bridge().Import(text);
  const msg = '导入完成：新增 ' + r.added + ' 个' + (r.updated ? '，更新 ' + r.updated + ' 个' : '');
  log(msg, 'ok');
  toast(msg, 'ok');
  await refresh();
  if (!selected && servers.length) selected = servers[servers.length - 1].id;
}

// Native Modal Dialog + light-dismiss fallback when closedby is unsupported
const dlg = $('dialog');
dlg.addEventListener('close', () => { dlg.returnValue = ''; });
if (!('closedBy' in HTMLDialogElement.prototype)) {
  const outside = (e, d) => {
    const r = d.getBoundingClientRect();
    return e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
  };
  let pressedOutside = false;
  dlg.addEventListener('pointerdown', e => { pressedOutside = outside(e, dlg); });
  dlg.addEventListener('pointerup', e => { if (pressedOutside && outside(e, dlg)) dlg.close(); });
}

function dialog(title, nodes, onOk, okText = '确定', destructive = false) {
  $('dialog-title').textContent = title;
  $('dialog-body').replaceChildren(...nodes);
  $('dialog-error').textContent = '';
  $('dialog-ok').textContent = okText;
  $('dialog-ok').hidden = !onOk;
  $('dialog-cancel').textContent = onOk ? '取消' : '关闭';
  $('dialog-form').onsubmit = async ev => {
    ev.preventDefault();
    if (!onOk) { dlg.close(); return; }
    $('dialog-ok').disabled = true;
    try {
      await onOk();
      dlg.close('ok');
    } catch (e) {
      $('dialog-error').textContent = errText(e);
    } finally {
      $('dialog-ok').disabled = false;
    }
  };
  dlg.showModal();
  if (destructive) $('dialog-cancel').focus();
  else dlg.querySelector('textarea, input')?.focus();
}
$('dialog-cancel').onclick = () => dlg.close('cancel');
$('dialog-x').onclick = () => dlg.close('cancel');

function field(label, input) {
  const l = el('label', label);
  l.append(input);
  return l;
}

function openMenu(id, x, y) {
  menuFor = id;
  selected = id;
  render();
  const m = $('menu');
  m.hidden = false;
  m.style.left = Math.min(x, innerWidth - m.offsetWidth - 8) + 'px';
  m.style.top = Math.min(y, innerHeight - m.offsetHeight - 8) + 'px';
}
function closeMenu() { $('menu').hidden = true; }

async function command(cmd, id) {
  const s = servers.find(v => v.id === id);
  if (!s) return;
  if (cmd === 'connect') return task('连接', () => connectTo(id));
  if (cmd === 'probe') return probe(id);
  if (cmd === 'copy') {
    return task('复制分享链接', async () => {
      await bridge().CopyShareLink(id);
      log('已复制「' + s.name + '」的分享链接', 'ok');
      toast('已复制分享链接', 'ok');
    });
  }
  if (cmd === 'rename') {
    const input = el('input');
    input.type = 'text';
    input.value = s.name;
    input.maxLength = 64;
    return dialog('重命名服务器', [field('节点别名', input)], async () => {
      await bridge().Rename(id, input.value);
      await refresh();
      toast('已重命名', 'ok');
    }, '保存');
  }
  if (cmd === 'remove') {
    return dialog(
      '删除服务器',
      [el('p', '确定要删除「' + s.name + '」吗？删除后需要重新导入分享链接。', 'note')],
      async () => {
        await bridge().Remove(id);
        probes.delete(id);
        log('已删除服务器：' + s.name);
        toast('已删除 ' + s.name);
        await refresh();
      },
      '删除',
      true,
    );
  }
}

function openManualImport() {
  const t = el('textarea');
  t.placeholder = 'txlite://… 或 txpulse://…\n可一次粘贴多个链接，每行一个';
  dialog('添加分享链接', [field('分享链接', t)], () => importText(t.value), '导入');
}

// Event bindings
for (const btn of document.querySelectorAll('.nav-item')) {
  btn.onclick = () => switchView(btn.dataset.view);
}

for (const btn of document.querySelectorAll('.seg-btn')) {
  btn.onclick = () => {
    const nextMode = btn.dataset.mode;
    const curMode = status.preferences?.proxy_mode === 'global' ? 'global' : 'bypass_cn';
    if (nextMode === curMode) return;
    const domains = (status.preferences?.direct_domains || []).join('\n');
    task('切换路由', async () => {
      await bridge().SaveProxyMode(nextMode, domains);
      const msg = '路由已切换为「' + modeNames[nextMode] + '」' + (connected() ? '（已即时生效并重置旧连接）' : '');
      log(msg, 'ok');
      toast(msg, 'ok');
    });
  };
}

$('tun-toggle').onchange = () => {
  const next = $('tun-toggle').checked;
  const tun = status.tun || {};
  task(next ? '开启 TUN' : '关闭 TUN', async () => {
    await bridge().SaveTUN(next);
    log(next ? '已启用 TUN 模式（可与绕过大陆或全局规则配合使用）' : '已关闭 TUN 模式', 'ok');
    if (next && tun.supported && !tun.elevated) {
      log('提示：TUN 模式需要管理员权限，请退出后右键「以管理员身份运行」', 'warn');
      toast('TUN 需以管理员身份运行后生效', 'warn');
    } else if (next && tun.supported && !tun.assets_ready) {
      log(tun.error || '缺少 TUN 组件，请完整解压客户端安装包', 'err');
      toast(tun.error || '缺少 TUN 组件', 'err');
    } else {
      toast(next ? '已开启 TUN（下次连接生效）' : '已关闭 TUN', 'ok');
    }
  });
};

$('connect-btn').onclick = () => task(connected() ? '断开' : '连接', async () => {
  if (connected()) {
    const hadProxy = status.system_proxy === true && status.system_proxy_taken !== true;
    const hadTun = status.tun_active === true;
    await bridge().Disconnect();
    const msg = hadTun ? '已断开，TUN 虚拟网卡与 DNS 已恢复' : hadProxy ? '已断开，Windows 系统代理已恢复' : '已断开连接';
    log(msg);
    toast(msg);
    return;
  }
  await connectTo(selected);
});
$('cancel-btn').onclick = () => bridge().CancelConnect().then(() => log('已取消连接', 'warn'));

$('rows').onclick = e => {
  const tr = e.target.closest('tr');
  if (tr) { selected = tr.dataset.id; render(); }
};
$('rows').ondblclick = e => {
  const tr = e.target.closest('tr');
  if (tr) command('connect', tr.dataset.id);
};
$('rows').oncontextmenu = e => {
  const tr = e.target.closest('tr');
  if (!tr) return;
  e.preventDefault();
  openMenu(tr.dataset.id, e.clientX, e.clientY);
};
$('menu').onclick = e => {
  const b = e.target.closest('button');
  if (!b) return;
  closeMenu();
  command(b.dataset.cmd, menuFor);
};
document.addEventListener('pointerdown', e => { if (!$('menu').contains(e.target)) closeMenu(); });
document.addEventListener('contextmenu', e => {
  if (!e.target.closest('#rows, #check-table, .selectable, input, textarea, .log-stream, .kv-list')) e.preventDefault();
});

$('import-clipboard').onclick = () => task('导入', () => importText());
$('empty-paste').onclick = () => task('导入', () => importText());
$('import-manual').onclick = openManualImport;
$('empty-manual').onclick = openManualImport;

$('probe-all').onclick = () => task('测试延迟', async () => {
  for (const s of servers) probes.set(s.id, { busy: true });
  render();
  log('正在并发测试全部服务器延迟…');
  for (const r of await bridge().ProbeAll()) {
    probes.set(r.id, r.error ? { error: r.error } : { ms: r.ms });
  }
  const ok = [...probes.values()].filter(p => p.ms !== undefined).length;
  const msg = '延迟测试完成：' + ok + ' / ' + servers.length + ' 个可用';
  log(msg, 'ok');
  toast(msg, 'ok');
});

$('save-exceptions').onclick = () => task('保存直连例外', async () => {
  const mode = status.preferences?.proxy_mode === 'global' ? 'global' : 'bypass_cn';
  const val = $('set-domains').value;
  await bridge().SaveProxyMode(mode, val);
  lastSavedDomains = val;
  settingsHydrated = false;
  const msg = '直连例外已保存' + (connected() ? '并立即生效' : '');
  log(msg, 'ok');
  toast(msg, 'ok');
});

$('set-dns-override').onchange = () => {
  $('set-domestic-dns').disabled = busy || connecting() || !$('set-dns-override').checked;
};

const dnsPresets = {
  'ali-tencent': 'https://223.5.5.5/dns-query\nhttps://223.6.6.6/dns-query\nhttps://1.12.12.12/dns-query',
  ali: 'https://223.5.5.5/dns-query\nhttps://223.6.6.6/dns-query',
  tencent: 'https://1.12.12.12/dns-query\nhttps://120.53.53.53/dns-query',
};
for (const btn of document.querySelectorAll('[data-dns-preset]')) {
  btn.onclick = () => {
    $('set-dns-override').checked = true;
    $('set-domestic-dns').disabled = false;
    $('set-domestic-dns').value = dnsPresets[btn.dataset.dnsPreset] || '';
  };
}

$('save-dns').onclick = () => task('保存 DNS 覆写', async () => {
  const enabled = $('set-dns-override').checked;
  const domestic = $('set-domestic-dns').value;
  const remote = $('set-remote-dns').value;
  await bridge().SaveDNS(enabled, domestic, remote);
  settingsHydrated = false;
  const msg = (enabled ? '防污染 DNS 覆写已保存' : '已关闭国内 DNS 覆写') + (connected() ? '并立即生效' : '');
  log(msg, 'ok');
  toast(msg, 'ok');
});

$('save-transport').onclick = () => task('保存传输设置', async () => {
  const t = $('set-transport').value === 'h2' ? 'h2' : 'tcp';
  if (t !== (status.transport_preference || 'tcp')) {
    await bridge().SaveTransport(t);
    log('传输方式已改为 ' + transportNames[t] + '，下次连接生效', 'ok');
  }
  lastSavedTransport = t;
  settingsHydrated = false;
  toast('传输设置已保存', 'ok');
});

$('btn-update-rules').onclick = () => task('更新分流规则', async () => {
  log('正在下载最新 MetaCubeX 分流规则…');
  await bridge().UpdateRoutingRules();
  const msg = '分流规则已更新' + (connected() ? '并立即生效' : '');
  log(msg, 'ok');
  toast(msg, 'ok');
});

const doRecover = () => task('恢复网络', async () => {
  await bridge().RecoverProxy();
  log('已恢复 Windows 原有系统代理与 TUN 网络状态', 'ok');
  toast('网络状态已恢复', 'ok');
});
$('btn-recover-proxy').onclick = doRecover;
$('banner-recover').onclick = doRecover;

$('btn-export-diag').onclick = () => task('导出诊断报告', async () => {
  const p = await bridge().ExportDiagnostics();
  if (p) {
    log('脱敏诊断报告已保存：' + p, 'ok');
    toast('诊断报告已导出', 'ok');
  }
});

const doOpenLogs = () => bridge().OpenLogs().catch(e => {
  log(errText(e), 'err');
  toast(errText(e), 'err');
});
$('btn-open-logs').onclick = doOpenLogs;
$('logs-open-dir').onclick = doOpenLogs;

for (const btn of document.querySelectorAll('.theme-btn')) {
  btn.onclick = () => applyTheme(btn.dataset.themeChoice);
}

$('btn-check-sites').onclick = runSiteCheck;
$('empty-check-start').onclick = runSiteCheck;
$('check-domain-form').onsubmit = e => {
  e.preventDefault();
  runCustomDomainCheck($('check-custom-input').value);
};
for (const chip of document.querySelectorAll('[data-check-cat]')) {
  chip.onclick = () => {
    checkCat = chip.dataset.checkCat;
    for (const c of document.querySelectorAll('[data-check-cat]')) c.classList.toggle('active', c === chip);
    renderCheckView();
  };
}

for (const chip of document.querySelectorAll('[data-log-filter]')) {
  chip.onclick = () => {
    logFilter = chip.dataset.logFilter;
    for (const c of document.querySelectorAll('[data-log-filter]')) c.classList.toggle('active', c === chip);
    renderLogs();
  };
}
$('clear-log').onclick = () => { logEntries = []; renderLogs(); };
$('filter').oninput = () => render();

document.addEventListener('keydown', e => {
  if (dlg.open || e.target.matches('input, textarea, select')) return;
  if (e.ctrlKey && e.key.toLowerCase() === 'v') {
    e.preventDefault();
    $('import-clipboard').click();
    return;
  }
  if (activeView !== 'nodes' || !selected) return;
  if (e.key === 'Enter') command('connect', selected);
  else if (e.key === 'Delete') command('remove', selected);
  else if (e.key === 'F2') command('rename', selected);
  else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    e.preventDefault();
    const rows = [...$('rows').children].map(r => r.dataset.id);
    const i = rows.indexOf(selected);
    selected = rows[Math.max(0, Math.min(rows.length - 1, i + (e.key === 'ArrowDown' ? 1 : -1)))] || selected;
    render();
  }
});

applyTheme(getStoredTheme());
log('txlite 已就绪。复制服务器面板的 txlite:// 或 txpulse:// 分享链接后按 Ctrl+V 即可导入。');
refresh();
setInterval(() => { if (!busy) refresh(); }, 1000);
