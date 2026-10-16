'use strict';
const $ = id => document.getElementById(id);
const bridge = () => { const b = window.go?.main?.App; if (!b) throw Error('客户端正在初始化，请稍候'); return b; };
let status = {}, servers = [], selected = '', probes = new Map(), busy = false, menuFor = '';
const stages = { restoring_proxy: '正在恢复代理设置', verifying_tls: '正在建立安全连接', authenticating: '正在验证密钥', starting_proxy: '正在启动本地代理', checking_tun_network: '正在检查 IPv6 出口', starting_tun: '正在配置 TUN 虚拟网卡', reconnecting: '网络变化，正在自动重连', cancelling: '正在取消' };

function el(tag, text, cls) { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; }
function bytes(n) { n = Math.max(0, Number(n) || 0); const u = ['B', 'KB', 'MB', 'GB']; let i = 0; while (n >= 1024 && i < 3) { n /= 1024; i++; } return n.toFixed(i ? 1 : 0) + ' ' + u[i]; }
function log(text, kind = '') {
  const line = el('span', new Date().toLocaleTimeString('zh-CN', { hour12: false }) + '  ' + text + '\n', kind);
  $('log').append(line);
  while ($('log').childNodes.length > 300) $('log').firstChild.remove();
  $('log').scrollTop = $('log').scrollHeight;
}
function errText(e) { const t = String(e?.message || e || '操作失败'); return /context canceled|context deadline exceeded/i.test(t) ? '已取消' : t; }
const connected = () => status.connected === true || ['connected', 'degraded'].includes(status.connection_state);
const connecting = () => status.connection_state === 'connecting';

async function task(label, fn) {
  if (busy) return;
  busy = true; render();
  try { await fn(); } catch (e) { const t = errText(e); if (t !== '已取消') log(label + '失败：' + t, 'err'); }
  finally { busy = false; await refresh(); }
}

async function refresh() {
  try { status = await bridge().Status(); servers = await bridge().Servers(); }
  catch (e) { return; }
  if (!servers.some(s => s.id === selected)) selected = status.preferences?.selected_id || servers[0]?.id || '';
  render();
}

function render() {
  const pref = status.preferences || {}, active = pref.selected_id, filter = $('filter').value.trim().toLowerCase();
  const shown = servers.filter(s => !filter || (s.name + ' ' + s.host).toLowerCase().includes(filter));
  $('empty').hidden = servers.length > 0;
  $('rows').replaceChildren(...shown.map(s => {
    const tr = el('tr'), p = probes.get(s.id);
    tr.dataset.id = s.id;
    if (s.id === selected) tr.classList.add('sel');
    if (s.id === active) tr.classList.add('active');
    const ms = el('td', p?.busy ? '测试中…' : p?.error ? p.error : p?.ms !== undefined ? p.ms + ' ms' : '', 'c-ms');
    if (p?.ms !== undefined) ms.className += p.ms < 200 ? ' ms-good' : p.ms < 500 ? ' ms-warm' : ' ms-bad';
    if (p?.error) { ms.className += ' ms-bad'; ms.title = p.error; }
    tr.append(el('td', s.id === active ? '✓' : '', 'c-act'), el('td', s.name), el('td', s.host), el('td', String(s.port), 'c-port'), el('td', 'txlite', 'c-type'), el('td', s.family, 'c-fam'), ms);
    return tr;
  }));
  const on = connected(), going = connecting();
  $('connect').textContent = on ? '断开' : going ? '连接中…' : '连接';
  $('connect').classList.toggle('on', on);
  $('connect').disabled = busy || going || (!on && !selected);
  $('cancel').hidden = !going;
  $('probe-all').disabled = busy || !servers.length;
  $('mode').value = pref.proxy_mode || 'bypass_cn';
  $('mode').disabled = busy || on || going;
  const taken = status.system_proxy_taken === true, proxyOn = status.system_proxy === true && !taken;
  $('system-proxy').textContent = '系统代理：' + (taken ? '已被其他程序修改' : proxyOn ? '已设置' : on && pref.proxy_mode === 'tun' ? 'TUN 接管' : '未设置');
  $('system-proxy').classList.toggle('sb-on', proxyOn);
  $('system-proxy').classList.toggle('sb-warn', taken);
  const state = status.connection_state || 'disconnected';
  $('state-dot').className = 'dot ' + state;
  $('state').textContent = going ? (stages[status.connection_stage] || '正在连接') : state === 'degraded' ? '连接异常' : on ? '已连接' : '未连接';
  const current = servers.find(s => s.id === (on || going ? status.node_id : active));
  $('current').textContent = current ? (on ? '当前：' : '活动服务器：') + current.name : '';
  $('speed').textContent = '↑ ' + bytes(on ? status.upload_rate : 0) + '/s  ↓ ' + bytes(on ? status.download_rate : 0) + '/s';
  $('ports').textContent = status.socks ? 'SOCKS ' + status.socks.split(':').pop() + ' · HTTP ' + status.http.split(':').pop() : '';
  const warning = [status.startup_warning, status.proxy_recovery_error].filter(Boolean).join(' ');
  $('warning').textContent = warning; $('warning').hidden = !warning;
}

async function connectTo(id) {
  const pref = status.preferences || {};
  if (connected()) { if (status.node_id === id) return; await bridge().Disconnect(); }
  await bridge().SavePreferences(id);
  const name = servers.find(s => s.id === id)?.name || '';
  log('正在连接 ' + name + ' …');
  const watch = setInterval(refresh, 400);
  try { await bridge().Connect(id); log('已连接 ' + name + '（' + $('mode').selectedOptions[0].text + (pref.proxy_mode !== 'tun' ? '，已设置 Windows 系统代理' : '') + '）', 'ok'); }
  finally { clearInterval(watch); }
}

async function probe(id) {
  probes.set(id, { busy: true }); render();
  try { probes.set(id, { ms: await bridge().Probe(id) }); }
  catch (e) { probes.set(id, { error: errText(e) }); }
  render();
}

async function importText(fn, text) {
  const r = text === undefined ? await bridge().ImportClipboard() : await bridge().Import(text);
  log('导入完成：新增 ' + r.added + ' 个' + (r.updated ? '，更新 ' + r.updated + ' 个' : ''), 'ok');
  await refresh();
  if (!selected && servers.length) selected = servers[servers.length - 1].id;
}

// dialog(title, fields, onOk): fields is a list of DOM nodes; onOk may throw to keep it open.
function dialog(title, nodes, onOk, okText = '确定') {
  const d = $('dialog');
  $('dialog-title').textContent = title; $('dialog-body').replaceChildren(...nodes); $('dialog-error').textContent = '';
  $('dialog-ok').textContent = okText; $('dialog-ok').hidden = !onOk;
  $('dialog-cancel').textContent = onOk ? '取消' : '关闭';
  $('dialog-form').onsubmit = async ev => {
    ev.preventDefault();
    if (!onOk) { d.close(); return; }
    $('dialog-ok').disabled = true;
    try { await onOk(); d.close(); } catch (e) { $('dialog-error').textContent = errText(e); }
    finally { $('dialog-ok').disabled = false; }
  };
  d.showModal();
  d.querySelector('textarea, input')?.focus();
}
$('dialog-cancel').onclick = () => $('dialog').close();

function field(label, input) { const l = el('label', label); l.append(input); return l; }

function openSettings() {
  const pref = status.preferences || {}, rules = status.routing_rules || {};
  const domains = el('textarea'); domains.value = (pref.direct_domains || []).join('\n'); domains.placeholder = '每行一个，例如 example.com';
  const theme = el('select'); for (const [v, t] of [['system', '跟随系统'], ['light', '浅色'], ['dark', '深色']]) { const o = el('option', t); o.value = v; theme.append(o); }
  theme.value = localStorage.getItem('txlite.theme') || 'system';
  const ruleInfo = el('p', '分流规则：' + Number(rules.domains || 0).toLocaleString() + ' 条域名 · ' + Number(rules.ip_prefixes || 0).toLocaleString() + ' 段 IP · ' + (rules.source === 'updated' ? '更新于 ' + new Date(rules.updated_at * 1000).toLocaleString('zh-CN') : '随版本内置') + '。来源：MetaCubeX meta-rules-dat（与 Clash Verge Rev 相同的 geosite / geoip）', 'note');
  const update = el('button', '更新分流规则'), recover = el('button', '恢复系统代理'), diag = el('button', '导出诊断报告');
  for (const b of [update, recover, diag]) b.type = 'button';
  update.onclick = () => task('更新分流规则', async () => { log('正在下载分流规则…'); await bridge().UpdateRoutingRules(); log('分流规则已更新，下次连接生效', 'ok'); $('dialog').close(); });
  recover.onclick = () => task('恢复系统代理', async () => { await bridge().RecoverProxy(); log('已恢复 Windows 原有系统代理设置', 'ok'); });
  diag.onclick = () => task('导出诊断', async () => { const p = await bridge().ExportDiagnostics(); if (p) log('诊断报告已保存：' + p, 'ok'); });
  const actions = el('div', undefined, 'row'); actions.append(update, recover, diag);
  const ports = el('p', '本地端口：SOCKS5 ' + (status.socks || '—') + ' · HTTP ' + (status.http || '—') + '（可在数据目录的 settings.json 修改）', 'note');
  const data = el('p', '数据目录：' + (status.data_directory || '—') + '　版本：' + (status.version || ''), 'note');
  dialog('设置', [field('绕过大陆模式下的直连例外', domains), field('界面主题', theme), ruleInfo, actions, ports, data], async () => {
    applyTheme(theme.value);
    if (connected() || connecting()) { if (domains.value.trim() !== (pref.direct_domains || []).join('\n')) throw Error('请先断开连接再修改直连例外'); return; }
    await bridge().SaveProxyMode(pref.proxy_mode || 'bypass_cn', domains.value);
    log('设置已保存', 'ok'); await refresh();
  }, '保存');
}

function applyTheme(v) {
  document.documentElement.dataset.theme = v === 'system' ? '' : v;
  try { localStorage.setItem('txlite.theme', v); } catch {}
  bridge().SetTheme(v).catch(() => {});
}

function openMenu(id, x, y) {
  menuFor = id; selected = id; render();
  const m = $('menu'); m.hidden = false;
  m.style.left = Math.min(x, innerWidth - m.offsetWidth - 4) + 'px';
  m.style.top = Math.min(y, innerHeight - m.offsetHeight - 4) + 'px';
}
function closeMenu() { $('menu').hidden = true; }

async function command(cmd, id) {
  const s = servers.find(v => v.id === id); if (!s) return;
  if (cmd === 'connect') return task('连接', () => connectTo(id));
  if (cmd === 'probe') return probe(id);
  if (cmd === 'copy') return task('复制分享链接', async () => { await bridge().CopyShareLink(id); log('已复制 ' + s.name + ' 的分享链接', 'ok'); });
  if (cmd === 'rename') { const input = el('input'); input.type = 'text'; input.value = s.name; input.maxLength = 64; return dialog('重命名服务器', [field('别名', input)], async () => { await bridge().Rename(id, input.value); await refresh(); }); }
  if (cmd === 'remove') return dialog('删除服务器', [el('p', '确定删除「' + s.name + '」？删除后需要重新导入分享链接。', 'note')], async () => { await bridge().Remove(id); probes.delete(id); log('已删除 ' + s.name); await refresh(); }, '删除');
}

$('rows').onclick = e => { const tr = e.target.closest('tr'); if (tr) { selected = tr.dataset.id; render(); } };
$('rows').ondblclick = e => { const tr = e.target.closest('tr'); if (tr) command('connect', tr.dataset.id); };
$('rows').oncontextmenu = e => { const tr = e.target.closest('tr'); if (!tr) return; e.preventDefault(); openMenu(tr.dataset.id, e.clientX, e.clientY); };
$('menu').onclick = e => { const b = e.target.closest('button'); if (!b) return; closeMenu(); command(b.dataset.cmd, menuFor); };
document.addEventListener('pointerdown', e => { if (!$('menu').contains(e.target)) closeMenu(); });
document.addEventListener('contextmenu', e => { if (!e.target.closest('#rows, input, textarea, .log')) e.preventDefault(); });

$('import-clipboard').onclick = () => task('导入', () => importText());
$('import-manual').onclick = () => { const t = el('textarea'); t.placeholder = 'txlite://…\n可一次粘贴多个，每行一个'; dialog('添加分享链接', [field('分享链接', t)], () => importText(null, t.value)); };
$('probe-all').onclick = () => task('测试延迟', async () => {
  for (const s of servers) probes.set(s.id, { busy: true }); render(); log('正在测试全部服务器延迟…');
  for (const r of await bridge().ProbeAll()) probes.set(r.id, r.error ? { error: r.error } : { ms: r.ms });
  const ok = [...probes.values()].filter(p => p.ms !== undefined).length;
  log('延迟测试完成：' + ok + ' / ' + servers.length + ' 个可用', 'ok');
});
$('connect').onclick = () => task(connected() ? '断开' : '连接', async () => {
  if (connected()) { const hadProxy = status.system_proxy === true && status.system_proxy_taken !== true; await bridge().Disconnect(); log(hadProxy ? '已断开，Windows 系统代理已恢复' : '已断开'); return; }
  await connectTo(selected);
});
$('cancel').onclick = () => bridge().CancelConnect().then(() => log('已取消连接'));
$('mode').onchange = () => task('切换路由', async () => { await bridge().SaveProxyMode($('mode').value, (status.preferences?.direct_domains || []).join('\n')); log('路由已切换为 ' + $('mode').selectedOptions[0].text + '，下次连接生效'); });
$('open-settings').onclick = openSettings;
$('open-logs').onclick = () => bridge().OpenLogs().catch(e => log(errText(e), 'err'));
$('clear-log').onclick = () => $('log').replaceChildren();
$('filter').oninput = render;
document.addEventListener('keydown', e => {
  if ($('dialog').open || e.target.matches('input, textarea, select')) return;
  if (e.ctrlKey && e.key.toLowerCase() === 'v') { e.preventDefault(); $('import-clipboard').click(); return; }
  if (!selected) return;
  if (e.key === 'Enter') command('connect', selected);
  else if (e.key === 'Delete') command('remove', selected);
  else if (e.key === 'F2') command('rename', selected);
  else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    e.preventDefault();
    const rows = [...$('rows').children].map(r => r.dataset.id), i = rows.indexOf(selected);
    selected = rows[Math.max(0, Math.min(rows.length - 1, i + (e.key === 'ArrowDown' ? 1 : -1)))] || selected; render();
  }
});

try { applyTheme(localStorage.getItem('txlite.theme') || 'system'); } catch {}
log('txlite 已启动。在服务器面板复制分享链接后，按 Ctrl+V 导入。');
refresh();
setInterval(() => { if (!busy) refresh(); }, 1000);
