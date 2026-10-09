'use strict';
const $ = id => document.getElementById(id);
let prev = null, polling = null;

function el(tag, text, cls) { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; }
function bytes(n) { n = Math.max(0, Number(n) || 0); const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; } return n.toFixed(i ? 1 : 0) + ' ' + u[i]; }
function duration(s) { const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60); return d ? d + ' 天 ' + h + ' 小时' : h ? h + ' 小时 ' + m + ' 分' : m + ' 分钟'; }
function notice(text, error = false) { const n = $('notice'); n.textContent = text || ''; n.hidden = !text; n.className = 'notice' + (error ? ' error' : ''); }

async function api(path, body) {
  const opts = { credentials: 'same-origin', cache: 'no-store', headers: {} };
  if (body !== undefined) { opts.method = 'POST'; opts.headers['Content-Type'] = 'application/json'; opts.headers['X-TXL'] = '1'; opts.body = JSON.stringify(body); }
  const r = await fetch('api/' + path, opts);
  if (r.status === 401 && path !== 'login') { showLogin(); throw Error('请先登录'); }
  const data = r.headers.get('Content-Type')?.includes('json') ? await r.json() : null;
  if (!r.ok) throw Error(data?.error || ('请求失败（HTTP ' + r.status + '）'));
  return data;
}

function showLogin() { clearInterval(polling); polling = null; $('app').hidden = true; $('login').hidden = false; $('password').focus(); }
async function showApp() { $('login').hidden = true; $('app').hidden = false; await Promise.all([refreshStatus(), loadLinks(), loadSettings(), loadLogs()]); clearInterval(polling); polling = setInterval(() => refreshStatus().catch(() => {}), 3000); }

async function refreshStatus() {
  const s = await api('status');
  $('server-name').textContent = s.name; $('version').textContent = s.version; $('state-dot').className = 'dot ok';
  $('uptime').textContent = duration(s.uptime); $('active').textContent = s.active;
  $('up').textContent = bytes(s.uploaded); $('down').textContent = bytes(s.downloaded);
  const now = Date.now();
  if (prev && now > prev.at) { const sec = (now - prev.at) / 1000; $('up-rate').textContent = bytes((s.uploaded - prev.up) / sec) + '/s'; $('down-rate').textContent = bytes((s.downloaded - prev.down) / sec) + '/s'; }
  prev = { at: now, up: s.uploaded, down: s.downloaded };
  const sys = s.system || {}, rows = [
    ['系统', sys.os || '—'], ['内核', sys.kernel || '—'], ['负载', sys.load || '—'],
    ['内存', sys.mem_total ? bytes(sys.mem_total - sys.mem_available) + ' / ' + bytes(sys.mem_total) : '—'],
    ['磁盘', sys.disk_total ? bytes(sys.disk_total - sys.disk_free) + ' / ' + bytes(sys.disk_total) : '—'],
    ['拥塞控制', (sys.congestion || '—') + (sys.qdisc ? ' + ' + sys.qdisc : '')],
    ['公网 IPv4', s.ipv4 || '未检测到'], ['公网 IPv6', s.ipv6 || '未检测到'],
    ['代理端口', s.port + ' / TCP'], ['面板端口', s.panel_port + ' / TCP'],
  ];
  $('system').replaceChildren(...rows.flatMap(([k, v]) => [el('dt', k), el('dd', v)]));
}

async function loadLinks() {
  const links = await api('links');
  if (!links.length) { $('links').replaceChildren(el('p', '没有检测到公网地址，请在设置里填写自定义分享地址。', 'muted')); return; }
  $('links').replaceChildren(...links.map((l, i) => {
    const row = el('div', undefined, 'link'), code = el('code', l.url), buttons = el('div', undefined, 'buttons');
    code.title = l.url;
    const copy = el('button', '复制'), qr = el('button', '二维码');
    copy.type = qr.type = 'button';
    copy.onclick = async () => { try { await navigator.clipboard.writeText(l.url); notice('已复制 ' + l.label + ' 分享链接'); } catch { prompt('复制下面的分享链接：', l.url); } };
    qr.onclick = () => { const old = row.querySelector('img'); if (old) { old.remove(); return; } const img = el('img', undefined, 'qr'); img.alt = l.label + ' 二维码'; img.src = 'api/qr?i=' + i + '&t=' + Date.now(); row.append(img); };
    buttons.append(copy, qr); row.append(el('span', l.label, 'tag'), code, buttons); return row;
  }));
}

async function loadSettings() {
  const s = await api('settings'), f = $('settings');
  f.name.value = s.name; f.port.value = s.port; f.outbound_ip.value = s.outbound_ip || ''; f.bandwidth_mbps.value = Math.round(s.bandwidth_mbps * 100) / 100; f.hosts.value = (s.hosts || []).join('\n');
}
async function loadLogs() { const lines = await api('logs'); $('logs').textContent = lines.length ? lines.slice(-200).join('\n') : '暂无日志'; $('logs').scrollTop = $('logs').scrollHeight; }

async function afterChange(result) {
  notice(result.message || '已保存');
  if (result.restart) { $('state-dot').className = 'dot bad'; setTimeout(() => { prev = null; Promise.all([refreshStatus(), loadLinks(), loadSettings()]).catch(e => notice('服务重启中，请稍后刷新页面：' + e.message, true)); }, 4000); }
  else await Promise.all([loadLinks(), loadSettings()]);
}
async function guard(button, fn) { button.disabled = true; try { await fn(); } catch (e) { notice(e.message, true); } finally { button.disabled = false; } }

$('login-form').onsubmit = async e => { e.preventDefault(); $('login-error').textContent = ''; try { await api('login', { password: $('password').value }); $('password').value = ''; await showApp(); } catch (err) { $('login-error').textContent = err.message; } };
$('settings').onsubmit = e => { e.preventDefault(); const f = e.target; guard(f.querySelector('button'), async () => afterChange(await api('settings', { name: f.name.value, port: Number(f.port.value), outbound_ip: f.outbound_ip.value, bandwidth_mbps: Number(f.bandwidth_mbps.value), hosts: f.hosts.value.split(/\s+/).filter(Boolean) }))); };
$('password-form').onsubmit = e => { e.preventDefault(); const f = e.target; guard(f.querySelector('button'), async () => { await api('password', { current: f.current.value, new: f.new.value }); f.reset(); notice('面板密码已修改，其他已登录的浏览器需要重新登录'); }); };
$('reset-token').onclick = e => { if (!confirm('重置后所有旧分享链接立即失效，客户端需要重新导入新链接。确定重置？')) return; guard(e.target, async () => afterChange(await api('token/reset', {}))); };
$('reset-traffic').onclick = e => { if (!confirm('确定清零累计流量统计？')) return; guard(e.target, async () => { notice((await api('traffic/reset', {})).message); prev = null; await refreshStatus(); }); };
$('restart').onclick = e => { if (!confirm('确定重启服务？当前连接会短暂中断。')) return; guard(e.target, async () => afterChange(await api('restart', {}))); };
$('refresh-logs').onclick = e => guard(e.target, loadLogs);
$('logout').onclick = async () => { try { await api('logout', {}); } catch {} showLogin(); };

api('status').then(showApp).catch(() => showLogin());
