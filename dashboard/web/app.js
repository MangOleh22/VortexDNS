'use strict';

/* ═══════════════════════════════════════════════════════════════
   VORTEXDNS DASHBOARD

   Every number, row and chart on this page comes from the VortexDNS
   REST API or the SSE query stream. There is no client-side
   simulation: when the API is unreachable the UI reports OFFLINE
   and renders an empty state rather than inventing data.

   Written in ES2017-compatible syntax (no optional chaining) so it
   runs unbuilt in older browsers and can be syntax-checked directly.
═══════════════════════════════════════════════════════════════ */

var API  = '/api';
var SSE  = '/api/logs/stream';
var POLL = 3000; // ms between stat polls

var HIST_LEN = 60;

var state = {
  page:      new URLSearchParams(window.location.search).get('page') || 'dashboard',
  sse:       null,
  sseRetry:  0,
  sseTimer:  null,
  pollTimer: null,
  rtTimer:   null,
  online:    false,
  loggedIn:  false,
  queryAuto: true,
  queries:   [],   // newest first, capped at 500
  config:    null, // last fetched full config
  clients:   [],
  audit:     [],
  syslog:    [],
  schedule:  [],
  stats:     null,
  // Sparklines use per-poll counter deltas; the realtime chart uses
  // per-second counts from the SSE stream. Kept separate so the two
  // timers never overwrite each other's series.
  poll:      { q: [], b: [], c: [], l: [] },
  rt:        { q: [], b: [], c: [], l: [] },
  bucket:    { q: 0, b: 0, c: 0, lSum: 0, lN: 0 },
  totals:    { q: 0, b: 0, c: 0, seeded: false },
};

(function seedHistory() {
  for (var i = 0; i < HIST_LEN; i++) {
    state.poll.q.push(0); state.poll.b.push(0); state.poll.c.push(0); state.poll.l.push(0);
    state.rt.q.push(0);   state.rt.b.push(0);   state.rt.c.push(0);   state.rt.l.push(0);
  }
})();

/* ── DOM HELPERS ────────────────────────────────────────── */
function $(id) { return document.getElementById(id); }

function setText(id, v) { var e = $(id); if (e) e.textContent = v; }

function setValue(id, v) { var e = $(id); if (e) e.value = (v === null || v === undefined) ? '' : v; }

function getVal(id) { var e = $(id); return e ? e.value : ''; }

function trimVal(id) { return String(getVal(id)).trim(); }

function push(arr, v) { arr.push(v); if (arr.length > HIST_LEN) arr.shift(); }

// Escape all API-derived text before it reaches innerHTML. Domain names and
// client-supplied values must never be able to inject markup.
function esc(v) {
  var s = (v === null || v === undefined) ? '' : String(v);
  return s.replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}

function num(v) { return Number(v || 0).toLocaleString('id-ID'); }

function pct(part, total) {
  if (!total) return 0;
  return (Number(part) / Number(total)) * 100;
}

function fmtUptime(seconds) {
  var s = Math.max(0, Math.floor(Number(seconds) || 0));
  var d = Math.floor(s / 86400);
  var h = Math.floor((s % 86400) / 3600);
  var m = Math.floor((s % 3600) / 60);
  if (d > 0) return d + 'd ' + h + 'h';
  if (h > 0) return h + 'h ' + m + 'm';
  return m + 'm';
}

function fmtTime(ts) {
  if (!ts) return '—';
  var d = new Date(ts);
  if (isNaN(d.getTime())) return String(ts);
  return d.toLocaleTimeString('id-ID');
}

function fmtDateTime(ts) {
  if (!ts) return '—';
  var d = new Date(ts);
  if (isNaN(d.getTime())) return String(ts);
  return d.toLocaleString('id-ID');
}

function emptyRow(cols, msg) {
  return '<tr><td colspan="' + cols + '" style="text-align:center;color:var(--text3);padding:18px 0">' +
    esc(msg || 'Belum ada data') + '</td></tr>';
}

function emptyBlock(msg) {
  return '<div style="text-align:center;color:var(--text3);font-size:12px;padding:18px 0">' +
    esc(msg || 'Belum ada data') + '</div>';
}

function showToast(msg, type) {
  var colors = {
    green: 'var(--green)', red: 'var(--red)', yellow: 'var(--yellow)',
    cyan: 'var(--cyan)', blue: 'var(--blue)',
  };
  var toast = $('toast'), inner = $('toast-inner');
  if (!toast || !inner) return;
  var color = colors[type || 'green'] || colors.green;
  inner.style.borderColor = color;
  inner.style.color = color;
  inner.textContent = msg;
  toast.classList.add('show');
  clearTimeout(toast._t);
  toast._t = setTimeout(function () { toast.classList.remove('show'); }, 2800);
}

/* Centered in-page confirmation modal. Returns a Promise<boolean>.
   Replaces window.confirm() so the dialog renders inside the app instead of
   the browser chrome. Falls back to confirm() if markup is missing. */
function confirmModal(opts) {
  opts = opts || {};
  return new Promise(function (resolve) {
    var bd = $('modal-backdrop');
    if (!bd) { resolve(window.confirm(opts.message || 'Anda yakin?')); return; }
    var box = bd.querySelector('.modal-box');
    setText('modal-title', opts.title || 'Konfirmasi');
    setText('modal-msg', opts.message || 'Anda yakin?');
    var okBtn = $('modal-ok'), cancelBtn = $('modal-cancel'), iconEl = $('modal-icon');
    okBtn.textContent = opts.okText || 'Ya, Lanjutkan';
    cancelBtn.textContent = opts.cancelText || 'Batal';
    if (iconEl) iconEl.textContent = opts.icon || '?';
    if (box) { if (opts.danger) box.classList.add('danger'); else box.classList.remove('danger'); }
    okBtn.className = 'btn ' + (opts.danger ? 'btn-danger' : 'btn-primary');

    function cleanup(result) {
      bd.classList.remove('show');
      okBtn.onclick = null; cancelBtn.onclick = null; bd.onclick = null;
      document.removeEventListener('keydown', onKey);
      resolve(result);
    }
    function onKey(e) {
      if (e.key === 'Escape') cleanup(false);
      else if (e.key === 'Enter') cleanup(true);
    }
    okBtn.onclick = function () { cleanup(true); };
    cancelBtn.onclick = function () { cleanup(false); };
    bd.onclick = function (e) { if (e.target === bd) cleanup(false); };
    document.addEventListener('keydown', onKey);
    bd.classList.add('show');
    okBtn.focus();
  });
}

/* ── API LAYER ──────────────────────────────────────────── */

function ApiError(message, status) {
  this.name = 'ApiError';
  this.message = message;
  this.status = status;
}
ApiError.prototype = Object.create(Error.prototype);

// apiFetch rejects on failure so callers surface a real error instead of
// silently substituting invented data.
function apiFetch(path, opts) {
  var options = { headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' } };
  if (opts) { for (var k in opts) { if (Object.prototype.hasOwnProperty.call(opts, k)) options[k] = opts[k]; } }

  return fetch(API + path, options).then(function (res) {
    return res.text().then(function (text) {
      var body = null;
      if (text) { try { body = JSON.parse(text); } catch (e) { /* non-JSON body */ } }
      if (!res.ok) {
        if (res.status === 401) sessionExpired();
        throw new ApiError((body && body.error) || ('HTTP ' + res.status), res.status);
      }
      setOnline(true);
      return body;
    });
  });
}

// apiTry resolves to null on failure, for panels where one missing section
// should not abort the rest of the render.
function apiTry(path, opts) {
  return apiFetch(path, opts).catch(function (err) {
    if (!(err instanceof ApiError)) setOnline(false);
    return null;
  });
}

// All mutations go through here, so each one reports either success or the
// actual server error. Nothing ever claims success on failure.
function apiMutate(path, opts, okMsg) {
  return apiFetch(path, opts).then(function () {
    if (okMsg) showToast('✓ ' + okMsg, 'green');
    return true;
  }).catch(function (err) {
    showToast('✕ ' + (err.message || 'Gagal'), 'red');
    return false;
  });
}

function setOnline(ok) {
  if (state.online === ok) return;
  state.online = ok;
  setConnStatus(ok ? (state.sse ? 'live' : 'polling') : 'disconnected');
}

function setConnStatus(status) {
  var label = $('conn-label'), bar = $('conn-bar'), msg = $('conn-bar-msg');
  if (!label) return;

  if (status === 'live') {
    label.textContent = 'LIVE';
    if (bar) bar.className = '';
  } else if (status === 'polling') {
    label.textContent = 'POLLING';
    if (bar) bar.className = '';
  } else if (status === 'reconnecting') {
    label.textContent = 'RECONNECTING';
    if (bar) bar.className = 'reconnecting show';
    if (msg) msg.textContent = '↻ Menyambung ulang ke stream VortexDNS...';
  } else {
    label.textContent = 'OFFLINE';
    if (bar) bar.className = 'disconnected show';
    if (msg) msg.textContent = '✕ Tidak dapat terhubung ke VortexDNS API';
  }
}

function sessionExpired() {
  if (!state.loggedIn) return;
  state.loggedIn = false;
  stopStreams();
  showLoginView();
  showToast('Sesi berakhir, silakan login ulang', 'yellow');
}

/* ═══════════════════════════════════════════════════════════
   LOGIN
═══════════════════════════════════════════════════════════ */
var loginAttempts = 0;
var loginRemember = true;
var loginPwVisible = false;
var loginClockTimer = null;

(function spawnParticles() {
  var wrap = $('l-particles');
  if (!wrap) return;
  var colors = ['#00d4ff', '#9b5cff', '#4f8eff', '#00e676'];
  for (var i = 0; i < 30; i++) {
    var p = document.createElement('div');
    p.className = 'l-particle';
    p.style.cssText =
      'left:' + (Math.random() * 100) + 'vw;top:' + (Math.random() * 100) + 'vh;' +
      'animation-duration:' + (7 + Math.random() * 10) + 's;' +
      'animation-delay:' + (Math.random() * 8) + 's;' +
      'background:' + colors[i % colors.length] + ';opacity:' + (0.2 + (i % 5) * 0.06);
    wrap.appendChild(p);
  }
})();

function loginClockTick() { setText('l-clock', new Date().toLocaleTimeString('id-ID')); }

// The login page has no session, so /api/stats is not readable from here.
// Show placeholders rather than fabricated counters.
function resetLoginStrip() {
  setText('l-live-stat', 'login untuk melihat statistik');
  setText('ls-q', '— queries');
  setText('ls-b', '— blocked');
  setText('ls-l', '—ms latency');
  setText('ls-u', 'uptime —');
}

function toggleLoginPw() {
  loginPwVisible = !loginPwVisible;
  var inp = $('l-pass'), eye = $('l-eye');
  if (inp) inp.type = loginPwVisible ? 'text' : 'password';
  if (eye) eye.innerHTML = loginPwVisible
    ? '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>'
    : '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
}

function toggleLoginRemember() {
  loginRemember = !loginRemember;
  var chk = $('l-chk');
  if (chk) { chk.classList.toggle('on', loginRemember); chk.textContent = loginRemember ? '✓' : ''; }
}

function showLoginErr(msg) {
  var box = $('l-err');
  setText('l-err-msg', msg);
  if (box) { box.classList.remove('show'); void box.offsetWidth; box.classList.add('show'); }
}

function resetLoginBtn() {
  var btn = $('l-btn');
  if (btn) { btn.disabled = false; btn.textContent = 'Masuk ke Dashboard →'; }
}

function doLogin() {
  var user = trimVal('l-user');
  var pass = getVal('l-pass');
  var btn = $('l-btn');

  if (!user || !pass) { showLoginErr('Username dan password tidak boleh kosong.'); return; }
  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Memverifikasi...'; }

  fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: user, password: pass }),
  }).then(function (res) {
    return res.text().then(function (text) {
      var body = null;
      if (text) { try { body = JSON.parse(text); } catch (e) { /* ignore */ } }
      return { res: res, body: body };
    });
  }).then(function (out) {
    if (out.res.ok) { onLoginSuccess(user); return; }
    if (out.res.status === 403) {
      resetLoginBtn();
      showLoginErr('Admin belum dikonfigurasi. Jalankan setup admin terlebih dahulu.');
      return;
    }
    onLoginFailure(out.body);
  }).catch(function () {
    resetLoginBtn();
    showLoginErr('Koneksi ke server gagal.');
  });
}

/* First-run: swap login form for the setup form. Used when the backend
   reports needs_setup (fresh deployment on a new machine, empty config). */
function showSetupView() {
  var lv = $('login-view');
  if (lv) { lv.style.display = ''; lv.classList.remove('out'); }
  var form = $('l-form'), setup = $('l-setup'), succ = $('l-success');
  if (form) form.style.display = 'none';
  if (setup) setup.style.display = '';
  if (succ) succ.classList.remove('show');
  var sub = document.querySelector('.login-brand-sub');
  if (sub) sub.textContent = 'Setup Awal · Buat Akun Administrator';
}

function doSetup() {
  var user = trimVal('s-user');
  var pass = getVal('s-pass');
  var pass2 = getVal('s-pass2');
  var btn = $('s-btn');

  if (user.length < 3) { showLoginErr('Username minimal 3 karakter.'); return; }
  if (pass.length < 6) { showLoginErr('Password minimal 6 karakter.'); return; }
  if (pass !== pass2) { showLoginErr('Password tidak cocok.'); return; }

  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Menyiapkan...'; }

  fetch('/api/auth/setup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: user, password: pass }),
  }).then(function (res) {
    return res.text().then(function (text) {
      var body = null;
      if (text) { try { body = JSON.parse(text); } catch (e) { /* ignore */ } }
      return { res: res, body: body };
    });
  }).then(function (out) {
    if (btn) { btn.disabled = false; btn.textContent = 'Buat Akun & Mulai →'; }
    if (out.res.ok) {
      showToast('✓ Akun admin dibuat. Silakan login.', 'green');
      var setup = $('l-setup'), form = $('l-form');
      if (setup) setup.style.display = 'none';
      if (form) form.style.display = '';
      var sub = document.querySelector('.login-brand-sub');
      if (sub) sub.textContent = 'DNS Management Dashboard · Restricted Access';
      setValue('l-user', user);
      var p = $('l-pass'); if (p) p.focus();
      return;
    }
    showLoginErr((out.body && out.body.error) || 'Gagal membuat akun.');
  }).catch(function () {
    if (btn) { btn.disabled = false; btn.textContent = 'Buat Akun & Mulai →'; }
    showLoginErr('Koneksi ke server gagal.');
  });
}

function onLoginSuccess(user) {
  loginAttempts = 0;
  var form = $('l-form'), succ = $('l-success');
  if (form) form.style.display = 'none';
  if (succ) succ.classList.add('show');
  setText('l-welcome', 'Selamat datang, ' + user + ' ✓');
  setText('t-uname', user);
  setText('t-avatar', user.charAt(0).toUpperCase());
  setTimeout(function () { var pg = $('l-prog'); if (pg) pg.style.width = '100%'; }, 50);
  setTimeout(function () { enterPanel(true); }, 1400);
}

function onLoginFailure(body) {
  loginAttempts++;
  resetLoginBtn();
  ['l-user', 'l-pass'].forEach(function (id) {
    var el = $(id);
    if (el) { el.classList.add('err'); setTimeout(function () { el.classList.remove('err'); }, 700); }
  });
  setValue('l-pass', '');

  var pips = $('l-pips');
  if (pips) pips.style.display = 'flex';
  for (var i = 0; i < Math.min(loginAttempts, 3); i++) {
    var pip = $('lp' + i);
    if (pip) pip.classList.add('used');
  }

  if (loginAttempts >= 3) {
    showLoginErr('Terlalu banyak percobaan. Tunggu 30 detik.');
    var btn = $('l-btn');
    if (btn) btn.disabled = true;
    setTimeout(function () {
      loginAttempts = 0;
      resetLoginBtn();
      document.querySelectorAll('.l-pip').forEach(function (p) { p.classList.remove('used'); });
      if (pips) pips.style.display = 'none';
    }, 30000);
    return;
  }

  var err = body && body.error;
  showLoginErr(!err || err === 'invalid credentials' ? 'Username atau password salah.' : err);
}

function showLoginView() {
  var lv = $('login-view');
  if (lv) { lv.style.display = ''; lv.classList.remove('out'); }
  var form = $('l-form'), succ = $('l-success');
  if (form) form.style.display = '';
  if (succ) succ.classList.remove('show');
  resetLoginBtn();
  setValue('l-user', '');
  setValue('l-pass', '');
  document.querySelectorAll('.l-pip').forEach(function (p) { p.classList.remove('used'); });
  var pips = $('l-pips');
  if (pips) pips.style.display = 'none';
  loginAttempts = 0;
  resetLoginStrip();
  if (!loginClockTimer) { loginClockTick(); loginClockTimer = setInterval(loginClockTick, 1000); }
}

function hideLoginView(animate) {
  var lv = $('login-view');
  if (lv) {
    if (animate) {
      lv.classList.add('out');
      setTimeout(function () { lv.style.display = 'none'; }, 450);
    } else {
      lv.style.display = 'none';
    }
  }
  if (loginClockTimer) { clearInterval(loginClockTimer); loginClockTimer = null; }
}

function enterPanel(animate) {
  state.loggedIn = true;
  hideLoginView(animate);
  startStreams();
  goPage(state.page || 'dashboard');
}

function doLogout() {
  confirmModal({
    title: 'Keluar dari VortexDNS',
    message: 'Anda akan keluar dari dashboard. Sesi saat ini akan diakhiri.',
    okText: 'Ya, Logout', cancelText: 'Batal', icon: '⎋', danger: true,
  }).then(function (ok) {
    if (!ok) return;
    apiTry('/auth/logout', { method: 'POST' }).then(function () {
      state.loggedIn = false;
      stopStreams();
      showLoginView();
      showToast('✓ Logout berhasil', 'green');
    });
  });
}

document.addEventListener('DOMContentLoaded', function () {
  var pass = $('l-pass');
  if (pass) {
    pass.addEventListener('keydown', function (e) { if (e.key === 'Enter') doLogin(); });
  }
  var user = $('l-user');
  if (user) {
    user.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { var p = $('l-pass'); if (p) p.focus(); }
    });
  }
  var form = $('settings-form');
  if (form) {
    form.addEventListener('submit', function (e) { e.preventDefault(); saveSettings(); });
  }
});

/* ═══════════════════════════════════════════════════════════
   SSE STREAM
═══════════════════════════════════════════════════════════ */
function connectSSE() {
  if (state.sse) { state.sse.close(); state.sse = null; }

  var es;
  try {
    es = new EventSource(SSE);
  } catch (e) {
    setConnStatus('disconnected');
    return;
  }
  state.sse = es;

  es.onopen = function () {
    state.sseRetry = 0;
    state.online = true;
    setConnStatus('live');
  };

  es.onmessage = function (e) {
    var entry;
    try { entry = JSON.parse(e.data); } catch (err) { return; }
    ingestQuery(entry);
  };

  // Reconnect with capped exponential backoff. The status label never claims
  // LIVE while the stream is actually down.
  es.onerror = function () {
    es.close();
    if (state.sse === es) state.sse = null;
    if (!state.loggedIn) return;
    setConnStatus('reconnecting');
    var delay = Math.min(30000, 1000 * Math.pow(2, state.sseRetry));
    state.sseRetry = Math.min(state.sseRetry + 1, 5);
    clearTimeout(state.sseTimer);
    state.sseTimer = setTimeout(connectSSE, delay);
  };
}

function normalizeQuery(e) {
  var status = String(e.status || '');
  var short = 'OK';
  if (status.indexOf('Blocked') === 0) short = 'Block';
  else if (status === 'Cached') short = 'Cache';
  return {
    time:      fmtTime(e.timestamp),
    domain:    String(e.domain || '').replace(/\.$/, ''),
    type:      e.type || '—',
    client:    e.client_ip || '—',
    status:    short,
    rawStatus: status,
    upstream:  e.upstream || '—',
    latency:   Number(e.elapsed_ms || 0),
    dnssec:    e.dnssec || '—',
  };
}

function ingestQuery(raw) {
  var q = normalizeQuery(raw);
  state.queries.unshift(q);
  if (state.queries.length > 500) state.queries.pop();

  var b = state.bucket;
  b.q++;
  if (q.status === 'Block') b.b++;
  if (q.status === 'Cache') b.c++;
  b.lSum += q.latency;
  b.lN++;

  if (state.page === 'realtime') appendRTStream(q);
  if (state.page === 'queries' && state.queryAuto) renderQueryLog();
}

function startStreams() {
  connectSSE();
  if (!state.pollTimer) state.pollTimer = setInterval(mainLoop, POLL);
  mainLoop();
}

function stopStreams() {
  if (state.sse) { state.sse.close(); state.sse = null; }
  clearTimeout(state.sseTimer);
  if (state.pollTimer) { clearInterval(state.pollTimer); state.pollTimer = null; }
  if (state.rtTimer) { clearInterval(state.rtTimer); state.rtTimer = null; }
}

/* ═══════════════════════════════════════════════════════════
   NAVIGATION
═══════════════════════════════════════════════════════════ */
var PAGE_LOADERS = {
  dashboard:   loadDashboard,
  logs:        loadLogsPage,
  realtime:    initRealtime,
  geo:         loadConditional,
  blocking:    loadBlocklists,
  whitelist:   loadRules,
  customblock: loadRules,
  services:    loadServices,
  schedule:    loadSchedule,
  upstream:    loadUpstreams,
  zones:       loadZoneRecords,
  cache:       loadCachePage,
  dnssec:      loadDnssecPage,
  clients:     loadClients,
  acl:         loadAclPage,
  metrics:     loadMetricsPage,
  settings:    loadSettings,
};

// Combined log page loads whichever tab is active.
function loadLogsPage() {
  var active = document.querySelector('.log-tab.active');
  var tab = active ? active.dataset.logtab : 'query';
  if (tab === 'query') loadQueryLog();
  else if (tab === 'audit') loadAuditLog();
  else if (tab === 'system') refreshSyslog();
}

function switchLogTab(tab) {
  document.querySelectorAll('.log-tab').forEach(function (b) {
    b.classList.toggle('active', b.dataset.logtab === tab);
  });
  document.querySelectorAll('.logtab-panel').forEach(function (p) {
    p.style.display = p.id === ('logtab-' + tab) ? '' : 'none';
  });
  if (tab === 'query') loadQueryLog();
  else if (tab === 'audit') loadAuditLog();
  else if (tab === 'system') refreshSyslog();
}

function goPage(name) {
  state.page = name;
  document.querySelectorAll('.page').forEach(function (p) { p.classList.add('hidden'); });
  document.querySelectorAll('.nav-item').forEach(function (n) { n.classList.remove('active'); });

  
  if (window.location.pathname === '/login' || new URLSearchParams(window.location.search).get('page') !== name) {
    history.pushState(null, '', '/?page=' + name);
  }

  var pg = $('page-' + name);
  if (pg) pg.classList.remove('hidden');

  document.querySelectorAll('.nav-item').forEach(function (n) {
    if (n.dataset.page === name) n.classList.add('active');
  });

  if (name !== 'realtime' && state.rtTimer) {
    clearInterval(state.rtTimer);
    state.rtTimer = null;
  }

  var loader = PAGE_LOADERS[name];
  if (loader) loader();
}

window.addEventListener('popstate', function () {
  var p = new URLSearchParams(window.location.search).get('page') || 'dashboard';
  if (state.loggedIn) goPage(p);
});
document.querySelectorAll('.nav-item[data-page]').forEach(function (n) {
  n.addEventListener('click', function () { goPage(n.dataset.page); });
});

function updateClock() { setText('topbar-clock', new Date().toLocaleTimeString('id-ID')); }
setInterval(updateClock, 1000);
updateClock();

/* ═══════════════════════════════════════════════════════════
   DASHBOARD
═══════════════════════════════════════════════════════════ */
function fetchStats() {
  return apiTry('/stats').then(function (data) {
    if (!data) return null;
    state.stats = data;

    // Track per-poll counter deltas so the sparklines show real traffic.
    // The first sample only seeds the baseline; it is not plotted as a spike.
    var t = state.totals;
    if (t.seeded) {
      push(state.poll.q, Math.max(0, data.total_queries - t.q));
      push(state.poll.b, Math.max(0, data.blocked_queries - t.b));
      push(state.poll.c, Math.max(0, data.cached_queries - t.c));
      push(state.poll.l, Number(data.avg_latency || 0));
    }
    t.q = data.total_queries;
    t.b = data.blocked_queries;
    t.c = data.cached_queries;
    t.seeded = true;

    setText('sb-uptime', fmtUptime(data.uptime_seconds));
      var archStr = (data.os || 'unknown') + '/' + (data.arch || 'unknown');
      setText('sys-arch', archStr);
      var sb = $('sys-arch-sb');
      if (sb) sb.textContent = archStr;

    return data;
  });
}

function loadDashboard() {
  return Promise.all([
    fetchStats(),
    apiTry('/topdomains?limit=7'),
    apiTry('/clients'),
    apiTry('/status'),
  ]).then(function (out) {
    var stats = out[0], top = out[1], clients = out[2], status = out[3];
    if (clients) state.clients = clients;

    renderStatCards(stats);
    renderStatusRows(status);
    renderTopBars('top-blocked-bars', top && top.blocked, 'red');
    renderTopBars('top-allowed-bars', top && top.allowed, 'green');
    renderTypeBars(top && top.types);
    renderTopClients();

    if (!state.queries.length) return loadRecentQueries().then(renderDashQueries);
    renderDashQueries();
  });
}

function renderStatCards(s) {
  if (!s) {
    ['s-queries', 's-blocked', 's-cached', 's-latency', 's-p95', 's-clients', 's-dnssec']
      .forEach(function (id) { setText(id, '—'); });
    setText('s-block-pct', '—% dari total');
    setText('s-cache-pct', '—% hit rate');
    return;
  }

  setText('s-queries', num(s.total_queries));
  setText('s-blocked', num(s.blocked_queries));
  setText('s-cached', num(s.cached_queries));
  setText('s-latency', s.avg_latency);
  setText('s-p95', s.p95_latency);
  setText('s-clients', s.active_clients);
  setText('s-dnssec', s.dnssec_rate);

  // Response-code breakdown (count + % of total).
  var rcTotal = Number(s.total_queries) || 0;
  function rc(id, val) {
    var n = Number(val) || 0;
    var p = rcTotal ? ((n / rcTotal) * 100).toFixed(1) : '0.0';
    setText(id, num(n) + ' (' + p + '%)');
  }
  rc('rc-noerror', s.noerror_queries);
  rc('rc-nxdomain', s.nxdomain_queries);
  rc('rc-refused', s.refused_queries);
  rc('rc-servfail', s.servfail_queries);

  var bp = pct(s.blocked_queries, s.total_queries);
  var cp = pct(s.cached_queries, s.total_queries);
  setText('s-block-pct', bp.toFixed(1) + '% dari total');
  setText('s-cache-pct', cp.toFixed(1) + '% hit rate');

  makeSpark('spark-q', state.poll.q, '#00d4ff');
  makeSpark('spark-b', state.poll.b, '#ff5252');
  makeSpark('spark-c', state.poll.c, '#00e676');
  makeSpark('spark-l', state.poll.l, '#9b5cff');
  renderDonut(cp, bp);
}

function makeSpark(id, data, color) {
  var el = $(id);
  if (!el || data.length < 2) return;
  var max = Math.max.apply(null, data.concat([1]));
  var pts = data.map(function (v, i) {
    return ((i / (data.length - 1)) * 120) + ',' + (36 - (v / max) * 33);
  }).join(' ');
  el.innerHTML =
    '<svg viewBox="0 0 120 36" preserveAspectRatio="none">' +
    '<defs><linearGradient id="sg-' + id + '" x1="0" y1="0" x2="1" y2="0">' +
    '<stop offset="0%" stop-color="' + color + '" stop-opacity=".5"/>' +
    '<stop offset="100%" stop-color="' + color + '"/></linearGradient></defs>' +
    '<polyline points="' + pts + '" fill="none" stroke="url(#sg-' + id + ')" stroke-width="1.8" ' +
    'stroke-linecap="round" stroke-linejoin="round" opacity=".9"/></svg>';
}

function renderDonut(cachePct, blockPct) {
  var fwdPct = Math.max(0, 100 - cachePct - blockPct);
  var offset = 0;
  function setCirc(id, p) {
    var el = $(id);
    if (!el) return;
    el.setAttribute('stroke-dasharray', p + ' ' + (100 - p));
    el.setAttribute('stroke-dashoffset', String(25 - offset));
    offset += p;
  }
  setCirc('donut-cached', cachePct);
  setCirc('donut-fwd', fwdPct);
  setCirc('donut-blocked', blockPct);

  setText('leg-cache', cachePct.toFixed(1) + '%');
  setText('leg-fwd', fwdPct.toFixed(1) + '%');
  setText('leg-blocked', blockPct.toFixed(1) + '%');
}

function renderTopBars(elId, rows, color) {
  var el = $(elId);
  if (!el) return;
  if (!rows || !rows.length) { el.innerHTML = emptyBlock('Belum ada query tercatat'); return; }
  var max = rows[0].count || 1;
  el.innerHTML = rows.map(function (d) {
    return '<div class="bar-row">' +
      '<span class="bar-label" title="' + esc(d.label) + '">' + esc(d.label) + '</span>' +
      '<div class="bar-track"><div class="bar-fill ' + color + '" style="width:' +
      Math.round((d.count / max) * 100) + '%"></div></div>' +
      '<span class="bar-count">' + num(d.count) + '</span></div>';
  }).join('');
}

function renderTypeBars(types) {
  var el = $('proto-bars');
  if (!el) return;
  var entries = Object.keys(types || {}).map(function (k) { return [k, types[k]]; })
    .sort(function (a, b) { return b[1] - a[1]; }).slice(0, 6);
  if (!entries.length) { el.innerHTML = emptyBlock('Belum ada query tercatat'); return; }
  var total = entries.reduce(function (sum, e) { return sum + e[1]; }, 0) || 1;
  el.innerHTML = entries.map(function (e) {
    var p = (e[1] / total) * 100;
    return '<div class="bar-row">' +
      '<span class="bar-label">' + esc(e[0]) + '</span>' +
      '<div class="bar-track"><div class="bar-fill cyan" style="width:' + p.toFixed(1) + '%"></div></div>' +
      '<span class="bar-count">' + p.toFixed(1) + '%</span></div>';
  }).join('');
}

function renderTopClients() {
  var el = $('top-clients-bars');
  if (!el) return;
  var rows = state.clients.slice(0, 5);
  if (!rows.length) { el.innerHTML = emptyBlock('Belum ada klien tercatat'); return; }
  var max = rows[0].queries || 1;
  el.innerHTML = rows.map(function (d) {
    return '<div class="bar-row">' +
      '<span class="bar-label" title="' + esc(d.ip) + '">' + esc(d.hostname || d.ip) + '</span>' +
      '<div class="bar-track"><div class="bar-fill cyan" style="width:' +
      Math.round((d.queries / max) * 100) + '%"></div></div>' +
      '<span class="bar-count">' + num(d.queries) + '</span></div>';
  }).join('');
}

function statusPill(feature, onLabel, offLabel) {
  if (!feature || !feature.enabled) {
    return '<span class="pill gray"><span class="pill-dot"></span>' + esc(offLabel || 'Disabled') + '</span>';
  }
  return '<span class="pill green"><span class="pill-dot"></span>' + esc(onLabel || 'Running') + '</span>';
}

function renderStatusRows(st) {
  var el = $('status-rows');
  if (!el) return;
  if (!st) { el.innerHTML = emptyBlock('Status tidak tersedia'); return; }

  var rateDetail = (st.rate_limit && st.rate_limit.address) || 'Active';
  var rows = [
    ['DNS UDP/TCP ' + ((st.dns && st.dns.address) || ''), statusPill(st.dns)],
    ['DNS-over-HTTPS', statusPill(st.doh)],
    ['DNS-over-TLS', statusPill(st.dot)],
    ['DNS-over-QUIC', statusPill(st.doq)],
    ['Recursive Resolver', statusPill(st.recursive, 'Active', 'Off')],
    ['DNSSEC', statusPill(st.dnssec, 'Active', 'Off')],
    ['Rate Limiting', statusPill(st.rate_limit, rateDetail, 'Off')],
    ['ACL', statusPill(st.acl, 'Active', 'Terbuka')],
    ['Safe Browsing', statusPill(st.safe_browsing, 'Active', 'Off')],
    ['Parental Control', statusPill(st.parental, 'Active', 'Off')],
  ];

  var sync = st.blocklist_sync || {};
  var syncPill;
  if (sync.error) {
    syncPill = '<span class="pill red"><span class="pill-dot"></span>Error</span>';
  } else if (sync.updating) {
    syncPill = '<span class="pill yellow"><span class="pill-dot"></span>Updating</span>';
  } else {
    syncPill = '<span class="pill cyan"><span class="pill-dot"></span>' + num(sync.total_rules) + ' rules</span>';
  }
  rows.push(['Blocklist Sync', syncPill]);

  el.innerHTML = rows.map(function (r) {
    return '<div class="status-row"><span class="status-key">' + esc(r[0]) + '</span>' + r[1] + '</div>';
  }).join('');
}

function renderDashQueries() {
  var el = $('dash-queries');
  if (!el) return;
  var rows = state.queries.slice(0, 8);
  if (!rows.length) { el.innerHTML = emptyRow(5, 'Belum ada query'); return; }
  var sc = { OK: 'green', Block: 'red', Cache: 'cyan' };
  el.innerHTML = rows.map(function (q) {
    return '<tr>' +
      '<td class="mono" style="color:var(--text3);font-size:10px">' + esc(q.time) + '</td>' +
      '<td class="mono" style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' +
      esc(q.domain) + '">' + esc(q.domain) + '</td>' +
      '<td><span class="pill blue">' + esc(q.type) + '</span></td>' +
      '<td><span class="pill ' + (sc[q.status] || 'gray') + '">' + esc(q.status) + '</span></td>' +
      '<td class="mono" style="color:var(--text3);font-size:10px;text-align:right">' + q.latency + 'ms</td>' +
      '</tr>';
  }).join('');
}

/* ═══════════════════════════════════════════════════════════
   QUERY LOG
═══════════════════════════════════════════════════════════ */
function loadRecentQueries() {
  return apiTry('/logs?limit=200').then(function (logs) {
    if (Array.isArray(logs)) state.queries = logs.map(normalizeQuery);
  });
}

function loadQueryLog() {
  return loadRecentQueries().then(function () {
    renderQueryLog();
    renderDashQueries();
  });
}

function renderQueryLog() {
  var el = $('query-log-body');
  if (!el) return;
  var filt = trimVal('q-filter').toLowerCase();
  var statF = getVal('q-status');
  var typF = getVal('q-type');

  var rows = state.queries.filter(function (q) {
    return (!filt || q.domain.toLowerCase().indexOf(filt) !== -1) &&
      (!statF || q.status === statF) &&
      (!typF || q.type === typF);
  }).slice(0, 200);

  if (!rows.length) { el.innerHTML = emptyRow(8, 'Tidak ada query yang cocok'); return; }

  var sc = { OK: 'green', Block: 'red', Cache: 'cyan' };
  var dsc = { Secure: 'green', Insecure: 'yellow' };
  el.innerHTML = rows.map(function (q) {
    return '<tr>' +
      '<td class="mono" style="color:var(--text3);font-size:10px">' + esc(q.time) + '</td>' +
      '<td class="mono" title="' + esc(q.domain) + '">' + esc(q.domain) + '</td>' +
      '<td class="mono" style="color:var(--text3);font-size:10px">' + esc(q.client) + '</td>' +
      '<td><span class="pill blue">' + esc(q.type) + '</span></td>' +
      '<td><span class="pill ' + (sc[q.status] || 'gray') + '" title="' + esc(q.rawStatus) + '">' +
      esc(q.status) + '</span></td>' +
      '<td class="mono" style="color:var(--text3);font-size:10px">' + esc(q.upstream) + '</td>' +
      '<td class="mono" style="text-align:right;color:var(--text3);font-size:10px">' + q.latency + 'ms</td>' +
      '<td><span class="pill ' + (dsc[q.dnssec] || 'gray') + '" style="font-size:9px">' +
      esc(q.dnssec) + '</span></td>' +
      '</tr>';
  }).join('');
}

function filterQueries() { renderQueryLog(); }

function toggleQAuto() {
  state.queryAuto = !state.queryAuto;
  setText('btn-qauto', state.queryAuto ? '⏸ Pause Auto' : '▶ Resume Auto');
  if (state.queryAuto) renderQueryLog();
}

/* ═══════════════════════════════════════════════════════════
   REALTIME
═══════════════════════════════════════════════════════════ */
function initRealtime() {
  if (state.rtTimer) clearInterval(state.rtTimer);
  drawRTChart();
  // Roll the SSE bucket into history once per second, so the chart plots
  // measured query rates rather than interpolated values.
  state.rtTimer = setInterval(function () {
    var b = state.bucket;
    var avgLat = b.lN ? Math.round(b.lSum / b.lN) : 0;

    push(state.rt.q, b.q);
    push(state.rt.b, b.b);
    push(state.rt.c, b.c);
    push(state.rt.l, avgLat);

    setText('rt-qps', b.q);
    setText('rt-bps', b.b);
    setText('rt-cps', b.c);
    setText('rt-lat', avgLat);

    state.bucket = { q: 0, b: 0, c: 0, lSum: 0, lN: 0 };
    drawRTChart();
  }, 1000);
}

function drawRTChart() {
  var cv = $('rt-chart');
  if (!cv) return;
  var ctx = cv.getContext('2d');
  cv.width = cv.offsetWidth || 700;
  cv.height = 80;
  var W = cv.width, H = cv.height;
  ctx.clearRect(0, 0, W, H);

  var h = state.rt;
  var max = Math.max.apply(null, h.q.concat(h.b, h.c, [1]));

  function drawLine(data, color, glow) {
    if (data.length < 2) return;
    ctx.save();
    ctx.shadowColor = color;
    ctx.shadowBlur = glow ? 8 : 0;
    ctx.beginPath();
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.8;
    data.forEach(function (v, i) {
      var x = (i / (data.length - 1)) * W;
      var y = H - (v / max) * H * 0.88 - 4;
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    });
    ctx.stroke();
    ctx.restore();
  }

  drawLine(h.q, '#00d4ff', true);
  drawLine(h.b, '#ff5252', false);
  drawLine(h.c, '#00e676', false);
}

function appendRTStream(q) {
  var el = $('rt-stream-body');
  if (!el || !q) return;
  var sc = { OK: 'var(--green)', Block: 'var(--red)', Cache: 'var(--cyan)' };
  var line = document.createElement('div');
  line.style.cssText = 'display:flex;gap:12px;padding:2px 0;border-bottom:1px solid var(--border2);' +
    'font-family:var(--font-mono);font-size:11px';
  line.innerHTML =
    '<span style="color:var(--text3);flex:0 0 70px">' + esc(q.time) + '</span>' +
    '<span style="color:' + (sc[q.status] || 'var(--text2)') + ';flex:0 0 50px">[' + esc(q.status) + ']</span>' +
    '<span style="color:var(--text);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' +
    esc(q.domain) + '</span>' +
    '<span style="color:var(--text3);flex:0 0 90px">' + esc(q.client) + '</span>' +
    '<span style="color:var(--purple);flex:0 0 40px">' + esc(q.type) + '</span>' +
    '<span style="color:var(--text3);flex:0 0 40px;text-align:right">' + q.latency + 'ms</span>';
  el.insertBefore(line, el.firstChild);
  while (el.children.length > 60) el.removeChild(el.lastChild);
}

/* ═══════════════════════════════════════════════════════════
   BLOCKLISTS
═══════════════════════════════════════════════════════════ */
function loadBlocklists() {
  return Promise.all([apiTry('/blocklists'), apiTry('/stats')]).then(function (out) {
    var rows = out[0], stats = out[1];

    if (stats) {
      setText('bl-total', num(stats.total_rules));
      setText('bl-count', stats.blocklist_count);
      setText('bl-last-update', fmtDateTime(stats.last_update));
    }

    var el = $('bl-body');
    if (!el) return;
    if (!Array.isArray(rows) || !rows.length) {
      el.innerHTML = emptyRow(5, 'Belum ada blocklist. Tambahkan URL di bawah.');
      return;
    }
    el.innerHTML = rows.map(function (b) {
      return '<tr>' +
        '<td>' + esc(b.name) + '</td>' +
        '<td class="mono" style="font-size:10px;max-width:260px;overflow:hidden;text-overflow:ellipsis;' +
        'white-space:nowrap" title="' + esc(b.url) + '">' + esc(b.url) + '</td>' +
        '<td class="mono">' + num(b.count) + '</td>' +
        '<td class="mono" style="font-size:10px">' + esc(fmtDateTime(b.updated)) + '</td>' +
        '<td><button class="btn btn-danger" style="font-size:10px;padding:3px 8px" ' +
        'data-url="' + esc(b.url) + '" onclick="delBlocklist(this.dataset.url)">✕</button></td>' +
        '</tr>';
    }).join('');
  });
}

function addBlocklist() {
  var url = trimVal('bl-url');
  if (!url) { showToast('✕ URL blocklist kosong', 'red'); return; }
  apiMutate('/blocklists', { method: 'POST', body: JSON.stringify({ url: url }) },
    'Blocklist ditambahkan, sinkronisasi dimulai').then(function (ok) {
      if (ok) { setValue('bl-url', ''); loadBlocklists(); }
    });
}

function delBlocklist(url) {
  if (!confirm('Hapus blocklist ini?\n\n' + url)) return;
  apiMutate('/blocklists?url=' + encodeURIComponent(url), { method: 'DELETE' }, 'Blocklist dihapus')
    .then(function (ok) { if (ok) loadBlocklists(); });
}

function updateAllBL() {
  apiMutate('/blocklists/update-all', { method: 'POST' }, 'Update semua blocklist dimulai')
    .then(function (ok) { if (ok) setTimeout(loadBlocklists, 2000); });
}

/* ═══════════════════════════════════════════════════════════
   WHITELIST & CUSTOM BLOCK — both backed by /api/rules
═══════════════════════════════════════════════════════════ */
function ruleRows(domains, type, emptyMsg) {
  if (!domains.length) return emptyRow(2, emptyMsg);
  return domains.map(function (d) {
    return '<tr><td class="mono">' + esc(d) + '</td>' +
      '<td><button class="btn btn-danger" style="font-size:10px;padding:3px 8px" ' +
      'data-domain="' + esc(d) + '" onclick="delRule(this.dataset.domain,\'' + type + '\')">✕</button></td></tr>';
  }).join('');
}

function loadRules() {
  return Promise.all([apiTry('/rules'), ensureConfigQuiet()]).then(function (out) {
    var data = out[0], cfg = out[1];

    var wl = $('wl-body');
    if (wl) wl.innerHTML = ruleRows((data && data.whitelist) || [], 'whitelist', 'Belum ada domain whitelist');

    var cb = $('cb-body');
    if (cb) cb.innerHTML = ruleRows((data && data.blacklist) || [], 'blacklist', 'Belum ada domain diblokir manual');

    // Report the blocking mode the server actually uses, instead of listing
    // per-domain modes it does not implement.
    var note = $('cb-mode-note');
    if (note && cfg) {
      var mode = cfg.blocking_mode === 'nxdomain' ? 'NXDOMAIN' : '0.0.0.0 (zero IP)';
      note.textContent = '⚠ Domain di sini diblokir permanen. Mode balasan saat ini: ' +
        mode + ' (ubah di Settings).';
    }
  });
}

function addRule(inputId, type, okMsg) {
  var domain = trimVal(inputId);
  if (!domain) { showToast('✕ Domain kosong', 'red'); return; }
  apiMutate('/rules/add', {
    method: 'POST', body: JSON.stringify({ domain: domain, type: type }),
  }, okMsg).then(function (ok) {
    if (ok) { setValue(inputId, ''); loadRules(); }
  });
}

function addWhitelist() { addRule('wl-domain', 'whitelist', 'Whitelist ditambahkan'); }
function addCustomBlock() { addRule('cb-domain', 'blacklist', 'Domain diblokir'); }

function delRule(domain, type) {
  if (!confirm('Hapus ' + domain + '?')) return;
  apiMutate('/rules/remove', {
    method: 'POST', body: JSON.stringify({ domain: domain, type: type }),
  }, 'Dihapus').then(function (ok) { if (ok) loadRules(); });
}

/* ═══════════════════════════════════════════════════════════
   BLOCKED SERVICES
═══════════════════════════════════════════════════════════ */
var SERVICE_ICONS = {
  facebook: '📘', instagram: '📷', whatsapp: '💬', tiktok: '🎵', youtube: '▶️',
  twitter: '🐦', snapchat: '👻', reddit: '👽', discord: '🎮', telegram: '✈️',
  netflix: '🎬', spotify: '🎧', twitch: '🟣', steam: '🎯', roblox: '🧱',
  epicgames: '🕹️', torrent: '🌊', crypto: '₿', dating: '❤️', disneyplus: '🏰',
  amazon: '📦', pinterest: '📌',
};

function loadServices() {
  return apiTry('/services').then(function (rows) {
    var el = $('services-grid');
    if (!el) return;
    if (!Array.isArray(rows) || !rows.length) {
      el.innerHTML = emptyBlock('Katalog service tidak tersedia');
      return;
    }
    el.innerHTML = rows.map(function (s) {
      return '<div class="svc-card ' + (s.blocked ? 'blocked' : '') + '" ' +
        'data-service="' + esc(s.id) + '" onclick="toggleService(this.dataset.service)">' +
        '<div class="svc-icon">' + (SERVICE_ICONS[s.id] || '🌐') + '</div>' +
        '<div class="svc-name">' + esc(s.id) + '</div>' +
        '<div class="svc-state">' + (s.blocked ? 'BLOCKED' : 'allowed') + '</div>' +
        '</div>';
    }).join('');
  });
}

function toggleService(id) {
  var card = document.querySelector('.svc-card[data-service="' + id + '"]');
  var blocked = !(card && card.classList.contains('blocked'));
  apiMutate('/services', {
    method: 'POST', body: JSON.stringify({ id: id, blocked: blocked }),
  }, (blocked ? 'Blokir ' : 'Izinkan ') + id).then(function (ok) {
    if (ok) loadServices();
  });
}

/* ═══════════════════════════════════════════════════════════
   SCHEDULE
═══════════════════════════════════════════════════════════ */
function loadSchedule() {
  return apiTry('/schedule').then(function (rows) {
    state.schedule = Array.isArray(rows) ? rows : [];
    var el = $('sched-body');
    if (!el) return;
    if (!state.schedule.length) { el.innerHTML = emptyRow(6, 'Belum ada aturan jadwal'); return; }
    el.innerHTML = state.schedule.map(function (r, i) {
      return '<tr>' +
        '<td>' + esc(r.name) + '</td>' +
        '<td class="mono" style="font-size:10px">' + esc((r.services || []).join(', ')) + '</td>' +
        '<td class="mono" style="font-size:10px">' + esc((r.days || []).join(', ')) + '</td>' +
        '<td class="mono">' + esc(r.start_time) + '</td>' +
        '<td class="mono">' + esc(r.end_time) + '</td>' +
        '<td><button class="btn btn-danger" style="font-size:10px;padding:3px 8px" ' +
        'onclick="delScheduleRule(' + i + ')">✕</button></td>' +
        '</tr>';
    }).join('');
  });
}

function splitList(value) {
  return String(value || '').split(',').map(function (s) { return s.trim(); })
    .filter(function (s) { return s.length > 0; });
}

var CLOCK_RE = /^([01][0-9]|2[0-3]):[0-5][0-9]$/;
var VALID_DAYS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'];

function addScheduleRule() {
  var name = trimVal('sched-name');
  var services = splitList(getVal('sched-services')).map(function (s) { return s.toLowerCase(); });
  var days = splitList(getVal('sched-days')).map(function (d) { return d.toLowerCase(); });
  var start = trimVal('sched-start');
  var end = trimVal('sched-end');

  if (!name) { showToast('✕ Nama aturan kosong', 'red'); return; }
  if (!services.length) { showToast('✕ Minimal satu service', 'red'); return; }
  if (!days.length) { showToast('✕ Minimal satu hari', 'red'); return; }

  var badDay = days.filter(function (d) { return VALID_DAYS.indexOf(d) === -1; });
  if (badDay.length) {
    showToast('✕ Hari tidak valid: ' + badDay.join(', ') + ' (pakai mon..sun)', 'red');
    return;
  }
  if (!CLOCK_RE.test(start) || !CLOCK_RE.test(end)) {
    showToast('✕ Format waktu harus HH:MM (24 jam)', 'red');
    return;
  }

  var rules = state.schedule.concat([{
    name: name, services: services, days: days, start_time: start, end_time: end,
  }]);
  saveScheduleRules(rules, 'Aturan jadwal disimpan').then(function (ok) {
    if (!ok) return;
    ['sched-name', 'sched-services', 'sched-days', 'sched-start', 'sched-end']
      .forEach(function (id) { setValue(id, ''); });
  });
}

function delScheduleRule(index) {
  if (!confirm('Hapus aturan ini?')) return;
  var rules = state.schedule.filter(function (_, i) { return i !== index; });
  saveScheduleRules(rules, 'Aturan dihapus');
}

function saveScheduleRules(rules, okMsg) {
  return apiMutate('/schedule', { method: 'POST', body: JSON.stringify({ rules: rules }) }, okMsg)
    .then(function (ok) {
      if (ok) return loadSchedule().then(function () { return true; });
      return false;
    });
}

/* ═══════════════════════════════════════════════════════════
   UPSTREAM
═══════════════════════════════════════════════════════════ */
function loadUpstreams() {
  return apiTry('/upstream').then(function (rows) {
    var list = Array.isArray(rows) ? rows : [];
    var el = $('upstream-body');

    if (el) {
      var primary = list.filter(function (u) { return !u.failover; });
      if (!primary.length) {
        el.innerHTML = emptyRow(5, 'Tidak ada upstream primer terdaftar');
      } else {
        var sc = { OK: 'green', Slow: 'yellow', Down: 'red' };
        el.innerHTML = primary.map(function (u) {
          return '<tr>' +
            '<td class="mono" title="' + esc(u.server) + '">' + esc(u.server) + '</td>' +
            '<td><span class="pill cyan">' + esc(u.proto) + '</span></td>' +
            '<td class="mono">' + u.latency + 'ms</td>' +
            '<td><span class="pill ' + (sc[u.status] || 'gray') + '">' + esc(u.status) +
            (u.failures ? ' (' + u.failures + ')' : '') + '</span></td>' +
            '<td><button class="btn btn-danger" style="font-size:10px;padding:3px 8px" ' +
            'data-server="' + esc(u.server) + '" onclick="delUpstream(this.dataset.server)">✕</button></td>' +
            '</tr>';
        }).join('');
      }
    }

    var fo = $('failover-list');
    if (fo) {
      var failovers = list.filter(function (u) { return u.failover; });
      fo.innerHTML = failovers.length
        ? '<div class="status-row"><span class="status-key">Failover aktif</span>' +
          '<span class="pill cyan">' + failovers.map(function (u) { return esc(u.server); }).join(', ') +
          '</span></div>'
        : emptyBlock('Tidak ada failover upstream dikonfigurasi');
    }
  });
}

function addUpstream() {
  var server = trimVal('up-inp');
  if (!server) { showToast('✕ Alamat upstream kosong', 'red'); return; }
  apiMutate('/upstream', {
    method: 'POST',
    body: JSON.stringify({ server: server, protocol: getVal('up-proto') || 'UDP' }),
  }, 'Upstream ditambahkan').then(function (ok) {
    if (ok) { setValue('up-inp', ''); loadUpstreams(); }
  });
}

function delUpstream(server) {
  if (!confirm('Hapus upstream ' + server + '?')) return;
  apiMutate('/upstream?server=' + encodeURIComponent(server), { method: 'DELETE' }, 'Upstream dihapus')
    .then(function (ok) { if (ok) loadUpstreams(); });
}

function testResolution() {
  var domain = trimVal('test-domain');
  var out = $('test-result');
  if (!out) return;
  if (!domain) { out.innerHTML = '<span class="c"># Masukkan domain terlebih dahulu</span>'; return; }

  out.innerHTML = '<span class="c"># Resolving...</span>';
  apiFetch('/dns/test?domain=' + encodeURIComponent(domain)).then(function (r) {
    if (r.error) {
      out.innerHTML = '<span class="c"># ' + esc(domain) + '</span>\n' +
        '<span style="color:var(--red)">ERROR: ' + esc(r.error) + '</span>\n' +
        '<span class="c">latency: ' + r.latency + 'ms</span>';
      return;
    }
    var answers = (r.answers || []).map(function (a) {
      return '<span class="k">' + esc(a.name) + '</span> ' + a.ttl +
        ' <span class="v">' + esc(a.type) + '</span> ' + esc(a.value);
    }).join('\n') || '<span class="c"># tidak ada jawaban</span>';
    out.innerHTML =
      '<span class="c"># ' + esc(r.domain) + ' (' + esc(r.type) + ')</span>\n' +
      '<span class="c"># rcode: ' + esc(r.rcode) + ' · latency: ' + r.latency + 'ms' +
      (r.blocked ? ' · DIBLOKIR oleh filter' : '') + '</span>\n' + answers;
  }).catch(function (err) {
    out.innerHTML = '<span style="color:var(--red)">✕ ' + esc(err.message) + '</span>';
  });
}

/* ═══════════════════════════════════════════════════════════
   ZONE RECORDS
═══════════════════════════════════════════════════════════ */
function loadZoneRecords() {
  return apiTry('/zones/records').then(function (rows) {
    var el = $('zone-body');
    if (!el) return;
    if (!Array.isArray(rows) || !rows.length) {
      el.innerHTML = emptyRow(6, 'Belum ada zone record');
      return;
    }
    el.innerHTML = rows.map(function (z) {
      return '<tr>' +
        '<td class="mono">' + esc(z.name) + '</td>' +
        '<td><span class="pill blue">' + esc(z.type) + '</span></td>' +
        '<td class="mono">' + esc(z.value) + '</td>' +
        '<td class="mono">' + z.ttl + '</td>' +
        '<td>' + (z.wildcard ? '<span class="pill purple">wildcard</span>'
                             : '<span class="pill gray">no</span>') + '</td>' +
        '<td><button class="btn btn-danger" style="font-size:10px;padding:3px 8px" ' +
        'data-name="' + esc(z.name) + '" data-type="' + esc(z.type) + '" ' +
        'onclick="delZoneRecord(this.dataset.name,this.dataset.type)">✕</button></td>' +
        '</tr>';
    }).join('');
  });
}

function addZoneRecord() {
  var name = trimVal('zr-name');
  var type = getVal('zr-type') || 'A';
  var value = trimVal('zr-value');
  var ttl = parseInt(getVal('zr-ttl'), 10);

  if (!name || !value) { showToast('✕ Name dan Value wajib diisi', 'red'); return; }
  apiMutate('/zones/records', {
    method: 'POST',
    body: JSON.stringify({
      name: name, type: type, value: value,
      ttl: (isFinite(ttl) && ttl > 0) ? ttl : 3600,
    }),
  }, 'Zone record ditambahkan').then(function (ok) {
    if (ok) { setValue('zr-name', ''); setValue('zr-value', ''); loadZoneRecords(); }
  });
}

function delZoneRecord(name, type) {
  if (!confirm('Hapus record ' + name + ' ' + type + '?')) return;
  var q = '/zones/records?name=' + encodeURIComponent(name) + '&type=' + encodeURIComponent(type);
  apiMutate(q, { method: 'DELETE' }, 'Record dihapus').then(function (ok) {
    if (ok) loadZoneRecords();
  });
}

/* ═══════════════════════════════════════════════════════════
   CACHE
═══════════════════════════════════════════════════════════ */
function loadCachePage() {
  return Promise.all([
    apiTry('/stats'), ensureConfigQuiet(), apiTry('/topdomains?limit=8'),
  ]).then(function (out) {
    var stats = out[0], cfg = out[1], top = out[2];

    if (stats) {
      setText('cache-size', num(stats.cache_size));
      setText('cache-hit', pct(stats.cached_queries, stats.total_queries).toFixed(1) + '%');
      setText('cache-ttl', stats.cache_min_ttl);
    }
    if (cfg) {
      setText('cache-max', num(cfg.cache_size));
      setValue('cfg-cache-size', cfg.cache_size);
      setValue('cfg-cache-min', cfg.cache_min_ttl);
      setValue('cfg-cache-max', cfg.cache_max_ttl);
      setToggle('cfg-prefetch', cfg.cache_prefetch);
    }
    renderTopBars('cache-top-bars', top && top.cached, 'green');
  });
}

function saveCacheConfig() {
  ensureConfig().then(function (cfg) {
    if (!cfg) return;
    var size = parseInt(getVal('cfg-cache-size'), 10);
    var min = parseInt(getVal('cfg-cache-min'), 10);
    var max = parseInt(getVal('cfg-cache-max'), 10);

    if (!(size > 0) || !(min > 0) || !(max > 0)) {
      showToast('✕ Ukuran dan TTL harus lebih besar dari 0', 'red');
      return;
    }
    if (min > max) { showToast('✕ Min TTL tidak boleh melebihi Max TTL', 'red'); return; }

    cfg.cache_size = size;
    cfg.cache_min_ttl = min;
    cfg.cache_max_ttl = max;
    cfg.cache_prefetch = getToggle('cfg-prefetch');
    saveConfig(cfg, 'Konfigurasi cache disimpan (ukuran berlaku setelah restart)');
  });
}

function flushCache() {
  confirmModal({
    title: 'Flush DNS Cache',
    message: 'Semua entry cache DNS akan dihapus. Query berikutnya akan diambil ulang dari upstream.',
    okText: 'Ya, Flush', cancelText: 'Batal', icon: '⚡', danger: true,
  }).then(function (ok) {
    if (!ok) return;
    apiMutate('/cache/flush', { method: 'POST' }, 'Cache dikosongkan').then(function (r) {
      if (r && state.page === 'cache') loadCachePage();
    });
  });
}

function resetStats() {
  confirmModal({
    title: 'Reset Statistik',
    message: 'Semua penghitung query (total, blocked, cached, rcode) dan riwayat statistik akan dinolkan. Tindakan ini tidak bisa dibatalkan.',
    okText: 'Ya, Reset', cancelText: 'Batal', icon: '🗑', danger: true,
  }).then(function (ok) {
    if (!ok) return;
    apiMutate('/stats/reset', { method: 'POST' }, 'Statistik direset').then(function (r) {
      if (r) fetchStats();
    });
  });
}

/* ═══════════════════════════════════════════════════════════
   DNSSEC
═══════════════════════════════════════════════════════════ */
function loadDnssecPage() {
  return Promise.all([apiTry('/stats'), ensureConfigQuiet()]).then(function (out) {
    var stats = out[0], cfg = out[1];
    if (stats) {
      setText('dn-ok', num(stats.dnssec_signatures));
      setText('dn-bogus', num(stats.rebinding_blocked));
      var insecure = Math.max(0, Number(stats.total_queries) - Number(stats.dnssec_signatures));
      setText('dn-insecure', num(insecure));
    }
    if (cfg) {
      setToggle('cfg-dnssec', cfg.dnssec_enabled);
      setToggle('cfg-rebinding', cfg.dns_rebinding_enabled);
    }
  });
}

function saveDnssecConfig() {
  ensureConfig().then(function (cfg) {
    if (!cfg) return;
    cfg.dnssec_enabled = getToggle('cfg-dnssec');
    cfg.dns_rebinding_enabled = getToggle('cfg-rebinding');
    saveConfig(cfg, 'Konfigurasi DNSSEC disimpan');
  });
}

// There is no dedicated DNSSEC validator endpoint. This resolves the name
// through the real pipeline; the per-query AD flag is shown in the Query Log.
function testDNSSEC() {
  var domain = trimVal('dnssec-inp');
  var out = $('dnssec-result');
  if (!out) return;
  if (!domain) { out.innerHTML = '<span class="c"># Masukkan domain untuk cek DNSSEC</span>'; return; }

  out.innerHTML = '<span class="c"># Testing...</span>';
  apiFetch('/dns/test?domain=' + encodeURIComponent(domain)).then(function (r) {
    if (r.error) {
      out.innerHTML = '<span style="color:var(--red)">ERROR: ' + esc(r.error) + '</span>';
      return;
    }
    out.innerHTML =
      '<span class="c"># ' + esc(r.domain) + '</span>\n' +
      '<span class="k">rcode</span> <span class="v">' + esc(r.rcode) + '</span>\n' +
      '<span class="k">answers</span> <span class="v">' + (r.answers || []).length + '</span>\n' +
      '<span class="k">latency</span> <span class="v">' + r.latency + 'ms</span>\n' +
      '<span class="c"># status DNSSEC per-query tampil di kolom DNSSEC pada Query Log</span>';
  }).catch(function (err) {
    out.innerHTML = '<span style="color:var(--red)">✕ ' + esc(err.message) + '</span>';
  });
}

/* ═══════════════════════════════════════════════════════════
   CLIENTS
═══════════════════════════════════════════════════════════ */
function loadClients() {
  return apiTry('/clients').then(function (rows) {
    state.clients = Array.isArray(rows) ? rows : [];
    var el = $('clients-body');
    if (!el) return;
    if (!state.clients.length) { el.innerHTML = emptyRow(6, 'Belum ada klien tercatat'); return; }
    el.innerHTML = state.clients.map(function (c) {
      return '<tr>' +
        '<td class="mono">' + esc(c.ip) + '</td>' +
        '<td>' + esc(c.hostname) + '</td>' +
        '<td><span class="pill gray">' + esc(c.group) + '</span></td>' +
        '<td class="mono">' + num(c.queries) + '</td>' +
        '<td class="mono" style="color:var(--red)">' + num(c.blocked) + '</td>' +
        '<td class="mono" style="font-size:10px">' + esc(fmtDateTime(c.last_seen)) + '</td>' +
        '</tr>';
    }).join('');
  });
}

/* ═══════════════════════════════════════════════════════════
   ACL
═══════════════════════════════════════════════════════════ */
function renderTags(elId, items, type) {
  var el = $(elId);
  if (!el) return;
  if (!items.length) { el.innerHTML = emptyBlock('Kosong'); return; }
  var danger = type === 'deny';
  el.innerHTML = items.map(function (v) {
    return '<div class="cidr-tag"' +
      (danger ? ' style="border-color:rgba(255,82,82,.2);color:var(--red)"' : '') + '>' + esc(v) +
      ' <button class="rm" data-value="' + esc(v) + '" ' +
      'onclick="rmACL(\'' + type + '\',this.dataset.value)">✕</button></div>';
  }).join('');
}

function loadAclPage() {
  return ensureConfigQuiet().then(function (cfg) {
    if (!cfg) return;
    renderTags('acl-allow-tags', cfg.acl_allow || [], 'allow');
    renderTags('acl-deny-tags', cfg.acl_deny || [], 'deny');
    setValue('cfg-qps', cfg.rate_limit_qps);
  });
}

// Accept only a bare IP or CIDR. Rejecting typos client-side avoids writing an
// ACL entry that could lock every client out of resolution.
var IPV4_CIDR_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/(\d|[12]\d|3[0-2]))?$/;
var IPV6_CIDR_RE = /^[0-9a-fA-F:]+(\/(\d|[1-9]\d|1[01]\d|12[0-8]))?$/;

function isValidCidr(v) {
  var m = IPV4_CIDR_RE.exec(v);
  if (m) {
    for (var i = 1; i <= 4; i++) { if (Number(m[i]) > 255) return false; }
    return true;
  }
  return v.indexOf(':') !== -1 && IPV6_CIDR_RE.test(v);
}

function addACL(type) {
  var inputId = 'acl-' + type + '-inp';
  var val = trimVal(inputId);
  if (!val) { showToast('✕ Nilai kosong', 'red'); return; }
  if (!isValidCidr(val)) { showToast('✕ Format harus IP atau CIDR, mis. 192.168.1.0/24', 'red'); return; }

  ensureConfig().then(function (cfg) {
    if (!cfg) return;
    var key = type === 'allow' ? 'acl_allow' : 'acl_deny';
    var list = cfg[key] || [];
    if (list.indexOf(val) !== -1) { showToast('✕ Sudah ada di daftar', 'red'); return; }
    cfg[key] = list.concat([val]);
    saveConfig(cfg, (type === 'allow' ? 'Allow' : 'Deny') + ': ' + val).then(function (ok) {
      if (ok) { setValue(inputId, ''); loadAclPage(); }
    });
  });
}

function rmACL(type, val) {
  ensureConfig().then(function (cfg) {
    if (!cfg) return;
    var key = type === 'allow' ? 'acl_allow' : 'acl_deny';
    cfg[key] = (cfg[key] || []).filter(function (v) { return v !== val; });
    saveConfig(cfg, 'Dihapus: ' + val).then(function (ok) { if (ok) loadAclPage(); });
  });
}

function saveAclConfig() {
  ensureConfig().then(function (cfg) {
    if (!cfg) return;
    var qps = parseInt(getVal('cfg-qps'), 10);
    if (!isFinite(qps) || qps < 0) { showToast('✕ QPS harus angka ≥ 0', 'red'); return; }
    cfg.rate_limit_qps = qps;
    saveConfig(cfg, 'ACL & rate limit disimpan');
  });
}

/* ═══════════════════════════════════════════════════════════
   CONDITIONAL FORWARDING (Routing page)
═══════════════════════════════════════════════════════════ */
function loadConditional() {
  return Promise.all([apiTry('/conditional'), ensureConfigQuiet()]).then(function (out) {
    var rows = out[0], cfg = out[1];

    var note = $('geo-state');
    if (note) {
      note.innerHTML = (cfg && cfg.geo_dns)
        ? '<div class="alert info">ℹ Geo DNS aktif di konfigurasi. Statistik per-negara tidak ' +
          'ditampilkan karena server tidak memakai database GeoIP.</div>'
        : '<div class="alert warn">⚠ Geo DNS nonaktif. Aktifkan di Settings bila diperlukan.</div>';
    }

    var el = $('cfwd-body');
    if (!el) return;
    if (!Array.isArray(rows) || !rows.length) {
      el.innerHTML = emptyRow(3, 'Belum ada aturan conditional forwarding');
      return;
    }
    el.innerHTML = rows.map(function (r) {
      return '<tr>' +
        '<td class="mono">' + esc(r.domain) + '</td>' +
        '<td class="mono" style="font-size:10px">' + esc((r.upstreams || []).join(', ')) + '</td>' +
        '<td><button class="btn btn-danger" style="font-size:10px;padding:3px 8px" ' +
        'data-domain="' + esc(r.domain) + '" onclick="delConditional(this.dataset.domain)">✕</button></td>' +
        '</tr>';
    }).join('');
  });
}

function addConditionalForward() {
  var domain = trimVal('cfwd-domain');
  var upstreams = splitList(getVal('cfwd-upstreams'));
  if (!domain) { showToast('✕ Domain kosong', 'red'); return; }
  if (!upstreams.length) { showToast('✕ Minimal satu upstream', 'red'); return; }

  apiMutate('/conditional', {
    method: 'POST', body: JSON.stringify({ domain: domain, upstreams: upstreams }),
  }, 'Aturan forwarding disimpan').then(function (ok) {
    if (ok) {
      setValue('cfwd-domain', '');
      setValue('cfwd-upstreams', '');
      loadConditional();
    }
  });
}

function delConditional(domain) {
  if (!confirm('Hapus aturan untuk ' + domain + '?')) return;
  apiMutate('/conditional?domain=' + encodeURIComponent(domain), { method: 'DELETE' }, 'Aturan dihapus')
    .then(function (ok) { if (ok) loadConditional(); });
}

/* ═══════════════════════════════════════════════════════════
   PROMETHEUS
═══════════════════════════════════════════════════════════ */
function loadMetricsPage() {
  return Promise.all([apiTry('/status'), ensureConfigQuiet()]).then(function (out) {
    var status = out[0], cfg = out[1];

    var note = $('metrics-state');
    if (note) {
      var prom = (status && status.prometheus) || null;
      var addr = (prom && prom.address) || '(belum diatur)';
      note.innerHTML = (prom && prom.enabled)
        ? '<div class="alert ok">✓ Endpoint Prometheus aktif di ' +
          '<strong style="font-family:var(--font-mono)">' + esc(addr) + '</strong></div>'
        : '<div class="alert warn">⚠ Endpoint Prometheus terpisah nonaktif. Metrik tetap tersedia di ' +
          '<strong style="font-family:var(--font-mono)">/metrics</strong> pada port dashboard.</div>';
    }
    if (cfg) {
      setValue('cfg-prom-addr', cfg.prometheus_address);
      setToggle('cfg-prometheus', cfg.prometheus_enabled);
    }
    return refreshMetrics();
  });
}

function savePrometheusConfig() {
  ensureConfig().then(function (cfg) {
    if (!cfg) return;
    var enabled = getToggle('cfg-prometheus');
    var addr = trimVal('cfg-prom-addr');
    if (enabled && !addr) {
      showToast('✕ Listen address wajib diisi bila endpoint diaktifkan', 'red');
      return;
    }
    cfg.prometheus_enabled = enabled;
    cfg.prometheus_address = addr;
    saveConfig(cfg, 'Konfigurasi Prometheus disimpan (berlaku setelah restart)');
  });
}

// /metrics returns text/plain, so it bypasses the JSON helper.
function refreshMetrics() {
  var el = $('metrics-preview');
  if (!el) return Promise.resolve();
  return fetch('/metrics', { headers: { 'Accept': 'text/plain' } }).then(function (res) {
    if (!res.ok) throw new Error('HTTP ' + res.status);
    return res.text();
  }).then(function (text) {
    el.innerHTML = text.split('\n').map(function (line) {
      return line.charAt(0) === '#' ? '<span class="c">' + esc(line) + '</span>' : esc(line);
    }).join('\n');
  }).catch(function (err) {
    el.innerHTML = '<span style="color:var(--red)">✕ Gagal memuat /metrics: ' + esc(err.message) + '</span>';
  });
}

/* ═══════════════════════════════════════════════════════════
   AUDIT LOG
═══════════════════════════════════════════════════════════ */
function loadAuditLog() {
  return apiTry('/audit').then(function (rows) {
    state.audit = Array.isArray(rows) ? rows : [];
    renderAuditLog();
  });
}

function renderAuditLog() {
  var el = $('audit-body');
  if (!el) return;
  var filt = trimVal('audit-filter').toLowerCase();
  var evF = getVal('audit-event');

  var rows = state.audit.filter(function (a) {
    return (!filt || String(a.detail || '').toLowerCase().indexOf(filt) !== -1) &&
      (!evF || a.event === evF);
  });

  if (!rows.length) { el.innerHTML = emptyBlock('Belum ada aktivitas tercatat'); return; }
  var ec = { login: 'green', logout: 'gray', config: 'blue', block: 'red' };
  el.innerHTML = rows.map(function (a) {
    return '<div class="audit-row">' +
      '<span class="mono" style="font-size:10px;color:var(--text3)">' + esc(fmtDateTime(a.time)) + '</span>' +
      '<span><span class="pill ' + (ec[a.event] || 'gray') + '">' + esc(a.event) + '</span></span>' +
      '<span style="font-size:11px">' + esc(a.detail) + '</span>' +
      '<span class="mono" style="font-size:10px;color:var(--text3)">' + esc(a.ip) + '</span>' +
      '<span><span class="pill ' + (a.ok ? 'green' : 'red') + '">' + (a.ok ? 'OK' : 'GAGAL') + '</span></span>' +
      '</div>';
  }).join('');
}

/* ═══════════════════════════════════════════════════════════
   SYSTEM LOG
═══════════════════════════════════════════════════════════ */
function refreshSyslog() {
  return apiTry('/syslog?limit=300').then(function (data) {
    var lines = (data && data.lines) || [];
    if (!lines.length && data && data.note) lines = ['# ' + data.note];
    state.syslog = lines;
    renderSyslog();
  });
}

function renderSyslog() {
  var el = $('syslog-body');
  if (!el) return;
  var filt = trimVal('log-filter').toLowerCase();
  var lvl = getVal('log-level');

  var lines = state.syslog.filter(function (l) {
    return (!filt || l.toLowerCase().indexOf(filt) !== -1) &&
      (!lvl || l.toUpperCase().indexOf(lvl) !== -1);
  });

  if (!lines.length) { el.innerHTML = '<span class="c"># Tidak ada baris log yang cocok</span>'; return; }
  el.innerHTML = lines.map(function (l) {
    var u = l.toUpperCase();
    var color = 'var(--text2)';
    if (u.indexOf('ERROR') !== -1 || u.indexOf('FATAL') !== -1) color = 'var(--red)';
    else if (u.indexOf('WARN') !== -1) color = 'var(--yellow)';
    else if (l.charAt(0) === '#') color = 'var(--text3)';
    return '<div style="color:' + color + '">' + esc(l) + '</div>';
  }).join('');
}

/* ═══════════════════════════════════════════════════════════
   CONFIG / SETTINGS
═══════════════════════════════════════════════════════════ */
function setToggle(id, on) {
  var row = $(id);
  if (!row) return;
  row.classList.toggle('on', !!on);
  var knob = row.querySelector('.toggle');
  if (knob) knob.classList.toggle('on', !!on);
}

function getToggle(id) {
  var row = $(id);
  return !!(row && row.classList.contains('on'));
}

function toggleTR(el) {
  el.classList.toggle('on');
  var knob = el.querySelector('.toggle');
  if (knob) knob.classList.toggle('on');
}

// ensureConfig always refetches: /api/advanced/config saves the whole object,
// so mutating a stale copy would silently revert other people's changes.
function ensureConfig() {
  return apiTry('/advanced/config').then(function (cfg) {
    if (!cfg) { showToast('✕ Gagal memuat konfigurasi', 'red'); return null; }
    state.config = cfg;
    return cfg;
  });
}

function ensureConfigQuiet() {
  return apiTry('/advanced/config').then(function (cfg) {
    if (cfg) state.config = cfg;
    return cfg;
  });
}

function saveConfig(cfg, okMsg) {
  return apiMutate('/advanced/config', {
    method: 'POST', body: JSON.stringify(cfg),
  }, okMsg).then(function (ok) {
    if (ok) state.config = cfg;
    return ok;
  });
}

function loadSettings() {
  return ensureConfig().then(function (cfg) {
    if (!cfg) return;

    setValue('cfg-upstream', (cfg.upstream_servers || []).join(', '));
    setValue('cfg-failover', (cfg.failover_upstreams || []).join(', '));
    setValue('cfg-blockmode', cfg.blocking_mode === 'nxdomain' ? 'nxdomain' : 'zero_ip');
    setValue('cfg-doh-addr', cfg.doh_address);
    setValue('cfg-dot-addr', cfg.dot_address);
    setValue('cfg-doq-addr', cfg.doq_address);

    setToggle('cfg-recursive', cfg.recursive_resolver);
    setToggle('cfg-aaaa', cfg.filter_aaaa);
    setToggle('cfg-safe', cfg.safe_browsing_enabled);
    setToggle('cfg-parental', cfg.parental_control_enabled);
    setToggle('cfg-geo', cfg.geo_dns);
    setToggle('cfg-rdns', cfg.reverse_dns_enabled);
    setToggle('cfg-longterm', cfg.long_term_stats);
    setValue('cfg-stats-retention', cfg.stats_retention_hours);
    setToggle('cfg-doh', cfg.doh_enabled);
    setToggle('cfg-dot', cfg.dot_enabled);
    setToggle('cfg-doq', cfg.doq_enabled);
  });
}

function saveSettings() {
  ensureConfig().then(function (cfg) {
    if (!cfg) return;

    var upstreams = splitList(getVal('cfg-upstream'));
    if (!upstreams.length) { showToast('✕ Minimal satu upstream harus diisi', 'red'); return; }

    cfg.upstream_servers = upstreams;
    cfg.failover_upstreams = splitList(getVal('cfg-failover'));
    cfg.blocking_mode = getVal('cfg-blockmode') === 'nxdomain' ? 'nxdomain' : 'zero_ip';
    cfg.recursive_resolver = getToggle('cfg-recursive');
    cfg.filter_aaaa = getToggle('cfg-aaaa');
    cfg.safe_browsing_enabled = getToggle('cfg-safe');
    cfg.parental_control_enabled = getToggle('cfg-parental');
    cfg.geo_dns = getToggle('cfg-geo');
    cfg.reverse_dns_enabled = getToggle('cfg-rdns');
    cfg.long_term_stats = getToggle('cfg-longterm');
    var retention = parseInt(getVal('cfg-stats-retention'), 10);
    if (isNaN(retention) || retention < 0) { retention = 0; }
    if (retention > 8760) { retention = 8760; }
    cfg.stats_retention_hours = retention;
    cfg.doh_enabled = getToggle('cfg-doh');
    cfg.dot_enabled = getToggle('cfg-dot');
    cfg.doq_enabled = getToggle('cfg-doq');
    cfg.doh_address = trimVal('cfg-doh-addr');
    cfg.dot_address = trimVal('cfg-dot-addr');
    cfg.doq_address = trimVal('cfg-doq-addr');

    var listeners = [
      [cfg.doh_enabled, cfg.doh_address, 'DoH'],
      [cfg.dot_enabled, cfg.dot_address, 'DoT'],
      [cfg.doq_enabled, cfg.doq_address, 'DoQ'],
    ];
    for (var i = 0; i < listeners.length; i++) {
      if (listeners[i][0] && !listeners[i][1]) {
        showToast('✕ Address ' + listeners[i][2] + ' wajib diisi bila diaktifkan', 'red');
        return;
      }
    }

    var btn = $('btn-save-cfg');
    if (btn) btn.disabled = true;
    saveConfig(cfg, 'Settings disimpan').then(function () {
      if (btn) btn.disabled = false;
      loadSettings();
    });
  });
}

function restartDNS() {
  confirmModal({
    title: 'Restart VortexDNS',
    message: 'Semua koneksi DNS akan terputus beberapa saat, dan query log yang tersimpan di memori akan hilang karena tidak dipersistenkan.',
    okText: 'Ya, Restart', cancelText: 'Batal', icon: '↺', danger: true,
  }).then(function (ok) {
    if (!ok) return;
    apiMutate('/service/restart', { method: 'POST' }, 'Perintah restart dikirim').then(function (r) {
      if (r) setConnStatus('reconnecting');
    });
  });
}

/* ═══════════════════════════════════════════════════════════
   TABS
═══════════════════════════════════════════════════════════ */
function switchTab(el, paneId) {
  var tabs = el.closest('.tabs');
  if (tabs) tabs.querySelectorAll('.tab-item').forEach(function (t) { t.classList.remove('active'); });
  el.classList.add('active');

  var page = el.closest('.page');
  if (page) {
    page.querySelectorAll('.tab-pane').forEach(function (p) {
      p.classList.remove('active');
      p.classList.add('hidden');
    });
  }
  var pane = $(paneId);
  if (pane) { pane.classList.add('active'); pane.classList.remove('hidden'); }
}

/* ═══════════════════════════════════════════════════════════
   MAIN POLL LOOP
═══════════════════════════════════════════════════════════ */
var LIVE_PAGES = {
  dashboard: loadDashboard,
  cache:     loadCachePage,
  dnssec:    loadDnssecPage,
  clients:   loadClients,
  upstream:  loadUpstreams,
  blocking:  loadBlocklists,
};

function mainLoop() {
  if (!state.loggedIn) return;
  if (state.page === 'queries') {
    if (state.queryAuto) renderQueryLog();
    return fetchStats();
  }
  var refresh = LIVE_PAGES[state.page];
  return refresh ? refresh() : fetchStats();
}


/* ═══════════════════════════════════════════════════════════
   INIT
═══════════════════════════════════════════════════════════ */
(function init() {
  resetLoginStrip();

  fetch('/api/auth/status').then(function (res) {
    if (!res.ok) throw new Error('HTTP ' + res.status);
    return res.json();
  }).then(function (status) {
    if (status.needs_setup) {
      showSetupView();
      return;
    }
    if (status.is_logged_in) {
      // Restore an existing session without replaying the login animation.
      enterPanel(false);
    } else {
      showLoginView();
    }
  }).catch(function () {
    showLoginView();
    setConnStatus('disconnected');
  });
})();
