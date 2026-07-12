/* Open ProPanel file explorer — a Cockpit/cPanel-style client for the jailed
 * file API. All state (sort, filter, view, selection, clipboard) lives here;
 * the server only lists (GET /files/api/list) and mutates (POST /files/*).
 *
 * SECURITY: file and folder names come from the filesystem and are rendered
 * with textContent / createElement ONLY. innerHTML is used exclusively for the
 * constant SVG icon strings below — never for any server- or user-supplied
 * value. Keep it that way. */
(function () {
  'use strict';
  var mount = document.getElementById('opp-fm');
  if (!mount) return;
  var SITE = mount.dataset.site;

  // ---- tiny DOM builder --------------------------------------------------
  function el(tag, props) {
    var n = document.createElement(tag);
    props = props || {};
    for (var k in props) {
      var v = props[k];
      if (v == null) continue;
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else if (k === 'html') n.innerHTML = v; // constant SVG only
      else if (k.indexOf('on') === 0 && typeof v === 'function') n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v);
    }
    for (var i = 2; i < arguments.length; i++) {
      var kids = arguments[i];
      if (!Array.isArray(kids)) kids = [kids];
      kids.forEach(function (c) {
        if (c == null) return;
        n.append(c.nodeType ? c : document.createTextNode(c));
      });
    }
    return n;
  }

  var ICON = {
    folder: '<svg viewBox="0 0 24 24" fill="currentColor" class="h-full w-full"><path d="M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6Z"/></svg>',
    file: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" class="h-full w-full"><path stroke-linecap="round" stroke-linejoin="round" d="M6 3h8l4 4v14a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Z"/><path stroke-linecap="round" stroke-linejoin="round" d="M14 3v4h4"/></svg>',
    code: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" class="h-full w-full"><path stroke-linecap="round" stroke-linejoin="round" d="M6 3h8l4 4v14a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Z"/><path stroke-linecap="round" stroke-linejoin="round" d="m10 12-2 2 2 2M14 12l2 2-2 2"/></svg>',
    image: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" class="h-full w-full"><rect x="4" y="5" width="16" height="14" rx="2"/><circle cx="9" cy="10" r="1.4"/><path stroke-linecap="round" stroke-linejoin="round" d="m5 17 4-4 3 3 3-3 4 4"/></svg>',
    archive: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" class="h-full w-full"><path stroke-linecap="round" stroke-linejoin="round" d="M6 3h8l4 4v14a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Z"/><path stroke-linecap="round" stroke-linejoin="round" d="M11 3v3m0 3v1m0 3v1"/></svg>',
    link: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" class="h-full w-full"><path stroke-linecap="round" stroke-linejoin="round" d="M10 13a3 3 0 0 0 4 0l3-3a3 3 0 1 0-4-4l-1 1M14 11a3 3 0 0 0-4 0l-3 3a3 3 0 1 0 4 4l1-1"/></svg>',
    drive: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" class="h-5 w-5"><rect x="3" y="4" width="18" height="12" rx="2"/><path stroke-linecap="round" d="M7 20h10M9 16v4M15 16v4"/><circle cx="16.5" cy="10" r="1" fill="currentColor"/></svg>'
  };

  var state = {
    path: mount.dataset.path || '',
    entries: [], counts: {}, owners: [], canChown: false,
    view: localStorage.getItem('opp-fm-view') || 'grid',
    sortKey: localStorage.getItem('opp-fm-sortk') || 'name',
    sortDir: localStorage.getItem('opp-fm-sortd') || 'asc',
    showHidden: localStorage.getItem('opp-fm-hidden') === '1',
    filter: '', sel: {}, anchor: null, clip: null, loading: false
  };
  function selList() { return Object.keys(state.sel); }
  function clearSel() { state.sel = {}; state.anchor = null; }

  // ---- server calls ------------------------------------------------------
  function load(path) {
    state.loading = true; state.path = path; render();
    var url = '/files/api/list?site=' + encodeURIComponent(SITE) + '&path=' + encodeURIComponent(path);
    fetch(url, { headers: { 'X-OPP-Ajax': '1' } })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
      .then(function (res) {
        state.loading = false;
        if (!res.ok) { toast(res.d.error || 'Could not read folder', true); render(); return; }
        state.path = res.d.path; state.parent = res.d.parent; state.atRoot = res.d.atRoot;
        state.crumbs = res.d.crumbs || []; state.entries = res.d.entries || [];
        state.counts = res.d.counts || {}; state.owners = res.d.owners || [];
        state.canChown = res.d.canChown; clearSel();
        history.replaceState(null, '', '/files?site=' + encodeURIComponent(SITE) + (path ? '&path=' + encodeURIComponent(path) : ''));
        render();
      })
      .catch(function () { state.loading = false; toast('Network error', true); render(); });
  }

  function api(action, params) {
    var body = new URLSearchParams();
    body.set('site', SITE);
    Object.keys(params).forEach(function (k) {
      var v = params[k];
      if (Array.isArray(v)) v.forEach(function (x) { body.append(k, x); });
      else if (v != null) body.set(k, v);
    });
    return fetch('/files/' + action, {
      method: 'POST',
      headers: { 'X-OPP-Ajax': '1', 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (d) { return { ok: r.ok, d: d }; });
    }).then(function (res) {
      if (!res.ok || res.d.error) { toast(res.d.error || 'Operation failed', true); return false; }
      if (res.d.msg) toast(res.d.msg);
      return true;
    }).catch(function () { toast('Network error', true); return false; });
  }
  function act(action, params) { return api(action, params).then(function (ok) { if (ok) load(state.path); return ok; }); }

  // ---- helpers -----------------------------------------------------------
  function join(dir, name) { return dir ? dir + '/' + name : name; }
  function hsize(n) {
    if (n < 1024) return n + ' B';
    var u = ['KB', 'MB', 'GB', 'TB'], i = -1;
    do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
    return n.toFixed(1) + ' ' + u[i];
  }
  function ago(sec) {
    var d = Math.floor(Date.now() / 1000) - sec;
    if (d < 60) return 'just now';
    if (d < 3600) return Math.floor(d / 60) + ' min ago';
    if (d < 86400) return Math.floor(d / 3600) + ' h ago';
    if (d < 2592000) return Math.floor(d / 86400) + ' d ago';
    return new Date(sec * 1000).toISOString().slice(0, 10);
  }
  var EXT_IMG = ['png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'ico', 'bmp'];
  var EXT_CODE = ['php', 'js', 'ts', 'css', 'html', 'json', 'go', 'py', 'sh', 'yml', 'yaml', 'md', 'xml', 'sql', 'env', 'txt', 'conf', 'ini'];
  var EXT_ZIP = ['zip'];
  function extOf(n) { var i = n.lastIndexOf('.'); return i < 0 ? '' : n.slice(i + 1).toLowerCase(); }
  function iconFor(e) {
    if (e.dir) return ICON.folder;
    if (e.link) return ICON.link;
    var x = extOf(e.name);
    if (EXT_IMG.indexOf(x) >= 0) return ICON.image;
    if (EXT_ZIP.indexOf(x) >= 0) return ICON.archive;
    if (EXT_CODE.indexOf(x) >= 0) return ICON.code;
    return ICON.file;
  }
  function isEditable(e) { return !e.dir && !e.link && EXT_CODE.indexOf(extOf(e.name)) >= 0; }

  function visibleEntries() {
    var list = state.entries.slice();
    if (!state.showHidden) list = list.filter(function (e) { return e.name.charAt(0) !== '.'; });
    if (state.filter) {
      var f = state.filter.toLowerCase();
      list = list.filter(function (e) { return e.name.toLowerCase().indexOf(f) >= 0; });
    }
    var dir = state.sortDir === 'asc' ? 1 : -1, k = state.sortKey;
    list.sort(function (a, b) {
      if (a.dir !== b.dir) return a.dir ? -1 : 1; // folders first, always
      var r = 0;
      if (k === 'size') r = a.size - b.size;
      else if (k === 'mtime') r = a.mtime - b.mtime;
      else if (k === 'owner') r = String(a.owner).localeCompare(String(b.owner));
      else if (k === 'perm') r = parseInt(a.perm, 8) - parseInt(b.perm, 8);
      else r = a.name.toLowerCase().localeCompare(b.name.toLowerCase());
      if (r === 0) r = a.name.toLowerCase().localeCompare(b.name.toLowerCase());
      return r * dir;
    });
    return list;
  }

  // ---- open / navigate ---------------------------------------------------
  function openEntry(e) {
    if (e.dir) { load(join(state.path, e.name)); return; }
    if (isEditable(e)) { window.location = '/files/edit?site=' + encodeURIComponent(SITE) + '&path=' + encodeURIComponent(join(state.path, e.name)); return; }
    download(e.name);
  }
  function download(name) {
    window.location = '/files/download?site=' + encodeURIComponent(SITE) + '&path=' + encodeURIComponent(join(state.path, name));
  }

  // ---- selection ---------------------------------------------------------
  function selectOnly(name) { state.sel = {}; state.sel[name] = true; state.anchor = name; }
  function toggle(name) { if (state.sel[name]) delete state.sel[name]; else state.sel[name] = true; state.anchor = name; }
  function selectRange(name) {
    var vis = visibleEntries().map(function (e) { return e.name; });
    var a = vis.indexOf(state.anchor), b = vis.indexOf(name);
    if (a < 0) { selectOnly(name); return; }
    var lo = Math.min(a, b), hi = Math.max(a, b);
    state.sel = {};
    for (var i = lo; i <= hi; i++) state.sel[vis[i]] = true;
  }
  function onItemMouseDown(e, ev) {
    if (ev.button === 2) { if (!state.sel[e.name]) selectOnly(e.name); render(); return; } // right-click
    if (ev.shiftKey) selectRange(e.name);
    else if (ev.ctrlKey || ev.metaKey) toggle(e.name);
    else selectOnly(e.name);
    render();
  }

  // ---- context menu ------------------------------------------------------
  var menuEl = null;
  function closeMenu() { if (menuEl) { menuEl.remove(); menuEl = null; } }
  function openMenu(x, y, items) {
    closeMenu();
    menuEl = el('div', { class: 'opp-fm-menu' });
    items.forEach(function (it) {
      if (it === '-') { menuEl.append(el('div', { class: 'my-1 border-t border-zinc-100' })); return; }
      menuEl.append(el('button', {
        class: 'flex w-full items-center gap-2 px-3 py-1.5 text-left text-sm ' +
          (it.disabled ? 'cursor-default text-zinc-300' : (it.danger ? 'text-red-600 hover:bg-red-50' : 'text-zinc-700 hover:bg-zinc-100')),
        onclick: function () { if (it.disabled) return; closeMenu(); it.run(); }
      }, it.label));
    });
    document.body.append(menuEl);
    var r = menuEl.getBoundingClientRect();
    var vw = window.innerWidth, vh = window.innerHeight;
    menuEl.style.left = Math.min(x, vw - r.width - 8) + 'px';
    menuEl.style.top = Math.min(y, vh - r.height - 8) + 'px';
  }
  function itemMenu(e, x, y) {
    var sel = selList(), multi = sel.length > 1;
    var items = [];
    if (!multi) {
      items.push({ label: e.dir ? 'Open' : (isEditable(e) ? 'Open / edit' : 'Open'), run: function () { openEntry(e); } });
      if (!e.dir) items.push({ label: 'Download', run: function () { download(e.name); } });
      if (extOf(e.name) === 'zip') items.push({ label: 'Extract here', run: function () { doExtract(e.name); } });
    }
    items.push({ label: 'Copy', run: function () { state.clip = { op: 'copy', path: state.path, names: multi ? sel : [e.name] }; toast('Copied ' + (multi ? sel.length + ' items' : e.name)); } });
    items.push({ label: 'Cut', run: function () { state.clip = { op: 'cut', path: state.path, names: multi ? sel : [e.name] }; toast('Cut ' + (multi ? sel.length + ' items' : e.name)); } });
    items.push({ label: 'Compress to .zip', run: function () { doZip(multi ? sel : [e.name]); } });
    items.push('-');
    if (!multi) items.push({ label: 'Rename', run: function () { doRename(e.name); } });
    if (!multi) items.push({ label: 'Edit permissions', run: function () { permModal(e); } });
    items.push('-');
    items.push({ label: multi ? 'Delete ' + sel.length + ' items' : 'Delete', danger: true, run: function () { doDelete(multi ? sel : [e.name]); } });
    openMenu(x, y, items);
  }
  function emptyMenu(x, y) {
    openMenu(x, y, [
      { label: 'Paste', disabled: !state.clip, run: doPaste },
      '-',
      { label: 'New folder', run: function () { promptModal('New folder', 'Folder name', '', function (v) { return act('mkdir', { path: state.path, name: v }); }); } },
      { label: 'New file', run: function () { promptModal('New file', 'File name', '', function (v) { return act('new', { path: state.path, name: v }); }); } },
      { label: 'Upload files', run: pickUpload },
      '-',
      { label: 'Select all', run: function () { state.sel = {}; visibleEntries().forEach(function (e) { state.sel[e.name] = true; }); render(); } },
      { label: 'Refresh', run: function () { load(state.path); } }
    ]);
  }

  // ---- actions -----------------------------------------------------------
  function doDelete(names) {
    if (!confirm('Delete ' + (names.length > 1 ? names.length + ' items' : names[0]) + '? This cannot be undone.')) return;
    if (names.length === 1) act('delete', { path: state.path, name: names[0] });
    else act('bulk-delete', { path: state.path, sel: names });
  }
  function doZip(names) {
    promptModal('Compress to .zip', 'Archive name', 'archive.zip', function (v) {
      return act('zip', { path: state.path, sel: names, archive: v });
    });
  }
  function doExtract(name) {
    if (!confirm('Extract ' + name + ' here? Files with the same name are overwritten.')) return;
    act('unzip', { path: state.path, name: name });
  }
  function doRename(name) {
    promptModal('Rename', 'New name', name, function (v) {
      return act('rename', { path: state.path, name: name, new_name: v });
    });
  }
  function doPaste() {
    if (!state.clip) return;
    var c = state.clip;
    if (c.op === 'cut') {
      act('bulk-move', { path: c.path, dest: state.path, sel: c.names }).then(function (ok) { if (ok) state.clip = null; });
    } else {
      // copy each item into the current directory, then refresh once
      var chain = Promise.resolve(true);
      c.names.forEach(function (n) { chain = chain.then(function () { return api('copy', { path: c.path, name: n, dest: state.path }); }); });
      chain.then(function () { load(state.path); });
    }
  }

  // ---- upload (button + drag/drop) --------------------------------------
  function uploadFiles(fileList) {
    if (!fileList || !fileList.length) return;
    var fd = new FormData();
    fd.append('site', SITE); fd.append('path', state.path);
    for (var i = 0; i < fileList.length; i++) fd.append('file', fileList[i]);
    toast('Uploading ' + fileList.length + ' file(s)…');
    fetch('/files/upload', { method: 'POST', headers: { 'X-OPP-Ajax': '1' }, body: fd })
      .then(function (r) { return r.json().catch(function () { return {}; }).then(function (d) { return { ok: r.ok, d: d }; }); })
      .then(function (res) {
        if (!res.ok || res.d.error) toast(res.d.error || 'Upload failed', true);
        else { if (res.d.msg) toast(res.d.msg); load(state.path); }
      }).catch(function () { toast('Upload failed', true); });
  }
  function pickUpload() {
    var inp = el('input', { type: 'file', multiple: 'multiple', style: 'display:none' });
    inp.addEventListener('change', function () { uploadFiles(inp.files); });
    document.body.append(inp); inp.click(); setTimeout(function () { inp.remove(); }, 0);
  }

  // ---- modals ------------------------------------------------------------
  function overlay(card) {
    var ov = el('div', { class: 'opp-fm-overlay', onclick: function (ev) { if (ev.target === ov) ov.remove(); } }, card);
    document.body.append(ov);
    return ov;
  }
  function promptModal(title, label, value, onSubmit) {
    var input = el('input', { class: 'opp-input mt-1 w-full', value: value });
    var err = el('p', { class: 'mt-1 text-xs text-red-600' });
    var form = el('form', {
      class: 'opp-fm-card', onsubmit: function (ev) {
        ev.preventDefault();
        var v = input.value.trim();
        if (!v) { err.textContent = 'Please enter a name'; return; }
        onSubmit(v).then(function (ok) { if (ok) ov.remove(); });
      }
    },
      el('h3', { class: 'text-sm font-semibold text-zinc-900', text: title }),
      el('label', { class: 'mt-3 block text-xs text-zinc-500', text: label }), input,
      err,
      el('div', { class: 'mt-4 flex justify-end gap-2' },
        el('button', { type: 'button', class: 'opp-btn', onclick: function () { ov.remove(); }, text: 'Cancel' }),
        el('button', { type: 'submit', class: 'opp-btn-primary', text: 'OK' })));
    var ov = overlay(form);
    input.focus(); input.select();
  }

  function permModal(e) {
    var oct = e.perm.slice(-3);
    var bits = [parseInt(oct[0], 8), parseInt(oct[1], 8), parseInt(oct[2], 8)];
    var initialOct = '0' + bits.join(''); // to detect whether perms actually changed
    var rows = ['Owner', 'Group', 'Others'], cols = [['Read', 4], ['Write', 2], ['Execute', 1]];
    var boxes = [];
    var octLabel = el('span', { class: 'font-mono text-sm text-zinc-700' });
    function refresh() {
      var o = boxes.map(function (r) { return r.reduce(function (s, cb, ci) { return s + (cb.checked ? cols[ci][1] : 0); }, 0); });
      octLabel.textContent = '0' + o.join('');
      return o;
    }
    var grid = el('div', { class: 'mt-2 space-y-1.5' });
    grid.append(el('div', { class: 'grid grid-cols-4 gap-2 text-xs font-medium text-zinc-400' },
      el('span', {}), el('span', { text: 'Read', class: 'text-center' }), el('span', { text: 'Write', class: 'text-center' }), el('span', { text: 'Execute', class: 'text-center' })));
    rows.forEach(function (rname, ri) {
      var rowBoxes = [];
      var cells = [el('span', { class: 'text-sm text-zinc-600', text: rname })];
      cols.forEach(function (c, ci) {
        var cb = el('input', { type: 'checkbox', class: 'mx-auto block h-4 w-4' });
        cb.checked = (bits[ri] & c[1]) !== 0;
        cb.addEventListener('change', refresh);
        rowBoxes.push(cb);
        cells.push(el('label', { class: 'flex justify-center' }, cb));
      });
      boxes.push(rowBoxes);
      grid.append(el('div', { class: 'grid grid-cols-4 items-center gap-2' }, cells));
    });

    var ownerSel = el('select', { class: 'opp-select mt-1 w-full' });
    var groupSel = el('select', { class: 'opp-select mt-1 w-full' });
    // Each select lists the allowed candidates PLUS the entry's actual current
    // value (so "leave it as-is" is always representable and nothing changes by
    // accident when the real owner/group isn't a candidate).
    function fillSel(sel, current) {
      var opts = state.owners.slice();
      if (current && opts.indexOf(current) < 0) opts.unshift(current);
      opts.forEach(function (o) { sel.append(el('option', { value: o, text: o + (state.owners.indexOf(o) < 0 ? ' (current)' : '') })); });
      sel.value = current;
    }
    fillSel(ownerSel, e.owner);
    fillSel(groupSel, e.group);
    var ownWrap = state.canChown ? el('div', {},
      el('label', { class: 'block text-xs text-zinc-500', text: 'Owner' }), ownerSel,
      el('label', { class: 'mt-2 block text-xs text-zinc-500', text: 'Group' }), groupSel)
      : el('p', { class: 'text-xs text-zinc-400', text: 'Ownership: ' + e.owner + ':' + e.group + ' (changing owner needs a Linux host)' });

    var card = el('div', { class: 'opp-fm-card' },
      el('div', { class: 'flex items-center justify-between' },
        el('h3', { class: 'text-sm font-semibold text-zinc-900' }, el('span', { class: 'font-mono', text: e.name || 'this folder' }), ' permissions'),
        el('button', { class: 'text-zinc-400 hover:text-zinc-700', onclick: function () { ov.remove(); }, html: '<svg viewBox="0 0 20 20" fill="currentColor" class="h-5 w-5"><path d="M6 6l8 8M14 6l-8 8" stroke="currentColor" stroke-width="2"/></svg>' })),
      el('p', { class: 'mt-0.5 text-xs text-zinc-400', text: e.dir ? 'Directory' : (e.link ? 'Symbolic link' : 'Regular file') }),
      el('div', { class: 'mt-4 text-xs font-semibold uppercase tracking-wide text-zinc-400', text: 'Access' }),
      grid,
      el('div', { class: 'mt-2 flex items-center gap-2 text-xs text-zinc-500' }, 'Mode ', octLabel),
      el('div', { class: 'mt-4 text-xs font-semibold uppercase tracking-wide text-zinc-400', text: 'Ownership' }),
      el('div', { class: 'mt-1' }, ownWrap),
      el('div', { class: 'mt-5 flex justify-end gap-2' },
        el('button', { class: 'opp-btn', onclick: function () { ov.remove(); }, text: 'Cancel' }),
        el('button', {
          class: 'opp-btn-primary', text: 'Apply', onclick: function () {
            var oct = '0' + refresh().join('');
            var p = { path: state.path, name: e.name };
            if (oct !== initialOct) p.mode = oct; // only chmod when perms actually changed
            if (state.canChown) {
              if (ownerSel.value && ownerSel.value !== e.owner) p.owner = ownerSel.value;
              if (groupSel.value && groupSel.value !== e.group) p.group = groupSel.value;
            }
            if (!p.mode && !p.owner && !p.group) { ov.remove(); return; } // nothing to do
            act('permissions', p).then(function (ok) { if (ok) ov.remove(); });
          }
        })));
    var ov = overlay(card);
    refresh();
  }

  // ---- toast -------------------------------------------------------------
  var toastBox;
  function toast(msg, bad) {
    if (!toastBox) { toastBox = el('div', { class: 'opp-fm-toasts' }); document.body.append(toastBox); }
    var t = el('div', { class: 'opp-fm-toast ' + (bad ? 'opp-fm-toast-bad' : 'opp-fm-toast-ok'), text: msg });
    toastBox.append(t);
    setTimeout(function () { t.style.opacity = '0'; setTimeout(function () { t.remove(); }, 300); }, bad ? 5000 : 2600);
  }

  // ---- render ------------------------------------------------------------
  function render() {
    closeMenu();
    mount.textContent = '';

    // Breadcrumb
    var crumbs = el('div', { class: 'flex flex-wrap items-center gap-1 text-sm' });
    crumbs.append(el('button', { class: 'grid h-7 w-7 place-items-center rounded-md text-zinc-500 hover:bg-zinc-100 hover:text-blue-600', title: 'Document root', onclick: function () { load(''); }, html: ICON.drive }));
    (state.crumbs || []).forEach(function (c, i) {
      if (i > 0) crumbs.append(el('span', { class: 'text-zinc-300', text: '/' }));
      if (c.path === state.path) crumbs.append(el('span', { class: 'px-1 font-medium text-zinc-900', text: c.name }));
      else crumbs.append(el('button', { class: 'rounded px-1.5 py-0.5 text-zinc-600 hover:bg-zinc-100 hover:text-blue-600', text: c.name, onclick: function () { load(c.path); } }));
    });

    var header = el('div', { class: 'mb-4 flex flex-wrap items-center justify-between gap-3' },
      crumbs,
      el('a', { href: '/files', class: 'text-sm text-zinc-500 hover:text-blue-600', text: '← All sites' }));

    // Toolbar
    var filterInput = el('input', { class: 'w-full rounded-lg border border-zinc-200 bg-white py-2 pl-9 pr-3 text-sm focus:border-blue-400 focus:outline-none', placeholder: 'Filter this folder…', value: state.filter });
    filterInput.addEventListener('input', function () { state.filter = filterInput.value; renderGrid(); });
    var filterWrap = el('div', { class: 'relative min-w-[200px] flex-1' },
      el('span', { class: 'pointer-events-none absolute left-3 top-2.5 text-zinc-400', html: '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" class="h-4 w-4"><circle cx="9" cy="9" r="6"/><path d="m14 14 3 3" stroke-linecap="round"/></svg>' }),
      filterInput);

    var viewBtn = el('button', { class: 'opp-btn', title: 'Toggle grid / list', onclick: function () { state.view = state.view === 'grid' ? 'list' : 'grid'; localStorage.setItem('opp-fm-view', state.view); render(); }, html: state.view === 'grid'
      ? '<svg viewBox="0 0 20 20" fill="currentColor" class="h-4 w-4"><path d="M3 4h6v2H3zM3 9h6v2H3zM3 14h6v2H3zM11 4h6v2h-6zM11 9h6v2h-6zM11 14h6v2h-6z"/></svg>'
      : '<svg viewBox="0 0 20 20" fill="currentColor" class="h-4 w-4"><path d="M3 3h5v5H3zM12 3h5v5h-5zM3 12h5v5H3zM12 12h5v5h-5z"/></svg>' });

    var sortBtn = el('button', { class: 'opp-btn', onclick: function (ev) { ev.stopPropagation(); sortMenu(ev); } }, 'Sort ▾');
    var uploadBtn = el('button', { class: 'opp-btn-primary', onclick: pickUpload }, 'Upload');
    var newBtn = el('button', { class: 'opp-btn', onclick: function (ev) { ev.stopPropagation(); var r = ev.currentTarget.getBoundingClientRect(); emptyMenu(r.left, r.bottom + 4); } }, '+ New ▾');

    var toolbar = el('div', { class: 'mb-3 flex flex-wrap items-center gap-2' },
      filterWrap, viewBtn, sortBtn, el('div', { class: 'flex-1' }), newBtn, uploadBtn);

    mount.append(header, toolbar);

    // Selection bar
    var selBar = el('div', { id: 'opp-fm-selbar' });
    mount.append(selBar);

    // Grid/list container
    var grid = el('div', { id: 'opp-fm-grid' });
    grid.addEventListener('contextmenu', function (ev) { if (ev.target === grid || ev.target.id === 'opp-fm-inner') { ev.preventDefault(); clearSel(); renderGrid(); emptyMenu(ev.clientX, ev.clientY); } });
    // drag/drop upload
    grid.addEventListener('dragover', function (ev) { ev.preventDefault(); grid.classList.add('opp-fm-drop'); });
    grid.addEventListener('dragleave', function (ev) { if (ev.target === grid) grid.classList.remove('opp-fm-drop'); });
    grid.addEventListener('drop', function (ev) { ev.preventDefault(); grid.classList.remove('opp-fm-drop'); if (ev.dataTransfer && ev.dataTransfer.files.length) uploadFiles(ev.dataTransfer.files); });
    mount.append(grid);

    // Status bar
    mount.append(el('div', { id: 'opp-fm-status', class: 'mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-zinc-200 pt-3 text-xs text-zinc-500' }));

    renderGrid();
  }

  function renderGrid() {
    var grid = document.getElementById('opp-fm-grid');
    if (!grid) return;
    grid.className = '';
    grid.textContent = '';
    var selbar = document.getElementById('opp-fm-selbar');
    selbar.textContent = ''; selbar.className = '';

    if (state.loading) { grid.append(el('div', { class: 'py-20 text-center text-sm text-zinc-400', text: 'Loading…' })); return; }

    var vis = visibleEntries();

    // selection action bar
    var sel = selList();
    if (sel.length) {
      selbar.className = 'mb-3 flex flex-wrap items-center gap-2 rounded-xl border border-blue-200 bg-blue-50 px-3 py-2 text-sm';
      selbar.append(el('span', { class: 'font-medium text-blue-800', text: sel.length + ' selected' }));
      selbar.append(el('button', { class: 'opp-btn', onclick: function () { state.clip = { op: 'copy', path: state.path, names: sel }; toast('Copied ' + sel.length + ' items'); } }, 'Copy'));
      selbar.append(el('button', { class: 'opp-btn', onclick: function () { state.clip = { op: 'cut', path: state.path, names: sel }; toast('Cut ' + sel.length + ' items'); } }, 'Cut'));
      selbar.append(el('button', { class: 'opp-btn', onclick: function () { doZip(sel); } }, 'Zip'));
      selbar.append(el('button', { class: 'opp-btn-danger', onclick: function () { doDelete(sel); } }, 'Delete'));
      selbar.append(el('button', { class: 'text-blue-700 hover:underline', onclick: function () { clearSel(); renderGrid(); } }, 'Clear'));
    }

    var inner;
    if (!vis.length) {
      inner = el('div', { id: 'opp-fm-inner', class: 'grid place-items-center rounded-2xl border border-dashed border-zinc-200 bg-white py-20 text-center text-sm text-zinc-400' },
        el('div', {}, state.filter ? 'No items match “' + state.filter + '”.' : 'This folder is empty. Drop files here or use Upload.'));
    } else if (state.view === 'grid') {
      inner = el('div', { id: 'opp-fm-inner', class: 'grid grid-cols-[repeat(auto-fill,minmax(112px,1fr))] gap-1 rounded-2xl border border-zinc-200 bg-white p-3' });
      vis.forEach(function (e) { inner.append(tile(e)); });
    } else {
      inner = listTable(vis);
    }
    grid.append(inner);

    // status bar
    var st = document.getElementById('opp-fm-status');
    st.textContent = '';
    var c = state.counts;
    st.append(el('span', { text: (c.dirs || 0) + ' director' + (c.dirs === 1 ? 'y' : 'ies') + ', ' + (c.files || 0) + ' file' + (c.files === 1 ? '' : 's') + ', ' + (c.hidden || 0) + ' hidden' }));
    if (sel.length) st.append(el('span', { class: 'text-blue-600', text: sel.length + ' selected' }));
    st.append(el('label', { class: 'ml-auto flex items-center gap-1.5' },
      (function () { var cb = el('input', { type: 'checkbox', class: 'h-3.5 w-3.5' }); cb.checked = state.showHidden; cb.addEventListener('change', function () { state.showHidden = cb.checked; localStorage.setItem('opp-fm-hidden', cb.checked ? '1' : '0'); renderGrid(); }); return cb; })(),
      'Show hidden'));
  }

  function tile(e) {
    var selected = !!state.sel[e.name];
    var t = el('div', {
      class: 'group relative flex cursor-pointer flex-col items-center gap-1 rounded-xl p-2.5 text-center ' + (selected ? 'bg-blue-50 ring-1 ring-blue-300' : 'hover:bg-zinc-50'),
      title: e.name,
      onmousedown: function (ev) { onItemMouseDown(e, ev); },
      ondblclick: function () { openEntry(e); },
      oncontextmenu: function (ev) { ev.preventDefault(); ev.stopPropagation(); itemMenu(e, ev.clientX, ev.clientY); }
    },
      el('div', { class: 'h-12 w-12 ' + (e.dir ? 'text-blue-500' : (e.link ? 'text-teal-500' : 'text-zinc-400')), html: iconFor(e) }),
      el('div', { class: 'w-full break-words text-xs leading-tight text-zinc-700', text: e.name }),
      el('div', { class: 'text-[10px] text-zinc-400', text: e.dir ? '' : hsize(e.size) }));
    return t;
  }

  function listTable(vis) {
    var allSel = vis.length && vis.every(function (e) { return state.sel[e.name]; });
    var head = el('div', { class: 'grid grid-cols-[auto_1fr_90px_110px_130px_90px] items-center gap-3 border-b border-zinc-200 px-4 py-2 text-xs font-medium uppercase tracking-wide text-zinc-400' },
      (function () { var cb = el('input', { type: 'checkbox', class: 'h-3.5 w-3.5' }); cb.checked = allSel; cb.addEventListener('change', function () { state.sel = {}; if (cb.checked) vis.forEach(function (e) { state.sel[e.name] = true; }); renderGrid(); }); return cb; })(),
      sortHead('Name', 'name'), sortHead('Size', 'size'), sortHead('Owner', 'owner'), sortHead('Modified', 'mtime'), sortHead('Perms', 'perm'));
    var body = el('div', { class: 'divide-y divide-zinc-100' });
    vis.forEach(function (e) { body.append(listRow(e)); });
    return el('div', { id: 'opp-fm-inner', class: 'overflow-hidden rounded-2xl border border-zinc-200 bg-white' }, head, body);
  }
  function sortHead(label, key) {
    var active = state.sortKey === key;
    return el('button', { class: 'flex items-center gap-1 text-left uppercase ' + (active ? 'text-blue-600' : 'hover:text-zinc-700'), onclick: function () {
      if (state.sortKey === key) state.sortDir = state.sortDir === 'asc' ? 'desc' : 'asc';
      else { state.sortKey = key; state.sortDir = 'asc'; }
      localStorage.setItem('opp-fm-sortk', state.sortKey); localStorage.setItem('opp-fm-sortd', state.sortDir);
      renderGrid();
    } }, label, active ? (state.sortDir === 'asc' ? '↑' : '↓') : '');
  }
  function listRow(e) {
    var selected = !!state.sel[e.name];
    var cb = el('input', { type: 'checkbox', class: 'h-3.5 w-3.5' });
    cb.checked = selected;
    cb.addEventListener('mousedown', function (ev) { ev.stopPropagation(); });
    cb.addEventListener('change', function () { toggle(e.name); renderGrid(); });
    return el('div', {
      class: 'grid grid-cols-[auto_1fr_90px_110px_130px_90px] items-center gap-3 px-4 py-2 text-sm ' + (selected ? 'bg-blue-50' : 'hover:bg-zinc-50'),
      onmousedown: function (ev) { if (ev.target === cb) return; onItemMouseDown(e, ev); },
      ondblclick: function () { openEntry(e); },
      oncontextmenu: function (ev) { ev.preventDefault(); ev.stopPropagation(); itemMenu(e, ev.clientX, ev.clientY); }
    },
      cb,
      el('div', { class: 'flex min-w-0 items-center gap-2' },
        el('div', { class: 'h-5 w-5 shrink-0 ' + (e.dir ? 'text-blue-500' : (e.link ? 'text-teal-500' : 'text-zinc-400')), html: iconFor(e) }),
        el('span', { class: 'truncate text-zinc-800', text: e.name })),
      el('span', { class: 'text-zinc-500', text: e.dir ? '—' : hsize(e.size) }),
      el('span', { class: 'truncate text-zinc-500', text: e.owner || '—' }),
      el('span', { class: 'text-zinc-500', text: ago(e.mtime) }),
      el('span', { class: 'font-mono text-xs text-zinc-500', text: e.sym }));
  }

  function sortMenu(ev) {
    var r = ev.currentTarget.getBoundingClientRect();
    function opt(label, key, dir) { return { label: (state.sortKey === key && state.sortDir === dir ? '✓ ' : '') + label, run: function () { state.sortKey = key; state.sortDir = dir; localStorage.setItem('opp-fm-sortk', key); localStorage.setItem('opp-fm-sortd', dir); renderGrid(); } }; }
    openMenu(r.left, r.bottom + 4, [
      opt('Name A–Z', 'name', 'asc'), opt('Name Z–A', 'name', 'desc'),
      opt('Largest', 'size', 'desc'), opt('Smallest', 'size', 'asc'),
      opt('Newest', 'mtime', 'desc'), opt('Oldest', 'mtime', 'asc'),
      opt('Owner A–Z', 'owner', 'asc'), opt('Owner Z–A', 'owner', 'desc'),
      opt('Most permissive', 'perm', 'desc'), opt('Least permissive', 'perm', 'asc'),
      '-',
      { label: (state.showHidden ? '✓ ' : '') + 'Show hidden items', run: function () { state.showHidden = !state.showHidden; localStorage.setItem('opp-fm-hidden', state.showHidden ? '1' : '0'); renderGrid(); } }
    ]);
  }

  // ---- global listeners --------------------------------------------------
  document.addEventListener('click', function (ev) { if (menuEl && !menuEl.contains(ev.target)) closeMenu(); });
  document.addEventListener('keydown', function (ev) {
    if (ev.target.tagName === 'INPUT' || ev.target.tagName === 'TEXTAREA' || ev.target.tagName === 'SELECT') return;
    if (document.querySelector('.opp-fm-overlay')) return;
    var sel = selList();
    if (ev.key === 'Delete' && sel.length) { ev.preventDefault(); doDelete(sel); }
    else if (ev.key === 'F2' && sel.length === 1) { ev.preventDefault(); doRename(sel[0]); }
    else if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 'a') { ev.preventDefault(); state.sel = {}; visibleEntries().forEach(function (e) { state.sel[e.name] = true; }); renderGrid(); }
    else if (ev.key === 'Escape') { closeMenu(); if (sel.length) { clearSel(); renderGrid(); } }
  });
  window.addEventListener('popstate', function () {
    var p = new URLSearchParams(location.search).get('path') || '';
    load(p);
  });

  load(state.path);
})();
