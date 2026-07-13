/* Domains detail page — the repo-folder "Browse…" picker. Folder names come
 * from the tenant's repository and reach the DOM via textContent ONLY. */
(function () {
  'use strict';
  function el(tag, props) {
    var n = document.createElement(tag);
    props = props || {};
    for (var k in props) {
      var v = props[k];
      if (v == null) continue;
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else if (k.indexOf('on') === 0 && typeof v === 'function') n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v);
    }
    for (var i = 2; i < arguments.length; i++) {
      var kids = arguments[i];
      if (!Array.isArray(kids)) kids = [kids];
      kids.forEach(function (c) { if (c != null) n.append(c.nodeType ? c : document.createTextNode(c)); });
    }
    return n;
  }

  function browse(repoID, startPath, targetId) {
    var panel = document.getElementById('opp-browse');
    if (!panel) return;
    panel.classList.remove('hidden');
    panel.textContent = 'Loading…';
    fetch('/repos/' + encodeURIComponent(repoID) + '/tree?path=' + encodeURIComponent(startPath || ''), { headers: { 'X-OPP-Ajax': '1' } })
      .then(function (r) { if (!r.ok) throw new Error(); return r.json(); })
      .then(function (data) {
        panel.textContent = '';
        var use = el('button', {
          type: 'button', class: 'opp-btn', text: 'Use this folder',
          onclick: function () { var t = document.getElementById(targetId); if (t) t.value = data.path || ''; panel.classList.add('hidden'); }
        });
        panel.append(el('div', { class: 'mb-1 flex items-center justify-between gap-2' },
          el('span', { class: 'truncate font-mono text-xs text-zinc-500', text: '/' + (data.path || '') }), use));
        function entry(label, cls, next) {
          panel.append(el('button', { type: 'button', class: 'block w-full truncate text-left text-xs ' + cls, text: label, onclick: function () { browse(repoID, next, targetId); } }));
        }
        if (data.path) entry('.. (up one level)', 'text-zinc-500 hover:text-blue-600', data.path.split('/').slice(0, -1).join('/'));
        (data.dirs || []).forEach(function (dname) { entry('📁 ' + dname, 'text-zinc-700 hover:text-blue-600', (data.path ? data.path + '/' : '') + dname); });
        if (!(data.dirs || []).length) panel.append(el('div', { class: 'text-xs text-zinc-400', text: '(no subfolders here)' }));
      })
      .catch(function () { panel.textContent = 'Could not list folders — deploy the repository first.'; });
  }

  document.addEventListener('click', function (ev) {
    var btn = ev.target.closest && ev.target.closest('[data-browse]');
    if (!btn) return;
    ev.preventDefault();
    var targetId = btn.getAttribute('data-target');
    var start = (document.getElementById(targetId) || {}).value || '';
    browse(btn.getAttribute('data-browse'), start, targetId);
  });
})();
