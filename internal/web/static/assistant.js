// AI deployment assistant chat client.
//
// Security: assistant text, tool-action summaries, and error strings are all
// model/server output and are rendered EXCLUSIVELY via textContent — never
// innerHTML — so nothing the model emits can inject markup into the page.
(function () {
  "use strict";

  var log = document.getElementById("chat-log");
  var form = document.getElementById("chat-form");
  var input = document.getElementById("chat-input");
  var send = document.getElementById("chat-send");
  if (!log || !form || !input) return;

  // One conversation id per page load; transcript state lives on the server.
  var convID =
    (window.crypto && window.crypto.randomUUID && window.crypto.randomUUID()) ||
    "c" + Date.now() + "-" + Math.random().toString(36).slice(2);

  // A per-domain chat scopes the conversation to one domain (data-domain on the
  // form); the operator then need not name it and it's authorized server-side.
  var scopedDomain = (form.dataset && form.dataset.domain) || "";

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text; // textContent — safe
    return e;
  }

  function scroll() {
    log.scrollTop = log.scrollHeight;
  }

  function bubble(role, text) {
    var row = el("div", "flex " + (role === "user" ? "justify-end" : "justify-start"));
    var b = el(
      "div",
      "max-w-[85%] whitespace-pre-wrap break-words rounded-2xl px-4 py-2 text-sm " +
        (role === "user"
          ? "bg-blue-600 text-white"
          : "bg-zinc-100 text-zinc-800"),
      text
    );
    row.appendChild(b);
    log.appendChild(row);
    scroll();
    return b;
  }

  // Renders the list of server actions (each = {tool, summary, error}).
  function actionsBlock(actions) {
    if (!actions || !actions.length) return;
    var wrap = el("div", "flex justify-start");
    var box = el("div", "max-w-[85%] space-y-1 rounded-xl border border-zinc-200 bg-white px-3 py-2");
    var head = el("div", "text-[11px] font-medium uppercase tracking-wide text-zinc-400", "Actions");
    box.appendChild(head);
    actions.forEach(function (a) {
      var line = el("div", "flex items-start gap-2 text-xs " + (a.error ? "text-red-600" : "text-zinc-700"));
      line.appendChild(el("span", "select-none", a.error ? "✗" : "✓"));
      line.appendChild(el("span", "", a.summary || a.tool));
      box.appendChild(line);
    });
    wrap.appendChild(box);
    log.appendChild(wrap);
    scroll();
  }

  function thinking() {
    var row = el("div", "flex justify-start");
    row.appendChild(el("div", "rounded-2xl bg-zinc-100 px-4 py-2 text-sm text-zinc-400", "Working…"));
    log.appendChild(row);
    scroll();
    return row;
  }

  var busy = false;

  function setBusy(v) {
    busy = v;
    if (send) send.disabled = v;
    input.disabled = v;
  }

  async function ask(message) {
    message = (message || "").trim();
    if (!message || busy) return;
    bubble("user", message);
    input.value = "";
    autoGrow();
    setBusy(true);
    var wait = thinking();
    try {
      var res = await fetch("/assistant/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ conv_id: convID, message: message, domain: scopedDomain }),
      });
      var data = {};
      try { data = await res.json(); } catch (e) { data = {}; }
      wait.remove();
      if (!res.ok || data.error) {
        bubble("assistant", data.error || "Something went wrong (HTTP " + res.status + ").");
      } else {
        if (data.text) bubble("assistant", data.text);
        actionsBlock(data.actions);
        if (!data.text && (!data.actions || !data.actions.length)) {
          bubble("assistant", "(no response)");
        }
      }
    } catch (e) {
      wait.remove();
      bubble("assistant", "Could not reach the server. Check your connection and try again.");
    } finally {
      setBusy(false);
      input.focus();
    }
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    ask(input.value);
  });

  // Enter sends; Shift+Enter inserts a newline.
  input.addEventListener("keydown", function (e) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      ask(input.value);
    }
  });

  function autoGrow() {
    input.style.height = "auto";
    input.style.height = Math.min(input.scrollHeight, 160) + "px";
  }
  input.addEventListener("input", autoGrow);

  // Example prompt chips fill the box and send.
  Array.prototype.forEach.call(document.querySelectorAll(".opp-example"), function (btn) {
    btn.addEventListener("click", function () {
      ask(btn.textContent);
    });
  });

  input.focus();
})();
