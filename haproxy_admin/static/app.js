// HAProxy Admin – small progressive enhancements (no external dependencies, CSP 'self').
document.addEventListener("DOMContentLoaded", () => {
  // Confirmation dialogs
  document.querySelectorAll("form[data-confirm]").forEach(f => {
    f.addEventListener("submit", e => { if (!confirm(f.dataset.confirm)) e.preventDefault(); });
  });
  document.querySelectorAll("[data-confirm-click]").forEach(b => {
    b.addEventListener("click", e => { if (!confirm(b.dataset.confirmClick)) e.preventDefault(); });
  });
  // Type-the-name confirmation
  document.querySelectorAll("form[data-confirm-name]").forEach(f => {
    f.addEventListener("submit", e => {
      const name = f.dataset.confirmName;
      const typed = prompt(`Type "${name}" to confirm:`);
      if (typed !== name) { e.preventDefault(); return; }
      f.querySelector("input[name=confirm]").value = typed;
    });
  });
  // Filter for tables (rows) and lists (direct children)
  document.querySelectorAll("input[data-filter]").forEach(inp => {
    const box = document.querySelector(inp.dataset.filter);
    if (!box) return;
    const items = box.tagName === "TABLE" ? [...box.querySelectorAll("tr")].slice(1) : [...box.children];
    inp.addEventListener("input", () => {
      const q = inp.value.toLowerCase();
      items.forEach(el => { el.style.display = el.textContent.toLowerCase().includes(q) ? "" : "none"; });
    });
  });

  // Rows from <template>: placeholder tokens are replaced by the next free index
  const nextIndex = (container, re) => {
    let max = -1;
    container.querySelectorAll("[name]").forEach(el => {
      const m = el.name.match(re);
      if (m) max = Math.max(max, parseInt(m[1], 10));
    });
    return max + 1;
  };
  const fromTemplate = (tplId, replacements) => {
    let html = document.getElementById(tplId).innerHTML;
    for (const [k, v] of Object.entries(replacements)) html = html.split(k).join(v);
    const t = document.createElement("template");
    t.innerHTML = html.trim();
    return t.content.firstElementChild;
  };
  const bindRoute = row => {
    row.querySelectorAll("[data-addcond]").forEach(btn => btn.addEventListener("click", () => {
      const i = row.dataset.index;
      const box = row.querySelector(".conds");
      const j = nextIndex(box, new RegExp(`^r${i}_c(\\d+)_type$`));
      const el = fromTemplate("tpl-cond", { "__R__": i, "__C__": j });
      box.appendChild(el);
      bindCond(el);
      el.querySelector("input").focus();
    }));
    row.querySelectorAll(".cond").forEach(bindCond);
  };
  const bindCond = el => {
    el.querySelectorAll("[data-remove]").forEach(b => b.addEventListener("click", () => el.remove()));
    const sel = el.querySelector("select"), inp = el.querySelector("input:not([type=checkbox])");
    if (sel && inp) sel.addEventListener("change", () => { inp.placeholder = sel.selectedOptions[0].dataset.hint || ""; });
  };
  const routes = document.getElementById("routes");
  if (routes) {
    routes.querySelectorAll("tr.route").forEach(bindRoute);
    document.getElementById("addroute").addEventListener("click", () => {
      const i = nextIndex(routes, /^r(\d+)_host$/);
      const row = fromTemplate("tpl-route", { "__R__": i });
      row.dataset.index = i;
      routes.appendChild(row);
      bindRoute(row);
      row.querySelector("input").focus();
    });
  }
  [["addsrv", "srvrows", "tpl-srv", "__S__", /^s(\d+)_name$/], ["addrd", "rdrows", "tpl-rd", "__D__", /^rd(\d+)_path$/]]
    .forEach(([btnId, bodyId, tpl, token, re]) => {
      const btn = document.getElementById(btnId), body = document.getElementById(bodyId);
      if (!btn || !body) return;
      btn.addEventListener("click", () => {
        const row = fromTemplate(tpl, { [token]: nextIndex(body, re) });
        body.appendChild(row);
        row.querySelector("input").focus();
      });
    });

  // Tab key inserts a tab in config editors
  document.querySelectorAll("textarea.editor").forEach(ta => {
    ta.addEventListener("keydown", e => {
      if (e.key === "Tab" && !e.shiftKey) {
        e.preventDefault();
        const s = ta.selectionStart;
        ta.setRangeText("\t", s, ta.selectionEnd, "end");
      }
    });
  });
  // Site name suggestion from the first host name
  document.querySelectorAll("input[data-suggest]").forEach(inp => {
    const target = document.querySelector(inp.dataset.suggest);
    inp.addEventListener("change", async () => {
      if (!target || target.value) return;
      const r = await fetch(`suggest-name?host=${encodeURIComponent(inp.value)}`);
      if (r.ok) target.placeholder = (await r.json()).name || "auto";
    });
  });
  // Auto refresh (logs)
  const auto = document.querySelector("[data-autorefresh]");
  if (auto) setTimeout(() => location.reload(), parseInt(auto.dataset.autorefresh, 10) * 1000);
  // Live job log
  const log = document.getElementById("job-log");
  if (log) {
    let total = log.textContent.split("\n").filter((l, i, a) => i < a.length - 1).length;
    const status = document.getElementById("job-status");
    const poll = async () => {
      const r = await fetch(`${log.dataset.jobUrl}?since=${total}`);
      if (!r.ok) return;
      const j = await r.json();
      if (j.lines.length) {
        log.textContent += j.lines.join("\n") + "\n";
        total = j.total;
        log.scrollTop = log.scrollHeight;
      }
      if (j.running) { setTimeout(poll, 1500); return; }
      status.innerHTML = j.rc === 0 ? '<span class="badge good">finished</span>' : `<span class="badge bad">failed (rc ${j.rc})</span>`;
    };
    poll();
  }
});
