/* KR-SecWatch 공통 스크립트: 테마 · 새 알람 확인(15초) · ⌘K 통합 검색 */
(function () {
  "use strict";
  const body = document.body;

  // ---------------------------------------------------------------- 테마
  document.getElementById("theme-toggle").addEventListener("click", () => {
    const root = document.documentElement;
    const isDark = root.dataset.theme
      ? root.dataset.theme === "dark"
      : matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = isDark ? "light" : "dark";
    try { localStorage.setItem("theme", root.dataset.theme); } catch (e) {}
    document.dispatchEvent(new CustomEvent("themechange"));
  });

  // ---------------------------------------------------------------- 토스트
  const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", ok: "OK" };
  window.showToast = function (a) {
    const box = document.getElementById("toasts");
    const el = document.createElement("a");
    el.className = "toast toast-" + a.severity;
    el.href = a.internal_url || a.url || body.dataset.alertsUrl;
    if (!a.internal_url && a.url) { el.target = "_blank"; el.rel = "noopener noreferrer"; }
    const head = document.createElement("span");
    head.className = "toast-head";
    head.textContent = (SEV_LABEL[a.severity] || a.severity) + " · " + (a.kind_label || "");
    const title = document.createElement("span");
    title.className = "toast-title";
    title.textContent = a.title;
    el.append(head, title);
    box.prepend(el);
    const ttl = a.severity === "critical" ? 15000 : 8000;
    setTimeout(() => el.classList.add("out"), ttl);
    setTimeout(() => el.remove(), ttl + 600);
    while (box.children.length > 4) box.lastChild.remove();
  };

  // ---------------------------------------------------------------- 새 알람 확인 (15초 주기)
  // SSE 대신 짧은 요청: 탭이 많아도 연결을 점유하지 않음. 화면이 안 보이는 탭은 멈춤.
  (function poll() {
    const live = document.getElementById("live");
    let lastId = Number(body.dataset.lastAlertId) || 0, timer = null;
    async function check() {
      try {
        const r = await fetch(body.dataset.pollUrl + "?after=" + lastId);
        const data = await r.json();
        live.classList.remove("off");
        if (data.alerts.length) {
          data.alerts.forEach((a) => { if (a.severity !== "medium") window.showToast(a); });
          body.dispatchEvent(new Event("alerts-changed"));
        }
        lastId = data.last_id;
      } catch (e) { live.classList.add("off"); }
    }
    function schedule() { clearInterval(timer); timer = document.hidden ? null : setInterval(check, 15000); }
    document.addEventListener("visibilitychange", () => { if (!document.hidden) check(); schedule(); });
    schedule();
  })();

  // ---------------------------------------------------------------- ⌘K 통합 검색
  const palette = document.getElementById("palette");
  const input = document.getElementById("palette-q");
  const list = document.getElementById("palette-list");
  const isMac = /Mac|iPhone|iPad/.test(navigator.platform);
  document.getElementById("search-kbd").textContent = isMac ? "⌘K" : "Ctrl K";

  let items = [], active = 0, seq = 0, timer, inflight = null, lastQ = null;
  const BADGE = { critical: "Critical", high: "High", medium: "Medium", kev: "KEV" };

  function render() {
    list.replaceChildren();
    if (!items.length) {
      const li = document.createElement("li");
      li.className = "palette-empty";
      li.textContent = input.value.trim().length < 2 ? "두 글자 이상 입력하세요" : "검색 결과가 없습니다";
      list.append(li);
      return;
    }
    let group = null;
    items.forEach((it, i) => {
      if (it.group !== group) {
        group = it.group;
        const h = document.createElement("li");
        h.className = "palette-group";
        h.textContent = group;
        h.setAttribute("role", "presentation");
        list.append(h);
      }
      const li = document.createElement("li");
      li.className = "palette-item" + (i === active ? " active" : "");
      li.id = "palette-opt-" + i;
      li.setAttribute("role", "option");
      li.setAttribute("aria-selected", i === active);
      const title = document.createElement("span");
      title.className = "palette-title";
      title.textContent = it.title;
      li.append(title);
      if (it.badge) {
        const b = document.createElement("span");
        b.className = "palette-badge pb-" + it.badge;
        b.textContent = BADGE[it.badge] || it.badge;
        li.append(b);
      }
      if (it.sub) {
        const s = document.createElement("span");
        s.className = "palette-sub";
        s.textContent = it.sub;
        li.append(s);
      }
      if (it.external) {
        const ext = document.createElement("span");
        ext.className = "palette-ext";
        ext.textContent = "↗";
        ext.setAttribute("aria-label", "새 탭");
        li.append(ext);
      }
      li.addEventListener("mousemove", () => { if (active !== i) { active = i; highlight(); } });
      li.addEventListener("click", () => go(i));
      list.append(li);
    });
    input.setAttribute("aria-activedescendant", "palette-opt-" + active);
  }

  function highlight() {
    list.querySelectorAll(".palette-item").forEach((li, i) => {
      li.classList.toggle("active", i === active);
      li.setAttribute("aria-selected", i === active);
      if (i === active) li.scrollIntoView({ block: "nearest" });
    });
    input.setAttribute("aria-activedescendant", "palette-opt-" + active);
  }

  function query() {
    clearTimeout(timer);
    const q = input.value.trim(), my = ++seq;
    inflight = fetch(body.dataset.searchUrl + "?q=" + encodeURIComponent(q))
      .then((r) => r.json())
      .then((data) => {
        if (my !== seq) return;  // 늦게 도착한 이전 응답 무시
        items = data; active = 0; lastQ = q; render();
      })
      .catch(() => { /* 네트워크 오류 시 기존 결과 유지 */ });
    return inflight;
  }

  function go(i) {
    const it = items[i];
    if (!it) return;
    palette.close();
    if (it.external) window.open(it.url, "_blank", "noopener");
    else location.href = it.url;
  }

  function open() {
    if (palette.open) return;
    palette.showModal();
    input.value = "";
    query();
    input.focus();
  }

  document.getElementById("search-open").addEventListener("click", open);
  input.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(query, 150); });
  palette.addEventListener("close", () => { clearTimeout(timer); seq++; });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); active = Math.min(items.length - 1, active + 1); highlight(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); active = Math.max(0, active - 1); highlight(); }
    else if (e.key === "Enter") {
      e.preventDefault();
      // 입력 직후 Enter: 결과가 아직 이전 검색어 기준이면 최신 결과를 받은 뒤 이동
      if (lastQ !== input.value.trim()) query().then(() => go(0));
      else go(active);
    }
    else if (e.key === "Escape") { e.preventDefault(); palette.close(); }  // 검색창의 기본 Esc(입력 지우기) 대신 닫기
  });
  palette.addEventListener("click", (e) => { if (e.target === palette) palette.close(); });  // 바깥 클릭 닫기

  document.addEventListener("keydown", (e) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); open(); }
    else if (e.key === "/" && !typing && !palette.open) { e.preventDefault(); open(); }
  });
})();
