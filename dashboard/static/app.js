/* ─────────────────────────────────────────────────────────────────────────
   Priv-Eye Dashboard — app.js
   Handles:
   1. Add-host form → POST /proxy/hosts → display one-time token
   2. Scan row filter by host
   3. Detail drawer with real ML numbers (risk, score, probabilities,
      feature importances, reasons)
   4. Gemini insight fetch from /proxy/insights
   ──────────────────────────────────────────────────────────────────────── */

"use strict";

// ── Helpers ──────────────────────────────────────────────────────────────

function qs(sel, root = document) { return root.querySelector(sel); }
function qsa(sel, root = document) { return [...root.querySelectorAll(sel)]; }

function riskColour(risk) {
  return { HIGH: "#ef4444", MEDIUM: "#f59e0b", LOW: "#22c55e" }[risk] ?? "#3b82f6";
}

function pctBar(value, colour, title) {
  const pct = Math.round(value * 100);
  return `
    <div class="prob-row" title="${title}">
      <span class="prob-label">${title}</span>
      <div class="prob-bar-track">
        <div class="prob-bar-fill" style="width:${pct}%;background:${colour}"></div>
      </div>
      <span class="prob-pct">${pct}%</span>
    </div>`;
}

function featBar(name, value, maxVal) {
  const pct = maxVal > 0 ? Math.round((value / maxVal) * 100) : 0;
  const display = name.replace("kernel_flavor_", "flav:").replace("suid_", "suid:");
  return `
    <div class="feat-row" title="${name}: ${(value * 100).toFixed(1)}%">
      <span class="feat-name">${display}</span>
      <div class="feat-bar-track">
        <div class="feat-bar-fill" style="width:${pct}%"></div>
      </div>
      <span class="feat-pct">${(value * 100).toFixed(1)}%</span>
    </div>`;
}

// ── Add host form ─────────────────────────────────────────────────────────

const addHostForm = qs("#add-host-form");
if (addHostForm) {
  addHostForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = qs("#add-host-btn");
    const resultArea = qs("#host-result");

    btn.disabled = true;
    btn.textContent = "Registering…";

    const body = JSON.stringify({
      hostname: qs("#new-hostname").value.trim(),
      environment: qs("#new-env").value.trim() || "default",
    });

    try {
      const resp = await fetch("/proxy/hosts", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body,
      });

      const data = await resp.json();

      if (resp.ok) {
        resultArea.style.display = "block";
        resultArea.innerHTML = `
          <div class="alert alert-success">Host registered successfully.</div>
          <br>
          <strong>Host ID</strong><br>
          <code style="word-break:break-all">${data.id}</code>
          <br><br>
          <strong>HMAC Key</strong> <em style="color:var(--text-dim);font-size:10px">(shown once — store it now)</em><br>
          <code style="word-break:break-all">${data.hmac_key}</code>
          <br><br>
          <span style="font-size:11px;color:var(--text-dim)">Run on your target host:</span><br>
          <code style="display:block;margin-top:4px;word-break:break-all">PRIVEYE_API=... PRIVEYE_HOST_ID=${data.id} PRIVEYE_HMAC_KEY=${data.hmac_key} priveye-agent scan</code>`;
        addHostForm.reset();
      } else {
        resultArea.style.display = "block";
        resultArea.innerHTML = `<div class="alert alert-error">${data.detail ?? JSON.stringify(data)}</div>`;
      }
    } catch (err) {
      resultArea.style.display = "block";
      resultArea.innerHTML = `<div class="alert alert-error">Network error: ${err.message}</div>`;
    } finally {
      btn.disabled = false;
      btn.textContent = "Add host";
    }
  });
}

// ── Host filter buttons ───────────────────────────────────────────────────

const clearFilterBtn = qs("#clear-filter-btn");

function setFilter(hostId) {
  qsa(".scan-row").forEach((row) => {
    row.classList.toggle("filtered-out", row.dataset.host !== hostId);
  });
  if (clearFilterBtn) {
    clearFilterBtn.style.display = "inline-block";
    clearFilterBtn.dataset.active = "1";
  }
}

function clearFilter() {
  qsa(".scan-row").forEach((row) => row.classList.remove("filtered-out"));
  if (clearFilterBtn) {
    clearFilterBtn.style.display = "none";
    delete clearFilterBtn.dataset.active;
  }
}

document.addEventListener("click", (e) => {
  const filterBtn = e.target.closest(".filter-btn");
  if (filterBtn) {
    setFilter(filterBtn.dataset.host);
    return;
  }
  if (e.target === clearFilterBtn) {
    clearFilter();
  }
});

// ── Detail drawer ─────────────────────────────────────────────────────────

const drawer = qs("#detail-drawer");
const drawerContent = qs("#drawer-content");
const drawerClose = qs("#drawer-close");

function openDrawer(scan) {
  drawerContent.innerHTML = buildDrawerHTML(scan);
  drawer.classList.add("open");
  drawer.setAttribute("aria-hidden", "false");
  wireInsightButton(scan.id);
}

function closeDrawer() {
  drawer.classList.remove("open");
  drawer.setAttribute("aria-hidden", "true");
}

if (drawerClose) drawerClose.addEventListener("click", closeDrawer);

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeDrawer();
});

document.addEventListener("click", (e) => {
  const btn = e.target.closest(".detail-btn");
  if (!btn) return;
  let scan;
  try {
    scan = JSON.parse(btn.dataset.scan);
  } catch {
    return;
  }
  openDrawer(scan);
});

function buildDrawerHTML(scan) {
  const colour = riskColour(scan.risk);
  const probs = scan.probabilities ?? {};
  const fi = scan.feature_importances ?? {};
  const reasons = scan.reasons ?? [];

  // Sort feature importances descending, keep top 8
  const topFeats = Object.entries(fi)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 8);
  const maxFeat = topFeats.length ? topFeats[0][1] : 1;

  return `
    <!-- Score + Risk -->
    <div class="d-section">
      <div class="d-section-title">Posture score</div>
      <div class="d-score-row">
        <span class="d-score-num" style="color:${colour}">${scan.score}</span>
        <div class="d-score-risk">
          <span class="risk-badge risk-${scan.risk.toLowerCase()}">${scan.risk}</span>
          <span style="font-size:10px;color:var(--text-dim)">model ${scan.model_version}</span>
        </div>
      </div>
    </div>

    <!-- Probabilities -->
    <div class="d-section">
      <div class="d-section-title">Class probabilities</div>
      ${pctBar(probs.HIGH   ?? 0, "#ef4444", "HIGH"  )}
      ${pctBar(probs.MEDIUM ?? 0, "#f59e0b", "MEDIUM")}
      ${pctBar(probs.LOW    ?? 0, "#22c55e", "LOW"   )}
    </div>

    <!-- Findings -->
    ${reasons.length ? `
    <div class="d-section">
      <div class="d-section-title">Findings</div>
      <ul class="reason-list">
        ${reasons.map(r => `
          <li class="reason-item">
            <span class="reason-bullet">▸</span>
            <span>${r}</span>
          </li>`).join("")}
      </ul>
    </div>` : ""}

    <!-- Feature importances -->
    ${topFeats.length ? `
    <div class="d-section">
      <div class="d-section-title">Feature importances <span style="font-weight:400;color:var(--text-muted)">(top 8, from RF)</span></div>
      ${topFeats.map(([name, val]) => featBar(name, val, maxFeat)).join("")}
    </div>` : ""}

    <!-- Gemini insight -->
    <div class="d-section" id="insight-section">
      <div class="d-section-title">AI synthesis</div>
      <button class="insight-trigger-btn" id="insight-btn" data-scan-id="${scan.id}">
        ✦ Generate Gemini insight for this scan
      </button>
    </div>`;
}

// ── Insight generation ────────────────────────────────────────────────────

function wireInsightButton(scanId) {
  const btn = qs("#insight-btn");
  if (!btn) return;

  btn.addEventListener("click", async () => {
    const section = qs("#insight-section");
    section.innerHTML = `
      <div class="d-section-title">AI synthesis</div>
      <p class="loading-msg"><span class="spinner"></span>Generating insight…</p>`;

    try {
      const resp = await fetch("/proxy/insights", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scan_id: scanId }),
      });

      if (resp.status === 503) {
        section.innerHTML = `
          <div class="d-section-title">AI synthesis</div>
          <p style="font-size:11px;color:var(--text-dim)">Insights disabled — set GEMINI_API_KEY to enable.</p>`;
        return;
      }

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        section.innerHTML = `
          <div class="d-section-title">AI synthesis</div>
          <div class="alert alert-error">${err.detail ?? "Insight generation failed"}</div>`;
        return;
      }

      const data = await resp.json();
      const steps = (data.remediation_roadmap ?? [])
        .map((s, i) => `<li data-n="${i + 1}">${s}</li>`)
        .join("");

      section.innerHTML = `
        <div class="d-section-title">AI synthesis <span style="font-weight:400;color:var(--text-muted)">via ${data.model}</span></div>
        <div class="insight-panel">
          <span class="insight-label">Threat landscape</span>
          <p class="insight-text">${data.threat_landscape}</p>
          <span class="insight-label">Compliance impact</span>
          <p class="insight-text">${data.compliance_impact}</p>
          <span class="insight-label">Remediation roadmap</span>
          <ol class="insight-steps">${steps}</ol>
        </div>`;
    } catch (err) {
      section.innerHTML = `
        <div class="d-section-title">AI synthesis</div>
        <div class="alert alert-error">Network error: ${err.message}</div>`;
    }
  });
}
