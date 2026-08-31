/**
 * PhishShield AI — Enterprise Popup Controller
 * Connects to background worker & FastAPI engine with clean telemetry state.
 */

document.addEventListener("DOMContentLoaded", async () => {
  // DOM Elements
  const statusDot = document.getElementById("ps-status-dot");
  const statusText = document.getElementById("ps-status-text");
  const currentDomainText = document.getElementById("ps-current-domain");
  const sslBadge = document.getElementById("ps-ssl-badge");
  const sslIcon = document.getElementById("ps-ssl-icon");
  const sslText = document.getElementById("ps-ssl-text");
  const urlInput = document.getElementById("ps-url-input");
  const btnScan = document.getElementById("ps-btn-scan-current");
  const scanBtnText = document.getElementById("ps-scan-btn-text");
  const loadingBar = document.getElementById("ps-loading-bar");

  // Metric & Result Elements
  const verdictHeadline = document.getElementById("ps-verdict-headline");
  const verdictBadge = document.getElementById("ps-verdict-badge");
  const valComposite = document.getElementById("ps-val-composite");
  const barComposite = document.getElementById("ps-bar-composite");
  const valMl = document.getElementById("ps-val-ml");
  const barMl = document.getElementById("ps-bar-ml");
  const valHeuristics = document.getElementById("ps-val-heuristics");
  const barHeuristics = document.getElementById("ps-bar-heuristics");
  const summaryText = document.getElementById("ps-summary-text");
  const flagsList = document.getElementById("ps-flags-list");
  const latencyText = document.getElementById("ps-scan-latency");
  const dashboardLink = document.getElementById("ps-open-dashboard-link");

  let activeTabUrl = "";

  // 1. Check Engine Health
  async function checkEngineStatus() {
    try {
      chrome.runtime.sendMessage({ type: "PING_BACKEND" }, (response) => {
        if (response && response.success) {
          statusDot.className = "ps-status-dot online";
          statusText.textContent = "Protection Active";
          statusText.style.color = "#94a3b8";
        } else {
          statusDot.className = "ps-status-dot offline";
          statusText.textContent = "Engine Offline";
          statusText.style.color = "#f87171";
        }
      });
    } catch (e) {
      statusDot.className = "ps-status-dot offline";
      statusText.textContent = "Engine Offline";
    }
  }

  // 2. Identify Active Browser Tab & SSL Status
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      activeTabUrl = tab.url;
      urlInput.value = tab.url;

      try {
        const parsed = new URL(tab.url);
        currentDomainText.textContent = parsed.hostname || tab.url;
        currentDomainText.title = tab.url;

        if (parsed.protocol === "https:") {
          sslBadge.className = "ps-ssl-badge";
          sslIcon.textContent = "🔒";
          sslText.textContent = "HTTPS Valid";
        } else if (parsed.protocol === "http:") {
          sslBadge.className = "ps-ssl-badge insecure";
          sslIcon.textContent = "⚠️";
          sslText.textContent = "HTTP Insecure";
        } else {
          sslBadge.className = "ps-ssl-badge";
          sslIcon.textContent = "⚙️";
          sslText.textContent = parsed.protocol.replace(":", "").toUpperCase();
        }
      } catch (e) {
        currentDomainText.textContent = tab.url;
      }
    }
  } catch (err) {
    console.debug("Unable to fetch current tab:", err);
  }

  await checkEngineStatus();

  // 3. Scan Button Event Handler
  btnScan.addEventListener("click", async () => {
    const targetUrl = urlInput.value.trim();
    if (!targetUrl) return;

    // Trigger Loading State
    btnScan.disabled = true;
    scanBtnText.textContent = "Auditing Security...";
    if (loadingBar) loadingBar.style.display = "block";
    verdictHeadline.textContent = "Evaluating Threat Vectors...";
    summaryText.textContent = "Extracting URL lexical tokens, XGBoost inference, and contextual inspection...";

    // Attempt to extract page text for Tier 3 contextual AI
    let pageText = "";
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab && tab.id && tab.url === targetUrl) {
        const res = await chrome.tabs.sendMessage(tab.id, { type: "EXTRACT_PAGE_CONTENT" });
        if (res && res.pageText) pageText = res.pageText;
      }
    } catch (err) {
      console.debug("Page text extraction skipped:", err);
    }

    chrome.runtime.sendMessage(
      {
        type: "SCAN_URL",
        url: targetUrl,
        pageText: pageText
      },
      (response) => {
        btnScan.disabled = false;
        scanBtnText.textContent = "Scan Current Page";
        if (loadingBar) loadingBar.style.display = "none";

        if (!response || !response.success) {
          verdictHeadline.textContent = "Audit Error";
          verdictBadge.textContent = "OFFLINE";
          verdictBadge.className = "ps-badge ps-badge-critical";
          summaryText.textContent = "Error: " + (response ? response.error : "Could not connect to backend. Click the ⚙️ icon above to configure your live Vercel backend URL.");
          return;
        }


        renderAuditResults(response.data);
      }
    );
  });

  // 4. Render Enterprise Results
  function renderAuditResults(data) {
    const { url, risk_score, risk_level, verdict, explainability_summary, tier_breakdown, detected_factors, scan_latency_ms } = data;

    // Headline & Severity Badge
    verdictHeadline.textContent = verdict;
    verdictBadge.textContent = risk_level;
    verdictBadge.className = `ps-badge ps-badge-${risk_level.toLowerCase()}`;

    // Metric 1: Composite Risk Score
    valComposite.textContent = `${risk_score}%`;
    barComposite.style.width = `${risk_score}%`;
    barComposite.style.backgroundColor = getSeverityColor(risk_level);

    // Metric 2 & 3: Tier Breakdown
    const tb = tier_breakdown || {
      heuristic_score: risk_score,
      ml_score: risk_score,
      ai_score: risk_score
    };

    valMl.textContent = `${tb.ml_score}%`;
    barMl.style.width = `${tb.ml_score}%`;
    barMl.style.backgroundColor = tb.ml_score > 60 ? "#f87171" : "#3b82f6";

    valHeuristics.textContent = `${tb.heuristic_score}%`;
    barHeuristics.style.width = `${tb.heuristic_score}%`;
    barHeuristics.style.backgroundColor = tb.heuristic_score > 60 ? "#f87171" : "#64748b";

    // Summary Text
    summaryText.textContent = explainability_summary || "Audit complete.";

    // Latency
    latencyText.textContent = `${scan_latency_ms} ms`;

    // Detected Threat Factors List
    flagsList.innerHTML = "";
    if (detected_factors && detected_factors.length > 0) {
      detected_factors.forEach(f => {
        const item = document.createElement("div");
        item.className = "ps-flag-item";
        item.innerHTML = `
          <span style="font-weight: 700; color: ${f.severity === 'CRITICAL' || f.severity === 'HIGH' ? '#fca5a5' : '#fbbf24'};">[${f.severity}]</span>
          <span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(f.message)}</span>
        `;
        item.title = `${f.code}: ${f.message}`;
        flagsList.appendChild(item);
      });
    } else {
      flagsList.innerHTML = `
        <div class="ps-flag-item">
          <span style="color: #34d399;">✓</span> Verified safe. Zero active threat signatures detected.
        </div>
      `;
    }
  }

  function getSeverityColor(level) {
    switch (level) {
      case "CRITICAL":
      case "HIGH":
        return "#f87171";
      case "MEDIUM":
      case "LOW":
        return "#fbbf24";
      default:
        return "#34d399";
    }
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // 5. Settings Panel & Custom Backend URL
  const settingsPanel = document.getElementById("ps-settings-panel");
  const toggleSettingsBtn = document.getElementById("ps-btn-toggle-settings");
  const engineStatusBtn = document.getElementById("ps-engine-status");
  const apiUrlInput = document.getElementById("ps-api-url-input");
  const saveApiBtn = document.getElementById("ps-btn-save-api");
  const settingsStatus = document.getElementById("ps-settings-status");

  // Load configured apiUrl
  chrome.storage.local.get("apiUrl", (res) => {
    if (res && res.apiUrl) {
      apiUrlInput.value = res.apiUrl;
    } else {
      apiUrlInput.value = "http://localhost:8000";
    }
  });

  function toggleSettings() {
    if (settingsPanel.style.display === "none" || !settingsPanel.style.display) {
      settingsPanel.style.display = "block";
      apiUrlInput.focus();
    } else {
      settingsPanel.style.display = "none";
    }
  }

  if (toggleSettingsBtn) toggleSettingsBtn.addEventListener("click", toggleSettings);
  if (engineStatusBtn) engineStatusBtn.addEventListener("click", toggleSettings);

  if (saveApiBtn) {
    saveApiBtn.addEventListener("click", async () => {
      let val = apiUrlInput.value.trim();
      if (!val) val = "http://localhost:8000";
      // Remove trailing slash
      val = val.replace(/\/+$/, "");
      if (!val.startsWith("http://") && !val.startsWith("https://")) {
        val = "https://" + val;
      }
      apiUrlInput.value = val;
      await chrome.storage.local.set({ apiUrl: val });
      settingsStatus.textContent = "Saved! Reconnecting to engine...";
      settingsStatus.style.color = "#34d399";
      await checkEngineStatus();
      setTimeout(() => {
        settingsStatus.textContent = "";
        settingsPanel.style.display = "none";
      }, 1200);
    });
  }

  // 6. Open SOC Analytics Dashboard Tab
  dashboardLink.addEventListener("click", async (e) => {
    e.preventDefault();
    const { apiUrl = "http://localhost:8000" } = await chrome.storage.local.get("apiUrl");
    chrome.tabs.create({ url: apiUrl });
  });
});

