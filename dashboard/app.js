/**
 * PhishShield SOC — Enterprise Dashboard Controller
 * REST client querying FastAPI engine for live telemetry, sandbox audits, and community intelligence.
 */

const API_BASE = "http://127.0.0.1:8000";

let isStreamActive = true;
let streamInterval = null;
let recentScansData = [];
let activeInspectLog = null;
let latestSandboxResult = null;
let isRefreshing = false;

document.addEventListener("DOMContentLoaded", () => {
  initClock();
  initEventListeners();
  fetchHealthStatus();
  fetchTelemetry();
  fetchCommunityReports();
  startTelemetryPolling();
  checkUrlQueryParams();
});

// Live UTC Clock
function initClock() {
  const clockEl = document.getElementById("live-clock");
  if (!clockEl) return;
  function updateClock() {
    const now = new Date();
    clockEl.textContent = now.toISOString().slice(11, 19) + " UTC";
  }
  updateClock();
  setInterval(updateClock, 1000);
}

// Check if a URL was passed in query string (e.g. ?url=https://...)
function checkUrlQueryParams() {
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get("url");
  if (targetUrl) {
    const input = document.getElementById("sandbox-url-input");
    if (input) input.value = targetUrl;
    executeSandboxAudit(targetUrl);
  }
}

// Event Listeners
function initEventListeners() {
  // Sandbox Form Submission
  const sandboxForm = document.getElementById("sandbox-form");
  sandboxForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const url = document.getElementById("sandbox-url-input").value.trim();
    const pageText = document.getElementById("sandbox-text-input").value.trim();
    if (url) {
      executeSandboxAudit(url, pageText);
    }
  });

  // Judge Presets
  const presetButtons = document.querySelectorAll(".preset-btn");
  presetButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const url = btn.getAttribute("data-url");
      const input = document.getElementById("sandbox-url-input");
      if (input) input.value = url;
      executeSandboxAudit(url);
    });
  });

  // Stream Toggle Button
  const toggleBtn = document.getElementById("toggle-stream-btn");
  toggleBtn.addEventListener("click", toggleTelemetryStream);

  // Refresh Button with Guaranteed Finite Animation
  const refreshBtn = document.getElementById("refresh-telemetry-btn");
  refreshBtn.addEventListener("click", handleManualRefresh);

  // Inspect Modal Close Handlers
  const inspectModal = document.getElementById("inspect-modal");
  const closeInspectBtn = document.getElementById("close-inspect-modal-btn");
  closeInspectBtn.addEventListener("click", () => inspectModal.classList.add("hidden"));
  
  inspectModal.addEventListener("click", (e) => {
    if (e.target === inspectModal) {
      inspectModal.classList.add("hidden");
    }
  });

  // Inspect Modal Action Buttons
  document.getElementById("modal-share-btn").addEventListener("click", () => {
    if (activeInspectLog) shareThreatAdvisory(activeInspectLog);
  });

  document.getElementById("modal-copy-btn").addEventListener("click", () => {
    if (activeInspectLog) copySecurityAdvisory(activeInspectLog);
  });

  document.getElementById("modal-sandbox-btn").addEventListener("click", () => {
    if (activeInspectLog) {
      inspectModal.classList.add("hidden");
      const input = document.getElementById("sandbox-url-input");
      if (input) input.value = activeInspectLog.url;
      executeSandboxAudit(activeInspectLog.url);
    }
  });

  // Sandbox Share Button
  document.getElementById("sandbox-share-btn").addEventListener("click", () => {
    if (latestSandboxResult) shareThreatAdvisory(latestSandboxResult);
  });

  // Report Modal Open/Close
  const openModalBtn = document.getElementById("open-report-modal-btn");
  const closeModalBtn = document.getElementById("close-report-modal-btn");
  const cancelReportBtn = document.getElementById("cancel-report-btn");
  const reportModal = document.getElementById("report-modal");

  openModalBtn.addEventListener("click", () => reportModal.classList.remove("hidden"));
  closeModalBtn.addEventListener("click", () => reportModal.classList.add("hidden"));
  cancelReportBtn.addEventListener("click", () => reportModal.classList.add("hidden"));
  
  reportModal.addEventListener("click", (e) => {
    if (e.target === reportModal) {
      reportModal.classList.add("hidden");
    }
  });

  // Keyboard Shortcuts (Esc to close modals)
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      inspectModal.classList.add("hidden");
      reportModal.classList.add("hidden");
    }
  });

  // Report Form Submit
  const reportForm = document.getElementById("threat-report-form");
  reportForm.addEventListener("submit", submitThreatReport);
}

// Manual Refresh with Smooth Animation & Guaranteed Stop
async function handleManualRefresh() {
  if (isRefreshing) return;
  isRefreshing = true;

  const refreshBtn = document.getElementById("refresh-telemetry-btn");
  refreshBtn.classList.add("is-refreshing");
  refreshBtn.disabled = true;

  try {
    await Promise.all([fetchTelemetry(), fetchCommunityReports()]);
    showToast("Telemetry & threat intelligence refreshed", "success");
  } catch (err) {
    showToast("Refresh error: " + err.message, "error");
  } finally {
    setTimeout(() => {
      refreshBtn.classList.remove("is-refreshing");
      refreshBtn.disabled = false;
      isRefreshing = false;
    }, 600);
  }
}

// Fetch Engine Health
async function fetchHealthStatus() {
  try {
    const res = await fetch(`${API_BASE}/health`);
    if (res.ok) {
      const data = await res.json();
      const engineStatus = document.getElementById("header-engine-status");
      if (data.ml_model_loaded) {
        engineStatus.textContent = "3-TIER MULTI-ENGINE ACTIVE";
      }
    }
  } catch (err) {
    console.debug("Backend status check failed:", err);
  }
}

// Telemetry Polling (every 3 seconds)
function startTelemetryPolling() {
  if (streamInterval) clearInterval(streamInterval);
  streamInterval = setInterval(() => {
    if (isStreamActive) {
      fetchTelemetry();
    }
  }, 3000);
}

function toggleTelemetryStream() {
  isStreamActive = !isStreamActive;
  const btnText = document.getElementById("stream-btn-text");
  const streamIcon = document.getElementById("stream-btn-icon");
  const pulseBadge = document.getElementById("stream-pulse");

  if (isStreamActive) {
    btnText.textContent = "Pause";
    if (streamIcon) streamIcon.setAttribute("data-lucide", "pause");
    pulseBadge.textContent = "POLLING (3s)";
    pulseBadge.className = "inline-flex items-center px-1.5 py-0.5 rounded text-[9px] sm:text-[10px] font-mono bg-slate-900 text-slate-300 border border-slate-700";
    fetchTelemetry();
    showToast("Telemetry polling resumed", "info");
  } else {
    btnText.textContent = "Resume";
    if (streamIcon) streamIcon.setAttribute("data-lucide", "play");
    pulseBadge.textContent = "PAUSED";
    pulseBadge.className = "inline-flex items-center px-1.5 py-0.5 rounded text-[9px] sm:text-[10px] font-mono bg-amber-950 text-amber-300 border border-amber-800";
    showToast("Telemetry polling paused", "info");
  }
  if (window.lucide) lucide.createIcons();
}

// Fetch Real-time Telemetry Stats & Recent Scans
async function fetchTelemetry() {
  try {
    // 1. Fetch Stats
    const statsRes = await fetch(`${API_BASE}/api/v1/analytics/stats`);
    if (statsRes.ok) {
      const stats = await statsRes.json();
      updateMetricCards(stats);
    }

    // 2. Fetch Recent Scan Logs
    const recentRes = await fetch(`${API_BASE}/api/v1/analytics/recent?limit=25`);
    if (recentRes.ok) {
      recentScansData = await recentRes.json();
      renderTelemetryTable(recentScansData);
    }
  } catch (err) {
    console.debug("Telemetry fetch error:", err);
  }
}

// Update Metric Cards
function updateMetricCards(stats) {
  const totalScans = stats.total_scans || 0;
  const threats = stats.threats_intercepted || 0;
  const avgLatency = Number(stats.avg_latency_ms) || 0.0;
  const totalReports = stats.total_community_reports || 0;

  document.getElementById("stat-total-scans").textContent = totalScans.toLocaleString();
  document.getElementById("stat-threats").textContent = threats.toLocaleString();
  document.getElementById("stat-latency").textContent = avgLatency.toFixed(1);
  document.getElementById("stat-reports").textContent = totalReports.toLocaleString();

  const threatRatio = totalScans > 0 
    ? ((threats / totalScans) * 100).toFixed(1) 
    : "0.0";
  document.getElementById("stat-threat-ratio").textContent = `${threatRatio}%`;
  
  // Header latency badge
  document.getElementById("header-latency").textContent = `${avgLatency.toFixed(1)} ms`;

  // Processing mode calculation
  const modeEl = document.getElementById("stat-processing-mode");
  if (avgLatency > 0 && avgLatency < 50) {
    modeEl.textContent = "Sub-Millisecond Engine";
  } else if (avgLatency >= 50 && avgLatency < 500) {
    modeEl.textContent = "Real-Time Multi-Tier";
  } else {
    modeEl.textContent = "Contextual Deep Scan";
  }
}

// Render Telemetry Table
function renderTelemetryTable(scans) {
  const tbody = document.getElementById("telemetry-table-body");
  if (!scans || scans.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="5" class="py-6 text-center text-slate-500 font-sans">
          No telemetry events registered yet. Scan a link in the sandbox or via extension.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = scans.map((scan, index) => {
    const timeStr = scan.timestamp ? new Date(scan.timestamp).toLocaleTimeString() : "--:--:--";
    const levelClass = getBadgeClass(scan.risk_level);
    const scoreColor = getScoreColor(scan.risk_score);
    const cleanUrl = scan.url.length > 34 ? scan.url.slice(0, 32) + "..." : scan.url;

    return `
      <tr class="soc-row border-b border-slate-750">
        <td class="py-2 pl-2 text-slate-400 font-mono">${timeStr}</td>
        <td class="py-2 text-slate-200 font-mono" title="${escapeHtml(scan.url)}">${escapeHtml(cleanUrl)}</td>
        <td class="py-2 text-center font-bold font-mono ${scoreColor}">${scan.risk_score}%</td>
        <td class="py-2 text-center">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono ${levelClass}">
            ${scan.risk_level}
          </span>
        </td>
        <td class="py-2 pr-2 text-right">
          <button onclick="openInspectModal(${index})" class="px-2.5 py-1 rounded text-[11px] font-medium bg-slate-750 hover:bg-slate-700 border border-slate-600 text-slate-300 hover:text-white transition active:scale-95">
            Inspect
          </button>
        </td>
      </tr>
    `;
  }).join("");
}

// Open Dedicated Inspect Modal (Mini Screen)
window.openInspectModal = function(index) {
  const log = recentScansData[index];
  if (!log) return;

  activeInspectLog = log;
  const modal = document.getElementById("inspect-modal");

  // Populate data
  document.getElementById("modal-url").textContent = log.url;
  document.getElementById("modal-timestamp").textContent = log.timestamp 
    ? new Date(log.timestamp).toLocaleString() 
    : "Timestamp unknown";

  const scoreEl = document.getElementById("modal-score");
  scoreEl.textContent = `${log.risk_score}%`;
  scoreEl.className = `text-lg font-bold ${getScoreColor(log.risk_score)}`;

  const badgeEl = document.getElementById("modal-severity-badge");
  badgeEl.textContent = log.risk_level;
  badgeEl.className = `inline-block mt-0.5 px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase ${getBadgeClass(log.risk_level)}`;

  document.getElementById("modal-latency").textContent = `${log.latency_ms || 0}ms`;

  // Tier breakdown
  const hScore = log.heuristic_score ?? 0;
  const mScore = log.ml_score ?? 0;
  const aScore = log.ai_score ?? 0;

  document.getElementById("modal-tier1-val").textContent = `${hScore}%`;
  document.getElementById("modal-tier1-bar").style.width = `${hScore}%`;

  document.getElementById("modal-tier2-val").textContent = `${mScore}%`;
  document.getElementById("modal-tier2-bar").style.width = `${mScore}%`;

  document.getElementById("modal-tier3-val").textContent = `${aScore}%`;
  document.getElementById("modal-tier3-bar").style.width = `${aScore}%`;

  document.getElementById("modal-summary").textContent = log.explainability_summary 
    || `Audit evaluated link as ${log.verdict} with composite score of ${log.risk_score}%.`;

  // Display modal
  modal.classList.remove("hidden");
  if (window.lucide) lucide.createIcons();
};

// Fetch Community Reports Feed
async function fetchCommunityReports() {
  try {
    const res = await fetch(`${API_BASE}/api/v1/reports?limit=15`);
    if (res.ok) {
      const reports = await res.json();
      const countEl = document.getElementById("community-reports-count");
      countEl.textContent = `${reports.length} Reports`;

      const feedEl = document.getElementById("community-reports-feed");
      if (reports.length === 0) {
        feedEl.innerHTML = `<div class="text-center py-4 text-slate-500 text-xs">No community threat reports filed yet.</div>`;
        return;
      }

      feedEl.innerHTML = reports.map((r) => {
        const timeAgo = r.created_at ? new Date(r.created_at).toLocaleTimeString() : "";
        return `
          <div class="p-2.5 rounded-lg bg-slate-900 border border-slate-700 text-xs space-y-1.5 hover:border-slate-600 transition">
            <div class="flex items-center justify-between text-[11px] gap-2">
              <span class="font-bold font-mono text-rose-300 truncate max-w-[200px]" title="${escapeHtml(r.url)}">${escapeHtml(r.url)}</span>
              <span class="text-slate-500 text-[10px] font-mono shrink-0">${timeAgo}</span>
            </div>
            <p class="text-slate-300 text-[11px] leading-snug font-sans">${escapeHtml(r.reason)}</p>
            <div class="flex items-center justify-between text-[10px] text-slate-500 font-mono pt-1 border-t border-slate-800/80">
              <span>Reporter: <strong class="text-slate-400">${escapeHtml(r.reporter_id || 'community')}</strong></span>
              <button onclick="shareCommunityReport('${encodeURIComponent(r.url)}', '${encodeURIComponent(r.reason)}')" class="text-blue-400 hover:text-blue-300 font-sans flex items-center gap-1 font-medium active:scale-95">
                <i data-lucide="share-2" class="w-3 h-3"></i> Share Alert
              </button>
            </div>
          </div>
        `;
      }).join("");

      if (window.lucide) lucide.createIcons();
    }
  } catch (err) {
    console.debug("Community reports fetch error:", err);
  }
}

// Share Community Report Helper
window.shareCommunityReport = function(encodedUrl, encodedReason) {
  const url = decodeURIComponent(encodedUrl);
  const reason = decodeURIComponent(encodedReason);

  const advisoryText = `🚨 [PhishShield Threat Advisory]\n⚠️ Suspicious Domain: ${url}\n🔎 Threat Evidence: ${reason}\n🛡️ Audit this link safely: ${window.location.origin}/?url=${encodeURIComponent(url)}`;

  if (navigator.share) {
    navigator.share({
      title: "PhishShield Threat Intelligence Alert",
      text: advisoryText,
      url: `${window.location.origin}/?url=${encodeURIComponent(url)}`
    }).catch(() => {
      copyToClipboard(advisoryText, "Threat advisory copied to clipboard!");
    });
  } else {
    copyToClipboard(advisoryText, "Threat advisory copied to clipboard!");
  }
};

// Share Threat Advisory from Inspection Modal or Sandbox
function shareThreatAdvisory(data) {
  const advisoryText = `🚨 [PhishShield Threat Forensics]\nTarget: ${data.url}\nRisk Score: ${data.risk_score}% (${data.risk_level})\nVerdict: ${data.verdict || 'Suspicious Activity'}\nSummary: ${data.explainability_summary || 'Threat signatures detected.'}\nInspect live: ${window.location.origin}/?url=${encodeURIComponent(data.url)}`;

  if (navigator.share) {
    navigator.share({
      title: `PhishShield Security Alert: ${data.risk_level}`,
      text: advisoryText,
      url: `${window.location.origin}/?url=${encodeURIComponent(data.url)}`
    }).catch(() => {
      copyToClipboard(advisoryText, "Threat advisory copied to clipboard!");
    });
  } else {
    copyToClipboard(advisoryText, "Threat advisory copied to clipboard!");
  }
}

function copySecurityAdvisory(data) {
  const advisoryText = `🚨 [PhishShield Threat Forensics]\nTarget: ${data.url}\nRisk Score: ${data.risk_score}%\nLevel: ${data.risk_level}\nSummary: ${data.explainability_summary || 'N/A'}`;
  copyToClipboard(advisoryText, "Advisory summary copied to clipboard!");
}

function copyToClipboard(text, successMsg) {
  navigator.clipboard.writeText(text).then(() => {
    showToast(successMsg, "success");
  }).catch(() => {
    showToast("Failed to copy to clipboard", "error");
  });
}

// Helper: Sleep promise
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Execute Sandbox Audit with Guaranteed Visible Loading Animation
async function executeSandboxAudit(url, pageText = "") {
  const placeholder = document.getElementById("sandbox-placeholder");
  const loading = document.getElementById("sandbox-loading");
  const card = document.getElementById("sandbox-card");
  const submitBtn = document.getElementById("sandbox-submit-btn");

  const stepLabel = document.getElementById("scan-step-label");
  const stepPercent = document.getElementById("scan-step-percent");
  const progressFill = document.getElementById("scan-progress-fill");

  // Show loading state
  placeholder.classList.add("hidden");
  card.classList.add("hidden");
  loading.classList.remove("hidden");
  submitBtn.disabled = true;

  // Step 1: Lexical Feature Extraction (0ms)
  stepLabel.textContent = "Extracting 12 lexical & structural URL features...";
  stepPercent.textContent = "35%";
  progressFill.style.width = "35%";

  // Prepare network call
  const payload = { url: url };
  if (pageText) payload.page_text = pageText;

  const fetchPromise = fetch(`${API_BASE}/api/v1/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  }).then(async (res) => {
    if (!res.ok) throw new Error(`Engine returned HTTP ${res.status}`);
    return await res.json();
  });

  try {
    // Step 2 Animation (250ms)
    await sleep(250);
    stepLabel.textContent = "Running Tier 2 XGBoost machine learning inference...";
    stepPercent.textContent = "70%";
    progressFill.style.width = "70%";

    // Step 3 Animation (250ms)
    await sleep(250);
    stepLabel.textContent = "Evaluating contextual threat signatures & brand models...";
    stepPercent.textContent = "90%";
    progressFill.style.width = "90%";

    // Wait for the actual API call
    const data = await fetchPromise;
    latestSandboxResult = data;

    // Step 4: Finalize
    await sleep(150);
    stepPercent.textContent = "100%";
    progressFill.style.width = "100%";

    await sleep(150);
    loading.classList.add("hidden");
    renderSandboxResult(data);
    showToast(`Audit complete: ${data.risk_level} (${data.risk_score}%)`, data.risk_score > 60 ? "error" : "success");

    // Refresh telemetry immediately
    fetchTelemetry();
  } catch (err) {
    loading.classList.add("hidden");
    placeholder.classList.remove("hidden");
    showToast(`Audit failed: ${err.message}`, "error");
  } finally {
    submitBtn.disabled = false;
  }
}

// Render Sandbox Analysis Result
function renderSandboxResult(data) {
  const card = document.getElementById("sandbox-card");
  card.classList.remove("hidden");

  // Top Banner
  const badge = document.getElementById("result-badge");
  const verdict = document.getElementById("result-verdict");
  const latency = document.getElementById("result-latency");
  const scoreNum = document.getElementById("result-score-num");

  badge.textContent = data.risk_level;
  badge.className = `px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase ${getBadgeClass(data.risk_level)}`;
  verdict.textContent = data.verdict;
  latency.textContent = `in ${data.scan_latency_ms}ms`;
  scoreNum.textContent = `${data.risk_score}%`;
  scoreNum.className = `text-xl font-bold font-mono ${getScoreColor(data.risk_score)}`;

  // Multi-Engine Breakdown
  const tb = data.tier_breakdown || {
    heuristic_score: data.risk_score,
    ml_score: data.risk_score,
    ai_score: data.risk_score
  };

  document.getElementById("tier1-score-val").textContent = `${tb.heuristic_score}%`;
  document.getElementById("tier1-bar").style.width = `${tb.heuristic_score}%`;

  document.getElementById("tier2-score-val").textContent = `${tb.ml_score}%`;
  document.getElementById("tier2-bar").style.width = `${tb.ml_score}%`;

  document.getElementById("tier3-score-val").textContent = `${tb.ai_score}%`;
  document.getElementById("tier3-bar").style.width = `${tb.ai_score}%`;

  // Summary
  document.getElementById("result-summary").textContent = data.explainability_summary || "Multi-tier evaluation complete.";

  // Detected Factors
  const factorsContainer = document.getElementById("result-factors");
  if (!data.detected_factors || data.detected_factors.length === 0) {
    factorsContainer.innerHTML = `
      <div class="p-2 rounded bg-slate-900 border border-slate-700 text-emerald-400 text-xs">
        ✓ Zero active threat signatures detected. Link verified structurally safe.
      </div>
    `;
  } else {
    factorsContainer.innerHTML = data.detected_factors.map(f => {
      const fClass = getBadgeClass(f.severity);
      return `
        <div class="p-2 rounded bg-slate-900 border border-slate-700 flex items-start gap-2 text-xs">
          <span class="px-1.5 py-0.5 rounded text-[9px] font-bold font-mono shrink-0 ${fClass}">
            ${f.severity}
          </span>
          <div>
            <strong class="text-slate-200 block text-[11px] font-mono">${f.code}</strong>
            <span class="text-slate-400 text-[11px] leading-tight block font-sans">${escapeHtml(f.message)}</span>
          </div>
        </div>
      `;
    }).join("");
  }

  if (window.lucide) lucide.createIcons();
}

// Submit Threat Report
async function submitThreatReport(e) {
  e.preventDefault();
  const url = document.getElementById("report-url-input").value.trim();
  const reason = document.getElementById("report-reason-input").value.trim();
  const user = document.getElementById("report-user-input").value.trim();
  const statusMsg = document.getElementById("report-status-msg");
  const submitBtn = document.getElementById("submit-report-btn");

  submitBtn.disabled = true;
  statusMsg.classList.remove("hidden");
  statusMsg.className = "text-xs py-2 px-3 rounded bg-slate-900 text-slate-300 border border-slate-700";
  statusMsg.textContent = "Registering threat report with security database...";

  try {
    const res = await fetch(`${API_BASE}/api/v1/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: url,
        reason: reason,
        reporter_id: user || "soc-analyst"
      })
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    statusMsg.className = "text-xs py-2 px-3 rounded bg-emerald-950 text-emerald-300 border border-emerald-800";
    statusMsg.textContent = "Report successfully registered and broadcast to SOC.";
    showToast("Community threat report submitted!", "success");

    setTimeout(() => {
      document.getElementById("threat-report-form").reset();
      statusMsg.classList.add("hidden");
      document.getElementById("report-modal").classList.add("hidden");
      submitBtn.disabled = false;
      fetchTelemetry();
      fetchCommunityReports();
    }, 800);

  } catch (err) {
    statusMsg.className = "text-xs py-2 px-3 rounded bg-rose-950 text-rose-300 border border-rose-800";
    statusMsg.textContent = `Error: ${err.message}`;
    showToast("Failed to submit threat report", "error");
    submitBtn.disabled = false;
  }
}

// Toast Notification Utility
function showToast(message, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = "ps-toast";

  let icon = "ℹ️";
  if (type === "success") {
    icon = "✓";
    toast.style.borderLeft = "3px solid #34d399";
  } else if (type === "error") {
    icon = "⚠️";
    toast.style.borderLeft = "3px solid #f87171";
  } else {
    toast.style.borderLeft = "3px solid #3b82f6";
  }

  toast.innerHTML = `
    <span style="font-weight: bold;">${icon}</span>
    <span>${escapeHtml(message)}</span>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add("hiding");
    setTimeout(() => toast.remove(), 250);
  }, 3500);
}

// Status Badge Styling Helper
function getBadgeClass(level) {
  switch (level) {
    case "SAFE": return "badge-safe";
    case "LOW":
    case "MEDIUM": return "badge-medium";
    case "HIGH":
    case "CRITICAL": return "badge-critical";
    default: return "badge-safe";
  }
}

function getScoreColor(score) {
  if (score >= 70) return "text-rose-400";
  if (score >= 40) return "text-amber-400";
  return "text-emerald-400";
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
