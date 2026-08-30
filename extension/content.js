/**
 * PhishShield AI — Enterprise In-Page Interception Script
 * Injects top-anchored, high-trust security warning banners on detected malicious sites.
 */

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SHOW_SCAN_RESULT") {
    displaySecurityBanner(message.data);
    sendResponse({ success: true });
    return true;
  }

  if (message.type === "EXTRACT_PAGE_CONTENT") {
    const pageText = document.body ? document.body.innerText.slice(0, 3000) : "";
    sendResponse({ success: true, pageText: pageText, title: document.title, url: window.location.href });
    return true;
  }
});

/**
 * Injects top-anchored enterprise security alert banner
 */
function displaySecurityBanner(data) {
  if (!data) return;

  const { url, risk_score, risk_level, verdict, explainability_summary } = data;

  // Only trigger full-width warning banner for high/critical risks or explicit user inspection
  const isHighRisk = risk_level === "HIGH" || risk_level === "CRITICAL";

  // Remove any existing banner
  const existing = document.getElementById("phishshield-intercept-banner");
  if (existing) {
    existing.remove();
  }

  const banner = document.createElement("div");
  banner.id = "phishshield-intercept-banner";

  if (!isHighRisk) {
    // Subtle info banner for Safe / Moderate
    banner.style.backgroundColor = "#0f172a";
    banner.style.borderBottom = "1px solid #334155";
  }

  banner.innerHTML = `
    <div class="ps-banner-info">
      <div class="ps-banner-icon">
        ${isHighRisk ? '🛡️' : 'ℹ️'}
      </div>
      <div class="ps-banner-text-group">
        <div class="ps-banner-headline">
          [!] PhishShield Intercepted a Suspicious Domain (${escapeHtml(verdict)} &bull; Risk: ${risk_score}%)
        </div>
        <div class="ps-banner-explanation">
          ${escapeHtml(explainability_summary || 'This web destination exhibits characteristics commonly associated with credential theft or brand mimicry.')}
        </div>
      </div>
    </div>

    <div class="ps-banner-actions">
      <button class="ps-banner-btn-safety" id="ps-banner-go-back">
        Go Back to Safety
      </button>
      <button class="ps-banner-btn-proceed" id="ps-banner-proceed">
        I Trust This Site (Proceed)
      </button>
    </div>
  `;

  document.documentElement.appendChild(banner);

  // Bind Actions
  banner.querySelector("#ps-banner-go-back")?.addEventListener("click", () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = "about:blank";
    }
  });

  banner.querySelector("#ps-banner-proceed")?.addEventListener("click", () => {
    banner.style.transition = "transform 0.2s ease, opacity 0.2s ease";
    banner.style.transform = "translateY(-100%)";
    banner.style.opacity = "0";
    setTimeout(() => banner.remove(), 250);
  });
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
