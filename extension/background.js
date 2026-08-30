/**
 * PhishShield AI - Service Worker (Manifest V3)
 * Handles context menu actions, backend communication, tab messaging, and badge updates.
 */

const DEFAULT_API_URL = "http://localhost:8000";

// Initialize Context Menus and Storage on Installation
chrome.runtime.onInstalled.addListener(async () => {
  chrome.contextMenus.create({
    id: "phishshield-scan-link",
    title: "🛡️ Scan link with PhishShield AI",
    contexts: ["link", "selection", "page"]
  });

  const config = await chrome.storage.local.get(["apiUrl", "scanHistory", "aiEnabled"]);
  if (!config.apiUrl) {
    await chrome.storage.local.set({
      apiUrl: DEFAULT_API_URL,
      scanHistory: [],
      aiEnabled: true,
      autoScanSuspicious: true
    });
  }
  console.log("PhishShield AI Service Worker initialized.");
});

// Context Menu Click Listener
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== "phishshield-scan-link") return;

  let targetUrl = info.linkUrl || (info.selectionText ? info.selectionText.trim() : "") || info.pageUrl || tab?.url;
  if (!targetUrl) return;

  // Basic normalization
  if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
    targetUrl = "https://" + targetUrl;
  }

  // Visual feedback: Update badge to indicate scanning
  await setScanningBadge(tab?.id);

  try {
    const result = await scanUrlWithBackend(targetUrl);
    await updateBadgeForResult(tab?.id, result);
    await saveScanToHistory(result);

    // Forward result to content script to display on-page warning modal
    if (tab && tab.id) {
      try {
        await chrome.tabs.sendMessage(tab.id, {
          type: "SHOW_SCAN_RESULT",
          data: result
        });
      } catch (err) {
        // If content script was not ready in this tab, inject dynamically
        try {
          await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            files: ["content.js"]
          });
          await chrome.scripting.insertCSS({
            target: { tabId: tab.id },
            files: ["styles.css"]
          });
          await chrome.tabs.sendMessage(tab.id, {
            type: "SHOW_SCAN_RESULT",
            data: result
          });
        } catch (injectErr) {
          console.warn("Could not inject content script on restricted tab:", injectErr);
        }
      }
    }
  } catch (error) {
    console.error("Context menu scan failed:", error);
    await setBadgeError(tab?.id);
  }
});

// Runtime Message Listener (for Popup and Content Scripts)
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SCAN_URL") {
    (async () => {
      try {
        const result = await scanUrlWithBackend(message.url, message.pageText);
        await saveScanToHistory(result);
        if (sender.tab && sender.tab.id) {
          await updateBadgeForResult(sender.tab.id, result);
        }
        sendResponse({ success: true, data: result });
      } catch (err) {
        sendResponse({ success: false, error: err.message || "Failed to scan link" });
      }
    })();
    return true; // Keep message channel open for async response
  }

  if (message.type === "PING_BACKEND") {
    (async () => {
      try {
        const { apiUrl = DEFAULT_API_URL } = await chrome.storage.local.get("apiUrl");
        const response = await fetch(`${apiUrl}/health`, { method: "GET" });
        if (response.ok) {
          const data = await response.json();
          sendResponse({ success: true, status: data });
        } else {
          sendResponse({ success: false, error: `HTTP ${response.status}` });
        }
      } catch (err) {
        sendResponse({ success: false, error: err.message || "Engine unreachable" });
      }
    })();
    return true;
  }

  if (message.type === "GET_PAGE_INFO") {
    (async () => {
      try {
        const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!activeTab) {
          sendResponse({ success: false, error: "No active tab" });
          return;
        }
        sendResponse({ success: true, tab: activeTab });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }
});

/**
 * Execute HTTP POST scan against FastAPI security backend
 */
async function scanUrlWithBackend(url, pageText = null) {
  const { apiUrl = DEFAULT_API_URL } = await chrome.storage.local.get("apiUrl");
  const endpoint = `${apiUrl}/api/v1/scan`;

  const payload = {
    url: url,
    page_text: pageText || null
  };

  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Engine returned ${response.status}: ${errorBody}`);
  }

  return await response.json();
}

/**
 * Save scan result to Chrome storage history
 */
async function saveScanToHistory(result) {
  try {
    const { scanHistory = [] } = await chrome.storage.local.get("scanHistory");
    const newEntry = {
      ...result,
      timestamp: Date.now()
    };
    // Keep last 30 scans
    const updated = [newEntry, ...scanHistory.filter(item => item.url !== result.url)].slice(0, 30);
    await chrome.storage.local.set({ scanHistory: updated });
  } catch (e) {
    console.warn("Failed to persist scan history:", e);
  }
}

/**
 * UI Badge helpers
 */
async function setScanningBadge(tabId) {
  if (!tabId) return;
  await chrome.action.setBadgeText({ tabId, text: "SCAN" });
  await chrome.action.setBadgeBackgroundColor({ tabId, color: "#6366f1" });
}

async function setBadgeError(tabId) {
  if (!tabId) return;
  await chrome.action.setBadgeText({ tabId, text: "ERR" });
  await chrome.action.setBadgeBackgroundColor({ tabId, color: "#9ca3af" });
}

async function updateBadgeForResult(tabId, result) {
  if (!tabId || !result) return;
  const level = result.risk_level;
  let text = "SAFE";
  let color = "#10b981"; // Green

  if (level === "CRITICAL") {
    text = "CRIT";
    color = "#dc2626"; // Crimson Red
  } else if (level === "HIGH") {
    text = "HIGH";
    color = "#ef4444"; // Red
  } else if (level === "MEDIUM") {
    text = "WARN";
    color = "#f59e0b"; // Amber
  } else if (level === "LOW") {
    text = "LOW";
    color = "#3b82f6"; // Blue
  }

  await chrome.action.setBadgeText({ tabId, text });
  await chrome.action.setBadgeBackgroundColor({ tabId, color });
}
