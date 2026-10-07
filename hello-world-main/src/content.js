import * as InboxSDK from '@inboxsdk/core';
import { scanEmailLinks } from './linkScanner.js';

// --- State Tracking ----------------------------------------------------

let flaggedThreadIds = new Set();
let checkedMessagesThreadIds = new Set();
let superFlaggedThreadIds = new Set();
let safeThreadIds = new Set(); // User-whitelisted threads

const SUSPICIOUS_WORDS = [
  "urgent", "immediately", "action required", "verify", "verification",
  "confirm", "account", "password", "security", "suspended", "locked",
  "unusual activity", "suspicious activity", "unauthorized activity",
  "payment", "billing", "invoice", "refund", "winner", "prize",
  "claim", "login", "sign in", "reset", "credit card"
];

// Load persisted state from storage
function loadStorage() {
  return new Promise((resolve) => {
    chrome.storage.local.get(
      ['flaggedThreadIds', 'checkedMessagesThreadIds', 'superFlaggedThreadIds', 'safeThreadIds'],
      (result) => {
        flaggedThreadIds = new Set(result.flaggedThreadIds || []);
        checkedMessagesThreadIds = new Set(result.checkedMessagesThreadIds || []);
        superFlaggedThreadIds = new Set(result.superFlaggedThreadIds || []);
        safeThreadIds = new Set(result.safeThreadIds || []);
        resolve();
      }
    );
  });
}

// Persist all sets to storage
function saveStorage() {
  chrome.storage.local.set({
    flaggedThreadIds: [...flaggedThreadIds],
    checkedMessagesThreadIds: [...checkedMessagesThreadIds],
    superFlaggedThreadIds: [...superFlaggedThreadIds],
    safeThreadIds: [...safeThreadIds]
  });
}

// Heuristic calculation
function calculateSuspiciousScore(text) {
  let score = 0;
  const lowerText = text.toLowerCase();

  for (const word of SUSPICIOUS_WORDS) {
    if (lowerText.includes(word)) score++;
  }

  if (
    lowerText.includes("account suspended") ||
    lowerText.includes("account locked") ||
    lowerText.includes("verify your account") ||
    lowerText.includes("urgent action required")
  ) {
    score += 2;
  }

  return score;
}

// --- Action Handlers ----------------------------------------------------

function markThreadAsSafe(threadID) {
  safeThreadIds.add(threadID);
  flaggedThreadIds.delete(threadID);
  superFlaggedThreadIds.delete(threadID);
  saveStorage();
}

function markThreadAsThreat(threadID) {
  superFlaggedThreadIds.add(threadID);
  flaggedThreadIds.delete(threadID);
  safeThreadIds.delete(threadID);
  saveStorage();
}

function clearThreadOverrides(threadID) {
  safeThreadIds.delete(threadID);
  superFlaggedThreadIds.delete(threadID);
  flaggedThreadIds.delete(threadID);
  saveStorage();
}

// --- SDK Initialization --------------------------------------------------

async function init() {
  await loadStorage();

  InboxSDK.load(2, 'sdk_respass_7ca4c6c1ed').then((sdk) => {

    // 1. Process individual incoming message views
    sdk.Conversations.registerMessageViewHandler((messageView) => {
      const sender = messageView.getSender();
      const threadView = messageView.getThreadView();

      threadView.getThreadIDAsync().then((threadID) => {
        // Skip heuristic scoring if user manually marked as safe or threat
        if (safeThreadIds.has(threadID) || superFlaggedThreadIds.has(threadID)) return;

        const subject = threadView.getSubject() || "";
        const senderText = `${sender?.name || ''} ${sender?.emailAddress || ''}`;
        const score = calculateSuspiciousScore(`${senderText} ${subject}`);

        if (score >= 2) {
          flaggedThreadIds.add(threadID);
          saveStorage();
        }
      });
    });

    // 2. Add badges to thread list rows
    sdk.Lists.registerThreadRowViewHandler((threadRowView) => {
      const threadID = threadRowView.getThreadID();

      // Explicitly marked safe by user -> No label
      if (safeThreadIds.has(threadID)) return;

      const subject = threadRowView.getSubject() || "";
      const senders = threadRowView.getContacts().map(c => `${c.name} ${c.emailAddress}`).join(" ");
      const score = calculateSuspiciousScore(`${senders} ${subject}`);

      if (superFlaggedThreadIds.has(threadID)) {
        threadRowView.addLabel({
          title: "Threat",
          backgroundColor: "#d93025",
          foregroundColor: "#ffffff",
        });
      } else if (!checkedMessagesThreadIds.has(threadID) && (flaggedThreadIds.has(threadID) || score >= 2)) {
        threadRowView.addLabel({
          title: "Flagged",
          backgroundColor: "#fbbc04",
          foregroundColor: "#202124",
        });
      }
    });

    // 3. Inject control panel banner and toolbar controls inside email view
    sdk.Conversations.registerThreadViewHandler((threadView) => {
      threadView.getThreadIDAsync().then((threadID) => {

        // Render Notice Banner with Controls
        function renderBanner() {
          const isThreat = superFlaggedThreadIds.has(threadID);
          const isFlagged = flaggedThreadIds.has(threadID);
          const isSafe = safeThreadIds.has(threadID);

          // Only show banner if there is a security flag or explicit safety confirmation
          if (!isThreat && !isFlagged && !isSafe) return;

          const notice = threadView.addNoticeBar();
          const container = notice.el;
          container.style.cssText = "display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; padding: 6px 12px;";

          const textSpan = document.createElement("span");
          const buttonGroup = document.createElement("div");
          buttonGroup.style.cssText = "display: flex; gap: 6px; align-items: center;";

          if (isThreat) {
            textSpan.innerHTML = "<strong>⚠ Malicious Threat Detected:</strong> Exercise extreme caution with links or attachments.";
            container.style.backgroundColor = "#fce8e6";
            container.style.color = "#a50e0e";
          } else if (isFlagged) {
            textSpan.innerHTML = "<strong>⚡ Suspicious Email:</strong> Preliminary analysis detected unusual patterns.";
            container.style.backgroundColor = "#fef7e0";
            container.style.color = "#b06000";
          } else if (isSafe) {
            textSpan.innerHTML = "<strong>✓ Verified Safe:</strong> Marked as trusted by user.";
            container.style.backgroundColor = "#e6f4ea";
            container.style.color = "#137333";
          }

          // Scan Button
          const scanBtn = createButton("Scan Links", "#1a73e8", "#ffffff", async () => {
            reportArea.textContent = "Scanning links...";
            const messageViews = threadView.getMessageViews();
            if (!messageViews.length) return;

            const results = await scanEmailLinks(messageViews[messageViews.length - 1], true);
            checkedMessagesThreadIds.add(threadID);

            if (!results || results.length === 0) {
              reportArea.textContent = "No links detected.";
              return;
            }

            const suspicious = results.filter(r => r.suspicious);
            if (suspicious.length > 0) {
              markThreadAsThreat(threadID);
              reportArea.textContent = `Found ${suspicious.length} suspicious link(s). Thread updated to Threat.`;
            } else {
              reportArea.textContent = `Scan complete: ${results.length} link(s) verified safe.`;
            }
            saveStorage();
          });

          // Mark Safe Button
          const safeBtn = createButton("Mark as Safe", "#1e8e3e", "#ffffff", () => {
            markThreadAsSafe(threadID);
            notice.destroy();
            renderBanner();
          });

          // Flag Threat Button
          const threatBtn = createButton("Flag Threat", "#d93025", "#ffffff", () => {
            markThreadAsThreat(threadID);
            notice.destroy();
            renderBanner();
          });

          // Reset Override Button (shown if user manually changed state)
          if (isSafe) {
            const resetBtn = createButton("Reset Status", "#5f6368", "#ffffff", () => {
              clearThreadOverrides(threadID);
              notice.destroy();
              renderBanner();
            });
            buttonGroup.appendChild(resetBtn);
          } else {
            buttonGroup.appendChild(scanBtn);
            buttonGroup.appendChild(safeBtn);
            buttonGroup.appendChild(threatBtn);
          }

          const reportArea = document.createElement("div");
          reportArea.style.cssText = "width: 100%; font-size: 12px; margin-top: 4px;";

          container.appendChild(textSpan);
          container.appendChild(buttonGroup);
          container.appendChild(reportArea);
        }

        // Add Quick Action Button to standard Gmail Toolbar
        threadView.addToolbarButton({
          title: "Security Options",
          iconUrl: "https://fonts.gstatic.com/s/i/short-term/release/googlesymbols/shield/default/24px.svg",
          onClick() {
            if (safeThreadIds.has(threadID)) {
              markThreadAsThreat(threadID);
            } else {
              markThreadAsSafe(threadID);
            }
          }
        });

        renderBanner();
      });
    });
  });
}

// Helper to create styled action buttons
function createButton(label, bgColor, textColor, onClickHandler) {
  const btn = document.createElement("button");
  btn.textContent = label;
  btn.style.cssText = `
    background-color: ${bgColor};
    color: ${textColor};
    border: none;
    padding: 4px 10px;
    font-size: 12px;
    font-weight: 500;
    border-radius: 4px;
    cursor: pointer;
    transition: opacity 0.2s;
  `;
  btn.onmouseover = () => btn.style.opacity = "0.85";
  btn.onmouseout = () => btn.style.opacity = "1.0";
  btn.addEventListener("click", onClickHandler);
  return btn;
}

init();