import * as InboxSDK from '@inboxsdk/core';
import { scanEmailContent } from './linkScanner.js';

(function loadCustomFont() {
  if (!document.getElementById('alan-sans-font')) {
    const link = document.createElement('link');
    link.id = 'alan-sans-font';
    link.rel = 'stylesheet';
    link.href = 'https://fonts.googleapis.com/css2?family=Alan+Sans:wght@400;700&display=swap';
    document.head.appendChild(link);
  }
})();

// --- State Tracking ----------------------------------------------------

let flaggedThreadIds = new Set();
let checkedMessagesThreadIds = new Set();
let superFlaggedThreadIds = new Set();
let safeThreadIds = new Set();

const SUSPICIOUS_WORDS = [
  "urgent", "immediately", "action required", "verify", "verification",
  "confirm", "account", "password", "security", "suspended", "locked",
  "unusual activity", "suspicious activity", "unauthorized activity",
  "payment", "billing", "invoice", "refund", "winner", "prize",
  "claim", "login", "sign in", "reset", "credit card", "gift card", "wire transfer",
  "social security", "ssn", "million dollars", "prince", "hurry", "phone number", "social security", "personal information",
  "free money", "limited time", "risk", "threat", "danger", "alert", "warning",
  "click here", "download"

];

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

function saveStorage() {
  chrome.storage.local.set({
    flaggedThreadIds: [...flaggedThreadIds],
    checkedMessagesThreadIds: [...checkedMessagesThreadIds],
    superFlaggedThreadIds: [...superFlaggedThreadIds],
    safeThreadIds: [...safeThreadIds]
  });
}

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

      if (safeThreadIds.has(threadID)) return;

      const subject = threadRowView.getSubject() || "";
      const senders = threadRowView.getContacts().map(c => `${c.name} ${c.emailAddress}`).join(" ");
      const score = calculateSuspiciousScore(`${senders} ${subject}`);

      if (superFlaggedThreadIds.has(threadID)) {
        threadRowView.addLabel({
          title: "UNSAFE",
          backgroundColor: "#d93025",
          foregroundColor: "#ffffff",
        });
      } else if (!checkedMessagesThreadIds.has(threadID) && (flaggedThreadIds.has(threadID) || score >= 2)) {
        threadRowView.addLabel({
          title: "CAUTION",
          backgroundColor: "#fbbc04",
          foregroundColor: "#202124",
        });
      }
    });

    // 3. Inject Control Panel on Email Threads
    sdk.Conversations.registerThreadViewHandler((threadView) => {
      threadView.getThreadIDAsync().then((threadID) => {

        function renderSecurityPanel() {
          const isThreat = superFlaggedThreadIds.has(threadID);
          const isFlagged = flaggedThreadIds.has(threadID);
          const isSafe = safeThreadIds.has(threadID);

          const notice = threadView.addNoticeBar();
          const container = notice.el;
          container.style.cssText = "display: flex; flex-direction: column; gap: 8px; padding: 12px 16px; border-radius: 2px; margin-bottom: 12px; font-family: 'Alan Sans', Arial, sans-serif;";

          const topRow = document.createElement("div");
          topRow.style.cssText = "display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px;";

          const statusText = document.createElement("span");
          statusText.style.cssText = "font-size: 16px; font-weight: bold;";

          const buttonGroup = document.createElement("div");
          buttonGroup.style.cssText = "display: flex; gap: 8px; align-items: center;";

          const reportArea = document.createElement("div");
          reportArea.style.cssText = "font-size: 14px; line-height: 1.5; margin-top: 4px; font-family: 'Alan Sans', Arial, sans-serif;";

          // Persistent warning text rendering based on state
          if (isThreat) {
            statusText.innerHTML = "<strong>DANGER: Do Not Trust This Email!</strong>";
            textSpan.innerHTML = "<strong> Malicious Threat Detected:</strong> Exercise extreme caution with links or attachments.";
            container.style.backgroundColor = "#fce8e6";
            container.style.color = "#a50e0e";
            container.style.border = "2px solid #d93025";
            reportArea.style.color = "#a50e0e";
            reportArea.innerHTML = "<div>Please <strong>do not click any links</strong>, open any attachments, or reply with credit card numbers, gift cards, or personal information.</div>";
          } else if (isFlagged) {
            statusText.innerHTML = "<strong>CAUTION: This Email Looks Suspicious</strong>";
            textSpan.innerHTML = "<strong> Suspicious Email:</strong> Preliminary analysis detected unusual patterns.";
            container.style.backgroundColor = "#fef7e0";
            container.style.color = "#8c4a00";
            container.style.border = "2px solid #fbbc04";
            reportArea.style.color = "#8c4a00";
            reportArea.innerHTML = "<div>Please be careful. We advise you to <strong>scan the email before proceeding</strong></div>";
          } else if (isSafe) {
            statusText.innerHTML = "<strong>SAFE: This Email Is Clear to Read</strong>";
            container.style.backgroundColor = "#e6f4ea";
            container.style.color = "#137333";
            container.style.border = "2px solid #1e8e3e";
          } else {
            statusText.innerHTML = "<strong>Security Controls: </strong>";
            container.style.backgroundColor = "#f1f3f4";
            container.style.color = "#202124";
            container.style.border = "2px solid #dadce0";
          }

          // --- Buttons ---
          const scanBtn = createButton("Check This Email", "#1a73e8", "#ffffff", async () => {
            reportArea.style.color = "#202124";
            reportArea.innerHTML = "<strong>Checking this email for safety... Please wait.</strong>";

            const messageViews = threadView.getMessageViews();
            if (!messageViews.length) return;

            const report = await scanEmailContent(messageViews[messageViews.length - 1], true);
            checkedMessagesThreadIds.add(threadID);

            if (!report) {
              reportArea.textContent = "Unable to check this email right now.";
              return;
            }

            if (report.suspicious) {
              markThreadAsThreat(threadID);
            } else {
              markThreadAsSafe(threadID);
            }

            setTimeout(() => {
              notice.destroy();
              renderSecurityPanel();
            }, 800);
          });

          const safeBtn = createButton("Mark as Safe", "#1e8e3e", "#ffffff", () => {
            markThreadAsSafe(threadID);
            notice.destroy();
            renderSecurityPanel();
          });

          const threatBtn = createButton("Mark as Unsafe", "#d93025", "#ffffff", () => {
            markThreadAsThreat(threadID);
            notice.destroy();
            renderSecurityPanel();
          });

          const resetBtn = createButton("Start Over", "#5f6368", "#ffffff", () => {
            clearThreadOverrides(threadID);
            notice.destroy();
            renderSecurityPanel();
          });

          buttonGroup.appendChild(scanBtn);
          buttonGroup.appendChild(safeBtn);
          buttonGroup.appendChild(threatBtn);
          if (isSafe || isThreat) {
            buttonGroup.appendChild(resetBtn);
          }

          topRow.appendChild(statusText);
          topRow.appendChild(buttonGroup);
          container.appendChild(topRow);
          container.appendChild(reportArea);
        }

        renderSecurityPanel();
      });
    });
  });
}

function createButton(label, bgColor, textColor, onClickHandler) {
  const btn = document.createElement("button");
  btn.textContent = label;
  btn.style.cssText = `
    background-color: ${bgColor};
    color: ${textColor};
    border: none;
    padding: 7px 14px;
    font-size: 13px;
    font-weight: bold;
    border-radius: 2px;
    font-family: 'Alan Sans', Arial, sans-serif;
    cursor: pointer;
    box-shadow: 0 1px 2px rgba(0,0,0,0.12);
    transition: background-color 0.2s;
  `;
  btn.onmouseover = () => btn.style.opacity = "0.9";
  btn.onmouseout = () => btn.style.opacity = "1.0";
  btn.addEventListener("click", onClickHandler);
  return btn;
}

init();