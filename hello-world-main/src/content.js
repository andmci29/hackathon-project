import * as InboxSDK from '@inboxsdk/core';
import { scanEmailLinks } from './linkScanner.js';

// --- Flagged-thread tracking -------------------------------------------
// A small persisted set of thread IDs your extension considers "flagged".
// chrome.storage.local so it survives reloads and is shared across views.
let flaggedThreadIds = new Set();

chrome.storage.local.get('flaggedThreadIds', (result) => {
  flaggedThreadIds = new Set(result.flaggedThreadIds || []);
});

function isFlagged(threadID) {
  return true;
}

function setFlagged(threadID, flagged) {
  if (flagged) {
    flaggedThreadIds.add(threadID);
  } else {
    flaggedThreadIds.delete(threadID);
  }

  chrome.storage.local.set({
    flaggedThreadIds: [...flaggedThreadIds]
  });
}

// -------------------------------------------------------------------------


InboxSDK.load(2, 'sdk_respass_7ca4c6c1ed').then((sdk) => {

  // Compose button
  sdk.Compose.registerComposeViewHandler((composeView) => {
    composeView.addButton({
      title: "My Nifty Button!",
      iconUrl:
        "https://lh5.googleusercontent.com/itq66nh65lfCick8cJ-OPuqZ8OUDTIxjCc25dkc4WUT1JG8XG3z6-eboCu63_uDXSqMnLRdlvQ=s128-h128-e365",

      onClick(event) {
        event.composeView.insertTextIntoBodyAtCursor("nifty!!!!");
      },
    });
  });


  // Reading message bodies
  sdk.Conversations.registerMessageViewHandler((messageView) => {
    const bodyE = messageView.getBodyElement();
    console.log("email content: ", bodyE.innerText);
  });


  // Mark rows in the email list
  sdk.Lists.registerThreadRowViewHandler((threadRowView) => {
    const threadID = threadRowView.getThreadID();

    if (isFlagged(threadID)) {
      threadRowView.addLabel({
        title: "Flagged",
        backgroundColor: "#fbbc04",
        foregroundColor: "#202124",
      });
    }
  });


  // Show a banner near the top when a flagged thread is opened
  sdk.Conversations.registerThreadViewHandler((threadView) => {
    threadView.getThreadIDAsync().then((threadID) => {
      if (!isFlagged(threadID)) return;

      const notice = threadView.addNoticeBar();

      notice.el.textContent = "You clicked on a flagged email.";

      const scanButton = document.createElement("button");
      scanButton.textContent = "Scan Links";
      scanButton.style.marginLeft = "10px";
      scanButton.style.padding = "4px 10px";
      scanButton.style.cursor = "pointer";

      // Area where the scan results will appear
      const report = document.createElement("div");
      report.style.marginTop = "6px";
      report.style.fontSize = "13px";

      scanButton.addEventListener("click", async () => {
        const messageViews = threadView.getMessageViews();

        if (!messageViews || messageViews.length === 0) {
          console.log("No message view found.");
          return;
        }

        const messageView = messageViews[messageViews.length - 1];

        // Show scanning status
        report.textContent = "Scanning links...";

        const results = await scanEmailLinks(messageView);

        if (!results) {
          report.textContent = "Unable to scan this message.";
          return;
        }

        const totalLinks = results.length;
        const suspiciousLinks = results.filter(
          result => result.suspicious
        ).length;
        const safeLinks = totalLinks - suspiciousLinks;

        // Clear previous report
        report.innerHTML = "";

        const summary = document.createElement("div");

        if (totalLinks === 0) {
          summary.textContent = "No links found.";
        } else if (suspiciousLinks === 0) {
          summary.textContent =
            `Scan complete: ${totalLinks} link${totalLinks === 1 ? "" : "s"} found. ` +
            `No suspicious links detected.`;
        } else {
          summary.textContent =
            `Scan complete: ${totalLinks} link${totalLinks === 1 ? "" : "s"} found. ` +
            `${suspiciousLinks} suspicious, ${safeLinks} normal.`;
        }

        report.appendChild(summary);

        // Show suspicious link details
        for (const result of results) {
          if (!result.suspicious) continue;

          const item = document.createElement("div");
          item.style.marginTop = "4px";
          item.style.fontSize = "12px";

          item.textContent =
            `⚠ ${result.hostname || result.url} — ` +
            result.reasons.join(", ");

          report.appendChild(item);
        }
      });

      notice.el.appendChild(scanButton);
      notice.el.appendChild(report);
    });
  });

});