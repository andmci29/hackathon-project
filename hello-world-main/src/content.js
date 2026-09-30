import * as InboxSDK from '@inboxsdk/core';
import { scanEmailLinks } from './linkScanner.js';


// --- Flagged-thread tracking -------------------------------------------

let flaggedThreadIds = new Set();

chrome.storage.local.get('flaggedThreadIds', (result) => {
  flaggedThreadIds = new Set(result.flaggedThreadIds || []);
});


const threadSenders = new Map();


// Preliminary check using sender + subject
function isFlagged(threadID, subject = "") {
  const sender = threadSenders.get(threadID);

  const senderName = sender?.name || "";
  const senderEmail = sender?.emailAddress || "";

  const text = `${senderName} ${senderEmail} ${subject}`.toLowerCase();

  let score = 0;

  const suspiciousWords = [
    "urgent",
    "immediately",
    "action required",
    "verify",
    "verification",
    "confirm",
    "account",
    "password",
    "security",
    "suspended",
    "locked",
    "unusual activity",
    "suspicious activity",
    "unauthorized activity",
    "payment",
    "billing",
    "invoice",
    "refund",
    "winner",
    "prize",
    "claim",
    "login",
    "sign in",
    "reset",
    "credit card"
  ];

  for (const word of suspiciousWords) {
    if (text.includes(word)) {
      score++;
    }
  }

  if (
    text.includes("account suspended") ||
    text.includes("account locked") ||
    text.includes("verify your account") ||
    text.includes("urgent action required")
  ) {
    score += 2;
  }

  return score >= 2;
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

  // -----------------------------------------------------------------------
  // nifty button
  // -----------------------------------------------------------------------

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


  // -----------------------------------------------------------------------
  // Reading message bodies + remembering sender information
  // -----------------------------------------------------------------------

  sdk.Conversations.registerMessageViewHandler((messageView) => {

    const bodyE = messageView.getBodyElement();

    if (bodyE) {
      console.log("email content: ", bodyE.innerText);
    }

    // Remember the sender for this thread
    const sender = messageView.getSender();
    const threadView = messageView.getThreadView();

    threadView.getThreadIDAsync().then((threadID) => {

      threadSenders.set(threadID, sender);

      console.log("Sender:", sender);

      const subject = threadView.getSubject();

      if (isFlagged(threadID, subject)) {
        setFlagged(threadID, true);

        console.log(
          "Email preliminarily flagged:",
          subject,
          sender
        );
      }
    });
  });


  // -----------------------------------------------------------------------
  // Mark rows in the email list
  // -----------------------------------------------------------------------

  sdk.Lists.registerThreadRowViewHandler((threadRowView) => {
    const threadID = threadRowView.getThreadID();
    const subject = threadRowView.getSubject();

    if (isFlagged(threadID, subject)) {

      threadRowView.addLabel({
        title: "Flagged",
        backgroundColor: "#fbbc04",
        foregroundColor: "#202124",
      });

      console.log(
        "Preliminary flag:",
        subject,
        threadSenders.get(threadID)
      );
    }
  });


  // -----------------------------------------------------------------------
  // Show banner + Scan Links button for ALL emails
  // -----------------------------------------------------------------------

  sdk.Conversations.registerThreadViewHandler((threadView) => {

    threadView.getThreadIDAsync().then((threadID) => {

      const isThreadFlagged = flaggedThreadIds.has(threadID);

      // Create Scan Links button
      const scanButton = document.createElement("button");
      scanButton.textContent = "Scan Links";
      scanButton.style.marginLeft = "10px";
      scanButton.style.padding = "4px 10px";
      scanButton.style.cursor = "pointer";

      const report = document.createElement("div");
      report.style.marginTop = "6px";
      report.style.fontSize = "13px";

      // Shared scan logic
      scanButton.addEventListener("click", async () => {

        const messageViews = threadView.getMessageViews();

        if (!messageViews || messageViews.length === 0) {
          console.log("No message view found.");
          report.textContent = "Unable to find the email message.";
          return;
        }

        const messageView =
          messageViews[messageViews.length - 1];

        report.textContent = "Scanning links...";

        const results =
          await scanEmailLinks(messageView);

        if (!results) {
          report.textContent =
            "Unable to scan this message.";
          return;
        }

        const totalLinks = results.length;
        const suspiciousLinks =
          results.filter(result => result.suspicious).length;

        const safeLinks =
          totalLinks - suspiciousLinks;

        report.innerHTML = "";

        const summary =
          document.createElement("div");

        if (totalLinks === 0) {

          summary.textContent =
            "No links found.";

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

          if (!result.suspicious) {
            continue;
          }

          const item =
            document.createElement("div");

          item.style.marginTop = "4px";
          item.style.fontSize = "12px";

          item.textContent =
            `⚠ ${result.hostname || result.url} — ` +
            result.reasons.join(", ");

          report.appendChild(item);
        }
      });

      // --------------------------------------------------
      // Placement logic
      // --------------------------------------------------

      if (isThreadFlagged) {
        // Existing flagged banner
        const notice = threadView.addNoticeBar();
        notice.el.textContent =
          "You clicked on a flagged email.";

        notice.el.appendChild(scanButton);
        notice.el.appendChild(report);

      } else {
        // New placement for non-flagged emails
        const notice = threadView.addNoticeBar();
        notice.el.textContent = "Link tools:";

        notice.el.appendChild(scanButton);
        notice.el.appendChild(report);
      }

    });
  });

});
