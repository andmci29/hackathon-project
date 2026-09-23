import * as InboxSDK from '@inboxsdk/core';

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
  chrome.storage.local.set({ flaggedThreadIds: [...flaggedThreadIds] });
}
// -------------------------------------------------------------------------

InboxSDK.load(2, 'sdk_respass_7ca4c6c1ed').then((sdk) => {
  // Compose button (your existing code)
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

  // Reading message bodies (your existing code)
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

  // NEW: show a banner near the top when a flagged thread is opened
  sdk.Conversations.registerThreadViewHandler((threadView) => {
    threadView.getThreadIDAsync().then((threadID) => {
      if (!isFlagged(threadID)) return;

      const notice = threadView.addNoticeBar();
      notice.el.textContent = "You clicked on a flagged email.";
      // addNoticeBar defaults to a yellow background already, but you can override:
      // notice.el.style.backgroundColor = '#fbbc04';
    });
  });
  const checkedMessages = new Set();

  sdk.Conversations.registerMessageViewHandler(messageView => {

    messageView.on('load', async () => {

      let messageId;

      try {
        messageId = await messageView.getMessageIDAsync();
      } catch {
        return;
      }

      // Only check each message once
      if (checkedMessages.has(messageId)) {
        return;
      }

      checkedMessages.add(messageId);

      const links = messageView.getLinksInBody();

      if (!links || links.length === 0) {
        console.log("No links found.");
        return;
      }

      const results = [];

      for (const link of links) {

        if (link.isInQuotedArea) {
          continue;
        }

        const rawUrl = link.href;
        const text = (link.text || "").trim();

        if (!rawUrl) {
          continue;
        }

        const reasons = [];

        let url;

        try {
          url = new URL(rawUrl);
        } catch {
          reasons.push("Invalid URL");
          results.push({
            url: rawUrl,
            text,
            suspicious: true,
            reasons
          });
          continue;
        }

        const hostname = url.hostname.toLowerCase();
        const fullUrl = url.href.toLowerCase();

        // --------------------------------------------------
        // 1. Dangerous protocols
        // --------------------------------------------------

        if (!["http:", "https:"].includes(url.protocol)) {
          reasons.push("Non-HTTP/HTTPS protocol");
        }

        // --------------------------------------------------
        // 2. Username/password hidden inside URL
        // --------------------------------------------------

        if (url.username || url.password) {
          reasons.push("URL contains user information before @");
        }

        // --------------------------------------------------
        // 3. Raw IP address
        // --------------------------------------------------

        if (
          /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname) ||
          hostname.includes(":")
        ) {
          reasons.push("Uses an IP address instead of a normal domain");
        }

        // --------------------------------------------------
        // 4. Punycode / internationalized hostname
        // --------------------------------------------------

        if (hostname.includes("xn--")) {
          reasons.push("Uses punycode/internationalized hostname");
        }

        // --------------------------------------------------
        // 5. Excessively long URL
        // --------------------------------------------------

        if (rawUrl.length > 500) {
          reasons.push("Extremely long URL");
        } else if (rawUrl.length > 300) {
          reasons.push("Unusually long URL");
        }

        // --------------------------------------------------
        // 6. Excessive subdomains
        // --------------------------------------------------

        const parts = hostname.split(".");

        if (parts.length >= 5) {
          reasons.push("Unusually deep subdomain structure");
        }

        // --------------------------------------------------
        // 7. Suspicious URL characters
        // --------------------------------------------------

        if (/%40|%2f|%5c|%3a/i.test(rawUrl)) {
          reasons.push("Contains encoded URL-control characters");
        }

        if (hostname.includes("\\") || hostname.includes("@")) {
          reasons.push("Contains suspicious hostname characters");
        }

        // --------------------------------------------------
        // 8. Suspicious redirect parameters
        // --------------------------------------------------

        const redirectParameterNames = [
          "url",
          "uri",
          "redirect",
          "redirecturl",
          "redirect_url",
          "return",
          "returnurl",
          "return_url",
          "next",
          "target",
          "dest",
          "destination",
          "continue",
          "callback"
        ];

        for (const [key, value] of url.searchParams.entries()) {

          if (
            redirectParameterNames.includes(
              key.toLowerCase()
            )
          ) {

            if (
              /^https?:\/\//i.test(value) ||
              value.startsWith("//")
            ) {
              reasons.push(
                `Possible external redirect parameter: ${key}`
              );
            }
          }
        }

        // --------------------------------------------------
        // 9. Suspicious words in URL
        // --------------------------------------------------

        const suspiciousWords = [
          "login",
          "signin",
          "sign-in",
          "verify",
          "verification",
          "authenticate",
          "password",
          "credential",
          "account",
          "secure",
          "security",
          "confirm",
          "confirmation",
          "update",
          "billing",
          "payment",
          "wallet",
          "recover",
          "unlock"
        ];

        const matchedWords = suspiciousWords.filter(word =>
          fullUrl.includes(word)
        );

        if (matchedWords.length >= 2) {
          reasons.push(
            "Contains multiple login/account-related terms"
          );
        }

        // --------------------------------------------------
        // 10. Suspicious file extensions
        // --------------------------------------------------

        if (
          /\.(exe|scr|msi|bat|cmd|com|vbs|js|jar|ps1)(?:$|[?#])/i
            .test(url.pathname)
        ) {
          reasons.push("Links to a potentially executable file");
        }

        // --------------------------------------------------
        // 11. Link text vs destination mismatch
        // --------------------------------------------------

        if (text) {

          const displayedUrlMatch =
            text.match(/https?:\/\/[^\s]+/i);

          if (displayedUrlMatch) {

            try {

              const displayedUrl =
                new URL(displayedUrlMatch[0]);

              if (
                displayedUrl.hostname.toLowerCase() !==
                hostname
              ) {
                reasons.push(
                  "Displayed URL does not match destination"
                );
              }

            } catch {
              reasons.push(
                "Displayed URL appears malformed"
              );
            }
          }

          // Email says something like "Google" but goes elsewhere
          const trustedBrandWords = [
            "google",
            "microsoft",
            "apple",
            "amazon",
            "paypal",
            "github",
            "discord",
            "instagram",
            "facebook",
            "linkedin",
            "dropbox",
            "docusign"
          ];

          const brandMatches = trustedBrandWords.filter(
            brand =>
              text.toLowerCase().includes(brand) &&
              !hostname.includes(brand)
          );

          if (brandMatches.length > 0) {
            reasons.push(
              `Text mentions ${brandMatches.join(", ")} but destination hostname differs`
            );
          }
        }

        // --------------------------------------------------
        // 12. Suspicious domain patterns
        // --------------------------------------------------

        const domainWords = [
          "login",
          "verify",
          "secure",
          "account",
          "update",
          "support",
          "confirmation"
        ];

        const domainMatches = domainWords.filter(word =>
          hostname.includes(word)
        );

        if (domainMatches.length >= 2) {
          reasons.push(
            "Hostname contains multiple security/account terms"
          );
        }

        // --------------------------------------------------
        // 13. Excessive hyphens
        // --------------------------------------------------

        const hyphens = (hostname.match(/-/g) || []).length;

        if (hyphens >= 4) {
          reasons.push(
            "Hostname contains an unusually large number of hyphens"
          );
        }
        //I love Mr.Respass, he is the best.

        // --------------------------------------------------
        // 14. Very suspicious hostname structure
        // --------------------------------------------------

        if (
          hostname.includes("login-") ||
          hostname.includes("-login") ||
          hostname.includes("secure-") ||
          hostname.includes("-secure") ||
          hostname.includes("verify-") ||
          hostname.includes("-verify")
        ) {
          reasons.push(
            "Hostname resembles a security/login impersonation domain"
          );
        }

        // --------------------------------------------------
        // Score
        // --------------------------------------------------

        let score = 0;

        for (const reason of reasons) {

          if (
            reason.includes("Non-HTTP") ||
            reason.includes("user information") ||
            reason.includes("IP address") ||
            reason.includes("punycode")
          ) {
            score += 3;
          } else {
            score += 1;
          }
        }

        const suspicious = score >= 3;

        const result = {
          url: rawUrl,
          text,
          hostname,
          score,
          suspicious,
          reasons
        };

        results.push(result);

        if (suspicious) {

          console.warn(
            "🚨 THIS IS SUS 🚨",
            result
          );

        } else {

          console.log(
            "Link appears normal:",
            rawUrl
          );
        }
      }

      // Make available globally for debugging
      window.emailLinkResults = results;

      console.log(
        "Email link scan complete:",
        results
      );

    });
  });
});