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
});