const checkedMessages = new Set();

const NO_LINK_SUSPICIOUS_PATTERNS = [
    { pattern: /(gift\s*card|steam\s*card|itunes\s*card|google\s*play\s*card)/i, score: 3 },
    { pattern: /(direct\s*deposit|routing\s*number|update\s*payroll|bank\s*account\s*details)/i, score: 3 },
    { pattern: /(wire\s*transfer|funds\s*transfer|swift\s*code|bank\s*wire)/i, score: 3 },
    { pattern: /(strictly\s*confidential|in\s*a\s*meeting|do\s*not\s*call|email\s*only|quick\s*favor)/i, score: 1 },
    { pattern: /(text\s*me|whatsapp|cell\s*phone\s*number|send\s*me\s*your\s*mobile)/i, score: 1 },
    { pattern: /(urgent\s*action\s*required|account\s*will\s*be\s*closed|immediate\s*attention)/i, score: 1 },
    { pattern: /(social\s*security|ssn|credit\s*card\s*number|credit\s*card\s*details)/i, score: 3 }, { pattern: /(million\s*dollars|lottery\s*winner|inheritance|nigerian\s*prince|free\s*money)/i, score: 3 },
    { pattern: /(hurry|time\s*is\s*ending|act\s*fast|limited\s*time)/i, score: 1 }
];

export async function scanEmailContent(messageView, forceRescan = false) {
    let messageId;

    try {
        messageId = await messageView.getMessageIDAsync();
    } catch {
        return null;
    }

    if (!forceRescan && checkedMessages.has(messageId)) {
        return window.emailScanResults || null;
    }

    checkedMessages.add(messageId);

    const links = messageView.getLinksInBody() || [];
    const linkResults = [];

    // --------------------------------------------------
    // 1. Scan Links
    // --------------------------------------------------
    for (const link of links) {
        if (link.isInQuotedArea) continue;

        const rawUrl = link.href;
        const text = (link.text || "").trim();
        if (!rawUrl) continue;

        let url;
        let isSuspiciousLink = false;
        let score = 0;

        try {
            url = new URL(rawUrl);
        } catch {
            linkResults.push({ url: rawUrl, text, suspicious: true, score: 3 });
            continue;
        }

        const hostname = url.hostname.toLowerCase();

        if (!["http:", "https:", "mailto:", "tel:"].includes(url.protocol)) score += 3;
        if (url.username || url.password) score += 3;

        const strippedHost = hostname.replace(/^\[|\]$/g, '');
        if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(strippedHost) || strippedHost.includes(":")) score += 3;
        if (hostname.includes("xn--")) score += 3;
        if (rawUrl.length > 500) score += 1;

        const redirectParams = ["url", "redirect", "redirecturl", "next", "target", "dest", "continue"];
        for (const [key, value] of url.searchParams.entries()) {
            if (redirectParams.includes(key.toLowerCase()) && (/^https?:\/\//i.test(value) || value.startsWith("//"))) {
                score += 1;
            }
        }

        if (text) {
            const displayedUrlMatch = text.match(/https?:\/\/[^\s\)\>]+/i);
            if (displayedUrlMatch) {
                try {
                    const displayedUrl = new URL(displayedUrlMatch[0]);
                    if (displayedUrl.hostname.toLowerCase() !== hostname) score += 2;
                } catch {
                    score += 1;
                }
            }
        }

        isSuspiciousLink = score >= 3;
        linkResults.push({ url: rawUrl, text, hostname, score, suspicious: isSuspiciousLink });
    }

    // --------------------------------------------------
    // 2. Scan Body Text & Metadata
    // --------------------------------------------------
    const bodyElement = messageView.getBodyElement();
    const bodyText = bodyElement ? bodyElement.innerText : "";
    let textScore = 0;

    for (const item of NO_LINK_SUSPICIOUS_PATTERNS) {
        if (item.pattern.test(bodyText)) {
            textScore += item.score;
        }
    }

    const sender = messageView.getSender();
    if (sender && sender.name && sender.emailAddress) {
        const nameLower = sender.name.toLowerCase();
        const emailLower = sender.emailAddress.toLowerCase();

        if ((nameLower.includes("admin") || nameLower.includes("support") || nameLower.includes("security")) &&
            !emailLower.includes("admin") && !emailLower.includes("support")) {
            textScore += 2;
        }
    }

    const suspiciousLinks = linkResults.filter(r => r.suspicious);
    const totalSuspiciousScore = textScore + suspiciousLinks.reduce((acc, curr) => acc + curr.score, 0);
    const isSuspicious = totalSuspiciousScore >= 3;

    const finalReport = {
        hasLinks: linkResults.length > 0,
        totalLinks: linkResults.length,
        suspiciousLinksCount: suspiciousLinks.length,
        score: totalSuspiciousScore,
        suspicious: isSuspicious
    };

    window.emailScanResults = finalReport;
    return finalReport;
}