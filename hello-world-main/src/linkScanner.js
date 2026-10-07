const checkedMessages = new Set();

export async function scanEmailLinks(messageView, forceRescan = false) {
    let messageId;

    try {
        messageId = await messageView.getMessageIDAsync();
    } catch {
        return null;
    }

    if (!forceRescan && checkedMessages.has(messageId)) {
        return window.emailLinkResults || [];
    }

    checkedMessages.add(messageId);

    const links = messageView.getLinksInBody();
    if (!links || links.length === 0) {
        return [];
    }

    const results = [];

    for (const link of links) {
        if (link.isInQuotedArea) {
            continue;
        }

        const rawUrl = link.href;
        const text = (link.text || "").trim();

        if (!rawUrl) continue;

        const reasons = [];
        let url;

        try {
            url = new URL(rawUrl);
        } catch {
            reasons.push("Invalid or malformed URL");
            results.push({
                url: rawUrl,
                text,
                suspicious: true,
                reasons,
                score: 3
            });
            continue;
        }

        const hostname = url.hostname.toLowerCase();
        const fullUrl = url.href.toLowerCase();

        // 1. Dangerous protocols
        if (!["http:", "https:", "mailto:", "tel:"].includes(url.protocol)) {
            reasons.push("Non-HTTP/HTTPS protocol");
        }

        // 2. Embedded credentials
        if (url.username || url.password) {
            reasons.push("URL contains embedded login credentials");
        }

        // 3. Raw IP address (IPv4 or IPv6)
        const strippedHost = hostname.replace(/^\[\vert{}\]$/g, '');
        if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(strippedHost) || strippedHost.includes(":")) {
            reasons.push("Uses a raw IP address instead of a domain name");
        }

        // 4. Punycode
        if (hostname.includes("xn--")) {
            reasons.push("Uses punycode / internationalized domain name");
        }

        // 5. URL length
        if (rawUrl.length > 500) {
            reasons.push("Extremely long URL (>500 chars)");
        } else if (rawUrl.length > 300) {
            reasons.push("Unusually long URL (>300 chars)");
        }

        // 6. Excessive subdomains
        const parts = hostname.split(".");
        if (parts.length >= 5) {
            reasons.push("Unusually deep subdomain hierarchy");
        }

        // 7. Suspicious encoded characters
        if (/%40|%2f|%5c|%3a/i.test(rawUrl)) {
            reasons.push("Contains encoded URL-control characters");
        }

        // 8. Open redirect parameters
        const redirectParams = [
            "url", "uri", "redirect", "redirecturl", "redirect_url",
            "return", "returnurl", "return_url", "next", "target",
            "dest", "destination", "continue", "callback"
        ];

        for (const [key, value] of url.searchParams.entries()) {
            if (redirectParams.includes(key.toLowerCase())) {
                if (/^https?:\/\//i.test(value) || value.startsWith("//")) {
                    reasons.push(`Possible external redirect parameter (${key})`);
                }
            }
        }

        // 9. Multiple suspicious keywords in URL
        const suspiciousWords = [
            "login", "signin", "sign-in", "verify", "verification",
            "authenticate", "password", "credential", "account", "secure",
            "security", "confirm", "confirmation", "update", "billing",
            "payment", "wallet", "recover", "unlock"
        ];

        const matchedWords = suspiciousWords.filter(word => fullUrl.includes(word));
        if (matchedWords.length >= 2) {
            reasons.push("Contains multiple login/security keywords");
        }

        // 10. Executable file extensions
        if (/\.(exe|scr|msi|bat|cmd|com|vbs|js|jar|ps1)(?:$|[?#])/i.test(url.pathname)) {
            reasons.push("Links directly to a downloadable/executable file");
        }

        // 11. Mismatched anchor text vs target destination
        if (text) {
            const displayedUrlMatch = text.match(/https?:\/\/[^\s\)\>]+/i);
            if (displayedUrlMatch) {
                try {
                    const displayedUrl = new URL(displayedUrlMatch[0]);
                    if (displayedUrl.hostname.toLowerCase() !== hostname) {
                        reasons.push(`Displayed URL domain (${displayedUrl.hostname}) does not match actual target (${hostname})`);
                    }
                } catch {
                    reasons.push("Displayed link text resembles a URL but is malformed");
                }
            }

            const trustedBrandWords = [
                "google", "microsoft", "apple", "amazon", "paypal",
                "github", "discord", "instagram", "facebook", "linkedin",
                "dropbox", "docusign"
            ];

            const brandMatches = trustedBrandWords.filter(
                brand => text.toLowerCase().includes(brand) && !hostname.includes(brand)
            );

            if (brandMatches.length > 0) {
                reasons.push(`Link text mentions ${brandMatches.join(", ")} but target host differs`);
            }
        }

        // 12. Domain keyword stacking
        const domainWords = ["login", "verify", "secure", "account", "update", "support", "confirmation"];
        const domainMatches = domainWords.filter(word => hostname.includes(word));
        if (domainMatches.length >= 2) {
            reasons.push("Domain name stacks multiple security keywords");
        }

        // 13. Excessive hyphens
        const hyphens = (hostname.match(/-/g) || []).length;
        if (hyphens >= 4) {
            reasons.push("Domain contains high hyphen count (potential spoofing)");
        }

        // 14. Impersonation patterns
        if (/(login|secure|verify)-|-(login|secure|verify)/i.test(hostname)) {
            reasons.push("Domain uses standard security-impersonation prefix/suffix patterns");
        }

        // Scoring
        let score = 0;
        for (const reason of reasons) {
            if (
                reason.includes("Non-HTTP") ||
                reason.includes("credentials") ||
                reason.includes("IP address") ||
                reason.includes("punycode")
            ) {
                score += 3;
            } else {
                score += 1;
            }
        }

        const suspicious = score >= 3;

        results.push({
            url: rawUrl,
            text,
            hostname,
            score,
            suspicious,
            reasons
        });
    }

    window.emailLinkResults = results;
    return results;
}