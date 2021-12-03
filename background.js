"use strict";

const headers = [
    {name: "cross-origin-opener-policy", value: "same-origin"},
    {name: "cross-origin-embedder-policy", value: "credentialless"},
    {name: "strict-transport-security", value: "max-age=31536000"},
    {name: "x-content-type-options", value: "nosniff"},
    {name: "x-frame-options", value: "SAMEORIGIN"},
    {name: "vary", value: "Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, Sec-Fetch-User"},
    {name: "document-policy", value: "force-load-at-top"}
];

// Require direct URL access by user or the same-origin.
const protectedOrigins = new Set(["https://example.com", "https://myaccount.google.com", "https://payments.google.com", "https://myactivity.google.com", "https://pay.google.com", "https://adssettings.google.com", "https://mail.google.com", "https://mail.protonmail.com", "https://account.protonmail.com", "https://outlook.live.com"]);

const exceptions = new Map()
.set("https://account-api.protonmail.com", ['x-frame-options'])
.set("https://en.wikipedia.org", ['document-policy']);

function isTrustworthy(url) {
    let u = new URL(url);
    
    // https://w3c.github.io/webappsec-secure-contexts/#is-url-trustworthy
    // If url is "about:blank" or "about:srcdoc", return "Potentially Trustworthy".
    if (u.href === 'about:blank' || u.href === 'about:srcdoc') return 'Potentially Trustworthy';
    
    // If url’s scheme is "data", return "Potentially Trustworthy".
    if (u.protocol === 'data:') return 'Potentially Trustworthy';
    
    // https://w3c.github.io/webappsec-secure-contexts/#is-origin-trustworthy
    // If origin is an opaque origin, return "Not Trustworthy".
    if (u.protocol === 'null') return 'Not Trustworthy';
    
    // Assert: origin is a tuple origin.
    if (u.protocol === undefined || u.host === undefined || u.port === undefined)  return 'Not Trustworthy';
    
    // If origin’s scheme is either "https" or "wss", return "Potentially Trustworthy".
    if (u.protocol === 'https:' || u.protocol === 'wss:') return 'Potentially Trustworthy';
    
    // If origin’s host matches one of the CIDR notations 127.0.0.0/8 or ::1/128 [RFC4632], return "Potentially Trustworthy".
    if (u.host === '127.0.0.1') return 'Potentially Trustworthy';
    
    // If the user agent conforms to the name resolution rules in [let-localhost-be-localhost] and one of the following is true:
    // origin’s host is "localhost" or "localhost."
    if (u.host === 'localhost' || u.host === 'localhost.') return 'Potentially Trustworthy';
    // origin’s host ends with ".localhost" or ".localhost."
    if (u.host.endsWith('.localhost') || u.host.endsWith('.localhost.')) return 'Potentially Trustworthy';
    
    // If origin’s scheme is "file", return "Potentially Trustworthy".
    if (u.protocol === 'file:') return 'Potentially Trustworthy';
    
    // If origin’s scheme component is one which the user agent considers to be authenticated, return "Potentially Trustworthy".
    if (u.protocol === 'app:' || u.protocol === 'chrome-extension:') return 'Potentially Trustworthy';

    return 'Not Trustworthy';
}

chrome.webRequest.onHeadersReceived.addListener(details => {
    let origin = new URL(details.url).origin;
    let whitelist = exceptions.has(origin) ? exceptions.get(origin) : [];
    let keys = new Set(details.responseHeaders.map(header => header.name.toLowerCase()));
    
    // Apply defaults.
    for (const header of headers) {
        if (!keys.has(header.name) && !whitelist.includes(header.name)) details.responseHeaders.push(header);
    }
    
    return {responseHeaders: details.responseHeaders};
}, {urls: ['<all_urls>']}, ['blocking', 'responseHeaders', 'extraHeaders']);

// Block acesss to origins when request is from a diffrent origin.
chrome.webRequest.onBeforeSendHeaders.addListener(details => {
    let url = new URL(details.url);
    let headers = new Map(details.requestHeaders.map(header => [header.name.toLowerCase(), header.value.toLowerCase()]))

    // Cant trust the origin for insecure protocols.
    if (isTrustworthy(url) === 'Not Trustworthy') {
        if (details.initiator === undefined || details.initiator === url.origin) {
            return {cancel: !confirm('[Not trustworthy target] ' + url.origin)};
        } else {
            return {cancel: !confirm('[Not trustworthy target and initiator] ' + url.origin)};
        }
    }
    
    // Defend SameSite Lax cookies and malicious subdomains.
    if (headers.get('sec-fetch-site') === 'cross-site' && headers.get('sec-fetch-mode') === 'navigate' && headers.get('sec-fetch-dest') === 'document') {
        if (headers.get('purpose') === 'prefetch') return {cancel: true};
        if (confirm(url.origin) !== true) return {cancel: true};
    }
    
    // Since this may inconvenience the user only do this for "important" origins.
    if (protectedOrigins.has(url.origin)) {
        // If the request does not contain the header use details.initiator instead.
        if (headers.has('sec-fetch-site') === false) {
            if (details.initiator === 'null' || details.initiator === url.origin) return;
            return {cancel: true};
        }
        let site = headers.get('sec-fetch-site');
        if (site === 'none' && headers.get('sec-fetch-user') === '?1' || site === 'same-origin') return;
        return {cancel: true};
    }
}, {urls: ['<all_urls>']}, ['blocking', 'requestHeaders']);
