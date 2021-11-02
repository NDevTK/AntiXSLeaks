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

// Origins that require direct URL access by user or the same-origin.
const protectedOrigins = new Set(["https://example.com", "https://myaccount.google.com", "https://payments.google.com", "https://myactivity.google.com", "https://pay.google.com", "https://adssettings.google.com", "https://mail.google.com", "https://mail.protonmail.com", "https://account.protonmail.com", "https://outlook.live.com"]);

const exceptions = new Map()
.set("https://account-api.protonmail.com", ['x-frame-options']);

const extensionEmbeding = new Set()
.add("");

chrome.webRequest.onHeadersReceived.addListener(details => {
    let origin = new URL(details.url).origin;
    let whitelist = exceptions.has(origin) ? exceptions.get(origin) : [];
    let keys = new Set(details.responseHeaders.map(header => header.name.toLowerCase()));
    
    // Apply defaults.
    for (const header of headers) {
        if (!keys.has(header.name) && !whitelist.includes(header.name)) details.responseHeaders.push(header);
    }
    
    //changeCookies(keys, details.responseHeaders);
    
    return {responseHeaders: details.responseHeaders};
}, {urls: ['<all_urls>']}, ['blocking', 'responseHeaders', 'extraHeaders']);

// Block acesss to protected origins when request is from a diffrent origin.
chrome.webRequest.onBeforeSendHeaders.addListener(details => {
    // Since this may inconvenience the user only do this for "important" origins.
    let origin = new URL(details.url).origin;
    
    if (url.protocol === 'chrome-extension:' && !extensionEmbeding.has(origin) || protectedOrigins.has(origin)) {
        let headers = new Map(details.requestHeaders.map(header => [header.name.toLowerCase(), header.value.toLowerCase()]));
        if (headers.has('sec-fetch-site')) {
              let value = headers.get('sec-fetch-site');
              if (value === 'none' && headers.get('sec-fetch-user') === '?1' || value === 'same-origin') return;
              return {cancel: true};
        }
    }
}, {urls: ['<all_urls>']}, ['blocking', 'requestHeaders']);

function changeCookies(keys, responseHeaders) {
    if (keys.has("cookie")) {
        for (let header of responseHeaders) {
            if (header.name.toLowerCase() === "cookie") {
                break;
            }
        }
    }
}
