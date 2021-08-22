"use strict";

const headers = [
    {name: "cross-origin-opener-policy", value: "same-origin"},
    {name: "strict-transport-security", value: "max-age=31536000"},
    {name: "x-content-type-options", value: "nosniff"},
    {name: "x-frame-options", value: "SAMEORIGIN"}
];

// Origins require direct URL access by user.
const protectedOrigins = new Set(["https://example.com", "https://mail.google.com", "https://mail.protonmail.com", "https://outlook.live.com"]);

const allowXFO = new Set(["account-api.protonmail.com]);

chrome.webRequest.onHeadersReceived.addListener(details => {
    let origin = new URL(details.url).origin;
    let keys = new Set(details.responseHeaders.map(header => header.name.toLowerCase()));

    if (allowXFO.has(origin) && !keys.has('x-frame-options')) {
         details.responseHeaders.push({name: "x-frame-options", value: "ALLOWALL"});
    }

    for (const header of headers) {
        if (!keys.has(header.name)) details.responseHeaders.push(header);
    }
    return {responseHeaders: details.responseHeaders};
}, {urls: ['<all_urls>']}, ['blocking', 'responseHeaders', 'extraHeaders']);

// Block acesss to protected origins when request is from a diffrent origin.
chrome.webRequest.onBeforeSendHeaders.addListener(details => {
    if (protectedOrigins.has(new URL(details.url).origin)) {
        for (const header of details.requestHeaders) {
            if (header.name === "Sec-Fetch-Site") {
                // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Site
                // User-originated operation or the initiator is same-origin can also use same-site.
                if (header.value === 'none' || header.value === 'same-origin') return;
                return {cancel: true};
            }
        }
    }
}, {urls: ['<all_urls>']}, ['blocking', 'requestHeaders']);
