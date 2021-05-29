"use strict";
const headers = [
{name: "cross-origin-opener-policy", value: "same-origin"},
{name: "strict-transport-security", value: "max-age=31536000"},
{name: "x-content-type-options", value: "nosniff"},
{name: "x-frame-options", value: "SAMEORIGIN"}
];

chrome.webRequest.onHeadersReceived.addListener(details => {
    let keys = new Set(details.responseHeaders.map(header => header.name.toLowerCase()));
    // Add CORS policy with a lot of exceptions.
    if (!keys.has("timing-allow-origin") && !keys.has("access-control-allow-origin") && !keys.has("cross-origin-resource-policy")) {
    details.responseHeaders.push({name: "cross-origin-resource-policy", value: "same-origin"});
    }
    for (const header of headers) {
    if (!keys.has(header.name)) details.responseHeaders.push(header);
    }
    return {responseHeaders: details.responseHeaders};
}, {urls: ['<all_urls>']}, ['blocking', 'responseHeaders', 'extraHeaders']);
