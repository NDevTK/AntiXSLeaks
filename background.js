chrome.webRequest.onHeadersReceived.addListener(function(details) {
  for (let i = 0; i < details.responseHeaders.length; i += 1) {
    if (details.responseHeaders[i].name.toLowerCase() === "x-frame-options") {
		details.responseHeaders.push({name: "Cross-Origin-Opener-Policy", value: "same-origin"});
	        break
    }
  }
return {responseHeaders: details.responseHeaders};
}, {urls: ["<all_urls>"]}, ["blocking", "responseHeaders"]);
