"use strict";

chrome.runtime.onMessage.addListener(message => {
  return Promise.resolve(confirm(message));
});
