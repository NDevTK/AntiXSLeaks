"use strict";

browser.runtime.onMessage.addListener(message => {
  return Promise.resolve(confirm(message));
});
