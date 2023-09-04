async function confirm(message) {
  let popup = await browser.windows.create({type: 'popup', url: "confirm.html"});
  await new Promise(resolve => setTimeout(resolve, 100));
  let result = await browser.tabs.sendMessage(popup.tabs[0].id, message);
  browser.windows.remove(popup.id);
  return result;
}

firefox = true;
