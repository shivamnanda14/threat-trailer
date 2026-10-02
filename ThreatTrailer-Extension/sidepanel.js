const iframe = document.getElementById('threat-frame');

// Initial load - point to dashboard without URL
iframe.src = "http://localhost:3000/";

// Listen for messages from background.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "update-iframe" && request.url) {
    // Force iframe to update its source to the new URL containing the query parameter
    iframe.src = request.url;
  }
});