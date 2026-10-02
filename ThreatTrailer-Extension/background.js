chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "detonate-link",
    title: "⚡ Detonate in Threat Trailer",
    contexts: ["all"]
  });
  // Note: Humne yahan se openPanelOnActionClick hata diya hai, taaki hum manually URL bhej sakein.
});

// TAREKA 1: Jab user direct Extension Icon par click kare
chrome.action.onClicked.addListener(async (tab) => {
  // Check karo ki tab me ek valid website khuli hai
  if (tab.url && tab.url.startsWith("http")) {
    const suspiciousUrl = encodeURIComponent(tab.url);
    
    // Panel kholo
    await chrome.sidePanel.open({ windowId: tab.windowId });
    
    // 1.5 second baad us URL ko iframe me bhej do
    setTimeout(() => {
      chrome.runtime.sendMessage({
        action: "update-iframe",
        url: `https://threat-trailer-app.onrender.com/?url=${suspiciousUrl}`
      });
    }, 1500);
  }
});

// TAREKA 2: Jab user Right-Click karke option select kare (Jo pehle se chal raha hai)
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "detonate-link") {
    let targetUrl = info.linkUrl || (info.selectionText && info.selectionText.startsWith("http") ? info.selectionText : "") || info.pageUrl;

    if (targetUrl) {
      const suspiciousUrl = encodeURIComponent(targetUrl);
      
      await chrome.sidePanel.open({ windowId: tab.windowId });
      
      setTimeout(() => {
        chrome.runtime.sendMessage({
          action: "update-iframe",
          url: `https://threat-trailer-app.onrender.com/?url=${suspiciousUrl}`
        });
      }, 1500);
    }
  }
});