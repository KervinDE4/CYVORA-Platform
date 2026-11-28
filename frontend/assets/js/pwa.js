(() => {
  const isStandalone = () =>
    window.matchMedia("(display-mode: standalone)").matches ||
    window.matchMedia("(display-mode: fullscreen)").matches ||
    window.navigator.standalone === true;

  let installPrompt = null;
  let installButton = null;

  function showHelp() {
    let panel = document.getElementById("cyvoraInstallHelp");
    if (panel) {
      panel.hidden = false;
      return;
    }

    panel = document.createElement("section");
    panel.id = "cyvoraInstallHelp";
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-modal", "true");
    panel.setAttribute("aria-labelledby", "cyvoraInstallTitle");
    Object.assign(panel.style, {
      position: "fixed",
      inset: "0",
      zIndex: "10000",
      background: "rgba(5, 10, 25, .78)",
      display: "grid",
      placeItems: "center",
      padding: "18px",
      boxSizing: "border-box"
    });

    const card = document.createElement("div");
    Object.assign(card.style, {
      width: "min(100%, 440px)",
      background: "#ffffff",
      color: "#14213d",
      borderRadius: "18px",
      padding: "24px",
      boxSizing: "border-box",
      font: "16px/1.5 system-ui, sans-serif",
      boxShadow: "0 16px 50px rgba(0,0,0,.35)"
    });

    const ios = /iphone|ipad|ipod/i.test(navigator.userAgent);
    const android = /android/i.test(navigator.userAgent);
    const heading = document.createElement("h2");
    heading.id = "cyvoraInstallTitle";
    heading.textContent = "Put CYVORA on your phone";
    heading.style.margin = "0 0 12px";

    const intro = document.createElement("p");
    intro.textContent = "Add CYVORA to your home screen so you can open it like an app.";
    const steps = document.createElement("ol");
    steps.style.paddingLeft = "24px";

    const instructions = ios
      ? ["Open this website in Safari (not inside another app).", "Tap the Share button (the square with an arrow).", "Choose “Add to Home Screen”.", "Tap “Add” at the top."]
      : android
        ? ["Open this website in Google Chrome.", "Tap the three dots ⋮ at the top or bottom.", "Choose “Install app” or “Add to Home screen”.", "Tap “Install” or “Add” to finish."]
        : ["Open this website in Chrome or Edge.", "Look for the install icon near the address bar, or open the browser menu.", "Choose “Install CYVORA” or “Install this site as an app”."];
    instructions.forEach((instruction) => {
      const item = document.createElement("li");
      item.textContent = instruction;
      item.style.margin = "8px 0";
      steps.appendChild(item);
    });

    const note = document.createElement("p");
    note.textContent = ios
      ? "Tip: On iPhone and iPad, installation is done through Safari's Share menu."
      : "If you do not see an install option, update your browser and open this page directly in Chrome.";
    note.style.fontSize = "14px";
    note.style.color = "#475569";

    const close = document.createElement("button");
    close.type = "button";
    close.textContent = "Got it";
    Object.assign(close.style, {
      width: "100%",
      padding: "14px",
      border: "0",
      borderRadius: "10px",
      background: "#1d4ed8",
      color: "#fff",
      font: "700 16px system-ui, sans-serif",
      cursor: "pointer"
    });
    close.addEventListener("click", () => panel.remove());

    card.append(heading, intro, steps, note, close);
    panel.appendChild(card);
    panel.addEventListener("click", (event) => {
      if (event.target === panel) panel.remove();
    });
    document.body.appendChild(panel);
    close.focus();
  }

  function createButton() {
    if (isStandalone() || document.getElementById("cyvoraInstallButton")) return;
    installButton = document.createElement("button");
    installButton.id = "cyvoraInstallButton";
    installButton.type = "button";
    installButton.textContent = "＋ Install CYVORA";
    installButton.setAttribute("aria-label", "Install CYVORA on this device");
    Object.assign(installButton.style, {
      position: "fixed",
      right: "16px",
      bottom: "16px",
      zIndex: "9998",
      padding: "14px 18px",
      border: "0",
      borderRadius: "999px",
      background: "#2563eb",
      color: "#ffffff",
      font: "700 16px system-ui, sans-serif",
      boxShadow: "0 5px 20px rgba(0,0,0,.3)",
      cursor: "pointer"
    });

    installButton.addEventListener("click", async () => {
      if (!installPrompt) {
        showHelp();
        return;
      }
      installPrompt.prompt();
      const choice = await installPrompt.userChoice;
      installPrompt = null;
      if (choice && choice.outcome === "accepted") installButton?.remove();
      else showHelp();
    });

    document.body.appendChild(installButton);
  }

  function updateInstallState() {
    if (isStandalone()) {
      installButton?.remove();
      document.getElementById("cyvoraInstallHelp")?.remove();
    } else {
      createButton();
    }
  }

  if ("serviceWorker" in navigator) {
    window.addEventListener("load", () => {
      navigator.serviceWorker.register("./service-worker.js")
        .catch((error) => console.error("CYVORA service worker registration failed:", error));
    });
  }

  window.addEventListener("beforeinstallprompt", (event) => {
    event.preventDefault();
    installPrompt = event;
    updateInstallState();
  });

  window.addEventListener("appinstalled", () => {
    installPrompt = null;
    installButton?.remove();
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", updateInstallState, { once: true });
  } else {
    updateInstallState();
  }
})();
