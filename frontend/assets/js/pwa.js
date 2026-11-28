(() => {
  if ("serviceWorker" in navigator) {
    window.addEventListener("load", () => {
      navigator.serviceWorker.register("./service-worker.js")
        .catch((error) => console.error("CYVORA service worker registration failed:", error));
    });
  }

  let installPrompt = null;

  window.addEventListener("beforeinstallprompt", (event) => {
    event.preventDefault();
    installPrompt = event;

    if (document.getElementById("cyvoraInstallButton")) return;

    const button = document.createElement("button");
    button.id = "cyvoraInstallButton";
    button.type = "button";
    button.textContent = "Install CYVORA";
    button.setAttribute("aria-label", "Install CYVORA app");
    Object.assign(button.style, {
      position: "fixed",
      right: "16px",
      bottom: "16px",
      zIndex: "9999",
      padding: "12px 16px",
      border: "0",
      borderRadius: "10px",
      background: "#2563eb",
      color: "#ffffff",
      font: "600 14px system-ui, sans-serif",
      boxShadow: "0 4px 18px rgba(0,0,0,.25)",
      cursor: "pointer"
    });

    button.addEventListener("click", async () => {
      if (!installPrompt) return;
      installPrompt.prompt();
      await installPrompt.userChoice;
      installPrompt = null;
      button.remove();
    });

    document.body.appendChild(button);
  });

  window.addEventListener("appinstalled", () => {
    document.getElementById("cyvoraInstallButton")?.remove();
    installPrompt = null;
  });
})();
