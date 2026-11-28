(function () {
  "use strict";
  const path = window.location.pathname.toLowerCase();
  const isCallTrust = path.endsWith("/call-trust.html");
  const isThreatScan = path.endsWith("/threat-scan.html");
  if (!isCallTrust && !isThreatScan) return;

  const contentRoot = isCallTrust
    ? document.querySelector(".main-wrap .content-grid")
    : document.querySelector(".cyvora-shell");
  if (!contentRoot) return;

  const emailBadge = document.getElementById("userEmailBadge");
  const signOutButton = document.getElementById("btnSignOut");
  const oldSidebar = document.querySelector(".app-shell > .sidebar");
  const oldTopbar = isCallTrust
    ? document.querySelector(".main-wrap > .topbar")
    : document.querySelector(".cyvora-shell > .topbar");
  const oldModuleNav = document.querySelector(".module-nav");

  oldSidebar?.remove();
  oldTopbar?.remove();
  oldModuleNav?.remove();

  const shell = document.createElement("div");
  shell.className = "cyvora-app-shell";
  const header = document.createElement("header");
  header.className = "cyvora-global-header";
  header.innerHTML = `
    <button class="cyvora-menu-button" type="button" aria-label="Open navigation" aria-expanded="false">☰</button>
    <a class="cyvora-brand" href="index.html" aria-label="CYVORA home">
      <img src="assets/images/cyvora-logo.jpeg" alt="">
      <span><strong>CYVORA</strong><small>PROTECT. VERIFY. REPORT.</small></span>
    </a>
    <input class="cyvora-header-search" type="search" aria-label="Global search" placeholder="Global search is being prepared" disabled>
    <div class="cyvora-header-actions">
      <span class="cyvora-user-slot"></span>
      <button class="cyvora-collapse-button" type="button" aria-label="Collapse sidebar" aria-pressed="false">⇤</button>
    </div>`;
  const workspace = document.createElement("div");
  workspace.className = "cyvora-workspace";
  const sidebar = document.createElement("aside");
  sidebar.className = "cyvora-sidebar";
  sidebar.setAttribute("aria-label", "Main navigation");
  sidebar.innerHTML = `
    <div class="cyvora-sidebar-heading">PLATFORM</div>
    <nav class="cyvora-sidebar-nav">
      <a class="cyvora-nav-link" href="index.html"><span class="cyvora-nav-icon">⌂</span><span class="cyvora-nav-label">Home</span></a>
      <a class="cyvora-nav-link" href="call-trust.html"><span class="cyvora-nav-icon">◉</span><span class="cyvora-nav-label">CallTrust</span></a>
      <a class="cyvora-nav-link" href="threat-scan.html"><span class="cyvora-nav-icon">⌕</span><span class="cyvora-nav-label">ThreatScan</span></a>
    </nav>
    <div class="cyvora-sidebar-heading" style="margin-top:22px">COMING NEXT</div>
    <div class="cyvora-sidebar-nav">
      <span class="cyvora-nav-disabled"><span class="cyvora-nav-icon">▥</span><span class="cyvora-nav-label">TrustVision</span><small>Planned</small></span>
      <span class="cyvora-nav-disabled"><span class="cyvora-nav-icon">◎</span><span class="cyvora-nav-label">Community</span><small>Planned</small></span>
      <span class="cyvora-nav-disabled"><span class="cyvora-nav-icon">▤</span><span class="cyvora-nav-label">Reports</span><small>Planned</small></span>
      <span class="cyvora-nav-disabled"><span class="cyvora-nav-icon">♧</span><span class="cyvora-nav-label">Verified Directory</span><small>Planned</small></span>
    </div>
    <div class="cyvora-sidebar-foot">Only available services are linked. More CYVORA modules will appear here as they become functional.</div>`;
  const main = document.createElement("main");
  main.className = "cyvora-main";
  const pageContent = document.createElement("div");
  pageContent.className = "cyvora-page-content";

  const userSlot = header.querySelector(".cyvora-user-slot");
  if (emailBadge) {
    userSlot.appendChild(emailBadge);
    emailBadge.removeAttribute("style");
  } else {
    userSlot.textContent = "Signed in";
  }
  if (signOutButton) {
    signOutButton.classList.add("cyvora-signout");
    header.querySelector(".cyvora-header-actions").appendChild(signOutButton);
  }

  if (isCallTrust) {
    pageContent.appendChild(contentRoot);
    document.querySelector(".app-shell")?.remove();
  } else {
    const oldShell = document.querySelector(".cyvora-shell");
    const children = Array.from(oldShell.children);
    children.forEach(node => pageContent.appendChild(node));
    oldShell.remove();
  }

  const activeHref = isCallTrust ? "call-trust.html" : "threat-scan.html";
  const activeLink = sidebar.querySelector('a[href="' + activeHref + '"]');
  activeLink?.setAttribute("aria-current", "page");
  main.appendChild(pageContent);
  workspace.append(sidebar, main);
  shell.append(header, workspace);
  const backdrop = document.createElement("button");
  backdrop.type = "button";
  backdrop.className = "cyvora-nav-backdrop";
  backdrop.setAttribute("aria-label", "Close navigation");
  shell.appendChild(backdrop);
  document.body.classList.add("cyvora-unified");
  document.body.prepend(shell);

  const menuButton = header.querySelector(".cyvora-menu-button");
  const collapseButton = header.querySelector(".cyvora-collapse-button");
  function closeMobileNav() {
    shell.classList.remove("mobile-nav-open");
    menuButton.setAttribute("aria-expanded", "false");
  }
  menuButton.addEventListener("click", () => {
    const open = shell.classList.toggle("mobile-nav-open");
    menuButton.setAttribute("aria-expanded", String(open));
  });
  backdrop.addEventListener("click", closeMobileNav);
  sidebar.addEventListener("click", event => {
    if (event.target.closest("a")) closeMobileNav();
  });
  collapseButton.addEventListener("click", () => {
    const collapsed = shell.classList.toggle("is-collapsed");
    collapseButton.setAttribute("aria-pressed", String(collapsed));
    collapseButton.setAttribute("aria-label", collapsed ? "Expand sidebar" : "Collapse sidebar");
    collapseButton.textContent = collapsed ? "⇥" : "⇤";
  });
})();