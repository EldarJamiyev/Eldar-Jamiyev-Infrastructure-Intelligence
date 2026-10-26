/*
 * EJII Meridian shell behavior.
 * Only presentation is handled here; authentication, telemetry, diagnostics and views
 * remain owned by EJII's established application modules.
 */
(function () {
  'use strict';

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const icon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 6h16M4 12h16M4 18h16"/></svg>';

  const viewMeta = {
    topology: { title: 'Network overview', eyebrow: 'Observe & understand' },
    'packet-sniffer': { title: 'Packet analysis', eyebrow: 'Inspect & investigate' },
    'ultra-ip-scanner': { title: 'IP & asset discovery', eyebrow: 'Discover & map' },
    'pc-automation': { title: 'Automation library', eyebrow: 'Execute & maintain' },
    'core-diagnostics': { title: 'Diagnostics & recovery', eyebrow: 'Diagnose & resolve' }
  };

  function setup() {
    const app = $('#app');
    const sidebar = $('#sidebar');
    const title = $('#pageTitle');
    const headerLeft = $('.topbar-left');
    if (!app || !sidebar || !title || !headerLeft) return;

    if (!$('#ejiiShellToggle')) {
      const toggle = document.createElement('button');
      toggle.id = 'ejiiShellToggle';
      toggle.type = 'button';
      toggle.className = 'ejii-shell-toggle';
      toggle.setAttribute('aria-label', 'Toggle navigation');
      toggle.setAttribute('aria-controls', 'sidebar');
      toggle.setAttribute('aria-expanded', 'true');
      toggle.title = 'Toggle navigation';
      toggle.innerHTML = icon;
      headerLeft.insertBefore(toggle, headerLeft.firstChild);
      toggle.addEventListener('click', handleNavigationToggle);
    }

    if (!$('.ejii-mobile-scrim')) {
      const scrim = document.createElement('div');
      scrim.className = 'ejii-mobile-scrim';
      scrim.setAttribute('aria-hidden', 'true');
      document.body.appendChild(scrim);
      scrim.addEventListener('click', closeMobileNavigation);
    }

    updateNavigationContext();
    const navObserver = new MutationObserver(() => updateNavigationContext());
    navObserver.observe(sidebar, { attributes: true, subtree: true, attributeFilter: ['class'] });

    sidebar.addEventListener('click', (event) => {
      const link = event.target.closest('.nav-link');
      if (!link) return;
      updateNavigationContext();
      if (window.matchMedia('(max-width: 850px)').matches) closeMobileNavigation();
    });

    // The status line beneath the navigation is the existing WebSocket status source of truth.
    // Do not create a second synthetic connection state.
    const statusNode = $('#wsStatusText');
    if (statusNode) {
      const textObserver = new MutationObserver(() => {
        const label = statusNode.textContent.trim();
        const dot = $('.status-dot', sidebar);
        if (dot) dot.setAttribute('aria-label', label);
      });
      textObserver.observe(statusNode, { childList: true, characterData: true, subtree: true });
    }

    updateClock();
    window.setInterval(updateClock, 30000);

    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') closeMobileNavigation();
    });

    try {
      if (window.matchMedia('(max-width: 850px)').matches) {
        document.body.classList.remove('ejii-sidebar-collapsed');
      } else if (localStorage.getItem('ejii_sidebar_collapsed') === 'true') {
        document.body.classList.add('ejii-sidebar-collapsed');
        $('#ejiiShellToggle')?.setAttribute('aria-expanded', 'false');
      }
    } catch (_) {}
  }

  function updateNavigationContext() {
    const sidebar = $('#sidebar');
    const title = $('#pageTitle');
    if (!sidebar || !title) return;

    const active = $('.nav-link.active, .nav-links li a.active', sidebar);
    if (!active) return;
    const view = active.dataset.view || 'topology';
    const meta = viewMeta[view] || viewMeta.topology;
    const name = $('.page-name', title);
    const eyebrow = $('.page-eyebrow', title);
    if (name) name.textContent = meta.title;
    if (eyebrow) eyebrow.textContent = meta.eyebrow;
    $$('.nav-link', sidebar).forEach((link) => {
      if (link === active) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    });
  }

  function updateClock() {
    const clock = $('#ejiiClockChip');
    if (!clock) return;
    try {
      const now = new Date();
      const time = new Intl.DateTimeFormat('en-GB', {
        timeZone: 'Asia/Baku', hour: '2-digit', minute: '2-digit', hour12: false
      }).format(now);
      const date = new Intl.DateTimeFormat('en-GB', {
        timeZone: 'Asia/Baku', day: '2-digit', month: 'short', year: 'numeric'
      }).format(now);
      clock.textContent = time + ' · BAKU';
      clock.title = date + ' · Azerbaijan Time';
    } catch (_) {
      clock.textContent = new Date().toLocaleTimeString();
    }
  }

  function handleNavigationToggle() {
    const toggle = $('#ejiiShellToggle');
    if (window.matchMedia('(max-width: 850px)').matches) {
      document.body.classList.toggle('ejii-mobile-nav-open');
      toggle?.setAttribute('aria-expanded', String(document.body.classList.contains('ejii-mobile-nav-open')));
      return;
    }
    document.body.classList.toggle('ejii-sidebar-collapsed');
    const collapsed = document.body.classList.contains('ejii-sidebar-collapsed');
    toggle?.setAttribute('aria-expanded', String(!collapsed));
    try { localStorage.setItem('ejii_sidebar_collapsed', String(collapsed)); } catch (_) {}
  }

  function closeMobileNavigation() {
    if (!document.body.classList.contains('ejii-mobile-nav-open')) return;
    document.body.classList.remove('ejii-mobile-nav-open');
    $('#ejiiShellToggle')?.setAttribute('aria-expanded', 'false');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', setup, { once: true });
  } else {
    setup();
  }
})();
