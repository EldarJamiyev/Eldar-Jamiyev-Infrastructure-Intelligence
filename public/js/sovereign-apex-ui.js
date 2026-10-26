/*
 * EJII Sovereign Apex UI controller — additive shell enhancements.
 * No API calls, telemetry fabrication, or replacements of existing view handlers.
 */
(function () {
  'use strict';

  const $ = (selector, root = document) => root.querySelector(selector);
  const createSvg = (paths) => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + paths + '</svg>';

  function init() {
    const sidebar = $('#sidebar');
    const topbar = $('.topbar');
    const pageTitle = $('#pageTitle');
    const stats = $('.topbar-stats');
    if (!sidebar || !topbar || !pageTitle || !stats) return;

    // A single real control adapts to an expandable desktop rail and an off-canvas mobile menu.
    if (!$('#ejiiShellToggle')) {
      const toggle = document.createElement('button');
      toggle.id = 'ejiiShellToggle';
      toggle.type = 'button';
      toggle.className = 'ejii-shell-toggle';
      toggle.setAttribute('aria-label', 'Toggle navigation');
      toggle.setAttribute('aria-controls', 'sidebar');
      toggle.setAttribute('aria-expanded', 'true');
      toggle.title = 'Toggle navigation rail';
      toggle.innerHTML = createSvg('<path d="M4 6h16M4 12h16M4 18h16"/>');
      pageTitle.insertBefore(toggle, pageTitle.firstChild);
      toggle.addEventListener('click', toggleNavigation);
    }

    if (!$('.ejii-mobile-scrim')) {
      const scrim = document.createElement('div');
      scrim.className = 'ejii-mobile-scrim';
      scrim.setAttribute('aria-hidden', 'true');
      document.body.appendChild(scrim);
      scrim.addEventListener('click', closeMobileNavigation);
    }

    if (!$('#ejiiLiveChip')) {
      const chip = document.createElement('div');
      chip.id = 'ejiiLiveChip';
      chip.className = 'ejii-live-chip';
      chip.dataset.state = 'connecting';
      chip.setAttribute('role', 'status');
      chip.setAttribute('aria-live', 'polite');
      chip.innerHTML = '<span class="ejii-live-led"></span><span class="ejii-chip-label">WebSocket</span><span class="ejii-live-text">Connecting</span>';
      const clock = document.createElement('div');
      clock.id = 'ejiiClockChip';
      clock.className = 'ejii-clock-chip';
      clock.setAttribute('aria-label', 'Current local time');
      clock.textContent = '--:--:-- AZT';
      const settingsButton = $('button[onclick*="openSettingsModal"]', topbar);
      stats.insertBefore(chip, stats.firstChild);
      stats.insertBefore(clock, settingsButton || stats.lastChild);
    }

    const updateClock = () => {
      const clock = $('#ejiiClockChip');
      if (!clock) return;
      try {
        const parts = new Intl.DateTimeFormat('en-GB', {
          timeZone: 'Asia/Baku', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
        }).format(new Date());
        clock.textContent = parts + ' AZT';
        clock.title = new Intl.DateTimeFormat('en-GB', {
          timeZone: 'Asia/Baku', dateStyle: 'full'
        }).format(new Date());
      } catch (_) {
        clock.textContent = new Date().toLocaleTimeString();
      }
    };
    updateClock();
    window.setInterval(updateClock, 1000);

    // Reuse the existing WebSocket status line as the source of truth for the new status chip.
    const connectionText = $('#wsStatusText');
    const connectionDot = $('.sidebar-footer .status-dot');
    const updateConnection = () => {
      const chip = $('#ejiiLiveChip');
      if (!chip) return;
      const text = (connectionText?.textContent || '').trim().toLowerCase();
      let state = 'connecting';
      let label = 'Connecting';
      if (text.includes('connected') && !text.includes('disconnected')) {
        state = 'connected';
        label = 'Live';
      } else if (text.includes('disconnected') || text.includes('reconnecting') || connectionDot?.style.backgroundColor === 'rgb(239, 68, 68)') {
        state = 'disconnected';
        label = 'Reconnecting';
      } else if (connectionDot?.style.backgroundColor === 'rgb(16, 185, 129)') {
        state = 'connected';
        label = 'Live';
      }
      chip.dataset.state = state;
      const statusText = $('.ejii-live-text', chip);
      if (statusText) statusText.textContent = label;
      chip.title = connectionText?.textContent?.trim() || 'WebSocket state';
    };
    updateConnection();
    if (connectionText && typeof MutationObserver !== 'undefined') {
      new MutationObserver(updateConnection).observe(connectionText, { childList: true, characterData: true, subtree: true });
    }
    if (connectionDot && typeof MutationObserver !== 'undefined') {
      new MutationObserver(updateConnection).observe(connectionDot, { attributes: true, attributeFilter: ['style', 'class'] });
    }

    // Keep header context aligned to the existing active navigation state (including palette navigation).
    const updatePageContext = () => {
      const active = $('.nav-link.active, .nav-links li a.active', sidebar);
      if (!active || !pageTitle) return;
      const label = $('.nav-label', active)?.textContent?.trim();
      const titleSpan = $(':scope > span', pageTitle);
      if (label && titleSpan) titleSpan.textContent = label;
      sidebar.querySelectorAll('.nav-link').forEach(link => {
        link.setAttribute('aria-current', link === active ? 'page' : 'false');
      });
    };
    updatePageContext();
    if (typeof MutationObserver !== 'undefined') {
      new MutationObserver(updatePageContext).observe(sidebar, { attributes: true, subtree: true, attributeFilter: ['class'] });
    }
    sidebar.addEventListener('click', event => {
      const link = event.target.closest('.nav-link');
      if (!link) return;
      if (window.matchMedia('(max-width: 900px)').matches) closeMobileNavigation();
      window.setTimeout(updatePageContext, 0);
    });

    document.addEventListener('keydown', event => {
      if (event.key === 'Escape') closeMobileNavigation();
    });

    // State restoration only affects the new navigation presentation layer.
    try {
      if (window.matchMedia('(max-width: 900px)').matches) {
        document.body.classList.remove('ejii-sidebar-collapsed');
      } else if (localStorage.getItem('ejii_sidebar_collapsed') === 'true') {
        document.body.classList.add('ejii-sidebar-collapsed');
        const toggle = $('#ejiiShellToggle');
        if (toggle) toggle.setAttribute('aria-expanded', 'false');
      }
    } catch (_) {}
  }

  function toggleNavigation() {
    const mobile = window.matchMedia('(max-width: 900px)').matches;
    if (mobile) {
      document.body.classList.toggle('ejii-mobile-nav-open');
      const open = document.body.classList.contains('ejii-mobile-nav-open');
      $('#ejiiShellToggle')?.setAttribute('aria-expanded', String(open));
      return;
    }
    document.body.classList.toggle('ejii-sidebar-collapsed');
    const collapsed = document.body.classList.contains('ejii-sidebar-collapsed');
    $('#ejiiShellToggle')?.setAttribute('aria-expanded', String(!collapsed));
    try { localStorage.setItem('ejii_sidebar_collapsed', String(collapsed)); } catch (_) {}
  }

  function closeMobileNavigation() {
    document.body.classList.remove('ejii-mobile-nav-open');
    const toggle = $('#ejiiShellToggle');
    if (toggle && window.matchMedia('(max-width: 900px)').matches) toggle.setAttribute('aria-expanded', 'false');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})();
