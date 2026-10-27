/**
 * EJII Learning Center — Rich Content & Markdown Renderer
 * Converts lesson markdown, tables, diagrams, callouts, and knowledge checks into sanitized HTML.
 */

'use strict';

if (typeof window !== 'undefined') {
  window.EJIILearning = window.EJIILearning || {};
}

(function() {
  function escapeHtml(text) {
    if (!text) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function renderMarkdown(md) {
    if (!md || typeof md !== 'string') return '';

    let out = md;

    // Code blocks with syntax copy button
    out = out.replace(/```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g, (match, lang, code) => {
      const language = lang || 'text';
      const escapedCode = escapeHtml(code.trim());
      return `
        <div class="ejii-learning-codeblock">
          <div class="ejii-learning-codeblock-header">
            <span class="ejii-learning-codeblock-lang">${language}</span>
            <button class="ejii-learning-codeblock-copy" onclick="navigator.clipboard.writeText(decodeURIComponent('${encodeURIComponent(code.trim())}')); this.textContent = 'Copied!'; setTimeout(() => this.textContent = 'Copy', 1500);">Copy</button>
          </div>
          <pre class="ejii-learning-codeblock-pre"><code>${escapedCode}</code></pre>
        </div>
      `;
    });

    // Callouts / Alerts: > [!NOTE], > [!TIP], > [!WARNING], > [!IMPORTANT]
    out = out.replace(/^>\s*\[!(NOTE|TIP|WARNING|IMPORTANT|CAUTION)\]\s*([\s\S]*?)(?=(?:\n\s*\n|\n[^\s>]|$))/gm, (match, type, content) => {
      const alertType = type.toLowerCase();
      let calloutClass = 'ejii-learning-callout';
      if (alertType === 'tip') calloutClass += ' ejii-learning-callout--tip';
      if (alertType === 'warning' || alertType === 'caution') calloutClass += ' ejii-learning-callout--warning';

      return `<div class="${calloutClass}"><strong>${type}:</strong> ${content.trim().replace(/^>\s*/gm, '')}</div>`;
    });

    // Tables
    out = out.replace(/\|(.+)\|\n\|(?:\s*[-:]+[-| :]*)\|\n((?:\|.*\|\n?)*)/g, (match, headerRow, bodyRows) => {
      const headers = headerRow.split('|').filter(c => c.trim().length > 0).map(c => `<th>${c.trim()}</th>`).join('');
      const rows = bodyRows.trim().split('\n').map(row => {
        const cells = row.split('|').filter(c => c.trim().length > 0).map(c => `<td>${c.trim()}</td>`).join('');
        return `<tr>${cells}</tr>`;
      }).join('');
      return `<table class="ejii-learning-table"><thead><tr>${headers}</tr></thead><tbody>${rows}</tbody></table>`;
    });

    // Headers
    out = out.replace(/^### (.*$)/gim, '<h3>$1</h3>');
    out = out.replace(/^## (.*$)/gim, '<h2>$1</h2>');
    out = out.replace(/^# (.*$)/gim, '<h1>$1</h1>');

    // Bold & Italic
    out = out.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    out = out.replace(/\*(.*?)\*/g, '<em>$1</em>');

    // Inline code
    out = out.replace(/`([^`]+)`/g, '<code style="background: var(--bg-surface-hover, #efece6); padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 0.9em;">$1</code>');

    // Unordered lists
    out = out.replace(/^\s*[-*]\s+(.*)$/gim, '<li>$1</li>');
    out = out.replace(/(<li>.*<\/li>(\s*\n)?)+/g, '<ul>$&</ul>');

    // Paragraphs
    out = out.split(/\n\n+/).map(p => {
      const trimmed = p.trim();
      if (!trimmed) return '';
      if (trimmed.startsWith('<h') || trimmed.startsWith('<div') || trimmed.startsWith('<table') || trimmed.startsWith('<ul') || trimmed.startsWith('<ol')) {
        return trimmed;
      }
      return `<p>${trimmed}</p>`;
    }).join('\n');

    return out;
  }

  function renderBreadcrumbs(items) {
    if (!Array.isArray(items) || items.length === 0) return '';
    const breadcrumbHtml = items.map((item, idx) => {
      const isLast = idx === items.length - 1;
      if (isLast) {
        return `<span style="font-weight: 600; color: var(--text-primary);">${escapeHtml(item.label)}</span>`;
      }
      return `
        <a href="${escapeHtml(item.href)}" class="ejii-learning-breadcrumb-link">${escapeHtml(item.label)}</a>
        <span class="ejii-learning-breadcrumb-sep">&sol;</span>
      `;
    }).join('');

    return `
      <div class="ejii-learning-nav">
        <div class="ejii-learning-breadcrumbs">${breadcrumbHtml}</div>
        <div class="ejii-learning-nav-actions">
          <a href="#/learning" class="ejii-learning-btn ejii-learning-btn--secondary" style="font-size: 12px; padding: 4px 10px; min-height: 30px;">Academies Hub</a>
          <a href="#/learning/progress" class="ejii-learning-btn ejii-learning-btn--secondary" style="font-size: 12px; padding: 4px 10px; min-height: 30px;">My Progress</a>
        </div>
      </div>
    `;
  }

  function renderKnowledgeCheck(kc) {
    if (!kc || !kc.question || !Array.isArray(kc.options)) return '';

    return `
      <div class="ejii-learning-check" id="kc-block">
        <div class="ejii-learning-check-title">&#9670; INLINE KNOWLEDGE CHECK</div>
        <div class="ejii-learning-check-prompt">${escapeHtml(kc.question)}</div>
        <div class="ejii-learning-check-options">
          ${kc.options.map((opt, idx) => `
            <div class="ejii-learning-check-option" data-idx="${idx}" data-correct="${idx === kc.correctIndex}">
              <span style="font-weight: 600; font-family: monospace; color: var(--accent-primary);">${String.fromCharCode(65 + idx)}.</span>
              <span>${escapeHtml(opt)}</span>
            </div>
          `).join('')}
        </div>
        <div id="kc-feedback" style="margin-top: 12px; font-size: 13px; display: none;"></div>
      </div>
    `;
  }

  const Renderer = {
    escapeHtml,
    renderMarkdown,
    renderBreadcrumbs,
    renderKnowledgeCheck
  };

  if (typeof window !== 'undefined') {
    window.EJIILearning.Renderer = Renderer;
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = Renderer;
  }
})();
