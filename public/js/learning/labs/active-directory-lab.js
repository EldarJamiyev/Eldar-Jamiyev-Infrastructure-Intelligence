/**
 * EJII Learning Center — Active Directory & Permissions Explorer Lab
 * Simulates OU hierarchies, group nesting, GPO LSDOU inheritance, and NTFS/Share effective access.
 * Mandate: Pure educational simulation.
 */

'use strict';

if (typeof window !== 'undefined') {
  window.EJIILearning = window.EJIILearning || {};
  window.EJIILearning.Labs = window.EJIILearning.Labs || {};
}

(function() {
  const DOMAIN_DATA = {
    domain: 'corp.ejii.local',
    users: [
      {
        id: 'alice',
        username: 'alice.smith',
        displayName: 'Alice Smith',
        ou: 'Engineering',
        title: 'Senior DevOps Engineer',
        groups: ['Domain Users', 'GG_DevOps_Engineers', 'GG_Production_Approvers']
      },
      {
        id: 'bob',
        username: 'bob.jones',
        displayName: 'Bob Jones',
        ou: 'Engineering',
        title: 'Junior Cloud Admin',
        groups: ['Domain Users', 'GG_DevOps_Engineers']
      },
      {
        id: 'carol',
        username: 'carol.white',
        displayName: 'Carol White',
        ou: 'Finance',
        title: 'Financial Auditor',
        groups: ['Domain Users', 'GG_Finance_Analysts']
      },
      {
        id: 'eldar',
        username: 'admin.eldar',
        displayName: 'Eldar Jamiyev (Domain Admin)',
        ou: 'IT_Admins',
        title: 'Enterprise Principal Architect',
        groups: ['Domain Users', 'Domain Admins', 'Enterprise Admins', 'Schema Admins']
      }
    ],
    gpos: [
      { id: 'gpo-local', name: '1. Local Computer Policy', scope: 'Local', precedence: 1, settings: ['Screen Timeout: 15 mins'] },
      { id: 'gpo-site', name: '2. Default Site Policy (HQ-Baku)', scope: 'Site', precedence: 2, settings: ['NTP Server: time.windows.com'] },
      { id: 'gpo-domain', name: '3. Default Domain Policy', scope: 'Domain', precedence: 3, settings: ['Min Password Length: 14', 'Account Lockout: 5 attempts', 'Kerberos Ticket Lifetime: 10 hrs'] },
      { id: 'gpo-eng', name: '4. GPO_Engineering_Workstations', scope: 'OU=Engineering', precedence: 4, settings: ['Developer Mode: Enabled', 'WSL2: Allowed', 'USB Storage: Read-Only'] },
      { id: 'gpo-fin', name: '4. GPO_Finance_Hardening', scope: 'OU=Finance', precedence: 4, settings: ['Restricted PowerShell (ConstrainedLanguage)', 'USB Storage: Blocked', 'Screen Lock: 5 mins'] },
      { id: 'gpo-admin', name: '4. GPO_Tier0_DomainAdmins', scope: 'OU=IT_Admins', precedence: 4, settings: ['MFA Smartcard Required', 'RDP Restricted to Jumpbox', 'Credential Guard: Enabled'] }
    ],
    shares: {
      '\\\\fs01\\Engineering': {
        name: 'Engineering Repository Share',
        shareAcl: {
          'Domain Users': 'Read',
          'GG_DevOps_Engineers': 'Change',
          'Domain Admins': 'Full Control'
        },
        ntfsAcl: {
          'Domain Users': 'Read & Execute',
          'GG_DevOps_Engineers': 'Modify',
          'GG_Production_Approvers': 'Full Control',
          'GG_Finance_Analysts': 'Deny Write',
          'Domain Admins': 'Full Control'
        }
      }
    }
  };

  function calculateEffectiveAccess(userId, sharePath) {
    const user = DOMAIN_DATA.users.find(u => u.id === userId || u.username === userId);
    if (!user) return { error: 'User not found in Active Directory database' };

    const share = DOMAIN_DATA.shares[sharePath] || DOMAIN_DATA.shares['\\\\fs01\\Engineering'];

    // Evaluate Share Permissions:
    // Order: Full Control > Change > Read > None
    let shareLevel = 'None';
    for (const group of user.groups) {
      const perm = share.shareAcl[group];
      if (perm === 'Full Control') shareLevel = 'Full Control';
      else if (perm === 'Change' && shareLevel !== 'Full Control') shareLevel = 'Change';
      else if (perm === 'Read' && shareLevel === 'None') shareLevel = 'Read';
    }

    // Evaluate NTFS Permissions:
    // Rule: Explicit Deny ALWAYS overrides Allow!
    let hasDenyWrite = false;
    let ntfsLevel = 'None';

    for (const group of user.groups) {
      const perm = share.ntfsAcl[group];
      if (perm === 'Deny Write') {
        hasDenyWrite = true;
      }
      if (perm === 'Full Control') ntfsLevel = 'Full Control';
      else if (perm === 'Modify' && ntfsLevel !== 'Full Control') ntfsLevel = 'Modify';
      else if (perm === 'Read & Execute' && ntfsLevel === 'None') ntfsLevel = 'Read & Execute';
    }

    // Effective Access is the MOST RESTRICTIVE between Share and NTFS!
    let effective = 'None';
    let rationale = '';

    if (shareLevel === 'None' || ntfsLevel === 'None') {
      effective = 'Access Denied';
      rationale = 'User has No Access in either Share or NTFS permissions.';
    } else if (hasDenyWrite) {
      effective = 'Read Only (Deny Override)';
      rationale = 'Explicit NTFS "Deny Write" applied via group membership overrides all Allow permissions.';
    } else if (shareLevel === 'Read' || ntfsLevel === 'Read & Execute') {
      effective = 'Read-Only';
      rationale = 'The most restrictive limit applies: Share level is ' + shareLevel + ', NTFS is ' + ntfsLevel + '.';
    } else if (shareLevel === 'Change' && (ntfsLevel === 'Modify' || ntfsLevel === 'Full Control')) {
      effective = 'Read, Write, Modify';
      rationale = 'Share allows Change and NTFS allows ' + ntfsLevel + '. User can create, modify, and delete files.';
    } else if (shareLevel === 'Full Control' && ntfsLevel === 'Full Control') {
      effective = 'Full Control (Ownership & Permissions)';
      rationale = 'Both Share and NTFS permit Full Control. User can manage ACLs and take ownership.';
    } else {
      effective = 'Read & Execute';
      rationale = 'Effective permissions constrained to Read & Execute by security bounds.';
    }

    return {
      user,
      shareName: share.name,
      sharePath,
      shareLevel,
      ntfsLevel,
      hasDenyWrite,
      effective,
      rationale
    };
  }

  function getLsdouPolicyChain(ouName) {
    const chain = [
      DOMAIN_DATA.gpos.find(g => g.scope === 'Local'),
      DOMAIN_DATA.gpos.find(g => g.scope === 'Site'),
      DOMAIN_DATA.gpos.find(g => g.scope === 'Domain')
    ];

    if (ouName === 'Engineering') {
      chain.push(DOMAIN_DATA.gpos.find(g => g.id === 'gpo-eng'));
    } else if (ouName === 'Finance') {
      chain.push(DOMAIN_DATA.gpos.find(g => g.id === 'gpo-fin'));
    } else if (ouName === 'IT_Admins') {
      chain.push(DOMAIN_DATA.gpos.find(g => g.id === 'gpo-admin'));
    }

    return chain.filter(Boolean);
  }

  function renderActiveDirectoryLab(containerEl) {
    if (!containerEl) return;

    let selectedUserId = 'alice';

    function renderUI() {
      const accessRes = calculateEffectiveAccess(selectedUserId, '\\\\fs01\\Engineering');
      const user = accessRes.user;
      const gpoChain = getLsdouPolicyChain(user.ou);

      containerEl.innerHTML = `
        <div class="ejii-learning-lab-header">
          <div>
            <span class="ejii-learning-badge ejii-learning-badge--accent">SIMULATED LAB</span>
            <span class="ejii-learning-badge" style="margin-left:8px;">Enterprise Active Directory</span>
            <h2 style="margin: 8px 0 4px; font-size: 20px;">Active Directory & Permissions Explorer</h2>
            <p style="margin: 0; color: var(--text-secondary); font-size: 13px;">
              Inspect OU hierarchy, group memberships, GPO LSDOU inheritance order, and calculate effective NTFS & Share permissions.
            </p>
          </div>
          <div style="display: flex; gap: 8px; align-items: center;">
            <label style="font-size: 12px; color: var(--text-secondary);">Select User:</label>
            <select id="selectAdUser" class="ejii-learning-input" style="width: auto; padding: 4px 10px;">
              ${DOMAIN_DATA.users.map(u => `
                <option value="${u.id}" ${u.id === selectedUserId ? 'selected' : ''}>${u.displayName} (${u.ou})</option>
              `).join('')}
            </select>
          </div>
        </div>

        <!-- User Identity Card -->
        <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px; margin-top: 16px;">
          <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 8px; margin-bottom: 12px;">
            <div>
              <span style="font-size: 16px; font-weight: 600; color: var(--text-primary);">${user.displayName}</span>
              <span style="font-size: 12px; color: var(--text-secondary); margin-left: 8px; font-family: monospace;">${user.username}@${DOMAIN_DATA.domain}</span>
            </div>
            <span class="ejii-learning-badge ejii-learning-badge--accent">OU: ${user.ou}</span>
          </div>
          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; font-size: 13px;">
            <div>
              <div style="color: var(--text-secondary); font-size: 11px; margin-bottom: 4px;">Job Title:</div>
              <div>${user.title}</div>
            </div>
            <div>
              <div style="color: var(--text-secondary); font-size: 11px; margin-bottom: 4px;">Security Group Memberships:</div>
              <div style="display: flex; gap: 6px; flex-wrap: wrap;">
                ${user.groups.map(g => `<span class="ejii-learning-badge" style="font-size: 11px; font-family: monospace;">${g}</span>`).join('')}
              </div>
            </div>
          </div>
        </div>

        <!-- Two Columns: GPO LSDOU vs Effective Permissions -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; margin-top: 16px;">
          <!-- GPO LSDOU Precedence -->
          <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px;">
            <div style="font-weight: 600; font-size: 14px; margin-bottom: 4px; color: #60a5fa;">
              GROUP POLICY PRECEDENCE (LSDOU ORDER)
            </div>
            <p style="font-size: 12px; color: var(--text-secondary); margin-bottom: 12px;">
              Applied in order: Local &rarr; Site &rarr; Domain &rarr; OU. Later policies overwrite earlier ones.
            </p>
            <div style="display: flex; flex-direction: column; gap: 10px;">
              ${gpoChain.map((gpo, idx) => `
                <div style="background: rgba(255,255,255,0.03); border-left: 3px solid #3b82f6; padding: 8px 12px; border-radius: 4px;">
                  <div style="display: flex; justify-content: space-between; font-size: 12px; font-weight: 600; margin-bottom: 4px;">
                    <span>${gpo.name}</span>
                    <span style="color: #60a5fa; font-size: 11px;">#${idx + 1} Evaluated</span>
                  </div>
                  <div style="font-size: 11px; color: var(--text-secondary);">
                    Settings: ${gpo.settings.join(' • ')}
                  </div>
                </div>
              `).join('')}
            </div>
          </div>

          <!-- Effective Permissions Calculator -->
          <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px;">
            <div style="font-weight: 600; font-size: 14px; margin-bottom: 4px; color: #34d399;">
              EFFECTIVE ACCESS CALCULATOR
            </div>
            <p style="font-size: 12px; color: var(--text-secondary); margin-bottom: 12px;">
              Target: <code style="color: var(--accent-color);">${accessRes.sharePath}</code>
            </p>

            <div style="display: flex; flex-direction: column; gap: 10px; font-size: 13px;">
              <div style="display: flex; justify-content: space-between; border-bottom: 1px solid var(--border-color); padding-bottom: 6px;">
                <span style="color: var(--text-secondary);">SMB Share Level:</span>
                <span style="font-weight: 600; color: #60a5fa;">${accessRes.shareLevel}</span>
              </div>
              <div style="display: flex; justify-content: space-between; border-bottom: 1px solid var(--border-color); padding-bottom: 6px;">
                <span style="color: var(--text-secondary);">NTFS File System Level:</span>
                <span style="font-weight: 600; color: #a78bfa;">${accessRes.ntfsLevel}</span>
              </div>
              <div style="display: flex; justify-content: space-between; border-bottom: 1px solid var(--border-color); padding-bottom: 6px;">
                <span style="color: var(--text-secondary);">Explicit Deny Applied:</span>
                <span style="font-weight: 600; color: ${accessRes.hasDenyWrite ? '#ef4444' : '#10b981'};">${accessRes.hasDenyWrite ? 'YES (Deny Write)' : 'None'}</span>
              </div>
              <div style="margin-top: 8px; background: rgba(16, 185, 129, 0.1); border: 1px solid #10b981; border-radius: 6px; padding: 10px;">
                <div style="font-size: 11px; text-transform: uppercase; color: #34d399; font-weight: 700; margin-bottom: 2px;">
                  Calculated Effective Access (Most Restrictive Rule)
                </div>
                <div style="font-size: 15px; font-weight: 700; color: #ffffff; margin-bottom: 4px;">
                  ${accessRes.effective}
                </div>
                <div style="font-size: 12px; color: var(--text-secondary);">
                  ${accessRes.rationale}
                </div>
              </div>
            </div>
          </div>
        </div>
      `;

      const selectUser = containerEl.querySelector('#selectAdUser');
      if (selectUser) {
        selectUser.addEventListener('change', (e) => {
          selectedUserId = e.target.value;
          renderUI();
        });
      }
    }

    renderUI();
  }

  if (typeof window !== 'undefined' && window.EJIILearning) {
    window.EJIILearning.Labs['sys-active-directory-lab'] = {
      render: renderActiveDirectoryLab,
      calculateEffectiveAccess,
      getLsdouPolicyChain,
      DOMAIN_DATA
    };
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      renderActiveDirectoryLab,
      calculateEffectiveAccess,
      getLsdouPolicyChain,
      DOMAIN_DATA
    };
  }
})();
