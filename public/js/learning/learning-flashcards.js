/**
 * EJII Learning Center — Interactive Revision Flashcards
 * Core engineering concept drill flashcards with flip card mechanics and recall filtering.
 */

'use strict';

if (typeof window !== 'undefined') {
  window.EJIILearning = window.EJIILearning || {};
}

(function() {
  const FLASHCARDS = [
    {
      category: 'Network Fundamentals',
      question: 'What is the exact functional distinction between Layer 2 MAC addresses and Layer 3 IP addresses?',
      answer: 'Layer 2 MAC addresses deliver frames hop-by-hop between directly connected network interfaces on the local broadcast domain and are rewritten at every Layer 3 routing hop. Layer 3 IP addresses provide end-to-end logical addressing and remain unchanged across intermediate routers.'
    },
    {
      category: 'Subnetting & Addressing',
      question: 'What is the usable host capacity and host address range of 192.168.10.64/26?',
      answer: 'Prefix /26 leaves 6 host bits (32 - 26 = 6). Total addresses: 2^6 = 64. Network address: 192.168.10.64. First usable host: 192.168.10.65. Last usable host: 192.168.10.126. Broadcast address: 192.168.10.127. Usable hosts: 62.'
    },
    {
      category: 'Switching & 802.1Q',
      question: 'What happens when an 802.1Q trunk receives an untagged Ethernet frame?',
      answer: 'The switch automatically assigns the untagged frame to the configured Native VLAN of that trunk port (default is VLAN 1 unless explicitly changed with "switchport trunk native vlan <id>"). If the native VLAN does not match on both sides of the trunk, CDP/STP generates an error.'
    },
    {
      category: 'IP Routing & FIB',
      question: 'In IP routing, if a destination matches a /24 OSPF route (AD 110) and a /25 eBGP route (AD 20), which route is chosen?',
      answer: 'The /25 eBGP route is chosen. Under the Longest-Prefix Match (LPM) rule, prefix length (most specific mask bits) ALWAYS takes precedence over Administrative Distance (AD). AD is only evaluated to break ties when prefix lengths are identical.'
    },
    {
      category: 'Windows & Active Directory',
      question: 'What is the Group Policy LSDOU evaluation order and what does it mean for conflicting settings?',
      answer: 'LSDOU order: 1. Local, 2. Site, 3. Domain, 4. Organizational Unit (OU), 5. Child OU. Policies evaluated later in the chain overwrite conflicting settings applied earlier, meaning Child OU settings override Domain settings unless Enforced is enabled.'
    },
    {
      category: 'Windows Permissions',
      question: 'When accessing a shared folder over SMB, how are Share Permissions and NTFS Permissions reconciled?',
      answer: 'The Effective Access is the MOST RESTRICTIVE combination of Share and NTFS permissions. Furthermore, within NTFS, an explicit Deny permission ALWAYS overrides any Allow permission regardless of group membership.'
    },
    {
      category: 'Linux Administration',
      question: 'What does systemd Exit Status 143 vs 137 indicate when analyzing service crashes via journalctl?',
      answer: 'Status 143 indicates the process was terminated cleanly by SIGTERM (128 + 15), usually initiated by systemctl stop or system shutdown. Status 137 indicates the process was forcefully killed by SIGKILL (128 + 9), frequently triggered by the Linux kernel Out-Of-Memory (OOM) Killer.'
    },
    {
      category: 'SRE & Systems Diagnostics',
      question: 'What is the mathematical definition of availability and how does "Four Nines" (99.99%) translate to allowed annual downtime?',
      answer: 'Availability = MTBF / (MTBF + MTTR). 99.99% availability ("Four Nines") permits a maximum of 52.6 minutes of unplanned downtime per year (or ~4.38 minutes per month).'
    }
  ];

  function renderFlashcards(containerEl) {
    if (!containerEl) return;

    let currentIndex = 0;
    let isFlipped = false;
    const renderer = window.EJIILearning.Renderer;

    const breadcrumbs = [
      { label: 'Learning Center', href: '#/learning' },
      { label: 'Revision Flashcards', href: '#/learning/flashcards' }
    ];

    function renderUI() {
      const card = FLASHCARDS[currentIndex];

      containerEl.innerHTML = `
        <div class="ejii-learning-container">
          ${renderer.renderBreadcrumbs(breadcrumbs)}

          <div class="ejii-learning-hero" style="padding: 24px;">
            <span class="ejii-learning-badge ejii-learning-badge--accent" style="margin-bottom: 8px;">RAPID ACTIVE RECALL</span>
            <h1 class="ejii-learning-hero-title">Engineering Revision Flashcards</h1>
            <p class="ejii-learning-hero-subtitle">
              High-yield technical flashcards for Cisco CCNA and Enterprise Systems Administration interview and certification prep.
            </p>
          </div>

          <!-- Flashcard Container -->
          <div style="max-width: 680px; margin: 24px auto;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
              <span class="ejii-learning-badge ejii-learning-badge--accent">${card.category}</span>
              <span style="font-size: 13px; color: var(--text-muted); font-weight: 600;">Card ${currentIndex + 1} of ${FLASHCARDS.length}</span>
            </div>

            <!-- Card Box -->
            <div id="flashcardBox" style="background: var(--bg-surface); border: 1px solid var(--border-default); border-radius: 12px; min-height: 260px; padding: 32px; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; cursor: pointer; box-shadow: 0 4px 16px rgba(0,0,0,0.06); transition: transform 0.2s ease, border-color 0.2s ease;">
              <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700; margin-bottom: 16px;">
                ${isFlipped ? '&#128065; Technical Solution & Explanation' : '&#10067; Engineering Concept Question (Click to Reveal)'}
              </div>

              <div style="font-size: 17px; font-weight: 600; line-height: 1.6; color: var(--text-primary); max-width: 580px;">
                ${isFlipped ? card.answer : card.question}
              </div>

              <div style="margin-top: 24px; font-size: 12px; color: var(--accent-primary); font-weight: 600;">
                ${isFlipped ? '&circlearrowleft; Click to see question' : '&circlearrowright; Click to flip card'}
              </div>
            </div>

            <!-- Controls Row -->
            <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 20px;">
              <button id="btnPrevCard" class="ejii-learning-btn ejii-learning-btn--secondary" ${currentIndex === 0 ? 'disabled' : ''}>
                &larr; Previous Card
              </button>
              <button id="btnFlipCard" class="ejii-learning-btn ejii-learning-btn--primary">
                ${isFlipped ? 'Show Question' : 'Reveal Answer'}
              </button>
              <button id="btnNextCard" class="ejii-learning-btn ejii-learning-btn--secondary" ${currentIndex === FLASHCARDS.length - 1 ? 'disabled' : ''}>
                Next Card &rarr;
              </button>
            </div>
          </div>
        </div>
      `;

      const cardBox = containerEl.querySelector('#flashcardBox');
      const btnFlip = containerEl.querySelector('#btnFlipCard');
      const btnPrev = containerEl.querySelector('#btnPrevCard');
      const btnNext = containerEl.querySelector('#btnNextCard');

      function flip() {
        isFlipped = !isFlipped;
        renderUI();
      }

      if (cardBox) cardBox.addEventListener('click', flip);
      if (btnFlip) btnFlip.addEventListener('click', flip);

      if (btnPrev) {
        btnPrev.addEventListener('click', () => {
          if (currentIndex > 0) {
            currentIndex--;
            isFlipped = false;
            renderUI();
          }
        });
      }

      if (btnNext) {
        btnNext.addEventListener('click', () => {
          if (currentIndex < FLASHCARDS.length - 1) {
            currentIndex++;
            isFlipped = false;
            renderUI();
          }
        });
      }
    }

    renderUI();
  }

  const FlashcardsView = {
    renderFlashcards,
    FLASHCARDS
  };

  if (typeof window !== 'undefined') {
    window.EJIILearning.FlashcardsView = FlashcardsView;
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = FlashcardsView;
  }
})();
