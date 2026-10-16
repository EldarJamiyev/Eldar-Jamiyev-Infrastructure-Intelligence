const { db } = require('../../src/database/database');

function seedTaxesTicket() {
  const now = new Date().toISOString();
  const targetResolve = new Date(Date.now() + 120 * 60000).toISOString();

  const existing = db.prepare('SELECT id FROM helpdesk_tickets WHERE id = ?').get('TCK-2026-005');
  if (!existing) {
    db.prepare(`
      INSERT INTO helpdesk_tickets (
        id, ticket_number, title, description, category, priority, status,
        requester_name, requester_email, assigned_team, affected_ci_id,
        sla_policy_id, sla_target_response_at, sla_target_resolve_at, sla_breached,
        created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      'TCK-2026-005', 1005,
      'Poçt Serverinə Bağlantı Xətası: mail.taxes.gov.az (Port 443/587)',
      '[DƏQİQ PROBLEM BİLDİRİŞİ — Caspel / Dövlət Şəbəkəsi Standartı]\n• Mənbə IP (Source IP): 10.168.195.33\n• Hədəf IP / Host (Destination IP): mail.taxes.gov.az (10.22.12.204)\n• URL / Xidmət: https://mail.taxes.gov.az\n• Port Nömrəsi: 443 (HTTPS WebMail) / 587 (SMTP Submission)\n• Alınan Xəta Mesajı: Sorğu göndərilir, cavab alınmır (ETIMEDOUT / Connection Timed Out)\n• İlkin Vəziyyət: Əvvəl A IP (10.168.195.33) ünvanından B IP (mail.taxes.gov.az) ünvanına bağlantı mövcud idi, hazırda bağlantı qurulmur.',
      'incident', 'P2_HIGH', 'in_progress',
      'Eldar Jamiyev (İnfrastruktur Mühəndisi)', 'eldar.jamiyev@caspel.com', 'netops', 'CI-HW-SRV-01',
      'SLA-P2', now, targetResolve, 0, now, now
    );
  }

  const existingComment = db.prepare('SELECT id FROM ticket_comments WHERE id = ?').get('CMT-TAXES-01');
  if (!existingComment) {
    db.prepare(`
      INSERT INTO ticket_comments (id, ticket_id, user_id, author_name, is_internal, comment_text, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      'CMT-TAXES-01', 'TCK-2026-005', 'USR-NETADMIN-01', 'Network Administrator', 1,
      'Dəqiq bildiriş daxil oldu. DNS sorğusu 10.22.10.11 serverindən uğurla 10.22.12.204 IP-sini qaytardı. Lakin ICMP echo perimetr firewall tərəfindən drop edilir. TCP 443 portu açıqdır, lakin bəzi iş stansiyalarından marşrutlaşdırma yoxlanılır.',
      now
    );
  }
  console.log('Successfully seeded TCK-2026-005 for mail.taxes.gov.az');
}

seedTaxesTicket();
