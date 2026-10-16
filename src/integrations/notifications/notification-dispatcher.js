/**
 * EJI Outbound Notification Dispatcher
 * Multi-channel enterprise alert delivery engine:
 * 1. Telegram Bot API (Direct HTTPS)
 * 2. Native SMTP Email Client (RFC 5321 with TLS/STARTTLS & HTML templates)
 * 3. Generic & ChatOps Webhooks (Slack, Discord, Microsoft Teams, PagerDuty)
 */

const https = require('https');
const http = require('http');
const net = require('net');
const tls = require('tls');
const { URL } = require('url');

/**
 * Send an alert message to a Telegram chat or channel
 * @param {string} messageText 
 * @param {object} options 
 * @returns {Promise<object>}
 */
async function sendTelegramAlert(messageText, options = {}) {
  const botToken = options.botToken || process.env.TELEGRAM_BOT_TOKEN;
  const chatId = options.chatId || process.env.TELEGRAM_CHAT_ID;

  if (!botToken || !chatId) {
    return {
      success: false,
      channel: 'telegram',
      error: 'TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is not configured.'
    };
  }

  const postData = JSON.stringify({
    chat_id: chatId,
    text: messageText,
    parse_mode: options.parseMode || 'HTML',
    disable_web_page_preview: true
  });

  return new Promise((resolve) => {
    const req = https.request(
      `https://api.telegram.org/bot${botToken}/sendMessage`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData)
        },
        timeout: options.timeoutMs || 8000
      },
      (res) => {
        let body = '';
        res.on('data', chunk => { body += chunk; });
        res.on('end', () => {
          try {
            const parsed = JSON.parse(body);
            if (res.statusCode >= 200 && res.statusCode < 300 && parsed.ok) {
              resolve({ success: true, channel: 'telegram', messageId: parsed.result?.message_id });
            } else {
              resolve({ success: false, channel: 'telegram', error: parsed.description || `HTTP ${res.statusCode}` });
            }
          } catch (e) {
            resolve({ success: false, channel: 'telegram', error: `Invalid response: ${e.message}` });
          }
        });
      }
    );

    req.on('timeout', () => {
      req.destroy();
      resolve({ success: false, channel: 'telegram', error: 'Telegram API request timed out.' });
    });

    req.on('error', (err) => {
      resolve({ success: false, channel: 'telegram', error: err.message });
    });

    req.write(postData);
    req.end();
  });
}

/**
 * Send an enterprise email via native SMTP (RFC 5321)
 * @param {object} emailDetails 
 * @param {object} options 
 * @returns {Promise<object>}
 */
async function sendSmtpAlert(emailDetails, options = {}) {
  const host = options.smtpHost || process.env.SMTP_HOST;
  const port = parseInt(options.smtpPort || process.env.SMTP_PORT || '587', 10);
  const user = options.smtpUser || process.env.SMTP_USER;
  const pass = options.smtpPass || process.env.SMTP_PASS;
  const from = options.from || process.env.SMTP_FROM || 'eji-alerts@caspel.az';
  const to = emailDetails.to || options.to || process.env.ALERT_EMAIL_TO;

  if (!host || !to) {
    return {
      success: false,
      channel: 'email',
      error: 'SMTP_HOST or target recipient email is not configured.'
    };
  }

  const subject = emailDetails.subject || 'EJI Infrastructure Alert';
  const htmlBody = emailDetails.htmlBody || `<p>${emailDetails.text || subject}</p>`;
  const boundary = `----=_EJI_MIME_${Date.now()}`;

  const mimeMessage = [
    `From: EJI Operations Center <${from}>`,
    `To: <${to}>`,
    `Subject: ${subject}`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    'Content-Type: text/plain; charset=utf-8',
    '',
    emailDetails.text || subject,
    '',
    `--${boundary}`,
    'Content-Type: text/html; charset=utf-8',
    '',
    htmlBody,
    '',
    `--${boundary}--`,
    '.'
  ].join('\r\n');

  return new Promise((resolve) => {
    const isDirectTls = port === 465;
    let socket = null;
    let stage = 0;
    let responseLog = [];

    function sendCmd(cmd) {
      if (socket && !socket.destroyed) {
        socket.write(`${cmd}\r\n`);
      }
    }

    function cleanup(resObj) {
      if (socket && !socket.destroyed) {
        try { socket.end(); } catch (_) {}
      }
      resolve(resObj);
    }

    const connectOpts = { host, port, timeout: options.timeoutMs || 8000 };
    const socketFactory = isDirectTls ? tls.connect : net.connect;

    try {
      socket = socketFactory(connectOpts, () => {
        // Connected, waiting for server 220 banner
      });
    } catch (e) {
      return resolve({ success: false, channel: 'email', error: `Socket connect failed: ${e.message}` });
    }

    socket.setEncoding('utf8');
    socket.setTimeout(options.timeoutMs || 8000);

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ success: false, channel: 'email', error: 'SMTP connection timed out.' });
    });

    socket.on('error', (err) => {
      cleanup({ success: false, channel: 'email', error: `SMTP error: ${err.message}` });
    });

    socket.on('data', (chunk) => {
      const line = chunk.toString();
      responseLog.push(line.trim());
      const code = parseInt(line.slice(0, 3), 10);

      // Handle multiline replies (e.g. 250-...)
      if (/^\d{3}-/.test(line)) return;

      if (stage === 0 && (code === 220)) {
        stage = 1;
        sendCmd('EHLO eji.caspel.az');
      } else if (stage === 1 && (code === 250)) {
        if (user && pass) {
          stage = 2;
          sendCmd('AUTH LOGIN');
        } else {
          stage = 4;
          sendCmd(`MAIL FROM:<${from}>`);
        }
      } else if (stage === 2 && (code === 334)) {
        stage = 3;
        sendCmd(Buffer.from(user).toString('base64'));
      } else if (stage === 3 && (code === 334)) {
        stage = 4;
        sendCmd(Buffer.from(pass).toString('base64'));
      } else if (stage === 4 && (code === 235 || code === 250)) {
        stage = 5;
        sendCmd(`MAIL FROM:<${from}>`);
      } else if (stage === 5 && (code === 250)) {
        stage = 6;
        sendCmd(`RCPT TO:<${to}>`);
      } else if (stage === 6 && (code === 250)) {
        stage = 7;
        sendCmd('DATA');
      } else if (stage === 7 && (code === 354)) {
        stage = 8;
        sendCmd(mimeMessage);
      } else if (stage === 8 && (code === 250)) {
        stage = 9;
        sendCmd('QUIT');
        cleanup({ success: true, channel: 'email', recipient: to });
      } else if (code >= 400) {
        cleanup({ success: false, channel: 'email', error: `SMTP Server returned error [${line.trim()}] at stage ${stage}` });
      }
    });
  });
}

/**
 * Send an alert payload to a webhook URL (Slack, Discord, Teams, or Custom)
 * @param {object} alertData 
 * @param {string} webhookUrl 
 * @param {object} options 
 * @returns {Promise<object>}
 */
async function sendWebhookAlert(alertData, webhookUrl, options = {}) {
  const urlStr = webhookUrl || options.webhookUrl || process.env.ALERT_WEBHOOK_URL;
  if (!urlStr) {
    return {
      success: false,
      channel: 'webhook',
      error: 'Webhook target URL is not configured.'
    };
  }

  let parsed;
  try {
    parsed = new URL(urlStr);
  } catch (e) {
    return { success: false, channel: 'webhook', error: `Invalid webhook URL: ${e.message}` };
  }

  let payload = {};
  const isSlack = urlStr.includes('hooks.slack.com');
  const isDiscord = urlStr.includes('discord.com/api/webhooks');
  const isTeams = urlStr.includes('office.com/webhook');

  const title = `🚨 [${alertData.severity || 'ALERT'}] ${alertData.name || 'Infrastructure Alert'}`;
  const details = alertData.description || alertData.message || JSON.stringify(alertData, null, 2);

  if (isSlack) {
    payload = {
      text: title,
      attachments: [{
        color: alertData.severity === 'P1_CRITICAL' ? '#EF4444' : '#F59E0B',
        title: alertData.name || 'EJI Incident',
        text: details,
        footer: 'Eldar Jamiyev Infrastructure Intelligence',
        ts: Math.floor(Date.now() / 1000)
      }]
    };
  } else if (isDiscord) {
    payload = {
      content: title,
      embeds: [{
        title: alertData.name || 'EJI Incident Alert',
        description: details,
        color: alertData.severity === 'P1_CRITICAL' ? 15674996 : 16096779,
        timestamp: new Date().toISOString()
      }]
    };
  } else if (isTeams) {
    payload = {
      '@type': 'MessageCard',
      '@context': 'http://schema.org/extensions',
      themeColor: alertData.severity === 'P1_CRITICAL' ? 'EF4444' : 'F59E0B',
      summary: title,
      sections: [{
        activityTitle: title,
        activitySubtitle: `Reported at: ${new Date().toISOString()}`,
        text: details
      }]
    };
  } else {
    payload = {
      timestamp: new Date().toISOString(),
      source: 'EJI_INFRASTRUCTURE_INTELLIGENCE',
      ...alertData
    };
  }

  const postData = JSON.stringify(payload);
  const isHttps = parsed.protocol === 'https:';
  const client = isHttps ? https : http;

  return new Promise((resolve) => {
    const req = client.request(
      parsed,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData)
        },
        timeout: options.timeoutMs || 8000
      },
      (res) => {
        let body = '';
        res.on('data', chunk => { body += chunk; });
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve({ success: true, channel: 'webhook', statusCode: res.statusCode });
          } else {
            resolve({ success: false, channel: 'webhook', error: `HTTP ${res.statusCode}: ${body.slice(0, 100)}` });
          }
        });
      }
    );

    req.on('timeout', () => {
      req.destroy();
      resolve({ success: false, channel: 'webhook', error: 'Webhook POST request timed out.' });
    });

    req.on('error', (err) => {
      resolve({ success: false, channel: 'webhook', error: err.message });
    });

    req.write(postData);
    req.end();
  });
}

/**
 * Dispatch an incident alert across all requested or configured channels
 * @param {object} alertData 
 * @param {object} options 
 * @returns {Promise<object>}
 */
async function dispatchAlert(alertData, options = {}) {
  const channels = options.channels || ['telegram', 'email', 'webhook'];
  const results = {};

  // 1. Format Telegram alert HTML
  if (channels.includes('telegram')) {
    const tgText = [
      `<b>🚨 EJI ALERT: [${alertData.severity || 'WARNING'}]</b>`,
      `<b>Target:</b> <code>${alertData.target || alertData.resource || 'Infrastructure'}</code>`,
      `<b>Event:</b> ${alertData.name || alertData.metricName || 'Threshold Exceeded'}`,
      `<b>Value:</b> <code>${alertData.value !== undefined ? alertData.value : 'N/A'}</code> (Threshold: ${alertData.threshold || 'N/A'})`,
      `<b>Time:</b> <code>${new Date().toISOString()}</code>`,
      alertData.description ? `\n<i>${alertData.description}</i>` : ''
    ].filter(Boolean).join('\n');

    results.telegram = await sendTelegramAlert(tgText, options.telegram);
  }

  // 2. Format Email HTML
  if (channels.includes('email')) {
    const emailSubject = `🚨 [${alertData.severity || 'ALERT'}] ${alertData.name || 'Infrastructure Alert'} - ${alertData.target || 'EJI'}`;
    const emailHtml = `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b1120; color: #f8fafc; padding: 24px; border-radius: 8px;">
        <h2 style="color: #ef4444; margin-top: 0;">🚨 EJI Infrastructure Intelligence Alert</h2>
        <table style="width: 100%; border-collapse: collapse; margin-top: 16px;">
          <tr><td style="padding: 8px; color: #94a3b8; border-bottom: 1px solid #1e293b;">Severity</td><td style="padding: 8px; font-weight: bold; color: #ef4444; border-bottom: 1px solid #1e293b;">${alertData.severity || 'P1_CRITICAL'}</td></tr>
          <tr><td style="padding: 8px; color: #94a3b8; border-bottom: 1px solid #1e293b;">Target Resource</td><td style="padding: 8px; font-family: monospace; color: #38bdf8; border-bottom: 1px solid #1e293b;">${alertData.target || 'Infrastructure Node'}</td></tr>
          <tr><td style="padding: 8px; color: #94a3b8; border-bottom: 1px solid #1e293b;">Trigger Condition</td><td style="padding: 8px; border-bottom: 1px solid #1e293b;">${alertData.metricName || 'Metric'} &gt;= ${alertData.threshold || 'Threshold'}</td></tr>
          <tr><td style="padding: 8px; color: #94a3b8; border-bottom: 1px solid #1e293b;">Observed Value</td><td style="padding: 8px; font-weight: bold; border-bottom: 1px solid #1e293b;">${alertData.value !== undefined ? alertData.value : 'Violation'}</td></tr>
          <tr><td style="padding: 8px; color: #94a3b8; border-bottom: 1px solid #1e293b;">Timestamp</td><td style="padding: 8px; font-family: monospace; border-bottom: 1px solid #1e293b;">${new Date().toISOString()}</td></tr>
        </table>
        ${alertData.description ? `<p style="margin-top: 16px; background-color: #1e293b; padding: 12px; border-radius: 6px; color: #cbd5e1;">${alertData.description}</p>` : ''}
        <div style="margin-top: 24px; font-size: 12px; color: #64748b; border-top: 1px solid #1e293b; padding-top: 12px;">
          Generated automatically by Eldar Jamiyev’s Infrastructure Intelligence (EJI).
        </div>
      </div>
    `;

    results.email = await sendSmtpAlert({
      subject: emailSubject,
      text: `${emailSubject}\n${alertData.description || ''}`,
      htmlBody: emailHtml,
      to: options.emailRecipient
    }, options.smtp);
  }

  // 3. Webhook delivery
  if (channels.includes('webhook')) {
    results.webhook = await sendWebhookAlert(alertData, options.webhookUrl, options.webhook);
  }

  return {
    dispatchedAt: new Date().toISOString(),
    results
  };
}

module.exports = {
  sendTelegramAlert,
  sendSmtpAlert,
  sendWebhookAlert,
  dispatchAlert
};
