/**
 * Lightweight Unprivileged NOC Activity Logger
 * Replaces heavy cryptographic HMAC audit chain with clean, fast console logging.
 */

function logAction({ userId, username, role, action, resource, details }) {
  const ts = new Date().toISOString();
  const detailStr = details ? ` - ${typeof details === 'object' ? JSON.stringify(details) : details}` : '';
  console.log(`[NOC Activity] ${ts} | ${action} on ${resource} by ${username || 'operator'}${detailStr}`);
  return { success: true, timestamp: ts };
}

module.exports = {
  logAction
};
