/**
 * EJI Enterprise Database Access Layer
 * Proxies connection to the WAL-mode SQLite database engine.
 */

const { db, initSchema } = require('../db/database');

module.exports = {
  db,
  initSchema
};
