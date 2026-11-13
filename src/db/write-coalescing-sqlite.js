'use strict';

/**
 * EJII Project Atlas IV+ Evolution — Write-Coalescing & WAL Concurrency SQLite Adapter
 *
 * Eliminates `SQLITE_BUSY` lock-escalation storms under concurrent control-plane enrollments,
 * heartbeats, and incident writes by:
 *   1. Enforcing `PRAGMA journal_mode = WAL`, `PRAGMA synchronous = NORMAL`, and `PRAGMA busy_timeout`.
 *   2. True Write-Coalescing Batch Collection: collects all concurrent write transactions queued
 *      within the active microtask/batch window (`this.pendingQueue`, bounded by `maxQueueSize`)
 *      and flushes the entire collected batch atomically inside a single `SAVEPOINT` transaction
 *      (with isolated sub-savepoints per operation so an individual failing write rolls back cleanly
 *      without corrupting valid sibling writes in the batch, or atomic batch rollback when
 *      `atomicBatch: true` is requested).
 *   3. Synchronous Savepoint Execution (`runImmediateSavepointSync`) for synchronous callers like
 *      `ProjectAtlasEngine._runDbWrite`.
 *   4. Exponential Backoff + Full Jitter retry on transient `SQLITE_BUSY` / `SQLITE_LOCKED` errors.
 */

const ACTIVE_DB_ADAPTER_REGISTRY = new WeakMap();

class WriteCoalescingSqliteAdapter {
  constructor(db, options = {}) {
    this.db = db;
    this.busyTimeoutMs = Math.max(1000, Number(options.busyTimeoutMs) || 5000);
    this.maxRetries = Math.max(1, Number(options.maxRetries) || 5);
    this.baseBackoffMs = Math.max(2, Number(options.baseBackoffMs) || 10);
    this.maxQueueSize = Math.max(16, Number(options.maxQueueSize) || 2048);
    this.maxBatchSize = Math.max(1, Number(options.maxBatchSize) || 128);

    this.pendingQueue = []; // Array<{ operationName, writeFn, resolve, reject, enqueuedAt, options }>
    this.flushScheduled = false;
    this.flushing = false;
    this.savepointSeq = 0;
    this.shutdownState = 'ACTIVE'; // 'ACTIVE' | 'DRAINING' | 'SHUTDOWN'
    this.isShuttingDown = false;
    this.isClosed = false;

    if (db && typeof db === 'object') {
      let handleCoord = ACTIVE_DB_ADAPTER_REGISTRY.get(db);
      if (!handleCoord) {
        handleCoord = {
          registeredAdaptersCount: 0,
          activeSavepointDepth: 0,
          concurrentContentionCount: 0
        };
        ACTIVE_DB_ADAPTER_REGISTRY.set(db, handleCoord);
      }
      handleCoord.registeredAdaptersCount += 1;
      this._handleCoord = handleCoord;
    } else {
      this._handleCoord = null;
    }

    this.metrics = {
      coalescedWritesCount: 0,
      batchesFlushedCount: 0,
      multiItemBatchesCount: 0,
      maxObservedBatchSize: 0,
      syncSavepointsCount: 0,
      busyRetriesCount: 0,
      savepointRollbacksCount: 0,
      rollbackFailuresCount: 0,
      lastRollbackError: null,
      queueOverflowRejectionsCount: 0,
      shutdownRejectedWritesCount: 0,
      concurrentContentionCount: 0,
      lateSavepointMutationBlockedCount: 0,
      manualTransactionBlockedCount: 0,
      closeInSavepointBlockedCount: 0,
      asyncThenableRejectedCount: 0,
      walCheckpointStatus: null,
      lastPragmaStatus: null
    };

    this.applyOptimalPragmas();
  }

  _assertNoManualTransactionSql(sqlText, methodName, spName, operationName) {
    if (typeof sqlText !== 'string' || !sqlText.trim()) return;
    const stripped = sqlText
      .replace(/--[^\r\n]*/g, ' ')
      .replace(/\/\*[\s\S]*?\*\//g, ' ');
    const statements = stripped
      .split(';')
      .map((s) => s.trim())
      .filter(Boolean);
    const rawTxRegex =
      /^\s*(?:BEGIN\b|COMMIT\b|END\b|ROLLBACK\b|SAVEPOINT\b|RELEASE\b)/i;
    for (const stmt of statements) {
      if (rawTxRegex.test(stmt)) {
        this.metrics.manualTransactionBlockedCount += 1;
        const err = new Error(
          `Manual transaction or savepoint control statement ("${stmt}") is forbidden inside SQLite savepoint "${spName}" (${operationName}) via db.${methodName}().`
        );
        err.code = 'SQLITE_MANUAL_TRANSACTION_FORBIDDEN_IN_SAVEPOINT';
        throw err;
      }
    }
  }

  /**
   * Creates a savepoint-scoped proxy around `this.db` that invalidates immediately when
   * the savepoint releases or rolls back. Guards all `DatabaseSync` and wrapper methods,
   * blocks `close()` and raw `BEGIN/COMMIT/ROLLBACK/SAVEPOINT/RELEASE` statements inside savepoints,
   * prevents raw `StatementSync` escape via chainable methods (`setReadBigInts`, `setReturnArrays`,
   * `setAllowBareNamedParameters`), and wraps returned callables/sessions/iterators so nothing
   * can execute after savepoint completion.
   */
  _createSavepointScopedDbProxy(spName, operationName) {
    const state = { closed: false };
    const throwClosedError = (methodName) => {
      this.metrics.lateSavepointMutationBlockedCount += 1;
      const err = new Error(
        `SQLite savepoint "${spName}" for operation "${operationName}" has already closed. Late out-of-savepoint call to db.${methodName}() from an unawaited async continuation is forbidden.`
      );
      err.code = 'SQLITE_SAVEPOINT_ALREADY_CLOSED_LATE_MUTATION_FORBIDDEN';
      throw err;
    };

    const wrapDependentValue = (rawVal, labelPrefix, selfTarget = null, selfProxy = null) => {
      if (rawVal === null || rawVal === undefined) return rawVal;
      if (selfTarget && rawVal === selfTarget && selfProxy) {
        return selfProxy;
      }
      if (typeof rawVal === 'function') {
        return (...fnArgs) => {
          if (state.closed) {
            throwClosedError(labelPrefix);
          }
          const out = rawVal(...fnArgs);
          return wrapDependentValue(out, labelPrefix);
        };
      }
      if (typeof rawVal === 'object' && !Buffer.isBuffer(rawVal) && !(rawVal instanceof Uint8Array)) {
        let objProxy = null;
        objProxy = new Proxy(rawVal, {
          get: (objTarget, objProp, objReceiver) => {
            if (state.closed) {
              throwClosedError(`${labelPrefix}.${String(objProp)}`);
            }
            const propVal = Reflect.get(objTarget, objProp, objReceiver);
            if (typeof propVal === 'function') {
              return (...mArgs) => {
                if (state.closed) {
                  throwClosedError(`${labelPrefix}.${String(objProp)}`);
                }
                const out = propVal.apply(objTarget, mArgs);
                if (out === objTarget) return objProxy;
                return wrapDependentValue(out, `${labelPrefix}.${String(objProp)}`, objTarget, objProxy);
              };
            }
            return propVal;
          }
        });
        return objProxy;
      }
      return rawVal;
    };

    const wrapIterator = (rawIterator) => {
      if (!rawIterator || typeof rawIterator !== 'object') return rawIterator;
      const iteratorProxy = new Proxy(rawIterator, {
        get: (iterTarget, iterProp, iterReceiver) => {
          if (iterProp === 'next' || iterProp === 'return' || iterProp === 'throw') {
            return (...iterArgs) => {
              if (state.closed) {
                throwClosedError(`statement.iterate.${String(iterProp)}`);
              }
              const fn = Reflect.get(iterTarget, iterProp, iterTarget);
              if (typeof fn !== 'function') {
                return { value: undefined, done: true };
              }
              return fn.apply(iterTarget, iterArgs);
            };
          }
          if (iterProp === Symbol.iterator) {
            return () => {
              if (state.closed) {
                throwClosedError('statement.iterate[Symbol.iterator]');
              }
              return iteratorProxy;
            };
          }
          const val = Reflect.get(iterTarget, iterProp, iterReceiver);
          return typeof val === 'function' ? val.bind(iterTarget) : val;
        }
      });
      return iteratorProxy;
    };

    const wrapStatement = (stmt) => {
      if (!stmt || typeof stmt !== 'object') return stmt;
      let stmtProxy = null;
      stmtProxy = new Proxy(stmt, {
        get: (target, prop, receiver) => {
          if (state.closed) {
            throwClosedError(`statement.${String(prop)}`);
          }
          if (prop === 'iterate') {
            return (...args) => {
              if (state.closed) {
                throwClosedError('statement.iterate');
              }
              const rawIter = Reflect.get(target, 'iterate', target).apply(target, args);
              return wrapIterator(rawIter);
            };
          }
          if (prop === 'run' || prop === 'get' || prop === 'all') {
            return (...args) => {
              if (state.closed) {
                throwClosedError(`statement.${String(prop)}`);
              }
              return Reflect.get(target, prop, target).apply(target, args);
            };
          }
          const val = Reflect.get(target, prop, receiver);
          if (typeof val === 'function') {
            return (...args) => {
              if (state.closed) {
                throwClosedError(`statement.${String(prop)}`);
              }
              const res = val.apply(target, args);
              // Prevent raw StatementSync reference escape and preserve chaining on configuration methods
              if (
                res === target ||
                ((prop === 'setReturnArrays' ||
                  prop === 'setReadBigInts' ||
                  prop === 'setAllowBareNamedParameters') &&
                  res === undefined)
              ) {
                return stmtProxy;
              }
              return res;
            };
          }
          return val;
        }
      });
      return stmtProxy;
    };

    const guardedDbMethods = new Set([
      'exec',
      'prepare',
      'close',
      'open',
      'enableLoadExtension',
      'function',
      'aggregate',
      'createSession',
      'applyChangeset',
      'pragma',
      'transaction',
      'backup',
      'serialize',
      'table',
      'loadExtension'
    ]);

    let proxy = null;
    proxy = new Proxy(this.db, {
      get: (target, prop, receiver) => {
        if (prop === '__savepointClosed') return state.closed;
        if (prop === 'close') {
          return () => {
            if (state.closed) {
              throwClosedError('close');
            }
            this.metrics.closeInSavepointBlockedCount += 1;
            const err = new Error(
              `Closing the SQLite database handle is forbidden inside active savepoint "${spName}" (${operationName}).`
            );
            err.code = 'SQLITE_CLOSE_FORBIDDEN_IN_SAVEPOINT';
            throw err;
          };
        }
        if (prop === 'prepare') {
          return (...args) => {
            if (state.closed) {
              throwClosedError('prepare');
            }
            this._assertNoManualTransactionSql(args[0], 'prepare', spName, operationName);
            const stmt = target.prepare(...args);
            return wrapStatement(stmt);
          };
        }
        if (prop === 'exec') {
          return (...args) => {
            if (state.closed) {
              throwClosedError('exec');
            }
            this._assertNoManualTransactionSql(args[0], 'exec', spName, operationName);
            const res = target.exec(...args);
            return res === target ? proxy : res;
          };
        }
        if (guardedDbMethods.has(String(prop))) {
          return (...args) => {
            if (state.closed) {
              throwClosedError(String(prop));
            }
            const fn = Reflect.get(target, prop, target);
            if (typeof fn !== 'function') {
              const unsupportedErr = new Error(
                `Method db.${String(prop)}() is not supported on the underlying SQLite handle inside savepoint "${spName}".`
              );
              unsupportedErr.code = 'SQLITE_METHOD_NOT_SUPPORTED_IN_SAVEPOINT';
              throw unsupportedErr;
            }
            const out = fn.apply(target, args);
            if (out === target) return proxy;
            return wrapDependentValue(out, String(prop), target, proxy);
          };
        }
        if (state.closed) {
          throwClosedError(String(prop));
        }
        const val = Reflect.get(target, prop, receiver);
        if (typeof val === 'function') {
          return (...args) => {
            if (state.closed) {
              throwClosedError(String(prop));
            }
            const out = val.apply(target, args);
            if (out === target) return proxy;
            return wrapDependentValue(out, String(prop), target, proxy);
          };
        }
        return val;
      }
    });

    return {
      scopedDb: proxy,
      revoke: () => {
        state.closed = true;
      }
    };
  }

  applyOptimalPragmas() {
    if (!this.db || typeof this.db.pragma !== 'function') {
      return { applied: false, reason: 'NO_PRAGMA_SUPPORT' };
    }
    try {
      const journalMode = this.db.pragma('journal_mode = WAL', { simple: true });
      this.db.pragma('synchronous = NORMAL');
      this.db.pragma(`busy_timeout = ${this.busyTimeoutMs}`);
      this.db.pragma('foreign_keys = ON');
      this.metrics.lastPragmaStatus = {
        applied: true,
        journalMode: String(journalMode || 'wal').toUpperCase(),
        synchronous: 'NORMAL',
        busyTimeoutMs: this.busyTimeoutMs
      };
      return this.metrics.lastPragmaStatus;
    } catch (err) {
      this.metrics.lastPragmaStatus = {
        applied: false,
        error: err && err.message ? err.message : String(err)
      };
      return this.metrics.lastPragmaStatus;
    }
  }

  _isTransientBusyError(err) {
    const code = String((err && err.code) || '');
    const msg = String((err && err.message) || '');
    return (
      code === 'SQLITE_BUSY' ||
      code === 'SQLITE_LOCKED' ||
      code.startsWith('SQLITE_BUSY_') ||
      code.startsWith('SQLITE_LOCKED_') ||
      msg.includes('database is locked') ||
      msg.includes('SQLITE_BUSY')
    );
  }

  _classifyDatabaseError(err) {
    const code = String((err && err.code) || '');
    const msg = String((err && err.message) || '');
    if (this._isTransientBusyError(err)) return 'TRANSIENT_CONTENTION_BUSY_OR_LOCKED';
    if (code === 'SQLITE_FULL' || msg.includes('database or disk is full') || msg.includes('ENOSPC')) {
      return 'STORAGE_EXHAUSTED_DISK_FULL';
    }
    if (code.startsWith('SQLITE_IOERR') || msg.includes('disk I/O error')) {
      return 'INTERRUPTED_DISK_IO_ERROR';
    }
    if (code === 'SQLITE_CORRUPT' || msg.includes('malformed')) {
      return 'DATABASE_CORRUPTION_DETECTED';
    }
    return 'TERMINAL_SQL_EXECUTION_FAILURE';
  }

  /**
   * Synchronously executes a write operation inside a named SQLite SAVEPOINT with automatic
   * rollback on failure. Strictly forbids async/Promise-returning writeFn callbacks so a callback
   * can never outlive its SQLite SAVEPOINT transaction, rolling back any synchronous mutations
   * immediately if a thenable is returned.
   */
  runImmediateSavepointSync(operationName, writeFn) {
    if (this.isShuttingDown || this.isClosed || this.shutdownState !== 'ACTIVE') {
      this.metrics.shutdownRejectedWritesCount += 1;
      const shutdownErr = new Error(
        `SQLite adapter is ${this.shutdownState}; rejecting new synchronous savepoint "${operationName}".`
      );
      shutdownErr.code = 'SQLITE_ADAPTER_SHUTTING_DOWN';
      throw shutdownErr;
    }
    if (!this.db || typeof this.db.prepare !== 'function') {
      return { persisted: false, status: 'IN_MEMORY_NO_DB' };
    }
    if (typeof writeFn !== 'function') {
      throw new TypeError('writeFn must be a synchronous function');
    }
    if (writeFn.constructor && writeFn.constructor.name === 'AsyncFunction') {
      this.metrics.asyncThenableRejectedCount += 1;
      const asyncErr = new Error(
        `Asynchronous callback forbidden inside SQLite savepoint (${operationName}): writeFn is an AsyncFunction and cannot outlive savepoint transaction.`
      );
      asyncErr.code = 'SQLITE_ASYNC_CALLBACK_FORBIDDEN_IN_SAVEPOINT';
      throw asyncErr;
    }
    if (this._handleCoord) {
      if (this._handleCoord.activeSavepointDepth > 0 || this.flushing) {
        this._handleCoord.concurrentContentionCount += 1;
        this.metrics.concurrentContentionCount += 1;
      }
      this._handleCoord.activeSavepointDepth += 1;
    }
    this.savepointSeq += 1;
    const spName = `sp_sync_${String(operationName || 'op').replace(/[^a-zA-Z0-9_]/g, '_')}_${this.savepointSeq}`;
    const canSavepoint = typeof this.db.exec === 'function';

    try {
      let attempt = 0;
      while (attempt <= this.maxRetries) {
        const { scopedDb, revoke } = this._createSavepointScopedDbProxy(spName, operationName);
        try {
          if (canSavepoint) this.db.exec(`SAVEPOINT ${spName}`);
          const value = writeFn(scopedDb);
          if (value && (typeof value === 'object' || typeof value === 'function') && typeof value.then === 'function') {
            this.metrics.asyncThenableRejectedCount += 1;
            try {
              if (typeof value.catch === 'function') value.catch(() => {});
            } catch (_) {}
            const asyncErr = new Error(
              `Asynchronous callback forbidden inside SQLite savepoint "${spName}" (${operationName}): callback returned a thenable/Promise and cannot outlive savepoint transaction.`
            );
            asyncErr.code = 'SQLITE_ASYNC_CALLBACK_FORBIDDEN_IN_SAVEPOINT';
            throw asyncErr;
          }
          if (canSavepoint) this.db.exec(`RELEASE SAVEPOINT ${spName}`);
          this.metrics.syncSavepointsCount += 1;
          return {
            persisted: true,
            executionMode: 'IMMEDIATE_SYNCHRONOUS_SAVEPOINT',
            status: 'DURABLE_SQLITE_SYNCED',
            savepoint: spName,
            value
          };
        } catch (err) {
          let rollbackFailed = false;
          if (canSavepoint) {
            try {
              this.db.exec(`ROLLBACK TO SAVEPOINT ${spName}`);
              this.db.exec(`RELEASE SAVEPOINT ${spName}`);
              this.metrics.savepointRollbacksCount += 1;
            } catch (rbErr) {
              rollbackFailed = true;
              this.metrics.rollbackFailuresCount += 1;
              const rbMsg = rbErr && rbErr.message ? rbErr.message : String(rbErr);
              this.metrics.lastRollbackError = rbMsg;
              err.rollbackError = rbMsg;
            }
          }
          err.failureClassification = rollbackFailed ? 'ROLLBACK_FAILED' : this._classifyDatabaseError(err);
          if (!rollbackFailed && this._isTransientBusyError(err) && attempt < this.maxRetries) {
            attempt += 1;
            this.metrics.busyRetriesCount += 1;
            continue;
          }
          throw err;
        } finally {
          revoke();
        }
      }
    } finally {
      if (this._handleCoord) {
        this._handleCoord.activeSavepointDepth = Math.max(0, this._handleCoord.activeSavepointDepth - 1);
      }
    }
  }

  /**
   * Enqueues a write transaction into the coalescing batch queue. All writes enqueued within the
   * current microtask window are collected and flushed together in a single outer `SAVEPOINT` batch.
   */
  enqueueWriteTransaction(operationName, writeFn, options = {}) {
    if (this.isShuttingDown || this.isClosed || this.shutdownState !== 'ACTIVE') {
      this.metrics.shutdownRejectedWritesCount += 1;
      const shutdownErr = new Error(
        `SQLite adapter is ${this.shutdownState}; rejecting new queued write "${operationName}".`
      );
      shutdownErr.code = 'SQLITE_ADAPTER_SHUTTING_DOWN';
      return Promise.reject(shutdownErr);
    }
    if (typeof writeFn !== 'function') {
      return Promise.reject(new TypeError('writeFn must be a function'));
    }

    if (this.pendingQueue.length >= this.maxQueueSize) {
      this.metrics.queueOverflowRejectionsCount += 1;
      const overflowErr = new Error(
        `WriteCoalescingSqliteAdapter queue capacity exceeded (maxQueueSize=${this.maxQueueSize}) during ${operationName}`
      );
      overflowErr.code = 'SQLITE_QUEUE_CAPACITY_EXCEEDED';
      overflowErr.legacyCode = 'SQLITE_COALESCER_QUEUE_OVERFLOW';
      return Promise.reject(overflowErr);
    }

    return new Promise((resolve, reject) => {
      this.pendingQueue.push({
        operationName: String(operationName || 'tx'),
        writeFn,
        options,
        enqueuedAt: Date.now(),
        resolve,
        reject
      });

      this._scheduleBatchFlush();
    });
  }

  _scheduleBatchFlush() {
    if (this.flushScheduled || this.flushing) return;
    this.flushScheduled = true;
    queueMicrotask(() => {
      this.flushScheduled = false;
      this._flushPendingQueue().catch(() => {});
    });
  }

  async _flushPendingQueue() {
    if (this.flushing) return;
    this.flushing = true;

    try {
      while (this.pendingQueue.length > 0) {
        const batch = this.pendingQueue.splice(0, this.maxBatchSize);
        await this._executeBatchWithRetry(batch);
      }
    } finally {
      this.flushing = false;
      if (this.pendingQueue.length > 0) {
        this._scheduleBatchFlush();
      }
    }
  }

  async _executeBatchWithRetry(batch) {
    if (!this.db) {
      for (const item of batch) {
        item.reject(new Error('Database instance is not initialized'));
      }
      return;
    }

    let attempt = 0;
    const canSavepoint = typeof this.db.exec === 'function';

    while (attempt <= this.maxRetries) {
      this.savepointSeq += 1;
      const batchSpName = `sp_batch_${this.savepointSeq}`;
      const batchSize = batch.length;
      const isAtomicBatch = batch.some((item) => item.options && item.options.atomicBatch === true);

      if (this._handleCoord) {
        if (this._handleCoord.activeSavepointDepth > 0) {
          this._handleCoord.concurrentContentionCount += 1;
          this.metrics.concurrentContentionCount += 1;
        }
        this._handleCoord.activeSavepointDepth += 1;
      }

      try {
        if (canSavepoint) {
          this.db.exec(`SAVEPOINT ${batchSpName}`);
        }

        const itemOutcomes = [];
        for (let i = 0; i < batch.length; i++) {
          const item = batch[i];
          const itemSpName = `${batchSpName}_item_${i}`;
          const { scopedDb: itemScopedDb, revoke: revokeItemDb } = this._createSavepointScopedDbProxy(
            itemSpName,
            item.operationName
          );
          try {
            if (item.writeFn.constructor && item.writeFn.constructor.name === 'AsyncFunction') {
              this.metrics.asyncThenableRejectedCount += 1;
              const asyncErr = new Error(
                `Asynchronous callback forbidden inside coalesced SQLite savepoint "${itemSpName}" (${item.operationName}): writeFn is an AsyncFunction.`
              );
              asyncErr.code = 'SQLITE_ASYNC_CALLBACK_FORBIDDEN_IN_SAVEPOINT';
              throw asyncErr;
            }
            if (canSavepoint && !isAtomicBatch && batch.length > 1) {
              this.db.exec(`SAVEPOINT ${itemSpName}`);
            }
            const val = item.writeFn(itemScopedDb);
            if (val && (typeof val === 'object' || typeof val === 'function') && typeof val.then === 'function') {
              this.metrics.asyncThenableRejectedCount += 1;
              try {
                if (typeof val.catch === 'function') val.catch(() => {});
              } catch (_) {}
              const asyncErr = new Error(
                `Asynchronous callback forbidden inside coalesced SQLite savepoint "${itemSpName}" (${item.operationName}): callback returned a thenable/Promise and cannot outlive savepoint transaction.`
              );
              asyncErr.code = 'SQLITE_ASYNC_CALLBACK_FORBIDDEN_IN_SAVEPOINT';
              throw asyncErr;
            }
            if (canSavepoint && !isAtomicBatch && batch.length > 1) {
              this.db.exec(`RELEASE SAVEPOINT ${itemSpName}`);
            }
            itemOutcomes.push({ ok: true, value: val, itemSpName });
          } catch (itemErr) {
            itemErr.failureClassification = this._classifyDatabaseError(itemErr);
            if (this._isTransientBusyError(itemErr)) {
              throw itemErr; // Trigger full batch retry with backoff
            }
            if (isAtomicBatch || batch.length === 1) {
              throw itemErr; // Roll back the entire batch savepoint
            }
            if (canSavepoint) {
              try {
                this.db.exec(`ROLLBACK TO SAVEPOINT ${itemSpName}`);
                this.db.exec(`RELEASE SAVEPOINT ${itemSpName}`);
                this.metrics.savepointRollbacksCount += 1;
              } catch (rbErr) {
                this.metrics.rollbackFailuresCount += 1;
                const rbMsg = rbErr && rbErr.message ? rbErr.message : String(rbErr);
                this.metrics.lastRollbackError = rbMsg;
                itemErr.rollbackError = rbMsg;
                itemErr.failureClassification = 'ROLLBACK_FAILED';
              }
            }
            itemOutcomes.push({ ok: false, error: itemErr, itemSpName });
          } finally {
            revokeItemDb();
          }
        }

        if (canSavepoint) {
          this.db.exec(`RELEASE SAVEPOINT ${batchSpName}`);
        }

        this.metrics.batchesFlushedCount += 1;
        if (batchSize > 1) {
          this.metrics.multiItemBatchesCount += 1;
        }
        if (batchSize > this.metrics.maxObservedBatchSize) {
          this.metrics.maxObservedBatchSize = batchSize;
        }

        const succeededItemsCount = itemOutcomes.filter((x) => x.ok).length;
        const failedItemsCount = batchSize - succeededItemsCount;
        const batchOutcomeStatus =
          failedItemsCount === 0
            ? 'ALL_ITEMS_COMMITTED'
            : succeededItemsCount > 0
              ? 'PARTIAL_BATCH_COMMITTED'
              : 'ALL_ITEMS_ROLLED_BACK';

        for (let i = 0; i < batch.length; i++) {
          const item = batch[i];
          const outcome = itemOutcomes[i];
          if (outcome.ok) {
            this.metrics.coalescedWritesCount += 1;
            item.resolve({
              persisted: true,
              executionMode: 'ASYNC_COALESCED_BATCH_SAVEPOINT',
              batchOutcomeStatus,
              operationName: item.operationName,
              savepoint: batchSpName,
              batchSize,
              succeededItemsCount,
              failedItemsCount,
              attempts: attempt + 1,
              value: outcome.value
            });
          } else {
            item.reject(outcome.error);
          }
        }
        return;
      } catch (err) {
        let rollbackFailed = false;
        if (canSavepoint) {
          try {
            this.db.exec(`ROLLBACK TO SAVEPOINT ${batchSpName}`);
            this.db.exec(`RELEASE SAVEPOINT ${batchSpName}`);
            this.metrics.savepointRollbacksCount += 1;
          } catch (rbErr) {
            rollbackFailed = true;
            this.metrics.rollbackFailuresCount += 1;
            const rbMsg = rbErr && rbErr.message ? rbErr.message : String(rbErr);
            this.metrics.lastRollbackError = rbMsg;
            err.rollbackError = rbMsg;
          }
        }
        err.failureClassification = rollbackFailed ? 'ROLLBACK_FAILED' : this._classifyDatabaseError(err);

        if (!rollbackFailed && this._isTransientBusyError(err) && attempt < this.maxRetries) {
          attempt += 1;
          this.metrics.busyRetriesCount += 1;
          const capMs = Math.min(250, this.baseBackoffMs * Math.pow(2, attempt));
          const sleepMs = Math.max(1, Math.floor(Math.random() * capMs));
          await new Promise((r) => setTimeout(r, sleepMs));
          continue;
        }

        for (const item of batch) {
          item.reject(err);
        }
        return;
      } finally {
        if (this._handleCoord) {
          this._handleCoord.activeSavepointDepth = Math.max(0, this._handleCoord.activeSavepointDepth - 1);
        }
      }
    }
  }

  /**
   * Gracefully drains all pending queued write batches, optionally runs a passive WAL checkpoint,
   * and transitions the adapter to SHUTDOWN state so no new writes can be accepted.
   */
  async drainAndShutdown(options = {}) {
    if (this.isClosed && this.shutdownState === 'SHUTDOWN') {
      return {
        drained: true,
        shutdownState: this.shutdownState,
        flushedPendingCount: 0,
        walCheckpointStatus: this.metrics.walCheckpointStatus
      };
    }
    this.isShuttingDown = true;
    this.shutdownState = 'DRAINING';
    const initialPending = this.pendingQueue.length;

    while (this.pendingQueue.length > 0 || this.flushing) {
      await this._flushPendingQueue();
      if (this.pendingQueue.length > 0 || this.flushing) {
        await new Promise((r) => setImmediate(r));
      }
    }

    if (options.checkpointWal !== false && this.db) {
      try {
        if (typeof this.db.pragma === 'function') {
          this.db.pragma('wal_checkpoint(PASSIVE)');
          this.metrics.walCheckpointStatus = 'CHECKPOINT_PASSIVE_OK';
        } else if (typeof this.db.exec === 'function') {
          this.db.exec('PRAGMA wal_checkpoint(PASSIVE)');
          this.metrics.walCheckpointStatus = 'CHECKPOINT_PASSIVE_OK';
        }
      } catch (cpErr) {
        this.metrics.walCheckpointStatus = `CHECKPOINT_ERROR: ${cpErr.message || String(cpErr)}`;
      }
    }

    if (this._handleCoord) {
      this._handleCoord.registeredAdaptersCount = Math.max(0, this._handleCoord.registeredAdaptersCount - 1);
      if (this._handleCoord.registeredAdaptersCount === 0) {
        ACTIVE_DB_ADAPTER_REGISTRY.delete(this.db);
      }
    }

    const canCloseUnderlying =
      options.closeUnderlyingDb === true &&
      this.db &&
      typeof this.db.close === 'function' &&
      (!this._handleCoord || this._handleCoord.registeredAdaptersCount === 0);

    if (canCloseUnderlying) {
      try {
        this.db.close();
      } catch (_) {}
    }

    this.isClosed = true;
    this.shutdownState = 'SHUTDOWN';
    return {
      drained: true,
      shutdownState: this.shutdownState,
      flushedPendingCount: initialPending,
      walCheckpointStatus: this.metrics.walCheckpointStatus
    };
  }

  async shutdown(options = {}) {
    return this.drainAndShutdown(options);
  }

  getMetrics() {
    return {
      ...this.metrics,
      pendingQueueDepth: this.pendingQueue.length,
      maxQueueSize: this.maxQueueSize,
      maxBatchSize: this.maxBatchSize,
      shutdownState: this.shutdownState,
      isShuttingDown: this.isShuttingDown,
      isClosed: this.isClosed,
      registeredAdaptersOnSameDbCount: this._handleCoord ? this._handleCoord.registeredAdaptersCount : 1,
      sharedHandleCoordination: this._handleCoord ? { ...this._handleCoord } : null
    };
  }
}

module.exports = {
  WriteCoalescingSqliteAdapter
};
