import type { DatabaseSync } from 'node:sqlite';

export const db: DatabaseSync & { pragma?: (str: string) => void };
export function initSchema(targetDb?: typeof db): void;
export function getDatabaseHealth(targetDb?: typeof db): Record<string, unknown>;
