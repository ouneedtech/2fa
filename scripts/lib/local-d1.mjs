// Test/preview adapter only. Production uses Cloudflare D1 directly.
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
export function localD1(filename = ':memory:') {
  const sqlite = new DatabaseSync(filename);
  sqlite.exec(readFileSync(new URL('../../schema.sql', import.meta.url), 'utf8'));
  const DB = {
    prepare(sql) {
      let args = [];
      return {
        bind(...values) { args = values; return this; },
        async first() { return sqlite.prepare(sql).get(...args) || null; },
        async all() { return { results: sqlite.prepare(sql).all(...args) }; },
        async run() { const r = sqlite.prepare(sql).run(...args); return { meta: { changes: Number(r.changes) } }; }
      };
    },
    async batch(statements) {
      sqlite.exec('BEGIN');
      try { const result = []; for (const s of statements) result.push(await s.run()); sqlite.exec('COMMIT'); return result; }
      catch (error) { sqlite.exec('ROLLBACK'); throw error; }
    }
  };
  return { DB, sqlite };
}
