import { db } from "../connection";
import "../schema";

export type Socks5ProxyRecord = {
  port: number;
  clientId: string;
  username: string | null;
  password: string | null;
  createdAt: number;
};

export function saveSocks5Proxy(
  port: number,
  clientId: string,
  username?: string,
  password?: string,
): void {
  db.run(
    `INSERT INTO socks5_proxies (port, client_id, username, password, created_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(port) DO UPDATE SET
       client_id = excluded.client_id,
       username = excluded.username,
       password = excluded.password,
       created_at = excluded.created_at`,
    port,
    clientId,
    username ?? null,
    password ?? null,
    Date.now(),
  );
}

export function deleteSocks5Proxy(port: number): void {
  db.run(`DELETE FROM socks5_proxies WHERE port = ?`, port);
}

export function listSocks5Proxies(): Socks5ProxyRecord[] {
  const rows = db.query<any>(`SELECT * FROM socks5_proxies ORDER BY created_at ASC`).all();
  return rows.map((r: any) => ({
    port: r.port as number,
    clientId: r.client_id as string,
    username: r.username ?? null,
    password: r.password ?? null,
    createdAt: Number(r.created_at) || 0,
  }));
}
