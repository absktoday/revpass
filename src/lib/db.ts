// SQLite Database helper module using @tauri-apps/plugin-sql
import Database from "@tauri-apps/plugin-sql";

let dbInstance: Database | null = null;

export async function getDb(): Promise<Database> {
  if (!dbInstance) {
    dbInstance = await Database.load("sqlite:vault.db");
  }
  return dbInstance;
}

// Run migrations to ensure all tables exist
export async function initDb(): Promise<void> {
  const db = await getDb();
  
  // Table for general app settings and recovery payload
  await db.execute(`
    CREATE TABLE IF NOT EXISTS vault_metadata (
      key TEXT PRIMARY KEY,
      value TEXT
    );
  `);
  
  // Table for registered passkeys
  await db.execute(`
    CREATE TABLE IF NOT EXISTS passkeys (
      credential_id TEXT PRIMARY KEY,
      name TEXT,
      prf_salt TEXT,
      encrypted_mek TEXT
    );
  `);
  
  // Table for encrypted credential records
  await db.execute(`
    CREATE TABLE IF NOT EXISTS credentials (
      id TEXT PRIMARY KEY,
      title_encrypted TEXT,
      url_encrypted TEXT,
      username_encrypted TEXT,
      password_encrypted TEXT,
      notes_encrypted TEXT,
      created_at INTEGER,
      updated_at INTEGER
    );
  `);
}

// Checks if the database contains 'vault_initialized' = 'true'
export async function checkVaultInitialized(): Promise<boolean> {
  const db = await getDb();
  const res = await db.select<{ value: string }[]>(
    "SELECT value FROM vault_metadata WHERE key = $1",
    ["vault_initialized"]
  );
  return res.length > 0 && res[0].value === "true";
}

export interface RecoveryMetadata {
  recoverySalt: string; // base64
  encryptedMekWithRecovery: string; // JSON string
}

export async function getRecoveryMetadata(): Promise<RecoveryMetadata | null> {
  const db = await getDb();
  const saltRes = await db.select<{ value: string }[]>("SELECT value FROM vault_metadata WHERE key = 'recovery_salt'");
  const mekRes = await db.select<{ value: string }[]>("SELECT value FROM vault_metadata WHERE key = 'encrypted_mek_with_recovery'");
  
  if (saltRes.length === 0 || mekRes.length === 0) {
    return null;
  }
  
  return {
    recoverySalt: saltRes[0].value,
    encryptedMekWithRecovery: mekRes[0].value
  };
}

// Save initial vault configuration
export async function initializeVaultMetadata(recoverySalt: string, encryptedMekWithRecovery: string): Promise<void> {
  const db = await getDb();
  await db.execute("INSERT OR REPLACE INTO vault_metadata (key, value) VALUES ('vault_initialized', 'true')");
  await db.execute("INSERT OR REPLACE INTO vault_metadata (key, value) VALUES ('recovery_salt', $1)", [recoverySalt]);
  await db.execute("INSERT OR REPLACE INTO vault_metadata (key, value) VALUES ('encrypted_mek_with_recovery', $1)", [encryptedMekWithRecovery]);
}

export interface PasskeyRecord {
  credential_id: string;
  name: string;
  prf_salt: string;
  encrypted_mek: string;
}

export async function loadPasskeys(): Promise<PasskeyRecord[]> {
  const db = await getDb();
  return await db.select<PasskeyRecord[]>("SELECT * FROM passkeys");
}

export async function savePasskey(credentialId: string, name: string, prfSalt: string, encryptedMek: string): Promise<void> {
  const db = await getDb();
  await db.execute(
    "INSERT OR REPLACE INTO passkeys (credential_id, name, prf_salt, encrypted_mek) VALUES ($1, $2, $3, $4)",
    [credentialId, name, prfSalt, encryptedMek]
  );
}

export async function deletePasskey(credentialId: string): Promise<void> {
  const db = await getDb();
  await db.execute("DELETE FROM passkeys WHERE credential_id = $1", [credentialId]);
}

export interface DbCredential {
  id: string;
  title_encrypted: string;
  url_encrypted: string;
  username_encrypted: string;
  password_encrypted: string;
  notes_encrypted: string;
  created_at: number;
  updated_at: number;
}

export async function loadCredentials(): Promise<DbCredential[]> {
  const db = await getDb();
  return await db.select<DbCredential[]>("SELECT * FROM credentials ORDER BY created_at DESC");
}

export async function saveCredential(cred: DbCredential): Promise<void> {
  const db = await getDb();
  await db.execute(
    `INSERT OR REPLACE INTO credentials (
      id, title_encrypted, url_encrypted, username_encrypted, password_encrypted, notes_encrypted, created_at, updated_at
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [
      cred.id,
      cred.title_encrypted,
      cred.url_encrypted,
      cred.username_encrypted,
      cred.password_encrypted,
      cred.notes_encrypted,
      cred.created_at,
      cred.updated_at
    ]
  );
}

export async function deleteCredential(id: string): Promise<void> {
  const db = await getDb();
  await db.execute("DELETE FROM credentials WHERE id = $1", [id]);
}
