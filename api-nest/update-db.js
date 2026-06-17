const { Client } = require('pg');
require('dotenv').config();

const client = new Client({
  connectionString: process.env.DATABASE_URL,
});

async function run() {
  try {
    await client.connect();
    console.log('Connected to Database successfully.');
    
    // Ensure UUID extension is loaded
    await client.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp";');
    
    // Create scan_audit_logs table if not exists
    await client.query(`
      CREATE TABLE IF NOT EXISTS scan_audit_logs (
        id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        scan_id     UUID REFERENCES scans(id) ON DELETE CASCADE,
        target_url  TEXT NOT NULL,
        action      VARCHAR(50) NOT NULL,
        ip_address  VARCHAR(45),
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);
    
    // Create index for audit logs
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_audit_user_id ON scan_audit_logs(user_id);
    `);

    // Ensure vulnerabilities columns are added
    await client.query(`
      ALTER TABLE vulnerabilities 
      ADD COLUMN IF NOT EXISTS attack_path JSONB DEFAULT '[]',
      ADD COLUMN IF NOT EXISTS attack_probability VARCHAR(20);
    `);
    
    console.log('✅ Database schema and columns updated successfully!');
  } catch (err) {
    console.error('❌ Error updating database:', err);
  } finally {
    await client.end();
  }
}

run();
