const { Client } = require('pg');
require('dotenv').config();

const client = new Client({
  connectionString: process.env.DATABASE_URL,
});

async function run() {
  try {
    await client.connect();
    console.log('Connected to Database successfully.');
    
    await client.query(`
      ALTER TABLE vulnerabilities 
      ADD COLUMN IF NOT EXISTS attack_path JSONB DEFAULT '[]',
      ADD COLUMN IF NOT EXISTS attack_probability VARCHAR(20);
    `);
    
    console.log('✅ Database columns added successfully!');
  } catch (err) {
    console.error('❌ Error updating database:', err);
  } finally {
    await client.end();
  }
}

run();
