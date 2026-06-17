let Client;
try {
  Client = require('pg').Client;
} catch (err) {
  try {
    Client = require('./api-nest/node_modules/pg').Client;
  } catch (err2) {
    try {
      Client = require('../api-nest/node_modules/pg').Client;
    } catch (err3) {
      console.error("Error: 'pg' module not found. Run 'npm install pg' or run this from a folder containing node_modules.");
      process.exit(1);
    }
  }
}

async function main() {
  const client = new Client({
    connectionString: "postgresql://postgres:password@localhost:5432/security_platform"
  });

  try {
    await client.connect();
    console.log("Connected to database successfully.\n");

    const res = await client.query(`
      SELECT id, target_url, status, risk_score, total_vulns, error_message, created_at
      FROM scans
      ORDER BY created_at DESC
      LIMIT 3
    `);

    if (res.rows.length === 0) {
      console.log("No scans found in database.");
      return;
    }

    for (const scan of res.rows) {
      console.log(`Scan ID   : ${scan.id}`);
      console.log(`Target URL: ${scan.target_url}`);
      console.log(`Status    : ${scan.status}`);
      console.log(`Risk Score: ${scan.risk_score}`);
      console.log(`Total Vulns: ${scan.total_vulns}`);
      if (scan.error_message) {
        console.log(`Error     : ${scan.error_message}`);
      }
      console.log(`Created At: ${scan.created_at}`);

      // Pull vulnerabilities
      const vulns = await client.query(`
        SELECT title, severity, category, cvss_score, affected_url
        FROM vulnerabilities
        WHERE scan_id = $1
      `, [scan.id]);

      if (vulns.rows.length > 0) {
        console.log("Vulnerabilities:");
        vulns.rows.forEach(v => {
          console.log(`  - [${v.severity}] ${v.title} (CVSS: ${v.cvss_score}) -> ${v.affected_url}`);
        });
      } else {
        console.log("No vulnerabilities found for this scan.");
      }
      console.log("----------------------------------------");
    }

  } catch (err) {
    console.error("Error running script:", err.message);
  } finally {
    await client.end();
  }
}

main();
