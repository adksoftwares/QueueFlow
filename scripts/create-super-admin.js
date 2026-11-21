#!/usr/bin/env node
require("dotenv").config();
const path = require("path");
const readline = require("readline");
const bcrypt = require("bcryptjs");
const { v4: uuid } = require("uuid");
const { initDatabase } = require("../src/db");
const { isValidEmail, audit } = require("../src/helpers");
const { generateTotpSecret, buildOtpAuthUri, generateRecoveryCodes } = require("../src/mfa");

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const val = argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[++i] : "true";
      args[key] = val;
    }
  }
  return args;
}

function ask(question, hidden = false) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  return new Promise((resolve) => {
    if (!hidden) {
      rl.question(question, (ans) => {
        rl.close();
        resolve(ans);
      });
      return;
    }
    rl.stdoutMuted = true;
    rl._writeToOutput = function (str) {
      if (!rl.stdoutMuted) process.stdout.write(str);
    };
    process.stdout.write(question);
    rl.question("", (ans) => {
      rl.close();
      process.stdout.write("\n");
      resolve(ans);
    });
  });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const storageDir = args["storage-dir"] || path.join(__dirname, "..", "storage");
  const db = initDatabase({ storageDir, sqliteOnly: Boolean(args["storage-dir"]) });
  await db.ready;

  try {
    const existingRow = await db
      .prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'super_admin'")
      .get();
    const existingCount = Number(existingRow?.n || 0);

    if (existingCount > 0 && process.env.ALLOW_ADDITIONAL_SUPER_ADMINS !== "true" && args.force !== "true") {
      console.error(
        "A Super Admin already exists. Set ALLOW_ADDITIONAL_SUPER_ADMINS=true (or pass --force true) to create another."
      );
      process.exitCode = 1;
      return;
    }

    const name = String(args.name || process.env.SUPER_ADMIN_NAME || (await ask("Super Admin Name: "))).trim();
    const email = String(args.email || process.env.SUPER_ADMIN_EMAIL || (await ask("Super Admin Email: ")))
      .toLowerCase()
      .trim();
    const password = String(
      args.password || process.env.SUPER_ADMIN_PASSWORD || (await ask("Super Admin Password (6+ chars): ", true))
    );

    if (!name || !isValidEmail(email) || password.length < 6) {
      console.error("Valid name, email, and password (at least 6 characters) are required.");
      process.exitCode = 1;
      return;
    }

    const existingUser = await db.prepare("SELECT id, role FROM users WHERE email = ?").get(email);
    if (existingUser) {
      console.error(`An account with email ${email} already exists.`);
      process.exitCode = 1;
      return;
    }

    const uid = uuid();
    const nowIso = new Date().toISOString();
    const hash = await bcrypt.hash(password, 12);

    const enableMfa = args["enable-mfa"] === "true";
    let mfaSecret = null;
    let recoveryCodes = null;
    let recoveryHashesJson = null;

    if (enableMfa) {
      mfaSecret = generateTotpSecret();
      const generated = generateRecoveryCodes(8);
      recoveryCodes = generated.codes;
      recoveryHashesJson = JSON.stringify(generated.hashes);
    }

    await db
      .prepare(
        `INSERT INTO users (
           id, name, email, password_hash, role, status,
           mfa_enabled, mfa_secret, mfa_recovery_hashes,
           privacy_notice_accepted_at, updated_at, created_at
         ) VALUES (?, ?, ?, ?, 'super_admin', 'active', ?, ?, ?, ?, ?, ?)`
      )
      .run(
        uid,
        name,
        email,
        hash,
        enableMfa ? 1 : 0,
        mfaSecret,
        recoveryHashesJson,
        nowIso,
        nowIso,
        nowIso
      );

    await audit(
      db,
      uid,
      "super_admin.initial_setup",
      uid,
      { email, mfa_enabled: enableMfa },
      "localhost",
      "super_admin",
      "user",
      "CLI"
    );

    console.log(`\nSuper Admin created: ${name} <${email}> (id: ${uid})`);
    if (enableMfa) {
      console.log(`TOTP Secret: ${mfaSecret}`);
      console.log(`OTPAuth URI: ${buildOtpAuthUri({ secret: mfaSecret, email })}`);
      console.log(`Recovery Codes (save securely): ${recoveryCodes.join(", ")}`);
    } else {
      console.log("MFA is not yet enrolled; enroll TOTP in the Super Admin Security tab upon first login.");
    }
  } finally {
    await db.close();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
