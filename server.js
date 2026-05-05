const express = require("express");
const crypto = require("crypto");
const { exec } = require("child_process");
require("dotenv").config();

const app = express();

const SECRET = process.env.WEBHOOK_SECRET;
const DEPLOY_SCRIPT = process.env.DEPLOY_SCRIPT;

// === Capture raw body for signature verification ===
app.use(
  "/webhook",
  express.raw({ type: "application/json" })
);

// === Verify GitHub signature ===
function verifySignature(req) {
  const signature = req.headers["x-hub-signature-256"];
  if (!signature || !req.body) {
    console.log("❌ Missing signature or body");
    return false;
  }

  // Log raw body size and a short preview
  console.log("📦 Raw body length:", req.body.length);
  console.log("📦 Raw body (first 100 bytes):", req.body.toString("utf8").slice(0, 100));

  // Compute HMAC digest
  const hmac = crypto.createHmac("sha256", SECRET);
  const digest = "sha256=" + hmac.update(req.body).digest("hex");

  // Log both sides for comparison
  console.log("🔍 Received signature:", signature);
  console.log("🔍 Computed digest:   ", digest);

  try {
    const isValid = crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(digest)
    );

    if (!isValid) {
      console.log("❌ Signature mismatch");
      return false;
    }

    console.log("✅ Signature verified successfully");
    return true;
  } catch (err) {
    console.error("⚠️ Error comparing signatures:", err.message);
    return false;
  }
}


// === Webhook endpoint ===
app.post("/webhook", (req, res) => {
  // Verify signature
  if (!verifySignature(req)) {
    return res.status(401).send("Invalid signature");
  }

  // Parse JSON manually from raw buffer
  let payload;
  try {
    payload = JSON.parse(req.body.toString("utf8"));
  } catch (err) {
    console.log("⚠️ Invalid JSON payload:", err.message);
    return res.status(400).send("Invalid JSON");
  }

  const event = req.headers["x-github-event"];
  if (event !== "push") {
    console.log(`Ignoring event: ${event}`);
    return res.status(200).send("Ignored");
  }

  const branch = payload.ref;
  if (branch !== "refs/heads/main") {
    console.log(`Push to ${branch} ignored (only main triggers deploy)`);
    return res.status(200).send("Ignored");
  }

  console.log("🚀 Push to main detected, running deploy...");
  console.log("📍 process.cwd():", process.cwd());
  console.log("📍 __dirname:", __dirname);


  exec(`bash ${DEPLOY_SCRIPT}`, {
    cwd: "/home/ubuntu/money_printer",
  }, (error, stdout, stderr) => {
    if (error) {
      console.error("❌ Deployment failed:");
      console.error(stderr || error.message);
      return;
    }

    console.log("✅ Deployment complete:");
    console.log(stdout);
  });

  res.status(200).send("Deployment started");
});

app.listen(4000, () => {
  console.log("🌐 Webhook server listening on port 4000");
});