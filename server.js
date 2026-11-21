require("dotenv").config();
const os = require("os");
const path = require("path");
require("express");
const { createApp } = require("./src/app");

const PORT = Number(process.env.PORT || 4200);
const storageDir =
  process.env.STORAGE_DIR ||
  (process.env.VERCEL ? path.join(os.tmpdir(), "queueflow-storage") : undefined);

const { app, server } = createApp({ storageDir });

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`QueueFlow running at http://localhost:${PORT}`);
  });
}

module.exports = server;
module.exports.app = app;
