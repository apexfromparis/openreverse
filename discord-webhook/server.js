const http = require("node:http");
const crypto = require("node:crypto");

const port = Number(process.env.PORT || 3000);
const discordWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
const webhookSecret = process.env.WEBHOOK_SECRET;

if (!discordWebhookUrl || !webhookSecret) {
  throw new Error("DISCORD_WEBHOOK_URL and WEBHOOK_SECRET are required");
}

function isValidSignature(body, signature) {
  if (!signature || !signature.startsWith("sha256=")) return false;
  const expected = crypto
    .createHmac("sha256", webhookSecret)
    .update(body)
    .digest("hex");
  const received = signature.slice("sha256=".length);
  return received.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(received), Buffer.from(expected));
}

function formatFiles(commit) {
  const files = [
    ...(commit.added || []).map((file) => `+ ${file}`),
    ...(commit.modified || []).map((file) => `~ ${file}`),
    ...(commit.removed || []).map((file) => `- ${file}`),
  ];
  return files.length ? files.join("\n").slice(0, 1000) : "Aucun fichier detaille.";
}

async function sendToDiscord(payload) {
  const response = await fetch(discordWebhookUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok) throw new Error(`Discord returned ${response.status}`);
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.on("data", (chunk) => {
      body += chunk;
      if (body.length > 2_000_000) request.destroy(new Error("Payload too large"));
    });
    request.on("end", () => resolve(body));
    request.on("error", reject);
  });
}

const server = http.createServer(async (request, response) => {
  if (request.method === "GET" && request.url === "/health") {
    response.writeHead(200, { "content-type": "text/plain" });
    response.end("ok");
    return;
  }

  if (request.method !== "POST" || request.url !== "/github-webhook") {
    response.writeHead(404);
    response.end("Not found");
    return;
  }

  try {
    const body = await readBody(request);
    if (!isValidSignature(body, request.headers["x-hub-signature-256"])) {
      response.writeHead(401);
      response.end("Invalid signature");
      return;
    }

    const event = request.headers["x-github-event"];
    if (event !== "push") {
      response.writeHead(200);
      response.end("Ignored");
      return;
    }

    const payload = JSON.parse(body);
    const commits = (payload.commits || []).slice(-5);
    const commitText = commits.length
      ? commits.map((commit) => `**${commit.message.split("\n")[0]}**\n${formatFiles(commit)}`).join("\n\n").slice(0, 4000)
      : "Aucun commit dans ce push.";

    await sendToDiscord({
      embeds: [{
        title: `${payload.repository.full_name} - push`,
        url: payload.compare,
        description: `**${payload.pusher.name}** a pousse sur **${payload.ref.replace("refs/heads/", "")}**`,
        color: 0x5865f2,
        fields: [{ name: "Changements", value: commitText }],
        timestamp: new Date().toISOString(),
      }],
    });

    response.writeHead(204);
    response.end();
  } catch (error) {
    console.error(error);
    response.writeHead(500);
    response.end("Webhook failed");
  }
});

server.listen(port, "0.0.0.0", () => {
  console.log(`Webhook server listening on port ${port}`);
});
