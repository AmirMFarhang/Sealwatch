// Copyright 2026 Amir Mohammad Farhang and contributors; all rights reserved; private.
import { createServer, type Server } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { assert } from "./core/validation.js";
import { canonicalJson } from "./core/crypto.js";
import type { loadConfig } from "./config.js";
import { attestationProblems } from "./verify/incoming.js";
const MAX_BODY_BYTES = 2 * 1024 * 1024;
export function createTrustServer(
  services: ReturnType<typeof loadConfig>,
  token: string,
): Server {
  assert(
    token.length >= 32,
    "HTTP bearer token must contain at least 32 characters",
  );
  const authorized = (header: string | undefined) => {
    const supplied = Buffer.from(header ?? "");
    const expected = Buffer.from(`Bearer ${token}`);
    return (
      supplied.length === expected.length && timingSafeEqual(supplied, expected)
    );
  };
  return createServer(async (req, res) => {
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    const respond = (status: number, body: unknown) => {
      res.statusCode = status;
      res.end(canonicalJson(body));
    };
    try {
      if (
        req.socket.remoteAddress !== "127.0.0.1" &&
        req.socket.remoteAddress !== "::ffff:127.0.0.1" &&
        req.socket.remoteAddress !== "::1"
      ) {
        respond(403, { error: "localhost only" });
        return;
      }
      if (req.headers.origin) {
        respond(403, { error: "browser cross-origin requests are refused" });
        return;
      }
      if (!authorized(req.headers.authorization)) {
        respond(401, { error: "bearer authentication required" });
        return;
      }
      if (req.method !== "POST") {
        respond(405, { error: "use authenticated POST" });
        return;
      }
      if (req.headers["content-type"]?.split(";")[0] !== "application/json") {
        respond(415, { error: "application/json required" });
        return;
      }
      const chunks: Buffer[] = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          respond(413, { error: "request body too large" });
          return;
        }
        chunks.push(Buffer.from(chunk));
      }
      const body = JSON.parse(Buffer.concat(chunks).toString());
      switch (req.url) {
        case "/v1/verify-incoming":
          respond(200, await services.verify.verifyIncoming(body));
          break;
        case "/v1/attestations/verify": {
          const problems = attestationProblems(body, {
            checkerPk: services.key.pubkey,
            flaggedIssuerKeys: services.config.flagged.trustedIssuerKeys,
            network: services.config.network,
            sanctionsListPins: services.sanctions.lists
              .filter((l) => !l.testOnly)
              .map((l) => l.sha256),
          });
          respond(200, { valid: !problems.length, problems });
          break;
        }
        case "/v1/log/verify": {
          const problems = services.log.verify();
          respond(200, { valid: !problems.length, problems });
          break;
        }
        case "/v1/policy":
          services.gate.install(body);
          respond(200, { installed: true });
          break;
        case "/v1/authorize":
          respond(200, services.gate.authorize(body));
          break;
        case "/v1/stop":
          services.gate.stop(body);
          respond(200, { stopped: true });
          break;
        case "/v1/why":
          respond(200, services.gate.why(String(body.actionId)));
          break;
        default:
          respond(404, { error: "route not found" });
      }
    } catch (e) {
      respond(400, { error: (e as Error).message });
    }
  });
}
