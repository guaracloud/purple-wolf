// Reference purple-wolf-relay subscriber in TypeScript (Hono).
//
// Run:
//   npm i hono @hono/node-server
//   PURPLEWOLF_SECRET=$(openssl rand -hex 32) tsx typescript.ts

import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { createHmac, timingSafeEqual } from "node:crypto";

const SECRET = Buffer.from(process.env.PURPLEWOLF_SECRET!);
const SKEW_S = 300;
const seen = new Map<string, number>();
const SEEN_CAP = 10_000;

const app = new Hono();

app.post("/webhook", async (c) => {
  const ts = c.req.header("x-purplewolf-timestamp") ?? "";
  const sig = c.req.header("x-purplewolf-signature") ?? "";
  const eid = c.req.header("x-purplewolf-event-id") ?? "";
  if (!/^\d+$/.test(ts) || !sig.startsWith("sha256=") || !eid) {
    return c.text("bad headers", 400);
  }
  if (Math.abs(Date.now() / 1000 - Number(ts)) > SKEW_S) {
    return c.text("skew", 401);
  }
  const body = Buffer.from(await c.req.arrayBuffer());
  const expected =
    "sha256=" +
    createHmac("sha256", SECRET).update(`${ts}.`).update(body).digest("hex");
  if (
    expected.length !== sig.length ||
    !timingSafeEqual(Buffer.from(expected), Buffer.from(sig))
  ) {
    return c.text("sig", 401);
  }
  if (seen.has(eid)) return c.text("", 200);
  seen.set(eid, Date.now());
  if (seen.size > SEEN_CAP) seen.delete(seen.keys().next().value!);
  console.log(`delivery ${eid}:`, body.toString());
  return c.text("", 200);
});

serve({ fetch: app.fetch, port: 8080 });
