import { randomFillSync } from "crypto";
globalThis.crypto = globalThis.crypto || {};
globalThis.crypto.getRandomValues = randomFillSync;
const { build } = await import("vite");
await build();
