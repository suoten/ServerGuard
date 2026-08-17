import { randomFillSync } from "crypto";
globalThis.crypto = globalThis.crypto || {};
globalThis.crypto.getRandomValues = randomFillSync;
