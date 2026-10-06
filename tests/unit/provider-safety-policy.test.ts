import { test, afterEach } from "node:test";
import assert from "node:assert/strict";

import {
  __resetProviderSafetyCacheForTests,
  assertModelProviderAllowedBySafetyPolicy,
  assertProviderAllowedBySafetyPolicy,
  getProviderSafetyBlockCategory,
  isAnonymousFallbackBlockedBySafetyPolicy,
  isProviderBlockedBySafetyPolicy,
  isProviderSafetyError,
  PROVIDER_SAFETY_BLOCKED_ERROR_CODE,
} from "../../src/shared/constants/providerSafety.ts";
import { getExecutor } from "../../open-sse/executors/index.ts";

const ENV_KEYS = ["OMNIROUTE_PROVIDER_SAFETY", "OMNIROUTE_SAFE_PROVIDER_ALLOW"] as const;
const savedEnv = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
  __resetProviderSafetyCacheForTests();
});

test("blocks subscription OAuth logins by default", () => {
  for (const id of ["claude", "codex", "cursor", "antigravity", "agy", "kiro", "xai-oauth"]) {
    assert.equal(getProviderSafetyBlockCategory(id), "oauth-subscription", id);
  }
});

test("blocks web-session, keyless and relay providers", () => {
  assert.equal(getProviderSafetyBlockCategory("chatgpt-web"), "web-session");
  assert.equal(getProviderSafetyBlockCategory("claude-web"), "web-session");
  assert.equal(getProviderSafetyBlockCategory("duckduckgo-web"), "keyless");
  assert.equal(getProviderSafetyBlockCategory("opencode"), "keyless");
  assert.equal(getProviderSafetyBlockCategory("cliproxyapi"), "subscription-relay");
});

test("blocks the project's ToS 'avoid' providers, including API-key ones", () => {
  for (const id of ["fireworks", "ai21", "featherless-ai", "blackbox"]) {
    assert.equal(isProviderBlockedBySafetyPolicy(id), true, id);
  }
});

test("blocks API-key providers that spend a consumer plan (cursor-api)", () => {
  assert.equal(getProviderSafetyBlockCategory("cursor-api"), "oauth-subscription");
});

test("blocks aliases of blocked providers", () => {
  // poe-web is a session provider; its own id must stay blocked.
  assert.equal(isProviderBlockedBySafetyPolicy("poe-web"), true);
  assert.equal(isProviderBlockedBySafetyPolicy("CLAUDE"), true, "case-insensitive");
});

test("keeps official API-key, local and cloud-agent providers usable", () => {
  for (const id of [
    "openai",
    "anthropic",
    "gemini",
    "mistral",
    "groq",
    "openrouter",
    "xai", // official API key; its OAuth path is the separate xai-oauth id
    "poe", // official Poe API; must not be shadowed by poe-web's "poe" alias
    "ollama-local",
    "codex-cloud", // authenticates with an OpenAI API key
    "devin",
    "jules",
  ]) {
    assert.equal(isProviderBlockedBySafetyPolicy(id), false, id);
  }
});

test("blocks keyless anonymous fallback on otherwise safe API-key providers", () => {
  assert.equal(isAnonymousFallbackBlockedBySafetyPolicy("opencode-go"), true);
  assert.equal(isAnonymousFallbackBlockedBySafetyPolicy("opencode-zen"), true);
  assert.equal(isAnonymousFallbackBlockedBySafetyPolicy("openai"), false);
});

test("assert helpers throw a typed 403 error", () => {
  assert.throws(
    () => assertProviderAllowedBySafetyPolicy("claude"),
    (err: unknown) => {
      assert.equal(isProviderSafetyError(err), true);
      const e = err as Error & { code: string; status: number };
      assert.equal(e.status, 403);
      assert.equal(e.code, PROVIDER_SAFETY_BLOCKED_ERROR_CODE);
      return true;
    }
  );
  assert.throws(() => assertModelProviderAllowedBySafetyPolicy("kiro/claude-sonnet-4"));
  assert.doesNotThrow(() => assertModelProviderAllowedBySafetyPolicy("openai/gpt-4o"));
  assert.doesNotThrow(() => assertModelProviderAllowedBySafetyPolicy("gpt-4o"));
});

test("OMNIROUTE_SAFE_PROVIDER_ALLOW re-enables only the listed providers", () => {
  process.env.OMNIROUTE_SAFE_PROVIDER_ALLOW = "fireworks, Groq";
  assert.equal(isProviderBlockedBySafetyPolicy("fireworks"), false);
  assert.equal(isProviderBlockedBySafetyPolicy("claude"), true);
});

test("OMNIROUTE_PROVIDER_SAFETY=off disables the guard", () => {
  process.env.OMNIROUTE_PROVIDER_SAFETY = "off";
  assert.equal(isProviderBlockedBySafetyPolicy("claude"), false);
  assert.equal(isAnonymousFallbackBlockedBySafetyPolicy("opencode-go"), false);
});

test("executor dispatch refuses blocked providers", async () => {
  await assert.rejects(getExecutor("claude"), (err: unknown) => isProviderSafetyError(err));
  await assert.rejects(getExecutor("chatgpt-web"), (err: unknown) => isProviderSafetyError(err));
  const executor = await getExecutor("openai");
  assert.ok(executor);
});

test("model list keeps a user-defined node whose prefix equals a blocked alias", async () => {
  // "gw" is grok-web's alias; a custom compatible node named "gw" must stay visible.
  // Covered end-to-end by catalog-provider-node-apitype-endpoints.test.ts; here we
  // pin the policy fact the catalog relies on: the alias is blocked, so the
  // catalog must resolve custom prefixes before consulting the policy.
  assert.equal(isProviderBlockedBySafetyPolicy("gw"), true);
});
