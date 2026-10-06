/**
 * Provider safety policy ("safe providers only").
 *
 * Blocks every provider whose use through a self-hosted gateway is likely to
 * break that provider's terms of service, so only official API-key providers
 * and local models can carry traffic. Blocked categories:
 *
 *  - OAuth subscription logins (Claude, Codex, Cursor, Copilot, Antigravity,
 *    Kiro, ...): reuse a personal/IDE subscription outside its official app.
 *    Also API-key providers flagged as spending a consumer plan (cursor-api).
 *  - Web-cookie providers (chatgpt-web, claude-web, gemini-web, ...): drive a
 *    consumer website with a browser session.
 *  - Keyless/no-auth providers (duckduckgo-web, opencode, local CLI bridges):
 *    piggy-back on another product's free or subscription backend.
 *  - Upstream subscription relays (cliproxyapi, 9router).
 *  - Keyless anonymous fallbacks on otherwise API-key providers
 *    (opencode-go, opencode-zen).
 *  - Every provider the project's own ToS catalog marks "avoid"
 *    (open-sse/config/freeTierCatalog.ts FREE_TIER_TOS), including API-key
 *    providers such as fireworks and ai21.
 *
 * The guard is ON by default and fails closed. Overrides (environment):
 *  - OMNIROUTE_PROVIDER_SAFETY=off            disable the guard entirely
 *  - OMNIROUTE_SAFE_PROVIDER_ALLOW=a,b,...    re-enable specific provider ids
 *                                             (after checking their terms)
 */
import { NOAUTH_PROVIDERS } from "./providers/noauth";
import { OAUTH_PROVIDERS } from "./providers/oauth";
import { WEB_COOKIE_PROVIDERS } from "./providers/web-cookie";
import { UPSTREAM_PROXY_PROVIDERS } from "./providers/upstream-proxy";
import { APIKEY_PROVIDERS } from "./providers/apikey";
import { LOCAL_PROVIDERS } from "./providers/local";
import { CLOUD_AGENT_PROVIDERS } from "./providers/cloud-agent";
import { SEARCH_PROVIDERS } from "./providers/search";
import { FREE_TIER_TOS } from "@omniroute/open-sse/config/freeTierCatalog";

export const PROVIDER_SAFETY_BLOCKED_ERROR_CODE = "PROVIDER_BLOCKED_BY_SAFETY_POLICY";

export type ProviderSafetyCategory =
  "oauth-subscription" | "web-session" | "keyless" | "subscription-relay" | "tos-avoid";

type ProviderEntry = {
  id?: unknown;
  alias?: unknown;
  anonymousFallback?: unknown;
  subscriptionRisk?: unknown;
  riskNoticeVariant?: unknown;
  oauthProviderId?: unknown;
};

let blockedMap: Map<string, ProviderSafetyCategory> | null = null;

function addEntries(
  map: Map<string, ProviderSafetyCategory>,
  providers: Record<string, ProviderEntry>,
  category: ProviderSafetyCategory,
  include: (key: string, entry: ProviderEntry) => boolean = () => true
): void {
  for (const [key, entry] of Object.entries(providers)) {
    if (!include(key, entry)) continue;
    for (const id of [key, entry?.id, entry?.alias]) {
      if (typeof id === "string" && id.trim()) {
        const norm = id.trim().toLowerCase();
        if (!map.has(norm)) map.set(norm, category);
      }
    }
  }
}

function buildBlockedMap(): Map<string, ProviderSafetyCategory> {
  const map = new Map<string, ProviderSafetyCategory>();
  addEntries(map, OAUTH_PROVIDERS as Record<string, ProviderEntry>, "oauth-subscription");
  addEntries(map, WEB_COOKIE_PROVIDERS as Record<string, ProviderEntry>, "web-session");
  addEntries(map, NOAUTH_PROVIDERS as Record<string, ProviderEntry>, "keyless");
  addEntries(map, UPSTREAM_PROXY_PROVIDERS as Record<string, ProviderEntry>, "subscription-relay");
  // API-key providers the project itself flags as spending a consumer plan
  // (e.g. cursor-api exchanges a Cursor plan key for a session token). Dual-auth
  // providers whose OAuth path lives under a separate id (xai -> xai-oauth) keep
  // their official API-key path; the OAuth id is already blocked above.
  addEntries(
    map,
    APIKEY_PROVIDERS as Record<string, ProviderEntry>,
    "oauth-subscription",
    (_key, entry) =>
      entry?.subscriptionRisk === true &&
      entry?.riskNoticeVariant === "oauth" &&
      typeof entry?.oauthProviderId !== "string"
  );

  const avoidIds = new Set(
    Object.entries(FREE_TIER_TOS)
      .filter(([, verdict]) => verdict === "avoid")
      .map(([id]) => id.toLowerCase())
  );
  // Resolve ToS-avoid ids to their API-key entries so aliases are blocked too.
  addEntries(
    map,
    APIKEY_PROVIDERS as Record<string, ProviderEntry>,
    "tos-avoid",
    (key, entry) =>
      avoidIds.has(key.toLowerCase()) ||
      (typeof entry?.id === "string" && avoidIds.has(entry.id.toLowerCase()))
  );
  for (const id of avoidIds) if (!map.has(id)) map.set(id, "tos-avoid");

  // Aliases must never shadow a separate, safe provider. Example: the poe-web
  // session provider uses alias "poe", which is also the official Poe API id.
  // Collect every primary id of a blocked-category provider first, then free
  // any id/alias belonging to a safe provider that is not one of those.
  const blockedPrimaryIds = new Set<string>();
  const collectPrimary = (
    providers: Record<string, ProviderEntry>,
    include: (key: string, entry: ProviderEntry) => boolean = () => true
  ) => {
    for (const [key, entry] of Object.entries(providers)) {
      if (!include(key, entry)) continue;
      blockedPrimaryIds.add(key.toLowerCase());
      if (typeof entry?.id === "string") blockedPrimaryIds.add(entry.id.toLowerCase());
    }
  };
  collectPrimary(OAUTH_PROVIDERS as Record<string, ProviderEntry>);
  collectPrimary(WEB_COOKIE_PROVIDERS as Record<string, ProviderEntry>);
  collectPrimary(NOAUTH_PROVIDERS as Record<string, ProviderEntry>);
  collectPrimary(UPSTREAM_PROXY_PROVIDERS as Record<string, ProviderEntry>);
  for (const id of avoidIds) blockedPrimaryIds.add(id);
  collectPrimary(
    APIKEY_PROVIDERS as Record<string, ProviderEntry>,
    (_key, entry) =>
      entry?.subscriptionRisk === true &&
      entry?.riskNoticeVariant === "oauth" &&
      typeof entry?.oauthProviderId !== "string"
  );

  for (const providers of [
    APIKEY_PROVIDERS,
    LOCAL_PROVIDERS,
    CLOUD_AGENT_PROVIDERS,
    SEARCH_PROVIDERS,
  ]) {
    for (const [key, entry] of Object.entries(providers as Record<string, ProviderEntry>)) {
      const keyNorm = key.toLowerCase();
      const idNorm = typeof entry?.id === "string" ? entry.id.toLowerCase() : keyNorm;
      if (blockedPrimaryIds.has(keyNorm) || blockedPrimaryIds.has(idNorm)) continue;
      for (const id of [key, entry?.id, entry?.alias]) {
        if (typeof id !== "string") continue;
        const norm = id.trim().toLowerCase();
        if (!blockedPrimaryIds.has(norm)) map.delete(norm);
      }
    }
  }
  return map;
}

function getBlockedMap(): Map<string, ProviderSafetyCategory> {
  if (!blockedMap) blockedMap = buildBlockedMap();
  return blockedMap;
}

/** API-key providers whose keyless "anonymous" fallback path must not be used. */
let anonymousFallbackIds: Set<string> | null = null;
function getAnonymousFallbackIds(): Set<string> {
  if (!anonymousFallbackIds) {
    const set = new Set<string>();
    for (const [key, entry] of Object.entries(APIKEY_PROVIDERS as Record<string, ProviderEntry>)) {
      if (entry?.anonymousFallback !== true) continue;
      for (const id of [key, entry.id, entry.alias]) {
        if (typeof id === "string" && id.trim()) set.add(id.trim().toLowerCase());
      }
    }
    anonymousFallbackIds = set;
  }
  return anonymousFallbackIds;
}

export function isProviderSafetyPolicyEnabled(): boolean {
  const flag = (process.env.OMNIROUTE_PROVIDER_SAFETY ?? "").trim().toLowerCase();
  return !["off", "0", "false", "disabled"].includes(flag);
}

function getAllowlist(): Set<string> {
  return new Set(
    (process.env.OMNIROUTE_SAFE_PROVIDER_ALLOW ?? "")
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean)
  );
}

function normalize(providerId: unknown): string | null {
  if (typeof providerId !== "string") return null;
  const norm = providerId.trim().toLowerCase();
  return norm || null;
}

/** Returns the reason a provider is blocked, or null when it may be used. */
export function getProviderSafetyBlockCategory(providerId: unknown): ProviderSafetyCategory | null {
  const norm = normalize(providerId);
  if (!norm || !isProviderSafetyPolicyEnabled()) return null;
  const category = getBlockedMap().get(norm) ?? null;
  if (!category) return null;
  if (getAllowlist().has(norm)) return null;
  return category;
}

export function isProviderBlockedBySafetyPolicy(providerId: unknown): boolean {
  return getProviderSafetyBlockCategory(providerId) !== null;
}

/** True when the keyless anonymous fallback of an API-key provider must be skipped. */
export function isAnonymousFallbackBlockedBySafetyPolicy(providerId: unknown): boolean {
  const norm = normalize(providerId);
  if (!norm || !isProviderSafetyPolicyEnabled()) return false;
  if (getAllowlist().has(norm)) return false;
  return getAnonymousFallbackIds().has(norm) || isProviderBlockedBySafetyPolicy(norm);
}

export type ProviderSafetyError = Error & {
  code: typeof PROVIDER_SAFETY_BLOCKED_ERROR_CODE;
  status: 403;
};

export function assertProviderAllowedBySafetyPolicy(providerId: unknown): void {
  const category = getProviderSafetyBlockCategory(providerId);
  if (!category) return;
  const error = new Error(
    `Provider "${String(providerId)}" is disabled by the safe-providers policy (${category}). ` +
      `Its terms likely prohibit use through a self-hosted gateway. ` +
      `To override after checking its terms, add it to OMNIROUTE_SAFE_PROVIDER_ALLOW.`
  ) as ProviderSafetyError;
  error.code = PROVIDER_SAFETY_BLOCKED_ERROR_CODE;
  error.status = 403;
  throw error;
}

export function assertModelProviderAllowedBySafetyPolicy(modelId: unknown): void {
  if (typeof modelId !== "string") return;
  const slash = modelId.indexOf("/");
  if (slash <= 0) return;
  assertProviderAllowedBySafetyPolicy(modelId.slice(0, slash));
}

export function isProviderSafetyError(error: unknown): error is ProviderSafetyError {
  if (!(error instanceof Error)) return false;
  const typed = error as Error & { code?: unknown; status?: unknown };
  return typed.code === PROVIDER_SAFETY_BLOCKED_ERROR_CODE && typed.status === 403;
}

/** Snapshot of every blocked id (for dashboards/tests). */
export function listProviderSafetyBlockedIds(): Array<{
  id: string;
  category: ProviderSafetyCategory;
}> {
  return Array.from(getBlockedMap().entries())
    .filter(([id]) => getProviderSafetyBlockCategory(id) !== null)
    .map(([id, category]) => ({ id, category }))
    .sort((a, b) => a.id.localeCompare(b.id));
}

/** Test hook: rebuild caches. */
export function __resetProviderSafetyCacheForTests(): void {
  blockedMap = null;
  anonymousFallbackIds = null;
}
