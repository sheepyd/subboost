import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  consumeLocalRateLimit: vi.fn(),
  getTrustedClientRateLimitKey: vi.fn(),
  hashLocalRateLimitKey: vi.fn(() => "token-hash"),
  localRateLimitResponse: vi.fn(
    () => new Response(JSON.stringify({ error: "limited", code: "RATE_LIMITED" }), { status: 429 })
  ),
  generateSubscriptionIosConfig: vi.fn(),
  resolveSubscriptionRuleSetSource: vi.fn(),
  loadConvertedRuleSet: vi.fn(),
}));

vi.mock("server-only", () => ({}));
vi.mock("./rate-limit", () => ({
  consumeLocalRateLimit: mocks.consumeLocalRateLimit,
  getTrustedClientRateLimitKey: mocks.getTrustedClientRateLimitKey,
  hashLocalRateLimitKey: mocks.hashLocalRateLimitKey,
  localRateLimitResponse: mocks.localRateLimitResponse,
}));
vi.mock("./subscription-service", () => ({
  generateSubscriptionIosConfig: mocks.generateSubscriptionIosConfig,
  resolveSubscriptionRuleSetSource: mocks.resolveSubscriptionRuleSetSource,
}));
vi.mock("./rule-set-convert", () => ({
  loadConvertedRuleSet: mocks.loadConvertedRuleSet,
}));

import { handleIosClientConfigRequest, handleRuleSetRequest } from "./ios-client-route";

describe("iOS client subscription routes", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.consumeLocalRateLimit.mockReturnValue({ allowed: true, retryAfterSeconds: 0 });
    mocks.getTrustedClientRateLimitKey.mockReturnValue("client-hash");
    mocks.generateSubscriptionIosConfig.mockResolvedValue({
      content: "[General]\n",
      name: "Main",
      subscriptionInfo: { upload: 1, download: 2, total: 3 },
      cacheExpirySeconds: 3600,
      autoUpdateIntervalSeconds: null,
      isAdmin: true,
    });
  });

  it("serves the generated config as plain text with subscription headers", async () => {
    const response = await handleIosClientConfigRequest(new Request("https://local.test/loon.conf"), "secret-token", "loon");

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("text/plain;charset=utf-8");
    expect(response.headers.get("subscription-userinfo")).toBe("upload=1; download=2; total=3");
    expect(await response.text()).toBe("[General]\n");
    expect(mocks.generateSubscriptionIosConfig).toHaveBeenCalledWith("secret-token", "loon");
    // 与 config.yaml 共用限流桶
    expect(mocks.consumeLocalRateLimit).toHaveBeenNthCalledWith(1, "subscription-yaml-client", "client-hash", {
      limit: 600,
      windowMs: 60_000,
    });
    expect(mocks.consumeLocalRateLimit).toHaveBeenNthCalledWith(2, "subscription-yaml-token", "token-hash", {
      limit: 120,
      windowMs: 60_000,
    });
  });

  it("rejects rate-limited and unknown subscriptions", async () => {
    mocks.consumeLocalRateLimit.mockReturnValueOnce({ allowed: false, retryAfterSeconds: 9 });
    const clientLimited = await handleIosClientConfigRequest(new Request("https://local.test/x"), "secret-token", "shadowrocket");
    expect(clientLimited.status).toBe(429);
    expect(mocks.localRateLimitResponse).toHaveBeenLastCalledWith("Too many subscription requests. Try again later.", 9);

    mocks.getTrustedClientRateLimitKey.mockReturnValueOnce(null);
    mocks.consumeLocalRateLimit.mockReturnValueOnce({ allowed: false, retryAfterSeconds: 4 });
    const tokenLimited = await handleIosClientConfigRequest(new Request("https://local.test/x"), "secret-token", "shadowrocket");
    expect(tokenLimited.status).toBe(429);
    expect(mocks.localRateLimitResponse).toHaveBeenLastCalledWith("Too many subscription requests. Try again later.", 4);
    expect(mocks.generateSubscriptionIosConfig).not.toHaveBeenCalled();

    mocks.generateSubscriptionIosConfig.mockResolvedValueOnce(null);
    const missing = await handleIosClientConfigRequest(new Request("https://local.test/x"), "secret-token", "shadowrocket");
    expect(missing.status).toBe(404);
  });

  it("rate limits rule set downloads separately", async () => {
    mocks.consumeLocalRateLimit.mockReturnValueOnce({ allowed: false, retryAfterSeconds: 3 });
    const response = await handleRuleSetRequest(new Request("https://local.test/rule-sets/a.list"), "secret-token", "a.list");
    expect(response.status).toBe(429);
    expect(mocks.resolveSubscriptionRuleSetSource).not.toHaveBeenCalled();
  });

  it("converts only rule sets that belong to the subscription", async () => {
    mocks.resolveSubscriptionRuleSetSource.mockResolvedValue({
      url: "https://rules.example.com/geoip/cn.mrs",
      behavior: "ipcidr",
    });
    mocks.loadConvertedRuleSet.mockResolvedValue({ ok: true, content: "IP-CIDR,1.0.1.0/24,no-resolve\n" });

    const response = await handleRuleSetRequest(
      new Request("https://local.test/rule-sets/cn-ip.list?no-resolve=1"),
      "secret-token",
      "cn-ip.list"
    );

    expect(response.status).toBe(200);
    expect(await response.text()).toBe("IP-CIDR,1.0.1.0/24,no-resolve\n");
    expect(mocks.resolveSubscriptionRuleSetSource).toHaveBeenCalledWith("secret-token", "cn-ip");
    expect(mocks.loadConvertedRuleSet).toHaveBeenCalledWith({
      url: "https://rules.example.com/geoip/cn.mrs",
      behavior: "ipcidr",
      noResolve: true,
    });
    expect(mocks.consumeLocalRateLimit).toHaveBeenCalledWith("subscription-rule-set-token", "token-hash", {
      limit: 600,
      windowMs: 60_000,
    });
  });

  it("decodes encoded provider names and reports missing or failed rule sets", async () => {
    mocks.resolveSubscriptionRuleSetSource.mockResolvedValueOnce(null);
    const missing = await handleRuleSetRequest(
      new Request("https://local.test/rule-sets/x"),
      "secret-token",
      encodeURIComponent("geolocation-!cn") + ".list"
    );
    expect(missing.status).toBe(404);
    expect(mocks.resolveSubscriptionRuleSetSource).toHaveBeenCalledWith("secret-token", "geolocation-!cn");

    const malformed = await handleRuleSetRequest(new Request("https://local.test/rule-sets/x"), "secret-token", "%E0%A4%A.list");
    expect(malformed.status).toBe(404);

    mocks.resolveSubscriptionRuleSetSource.mockResolvedValueOnce({ url: "https://rules.example.com/a.mrs", behavior: "domain" });
    mocks.loadConvertedRuleSet.mockResolvedValueOnce({ ok: false, status: 502, error: "HTTP 404" });
    const failed = await handleRuleSetRequest(new Request("https://local.test/rule-sets/a.list"), "secret-token", "a.list");
    expect(failed.status).toBe(502);
    expect(await failed.json()).toEqual({ error: "HTTP 404", code: "UPSTREAM_ERROR" });
  });
});
