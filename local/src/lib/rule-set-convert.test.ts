import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  fetchPublicTextDirect: vi.fn(),
}));

vi.mock("server-only", () => ({}));
vi.mock("./source-import", () => ({
  fetchPublicTextDirect: mocks.fetchPublicTextDirect,
}));

import { clearRuleSetCacheForTests, loadConvertedRuleSet } from "./rule-set-convert";

describe("rule set conversion service", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    clearRuleSetCacheForTests();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("fetches the text sibling of mrs providers and caches the converted list", async () => {
    mocks.fetchPublicTextDirect.mockResolvedValue({ ok: true, content: "+.google.com\ngoogle.cn\n" });

    const first = await loadConvertedRuleSet({ url: "https://rules.example.com/geosite/google.mrs", behavior: "domain", noResolve: false });
    const second = await loadConvertedRuleSet({ url: "https://rules.example.com/geosite/google.mrs", behavior: "domain", noResolve: false });

    expect(first).toEqual({ ok: true, content: "DOMAIN-SUFFIX,google.com\nDOMAIN,google.cn\n" });
    expect(second).toEqual(first);
    expect(mocks.fetchPublicTextDirect).toHaveBeenCalledTimes(1);
    expect(mocks.fetchPublicTextDirect).toHaveBeenCalledWith({
      url: "https://rules.example.com/geosite/google.list",
      userAgent: "SubBoost-RuleSet/1.0",
      timeoutMs: 20_000,
      maxBytes: 16 * 1024 * 1024,
    });
  });

  it("deduplicates concurrent downloads and keys the cache by no-resolve", async () => {
    mocks.fetchPublicTextDirect.mockResolvedValue({ ok: true, content: "1.0.1.0/24\n" });
    const source = { url: "https://rules.example.com/geoip/cn.mrs", behavior: "ipcidr" };

    const [a, b] = await Promise.all([
      loadConvertedRuleSet({ ...source, noResolve: true }),
      loadConvertedRuleSet({ ...source, noResolve: true }),
    ]);
    const plain = await loadConvertedRuleSet({ ...source, noResolve: false });

    expect(a).toEqual({ ok: true, content: "IP-CIDR,1.0.1.0/24,no-resolve\n" });
    expect(b).toEqual(a);
    expect(plain).toEqual({ ok: true, content: "IP-CIDR,1.0.1.0/24\n" });
    expect(mocks.fetchPublicTextDirect).toHaveBeenCalledTimes(2);
  });

  it("reports upstream failures and non-text content", async () => {
    mocks.fetchPublicTextDirect.mockResolvedValueOnce({ ok: false, error: "HTTP 404", publicReason: "HTTP 404" });
    expect(await loadConvertedRuleSet({ url: "https://rules.example.com/a.mrs", behavior: "domain", noResolve: false })).toEqual({
      ok: false,
      status: 502,
      error: "HTTP 404",
    });

    mocks.fetchPublicTextDirect.mockResolvedValueOnce({ ok: false });
    expect(await loadConvertedRuleSet({ url: "https://rules.example.com/b.mrs", behavior: "domain", noResolve: false })).toEqual({
      ok: false,
      status: 502,
      error: "规则集下载失败",
    });

    mocks.fetchPublicTextDirect.mockResolvedValueOnce({ ok: true });
    expect(await loadConvertedRuleSet({ url: "https://rules.example.com/c.mrs", behavior: "domain", noResolve: false })).toEqual({
      ok: false,
      status: 502,
      error: "规则集为空或不是文本格式",
    });
  });

  it("serves stale content when a refresh fails after the cache expires", async () => {
    vi.useFakeTimers();
    const source = { url: "https://rules.example.com/geosite/x.mrs", behavior: "domain", noResolve: false };
    mocks.fetchPublicTextDirect.mockResolvedValueOnce({ ok: true, content: "x.example\n" });
    await loadConvertedRuleSet(source);

    vi.advanceTimersByTime(6 * 60 * 60 * 1000 + 1);
    mocks.fetchPublicTextDirect.mockResolvedValueOnce({ ok: false, publicReason: "HTTP 500" });

    expect(await loadConvertedRuleSet(source)).toEqual({ ok: true, content: "DOMAIN,x.example\n" });
    expect(mocks.fetchPublicTextDirect).toHaveBeenCalledTimes(2);
  });

  it("evicts the oldest entries beyond the cache limit", async () => {
    mocks.fetchPublicTextDirect.mockImplementation(async ({ url }: { url: string }) => ({ ok: true, content: `${url.length}.example\n` }));
    for (let index = 0; index <= 128; index += 1) {
      await loadConvertedRuleSet({ url: `https://rules.example.com/${index}.mrs`, behavior: "domain", noResolve: false });
    }
    expect(mocks.fetchPublicTextDirect).toHaveBeenCalledTimes(129);

    // 最早的条目已被淘汰，需要重新下载；最近的条目仍在缓存中
    await loadConvertedRuleSet({ url: "https://rules.example.com/128.mrs", behavior: "domain", noResolve: false });
    expect(mocks.fetchPublicTextDirect).toHaveBeenCalledTimes(129);
    await loadConvertedRuleSet({ url: "https://rules.example.com/0.mrs", behavior: "domain", noResolve: false });
    expect(mocks.fetchPublicTextDirect).toHaveBeenCalledTimes(130);
  });
});
