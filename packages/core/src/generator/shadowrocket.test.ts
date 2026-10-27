import { describe, expect, it } from "vitest";
import type { ClashConfig } from "@subboost/core/types/config";
import type { ParsedNode } from "@subboost/core/types/node";
import { generateClashConfig, generateIosClientConfig } from "./index";
import { buildTestClientOptions, section } from "./ios-client.test-helpers";
import { generateShadowrocketConfigFromClash } from "./shadowrocket";

const clientOptions = buildTestClientOptions("shadowrocket");

describe("Shadowrocket config generation", () => {
  it("references subscription nodes by name and keeps rule order", () => {
    const nodes = [
      { name: "HK 01", type: "ss", server: "hk.example.com", port: 8388, cipher: "aes-128-gcm", password: "pw" },
      { name: "TUIC", type: "tuic", server: "tuic.example.com", port: 443, uuid: "52396e06-041a-4cc2-be5c-8525eb457809", password: "p" },
      { name: "Bad, Name", type: "ss", server: "bad.example.com", port: 8388, cipher: "aes-128-gcm", password: "pw" },
    ] as unknown as ParsedNode[];

    const generateOptions = {
      nodes,
      template: "minimal" as const,
      userConfig: { customRules: [{ id: "c1", type: "IP-CIDR" as const, value: "10.0.0.0/8", target: "DIRECT", noResolve: true }] },
    };
    const config = generateIosClientConfig("shadowrocket", generateOptions, clientOptions);

    expect(config).toContain("#      https://sub.example.com/api/subscriptions/token/config.yaml");
    expect(config).toContain("#   - Bad, Name");
    expect(config).not.toContain("proxy-providers");
    expect(section(config, "General")).toContain("update-url = https://sub.example.com/api/subscriptions/token/shadowrocket.conf");

    const groups = section(config, "Proxy Group");
    // Shadowrocket 支持 TUIC，节点仍可引用；名称含逗号的节点无法引用
    expect(groups.some((item) => item.startsWith("🚀 节点选择 = select,⚡ 自动选择,DIRECT,REJECT,HK 01,TUIC"))).toBe(true);
    expect(groups.some((item) => item.includes("Bad"))).toBe(false);
    expect(groups.some((item) => /^⚡ 自动选择 = url-test,HK 01,TUIC,url=.+,interval=\d+,timeout=5,tolerance=100$/.test(item))).toBe(
      true
    );

    const rules = section(config, "Rule");
    // Shadowrocket 自上而下匹配，规则顺序必须与 Clash 配置完全一致
    const clashRules = generateClashConfig(generateOptions).rules ?? [];
    const toClashShape = (rule: string) =>
      rule
        .replace(/^RULE-SET,https:\/\/sub\.example\.com\/api\/subscriptions\/token\/rule-sets\/([^.]+)\.list(\?no-resolve=1)?,(.+)$/, (_m, name, nr, target) =>
          `RULE-SET,${name},${target}${nr ? ",no-resolve" : ""}`)
        .replace(/^FINAL,/, "MATCH,");
    expect(rules.map(toClashShape)).toEqual(clashRules);
    expect(rules).toContain("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve");
    expect(rules.some((item) => /^RULE-SET,https:\/\/sub\.example\.com\/.+\/rule-sets\/cn-ip\.list\?no-resolve=1,/.test(item))).toBe(true);
  });

  it("maps group types, builtin aliases and skipped rules", () => {
    const clash: ClashConfig = {
      ipv6: false,
      dns: { nameserver: ["https://doh.pub/dns-query", "quic://dns.adguard.com", "h3://dns.google/dns-query"] },
      proxies: [
        { name: "A", type: "ss", server: "a.example", port: 1, cipher: "aes-128-gcm", password: "pw" },
        { name: "B", type: "ss", server: "b.example", port: 1, cipher: "aes-128-gcm", password: "pw" },
        { name: "Pick", type: "ss", server: "c.example", port: 1, cipher: "aes-128-gcm", password: "pw" },
      ] as unknown as ParsedNode[],
      "proxy-providers": { url_1: { type: "http", url: "https://airport.example.com/sub" } },
      "proxy-groups": [
        { name: "RR", type: "load-balance", proxies: ["A", "B"], strategy: "round-robin", url: "http://t.example", interval: 300 },
        { name: "Hash", type: "load-balance", proxies: ["A", "B"], strategy: "consistent-hashing" },
        { name: "Fall", type: "fallback", proxies: ["A", "Missing"], url: "http://t.example" },
        { name: "Auto", type: "url-test", proxies: ["A"], tolerance: 20 },
        { name: "Empty", type: "url-test", proxies: ["Missing"] },
        { name: "Pick", type: "select", proxies: ["RR", "REJECT-DROP", "A"] },
      ],
      "rule-providers": { google: { type: "http", behavior: "domain", url: "https://x/geosite/google.mrs" } },
      rules: ["GEOIP,CN,DIRECT", "RULE-SET,google,Pick", "GEOSITE,cn,DIRECT", "DST-PORT,22,DIRECT", "MATCH,Pick"],
    };

    const config = generateShadowrocketConfigFromClash(clash, { resolveRuleSetUrl: ({ name }) => `https://r/${name}.list` });
    expect(config).toContain("# 注意：proxy-providers 模式的订阅源");
    expect(config).toContain("#   - Pick");
    expect(config).toContain("#   - GEOSITE,cn,DIRECT");
    expect(config).not.toContain("#      http");

    const general = section(config, "General");
    expect(general).toContain(
      "dns-server = https://doh.pub/dns-query,h3://dns.google/dns-query,quic://dns.adguard.com,223.5.5.5,119.29.29.29"
    );
    expect(general).toContain("ipv6 = false");
    expect(general.some((item) => item.startsWith("update-url"))).toBe(false);

    expect(section(config, "Proxy Group")).toEqual([
      "RR = random,A,B,url=http://t.example,interval=300,timeout=5",
      "Hash = load-balance,A,B,url=http://t.example,interval=600,timeout=5",
      "Fall = fallback,A,url=http://t.example,interval=600,timeout=5",
      "Auto = url-test,A,url=http://t.example,interval=600,timeout=5,tolerance=20",
      "Empty = select,DIRECT",
      "Pick = select,RR,REJECT,A",
    ]);
    expect(section(config, "Rule")).toEqual([
      "GEOIP,CN,DIRECT",
      "RULE-SET,https://r/google.list,Pick",
      "DST-PORT,22,DIRECT",
      "FINAL,Pick",
    ]);
  });
});
