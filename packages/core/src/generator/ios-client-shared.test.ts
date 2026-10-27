import { describe, expect, it } from "vitest";
import type { ClashConfig } from "@subboost/core/types/config";
import type { ParsedNode } from "@subboost/core/types/node";
import { buildTestClientOptions } from "./ios-client.test-helpers";
import {
  asRecord,
  collectIosClientInputs,
  commentList,
  convertIosRules,
  createPolicyNameMap,
  parseClashRule,
  pickNumber,
  pickString,
  pickStringList,
  resolveBuiltinPolicy,
  resolveGroupMembers,
  splitDnsServers,
} from "./ios-client-shared";

describe("iOS client shared helpers", () => {
  it("normalizes loose scalar values", () => {
    expect(pickString("  a ")).toBe("a");
    expect(pickString(42)).toBe("42");
    expect(pickString(Number.NaN)).toBe("");
    expect(pickString(null)).toBe("");
    expect(pickNumber("8080")).toBe(8080);
    expect(pickNumber(" ")).toBeUndefined();
    expect(pickNumber("abc")).toBeUndefined();
    expect(pickNumber(7)).toBe(7);
    expect(pickStringList(["h2", " ", "http/1.1"])).toEqual(["h2", "http/1.1"]);
    expect(pickStringList("h2, h3")).toEqual(["h2", "h3"]);
    expect(pickStringList(undefined)).toEqual([]);
    expect(asRecord([1])).toEqual({});
    expect(asRecord({ a: 1 })).toEqual({ a: 1 });
  });

  it("escapes policy names and keeps them unique", () => {
    const map = createPolicyNameMap(["A,B", "A，B", "x=y", 'q"t', "line\nbreak", "  ", "DIRECT", "A,B"]);

    expect([...map.values()]).toEqual(["A，B", "A，B (2)", "x＝y", "q't", "line break", "未命名", "DIRECT (2)"]);
    expect(map.size).toBe(7);
  });

  it("resolves builtin policies case-insensitively", () => {
    expect(resolveBuiltinPolicy(" direct ")).toBe("DIRECT");
    expect(resolveBuiltinPolicy("REJECT-DROP")).toBe("REJECT");
    expect(resolveBuiltinPolicy("PASS")).toBeNull();
  });

  it("parses the Clash rule shapes SubBoost generates", () => {
    expect(parseClashRule("MATCH,Proxy")).toEqual({ kind: "match", target: "Proxy" });
    expect(parseClashRule("MATCH")).toBeNull();
    expect(parseClashRule("RULE-SET,cn-ip,DIRECT,no-resolve")).toEqual({
      kind: "rule-set",
      provider: "cn-ip",
      target: "DIRECT",
      noResolve: true,
    });
    expect(parseClashRule("domain-suffix,example.com,Proxy")).toEqual({
      kind: "plain",
      type: "DOMAIN-SUFFIX",
      value: "example.com",
      target: "Proxy",
      noResolve: false,
    });
    expect(parseClashRule("DOMAIN,example.com")).toBeNull();
  });

  it("resolves group members without self references or duplicates", () => {
    const resolve = (name: string) => (name === "Missing" ? null : name.toUpperCase());

    expect(resolveGroupMembers({ name: "g", type: "select", proxies: ["a", "g", "Missing", "A", "b"] }, "G", resolve)).toEqual([
      "A",
      "B",
    ]);
    expect(resolveGroupMembers({ name: "g", type: "select" }, "G", resolve)).toEqual([]);
  });

  it("converts rules in order and reports skipped ones", () => {
    const result = convertIosRules({
      rules: [
        "DOMAIN,a.example,Proxy",
        "RULE-SET,google,Missing,no-resolve",
        "RULE-SET,unknown,Proxy",
        "PROCESS-NAME,curl,DIRECT",
        'DOMAIN,"quoted",Proxy',
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "broken",
        "MATCH,Proxy",
      ],
      ruleProviders: { google: { type: "http", behavior: "domain" } },
      plainTypes: { DOMAIN: "DOMAIN", "IP-CIDR": "IP-CIDR" },
      resolvePolicy: (name) => (name === "Missing" ? null : name),
      options: buildTestClientOptions("loon"),
    });

    expect(result.entries).toEqual([
      { kind: "plain", line: "DOMAIN,a.example,Proxy" },
      {
        kind: "rule-set",
        name: "google",
        url: "https://sub.example.com/api/subscriptions/token/rule-sets/google.list?no-resolve=1",
        target: "DIRECT",
      },
      { kind: "plain", line: "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve" },
    ]);
    expect(result.skipped).toEqual([
      "RULE-SET,unknown,Proxy",
      "PROCESS-NAME,curl,DIRECT",
      'DOMAIN,"quoted",Proxy',
      "broken",
    ]);
    expect(result.finalPolicy).toBe("Proxy");
  });

  it("collects inputs from partial Clash configs", () => {
    expect(collectIosClientInputs({})).toEqual({
      nodes: [],
      groups: [],
      ruleProviders: {},
      proxyProviders: {},
      rules: [],
      testUrl: "http://www.gstatic.com/generate_204",
    });

    const inputs = collectIosClientInputs({
      proxies: [
        { name: "ok", type: "ss", server: "a.example", port: 1, cipher: "aes-128-gcm", password: "p" },
        { name: "bad", type: "ss", server: "b.example", port: 1, cipher: "aes-128-gcm" },
      ] as unknown as ParsedNode[],
      "proxy-groups": [{ name: "g", type: "select", proxies: [] }, { name: "auto", type: "url-test", url: "http://t" }],
    });
    expect(inputs.nodes.map((node) => node.name)).toEqual(["ok"]);
    expect(inputs.testUrl).toBe("http://t");
  });

  it("splits Clash nameservers by DNS transport", () => {
    const config: ClashConfig = {
      dns: {
        nameserver: [
          "223.5.5.5",
          "udp://119.29.29.29",
          "223.5.5.5",
          "[2400:3200::1]:53",
          "2400:3200::1",
          "https://dns.alidns.com/dns-query#h3=true",
          "h3://dns.google/dns-query",
          "quic://dns.adguard.com",
          "tls://8.8.4.4",
          "dhcp://en0",
          "dns.example.com",
        ],
      },
    };

    expect(splitDnsServers(config)).toEqual({
      plain: ["223.5.5.5", "119.29.29.29", "[2400:3200::1]:53", "2400:3200::1"],
      doh: ["https://dns.alidns.com/dns-query"],
      doh3: ["h3://dns.google/dns-query"],
      doq: ["quic://dns.adguard.com"],
    });
    expect(splitDnsServers({}).plain).toEqual(["223.5.5.5", "119.29.29.29"]);
  });

  it("renders comment lists only when there is something to list", () => {
    expect(commentList("# title", [])).toEqual([]);
    expect(commentList("# title", ["a"])).toEqual(["# title", "#   - a"]);
  });
});
