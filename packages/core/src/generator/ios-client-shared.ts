/**
 * Loon / Shadowrocket 配置生成的共享逻辑
 *
 * 两个客户端都使用 Surge 风格的 INI 配置（[General] / [Proxy Group] / [Rule] …），
 * 这里统一把 SubBoost 已生成的 Clash 配置（节点、代理组、规则、rule-providers）
 * 拆成与客户端无关的中间结构，再由各客户端模块输出具体语法。
 */

import type { ClashConfig, ProxyGroup, RuleProvider } from "@subboost/core/types/config";
import { isMihomoSupportedProxyNode, sanitizeMihomoProxyNode } from "../mihomo/proxy-sanitizer";

export type IosClientTarget = "loon" | "shadowrocket";

export interface IosRuleSetReference {
  name: string;
  provider: RuleProvider;
  noResolve: boolean;
}

export interface IosClientConfigOptions {
  // 把 Clash rule-provider 映射为客户端可下载的经典规则列表地址
  resolveRuleSetUrl: (ref: IosRuleSetReference) => string;
  // 配置自身的下载地址（Shadowrocket 写入 update-url，Loon 写入注释）
  configUrl?: string;
  // Clash YAML 订阅地址（Shadowrocket 通过订阅导入节点）
  nodeSubscriptionUrl?: string;
}

export type PolicyResolver = (name: string) => string | null;

const BUILTIN_POLICY_ALIASES: Record<string, string> = {
  DIRECT: "DIRECT",
  REJECT: "REJECT",
  "REJECT-DROP": "REJECT",
};

export function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export function asRecord(value: unknown): Record<string, unknown> {
  return isPlainRecord(value) ? value : {};
}

export function pickString(value: unknown): string {
  if (typeof value === "string") return value.trim();
  return typeof value === "number" && Number.isFinite(value) ? String(value) : "";
}

export function pickNumber(value: unknown): number | undefined {
  const number = typeof value === "string" && value.trim() ? Number(value) : value;
  return typeof number === "number" && Number.isFinite(number) ? number : undefined;
}

export function pickStringList(value: unknown): string[] {
  const list = Array.isArray(value) ? value : pickString(value).split(",");
  return list.map(pickString).filter(Boolean);
}

/**
 * INI 风格配置里 `,` 分隔参数、`=` 分隔键值，策略名包含这些字符会破坏整行解析。
 * 统一替换为全角字符，并保证替换后仍然唯一。
 */
export function sanitizePolicyName(name: string): string {
  return name
    .replace(/[\r\n\t]+/g, " ")
    .replace(/,/g, "，")
    .replace(/=/g, "＝")
    .replace(/"/g, "'")
    .trim();
}

export function createPolicyNameMap(names: string[]): Map<string, string> {
  const map = new Map<string, string>();
  const used = new Set<string>(Object.keys(BUILTIN_POLICY_ALIASES));
  for (const original of names) {
    if (map.has(original)) continue;
    const base = sanitizePolicyName(original) || "未命名";
    let candidate = base;
    for (let index = 2; used.has(candidate); index += 1) candidate = `${base} (${index})`;
    used.add(candidate);
    map.set(original, candidate);
  }
  return map;
}

export function resolveBuiltinPolicy(name: string): string | null {
  return BUILTIN_POLICY_ALIASES[name.trim().toUpperCase()] ?? null;
}

/**
 * 代理组成员 → 客户端策略名：去掉无法解析的成员、自身和重复项
 */
export function resolveGroupMembers(group: ProxyGroup, selfName: string, resolvePolicy: PolicyResolver): string[] {
  const members: string[] = [];
  for (const member of group.proxies ?? []) {
    const resolved = resolvePolicy(member);
    if (resolved && resolved !== selfName && !members.includes(resolved)) members.push(resolved);
  }
  return members;
}

export type ParsedClashRule =
  | { kind: "match"; target: string }
  | { kind: "rule-set"; provider: string; target: string; noResolve: boolean }
  | { kind: "plain"; type: string; value: string; target: string; noResolve: boolean };

/**
 * 解析 SubBoost 生成的 Clash 规则行（不支持 AND/OR/NOT 等逻辑规则，SubBoost 也不会生成）
 */
export function parseClashRule(rule: string): ParsedClashRule | null {
  const [rawType = "", value = "", target = "", ...options] = rule.split(",").map((part) => part.trim());
  const type = rawType.toUpperCase();
  if (type === "MATCH") return value ? { kind: "match", target: value } : null;
  if (!value || !target) return null;
  const noResolve = options.some((option) => option.toLowerCase() === "no-resolve");
  if (type === "RULE-SET") return { kind: "rule-set", provider: value, target, noResolve };
  return { kind: "plain", type, value, target, noResolve };
}

export type ConvertedIosRule =
  | { kind: "plain"; line: string }
  | { kind: "rule-set"; name: string; url: string; target: string };

export interface ConvertedIosRules {
  // 保持 Clash 规则原有顺序（Shadowrocket 自上而下匹配）
  entries: ConvertedIosRule[];
  skipped: string[];
  finalPolicy: string;
}

/**
 * Clash 规则 → 客户端规则：plainTypes 映射本地规则类型（Clash 类型 → 客户端类型），未列出的类型跳过
 */
export function convertIosRules(params: {
  rules: string[];
  ruleProviders: Record<string, RuleProvider>;
  plainTypes: Record<string, string>;
  resolvePolicy: PolicyResolver;
  options: IosClientConfigOptions;
}): ConvertedIosRules {
  const out: ConvertedIosRules = { entries: [], skipped: [], finalPolicy: "DIRECT" };
  for (const rule of params.rules) {
    const parsed = parseClashRule(rule);
    const target = parsed ? (params.resolvePolicy(parsed.target) ?? "DIRECT") : "DIRECT";
    if (parsed?.kind === "match") {
      out.finalPolicy = target;
    } else if (parsed?.kind === "rule-set" && Object.prototype.hasOwnProperty.call(params.ruleProviders, parsed.provider)) {
      const provider = params.ruleProviders[parsed.provider]!;
      const url = params.options.resolveRuleSetUrl({ name: parsed.provider, provider, noResolve: parsed.noResolve });
      out.entries.push({ kind: "rule-set", name: parsed.provider, url, target });
    } else if (parsed?.kind === "plain" && params.plainTypes[parsed.type] && !/[\r\n"]/.test(parsed.value)) {
      const line = `${params.plainTypes[parsed.type]},${parsed.value},${target}${parsed.noResolve ? ",no-resolve" : ""}`;
      out.entries.push({ kind: "plain", line });
    } else {
      out.skipped.push(rule);
    }
  }
  return out;
}

export interface IosClientInputs {
  nodes: Array<Record<string, unknown>>;
  groups: ProxyGroup[];
  ruleProviders: Record<string, RuleProvider>;
  proxyProviders: Record<string, unknown>;
  rules: string[];
  testUrl: string;
}

const DEFAULT_TEST_URL = "http://www.gstatic.com/generate_204";

/**
 * 从已生成的 Clash 配置提取客户端需要的部分；节点先走一遍 Mihomo 规范化，和 YAML 输出保持一致
 */
export function collectIosClientInputs(config: ClashConfig): IosClientInputs {
  const nodes = (config.proxies ?? []).map((node) => sanitizeMihomoProxyNode(node)).filter(isMihomoSupportedProxyNode);
  const groups = config["proxy-groups"] ?? [];
  return {
    nodes,
    groups,
    ruleProviders: config["rule-providers"] ?? {},
    proxyProviders: config["proxy-providers"] ?? {},
    rules: config.rules ?? [],
    testUrl: groups.map((group) => pickString(group.url)).find(Boolean) ?? DEFAULT_TEST_URL,
  };
}

export interface IosDnsServers {
  plain: string[];
  doh: string[];
  doq: string[];
  doh3: string[];
}

const PLAIN_DNS_RE = /^(?:\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?|\[[0-9a-f:]+\](?::\d+)?|[0-9a-f]*:[0-9a-f:]+)$/i;
const DNS_SCHEMES: Array<[prefix: string, key: keyof IosDnsServers]> = [
  ["https://", "doh"],
  ["h3://", "doh3"],
  ["quic://", "doq"],
];

/**
 * Clash dns.nameserver → 客户端 DNS 列表。DoT（tls://）、DHCP 等客户端不支持的写法直接忽略。
 */
export function splitDnsServers(config: ClashConfig): IosDnsServers {
  const out: IosDnsServers = { plain: [], doh: [], doq: [], doh3: [] };
  for (const raw of pickStringList(config.dns?.nameserver)) {
    // Mihomo 的 `#h3=true` / `#PROXY` 等后缀是客户端私有参数
    const value = raw.split("#")[0]!.trim().replace(/^udp:\/\//i, "");
    const key = DNS_SCHEMES.find(([prefix]) => value.toLowerCase().startsWith(prefix))?.[1]
      ?? (PLAIN_DNS_RE.test(value) ? "plain" : null);
    if (key && !out[key].includes(value)) out[key].push(value);
  }
  if (out.plain.length === 0) out.plain.push(...DEFAULT_PLAIN_DNS);
  return out;
}

export const DEFAULT_PLAIN_DNS = ["223.5.5.5", "119.29.29.29"];
export const DEFAULT_SKIP_PROXY = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,localhost,*.local,captive.apple.com";
export const DEFAULT_BYPASS_TUN =
  "10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.51.100.0/24,203.0.113.0/24,224.0.0.0/4,255.255.255.255/32";

// 生成配置头部的注释列表；没有条目时不输出标题
export function commentList(title: string, items: string[]): string[] {
  return items.length > 0 ? [title, ...items.map((item) => `#   - ${item}`)] : [];
}

export function renderSection(title: string, lines: string[]): string {
  return [`[${title}]`, ...lines].join("\n");
}
