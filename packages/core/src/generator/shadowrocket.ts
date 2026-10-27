/**
 * Shadowrocket 配置生成器
 *
 * Shadowrocket 官方文档建议节点通过「订阅」导入，配置文件内的本地节点仅用于兼容；
 * 它的订阅解析器能完整识别 Clash YAML 的 proxies（含 Reality、dialer-proxy 等字段）。
 * 因此这里输出的 .conf 只包含 [General] / [Proxy Group] / [Rule]，
 * 代理组按节点名引用通过 SubBoost Clash 订阅导入的节点。
 *
 * 语法参考 LOWERTOP/Shadowrocket 使用说明与示例配置。
 */

import type { ClashConfig, ProxyGroup } from "@subboost/core/types/config";
import {
  DEFAULT_BYPASS_TUN,
  DEFAULT_SKIP_PROXY,
  collectIosClientInputs,
  commentList,
  convertIosRules,
  createPolicyNameMap,
  pickNumber,
  pickString,
  renderSection,
  resolveBuiltinPolicy,
  resolveGroupMembers,
  splitDnsServers,
  type IosClientConfigOptions,
  type PolicyResolver,
} from "./ios-client-shared";

const SHADOWROCKET_RULE_TYPES: Record<string, string> = {
  DOMAIN: "DOMAIN",
  "DOMAIN-SUFFIX": "DOMAIN-SUFFIX",
  "DOMAIN-KEYWORD": "DOMAIN-KEYWORD",
  "IP-CIDR": "IP-CIDR",
  "IP-CIDR6": "IP-CIDR6",
  "IP-ASN": "IP-ASN",
  GEOIP: "GEOIP",
  "DST-PORT": "DST-PORT",
};

const SHADOWROCKET_AUTO_GROUP_TYPES = new Set(["url-test", "fallback", "load-balance"]);
const DEFAULT_TEST_INTERVAL = 600;
// 节点名来自订阅，无法改名；含这些字符的节点没法在配置里引用
const UNREFERENCEABLE_NODE_NAME = /[\r\n",=]/;

function buildShadowrocketGroupLine(group: ProxyGroup, name: string, members: string[], testUrl: string): string {
  const type = pickString(group.type);
  if (members.length === 0) return `${name} = select,DIRECT`;
  if (!SHADOWROCKET_AUTO_GROUP_TYPES.has(type)) return `${name} = select,${members.join(",")}`;

  // Shadowrocket 的 load-balance 会让同一域名固定走同一节点（≈ consistent-hashing），random 才是轮询式分配
  const outputType = type === "load-balance" && group.strategy === "round-robin" ? "random" : type;
  const params = [
    `url=${pickString(group.url) || testUrl}`,
    `interval=${pickNumber(group.interval) ?? DEFAULT_TEST_INTERVAL}`,
    "timeout=5",
  ];
  if (type === "url-test") params.push(`tolerance=${pickNumber(group.tolerance) ?? 100}`);
  return `${name} = ${outputType},${members.join(",")},${params.join(",")}`;
}

function buildGeneralSection(config: ClashConfig, options: IosClientConfigOptions): string[] {
  const dns = splitDnsServers(config);
  // Shadowrocket 的 dns-server 同时接受普通 DNS 与 DoH/DoQ/H3 地址
  const dnsServers = [...dns.doh, ...dns.doh3, ...dns.doq, ...dns.plain];
  return [
    "bypass-system = true",
    `skip-proxy = ${DEFAULT_SKIP_PROXY}`,
    `tun-excluded-routes = ${DEFAULT_BYPASS_TUN}`,
    `dns-server = ${dnsServers.join(",")}`,
    "fallback-dns-server = system",
    `ipv6 = ${config.ipv6 !== false}`,
    "prefer-ipv6 = false",
    "dns-direct-system = false",
    "icmp-auto-reply = true",
    "private-ip-answer = true",
    "dns-direct-fallback-proxy = true",
    "udp-policy-not-supported-behaviour = REJECT",
    ...(options.configUrl ? [`update-url = ${options.configUrl}`] : []),
  ];
}

/**
 * Clash 配置 → Shadowrocket .conf 文本（节点通过 Clash 订阅导入）
 */
export function generateShadowrocketConfigFromClash(config: ClashConfig, options: IosClientConfigOptions): string {
  const inputs = collectIosClientInputs(config);
  const groupNameMap = createPolicyNameMap(inputs.groups.map((group) => group.name));

  const nodeNames = new Set<string>();
  const unreferencedNodes: string[] = [];
  for (const node of inputs.nodes) {
    const name = pickString(node.name);
    if (UNREFERENCEABLE_NODE_NAME.test(name) || groupNameMap.has(name)) unreferencedNodes.push(name);
    else nodeNames.add(name);
  }

  const resolvePolicy: PolicyResolver = (name) =>
    resolveBuiltinPolicy(name) ?? groupNameMap.get(name) ?? (nodeNames.has(name) ? name : null);

  const groupLines = inputs.groups.map((group) => {
    const name = groupNameMap.get(group.name)!;
    return buildShadowrocketGroupLine(group, name, resolveGroupMembers(group, name, resolvePolicy), inputs.testUrl);
  });

  const rules = convertIosRules({
    rules: inputs.rules,
    ruleProviders: inputs.ruleProviders,
    plainTypes: SHADOWROCKET_RULE_TYPES,
    resolvePolicy,
    options,
  });

  const header = [
    "# Shadowrocket 配置 — 由 SubBoost 生成，请勿手动修改（更新配置会覆盖）",
    "# 使用方法：",
    "#   1. 首页 ➕ → 类型 Subscribe，添加 SubBoost 的 Clash 订阅链接导入节点",
    ...(options.nodeSubscriptionUrl ? [`#      ${options.nodeSubscriptionUrl}`] : []),
    "#   2. 配置 → ➕ 下载本配置并「使用配置」，代理组会按节点名引用订阅中的节点",
    ...(Object.keys(inputs.proxyProviders).length > 0
      ? ["# 注意：proxy-providers 模式的订阅源不会出现在 Clash 订阅的节点里，请在 Shadowrocket 中单独添加这些机场订阅"]
      : []),
    ...commentList("# 以下节点名包含 , = \" 等字符，无法在配置中引用：", unreferencedNodes),
    ...commentList("# 以下规则 Shadowrocket 不支持，已跳过：", rules.skipped),
  ];

  return [
    header.join("\n"),
    renderSection("General", buildGeneralSection(config, options)),
    renderSection("Proxy Group", groupLines),
    renderSection("Rule", [
      ...rules.entries.map((entry) => (entry.kind === "plain" ? entry.line : `RULE-SET,${entry.url},${entry.target}`)),
      `FINAL,${rules.finalPolicy}`,
    ]),
  ].join("\n\n") + "\n";
}
