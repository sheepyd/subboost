/**
 * Loon 配置生成器
 *
 * 以 SubBoost 生成的 Clash 配置为输入，输出 Loon 原生 .conf：
 * - [Proxy]：节点按 Loon 语法逐个转换，不支持的协议/传输方式会跳过并在注释中列出
 * - [Proxy Group]：保持代理组结构与顺序
 * - [Proxy Chain]：dialer-proxy（中转）映射为代理链
 * - [Remote Rule]：rule-providers 映射为远程规则（由 SubBoost 转换成经典规则列表）
 *
 * 语法参考 Loon 官方示例配置（Loon0x00/LoonExampleConfig）。
 */

import type { ClashConfig, ProxyGroup } from "@subboost/core/types/config";
import {
  DEFAULT_BYPASS_TUN,
  DEFAULT_SKIP_PROXY,
  asRecord,
  collectIosClientInputs,
  commentList,
  convertIosRules,
  createPolicyNameMap,
  pickNumber,
  pickString,
  pickStringList,
  renderSection,
  resolveBuiltinPolicy,
  resolveGroupMembers,
  splitDnsServers,
  type IosClientConfigOptions,
  type PolicyResolver,
} from "./ios-client-shared";

export type LoonProxyLineResult = { ok: true; line: string } | { ok: false; reason: string };

const LOON_SS_CIPHERS = new Set([
  "rc4",
  "rc4-md5",
  "aes-128-cfb",
  "aes-192-cfb",
  "aes-256-cfb",
  "aes-128-ctr",
  "aes-192-ctr",
  "aes-256-ctr",
  "bf-cfb",
  "camellia-128-cfb",
  "camellia-192-cfb",
  "camellia-256-cfb",
  "salsa20",
  "chacha20",
  "chacha20-ietf",
  "aes-128-gcm",
  "aes-192-gcm",
  "aes-256-gcm",
  "chacha20-ietf-poly1305",
  "xchacha20-ietf-poly1305",
  "2022-blake3-aes-128-gcm",
  "2022-blake3-aes-256-gcm",
]);

const LOON_VMESS_CIPHERS: Record<string, string> = {
  "aes-128-gcm": "aes-128-gcm",
  "chacha20-poly1305": "chacha20-ietf-poly1305",
  "chacha20-ietf-poly1305": "chacha20-ietf-poly1305",
  none: "none",
};

const LOON_IP_MODES: Record<string, string> = {
  dual: "dual",
  ipv4: "v4-only",
  ipv6: "v6-only",
  "ipv4-prefer": "prefer-v4",
  "ipv6-prefer": "prefer-v6",
};

const LOON_RULE_TYPES: Record<string, string> = {
  DOMAIN: "DOMAIN",
  "DOMAIN-SUFFIX": "DOMAIN-SUFFIX",
  "DOMAIN-KEYWORD": "DOMAIN-KEYWORD",
  "IP-CIDR": "IP-CIDR",
  "IP-CIDR6": "IP-CIDR6",
  "IP-ASN": "IP-ASN",
  GEOIP: "GEOIP",
  "DST-PORT": "DEST-PORT",
};

const LOON_AUTO_GROUP_TYPES = new Set(["url-test", "fallback", "load-balance"]);

const LOON_LOAD_BALANCE_ALGORITHMS: Record<string, string> = {
  "consistent-hashing": "pcc",
  "sticky-sessions": "pcc",
  "round-robin": "round-robin",
};

const DEFAULT_TEST_INTERVAL = 600;
const LANDING_SUFFIX = "（落地）";

// Loon 语法没有转义：带引号的值不能含 `"`，裸值还不能含 `,`
const UNSAFE_QUOTED_VALUE = /[\r\n"]/;
const UNSAFE_PLAIN_VALUE = /[\r\n",]/;

class LineBuilder {
  private readonly parts: string[];
  private unsafe = false;

  constructor(name: string, protocol: string) {
    this.parts = [`${name} = ${protocol}`];
  }

  private push(text: string, value: string, quoted: boolean) {
    if ((quoted ? UNSAFE_QUOTED_VALUE : UNSAFE_PLAIN_VALUE).test(value)) this.unsafe = true;
    this.parts.push(text);
    return this;
  }

  // 位置参数（服务器、端口、加密方式等）
  value(value: unknown) {
    return this.push(String(value), String(value), false);
  }

  quoted(value: string) {
    return this.push(`"${value}"`, value, true);
  }

  // 空值不输出
  param(key: string, value: string | number | undefined, quoted = false) {
    if (value === undefined || value === "") return this;
    const text = String(value);
    return this.push(quoted ? `${key}="${text}"` : `${key}=${text}`, text, quoted);
  }

  enable(key: string, enabled: boolean) {
    if (enabled) this.parts.push(`${key}=true`);
    return this;
  }

  // 已自行拼装的复合参数（WireGuard peers），需要校验的值单独传入
  raw(text: string, quotedValues: string[]) {
    if (quotedValues.some((value) => UNSAFE_QUOTED_VALUE.test(value))) this.unsafe = true;
    this.parts.push(text);
    return this;
  }

  build(): LoonProxyLineResult {
    return this.unsafe ? skip("参数包含无法转义的字符") : { ok: true, line: this.parts.join(",") };
  }
}

function skip(reason: string): LoonProxyLineResult {
  return { ok: false, reason };
}

function endpoint(builder: LineBuilder, node: Record<string, unknown>) {
  return builder.value(pickString(node.server)).value(pickNumber(node.port));
}

function getTlsProfile(node: Record<string, unknown>): string | undefined {
  const fingerprint = pickString(node["client-fingerprint"]).toLowerCase();
  const isSafari = fingerprint === "safari" || fingerprint === "ios";
  if (asRecord(node["reality-opts"])["support-x25519mlkem768"] === true) return isSafari ? "safari-ios-26" : "chrome147";
  if (fingerprint === "chrome") return "chrome";
  return isSafari ? "safari-ios18" : undefined;
}

function getSni(node: Record<string, unknown>): string {
  return pickString(node.servername) || pickString(node.sni);
}

/**
 * TLS 相关参数：Reality 使用 sni/public-key/short-id，普通 TLS 使用 tls-name
 */
function appendTls(builder: LineBuilder, node: Record<string, unknown>): string | null {
  builder
    .enable("skip-cert-verify", node["skip-cert-verify"] === true)
    .param("tls-profile", getTlsProfile(node))
    .param("alpn", pickStringList(node.alpn).join(","), true);

  if (!node["reality-opts"]) {
    builder.param("tls-name", getSni(node));
    return null;
  }
  const reality = asRecord(node["reality-opts"]);
  const publicKey = pickString(reality["public-key"]);
  if (!publicKey) return "Reality 缺少 public-key";
  builder.param("sni", getSni(node)).param("public-key", publicKey, true).param("short-id", pickString(reality["short-id"]));
  return null;
}

function appendTransport(builder: LineBuilder, node: Record<string, unknown>): string | null {
  const network = pickString(node.network) || "tcp";
  if (network === "tcp") {
    builder.param("transport", "tcp");
    return null;
  }
  if (network === "ws") {
    const opts = asRecord(node["ws-opts"]);
    if (opts["v2ray-http-upgrade"] === true) return "Loon 不支持 HTTPUpgrade";
    const headers = asRecord(opts.headers);
    builder
      .param("transport", "ws")
      .param("path", pickString(opts.path) || "/")
      .param("host", pickString(headers.Host ?? headers.host));
    return null;
  }
  if (network === "http") {
    const opts = asRecord(node["http-opts"]);
    const headers = asRecord(opts.headers);
    builder
      .param("transport", "http")
      .param("path", pickStringList(opts.path)[0] || "/")
      .param("host", pickStringList(headers.Host ?? headers.host)[0]);
    return null;
  }
  return `Loon 不支持 ${network} 传输`;
}

function appendCommon(builder: LineBuilder, node: Record<string, unknown>, udp: boolean): LoonProxyLineResult {
  return builder
    .enable("fast-open", node.tfo === true)
    .enable("udp", udp && node.udp !== false)
    .param("ip-mode", LOON_IP_MODES[pickString(node["ip-version"])])
    .build();
}

function appendCredentials(builder: LineBuilder, node: Record<string, unknown>) {
  const username = pickString(node.username);
  if (username) builder.value(username).quoted(pickString(node.password));
  return builder;
}

function buildShadowsocks(name: string, node: Record<string, unknown>): LoonProxyLineResult {
  const cipher = pickString(node.cipher).toLowerCase();
  if (!LOON_SS_CIPHERS.has(cipher)) return skip(`Loon 不支持 Shadowsocks 加密方式 ${cipher}`);
  const builder = endpoint(new LineBuilder(name, "Shadowsocks"), node).value(cipher).quoted(pickString(node.password));

  const plugin = pickString(node.plugin);
  const opts = asRecord(node["plugin-opts"]);
  if (plugin === "obfs") {
    const mode = pickString(opts.mode);
    if (mode !== "http" && mode !== "tls") return skip(`Loon 不支持 obfs 模式 ${mode}`);
    builder.param("obfs-name", mode).param("obfs-host", pickString(opts.host)).param("obfs-uri", pickString(opts.path));
  } else if (plugin === "shadow-tls") {
    const version = pickNumber(opts.version);
    if (version !== undefined && version < 2) return skip("Loon 仅支持 ShadowTLS v2/v3");
    builder
      .param("shadow-tls-password", pickString(opts.password))
      .param("shadow-tls-sni", pickString(opts.host))
      .param("shadow-tls-version", version);
  } else if (plugin) {
    return skip(`Loon 不支持 Shadowsocks 插件 ${plugin}`);
  }

  // Loon 的 udp-over-tcp 仅兼容 v2，且不能与 obfs 同时使用
  builder.enable(
    "udp-over-tcp",
    node["udp-over-tcp"] === true && pickNumber(node["udp-over-tcp-version"]) === 2 && plugin !== "obfs"
  );
  return appendCommon(builder, node, true);
}

function buildShadowsocksR(name: string, node: Record<string, unknown>): LoonProxyLineResult {
  const builder = endpoint(new LineBuilder(name, "ShadowsocksR"), node)
    .value(pickString(node.cipher))
    .quoted(pickString(node.password))
    .param("protocol", pickString(node.protocol))
    .param("protocol-param", pickString(node["protocol-param"]))
    .param("obfs", pickString(node.obfs))
    .param("obfs-param", pickString(node["obfs-param"]));
  return appendCommon(builder, node, true);
}

function buildVmess(name: string, node: Record<string, unknown>): LoonProxyLineResult {
  const cipher = LOON_VMESS_CIPHERS[pickString(node.cipher).toLowerCase()] ?? "auto";
  const builder = endpoint(new LineBuilder(name, "VMess"), node).value(cipher).quoted(pickString(node.uuid));
  const transportError = appendTransport(builder, node);
  if (transportError) return skip(transportError);
  builder.param("alterId", pickNumber(node.alterId) ?? 0).param("over-tls", String(node.tls === true));
  const tlsError = node.tls === true ? appendTls(builder, node) : null;
  return tlsError ? skip(tlsError) : appendCommon(builder, node, true);
}

function buildVless(name: string, node: Record<string, unknown>): LoonProxyLineResult {
  const encryption = pickString(node.encryption);
  if (encryption && encryption !== "none") return skip("Loon 不支持 VLESS encryption");
  const flow = pickString(node.flow);
  if (flow && flow !== "xtls-rprx-vision") return skip(`Loon 不支持 VLESS flow ${flow}`);

  const builder = endpoint(new LineBuilder(name, "VLESS"), node).quoted(pickString(node.uuid));
  const transportError = appendTransport(builder, node);
  if (transportError) return skip(transportError);
  const tls = node.tls === true || Boolean(node["reality-opts"]);
  builder.param("flow", flow).param("over-tls", String(tls));
  const tlsError = tls ? appendTls(builder, node) : null;
  return tlsError ? skip(tlsError) : appendCommon(builder, node, true);
}

function buildTrojan(name: string, node: Record<string, unknown>): LoonProxyLineResult {
  const builder = endpoint(new LineBuilder(name, "Trojan"), node).quoted(pickString(node.password));
  // Trojan 默认就是 TCP，不输出 transport=tcp
  const transportError = pickString(node.network) && node.network !== "tcp" ? appendTransport(builder, node) : null;
  const error = transportError ?? appendTls(builder, node);
  return error ? skip(error) : appendCommon(builder, node, true);
}

function buildAnyTls(name: string, node: Record<string, unknown>): LoonProxyLineResult {
  const builder = endpoint(new LineBuilder(name, "AnyTLS"), node).quoted(pickString(node.password));
  const tlsError = appendTls(builder, node);
  if (tlsError) return skip(tlsError);
  const idleTimeout = pickNumber(node["idle-session-timeout"]);
  builder.param("idle-session-timeout", Number.isInteger(idleTimeout) ? idleTimeout : undefined);
  return appendCommon(builder, node, true);
}

function buildHysteria2(name: string, node: Record<string, unknown>): LoonProxyLineResult {
  const obfs = pickString(node.obfs);
  if (obfs && obfs !== "salamander") return skip("Loon 仅支持 salamander 混淆");
  const builder = endpoint(new LineBuilder(name, "Hysteria2"), node)
    .quoted(pickString(node.password))
    .param("tls-name", pickString(node.sni))
    .enable("skip-cert-verify", node["skip-cert-verify"] === true)
    .param("alpn", pickStringList(node.alpn).join(","), true)
    .param("salamander-password", obfs ? pickString(node["obfs-password"]) : undefined)
    .param("server-ports", pickString(node.ports), true)
    .param("hop-interval", pickNumber(node["hop-interval"]))
    .param("download-bandwidth", pickString(node.down).match(/\d+/)?.[0]);
  return appendCommon(builder, node, true);
}

function buildHttp(name: string, node: Record<string, unknown>): LoonProxyLineResult {
  const tls = node.type === "https" || node.tls === true;
  const builder = appendCredentials(endpoint(new LineBuilder(name, tls ? "HTTPS" : "HTTP"), node), node);
  if (tls) {
    builder
      .param("sni", pickString(node.sni))
      .enable("skip-cert-verify", node["skip-cert-verify"] === true)
      .param("tls-profile", getTlsProfile(node));
  }
  return appendCommon(builder, node, false);
}

function buildSocks5(name: string, node: Record<string, unknown>): LoonProxyLineResult {
  const builder = appendCredentials(endpoint(new LineBuilder(name, "SOCKS5"), node), node);
  if (node.tls === true) {
    builder
      .enable("over-tls", true)
      .param("sni", pickString(node.sni))
      .enable("skip-cert-verify", node["skip-cert-verify"] === true);
  }
  return appendCommon(builder, node, true);
}

function decodeReserved(value: unknown): number[] {
  if (Array.isArray(value)) return value.map(pickNumber).filter((item): item is number => item !== undefined);
  const text = pickString(value);
  if (/^\d+(\s*,\s*\d+)*$/.test(text)) return text.split(",").map(Number);
  // Mihomo 也接受 base64 形式的 reserved（如 "U4An"）
  try {
    return Array.from(atob(text), (char) => char.charCodeAt(0));
  } catch {
    return [];
  }
}

function buildWireGuard(name: string, node: Record<string, unknown>): LoonProxyLineResult {
  const privateKey = pickString(node["private-key"]);
  if (!privateKey) return skip("WireGuard 缺少 private-key");
  const rawPeers = Array.isArray(node.peers) && node.peers.length > 0 ? node.peers.map(asRecord) : [node];

  const peers: string[] = [];
  const quotedValues: string[] = [];
  for (const peer of rawPeers) {
    const server = pickString(peer.server);
    const port = pickNumber(peer.port);
    const publicKey = pickString(peer["public-key"]);
    if (!server || port === undefined || !publicKey) return skip("WireGuard peer 缺少 server、port 或 public-key");
    const allowedIps = pickStringList(peer["allowed-ips"]).join(",") || "0.0.0.0/0,::/0";
    const presharedKey = pickString(peer["pre-shared-key"] ?? peer["preshared-key"]);
    const reserved = decodeReserved(peer.reserved);
    const host = server.includes(":") ? `[${server}]` : server;
    const fields = [`public-key="${publicKey}"`, `allowed-ips="${allowedIps}"`, `endpoint=${host}:${port}`];
    if (presharedKey) fields.push(`preshared-key="${presharedKey}"`);
    if (reserved.length > 0) fields.push(`reserved=[${reserved.join(",")}]`);
    peers.push(`{${fields.join(",")}}`);
    quotedValues.push(publicKey, allowedIps, presharedKey, server);
  }

  const dnsList = pickStringList(node.dns);
  const builder = new LineBuilder(name, "WireGuard")
    .param("interface-ip", pickString(node.ip).replace(/\/\d+$/, ""))
    .param("interface-ipv6", pickString(node.ipv6).replace(/\/\d+$/, ""))
    .param("private-key", privateKey, true)
    .param("mtu", pickNumber(node.mtu))
    .param("dns", dnsList.find((item) => !item.includes(":")))
    .param("dnsv6", dnsList.find((item) => item.includes(":")))
    .param("keepalive", pickNumber(node["persistent-keepalive"] ?? node.keepalive))
    .raw(`peers=[${peers.join(",")}]`, quotedValues);
  return appendCommon(builder, node, true);
}

const LOON_PROXY_BUILDERS: Record<string, (name: string, node: Record<string, unknown>) => LoonProxyLineResult> = {
  ss: buildShadowsocks,
  ssr: buildShadowsocksR,
  vmess: buildVmess,
  vless: buildVless,
  trojan: buildTrojan,
  anytls: buildAnyTls,
  hysteria2: buildHysteria2,
  http: buildHttp,
  https: buildHttp,
  socks5: buildSocks5,
  wireguard: buildWireGuard,
};

/**
 * 单个 Clash 节点 → Loon [Proxy] 行
 */
export function buildLoonProxyLine(node: Record<string, unknown>, name: string): LoonProxyLineResult {
  const type = pickString(node.type);
  const builder = LOON_PROXY_BUILDERS[type];
  if (!builder) return skip(`Loon 不支持 ${type} 协议`);
  if (type !== "wireguard" && (!pickString(node.server) || pickNumber(node.port) === undefined)) {
    return skip("缺少服务器地址或端口");
  }
  return builder(name, node);
}

function buildLoonGroupLine(group: ProxyGroup, name: string, members: string[], testUrl: string): string {
  const type = pickString(group.type);
  // 空组 Loon 会拒绝加载，退化为只含 DIRECT 的手动组
  if (members.length === 0) return `${name} = select,DIRECT`;
  if (!LOON_AUTO_GROUP_TYPES.has(type)) return `${name} = select,${members.join(",")}`;

  const params = [
    `url=${pickString(group.url) || testUrl}`,
    `interval=${pickNumber(group.interval) ?? DEFAULT_TEST_INTERVAL}`,
  ];
  if (type === "url-test" && group.tolerance !== undefined) params.push(`tolerance=${group.tolerance}`);
  if (type !== "url-test") params.push("max-timeout=3000");
  if (type === "load-balance") params.push(`algorithm=${LOON_LOAD_BALANCE_ALGORITHMS[pickString(group.strategy)] ?? "pcc"}`);
  return `${name} = ${type},${members.join(",")},${params.join(",")}`;
}

function buildGeneralSection(config: ClashConfig, testUrl: string): string[] {
  const dns = splitDnsServers(config);
  const encrypted: Array<[key: string, servers: string[]]> = [
    ["doh-server", dns.doh],
    ["doh3-server", dns.doh3],
    ["doq-server", dns.doq],
  ];
  return [
    `skip-proxy = ${DEFAULT_SKIP_PROXY}`,
    `bypass-tun = ${DEFAULT_BYPASS_TUN}`,
    `dns-server = system,${dns.plain.join(",")}`,
    ...encrypted.filter(([, servers]) => servers.length > 0).map(([key, servers]) => `${key} = ${servers.join(",")}`),
    `ip-mode = ${config.ipv6 === false ? "v4-only" : "dual"}`,
    "allow-wifi-access = false",
    `proxy-test-url = ${testUrl}`,
    "internet-test-url = http://wifi.vivo.com.cn/generate_204",
    "test-timeout = 5",
    "sni-sniffing = true",
    "disable-stun = false",
  ];
}

/**
 * Clash 配置 → Loon .conf 文本
 */
export function generateLoonConfigFromClash(config: ClashConfig, options: IosClientConfigOptions): string {
  const inputs = collectIosClientInputs(config);
  const groupByName = new Map(inputs.groups.map((group) => [group.name, group]));
  const providerNames = Object.keys(inputs.proxyProviders);
  const nodeNames = inputs.nodes.map((node) => pickString(node.name));

  // 中转（dialer-proxy）节点在 Loon 中拆成“落地节点 + 代理链”，代理链沿用原节点名，
  // 这样代理组/规则里对原节点的引用无需改动。
  const nameMap = createPolicyNameMap([
    ...nodeNames,
    ...inputs.groups.map((group) => group.name),
    ...providerNames,
    ...nodeNames.map((name) => `${name}${LANDING_SUFFIX}`),
  ]);

  const skippedNodes: string[] = [];
  const availableNodes = new Map<string, Record<string, unknown>>();
  for (const node of inputs.nodes) {
    const original = pickString(node.name);
    const result = buildLoonProxyLine(node, nameMap.get(original)!);
    if (result.ok) availableNodes.set(original, node);
    else skippedNodes.push(`${original}：${result.reason}`);
  }

  const providerPolicies = new Map<string, string>();
  const remoteProxyLines: string[] = [];
  for (const providerName of providerNames) {
    const url = pickString(asRecord(inputs.proxyProviders[providerName]).url);
    if (!url) continue;
    providerPolicies.set(providerName, nameMap.get(providerName)!);
    remoteProxyLines.push(
      `${nameMap.get(providerName)} = ${url},udp=default,fast-open=default,skip-cert-verify=default,enabled=true`
    );
  }

  const resolvePolicy: PolicyResolver = (name) => {
    const builtin = resolveBuiltinPolicy(name);
    if (builtin) return builtin;
    if (availableNodes.has(name) || groupByName.has(name)) return nameMap.get(name)!;
    return providerPolicies.get(name) ?? null;
  };

  const chainLines: string[] = [];
  const chainedNodes = new Set<string>();
  for (const [original, node] of availableNodes) {
    const dialer = pickString(node["dialer-proxy"]);
    // 中转组只有一个可用节点时直接链到该节点，兼容性最好；否则链到中转组本身
    const relayMembers = (groupByName.get(dialer)?.proxies ?? []).filter((member) => availableNodes.has(member));
    const relay = relayMembers.length === 1 ? nameMap.get(relayMembers[0]!)! : resolvePolicy(dialer);
    // 中转不可用（或直连）时按普通节点输出，避免代理组引用到不存在的代理链
    if (!relay || relay === "DIRECT" || relay === "REJECT") continue;
    chainedNodes.add(original);
    chainLines.push(`${nameMap.get(original)} = ${relay},${nameMap.get(`${original}${LANDING_SUFFIX}`)},udp=true`);
  }

  const proxyLines = [...availableNodes].map(([original, node]) => {
    const lineName = nameMap.get(chainedNodes.has(original) ? `${original}${LANDING_SUFFIX}` : original)!;
    return (buildLoonProxyLine(node, lineName) as { line: string }).line;
  });

  const groupLines = inputs.groups.map((group) => {
    const name = nameMap.get(group.name)!;
    const members = [
      ...resolveGroupMembers(group, name, resolvePolicy),
      ...(group.use ?? []).flatMap((provider) => providerPolicies.get(provider) ?? []),
    ];
    return buildLoonGroupLine(group, name, [...new Set(members)], inputs.testUrl);
  });

  const rules = convertIosRules({
    rules: inputs.rules,
    ruleProviders: inputs.ruleProviders,
    plainTypes: LOON_RULE_TYPES,
    resolvePolicy,
    options,
  });

  const header = [
    "# Loon 配置 — 由 SubBoost 生成，请勿手动修改（更新订阅会覆盖）",
    ...(options.configUrl ? [`# 配置地址：${options.configUrl}`] : []),
    "# 说明：Loon 的匹配优先级为 本地规则 > 远程规则，且域名类规则先于 IP 类规则，",
    "#       因此自定义的本地规则会排在所有规则集之前生效。",
    ...commentList("# 以下节点 Loon 不支持，已跳过：", skippedNodes),
    ...commentList("# 以下规则 Loon 不支持，已跳过：", rules.skipped),
  ];

  return [
    header.join("\n"),
    renderSection("General", buildGeneralSection(config, inputs.testUrl)),
    renderSection("Proxy", proxyLines),
    renderSection("Remote Proxy", remoteProxyLines),
    renderSection("Proxy Group", groupLines),
    renderSection("Proxy Chain", chainLines),
    renderSection("Rule", [
      ...rules.entries.flatMap((entry) => (entry.kind === "plain" ? [entry.line] : [])),
      `FINAL,${rules.finalPolicy}`,
    ]),
    renderSection(
      "Remote Rule",
      rules.entries.flatMap((entry) =>
        entry.kind === "rule-set" ? [`${entry.url},policy=${entry.target},tag=${entry.name},enabled=true`] : []
      )
    ),
  ].join("\n\n") + "\n";
}
