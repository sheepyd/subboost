/**
 * MetaCubeX meta-rules-dat 的 .list（Mihomo text 格式）→ Surge/Loon/Shadowrocket 经典规则列表
 *
 * Mihomo text 规则集没有规则类型前缀：
 * - domain 行为：`example.com` 精确匹配，`+.example.com` 匹配自身及子域名，
 *   `.example.com` 仅匹配子域名，`*.example.com` 匹配单层子域名
 * - ipcidr 行为：每行一个 CIDR
 * iOS 客户端的 RULE-SET / Remote Rule 需要带类型的经典格式（DOMAIN-SUFFIX,xxx）。
 * SubBoost 生成的 rule-provider 只有 domain / ipcidr 两种行为。
 */

export interface ConvertRuleSetTextOptions {
  behavior: "domain" | "ipcidr";
  // 为 IP 类规则追加 no-resolve（与 Clash 规则行上的 no-resolve 等价）
  noResolve: boolean;
}

/**
 * rule-provider 的 mrs 地址 → 同目录的 text 版本地址（meta-rules-dat 对每个规则集同时发布 .mrs/.list/.yaml）
 */
export function toRuleSetTextUrl(url: string): string {
  return url.replace(/\.mrs$/i, ".list");
}

function convertDomainEntry(entry: string): string | null {
  // `+.` / `.` / `*.` 前缀都按后缀匹配（经典格式没有“仅子域名/单层通配”的写法，会额外命中根域名）
  const suffix = entry.replace(/^[+*]?\./, "");
  // 中间带通配符的写法无法安全表达，直接跳过
  if (!suffix || suffix.includes("*")) return null;
  return suffix === entry ? `DOMAIN,${entry}` : `DOMAIN-SUFFIX,${suffix}`;
}

function convertIpEntry(entry: string, noResolve: boolean): string {
  const type = entry.includes(":") ? "IP-CIDR6" : "IP-CIDR";
  return noResolve ? `${type},${entry},no-resolve` : `${type},${entry}`;
}

/**
 * 把 Mihomo text / yaml payload 规则集转换为经典规则列表文本（每行一条，带类型前缀）
 */
export function convertMihomoRuleSetText(content: string, options: ConvertRuleSetTextOptions): string {
  const out = new Set<string>();

  for (const rawLine of content.split(/\r?\n/)) {
    // 兼容 yaml payload 写法：`payload:` / `  - 'example.com'`
    const entry = rawLine
      .trim()
      .replace(/^-\s+/, "")
      .replace(/^['"]|['"]$/g, "")
      .trim();
    if (!entry || entry.startsWith("#") || entry === "payload:") continue;
    const converted = options.behavior === "ipcidr" ? convertIpEntry(entry, options.noResolve) : convertDomainEntry(entry);
    if (converted) out.add(converted);
  }

  return out.size > 0 ? `${[...out].join("\n")}\n` : "";
}
