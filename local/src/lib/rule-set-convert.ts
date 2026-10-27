import "server-only";

import { convertMihomoRuleSetText, toRuleSetTextUrl } from "@subboost/core/generator/rule-set-text";
import { fetchPublicTextDirect } from "./source-import";

const CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const MAX_CACHE_ENTRIES = 128;
const FETCH_TIMEOUT_MS = 20_000;
// geosite/cn 的 text 版本约 2MB，留足余量
const MAX_RULE_SET_BYTES = 16 * 1024 * 1024;
const RULE_SET_USER_AGENT = "SubBoost-RuleSet/1.0";

type CacheEntry = { content: string; expiresAt: number };

const cache = new Map<string, CacheEntry>();
const inflight = new Map<string, Promise<ConvertedRuleSetResult>>();

export type ConvertedRuleSetResult =
  | { ok: true; content: string }
  | { ok: false; status: number; error: string };

function remember(key: string, content: string) {
  cache.delete(key);
  cache.set(key, { content, expiresAt: Date.now() + CACHE_TTL_MS });
  // Map 按插入顺序迭代，超出上限时淘汰最早写入的条目
  for (const oldest of cache.keys()) {
    if (cache.size <= MAX_CACHE_ENTRIES) break;
    cache.delete(oldest);
  }
}

async function fetchAndConvert(
  textUrl: string,
  behavior: "domain" | "ipcidr",
  noResolve: boolean
): Promise<ConvertedRuleSetResult> {
  const response = await fetchPublicTextDirect({
    url: textUrl,
    userAgent: RULE_SET_USER_AGENT,
    timeoutMs: FETCH_TIMEOUT_MS,
    maxBytes: MAX_RULE_SET_BYTES,
  });
  if (!response.ok) return { ok: false, status: 502, error: response.publicReason ?? "规则集下载失败" };
  const content = convertMihomoRuleSetText(response.content ?? "", { behavior, noResolve });
  return content ? { ok: true, content } : { ok: false, status: 502, error: "规则集为空或不是文本格式" };
}

/**
 * 下载 rule-provider 对应的 text 版本并转换为 Loon / Shadowrocket 可读的经典规则列表。
 * 上游失败时，若有过期缓存则继续返回旧内容，避免客户端规则集被清空。
 */
export async function loadConvertedRuleSet(params: {
  url: string;
  behavior: string;
  noResolve: boolean;
}): Promise<ConvertedRuleSetResult> {
  const textUrl = toRuleSetTextUrl(params.url);
  const behavior = params.behavior === "ipcidr" ? "ipcidr" : "domain";
  const key = `${behavior}|${params.noResolve}|${textUrl}`;
  const cached = cache.get(key);
  if (cached && cached.expiresAt > Date.now()) return { ok: true, content: cached.content };

  let task = inflight.get(key);
  if (!task) {
    task = fetchAndConvert(textUrl, behavior, params.noResolve).finally(() => inflight.delete(key));
    inflight.set(key, task);
  }
  const result = await task;
  if (result.ok) remember(key, result.content);
  return !result.ok && cached ? { ok: true, content: cached.content } : result;
}

export function clearRuleSetCacheForTests(): void {
  cache.clear();
  inflight.clear();
}
