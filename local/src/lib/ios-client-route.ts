import type { IosClientTarget } from "@subboost/core/generator/ios-client-shared";
import { buildSubscriptionResponseHeaders } from "@subboost/server-core/subscription";
import { apiError } from "./http";
import {
  consumeLocalRateLimit,
  getTrustedClientRateLimitKey,
  hashLocalRateLimitKey,
  localRateLimitResponse,
} from "./rate-limit";
import {
  generateSubscriptionIosConfig,
  resolveSubscriptionRuleSetSource,
} from "./subscription-service";
import { loadConvertedRuleSet } from "./rule-set-convert";

const RATE_LIMIT_MESSAGE = "Too many subscription requests. Try again later.";

// 与 config.yaml 共用同一组限流桶：同一订阅无论以哪种格式拉取都计入同一配额
function consumeSubscriptionDownloadLimit(request: Request, token: string): Response | null {
  const clientKey = getTrustedClientRateLimitKey(request);
  if (clientKey) {
    const clientLimit = consumeLocalRateLimit("subscription-yaml-client", clientKey, {
      limit: 600,
      windowMs: 60_000,
    });
    if (!clientLimit.allowed) return localRateLimitResponse(RATE_LIMIT_MESSAGE, clientLimit.retryAfterSeconds);
  }
  const tokenLimit = consumeLocalRateLimit("subscription-yaml-token", hashLocalRateLimitKey(token), {
    limit: 120,
    windowMs: 60_000,
  });
  if (!tokenLimit.allowed) return localRateLimitResponse(RATE_LIMIT_MESSAGE, tokenLimit.retryAfterSeconds);
  return null;
}

export async function handleIosClientConfigRequest(
  request: Request,
  token: string,
  target: IosClientTarget
): Promise<Response> {
  const limited = consumeSubscriptionDownloadLimit(request, token);
  if (limited) return limited;

  const result = await generateSubscriptionIosConfig(token, target);
  if (!result) return apiError("Subscription config not found.", "NOT_FOUND", 404);
  const headers = buildSubscriptionResponseHeaders(result.name, result.subscriptionInfo, {
    cacheControl: "no-store",
    cacheExpirySeconds: result.cacheExpirySeconds,
    autoUpdateIntervalSeconds: result.autoUpdateIntervalSeconds,
    isAdmin: result.isAdmin,
  });
  return new Response(result.content, {
    headers: { ...headers, "content-type": "text/plain;charset=utf-8" },
  });
}

const RULE_SET_NAME_SUFFIX = /\.list$/i;

export async function handleRuleSetRequest(request: Request, token: string, rawName: string): Promise<Response> {
  // 客户端更新配置时会并发拉取全部规则集，单独计数，避免挤占订阅本身的配额
  const tokenLimit = consumeLocalRateLimit("subscription-rule-set-token", hashLocalRateLimitKey(token), {
    limit: 600,
    windowMs: 60_000,
  });
  if (!tokenLimit.allowed) return localRateLimitResponse(RATE_LIMIT_MESSAGE, tokenLimit.retryAfterSeconds);

  let providerName: string;
  try {
    providerName = decodeURIComponent(rawName).replace(RULE_SET_NAME_SUFFIX, "");
  } catch {
    return apiError("Rule set not found.", "NOT_FOUND", 404);
  }
  const source = await resolveSubscriptionRuleSetSource(token, providerName);
  if (!source) return apiError("Rule set not found.", "NOT_FOUND", 404);

  const noResolve = new URL(request.url).searchParams.get("no-resolve") === "1";
  const result = await loadConvertedRuleSet({ ...source, noResolve });
  if (!result.ok) return apiError(result.error, "UPSTREAM_ERROR", result.status);
  return new Response(result.content, {
    headers: {
      "content-type": "text/plain;charset=utf-8",
      "cache-control": "public, max-age=3600",
    },
  });
}
