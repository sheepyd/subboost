import type { IosClientConfigOptions } from "./ios-client-shared";

export function buildTestClientOptions(target: "loon" | "shadowrocket"): IosClientConfigOptions {
  return {
    configUrl: `https://sub.example.com/api/subscriptions/token/${target}.conf`,
    nodeSubscriptionUrl: "https://sub.example.com/api/subscriptions/token/config.yaml",
    resolveRuleSetUrl: ({ name, noResolve }) =>
      `https://sub.example.com/api/subscriptions/token/rule-sets/${name}.list${noResolve ? "?no-resolve=1" : ""}`,
  };
}

// 取出某个 [Section] 下的非空行
export function section(config: string, title: string): string[] {
  const lines = config.split("\n");
  const start = lines.indexOf(`[${title}]`);
  if (start === -1) return [];
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((item) => item.startsWith("["));
  return (end === -1 ? rest : rest.slice(0, end)).filter((item) => item.trim() !== "");
}
