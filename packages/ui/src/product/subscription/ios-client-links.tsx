"use client";

import { Copy } from "lucide-react";
import type { IosClientTarget } from "@subboost/core/generator/ios-client-shared";
import { Button } from "@subboost/ui/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@subboost/ui/components/ui/dropdown-menu";
import { IconButton } from "@subboost/ui/components/ui/icon-button";
import { Input } from "@subboost/ui/components/ui/input";
import { toast } from "@subboost/ui/components/ui/toaster";
import { copyTextToClipboard } from "@subboost/ui/lib/clipboard";

const IOS_CLIENTS: Array<{ target: IosClientTarget; label: string; hint: string }> = [
  {
    target: "loon",
    label: "Loon",
    hint: "配置 → 从 URL 下载配置；已包含节点、代理组、规则和代理链",
  },
  {
    target: "shadowrocket",
    label: "Shadowrocket",
    hint: "先在首页 ➕ 以 Subscribe 类型添加上方 Clash 订阅导入节点，再在 配置 → ➕ 下载此配置",
  },
];

const CONFIG_YAML_PATH = /\/config\.yaml(?=$|[?#])/;

export type IosClientLink = (typeof IOS_CLIENTS)[number] & { url: string };

/**
 * Clash 订阅链接 → 同一订阅的 Loon / Shadowrocket 配置链接（对应服务端路由 /api/subscriptions/:token/:target.conf）
 */
export function buildIosClientLinks(subscriptionUrl: string): IosClientLink[] {
  if (!CONFIG_YAML_PATH.test(subscriptionUrl)) return [];
  return IOS_CLIENTS.map((client) => ({
    ...client,
    url: subscriptionUrl.replace(CONFIG_YAML_PATH, `/${client.target}.conf`),
  }));
}

export async function copyIosClientLink(link: IosClientLink): Promise<void> {
  const copied = await copyTextToClipboard(link.url);
  toast(
    copied
      ? { title: `已复制 ${link.label} 配置链接`, variant: "success" }
      : { title: "复制失败，请手动复制订阅链接", variant: "destructive" }
  );
}

export function IosClientLinkList({ subscriptionUrl }: { subscriptionUrl: string }) {
  const links = buildIosClientLinks(subscriptionUrl);
  if (links.length === 0) return null;

  return (
    <div className="space-y-3">
      <p className="text-sm font-medium">iOS 客户端</p>
      {links.map((link) => (
        <div key={link.target} className="space-y-1">
          <p className="text-xs text-fg-60">{link.label} 配置链接</p>
          <div className="flex gap-2">
            <Input value={link.url} readOnly className="font-mono text-xs" />
            <IconButton
              label={`复制 ${link.label} 配置链接`}
              variant="outline"
              onClick={() => void copyIosClientLink(link)}
              className="flex-shrink-0"
            >
              <Copy className="h-4 w-4" />
            </IconButton>
          </div>
          <p className="text-xs text-fg-50">{link.hint}</p>
        </div>
      ))}
    </div>
  );
}

export function IosClientLinksMenu({ subscriptionUrl }: { subscriptionUrl: string }) {
  const links = buildIosClientLinks(subscriptionUrl);
  if (links.length === 0) return null;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm" className="gap-0 sm:gap-2" title="复制 Loon / Shadowrocket 配置链接">
          <Copy className="h-4 w-4" />
          <span className="hidden sm:inline">iOS</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-72 border-ink/10 bg-surface-raised text-fg">
        {links.map((link) => (
          <DropdownMenuItem
            key={link.target}
            onSelect={() => void copyIosClientLink(link)}
            className="flex-col items-start gap-1 py-2.5 focus:bg-ink/5 focus:text-fg"
          >
            <span className="text-sm">复制 {link.label} 配置链接</span>
            <span className="text-xs text-fg-50">{link.hint}</span>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
