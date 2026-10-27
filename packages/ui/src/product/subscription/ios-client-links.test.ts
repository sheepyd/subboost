import * as React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  captures: { iconButtons: [] as any[], menuItems: [] as any[] },
  copyTextToClipboard: vi.fn(),
  toast: vi.fn(),
}));

vi.mock("@subboost/ui/lib/clipboard", () => ({ copyTextToClipboard: mocks.copyTextToClipboard }));
vi.mock("@subboost/ui/components/ui/toaster", () => ({ toast: mocks.toast }));
vi.mock("@subboost/ui/components/ui/icon-button", () => ({
  IconButton: (props: any) => {
    mocks.captures.iconButtons.push(props);
    return React.createElement("button", { "aria-label": props.label }, props.children);
  },
}));
vi.mock("@subboost/ui/components/ui/dropdown-menu", () => ({
  DropdownMenu: (props: any) => React.createElement("div", null, props.children),
  DropdownMenuTrigger: (props: any) => React.createElement("div", null, props.children),
  DropdownMenuContent: (props: any) => React.createElement("div", null, props.children),
  DropdownMenuItem: (props: any) => {
    mocks.captures.menuItems.push(props);
    return React.createElement("div", null, props.children);
  },
}));

import { IosClientLinkList, IosClientLinksMenu, buildIosClientLinks, copyIosClientLink } from "./ios-client-links";

const SUBSCRIPTION_URL = "https://sub.example.com/api/subscriptions/abc/config.yaml";

describe("iOS client config links", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.captures.iconButtons = [];
    mocks.captures.menuItems = [];
  });

  it("derives Loon and Shadowrocket URLs from the Clash subscription URL", () => {
    expect(buildIosClientLinks(SUBSCRIPTION_URL).map((link) => link.url)).toEqual([
      "https://sub.example.com/api/subscriptions/abc/loon.conf",
      "https://sub.example.com/api/subscriptions/abc/shadowrocket.conf",
    ]);
    expect(buildIosClientLinks(`${SUBSCRIPTION_URL}?flag=1`)[1]!.url).toBe(
      "https://sub.example.com/api/subscriptions/abc/shadowrocket.conf?flag=1"
    );
    expect(buildIosClientLinks("https://sub.example.com/api/subscriptions/abc")).toEqual([]);
  });

  it("copies links and reports the result", async () => {
    const [loon] = buildIosClientLinks(SUBSCRIPTION_URL);

    mocks.copyTextToClipboard.mockResolvedValueOnce(true);
    await copyIosClientLink(loon!);
    expect(mocks.copyTextToClipboard).toHaveBeenCalledWith("https://sub.example.com/api/subscriptions/abc/loon.conf");
    expect(mocks.toast).toHaveBeenLastCalledWith({ title: "已复制 Loon 配置链接", variant: "success" });

    mocks.copyTextToClipboard.mockResolvedValueOnce(false);
    await copyIosClientLink(loon!);
    expect(mocks.toast).toHaveBeenLastCalledWith({ title: "复制失败，请手动复制订阅链接", variant: "destructive" });
  });

  it("renders a copy row per client in the link dialog", () => {
    mocks.copyTextToClipboard.mockResolvedValue(true);
    const html = renderToStaticMarkup(React.createElement(IosClientLinkList, { subscriptionUrl: SUBSCRIPTION_URL }));

    expect(html).toContain("https://sub.example.com/api/subscriptions/abc/loon.conf");
    expect(html).toContain("https://sub.example.com/api/subscriptions/abc/shadowrocket.conf");
    expect(mocks.captures.iconButtons.map((props) => props.label)).toEqual([
      "复制 Loon 配置链接",
      "复制 Shadowrocket 配置链接",
    ]);
    mocks.captures.iconButtons[1].onClick();
    expect(mocks.copyTextToClipboard).toHaveBeenCalledWith("https://sub.example.com/api/subscriptions/abc/shadowrocket.conf");
    expect(renderToStaticMarkup(React.createElement(IosClientLinkList, { subscriptionUrl: "" }))).toBe("");
  });

  it("renders a dashboard menu with one item per client", () => {
    mocks.copyTextToClipboard.mockResolvedValue(true);
    const html = renderToStaticMarkup(React.createElement(IosClientLinksMenu, { subscriptionUrl: SUBSCRIPTION_URL }));

    expect(html).toContain("复制 Loon 配置链接");
    expect(html).toContain("复制 Shadowrocket 配置链接");
    mocks.captures.menuItems[0].onSelect();
    expect(mocks.copyTextToClipboard).toHaveBeenCalledWith("https://sub.example.com/api/subscriptions/abc/loon.conf");
    expect(renderToStaticMarkup(React.createElement(IosClientLinksMenu, { subscriptionUrl: "" }))).toBe("");
  });
});
