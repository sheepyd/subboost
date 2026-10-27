import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  handleIosClientConfigRequest: vi.fn(async () => new Response("conf")),
  handleRuleSetRequest: vi.fn(async () => new Response("list")),
}));

vi.mock("@local/lib/ios-client-route", () => mocks);

import * as loonRoute from "./loon.conf/route";
import * as shadowrocketRoute from "./shadowrocket.conf/route";
import * as ruleSetRoute from "./rule-sets/[name]/route";

describe("iOS client route entry points", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("delegates config downloads with the matching client target", async () => {
    const request = new Request("https://local.test/api/subscriptions/token/loon.conf");

    expect(await (await loonRoute.GET(request, { params: Promise.resolve({ id: "token" }) })).text()).toBe("conf");
    expect(mocks.handleIosClientConfigRequest).toHaveBeenLastCalledWith(request, "token", "loon");

    await shadowrocketRoute.GET(request, { params: Promise.resolve({ id: "token" }) });
    expect(mocks.handleIosClientConfigRequest).toHaveBeenLastCalledWith(request, "token", "shadowrocket");
  });

  it("delegates rule set downloads with the provider file name", async () => {
    const request = new Request("https://local.test/api/subscriptions/token/rule-sets/google.list");

    expect(await (await ruleSetRoute.GET(request, { params: Promise.resolve({ id: "token", name: "google.list" }) })).text()).toBe("list");
    expect(mocks.handleRuleSetRequest).toHaveBeenCalledWith(request, "token", "google.list");
  });
});
