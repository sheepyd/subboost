import { describe, expect, it } from "vitest";
import { convertMihomoRuleSetText, toRuleSetTextUrl } from "./rule-set-text";

describe("Mihomo text rule set conversion", () => {
  it("maps mrs provider URLs to their text siblings", () => {
    expect(toRuleSetTextUrl("https://example.com/geo/geosite/google.mrs")).toBe(
      "https://example.com/geo/geosite/google.list"
    );
    expect(toRuleSetTextUrl("https://example.com/custom/rules.yaml")).toBe("https://example.com/custom/rules.yaml");
  });

  it("converts domain entries to classical rules", () => {
    const content = [
      "# comment",
      "google.com",
      "+.googleapis.com",
      ".gstatic.com",
      "*.youtube.com",
      "stun.*.example.com",
      "+.",
      "google.com",
      "",
    ].join("\n");

    expect(convertMihomoRuleSetText(content, { behavior: "domain", noResolve: false })).toBe(
      ["DOMAIN,google.com", "DOMAIN-SUFFIX,googleapis.com", "DOMAIN-SUFFIX,gstatic.com", "DOMAIN-SUFFIX,youtube.com", ""].join(
        "\n"
      )
    );
  });

  it("converts ipcidr entries and appends no-resolve on request", () => {
    const content = "1.0.1.0/24\r\n2001:db8::/32\n";

    expect(convertMihomoRuleSetText(content, { behavior: "ipcidr", noResolve: false })).toBe(
      "IP-CIDR,1.0.1.0/24\nIP-CIDR6,2001:db8::/32\n"
    );
    expect(convertMihomoRuleSetText(content, { behavior: "ipcidr", noResolve: true })).toBe(
      "IP-CIDR,1.0.1.0/24,no-resolve\nIP-CIDR6,2001:db8::/32,no-resolve\n"
    );
  });

  it("accepts yaml payload layouts", () => {
    const content = "payload:\n    - '+.example.com'\n    - \"example.org\"\n    - ''\n";

    expect(convertMihomoRuleSetText(content, { behavior: "domain", noResolve: false })).toBe(
      "DOMAIN-SUFFIX,example.com\nDOMAIN,example.org\n"
    );
  });

  it("returns empty text when nothing is convertible", () => {
    expect(convertMihomoRuleSetText("# only comments\n", { behavior: "domain", noResolve: false })).toBe("");
  });
});
