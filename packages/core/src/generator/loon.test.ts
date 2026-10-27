import { describe, expect, it } from "vitest";
import type { ClashConfig } from "@subboost/core/types/config";
import type { ParsedNode } from "@subboost/core/types/node";
import { generateIosClientConfig } from "./index";
import { buildTestClientOptions, section } from "./ios-client.test-helpers";
import { buildLoonProxyLine, generateLoonConfigFromClash } from "./loon";

const clientOptions = buildTestClientOptions("loon");
const UUID = "52396e06-041a-4cc2-be5c-8525eb457809";

function line(node: Record<string, unknown>) {
  return buildLoonProxyLine({ name: "N", server: "s.example", port: 443, ...node }, "N");
}

describe("Loon proxy lines", () => {
  it.each([
    [
      "shadowsocks with tls obfs",
      { type: "ss", cipher: "AES-128-GCM", password: "pw", plugin: "obfs", "plugin-opts": { mode: "tls", host: "www.bing.com" } },
      'N = Shadowsocks,s.example,443,aes-128-gcm,"pw",obfs-name=tls,obfs-host=www.bing.com,udp=true',
    ],
    [
      "shadowsocks with http obfs and path, tfo, no udp, ip mode",
      {
        type: "ss",
        cipher: "chacha20-ietf-poly1305",
        password: "pw",
        plugin: "obfs",
        "plugin-opts": { mode: "http", host: "h.example", path: "/p" },
        tfo: true,
        udp: false,
        "ip-version": "ipv4-prefer",
        "udp-over-tcp": true,
        "udp-over-tcp-version": 2,
      },
      'N = Shadowsocks,s.example,443,chacha20-ietf-poly1305,"pw",obfs-name=http,obfs-host=h.example,obfs-uri=/p,fast-open=true,ip-mode=prefer-v4',
    ],
    [
      "shadowsocks 2022 with shadow-tls and udp-over-tcp v2",
      {
        type: "ss",
        cipher: "2022-blake3-aes-128-gcm",
        password: "key",
        plugin: "shadow-tls",
        "plugin-opts": { password: "stls", host: "www.apple.com", version: 3 },
        "udp-over-tcp": true,
        "udp-over-tcp-version": 2,
      },
      'N = Shadowsocks,s.example,443,2022-blake3-aes-128-gcm,"key",shadow-tls-password=stls,shadow-tls-sni=www.apple.com,shadow-tls-version=3,udp-over-tcp=true,udp=true',
    ],
    [
      "shadowsocks with udp-over-tcp v1 and shadow-tls without version",
      {
        type: "ss",
        cipher: "aes-256-gcm",
        password: "pw",
        plugin: "shadow-tls",
        "plugin-opts": { password: "stls" },
        "udp-over-tcp": true,
      },
      'N = Shadowsocks,s.example,443,aes-256-gcm,"pw",shadow-tls-password=stls,udp=true',
    ],
    [
      "shadowsocksr",
      { type: "ssr", cipher: "aes-256-cfb", password: "pw", protocol: "auth_aes128_md5", "protocol-param": "1:p", obfs: "tls1.2_ticket_auth", "obfs-param": "o.example" },
      'N = ShadowsocksR,s.example,443,aes-256-cfb,"pw",protocol=auth_aes128_md5,protocol-param=1:p,obfs=tls1.2_ticket_auth,obfs-param=o.example,udp=true',
    ],
    [
      "vmess over websocket TLS",
      {
        type: "vmess",
        uuid: UUID,
        alterId: 0,
        cipher: "auto",
        tls: true,
        servername: "cdn.example.com",
        "client-fingerprint": "chrome",
        "skip-cert-verify": true,
        alpn: ["h2", "http/1.1"],
        network: "ws",
        "ws-opts": { path: "/ws", headers: { Host: "cdn.example.com" } },
      },
      `N = VMess,s.example,443,auto,"${UUID}",transport=ws,path=/ws,host=cdn.example.com,alterId=0,over-tls=true,skip-cert-verify=true,tls-profile=chrome,alpn="h2,http/1.1",tls-name=cdn.example.com,udp=true`,
    ],
    [
      "vmess over http transport without TLS",
      {
        type: "vmess",
        uuid: UUID,
        cipher: "chacha20-poly1305",
        network: "http",
        "http-opts": { path: ["/a", "/b"], headers: { Host: ["h.example"] } },
      },
      `N = VMess,s.example,443,chacha20-ietf-poly1305,"${UUID}",transport=http,path=/a,host=h.example,alterId=0,over-tls=false,udp=true`,
    ],
    [
      "vmess websocket defaults and lowercase host header",
      { type: "vmess", uuid: UUID, cipher: "none", alterId: 2, network: "ws", "ws-opts": { headers: { host: "lower.example" } } },
      `N = VMess,s.example,443,none,"${UUID}",transport=ws,path=/,host=lower.example,alterId=2,over-tls=false,udp=true`,
    ],
    [
      "vmess http transport defaults and unknown cipher",
      { type: "vmess", uuid: UUID, cipher: "zero", network: "http" },
      `N = VMess,s.example,443,auto,"${UUID}",transport=http,path=/,alterId=0,over-tls=false,udp=true`,
    ],
    [
      "vless vision reality",
      {
        type: "vless",
        uuid: UUID,
        flow: "xtls-rprx-vision",
        servername: "www.apple.com",
        "reality-opts": { "public-key": "PUBKEY", "short-id": "abcd" },
        "client-fingerprint": "safari",
      },
      `N = VLESS,s.example,443,"${UUID}",transport=tcp,flow=xtls-rprx-vision,over-tls=true,tls-profile=safari-ios18,sni=www.apple.com,public-key="PUBKEY",short-id=abcd,udp=true`,
    ],
    [
      "vless reality with post-quantum key exchange",
      {
        type: "vless",
        uuid: UUID,
        encryption: "none",
        sni: "www.apple.com",
        "reality-opts": { "public-key": "PUBKEY", "support-x25519mlkem768": true },
        "client-fingerprint": "ios",
      },
      `N = VLESS,s.example,443,"${UUID}",transport=tcp,over-tls=true,tls-profile=safari-ios-26,sni=www.apple.com,public-key="PUBKEY",udp=true`,
    ],
    [
      "vless post-quantum with chrome-like fingerprint and plain tcp",
      { type: "vless", uuid: UUID, "reality-opts": { "public-key": "K", "support-x25519mlkem768": true }, "client-fingerprint": "firefox" },
      `N = VLESS,s.example,443,"${UUID}",transport=tcp,over-tls=true,tls-profile=chrome147,public-key="K",udp=true`,
    ],
    [
      "vless without TLS",
      { type: "vless", uuid: UUID, network: "ws" },
      `N = VLESS,s.example,443,"${UUID}",transport=ws,path=/,over-tls=false,udp=true`,
    ],
    [
      "trojan over websocket",
      { type: "trojan", password: "pw", network: "ws", sni: "t.example", "ws-opts": { path: "/t" }, "client-fingerprint": "random" },
      'N = Trojan,s.example,443,"pw",transport=ws,path=/t,tls-name=t.example,udp=true',
    ],
    [
      "trojan with explicit tcp and reality",
      { type: "trojan", password: "pw", network: "tcp", sni: "r.example", "reality-opts": { "public-key": "K", "short-id": "01" } },
      'N = Trojan,s.example,443,"pw",sni=r.example,public-key="K",short-id=01,udp=true',
    ],
    [
      "anytls with integer idle timeout",
      { type: "anytls", password: "pw", sni: "a.example", "idle-session-timeout": 30 },
      'N = AnyTLS,s.example,443,"pw",tls-name=a.example,idle-session-timeout=30,udp=true',
    ],
    [
      "anytls ignores fractional idle timeout",
      { type: "anytls", password: "pw", "idle-session-timeout": 1.5 },
      'N = AnyTLS,s.example,443,"pw",udp=true',
    ],
    [
      "hysteria2 with salamander, port hopping and bandwidth",
      {
        type: "hysteria2",
        password: "pw",
        sni: "hy.example.com",
        obfs: "salamander",
        "obfs-password": "obfs",
        ports: "443,8443-8450",
        "hop-interval": 30,
        down: "100 Mbps",
        alpn: ["h3"],
        "skip-cert-verify": true,
      },
      'N = Hysteria2,s.example,443,"pw",tls-name=hy.example.com,skip-cert-verify=true,alpn="h3",salamander-password=obfs,server-ports="443,8443-8450",hop-interval=30,download-bandwidth=100,udp=true',
    ],
    ["hysteria2 minimal", { type: "hysteria2", password: "pw" }, 'N = Hysteria2,s.example,443,"pw",udp=true'],
    [
      "https proxy with credentials",
      { type: "https", username: "u", password: "p", sni: "h.example", "skip-cert-verify": true, "client-fingerprint": "chrome" },
      'N = HTTPS,s.example,443,u,"p",sni=h.example,skip-cert-verify=true,tls-profile=chrome',
    ],
    ["plain http proxy", { type: "http", tfo: true }, "N = HTTP,s.example,443,fast-open=true"],
    ["plain socks5", { type: "socks5" }, "N = SOCKS5,s.example,443,udp=true"],
    [
      "socks5 over TLS with credentials",
      { type: "socks5", username: "u", password: "p", tls: true, sni: "s5.example", "skip-cert-verify": true, udp: false },
      'N = SOCKS5,s.example,443,u,"p",over-tls=true,sni=s5.example,skip-cert-verify=true',
    ],
    [
      "wireguard with top-level peer",
      {
        type: "wireguard",
        server: "2001:db8::1",
        port: 51820,
        ip: "172.16.0.2/32",
        ipv6: "fd00::2/128",
        "private-key": "PRIV",
        "public-key": "PUB",
        reserved: [1, 2, 3],
        mtu: 1280,
        dns: ["1.1.1.1", "2606:4700:4700::1111"],
        "persistent-keepalive": 25,
      },
      'N = WireGuard,interface-ip=172.16.0.2,interface-ipv6=fd00::2,private-key="PRIV",mtu=1280,dns=1.1.1.1,dnsv6=2606:4700:4700::1111,keepalive=25,peers=[{public-key="PUB",allowed-ips="0.0.0.0/0,::/0",endpoint=[2001:db8::1]:51820,reserved=[1,2,3]}],udp=true',
    ],
    [
      "wireguard with peers array and encoded reserved bytes",
      {
        type: "wireguard",
        server: undefined,
        port: undefined,
        "private-key": "PRIV",
        keepalive: 10,
        peers: [
          { server: "a.example", port: 1, "public-key": "A", "pre-shared-key": "PSK", "allowed-ips": ["0.0.0.0/0"], reserved: "AQID" },
          { server: "b.example", port: 2, "public-key": "B", reserved: "4, 5, 6" },
          { server: "c.example", port: 3, "public-key": "C", reserved: "!!!" },
        ],
      },
      'N = WireGuard,private-key="PRIV",keepalive=10,peers=[{public-key="A",allowed-ips="0.0.0.0/0",endpoint=a.example:1,preshared-key="PSK",reserved=[1,2,3]},{public-key="B",allowed-ips="0.0.0.0/0,::/0",endpoint=b.example:2,reserved=[4,5,6]},{public-key="C",allowed-ips="0.0.0.0/0,::/0",endpoint=c.example:3}],udp=true',
    ],
  ])("renders %s", (_label, node, expected) => {
    expect(line(node)).toEqual({ ok: true, line: expected });
  });

  it.each([
    ["unsupported protocol", { type: "tuic", uuid: "u" }, "Loon 不支持 tuic 协议"],
    ["missing endpoint", { type: "ss", server: "", cipher: "aes-128-gcm", password: "p" }, "缺少服务器地址或端口"],
    ["missing port", { type: "trojan", port: "x", password: "p" }, "缺少服务器地址或端口"],
    ["unsupported ss cipher", { type: "ss", cipher: "none", password: "p" }, "Loon 不支持 Shadowsocks 加密方式 none"],
    ["unsupported obfs mode", { type: "ss", cipher: "aes-128-gcm", password: "p", plugin: "obfs", "plugin-opts": { mode: "ws" } }, "Loon 不支持 obfs 模式 ws"],
    ["shadow-tls v1", { type: "ss", cipher: "aes-128-gcm", password: "p", plugin: "shadow-tls", "plugin-opts": { version: 1 } }, "Loon 仅支持 ShadowTLS v2/v3"],
    ["v2ray-plugin", { type: "ss", cipher: "aes-128-gcm", password: "p", plugin: "v2ray-plugin" }, "Loon 不支持 Shadowsocks 插件 v2ray-plugin"],
    ["quote in password", { type: "ss", cipher: "aes-128-gcm", password: 'a"b' }, "参数包含无法转义的字符"],
    ["comma in websocket path", { type: "vmess", uuid: UUID, network: "ws", "ws-opts": { path: "/a,b" } }, "参数包含无法转义的字符"],
    ["httpupgrade", { type: "vmess", uuid: UUID, network: "ws", "ws-opts": { "v2ray-http-upgrade": true } }, "Loon 不支持 HTTPUpgrade"],
    ["h2 transport", { type: "vmess", uuid: UUID, network: "h2" }, "Loon 不支持 h2 传输"],
    ["vmess reality without key", { type: "vmess", uuid: UUID, tls: true, "reality-opts": { "short-id": "1" } }, "Reality 缺少 public-key"],
    ["vless encryption", { type: "vless", uuid: UUID, encryption: "mlkem768x25519plus" }, "Loon 不支持 VLESS encryption"],
    ["vless flow", { type: "vless", uuid: UUID, flow: "xtls-rprx-direct" }, "Loon 不支持 VLESS flow xtls-rprx-direct"],
    ["vless grpc", { type: "vless", uuid: UUID, network: "grpc" }, "Loon 不支持 grpc 传输"],
    ["vless reality without key", { type: "vless", uuid: UUID, "reality-opts": {} }, "Reality 缺少 public-key"],
    ["trojan grpc", { type: "trojan", password: "p", network: "grpc" }, "Loon 不支持 grpc 传输"],
    ["trojan reality without key", { type: "trojan", password: "p", "reality-opts": {} }, "Reality 缺少 public-key"],
    ["anytls reality without key", { type: "anytls", password: "p", "reality-opts": {} }, "Reality 缺少 public-key"],
    ["hysteria2 obfs", { type: "hysteria2", password: "p", obfs: "gfw" }, "Loon 仅支持 salamander 混淆"],
    ["wireguard without private key", { type: "wireguard", "public-key": "PUB" }, "WireGuard 缺少 private-key"],
    ["wireguard peer without key", { type: "wireguard", "private-key": "K", peers: [{ server: "a", port: 1 }] }, "WireGuard peer 缺少 server、port 或 public-key"],
    ["wireguard quote in key", { type: "wireguard", "private-key": "K", "public-key": 'P"' }, "参数包含无法转义的字符"],
  ])("skips %s", (_label, node, reason) => {
    expect(line(node)).toEqual({ ok: false, reason });
  });
});

describe("Loon config generation", () => {
  const nodes = [
    { name: "HK 01", type: "ss", server: "hk.example.com", port: 8388, cipher: "aes-128-gcm", password: "pw" },
    { name: "US, Home", type: "trojan", server: "us.example.com", port: 443, password: "pw", sni: "us.example.com" },
    { name: "Relay", type: "ss", server: "relay.example.com", port: 8388, cipher: "aes-128-gcm", password: "pw" },
    { name: "TUIC", type: "tuic", server: "tuic.example.com", port: 443, uuid: UUID, password: "p" },
  ] as unknown as ParsedNode[];

  it("converts the generated SubBoost config end to end", () => {
    const config = generateIosClientConfig(
      "loon",
      {
        nodes,
        template: "minimal",
        dialerProxyGroups: [
          { id: "relay", name: "🔗 中转", type: "select", relayNodes: ["Relay"], targetNodes: ["US, Home"] },
        ],
        userConfig: {
          customRules: [{ id: "c1", type: "DOMAIN-SUFFIX", value: "corp.example", target: "DIRECT" }],
        },
      },
      clientOptions
    );

    expect(config).toContain("# 配置地址：https://sub.example.com/api/subscriptions/token/loon.conf");
    expect(config).toContain("#   - TUIC：Loon 不支持 tuic 协议");

    const proxies = section(config, "Proxy");
    expect(proxies).toContain('HK 01 = Shadowsocks,hk.example.com,8388,aes-128-gcm,"pw",udp=true');
    // 中转目标节点改名为落地节点，代理链沿用（转义后的）原节点名
    expect(proxies).toContain('US， Home（落地） = Trojan,us.example.com,443,"pw",tls-name=us.example.com,udp=true');
    expect(section(config, "Proxy Chain")).toEqual(["US， Home = Relay,US， Home（落地）,udp=true"]);

    const groups = section(config, "Proxy Group");
    expect(groups.some((item) => item.startsWith("🚀 节点选择 = select,⚡ 自动选择,DIRECT,REJECT,HK 01,US， Home,Relay"))).toBe(true);
    expect(groups.some((item) => item.startsWith("⚡ 自动选择 = url-test,HK 01,US， Home,Relay,url="))).toBe(true);
    expect(groups.some((item) => item.includes("TUIC"))).toBe(false);

    const rules = section(config, "Rule");
    expect(rules[0]).toBe("DOMAIN-SUFFIX,corp.example,DIRECT");
    expect(rules[rules.length - 1]).toMatch(/^FINAL,/);

    const remoteRules = section(config, "Remote Rule");
    expect(remoteRules.some((item) => item.includes("/rule-sets/cn-ip.list?no-resolve=1,policy="))).toBe(true);
    expect(remoteRules.every((item) => item.endsWith(",enabled=true"))).toBe(true);
  });

  it("maps proxy-providers, group types and chains from a hand-written Clash config", () => {
    const clash: ClashConfig = {
      ipv6: false,
      proxies: [
        { name: "A", type: "ss", server: "a.example", port: 1, cipher: "aes-128-gcm", password: "pw", "dialer-proxy": "Relays" },
        { name: "B", type: "ss", server: "b.example", port: 1, cipher: "aes-128-gcm", password: "pw", "dialer-proxy": "DIRECT" },
        { name: "C", type: "ss", server: "c.example", port: 1, cipher: "aes-128-gcm", password: "pw", "dialer-proxy": "Gone" },
        { name: "D", type: "ss", server: "d.example", port: 1, cipher: "aes-128-gcm", password: "pw", "dialer-proxy": "url_1" },
        { name: "R1", type: "ss", server: "r1.example", port: 1, cipher: "aes-128-gcm", password: "pw" },
        { name: "R2", type: "ss", server: "r2.example", port: 1, cipher: "aes-128-gcm", password: "pw" },
      ] as unknown as ParsedNode[],
      "proxy-providers": {
        url_1: { type: "http", url: "https://airport.example.com/sub" },
        url_2: { type: "http" },
      },
      "proxy-groups": [
        { name: "Relays", type: "select", proxies: ["R1", "R2"] },
        { name: "Auto", type: "url-test", proxies: ["A", "B"], url: "http://cp.cloudflare.com", interval: 300, tolerance: 50 },
        { name: "Fall", type: "fallback", proxies: ["A", "B"] },
        { name: "Sticky", type: "load-balance", proxies: ["A"], strategy: "sticky-sessions" },
        { name: "Hash", type: "load-balance", proxies: ["A"] },
        { name: "Empty", type: "url-test", proxies: [] },
        { name: "Select", type: "select", proxies: ["Auto", "DIRECT", "Missing"], use: ["url_1", "url_2"] },
        { name: "Balance", type: "load-balance", use: ["url_1"], strategy: "round-robin" },
        { name: "Relay group", type: "relay", proxies: ["A"] },
      ],
      rules: ["MATCH,Select"],
    };

    const config = generateLoonConfigFromClash(clash, { resolveRuleSetUrl: () => "unused" });
    expect(config).not.toContain("# 配置地址");
    expect(config).not.toContain("已跳过");
    expect(section(config, "General")).toContain("ip-mode = v4-only");
    expect(section(config, "Remote Proxy")).toEqual([
      "url_1 = https://airport.example.com/sub,udp=default,fast-open=default,skip-cert-verify=default,enabled=true",
    ]);
    expect(section(config, "Proxy Chain")).toEqual(["A = Relays,A（落地）,udp=true", "D = url_1,D（落地）,udp=true"]);
    expect(section(config, "Proxy").map((item) => item.split(" = ")[0])).toEqual(["A（落地）", "B", "C", "D（落地）", "R1", "R2"]);
    expect(section(config, "Proxy Group")).toEqual([
      "Relays = select,R1,R2",
      "Auto = url-test,A,B,url=http://cp.cloudflare.com,interval=300,tolerance=50",
      "Fall = fallback,A,B,url=http://cp.cloudflare.com,interval=600,max-timeout=3000",
      "Sticky = load-balance,A,url=http://cp.cloudflare.com,interval=600,max-timeout=3000,algorithm=pcc",
      "Hash = load-balance,A,url=http://cp.cloudflare.com,interval=600,max-timeout=3000,algorithm=pcc",
      "Empty = select,DIRECT",
      "Select = select,Auto,DIRECT,url_1",
      "Balance = load-balance,url_1,url=http://cp.cloudflare.com,interval=600,max-timeout=3000,algorithm=round-robin",
      "Relay group = select,A",
    ]);
    expect(section(config, "Rule")).toEqual(["FINAL,Select"]);
    expect(section(config, "Remote Rule")).toEqual([]);
  });

  it("chains directly to the only usable relay node", () => {
    const config = generateLoonConfigFromClash(
      {
        proxies: [
          { name: "T", type: "ss", server: "t.example", port: 1, cipher: "aes-128-gcm", password: "pw", "dialer-proxy": "Relays" },
          { name: "R", type: "ss", server: "r.example", port: 1, cipher: "aes-128-gcm", password: "pw" },
          { name: "X", type: "tuic", server: "x.example", port: 1, uuid: UUID, password: "pw" },
        ] as unknown as ParsedNode[],
        "proxy-groups": [{ name: "Relays", type: "select", proxies: ["R", "X"] }],
      },
      clientOptions
    );

    expect(section(config, "Proxy Chain")).toEqual(["T = R,T（落地）,udp=true"]);
    expect(section(config, "Rule")).toEqual(["FINAL,DIRECT"]);
  });
});
