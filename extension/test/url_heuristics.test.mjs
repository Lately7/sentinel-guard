import { test } from "node:test";
import assert from "node:assert/strict";
import { scoreUrl, registrableDomain } from "../src/url_heuristics.js";

const LEGIT = [
  "https://www.google.com/search?q=test", "https://accounts.google.com/signin/v2/identifier",
  "https://login.microsoftonline.com/common/oauth2/authorize", "https://login.live.com/login.srf",
  "https://github.com/login", "https://vnexpress.net/", "https://shopee.vn/buyer/login", "https://momo.vn/",
  "https://www.vietcombank.com.vn/vi-VN", "https://digiapp.vietcombank.com.vn/", "https://www.paypal.com/signin",
  "http://localhost:3000/login", "https://www.facebook.com/login/", "https://m.facebook.com/", "https://www.youtube.com/",
  "https://appleid.apple.com/sign-in", "https://www.icloud.com/", "https://www.amazon.com/ap/signin",
  "https://www.netflix.com/login", "https://accounts.binance.com/en/login", "https://metamask.io/download/",
  "https://chat.zalo.me/", "https://id.zalo.me/account", "https://www.techcombank.com.vn/", "https://online.mbbank.com.vn/",
  "https://www.wikipedia.org/", "https://vi.wikipedia.org/wiki/Vi%E1%BB%87t_Nam", "https://stackoverflow.com/users/login",
  "https://www.reddit.com/login/", "https://x.com/i/flow/login", "https://www.instagram.com/accounts/login/",
  "https://outlook.live.com/mail/0/", "https://www.office.com/login", "https://drive.google.com/drive/my-drive",
  "https://docs.github.com/en/authentication", "https://tuoitre.vn/", "https://thanhnien.vn/", "https://dantri.com.vn/",
  "https://www.lazada.vn/customer/account/login/", "https://tiki.vn/", "https://www.bbc.co.uk/news",
  "https://www.tiktok.com/login", "https://web.telegram.org/k/", "https://store.steampowered.com/login/",
  "https://www.coinbase.com/signin", "https://portal.azure.com/", "https://helium.computer/",
];

test("popular legitimate sites stay below the warning threshold", () => {
  for (const url of LEGIT) {
    const { score, reasons } = scoreUrl(url);
    assert.ok(score < 70, `${url} scored ${score}: ${reasons.map((r) => r.id).join(",")}`);
  }
});

test("most legitimate sites score zero", () => {
  const zero = LEGIT.filter((u) => scoreUrl(u).score === 0).length;
  assert.ok(zero / LEGIT.length > 0.9, `${zero}/${LEGIT.length} scored 0`);
});

test("typical phishing URL shapes cross the warning threshold", () => {
  const bad = [
    "http://paypa1.com/signin/verify",
    "http://secure-paypal.account-verify.top/login",
    "https://vietcombank-xacminh.click/dang-nhap/login",
    "http://203.0.113.7/microsoft/login.php?verify=1",
    "https://www.google.com@login-micros0ft.xyz/signin",
    "http://metamaskk.io/wallet/recover",
  ];
  for (const url of bad) {
    const { score, reasons } = scoreUrl(url);
    assert.ok(score >= 70, `${url} only scored ${score}: ${reasons.map((r) => r.id).join(",")}`);
  }
});

test("non-web schemes and garbage are ignored", () => {
  for (const url of ["chrome://extensions", "about:blank", "file:///C:/x.html", "javascript:alert(1)", "", "::::", null]) {
    assert.equal(scoreUrl(url).score, 0);
  }
});

test("registrableDomain", () => {
  assert.equal(registrableDomain("a.b.example.com"), "example.com");
  assert.equal(registrableDomain("digiapp.vietcombank.com.vn"), "vietcombank.com.vn");
  assert.equal(registrableDomain("www.bbc.co.uk"), "bbc.co.uk");
  assert.equal(registrableDomain("example.com"), "example.com");
  assert.equal(registrableDomain("192.168.1.1"), "192.168.1.1");
  assert.equal(registrableDomain(undefined), "");
});
