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
![[Pasted image 20260425173820.png]]


# Another One

> Flag format: `CTFAC{SHA256(key)}`

## 문제

> I cannot anymore with Khaled. He said "another one" and meant another byte, another row, another direction. The man takes everything too literally. This time the record does not even start where it should. Maybe he leaned into his roots, maybe he just shuffled the whole track until the beginning forgot where it belonged. Either way, the track is there, the key is there, and somewhere inside the noise Khaled is still waiting to say the only thing he ever needed to say: we the best music.

문제 설명에 힌트가 거의 다 들어있다. "another byte / another row / another direction", "record does not even start where it should". 뭔가가 row 단위로 뒤집혀 있고, 시작점이 어긋났다는 얘기다.

## 1. 파일 살펴보기

바이너리를 IDA에 로드하니 함수가 4개밖에 안 잡힌다. 모든 게 단일 raw 세그먼트로 들어가 있고 entry point도 없다. 정상적인 ELF로 인식이 안 된 거다.

처음 16바이트를 떠봤다.

```
00 00 00 00 00 00 00 00 00 01 01 02 46 4C 45 7F
                                  F  L  E  ?
```

ELF 매직 `7F 45 4C 46`이 거꾸로 들어가 있다. 그것도 맨 끝에. 16바이트 단위로 뒤집어 보면 정상적인 ELF64 헤더가 나온다.

```
7F 45 4C 46 02 01 01 00 00 00 00 00 00 00 00 00
```

"another row"는 16바이트 hexdump 한 줄을 의미했고, "another direction"은 그 row를 뒤집으라는 얘기였다. 전체 파일을 16바이트씩 잘라서 각각 reverse하면 원본 ELF가 복원된다.

```python
fixed = bytearray()
for i in range(0, len(data), 16):
    fixed.extend(data[i:i+16][::-1])
```

복원 후 헤더 파싱:

- 64-bit LSB ELF, x86-64
- ET_DYN (PIE)
- entry point `0xe990`
- `.text`: vaddr `0xe990` ~ `0x4a5e0` (file 오프셋 - 0x1000)
- `.rodata`: file/vaddr `0x2ef0` ~ `0x7c98`

Rust로 빌드된 바이너리다. strings에서 보이는 단서:

- `record key>` — 입력 프롬프트
- `+] DJ Khaled says: we the best music` — 성공 메시지
- `-] DJ Khaled says: they did not believe in us.` — 실패 메시지
- `we the best music`, `we the best`, `major key`, `bless up`, `secure the bag`, `they did not believe in us`, `god did` — 7개의 DJ Khaled 키워드 (banner 출력용)
- `record key>` 직후에 27바이트의 의문의 데이터:
    
    ```
    e8 dd ae cb 2f bc 8c a8 ec 28 1d 11 7c 88 fd 7c37 43 45 02 a8 29 c4 11 24 73 e0
    ```
    

## 2. main 찾기

`_start`(0xe990)는 표준적인 형태다.

```asm
xor    ebp, ebp
mov    r9, rdx
pop    rsi
mov    rdx, rsp
and    rsp, 0xfffffffffffffff0
push   rax
push   rsp
xor    r8d, r8d
xor    ecx, ecx
lea    rdi, [rip+0xd95]   ; main
call   __libc_start_main
```

main은 `0xf744`. 그런데 이건 Rust runtime 진입점에 가깝고 (poll/dup/sigaction 같은 fd setup), 실제 사용자 코드는 따로 있다.

`record key>` 문자열(rodata vaddr `0x5a02`)을 참조하는 `lea rip+disp` 명령을 찾으니 한 곳에서만 참조한다 — `0xec8b`. 이 주소가 속한 함수는 `0xeaa1`에서 시작한다.

## 3. 챌린지 함수 분석 (0xeaa1)

함수 앞부분은 banner 출력이다. `+--------+`, `| DJ Khaled says: we the best music |`, `+--------+` 세 줄을 찍고, 그 다음 7개 DJ Khaled 문구를 (string ptr, length) 페어로 스택에 쌓아서 같은 출력 함수에 전달한다. 이건 단순 장식이다.

핵심은 `0xec8b` 이후. `record key>` 출력 → stdin에서 한 줄 읽기(BufReader/read_until 표준 코드) → 검증.

검증 부분을 찾는 게 목표다. read_until 루프를 지나 트레일링 `\r`/`\n` 트리밍을 한 후 다음 코드가 나온다.

```asm
0xf307: sub     rax, rbx
0xf30a: cmp     rax, 0x1b              ; 길이 == 27 ?
0xf30e: jne     fail
0xf314: xorps   xmm0, xmm0
0xf317: movups  [rsp+0x6b], xmm0       ; 27바이트 zero buffer
0xf31c: movaps  [rsp+0x60], xmm0
0xf321: lea     r14, [rsp+0x60]
0xf326: mov     rdi, rbx               ; 입력 ptr
0xf329: mov     rsi, r14               ; output buffer
0xf32c: xor     edx, edx
0xf32e: call    0xf630                 ; transformer
0xf333: mov     rdi, r14               ; 변환된 27바이트
0xf336: xor     esi, esi               ; i = 0
0xf338: mov     edx, 0x50414c31        ; "1LAP" — 초기 hash
0xf33d: xor     ecx, ecx               ; prev_b = 0
0xf33f: call    0xf560                 ; validator
0xf344: test    dl, dl
0xf346: jne     fail                   ; dl != 0 이면 실패
0xf34c: cmp     eax, 0xf459236d
0xf351: jne     fail                   ; eax != 0xf459236d 이면 실패
0xf357: lea     rdi, [success_msg]
0xf363: call    print
```

정리하면:

1. 입력은 정확히 **27바이트**
2. `0xf630`에서 변환
3. 변환된 27바이트를 `0xf560`에 넘김 (초기 hash `"1LAP"` = `0x50414c31`)
4. 검증 통과 조건 두 개:
    - 리턴된 `dl == 0`
    - 리턴된 `eax == 0xf459236d`

## 4. transformer (0xf630)

```asm
0xf630: push    r14
0xf632: push    rbx
0xf633: push    rax
0xf634: cmp     rdx, 0x1b
0xf638: je      ret
0xf63a: mov     eax, 0x1a              ; 26
0xf63f: sub     rax, rdx               ; 26 - i
0xf642: cmp     rax, 0x1a
0xf646: ja      panic
0xf648: cmp     rdx, 0x1b
0xf64c: jae     panic
0xf64e: movzx   eax, byte ptr [rdi + rax]   ; input[26-i]
0xf652: mov     byte ptr [rsi + rdx], al    ; output[i] = input[26-i]
0xf655: lea     rax, [rdx + 1]
...
0xf662: call    0xf630                 ; recurse with i+1
```

재귀로 `output[i] = input[26 - i]` 만든다. 그냥 **27바이트 reverse**다. "another direction"이 이걸 가리킨다.

이로써 검증 함수는 reverse된 입력 위에서 동작한다. 즉 우리가 솔버를 써서 transformed buffer를 얻으면, 원본 입력은 그걸 다시 reverse한 값이다.

## 5. validator (0xf560)

이게 핵심이다. 27회 꼬리 재귀로 doing:

```asm
0xf565: mov     r8d, ecx               ; r8 = caller가 넘긴 prev_b
0xf568: mov     eax, edx               ; eax = caller가 넘긴 hash
0xf56a: cmp     rsi, 0x1b              ; i == 27 ?
0xf56e: jne     0xf579
0xf570: mov     edx, r8d               ; ret: dl = prev_b
0xf578: ret                            ; eax는 그대로 = 마지막 hash

0xf57f: movzx   r9d, [rdi + rsi]       ; b = transformed[i]
0xf584: imul    ecx, esi, 0x31         ; c = i*0x31
0xf587: add     ecx, r9d               ; c += b
0xf58a: rol     eax, 5                 ; eax = rol(eax, 5)
0xf58d: imul    edx, ecx, 0x45d9f3b
0xf593: xor     edx, eax               ; edx = (c * 0x45d9f3b) ^ rol(eax,5)

; rotation amount cl 계산
0xf595: lea     eax, [rsi + rsi*8]     ; i*9
0xf598: lea     eax, [rsi + rax*4]     ; i + (i*9)*4 = i*37
0xf59b: shr     eax, 8                 ; tmp = (i*37) >> 8
0xf59e: mov     ecx, esi
0xf5a0: sub     cl, al                 ; cl = i - tmp
0xf5a2: shr     cl, 1
0xf5a4: add     cl, al
0xf5a6: shr     cl, 2
0xf5a9: add     cl, sil                ; cl += i
0xf5ac: inc     cl
0xf5ae: rol     r9b, cl                ; b = rol8(b, cl)

; table1 인덱스 계산
0xf5b1: imul    eax, esi, 0xab
0xf5b7: shr     eax, 9                 ; tmp2 = (i*0xab) >> 9
0xf5ba: lea     ecx, [rsi*8]           ; cl = (i*8) & 0x1f for shr
0xf5c1: mov     r10d, edx
0xf5c4: shr     r10d, cl               ; r10b = (edx >> ((i*8)&31)) & 0xff
0xf5c7: and     eax, 0x7c
0xf5ca: lea     eax, [rax + rax*2]     ; eax = 3*(tmp2 & 0x7c)
0xf5cd: mov     ecx, esi
0xf5cf: sub     cl, al                 ; ax = i - 3*(tmp2 & 0x7c)
0xf5d1: movzx   eax, cl

0xf5d4: lea     rcx, [rip - 0x9b8c]    ; table1 @ 0x5a4f
0xf5db: xor     r9b, [rax + rcx]
0xf5df: lea     rax, [rip - 0x9bb2]    ; table2 @ 0x5a34
0xf5e6: xor     r9b, [rsi + rax]
0xf5ea: xor     r9b, r10b
0xf5ed: or      r9b, r8b               ; b |= prev_b

; 다음 iter로 재귀
0xf5f6: movzx   ecx, r9b               ; 다음 iter의 prev_b = 현재 b
0xf5fd: mov     rsi, rax               ; i+1
0xf600: call    0xf560                 ; rdx는 그대로 (= 새 hash)
```

테이블 두 개의 위치를 풀면:

- `table1`: vaddr `0x5a4f` → `"DJ KHALED!\x13\x37" + ...`
- `table2`: vaddr `0x5a4f - (0x5a4f - 0x5a34)` = `0x5a34` → 27바이트의 그 의문의 데이터

`ax`(table1 인덱스)의 실제 범위를 i = 0..26에서 계산해보면 0..11 사이에서 사이클을 돈다. 즉 table1은 사실상 첫 12바이트 `"DJ KHALED!\x13\x37"`만 쓰인다.

### 검증 조건 정리

매 iteration마다:

```
b_i = ( rol8(b, cl_i) XOR table1[ax_i] XOR table2[i] XOR r10b ) | prev_b
```

여기서 prev_b는 이전 iter의 `b_{i-1}`. 그리고 마지막 base case에서 `dl = b_26`이 리턴된다. 통과 조건은 `dl == 0` 즉 `b_26 == 0`.

여기서 핵심 관찰: `b_i = (...) | b_{i-1}`. **OR**이기 때문에 한 번 켜진 비트는 절대 안 꺼진다. 따라서 `b_26 == 0`이려면 **모든 `b_0, b_1, ..., b_26`이 0**이어야 한다.

이게 strong constraint다. 매 iter마다 다음 식이 성립해야 한다.

```
rol8(input[i], cl_i) XOR table1[ax_i] XOR table2[i] XOR r10b(edx_i) == 0
```

`r10b`가 `edx`(즉 입력 b의 함수)에 의존하므로 닫힌 형태로 풀리진 않지만, 매 iter마다 b 후보는 256개뿐이라 brute force로 충분하다.

## 6. 솔버

처음에는 그리디로 풀었더니 i=7에서 막혔다. 첫 iter에서 b=0을 만족하는 byte가 여러 개일 때 잘못된 분기를 선택해서 그렇다. backtracking으로 바꾸니 한 방에 풀린다.

```python
import hashlib

table1 = b'DJ KHALED!\x13\x37'
table2 = bytes([
    0xe8, 0xdd, 0xae, 0xcb, 0x2f, 0xbc, 0x8c, 0xa8,
    0xec, 0x28, 0x1d, 0x11, 0x7c, 0x88, 0xfd, 0x7c,
    0x37, 0x43, 0x45, 0x02, 0xa8, 0x29, 0xc4, 0x11,
    0x24, 0x73, 0xe0
])

def rol32(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF if n else x & 0xFFFFFFFF

def rol8(x, n):
    n &= 7
    x &= 0xff
    return ((x << n) | (x >> (8 - n))) & 0xff if n else x

def cl_for_i(i):
    tmp = (i * 37) >> 8
    cl = (i - tmp) & 0xff
    cl = ((cl >> 1) + tmp) & 0xff
    cl = (cl >> 2)
    cl = (cl + i + 1) & 0xff
    return cl

def ax_for_i(i):
    tmp2 = (i * 0xab) >> 9
    return (i - 3 * (tmp2 & 0x7c)) & 0xff

def step(eax, b, i):
    c = (i * 0x31 + b) & 0xFFFFFFFF
    eax = rol32(eax, 5)
    edx = ((c * 0x45d9f3b) & 0xFFFFFFFF) ^ eax
    cl = cl_for_i(i)
    b_rot = rol8(b, cl)
    shift = (i * 8) & 31
    r10b = (edx >> shift) & 0xff
    ax = ax_for_i(i)
    b_out = (b_rot ^ table1[ax] ^ table2[i] ^ r10b) & 0xff
    return b_out, edx

TARGET_FINAL_EAX = 0xf459236d
solutions = []

def dfs(i, eax, path):
    if i == 27:
        if eax == TARGET_FINAL_EAX:
            solutions.append(bytes(path))
        return
    for b in range(256):
        b_out, next_eax = step(eax, b, i)
        if b_out == 0:
            path.append(b)
            dfs(i + 1, next_eax, path)
            path.pop()

dfs(0, 0x50414c31, [])

transformed = solutions[0]
key = transformed[::-1]   # transformer 0xf630이 reverse 였으므로
print(f'KEY: {key!r}')
print(f'FLAG: CTFAC{{{hashlib.sha256(key).hexdigest()}}}')
```

실행:

```
KEY: b'fr1dg31s3mptys01sy0urv1s1on'
FLAG: CTFAC{19de747e6bafb8e23a4e050e61213679d1c3865f7e854c217a5fdcbdd7fcb647}
```

## 키 해석

`fr1dg31s3mptys01sy0urv1s1on` — leetspeak를 풀면 **"fridge is empty so is your vision"**. 텅 빈 냉장고, 텅 빈 미래. 출제자가 DJ Khaled 페르소나에 잘 맞춰놨다.

## 정리

|단계|트릭|
|---|---|
|1|ELF가 16바이트 row 단위로 reverse 되어있음 (`another row`, `another direction`)|
|2|정적 분석으로 검증 흐름 추적 — 길이 27, 변환자, validator, expected hash|
|3|변환자(0xf630)는 단순 byte reverse|
|4|validator(0xf560)는 27회 꼬리 재귀, OR-누적이라 매 iter base가 0이어야 함|
|5|iter당 256개 후보 중 base==0인 것만 따라가는 DFS|

## Flag

```
CTFAC{19de747e6bafb8e23a4e050e61213679d1c3865f7e854c217a5fdcbdd7fcb647}
```