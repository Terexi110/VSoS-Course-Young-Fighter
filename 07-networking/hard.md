# Глава 7 (hard). Автоматизация сервисов: pwntools, proof-of-work, бинарные протоколы

Когда сервер требует быстрых вычислений, решения "пруфа работы" или обмена бинарными данными.

## 1. pwntools - рабочий стандарт

```python
from pwn import *

io = remote("10.0.0.5", 31337)
io.recvuntil(b"> ")              # читать до приглашения
io.sendline(b"42")              # отправить строку (\n добавится сам)
line = io.recvline()            # прочитать строку ответа
data = io.recvuntil(b"flag")    # читать до подстроки
io.interactive()                # ручной режим
```

Разбор чисел/значений из ответа:
```python
io.recvuntil(b"result: ")
n = int(io.recvline().strip())   # вытащили число, которое прислал сервер
```

💡 Фишки, которых нет на medium:
- `context.log_level = 'debug'` - печатает ВСЕ отправленные/принятые байты (главный отладчик сетевых скриптов).
- `p64()/p32()` и `u64()/u32()` - встроенные обёртки над `struct.pack/unpack` (мостик к pwn, глава 9).

## 2. Proof-of-Work (очень частое начало задач)

Сервер часто требует: "пришли строку X, чтобы `sha256(префикс + X)` начинался с нулей". Решается
перебором - надо успеть быстро:

```python
import hashlib, itertools, string

prefix = b"abc123"              # сервер пришлёт свой префикс
want = "0000"                    # и сколько нулей нужно
def solve_pow(prefix, want):
    for i in range(10_000_000):
        s = prefix + str(i).encode()
        if hashlib.sha256(s).hexdigest().startswith(want):
            return str(i).encode()
# вариант "подобрать суффикс из символов":
def solve_pow_chars(prefix, want, n=6):
    al = string.ascii_letters + string.digits
    for L in range(1, n):
        for combo in itertools.product(al, repeat=L):
            s = prefix + "".join(combo).encode()
            if hashlib.sha256(s).hexdigest().startswith(want):
                return "".join(combo).encode()
```

Связка "решить PoW и отправить" целиком:
```python
from pwn import *
io = remote("host", 1337)
io.recvuntil(b"prefix: "); pref = io.recvline().strip()
io.recvuntil(b"zeros: ");  z = int(io.recvline().strip())
io.sendline(solve_pow(pref, "0"*z))
print(io.recvall(timeout=5))
```

## 3. Бинарные протоколы: struct

Если сервер ждёт не текст, а бинарь (длины, числа) - собирай пакеты через `struct` (см.
`03-python/hard.md`):

```python
import struct
payload = struct.pack("<I", 1337) + struct.pack("<H", 7) + b"data"   # LE uint32 + uint16 + байты
io.send(payload)
resp = io.recv(8)
value = struct.unpack("<Q", resp)[0]                                  # распаковать ответ
```

## 4. Циклы "вопрос-ответ" на чистом socket (без pwntools)

Если `pwntools` нет - то же на стандартном `socket` + `makefile`:

```python
import socket
s = socket.socket(); s.connect(("host", 1337))
f = s.makefile("rwb")
while True:
    line = f.readline()
    if not line: break
    if b"flag" in line: print(line); break
    # распарсить задачу из line, посчитать ответ:
    ans = str(eval(line.split(b"=")[0].decode())).encode()   # eval только для доверенного формата!
    f.write(ans + b"\n"); f.flush()
```

⚠️ Если сервер пишет приглашение **без `\n`** (`Enter answer: ` и ждёт ввода на той же строке),
`f.readline()` зависнет навсегда. Тогда читай до подстроки по одному байту:
```python
def recv_until(sock, delim=b": "):
    buf = b""
    while not buf.endswith(delim):
        ch = sock.recv(1)
        if not ch: break
        buf += ch
    return buf
```

## 5. Крафт пакетов (scapy) - 🔺

Для задач про низкоуровневый трафик (ARP, ICMP, кастомные пакеты) есть `scapy`:
```python
from scapy.all import IP, ICMP, sr1
sr1(IP(dst="10.0.0.1")/ICMP())     # отправить ping-пакет и получить ответ
```
На муниципале почти не нужно; знать, что инструмент существует.

🎯 **Тренировка (hard).** Напиши `solve_pow`, который находит такое `i`, что `sha256(b"chal_"+i)`
начинается с `000`. Затем собери сервер-викторину на `socket`, требующую PoW перед вопросами, и
клиента, который его проходит.

---
*Уровень: **hard**. Рядом: [easy](easy.md) | [medium](medium.md) | [оглавление](../00-about.md)*
