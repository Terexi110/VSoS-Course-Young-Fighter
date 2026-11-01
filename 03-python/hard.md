# Глава 3 (hard). Python для CTF: байты, struct, перебор, регулярки

Продвинутый инструментарий, который нужен в крипте, реверсе и pwn.

## 1. Числа <-> байты и порядок байтов (endianness)

Критично для реверса и pwn: одно и то же число в памяти лежит "задом наперёд" (little-endian).

```python
>>> (0x41424344).to_bytes(4, "big")      # число -> 4 байта, обычный порядок
b'ABCD'
>>> (0x41424344).to_bytes(4, "little")   # little-endian (как в x86)
b'DCBA'
>>> int.from_bytes(b'DCBA', "little")     # байты -> число обратно
1094861636
```

## 2. `struct` - упаковка/распаковка бинарных структур

```python
import struct
struct.pack("<I", 0x41424344)        # < = little-endian, I = uint32  -> b'DCBA'
struct.unpack("<I", b"DCBA")[0]      # обратно -> 1094861636
struct.pack("<Q", 0xdeadbeef)        # Q = uint64 (8 байт) - адреса в pwn
struct.unpack("<2I", b"AAAABBBB")    # два uint32 сразу -> (кортеж)
```
Форматы: `B`=1 байт, `H`=2, `I`=4, `Q`=8; `<` little-endian, `>` big-endian.
💡 В pwn адрес функции кладут в payload так: `payload = b"A"*offset + struct.pack("<Q", addr)`.

## 3. Перебор через `itertools`

```python
import itertools, string
# все пароли длины 4 из строчных букв и цифр
chars = string.ascii_lowercase + string.digits
for combo in itertools.product(chars, repeat=4):
    pwd = "".join(combo)
    # ... проверка pwd ...

# все перестановки/комбинации
list(itertools.permutations([1,2,3]))      # перестановки
itertools.cycle(b"KEY")                     # бесконечное повторение ключа (для XOR)
```

## 4. Регулярные выражения - вытащить нужное

```python
import re
data = b"...mess... flag{hidden_123} ...more..."
m = re.search(rb'flag\{[^}]+\}', data)      # rb'...' = байтовая регулярка
print(m.group())                             # b'flag{hidden_123}'

re.findall(rb'[0-9a-f]{32}', data)           # найти все MD5-подобные хеши
re.findall(r'\d+', "a12b34")                  # все числа -> ['12','34']
```

## 5. Срезы байтов и быстрые преобразования

```python
data[:16]        # первые 16 байт
data[-8:]        # последние 8
data[::-1]       # развернуть
bytes(b ^ 0x42 for b in data)                # XOR всего с байтом
bytes(a ^ b for a, b in zip(data, cycle(b"KEY")))  # XOR с повторяющимся ключом (нужен from itertools import cycle)
```

Канонический перебор однобайтового XOR с фильтром по флагу (держи в пальцах):
```python
for k in range(256):
    res = bytes(b ^ k for b in data)
    if b"flag" in res: print(k, res)
```

## 6. Полезные модули стандартной библиотеки

```python
import zlib;    zlib.decompress(data)         # распаковать zlib/deflate (куски PNG, zip)
import gzip;    gzip.decompress(data)         # gzip
import binascii; binascii.unhexlify("4142")   # hex -> байты (аналог bytes.fromhex)
import hashlib; hashlib.sha256(b"x").hexdigest()
import codecs;  codecs.decode("uryyb","rot13") # ROT13 для текста
import ast;     ast.literal_eval("[102,108,97,103]")  # строку-литерал -> список/байты (безопасно)
from urllib.parse import unquote; unquote("%7Bflag%7D")  # URL-декод (%7B->{) - частое в web/логах
```

## 7. Шаблон универсальной "решалки"

Держи заготовку под рукой - набрасываешь решение поверх:

```python
#!/usr/bin/env python3
import sys, re, base64, struct
from itertools import product

data = open(sys.argv[1], "rb").read() if len(sys.argv) > 1 else b""

def find_flag(b):
    m = re.search(rb'[a-zA-Z0-9_]+\{[^}]+\}', b)
    return m.group() if m else None

# ... тут логика задачи ...
print(find_flag(data))
```

🔺 **Для тяжёлого реверса** бывает полезен солвер ограничений **z3** (`pip install z3-solver`, если
есть), который сам находит вход, удовлетворяющий проверкам. Но на олимпиадной ВМ его может не быть -
надёжнее уметь перебор (`itertools.product`) и обращение функции руками (см. `08-reverse/hard.md`).

🎯 **Тренировка (hard).** Запакуй число `0xcafebabe` в little-endian через `struct.pack("<I", ...)`,
распакуй обратно. Потом вытащи регуляркой все `flag{...}` из байтовой строки с мусором.

---
*Уровень: **hard**. Рядом: [easy](easy.md) | [medium](medium.md) | [оглавление](../00-about.md)*
