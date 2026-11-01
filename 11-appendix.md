# Приложения

Это выжимка всего курса. Напомню: на тур ничего взять нельзя, поэтому приложения - **тренажёр для
запоминания**, а не шпаргалка "подсмотреть на туре". Цель - прогнать их столько раз, чтобы команды и
шаблоны всплывали в голове сами.

---

## Приложение A. Шпаргалка bash-однострочников

**Разведка файла:**
```bash
file *                                   # типы всех файлов
strings файл | grep -i '{'               # флаг открытым текстом?
strings -n 8 файл | less                 # читаемые строки от 8 символов
xxd файл | head                          # магические байты
grep -raoE '\w+\{[^}]+\}' .              # флаг где угодно в папке
find . -type f                           # все файлы в дереве
```

**Кодировки прямо в терминале:**
```bash
echo 'ZmxhZw==' | base64 -d              # Base64 -> текст
echo -n 'flag' | base64                  # текст -> Base64
echo -n '666c6167' | xxd -r -p           # hex -> текст
echo -n 'flag' | xxd -p                  # текст -> hex
echo -n 'flag' | md5sum                  # MD5
echo -n 'flag' | sha256sum               # SHA-256
```

**Форензика/стего:**
```bash
exiftool файл                            # метаданные
binwalk -e файл                          # найти и извлечь вложенные файлы
zsteg -a картинка.png                    # перебор LSB-схем
steghide extract -sf файл.jpg            # стего с паролем
pngcheck -v картинка.png                 # структура PNG
strings дамп.pcap | grep -i flag         # флаг в трафике
tshark -r дамп.pcap -Y http              # HTTP-пакеты из дампа
```

**Веб:**
```bash
curl -i URL                              # запрос с заголовками
curl -L URL                              # идти по редиректам
curl -X POST -d "a=1&b=2" URL            # POST-форма
curl -H "Cookie: role=admin" URL         # своя кука
curl URL/robots.txt                      # спрятанные пути
```

**Сети:**
```bash
nc IP ПОРТ                               # подключиться к сервису
echo "ответ" | nc IP ПОРТ                # отправить и получить
ip addr; ip route; ping IP               # сетевая диагностика
```

**Архивы:**
```bash
unzip a.zip; tar -xf a.tar; 7z x a.7z    # распаковка
zip2john a.zip > h.txt && john h.txt --wordlist=words.txt   # пароль zip: вытащить хеш и подобрать
```

---

## Приложение B. Python-шаблоны (для заучивания)

Это "мышечная память" курса - научись писать их без подглядывания.

**Чтение файла и байты:**
```python
data = open("file", "rb").read()
print(len(data), data[:32], data[:32].hex())
```

**Цезарь (латиница), перебор сдвигов:**
```python
import string; low = string.ascii_lowercase
def caesar(s, k):
    return "".join(low[(low.index(c)-k)%26] if c in low else c for c in s)
for k in range(26): print(k, caesar(ct, k))
```

**Цезарь/Виженер (кириллица):**
```python
A = "абвгдежзийклмнопрстуфхцчшщъыьэюя"      # 32 буквы
def vig(s, key, dec=False):
    out=""; ki=0
    for c in s:
        if c in A:
            k=A.index(key[ki%len(key)]); ki+=1
            out+=A[(A.index(c)+(-k if dec else k))%32]
        else: out+=c
    return out
# Цезарь = Виженер с ключом из одной буквы
```

**XOR: перебор однобайтового ключа / повторяющийся ключ:**
```python
for k in range(256):                        # однобайтовый
    pt = bytes(b ^ k for b in ct)
    if b"flag" in pt: print(k, pt)

key = bytes(ct[i] ^ b"flag{"[i] for i in range(5))   # восстановить ключ по крибу
pt  = bytes(ct[i] ^ key[i % len(key)] for i in range(len(ct)))
```

**Скелет дешифратора самодельного шифра (обращай операции в обратном порядке):**
```python
def decrypt(data, key):
    out=[]; state=0x3F
    for i, x in enumerate(data):            # x - шифробайт
        y = x ^ state                       # <- обратить операции шифрования
        y = ((y >> 3) | (y << 5)) & 0xFF    #   в ОБРАТНОМ порядке
        y = (y - 0x11) & 0xFF
        b = y ^ key[i % len(key)]
        state = (state + x) & 0xFF
        out.append(b)
    return bytes(out)
```

**RSA (Ферма для близких простых):**
```python
import math
a = math.isqrt(n);  a += (a*a < n)
while True:
    b2 = a*a - n; b = math.isqrt(b2)
    if b*b == b2: p, q = a-b, a+b; break
    a += 1
d = pow(e, -1, (p-1)*(q-1)); m = pow(c, d, n)
print(m.to_bytes((m.bit_length()+7)//8, "big"))
```

**Хеш: словарный подбор:**
```python
import hashlib
for w in open("words.txt").read().split():
    if hashlib.md5(w.encode()).hexdigest() == target: print(w)
```

**LSB-стего (достать младшие биты):**
```python
from PIL import Image; import numpy as np, re
flat = np.array(Image.open("img.png").convert("RGB")).flatten()
bits = "".join(str(b & 1) for b in flat)
data = bytes(int(bits[i:i+8],2) for i in range(0, len(bits)-7, 8))
print(re.search(rb'flag\{[^}]+\}', data))
```

**Общение с сервером (socket):**
```python
import socket
s = socket.socket(); s.connect(("IP", ПОРТ))
print(s.recv(1024))
s.sendall(b"ответ\n")
print(s.recv(1024))
```

---

## Приложение C. Мастер-таблица "вижу X -> делаю Y"

| Что видишь | Категория | Действие |
|---|---|---|
| любой файл | - | `file` -> `strings\|grep '{'` -> `xxd\|head` |
| `A-Za-z0-9+/=` | Crypto | Base64: `base64 -d` |
| только `0-9a-f` | Crypto | hex: `bytes.fromhex` |
| 32/40/64 hex-символа | Crypto | хеш - подбор по словарю |
| хеш `0e`+цифры и PHP `==` | Web/Crypto | magic hash: `240610708` |
| текст со сдвигом букв | Crypto | Цезарь - перебор сдвигов |
| текст + ключ-слово | Crypto | Виженер |
| hex/байты без структуры | Crypto | XOR (256 ключей / криб) |
| **дан скрипт шифрования** | Crypto | написать обратную функцию |
| `n, e, c` | Crypto | RSA: разложить n (Ферма) -> d -> `pow(c,d,n)` |
| картинка, пусто в strings | Stego | `binwalk -e`, `zsteg -a` |
| `.jpg/.wav`, тулзы молчат | Stego | `steghide extract -sf` |
| фото/есть метаданные | Forensics | `exiftool` / `getexif()` |
| `.pcap` | Forensics | Wireshark -> Follow TCP Stream; `strings\|grep` |
| сайт без флага | Web | Ctrl+U, комментарии, `.js` в Sources |
| форма логина | Web | `' OR '1'='1` |
| кука `role=user` | Web | поменять на `admin` |
| токен `xxx.yyy.zzz` | Web | JWT: декодировать, `alg:none` |
| параметр-имя файла | Web | Path Traversal `../../etc/passwd` |
| дан `IP ПОРТ` | Networking | `nc IP ПОРТ`, затем скрипт `socket` |
| ELF/.exe | Reverse | `strings` -> `ltrace` -> Ghidra (`main`) |
| `.py/.js` скрипт | Reverse | читать; `print()` перед проверкой |
| бинарник + порт, нет проверки длины | Pwn | переполнение буфера |
| `01001000...` / Морзе / QR | Misc | перевести в текст (Python; QR - телефон или `qr`/декодер) |
| запароленный архив | Misc | `zip2john`+`john` (или `zipfile`), пароль искать рядом |

---

## Приложение D. Подготовка: ВМ и план тренировок

### Что должно быть в виртуалке (проверь заранее)

Образ участника обычно на базе Linux (часто Kali/аналог) и уже содержит нужное. Проверь, что
запускаются:

- `python3` (+ модули `pillow`/`numpy` для стего), `gcc`
- `file`, `strings`, `xxd`, `grep`, `binwalk`, `foremost`
- `exiftool`, `zsteg`, `steghide`, `stegseek`, `pngcheck`
- `wireshark`, `tshark`, `nc`, `curl`
- `ghidra`, `ltrace`/`strace`, `objdump`
- `unzip`, `7z`, `john` (+`zip2john`/`rar2john`) - пароли архивов
- `openssl`, `ssh`/`scp`, `hydra` (перебор сетевых логинов), `qr` (генерация QR); `zbarimg` - если есть

Проверка одной строкой:
```bash
for t in python3 gcc file strings binwalk exiftool zsteg steghide wireshark nc curl ghidra unzip 7z john openssl ssh qr; do
    command -v $t >/dev/null && echo "+ $t" || echo " НЕТ: $t"
done
```

⚠️ Чего нет - не доустановишь на туре (интернета нет). Поэтому важен навык **делать то же руками на
Python**: читать EXIF, доставать LSB, вырезать вложения, переводить кодировки - всё это в курсе
показано без спец-утилит. Если утилиты вдруг не окажется, Python выручит.

### План подготовки (2 недели, по ~1 часу в день)

| День | Тема | Тренировки |
|---|---|---|
| 1 | Linux: навигация, `file/strings/grep/xxd`, пайпы | 1-4 |
| 2 | Python: режимы, `dir/help`, байты, файлы, hex/base64, XOR | 5-6 |
| 3 | Крипта: теория (Алиса/Боб, симм/асимм), кодировки, хеши | 7-8 |
| 4 | Крипта: Атбаш, Цезарь (лат+кир), частотный, Виженер | 9 |
| 5 | Крипта: XOR (перебор + криб) | 10 |
| 6 | Крипта: **дешифратор к самодельному шифру** (главное!) | 11 |
| 7 | Крипта: RSA (базовый + Ферма) | 12 |
| 8 | Форензика: метаданные, вложения, carve | 13-14 |
| 9 | Стего: LSB, steghide, структура PNG | 15 |
| 10 | Форензика: трафик (Wireshark/tshark) | 16 |
| 11 | Web: HTTP, DevTools, curl, robots, JWT, SQLi | 17-18 |
| 12 | Сети: nc, socket, автоматизация | 19-20 |
| 13 | Реверс: скрипты, strings, Ghidra, обращение проверки | 21-22 |
| 14 | Pwn (идея) + Misc (архивы, кодировки, QR) + повтор | 23 |

### Главные принципы, которые решают больше всего

1. **Ритуал первых секунд** над каждым файлом: `file` -> `strings|grep '{'` -> `xxd|head`. Половина
   лёгких флагов берётся здесь.
2. **Опознавай категорию, а не решай вслепую.** Мастер-таблица (Приложение C) - для этого.
3. **Python вместо калькулятора и онлайн-тулзов.** Всё считается и декодируется локально.
4. **Главный навык крипты/реверса** - прочитать алгоритм и обратить его (п. 4.12, п. 8.5).
5. **Бери сначала лёгкое.** Набери быстрые баллы, потом возвращайся к сложному.
6. **Тренируйся руками.** Навык даёт не чтение курса, а 26 выполненных тренировок.

## Приложение E. Где тренироваться заранее (онлайн-тренажёры)

На самом туре интернета нет, поэтому эти площадки - чтобы наработать навык **заранее**. Проходишь
их дома, набиваешь руку - и на туре приёмы уже в голове и в пальцах. Начинай с простого (Bandit,
picoCTF easy), потом по темам курса.

### По темам курса

| Площадка | Тема | Ссылка |
|---|---|---|
| OverTheWire: Bandit | Linux-терминал (гл. 02) | https://overthewire.org/wargames/bandit/ |
| OverTheWire: Krypton | Криптография (гл. 04) | https://overthewire.org/wargames/krypton/ |
| forkbomb (web-kids) | Реверс (гл. 08) | https://web-kids20.forkbomb.ru/tasks |
| forkbomb | Разные категории | https://forkbomb.ru/ |

**Bandit** - лучший первый шаг: проходишь уровни в терминале по SSH, каждый учит одной команде
(гл. 02 и 07). **Krypton** - то же самое для шифров (гл. 04).

### Олимпиадные задачи (ближе всего к туру)

| Площадка | Что там | Ссылка |
|---|---|---|
| CTF INF | Задачи с разных олимпиад, включая ВсОШ | https://ctfinf.ru/challenges |
| ВсОШ (МИЭМ ВШЭ) | Задачи прошлых лет: регион и заключительный этап | https://vsosh.miem.hse.ru/prepare |

Это самый близкий к реальному туру материал - прорешай, чтобы привыкнуть к формату и уровню.

### Зарубежные (с разборами)

| Площадка | Что там | Ссылка |
|---|---|---|
| picoCTF | CTF для новичков, много easy-задач с разборами | https://picoctf.com/ |

Начинай с **easy**: к задачам есть врайтапы (writeups), на них удобно учиться, когда застрял.

### Тренажёры ejudge

⚠️ На этих трёх **регистрация подтверждается лично**, а **ник создавай по ФИО**.

| Курс | Тема | Ссылка |
|---|---|---|
| Контекст на СИ | C/C++ (гл. 07a) | https://ejudge.insyo.org:44367/cgi-bin/new-client?contest_id=260904 |
| Реверс и патчинг | Реверс (гл. 08) | https://ejudge.insyo.org:44367/cgi-bin/new-client?contest_id=260210 |
| Системы счисления и память | Misc и память (гл. 10, 07a) | https://ejudge.insyo.org:44367/cgi-bin/new-client?contest_id=260816 |

💡 Порядок простой: **Bandit -> picoCTF easy -> задачи ctfinf/ВсОШ по уже пройденным темам**.
Застрял на задаче - вернись к нужной главе курса, разбери приём и снова на тренажёр.

---

> Удачи на туре! Спокойствие, ритуал и наработанные техники решают больше, чем попытки угадать.

---
*[К оглавлению курса](00-about.md)*
