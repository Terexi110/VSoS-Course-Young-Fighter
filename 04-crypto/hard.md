# Глава 4 (hard). Криптоанализ и слабости RSA

Здесь - атаки, которых нет на medium: взлом Виженера **без ключа**, аффинный шифр, и три классические
уязвимости RSA. Всё в пределах регионального уровня (🔺), весь код проверен на запуск.

## 1. Аффинный шифр

Каждая буква: `y = (a*x + b) mod 26`. Ключ - пара `(a, b)`, причём `a` взаимно просто с 26.
Расшифровка: `x = a^-1*(y - b) mod 26`.

```python
import string
low = string.ascii_lowercase

def affine_decrypt(ct, a, b):
    ai = pow(a, -1, 26)                      # обратный к a по модулю 26
    out = ""
    for c in ct:
        if c in low:
            out += low[(ai * (low.index(c) - b)) % 26]
        else:
            out += c
    return out

# если (a,b) неизвестны - их всего 12*26=312, перебираем все:
for a in [1,3,5,7,9,11,15,17,19,21,23,25]:    # a, взаимно простые с 26
    for b in range(26):
        pt = affine_decrypt(ct, a, b)
        if "the" in pt or "flag" in pt:        # фильтр по признаку текста
            print(a, b, pt)
```

## 2. Взлом Виженера без ключа (IoC + частотный анализ)

Два шага: (1) найти длину ключа через **индекс совпадений**, (2) взломать каждую колонку как Цезаря.

```python
import string
from collections import Counter
low = string.ascii_lowercase

def ioc(s):                                   # индекс совпадений
    c = Counter(s); n = len(s)
    return sum(v*(v-1) for v in c.values()) / (n*(n-1)) if n > 1 else 0

# --- шаг 1: длина ключа (английский текст даёт IoC ~0.066, мусор ~0.038) ---
raw_ct = "...шифротекст (может быть с пробелами, запятыми и заглавными)..."
ct = "".join(c for c in raw_ct.lower() if c in low)   # ОЧИСТКА: только строчные буквы!
for klen in range(1, 11):
    cols = [ct[i::klen] for i in range(klen)]           # разбить на колонки
    avg = sum(ioc(col) for col in cols) / klen
    print(klen, round(avg, 4))                           # пик = длина ключа

# --- шаг 2: взлом каждой колонки (Цезарь) по близости к частотам языка ---
def break_col(col):
    eng = "etaoinshrdlu"                                  # частые буквы английского
    best_sh, best_score = 0, -1
    for sh in range(26):
        dec = "".join(low[(low.index(c)-sh) % 26] for c in col)
        score = sum(dec.count(ch) for ch in eng)
        if score > best_score:
            best_score, best_sh = score, sh
    return best_sh

klen = 5                                                  # взять из шага 1
cols = [ct[i::klen] for i in range(klen)]
key  = "".join(low[break_col(c)] for c in cols)
print("ключ:", key)                                       # напр. 'lemon'
```

⚠️ Нужен текст подлиннее (от ~100 символов) - на коротком IoC шумит. Для русского замени `eng` на
частые русские буквы и алфавит на 32 буквы.

## 3. RSA: малая экспонента (e=3) без паддинга

🔺 Если `e = 3`, сообщение короткое, и `m^3 < n`, то при шифровании **не было переполнения по модулю**:
`c = m^3`. Тогда `m` - это обычный кубический корень из `c`, безо всякого `d`.

```python
def iroot(x, n):                              # целочисленный корень n-й степени
    lo, hi = 0, 1
    while hi**n < x: hi *= 2
    while lo < hi:
        mid = (lo + hi) // 2
        if mid**n < x: lo = mid + 1
        else: hi = mid
    return lo

m = iroot(c, 3)                               # c = m^3, берём кубический корень
print(m.to_bytes((m.bit_length()+7)//8, "big"))
```

Признак: в условии `e = 3` (или другое маленькое) и подозрительно маленькое сообщение.

💡 Если кубический корень из `c` не извлёкся нацело - сообщение чуть длиннее и было небольшое
переполнение (`c = m^3 - k*n`). Перебери маленькое `k`:
```python
for k in range(10000):
    r = iroot(c + k*n, 3)
    if r**3 == c + k*n:
        print(r.to_bytes((r.bit_length()+7)//8, "big")); break
```

## 4. RSA: общий модуль (common modulus)

🔺 Одно и то же `m` зашифровали **одним `n`**, но **двумя разными `e`** (взаимно простыми). Тогда `m`
восстанавливается без факторизации `n` - по расширенному алгоритму Евклида.

```python
def ext(a, b):                                # расширенный Евклид: g, x, y: a*x+b*y=g
    if b == 0: return (a, 1, 0)
    g, x, y = ext(b, a % b)
    return (g, y, x - (a // b) * y)

def powneg(c, x, n):                           # возведение в возможно отрицательную степень
    return pow(pow(c, -1, n), -x, n) if x < 0 else pow(c, x, n)

# даны: n, (e1, c1), (e2, c2), gcd(e1,e2)=1
g, a, b = ext(e1, e2)                          # a*e1 + b*e2 = 1
m = (powneg(c1, a, n) * powneg(c2, b, n)) % n  # m = c1^a * c2^b mod n
print(m.to_bytes((m.bit_length()+7)//8, "big"))
```

💡 Без самописного Евклида коэффициенты Безу находятся короче (раз `gcd(e1,e2)=1`):
```python
a = pow(e1, -1, e2)          # a*e1 = 1 (mod e2)
b = (1 - a*e1) // e2         # из a*e1 + b*e2 = 1
m = (powneg(c1, a, n) * powneg(c2, b, n)) % n
```

Признак: в условии один `n`, но две пары `(e, c)`.

## 5. Хеши: продвинутое

JWT - токен из трёх частей через точку `header.payload.signature` (первые две - Base64url от JSON; подробнее в `06-web/medium.md`).

- **Взлом JWT с HMAC.** Если токен подписан `HS256` слабым секретом - секрет перебирают:
  ```bash
  john jwt.txt --wordlist=words.txt          # или hashcat -m 16500 jwt.txt words.txt
  ```
  Зная секрет, подписываешь свой токен (например, `admin:true`).
- **Length extension attack** (🔺🔺, обычно регион+): если сервер считает `hash(secret || data)` на
  уязвимом алгоритме (MD5/SHA1/SHA256 без HMAC), можно дописать данные к `data` и пересчитать
  валидный хеш, **не зная secret**. Инструмент - `hashpump`/`hash_extender`. На муниципале почти не
  встречается - достаточно знать, что такое бывает и почему нужен именно HMAC.
- **Режимы hashcat** (пригодится): `0` = MD5, `100` = SHA1, `1400` = SHA256, `1700` = SHA512,
  `16500` = JWT, `13100` = Kerberos. Запуск: `hashcat -m <режим> hash.txt words.txt`.

## 6. AES: детектор режима ECB

AES шифрует данные блоками фиксированной длины - по **16 байт** (см. п. 4.2-4.3).

🔺 Режим **ECB** шифрует одинаковые блоки одинаково -> в шифротексте видны **повторяющиеся
16-байтовые блоки**. Это признак ECB (слабого режима):

```python
def looks_like_ecb(data, bs=16):
    blocks = [data[i:i+bs] for i in range(0, len(data), bs)]
    return len(blocks) != len(set(blocks))     # есть повторяющиеся блоки?
```

🎯 **Тренировка (hard).** (а) Зашифруй аффинным шифром фразу и взломай перебором всех 312 ключей.
(б) Сгенерируй RSA с `e=3` и коротким сообщением, восстанови его кубическим корнем. (в) Собери
common-modulus: один `n`, два `e`, восстанови `m` без факторизации.

---
*Уровень: **hard**. Рядом: [easy](easy.md) | [medium](medium.md) | [оглавление](../00-about.md)*
