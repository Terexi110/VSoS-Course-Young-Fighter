# Скриншоты для burpsuite.md

Все кадры сняты на учебном стенде (`python3 lab/stand.py`, http://127.0.0.1:5000), так что на
картинках только синтетические данные. Выноски нанесены поверх (оранжевые рамки и подписи), исходники
уменьшены до ширины 1500 px.

| Файл | Что в кадре | Где в главе | Статус |
|---|---|---|---|
| `burp-flow.svg` | схема: браузер -> Burp -> сервер | п. 1 | готово (схема) |
| `burp-03-history.png` | HTTP history, `GET /panel` -> `403 admins only` | п. 3.1 | готово |
| `burp-05-send-to-repeater.png` | меню правого клика: Send to Repeater, Copy as curl | п. 3.1 | готово |
| `burp-04-intercept.png` | Intercept держит `POST /login`, тело запроса | п. 3.2 | готово |
| `burp-06-repeater-badlogin.png` | Repeater: `user=admin&pass=admin` -> `bad login` | п. 4, шаг 2 | готово |
| `burp-07-repeater-flag.png` | Repeater: `Cookie: role=admin` -> флаг | п. 4, шаг 3 | готово |

**По желанию (в тексте не используются):**
- `burp-01-proxy-settings.png` - *Proxy -> Proxy settings*, слушатель `127.0.0.1:8080`;
- `burp-02-ca-cert.png` - страница `http://burp` с кнопкой *CA Certificate*.

Нужны, только если в п. 2 захочется показать настройку своего Firefox вместо встроенного браузера.
Снимать так же: окно Burp ~1500x950, лишний трафик убрать через Scope + *Show only in-scope items*.
