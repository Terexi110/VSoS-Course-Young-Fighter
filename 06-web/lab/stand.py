#!/usr/bin/env python3
# Учебный стенд для 06-web: запусти `python3 stand.py` и открывай http://127.0.0.1:5000
# Только для тренировки на своём компьютере. Все флаги выдуманные.
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from http.cookies import SimpleCookie
from urllib.parse import urlparse, parse_qs

db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE items(id INTEGER, name TEXT)")
db.execute("CREATE TABLE secrets(flag TEXT)")
db.executemany("INSERT INTO items VALUES(?,?)", [(1, "pen"), (2, "book"), (3, "lamp")])
db.execute("INSERT INTO secrets VALUES('flag{un10n_s3l3ct_w1ns}')")

INDEX = """<html><body>
<h1>Shop</h1>
<!-- TODO: убрать старый бэкап из корня -->
<form method="POST" action="/login">
  <input name="user"> <input name="pass" type="password"> <button>Войти</button>
</form>
<a href="/item?id=1">Товар 1</a> | <a href="/panel">Панель</a>
</body></html>"""


class H(BaseHTTPRequestHandler):
    server_version = "nginx/1.18.0"          # притворяемся nginx (видно в curl -I)
    sys_version = ""

    def send(self, code, body, headers=()):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":              # на HEAD отдаём только заголовки
            self.wfile.write(data)

    def cookies(self):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        return {k: m.value for k, m in c.items()}

    def do_GET(self):
        u = urlparse(self.path)
        p = u.path
        if p == "/":
            self.send(200, INDEX)
        elif p == "/robots.txt":
            self.send(200, "User-agent: *\nDisallow: /backup_2021\n")
        elif p == "/backup_2021":
            self.send(200, "backup 2021: права пользователя хранятся в куке role\n")
        elif p == "/admin":
            self.send(403, "Forbidden\n")
        elif p == "/panel":
            if self.cookies().get("role") == "admin":
                self.send(200, "flag{cookie_tampering_is_classic}\n")
            else:
                self.send(403, "admins only\n")
        elif p == "/item":
            item_id = parse_qs(u.query).get("id", ["1"])[0]
            q = f"SELECT name FROM items WHERE id = {item_id}"   # уязвимо: ввод прямо в SQL
            try:
                rows = db.execute(q).fetchall()
                self.send(200, "\n".join(r[0] for r in rows) + "\n")
            except sqlite3.Error as e:
                self.send(500, f"SQL error: {e}\n")
        else:
            self.send(404, "Not found\n")

    do_HEAD = do_GET                           # чтобы работал curl -I

    def do_POST(self):
        if self.path == "/login":
            n = int(self.headers.get("Content-Length", 0))
            form = parse_qs(self.rfile.read(n).decode())
            if form.get("user") == ["guest"] and form.get("pass") == ["guest"]:
                self.send(302, "", [("Location", "/"), ("Set-Cookie", "role=user; Path=/")])
            else:
                self.send(200, "bad login\n")
        else:
            self.send(404, "Not found\n")

    def log_message(self, *a):
        pass                                   # не мусорим в консоль


if __name__ == "__main__":
    print("Стенд: http://127.0.0.1:5000  (Ctrl+C - остановить)")
    HTTPServer(("127.0.0.1", 5000), H).serve_forever()
