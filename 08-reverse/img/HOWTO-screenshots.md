# Как снять 3 реальных скриншота Ghidra

В этой папке лежит готовый учебный бинарь **`reverse_demo`** (исходник - `reverse_demo.c`).
Он ровно из примера главы 8.5:
- правильный пароль - `secret99`;
- при верном вводе печатает `flag{r3v3rs3_m3}`;
- проверка: каждый символ `^ 0x2A` сравнивается с массивом `target[8]`;
- собран `-no-pie -fno-stack-protector`, **не stripped** - адреса чистые, `main` и `check` видны.

## Подготовка (один раз)
1. Открой Ghidra -> *File -> New Project* -> Non-Shared Project -> имя любое.
2. *File -> Import File* -> выбери `reverse_demo` из этой папки -> OK.
3. Двойной клик по `reverse_demo` в проекте -> спросит про анализ -> **Analyze -> Yes** (жди ~15-30 сек).
4. Разверни окно CodeBrowser на весь экран.

## Три кадра (сохрани PNG в эту же папку под ТОЧНО такими именами - они уже прописаны в `medium.md`)

### 1. `ghidra-layout.png` - общий вид окна
- Слева в **Symbol Tree -> Functions** должны быть видны `main` и `check`.
- По центру - **Listing**, справа - **Decompile** с функцией `main`
  (видно `printf("Enter password: ")`, вызов `check(...)`, ветки `Correct!` / `Wrong`).
- Сними всё окно целиком.

### 2. `ghidra-decompile.png` - разбор проверки
- Дважды кликни функцию **`check`** в Symbol Tree -> справа в Decompile откроется её псевдокод.
- В нём виден массив `target` с байтами `0x59,0x4f,...` и цикл с `^ 0x2A` и сравнением `!= target[i]`.
- Сними окно Decompile крупно (можно только правую панель).

### 3. `ghidra-strings-xref.png` - строки и переход в код
- Меню **Window -> Defined Strings**.
- Найди строки `"Enter password: "` и `"Correct! flag{r3v3rs3_m3}"`.
- (По желанию: правый клик по строке -> *References -> Show References to...* - покажет XREF в `main`.)
- Сними окно Defined Strings (вместе с окошком References, если открыл).

## После
Три PNG лежат в `08-reverse/img/` под указанными именами - и в тексте главы они уже подхватятся
(ссылки `![...](img/ghidra-layout.png)` и т.д. вставлены в `08-reverse/medium.md`).
Схемы, что я нарисовал, можно оставить как запасной вариант или удалить - как удобнее.
