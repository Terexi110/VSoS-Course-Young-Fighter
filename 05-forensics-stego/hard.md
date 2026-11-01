# Глава 5 (hard). Глубокая форензика и стего

Разбор файлов на уровне структуры: битовые плоскости, чанки PNG, полиглоты, глубокий анализ трафика,
аудио-спектрограммы.

## 1. LSB по всем битовым плоскостям и каналам

На medium мы доставали младший бит. Но данные могут быть в **другом бите** или **одном канале**.
Переберём все варианты:

```python
from PIL import Image
import numpy as np, re

img = np.array(Image.open("img.png").convert("RGB"))
h, w, _ = img.shape
for ch in range(3):                         # каналы R,G,B
    for bit in range(8):                     # биты 0..7
        plane = (img[:, :, ch] >> bit) & 1   # вытащить нужный бит каждого пикселя
        data = np.packbits(plane).tobytes()  # мгновенно собрать биты в байты (вместо медленного join)
        m = re.search(rb'flag\{[^}]+\}', data)
        if m:
            print(f"канал={ch} бит={bit}:", m.group())
```

💡 Это ровно то, что перебирает `zsteg -a` для PNG/BMP. Если `zsteg` есть - начинай с него;
скрипт - когда формат нестандартный или хочешь контролировать порядок обхода.

## 2. Разбор структуры PNG по чанкам

PNG состоит из "чанков": `IHDR` (размеры), `IDAT` (пиксели), `IEND` (конец), плюс могут быть
"лишние" (`tEXt`, `zTXt` - текст; данные после `IEND` - спрятанный хвост).

```python
import struct
def png_chunks(data):
    assert data[:8] == b"\x89PNG\r\n\x1a\n", "не PNG"
    i = 8; out = []
    while i < len(data):
        ln  = struct.unpack(">I", data[i:i+4])[0]     # длина (big-endian)
        typ = data[i+4:i+8].decode("latin1")           # тип чанка
        out.append((typ, ln, i))
        i += 12 + ln                                    # 4 длина +4 тип +ln данные +4 CRC
        if typ == "IEND":
            if i < len(data):
                print("!!! данные после IEND:", data[i:i+32])   # спрятанный хвост
            break
    return out

print(png_chunks(open("img.png","rb").read()))
```

⚠️ Трюк с **заниженными размерами**: в `IHDR` записаны ширина/высота. Если их уменьшили - часть
картинки не рисуется. Исправляешь байты размеров в `IHDR` (первые 8 байт данных чанка: 4 ширина, 4
высота, big-endian) - и флаг проявляется. Проверяй через `pngcheck -v`.

💡 Поменял ширину/высоту - пересчитай CRC чанка IHDR, иначе просмотрщики откажутся открывать файл:
```python
import zlib, struct
d = open("img.png", "rb").read()
w, h = 800, 600                                  # настоящие размеры
ihdr = struct.pack(">II", w, h) + d[24:29]       # width,height + остальные 5 байт IHDR
crc  = zlib.crc32(b"IHDR" + ihdr)                # CRC = от типа чанка + его данных
fixed = d[:16] + ihdr + struct.pack(">I", crc) + d[33:]
open("fixed.png", "wb").write(fixed)
```

## 3. Полиглоты и приклеенные файлы

Файл может быть сразу двух форматов (полиглот) или нести хвост после своего конца:

```bash
binwalk файл                                # обзор вложений
foremost -i файл -o out                      # вырезать по сигнатурам
# вручную: найти начало вложенного zip и вырезать
python3 -c "d=open('f','rb').read(); i=d.find(b'PK\x03\x04'); open('x.zip','wb').write(d[i:])"
```
Маркеры концов: JPEG - `FF D9`, PNG - `IEND`, GIF - `00 3B`. Всё после - подозрительно.

## 4. Глубокий анализ трафика (tshark)

```bash
tshark -r d.pcap -Y 'http.request' -T fields -e http.host -e http.request.uri   # все URL
tshark -r d.pcap -Y 'dns' -T fields -e dns.qry.name                              # DNS-запросы (эксфильтрация в поддоменах!)
tshark -r d.pcap -Y 'ftp' -T fields -e ftp.request.command -e ftp.request.arg   # логины FTP
tshark -r d.pcap --export-objects http,out_dir                                   # вытащить переданные файлы
tshark -r d.pcap -qz follow,tcp,ascii,3                                          # тело TCP-потока №3
tshark -r usb.pcap -T fields -e usbhid.data -e usb.capdata                        # нажатия USB-клавиатуры/мыши (HID)
```

💡 Данные часто разбиты по пакетам и закодированы (Base64/hex) - собери поток целиком (Follow Stream /
`export-objects`), потом декодируй через главу 4. Эксфильтрацию часто прячут в **DNS-запросах**
(`секрет.attacker.com`) или в ICMP.

## 5. Аудио-стего: спектрограмма своими руками

Если в `.wav` флаг "нарисован" в спектре - построй спектрограмму:

```python
import numpy as np, wave, matplotlib
matplotlib.use("Agg"); import matplotlib.pyplot as plt
w = wave.open("a.wav"); fr = w.getframerate(); ch = w.getnchannels()
sig = np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16)[::ch]  # [::ch] -> один канал (стерео в моно)
plt.specgram(sig, Fs=fr); plt.savefig("spec.png")       # открыть spec.png - флаг виден надписью
```
Либо в GUI: **Audacity** / **Sonic Visualiser** -> режим спектрограммы.

## 6. Образы дисков и файловых систем

Дали `.img`/`.dd`/`.raw` (образ диска) - внутри файловая система, часто с "удалёнными" файлами:

```bash
7z l disk.img                      # просто посмотреть содержимое (часто уже хватает)
mount -o loop,ro disk.img /mnt     # примонтировать только на чтение
# пакет sleuthkit - анализ ФС и удалённых файлов:
fls -r disk.img                    # список файлов, включая удалённые (помечены *)
icat disk.img <inode>              # вытащить файл по номеру inode
```
(Перебор пароля `steghide` словарём - `stegseek` - уже был в `medium.md` п. 5.5.)

🎯 **Тренировка (hard).** (а) Зашей флаг в бит №3 зелёного канала картинки и достань его перебором
каналов/битов. (б) Распарси чанки своего PNG и припиши после `IEND` текст - убедись, что скрипт его
находит.

---
*Уровень: **hard**. Рядом: [easy](easy.md) | [medium](medium.md) | [оглавление](../00-about.md)*
