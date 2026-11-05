# gostsum

Implementation of GOST R 34.11-94, GOST R 34.11-2012 (STRIBOG-256/512), SHA, SHA2, SHA3
and hash-based algorithms: HMAC, PBKDF, SSHA.

Утилита командной строки для расчёта и проверки контрольной суммы файла (GOST / SHA),
в том числе по ГОСТ Р 34.11-94 и ГОСТ Р 34.11-2012 (СТРИБОГ).

**Применение:** учёт электронных копий в составе конструкторской документации (КД)
по ГОСТ 2.051-2013 (ЕСКД. Электронные документы) — взаимное соответствие содержимого
файла и реквизитной части через контрольную сумму. Практика: листок с суммами
на каждую прошивку; в архиве вместе с КД — любой электронный экземпляр (в т.ч. PDF
чертежа) входит с своим хешем, запись идёт в Лист учёта электронных документов (ЛУЭД).

Для архивного контура те же хэш-суммы стыкуются с Приказом Росархива № 77 (Гл. X)
и ориентирами ГОСТ Р 7.0.102-2024, ГОСТ Р 7.0.8-2013, ГОСТ Р ИСО 15489-1-2019.

**License:** MIT (совместима с BSD). См. [LICENSE](LICENSE).

Репозиторий: https://github.com/AnatolyGeorgievski/gostsum

Утилита изначально рассчитана на Windows (MinGW / MSYS2). Тот же `Makefile` собирает под Linux и FreeBSD.

## Сборка: Linux / FreeBSD

```sh
git clone https://github.com/AnatolyGeorgievski/gostsum.git
cd gostsum
make
make check
```

Нужен GCC или Clang с поддержкой C11 (`aligned_alloc`, vector extensions для STRIBOG/GOST).  
Пакеты: `build-essential` (Debian/Ubuntu) или `gcc` + `make` (FreeBSD: `pkg install gcc gmake`, затем `gmake`).

На x86_64 без SHA-NI используется `sha256.c`; при `__SHA__` — `sha256_ni.c`.  
Сетевой порядок байт — [`net.h`](net.h) (`ntoh*` / `hton*`).

Отключить `-march=native`:

```sh
make NO_NATIVE=1
```

## Сборка: Windows (MSYS2)

1. Установите [MSYS2](https://www.msys2.org/).
2. Откройте оболочку **UCRT64** или **MINGW64** (не чистый `msys`).
3. Пакеты:

```sh
pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-make make
# или для MINGW64:
# pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-make make
```

4. Сборка:

```sh
cd /path/to/gostsum
make
make check
./gostsum.exe -l
```

В Mingw CRT уже есть `_aligned_malloc` / `_aligned_free` — `gosthash.c` их использует.  
`sha256_ni.c` подключается только если компилятор видит `__SHA__`.

## Использование

```sh
./gostsum -l
./gostsum -a gost FILE
./gostsum -a gost512 FILE
./gostsum -a sha256 FILE
./gostsum -a sha3-256 FILE

# stdin (issue #3): без файлов или имя «-»
printf abc | ./gostsum -a sha256 -
./gostsum -a sha256 < FILE

# проверка списка сумм (issue #4), формат: HEX *имя
./gostsum -a sha256 FILE > sums.txt
./gostsum -a sha256 -c sums.txt

# листок на прошивку / комплект КД (PDF чертежа и др.)
./gostsum -a gost firmware.bin drawing.pdf > lued-sums.txt
./gostsum -a gost -c lued-sums.txt
```

`sha256` — SHA-2-256; `sha3-256` — SHA-3-256.

## Совместимость

| Платформа        | Статус                          |
|------------------|---------------------------------|
| Linux x86_64     | `make` / `make check`           |
| Linux aarch64    | `sha256_arm.c`                  |
| FreeBSD          | `gmake`; C11 `aligned_alloc`    |
| MSYS2 MinGW/UCRT | `gostsum.exe`                   |
| Clang            | `make CC=clang` / `make check`  |

Открытые темы закрыты в коде: чтение stdin (`-` / без аргументов), `-c` для списка сумм.
