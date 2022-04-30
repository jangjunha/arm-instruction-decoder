# ARM Instruction Decoder

[sample.mif](./sample.mif) 파일을 읽어서 명령어를 해독한 결과를 출력합니다.

해독에 실패한 명령은 명령 위치 뒤에 느낌표(!) 표시와 함께 바이너리를 출력합니다.

**Sample**

```arm
000       :: MOV        $10 := sign-ext(#0x4 << 0)  # do not alter condition codes
002       :: B  #0x5
003       :: CMP        set condition codes on $11 - logical-left-shift($8, #0x0)  # set condition codes
004       :: CMP        set condition codes on $10 - sign-ext(#0x20 << 0)  # set condition codes
005       :: ADD        $11 := $11 + sign-ext(#0x1 << 0)  # do not alter condition codes
[006..007]:: LDR        $8, [$15 + #0x1c]  # pre/up/byte/no-wb
```

## Requirements
- Python 3.8

## Quickstart

### Create virtualenv and Install deps

```bash
# Create virtualenv
$ python3.8 -m venv venv

# Activate virtualenv (Unix)
$ source venv/bin/activate
# Activate virtualenv (Windows)
$ .\venv\Scripts\activate

# Install deps
(venv) $ pip install -r requirements.txt
```

### Activate virtualenv and Execute

```bash
# venv 활성화 안돼있으면 활성화 (Unix)
$ source venv/bin/activate
(venv) $

(venv) $ python run.py
```

## Code formatting

```bash
(venv) $ python -m black run.py
```
