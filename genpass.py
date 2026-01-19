#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
genpass.py - Professional Offline Password Generator
"""

import secrets
import string
import argparse
import sys
import math
import time
import subprocess
import platform
import shutil
from textwrap import dedent

# ==========================================
# КОНФИГУРАЦИЯ
# ==========================================

MIN_LENGTH = 8
MAX_LENGTH = 128
DEFAULT_LENGTH = 20

CHARS_LOWER = string.ascii_lowercase
CHARS_UPPER = string.ascii_uppercase
CHARS_DIGITS = string.digits
CHARS_SYMBOLS = string.punctuation
CHARS_SYMBOLS_SAFE = "!#%&()*+,-./:;=?@[]^{}~_"

EXIT_SUCCESS = 0
EXIT_ARG_ERROR = 1
EXIT_SYS_ERROR = 2
EXIT_TEST_FAIL = 3

PRESETS = {
    'web':      {'len': 16, 'u': True, 'l': True, 'd': True, 's': True, 'safe': True},
    'strong':   {'len': 32, 'u': True, 'l': True, 'd': True, 's': True, 'safe': False},
    'pin':      {'len': 8,  'u': False,'l': False,'d': True, 's': False,'safe': True},
    'wifi':     {'len': 24, 'u': False,'l': True, 'd': True, 's': False,'safe': True},
}

# ==========================================
# ВВОД С ПРОВЕРКАМИ (STRICT INPUT)
# ==========================================

def input_int(prompt, min_val, max_val, default):
    """Жёсткая проверка числа с диапазоном."""
    while True:
        raw = input(f"{prompt} ({min_val}-{max_val}) [Default: {default}]: ").strip()
        if not raw:
            return default
        try:
            val = int(raw)
            if min_val <= val <= max_val:
                return val
            print(f"❌ Ошибка: Число должно быть от {min_val} до {max_val}. Попробуйте снова.")
        except ValueError:
            print("❌ Ошибка: Введите целое число.")

def input_bool(prompt, default=True):
    """Жёсткая проверка y/n."""
    hint = "[Y/n]" if default else "[y/N]"
    valid_y = {'y', 'yes', 'д', 'да', '1'}
    valid_n = {'n', 'no', 'н', 'нет', '0'}
    
    while True:
        raw = input(f"{prompt} {hint}: ").strip().lower()
        if not raw:
            return default
        if raw in valid_y:
            return True
        if raw in valid_n:
            return False
        print("❌ Ошибка: Введите 'y' или 'n'.")

# ==========================================
# ЛОГИКА
# ==========================================

def calculate_entropy(pool_size, length):
    if pool_size == 0 or length == 0: return 0
    return length * math.log2(pool_size)

def generate_password(length, use_upper, use_lower, use_digits, use_symbols, use_safe, custom_chars=None):
    pools = []
    full_pool = ""

    if custom_chars:
        if len(set(custom_chars)) < 2:
            raise ValueError("В наборе --custom должно быть минимум 2 РАЗНЫХ символа.")
        pools.append(custom_chars)
        full_pool = custom_chars
    else:
        if use_lower:
            pools.append(CHARS_LOWER)
            full_pool += CHARS_LOWER
        if use_upper:
            pools.append(CHARS_UPPER)
            full_pool += CHARS_UPPER
        if use_digits:
            pools.append(CHARS_DIGITS)
            full_pool += CHARS_DIGITS
        if use_symbols:
            syms = CHARS_SYMBOLS_SAFE if use_safe else CHARS_SYMBOLS
            pools.append(syms)
            full_pool += syms

    if not full_pool:
        raise ValueError("Не выбрана ни одна категория символов.")
    if length < MIN_LENGTH:
        raise ValueError(f"Минимальная длина пароля: {MIN_LENGTH}.")
    if length < len(pools):
        raise ValueError(f"Длина {length} недостаточна для {len(pools)} обязательных категорий.")

    password_chars = []
    try:
        for pool in pools:
            password_chars.append(secrets.choice(pool))
        for _ in range(length - len(password_chars)):
            password_chars.append(secrets.choice(full_pool))
        
        secrets.SystemRandom().shuffle(password_chars)
        return ''.join(password_chars), calculate_entropy(len(full_pool), length)
    except Exception as e:
        raise RuntimeError(f"Internal Error: {e}")

def format_output(password, group_size, separator):
    if group_size and group_size > 0:
        parts = [password[i:i+group_size] for i in range(0, len(password), group_size)]
        return separator.join(parts)
    return password

def copy_to_clipboard(text):
    system = platform.system()
    try:
        if system == 'Darwin':
            subprocess.run("pbcopy", universal_newlines=True, input=text, check=True)
        elif system == 'Windows':
            subprocess.run("clip", universal_newlines=True, input=text, check=True)
        elif system == 'Linux':
            if shutil.which("xclip"):
                subprocess.run(["xclip", "-selection", "clipboard"], universal_newlines=True, input=text, check=True)
            elif shutil.which("xsel"):
                subprocess.run(["xsel", "--clipboard", "--input"], universal_newlines=True, input=text, check=True)
            else:
                return False, "Утилиты xclip/xsel не найдены"
        else:
            return False, "ОС не поддерживается"
        return True, "OK"
    except Exception as e:
        return False, str(e)

def clear_clipboard_timer(seconds):
    try:
        time.sleep(seconds)
        copy_to_clipboard(" ") 
        return True
    except KeyboardInterrupt:
        return False

# ==========================================
# UI
# ==========================================

def run_selftest():
    print("🧪 Запуск самодиагностики...")
    errors = []
    try:
        p, _ = generate_password(20, True, True, True, True, False)
        if len(p) != 20: errors.append("FAIL: Неверная длина")
    except Exception as e: errors.append(f"FAIL: {e}")

    if errors:
        print("\n".join(errors))
        sys.exit(EXIT_TEST_FAIL)
    print("✅ Все системы в норме.")
    sys.exit(EXIT_SUCCESS)

def interactive_mode():
    print("\n🔒 --- Интерактивный режим ---")
    
    # 1. Длина с жесткой проверкой
    length = input_int("Длина пароля", MIN_LENGTH, MAX_LENGTH, DEFAULT_LENGTH)
    
    print("\nНастройки состава (y=Да, n=Нет):")
    
    # 2. Категории с циклом проверки, пока пользователь не выберет хотя бы одну
    while True:
        u = input_bool(" Заглавные (A-Z)")
        l = input_bool(" Строчные (a-z)")
        d = input_bool(" Цифры (0-9)")
        s = input_bool(" Спецсимволы (#$%)")
        
        if not any([u, l, d, s]):
            print("\n❌ Ошибка: Нужно выбрать хотя бы одну категорию! Повторите ввод.\n")
            continue
        
        # Проверка совместимости длины и категорий
        categories_count = sum([u, l, d, s])
        if length < categories_count:
            print(f"\n❌ Ошибка: Вы выбрали {categories_count} категорий, а длина всего {length}.")
            print("Уменьшите число категорий или перезапустите с большей длиной.\n")
            continue
            
        break
    
    safe = False
    if s:
        safe = input_bool(" Только безопасные символы (без кавычек)?", default=False)
            
    return {
        'len': length, 'u': u, 'l': l, 'd': d, 's': s, 'safe': safe, 
        'custom': None, 'count': 1, 'quiet': False, 'copy': False, 
        'clear': 0, 'group': 0, 'sep': '-'
    }

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--len', type=int)
    parser.add_argument('--count', type=int, default=1)
    parser.add_argument('--preset', choices=PRESETS.keys())
    parser.add_argument('--upper', action='store_true')
    parser.add_argument('--lower', action='store_true')
    parser.add_argument('--digits', action='store_true')
    parser.add_argument('--symbols', action='store_true')
    parser.add_argument('--safe', action='store_true')
    parser.add_argument('--custom', type=str)
    parser.add_argument('--group', type=int, default=0)
    parser.add_argument('--sep', type=str, default='-')
    parser.add_argument('--quiet', '-q', action='store_true')
    parser.add_argument('--copy', '-c', action='store_true')
    parser.add_argument('--clear', type=int, default=0)
    parser.add_argument('--selftest', action='store_true')

    if len(sys.argv) == 1:
        cfg = interactive_mode()
    else:
        args = parser.parse_args()
        if args.selftest: run_selftest()

        if args.preset:
            p = PRESETS[args.preset]
            length = args.len if args.len else p['len']
            u, l, d, s = p['u'], p['l'], p['d'], p['s']
            safe = args.safe if args.safe else p['safe']
        else:
            length = args.len if args.len else DEFAULT_LENGTH
            u, l, d, s = args.upper, args.lower, args.digits, args.symbols
            safe = args.safe
            if not any([u, l, d, s, args.custom]):
                u = l = d = s = True

        cfg = {
            'len': length, 'u': u, 'l': l, 'd': d, 's': s, 'safe': safe,
            'custom': args.custom, 'count': args.count,
            'quiet': args.quiet, 'copy': args.copy, 'clear': args.clear,
            'group': args.group, 'sep': args.sep
        }

    passwords = []
    try:
        for _ in range(cfg['count']):
            raw, bits = generate_password(
                cfg['len'], cfg['u'], cfg['l'], cfg['d'], cfg['s'], cfg['safe'], cfg['custom']
            )
            passwords.append((format_output(raw, cfg['group'], cfg['sep']), bits))

        if not cfg['quiet']: print("-" * 50)
        
        out_buf = []
        for i, (pwd, bits) in enumerate(passwords):
            out_buf.append(pwd)
            if cfg['quiet']:
                print(pwd)
            else:
                q = "🔒 STRONG" if bits >= 80 else ("✅ OK" if bits >= 60 else "⚠️ WEAK")
                pfx = f"[{i+1}] " if cfg['count'] > 1 else ""
                print(f"{pfx}{pwd}\n    └── Entropy: {int(bits)} bits | {q}")

        if not cfg['quiet']: print("-" * 50)

        if cfg['copy'] and out_buf:
            txt = out_buf[-1] if len(out_buf) == 1 else "\n".join(out_buf)
            ok, msg = copy_to_clipboard(txt)
            if ok:
                if not cfg['quiet']: print("📋 Скопировано.")
                if cfg['clear'] > 0:
                    if not cfg['quiet']: 
                        sys.stdout.write(f"⏳ Очистка через {cfg['clear']}с... ")
                        sys.stdout.flush()
                    clear_clipboard_timer(cfg['clear'])
                    if not cfg['quiet']: print("Буфер очищен.")
            else:
                if not cfg['quiet']: print(f"❌ Ошибка буфера: {msg}")
                sys.exit(EXIT_SYS_ERROR)

    except ValueError as ve:
        if not cfg.get('quiet'): print(f"❌ Ошибка: {ve}")
        sys.exit(EXIT_ARG_ERROR)
    except KeyboardInterrupt:
        sys.exit(EXIT_SUCCESS)

if __name__ == "__main__":
    main()
