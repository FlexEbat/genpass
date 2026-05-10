#!/usr/bin/env python3
import os
import sys
import json
import math
import time
import string
import secrets
import argparse
import platform
import subprocess
import threading
import shutil

try:
    import pyperclip
    HAS_PYPERCLIP = True
except ImportError:
    HAS_PYPERCLIP = False

MIN_LENGTH = 8
MAX_LENGTH = 128
DEFAULT_LENGTH = 20

CHARS_LOWER = string.ascii_lowercase
CHARS_UPPER = string.ascii_uppercase
CHARS_DIGITS = string.digits
CHARS_SYMBOLS = string.punctuation
CHARS_SYMBOLS_SAFE = "!#%&()*+,-./:;=?@[]^{}~_"
AMBIGUOUS_CHARS = "l1IoO0"

EXIT_SUCCESS = 0
EXIT_ARG_ERROR = 1
EXIT_SYS_ERROR = 2
EXIT_TEST_FAIL = 3

COLOR_GREEN = '\033[92m'
COLOR_RED = '\033[91m'
COLOR_YELLOW = '\033[93m'
COLOR_RESET = '\033[0m'

NATO_ALPHABET = {
    'A': 'Alpha', 'B': 'Bravo', 'C': 'Charlie', 'D': 'Delta', 'E': 'Echo',
    'F': 'Foxtrot', 'G': 'Golf', 'H': 'Hotel', 'I': 'India', 'J': 'Juliet',
    'K': 'Kilo', 'L': 'Lima', 'M': 'Mike', 'N': 'November', 'O': 'Oscar',
    'P': 'Papa', 'Q': 'Quebec', 'R': 'Romeo', 'S': 'Sierra', 'T': 'Tango',
    'U': 'Uniform', 'V': 'Victor', 'W': 'Whiskey', 'X': 'X-ray', 'Y': 'Yankee',
    'Z': 'Zulu', '0': 'Zero', '1': 'One', '2': 'Two', '3': 'Three',
    '4': 'Four', '5': 'Five', '6': 'Six', '7': 'Seven', '8': 'Eight', '9': 'Nine'
}

PRESETS = {
    'web':      {'len': 16, 'u': True, 'l': True, 'd': True, 's': True, 'safe': True},
    'strong':   {'len': 32, 'u': True, 'l': True, 'd': True, 's': True, 'safe': False},
    'pin':      {'len': 8,  'u': False,'l': False,'d': True, 's': False,'safe': True},
    'wifi':     {'len': 24, 'u': False,'l': True, 'd': True, 's': False,'safe': True},
}

DEFAULT_CONFIG = {
    "len": 20,
    "count": 1,
    "preset": None,
    "upper": True,
    "lower": True,
    "digits": True,
    "symbols": True,
    "safe": False,
    "custom": "",
    "group": 0,
    "sep": "-",
    "quiet": False,
    "copy": False,
    "clear": 0,
    "clear_console": False,
    "no_ambiguous": False,
    "words": 0,
    "wordlist": "wordlist.txt",
    "mask": "",
    "exclude": "",
    "output": "",
    "phonetic": False,
    "interactive": False,
    "ru": False
}

ASCII_LOGO = r"""
  __ _  ___ _ __  _ __   __ _ ___ ___
 / _` |/ _ \ '_ \| '_ \ / _` / __/ __|
| (_| |  __/ | | | |_) | (_| \__ \__ \
 \__, |\___|_| |_| .__/ \__,_|___/___/
  __/ |          | |
 |___/           |_|
"""

L = {
    'en': {
        'rules': "Even the most complex password is useless without basic security rules:\n1. Enable 2FA (Two-Factor Authentication) wherever possible.\n2. Never use the same password for different services.\n3. Use reliable password managers (KeePass, Bitwarden, etc.).\n4. Beware of phishing and always check the URL in your browser.\n5. Do not send passwords in plain text via messengers.\n",
        'os_detect': "OS Detected: ",
        'press_any': "Press any key to continue...",
        'err_num_range': "Error: Number must be between {min_val} and {max_val}.",
        'err_int': "Error: Please enter an integer.",
        'err_yn': "Error: Please enter 'y' or 'n'.",
        'err_pool_filter': "After filtering, the --custom set has fewer than 2 unique characters.",
        'err_pool_empty': "No character category selected or pool is empty after exclusions.",
        'err_min_len': "Minimum password length: {MIN_LENGTH}.",
        'err_cat_len': "Length {length} is insufficient for {cats} required categories.",
        'err_dw_min': "A passphrase requires at least 2 words.",
        'err_wl_not_found': "Wordlist '{filepath}' not found.\n{COLOR_YELLOW}A text file with words is required for Diceware passphrases.{COLOR_RESET}\nYou can download a good wordlist here: https://weakpass.com/wordlists\nPlace the file next to the script named '{basename}' or specify the path via the --wordlist flag.",
        'err_wl_short': "The wordlist '{filepath}' has too few words (found {count}, need at least 2).",
        'err_mask_pool': "Pool for mask character '{ch}' is empty after filtering.",
        'err_xclip': "xclip/xsel utilities not found",
        'err_os_unsupported': "OS not supported",
        'test_start': "Starting selftest...",
        'test_fail_len': "FAIL: Incorrect length (standard)",
        'test_fail_dw': "FAIL: Incorrect word count (diceware)",
        'test_fail_mask': "FAIL: Mask error",
        'test_ok': "All systems nominal.",
        'int_title': "--- INTERACTIVE MODE ---",
        'int_opt1': "1. Generate standard password (customizable length, characters, rules)",
        'int_opt2': "2. Generate passphrase (Diceware - memorable words)",
        'int_opt3': "3. Generate by mask (strict format like Ulll-dddd-S)",
        'int_opt4': "4. Generate MAXIMUM SECURE PASSWORD (64 chars, all types, auto-clear, hidden)",
        'int_opt0': "0. Exit",
        'int_choice': "\nSelect an option: ",
        'int_len': "Password length",
        'int_up': "Uppercase (A-Z)?",
        'int_low': "Lowercase (a-z)?",
        'int_dig': "Digits (0-9)?",
        'int_sym': "Symbols (#$%)?",
        'err_no_cat': "Error: You must select at least one category!",
        'err_len_cat': "Error: Categories exceed password length.",
        'int_ambig': "Exclude ambiguous characters (l, 1, O, 0)?",
        'int_safe': "Use only safe symbols?",
        'int_words': "Number of words",
        'int_sep': "Word separator[Default: -]: ",
        'int_wl': "Path to wordlist file[Default: wordlist.txt]: ",
        'int_mask_fmt': "\nMask format: U=Uppercase, l=Lowercase, d=Digit, S=Symbol. Other chars inserted as is.",
        'int_mask_in': "Enter mask (e.g. Ulll-dddd-S): ",
        'int_max_sec': "Maximum Security settings applied.",
        'arg_desc': "FULL FEATURE LIST:\n  - Generation of standard passwords, passphrases (Diceware), and strict masks.\n  - Exclusion of visually similar characters (-A) and user-specified chars (--exclude).\n  - Clipboard copy with automatic background clear support.\n  - Timer-based console clearing to hide passwords from the screen.\n  - Support for custom wordlists from text files (--wordlist).\n  - Configuration file support (config.json) and file output.\n  - Phonetic alphabet display (Alpha, Bravo...) for dictation.",
        'arg_epi': "Usage examples:",
        'arg_interactive': "Launch in interactive mode with menu.",
        'arg_ru': "Translate output to Russian.",
        'arg_len': "Standard password length.",
        'arg_count': "Number of generated passwords.",
        'arg_preset': "Use predefined preset (web, strong, pin, wifi).",
        'arg_u': "Include uppercase letters (A-Z).",
        'arg_l': "Include lowercase letters (a-z).",
        'arg_d': "Include digits (0-9).",
        'arg_s': "Include symbols.",
        'arg_safe': "Use only safe symbols.",
        'arg_A': "Exclude ambiguous characters (l, 1, I, o, O, 0).",
        'arg_w': "Diceware mode: number of words in passphrase.",
        'arg_wordlist': "Path to wordlist file for Diceware mode (default: wordlist.txt).",
        'arg_mask': "Generate by mask (U=A-Z, l=a-z, d=0-9, S=Symbol).",
        'arg_exclude': "Exclude specified characters from the pool.",
        'arg_custom': "Use only the specified custom character set.",
        'arg_group': "Group characters by N.",
        'arg_sep': "Separator for groups or words.",
        'arg_q': "Quiet mode: only output password to stdout.",
        'arg_c': "Copy result to clipboard.",
        'arg_clear': "Timer in seconds for background clipboard clearing.",
        'arg_clear_console': "Clear terminal after timer expires (requires --clear).",
        'arg_o': "Save result to file.",
        'arg_phonetic': "Output password using phonetic alphabet.",
        'out_saved': "Saved to file: ",
        'err_file': "Error writing to file: ",
        'out_copied': "📋 Copied to clipboard.",
        'out_timer': "⏳ Background clipboard clear in {clear}s...",
        'out_bg': "You can continue working, clearing will happen in the background.",
        'err_clip': "Clipboard error: ",
        'err_main': "Error: ",
        'phonetic_lbl': "Phonetic",
        'entropy_lbl': "Entropy",
        'bits_lbl': "bits",
        'def_lbl': "[Default: {default}]"
    },
    'ru': {
        'rules': "Даже самый сложный пароль бесполезен без соблюдения базовых правил безопасности:\n1. Включайте 2FA (Двухфакторную аутентификацию) везде, где это возможно.\n2. Никогда не используйте один и тот же пароль для разных сервисов.\n3. Используйте надежные менеджеры паролей (KeePass, Bitwarden и др.).\n4. Остерегайтесь фишинга и всегда проверяйте URL адрес в браузере.\n5. Не отправляйте пароли в мессенджерах открытым текстом.\n",
        'os_detect': "Обнаружена ОС: ",
        'press_any': "Нажмите любую клавишу для продолжения...",
        'err_num_range': "Ошибка: Число должно быть от {min_val} до {max_val}.",
        'err_int': "Ошибка: Введите целое число.",
        'err_yn': "Ошибка: Введите 'y' или 'n'.",
        'err_pool_filter': "После фильтрации в наборе --custom осталось менее 2 уникальных символов.",
        'err_pool_empty': "Не выбрана ни одна категория символов или пул пуст после исключений.",
        'err_min_len': "Минимальная длина пароля: {MIN_LENGTH}.",
        'err_cat_len': "Длина {length} недостаточна для {cats} обязательных категорий.",
        'err_dw_min': "Для парольной фразы нужно минимум 2 слова.",
        'err_wl_not_found': "Словарь '{filepath}' не найден.\n{COLOR_YELLOW}Для генерации парольных фраз (Diceware) требуется текстовый файл со словами.{COLOR_RESET}\nВы можете скачать хороший словарь здесь: https://weakpass.com/wordlists\nПоместите файл рядом со скриптом под именем '{basename}' или укажите путь через флаг --wordlist.",
        'err_wl_short': "В словаре '{filepath}' слишком мало слов (найдено {count}, нужно минимум 2).",
        'err_mask_pool': "Пул для символа маски '{ch}' пуст после фильтрации.",
        'err_xclip': "Утилиты xclip/xsel не найдены",
        'err_os_unsupported': "ОС не поддерживается",
        'test_start': "Запуск самодиагностики...",
        'test_fail_len': "FAIL: Неверная длина (standard)",
        'test_fail_dw': "FAIL: Неверное количество слов (diceware)",
        'test_fail_mask': "FAIL: Ошибка маски",
        'test_ok': "Все системы в норме.",
        'int_title': "--- ИНТЕРАКТИВНЫЙ РЕЖИМ ---",
        'int_opt1': "1. Сгенерировать стандартный пароль (настройка длины, символов, правил)",
        'int_opt2': "2. Сгенерировать парольную фразу (Diceware - легко запомнить)",
        'int_opt3': "3. Сгенерировать по маске (строгий формат, напр. Ulll-dddd-S)",
        'int_opt4': "4. Сгенерировать МАКСИМАЛЬНО ЗАЩИЩЕННЫЙ пароль (64 символа, автоочистка, скрытно)",
        'int_opt0': "0. Выход",
        'int_choice': "\nВыберите опцию: ",
        'int_len': "Длина пароля",
        'int_up': "Заглавные (A-Z)?",
        'int_low': "Строчные (a-z)?",
        'int_dig': "Цифры (0-9)?",
        'int_sym': "Спецсимволы (#$%)?",
        'err_no_cat': "Ошибка: Нужно выбрать хотя бы одну категорию!",
        'err_len_cat': "Ошибка: Категорий больше чем длина пароля.",
        'int_ambig': "Исключить похожие символы (l, 1, O, 0)?",
        'int_safe': "Использовать только безопасные спецсимволы?",
        'int_words': "Количество слов",
        'int_sep': "Разделитель слов [Default: -]: ",
        'int_wl': "Путь к файлу-словарю [Default: wordlist.txt]: ",
        'int_mask_fmt': "\nФормат маски: U=Заглавная, l=Строчная, d=Цифра, S=Спецсимвол. Остальные символы вставляются как есть.",
        'int_mask_in': "Введите маску (напр. Ulll-dddd-S): ",
        'int_max_sec': "Настройки Максимальной Защиты применены.",
        'arg_desc': "ПОЛНЫЙ СПИСОК ВОЗМОЖНОСТЕЙ:\n  - Генерация стандартных паролей, парольных фраз (Diceware) и по строгим маскам.\n  - Исключение визуально похожих символов (-A) и пользовательских символов (--exclude).\n  - Копирование в буфер обмена с поддержкой автоматической фоновой очистки.\n  - Очистка консоли по таймеру для скрытия пароля с экрана.\n  - Поддержка кастомных словарей из текстовых файлов (--wordlist).\n  - Поддержка конфигурационного файла (config.json) и вывод результата в файл.\n  - Отображение фонетического алфавита (Alpha, Bravo...) для диктовки.",
        'arg_epi': "Примеры использования:",
        'arg_interactive': "Запуск в интерактивном режиме с меню.",
        'arg_ru': "Перевод вывода на русский язык.",
        'arg_len': "Длина стандартного пароля.",
        'arg_count': "Количество генерируемых паролей.",
        'arg_preset': "Использовать готовый пресет (web, strong, pin, wifi).",
        'arg_u': "Включить заглавные буквы (A-Z).",
        'arg_l': "Включить строчные буквы (a-z).",
        'arg_d': "Включить цифры (0-9).",
        'arg_s': "Включить спецсимволы.",
        'arg_safe': "Использовать только безопасные спецсимволы.",
        'arg_A': "Исключить похожие символы (l, 1, I, o, O, 0).",
        'arg_w': "Режим Diceware: количество слов в парольной фразе.",
        'arg_wordlist': "Путь к файлу словаря для режима Diceware (по умолчанию: wordlist.txt).",
        'arg_mask': "Генерация по маске (U=A-Z, l=a-z, d=0-9, S=Спецсимвол).",
        'arg_exclude': "Исключить указанные символы из пула.",
        'arg_custom': "Использовать только указанный кастомный набор символов.",
        'arg_group': "Группировать символы по N.",
        'arg_sep': "Разделитель для групп или слов.",
        'arg_q': "Тихий режим: только пароль в stdout.",
        'arg_c': "Скопировать результат в буфер обмена.",
        'arg_clear': "Таймер в секундах для фоновой очистки буфера.",
        'arg_clear_console': "Очистить терминал после истечения таймера (требует --clear).",
        'arg_o': "Сохранить результат в файл.",
        'arg_phonetic': "Вывести пароль с использованием фонетического алфавита.",
        'out_saved': "Сохранено в файл: ",
        'err_file': "Ошибка записи в файл: ",
        'out_copied': "📋 Скопировано в буфер обмена.",
        'out_timer': "⏳ Фоновая очистка буфера через {clear}с...",
        'out_bg': "Вы можете продолжать работу, очистка произойдет в фоне.",
        'err_clip': "Ошибка буфера: ",
        'err_main': "Ошибка: ",
        'phonetic_lbl': "Фонетика",
        'entropy_lbl': "Энтропия",
        'bits_lbl': "бит",
        'def_lbl': "[По умолчанию: {default}]"
    }
}

def get_lang():
    if '-ru' in sys.argv or '--ru' in sys.argv:
        return 'ru'
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
            if cfg.get('ru'): return 'ru'
    except:
        pass
    return 'en'

LANG = get_lang()
P = L[LANG]

def load_config():
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    if not os.path.exists(config_path):
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(DEFAULT_CONFIG, f, indent=4)
        except:
            pass
        return DEFAULT_CONFIG.copy()
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            user_cfg = json.load(f)
            merged = DEFAULT_CONFIG.copy()
            merged.update(user_cfg)
            return merged
    except:
        return DEFAULT_CONFIG.copy()

def load_wordlist(filepath):
    if not os.path.exists(filepath):
        raise FileNotFoundError(
            P['err_wl_not_found'].format(filepath=filepath, COLOR_YELLOW=COLOR_YELLOW, COLOR_RESET=COLOR_RESET, basename=os.path.basename(filepath))
        )
    with open(filepath, 'r', encoding='utf-8') as f:
        words =[line.strip() for line in f if line.strip()]
    if len(words) < 2:
        raise ValueError(P['err_wl_short'].format(filepath=filepath, count=len(words)))
    return words

def wait_key():
    if platform.system() == 'Windows':
        import msvcrt
        msvcrt.getch()
    else:
        import tty, termios
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

def startup_banner():
    print(f"{COLOR_YELLOW}{ASCII_LOGO}{COLOR_RESET}")
    print(P['rules'])
    print(f"{P['os_detect']}{COLOR_GREEN}{platform.system()}{COLOR_RESET}")
    print(P['press_any'])
    wait_key()
    print("\n")

def clear_console():
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def input_int(prompt, min_val, max_val, default):
    while True:
        dlbl = P['def_lbl'].format(default=default)
        raw = input(f"{prompt} ({min_val}-{max_val}) {dlbl}: ").strip()
        if not raw:
            return default
        try:
            val = int(raw)
            if min_val <= val <= max_val:
                return val
            print(P['err_num_range'].format(min_val=min_val, max_val=max_val))
        except ValueError:
            print(P['err_int'])

def input_bool(prompt, default=True):
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
        print(P['err_yn'])

def calculate_entropy(pool_size, length):
    if pool_size <= 0 or length <= 0: return 0
    return length * math.log2(pool_size)

def filter_pool(pool, exclude, no_ambiguous):
    res = pool
    if exclude:
        res = "".join(c for c in res if c not in exclude)
    if no_ambiguous:
        res = "".join(c for c in res if c not in AMBIGUOUS_CHARS)
    return res

def generate_password_standard(length, use_upper, use_lower, use_digits, use_symbols, use_safe, custom_chars, exclude, no_ambiguous):
    pools =[]
    full_pool = ""
    if custom_chars:
        f = filter_pool(custom_chars, exclude, no_ambiguous)
        if len(set(f)) < 2:
            raise ValueError(P['err_pool_filter'])
        pools.append(f)
        full_pool = f
    else:
        if use_lower:
            f = filter_pool(CHARS_LOWER, exclude, no_ambiguous)
            if f: pools.append(f); full_pool += f
        if use_upper:
            f = filter_pool(CHARS_UPPER, exclude, no_ambiguous)
            if f: pools.append(f); full_pool += f
        if use_digits:
            f = filter_pool(CHARS_DIGITS, exclude, no_ambiguous)
            if f: pools.append(f); full_pool += f
        if use_symbols:
            syms = CHARS_SYMBOLS_SAFE if use_safe else CHARS_SYMBOLS
            f = filter_pool(syms, exclude, no_ambiguous)
            if f: pools.append(f); full_pool += f
    if not full_pool:
        raise ValueError(P['err_pool_empty'])
    if length < MIN_LENGTH:
        raise ValueError(P['err_min_len'].format(MIN_LENGTH=MIN_LENGTH))
    if length < len(pools):
        raise ValueError(P['err_cat_len'].format(length=length, cats=len(pools)))

    password_chars =[]
    for pool in pools:
        password_chars.append(secrets.choice(pool))
    for _ in range(length - len(password_chars)):
        password_chars.append(secrets.choice(full_pool))
    secrets.SystemRandom().shuffle(password_chars)

    return ''.join(password_chars), calculate_entropy(len(full_pool), length)

def generate_passphrase(word_count, sep, wordlist_path):
    if word_count < 2:
        raise ValueError(P['err_dw_min'])
    words = load_wordlist(wordlist_path)
    chosen =[secrets.choice(words) for _ in range(word_count)]
    bits = word_count * math.log2(len(words))
    return sep.join(chosen), bits

def generate_mask(mask, use_safe, exclude, no_ambiguous):
    res =[]
    bits = 0
    for ch in mask:
        pool = ""
        if ch == 'U': pool = filter_pool(CHARS_UPPER, exclude, no_ambiguous)
        elif ch == 'l': pool = filter_pool(CHARS_LOWER, exclude, no_ambiguous)
        elif ch == 'd': pool = filter_pool(CHARS_DIGITS, exclude, no_ambiguous)
        elif ch == 'S': pool = filter_pool(CHARS_SYMBOLS_SAFE if use_safe else CHARS_SYMBOLS, exclude, no_ambiguous)
        else:
            res.append(ch)
            continue
        if not pool:
            raise ValueError(P['err_mask_pool'].format(ch=ch))
        res.append(secrets.choice(pool))
        bits += math.log2(len(pool))
    return "".join(res), bits

def format_output(password, group_size, separator):
    if group_size and group_size > 0:
        parts = [password[i:i+group_size] for i in range(0, len(password), group_size)]
        return separator.join(parts)
    return password

def copy_to_clipboard(text):
    if HAS_PYPERCLIP:
        try:
            pyperclip.copy(text)
            return True, "OK (pyperclip)"
        except Exception:
            pass
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
                return False, P['err_xclip']
        else:
            return False, P['err_os_unsupported']
        return True, "OK (subprocess)"
    except Exception as e:
        return False, str(e)

def background_cleaner(seconds, clear_c):
    time.sleep(seconds)
    copy_to_clipboard(" ")
    if clear_c:
        clear_console()

def get_phonetic_string(password):
    res =[]
    for c in password:
        if c.upper() in NATO_ALPHABET:
            res.append(NATO_ALPHABET[c.upper()])
        else:
            res.append(c)
    return " ".join(res)

def run_selftest():
    print(P['test_start'])
    errors =[]
    test_wordlist = "__test_wordlist.txt"
    try:
        p, _ = generate_password_standard(20, True, True, True, True, False, None, "", False)
        if len(p) != 20: errors.append(P['test_fail_len'])

        with open(test_wordlist, 'w', encoding='utf-8') as f:
            f.write("testword1\ntestword2\ntestword3\n")

        pw, _ = generate_passphrase(4, "-", test_wordlist)
        if len(pw.split("-")) != 4: errors.append(P['test_fail_dw'])

        pm, _ = generate_mask("UldS", False, "", False)
        if len(pm) != 4: errors.append(P['test_fail_mask'])
    except Exception as e:
        errors.append(f"FAIL: {e}")
    finally:
        if os.path.exists(test_wordlist):
            os.remove(test_wordlist)

    if errors:
        print("\n".join(errors))
        sys.exit(EXIT_TEST_FAIL)
    print(P['test_ok'])
    sys.exit(EXIT_SUCCESS)

def interactive_mode():
    cfg = DEFAULT_CONFIG.copy()
    while True:
        clear_console()
        print(f"{COLOR_YELLOW}{ASCII_LOGO}{COLOR_RESET}")
        print(P['int_title'])
        print(P['int_opt1'])
        print(P['int_opt2'])
        print(P['int_opt3'])
        print(P['int_opt4'])
        print(P['int_opt0'])
        choice = input(P['int_choice']).strip()

        if choice == '0':
            sys.exit(EXIT_SUCCESS)

        elif choice == '1':
            cfg['len'] = input_int(P['int_len'], MIN_LENGTH, MAX_LENGTH, DEFAULT_LENGTH)
            while True:
                cfg['upper'] = input_bool(P['int_up'])
                cfg['lower'] = input_bool(P['int_low'])
                cfg['digits'] = input_bool(P['int_dig'])
                cfg['symbols'] = input_bool(P['int_sym'])
                if not any([cfg['upper'], cfg['lower'], cfg['digits'], cfg['symbols']]):
                    print(f"{COLOR_RED}{P['err_no_cat']}{COLOR_RESET}")
                    continue
                cats = sum([cfg['upper'], cfg['lower'], cfg['digits'], cfg['symbols']])
                if cfg['len'] < cats:
                    print(f"{COLOR_RED}{P['err_len_cat']}{COLOR_RESET}")
                    continue
                break
            cfg['no_ambiguous'] = input_bool(P['int_ambig'], default=True)
            if cfg['symbols']:
                cfg['safe'] = input_bool(P['int_safe'], default=True)
            return cfg

        elif choice == '2':
            cfg['words'] = input_int(P['int_words'], 2, 20, 4)
            cfg['sep'] = input(P['int_sep']).strip()
            if not cfg['sep']: cfg['sep'] = "-"

            wl_path = input(P['int_wl']).strip()
            if wl_path:
                cfg['wordlist'] = wl_path

            return cfg

        elif choice == '3':
            print(P['int_mask_fmt'])
            cfg['mask'] = input(P['int_mask_in']).strip()
            if not cfg['mask']: cfg['mask'] = "Ulll-dddd-S"
            cfg['no_ambiguous'] = input_bool(P['int_ambig'], default=True)
            return cfg

        elif choice == '4':
            cfg['len'] = 64
            cfg['upper'] = True
            cfg['lower'] = True
            cfg['digits'] = True
            cfg['symbols'] = True
            cfg['safe'] = False
            cfg['no_ambiguous'] = True
            cfg['clear'] = 10
            cfg['copy'] = True
            cfg['clear_console'] = True
            print(f"{COLOR_GREEN}{P['int_max_sec']}{COLOR_RESET}")
            time.sleep(1)
            return cfg

def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description=f"{COLOR_YELLOW}{ASCII_LOGO}{COLOR_RESET}\n{P['arg_desc']}",
        epilog=f"{P['arg_epi']}\n"
               "  genpass --len 24 -ulds -A -c\n"
               "  genpass -w 5 --sep - --wordlist eff_large_wordlist.txt\n"
               "  genpass --mask Ulll-dddd-S -c --clear 10\n"
               "  genpass -i"
    )
    parser.add_argument('-i', '--interactive', action='store_true', help=P['arg_interactive'])
    parser.add_argument('-ru', '--ru', action='store_true', help=P['arg_ru'])
    parser.add_argument('--len', type=int, help=P['arg_len'])
    parser.add_argument('--count', type=int, help=P['arg_count'])
    parser.add_argument('--preset', choices=PRESETS.keys(), help=P['arg_preset'])
    parser.add_argument('-u', '--upper', action='store_true', help=P['arg_u'])
    parser.add_argument('-l', '--lower', action='store_true', help=P['arg_l'])
    parser.add_argument('-d', '--digits', action='store_true', help=P['arg_d'])
    parser.add_argument('-s', '--symbols', action='store_true', help=P['arg_s'])
    parser.add_argument('--safe', action='store_true', help=P['arg_safe'])
    parser.add_argument('-A', '--no-ambiguous', action='store_true', help=P['arg_A'])
    parser.add_argument('-w', '--words', type=int, help=P['arg_w'])
    parser.add_argument('--wordlist', type=str, help=P['arg_wordlist'])
    parser.add_argument('--mask', type=str, help=P['arg_mask'])
    parser.add_argument('--exclude', type=str, help=P['arg_exclude'])
    parser.add_argument('--custom', type=str, help=P['arg_custom'])
    parser.add_argument('--group', type=int, help=P['arg_group'])
    parser.add_argument('--sep', type=str, help=P['arg_sep'])
    parser.add_argument('-q', '--quiet', action='store_true', help=P['arg_q'])
    parser.add_argument('-c', '--copy', action='store_true', help=P['arg_c'])
    parser.add_argument('--clear', type=int, help=P['arg_clear'])
    parser.add_argument('--clear-console', action='store_true', help=P['arg_clear_console'])
    parser.add_argument('-o', '--output', type=str, help=P['arg_o'])
    parser.add_argument('--phonetic', action='store_true', help=P['arg_phonetic'])
    parser.add_argument('--selftest', action='store_true', help=argparse.SUPPRESS)

    args = parser.parse_args()

    if len(sys.argv) == 1 or (len(sys.argv) == 2 and args.ru):
        args.interactive = True

    if args.selftest:
        run_selftest()

    config = load_config()

    if args.interactive:
        startup_banner()
        cli_cfg = interactive_mode()
        config.update(cli_cfg)
    else:
        for k, v in vars(args).items():
            if v is not None and v is not False:
                config[k] = v

    if config.get('preset'):
        p = PRESETS[config['preset']]
        if not args.len: config['len'] = p['len']
        config['upper'], config['lower'], config['digits'], config['symbols'] = p['u'], p['l'], p['d'], p['s']
        if not args.safe: config['safe'] = p['safe']

    if not config['preset'] and not config['words'] and not config['mask'] and not config['custom']:
        if not any([config['upper'], config['lower'], config['digits'], config['symbols']]):
            config['upper'] = config['lower'] = config['digits'] = config['symbols'] = True

    passwords =[]
    try:
        for _ in range(config['count']):
            if config['words'] and config['words'] > 0:
                raw, bits = generate_passphrase(config['words'], config['sep'], config['wordlist'])
            elif config['mask']:
                raw, bits = generate_mask(config['mask'], config['safe'], config['exclude'], config['no_ambiguous'])
            else:
                raw, bits = generate_password_standard(
                    config['len'], config['upper'], config['lower'], config['digits'], config['symbols'],
                    config['safe'], config['custom'], config['exclude'], config['no_ambiguous']
                )

            if not config['words'] and not config['mask']:
                fmt = format_output(raw, config['group'], config['sep'])
            else:
                fmt = raw
            passwords.append((fmt, bits))

        out_buf =[]
        if not config['quiet']: print("-" * 50)

        for i, (pwd, bits) in enumerate(passwords):
            out_buf.append(pwd)
            if config['quiet']:
                print(pwd)
            else:
                if bits >= 80:
                    q = f"{COLOR_GREEN}🔒 STRONG{COLOR_RESET}"
                elif bits >= 60:
                    q = f"{COLOR_YELLOW}✅ OK{COLOR_RESET}"
                else:
                    q = f"{COLOR_RED}⚠️ WEAK{COLOR_RESET}"
                pfx = f"[{i+1}] " if config['count'] > 1 else ""
                print(f"{pfx}{pwd}\n    └── {P['entropy_lbl']}: {int(bits)} {P['bits_lbl']} | {q}")
                if config['phonetic']:
                    print(f"    └── {P['phonetic_lbl']}: {get_phonetic_string(pwd)}")

        if not config['quiet']: print("-" * 50)

        if config['output']:
            try:
                with open(config['output'], 'w', encoding='utf-8') as f:
                    f.write("\n".join(out_buf) + "\n")
                if not config['quiet']: print(f"{P['out_saved']}{config['output']}")
            except Exception as e:
                if not config['quiet']: print(f"{COLOR_RED}{P['err_file']}{e}{COLOR_RESET}")

        if config['copy'] and out_buf:
            txt = out_buf[-1] if len(out_buf) == 1 else "\n".join(out_buf)
            ok, msg = copy_to_clipboard(txt)
            if ok:
                if not config['quiet']: print(P['out_copied'])
                if config['clear'] > 0:
                    if not config['quiet']:
                        print(P['out_timer'].format(clear=config['clear']))
                    threading.Thread(target=background_cleaner, args=(config['clear'], config['clear_console']), daemon=True).start()
                    if not config['quiet'] and not config['clear_console']:
                        print(P['out_bg'])
            else:
                if not config['quiet']: print(f"{COLOR_RED}{P['err_clip']}{msg}{COLOR_RESET}")
                sys.exit(EXIT_SYS_ERROR)

        if config['clear'] > 0 and config['copy']:
            if config['clear_console']:
                time.sleep(config['clear'])

    except FileNotFoundError as fnf:
        if not config.get('quiet'): print(f"{COLOR_RED}{fnf}{COLOR_RESET}")
        sys.exit(EXIT_ARG_ERROR)
    except ValueError as ve:
        if not config.get('quiet'): print(f"{COLOR_RED}{P['err_main']}{ve}{COLOR_RESET}")
        sys.exit(EXIT_ARG_ERROR)
    except KeyboardInterrupt:
        sys.exit(EXIT_SUCCESS)

if __name__ == "__main__":
    main()
