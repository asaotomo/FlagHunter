#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import time
import mmap
import yaml
import base64
import binascii
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

CONFIG_FILE = 'config.yml'
LOG_FILE = 'found_flags.log'

DEFAULT_CONFIG = {
    'flag_rules': [{'prefix': 'flag'}, {'prefix': 'ctf'}, {'prefix': 'CTF'}, {'prefix': 'FLAG'}],
    'scan_cooldown': 10,
    'max_file_size_mb': 100,
    'context_bytes': 40
}

class Colors:
    GREEN = '\033[92m'
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

IS_WIN = sys.platform.startswith('win')

def banner():
    print(f"""{Colors.GREEN}{Colors.BOLD}
==================================================
   ███████╗██╗      █████╗  ██████╗      ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
   ██╔════╝██║     ██╔══██╗██╔════╝      ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
   █████╗  ██║     ███████║██║  ███╗     ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
   ██╔══╝  ██║     ██╔══██║██║   ██║     ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
   ██║     ███████╗██║  ██║╚██████╔╝     ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
   ╚═╝     ╚══════╝╚═╝  ╚═╝ ╚═════╝      ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
==================================================
{Colors.CYAN}{Colors.BOLD}                   Coded By {Colors.ENDC}{Colors.CYAN}Hx0战队{Colors.ENDC}
""")

def get_time():
    return datetime.now().strftime("%H:%M:%S")

def log_info(msg):
    color = Colors.CYAN if not IS_WIN else ""
    print(f"{color}[{get_time()}] [INFO] {msg}{Colors.ENDC}")

def log_warn(msg):
    color = Colors.YELLOW if not IS_WIN else ""
    print(f"{color}[{get_time()}] [WARN] {msg}{Colors.ENDC}")

def log_error(msg):
    color = Colors.RED if not IS_WIN else ""
    print(f"{color}[{get_time()}] [ERROR] {msg}{Colors.ENDC}")

def log_flag_to_file(text):
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(text + "\n\n")
    except Exception as e:
        log_warn(f"无法写入日志文件: {e}")

def load_or_create_config():
    path = os.path.abspath(CONFIG_FILE)
    if not os.path.exists(path):
        with open(path, 'w', encoding='utf-8') as f:
            yaml.dump(DEFAULT_CONFIG, f, allow_unicode=True)
        log_info(f"未找到配置文件，已创建默认 {CONFIG_FILE}")
        return DEFAULT_CONFIG
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        if not data:
            raise ValueError("配置为空")
        return {**DEFAULT_CONFIG, **data}
    except Exception as e:
        log_warn(f"加载配置失败，使用默认配置: {e}")
        return DEFAULT_CONFIG

def build_regex_from_rules(rules):
    patterns = []
    for rule in rules:
        prefix = rule.get('prefix', '')
        if not prefix:
            continue
        try:
            # 明文格式 - 更宽松的匹配，允许任何字符直到闭合大括号
            patterns.append((f"Plaintext ({prefix})", re.compile(prefix.encode() + b'\\{[\\s\\S]*?\\}', re.DOTALL)))
            # Base64 格式
            b64 = base64.b64encode((prefix + "{").encode()).rstrip(b'=')
            patterns.append((f"Base64 ({prefix})", re.compile(re.escape(b64) + b'[A-Za-z0-9+/=]{10,}')))
            # Hex 格式
            hex_prefix = binascii.hexlify((prefix + "{").encode())
            patterns.append((f"Hex ({prefix})", re.compile(re.escape(hex_prefix) + b'[0-9a-fA-F]{10,}')))
            # 直接匹配前缀，用于二进制文件
            patterns.append((f"Raw ({prefix})", re.compile(prefix.encode() + b'.{10,}')))
        except Exception as e:
            log_warn(f"规则错误: {e}")
    return patterns

flag_counter = 0
scanned_files = {}

def _report_flag(buffer, file_path, context_bytes, rules):
    global flag_counter
    for name, regex in rules:
        for match in regex.finditer(buffer):
            flag_counter += 1
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            found = match.group(0)
            try:
                flag_text = found.decode('utf-8')
            except:
                flag_text = repr(found)

            offset = match.start()
            line_num = 1 + buffer[:offset].count(b'\n')

            ctx_start = max(0, offset - context_bytes)
            ctx_end = min(len(buffer), match.end() + context_bytes)
            ctx = buffer[ctx_start:ctx_end].decode('utf-8', errors='replace')

            decoded = None
            if name.startswith("Base64"):
                try:
                    d = found
                    pad = len(d) % 4
                    if pad:
                        d += b'=' * (4 - pad)
                    decoded = base64.b64decode(d).decode('utf-8', errors='replace')
                except:
                    pass
            elif name.startswith("Hex"):
                try:
                    d = found
                    if len(d) % 2:
                        d = d[:-1]
                    decoded = binascii.unhexlify(d).decode('utf-8', errors='replace')
                except:
                    pass

            border = f"{Colors.GREEN}{'=' * 60}{Colors.ENDC}"
            print(f"\n{border}")
            print(f"{Colors.BOLD}{Colors.GREEN}[ FLAG FOUND #{flag_counter} ]{Colors.ENDC}")
            print(f"{Colors.CYAN}时间:{Colors.ENDC} {timestamp}")
            print(f"{Colors.CYAN}文件:{Colors.ENDC} {file_path}")
            print(f"{Colors.CYAN}类型:{Colors.ENDC} {name}")
            print(f"{Colors.CYAN}行号:{Colors.ENDC} {line_num}")
            print(f"{Colors.CYAN}偏移:{Colors.ENDC} {offset}")
            print(f"{Colors.CYAN}Flag:{Colors.ENDC} {Colors.RED}{flag_text}{Colors.ENDC}")
            if decoded:
                print(f"{Colors.CYAN}解码:{Colors.ENDC} {Colors.RED}{decoded}{Colors.ENDC}")
            print(f"{Colors.CYAN}上下文:{Colors.ENDC}")
            print(f"{Colors.YELLOW}{ctx}{Colors.ENDC}")
            print(border)

            log_text = (
                "=" * 40 + "\n"
                f"Flag #{flag_counter}\n"
                f"Time: {timestamp}\n"
                f"File: {file_path}\n"
                f"Type: {name}\n"
                f"Line: {line_num}\n"
                f"Offset: {offset}\n"
                f"Flag: {flag_text}\n"
                + (f"Decoded: {decoded}\n" if decoded else "")
                + f"Context:\n{ctx}\n" + "=" * 40
            )
            log_flag_to_file(log_text)

def scan_file(path, ignore, rules, max_size, ctx_bytes):
    try:
        abs_path = os.path.abspath(path)
        if abs_path in ignore or not os.path.isfile(abs_path):
            return
        size = os.path.getsize(abs_path)
        if size == 0 or size > max_size:
            return
        scanned_files[abs_path] = time.time()
        with open(abs_path, 'rb') as f:
            try:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    _report_flag(mm, path, ctx_bytes, rules)
            except:
                _report_flag(f.read(), path, ctx_bytes, rules)
    except Exception:
        pass

def initial_scan(dir_path, ignore, rules, max_size, ctx_bytes):
    log_info(f"开始初始扫描: {dir_path}")
    for root, _, files in os.walk(dir_path):
        for name in files:
            scan_file(os.path.join(root, name), ignore, rules, max_size, ctx_bytes)
    log_info("初始扫描完成")

def process_event(path, ignore, rules, max_size, ctx_bytes, cooldown):
    now = time.time()
    abs_path = os.path.abspath(path)
    if abs_path in ignore or not os.path.exists(abs_path):
        return
    if os.path.isfile(abs_path):
        last = scanned_files.get(abs_path, 0)
        if now - last > cooldown:
            scan_file(abs_path, ignore, rules, max_size, ctx_bytes)
    else:
        for root, _, files in os.walk(abs_path):
            for name in files:
                file_path = os.path.join(root, name)
                last = scanned_files.get(file_path, 0)
                if now - last > cooldown:
                    scan_file(file_path, ignore, rules, max_size, ctx_bytes)

class WatchHandler(FileSystemEventHandler):
    def __init__(self, ignore, rules, max_size, ctx_bytes, cooldown):
        super().__init__()
        self.ignore = ignore
        self.rules = rules
        self.max_size = max_size
        self.ctx_bytes = ctx_bytes
        self.cooldown = cooldown

    def on_created(self, event):
        log_info(f"检测到创建: {event.src_path}")
        process_event(event.src_path, self.ignore, self.rules, self.max_size, self.ctx_bytes, self.cooldown)

    def on_modified(self, event):
        if not event.is_directory:
            log_info(f"检测到修改: {event.src_path}")
            process_event(event.src_path, self.ignore, self.rules, self.max_size, self.ctx_bytes, self.cooldown)

    def on_moved(self, event):
        log_info(f"检测到移动: {event.dest_path}")
        process_event(event.dest_path, self.ignore, self.rules, self.max_size, self.ctx_bytes, self.cooldown)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"用法: python {sys.argv[0]} <目录>")
        sys.exit(1)

    if IS_WIN:
        os.system("color")

    os.system("clear" if not IS_WIN else "cls")
    banner()

    watch_dir = sys.argv[1]
    if not os.path.isdir(watch_dir):
        log_error("提供的路径无效。")
        sys.exit(1)

    log_info("CTF Flag 搜寻器启动中...")

    config = load_or_create_config()
    rules = build_regex_from_rules(config['flag_rules'])
    cooldown = config['scan_cooldown']
    ctx_bytes = config['context_bytes']
    max_size = config['max_file_size_mb'] * 1024 * 1024

    ignore = {
        os.path.abspath(CONFIG_FILE),
        os.path.abspath(LOG_FILE),
        os.path.abspath(sys.argv[0])
    }

    log_info(f"忽略文件数: {len(ignore)}")
    initial_scan(watch_dir, ignore, rules, max_size, ctx_bytes)

    log_info(f"实时监控中: {watch_dir}")
    log_info(f"按 Ctrl+C 退出。")

    handler = WatchHandler(ignore, rules, max_size, ctx_bytes, cooldown)
    observer = Observer()
    observer.schedule(handler, watch_dir, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print()
        log_info("监控器已停止。")
    observer.join()
