# SeevvoDownloader
# Copyright (C) [2026] [HelloGaoo,WHYOS]
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
import ctypes
import glob
import hashlib
import logging
import math
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
import tkinter.messagebox as messagebox
from concurrent import futures as concurrent_futures
import winreg
import zipfile
from concurrent.futures import ThreadPoolExecutor
from logging.handlers import RotatingFileHandler
from tkinter import TclError
from tkinter import font as tkfont

import customtkinter as ctk
import py7zr
import requests
import urllib3
from plyer import notification
import pythoncom
from win32com.client import Dispatch
from version import __version__

VERSION = f"v{__version__}"

if getattr(sys, 'frozen', False):
    # exe时
    BASE_DIR = os.path.dirname(os.path.abspath(sys.executable))
    MEIPASS_DIR = sys._MEIPASS
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    MEIPASS_DIR = None

def extract_bundled_files():
    """从打包文件中提取必要的文件夹和文件"""
    if not getattr(sys, 'frozen', False) or not MEIPASS_DIR:
        return
    
    # 需要提取的文件夹列表
    bundled_folders = ['icon', 'Tools', 'config']
    
    for folder in bundled_folders:
        src_folder = os.path.join(MEIPASS_DIR, folder)
        dst_folder = os.path.join(BASE_DIR, folder)
        
        if not os.path.exists(src_folder):
            continue
        
        if not os.path.exists(dst_folder):
            try:
                shutil.copytree(src_folder, dst_folder)
            except Exception:
                pass
        else:
            for root, dirs, files in os.walk(src_folder):
                rel_path = os.path.relpath(root, src_folder)
                dst_root = os.path.join(dst_folder, rel_path) if rel_path != '.' else dst_folder
                
                if not os.path.exists(dst_root):
                    os.makedirs(dst_root, exist_ok=True)
                
                for file in files:
                    src_file = os.path.join(root, file)
                    dst_file = os.path.join(dst_root, file)
                    if not os.path.exists(dst_file):
                        try:
                            shutil.copy2(src_file, dst_file)
                        except Exception:
                            pass

extract_bundled_files()
LOGS_DIR = os.path.join(BASE_DIR, "Logs")
CACHE_DIR = os.path.join(BASE_DIR, "cache")
TEMP_DIR = os.path.join(BASE_DIR, "Temporary")
TOOLS_DIR = os.path.join(BASE_DIR, "Tools")
UPDATE_DIR = os.path.join(BASE_DIR, "Update")

SEVEN_ZIP_PATH = os.path.join(TOOLS_DIR, "7z.exe")
icon_path = os.path.join(BASE_DIR, "icon", "001.ico")

DOWNLOAD_SOURCES = {
    "hk": {
        "name": "香港加速站",
        "prefix": "https://hk.gh-proxy.org/https://github.com"
    },
    "cloudflare": {
        "name": "CloudFlare加速站",
        "prefix": "https://gh-proxy.org/https://github.com"
    },
    "edgeone": {
        "name": "EdgeOne加速站",
        "prefix": "https://edgeone.gh-proxy.org/https://github.com"
    }
}

DEFAULT_SOURCE = "hk"
current_source = DEFAULT_SOURCE
SOURCE_CONFIG_FILE = os.path.join(BASE_DIR, "config", "download_source.ini")
RETAIN_INSTALLER_CONFIG_FILE = os.path.join(BASE_DIR, "config", "retain_installer.ini")

def load_download_source():
    """从配置文件加载下载源设置"""
    global current_source
    try:
        if os.path.exists(SOURCE_CONFIG_FILE):
            with open(SOURCE_CONFIG_FILE, 'r', encoding='utf-8') as f:
                saved_source = f.read().strip()
                if saved_source in DOWNLOAD_SOURCES:
                    current_source = saved_source
                    return True
    except Exception:
        pass
    return False

def save_download_source():
    """保存下载源设置到配置文件"""
    try:
        config_dir = os.path.dirname(SOURCE_CONFIG_FILE)
        if not os.path.exists(config_dir):
            os.makedirs(config_dir, exist_ok=True)
        with open(SOURCE_CONFIG_FILE, 'w', encoding='utf-8') as f:
            f.write(current_source)
        return True
    except Exception:
        return False

def load_retain_installer():
    """从配置文件加载保留安装包选项设置"""
    try:
        if os.path.exists(RETAIN_INSTALLER_CONFIG_FILE):
            with open(RETAIN_INSTALLER_CONFIG_FILE, 'r', encoding='utf-8') as f:
                saved_value = f.read().strip()
                return saved_value == "1"
    except Exception:
        pass
    return False

def save_retain_installer(value):
    """保存保留安装包选项设置到配置文件"""
    try:
        config_dir = os.path.dirname(RETAIN_INSTALLER_CONFIG_FILE)
        if not os.path.exists(config_dir):
            os.makedirs(config_dir, exist_ok=True)
        with open(RETAIN_INSTALLER_CONFIG_FILE, 'w', encoding='utf-8') as f:
            f.write("1" if value else "0")
        return True
    except Exception:
        return False

load_download_source()

def get_github_url(path):
    """获取带有下载源前缀的GitHub URL"""
    global current_source
    prefix = DOWNLOAD_SOURCES[current_source]["prefix"]
    return f"{prefix}{path}"

def set_download_source(source_key):
    """设置下载源并保存配置"""
    global current_source
    if source_key in DOWNLOAD_SOURCES:
        current_source = source_key
        save_download_source()
        return True
    return False

def get_current_source_name():
    """获取当前下载源的名称"""
    return DOWNLOAD_SOURCES[current_source]["name"]

DEFAULT_LOG_LEVEL = logging.INFO
LOG_FORMAT = '%(asctime)s|%(levelname)s|SeevvoDownloader.%(name)s.%(funcName)s|%(module)s:%(lineno)d|%(message)s'
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
LOG_DATE_FORMAT = '%Y/%m/%d %H:%M:%S'
LOG_MAX_BYTES = 1 * 1024 * 1024  # 1MB
LOG_BACKUP_COUNT = 50
LOG_RETENTION_DAYS = 7  # 日志保留天数

SEVEN_ZIP_PASSWORD = 'zQt83iOY3xXLfDVg6SJ7ocnapy90I1d62w6jh79WlT0m1qPC8b55HU5Nk4ARZFBs'

def get_logger(module_name):
    """获取指定模块的日志记录器"""
    return logging.getLogger(module_name)

os.makedirs(LOGS_DIR, exist_ok=True)

def custom_exception_hook(exctype, value, tb):
    """自定义异常钩子，用于记录未处理的异常"""
    if issubclass(exctype, KeyboardInterrupt):
        sys.__excepthook__(exctype, value, tb)
        return
    
    # 记录异常信息
    logging.critical(f"未处理的异常: {exctype.__name__}: {value}", exc_info=(exctype, value, tb))
    sys.__excepthook__(exctype, value, tb)

# 设置全局异常钩子
sys.excepthook = custom_exception_hook

def is_admin():
    """检查当前用户是否具有管理员权限"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def send_notification(title, message, timeout=8):
    """发送桌面通知"""
    icon_path = os.path.join(BASE_DIR, "icon", "001.ico")
    try:
        notification.notify(
            title=title,
            message=message,
            app_name="SEEVVO全家桶一剑下崽弃",
            timeout=timeout,
            app_icon=icon_path if os.path.exists(icon_path) else None
        )
        return True
    except Exception as err:
        logging.getLogger("Main").error(f"发送通知失败: {err}")
        try:
            notification.notify(
                title=title,
                message=message,
                timeout=timeout,
                app_icon=icon_path if os.path.exists(icon_path) else None
            )
            return True
        except Exception:
            return False

def run_as_admin():
    """以管理员权限重新运行当前程序"""
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        return True
    except:
        return False

def setup_logging(level=DEFAULT_LOG_LEVEL):
    """配置日志系统"""
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    
    # 控制台日志
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # 文件日志
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    log_filename = os.path.join(LOGS_DIR, f"app_{timestamp}.log")
    file_handler = RotatingFileHandler(
        log_filename,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    return logger

def cleanup_old_logs_by_count(directory, max_count=10, keep_count=3):
    """根据文件数量清理旧日志文件"""
    try:
        log_files = glob.glob(os.path.join(directory, "*.log"))
        log_files.extend(glob.glob(os.path.join(directory, "*.log.*")))
        
        log_files = [f for f in log_files if os.path.isfile(f)]
        
        if len(log_files) > max_count:
            log_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
            
            files_to_delete = log_files[keep_count:]
            total_files = len(log_files)
            deleted_count = 0
            failed_count = 0
            
            for log_file in files_to_delete:
                try:
                    get_logger("Main").info(f"删除过期日志文件: {log_file}")
                    os.remove(log_file)
                    deleted_count += 1
                except Exception as err:
                    failed_count += 1
                    if failed_count <= 5:
                        get_logger("Main").error(f"删除日志文件 {log_file} 失败: {str(err)}")
            
            get_logger("Main").info(f"清理日志完成: 共 {total_files} 个文件，保留 {keep_count} 个，删除 {deleted_count} 个，失败 {failed_count} 个")
    except Exception as err:
        get_logger("Main").error(f"清理旧日志时出错: {str(err)}")

def cleanup_old_logs(directory, retention_days=LOG_RETENTION_DAYS):
    """清理旧日志文件"""
    # 数量清理，超过10个保留最近3个
    cleanup_old_logs_by_count(directory, max_count=10, keep_count=3)


def shared_download_file(software_name, cache_file, download_path,
                         status_cb=None, progress_cb=None, speed_cb=None,
                         logger=None, download_rate_limit=0, progress_update_interval=0.5):
    """共享下载函数
    
    Args:
        software_name: 软件名称
        cache_file: 缓存文件信息（包含 url）
        download_path: 本地写入路径
        status_cb: 状态回调函数
        progress_cb: 进度回调函数
        speed_cb: 速度回调函数
        logger: 日志记录器
        download_rate_limit: 限速（bytes/s），0表示不限速
        progress_update_interval: UI更新间隔（秒）
    """
    if logger is None:
        logger = get_logger("Downloader")

    def _set_status(s):
        try:
            if status_cb:
                status_cb(s)
        except Exception:
            pass

    def _set_progress(p):
        try:
            if progress_cb:
                progress_cb(p)
        except Exception:
            pass

    def _set_speed(sp):
        try:
            if speed_cb:
                speed_cb(sp)
        except Exception:
            pass

    _set_status("下载中")

    max_retries = 3
    retry_count = 0
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Referer": "https://www.seewo.com/",
        "Cache-Control": "max-age=0"
    }

    url = get_download_url(cache_file) if isinstance(cache_file, dict) else None
    if not url:
        logger.error(f"{software_name}: 未提供下载 URL")
        _set_status("下载失败")
        raise RuntimeError("未提供下载 URL")

    while retry_count < max_retries:
        try:
            logger.info(f"{software_name}: 发送下载请求到: {url} (重试 {retry_count + 1}/{max_retries})")
            session = requests.Session()
            session.headers.update(headers)

            response = session.get(url, stream=True, timeout=60, allow_redirects=False, verify=False)
            if response.status_code in (301, 302):
                redirect_url = response.headers.get("Location")
                if redirect_url:
                    logger.info(f"{software_name}: 跟随重定向到: {redirect_url}")
                    response = session.get(redirect_url, stream=True, timeout=60, verify=False)

            response.raise_for_status()
            total_size = int(response.headers.get('content-length', 0))
            logger.info(f"{software_name}: 文件大小: {total_size} bytes")

            download_dir = os.path.dirname(download_path)
            if download_dir and not os.path.exists(download_dir):
                os.makedirs(download_dir, exist_ok=True)

            downloaded_size = 0
            start_time = time.time()
            window_start = start_time
            window_downloaded = 0
            last_update_time = 0

            with open(download_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        chunk_len = len(chunk)
                        downloaded_size += chunk_len

                        # 限速
                        if download_rate_limit and download_rate_limit > 0:
                            window_downloaded += chunk_len
                            now_t = time.time()
                            elapsed_window = now_t - window_start
                            if elapsed_window >= 1.0:
                                window_start = now_t
                                window_downloaded = 0
                            else:
                                expected_time = window_downloaded / float(download_rate_limit)
                                if expected_time > elapsed_window:
                                    time_to_sleep = expected_time - elapsed_window
                                    time.sleep(time_to_sleep)

                        now = time.time()
                        if last_update_time == 0 or (now - last_update_time) >= progress_update_interval:
                            elapsed_time = now - start_time if (now - start_time) > 0 else 1e-6
                            speed = downloaded_size / elapsed_time
                            if speed < 1024:
                                speed_str = f"{speed:.2f} B/s"
                            elif speed < 1024 * 1024:
                                speed_str = f"{speed / 1024:.2f} KB/s"
                            else:
                                speed_str = f"{speed / (1024 * 1024):.2f} MB/s"
                            _set_speed(speed_str)
                            if total_size > 0:
                                progress = int((downloaded_size / total_size) * 100)
                                _set_progress(progress)
                            last_update_time = now

            logger.info(f"{software_name}: 下载完成")
            _set_progress(100)
            _set_status("已完成")
            return download_path
        except requests.exceptions.RequestException as e:
            retry_count += 1
            logger.warning(f"{software_name}: 下载失败，将重试 ({retry_count}/{max_retries}) - {str(e)}")
            time.sleep(5)
            if retry_count >= max_retries:
                logger.error(f"{software_name}: 下载失败 - {str(e)}", exc_info=True)
                _set_status("下载失败")
                raise RuntimeError(str(e)) from e
        except OSError as e:
            logger.error(f"{software_name}: 文件操作失败 - {str(e)}", exc_info=True)
            _set_status("下载失败")
            raise RuntimeError(str(e)) from e
        except Exception:
            logger.error(f"{software_name}: 下载异常 - {str(e)}", exc_info=True)
            _set_status("下载失败")
            raise RuntimeError(str(e)) from e


# --------------------
# 进程/子进程 优先级控制
# --------------------
PRIORITY_CLASSES = {
    'idle': 0x40,
    'below_normal': 0x00004000,
    'normal': 0x20,
    'above_normal': 0x00008000,
    'high': 0x00000080,
    'realtime': 0x00000100,
}

def set_priority_for_pid(pid, level='below_normal'):
    """设置指定 pid 的进程优先级
    
    Args:
        pid: 进程ID
        level: 优先级级别，可选值：'idle'|'below_normal'|'normal'|'above_normal'|'high'|'realtime'
    
    Returns:
        bool: 设置是否成功
    """
    try:
        level_const = PRIORITY_CLASSES.get(level, PRIORITY_CLASSES['normal'])
        PROCESS_SET_INFORMATION = 0x0200
        PROCESS_QUERY_INFORMATION = 0x0400
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION, False, int(pid))
        if not handle:
            return False
        try:
            res = ctypes.windll.kernel32.SetPriorityClass(handle, int(level_const))
            return bool(res)
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    except Exception:
        return False


def set_current_process_priority(level='high'):
    """将当前进程优先级设置为指定级别
    
    Args:
        level: 优先级级别，可选值：'idle'|'below_normal'|'normal'|'above_normal'|'high'|'realtime'
    """
    try:
        set_priority_for_pid(os.getpid(), level)
        logging.getLogger('Main').info(f"已设置当前进程优先级为: {level}")
    except Exception:
        logging.getLogger('Main').warning("设置当前进程优先级失败")


_original_popen = subprocess.Popen

def _popen_with_priority(*popen_args, **popen_kwargs):
    """为子进程设置优先级的包装函数"""
    process = _original_popen(*popen_args, **popen_kwargs)
    try:
        # 将子进程优先级降到 below_normal
        set_priority_for_pid(process.pid, 'below_normal')
    except Exception:
        pass
    return process

# 替换 subprocess.Popen
subprocess.Popen = _popen_with_priority

# 创建必要的目录
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(TEMP_DIR, exist_ok=True)
os.makedirs(UPDATE_DIR, exist_ok=True)

# 清理临时目录
for item in os.listdir(TEMP_DIR):
    item_path = os.path.join(TEMP_DIR, item)
    try:
        if os.path.isfile(item_path):
            os.remove(item_path)
        elif os.path.isdir(item_path):
            shutil.rmtree(item_path)
    except Exception:
        pass

# 禁用SSL验证警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

class DisclaimerWindow:
    """用户协议窗口"""
    def __init__(self, main_app=None, parent_root=None):
        self.disclaimer_logger = get_logger("Disclaimer")
        self.disclaimer_logger.info("初始化用户协议窗口")
        self.main_app = main_app
        
        if parent_root:
            self.root = ctk.CTkToplevel(parent_root)
        elif main_app and hasattr(main_app, 'root'):
            self.root = ctk.CTkToplevel(main_app.root)
            main_app.root.withdraw()
        else:
            self.root = ctk.CTk()
        
        self.root.title(f"SEEVVO全家桶一剑下崽弃 {MainWindowApp.VERSION} - 软件用户使用协议及免责协议 - 作者：HelloGaoo & WHYOS")
        self.root.geometry("1000x650")
        self.root.resizable(False, False)
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self._create_widgets()
        
    def _create_widgets(self):
        main_frame = ctk.CTkFrame(self.root, fg_color=Colors.BACKGROUND)
        main_frame.pack(fill=ctk.BOTH, expand=True, padx=0, pady=0)
        
        content_container = ctk.CTkFrame(main_frame, fg_color=Colors.BACKGROUND)
        content_container.pack(fill=ctk.BOTH, expand=True, padx=Dimensions.PADX_LARGE, pady=(Dimensions.PADY_XLARGE, Dimensions.PADY_SMALL))
        
        card_frame = ctk.CTkFrame(
            content_container,
            corner_radius=Dimensions.CORNER_RADIUS_LARGE,
            border_width=Dimensions.BORDER_WIDTH,
            border_color=Colors.BORDER,
            fg_color=Colors.CARD_BACKGROUND
        )
        card_frame.pack(fill=ctk.BOTH, expand=True, padx=0, pady=0)
        
        title_bar = ctk.CTkFrame(
            card_frame,
            fg_color=Colors.CARD_BACKGROUND,
            border_width=0,
            corner_radius=0
        )
        title_bar.pack(fill=ctk.X, padx=Dimensions.PADX_LARGE, pady=(Dimensions.PADY_LARGE, Dimensions.PADY_MEDIUM))
        
        title_label = ctk.CTkLabel(
            title_bar,
            text="软件用户使用协议及免责协议",
            font=create_global_font(24, "bold", logger=get_logger("Fonts")),
            text_color=Colors.TEXT
        )
        title_label.pack(anchor="w")
        
        divider = ctk.CTkFrame(
            card_frame,
            fg_color=Colors.SECTION_DIVIDER,
            border_width=0,
            height=1
        )
        divider.pack(fill=ctk.X, padx=Dimensions.PADX_LARGE)
        
        self.textbox = ctk.CTkTextbox(
            card_frame,
            fg_color=Colors.CARD_BACKGROUND,
            border_color=Colors.BORDER,
            border_width=1,
            corner_radius=Dimensions.CORNER_RADIUS_MEDIUM,
            font=create_global_font(14, logger=get_logger("Fonts"))
        )
        self.textbox.pack(fill=ctk.BOTH, expand=True, padx=Dimensions.PADX_LARGE, pady=Dimensions.PADY_LARGE)
        try:
            title_bar.bind("<Button-1>", self._start_move)
            title_bar.bind("<B1-Motion>", self._on_move)
            title_label.bind("<Button-1>", self._start_move)
            title_label.bind("<B1-Motion>", self._on_move)
        except Exception:
            pass
        
        disclaimer_content = """免责声明及法律参考：
更新日期：2026/2/27
生效日期：2026/2/27

重要提示：
本程序部分工具中的"白板去除横幅"已设置为不可选择状态，用户无法通过本程序直接获取该工具。

使用目的：本程序及其子目录下的所有资源仅供学习和研究使用，项目已开源。其旨在为学术和研究人员提供参考和资料，任何其他目的均不适用。

非商业与非法用途：严禁将本程序及其内容用于任何商业或非法用途。对于因违反此规定而产生的任何法律后果，用户需自行承担全部责任。

来源与版权：
1. 大部分软件资源直接来源于希沃（Seewo）官方服务器（seewo.com域名）
2. 部分资源来源于GitHub等平台托管的原版安装包
3. 部分第三方工具（如激活工具等）与希沃无关
4. 如有关于版权的争议或问题，请联系原作者或权利人

下载后的处理：请注意，您在下载任何资源后，必须在24小时内从您的电脑或存储设备中彻底删除上述资源，无论这些资源是软件、文档还是其他形式的数据。

支持正版：如果您发现某个程序或资源对您有帮助或您喜欢它，请积极支持正版，从官方渠道获取软件和服务。

特别说明：
- 本程序仅作为软件下载聚合工具，不修改、不破解、不逆向工程任何软件
- 所有软件的知识产权归各自权利人所有
- 第三方工具（如激活工具等）的使用风险由用户自行承担，与本程序作者无关
- 本程序作者不对任何软件的使用后果承担责任
- 本程序与希沃（Seewo）公司无任何关联，不是希沃官方产品
- 本程序不提供任何软件破解、激活或授权绕过服务
- 用户确认已充分理解本协议内容，并具备相应的民事行为能力
- 本项目已在GitHub开源

法律参考：根据《计算机软件保护条例》（2002年1月1日实施）的第十七条规定：为了学习和研究软件内含的设计思想和原理，通过安装、显示、传输或者存储软件的方式使用软件，可以不经软件著作权人许可，不向其支付报酬。鉴于此，我们强烈建议用户在使用本程序及其内容时，遵循上述法规，并确保其行为目的仅限于学习和研究软件内部的设计思想和原理。

最终解释权：本免责声明的最终解释权归声明者所有。

解释权说明：本声明中的“最终解释权”条款并非意在单方面施加权利或霸王条款，而是为了在可能出现的模糊或争议情况下提供清晰的指导和解释。其目的是确保本声明的内容和意图得到恰当和公正的实施，同时为用户提供更明确的方向和帮助。

在使用该程序及其内容前，请确保已仔细阅读并完全理解上述声明和法律参考。您的使用行为将被视为对上述内容的完全接受。

隐私政策：
更新日期：2026/2/27
生效日期：2026/2/27

重要说明：本程序不收集、不存储、不传输任何用户个人信息。

本程序是一款本地运行的软件下载工具，所有功能均在您的本地电脑上完成：
- 不收集您的任何个人身份信息
- 不收集您的设备信息
- 不收集您的使用记录
- 不使用任何 cookies 或追踪技术
- 不向任何第三方服务器发送数据

如对本隐私政策有任何问题，请通过 gaoo1228@163.com 与我们联系。"""
        try:
            self.textbox.insert("0.0", disclaimer_content)
            self.textbox.configure(state="disabled")  # 设置为只读
        except Exception as e:
            try:
                self.disclaimer_logger.error(f"插入协议内容失败: {e}")
            except Exception:
                pass
            self.textbox.insert("0.0", "无法加载协议内容。")
            self.textbox.configure(state="disabled")
        
        button_frame = ctk.CTkFrame(card_frame, fg_color=Colors.CARD_BACKGROUND, border_width=0)
        button_frame.pack(pady=(0, Dimensions.PADY_LARGE), fill=ctk.X, padx=Dimensions.PADX_LARGE)
        
        btn_container = ctk.CTkFrame(button_frame, fg_color="transparent")
        btn_container.pack(anchor="e", padx=Dimensions.PADY_SMALL)
        
        self.agree_btn = ctk.CTkButton(
            btn_container,
            text="同意",
            fg_color=Colors.BUTTON,
            hover_color=Colors.BUTTON_HOVER,
            width=Dimensions.BUTTON_WIDTH,
            height=Dimensions.BUTTON_HEIGHT,
            font=create_global_font(14, "bold", logger=get_logger("Fonts")),
            command=self.on_agree
        )
        self.agree_btn.pack(side=ctk.RIGHT, padx=Dimensions.PADX_MEDIUM)
        
        self.disagree_btn = ctk.CTkButton(
            btn_container,
            text="不同意",
            fg_color=Colors.BUTTON,
            hover_color=Colors.BUTTON_HOVER,
            width=Dimensions.BUTTON_WIDTH,
            height=Dimensions.BUTTON_HEIGHT,
            font=create_global_font(14, "bold", logger=get_logger("Fonts")),
            command=self.on_disagree
        )
        self.disagree_btn.pack(side=ctk.RIGHT, padx=Dimensions.PADX_MEDIUM)
        
        contact_label = ctk.CTkLabel(
            main_frame,
            text="作者：HelloGaoo & WHYOS | 用户需自觉遵守并履行协议。如果资源存在违规或侵犯了您的合法权益，请联系作者我们会及时删除。邮箱：gaoo1228@163.com",
            text_color=Colors.CONTACT_INFO,
            font=create_global_font(12, logger=get_logger("Fonts")),
            justify=ctk.CENTER
        )
        contact_label.pack(fill=ctk.X, pady=(Dimensions.PADY_SMALL, Dimensions.PADY_MEDIUM), padx=Dimensions.PADX_LARGE)
    
    def on_agree(self):
        """用户同意协议"""
        self._save_disclaimer_status(True)
        self.root.destroy()
        if self.main_app and hasattr(self.main_app, 'root'):
            try:
                self.main_app.root.deiconify()
            except Exception:
                pass
    
    def on_disagree(self):
        """用户不同意协议"""
        self._save_disclaimer_status(False)
        self.root.destroy()
        if self.main_app and hasattr(self.main_app, 'root'):
            try:
                self.main_app.root.destroy()  # 退出应用
            except Exception:
                pass
        else:
            sys.exit(0)
    
    def on_close(self):
        """窗口关闭事件处理"""
        self.on_disagree()

    def _start_move(self, event):
        """开始拖动窗口"""
        try:
            self._drag_start_x = event.x_root
            self._drag_start_y = event.y_root
            self._win_start_x = self.root.winfo_x()
            self._win_start_y = self.root.winfo_y()
        except Exception:
            pass

    def _on_move(self, event):
        """拖动窗口"""
        try:
            dx = event.x_root - getattr(self, '_drag_start_x', event.x_root)
            dy = event.y_root - getattr(self, '_drag_start_y', event.y_root)
            new_x = int(getattr(self, '_win_start_x', self.root.winfo_x()) + dx)
            new_y = int(getattr(self, '_win_start_y', self.root.winfo_y()) + dy)
            self.root.geometry(f"+{new_x}+{new_y}")
        except Exception:
            pass
    
    def _save_disclaimer_status(self, status):
        """保存用户协议状态到配置文件"""
        try:
            config_dir = os.path.join(BASE_DIR, "config")
            try:
                self.disclaimer_logger.info(f"确保目录存在: {config_dir}")
            except Exception:
                pass
            os.makedirs(config_dir, exist_ok=True)
            disclaimer_file = os.path.join(config_dir, "Disclaimer.ini")
            try:
                self.disclaimer_logger.info(f"写入用户协议状态到: {disclaimer_file}")
            except Exception:
                pass
            with open(disclaimer_file, "w", encoding="utf-8") as f:
                f.write(str(status))
            try:
                self.disclaimer_logger.info(f"用户协议状态已保存: {status}")
            except Exception:
                pass
        except Exception as e:
            try:
                self.disclaimer_logger.error(f"保存用户协议状态失败: {e}")
            except Exception:
                pass

def check_disclaimer_status():
    """检查用户协议状态"""
    try:
        disclaimer_file = os.path.join(BASE_DIR, "config", "Disclaimer.ini")
        if os.path.exists(disclaimer_file):
            try:
                get_logger("Main").info(f"读取用户协议状态从: {disclaimer_file}")
            except Exception:
                pass
            with open(disclaimer_file, "r", encoding="utf-8") as f:
                content = f.read().strip().lower()
            return content == "true"
        try:
            get_logger("Main").info(f"用户协议文件不存在: {disclaimer_file}")
        except Exception:
            pass
        return False
    except Exception as e:
        try:
            get_logger("Main").error(f"检查用户协议状态失败: {e}")
        except Exception:
            pass
        return False

# 颜色配置
class Colors:
    """颜色配置类"""
    BACKGROUND = "#f5f7fa"
    BORDER = "#e0e5ec"
    TEXT = "#2d3748"
    TEXT_SECONDARY = "#718096"
    HOVER = "#edf2f7"
    BUTTON = "#4299e1"
    BUTTON_HOVER = "#3182ce"
    PRIMARY = "#4299e1"
    PRIMARY_HOVER = "#3182ce"
    SECONDARY = "#48bb78"
    SECONDARY_HOVER = "#38a169"
    ACCENT = "#ed8936"
    ACCENT_HOVER = "#dd6b20"
    CARD_BACKGROUND = "#ffffff"
    LIST_BACKGROUND = "#fafbfc"
    SECTION_DIVIDER = "#e2e8f0"
    TABLE_HEADER = "#f7fafc"
    TABLE_HEADER_TEXT = "#4a5568"
    TABLE_ROW = "#ffffff"
    TABLE_ROW_HOVER = "#edf2f7"
    PROGRESS_BACKGROUND = "#e2e8f0"
    PROGRESS_FOREGROUND = "#4299e1"
    CHECKBOX_BORDER = "#94a3b8"
    CHECKMARK = "#ffffff"
    TEXT_WHITE = "#ffffff"
    CONTACT_INFO = "#4a5568"

# 尺寸配置
class Dimensions:
    """尺寸配置类"""
    # 主窗口配置
    MAIN_WINDOW_WIDTH = 1100
    MAIN_WINDOW_HEIGHT = 740
    # 安装窗口配置
    INSTALL_WINDOW_WIDTH = 1000
    INSTALL_WINDOW_HEIGHT = 700
    INSTALL_WINDOW_MIN_WIDTH = 1000
    INSTALL_WINDOW_MIN_HEIGHT = 700
    # 组件尺寸
    BUTTON_WIDTH = 120
    BUTTON_HEIGHT = 40
    BORDER_WIDTH = 1
    CHECKBOX_BORDER_WIDTH = 2
    # 边距配置
    PADX_SMALL = 5
    PADX_MEDIUM = 10
    PADX_LARGE = 15
    PADY_SMALL = 5
    PADY_MEDIUM = 10
    PADY_MEDIUM1 = 13
    PADY_LARGE = 15
    PADY_XLARGE = 20
    # 圆角配置
    CORNER_RADIUS_SMALL = 6
    CORNER_RADIUS_MEDIUM = 8
    CORNER_RADIUS_LARGE = 10



def create_global_font(size, weight="normal", logger=None):
    """创建全局字体
    
    Args:
        size: 字体大小
        weight: 字体粗细，默认为"normal"
        logger: 日志记录器
    
    Returns:
        ctk.CTkFont: 创建的字体对象
    """
    preferred_fonts = [
        "Microsoft YaHei UI",
        "Microsoft YaHei",
        "Source Han Sans CN",
        "SimHei",
        "Segoe UI",
        "Arial"
    ]

    try:
        available_fonts = tkfont.families()
    except Exception:
        available_fonts = []

    selected_font = None
    for font_name in preferred_fonts:
        if font_name in available_fonts:
            selected_font = font_name
            break

    try:
        if selected_font:
            font = ctk.CTkFont(family=selected_font, size=size, weight=weight)
            if not hasattr(create_global_font, "font_used") and logger:
                logger.info(f"成功使用字体: {selected_font}")
                create_global_font.font_used = True
            return font
        else:
            font = ctk.CTkFont(family="sans-serif", size=size, weight=weight)
            if hasattr(font, 'actual') and not hasattr(create_global_font, "font_used") and logger:
                try:
                    actual_family = font.actual().get('family', 'sans-serif')
                    logger.info(f"使用默认无衬线字体: {actual_family}")
                except Exception:
                    logger.info("使用默认无衬线字体")
                create_global_font.font_used = True
            return font
    except Exception as e:
        if logger:
            logger.error(f"创建字体失败: {e}")
        return ctk.CTkFont(size=size, weight=weight)




# 缓存文件信息列表
# github_path: GitHub路径
# url: 官网
CACHE_FILES = [
    {"filename": "剪辑师.exe", "url": "https://store-g1.seewo.com/seewo-report_a8af6d2a461847f1b851d31a6b391428?attname=Jianjishi_1.7.0.775.exe"},
    {"filename": "轻录播.exe", "url": "https://store-g1.seewo.com/seewo-report_86c15cf3e8b34875bacc4e0aa391b401?attname=EasiRecorderSetup_1.0.2.540.exe"},
    {"filename": "知识胶囊.exe", "url": "https://cstore-pub-seewo-report-tx.seewo.com/seewo-report_fd2dc77b5ee24f83a9f6ce257e44fb4d?attname=EasiCapsuleSetup_2.4.0.7802.exe"},
    {"filename": "掌上看班.exe", "url": "https://imlizhi-store-https.seewo.com/SeewoHugoKanbanWebApp_1.4.5.68(20240329093729).exe"},
    {"filename": "激活工具.7z", "github_path": "/HelloGaoo/SeevvoDownloader/releases/download/v1.0.0/HEU_KMS_Activator.7z"},
    {"filename": "希沃壁纸.7z", "github_path": "/HelloGaoo/SeevvoDownloader/releases/download/v1.0.0/seewoWallpaper.7z"},
    {"filename": "希沃管家.exe", "url": "https://cstore-pub-seewo-report-tx.seewo.com/seewo-report_79fc6c21a6694bf29160feda273b99c7?attname=SeewoServiceSetup_1.3.6.3254.exe"},
    {"filename": "希沃桌面.7z", "github_path": "/HelloGaoo/SeevvoDownloader/releases/download/v1.0.0/seewoDesktop.7z"},
    {"filename": "希沃快传.exe", "url": "https://imlizhi-store-https.seewo.com/SeewoFileTransfer_2.0.10(20240830095652).exe"},
    {"filename": "希沃集控.exe", "url": "https://store-g1.seewo.com/seewo-report_abc60b691ca74da088507021f92bc381?attname=SeewoHugoWebApp_1.1.8.42.exe"},
    {"filename": "希沃截图.7z", "github_path": "/HelloGaoo/SeevvoDownloader/releases/download/v1.0.0/seewoScreenshot.7z"},
    {"filename": "希沃批注.7z", "github_path": "/HelloGaoo/SeevvoDownloader/releases/download/v1.0.0/seewoAnnotation.7z"},
    {"filename": "希沃计时器.7z", "github_path": "/HelloGaoo/SeevvoDownloader/releases/download/v1.0.0/seewoTimer.7z"},
    {"filename": "希沃放大镜.7z", "github_path": "/HelloGaoo/SeevvoDownloader/releases/download/v1.0.0/seewoMagnifier.7z"},
    {"filename": "希沃浏览器.7z", "github_path": "/HelloGaoo/SeevvoDownloader/releases/download/v1.0.0/seewoBrowser.7z"},
    {"filename": "希沃智能笔.exe", "url": "https://imlizhi-store-https.seewo.com/SmartpenServiceSetup_2.0.1.749(20240619165806).exe"},
    {"filename": "反馈器助手.exe", "github_path": "/HelloGaoo/SeevvoDownloader/releases/download/v1.0.0/feedbackAssistant.exe"},
    {"filename": "希沃易课堂.exe", "url": "https://cstore-pub-seewo-report-tx.seewo.com/seewo-report_31a18b9dc7e74439b42669918dbdaf55?attname=EasiClassSetup_2.1.22.6341.exe"},
    {"filename": "希沃输入法.exe", "url": "https://imlizhi-store-https.seewo.com/seewoinput_1.0.5(20250820092142).exe"},
    {"filename": "PPT小工具.exe", "url": "https://store-g1.seewo.com/seewo-report_6594548a69c34306af2c9cc73a060e19?attname=PPTServiceSetup_1.0.0.795.exe"},
    {"filename": "希沃轻白板.exe", "url": "https://imlizhi-store-https.seewo.com/EasiNote5C_1.0.1.8095(20240703115236).exe"},
    {"filename": "希沃白板5.exe", "url": "https://cstore-pub-seewo-report-tx.seewo.com/seewo-report_2fc45eb4318e41c4bc538fd0660bae43?attname=EasiNoteSetup_5.2.4.9120_seewo.exe"},
    {"filename": "希沃白板3.exe", "github_path": "/HelloGaoo/SeevvoDownloader/releases/download/v1.0.0/seewowhiteboard3.exe"},
    {"filename": "ikun启动图.7z", "github_path": "/HelloGaoo/SeevvoDownloader/releases/download/v1.0.0/ikunSplashScreen.7z"},
    {"filename": "白板去除横幅.7z", "github_path": "/HelloGaoo/SeevvoDownloader/releases/download/v1.0.0/Remove_banner_from_whiteboard.7z"},
    {"filename": "班级优化大师.exe", "url": "https://imlizhi-store-https.seewo.com/EasiCare_PC_2.1.0.3239(20250328203940).exe"},
    {"filename": "希沃课堂助手.exe", "url": "https://cstore-pub-seewo-report-tx.seewo.com/seewo-report_83de79eec5a94c07a337baeab68a8b07?attname=SeewoIwbAssistant_0.0.3.1207.exe"},
    {"filename": "希沃电脑助手.exe", "url": "https://imlizhi-store-https.seewo.com/seewoPCAssistant_2.1.6(20250523210530).exe"},
    {"filename": "希沃导播助手.exe", "url": "https://imlizhi-store-https.seewo.com/EasiDirector_1.0.10.195(20211105150841).exe"},
    {"filename": "希沃视频展台.exe", "url": "https://cstore-pub-seewo-report-tx.seewo.com/seewo-report_12f92ef48ca24ec982a5803393c2f719?attname=EasiCameraSetup_2.0.10.3816.exe"},
    {"filename": "希沃物联校园.exe", "url": "https://imlizhi-store-https.seewo.com/SeewoIotManageWebApp_1.0.0.8(20210609110648).exe"},
    {"filename": "希沃互动签名.7z", "github_path": "/HelloGaoo/SeevvoDownloader/releases/download/v1.0.0/seewoInteractiveSignature.7z"},
    {"filename": "希沃伪装插件.7z", "github_path": "/HelloGaoo/SeevvoDownloader/releases/download/v1.0.0/seewoDisguisePlugin.7z"},
    {"filename": "远程互动课堂.exe", "url": "https://imlizhi-store-https.seewo.com/AirTeach_AirteachSetup_2.0.17.17064(20250507123142).exe"},
    {"filename": "AGC解锁工具.7z", "github_path": "/HelloGaoo/SeevvoDownloader/releases/download/v1.0.0/agcUnlockTool.7z"},
    {"filename": "触摸服务程序.7z", "github_path": "/HelloGaoo/SeevvoDownloader/releases/download/v1.0.0/touchServiceProgram.7z"},
    {"filename": "希沃随机抽选.7z", "github_path": "/HelloGaoo/SeevvoDownloader/releases/download/v1.0.0/seewoLuckyRandom.7z"},
    {"filename": "触摸框测试程序.7z", "github_path": "/HelloGaoo/SeevvoDownloader/releases/download/v1.0.0/touchFrameTestProgram.7z"},
    {"filename": "省平台登录插件.exe", "url": "https://imlizhi-store-https.seewo.com/EasiNote_plugin_anhui_V0.1(20200616170758).exe"},
    {"filename": "希象传屏[发送端].exe", "url": "https://imlizhi-store-https.seewo.com/ExceedShare_6.7.1.20(20250610165636).exe"},
    {"filename": "希象传屏[接收端].exe", "github_path": "/HelloGaoo/SeevvoDownloader/releases/download/v1.0.0/screensharesuite.exe"},
    {"filename": "希沃品课[小组端].exe", "url": "https://cstore-pub-seewo-report-tx.seewo.com/seewo-report_5d829b9cd5e24d5fa1c0a2b5602c9d6e?attname=seewoPincoGroupSetup_1.2.30.1640.exe"},
    {"filename": "希沃品课[教师端].exe", "url": "https://imlizhi-store-https.seewo.com/seewoPincoTeacher_1.2.43.7285(20250530191221).exe"},
    {"filename": "ClassIsland2.exe", "url": "https://get.classisland.tech/d/ClassIsland-Ningbo-S3/classisland/distribution-v2/2.0/2.0.0.2/ClassIsland_app_windows_x64_selfContained_folder.zip"},
    {"filename": "ClassWidgets.exe", "url": "https://ghfile.geekertao.top/https://github.com/Class-Widgets/Class-Widgets/releases/download/1.2.0.5/ClassWidgets-Windows-x64.zip"},
    {"filename": "微信.exe", "url": "https://dldir1v6.qq.com/weixin/Universal/Windows/WeChatWin.exe"},
    {"filename": "QQ.exe", "url": "https://dldir1v6.qq.com/qqfile/qq/QQNT/Windows/QQ_9.9.21_250822_x64_01.exe"},
    {"filename": "UU远程.exe", "github_path": "/HelloGaoo/SeevvoDownloader/releases/download/v1.0.0/uuyc_4.16.5_gwgame.exe"},
    {"filename": "网易云音乐.exe", "github_path": "/HelloGaoo/SeevvoDownloader/releases/download/v1.0.0/neteaseCloudMusic.exe"},
    {"filename": "office2021.exe", "url": "https://c2rsetup.officeapps.live.com/c2r/download.aspx?productReleaseID=ProPlus2021Retail&platform=X64&language=zh-cn"},
]

def get_download_url(file_info):
    if "github_path" in file_info:
        return get_github_url(file_info["github_path"])
    return file_info.get("url", "")

class MainWindowApp:
    """主窗口应用类"""
    CHINESE_NAME = "SEEVVO全家桶一剑下崽弃"
    ENGLISH_NAME = "SeevvoDownloader"
    VERSION = VERSION
    
    SOFTWARE_LIST = [
        "剪辑师", "轻录播", "知识胶囊", "掌上看班", "激活工具", "希沃壁纸", "希沃管家", "希沃桌面", "希沃快传", "希沃集控",
        "希沃截图", "希沃批注", "希沃计时器", "希沃放大镜", "希沃浏览器", "希沃智能笔", "反馈器助手", "希沃易课堂", "希沃输入法", "PPT小工具",
        "希沃轻白板", "希沃白板5", "希沃白板3", "ikun启动图", "白板去除横幅", "班级优化大师", "希沃课堂助手", "希沃电脑助手", "希沃导播助手", "希沃视频展台",
        "希沃物联校园", "希沃互动签名", "希沃伪装插件", "远程互动课堂", "AGC解锁工具", "触摸服务程序", "希沃随机抽选", "触摸框测试程序", "省平台登录插件",
        "希象传屏[发送端]", "希象传屏[接收端]", "希沃品课[小组端]", "希沃品课[教师端]", "ClassIsland2", "ClassWidgets", "微信", "QQ", "UU远程", "网易云音乐", "office2021"
    ]

    def __init__(self):
        main_logger = get_logger("Main")
        main_logger.info("开始初始化主应用窗口")
        self.root = ctk.CTk()
        self.root.title(f"SEEVVO全家桶一剑下崽弃 {self.VERSION} - 主窗口 - 作者：HelloGaoo & WHYOS")
        self.root.geometry(f"{Dimensions.MAIN_WINDOW_WIDTH}x{Dimensions.MAIN_WINDOW_HEIGHT}")
        self.root.resizable(False, False)
        
        self.root.protocol("WM_DELETE_WINDOW", self._on_main_window_close)
        
        main_logger.info(f"主窗口创建完成，标题: {self.root.title()}, 尺寸: {Dimensions.MAIN_WINDOW_WIDTH}x{Dimensions.MAIN_WINDOW_HEIGHT}")
        
        self._init_window()
        
        self.software_checkboxes = {}  # 存储所有软件复选框
        self.is_all_selected = False   # 全选状态标志
        self.install_window = None     # 安装窗口实例引用
        self.update_window = None      # 更新窗口实例引用
        
        self.fonts_logger = get_logger("Fonts")
        self.create_font = create_global_font
        
        self._create_all_widgets()
        
        main_logger.info("检测网络连接状态")
        is_network_available = self._check_network_availability()
        
        if not is_network_available:
            main_logger.warning("网络不可用，跳过更新检查")
            messagebox.showinfo("SEEVVO全家桶一剑下崽弃", "网络不可用，跳过更新检查")
        else:
            main_logger.info("网络可用，检查更新状态")
            loading = LoadingWindow(self.root, title="初始化", message="正在检测下载器更新版本")
            
            def check_update_in_background():
                should_open_update_window = self._check_update_status()
                if should_open_update_window:
                    main_logger.info("检测到新版本，检查许可协议状态")
                    if check_disclaimer_status():
                        main_logger.info("用户已同意许可协议，直接打开更新窗口")
                        self.root.after(0, lambda: self.open_update_window())
                    else:
                        main_logger.info("用户未同意许可协议，先打开许可协议窗口")
                        def open_disclaimer_then_update():
                            disclaimer_window = DisclaimerWindow(self)
                            self.root.wait_window(disclaimer_window.root)
                            if check_disclaimer_status():
                                main_logger.info("用户同意了许可协议，打开更新窗口")
                                self.open_update_window()
                        self.root.after(0, open_disclaimer_then_update)
            
            update_thread = threading.Thread(target=check_update_in_background, daemon=True)
            update_thread.start()
            
            def monitor():
                try:
                    if update_thread.is_alive():
                        self.root.after(200, monitor)
                    else:
                        try:
                            loading.close()
                        except Exception:
                            pass
                except Exception:
                    try:
                        loading.close()
                    except Exception:
                        pass
            
            self.root.after(200, monitor)
        
        main_logger.info("应用程序初始化完成")
    
    def _init_window(self):
        """初始化窗口设置"""
        main_logger = get_logger("Main")
        self.root.configure(fg_color=Colors.BACKGROUND)
        
        self.root.attributes("-alpha", 1.0)
        self.root.attributes("-transparentcolor", "#000001")
        
        self.root.update_idletasks()

        try:
            icon_path = os.path.join(BASE_DIR, "icon", "001.ico")
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception as e:
            main_logger.error(f"设置图标时出错: {e}")

    def _on_main_window_close(self):
        """主窗口关闭事件处理"""
        main_logger = get_logger("Main")
        main_logger.info("主窗口关闭事件触发")
        
        if hasattr(self, 'install_window') and self.install_window is not None:
            try:
                main_logger.info("关闭安装窗口")
                self.install_window.root.destroy()
            except (AttributeError, TclError):
                main_logger.info("安装窗口已关闭")
        
        main_logger.info("销毁主窗口")
        self.root.destroy()
        
        main_logger.info("退出应用程序进程")
        sys.exit(0)
    
    def _create_all_widgets(self):
        """创建主窗口所有组件"""
        main_frame = ctk.CTkFrame(self.root, fg_color=Colors.BACKGROUND, corner_radius=0)
        main_frame.pack(fill=ctk.BOTH, expand=True, padx=0, pady=0)
        
        content_container = ctk.CTkFrame(main_frame, fg_color=Colors.BACKGROUND)
        content_container.pack(fill=ctk.BOTH, expand=True, padx=Dimensions.PADX_LARGE, pady=(Dimensions.PADY_XLARGE, Dimensions.PADY_SMALL))
        
        card_frame = ctk.CTkFrame(
            content_container,
            corner_radius=Dimensions.CORNER_RADIUS_LARGE,
            border_width=Dimensions.BORDER_WIDTH,
            border_color=Colors.BORDER,
            fg_color=Colors.CARD_BACKGROUND
        )
        card_frame.pack(fill=ctk.BOTH, expand=True, padx=0, pady=0)
        
        title_bar = ctk.CTkFrame(
            card_frame,
            fg_color=Colors.CARD_BACKGROUND,
            border_width=0,
            corner_radius=0
        )
        title_bar.pack(fill=ctk.X, padx=Dimensions.PADX_LARGE, pady=(Dimensions.PADY_LARGE, Dimensions.PADY_MEDIUM))
        
        title_row = ctk.CTkFrame(title_bar, fg_color="transparent")
        title_row.pack(fill=ctk.X)
        
        title_label = ctk.CTkLabel(
            title_row,
            text="软件列表",
            text_color=Colors.TEXT,
            font=self.create_font(24, "bold", logger=self.fonts_logger)
        )
        title_label.pack(side="left")
        
        source_frame = ctk.CTkFrame(title_row, fg_color="transparent")
        source_frame.pack(side="right")
        
        source_label = ctk.CTkLabel(
            source_frame,
            text="GitHub下载源:",
            text_color=Colors.TEXT,
            font=self.create_font(18, logger=self.fonts_logger)
        )
        source_label.pack(side="left", padx=(0, 5))
        
        self.source_var = ctk.StringVar(value=current_source)
        source_menu = ctk.CTkOptionMenu(
            source_frame,
            variable=self.source_var,
            values=list(DOWNLOAD_SOURCES.keys()),
            command=self._on_source_change,
            width=120,
            height=32,
            font=self.create_font(18, logger=self.fonts_logger),
            fg_color=Colors.BUTTON,
            button_color=Colors.BUTTON_HOVER,
            button_hover_color=Colors.BUTTON_HOVER,
            dropdown_fg_color=Colors.CARD_BACKGROUND,
            dropdown_hover_color=Colors.BUTTON_HOVER
        )
        source_menu.pack(side="left")
        
        # 保留安装包选项
        retain_frame = ctk.CTkFrame(title_row, fg_color="transparent")
        retain_frame.pack(side="right", padx=(0, 20))
        
        retain_installer_value = load_retain_installer()
        self.retain_installer_var = ctk.IntVar(value=1 if retain_installer_value else 0)
        
        def on_retain_installer_change():
            save_retain_installer(self.retain_installer_var.get() == 1)
        
        retain_checkbox = ctk.CTkCheckBox(
            retain_frame,
            text="安装后保留安装包",
            variable=self.retain_installer_var,
            command=on_retain_installer_change,
            text_color=Colors.TEXT,
            font=self.create_font(18, logger=self.fonts_logger),
            fg_color=Colors.BUTTON,
            hover_color=Colors.HOVER,
            border_color=Colors.CHECKBOX_BORDER,
            checkmark_color=Colors.CHECKMARK,
            border_width=Dimensions.CHECKBOX_BORDER_WIDTH,
            corner_radius=Dimensions.CORNER_RADIUS_SMALL
        )
        retain_checkbox.pack(side="left")
        
        divider = ctk.CTkFrame(
            card_frame,
            fg_color=Colors.SECTION_DIVIDER,
            border_width=0,
            height=1
        )
        divider.pack(fill=ctk.X, padx=Dimensions.PADX_LARGE)
        
        self.fixed_frame = ctk.CTkFrame(
            card_frame,
            fg_color=Colors.LIST_BACKGROUND,
            border_color=Colors.SECTION_DIVIDER,
            border_width=Dimensions.BORDER_WIDTH,
            corner_radius=Dimensions.CORNER_RADIUS_MEDIUM
        )
        self.fixed_frame.pack(fill=ctk.BOTH, expand=True, padx=Dimensions.PADX_LARGE, pady=Dimensions.PADY_LARGE)
        
        self._create_software_checkboxes(self.fixed_frame)
        
        button_frame = ctk.CTkFrame(card_frame, fg_color=Colors.CARD_BACKGROUND, border_width=0)
        button_frame.pack(pady=(0, Dimensions.PADY_LARGE), fill=ctk.X, padx=Dimensions.PADX_LARGE)
        
        btn_container = ctk.CTkFrame(button_frame, fg_color="transparent")
        btn_container.pack(anchor="e", padx=Dimensions.PADY_SMALL)
        
        install_btn = ctk.CTkButton(
            btn_container,
            text="安装",
            fg_color=Colors.BUTTON,
            hover_color=Colors.BUTTON_HOVER,
            text_color="#ffffff",
            width=Dimensions.BUTTON_WIDTH,
            height=Dimensions.BUTTON_HEIGHT,
            corner_radius=Dimensions.CORNER_RADIUS_MEDIUM,
            font=self.create_font(14, "bold", logger=self.fonts_logger),
            command=self.start_installation
        )
        
        install_btn.pack(side="right", padx=Dimensions.PADX_MEDIUM)
        self.toggle_select_btn = ctk.CTkButton(
            btn_container,
            text="全选",
            fg_color=Colors.BUTTON,
            hover_color=Colors.BUTTON_HOVER,
            text_color=Colors.TEXT_WHITE,
            width=Dimensions.BUTTON_WIDTH,
            height=Dimensions.BUTTON_HEIGHT,
            corner_radius=Dimensions.CORNER_RADIUS_MEDIUM,
            font=self.create_font(14, "bold", logger=self.fonts_logger),
            command=self.toggle_select_all
        )
        self.toggle_select_btn.pack(side="right", padx=Dimensions.PADX_MEDIUM)

        update_btn = ctk.CTkButton(
            btn_container,
            text="更新",
            fg_color="#6B7280",
            hover_color="#4B5563",
            text_color="#ffffff",
            width=Dimensions.BUTTON_WIDTH,
            height=Dimensions.BUTTON_HEIGHT,
            corner_radius=Dimensions.CORNER_RADIUS_MEDIUM,
            font=self.create_font(14, "bold", logger=self.fonts_logger),
            command=self.open_update_window
        )
        update_btn.pack(side="left", padx=Dimensions.PADX_MEDIUM)
        
        cache_btn = ctk.CTkButton(
            btn_container,
            text="缓存",
            fg_color=Colors.BUTTON,
            hover_color=Colors.BUTTON_HOVER,
            text_color="#ffffff",
            width=Dimensions.BUTTON_WIDTH,
            height=Dimensions.BUTTON_HEIGHT,
            corner_radius=Dimensions.CORNER_RADIUS_MEDIUM,
            font=self.create_font(14, "bold", logger=self.fonts_logger),
            command=self.open_cache_window
        )
        cache_btn.pack(side="left", padx=Dimensions.PADX_MEDIUM)
        
        contact_label = ctk.CTkLabel(
            main_frame,
            text="作者：HelloGaoo & WHYOS | 用户需自觉遵守并履行协议。如果资源存在违规或侵犯了您的合法权益，请联系作者我们会及时删除。邮箱：gaoo1228@163.com",
            text_color=Colors.CONTACT_INFO,
            font=self.create_font(12, logger=self.fonts_logger),
            justify=ctk.CENTER
        )
        contact_label.pack(fill=ctk.X, pady=(Dimensions.PADY_SMALL, Dimensions.PADY_MEDIUM), padx=Dimensions.PADX_LARGE)
    
    def _create_software_checkboxes(self, parent):
        """创建软件复选框列表"""
        center_container = ctk.CTkFrame(parent, fg_color="transparent")
        center_container.pack(fill="both", expand=True, anchor="center")
        
        self.column_frames = []
        for i in range(5):
            col_frame = ctk.CTkFrame(center_container, fg_color="transparent")
            col_frame.grid(row=0, column=i, padx=Dimensions.PADX_SMALL, pady=Dimensions.PADY_SMALL, sticky="nsew")
            center_container.grid_columnconfigure(i, weight=1, uniform="columns")
            self.column_frames.append(col_frame)
        
        current_index = 0
        software_list = self.SOFTWARE_LIST
        items_per_column = len(software_list) // len(self.column_frames)
        remainder = len(software_list) % len(self.column_frames)
        
        for col_idx, col_frame in enumerate(self.column_frames):
            col_items = items_per_column + 1 if col_idx < remainder else items_per_column
            
            for i in range(col_items):
                if current_index < len(software_list):
                    software = software_list[current_index]
                    checkbox = ctk.CTkCheckBox(
                        col_frame,
                        text=software,
                        text_color=Colors.TEXT,
                        fg_color=Colors.BUTTON,
                        hover_color=Colors.HOVER,
                        border_color=Colors.CHECKBOX_BORDER,
                        checkmark_color=Colors.CHECKMARK,
                        border_width=Dimensions.CHECKBOX_BORDER_WIDTH,
                        corner_radius=Dimensions.CORNER_RADIUS_SMALL,
                        font=self.create_font(20, logger=self.fonts_logger),
                        command=lambda s=software: self._on_checkbox_change(s)
                    )
                    checkbox.pack(anchor="w", pady=(Dimensions.PADY_MEDIUM1, Dimensions.PADY_MEDIUM1), padx=Dimensions.PADX_SMALL, fill="x")
                    self.software_checkboxes[software] = checkbox
                    
                    if software in ["白板去除横幅"]:
                        checkbox.configure(state="disabled")
                    
                    current_index += 1
    
    def _on_checkbox_change(self, software):
        """处理软件复选框状态变化"""
        if software == "希沃输入法":
            if self.software_checkboxes[software].get() == 1:
                result = messagebox.askokcancel(
                    "SEEVVO全家桶一剑下崽弃",
                    "此输入法需要搭配希沃设备或者希沃键鼠使用"
                )
                if not result:
                    self.software_checkboxes[software].deselect()
        
        elif software == "希沃电脑助手":
            if self.software_checkboxes[software].get() == 1:
                result = messagebox.askokcancel(
                    "SEEVVO全家桶一剑下崽弃",
                    "此软件需要搭配希沃设备或者希沃键鼠使用，如果没有以上设备则需要账号授权"
                )
                if not result:
                    self.software_checkboxes[software].deselect()
        
        elif software == "PPT小工具" or software == "希沃课堂助手":
            if self.software_checkboxes[software].get() == 1:
                if software == "PPT小工具":
                    other_software = "希沃课堂助手"
                else:
                    other_software = "PPT小工具"
                
                if self.software_checkboxes[other_software].get() == 1:
                    result = messagebox.askokcancel(
                        "SEEVVO全家桶一剑下崽弃",
                        f"同时安装{software}和{other_software}会导致PPT工具重叠"
                    )
                    if not result:
                        self.software_checkboxes[software].deselect()
        
        elif software == "希沃课堂助手" or software == "希沃品课[教师端]":
            if self.software_checkboxes[software].get() == 1:
                if software == "希沃课堂助手":
                    other_software = "希沃品课[教师端]"
                else:
                    other_software = "希沃课堂助手"
                
                if self.software_checkboxes[other_software].get() == 1:
                    result = messagebox.askokcancel(
                        "SEEVVO全家桶一剑下崽弃",
                        "希沃品课(教师端)安装后课堂助手的PPT小工具有概率无法启用"
                    )
                    if not result:
                        self.software_checkboxes[software].deselect()
        
        elif software == "ClassIsland2" or software == "ClassWidgets":
            if self.software_checkboxes[software].get() == 1:
                if software == "ClassIsland2":
                    other_software = "ClassWidgets"
                else:
                    other_software = "ClassIsland2"
                
                if self.software_checkboxes[other_software].get() == 1:
                    result = messagebox.askokcancel(
                        "SEEVVO全家桶一剑下崽弃",
                        "同时安装课表软件：ClassIsland2和ClassWidgets 可能会导致功能冲突，建议选择其一安装"
                    )
                    if not result:
                        self.software_checkboxes[software].deselect()
        
        if software == "希沃品课[小组端]":
            if self.software_checkboxes[software].get() == 1:
                if self.software_checkboxes["希沃品课[教师端]"].get() == 1:
                    result = messagebox.askokcancel(
                        "SEEVVO全家桶一剑下崽弃",
                        "希沃品课[小组端]与希沃品课[教师端]同时安装会覆盖，是否继续选择？"
                    )
                    if not result:
                        self.software_checkboxes[software].deselect()
        elif software == "希沃品课[教师端]":
            if self.software_checkboxes[software].get() == 1:
                if self.software_checkboxes["希沃品课[小组端]"].get() == 1:
                    result = messagebox.askokcancel(
                        "SEEVVO全家桶一剑下崽弃",
                        "希沃品课[小组端]与希沃品课[教师端]同时安装会覆盖，是否继续选择？"
                    )
                    if not result:
                        self.software_checkboxes[software].deselect()
        

        
        selected_count = sum(1 for checkbox in self.software_checkboxes.values() if checkbox.get() == 1)
        total_count = len(self.software_checkboxes)
        self.is_all_selected = selected_count == total_count
        
        if self.is_all_selected:
            self.toggle_select_btn.configure(text="全不选")
        else:
            self.toggle_select_btn.configure(text="全选")
    
    def select_all(self):
        """全选所有可选软件"""
        excluded_software = ["希沃输入法", "希沃电脑助手", "希沃课堂助手", "希沃品课[教师端]", "希沃品课[小组端]", "白板去除横幅", "ClassIsland2", "ClassWidgets"]
        
        for software, checkbox in self.software_checkboxes.items():
            if software not in excluded_software:
                checkbox.select()
        self.is_all_selected = True
    
    def deselect_all(self):
        """取消全选所有可选软件"""
        excluded_software = ["白板去除横幅"]
        
        for software, checkbox in self.software_checkboxes.items():
            if software not in excluded_software:
                checkbox.deselect()
        self.is_all_selected = False
    
    def toggle_select_all(self):
        """切换全选/取消全选状态"""
        if self.is_all_selected:
            self.deselect_all()
            self.toggle_select_btn.configure(text="全选")
        else:
            self.select_all()
            self.toggle_select_btn.configure(text="全不选")

    def _on_source_change(self, choice):
        """处理下载源切换事件"""
        global current_source
        if set_download_source(choice):
            main_logger = get_logger("Main")
            main_logger.info(f"下载源已切换为: {DOWNLOAD_SOURCES[choice]['name']}")

    def start_installation(self):
        """开始安装所选软件"""
        main_logger = get_logger("Main")
        selected_software = [software for software, checkbox in self.software_checkboxes.items() if checkbox.get() == 1]
        
        if selected_software:
            main_logger.info(f"用户选择了 {len(selected_software)} 个软件进行安装: {', '.join(selected_software)}")
            if hasattr(self, 'install_window') and self.install_window is not None:
                try:
                    main_logger.info("更新现有安装窗口的软件列表")
                    self.install_window.selected_software = selected_software
                    self.install_window._refresh_table()
                    self.install_window.root.focus_force()
                except (AttributeError, TclError):
                    main_logger.info("现有安装窗口已关闭，创建新的安装窗口")
                    self.install_window = InstallationWindow(selected_software, self, self.retain_installer_var.get())
            else:
                main_logger.info("创建新的安装窗口")
                self.install_window = InstallationWindow(selected_software, self, self.retain_installer_var.get())
            
            main_logger.info("隐藏主窗口")
            try:
                if hasattr(self, 'root') and self.root.winfo_exists():
                    self.root.withdraw()
            except Exception:
                main_logger.warning("隐藏主窗口失败，可能窗口已被销毁")
        else:
            main_logger.info("用户尝试安装，但未选择任何软件")

    def open_update_window(self):
        """打开更新窗口"""
        main_logger = get_logger("Main")
        main_logger.info("用户打开更新窗口")
        
        self.update_window = UpdateWindow(self)
        
        main_logger.info("隐藏主窗口")
        try:
            if hasattr(self, 'root') and self.root.winfo_exists():
                self.root.withdraw()
        except Exception:
            main_logger.warning("隐藏主窗口失败，可能窗口已被销毁")

    def open_cache_window(self):
        """打开缓存窗口"""
        main_logger = get_logger("Main")
        selected_software = [software for software, checkbox in self.software_checkboxes.items() if checkbox.get() == 1]

        if selected_software:
            main_logger.info(f"用户选择了 {len(selected_software)} 个软件进行缓存: {', '.join(selected_software)}")
            if hasattr(self, 'cache_window') and self.cache_window is not None:
                try:
                    main_logger.info("更新现有缓存窗口的软件列表")
                    self.cache_window.selected_software = selected_software
                    self.cache_window._refresh_table()
                    self.cache_window.root.focus_force()
                except (AttributeError, TclError):
                    main_logger.info("现有缓存窗口已关闭，创建新的缓存窗口")
                    self.cache_window = CacheWindow(selected_software, self)
            else:
                main_logger.info("创建新的缓存窗口")
                self.cache_window = CacheWindow(selected_software, self)

            main_logger.info("隐藏主窗口")
            try:
                if hasattr(self, 'root') and self.root.winfo_exists():
                    self.root.withdraw()
            except Exception:
                main_logger.warning("隐藏主窗口失败，可能窗口已被销毁")
        else:
            main_logger.info("用户尝试缓存，但未选择任何软件")
    
    def _check_network_availability(self):
        """检查网络连接是否可用"""
        main_logger = get_logger("Main")
        try:
            dns_servers = [
                ("8.8.8.8", 53),
                ("1.1.1.1", 53),
                ("180.76.76.76", 53),
                ("223.5.5.5", 53)
            ]
            
            for server, port in dns_servers:
                try:
                    socket.create_connection((server, port), timeout=3)
                    main_logger.info(f"网络连接可用（通过 {server}:{port}）")
                    return True
                except Exception as err:
                    main_logger.warning(f"连接到 {server}:{port} 失败: {err}")
            
            # 所有服务器都连接失败
            main_logger.warning("所有DNS服务器连接失败，网络连接不可用")
            return False
        except Exception as err:
            main_logger.warning(f"网络连接检查出错: {err}")
            return False
    
    def _check_update_status(self):
        """检查是否有新版本可用"""
        main_logger = get_logger("Main")
        github_path = "/HelloGaoo/SeevvoDownloader/releases/download/v1.0.0/Version.ini"
        main_logger.info("静默检查更新")
        
        def fetch_version(source_key):
            try:
                prefix = DOWNLOAD_SOURCES[source_key]["prefix"]
                url = f"{prefix}{github_path}"
                response = requests.get(url, timeout=10, verify=False)
                if response.status_code == 200:
                    content = response.content.decode('utf-8').strip()
                    if content:
                        return (source_key, content.split('\n')[0].strip(), None)
                return (source_key, None, f"状态码: {response.status_code}")
            except Exception as err:
                return (source_key, None, str(err))
        
        results = []
        with concurrent_futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = {executor.submit(fetch_version, key): key for key in DOWNLOAD_SOURCES.keys()}
            for future in concurrent_futures.as_completed(futures):
                source_key, version, error = future.result()
                if version:
                    main_logger.info(f"从 {DOWNLOAD_SOURCES[source_key]['name']} 获取到版本号: {version}")
                    results.append((source_key, version))
                    for f in futures:
                        f.cancel()
                    break
                elif error:
                    main_logger.warning(f"从 {DOWNLOAD_SOURCES[source_key]['name']} 获取失败: {error}")
        
        if not results:
            main_logger.error("所有下载源都无法获取版本信息")
            return False
        
        _, latest_version = results[0]
        current_version = self.VERSION[1:] if self.VERSION.startswith("v") else self.VERSION
        latest_version_clean = latest_version[1:] if latest_version.startswith("v") else latest_version
        
        current_parts = list(map(int, current_version.split(".")))
        latest_parts = list(map(int, latest_version_clean.split(".")))
        
        if latest_parts > current_parts:
            main_logger.info("检测到新版本")
            return True
        else:
            main_logger.info("当前版本为最新")
            return False
    
    def run(self):
        """运行应用程序主循环"""
        main_logger = get_logger("Main")
        main_logger.info("应用程序开始运行")
        main_logger.info("主窗口进入事件循环")
        
        try:
            self.root.mainloop()
        except Exception as err:
            main_logger.critical(f"应用程序运行异常: {err}", exc_info=True)
        finally:
            main_logger.info("主窗口事件循环结束")
            main_logger.info("应用程序退出")

class UpdateWindow:
    VERSION = MainWindowApp.VERSION
    CURRENT_VERSION = VERSION
    def __init__(self, main_window=None):
        self.update_logger = get_logger("Update")
        self.update_logger.info("更新窗口初始化开始")
        
        self.root = ctk.CTkToplevel()
        self.root.title(f"SEEVVO全家桶一剑下崽弃 {self.VERSION} - 软件更新 - 作者：HelloGaoo & WHYOS")
        self.root.geometry(f"{Dimensions.INSTALL_WINDOW_WIDTH}x{Dimensions.INSTALL_WINDOW_HEIGHT}")  # 设置初始尺寸
        self.root.minsize(Dimensions.INSTALL_WINDOW_MIN_WIDTH, Dimensions.INSTALL_WINDOW_MIN_HEIGHT)  # 设置最小尺寸
        self.root.resizable(True, True)  # 允许调整窗口大小
        self.update_logger.info(f"更新窗口创建完成，初始尺寸: {Dimensions.INSTALL_WINDOW_WIDTH}x{Dimensions.INSTALL_WINDOW_HEIGHT}")
        
        self.root.focus_force()
        self.root.attributes("-alpha", 1.0)
        self.root.update_idletasks()
        
        self.root.protocol("WM_DELETE_WINDOW", self._on_window_close)
        
        try:
            icon_path = os.path.join(BASE_DIR, "icon", "001.ico")
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
                self.update_logger.info("更新窗口图标设置成功")
        except Exception as err:
            self.update_logger.error(f"设置更新窗口图标时出错: {err}")
        
        self.fonts_logger = get_logger("Fonts")
        self.create_font = create_global_font
        
        self._main_window = main_window
        
        # 初始化版本信息
        self.latest_version = ""
        self.changelogs = ""
        self.update_status = ""
        self.is_checking_update = False
        
        self.update_logger.info("更新窗口初始化完成")
        
        self.executor = None
        
        self._create_all_widgets()
        self._check_for_updates()
    
    def _create_all_widgets(self):
        main_frame = ctk.CTkFrame(self.root, fg_color=Colors.BACKGROUND, corner_radius=0)
        main_frame.pack(fill=ctk.BOTH, expand=True, padx=0, pady=0)
        
        content_container = ctk.CTkFrame(main_frame, fg_color=Colors.BACKGROUND)
        content_container.pack(fill=ctk.BOTH, expand=True, padx=Dimensions.PADX_LARGE, pady=(Dimensions.PADY_XLARGE, Dimensions.PADY_SMALL))
        
        card_frame = ctk.CTkFrame(
            content_container,
            corner_radius=Dimensions.CORNER_RADIUS_LARGE,
            border_width=Dimensions.BORDER_WIDTH,
            border_color=Colors.BORDER,
            fg_color=Colors.CARD_BACKGROUND
        )
        card_frame.pack(fill=ctk.BOTH, expand=True, padx=0, pady=0)
        
        title_bar = ctk.CTkFrame(
            card_frame,
            fg_color=Colors.CARD_BACKGROUND,
            border_width=0,
            corner_radius=0
        )
        title_bar.pack(fill=ctk.X, padx=Dimensions.PADX_LARGE, pady=(Dimensions.PADY_LARGE, Dimensions.PADY_MEDIUM))
        
        title_label = ctk.CTkLabel(
            title_bar,
            text="软件更新",
            text_color=Colors.TEXT,
            font=self.create_font(24, "bold", logger=self.fonts_logger)
        )
        title_label.pack(anchor="w")
        
        divider = ctk.CTkFrame(
            card_frame,
            fg_color=Colors.SECTION_DIVIDER,
            border_width=0,
            height=1
        )
        divider.pack(fill=ctk.X, padx=Dimensions.PADX_LARGE)
        
        update_content_frame = ctk.CTkFrame(
            card_frame,
            fg_color=Colors.LIST_BACKGROUND,
            border_color=Colors.SECTION_DIVIDER,
            border_width=Dimensions.BORDER_WIDTH,
            corner_radius=Dimensions.CORNER_RADIUS_MEDIUM
        )
        update_content_frame.pack(fill=ctk.BOTH, expand=True, padx=Dimensions.PADX_LARGE, pady=Dimensions.PADY_LARGE)
        
        version_frame = ctk.CTkFrame(update_content_frame, fg_color="transparent")
        version_frame.pack(fill=ctk.X, padx=Dimensions.PADX_LARGE, pady=(Dimensions.PADY_LARGE, Dimensions.PADY_MEDIUM))
        
        version_horizontal_frame = ctk.CTkFrame(version_frame, fg_color="transparent")
        version_horizontal_frame.pack(fill=ctk.X, padx=0, pady=0)
        
        VERSION_label = ctk.CTkLabel(
            version_horizontal_frame,
            text=f"当前版本: {self.VERSION}",
            text_color=Colors.TEXT,
            font=self.create_font(20, logger=self.fonts_logger)
        )
        VERSION_label.pack(side="left", padx=Dimensions.PADX_MEDIUM, pady=Dimensions.PADY_SMALL)
        
        self.latest_version_label = ctk.CTkLabel(
            version_horizontal_frame,
            text="最新版本: 获取中",
            text_color=Colors.TEXT,
            font=self.create_font(20, logger=self.fonts_logger)
        )
        self.latest_version_label.pack(side="left", padx=Dimensions.PADX_MEDIUM, pady=Dimensions.PADY_SMALL)
        
        self.update_status_label = ctk.CTkLabel(
            version_horizontal_frame,
            text="更新状态: 获取中",
            text_color=Colors.TEXT,
            font=self.create_font(20, logger=self.fonts_logger)
        )
        self.update_status_label.pack(side="left", padx=Dimensions.PADX_MEDIUM, pady=Dimensions.PADY_SMALL)
        
        changelog_title_label = ctk.CTkLabel(
            update_content_frame,
            text="更新日志:",
            text_color=Colors.TEXT,
            font=self.create_font(16, "bold", logger=self.fonts_logger)
        )
        changelog_title_label.pack(anchor="w", padx=Dimensions.PADX_LARGE, pady=(Dimensions.PADY_LARGE, Dimensions.PADY_SMALL))
        
        self.changelog_text = ctk.CTkTextbox(
            update_content_frame,
            fg_color=Colors.BACKGROUND,
            text_color=Colors.TEXT,
            border_color=Colors.SECTION_DIVIDER,
            border_width=Dimensions.BORDER_WIDTH,
            corner_radius=Dimensions.CORNER_RADIUS_MEDIUM,
            font=self.create_font(19, logger=self.fonts_logger),
            height=200
        )
        self.changelog_text.pack(fill=ctk.BOTH, expand=True, padx=Dimensions.PADX_LARGE, pady=Dimensions.PADY_SMALL)
        self.changelog_text.insert("0.0", "正在获取更新日志")
        self.changelog_text.configure(state="disabled")
        
        download_progress_frame = ctk.CTkFrame(
            card_frame,
            fg_color=Colors.CARD_BACKGROUND,
            border_width=0
        )
        download_progress_frame.pack(fill=ctk.X, padx=Dimensions.PADX_LARGE, pady=(Dimensions.PADY_MEDIUM, Dimensions.PADY_SMALL))
        
        progress_info_frame = ctk.CTkFrame(download_progress_frame, fg_color="transparent")
        progress_info_frame.pack(fill=ctk.X, padx=0, pady=(0, Dimensions.PADY_SMALL))
        
        self.download_percentage_label = ctk.CTkLabel(
            progress_info_frame,
            text="0.0%",
            text_color=Colors.TEXT,
            font=self.create_font(13, "bold", logger=self.fonts_logger)
        )
        self.download_percentage_label.pack(side="left", padx=0)
        
        self.download_speed_label = ctk.CTkLabel(
            progress_info_frame,
            text="0 B/s",
            text_color=Colors.TEXT_SECONDARY,
            font=self.create_font(13, logger=self.fonts_logger)
        )
        self.download_speed_label.pack(side="left", padx=(Dimensions.PADX_MEDIUM, 0))
        
        self.download_progress_bar = ctk.CTkProgressBar(
            download_progress_frame,
            fg_color=Colors.SECTION_DIVIDER,
            progress_color="#3B8ED0",
            border_width=0,
            corner_radius=Dimensions.CORNER_RADIUS_SMALL,
            height=12
        )
        self.download_progress_bar.pack(fill=ctk.X, pady=0)
        self.download_progress_bar.set(0)
        
        self.download_status_label = ctk.CTkLabel(
            download_progress_frame,
            text="等待下载...",
            text_color=Colors.TEXT_SECONDARY,
            font=self.create_font(12, logger=self.fonts_logger)
        )
        self.download_status_label.pack(anchor="w", pady=(Dimensions.PADY_SMALL, 0))
        
        button_frame = ctk.CTkFrame(card_frame, fg_color=Colors.CARD_BACKGROUND, border_width=0)
        button_frame.pack(pady=(0, Dimensions.PADY_LARGE), fill=ctk.X, padx=Dimensions.PADX_LARGE)
        
        self.update_btn = ctk.CTkButton(
            button_frame,
            text="更新",
            fg_color=Colors.BUTTON,
            hover_color=Colors.BUTTON_HOVER,
            text_color=Colors.TEXT_WHITE,
            width=Dimensions.BUTTON_WIDTH,
            height=Dimensions.BUTTON_HEIGHT,
            corner_radius=Dimensions.CORNER_RADIUS_MEDIUM,
            font=self.create_font(14, "bold", logger=self.fonts_logger),
            command=self._on_update_click,
            state=ctk.DISABLED
        )
        self.update_btn.pack(side="right", padx=Dimensions.PADX_MEDIUM)
        
        contact_label = ctk.CTkLabel(
            main_frame,
            text="作者：HelloGaoo & WHYOS | 用户需自觉遵守并履行协议。如果资源存在违规或侵犯了您的合法权益，请联系作者我们会及时删除。邮箱：gaoo1228@163.com",
            text_color=Colors.CONTACT_INFO,
            font=self.create_font(12, logger=self.fonts_logger),
            justify=ctk.CENTER
        )
        contact_label.pack(fill=ctk.X, pady=(Dimensions.PADY_SMALL, Dimensions.PADY_MEDIUM), padx=Dimensions.PADX_LARGE)
        
    def _check_for_updates(self):
        self.update_logger.info("开始检查更新")
        self.is_checking_update = True
        
        update_thread = threading.Thread(target=self._fetch_update_info)
        update_thread.daemon = True
        update_thread.start()
    
    def _fetch_update_info(self):
        try:
            version_url = get_github_url("/HelloGaoo/SeevvoDownloader/releases/download/v1.0.0/Version.ini")
            self.update_logger.info(f"获取最新版本号和强制更新标志: {version_url}")
            
            # 带重试的请求
            max_retries = 1
            retry_count = 0
            while retry_count <= max_retries:
                try:
                    self.update_logger.info(f"请求 {version_url} (尝试 {retry_count+1}/{max_retries+1})")
                    response = requests.get(version_url, timeout=10, verify=False)
                    break
                except Exception as e:
                    retry_count += 1
                    if retry_count > max_retries:
                        raise
                    self.update_logger.warning(f"请求失败，正在重试: {e}")
            if response.status_code == 200:
                lines = response.content.decode('utf-8').strip().split('\n')
                if len(lines) > 0:
                    self.latest_version = lines[0].strip()
                    self.update_logger.info(f"获取到最新版本号: {self.latest_version}")
                else:
                    self.latest_version = self.CURRENT_VERSION
                    self.update_logger.error("Version.ini文件为空")
                
                # 第二行作为强制更新标志
                self.force_update = False
                if len(lines) > 1:
                    force_update_str = lines[1].strip().lower()
                    self.force_update = force_update_str in ["true", "1", "yes", "y"]
                    self.update_logger.info(f"获取到强制更新标志: {self.force_update}")
                else:
                    self.force_update = False
                    self.update_logger.info("Version.ini文件没有第二行，默认为非强制更新")
            else:
                self.update_logger.error(f"获取最新版本号失败，状态码: {response.status_code}")
                self.latest_version = self.CURRENT_VERSION
                self.force_update = False
            
            # 获取更新日志
            changelog_url = get_github_url("/HelloGaoo/SeevvoDownloader/releases/download/v1.0.0/Changelogs.txt")
            self.update_logger.info(f"获取更新日志: {changelog_url}")
            
            # 带重试的请求
            max_retries = 1
            retry_count = 0
            while retry_count <= max_retries:
                try:
                    self.update_logger.info(f"请求 {changelog_url} (尝试 {retry_count+1}/{max_retries+1})")
                    response = requests.get(changelog_url, timeout=10, verify=False)
                    break
                except Exception as err:
                    retry_count += 1
                    if retry_count > max_retries:
                        raise
                    self.update_logger.warning(f"请求失败，正在重试: {err}")
            if response.status_code == 200:
                self.changelogs = response.text
                self.update_logger.info(f"获取到更新日志")
            else:
                self.update_logger.error(f"获取更新日志失败，状态码: {response.status_code}")
                self.changelogs = "无法获取更新日志"
            
            # 版本比对
            self._compare_versions()
            
            # 更新UI
            self.root.after(0, self._update_ui)
            
        except Exception as err:
            self.update_logger.error(f"获取更新信息失败: {err}", exc_info=True)
            self.latest_version = self.VERSION
            self.changelogs = "获取更新信息时出错"
            self.update_status = "检查失败"
            self.force_update = False
            
            self.root.after(0, self._update_ui)
        finally:
            # 检查更新完成，重置标志
            self.is_checking_update = False
            self.update_logger.info("检查更新完成")
    
    def _compare_versions(self):
        try:
            current_version = self.CURRENT_VERSION[1:] if self.CURRENT_VERSION.startswith("v") else self.CURRENT_VERSION
            latest_version = self.latest_version[1:] if self.latest_version.startswith("v") else self.latest_version
            
            current_parts = list(map(int, current_version.split(".")))
            latest_parts = list(map(int, latest_version.split(".")))
            
            if latest_parts > current_parts:
                self.update_status = "有新版本"
            else:
                self.update_status = "最新"
            
            self.update_logger.info(f"版本比对结果: {self.update_status}")
        except Exception as err:
            self.update_logger.error(f"版本比对失败: {err}", exc_info=True)
            self.update_status = "比对失败"
    
    def _update_ui(self):
        """更新UI显示"""
        try:
            self.latest_version_label.configure(text=f"最新版本: {self.latest_version}")
            
            if self.update_status == "有新版本":
                if self.force_update:
                    status_text = "有新版本（强制更新）"
                    status_color = Colors.ACCENT
                else:
                    status_text = "有新版本"
                    status_color = Colors.ACCENT
            else:
                status_text = self.update_status
                status_color = Colors.TEXT
            self.update_status_label.configure(text=f"更新状态: {status_text}", text_color=status_color)
            
            self.changelog_text.configure(state="normal")
            self.changelog_text.delete("0.0", ctk.END)
            self.changelog_text.insert("0.0", self.changelogs)
            self.changelog_text.configure(state="disabled")
            
            if hasattr(self, 'update_btn'):
                self.update_btn.configure(state=ctk.NORMAL)
            
        except Exception as err:
            self.update_logger.error(f"更新UI失败: {err}", exc_info=True)
    
    def _on_update_click(self):
        if self.update_status == "最新" or self.update_status == "检查失败" or self.update_status == "比对失败":
            if self.update_status == "最新":
                self.update_logger.info("当前已是最新版本，无需更新")
                messagebox.showinfo("SEEVVO全家桶一剑下崽弃", "当前已是最新版本，无需更新。")
            else:
                self.update_logger.info(f"{self.update_status}，无法更新")
                messagebox.showinfo("SEEVVO全家桶一剑下崽弃", f"{self.update_status}，无法进行更新操作。")
            return
        
        # 检查是否正在下载
        if hasattr(self, '_is_downloading') and self._is_downloading:
            self.update_logger.info("正在下载更新，请稍候")
            messagebox.showinfo("SEEVVO全家桶一剑下崽弃", "正在下载更新，请稍候。")
            return
        
        # 禁用更新按钮，防止重复点击
        self.update_btn.configure(state=ctk.DISABLED, text="下载中...")
        
        self._is_downloading = True
        self._download_cancelled = False
        
        self.download_percentage_label.configure(text="0.0%")
        self.download_speed_label.configure(text="0 B/s")
        self.download_status_label.configure(text="正在准备下载...")
        self.download_progress_bar.set(0)
        
        download_thread = threading.Thread(target=self._download_update)
        download_thread.daemon = True
        download_thread.start()
    
    def _download_update(self):
        try:
            download_url = get_github_url("/HelloGaoo/SeevvoDownloader/releases/download/v2.0.0/Update.7z")
            self.update_logger.info(f"开始下载更新文件: {download_url}")
            
            self.root.after(0, lambda: self.download_status_label.configure(text="正在连接服务器..."))
            
            try:
                head_response = requests.head(download_url, timeout=10, verify=False, allow_redirects=True)
                total_size = int(head_response.headers.get('content-length', 0))
                self.update_logger.info(f"文件总大小: {total_size} 字节")
            except Exception as err:
                self.update_logger.warning(f"无法获取文件大小: {err}")
                total_size = 0
            
            response = requests.get(download_url, stream=True, timeout=30, verify=False)
            
            if response.status_code != 200:
                raise Exception(f"下载失败，状态码: {response.status_code}")
            
            if total_size == 0:
                total_size = int(response.headers.get('content-length', 0))
            
            temp_dir = os.path.join(BASE_DIR, "Update")
            os.makedirs(temp_dir, exist_ok=True)
            temp_file = os.path.join(temp_dir, "Update.7z")
            
            downloaded_size = 0
            start_time = time.time()
            last_update_time = start_time
            last_downloaded_size = 0
            
            self.root.after(0, lambda: self.download_status_label.configure(text="正在下载..."))
            
            with open(temp_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if self._download_cancelled:
                        self.update_logger.info("下载已取消")
                        return
                    
                    if chunk:
                        f.write(chunk)
                        downloaded_size += len(chunk)
                        
                        current_time = time.time()
                        time_elapsed = current_time - last_update_time
                        
                        if time_elapsed >= 0.1:
                            speed = (downloaded_size - last_downloaded_size) / time_elapsed
                            
                            if total_size > 0:
                                percentage = (downloaded_size / total_size) * 100
                            else:
                                percentage = 0
                            
                            self.root.after(0, lambda p=percentage, s=speed, d=downloaded_size, t=total_size: self._update_download_progress(p, s, d, t))
                            
                            last_update_time = current_time
                            last_downloaded_size = downloaded_size
            
            self.update_logger.info("下载完成")
            
            self.root.after(0, lambda: self._update_download_progress(100, 0, total_size, total_size))
            self.root.after(0, lambda: self.download_status_label.configure(text="下载完成，正在准备更新..."))
            
            self._prepare_update(temp_file)
            
        except Exception as err:
            self.update_logger.error(f"下载更新失败: {err}", exc_info=True)
            self._is_downloading = False
            self.root.after(0, lambda: self._on_download_error(str(err)))
    
    def _update_download_progress(self, percentage, speed, downloaded, total):
        """更新下载进度显示"""
        try:
            self.download_progress_bar.set(percentage / 100)
            
            self.download_percentage_label.configure(text=f"{percentage:.1f}%")
            
            if speed > 0:
                if speed < 1024:
                    speed_text = f"{speed:.1f} B/s"
                elif speed < 1024 * 1024:
                    speed_text = f"{speed / 1024:.1f} KB/s"
                else:
                    speed_text = f"{speed / (1024 * 1024):.1f} MB/s"
                self.download_speed_label.configure(text=speed_text)
            
            def format_size(size):
                if size < 1024:
                    return f"{size} B"
                elif size < 1024 * 1024:
                    return f"{size / 1024:.1f} KB"
                else:
                    return f"{size / (1024 * 1024):.1f} MB"
            
            if total > 0:
                status_text = f"已下载: {format_size(downloaded)} / {format_size(total)}"
            else:
                status_text = f"已下载: {format_size(downloaded)}"
            self.download_status_label.configure(text=status_text)
            
        except Exception as err:
            self.update_logger.error(f"更新下载进度失败: {err}")
    
    def _prepare_update(self, downloaded_file):
        try:
            self.root.after(0, lambda: self.download_status_label.configure(text="正在解压更新文件..."))
            
            # 获取当前程序路径
            current_exe = sys.executable if getattr(sys, 'frozen', False) else __file__
            app_dir = BASE_DIR
            
            # 解压目录
            extract_dir = os.path.join(BASE_DIR, "Update", "update_extract")
            os.makedirs(extract_dir, exist_ok=True)
            
            # 7z解压密码
            SEVEN_ZIP_PASSWORD = 'zQt83iOY3xXLfDVg6SJ7ocnapy90I1d62w6jh79WlT0m1qPC8b55HU5Nk4ARZFBs'
            
            # 使用7z解压
            seven_zip_path = os.path.join(BASE_DIR, "Tools", "7z.exe")
            
            if not os.path.exists(seven_zip_path):
                raise Exception("找不到7z.exe解压工具")
            
            # 解压命令
            extract_cmd = [
                seven_zip_path,
                "x",
                f"-p{SEVEN_ZIP_PASSWORD}",
                "-o" + extract_dir,
                "-y",
                downloaded_file
            ]
            
            self.update_logger.info(f"解压更新文件: {downloaded_file}")
            
            result = subprocess.run(extract_cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise Exception(f"解压失败: {result.stderr}")
            
            self.update_logger.info("解压完成")
            
            # 更新UI状态
            self.root.after(0, lambda: self.download_status_label.configure(text="正在准备更新..."))
            
            # 创建更新批处理文件
            update_bat = os.path.join(BASE_DIR, "Update", "apply_update.bat")
            
            # 批处理内容：强制终止主进程，然后复制所有文件并启动新版本
            bat_content = f'''@echo off
chcp 65001 >nul
title SEEVVO更新程序
echo 正在准备更新...

echo 正在终止主程序...
taskkill /F /IM "SEEVVO全家桶一剑下崽弃.exe" >nul 2>&1
ping 127.0.0.1 -n 3 >nul

echo 正在应用更新...
robocopy "{extract_dir}" "{app_dir}" /E /IS /R:3 /W:2
if errorlevel 8 (
    echo 更新失败！
    pause
    exit /b 1
)

echo 更新完成！

cd /d "{app_dir}"

if exist "{app_dir}\\Update.bat" (
    echo 正在运行更新脚本...
    start "" "{app_dir}\\Update.bat"
    echo 等待更新脚本完成（最多3分钟）...
    ping 127.0.0.1 -n 181 >nul
)

echo 正在启动新版本...
start "" "{current_exe}"
exit
'''
            
            with open(update_bat, 'w', encoding='utf-8') as f:
                f.write(bat_content)
            
            self.update_logger.info(f"创建更新批处理文件: {update_bat}")
            
            # 提示用户
            self.root.after(0, lambda: messagebox.showinfo("SEEVVO全家桶一剑下崽弃", "下载完成！程序将关闭并应用更新。"))
            
            # 运行更新批处理 - 使用os.startfile方式
            os.system(f'start "" "{update_bat}"')
            
            # 关闭当前程序
            self._is_downloading = False
            self.root.after(500, self._exit_program)
            
        except Exception as e:
            self.update_logger.error(f"准备更新失败: {e}", exc_info=True)
            self._is_downloading = False
            self.root.after(0, lambda: messagebox.showerror("SEEVVO全家桶一剑下崽弃", f"准备更新失败: {e}"))
            self.root.after(0, self._reset_update_button)
    
    def _on_download_error(self, error_message):
        messagebox.showerror("SEEVVO全家桶一剑下崽弃", f"下载更新失败: {error_message}")
        self._reset_update_button()
    
    def _reset_update_button(self):
        try:
            self.update_btn.configure(state=ctk.NORMAL, text="更新")
            self.download_progress_bar.set(0)
            self.download_percentage_label.configure(text="")
            self.download_speed_label.configure(text="")
            self.download_status_label.configure(text="")
        except Exception:
            pass
    
    def _exit_program(self):
        try:
            os._exit(0)
        except Exception:
            sys.exit(0)
    
    def _on_window_close(self):
        self.update_logger.info("更新窗口关闭事件触发")
        
        if self.force_update and self.update_status == "有新版本":
            self.update_logger.info("强制更新模式，弹出提示")
            messagebox.showinfo("SEEVVO全家桶一剑下崽弃", "当前版本过低，必须更新才能继续使用！")
            return
        
        # 标记检查更新已停止
        self.is_checking_update = False
        
        # 显示主窗口
        if self._main_window and hasattr(self._main_window, 'root'):
            try:
                if self._main_window.root.winfo_exists():
                    self._main_window.root.deiconify()
            except Exception:
                pass
        
        # 销毁更新窗口
        self.update_logger.info("销毁更新窗口")
        try:
            self.root.destroy()
        except Exception:
            pass

class InstallationWindow:
    def __init__(self, selected_software, main_window=None, retain_installer=False):
        self.installer_logger = get_logger("Installer")
        self.installer_logger.info("安装窗口初始化开始")
        
        self.root = ctk.CTkToplevel()
        self.root.title(f"SEEVVO全家桶一剑下崽弃 {MainWindowApp.VERSION} - 软件安装 - 作者：HelloGaoo & WHYOS")
        self.root.geometry(f"{Dimensions.INSTALL_WINDOW_WIDTH}x{Dimensions.INSTALL_WINDOW_HEIGHT}")  # 设置初始尺寸
        self.root.minsize(Dimensions.INSTALL_WINDOW_MIN_WIDTH, Dimensions.INSTALL_WINDOW_MIN_HEIGHT)  # 设置最小尺寸
        self.root.resizable(True, True)  # 允许调整窗口大小
        self.installer_logger.info(f"安装窗口创建完成，初始尺寸: {Dimensions.INSTALL_WINDOW_WIDTH}x{Dimensions.INSTALL_WINDOW_HEIGHT}")
        
        self.root.focus_force()
        self.root.attributes("-alpha", 1.0)
        self.root.update_idletasks()
        
        self.root.protocol("WM_DELETE_WINDOW", self._on_window_close)
        
        try:
            icon_path = os.path.join(BASE_DIR, "icon", "001.ico")
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
                self.installer_logger.info("安装窗口图标设置成功")
        except Exception as err:
            self.installer_logger.error(f"设置安装窗口图标时出错: {err}")
        
        self.fonts_logger = get_logger("Fonts")
        self.create_font = create_global_font
        
        self._main_window = main_window
        self.retain_installer = retain_installer
        self.installer_logger.info(f"保留安装包选项: {retain_installer}")
        
        self.selected_software = selected_software
        self.installer_logger.info(f"安装窗口初始化完成，共 {len(selected_software)} 个软件待安装")
        self._initializing = True
        
        self.executor = None
        
        self.table_frame = None
        self.scrollable_frame = None
        self.col_widths = None
        self.table_rows = {}
        
        self.download_rate_limit = getattr(self, 'download_rate_limit', 0)
        self.progress_update_interval = 0.5
        
        self._summary_state = {sw: 'not_started' for sw in self.selected_software}
        
        self._create_all_widgets()
        
    def _create_all_widgets(self):
        main_frame = ctk.CTkFrame(self.root, fg_color=Colors.BACKGROUND, corner_radius=0)
        main_frame.pack(fill=ctk.BOTH, expand=True, padx=0, pady=0)
        
        content_container = ctk.CTkFrame(main_frame, fg_color=Colors.BACKGROUND)
        content_container.pack(fill=ctk.BOTH, expand=True, padx=Dimensions.PADX_LARGE, pady=(Dimensions.PADY_XLARGE, Dimensions.PADY_SMALL))
        
        card_frame = ctk.CTkFrame(
            content_container,
            corner_radius=Dimensions.CORNER_RADIUS_LARGE,
            border_width=Dimensions.BORDER_WIDTH,
            border_color=Colors.BORDER,
            fg_color=Colors.CARD_BACKGROUND
        )
        card_frame.pack(fill=ctk.BOTH, expand=True, padx=0, pady=0)
        
        title_bar = ctk.CTkFrame(
            card_frame,
            fg_color=Colors.CARD_BACKGROUND,
            border_width=0,
            corner_radius=0
        )
        title_bar.pack(fill=ctk.X, padx=Dimensions.PADX_LARGE, pady=(Dimensions.PADY_LARGE, Dimensions.PADY_MEDIUM))
        
        title_label = ctk.CTkLabel(
            title_bar,
            text="软件安装",
            text_color=Colors.TEXT,
            font=self.create_font(24, "bold", logger=self.fonts_logger)
        )
        title_label.pack(anchor="w")
        
        divider = ctk.CTkFrame(
            card_frame,
            fg_color=Colors.SECTION_DIVIDER,
            border_width=0,
            height=1
        )
        divider.pack(fill=ctk.X, padx=Dimensions.PADX_LARGE)
        
        table_container = ctk.CTkFrame(
            card_frame,
            fg_color=Colors.CARD_BACKGROUND,
            border_width=0,
            corner_radius=0
        )
        table_container.pack(fill=ctk.BOTH, expand=True, padx=Dimensions.PADX_LARGE, pady=Dimensions.PADY_LARGE)

        self.summary_frame = ctk.CTkFrame(card_frame, fg_color=Colors.CARD_BACKGROUND, border_width=0)
        self.summary_frame.pack(fill=ctk.X, padx=Dimensions.PADX_LARGE, pady=(0, Dimensions.PADY_SMALL))
        self.summary_status_label = ctk.CTkLabel(
            self.summary_frame,
            text="状态：未开始    完成：成功 0，失败 0",
            text_color=Colors.TEXT_SECONDARY,
            font=self.create_font(16, logger=self.fonts_logger),
            anchor="w"
        )
        self.summary_status_label.pack(anchor="w", padx=Dimensions.PADX_MEDIUM, pady=(Dimensions.PADY_SMALL, 0))

        try:
            self._summary_state = {sw: 'not_started' for sw in self.selected_software}
            try:
                self._recalculate_summary_label()
            except Exception:
                pass
        except Exception:
            pass

        self._create_table(table_container)

        button_frame = ctk.CTkFrame(card_frame, fg_color=Colors.CARD_BACKGROUND, border_width=0)
        button_frame.pack(pady=(0, Dimensions.PADY_LARGE), fill=ctk.X, padx=Dimensions.PADX_LARGE)
        
        btn_container = ctk.CTkFrame(button_frame, fg_color="transparent")
        btn_container.pack(anchor="e", padx=Dimensions.PADY_SMALL)
        
        # 开始按钮
        self.start_btn = ctk.CTkButton(
            btn_container,
            text="开始",
            fg_color=Colors.BUTTON,
            hover_color=Colors.BUTTON_HOVER,
            text_color="#ffffff",
            width=Dimensions.BUTTON_WIDTH,
            height=Dimensions.BUTTON_HEIGHT,
            corner_radius=Dimensions.CORNER_RADIUS_MEDIUM,
            font=self.create_font(14, "bold", logger=self.fonts_logger),
            command=self.start_installation_process
        )
        self.start_btn.pack(side="right", padx=Dimensions.PADX_MEDIUM)
        
        # 添加联系信息到主框架底部
        contact_label = ctk.CTkLabel(
            main_frame,
            text="作者：HelloGaoo & WHYOS | 用户需自觉遵守并履行协议。如果资源存在违规或侵犯了您的合法权益，请联系作者我们会及时删除。邮箱：gaoo1228@163.com",
            text_color=Colors.CONTACT_INFO,
            font=self.create_font(12, logger=self.fonts_logger),
            justify=ctk.CENTER
        )
        contact_label.pack(fill=ctk.X, pady=(Dimensions.PADY_SMALL, Dimensions.PADY_MEDIUM), padx=Dimensions.PADX_LARGE)
    
    def _create_table(self, parent):
        self.table_frame = ctk.CTkFrame(parent, fg_color=Colors.CARD_BACKGROUND, border_width=0)
        self.table_frame.pack(fill=ctk.BOTH, expand=True)
        
        self.scrollable_frame = ctk.CTkScrollableFrame(
            self.table_frame,
            fg_color="transparent",
            scrollbar_button_color=Colors.BORDER,
            scrollbar_button_hover_color=Colors.HOVER
        )
        self.scrollable_frame.pack(fill=ctk.BOTH, expand=True)
        
        self.scrollable_frame.configure(corner_radius=0)
        
        # 表格列宽配置
        self.col_widths = {
            "软件名称": 200,
            "安装状态": 140,
            "缓存状态": 130,
            "下载速度": 130,
            "总进度": 130
        }
        
        header_frame = ctk.CTkFrame(self.scrollable_frame, fg_color=Colors.TABLE_HEADER, border_width=0)
        header_frame.pack(fill=ctk.X, padx=Dimensions.PADY_SMALL, pady=Dimensions.PADY_SMALL)
        
        headers = ["软件名称", "安装状态", "缓存状态", "下载速度", "总进度"]
        for i, header in enumerate(headers):
            label = ctk.CTkLabel(
                header_frame,
                text=header,
                text_color=Colors.TABLE_HEADER_TEXT,
                font=self.create_font(18, "bold", logger=self.fonts_logger),
                width=self.col_widths[header],
                anchor="w"
            )
            label.grid(row=0, column=i, padx=Dimensions.PADX_LARGE, pady=Dimensions.PADY_MEDIUM, sticky="w")
        
        header_divider = ctk.CTkFrame(self.scrollable_frame, fg_color=Colors.BORDER, height=1)
        header_divider.pack(fill=ctk.X, padx=Dimensions.PADY_SMALL)
        
        self._refresh_table()
    
    def _refresh_table(self):
        if hasattr(self, 'scrollable_frame'):
            children = self.scrollable_frame.winfo_children()
            for widget in children:
                if isinstance(widget, ctk.CTkFrame) and widget not in (children[0], children[1]):
                    widget.destroy()

        self.table_rows = {}
        for idx, software in enumerate(self.selected_software):
            self._create_table_row(self.scrollable_frame, software, idx + 1, self.col_widths)

        loading = LoadingWindow(self.root, title="初始化", message="正在检测缓存状态")

        def update_cache_status():
            for software in self.selected_software:
                try:
                    loading.set_subtext(f"检测: {software}")
                except Exception:
                    pass
                if software in self.table_rows:
                    try:
                        cache_status = self._check_cache_status(software)
                    except Exception:
                        cache_status = "未缓存"
                    try:
                        self.root.after(0, lambda s=software, cs=cache_status: self._update_cache_status(s, cs))
                    except Exception:
                        pass

        cache_thread = threading.Thread(target=update_cache_status, daemon=True)
        cache_thread.start()

        def monitor():
            try:
                if cache_thread.is_alive():
                    self.root.after(200, monitor)
                else:
                    try:
                        loading.close()
                    except Exception:
                        pass
                    try:
                        self._initializing = False
                        try:
                            self._summary_state = {sw: 'not_started' for sw in self.selected_software}
                            self._recalculate_summary_label()
                        except Exception:
                            pass
                    except Exception:
                        pass
            except Exception:
                try:
                    loading.close()
                except Exception:
                    pass

        self.root.after(200, monitor)
    
    def _update_cache_status(self, software_name, cache_status):
        def update_ui():
            if software_name in self.table_rows:
                self.table_rows[software_name]["cache_label"].configure(text=cache_status)
                if cache_status == "已缓存":
                    self.table_rows[software_name]["speed_label"].configure(text="已缓存")
        
        self.root.after(0, update_ui)
    
    def _update_status(self, software_name, status):
        def update_ui():
            if software_name in self.table_rows:
                self.table_rows[software_name]["status_label"].configure(text=status)
                if status == "下载完成":
                    self.table_rows[software_name]["progress_text"].configure(text="50%")
                elif status == "解压完成":
                    self.table_rows[software_name]["progress_text"].configure(text="70%")
                elif status == "已安装" or status == "安装完成":
                    self.table_rows[software_name]["progress_text"].configure(text="100%")
                elif status in ("安装失败", "下载失败", "解压失败"):
                    self.table_rows[software_name]["progress_text"].configure(text="0%")
            try:
                if hasattr(self, '_update_summary_state'):
                    try:
                        self._update_summary_state(software_name, status)
                    except Exception:
                        pass
            except Exception:
                pass
        
        self.root.after(0, update_ui)
    
    def _update_progress(self, software_name, progress):
        def update_ui():
            if software_name in self.table_rows:
                self.table_rows[software_name]["progress_text"].configure(text=f"{progress}%")
        
        self.root.after(0, update_ui)
    
    def _update_speed(self, software_name, speed):
        def update_ui():
            if software_name in self.table_rows:
                self.table_rows[software_name]["speed_label"].configure(text=speed)
        
        self.root.after(0, update_ui)
    
    def _update_summary_state(self, software, status):
        try:
            if not hasattr(self, '_summary_state'):
                self._summary_state = {sw: 'not_started' for sw in self.selected_software}
            norm = None
            if status in ("已安装", "安装完成"):
                norm = 'success'
            elif status in ("安装失败", "下载失败", "解压失败"):
                norm = 'failed'
            elif status in ("下载中", "解压中", "安装中"):
                norm = 'installing'
            else:
                norm = 'other'

            prev = self._summary_state.get(software)
            if prev == norm:
                return
            self._summary_state[software] = norm
            try:
                self._recalculate_summary_label()
            except Exception:
                pass
        except Exception:
            pass
    
    def _recalculate_summary_label(self):
        try:
            success = sum(1 for v in self._summary_state.values() if v == 'success')
            failed = sum(1 for v in self._summary_state.values() if v == 'failed')
            in_progress = any(v in ('installing', 'downloading') for v in self._summary_state.values())

            if in_progress:
                state_text = '进行中'
            elif success + failed == 0:
                state_text = '未开始'
            else:
                state_text = '已结束'
                
            if hasattr(self, 'summary_status_label') and getattr(self.summary_status_label, 'winfo_exists', lambda: False)():
                try:
                    self.summary_status_label.configure(text=f"状态：{state_text}    完成：成功 {success}，失败 {failed}")
                except Exception:
                    pass
        except Exception:
            pass
    
    def _download_file(self, software_name, cache_file, download_location="cache"):
        # 跳过某些已知无法下载的文件
        skip_software = []
        if software_name in skip_software:
            self.installer_logger.warning(f"{software_name}: 跳过已知无法下载的软件")
            self._update_status(software_name, "跳过")
            raise RuntimeError(f"{software_name}: 跳过已知无法下载的软件")
        # 检查缓存状态
        cache_path = os.path.join(CACHE_DIR, cache_file["filename"])
        cache_status = self._check_cache_status(software_name)
        
        # 已缓存文件处理
        if cache_status == "已缓存":
            self.installer_logger.info(f"{software_name}: 使用cache目录的已缓存文件: {cache_path}")
            
            return cache_path
        
        # 未缓存文件处理
        # 检查cache目录是否存在文件
        if os.path.exists(cache_path):
            # 缓存存在但不匹配，重新下载到cache目录
            download_path = cache_path
            self.installer_logger.info(f"{software_name}: cache目录文件存在但不匹配，重新下载到cache目录: {download_path}")
        else:
            # 未缓存，下载到Temporary目录
            download_path = os.path.join(TEMP_DIR, cache_file["filename"])
            self.installer_logger.info(f"{software_name}: 未缓存，下载到Temporary目录: {download_path}")
        
        self.installer_logger.info(f"{software_name}: 开始下载到 {download_path}")
        # 更新状态为下载中
        self._update_status(software_name, "下载中")
        
        max_retries = 3  # 最大重试次数
        retry_count = 0
        
        # 模拟浏览器的请求头
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Referer": "https://www.seewo.com/",
            "Cache-Control": "max-age=0"
        }
        
        while retry_count < max_retries:
            try:
                # 发送请求
                url = get_download_url(cache_file)
                self.installer_logger.info(f"{software_name}: 发送下载请求到: {url} (重试次数: {retry_count + 1}/{max_retries})")
                
                # 使用Session保持会话
                session = requests.Session()
                session.headers.update(headers)
                
                # 禁用重定向自动处理，先处理301/302
                response = session.get(url, stream=True, timeout=60, allow_redirects=False, verify=False)  # 忽略SSL证书验证
                
                # 处理重定向
                if response.status_code in [301, 302]:
                    redirect_url = response.headers.get("Location")
                    if redirect_url:
                        self.installer_logger.info(f"{software_name}: 跟随重定向到: {redirect_url}")
                        response = session.get(redirect_url, stream=True, timeout=60, verify=False)  # 忽略SSL证书验证
                
                response.raise_for_status()
                self.installer_logger.info(f"{software_name}: 收到响应，状态码: {response.status_code}")
                
                # 获取文件大小
                total_size = int(response.headers.get('content-length', 0))
                self.installer_logger.info(f"{software_name}: 文件大小: {total_size} bytes")
                downloaded_size = 0
                
                # 开始下载时间
                start_time = time.time()

                # 限速与更新节流参数（可在实例上设置：download_rate_limit（bytes/s），progress_update_interval（秒））
                rate_limit = getattr(self, 'download_rate_limit', 0)  # 0 表示不限制
                update_interval = getattr(self, 'progress_update_interval', 0.5)  # 平衡实时性和性能

                # 用于限速的滑动窗口和用于节流的上次更新时间戳
                window_start = start_time
                window_downloaded = 0
                last_update_time = 0

                # 写入文件
                self.installer_logger.info(f"开始写入文件: {download_path}")
                with open(download_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            chunk_len = len(chunk)
                            downloaded_size += chunk_len

                            # 限速：使用简单的每秒滑动窗口，如果超过速率则睡眠补偿
                            if rate_limit and rate_limit > 0:
                                window_downloaded += chunk_len
                                now_t = time.time()
                                elapsed_window = now_t - window_start
                                if elapsed_window >= 1.0:
                                    # 重置窗口
                                    window_start = now_t
                                    window_downloaded = 0
                                else:
                                    expected_time = window_downloaded / float(rate_limit)
                                    if expected_time > elapsed_window:
                                        time_to_sleep = expected_time - elapsed_window
                                        time.sleep(time_to_sleep)

                            # 节流更新速度与进度，避免每个chunk都刷新UI
                            now = time.time()
                            if last_update_time == 0 or (now - last_update_time) >= update_interval:
                                elapsed_time = now - start_time if (now - start_time) > 0 else 1e-6
                                speed = downloaded_size / elapsed_time

                                # 格式化速度
                                if speed < 1024:
                                    speed_str = f"{speed:.2f} B/s"
                                elif speed < 1024 * 1024:
                                    speed_str = f"{speed / 1024:.2f} KB/s"
                                else:
                                    speed_str = f"{speed / (1024 * 1024):.2f} MB/s"

                                # 更新速度
                                self._update_speed(software_name, speed_str)

                                # 计算并更新进度
                                if total_size > 0:
                                    progress = int((downloaded_size / total_size) * 100)
                                    self._update_progress(software_name, progress)

                                last_update_time = now
                
                self.installer_logger.info(f"{software_name}: 下载完成")
                # 下载完成，设置进度为50%
                self._update_progress(software_name, 50)
                
                return download_path  # 返回实际的下载路径
            except requests.exceptions.RequestException as e:
                retry_count += 1
                if retry_count < max_retries:
                    self.installer_logger.warning(f"{software_name}: 下载失败，将重试 ({retry_count}/{max_retries}) - {str(e)}")
                    time.sleep(5)  # 等待5秒后重试
                else:
                    self.installer_logger.error(f"{software_name}: 下载失败 - {str(e)}", exc_info=True)
                    # 更新状态为下载失败
                    self._update_status(software_name, "下载失败")
                    raise RuntimeError(f"{software_name}: 下载失败 - {str(e)}") from e
            except OSError as e:
                self.installer_logger.error(f"{software_name}: 文件操作失败 - {str(e)}", exc_info=True)
                # 更新状态为下载失败
                self._update_status(software_name, "下载失败")
                raise RuntimeError(f"{software_name}: 文件操作失败 - {str(e)}") from e
            except Exception:
                self.installer_logger.error(f"{software_name}: 下载异常 - {str(e)}", exc_info=True)
                # 更新状态为下载失败
                self._update_status(software_name, "下载失败")
                raise RuntimeError(f"{software_name}: 下载异常 - {str(e)}") from e
    
    def _decompress_7Z(self, software_name, file_to_extract, output_dir):
        """解压缩7Z文件
        
        Args:
            software_name: 软件名称
            file_to_extract: 要解压的文件路径
            output_dir: 解压到的目标目录
        """
        self.installer_logger.info(f"{software_name}: 开始解压7Z文件: {file_to_extract} 到 {output_dir}")

        # 更新状态为解压中
        self._update_status(software_name, "解压中")

        # 基础检查
        if not os.path.exists(file_to_extract):
            self.installer_logger.error(f"{software_name}: 要解压的文件不存在: {file_to_extract}")
            self._update_status(software_name, "解压失败")
            raise FileNotFoundError(f"要解压的文件不存在: {file_to_extract}")

        # 确保目标目录存在
        try:
            os.makedirs(output_dir, exist_ok=True)
        except Exception as e:
            self.installer_logger.error(f"{software_name}: 无法创建输出目录 {output_dir}: {e}")
            self._update_status(software_name, "解压失败")
            raise

        # 先尝试使用本地/系统的7z可执行文件
        seven_path = None
        if os.path.exists(SEVEN_ZIP_PATH):
            seven_path = SEVEN_ZIP_PATH
        else:
            seven_path = shutil.which("7z") or shutil.which("7za")

        # 如果找到了7z命令，优先使用它（支持密码）
        if seven_path:
            args = [
                seven_path,
                "x",
                file_to_extract,
                f"-p{SEVEN_ZIP_PASSWORD}",
                f"-o{output_dir}",
                "-y",
            ]
            self.installer_logger.info(f"{software_name}: 使用7z执行解压: {seven_path}")
            try:
                result = subprocess.run(
                    args,
                    check=True,
                    shell=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
                )
                self.installer_logger.info(f"{software_name}: 解压缩完成")
                # 解压完成，设置进度为70%
                self._update_progress(software_name, 70)
                return
            except subprocess.CalledProcessError as e:
                # 记录有限的错误信息以便排查（不包含命令行参数列表）
                stderr_snippet = (e.stderr or "").strip()[:1000]
                self.installer_logger.error(f"{software_name}: 7z 解压失败: {stderr_snippet}")
                self._update_status(software_name, "解压失败")
                raise RuntimeError(f"{software_name}: 7z 解压失败: {stderr_snippet}") from e
            except Exception as e:
                self.installer_logger.error(f"{software_name}: 使用7z解压时出现异常: {e}")
                self._update_status(software_name, "解压失败")
                raise

        # 如果没有7z，可针对.zip使用内置zipfile，或尝试py7zr库作为回退
        ext = os.path.splitext(file_to_extract)[1].lower()
        if ext == ".zip":
            try:
                with zipfile.ZipFile(file_to_extract, 'r') as zf:
                    zf.extractall(output_dir)
                self.installer_logger.info(f"{software_name}: 使用zipfile解压完成")
                self._update_progress(software_name, 70)
                return
            except Exception as e:
                self.installer_logger.error(f"{software_name}: 使用zipfile解压失败: {e}")
                self._update_status(software_name, "解压失败")
                raise

        try:
            try:
                with py7zr.SevenZipFile(file_to_extract, mode='r', password=SEVEN_ZIP_PASSWORD) as archive:
                    archive.extractall(path=output_dir)
                self.installer_logger.info(f"{software_name}: 使用 py7zr 解压完成")
                # 解压完成，设置进度为70%
                self._update_progress(software_name, 70)
                return
            except Exception as e:
                self.installer_logger.error(f"{software_name}: py7zr 解压失败: {e}")
                self._update_status(software_name, "解压失败")
                raise
        except ImportError:
            self.installer_logger.error(f"{software_name}: 未找到7z可执行文件，且未安装py7zr库，请安装7-Zip或py7zr以支持 .7z 解压")
            self._update_status(software_name, "解压失败")
            raise RuntimeError("缺少解压工具：请将7z.exe放入 Tools 目录或在系统PATH中安装7z")
    
    def silent_installation(self, software_name, installer_path):
        """静默安装软件
        
        Args:
            software_name: 软件名称
            installer_path: 安装包的路径
        """
        # 更新状态为安装中
        self._update_status(software_name, "安装中")
        
        self.installer_logger.info(f"{software_name}: 开始静默安装")
        
        # 使用 /S 参数进行静默安装
        try:
            subprocess.run([installer_path, "/S"], check=True, shell=False)
            
            self.installer_logger.info(f"{software_name}: 静默安装完成")
        except subprocess.CalledProcessError as e:
            self.installer_logger.error(f"{software_name}: 静默安装失败 - {str(e)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise RuntimeError(f"{software_name}: 静默安装失败 - {str(e)}") from e
        except Exception:
            self.installer_logger.error(f"{software_name}: 静默安装异常 - {str(e)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise RuntimeError(f"{software_name}: 静默安装异常 - {str(e)}") from e
    
    def _create_table_row(self, parent, software, row_idx, col_widths):
        """创建表格行
        
        Args:
            parent: 父容器
            software: 软件名称
            row_idx: 行索引
            col_widths: 列宽配置
        """
        # 行框架
        row_frame = ctk.CTkFrame(parent, fg_color=Colors.TABLE_ROW, border_width=0)
        row_frame.pack(fill=ctk.X, padx=Dimensions.PADY_SMALL, pady=Dimensions.PADY_SMALL)
        
        # 软件名称
        name_label = ctk.CTkLabel(
            row_frame,
            text=software,
            text_color=Colors.TEXT,
            font=self.create_font(18, logger=self.fonts_logger),
            width=col_widths["软件名称"],
            anchor="w"
        )
        name_label.grid(row=0, column=0, padx=Dimensions.PADX_LARGE, pady=Dimensions.PADY_MEDIUM, sticky="w")
        
        # 安装状态
        status_label = ctk.CTkLabel(
            row_frame,
            text="等待安装",
            text_color=Colors.TEXT_SECONDARY,
            font=self.create_font(18, logger=self.fonts_logger),
            width=col_widths["安装状态"],
            anchor="w"
        )
        status_label.grid(row=0, column=1, padx=Dimensions.PADX_LARGE, pady=Dimensions.PADY_MEDIUM, sticky="w")
        
        # 缓存状态 - 先显示"检测中"
        cache_label = ctk.CTkLabel(
            row_frame,
            text="检测中",
            text_color=Colors.TEXT_SECONDARY,
            font=self.create_font(18, logger=self.fonts_logger),
            width=col_widths["缓存状态"],
            anchor="w"
        )
        cache_label.grid(row=0, column=2, padx=Dimensions.PADX_LARGE, pady=Dimensions.PADY_MEDIUM, sticky="w")
        
        # 下载速度
        speed_label = ctk.CTkLabel(
            row_frame,
            text="0 KB/s",
            text_color=Colors.TEXT_SECONDARY,
            font=self.create_font(18, logger=self.fonts_logger),
            width=col_widths["下载速度"],
            anchor="w"
        )
        speed_label.grid(row=0, column=3, padx=Dimensions.PADX_LARGE, pady=Dimensions.PADY_MEDIUM, sticky="w")
        
        # 总进度
        progress_text = ctk.CTkLabel(
            row_frame,
            text="0%",
            text_color=Colors.TEXT_SECONDARY,
            font=self.create_font(18, logger=self.fonts_logger),
            width=col_widths["总进度"],
            anchor="w"
        )
        progress_text.grid(row=0, column=4, padx=Dimensions.PADX_LARGE, pady=Dimensions.PADY_MEDIUM, sticky="w")
        
        # 存储行组件引用
        self.table_rows[software] = {
            "row_frame": row_frame,
            "status_label": status_label,
            "cache_label": cache_label,
            "speed_label": speed_label,
            "progress_text": progress_text
        }
    
    def _check_cache_status(self, software_name):
        cache_logger = get_logger("Cache")
        cache_file = next((item for item in CACHE_FILES if software_name in item["filename"] and 
                          (item["filename"].endswith(".exe") or item["filename"].endswith(".7z"))), None)
        
        if not cache_file:
            cache_logger.warning(f"{software_name}: 未找到缓存文件信息")
            return "未缓存"
        
        filename = cache_file["filename"]
        cache_path = os.path.join(CACHE_DIR, filename)
        
        if not os.path.exists(cache_path):
            cache_logger.info(f"{software_name}: cache目录文件不存在: {cache_path}")
            return "未缓存"
        
        local_path = cache_path
        
        try:
            local_size = os.path.getsize(local_path)
            
            def calculate_file_hash(file_path):
                hash_obj = hashlib.md5()
                with open(file_path, 'rb') as f:
                    while chunk := f.read(8192):
                        hash_obj.update(chunk)
                return hash_obj.hexdigest()
            
            local_hash = calculate_file_hash(local_path)
            cache_logger.info(f"{software_name}: 本地文件哈希值: {local_hash}")
            
            url = get_download_url(cache_file)
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
            
            cache_logger.info(f"{software_name}: 检查服务器文件大小，URL: {url}")
            response = requests.head(url, headers=headers, timeout=5, allow_redirects=True, verify=False)
            cache_logger.info(f"{software_name}: 服务器响应状态码: {response.status_code}")
            if response.status_code == 200 and "content-length" in response.headers:
                server_size = int(response.headers["content-length"])
                cache_logger.info(f"{software_name}: 服务器文件大小: {server_size} bytes")
                
                if local_size == server_size:
                    cache_logger.info(f"{software_name}: cache文件大小: {local_size}, 服务器响应状态码: 200, 服务器文件大小: {server_size}, 大小一致，返回已缓存")
                    return "已缓存"
                else:
                    cache_logger.info(f"{software_name}: cache文件大小: {local_size}, 服务器响应状态码: 200, 服务器文件大小: {server_size}, 大小不一致，返回未缓存")
                    return "未缓存"
            else:
                cache_logger.warning(f"{software_name}: 服务器响应状态码: {response.status_code}, 服务器响应没有content-length")
                return "未缓存"
        except requests.exceptions.RequestException as err:
            cache_logger.error(f"{software_name}: 网络请求异常: {err}", exc_info=True)
            return "未缓存"
        except OSError as err:
            cache_logger.error(f"{software_name}: 文件操作异常: {err}", exc_info=True)
            return "未缓存"
        except Exception as err:
            cache_logger.error(f"{software_name}: 异常: {err}", exc_info=True)
            return "未缓存"
    
    def start_installation_process(self):
        self.installer_logger.info(f"开始安装过程，共 {len(self.selected_software)} 个软件待安装")
        
        self.start_btn.configure(state="disabled")
        
        self.root.protocol("WM_DELETE_WINDOW", lambda: None)
        
        try:
            if hasattr(self, 'summary_status_label') and getattr(self.summary_status_label, 'winfo_exists', lambda: False)():
                try:
                    self.summary_status_label.configure(text="状态：安装中    完成：成功 0，失败 0")
                except Exception:
                    pass
        except Exception:
            pass
        try:
            self._summary_state = {sw: 'not_started' for sw in self.selected_software}
            for sw in list(self._summary_state.keys()):
                self._summary_state[sw] = 'installing'
                row = self.table_rows.get(sw)
                if row:
                    cache_label = row.get("cache_label")
                    if cache_label and getattr(cache_label, "winfo_exists", lambda: False)():
                        cache_status = cache_label.cget("text")
                        if cache_status == "已缓存":
                            self.root.after(0, lambda s=sw: self._update_progress(s, 50))
            try:
                self._recalculate_summary_label()
            except Exception:
                pass
        except Exception:
            pass
        
        # 收集所有可安装的软件及其缓存文件信息
        installable_software = []
        for software in self.selected_software:
            # 查找对应的缓存文件信息
            cache_file = None
            for item in CACHE_FILES:
                if software in item["filename"] or item["filename"].startswith(software):
                    cache_file = item
                    break
            
            if cache_file:
                installable_software.append((software, cache_file))
            else:
                self.installer_logger.warning(f"未找到 {software} 的缓存文件信息，跳过安装")
        
        self.installer_logger.info(f"准备安装 {len(installable_software)} 个软件")

        # 确保先关闭可能存在的旧线程池
        if hasattr(self, 'executor') and self.executor is not None:
            try:
                self.installer_logger.info("关闭可能存在的旧线程池")
                self.executor.shutdown(wait=True)
                self.installer_logger.info("旧线程池已关闭")
            except Exception:
                self.installer_logger.error(f"关闭旧线程池时出错: {str(e)}")

        max_workers = os.cpu_count() if os.cpu_count() else 4
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.installer_logger.info(f"创建线程池，最大并发数: {max_workers}")

        # 存储所有任务的Future对象
        self.futures = []

        # 构建安装映射，便于按名称查找
        install_map = {s: cf for s, cf in installable_software}

        # 依赖规则：建立全面的依赖关系表
        dependency_map = {
            "希沃白板5": ["希沃伪装插件", "白板去除横幅"],
            # 可以在这里添加更多依赖关系
            # 例如: "软件A": ["依赖1", "依赖2"]
        }

        # 检查是否存在依赖关系
        has_dependency_flow = False
        main_dependency = None
        dependent_names = []
        
        # 查找第一个存在的依赖关系
        for main, deps in dependency_map.items():
            if main in install_map and all(dep in install_map for dep in deps):
                main_dependency = main
                dependent_names = deps
                has_dependency_flow = True
                break

        if has_dependency_flow:
            # 先提交主依赖任务
            self.installer_logger.info(f"检测到依赖关系：先安装 {main_dependency}，再安装其依赖组件: {', '.join(dependent_names)}")
            main_future = self.executor.submit(self._install_software, main_dependency, install_map[main_dependency])
            self.futures.append(main_future)

            # 其余不依赖于希沃白板5的任务可以并行提交
            for software, cache_file in installable_software:
                if software == main_dependency or software in dependent_names:
                    continue
                fut = self.executor.submit(self._install_software, software, cache_file)
                self.futures.append(fut)

            # 将依赖项标记为等待依赖（UI上显示）
            for dep in dependent_names:
                if dep in self.table_rows:
                    try:
                        self._update_status(dep, "等待依赖")
                    except Exception:
                        pass

            # 当主依赖完成且成功后再提交依赖任务
            def _on_main_done(fut):
                try:
                    # 如果主任务抛出异常，result() 会抛出
                    fut.result()
                    # 主依赖成功，提交依赖任务
                    for dep in dependent_names:
                        if dep in install_map:
                            try:
                                self.installer_logger.info(f"主依赖 {main_dependency} 安装成功，提交依赖任务: {dep}")
                                df = self.executor.submit(self._install_software, dep, install_map[dep])
                                self.futures.append(df)
                            except Exception:
                                try:
                                    self._update_status(dep, "安装失败")
                                except Exception:
                                    pass
                except Exception as e:
                    # 主依赖失败，标记依赖项为安装失败（依赖未满足）
                    self.installer_logger.error(f"主依赖 {main_dependency} 安装失败，依赖任务将被标记为安装失败: {e}")
                    for dep in dependent_names:
                        if dep in self.table_rows:
                            try:
                                self._update_status(dep, "安装失败")
                            except Exception:
                                pass

            # 使用主线程的轮询方式检查主任务完成，避免在工作线程中执行可能影响UI的回调
            def _poll_main():
                try:
                    if main_future.done():
                        # 在主线程安全地调用处理函数
                        try:
                            _on_main_done(main_future)
                        except Exception:
                            pass
                    else:
                        self.root.after(500, _poll_main)
                except Exception:
                    # 忽略轮询中的异常，继续轮询
                    try:
                        self.root.after(500, _poll_main)
                    except Exception:
                        pass

            self.root.after(500, _poll_main)

        else:
            # 无特殊依赖，一律提交
            for software, cache_file in installable_software:
                future = self.executor.submit(self._install_software, software, cache_file)
                self.futures.append(future)

        # 等待所有任务完成后关闭线程池
        def wait_for_tasks():
            all_done = all(future.done() for future in self.futures)
            if not all_done:
                # 继续检查任务状态
                self.root.after(1000, wait_for_tasks)
            else:
                # 所有初始任务完成，检查是否需要重试
                self._check_and_retry_failed_installations()

        # 启动任务检查
        self.root.after(1000, wait_for_tasks)

        self.installer_logger.info("所有安装任务已提交")
    
    def _check_and_retry_failed_installations(self):
        """检查安装失败的软件并进行重试"""
        self.installer_logger.info("进入_check_and_retry_failed_installations方法，准备检查安装结果")
        # 收集安装失败的软件
        failed_software = []
        for software, row in self.table_rows.items():
            status = row["status_label"].cget("text")
            self.installer_logger.info(f"{software} 的安装状态: {status}")
            if status == "安装失败":
                failed_software.append(software)
        
        if failed_software:
            self.installer_logger.info(f"检测到 {len(failed_software)} 个软件安装失败，准备重试")
            
            # 收集失败软件的缓存文件信息
            retry_software = []
            for software in failed_software:
                # 查找对应的缓存文件信息
                cache_file = None
                for item in CACHE_FILES:
                    if software in item["filename"] or item["filename"].startswith(software):
                        cache_file = item
                        break
                
                if cache_file:
                    retry_software.append((software, cache_file))
                else:
                    self.installer_logger.warning(f"未找到 {software} 的缓存文件信息，跳过重试")
            
            if retry_software:
                self.installer_logger.info(f"准备重试安装 {len(retry_software)} 个软件")
                
                # 确保先关闭原来的线程池
                if hasattr(self, 'executor') and self.executor is not None:
                    try:
                        self.installer_logger.info("关闭原来的线程池")
                        self.executor.shutdown(wait=True)
                        self.installer_logger.info("原来的线程池已关闭")
                    except Exception:
                        self.installer_logger.error(f"关闭原来的线程池时出错: {str(e)}")
                
                # 重新创建线程池
                max_workers = os.cpu_count() if os.cpu_count() else 4  # CPU核心数，默认4
                self.executor = ThreadPoolExecutor(max_workers=max_workers)
                self.installer_logger.info(f"重新创建线程池，最大并发数: {max_workers}")
                
                # 为失败的软件提交重试任务
                self.futures = []
                for software, cache_file in retry_software:
                    self.installer_logger.info(f"提交 {software} 的重试安装任务")
                    future = self.executor.submit(self._install_software, software, cache_file)
                    self.futures.append(future)
                
                # 启动重试任务检查
                def wait_for_retry_tasks():
                    all_done = all(future.done() for future in self.futures)
                    if not all_done:
                        # 继续检查任务状态
                        self.root.after(1000, wait_for_retry_tasks)
                    else:
                        # 所有重试任务完成，关闭线程池
                        self.executor.shutdown(wait=True)
                        self.installer_logger.info("所有重试安装任务已完成，线程池已关闭")
                        
                        # 启用窗口关闭按钮
                        self.root.protocol("WM_DELETE_WINDOW", self._on_window_close)
                        
                        # 统计安装结果
                        success_count = 0
                        failed_count = 0
                        for software, row in self.table_rows.items():
                            status = row["status_label"].cget("text")
                            if status == "已安装":
                                success_count += 1
                            elif status == "安装失败":
                                failed_count += 1
                        
                        self.installer_logger.info(f"安装结果统计: 成功 {success_count} 个，失败 {failed_count} 个")
                        
                        if failed_count == 0:
                            self.installer_logger.info("准备发送安装成功通知")
                            send_notification("SEEVVO全家桶一剑下崽弃", f"共 {success_count} 个软件安装成功！")
                            self.installer_logger.info("安装成功通知发送完成")
                        else:
                            self.installer_logger.info("准备发送安装存在错误通知")
                            send_notification("SEEVVO全家桶一剑下崽弃", f"安装完成，但有 {failed_count} 个软件安装失败，{success_count} 个软件安装成功")
                            self.installer_logger.info("安装存在错误通知发送完成")
                        
                        # 显示结果覆盖层
                        try:
                            if failed_count == 0:
                                message = f"共 {success_count} 个软件安装成功！"
                                subtext = "安装过程已顺利完成，所有软件均已成功安装到您的系统中。"
                            else:
                                message = f"安装完成，但有 {failed_count} 个软件安装失败"
                                subtext = f"成功安装 {success_count} 个软件，失败 {failed_count} 个软件。您可以查看日志了解详细信息。"
                            ResultOverlay(
                                parent=self.root,
                                title="安装完成",
                                message=message,
                                subtext=subtext,
                                success_count=success_count,
                                failed_count=failed_count,
                                operation_type="安装"
                            )
                        except Exception:
                            self.installer_logger.error(f"显示结果覆盖层失败: {str(e)}", exc_info=True)
                
                self.root.after(1000, wait_for_retry_tasks)
            else:
                self.installer_logger.info("没有可重试的软件，关闭线程池")
                self.executor.shutdown(wait=True)
                
                # 启用窗口关闭按钮
                self.root.protocol("WM_DELETE_WINDOW", self._on_window_close)
                
                # 统计安装结果
                success_count = 0
                failed_count = 0
                for software, row in self.table_rows.items():
                    status = row["status_label"].cget("text")
                    if status == "已安装":
                        success_count += 1
                    elif status == "安装失败":
                        failed_count += 1
                
                self.installer_logger.info(f"安装结果统计: 成功 {success_count} 个，失败 {failed_count} 个")
                
                if failed_count == 0:
                    self.installer_logger.info("准备发送安装成功通知")
                    send_notification("SEEVVO全家桶一剑下崽弃", f"共 {success_count} 个软件安装成功！")
                    self.installer_logger.info("安装成功通知发送完成")
                else:
                    self.installer_logger.info("准备发送安装存在错误通知")
                    send_notification("SEEVVO全家桶一剑下崽弃", f"安装完成，但有 {failed_count} 个软件安装失败，{success_count} 个软件安装成功")
                    self.installer_logger.info("安装存在错误通知发送完成")
                
                try:
                    if failed_count == 0:
                        message = f"共 {success_count} 个软件安装成功！"
                        subtext = "安装过程已顺利完成，所有软件均已成功安装到您的系统中。"
                    else:
                        message = f"安装完成，但有 {failed_count} 个软件安装失败"
                        subtext = f"成功安装 {success_count} 个软件，失败 {failed_count} 个软件。您可以查看日志了解详细信息。"
                    ResultOverlay(
                        parent=self.root,
                        title="安装完成",
                        message=message,
                        subtext=subtext,
                        success_count=success_count,
                        failed_count=failed_count,
                        operation_type="安装"
                    )
                except Exception:
                    self.installer_logger.error(f"显示结果覆盖层失败: {str(e)}", exc_info=True)
        else:
            self.installer_logger.info("所有软件安装成功，关闭线程池")
            self.executor.shutdown(wait=True)
            
            # 启用窗口关闭按钮
            self.root.protocol("WM_DELETE_WINDOW", self._on_window_close)
            
            # 统计安装结果
            success_count = len(self.table_rows)
            failed_count = 0
            
            self.installer_logger.info(f"安装结果统计: 成功 {success_count} 个，失败 {failed_count} 个")
            
            self.installer_logger.info("准备发送安装成功通知")
            send_notification("SEEVVO全家桶一剑下崽弃", f"共 {success_count} 个软件安装成功！")
            self.installer_logger.info("安装成功通知发送完成")
            
            try:
                message = f"共 {success_count} 个软件安装成功！"
                subtext = "安装过程已顺利完成，所有软件均已成功安装到您的系统中。"
                ResultOverlay(
                    parent=self.root,
                    title="安装完成",
                    message=message,
                    subtext=subtext,
                    success_count=success_count,
                    failed_count=failed_count,
                    operation_type="安装"
                )
            except Exception:
                self.installer_logger.error(f"显示结果覆盖层失败: {str(e)}", exc_info=True)
    
    def _install_software(self, software_name, cache_file):
        try:
            try:
                sanitized = re.sub(r'[\[\]\s]', '', software_name)
            except Exception:
                sanitized = software_name.replace(' ', '')
            install_func_name = f"_install_{sanitized}"
            install_func = getattr(self, install_func_name, None)
            if install_func is not None:
                install_func(software_name, cache_file)
            else:
                self.installer_logger.info(f"{software_name}: 使用默认安装方式")
                installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
                self.silent_installation(software_name, installer_path)
                self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "已安装")
            self._update_progress(software_name, 100)
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装过程中出错 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            self._update_progress(software_name, 0)
    
    def _cleanup_temp_files(self, temp_dir, filename, software_name=None):
        temp_path = os.path.join(temp_dir, filename)
        
        if self.retain_installer and TEMP_DIR in temp_path:
            # 保留安装包选项开启，且文件在Temporary目录中，将其剪切到cache目录
            cache_path = os.path.join(CACHE_DIR, filename)
            self.installer_logger.info(f"保留安装包选项已开启，将文件从 {temp_path} 剪切到 {cache_path}")
            try:
                os.makedirs(CACHE_DIR, exist_ok=True)
                shutil.move(temp_path, cache_path)
                self.installer_logger.info(f"文件成功剪切到cache目录")
                if software_name:
                    self._update_cache_status(software_name, "已缓存")
                return
            except Exception as e:
                self.installer_logger.error(f"剪切文件到cache目录失败 - {str(e)}")
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                if os.path.exists(temp_path):
                    self.installer_logger.info(f"清理临时文件: {temp_path} (重试次数: {retry_count + 1}/{max_retries})")
                    os.remove(temp_path)
                    break
                else:
                    break
            except Exception as err:
                retry_count += 1
                if retry_count < max_retries:
                    self.installer_logger.warning(f"清理临时文件失败，将重试 ({retry_count}/{max_retries}) - {err}")
                    time.sleep(2)
                else:
                    self.installer_logger.warning(f"清理临时文件失败: {err}")
    
    def _kill_process(self, software_name, process_name):
        self.installer_logger.info(f"{software_name}: 终止进程 {process_name}")
        try:
            subprocess.run(["taskkill", "/f", "/im", process_name], check=True, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.installer_logger.info(f"{software_name}: {process_name} 进程已终止")
            return True
        except subprocess.CalledProcessError:
            self.installer_logger.warning(f"{software_name}: {process_name} 进程未找到")
            return False
    
    def _wait_for_process(self, software_name, process_name, timeout=30, check_interval=1):
        self.installer_logger.info(f"{software_name}: 等待进程 {process_name} 出现，超时 {timeout} 秒")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                result = subprocess.run(
                    ["tasklist", "/FI", f"IMAGENAME eq {process_name}", "/NH"],
                    capture_output=True, text=True, shell=False
                )
                if process_name in result.stdout:
                    self.installer_logger.info(f"{software_name}: 进程 {process_name} 已出现")
                    return True
            except Exception as err:
                self.installer_logger.warning(f"{software_name}: 检查进程 {process_name} 时出错 - {err}")
            
            time.sleep(check_interval)
        
        self.installer_logger.warning(f"{software_name}: 等待进程 {process_name} 超时（{timeout} 秒）")
        return False
    
    def _wait_for_process_exit(self, software_name, process, timeout=60, check_interval=2):
        self.installer_logger.info(f"{software_name}: 等待进程退出，超时 {timeout} 秒")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if process.poll() is not None:
                self.installer_logger.info(f"{software_name}: 进程已退出")
                return True
            time.sleep(check_interval)
        
        self.installer_logger.warning(f"{software_name}: 等待进程退出超时（{timeout} 秒）")
        return False
    
    def _wait_for_condition(self, software_name, condition_func, timeout=30, check_interval=1):
        self.installer_logger.info(f"{software_name}: 等待条件满足，超时 {timeout} 秒")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                if condition_func():
                    self.installer_logger.info(f"{software_name}: 条件已满足")
                    return True
            except Exception as err:
                self.installer_logger.warning(f"{software_name}: 检查条件时出错 - {err}")
            
            time.sleep(check_interval)
        
        self.installer_logger.warning(f"{software_name}: 等待条件满足超时（{timeout} 秒）")
        return False

    # 剪辑师安装函数
    def _install_剪辑师(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
    # 轻录播安装函数
    def _install_轻录播(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 知识胶囊安装函数
    def _install_知识胶囊(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 掌上看班安装函数
    def _install_掌上看班(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 激活工具安装函数
    def _install_激活工具(self, software_name, cache_file):
        try:
            self.installer_logger.info(f"{software_name}: 开始下载")
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            output_dir = r"C:\Program Files (x86)\Seewo"
            self._decompress_7Z(software_name, installer_path, output_dir)
            
            source_shortcut = os.path.join(output_dir, "激活工具-WHYOS-Gaoo", "激活工具.lnk")
            dest_shortcut = os.path.join(r"C:\Users\Public\Desktop", "激活工具.lnk")
            
            if os.path.exists(source_shortcut):
                self.installer_logger.info(f"{software_name}: 复制快捷方式到桌面")
                shutil.copy2(source_shortcut, dest_shortcut)
                self.installer_logger.info(f"{software_name}: 快捷方式已复制到桌面")
            else:
                self.installer_logger.warning(f"{software_name}: 未找到快捷方式: {source_shortcut}")
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    # 希沃壁纸安装函数
    def _install_希沃壁纸(self, software_name, cache_file):
        try:
            self.installer_logger.info(f"{software_name}: 开始下载")
            # 明确更新状态为下载中
            self._update_status(software_name, "下载中")
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            output_dir = r"C:\Windows\Web"
            # 明确更新状态为解压中
            self._update_status(software_name, "解压中")
            self._decompress_7Z(software_name, installer_path, output_dir)
            
            self._update_status(software_name, "配置中")
            
            SPI_SETDESKWALLPAPER = 20
            SPIF_UPDATEINIFILE = 0x01
            SPIF_SENDCHANGE = 0x02
            
            wallpaper_path = os.path.join(output_dir, "img0.jpg")
            if os.path.exists(wallpaper_path):
                self.installer_logger.info(f"{software_name}: 更改桌面背景")
                # 调用SystemParametersInfo函数更改桌面背景
                ctypes.windll.user32.SystemParametersInfoW(
                    SPI_SETDESKWALLPAPER, 
                    0, 
                    wallpaper_path, 
                    SPIF_UPDATEINIFILE | SPIF_SENDCHANGE
                )
                self.installer_logger.info(f"{software_name}: 桌面背景已更改")
            else:
                self.installer_logger.warning(f"{software_name}: 未找到壁纸文件: {wallpaper_path}")
            
            self._update_status(software_name, "安装完成")
            self.installer_logger.info(f"{software_name}: 安装完成")
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    # 希沃管家安装函数
    def _install_希沃管家(self, software_name, cache_file):
        """安装希沃管家 07
        
        Args:
            software_name: 软件名称
            cache_file: 缓存文件信息
        """
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 希沃桌面安装函数
    def _install_希沃桌面(self, software_name, cache_file):
        """安装希沃桌面 08
        
        Args:
            software_name: 软件名称
            cache_file: 缓存文件信息
        """
        try:
            self.installer_logger.info(f"{software_name}: 开始下载")
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.installer_logger.info(f"{software_name}: 开始解压到Temporary目录")
            output_dir = TEMP_DIR
            self._decompress_7Z(software_name, installer_path, output_dir)
            
            setup_files = ["setup.exe", "install.exe", "希沃桌面.exe"]
            setup_path = None
            for setup_file in setup_files:
                potential_path = os.path.join(TEMP_DIR, setup_file)
                if os.path.exists(potential_path):
                    setup_path = potential_path
                    break
            
            if setup_path:
                self.installer_logger.info(f"{software_name}: 开始静默安装")
                self.silent_installation(software_name, setup_path)
            else:
                self.installer_logger.warning(f"{software_name}: 未找到静默安装程序，跳过安装步骤")
            
            # 复制main.js文件到指定目录
            main_js_source = os.path.join(TEMP_DIR, "main.js")
            main_js_dest = r"C:\Programcache\LightAppRendersResources\seewo-lightapp-launcher\seewo-lightapp-launcher_0.3.0.67\main.js"
            if os.path.exists(main_js_source):
                main_js_dest_dir = os.path.dirname(main_js_dest)
                os.makedirs(main_js_dest_dir, exist_ok=True)
                
                try:
                    self.installer_logger.info(f"{software_name}: 复制main.js到 {main_js_dest}")
                    shutil.copy2(main_js_source, main_js_dest)
                    self.installer_logger.info(f"{software_name}: main.js复制完成")
                except Exception as err:
                    self.installer_logger.warning(f"{software_name}: 复制main.js失败 - {str(err)}")
            else:
                self.installer_logger.warning(f"{software_name}: 未找到main.js文件: {main_js_source}")
            
            # 复制希沃桌面.lnk到桌面
            shortcut_source = os.path.join(TEMP_DIR, "希沃桌面.lnk")
            shortcut_dest = r"C:\Users\Public\Desktop\希沃桌面.lnk"
            if os.path.exists(shortcut_source):
                try:
                    self.installer_logger.info(f"{software_name}: 复制快捷方式到桌面")
                    shutil.copy2(shortcut_source, shortcut_dest)
                    self.installer_logger.info(f"{software_name}: 快捷方式已复制到桌面")
                except Exception as err:
                    self.installer_logger.warning(f"{software_name}: 复制快捷方式失败 - {str(err)}")
            else:
                self.installer_logger.warning(f"{software_name}: 未找到快捷方式: {shortcut_source}")
            
            # 设置系统环境变量MAUMainVersion为"6"
            try:
                self.installer_logger.info(f"{software_name}: 设置系统环境变量MAUMainVersion为'6'")
                subprocess.run(["setx", "/M", "MAUMainVersion", "6"], 
                              check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.installer_logger.info(f"{software_name}: 系统环境变量设置成功")
            except subprocess.CalledProcessError as err:
                self.installer_logger.warning(f"{software_name}: 设置系统环境变量失败 - {str(err)}")
            
            self.installer_logger.info(f"{software_name}: 清理临时文件")
            
            try:
                os.remove(os.path.join(TEMP_DIR, "希沃桌面.lnk"))
                self.installer_logger.info(f"{software_name}: 删除临时文件: 希沃桌面.lnk")
            except Exception as err:
                self.installer_logger.warning(f"{software_name}: 删除希沃桌面.lnk失败 - {str(err)}")
            
            try:
                os.remove(os.path.join(TEMP_DIR, "main.js"))
                self.installer_logger.info(f"{software_name}: 删除临时文件: main.js")
            except Exception as err:
                self.installer_logger.warning(f"{software_name}: 删除main.js失败 - {str(err)}")
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
            self.installer_logger.info(f"{software_name}: 安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 希沃快传安装函数
    def _install_希沃快传(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 希沃集控安装函数
    def _install_希沃集控(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 希沃截图安装函数
    def _install_希沃截图(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            output_dir = r"C:\Program Files (x86)\Seewo"
            self._decompress_7Z(software_name, installer_path, output_dir)
            
            # 拷贝快捷方式到C:\Users\Public\Desktop
            source_shortcut = os.path.join(output_dir, "希沃截图-WHYOS-Gaoo", "希沃截图.lnk")
            dest_shortcut = os.path.join(r"C:\Users\Public\Desktop", "希沃截图.lnk")
            
            if os.path.exists(source_shortcut):
                shutil.copy2(source_shortcut, dest_shortcut)
            else:
                self.installer_logger.warning(f"{software_name}: 未找到快捷方式: {source_shortcut}")
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 希沃批注安装函数
    def _install_希沃批注(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            output_dir = r"C:\Program Files (x86)\Seewo"
            self._decompress_7Z(software_name, installer_path, output_dir)
            
            # 拷贝快捷方式到C:\Users\Public\Desktop
            source_shortcut = os.path.join(output_dir, "希沃批注-WHYOS-Gaoo", "希沃批注.lnk")
            dest_shortcut = os.path.join(r"C:\Users\Public\Desktop", "希沃批注.lnk")
            
            if os.path.exists(source_shortcut):
                shutil.copy2(source_shortcut, dest_shortcut)
            else:
                self.installer_logger.warning(f"{software_name}: 未找到快捷方式: {source_shortcut}")
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 希沃计时器安装函数
    def _install_希沃计时器(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            output_dir = r"C:\Program Files (x86)\Seewo"
            self._decompress_7Z(software_name, installer_path, output_dir)
            
            source_shortcut = os.path.join(output_dir, "希沃计时器-WHYOS-Gaoo", "希沃计时器.lnk")
            dest_shortcut = os.path.join(r"C:\Users\Public\Desktop", "希沃计时器.lnk")
            
            if os.path.exists(source_shortcut):
                shutil.copy2(source_shortcut, dest_shortcut)
            else:
                self.installer_logger.warning(f"{software_name}: 未找到快捷方式: {source_shortcut}")
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 希沃放大镜安装函数
    def _install_希沃放大镜(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            output_dir = r"C:\Program Files (x86)\Seewo"
            self._decompress_7Z(software_name, installer_path, output_dir)
            
            source_shortcut = os.path.join(output_dir, "希沃放大镜-WHYOS-Gaoo", "希沃放大镜.lnk")
            dest_shortcut = os.path.join(r"C:\Users\Public\Desktop", "希沃放大镜.lnk")
            
            if os.path.exists(source_shortcut):
                shutil.copy2(source_shortcut, dest_shortcut)
            else:
                self.installer_logger.warning(f"{software_name}: 未找到快捷方式: {source_shortcut}")
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 希沃浏览器安装函数
    def _install_希沃浏览器(self, software_name, cache_file):
        try:
            download_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            # 调用解压参数解压到C:\Program Files (x86)\Seewo
            extract_dir = "C:\\Program Files (x86)\\Seewo"
            os.makedirs(extract_dir, exist_ok=True)
            self._decompress_7Z(software_name, download_path, extract_dir)
            
            # 拷贝希沃浏览器.lnk到C:\Users\Public\Desktop
            source_lnk = os.path.join(extract_dir, "希沃浏览器-WHYOS-Gaoo", "希沃浏览器.lnk")
            desktop_path = os.path.join(os.environ["PUBLIC"], "Desktop")
            dest_lnk = os.path.join(desktop_path, "希沃浏览器.lnk")
            
            if os.path.exists(source_lnk):
                shutil.copy2(source_lnk, dest_lnk)
            else:
                self.installer_logger.warning(f"{software_name}: 未找到源快捷方式文件: {source_lnk}")
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 希沃智能笔安装函数
    def _install_希沃智能笔(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 反馈器助手安装函数
    def _install_反馈器助手(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 希沃易课堂安装函数
    def _install_希沃易课堂(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 希沃输入法安装函数
    def _install_希沃输入法(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "已安装")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # PPT小工具安装函数
    def _install_PPT小工具(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "已安装")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 希沃轻白板安装函数
    def _install_希沃轻白板(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "已安装")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 希沃白板5安装函数
    def _install_希沃白板5(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "已安装")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 希沃白板3安装函数
    def _install_希沃白板3(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "已安装")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
# ikun启动图安装函数
    def _install_ikun启动图(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            seven_path = None
            if os.path.exists(SEVEN_ZIP_PATH):
                seven_path = SEVEN_ZIP_PATH
            else:
                seven_path = shutil.which("7z") or shutil.which("7za")
            
            if seven_path:
                subprocess.run(
                    [seven_path, "x", installer_path, f"-p{SEVEN_ZIP_PASSWORD}", "-oTemporary", "-y"],
                    check=True,
                    shell=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
                )
            
            appdata = os.environ.get('APPDATA')
            target_dir = os.path.join(appdata, "Seewo", "EasiNote5", "Resources", "Banner")
            os.makedirs(target_dir, exist_ok=True)
            
            source_file = os.path.join("Temporary", "Banner.png")
            target_file = os.path.join(target_dir, "Banner.png")
            shutil.copy2(source_file, target_file)
            
            self._update_status(software_name, "安装完成")
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 白板去除横幅安装函数
    def _install_白板去除横幅(self, software_name, cache_file):
        try:
            self.installer_logger.info(f"{software_name}: 请你确保已安装希沃白板 5，某些白板可能应用不成功")
            
            self.installer_logger.info(f"{software_name}: 开始下载")
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            output_dir = TEMP_DIR
            self.installer_logger.info(f"{software_name}: 开始解压到 {output_dir}")
            self._decompress_7Z(software_name, installer_path, output_dir)
            
            # 复制破解补丁文件到指定目录
            source_file = os.path.join(TEMP_DIR, "SWCoreSharp.SWAuthorization.SWAuthClients.dll")
            dest_file = "C:\\Program Files (x86)\\Seewo\\EasiNote5\\EasiNote5_5.2.2.9633\\Main\\SWCoreSharp.SWAuthorization.SWAuthClients.dll"
            
            # 确保目标目录存在
            dest_dir = os.path.dirname(dest_file)
            os.makedirs(dest_dir, exist_ok=True)
            
            if os.path.exists(source_file):
                # 检查是否有管理员权限
                if not is_admin():
                    self.installer_logger.warning(f"{software_name}: 当前进程没有管理员权限，需要以管理员身份运行才能写入Program Files目录")
                    self._update_status(software_name, "需要管理员权限")
                    # 尝试以管理员身份重启
                    if run_as_admin():
                        self.installer_logger.info(f"{software_name}: 已尝试以管理员身份重启程序，请在新窗口中继续安装")
                        self._update_status(software_name, "请在新窗口中继续")
                        return
                    else:
                        self.installer_logger.error(f"{software_name}: 无法获取管理员权限，请手动以管理员身份运行程序")
                        self._update_status(software_name, "安装失败")
                        raise PermissionError("需要管理员权限才能写入Program Files目录")
                
                # 尝试复制文件
                self.installer_logger.info(f"{software_name}: 复制破解补丁文件到 {dest_file}")
                try:
                    shutil.copy2(source_file, dest_file)
                    self.installer_logger.info(f"{software_name}: 破解补丁文件已复制")
                except PermissionError as pe:
                    self.installer_logger.error(f"{software_name}: 复制文件时权限不足 - {str(pe)}")
                    self._update_status(software_name, "安装失败")
                    # 尝试以管理员身份重启
                    if run_as_admin():
                        self.installer_logger.info(f"{software_name}: 已尝试以管理员身份重启程序，请在新窗口中继续安装")
                        self._update_status(software_name, "请在新窗口中继续")
                    raise
            else:
                self.installer_logger.error(f"{software_name}: 未找到破解补丁文件: {source_file}")
                self._update_status(software_name, "安装失败")
                raise FileNotFoundError(f"未找到破解补丁文件: {source_file}")
            
            # 删除临时文件
            self.installer_logger.info(f"{software_name}: 删除临时文件: {source_file}")
            os.remove(source_file)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
            self.installer_logger.info(f"{software_name}: 安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 班级优化大师安装函数
    def _install_班级优化大师(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "已安装")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 希沃课堂助手安装函数
    def _install_希沃课堂助手(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "已安装")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 希沃电脑助手安装函数
    def _install_希沃电脑助手(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "已安装")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 希沃导播助手安装函数
    def _install_希沃导播助手(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "已安装")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 希沃视频展台安装函数
    def _install_希沃视频展台(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "已安装")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 希沃物联校园安装函数
    def _install_希沃物联校园(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "已安装")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 希沃互动签名安装函数
    def _install_希沃互动签名(self, software_name, cache_file):
        try:
            self.installer_logger.info(f"{software_name}: 开始下载")
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            output_dir = r"C:\Program Files (x86)\Seewo"
            self.installer_logger.info(f"{software_name}: 开始解压到 {output_dir}")
            self._decompress_7Z(software_name, installer_path, output_dir)
            
            shortcut_info = [
                ("古韵水墨风签名.lnk", "创建古韵水墨风签名桌面快捷方式失败"),
                ("简约商务风签名.lnk", "创建简约商务风签名桌面快捷方式失败"),
                ("喜庆中国风签名.lnk", "创建喜庆中国风签名桌面快捷方式失败")
            ]
            
            for shortcut_name, error_msg in shortcut_info:
                source_shortcut = os.path.join(output_dir, "希沃互动签名-WHYOS-Gaoo", shortcut_name)
                dest_shortcut = os.path.join(r"C:\Users\Public\Desktop", shortcut_name)
                
                if os.path.exists(source_shortcut):
                    try:
                        self.installer_logger.info(f"{software_name}: 复制{shortcut_name}到桌面")
                        shutil.copy2(source_shortcut, dest_shortcut)
                        self.installer_logger.info(f"{software_name}: {shortcut_name}已复制到桌面")
                    except Exception:
                        self.installer_logger.warning(f"{software_name}: {error_msg}: {str(e)}")
                else:
                    self.installer_logger.warning(f"{software_name}: 未找到快捷方式: {source_shortcut}")
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
            self.installer_logger.info(f"{software_name}: 安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 希沃伪装插件安装函数
    def _install_希沃伪装插件(self, software_name, cache_file):
        try:
            # 检查希沃白板5快捷方式是否存在
            seewowhiteboard5_lnk = "C:\\Users\\Public\\Desktop\\希沃白板 5.lnk"
            if os.path.exists(seewowhiteboard5_lnk):
                self.installer_logger.info(f"{software_name}: 检测到希沃白板5快捷方式存在")
                
                # 下载希沃伪装插件.7z
                self.installer_logger.info(f"{software_name}: 开始下载")
                installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
                
                # 解压到Temporary目录
                self.installer_logger.info(f"{software_name}: 解压7z文件到Temporary目录")
                output_dir = TEMP_DIR
                self._decompress_7Z(software_name, installer_path, output_dir)
                
                # 启动希沃白板5快捷方式
                self.installer_logger.info(f"{software_name}: 启动希沃白板5快捷方式")
                os.startfile(seewowhiteboard5_lnk)
                
                # EasiNote.exe进程出现后终止（最多等待1分钟）
                self.installer_logger.info(f"{software_name}: 等待EasiNote.exe进程出现")
                if self._wait_for_process(software_name, "EasiNote.exe", timeout=60, check_interval=2):
                    self.installer_logger.info(f"{software_name}: EasiNote.exe进程已出现，等待30秒后终止")
                    time.sleep(30)
                    self._kill_process(software_name, "EasiNote.exe")
                else:
                    self.installer_logger.warning(f"{software_name}: 等待EasiNote.exe进程超时，继续执行")
                
                # 运行Temporary\希沃伪装插件.exe
                伪装插件_exe = os.path.join(TEMP_DIR, "希沃伪装插件.exe")
                if os.path.exists(伪装插件_exe):
                    self.installer_logger.info(f"{software_name}: 运行希沃伪装插件.exe")
                    subprocess.Popen([伪装插件_exe])
                    
                    # 等待三十秒
                    self.installer_logger.info(f"{software_name}: 等待30秒")
                    time.sleep(30)
                    
                    # 终止希沃伪装插件.exe
                    self.installer_logger.info(f"{software_name}: 终止希沃伪装插件.exe进程")
                    self._kill_process(software_name, "希沃伪装插件.exe")
                    
                    self._update_status(software_name, "安装完成")
                    self.installer_logger.info(f"{software_name}: 安装完成")
                else:
                    self.installer_logger.error(f"{software_name}: 安装失败，未找到希沃伪装插件.exe")
                    self._update_status(software_name, "安装失败")
                    raise FileNotFoundError(f"未找到希沃伪装插件.exe，路径不存在: {伪装插件_exe}")
                
                    self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            else:
                # 不存在希沃白板5快捷方式，报错安装失败
                self.installer_logger.error(f"{software_name}: 安装失败，未找到希沃白板5快捷方式")
                self._update_status(software_name, "安装失败")
                raise FileNotFoundError(f"未找到希沃白板5快捷方式，路径不存在: {seewowhiteboard5_lnk}")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    # 远程互动课堂安装函数
    def _install_远程互动课堂(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "已安装")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # AGC解锁工具安装函数
    def _install_AGC解锁工具(self, software_name, cache_file):
        try:
            self.installer_logger.info(f"{software_name}: 开始下载")
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            output_dir = r"C:\Program Files (x86)\Seewo"
            self.installer_logger.info(f"{software_name}: 开始解压到 {output_dir}")
            self._decompress_7Z(software_name, installer_path, output_dir)
            
            source_shortcut = os.path.join(output_dir, "AGC解锁工具-WHYOS-Gaoo", "AGC解锁工具.lnk")
            dest_shortcut = os.path.join(os.environ["PUBLIC"], "Desktop", "AGC解锁工具.lnk")
            
            if os.path.exists(source_shortcut):
                self.installer_logger.info(f"{software_name}: 复制快捷方式到桌面")
                shutil.copy2(source_shortcut, dest_shortcut)
                self.installer_logger.info(f"{software_name}: 快捷方式已复制到桌面")
            else:
                self.installer_logger.warning(f"{software_name}: 未找到快捷方式: {source_shortcut}")
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
            self.installer_logger.info(f"{software_name}: 安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 触摸服务程序安装函数
    def _install_触摸服务程序(self, software_name, cache_file):
        try:
            self.installer_logger.info(f"{software_name}: 开始下载")
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            output_dir = r"C:\Program Files (x86)\Seewo"
            self.installer_logger.info(f"{software_name}: 开始解压到 {output_dir}")
            self._decompress_7Z(software_name, installer_path, output_dir)
            
            # 运行ProjectionBoardTool.exe进行静默安装
            projection_board_tool = os.path.join(output_dir, "ProjectionBoardTool.exe")
            if os.path.exists(projection_board_tool):
                self.installer_logger.info(f"{software_name}: 开始安装ProjectionBoardTool")
                subprocess.run([projection_board_tool, "/S"], check=True, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.installer_logger.info(f"{software_name}: ProjectionBoardTool安装完成")
                
                # 删除ProjectionBoardTool.exe
                self.installer_logger.info(f"{software_name}: 删除ProjectionBoardTool.exe")
                os.remove(projection_board_tool)
            else:
                self.installer_logger.warning(f"{software_name}: 未找到ProjectionBoardTool.exe")
            
            # 复制快捷方式到C:\Users\Public\Desktop
            source_shortcut = os.path.join(output_dir, "触摸服务程序-WHYOS-Gaoo", "触摸服务程序.lnk")
            dest_shortcut = os.path.join(os.environ["PUBLIC"], "Desktop", "触摸服务程序.lnk")
            
            if os.path.exists(source_shortcut):
                self.installer_logger.info(f"{software_name}: 复制快捷方式到桌面")
                shutil.copy2(source_shortcut, dest_shortcut)
                self.installer_logger.info(f"{software_name}: 快捷方式已复制到桌面")
            else:
                self.installer_logger.warning(f"{software_name}: 未找到快捷方式: {source_shortcut}")
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
            self.installer_logger.info(f"{software_name}: 安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 希沃随机抽选安装函数
    def _install_希沃随机抽选(self, software_name, cache_file):
        try:
            self.installer_logger.info(f"{software_name}: 开始下载")
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            output_dir = r"C:\Program Files (x86)\Seewo"
            self.installer_logger.info(f"{software_name}: 开始解压到 {output_dir}")
            self._decompress_7Z(software_name, installer_path, output_dir)
            
            # 复制快捷方式到C:\Users\Public\Desktop
            source_shortcut = os.path.join(output_dir, "希沃随机抽选-WHYOS-Gaoo", "希沃随机抽选.lnk")
            dest_shortcut = os.path.join(os.environ["PUBLIC"], "Desktop", "希沃随机抽选.lnk")
            
            if os.path.exists(source_shortcut):
                self.installer_logger.info(f"{software_name}: 复制快捷方式到桌面")
                shutil.copy2(source_shortcut, dest_shortcut)
                self.installer_logger.info(f"{software_name}: 快捷方式已复制到桌面")
            else:
                self.installer_logger.warning(f"{software_name}: 未找到快捷方式: {source_shortcut}")
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
            self.installer_logger.info(f"{software_name}: 安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 触摸框测试程序安装函数
    def _install_触摸框测试程序(self, software_name, cache_file):
        try:
            self.installer_logger.info(f"{software_name}: 开始下载")
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            output_dir = r"C:\Program Files (x86)\Seewo"
            self.installer_logger.info(f"{software_name}: 开始解压到 {output_dir}")
            self._decompress_7Z(software_name, installer_path, output_dir)
            
            # 复制快捷方式到C:\Users\Public\Desktop
            source_shortcut = os.path.join(output_dir, "触摸框测试程序-WHYOS-Gaoo", "触摸框测试程序.lnk")
            dest_shortcut = os.path.join(os.environ["PUBLIC"], "Desktop", "触摸框测试程序.lnk")
            
            if os.path.exists(source_shortcut):
                self.installer_logger.info(f"{software_name}: 复制快捷方式到桌面")
                shutil.copy2(source_shortcut, dest_shortcut)
                self.installer_logger.info(f"{software_name}: 快捷方式已复制到桌面")
            else:
                self.installer_logger.warning(f"{software_name}: 未找到快捷方式: {source_shortcut}")
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
            self.installer_logger.info(f"{software_name}: 安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 省平台登录插件安装函数
    def _install_省平台登录插件(self, software_name, cache_file):
        try:
            self.installer_logger.info(f"{software_name}: 开始下载")
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            # 运行安装程序
            self.installer_logger.info(f"{software_name}: 开始安装")

            
            # 启动安装程序
            process = subprocess.Popen([installer_path])
            
            # 等待省平台登录插件进程出现
            self._wait_for_process(software_name, "省平台登录插件.exe", timeout=15, check_interval=2)
            
            # 终止安装程序进程
            self._kill_process(software_name, "省平台登录插件.exe")
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
            self.installer_logger.info(f"{software_name}: 安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 希象传屏[发送端]安装函数
    def _install_希象传屏发送端(self, software_name, cache_file):
        installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
        
        self.silent_installation(software_name, installer_path)
        
        self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
    
    # 希象传屏[接收端]安装函数
    def _install_希象传屏接收端(self, software_name, cache_file):
        installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
        
        self.silent_installation(software_name, installer_path)
        
        self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
    
    # 希沃品课[小组端]安装函数
    def _install_希沃品课小组端(self, software_name, cache_file):
        try:
            # 创建安装目录
            install_dir = r"C:\Program Files (x86)\Seewo\SeewoPinK"
            self.installer_logger.info(f"{software_name}: 创建安装目录: {install_dir}")
            os.makedirs(install_dir, exist_ok=True)
            
            self.installer_logger.info(f"{software_name}: 开始下载")
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.installer_logger.info(f"{software_name}: 开始静默安装")
            # 使用/S参数进行静默安装
            process = subprocess.Popen([installer_path, "/S"])
            
            # 等待seewoPincoGroup.exe进程出现
            self._wait_for_process(software_name, "seewoPincoGroup.exe", timeout=20, check_interval=3)
            
            # 等待安装进程退出
            self._wait_for_process_exit(software_name, process, timeout=45, check_interval=5)
            
            # 终止进程（确保已退出）
            self._kill_process(software_name, "seewoPincoGroup.exe")
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
            self.installer_logger.info(f"{software_name}: 安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 希沃品课[教师端]安装函数
    def _install_希沃品课教师端(self, software_name, cache_file):
        try:
            self.installer_logger.info(f"{software_name}: 开始下载")
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.installer_logger.info(f"{software_name}: 开始静默安装")

            
            # 使用/S参数进行静默安装
            process = subprocess.Popen([installer_path, "/S"])
            
            # 等待seewoPincoTeacher.exe进程出现
            self._wait_for_process(software_name, "seewoPincoTeacher.exe", timeout=20, check_interval=3)
            
            # 等待安装进程退出
            self._wait_for_process_exit(software_name, process, timeout=45, check_interval=5)
            
            # 终止进程（确保已退出）
            self._kill_process(software_name, "seewoPincoTeacher.exe")
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
            self.installer_logger.info(f"{software_name}: 安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 易启学[学生端]安装函数
    def _install_易启学学生端(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "已安装")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 易启学[教师端]安装函数
    def _install_易启学教师端(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "已安装")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 微信安装函数
    def _install_微信(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "已安装")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # QQ安装函数
    def _install_QQ(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "已安装")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # UU远程安装函数
    def _install_UU远程(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "已安装")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # 网易云音乐安装函数
    def _install_网易云音乐(self, software_name, cache_file):
        try:
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.silent_installation(software_name, installer_path)
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "已安装")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # office2021安装函数
    def _install_office2021(self, software_name, cache_file):
        try:            
            self.installer_logger.info(f"{software_name}: 开始下载")
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.installer_logger.info(f"{software_name}: 开始安装")

            self.installer_logger.info(f"{software_name}: 运行office2021.exe安装程序")
            office_process = subprocess.Popen([installer_path])
            
            self.installer_logger.info(f"{software_name}: 等待office2021.exe进程结束")
            office_process.wait()
            self.installer_logger.info(f"{software_name}: office2021.exe进程已结束")
            
            self.installer_logger.info(f"{software_name}: 检查并结束OfficeC2RClient.exe进程")
            try:
                subprocess.run(["taskkill", "/f", "/im", "OfficeC2RClient.exe"], check=False, shell=False)
            except Exception:
                self.installer_logger.error(f"{software_name}: 结束OfficeC2RClient.exe进程时出错: {str(e)}")
            
            def check_process_exited():
                try:
                    result = subprocess.run(
                        ["wmic", "process", "where", "name='OfficeC2RClient.exe'", "get", "name"],
                        capture_output=True, text=True, shell=False
                    )
                    return "OfficeC2RClient.exe" not in result.stdout
                except Exception:
                    return True
            
            self._wait_for_condition(software_name, check_process_exited, timeout=10, check_interval=1)
            
            try:
                subprocess.run(["taskkill", "/f", "/im", "OfficeC2RClient.exe"], check=False, shell=False)
            except Exception:
                self.installer_logger.error(f"{software_name}: 再次结束OfficeC2RClient.exe进程时出错: {str(e)}")
            
            self._update_status(software_name, "安装完成")
            self.installer_logger.info(f"{software_name}: 安装完成")
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # ClassIsland2安装函数
    def _install_ClassIsland2(self, software_name, cache_file):
        try:
            self.installer_logger.info(f"{software_name}: 开始下载")
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.installer_logger.info(f"{software_name}: 开始安装")
            
            install_dir = "C:\\ClassIsland2"
            self.installer_logger.info(f"{software_name}: 创建安装目录: {install_dir}")
            os.makedirs(install_dir, exist_ok=True)
            
            self.installer_logger.info(f"{software_name}: 解压文件到: {install_dir}")
            with zipfile.ZipFile(installer_path, 'r') as zip_ref:
                zip_ref.extractall(install_dir)
            
            shortcut_name = "ClassIsland2"
            target_path = os.path.join(install_dir, "ClassIsland.exe")
            public_desktop = os.path.join(os.environ.get("PUBLIC"), "Desktop")
            shortcut_path = os.path.join(public_desktop, f"{shortcut_name}.lnk")
            
            self.installer_logger.info(f"{software_name}: 创建快捷方式到公用桌面: {shortcut_path}")
            try:
                pythoncom.CoInitialize()
                shell = Dispatch('WScript.Shell')
                shortcut = shell.CreateShortCut(shortcut_path)
                shortcut.TargetPath = target_path
                shortcut.WorkingDirectory = install_dir
                shortcut.IconLocation = target_path
                shortcut.save()
                self.installer_logger.info(f"{software_name}: 快捷方式创建成功")
            except Exception as e:
                self.installer_logger.warning(f"{software_name}: 创建快捷方式失败 - {str(e)}")
            finally:
                try:
                    pythoncom.CoUninitialize()
                except Exception:
                    pass
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
            self.installer_logger.info(f"{software_name}: 安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise
    
    # ClassWidgets安装函数
    def _install_ClassWidgets(self, software_name, cache_file):
        try:
            self.installer_logger.info(f"{software_name}: 开始下载")
            installer_path = self._download_file(software_name, cache_file, download_location="Temporary")
            
            self.installer_logger.info(f"{software_name}: 开始安装")
            
            install_dir = "C:\\ClassWidgets"
            self.installer_logger.info(f"{software_name}: 创建安装目录: {install_dir}")
            os.makedirs(install_dir, exist_ok=True)
            
            self.installer_logger.info(f"{software_name}: 解压文件到: {install_dir}")
            with zipfile.ZipFile(installer_path, 'r') as zip_ref:
                zip_ref.extractall(install_dir)
            
            shortcut_name = "ClassWidgets"
            target_path = r"C:\ClassWidgets\ClassWidgets.exe"
            
            public_desktop = os.path.join(os.environ.get("PUBLIC"), "Desktop")
            shortcut_path = os.path.join(public_desktop, f"{shortcut_name}.lnk")
            
            self.installer_logger.info(f"{software_name}: 创建快捷方式到公用桌面: {shortcut_path}")
            try:
                pythoncom.CoInitialize()
                shell = Dispatch('WScript.Shell')
                shortcut = shell.CreateShortCut(shortcut_path)
                shortcut.TargetPath = target_path
                shortcut.WorkingDirectory = r"C:\ClassWidgets"
                shortcut.IconLocation = target_path
                shortcut.save()
                self.installer_logger.info(f"{software_name}: 快捷方式创建成功")
            except Exception as e:
                self.installer_logger.warning(f"{software_name}: 创建快捷方式失败 - {str(e)}")
            finally:
                try:
                    pythoncom.CoUninitialize()
                except Exception:
                    pass
            
            self._cleanup_temp_files(TEMP_DIR, cache_file["filename"], software_name)
            
            self._update_status(software_name, "安装完成")
            self.installer_logger.info(f"{software_name}: 安装完成")
        except Exception as err:
            self.installer_logger.error(f"{software_name}: 安装失败 - {str(err)}", exc_info=True)
            self._update_status(software_name, "安装失败")
            raise

    def _on_window_close(self):
        """窗口关闭事件处理"""
        self.installer_logger.info("窗口关闭事件触发，正常退出应用程序")
        
        # 关闭窗口
        if hasattr(self, 'root') and self.root.winfo_exists():
            self.root.destroy()
        
        # 通知主窗口关闭
        if hasattr(self, '_main_window') and self._main_window:
            self.installer_logger.info("通知主窗口关闭")
            try:
                self._main_window.root.deiconify()  # 显示主窗口
            except Exception:
                self.installer_logger.warning(f"显示主窗口失败: {str(e)}")
        
        # 正常退出应用程序
        self.installer_logger.info("应用程序正常退出")


class CacheWindow:
    """缓存器窗口类 - 与安装器样式一致，用于将选中的软件缓存到 cache 目录"""
    def __init__(self, selected_software, main_window=None):
        self.logger = get_logger("Cache")
        self.logger.info("缓存窗口初始化开始")
        # 初始化标记：在检测缓存与远程大小期间为 True，期间不更新底部汇总状态
        self._initializing = True
        self.root = ctk.CTkToplevel()
        self.root.title(f"SEEVVO全家桶一剑下崽弃 {MainWindowApp.VERSION} - 缓存管理 - 作者：HelloGaoo & WHYOS")
        self.root.geometry(f"{Dimensions.INSTALL_WINDOW_WIDTH}x{Dimensions.INSTALL_WINDOW_HEIGHT}")
        self.root.minsize(Dimensions.INSTALL_WINDOW_MIN_WIDTH, Dimensions.INSTALL_WINDOW_MIN_HEIGHT)
        self.root.resizable(True, True)

        self.root.focus_force()
        self.root.update_idletasks()
        self.root.protocol("WM_DELETE_WINDOW", self._on_window_close)
        
        # 设置窗口图标
        try:
            icon_path = os.path.join(BASE_DIR, "icon", "001.ico")
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
                self.logger.info("缓存窗口图标设置成功")
        except Exception as e:
            self.logger.error(f"设置缓存窗口图标时出错: {e}")

        self._main_window = main_window
        self.selected_software = selected_software

        # 线程池
        self.executor = None

        # 表格
        self.table_frame = None
        self.scrollable_frame = None
        self.col_widths = None
        self.table_rows = {}

        # 限速与更新节流（平衡实时性和性能）
        self.download_rate_limit = getattr(self, 'download_rate_limit', 0)
        self.progress_update_interval = 0.5  # 调整为0.5秒，提高实时性

        self.fonts_logger = get_logger("Fonts")
        self.create_font = create_global_font
        # 是否聚合通知（True=只在全部完成后发送汇总通知；False=仍发送逐项通知）
        self.aggregate_notifications = True

        self._create_all_widgets()
        self.logger.info(f"缓存窗口初始化完成，共 {len(selected_software)} 个软件待缓存")

    def _create_all_widgets(self):
        main_frame = ctk.CTkFrame(self.root, fg_color=Colors.BACKGROUND, corner_radius=0)
        main_frame.pack(fill=ctk.BOTH, expand=True, padx=0, pady=0)

        # 初始化每个软件的汇总状态映射（用于实时统计成功/失败）
        try:
            self._summary_state = {sw: 'not_started' for sw in self.selected_software}
        except Exception:
            self._summary_state = {}

        content_container = ctk.CTkFrame(main_frame, fg_color=Colors.BACKGROUND)
        content_container.pack(fill=ctk.BOTH, expand=True, padx=Dimensions.PADX_LARGE, pady=(Dimensions.PADY_XLARGE, Dimensions.PADY_SMALL))

        card_frame = ctk.CTkFrame(
            content_container,
            corner_radius=Dimensions.CORNER_RADIUS_LARGE,
            border_width=Dimensions.BORDER_WIDTH,
            border_color=Colors.BORDER,
            fg_color=Colors.CARD_BACKGROUND
        )
        card_frame.pack(fill=ctk.BOTH, expand=True, padx=0, pady=0)

        title_bar = ctk.CTkFrame(card_frame, fg_color=Colors.CARD_BACKGROUND, border_width=0, corner_radius=0)
        title_bar.pack(fill=ctk.X, padx=Dimensions.PADX_LARGE, pady=(Dimensions.PADY_LARGE, Dimensions.PADY_MEDIUM))

        title_label = ctk.CTkLabel(
            title_bar,
            text="缓存管理",
            text_color=Colors.TEXT,
            font=self.create_font(24, "bold", logger=self.fonts_logger)
        )
        title_label.pack(anchor="w")

        divider = ctk.CTkFrame(card_frame, fg_color=Colors.SECTION_DIVIDER, border_width=0, height=1)
        divider.pack(fill=ctk.X, padx=Dimensions.PADX_LARGE)

        table_container = ctk.CTkFrame(card_frame, fg_color=Colors.CARD_BACKGROUND, border_width=0, corner_radius=0)
        table_container.pack(fill=ctk.BOTH, expand=True, padx=Dimensions.PADX_LARGE, pady=Dimensions.PADY_LARGE)

        # 表格容器
        self.table_frame = ctk.CTkFrame(table_container, fg_color=Colors.CARD_BACKGROUND, border_width=0)
        self.table_frame.pack(fill=ctk.BOTH, expand=True)

        self.scrollable_frame = ctk.CTkScrollableFrame(self.table_frame, fg_color="transparent", scrollbar_button_color=Colors.BORDER, scrollbar_button_hover_color=Colors.HOVER)
        self.scrollable_frame.pack(fill=ctk.BOTH, expand=True)

        self.col_widths = {
            "缓存名称": 200,
            "缓存状态": 130,
            "远程大小": 130,
            "缓存速度": 130,
            "缓存进度": 130
        }

        header_frame = ctk.CTkFrame(self.scrollable_frame, fg_color=Colors.TABLE_HEADER, border_width=0)
        header_frame.pack(fill=ctk.X, padx=Dimensions.PADY_SMALL, pady=Dimensions.PADY_SMALL)

        headers = ["缓存名称", "缓存状态", "远程大小", "缓存速度", "缓存进度"]
        for i, header in enumerate(headers):
            label = ctk.CTkLabel(
                header_frame,
                text=header,
                text_color=Colors.TABLE_HEADER_TEXT,
                font=self.create_font(18, "bold", logger=self.fonts_logger),
                width=self.col_widths[header],
                anchor="w"
            )
            label.grid(row=0, column=i, padx=Dimensions.PADX_LARGE, pady=Dimensions.PADY_MEDIUM, sticky="w")

        header_divider = ctk.CTkFrame(self.scrollable_frame, fg_color=Colors.BORDER, height=1)
        header_divider.pack(fill=ctk.X, padx=Dimensions.PADY_SMALL)

        # 汇总状态显示（底部）：初始为未开始（先创建，保证后续刷新有目标控件）
        self.summary_frame = ctk.CTkFrame(card_frame, fg_color=Colors.CARD_BACKGROUND, border_width=0)
        self.summary_frame.pack(fill=ctk.X, padx=Dimensions.PADX_LARGE, pady=(0, Dimensions.PADY_SMALL))
        self.summary_status_label = ctk.CTkLabel(
            self.summary_frame,
            text="状态：未开始    完成：成功 0，失败 0",
            text_color=Colors.TEXT_SECONDARY,
            font=self.create_font(16, logger=self.fonts_logger),
            anchor="w"
        )
        self.summary_status_label.pack(anchor="w", padx=Dimensions.PADX_MEDIUM, pady=(Dimensions.PADY_SMALL, 0))

        # 确保内部汇总状态初始正确
        try:
            self._summary_state = {sw: 'not_started' for sw in self.selected_software}
            try:
                self._recalculate_summary_label()
            except Exception:
                pass
        except Exception:
            pass

        # 刷新表格内容并检测 cache 目录（在创建汇总标签之后调用）
        self._refresh_table()

        # 底部开始按钮
        button_frame = ctk.CTkFrame(card_frame, fg_color=Colors.CARD_BACKGROUND, border_width=0)
        button_frame.pack(pady=(0, Dimensions.PADY_LARGE), fill=ctk.X, padx=Dimensions.PADX_LARGE)

        btn_container = ctk.CTkFrame(button_frame, fg_color="transparent")
        btn_container.pack(anchor="e", padx=Dimensions.PADY_SMALL)

        self.start_btn = ctk.CTkButton(
            btn_container,
            text="开始",
            fg_color=Colors.BUTTON,
            hover_color=Colors.BUTTON_HOVER,
            text_color="#ffffff",
            width=Dimensions.BUTTON_WIDTH,
            height=Dimensions.BUTTON_HEIGHT,
            corner_radius=Dimensions.CORNER_RADIUS_MEDIUM,
            font=self.create_font(14, "bold", logger=self.fonts_logger),
            command=self.start_cache_process
        )
        self.start_btn.pack(side="right", padx=Dimensions.PADX_MEDIUM)
        
        # 添加联系信息到主框架底部
        contact_label = ctk.CTkLabel(
            main_frame,
            text="作者：HelloGaoo & WHYOS | 用户需自觉遵守并履行协议。如果资源存在违规或侵犯了您的合法权益，请联系作者我们会及时删除。邮箱：gaoo1228@163.com",
            text_color=Colors.CONTACT_INFO,
            font=self.create_font(12, logger=self.fonts_logger),
            justify=ctk.CENTER
        )
        contact_label.pack(fill=ctk.X, pady=(Dimensions.PADY_SMALL, Dimensions.PADY_MEDIUM), padx=Dimensions.PADX_LARGE)
        
    def _create_table_row(self, parent, software, row_idx, col_widths):
        row_frame = ctk.CTkFrame(parent, fg_color=Colors.TABLE_ROW, border_width=0)
        row_frame.pack(fill=ctk.X, padx=Dimensions.PADY_SMALL, pady=Dimensions.PADY_SMALL)

        name_label = ctk.CTkLabel(row_frame, text=software, text_color=Colors.TEXT, font=self.create_font(18, logger=self.fonts_logger), width=col_widths["缓存名称"], anchor="w")
        name_label.grid(row=0, column=0, padx=Dimensions.PADX_LARGE, pady=Dimensions.PADY_MEDIUM, sticky="w")

        cache_label = ctk.CTkLabel(row_frame, text="检测中", text_color=Colors.TEXT_SECONDARY, font=self.create_font(18, logger=self.fonts_logger), width=col_widths["缓存状态"], anchor="w")
        cache_label.grid(row=0, column=1, padx=Dimensions.PADX_LARGE, pady=Dimensions.PADY_MEDIUM, sticky="w")

        remote_size_label = ctk.CTkLabel(row_frame, text="-", text_color=Colors.TEXT_SECONDARY, font=self.create_font(18, logger=self.fonts_logger), width=col_widths["远程大小"], anchor="w")
        remote_size_label.grid(row=0, column=2, padx=Dimensions.PADX_LARGE, pady=Dimensions.PADY_MEDIUM, sticky="w")

        speed_label = ctk.CTkLabel(row_frame, text="0 KB/s", text_color=Colors.TEXT_SECONDARY, font=self.create_font(18, logger=self.fonts_logger), width=col_widths["缓存速度"], anchor="w")
        speed_label.grid(row=0, column=3, padx=Dimensions.PADX_LARGE, pady=Dimensions.PADY_MEDIUM, sticky="w")

        progress_text = ctk.CTkLabel(row_frame, text="0%", text_color=Colors.TEXT_SECONDARY, font=self.create_font(18, logger=self.fonts_logger), width=col_widths["缓存进度"], anchor="w")
        progress_text.grid(row=0, column=4, padx=Dimensions.PADX_LARGE, pady=Dimensions.PADY_MEDIUM, sticky="w")

        self.table_rows[software] = {
            "row_frame": row_frame,
            "cache_label": cache_label,
            "remote_size_label": remote_size_label,
            "speed_label": speed_label,
            "progress_text": progress_text
        }

    def _refresh_table(self):
        # 清除旧行（保留表头和分隔线）
        if hasattr(self, 'scrollable_frame'):
            children = self.scrollable_frame.winfo_children()
            for widget in children:
                if isinstance(widget, ctk.CTkFrame) and widget not in (children[0], children[1]):
                    widget.destroy()

        self.table_rows = {}
        for idx, software in enumerate(self.selected_software):
            self._create_table_row(self.scrollable_frame, software, idx + 1, self.col_widths)

        def check_one(software):
            cache_file = next((item for item in CACHE_FILES if software in item["filename"] or item["filename"].startswith(software)), None)
            if not cache_file:
                self.root.after(0, lambda s=software: self._set_cache_status(s, "未缓存"))
                self.root.after(0, lambda s=software: self._set_remote_size(s, 0))
                return

            filename = cache_file["filename"]
            local_path = os.path.join(CACHE_DIR, filename)

            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            server_size = None
            try:
                resp = requests.head(get_download_url(cache_file), headers=headers, timeout=10, allow_redirects=True, verify=False)
                if resp.status_code == 200 and "content-length" in resp.headers:
                    server_size = int(resp.headers["content-length"])
                    self.root.after(0, lambda s=software, ss=server_size: self._set_remote_size(s, ss))
                else:
                    self.root.after(0, lambda s=software: self._set_remote_size(s, 0))
            except Exception:
                self.root.after(0, lambda s=software: self._set_remote_size(s, 0))

            if os.path.exists(local_path):
                if server_size is not None:
                    try:
                        local_size = os.path.getsize(local_path)
                        if local_size == server_size:
                            self.root.after(0, lambda s=software: self._set_cache_status(s, "已缓存"))
                            return
                        else:
                            # 大小不一致，删除本地文件
                            try:
                                os.remove(local_path)
                            except Exception:
                                pass
                            self.root.after(0, lambda s=software: self._set_cache_status(s, "未缓存"))
                            return
                    except Exception:
                        self.root.after(0, lambda s=software: self._set_cache_status(s, "未缓存"))
                        return
                else:
                    # 无法获取服务器大小，标记为未缓存以便用户手动缓存
                    self.root.after(0, lambda s=software: self._set_cache_status(s, "未缓存"))
                    return
            else:
                self.root.after(0, lambda s=software: self._set_cache_status(s, "未缓存"))

        loading = LoadingWindow(self.root, title="初始化", message="正在检测缓存与远程大小")
        try:
            self.cache_executor = ThreadPoolExecutor(max_workers=(os.cpu_count() or 4))
            self.cache_futures = [self.cache_executor.submit(check_one, sw) for sw in self.selected_software]
        except Exception:
            # 提交失败则关闭加载窗口并标记未缓存
            try:
                loading.close()
            except Exception:
                pass
            for sw in self.selected_software:
                self.root.after(0, lambda s=sw: self._set_cache_status(s, "未缓存"))
            return

        # 监控 futures 完成状态，完成后关闭加载窗口
        def monitor_futures():
            try:
                all_done = all(f.done() for f in getattr(self, 'cache_futures', []))
                if not all_done:
                    self.root.after(300, monitor_futures)
                else:
                    try:
                        loading.close()
                    except Exception:
                        pass
                    try:
                        self.cache_executor.shutdown(wait=False)
                    except Exception:
                        pass
                    # 初始检测完成：取消初始化标记，并重置汇总为未开始
                    try:
                        self._initializing = False
                        # 将内部汇总状态重置为未开始，界面底部显示未开始
                        try:
                            self._summary_state = {sw: 'not_started' for sw in self.selected_software}
                            self._recalculate_summary_label()
                        except Exception:
                            pass
                    except Exception:
                        pass
            except Exception:
                try:
                    loading.close()
                except Exception:
                    pass

        self.root.after(300, monitor_futures)

    def _set_cache_status(self, software, status):
        try:
            row = self.table_rows.get(software)
            if not row:
                return
            lbl = row.get("cache_label")
            if lbl and getattr(lbl, "winfo_exists", lambda: False)():
                lbl.configure(text=status)
            # 当缓存状态为已缓存时，设置缓存速度为已缓存
            if status == "已缓存":
                speed_lbl = row.get("speed_label")
                if speed_lbl and getattr(speed_lbl, "winfo_exists", lambda: False)():
                    speed_lbl.configure(text="已缓存")
                # 已缓存，设置进度为100%
                progress_lbl = row.get("progress_text")
                if progress_lbl and getattr(progress_lbl, "winfo_exists", lambda: False)():
                    progress_lbl.configure(text="100%")
            elif status == "缓存失败":
                # 缓存失败，设置进度为0%
                progress_lbl = row.get("progress_text")
                if progress_lbl and getattr(progress_lbl, "winfo_exists", lambda: False)():
                    progress_lbl.configure(text="0%")
            # 更新实时汇总状态
            # 在初始化（检测缓存与远端大小）期间不要更新汇总状态
            try:
                if not getattr(self, '_initializing', False):
                    if hasattr(self, '_update_summary_state'):
                        try:
                            self._update_summary_state(software, status)
                        except Exception:
                            pass
            except Exception:
                pass
        except Exception:
            pass

    def _set_remote_size(self, software, size):
        try:
            row = self.table_rows.get(software)
            if not row:
                return
            # 处理特殊值：None 或 -1 表示获取失败
            if size is None or (isinstance(size, int) and size < 0):
                txt = "获取失败"
            else:
                # 格式化大小
                if size < 1024:
                    txt = f"{size} B"
                elif size < 1024 * 1024:
                    txt = f"{size/1024:.2f} KB"
                else:
                    txt = f"{size/(1024*1024):.2f} MB"
            lbl = row.get("remote_size_label")
            if lbl and getattr(lbl, "winfo_exists", lambda: False)():
                lbl.configure(text=txt)
        except Exception:
            pass

    def _update_speed(self, software, speed):
        try:
            row = self.table_rows.get(software)
            if not row:
                return
            lbl = row.get("speed_label")
            if lbl and getattr(lbl, "winfo_exists", lambda: False)():
                lbl.configure(text=speed)
        except Exception:
            pass

    def _update_progress(self, software, progress):
        try:
            row = self.table_rows.get(software)
            if not row:
                return
            lbl = row.get("progress_text")
            if lbl and getattr(lbl, "winfo_exists", lambda: False)():
                lbl.configure(text=f"{progress}%")
        except Exception:
            pass

    def _update_summary_state(self, software, status):
        """内部：将表格状态映射到 summary_state 并刷新底部汇总标签。"""
        try:
            if not hasattr(self, '_summary_state'):
                self._summary_state = {sw: 'not_started' for sw in self.selected_software}
            # 规范化状态
            norm = None
            if status in ("已缓存",):
                norm = 'success'
            elif status in ("下载中", "检测中"):
                norm = 'downloading'
            else:
                norm = 'other'  # 将"未缓存"等状态映射为'other'

            prev = self._summary_state.get(software)
            if prev == norm:
                # 无变更
                return
            self._summary_state[software] = norm
            # 刷新汇总显示
            try:
                self._recalculate_summary_label()
            except Exception:
                pass
        except Exception:
            pass

    def _recalculate_summary_label(self):
        try:
            success = sum(1 for v in self._summary_state.values() if v == 'success')
            failed = sum(1 for v in self._summary_state.values() if v == 'failed')
            in_progress = any(v in ('installing', 'downloading') for v in self._summary_state.values())

            # 确定状态文本
            if in_progress:
                state_text = '进行中'
            elif success + failed == 0:
                state_text = '未开始'
            else:
                state_text = '已结束'
                
            if hasattr(self, 'summary_status_label') and getattr(self.summary_status_label, 'winfo_exists', lambda: False)():
                try:
                    self.summary_status_label.configure(text=f"状态：{state_text}    完成：成功 {success}，失败 {failed}")
                except Exception:
                    pass
        except Exception:
            pass

    def start_cache_process(self):
        self.logger.info("开始缓存过程")
        self.start_btn.configure(state="disabled")
        
        # 禁用窗口关闭按钮
        self.root.protocol("WM_DELETE_WINDOW", lambda: None)

        # 更新汇总状态为 缓存中
        try:
            if hasattr(self, 'summary_status_label') and getattr(self.summary_status_label, 'winfo_exists', lambda: False)():
                try:
                    self.summary_status_label.configure(text="状态：缓存中    完成：成功 0，失败 0")
                except Exception:
                    pass
        except Exception:
            pass
        # 重置内部统计状态
        try:
            self._summary_state = {sw: 'not_started' for sw in self.selected_software}
            # 立即标记为下载中状态
            for sw in list(self._summary_state.keys()):
                self._summary_state[sw] = 'downloading'
                # 检查缓存状态，如果已缓存则设置进度为100%
                row = self.table_rows.get(sw)
                if row:
                    cache_label = row.get("cache_label")
                    if cache_label and getattr(cache_label, "winfo_exists", lambda: False)():
                        cache_status = cache_label.cget("text")
                        if cache_status == "已缓存":
                            # 已缓存，设置进度为100%
                            self.root.after(0, lambda s=sw: self._update_progress(s, 100))
                        elif cache_status == "缓存失败":
                            # 缓存失败，设置进度为0%
                            self.root.after(0, lambda s=sw: self._update_progress(s, 0))
            # 刷新汇总显示
            try:
                self._recalculate_summary_label()
            except Exception:
                pass
        except Exception:
            pass

        cachable = []
        for software in self.selected_software:
            cache_file = next((item for item in CACHE_FILES if software in item["filename"] or item["filename"].startswith(software)), None)
            if cache_file:
                cachable.append((software, cache_file))

        if not cachable:
            self.logger.info("没有可缓存的软件")
            self.start_btn.configure(state="normal")
            return

        # 线程池
        max_workers = os.cpu_count() if os.cpu_count() else 4
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.futures = []
        for software, cache_file in cachable:
            fut = self.executor.submit(self._cache_software, software, cache_file)
            # store tuple (future, software) for later reporting
            self.futures.append((fut, software))

        def wait_tasks():
            all_done = all(fut.done() for fut, _ in self.futures)
            if not all_done:
                self.root.after(1000, wait_tasks)
            else:
                try:
                    self.executor.shutdown(wait=True)
                except Exception:
                    pass

                # 统计成功/失败，优先参考表格状态（已缓存视为成功），否则根据 future.exception() 决定
                success = 0
                failed = 0
                total = len(self.futures)
                failed_list = []
                for fut, sw in self.futures:
                    try:
                        exc = fut.exception(timeout=0)
                    except Exception:
                        exc = None

                    if exc is not None:
                        failed += 1
                        failed_list.append(sw)
                        continue

                    # 若没有异常，再次以表格状态为准
                    try:
                        row = self.table_rows.get(sw)
                        lbl = row.get("cache_label") if row else None
                        text = None
                        if lbl and getattr(lbl, "winfo_exists", lambda: False)():
                            try:
                                text = lbl.cget("text")
                            except Exception:
                                text = None
                        if text == "已缓存":
                            success += 1
                        else:
                            failed += 1
                            failed_list.append(sw)
                    except Exception:
                        failed += 1
                        failed_list.append(sw)

                if failed == 0:
                    send_notification("SEEVVO全家桶一剑下崽弃", f"共 {total} 个软件，全部缓存成功", timeout=8)
                else:
                    send_notification("SEEVVO全家桶一剑下崽弃", f"共 {total} 个软件：成功 {success}，失败 {failed}", timeout=8)
                try:
                    if hasattr(self, 'summary_status_label') and getattr(self.summary_status_label, 'winfo_exists', lambda: False)():
                        try:
                            status_text = f"状态：已结束    完成：成功 {success}，失败 {failed}"
                            self.summary_status_label.configure(text=status_text)
                        except Exception:
                            pass
                except Exception:
                    pass

                self.start_btn.configure(state="normal")
                
                # 启用窗口关闭按钮
                self.root.protocol("WM_DELETE_WINDOW", self._on_window_close)

                # 显示结果覆盖层
                self.logger.info(f"准备显示结果覆盖层，成功: {success}, 失败: {failed}")
                def show_overlay():
                    try:
                        if failed == 0:
                            message = f"共 {success} 个软件缓存成功！"
                            subtext = "缓存过程已顺利完成，所有软件均已成功缓存到cache目录中。"
                        else:
                            message = f"缓存完成，但有 {failed} 个软件缓存失败"
                            subtext = f"成功缓存 {success} 个软件，失败 {failed} 个软件。您可以查看日志了解详细信息。"
                        self.logger.info(f"创建ResultOverlay实例，标题: 缓存完成, 消息: {message}")
                        overlay = ResultOverlay(
                            parent=self.root,
                            title="缓存完成",
                            message=message,
                            subtext=subtext,
                            success_count=success,
                            failed_count=failed,
                            operation_type="缓存"
                        )
                        self.logger.info("ResultOverlay实例创建成功")
                        # 强制刷新GUI
                        self.root.update_idletasks()
                    except Exception:
                        self.logger.error(f"显示结果覆盖层失败: {str(e)}", exc_info=True)
                # 在主线程中显示结果覆盖层
                self.root.after(0, show_overlay)

        self.root.after(1000, wait_tasks)

    def _cache_software(self, software, cache_file):
        """缓存单个软件到 cache 目录，使用与安装器相同的下载方式"""
        filename = cache_file["filename"]
        download_path = os.path.join(CACHE_DIR, filename)
        url = get_download_url(cache_file)

        # 若已存在且已被标记为已缓存，跳过
        if os.path.exists(download_path):
            # 由刷新时已经处理过一致性，这里尽量再验证一次
            try:
                resp = requests.head(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=10, allow_redirects=True)
                if resp.status_code == 200 and "content-length" in resp.headers:
                    server_size = int(resp.headers["content-length"])
                    if os.path.getsize(download_path) == server_size:
                        self.root.after(0, lambda s=software: self._set_cache_status(s, "已缓存"))
                        if not getattr(self, 'aggregate_notifications', True):
                            try:
                                notification.notify(title="SEEVVO全家桶一剑下崽弃", message=f"{software} 已存在且完整，已标记为已缓存", app_icon=icon_path if os.path.exists(icon_path) else None)
                            except Exception:
                                pass
                        return
                    else:
                        try:
                            os.remove(download_path)
                        except Exception:
                            pass
            except Exception:
                pass

        # 开始下载（使用与安装器相同的共享下载实现）
        self.root.after(0, lambda s=software: self._set_cache_status(s, "下载中"))
        try:
            try:
                shared_download_file(
                    software,
                    cache_file,
                    download_path,
                    status_cb=lambda st: self.root.after(0, lambda s=software, st2=st: self._set_cache_status(s, st2)),
                    progress_cb=lambda p: self.root.after(0, lambda s=software, p2=p: self._update_progress(s, p2)),
                    speed_cb=lambda sp: self.root.after(0, lambda s=software, sp2=sp: self._update_speed(s, sp2)),
                    logger=get_logger("Cache"),
                    download_rate_limit=0,
                    progress_update_interval=self.progress_update_interval,
                )
            except Exception:
                # 共享下载实现已负责重试与状态回调，这里记录并（可选）通知
                if not getattr(self, 'aggregate_notifications', True):
                    try:
                        notification.notify(title="SEEVVO全家桶一剑下崽弃", message=f"{software} 缓存失败：{str(e)}", app_icon=icon_path if os.path.exists(icon_path) else None)
                    except Exception:
                        pass
                self.root.after(0, lambda s=software: self._set_cache_status(s, "未缓存"))
                return

            # 下载完成：确保进度被标为100%，校验远端大小更新远程大小显示
            self.root.after(0, lambda s=software: self._update_progress(s, 100))
            # 再次尝试获取远程大小
            try:
                head = requests.head(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=10, allow_redirects=True, verify=False)
                if head.status_code == 200 and "content-length" in head.headers:
                    server_size = int(head.headers["content-length"])
                    self.root.after(0, lambda s=software, ss=server_size: self._set_remote_size(s, ss))
                    if os.path.getsize(download_path) == server_size:
                        self.root.after(0, lambda s=software: self._set_cache_status(s, "已缓存"))
                        if not getattr(self, 'aggregate_notifications', True):
                            try:
                                notification.notify(title="SEEVVO全家桶一剑下崽弃", message=f"{software} 缓存已完成", app_icon=icon_path if os.path.exists(icon_path) else None)
                            except Exception:
                                pass
                    else:
                        try:
                            os.remove(download_path)
                        except Exception:
                            pass
                        self.root.after(0, lambda s=software: self._set_cache_status(s, "未缓存"))
                        if not getattr(self, 'aggregate_notifications', True):
                            try:
                                notification.notify(title="SEEVVO全家桶一剑下崽弃", message=f"{software} 缓存失败：大小不一致", app_icon=icon_path if os.path.exists(icon_path) else None)
                            except Exception:
                                pass
                else:
                    # 没有远程大小信息，仍视为已缓存
                    # 标记远程大小获取失败
                    self.root.after(0, lambda s=software: self._set_remote_size(s, -1))
                    self.root.after(0, lambda s=software: self._set_cache_status(s, "已缓存"))
                    if not getattr(self, 'aggregate_notifications', True):
                        try:
                            notification.notify(title="SEEVVO全家桶一剑下崽弃", message=f"{software} 缓存已完成（远端无大小信息）", app_icon=icon_path if os.path.exists(icon_path) else None)
                        except Exception:
                            pass
            except Exception:
                # HEAD 请求失败或其他异常，若文件存在则标为已缓存，否则标为未缓存
                try:
                    if os.path.exists(download_path):
                        # HEAD 失败，显示远程大小获取失败并视为已缓存
                        self.root.after(0, lambda s=software: self._set_remote_size(s, -1))
                        self.root.after(0, lambda s=software: self._set_cache_status(s, "已缓存"))
                        if not getattr(self, 'aggregate_notifications', True):
                            try:
                                notification.notify(title="SEEVVO全家桶一剑下崽弃", message=f"{software} 缓存已完成", app_icon=icon_path if os.path.exists(icon_path) else None)
                            except Exception:
                                pass
                    else:
                        self.root.after(0, lambda s=software: self._set_cache_status(s, "未缓存"))
                        if not getattr(self, 'aggregate_notifications', True):
                            try:
                                notification.notify(title="SEEVVO全家桶一剑下崽弃", message=f"{software} 缓存失败（文件缺失）", app_icon=icon_path if os.path.exists(icon_path) else None)
                            except Exception:
                                pass
                except Exception:
                    self.root.after(0, lambda s=software: self._set_cache_status(s, "未缓存"))
                    if not getattr(self, 'aggregate_notifications', True):
                        try:
                            notification.notify(title="SEEVVO全家桶一剑下崽弃", message=f"{software} 缓存异常", app_icon=icon_path if os.path.exists(icon_path) else None)
                        except Exception:
                            pass

            # 下载完成后再次校验大小
            try:
                total_size = locals().get('server_size', None)
                if total_size and total_size > 0:
                    if os.path.getsize(download_path) == total_size:
                        self.root.after(0, lambda s=software: self._set_cache_status(s, "已缓存"))
                        if not getattr(self, 'aggregate_notifications', True):
                            try:
                                notification.notify(title="SEEVVO全家桶一剑下崽弃", message=f"{software} 缓存已完成", app_icon=icon_path if os.path.exists(icon_path) else None)
                            except Exception:
                                pass
                    else:
                        # 大小不一致，删除
                        try:
                            os.remove(download_path)
                        except Exception:
                            pass
                        self.root.after(0, lambda s=software: self._set_cache_status(s, "未缓存"))
                        if not getattr(self, 'aggregate_notifications', True):
                            try:
                                notification.notify(title="SEEVVO全家桶一剑下崽弃", message=f"{software} 缓存失败：大小不一致", app_icon=icon_path if os.path.exists(icon_path) else None)
                            except Exception:
                                pass
                else:
                    # 无远程大小信息：保留文件并视为已缓存，远程大小显示为获取失败
                    try:
                        self.root.after(0, lambda s=software: self._set_remote_size(s, -1))
                        self.root.after(0, lambda s=software: self._set_cache_status(s, "已缓存"))
                        if not getattr(self, 'aggregate_notifications', True):
                            try:
                                notification.notify(title="SEEVVO全家桶一剑下崽弃", message=f"{software} 缓存已完成（远端无大小信息）", app_icon=icon_path if os.path.exists(icon_path) else None)
                            except Exception:
                                pass
                    except Exception:
                        self.root.after(0, lambda s=software: self._set_cache_status(s, "未缓存"))
                        if not getattr(self, 'aggregate_notifications', True):
                            try:
                                notification.notify(title="SEEVVO全家桶一剑下崽弃", message=f"{software} 缓存异常", app_icon=icon_path if os.path.exists(icon_path) else None)
                            except Exception:
                                pass
            except Exception:
                self.root.after(0, lambda s=software: self._set_cache_status(s, "未缓存"))
                if not getattr(self, 'aggregate_notifications', True):
                    try:
                        notification.notify(title="SEEVVO全家桶一剑下崽弃", message=f"{software} 缓存异常", app_icon=icon_path if os.path.exists(icon_path) else None)
                    except Exception:
                        pass
        except Exception as e:
            self.logger.error(f"{software}: 缓存下载失败 - {e}")
            self.root.after(0, lambda s=software: self._set_cache_status(s, "未缓存"))
            if not getattr(self, 'aggregate_notifications', True):
                try:
                    notification.notify(title="SEEVVO全家桶一剑下崽弃", message=f"{software} 缓存失败：{e}", app_icon=icon_path if os.path.exists(icon_path) else None)
                except Exception:
                    pass

    def _on_window_close(self):
        try:
            if hasattr(self, '_main_window') and self._main_window and hasattr(self._main_window, 'root'):
                try:
                    if self._main_window.root.winfo_exists():
                        self._main_window.root.deiconify()
                        try:
                            self._main_window.root.focus_force()
                        except Exception:
                            pass
                except TclError:
                    pass
        except Exception:
            pass
        try:
            if hasattr(self, 'executor') and self.executor is not None:
                self.executor.shutdown(wait=False)
        except Exception:
            pass
        try:
            if hasattr(self, 'root') and self.root.winfo_exists():
                self.root.destroy()
        except Exception:
            pass

class LoadingWindow:
    #在父窗口上创建覆盖层，覆盖父窗口内容并居中显示初始化信息。

    #API 与原先保持一致：`LoadingWindow(parent, title, message)`、`set_subtext(text)`、`close()`。
    def __init__(self, parent, title="初始化", message="正在初始化"):
        self.parent = parent
        self._running = True

        try:
            # 覆盖层为父窗口内的全尺寸 Frame，设置为纯白色背景
            self.root = ctk.CTkFrame(parent, fg_color="#ffffff", corner_radius=0)
        except Exception:
            # 回退到白色
            self.root = ctk.CTkFrame(parent, fg_color="#ffffff", corner_radius=0)

        # 半透明效果：customtkinter 不直接支持 alpha 背景，这里使用深色背景并降低前景元素亮度
        try:
            self.root.place(relx=0, rely=0, relwidth=1, relheight=1)
            self.root.lift()
        except Exception:
            pass

        # 阻止父窗口在初始化期间被关闭（覆盖期间不可关闭）
        try:
            toplevel = parent.winfo_toplevel()
            self._toplevel = toplevel
            try:
                self._prev_wm_delete = toplevel.protocol("WM_DELETE_WINDOW")
            except Exception:
                self._prev_wm_delete = None
            try:
                toplevel.protocol("WM_DELETE_WINDOW", lambda: None)
            except Exception:
                pass
            try:
                toplevel.grab_set()
            except Exception:
                pass
        except Exception:
            self._toplevel = None
            self._prev_wm_delete = None

        # 两层次布局：将容器垂直居中，整体向上偏移11px
        container = ctk.CTkFrame(self.root, fg_color="transparent", corner_radius=0)
        try:
            # 使用 anchor='center' 将容器中心置于窗口中心，然后向上偏移 y=-11
            container.place(relx=0.5, rely=0.5, anchor='center', y=-11)
        except Exception:
            # 回退到之前的下移位置（更靠下一些）
            try:
                container.place(relx=0.5, rely=0.30, anchor='n')
            except Exception:
                container.place(relx=0.5, rely=0.26, anchor='n')

        card = ctk.CTkFrame(container, fg_color=Colors.CARD_BACKGROUND, corner_radius=8)
        card.pack(padx=12, pady=12)

        # 粗体标题（中上层）
        title_label = ctk.CTkLabel(
            card,
            text=title if title else "初始化",
            text_color="#000000",
            font=create_global_font(34, "bold", logger=get_logger("Fonts")),
            anchor="center",
            justify=ctk.CENTER
        )
        title_label.pack(padx=20, pady=(12, 6))

        # 初始化状态文案（位于标题下方）
        self.sub_label = ctk.CTkLabel(card, text=message, text_color="#000000", font=create_global_font(20, logger=get_logger("Fonts")), anchor="center", justify=ctk.CENTER)
        self.sub_label.pack(padx=20, pady=(0, 8))

        # 加载动画：三个横向点的循环高亮（深 浅 浅 -> 浅 深 浅 -> 浅 浅 深），深色点略大
        try:
            size = 80
            canvas_bg = Colors.CARD_BACKGROUND if hasattr(Colors, 'CARD_BACKGROUND') else '#ffffff'
            self._spinner_canvas = tk.Canvas(card, width=size, height=size, bg=canvas_bg, highlightthickness=0)
            self._spinner_canvas.pack(pady=(0, 12))

            cx = size / 2
            cy = size / 2
            spacing = 22
            self._three_dot_ids = []
            self._three_dot_centers = []
            self._min_side = 8
            self._max_side = 22
            for i in range(3):
                x = cx + (i - 1) * spacing
                y = cy
                side = self._min_side
                oid = self._spinner_canvas.create_oval(x - side/2, y - side/2, x + side/2, y + side/2, fill='#000000', outline='')
                self._three_dot_ids.append(oid)
                self._three_dot_centers.append((x, y))

            # 初始化动画索引：0 表示第一个点为深色
            self._dot_index = 0
            self._dot_interval = 360
            self._deep_color = "#111111"
            self._light_color = "#d0d0d0"
            self._dot_phase = 0.0
        except Exception:
            # 回退的字符动画
            self._spinner_chars = ["|", "/", "-", "\\"]
            self._spinner_idx = 0
            self._animate_label = ctk.CTkLabel(card, text=self._spinner_chars[0], text_color="#000000", font=create_global_font(34, logger=get_logger("Fonts")))
            self._animate_label.pack(pady=(0, 12))

        self._animate()

    def _animate(self):
        if not self._running:
            return
        try:
            # 优先使用三个点的循环高亮动画（若已创建）
            if hasattr(self, '_three_dot_ids') and hasattr(self, '_three_dot_centers') and hasattr(self, '_spinner_canvas'):
                try:
                    idx = getattr(self, '_dot_index', 0)
                    deep = getattr(self, '_deep_color', '#111111')
                    light = getattr(self, '_light_color', '#d0d0d0')
                    for i, oid in enumerate(self._three_dot_ids):
                        try:
                            if i == idx:
                                # 深色点略大一点
                                side = self._min_side + (self._max_side - self._min_side) * 0.28
                                color = deep
                            else:
                                side = self._min_side
                                color = light
                            x, y = self._three_dot_centers[i]
                            self._spinner_canvas.coords(oid, x - side/2, y - side/2, x + side/2, y + side/2)
                            self._spinner_canvas.itemconfigure(oid, fill=color)
                        except Exception:
                            pass

                    # 前进到下一个高亮点
                    try:
                        self._dot_index = (idx + 1) % 3
                    except Exception:
                        self._dot_index = 0

                    interval = getattr(self, '_dot_interval', 360)
                    self.parent.after(interval, self._animate)
                    return
                except Exception:
                    pass

            # 若使用 Canvas 的细线分段旋转环
            if hasattr(self, '_spinner_canvas') and hasattr(self, '_spinner_seg_ids'):
                self._spinner_head = (self._spinner_head + 1) % self._spinner_n
                for i, oid in enumerate(self._spinner_seg_ids):
                    offset = (i - self._spinner_head) % self._spinner_n
                    t = (self._spinner_n - offset) / self._spinner_n
                    t = max(0.0, min(1.0, t))
                    # 伸缩比例（从 min 到 max）
                    scale = 0.2 + 0.8 * (t ** 1.6)
                    side = self._min_side + (self._max_side - self._min_side) * scale
                    x, y, cos_a, sin_a = self._spinner_seg_coords[i]
                    try:
                        self._spinner_canvas.coords(oid, x - side/2, y - side/2, x + side/2, y + side/2)
                        color = self._blend(self._seg_color_from, self._seg_color_to, t)
                        self._spinner_canvas.itemconfigure(oid, fill=color)
                    except Exception:
                        pass
                self.parent.after(60, self._animate)
            else:
                # 回退的字符动画
                self._spinner_idx = (self._spinner_idx + 1) % len(self._spinner_chars)
                try:
                    self._animate_label.configure(text=self._spinner_chars[self._spinner_idx])
                except Exception:
                    pass
                self.parent.after(160, self._animate)
        except Exception:
            pass

    def set_subtext(self, text):
        try:
            self.sub_label.configure(text=text)
        except Exception:
            pass

    def close(self):
        self._running = False
        # 恢复窗口关闭行为并释放 grab
        try:
            if getattr(self, '_toplevel', None):
                try:
                    prev = getattr(self, '_prev_wm_delete', None)
                    if prev:
                        try:
                            self._toplevel.protocol("WM_DELETE_WINDOW", prev)
                        except Exception:
                            pass
                except Exception:
                    pass
                try:
                    self._toplevel.grab_release()
                except Exception:
                    pass
        except Exception:
            pass
        try:
            self.root.place_forget()
        except Exception:
            try:
                self.root.destroy()
            except Exception:
                pass


class ResultOverlay:
    #在父窗口上创建覆盖层，覆盖父窗口内容并居中显示操作结果信息。
    def __init__(self, parent, title="操作完成", message="操作已完成", subtext="", success_count=0, failed_count=0, operation_type="安装"):
        """初始化结果覆盖层
        
        Args:
            parent: 父窗口
            title: 标题文本
            message: 主消息文本
            subtext: 小字说明文本
            success_count: 成功数量
            failed_count: 失败数量
            operation_type: 操作类型（"安装"或"缓存"）
        """
        self.parent = parent
        self.success_count = success_count
        self.failed_count = failed_count
        self.operation_type = operation_type

        # 创建覆盖层框架，设置为纯白色背景
        try:
            self.root = ctk.CTkFrame(parent, fg_color="#ffffff", corner_radius=0)
        except Exception:
            self.root = ctk.CTkFrame(parent, fg_color="#ffffff", corner_radius=0)

        # 放置覆盖层并提升层级
        try:
            self.root.place(relx=0, rely=0, relwidth=1, relheight=1)
            self.root.lift()
        except Exception:
            pass

        # 阻止父窗口在覆盖层显示期间被关闭
        try:
            toplevel = parent.winfo_toplevel()
            self._toplevel = toplevel
            try:
                self._prev_wm_delete = toplevel.protocol("WM_DELETE_WINDOW")
            except Exception:
                self._prev_wm_delete = None
            try:
                toplevel.protocol("WM_DELETE_WINDOW", lambda: None)
            except Exception:
                pass
            try:
                toplevel.grab_set()
            except Exception:
                pass
        except Exception:
            self._toplevel = None
            self._prev_wm_delete = None

        # 两层次布局：将容器垂直居中，并整体向上偏移约 0.3cm（≈11px）
        container = ctk.CTkFrame(self.root, fg_color="transparent", corner_radius=0)
        try:
            container.place(relx=0.5, rely=0.5, anchor='center', y=-11)
        except Exception:
            try:
                container.place(relx=0.5, rely=0.30, anchor='n')
            except Exception:
                container.place(relx=0.5, rely=0.26, anchor='n')

        # 卡片框架
        card = ctk.CTkFrame(container, fg_color=Colors.CARD_BACKGROUND, corner_radius=8)
        card.pack(padx=12, pady=12)

        # 标题（与初始化覆盖层保持一致）
        title_label = ctk.CTkLabel(
            card,
            text=title,
            text_color="#000000",
            font=create_global_font(34, "bold", logger=get_logger("Fonts")),
            anchor="center",
            justify=ctk.CENTER
        )
        title_label.pack(padx=20, pady=(12, 6))

        # 主消息文本
        self.message_label = ctk.CTkLabel(
            card,
            text=message,
            text_color="#000000",
            font=create_global_font(20, logger=get_logger("Fonts")),
            anchor="center",
            justify=ctk.CENTER
        )
        self.message_label.pack(padx=20, pady=(0, 8))

        # 小字说明文本
        self.sub_label = ctk.CTkLabel(
            card,
            text=subtext,
            text_color="#666666",
            font=create_global_font(14, logger=get_logger("Fonts")),
            anchor="center",
            justify=ctk.CENTER
        )
        self.sub_label.pack(padx=20, pady=(0, 16))

        # 按钮框架
        button_frame = ctk.CTkFrame(card, fg_color="transparent")
        button_frame.pack(pady=(0, 12))

        # 打开日志按钮
        self.open_log_btn = ctk.CTkButton(
            button_frame,
            text="打开日志",
            fg_color=Colors.BUTTON,
            hover_color=Colors.BUTTON_HOVER,
            text_color="#ffffff",
            width=Dimensions.BUTTON_WIDTH,
            height=Dimensions.BUTTON_HEIGHT,
            corner_radius=Dimensions.CORNER_RADIUS_MEDIUM,
            font=create_global_font(14, "bold", logger=get_logger("Fonts")),
            command=self._open_log
        )
        self.open_log_btn.pack(side=ctk.LEFT, padx=10)

        # 确定按钮
        self.ok_btn = ctk.CTkButton(
            button_frame,
            text="确定",
            fg_color=Colors.BUTTON,
            hover_color=Colors.BUTTON_HOVER,
            text_color="#ffffff",
            width=Dimensions.BUTTON_WIDTH,
            height=Dimensions.BUTTON_HEIGHT,
            corner_radius=Dimensions.CORNER_RADIUS_MEDIUM,
            font=create_global_font(14, "bold", logger=get_logger("Fonts")),
            command=self.close
        )
        self.ok_btn.pack(side=ctk.LEFT, padx=10)

    def _open_log(self):
        try:
            log_dir = os.path.join(BASE_DIR, "Logs")
            if os.path.exists(log_dir):
                os.startfile(log_dir)
            else:
                os.startfile(BASE_DIR)
        except Exception as e:
            get_logger("Main").error(f"打开日志文件夹失败: {e}")

    def close(self):
        """关闭覆盖层"""
        # 恢复窗口关闭行为并释放 grab
        try:
            if getattr(self, '_toplevel', None):
                try:
                    prev = getattr(self, '_prev_wm_delete', None)
                    if prev:
                        try:
                            self._toplevel.protocol("WM_DELETE_WINDOW", prev)
                        except Exception:
                            pass
                except Exception:
                    pass
                try:
                    self._toplevel.grab_release()
                except Exception:
                    pass
        except Exception:
            pass

        # 销毁覆盖层
        try:
            self.root.place_forget()
        except Exception:
            try:
                self.root.destroy()
            except Exception:
                pass

if __name__ == "__main__":
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    if not is_admin():
        script_path = os.path.abspath(sys.argv[0])
        
        ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            f'"{script_path}"',
            os.path.dirname(script_path),
            1
        )
        # 退出当前非管理员进程
        sys.exit()
    
    # 设置日志
    setup_logging()
    logger = get_logger("Main")
    
    # 清理旧日志
    cleanup_old_logs(LOGS_DIR)
    
    main_logger = get_logger("Main")
    main_logger.info("应用程序启动")
    
    # 检查用户协议状态
    if check_disclaimer_status():
        # 已同意协议，直接创建并运行主窗口
        app = MainWindowApp()
        app.run()
    else:
        # 未同意协议，先显示协议弹窗
        # 创建临时根窗口用于显示协议
        temp_root = ctk.CTk()
        temp_root.withdraw()  # 隐藏临时窗口
        
        # 协议窗口启动前弹出提示
        messagebox.showinfo("SEEVVO全家桶一剑下崽弃", f"""做事要讲良心！！
原作者：https://space.bilibili.com/1264913123""")
        
        # 创建协议窗口
        disclaimer_window = DisclaimerWindow(None, temp_root)
        temp_root.wait_window(disclaimer_window.root)
        
        # 销毁临时窗口
        temp_root.destroy()
        
        # 再检查协议状态
        if check_disclaimer_status():
            # 同意了协议，创建并运行主窗口
            app = MainWindowApp()
            app.run()
        else:
            # 拒绝了协议，退出程序
            main_logger.info("用户拒绝了许可协议，退出程序")
            sys.exit(0)
    
    main_logger.info("应用程序退出")