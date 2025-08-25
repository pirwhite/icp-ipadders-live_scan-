#!/usr/bin/env python3
import os
import sys
import subprocess
import requests
import socket
import csv
import time
import json
from urllib.parse import urlparse, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from typing import List, Dict, Optional, Tuple

# 工具信息
TOOL_NAME = "url_check_ip_only"
AUTHOR = "p1r07"
VERSION = "4.1.0"

# 图标定义 - 兼容全平台Unicode字符
ICONS = {
    "success": "✅",
    "error": "❌",
    "info": "ℹ️",
    "warning": "⚠️",
    "check": "🔍",
    "file": "📄",
    "ip": "🌐",
    "settings": "⚙️",
    "version": "📌",
    "exit": "🚪",
    "install": "📦",
    "history": "📜",
    "clear": "🧹",
    "https": "🔒",
    "http": "🔓",
    "risk": "⚠️",
    "safe": "✅",
    "unknown": "❓"
}

# 配置和默认值（跨平台路径处理）
DEFAULT_WORKERS = 5
DEFAULT_TIMEOUT = 10
CONFIG_FILE = os.path.expanduser("~/.url_check_ip_config")
API_CONFIG_FILE = os.path.expanduser("~/.url_check_ip_api_keys")
IP_CACHE_FILE = os.path.expanduser("~/.url_check_ip_cache")

# IP属地查询API列表（多源保障准确性，兼容国内网络）
IP_LOCATION_APIS = [
    {
        "name": "ipapi",
        "url": "https://ipapi.co/{target}/json/",
        "timeout": 8,
        "mapping": {
            "country": "country_name",
            "region": "region",
            "city": "city",
            "isp": "org",
            "asn": "asn"
        }
    },
    {
        "name": "ipinfo",
        "url": "https://ipinfo.io/{target}/json",
        "timeout": 8,
        "mapping": {
            "country": "country",
            "region": "region",
            "city": "city",
            "isp": "org",
            "asn": "asn"
        }
    },
    {
        "name": "taobao",
        "url": "https://ip.taobao.com/outGetIpInfo?ip={target}&accessKey=alibaba-inc",
        "timeout": 6,
        "success_key": "code",
        "success_value": 0,
        "data_key": "data",
        "mapping": {
            "country": "country",
            "region": "region",
            "city": "city",
            "isp": "isp",
            "asn": "null"
        }
    }
]

# 所需依赖（精简必要依赖）
REQUIRED_PACKAGES = ['requests']

# 配置日志（兼容不同环境输出）
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(TOOL_NAME)

def load_ip_cache() -> Dict[str, Dict]:
    """加载IP属地查询缓存（减少重复请求）"""
    try:
        if os.path.exists(IP_CACHE_FILE):
            with open(IP_CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        logger.debug(f"{ICONS['warning']} 加载IP缓存失败: {str(e)}")
    return {}

def save_ip_cache(cache: Dict[str, Dict]) -> None:
    """保存IP属地查询缓存（缓存有效期24小时）"""
    try:
        with open(IP_CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(cache, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.debug(f"{ICONS['warning']} 保存IP缓存失败: {str(e)}")

def print_hack_banner():
    """简约Hack风格启动标识（适配不同终端宽度）"""
    # 跨平台清屏
    if sys.platform.startswith('win32'):
        os.system('cls')
    else:
        os.system('clear')
    
    # 适配窄终端的ASCII标识
    banner = f"""
    ╔════════════════════════════════════════╗
    ║  __    __     ______     ______        ║
    ║ |  |  |  |   /      \\   /      \\       ║
    ║ |  |__|  |  |        | |        |      ║
    ║ |   __   |  |        | |        |      ║
    ║ |  |  |  |  |        | |        |      ║
    ║ |__|  |__|   \\______/   \\______/       ║
    ║                                        ║
    ║  IP LOCATION CHECKER v{VERSION}  -  by {AUTHOR}  ║
    ╚════════════════════════════════════════╝
    """
    
    print(banner)
    # 初始化动画（兼容无动画环境）
    try:
        sys.stdout.write("  [*] 初始化中")
        sys.stdout.flush()
        for _ in range(3):
            time.sleep(0.5)
            sys.stdout.write(".")
            sys.stdout.flush()
        sys.stdout.write("\n\n")
    except:
        print("  [*] 初始化完成\n")

def print_menu():
    """命令菜单（清晰简洁）"""
    menu = f"""
{ICONS['check']}  请选择操作:
1. {ICONS['file']}  批量检查URL列表 (从文件读取)
2. {ICONS['check']}  单个URL/IP检查
3. {ICONS['history']}  查看历史检查结果
4. {ICONS['settings']} 设置默认并发数 ({DEFAULT_WORKERS})
5. {ICONS['settings']} 设置默认超时时间 ({DEFAULT_TIMEOUT}秒)
6. {ICONS['settings']} 配置API密钥 (威胁情报分析)
7. {ICONS['info']}  查看帮助信息
8. {ICONS['version']} 查看版本信息
9. {ICONS['install']} 检查并更新依赖
10. {ICONS['clear']} 清除历史结果/缓存
11. {ICONS['exit']} 退出工具
    """
    print(menu)
    print("-" * 60)

def load_config():
    """加载基础配置（跨平台路径）"""
    global DEFAULT_WORKERS, DEFAULT_TIMEOUT
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or '=' not in line:
                        continue
                    key, value = line.split('=', 1)
                    if key == 'workers':
                        DEFAULT_WORKERS = int(value) if value.isdigit() else DEFAULT_WORKERS
                    elif key == 'timeout':
                        DEFAULT_TIMEOUT = int(value) if value.isdigit() else DEFAULT_TIMEOUT
    except Exception as e:
        logger.warning(f"{ICONS['warning']} 加载配置失败: {str(e)}")

def save_config():
    """保存基础配置（兼容权限问题）"""
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            f.write(f"workers={DEFAULT_WORKERS}\n")
            f.write(f"timeout={DEFAULT_TIMEOUT}\n")
        logger.info(f"{ICONS['success']} 配置已保存")
    except PermissionError:
        # 兼容无权限写入用户目录的情况
        local_config = os.path.join(os.getcwd(), ".url_check_ip_config")
        with open(local_config, 'w', encoding='utf-8') as f:
            f.write(f"workers={DEFAULT_WORKERS}\n")
            f.write(f"timeout={DEFAULT_TIMEOUT}\n")
        logger.info(f"{ICONS['success']} 配置已保存到当前目录: {local_config}")
    except Exception as e:
        logger.error(f"{ICONS['error']} 保存配置失败: {str(e)}")

def install_package(package: str) -> bool:
    """安装依赖（兼容不同Python环境）"""
    try:
        logger.info(f"{ICONS['install']} 正在安装依赖: {package}...")
        # 适配不同Python解释器路径
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--upgrade", package],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        logger.info(f"{ICONS['success']} 依赖 {package} 安装/更新成功")
        return True
    except subprocess.CalledProcessError:
        logger.error(f"{ICONS['error']} 安装依赖 {package} 失败，请手动执行: pip install {package}")
        return False
    except Exception as e:
        logger.error(f"{ICONS['error']} 安装依赖出错: {str(e)}")
        return False

def check_and_install_dependencies(force_update: bool = False) -> bool:
    """检查并安装依赖（兼容离线环境提示）"""
    logger.info(f"{ICONS['info']} 检查必要依赖...")
    
    # 检查pip是否可用
    try:
        import pip
    except ImportError:
        logger.error(f"{ICONS['error']} 未找到pip，请先安装Python并配置环境变量")
        return False
    
    # 检查每个依赖
    for package in REQUIRED_PACKAGES:
        try:
            if force_update:
                raise ImportError("强制更新")
            __import__(package)
            logger.info(f"{ICONS['success']} 依赖 {package} 已安装")
        except ImportError:
            if not install_package(package):
                logger.warning(f"{ICONS['warning']} 依赖 {package} 未安装，部分功能可能无法使用")
                return False
    
    return True

def get_ip_address(hostname: str) -> Optional[str]:
    """获取主机名对应的IP（兼容多IP情况）"""
    try:
        # 获取所有IP，返回第一个有效IP
        ip_list = socket.getaddrinfo(hostname, None, socket.AF_INET)
        for addr in ip_list:
            return addr[4][0]
        return socket.gethostbyname(hostname)
    except (socket.gaierror, socket.error, Exception):
        return None

def reverse_ip_lookup(ip: str) -> List[str]:
    """IP反查关联域名（兼容无反向解析情况）"""
    try:
        hostnames = socket.gethostbyaddr(ip)
        return [host for host in hostnames if host]
    except (socket.herror, socket.gaierror, Exception) as e:
        logger.debug(f"{ICONS['warning']} IP反查失败: {str(e)}")
        return []

def is_valid_url(url: str) -> bool:
    """检查URL有效性（严格验证http/https）"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']
    except Exception:
        return False

def normalize_url(url: str) -> Optional[str]:
    """标准化URL（兼容无协议、多斜杠等情况）"""
    if not url or not isinstance(url, str):
        return None
        
    # 移除首尾空格和多余斜杠
    url = url.strip().rstrip('/')
    
    # 处理无协议URL
    parsed = urlparse(url)
    if not parsed.scheme:
        # 优先尝试HTTPS，再尝试HTTP
        for scheme in ['https', 'http']:
            test_url = f"{scheme}://{url}"
            if is_valid_url(test_url):
                return test_url
        return None
    
    # 仅保留http/https协议
    if parsed.scheme not in ['http', 'https']:
        return None
        
    # 重组URL确保格式正确
    normalized = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        parsed.query,
        parsed.fragment
    ))
    
    return normalized if is_valid_url(normalized) else None

def query_ip_location_from_api(ip: str, api: Dict) -> Optional[Dict]:
    """从单个API查询IP属地（超时重试机制）"""
    if not ip.replace('.', '').isdigit():
        return None
        
    try:
        # 构建查询URL
        url = api['url'].format(target=ip)
        retry_count = 2
        
        # 重试机制
        for _ in range(retry_count):
            try:
                response = requests.get(url, timeout=api.get('timeout', 5), verify=True)
                if response.status_code == 200:
                    result = response.json()
                    break
            except requests.exceptions.Timeout:
                continue
        else:
            return None
        
        # 检查API返回状态
        if 'success_key' in api:
            if result.get(api['success_key']) != api.get('success_value'):
                return None
            # 提取数据节点
            result = result.get(api['data_key'], {})
            if not result:
                return None
        
        # 映射统一字段
        location_data = {
            'ip': ip,
            'country': '未知',
            'region': '未知',
            'city': '未知',
            'isp': '未知',
            'asn': '未知',
            'source': api['name'],
            'query_time': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # 填充数据
        for our_key, api_key in api['mapping'].items():
            if api_key == 'null':
                continue
            value = result.get(api_key, '未知')
            # 处理空值情况
            if value and str(value).strip().lower() not in ['', 'none', 'unknown']:
                location_data[our_key] = str(value)
        
        return location_data
        
    except Exception as e:
        logger.debug(f"{ICONS['warning']} IP API {api['name']} 查询失败: {str(e)}")
        return None

def query_ip_location(ip: str) -> Dict:
    """查询IP属地（多源验证+缓存）"""
    # 默认结果
    default_result = {
        'ip': ip,
        'country': '未知',
        'region': '未知',
        'city': '未知',
        'isp': '未知',
        'asn': '未知',
        'source': '无有效数据',
        'query_time': time.strftime('%Y-%m-%d %H:%M:%S')
    }
    
    # 检查缓存（24小时有效期）
    cache = load_ip_cache()
    cache_key = ip.lower()
    
    if cache_key in cache:
        cached = cache[cache_key]
        cache_time = time.mktime(time.strptime(cached['query_time'], '%Y-%m-%d %H:%M:%S'))
        if time.time() - cache_time < 86400:  # 24小时
            return cached
    
    # 多API查询，取第一个有效结果
    results = []
    for api in IP_LOCATION_APIS:
        result = query_ip_location_from_api(ip, api)
        if result:
            results.append(result)
            # 避免API请求过于频繁
            time.sleep(0.5)
    
    # 处理结果
    if results:
        # 优先选择包含详细信息的结果
        results.sort(key=lambda x: sum(1 for v in x.values() if v != '未知'), reverse=True)
        best_result = results[0]
        
        # 缓存结果
        cache[cache_key] = best_result
        save_ip_cache(cache)
        
        return best_result
    
    # 缓存默认结果
    cache[cache_key] = default_result
    save_ip_cache(cache)
    
    return default_result

def query_virustotal(resource: str, api_key: str) -> Optional[Dict]:
    """查询VirusTotal威胁情报（兼容API限制）"""
    if not api_key:
        return None
        
    try:
        # 区分URL和IP查询端点
        if resource.startswith(('http', 'https')):
            url = "https://www.virustotal.com/vtapi/v2/url/report"
        elif resource.replace('.', '').isdigit():
            url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
        else:
            url = "https://www.virustotal.com/vtapi/v2/domain/report"
        
        params = {'apikey': api_key, 'resource': resource}
        response = requests.get(url, params=params, timeout=15)
        
        if response.status_code == 200:
            result = response.json()
            if result.get('response_code') == 1:
                positives = result.get('positives', 0)
                total = result.get('total', 0)
                return {
                    'detected': positives > 0,
                    'positives': positives,
                    'total': total,
                    'scan_date': result.get('scan_date', '未知'),
                    'risk_level': '高' if positives > total * 0.3 else '中' if positives > 0 else '低'
                }
            else:
                return {'detected': False, 'message': '未找到记录'}
        elif response.status_code == 429:
            return {'detected': False, 'message': 'API请求频率超限'}
        else:
            return {'detected': False, 'message': f'请求失败 (状态码: {response.status_code})'}
            
    except Exception as e:
        logger.debug(f"{ICONS['warning']} VirusTotal查询失败: {str(e)}")
        return None

def query_weibu_intel(resource: str, api_key: str) -> Optional[Dict]:
    """查询微步情报（兼容国内网络）"""
    if not api_key:
        return None
        
    try:
        # 区分IP和域名查询
        if resource.replace('.', '').isdigit():
            url = "https://api.threatbook.cn/v3/scene/ip_reputation"
        else:
            url = "https://api.threatbook.cn/v3/domain/reputation"
        
        params = {'apikey': api_key, 'resource': resource}
        response = requests.get(url, params=params, timeout=15)
        
        if response.status_code == 200:
            result = response.json()
            if result.get('response_code') == 0:
                data = result.get('data', {}).get(resource, {})
                return {
                    'judgment': data.get('judgment', '未知'),
                    'confidence_level': data.get('confidence_level', 0),
                    'tags': data.get('tags', []),
                    'severity': data.get('severity', '未知')
                }
            else:
                return {'judgment': '未知', 'message': result.get('verbose_msg', '查询失败')}
        else:
            return {'judgment': '未知', 'message': f'请求失败 (状态码: {response.status_code})'}
            
    except Exception as e:
        logger.debug(f"{ICONS['warning']} 微步情报查询失败: {str(e)}")
        return None

def check_protocol(url: str, timeout: int, protocol: str) -> Dict[str, any]:
    """检查指定协议的URL可用性（兼容SSL和重定向）"""
    parsed_url = urlparse(url)
    # 构建指定协议的URL
    protocol_url = urlunparse((
        protocol, parsed_url.netloc, parsed_url.path,
        parsed_url.params, parsed_url.query, parsed_url.fragment
    ))
    
    result = {
        'url': protocol_url,
        'status_code': None,
        'is_accessible': False,
        'error': None,
        'redirect_count': 0,
        'final_url': protocol_url
    }
    
    try:
        # 模拟浏览器请求头，避免被拦截
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9'
        }
        
        # 先尝试HEAD请求（效率高），失败再用GET
        try:
            response = requests.head(
                protocol_url,
                timeout=timeout,
                allow_redirects=True,
                headers=headers,
                verify=True
            )
            # 部分服务器不支持HEAD，直接用GET
            if response.status_code not in [200, 301, 302, 307, 308]:
                raise requests.exceptions.RequestException("HEAD请求状态码异常")
        except:
            response = requests.get(
                protocol_url,
                timeout=timeout,
                allow_redirects=True,
                headers=headers,
                verify=True
            )
        
        # 填充结果
        result['status_code'] = response.status_code
        result['is_accessible'] = response.status_code == 200
        result['redirect_count'] = len(response.history)
        result['final_url'] = response.url
        
    except requests.exceptions.SSLError:
        # SSL错误时尝试不验证证书
        try:
            response = requests.get(
                protocol_url,
                timeout=timeout,
                allow_redirects=True,
                headers=headers,
                verify=False
            )
            result['status_code'] = response.status_code
            result['is_accessible'] = response.status_code == 200
            result['error'] = "SSL证书验证失败（已跳过验证）"
            result['redirect_count'] = len(response.history)
            result['final_url'] = response.url
        except Exception as e:
            result['error'] = f"SSL错误: {str(e)}"
            
    except requests.exceptions.RequestException as e:
        result['error'] = str(e)
        
    except Exception as e:
        result['error'] = f"未知错误: {str(e)}"
        
    return result

def check_url(url: str, timeout: int = 10, api_keys: Dict[str, str] = None) -> Dict[str, any]:
    """核心检查函数：URL可用性+IP属地+威胁情报"""
    if api_keys is None:
        api_keys = {}
        
    # 解析URL基础信息
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc or parsed_url.path  # 兼容特殊URL格式
    ip_address = get_ip_address(hostname) if hostname else '未知'
    
    # 初始化结果（确保所有字段有默认值，避免NoneType错误）
    result = {
        'original_url': url,
        'hostname': hostname or '未知',
        'ip_address': ip_address,
        'ip_location': query_ip_location(ip_address) if ip_address != '未知' else {},
        'http': {
            'url': '',
            'status_code': None,
            'is_accessible': False,
            'error': None,
            'redirect_count': 0,
            'final_url': ''
        },
        'https': {
            'url': '',
            'status_code': None,
            'is_accessible': False,
            'error': None,
            'redirect_count': 0,
            'final_url': ''
        },
        'reverse_domains': reverse_ip_lookup(ip_address) if ip_address != '未知' else [],
        'virustotal': None,
        'weibu': None,
        'check_time': time.strftime('%Y-%m-%d %H:%M:%S')
    }
    
    # 同时检查HTTP和HTTPS
    try:
        result['https'] = check_protocol(url, timeout, 'https')
    except Exception as e:
        logger.debug(f"HTTPS检查失败: {str(e)}")
    
    try:
        result['http'] = check_protocol(url, timeout, 'http')
    except Exception as e:
        logger.debug(f"HTTP检查失败: {str(e)}")
    
    # 威胁情报查询（如果有API密钥）
    try:
        if api_keys.get('virustotal') and hostname != '未知':
            result['virustotal'] = query_virustotal(hostname, api_keys['virustotal'])
    except Exception as e:
        logger.debug(f"VirusTotal查询失败: {str(e)}")
    
    try:
        if api_keys.get('weibu') and hostname != '未知':
            result['weibu'] = query_weibu_intel(hostname, api_keys['weibu'])
    except Exception as e:
        logger.debug(f"微步情报查询失败: {str(e)}")
    
    # IP威胁情报（如果有IP）
    if ip_address != '未知' and ip_address != '':
        try:
            if api_keys.get('virustotal'):
                result['virustotal_ip'] = query_virustotal(ip_address, api_keys['virustotal'])
        except Exception as e:
            logger.debug(f"VirusTotal IP查询失败: {str(e)}")
        
        try:
            if api_keys.get('weibu'):
                result['weibu_ip'] = query_weibu_intel(ip_address, api_keys['weibu'])
        except Exception as e:
            logger.debug(f"微步IP查询失败: {str(e)}")
    
    return result

def read_urls_from_file(file_path: str) -> List[str]:
    """读取URL文件（兼容不同编码和格式）"""
    # 处理相对路径和绝对路径
    file_path = os.path.abspath(file_path)
    
    try:
        # 尝试UTF-8编码
        with open(file_path, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
    except UnicodeDecodeError:
        # 兼容GBK编码文件（Windows常见）
        try:
            with open(file_path, 'r', encoding='gbk') as f:
                urls = [line.strip() for line in f if line.strip()]
        except:
            # 兼容其他编码
            with open(file_path, 'r', encoding='latin-1') as f:
                urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logger.error(f"{ICONS['error']} 文件不存在: {file_path}")
        return []
    except PermissionError:
        logger.error(f"{ICONS['error']} 无权限读取文件: {file_path}")
        return []
    except Exception as e:
        logger.error(f"{ICONS['error']} 读取文件出错: {str(e)}")
        return []
    
    logger.info(f"{ICONS['success']} 从 {file_path} 读取到 {len(urls)} 个URL")
    return urls

def safe_get(data: Dict, path: List[str], default: any = '') -> any:
    """安全获取嵌套字典值（彻底解决NoneType错误）"""
    current = data
    for key in path:
        if current is None or not isinstance(current, dict):
            return default
        current = current.get(key)
    return current if current is not None else default

def save_results_to_csv(results: List[Dict], base_filename: str = None) -> str:
    """保存结果到CSV（兼容路径权限和编码）"""
    if not results:
        logger.warning(f"{ICONS['warning']} 没有结果可保存")
        return ""
    
    # 生成安全的文件名
    if not base_filename:
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        base_filename = f"ip_check_result_{timestamp}.csv"
    else:
        base_filename = base_filename.replace('/', '_').replace('\\', '_').replace(':', '_')
        if not base_filename.endswith('.csv'):
            base_filename += '.csv'
    
    # 定义CSV字段（细分IP属地信息）
    fieldnames = [
        # 基础信息
        'original_url', 'hostname', 'ip_address',
        # IP属地信息
        'ip_country', 'ip_region', 'ip_city', 'ip_isp', 'ip_asn', 'ip_data_source',
        # HTTPS信息
        'https_url', 'https_status', 'https_accessible', 'https_redirects', 'https_final_url', 'https_error',
        # HTTP信息
        'http_url', 'http_status', 'http_accessible', 'http_redirects', 'http_final_url', 'http_error',
        # 反向域名
        'reverse_domains',
        # 威胁情报（域名）
        'vt_domain_detected', 'vt_domain_positives', 'vt_domain_total', 'vt_domain_risk',
        'weibu_domain_judgment', 'weibu_domain_severity', 'weibu_domain_tags',
        # 威胁情报（IP）
        'vt_ip_detected', 'vt_ip_positives', 'vt_ip_total', 'vt_ip_risk',
        'weibu_ip_judgment', 'weibu_ip_severity', 'weibu_ip_tags',
        # 检查时间
        'check_time'
    ]
    
    # 尝试保存（多路径 fallback）
    save_paths = [
        base_filename,
        os.path.join(os.getcwd(), base_filename),
        os.path.expanduser(f"~/Documents/{base_filename}")  # 兼容用户文档目录
    ]
    
    for save_path in save_paths:
        try:
            with open(save_path, 'w', newline='', encoding='utf-8-sig') as csvfile:  # utf-8-sig兼容Excel
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for result in results:
                    # 处理反向域名
                    reverse_domains = ', '.join(result.get('reverse_domains', [])) or '无'
                    
                    # 处理威胁情报
                    vt_domain = result.get('virustotal', {})
                    vt_ip = result.get('virustotal_ip', {})
                    weibu_domain = result.get('weibu', {})
                    weibu_ip = result.get('weibu_ip', {})
                    
                    # 构建行数据
                    row = {
                        # 基础信息
                        'original_url': safe_get(result, ['original_url']),
                        'hostname': safe_get(result, ['hostname']),
                        'ip_address': safe_get(result, ['ip_address']),
                        # IP属地
                        'ip_country': safe_get(result, ['ip_location', 'country']),
                        'ip_region': safe_get(result, ['ip_location', 'region']),
                        'ip_city': safe_get(result, ['ip_location', 'city']),
                        'ip_isp': safe_get(result, ['ip_location', 'isp']),
                        'ip_asn': safe_get(result, ['ip_location', 'asn']),
                        'ip_data_source': safe_get(result, ['ip_location', 'source']),
                        # HTTPS
                        'https_url': safe_get(result, ['https', 'url']),
                        'https_status': safe_get(result, ['https', 'status_code'], 'N/A'),
                        'https_accessible': safe_get(result, ['https', 'is_accessible'], False),
                        'https_redirects': safe_get(result, ['https', 'redirect_count'], 0),
                        'https_final_url': safe_get(result, ['https', 'final_url']),
                        'https_error': safe_get(result, ['https', 'error'], ''),
                        # HTTP
                        'http_url': safe_get(result, ['http', 'url']),
                        'http_status': safe_get(result, ['http', 'status_code'], 'N/A'),
                        'http_accessible': safe_get(result, ['http', 'is_accessible'], False),
                        'http_redirects': safe_get(result, ['http', 'redirect_count'], 0),
                        'http_final_url': safe_get(result, ['http', 'final_url']),
                        'http_error': safe_get(result, ['http', 'error'], ''),
                        # 反向域名
                        'reverse_domains': reverse_domains,
                        # 威胁情报（域名）
                        'vt_domain_detected': safe_get(vt_domain, ['detected'], False),
                        'vt_domain_positives': safe_get(vt_domain, ['positives'], 0),
                        'vt_domain_total': safe_get(vt_domain, ['total'], 0),
                        'vt_domain_risk': safe_get(vt_domain, ['risk_level'], '未知'),
                        'weibu_domain_judgment': safe_get(weibu_domain, ['judgment'], '未知'),
                        'weibu_domain_severity': safe_get(weibu_domain, ['severity'], '未知'),
                        'weibu_domain_tags': ', '.join(safe_get(weibu_domain, ['tags'], [])),
                        # 威胁情报（IP）
                        'vt_ip_detected': safe_get(vt_ip, ['detected'], False),
                        'vt_ip_positives': safe_get(vt_ip, ['positives'], 0),
                        'vt_ip_total': safe_get(vt_ip, ['total'], 0),
                        'vt_ip_risk': safe_get(vt_ip, ['risk_level'], '未知'),
                        'weibu_ip_judgment': safe_get(weibu_ip, ['judgment'], '未知'),
                        'weibu_ip_severity': safe_get(weibu_ip, ['severity'], '未知'),
                        'weibu_ip_tags': ', '.join(safe_get(weibu_ip, ['tags'], [])),
                        # 时间
                        'check_time': safe_get(result, ['check_time'])
                    }
                    
                    writer.writerow(row)
            
            logger.info(f"{ICONS['success']} 结果已保存到: {os.path.abspath(save_path)}")
            return save_path
        
        except PermissionError:
            continue
        except Exception as e:
            logger.debug(f"保存到 {save_path} 失败: {str(e)}")
            continue
    
    # 所有路径都失败时的最终fallback
    fallback_path = f"ip_check_fallback_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    try:
        with open(fallback_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            # 写入至少一条数据
            if results:
                result = results[0]
                writer.writerow({k: safe_get(result, k.split('_'), '') for k in fieldnames})
        logger.warning(f"{ICONS['warning']} 仅能保存到当前目录: {os.path.abspath(fallback_path)}")
        return fallback_path
    except:
        logger.error(f"{ICONS['error']} 所有保存路径都失败，请手动记录结果")
        return ""

def display_single_result(result: Dict[str, any]) -> None:
    """显示单个目标的详细结果（适配不同终端）"""
    print("\n" + "=" * 80)
    print(f"{ICONS['info']} 详细检查结果: {result.get('original_url', '未知URL')}")
    print("-" * 80)
    
    # 基础信息
    print(f"{ICONS['ip']} 主机名: {result.get('hostname', '未知')}")
    print(f"{ICONS['ip']} IP地址: {result.get('ip_address', '未知')}")
    
    # IP属地信息（重点展示）
    print("\n" + "-" * 40)
    print(f"{ICONS['info']} IP属地信息:")
    ip_loc = result.get('ip_location', {})
    print(f"  国家/地区: {ip_loc.get('country', '未知')}")
    print(f"  省份/区域: {ip_loc.get('region', '未知')}")
    print(f"  城市: {ip_loc.get('city', '未知')}")
    print(f"  运营商: {ip_loc.get('isp', '未知')}")
    print(f"  ASN编号: {ip_loc.get('asn', '未知')}")
    print(f"  数据来源: {ip_loc.get('source', '未知')}")
    
    # HTTP/HTTPS检查结果
    print("\n" + "-" * 40)
    print(f"{ICONS['https']} HTTPS检查:")
    https = result.get('https', {})
    if https.get('is_accessible'):
        print(f"  {ICONS['success']} 可访问 | 状态码: {https.get('status_code')}")
    else:
        print(f"  {ICONS['error']} 不可访问 | 状态码: {https.get('status_code', 'N/A')}")
    print(f"  请求URL: {https.get('url', 'N/A')}")
    print(f"  最终URL: {https.get('final_url', 'N/A')}")
    print(f"  重定向次数: {https.get('redirect_count', 0)}")
    if https.get('error'):
        print(f"  错误信息: {https.get('error')}")
    
    print(f"\n{ICONS['http']} HTTP检查:")
    http = result.get('http', {})
    if http.get('is_accessible'):
        print(f"  {ICONS['success']} 可访问 | 状态码: {http.get('status_code')}")
    else:
        print(f"  {ICONS['error']} 不可访问 | 状态码: {http.get('status_code', 'N/A')}")
    print(f"  请求URL: {http.get('url', 'N/A')}")
    print(f"  最终URL: {http.get('final_url', 'N/A')}")
    print(f"  重定向次数: {http.get('redirect_count', 0)}")
    if http.get('error'):
        print(f"  错误信息: {http.get('error')}")
    
    # 反向域名
    reverse_domains = result.get('reverse_domains', [])
    if reverse_domains:
        print("\n" + "-" * 40)
        print(f"{ICONS['info']} IP关联域名 ({len(reverse_domains)}个):")
        for i, domain in enumerate(reverse_domains[:10], 1):  # 限制显示数量
            print(f"  {i}. {domain}")
        if len(reverse_domains) > 10:
            print(f"  ... 还有 {len(reverse_domains) - 10} 个域名")
    
    # 威胁情报
    print("\n" + "-" * 40)
    print(f"{ICONS['risk']} 威胁情报分析:")
    
    # 域名威胁情报
    vt_domain = result.get('virustotal')
    if vt_domain:
        print(f"\n{ICONS['info']} VirusTotal 域名检测:")
        if vt_domain.get('detected'):
            print(f"  {ICONS['risk']} 威胁检测: {vt_domain['positives']}/{vt_domain['total']} 引擎报警")
            print(f"  风险等级: {vt_domain['risk_level']}")
        else:
            print(f"  {ICONS['safe']} 未检测到威胁")
    
    weibu_domain = result.get('weibu')
    if weibu_domain:
        print(f"\n{ICONS['info']} 微步情报 域名检测:")
        judgment = weibu_domain.get('judgment', '未知')
        if judgment in ['malicious', 'suspicious']:
            print(f"  {ICONS['risk']} 判定: {judgment}")
            print(f"  严重程度: {weibu_domain.get('severity', '未知')}")
            print(f"  标签: {', '.join(weibu_domain.get('tags', []))}")
        else:
            print(f"  {ICONS['safe']} 判定: {judgment}")
    
    # IP威胁情报
    vt_ip = result.get('virustotal_ip')
    if vt_ip:
        print(f"\n{ICONS['info']} VirusTotal IP检测:")
        if vt_ip.get('detected'):
            print(f"  {ICONS['risk']} 威胁检测: {vt_ip['positives']}/{vt_ip['total']} 引擎报警")
            print(f"  风险等级: {vt_ip['risk_level']}")
        else:
            print(f"  {ICONS['safe']} 未检测到威胁")
    
    weibu_ip = result.get('weibu_ip')
    if weibu_ip:
        print(f"\n{ICONS['info']} 微步情报 IP检测:")
        judgment = weibu_ip.get('judgment', '未知')
        if judgment in ['malicious', 'suspicious']:
            print(f"  {ICONS['risk']} 判定: {judgment}")
            print(f"  严重程度: {weibu_ip.get('severity', '未知')}")
            print(f"  标签: {', '.join(weibu_ip.get('tags', []))}")
        else:
            print(f"  {ICONS['safe']} 判定: {judgment}")
    
    if not vt_domain and not vt_ip and not weibu_domain and not weibu_ip:
        print(f"\n  {ICONS['warning']} 未配置API密钥，无法获取威胁情报")
    
    print("\n" + "=" * 80)

def check_url_list():
    """批量检查URL列表（兼容大文件和并发控制）"""
    print(f"\n{ICONS['check']} 批量URL检查功能")
    print("-" * 50)
    
    # 获取文件路径
    file_path = input("请输入URL文件路径: ").strip()
    if not file_path:
        logger.error(f"{ICONS['error']} 文件路径不能为空")
        return
    
    # 验证文件
    if not os.path.exists(file_path):
        logger.error(f"{ICONS['error']} 文件不存在: {file_path}")
        return
    if not os.path.isfile(file_path):
        logger.error(f"{ICONS['error']} 不是有效文件: {file_path}")
        return
    
    # 获取并发数和超时（兼容无效输入）
    try:
        workers_input = input(f"请输入并发数 (默认: {DEFAULT_WORKERS}): ").strip()
        workers = int(workers_input) if workers_input.isdigit() else DEFAULT_WORKERS
        workers = max(1, min(workers, 30))  # 限制并发数在1-30之间
        
        timeout_input = input(f"请输入超时时间(秒) (默认: {DEFAULT_TIMEOUT}): ").strip()
        timeout = int(timeout_input) if timeout_input.isdigit() else DEFAULT_TIMEOUT
        timeout = max(3, min(timeout, 60))  # 限制超时在3-60秒之间
    except:
        logger.warning(f"{ICONS['warning']} 输入无效，使用默认值")
        workers = DEFAULT_WORKERS
        timeout = DEFAULT_TIMEOUT
    
    # 加载API密钥
    api_keys = load_api_keys()
    
    # 读取并处理URL
    urls = read_urls_from_file(file_path)
    if not urls:
        logger.warning(f"{ICONS['warning']} 未找到有效URL")
        return
    
    # 标准化URL
    processed_urls = []
    invalid_urls = []
    for url in urls:
        normalized = normalize_url(url)
        if normalized:
            processed_urls.append(normalized)
        else:
            invalid_urls.append(url)
    
    # 显示无效URL信息
    if invalid_urls:
        logger.warning(f"{ICONS['warning']} 发现 {len(invalid_urls)} 个无效URL（已跳过）")
        show_invalid = input("是否显示无效URL? (y/n): ").strip().lower()
        if show_invalid == 'y':
            for url in invalid_urls[:20]:  # 限制显示数量
                print(f"  - {url}")
            if len(invalid_urls) > 20:
                print(f"  ... 还有 {len(invalid_urls) - 20} 个无效URL")
    
    if not processed_urls:
        logger.error(f"{ICONS['error']} 没有有效URL可检查")
        return
    
    # 开始检查
    logger.info(f"{ICONS['info']} 开始检查 {len(processed_urls)} 个URL（并发: {workers}, 超时: {timeout}秒）")
    print("-" * 80)
    
    results = []
    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            # 提交任务
            futures = {executor.submit(check_url, url, timeout, api_keys): url for url in processed_urls}
            
            # 处理结果
            for idx, future in enumerate(as_completed(futures), 1):
                url = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    # 实时显示进度
                    ip = result.get('ip_address', '未知IP')
                    ip_country = result.get('ip_location', {}).get('country', '未知地区')
                    https_ok = result['https']['is_accessible']
                    http_ok = result['http']['is_accessible']
                    
                    if https_ok or http_ok:
                        status = f"{ICONS['success']} 成功"
                    else:
                        status = f"{ICONS['error']} 失败"
                    
                    print(f"[{idx}/{len(processed_urls)}] {status} | {url} | {ip} | {ip_country}")
                    
                except Exception as e:
                    logger.error(f"[{idx}/{len(processed_urls)}] {ICONS['error']} 检查 {url} 出错: {str(e)}")
    
    except KeyboardInterrupt:
        logger.warning(f"{ICONS['warning']} 检测到中断，正在停止任务...")
        return
    
    # 保存结果
    if results:
        save_results_to_csv(results)
        
        # 显示总结
        print("\n" + "-" * 80)
        print(f"{ICONS['info']} 检查总结:")
        print(f"总URL数: {len(urls)}")
        print(f"有效URL数: {len(processed_urls)}")
        print(f"无效URL数: {len(invalid_urls)}")
        
        # 统计可用性
        https_ok = sum(1 for r in results if r['https']['is_accessible'])
        http_ok = sum(1 for r in results if r['http']['is_accessible'])
        total_ok = sum(1 for r in results if r['https']['is_accessible'] or r['http']['is_accessible'])
        
        print(f"\n{ICONS['success']} 可访问URL数: {total_ok}")
        print(f"  - {ICONS['https']} HTTPS可访问: {https_ok}")
        print(f"  - {ICONS['http']} HTTP可访问: {http_ok}")
        print(f"{ICONS['error']} 不可访问URL数: {len(processed_urls) - total_ok}")
        
        # IP属地统计
        countries = {}
        for r in results:
            country = r.get('ip_location', {}).get('country', '未知')
            countries[country] = countries.get(country, 0) + 1
        
        print(f"\n{ICONS['info']} IP属地分布:")
        for country, count in sorted(countries.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {country}: {count} 个")
        
        print("-" * 80)
    else:
        logger.warning(f"{ICONS['warning']} 没有获取到检查结果")

def check_single_target():
    """检查单个URL/IP（兼容直接输入IP的情况）"""
    print(f"\n{ICONS['check']} 单个URL/IP检查功能")
    print("-" * 50)
    
    # 获取目标
    target = input("请输入URL或IP地址: ").strip()
    if not target:
        logger.error(f"{ICONS['error']} 输入不能为空")
        return
    
    # 处理目标
    if target.replace('.', '').isdigit() and len(target.split('.')) == 4:
        # 是IP地址
        ip_address = target
        # 尝试获取域名
        hostnames = reverse_ip_lookup(ip_address)
        if hostnames:
            print(f"{ICONS['info']} 找到IP关联域名: {', '.join(hostnames[:3])}")
            use_domain = input("是否使用域名进行检查? (y/n): ").strip().lower()
            if use_domain == 'y':
                target = normalize_url(hostnames[0]) or f"http://{ip_address}"
            else:
                target = f"http://{ip_address}"
        else:
            target = f"http://{ip_address}"
    else:
        # 是URL，标准化
        normalized = normalize_url(target)
        if not normalized:
            logger.error(f"{ICONS['error']} 无效的URL格式，请包含http/https")
            return
        target = normalized
    
    # 获取超时时间
    try:
        timeout_input = input(f"请输入超时时间(秒) (默认: {DEFAULT_TIMEOUT}): ").strip()
        timeout = int(timeout_input) if timeout_input.isdigit() else DEFAULT_TIMEOUT
        timeout = max(3, min(timeout, 60))
    except:
        timeout = DEFAULT_TIMEOUT
    
    # 加载API密钥
    api_keys = load_api_keys()
    
    # 开始检查
    logger.info(f"{ICONS['info']} 开始检查: {target}（超时: {timeout}秒）")
    print("-" * 80)
    
    try:
        result = check_url(target, timeout, api_keys)
        # 显示详细结果
        display_single_result(result)
        
        # 保存结果
        save_choice = input("\n是否保存当前结果? (y/n): ").strip().lower()
        if save_choice == 'y':
            save_results_to_csv([result])
    
    except Exception as e:
        logger.error(f"{ICONS['error']} 检查出错: {str(e)}")

def load_api_keys() -> Dict[str, str]:
    """加载API密钥（兼容不同配置路径）"""
    api_keys = {
        'virustotal': '',
        'weibu': ''
    }
    
    # 尝试多个配置路径
    config_paths = [
        API_CONFIG_FILE,
        os.path.join(os.getcwd(), ".url_check_ip_api_keys"),
        os.path.expanduser("~/Documents/.url_check_ip_api_keys")
    ]
    
    for path in config_paths:
        try:
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    api_keys.update({k: v for k, v in config.items() if k in api_keys})
                break
        except Exception as e:
            logger.debug(f"加载API配置 {path} 失败: {str(e)}")
    
    return api_keys

def save_api_keys(api_keys: Dict[str, str]) -> None:
    """保存API密钥（兼容权限问题）"""
    # 只保存支持的密钥
    valid_keys = {k: v for k, v in api_keys.items() if k in ['virustotal', 'weibu']}
    
    # 尝试多个保存路径
    save_paths = [
        API_CONFIG_FILE,
        os.path.join(os.getcwd(), ".url_check_ip_api_keys")
    ]
    
    for path in save_paths:
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(valid_keys, f, indent=2, ensure_ascii=False)
            logger.info(f"{ICONS['success']} API密钥已保存到: {os.path.abspath(path)}")
            return
        except PermissionError:
            continue
        except Exception as e:
            logger.debug(f"保存API配置 {path} 失败: {str(e)}")
    
    # 最终fallback
    fallback_path = ".url_check_ip_api_keys"
    with open(fallback_path, 'w', encoding='utf-8') as f:
        json.dump(valid_keys, f, indent=2, ensure_ascii=False)
    logger.warning(f"{ICONS['warning']} API密钥已保存到当前目录: {os.path.abspath(fallback_path)}")

def configure_api_keys():
    """配置API密钥（清晰的用户引导）"""
    print(f"\n{ICONS['settings']} API密钥配置")
    print("-" * 50)
    print("配置以下API密钥以启用威胁情报分析（可选）")
    print("获取地址:")
    print("  - VirusTotal: https://www.virustotal.com/ (免费账号有查询限制)")
    print("  - 微步情报: https://x.threatbook.cn/ (需注册账号)")
    print("提示: 不配置API密钥仅影响威胁情报功能，IP属地查询不受影响")
    
    # 加载现有密钥
    api_keys = load_api_keys()
    
    # 获取用户输入（支持保留现有密钥）
    print(f"\n当前配置:")
    print(f"  VirusTotal: {'已配置' if api_keys['virustotal'] else '未配置'}")
    print(f"  微步情报: {'已配置' if api_keys['weibu'] else '未配置'}")
    
    vt_key = input(f"\n请输入VirusTotal API密钥 (按回车保留现有): ").strip()
    weibu_key = input(f"请输入微步情报API密钥 (按回车保留现有): ").strip()
    
    # 更新密钥
    if vt_key:
        api_keys['virustotal'] = vt_key
    if weibu_key:
        api_keys['weibu'] = weibu_key
    
    # 保存配置
    save_api_keys(api_keys)
    
    # 验证密钥（简单测试）
    if vt_key:
        print(f"\n{ICONS['info']} 正在验证VirusTotal API密钥...")
        test_result = query_virustotal("example.com", vt_key)
        if test_result and 'message' not in test_result:
            logger.info(f"{ICONS['success']} VirusTotal API密钥验证成功")
        else:
            logger.warning(f"{ICONS['warning']} VirusTotal API密钥可能无效或无权限")
    
    print("\n" + "-" * 50)

def view_history():
    """查看历史结果（兼容不同目录）"""
    print(f"\n{ICONS['history']} 历史检查结果")
    print("-" * 50)
    
    # 查找CSV结果文件
    result_files = []
    # 搜索当前目录
    for f in os.listdir('.'):
        if f.startswith(('ip_check_result_', 'ip_check_fallback_')) and f.endswith('.csv'):
            result_files.append(f)
    
    # 搜索用户文档目录
    docs_dir = os.path.expanduser("~/Documents")
    if os.path.exists(docs_dir):
        for f in os.listdir(docs_dir):
            if f.startswith(('ip_check_result_', 'ip_check_fallback_')) and f.endswith('.csv'):
                result_files.append(os.path.join(docs_dir, f))
    
    if not result_files:
        print(f"{ICONS['info']} 未找到历史检查结果")
        return
    
    # 按创建时间排序（最新在前）
    result_files.sort(key=lambda x: os.path.getctime(x), reverse=True)
    
    # 显示历史文件
    print(f"{ICONS['file']} 最近的检查结果:")
    for i, filepath in enumerate(result_files[:10], 1):
        filename = os.path.basename(filepath)
        ctime = time.ctime(os.path.getctime(filepath))
        size = os.path.getsize(filepath) / 1024
        print(f"{i}. {filename} | 创建时间: {ctime} | 大小: {size:.2f}KB")
    
    # 选择查看文件
    try:
        choice = input("\n请输入要查看的文件编号 (0取消): ").strip()
        if choice == '0':
            return
        if not choice.isdigit():
            logger.error(f"{ICONS['error']} 请输入数字编号")
            return
        
        index = int(choice) - 1
        if 0 <= index < len(result_files[:10]):
            filepath = result_files[index]
            print(f"\n{ICONS['file']} 显示 {os.path.basename(filepath)} 的前15行:")
            print("-" * 120)
            
            # 读取并显示文件
            try:
                with open(filepath, 'r', encoding='utf-8-sig') as f:
                    for i, line in enumerate(f):
                        if i > 15:
                            print("... (仅显示前15行，完整内容请用Excel打开)")
                            break
                        # 处理长行，避免终端错乱
                        if len(line) > 120:
                            print(line[:117] + "...")
                        else:
                            print(line.strip())
                print("-" * 120)
                
                # 打开文件
                open_choice = input(f"是否用默认程序打开该文件? (y/n): ").strip().lower()
                if open_choice == 'y':
                    if sys.platform.startswith('win32'):
                        os.startfile(filepath)
                    elif sys.platform.startswith('darwin'):
                        subprocess.run(['open', filepath])
                    else:
                        subprocess.run(['xdg-open', filepath])
            except Exception as e:
                logger.error(f"{ICONS['error']} 读取文件出错: {str(e)}")
        else:
            logger.error(f"{ICONS['error']} 无效的编号")
    except Exception as e:
        logger.error(f"{ICONS['error']} 操作出错: {str(e)}")

def set_workers():
    """设置并发数（范围限制）"""
    global DEFAULT_WORKERS
    print(f"\n{ICONS['settings']} 设置默认并发数")
    print("-" * 50)
    
    try:
        new_workers = input(f"当前默认并发数: {DEFAULT_WORKERS} (建议1-30): ").strip()
        if not new_workers:
            logger.info(f"{ICONS['info']} 未输入，保持当前值")
            return
        
        new_workers = int(new_workers)
        if 1 <= new_workers <= 30:
            DEFAULT_WORKERS = new_workers
            save_config()
            logger.info(f"{ICONS['success']} 默认并发数已更新为: {DEFAULT_WORKERS}")
        else:
            logger.warning(f"{ICONS['warning']} 并发数必须在1-30之间")
    except ValueError:
        logger.error(f"{ICONS['error']} 请输入有效数字")
    except Exception as e:
        logger.error(f"{ICONS['error']} 操作出错: {str(e)}")

def set_timeout():
    """设置超时时间（范围限制）"""
    global DEFAULT_TIMEOUT
    print(f"\n{ICONS['settings']} 设置默认超时时间")
    print("-" * 50)
    
    try:
        new_timeout = input(f"当前默认超时: {DEFAULT_TIMEOUT}秒 (建议3-60): ").strip()
        if not new_timeout:
            logger.info(f"{ICONS['info']} 未输入，保持当前值")
            return
        
        new_timeout = int(new_timeout)
        if 3 <= new_timeout <= 60:
            DEFAULT_TIMEOUT = new_timeout
            save_config()
            logger.info(f"{ICONS['success']} 默认超时时间已更新为: {DEFAULT_TIMEOUT}秒")
        else:
            logger.warning(f"{ICONS['warning']} 超时时间必须在3-60秒之间")
    except ValueError:
        logger.error(f"{ICONS['error']} 请输入有效数字")
    except Exception as e:
        logger.error(f"{ICONS['error']} 操作出错: {str(e)}")

def show_help():
    """显示帮助信息（清晰的功能说明）"""
    print(f"\n{ICONS['info']} 帮助信息")
    print("-" * 50)
    help_text = f"""
{TOOL_NAME} v{VERSION} - 专注IP属地查询的URL检查工具

核心功能:
1. 批量URL检查: 从文件读取URL列表，批量检查可用性和IP属地
2. 单个目标检查: 检查单个URL或IP的详细信息（含属地、协议可用性）
3. IP属地查询: 多源验证IP的国家/地区、城市、运营商信息
4. 协议检测: 同时检查HTTP和HTTPS可用性，支持重定向追踪
5. 威胁情报: 集成VirusTotal和微步情报（需配置API密钥）
6. 结果导出: 自动保存详细结果到CSV，兼容Excel打开

使用说明:
- 批量检查: 准备每行一个URL的文本文件，选择功能1并输入文件路径
- 单个检查: 直接输入URL（需含http/https）或IP地址
- IP属地: 无需额外配置，工具自动查询多源IP数据库
- 威胁情报: 需通过功能6配置API密钥，免费账号有查询频率限制

注意事项:
- 并发数建议设置为5-10（过高可能被目标服务器拦截）
- 超时时间建议10-20秒（根据网络环境调整）
- CSV结果使用UTF-8编码，Excel打开时选择对应编码
- 部分API可能存在访问限制，建议避免短时间大量查询

快捷键:
- Ctrl+C: 中断当前操作，返回主菜单
- 回车: 确认输入，返回主菜单
    """
    print(help_text)
    print("-" * 50)

def show_version():
    """显示版本信息（清晰的更新日志）"""
    print(f"\n{ICONS['version']} 版本信息")
    print("-" * 50)
    version_text = f"""
工具名称: {TOOL_NAME}
版本号: v{VERSION}
作者: {AUTHOR}
兼容平台: Windows 7+, macOS 10.12+, Linux (Ubuntu/Debian/CentOS)

更新日志:
v4.1.0 (当前):
- 彻底移除ICP备案查询功能，专注IP属地查询
- 新增多源IP属地查询（ipapi/ipinfo/淘宝IP）
- 优化CSV保存逻辑，兼容多路径和权限问题
- 增强跨平台兼容性，修复Windows特殊字符问题

v4.0.0:
- 重构IP属地查询模块，增加缓存机制
- 优化HTTP/HTTPS检查逻辑，支持SSL跳过验证
- 增加IP反查关联域名功能

v3.2.0:
- 解决CSV保存失败问题，增加备份机制
- 优化命令行界面，增强用户体验

依赖要求:
- Python 3.6+
- requests 2.25.0+

使用命令:
python {os.path.basename(__file__)}
    """
    print(version_text)
    print("-" * 50)

def clear_history_cache():
    """清除历史结果和缓存（安全确认）"""
    print(f"\n{ICONS['clear']} 清除历史结果和缓存")
    print("-" * 50)
    
    # 查找要删除的文件
    delete_files = []
    # 结果文件
    for f in os.listdir('.'):
        if f.startswith(('ip_check_result_', 'ip_check_fallback_')) and f.endswith('.csv'):
            delete_files.append(f)
    
    # 缓存文件
    cache_files = [
        IP_CACHE_FILE,
        CONFIG_FILE,
        API_CONFIG_FILE,
        os.path.join(os.getcwd(), ".url_check_ip_config"),
        os.path.join(os.getcwd(), ".url_check_ip_api_keys")
    ]
    
    for f in cache_files:
        if os.path.exists(f):
            delete_files.append(f)
    
    if not delete_files:
        print(f"{ICONS['info']} 没有可清除的文件")
        return
    
    # 显示要删除的文件
    print(f"{ICONS['warning']} 即将删除以下 {len(delete_files)} 个文件:")
    for i, f in enumerate(delete_files[:10], 1):
        print(f"  {i}. {os.path.basename(f)}")
    if len(delete_files) > 10:
        print(f"  ... 还有 {len(delete_files) - 10} 个文件")
    
    # 确认删除
    confirm = input(f"\n确定要删除这些文件吗? (y/N): ").strip().lower()
    if confirm != 'y':
        logger.info(f"{ICONS['info']} 已取消删除")
        return
    
    # 执行删除
    deleted = 0
    failed = 0
    for f in delete_files:
        try:
            os.remove(f)
            deleted += 1
        except Exception as e:
            logger.error(f"{ICONS['error']} 删除 {os.path.basename(f)} 失败: {str(e)}")
            failed += 1
    
    print(f"\n{ICONS['info']} 清除完成:")
    print(f"  成功删除: {deleted} 个文件")
    print(f"  删除失败: {failed} 个文件")
    print("-" * 50)

def main():
    """主函数（兼容不同环境的启动流程）"""
    # 显示启动标识
    try:
        print_hack_banner()
    except Exception as e:
        # 兼容无终端动画的环境
        print(f"{ICONS['info']} {TOOL_NAME} v{VERSION} - 专注IP属地查询")
        print(f"{ICONS['info']} 作者: {AUTHOR}\n")
    
    # 加载配置
    load_config()
    
    # 检查依赖
    try:
        check_and_install_dependencies()
    except Exception as e:
        logger.warning(f"{ICONS['warning']} 依赖检查失败: {str(e)}，部分功能可能异常")
    
    # 主循环
    while True:
        print_menu()
        
        try:
            choice = input("请输入操作编号 (1-11): ").strip()
            
            # 功能路由
            if choice == '1':
                check_url_list()
            elif choice == '2':
                check_single_target()
            elif choice == '3':
                view_history()
            elif choice == '4':
                set_workers()
            elif choice == '5':
                set_timeout()
            elif choice == '6':
                configure_api_keys()
            elif choice == '7':
                show_help()
            elif choice == '8':
                show_version()
            elif choice == '9':
                check_and_install_dependencies(force_update=True)
            elif choice == '10':
                clear_history_cache()
            elif choice == '11':
                print(f"\n{ICONS['exit']} 感谢使用，再见!")
                sys.exit(0)
            else:
                logger.warning(f"{ICONS['warning']} 请输入1-11之间的有效编号")
        
        except KeyboardInterrupt:
            print(f"\n{ICONS['warning']} 检测到中断，返回主菜单")
        except Exception as e:
            logger.error(f"{ICONS['error']} 操作出错: {str(e)}")
        
        # 等待用户确认返回
        input("\n按回车键返回主菜单...")
        # 清屏（兼容不同终端）
        if sys.platform.startswith('win32'):
            os.system('cls')
        else:
            os.system('clear')
        # 重新显示标识
        try:
            print_hack_banner()
        except:
            print(f"{ICONS['info']} {TOOL_NAME} v{VERSION}\n")

if __name__ == "__main__":
    # 兼容Windows下的编码问题
    if sys.platform.startswith('win32'):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
            sys.stderr.reconfigure(encoding='utf-8')
        except:
            pass
    
    # 启动主程序
    main()
