#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
工具集：火焰URL扫描工具
作者：p1r07
版本：5.0.0（火焰主题优化版）
功能：URL扫描与ICP备案查询，火焰风格展示
"""

import os
import sys
import subprocess
import pkg_resources
import requests
import socket
import csv
import time
import json
import asyncio
import aiohttp
import hashlib
import re
import base64
import random
import tldextract
from urllib.parse import urlparse, urlunparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from colorama import init, Fore, Style
import logging

# -------------------------- 依赖检查 --------------------------
def 检查依赖():
    """检查并确保所有依赖包已安装"""
    required_packages = [
        'colorama>=0.4.6',
        'pycryptodome>=3.18.0',
        'tldextract>=3.4.0',
        'aiohttp>=3.8.4'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            pkg_resources.require(package)
        except:
            missing_packages.append(package.split('>=')[0])
    
    if missing_packages:
        print(f"{Fore.RED}检测到缺失的依赖包: {', '.join(missing_packages)}{Style.RESET_ALL}")
        install_cmd = f"pip install {' '.join(missing_packages)}"
        print(f"请运行以下命令安装: {Fore.GREEN}{install_cmd}{Style.RESET_ALL}")
        sys.exit(1)

# 预先检查依赖
检查依赖()

# -------------------------- 火焰主题配置 --------------------------
# 火焰主题颜色 - 模拟火焰的红、橙、黄渐变
FIRE_COLORS = {
    "red": Fore.RED,
    "dark_red": Fore.LIGHTRED_EX,
    "orange": Fore.LIGHTYELLOW_EX,
    "yellow": Fore.YELLOW,
    "gold": Fore.LIGHTGREEN_EX,  # 用于高亮
    "blue": Fore.BLUE,
    "reset": Style.RESET_ALL
}

# 火焰风格图标
FIRE_ICONS = {
    "flame": f"{FIRE_COLORS['red']}🔥{FIRE_COLORS['reset']}",
    "spark": f"{FIRE_COLORS['orange']}✨{FIRE_COLORS['reset']}",
    "success": f"{FIRE_COLORS['yellow']}✅{FIRE_COLORS['reset']}",
    "error": f"{FIRE_COLORS['red']}❌{FIRE_COLORS['reset']}",
    "info": f"{FIRE_COLORS['blue']}ℹ️{FIRE_COLORS['reset']}",
    "warning": f"{FIRE_COLORS['orange']}⚠️{FIRE_COLORS['reset']}",
    "check": f"{FIRE_COLORS['yellow']}🔍{FIRE_COLORS['reset']}",
    "icp": f"{FIRE_COLORS['blue']}📋{FIRE_COLORS['reset']}",
    "ip": f"{FIRE_COLORS['gold']}🌐{FIRE_COLORS['reset']}",
    "asn": f"{FIRE_COLORS['orange']}🔢{FIRE_COLORS['reset']}",
    "isp": f"{FIRE_COLORS['yellow']}📡{FIRE_COLORS['reset']}",
    "csv": f"{FIRE_COLORS['gold']}📊{FIRE_COLORS['reset']}",
    "author": f"{FIRE_COLORS['dark_red']}👤{FIRE_COLORS['reset']}"
}

# 火焰分隔线
FIRE_SEPARATOR = f"{FIRE_COLORS['red']}-{FIRE_COLORS['orange']}-{FIRE_COLORS['yellow']}-" * 15

# -------------------------- 基础配置 --------------------------
# 工具核心信息
TOOL_NAME = "火焰URL扫描工具"
AUTHOR = "p1r07"
VERSION = "5.0.0"
MODIFY_TIME = "2024/05/26 14:20"

# 路径配置
CSV_OUTPUT_DIR = os.path.expanduser(f"~/.fire_scan_results/{time.strftime('%Y%m%d')}")
os.makedirs(CSV_OUTPUT_DIR, exist_ok=True)
CACHE_DIR = os.path.expanduser("~/.fire_scan_cache")
os.makedirs(CACHE_DIR, exist_ok=True)

# 配置参数
DEFAULT_WORKERS = 3
DEFAULT_TIMEOUT = 15
RETRY_ATTEMPTS = 2
PRINT_DELAY = 0.05  # 打印延迟，解决速度过快问题
CACHE_EXPIRE = {
    "icp": 86400,      # ICP信息缓存24小时
    "ip": 3600,        # IP信息缓存1小时
    "asn": 86400,      # ASN信息缓存24小时
    "dns": 300         # DNS解析缓存5分钟
}

# 多源API配置
IP_INFO_APIS = [
    {
        "name": "ip-api",
        "url": "http://ip-api.com/json/{target}?fields=status,message,country,regionName,city,isp,org,as,asname,query",
        "timeout": 8,
        "success_key": "status",
        "success_value": "success",
        "mapping": {
            "country": "country",
            "region": "regionName",
            "city": "city",
            "isp": "isp",
            "org": "org",
            "asn": "as",
            "as_name": "asname",
            "ip": "query"
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
            "org": "org",
            "asn": lambda x: x.get("asn", "").split("AS")[1] if x.get("asn") else "",
            "as_name": lambda x: " ".join(x.get("asn", "").split(" ")[1:]) if x.get("asn") else "",
            "ip": "ip"
        }
    },
    {
        "name": "ip2location",
        "url": "https://api.ip2location.io/?ip={target}&key=demo",
        "timeout": 8,
        "success_key": "response",
        "success_value": "OK",
        "mapping": {
            "country": "country_name",
            "region": "region_name",
            "city": "city_name",
            "isp": "isp",
            "org": "domain",
            "asn": "asn",
            "as_name": "as",
            "ip": "ip"
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
            "org": "isp",
            "asn": None,
            "as_name": None,
            "ip": "ip"
        }
    }
]

# ICP备案查询源
ICP_QUERY_SOURCES = [
    {
        "name": "miit-official",
        "priority": 10,
        "reliable": True
    },
    {
        "name": "third-party-api1",
        "priority": 8,
        "reliable": False
    }
]

# 日志配置
init(autoreset=True)
logging.basicConfig(
    level=logging.INFO,
    format=f"{FIRE_COLORS['orange']}[%(asctime)s]{FIRE_COLORS['reset']} %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout
)
logger = logging.getLogger(TOOL_NAME)

# -------------------------- 火焰Banner --------------------------
def 打印火焰Banner():
    """打印火焰风格的工具Banner"""
    banner = f"""
{FIRE_COLORS['red']}███████╗{FIRE_COLORS['orange']}██████╗ {FIRE_COLORS['yellow']}██████╗  {FIRE_COLORS['red']}██████╗ {FIRE_COLORS['orange']}███████╗
{FIRE_COLORS['red']}██╔════╝{FIRE_COLORS['orange']}██╔══██╗{FIRE_COLORS['yellow']}██╔══██╗{FIRE_COLORS['red']}██╔═══██╗{FIRE_COLORS['orange']}██╔════╝
{FIRE_COLORS['red']}█████╗  {FIRE_COLORS['orange']}██████╔╝{FIRE_COLORS['yellow']}██████╔╝{FIRE_COLORS['red']}██║   ██║{FIRE_COLORS['orange']}█████╗  
{FIRE_COLORS['red']}██╔══╝  {FIRE_COLORS['orange']}██╔══██╗{FIRE_COLORS['yellow']}██╔══██╗{FIRE_COLORS['red']}██║   ██║{FIRE_COLORS['orange']}██╔══╝  
{FIRE_COLORS['red']}██║     {FIRE_COLORS['orange']}██║  ██║{FIRE_COLORS['yellow']}██████╔╝{FIRE_COLORS['red']}╚██████╔╝{FIRE_COLORS['orange']}███████╗
{FIRE_COLORS['red']}╚═╝     {FIRE_COLORS['orange']}╚═╝  ╚═╝{FIRE_COLORS['yellow']}╚═════╝ {FIRE_COLORS['red']}╚═════╝ {FIRE_COLORS['orange']}╚══════╝{FIRE_COLORS['reset']}

{FIRE_COLORS['yellow']}              {TOOL_NAME} v{VERSION}{FIRE_COLORS['reset']}
{FIRE_ICONS['author']} {FIRE_COLORS['dark_red']}作者: {AUTHOR} | 最后更新: {MODIFY_TIME}{FIRE_COLORS['reset']}
{FIRE_SEPARATOR}{FIRE_COLORS['reset']}
    """
    print(banner)
    # 模拟火焰燃烧效果
    for i in range(3):
        print(f"{FIRE_ICONS['flame']}", end=' ', flush=True)
        time.sleep(0.2)
    print("\n")

# -------------------------- 缓存管理 --------------------------
class CacheManager:
    """缓存管理器"""
    def __init__(self, cache_dir=CACHE_DIR):
        self.cache_dir = cache_dir
        self.caches = {
            "icp": self._load_cache("icp_cache.json"),
            "ip": self._load_cache("ip_cache.json"),
            "asn": self._load_cache("asn_cache.json"),
            "dns": self._load_cache("dns_cache.json")
        }

    def _load_cache(self, filename):
        """加载缓存文件"""
        cache_path = os.path.join(self.cache_dir, filename)
        try:
            if os.path.exists(cache_path):
                with open(cache_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"{FIRE_ICONS['warning']} 加载缓存 {filename} 失败: {str(e)}")
        return {}

    def _save_cache(self, cache_type):
        """保存缓存到文件"""
        filename = f"{cache_type}_cache.json"
        cache_path = os.path.join(self.cache_dir, filename)
        try:
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(self.caches[cache_type], f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f"{FIRE_ICONS['warning']} 保存缓存 {filename} 失败: {str(e)}")

    def get_cached_data(self, cache_type, key):
        """获取缓存数据（带过期检查）"""
        if cache_type not in self.caches:
            return None
            
        cache_entry = self.caches[cache_type].get(key)
        if not cache_entry:
            return None
            
        # 检查缓存是否过期
        expire_time = CACHE_EXPIRE.get(cache_type, 3600)
        if time.time() - cache_entry['timestamp'] < expire_time:
            return cache_entry['data']
            
        # 缓存过期，删除
        del self.caches[cache_type][key]
        self._save_cache(cache_type)
        return None

    def set_cached_data(self, cache_type, key, data):
        """设置缓存数据"""
        if cache_type not in self.caches:
            return False
            
        self.caches[cache_type][key] = {
            'timestamp': time.time(),
            'data': data
        }
        self._save_cache(cache_type)
        return True

    def save_all_caches(self):
        """保存所有缓存"""
        for cache_type in self.caches:
            self._save_cache(cache_type)

# -------------------------- ICP备案查询核心 --------------------------
class ICP备案查询器:
    """ICP备案查询核心类"""
    def __init__(self, cache_manager):
        self.cache_manager = cache_manager
        self.base_url = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api"
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
            'Origin': 'https://beian.miit.gov.cn',
            'Referer': 'https://beian.miit.gov.cn/',
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/json;charset=UTF-8'
        }
        self.session = None
        self.token = None
        self.sign = None
        self.uuid = None
        self.initialized = False

    async def initialize(self):
        """初始化会话"""
        if self.initialized:
            return True
            
        # 创建新的会话
        self.session = aiohttp.ClientSession(headers=self.headers)
            
        # 最多尝试3次初始化
        for _ in range(3):
            if await self._setup_session():
                self.initialized = True
                return True
            await asyncio.sleep(2)
            
        logger.warning(f"{FIRE_ICONS['warning']} ICP查询器初始化失败，将使用缓存和备用源")
        return False

    async def _setup_session(self):
        """设置会话信息"""
        try:
            # 获取基础Cookie
            if not await self._get_base_cookie():
                return False
                
            # 获取认证Token
            if not await self._get_auth_token():
                return False
                
            # 处理验证码
            if not await self._handle_captcha():
                return False
                
            return True
        except Exception as e:
            logger.error(f"{FIRE_ICONS['error']} 会话设置失败: {str(e)}")
            return False

    async def _get_base_cookie(self):
        """获取基础Cookie"""
        try:
            async with self.session.get("https://beian.miit.gov.cn/") as response:
                cookies = response.cookies
                cookie_str = []
                for cookie in cookies:
                    cookie_str.append(f"{cookie.name}={cookie.value}")
                    if cookie.name.startswith("__jsluid_s"):
                        self.headers['Cookie'] = "; ".join(cookie_str)
                        return True
            logger.warning(f"{FIRE_ICONS['warning']} 未能获取有效Cookie")
            return False
        except Exception as e:
            logger.error(f"{FIRE_ICONS['error']} 获取Cookie失败: {str(e)}")
            return False

    async def _get_auth_token(self):
        """获取认证Token"""
        try:
            timestamp = round(time.time() * 1000)
            auth_secret = f"testtest{timestamp}"
            auth_key = hashlib.md5(auth_secret.encode()).hexdigest()
            
            data = {"authKey": auth_key, "timeStamp": timestamp}
            async with self.session.post(f"{self.base_url}/auth", json=data) as response:
                result = await response.json()
                if result.get("success"):
                    self.token = result["params"]["bussiness"]
                    self.headers['Token'] = self.token
                    return True
            logger.warning(f"{FIRE_ICONS['warning']} 未能获取有效认证Token")
            return False
        except Exception as e:
            logger.error(f"{FIRE_ICONS['error']} 获取认证Token失败: {str(e)}")
            return False

    async def _handle_captcha(self):
        """处理验证码"""
        try:
            client_uid = self._generate_client_id()
            
            async with self.session.post(
                f"{self.base_url}/image/getCheckImagePoint",
                json=json.loads(client_uid)
            ) as response:
                result = await response.json()
                if not result.get("success"):
                    logger.warning(f"{FIRE_ICONS['warning']} 获取验证码图片失败: {result.get('msg')}")
                    return False
                
                self.uuid = result["params"]["uuid"]
                secret_key = result["params"]["secretKey"]
                self.headers['Uuid'] = self.uuid
                
                point_json = self._solve_captcha(secret_key)
                if not point_json:
                    return False
                
                verify_data = {
                    "token": self.uuid,
                    "secretKey": secret_key,
                    "clientUid": json.loads(client_uid)["clientUid"],
                    "pointJson": point_json
                }
                
                async with self.session.post(
                    f"{self.base_url}/image/checkImage",
                    json=verify_data
                ) as verify_response:
                    verify_result = await verify_response.json()
                    if verify_result.get("success"):
                        self.sign = verify_result["params"]["sign"]
                        self.headers['Sign'] = self.sign
                        return True
                logger.warning(f"{FIRE_ICONS['warning']} 验证码验证失败: {verify_result.get('msg')}")
                return False
        except Exception as e:
            logger.error(f"{FIRE_ICONS['error']} 处理验证码失败: {str(e)}")
            return False

    def _generate_client_id(self):
        """生成客户端唯一ID"""
        chars = "0123456789abcdef"
        uuid = [random.choice(chars) for _ in range(36)]
        uuid[14] = '4'
        uuid[19] = chars[(3 & int(uuid[19], 16)) | 8]
        uuid[8] = uuid[13] = uuid[18] = uuid[23] = "-"
        return json.dumps({"clientUid": f"point-{''.join(uuid)}"})

    def _solve_captcha(self, secret_key):
        """解决验证码"""
        try:
            points = [
                {"x": 110 + random.randint(-3, 3), "y": 105 + random.randint(-3, 3)},
                {"x": 220 + random.randint(-3, 3), "y": 145 + random.randint(-3, 3)}
            ]
            
            cipher = AES.new(secret_key.encode(), AES.MODE_ECB)
            ciphertext = cipher.encrypt(pad(json.dumps(points).encode(), AES.block_size))
            return base64.b64encode(ciphertext).decode('utf-8')
        except Exception as e:
            logger.error(f"{FIRE_ICONS['error']} 验证码处理失败: {str(e)}")
            return None

    async def 查询域名备案(self, domain):
        """查询域名备案信息"""
        # 1. 先检查缓存
        cached = self.cache_manager.get_cached_data("icp", domain)
        if cached:
            cached['source'] = 'cache'
            return cached
        
        # 2. 提取主域名
        main_domain = self._extract_main_domain(domain)
        if not main_domain:
            result = {"has_icp": False, "message": "无效域名格式", "source": "local"}
            self.cache_manager.set_cached_data("icp", domain, result)
            return result
        
        # 3. 多源查询与验证
        results = []
        
        # 优先使用工信部官方接口
        official_result = await self._query_official_icp(main_domain)
        if official_result:
            results.append((official_result, ICP_QUERY_SOURCES[0]['priority']))
        
        # 使用第三方接口作为补充
        third_party_result = await self._query_third_party_icp(main_domain)
        if third_party_result:
            results.append((third_party_result, ICP_QUERY_SOURCES[1]['priority']))
        
        # 4. 结果融合与验证
        if not results:
            result = {"has_icp": False, "message": "所有查询源均失败", "source": "none"}
            self.cache_manager.set_cached_data("icp", domain, result)
            return result
        
        # 按优先级排序，取最可信结果
        results.sort(key=lambda x: x[1], reverse=True)
        best_result = results[0][0]
        
        # 交叉验证
        if len(results) > 1:
            if self._verify_icp_results(best_result, results[1][0]):
                best_result['verified'] = True
            else:
                best_result['verified'] = False
                best_result['conflict_note'] = "不同查询源结果不一致"
        
        self.cache_manager.set_cached_data("icp", domain, best_result)
        return best_result

    async def _query_official_icp(self, domain):
        """通过官方接口查询ICP备案"""
        try:
            # 确保会话已初始化
            if not self.initialized and not await self.initialize():
                return None
                
            # 多条件查询提高准确性
            for service_type in [1, 0]:  # 1:网站, 0:全部类型
                for attempt in range(RETRY_ATTEMPTS):
                    try:
                        data = {
                            "pageNum": 1,
                            "pageSize": 20,
                            "unitName": "",
                            "serviceType": service_type,
                            "domainName": domain
                        }
                        
                        async with self.session.post(
                            f"{self.base_url}/icpAbbreviateInfo/queryByCondition",
                            json=data
                        ) as response:
                            result = await response.json()
                            parsed = self._parse_official_response(result, domain)
                            if parsed:
                                parsed['source'] = 'miit-official'
                                return parsed
                    except Exception as e:
                        logger.warning(f"{FIRE_ICONS['warning']} 官方接口尝试 {attempt+1} 失败: {str(e)}")
                        if attempt < RETRY_ATTEMPTS - 1:
                            await asyncio.sleep(1)
            
            # 尝试按单位名称查询
            domain_prefix = domain.split('.')[0] if '.' in domain else domain
            data = {
                "pageNum": 1,
                "pageSize": 20,
                "unitName": domain_prefix,
                "serviceType": 1
            }
            
            async with self.session.post(
                f"{self.base_url}/icpAbbreviateInfo/queryByCondition",
                json=data
            ) as response:
                result = await response.json()
                parsed = self._parse_official_response(result, domain)
                if parsed:
                    parsed['source'] = 'miit-official'
                    return parsed
                    
            return {"has_icp": False, "message": "未找到备案信息", "source": "miit-official"}
            
        except Exception as e:
            logger.error(f"{FIRE_ICONS['error']} 官方ICP查询失败: {str(e)}")
            return None

    async def _query_third_party_icp(self, domain):
        """通过第三方接口查询ICP备案"""
        try:
            # 第三方API示例
            third_party_url = f"https://api.example.com/icp?domain={domain}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(third_party_url, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("status") == "success" and data.get("has_icp"):
                            return {
                                "has_icp": True,
                                "domain": domain,
                                "license": data.get("license", "未知"),
                                "unit": data.get("unit", "未知"),
                                "website_name": data.get("website_name", "未知"),
                                "update_time": data.get("update_time", "未知"),
                                "source": "third-party"
                            }
                        else:
                            return {
                                "has_icp": False,
                                "message": data.get("message", "未找到备案信息"),
                                "source": "third-party"
                            }
            return {"has_icp": False, "message": "第三方接口查询失败", "source": "third-party"}
        except Exception as e:
            logger.warning(f"{FIRE_ICONS['warning']} 第三方ICP查询失败: {str(e)}")
            return None

    def _parse_official_response(self, response_data, domain):
        """解析官方接口响应"""
        try:
            if response_data.get("code") != 200:
                return {"has_icp": False, "message": response_data.get("msg", "查询失败")}
                
            params = response_data.get("params", {})
            records = params.get("list", [])
            
            if not records:
                return {"has_icp": False, "message": "未找到备案信息"}
            
            # 精确匹配域名
            domain_parts = tldextract.extract(domain)
            main_domain = f"{domain_parts.domain}.{domain_parts.suffix}"
            matched_records = []
            
            for record in records:
                record_domain = str(record.get("domain", "")).lower()
                record_parts = tldextract.extract(record_domain)
                record_main = f"{record_parts.domain}.{record_parts.suffix}"
                
                if record_main == main_domain:
                    matched_records.append(record)
            
            # 选择最佳匹配
            if matched_records:
                best_record = matched_records[0]
            else:
                best_record = records[0]
            
            return {
                "has_icp": True,
                "domain": domain,
                "main_domain": main_domain,
                "license": best_record.get("serviceLicence", "未知"),
                "unit": best_record.get("unitName", "未知"),
                "unit_type": best_record.get("unitType", "未知"),
                "website_name": best_record.get("serviceName", "未知"),
                "website_type": best_record.get("serviceType", "未知"),
                "update_time": best_record.get("updateRecordTime", "未知"),
                "matched_count": len(matched_records) if matched_records else 1
            }
            
        except Exception as e:
            logger.error(f"{FIRE_ICONS['error']} 解析备案信息失败: {str(e)}")
            return {"has_icp": False, "message": f"解析错误: {str(e)}"}

    def _extract_main_domain(self, domain):
        """提取主域名"""
        try:
            ext = tldextract.extract(domain)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}"
            
            parsed = urlparse(domain)
            if parsed.netloc:
                return parsed.netloc.split(':')[0]
            return domain.split('/')[0].split(':')[0]
        except Exception as e:
            logger.error(f"{FIRE_ICONS['error']} 提取主域名失败: {str(e)}")
            return domain

    def _verify_icp_results(self, result1, result2):
        """验证两个备案查询结果是否一致"""
        if not result1.get("has_icp") or not result2.get("has_icp"):
            return result1.get("has_icp") == result2.get("has_icp")
            
        # 关键信息匹配度
        match_count = 0
        total_checks = 0
        
        # 检查许可证号
        if result1.get("license") and result2.get("license"):
            total_checks += 1
            if result1["license"] in result2["license"] or result2["license"] in result1["license"]:
                match_count += 1
        
        # 检查主办单位
        if result1.get("unit") and result2.get("unit"):
            total_checks += 1
            if result1["unit"] in result2["unit"] or result2["unit"] in result1["unit"]:
                match_count += 1
        
        # 检查网站名称
        if result1.get("website_name") and result2.get("website_name"):
            total_checks += 1
            if result1["website_name"] in result2["website_name"] or result2["website_name"] in result1["website_name"]:
                match_count += 1
        
        # 匹配度超过60%视为一致
        return total_checks == 0 or (match_count / total_checks) > 0.6

    async def close(self):
        """关闭会话"""
        if self.session:
            await self.session.close()
            self.session = None
        self.initialized = False

# -------------------------- IP与网络信息查询核心 --------------------------
class IP信息查询器:
    """IP信息查询器"""
    def __init__(self, cache_manager):
        self.cache_manager = cache_manager
        self.session = None

    async def 初始化会话(self):
        """初始化会话"""
        if not self.session:
            self.session = aiohttp.ClientSession()
        return True

    async def 查询IP信息(self, ip):
        """查询IP信息"""
        # 确保会话已初始化
        await self.初始化会话()
        
        # 1. 检查缓存
        cached = self.cache_manager.get_cached_data("ip", ip)
        if cached:
            cached['source'] = 'cache'
            return cached
        
        # 2. 多源查询
        results = []
        for api in IP_INFO_APIS:
            try:
                result = await self._query_ip_api(api, ip)
                if result:
                    results.append((result, api))
                    if api.get("reliable", False):
                        break
            except Exception as e:
                logger.warning(f"{FIRE_ICONS['warning']} API {api['name']} 查询失败: {str(e)}")
                continue
        
        # 3. 融合结果提高准确性
        if not results:
            result = {
                "ip": ip,
                "country": "未知",
                "region": "未知",
                "city": "未知",
                "isp": "未知",
                "org": "未知",
                "asn": "未知",
                "as_name": "未知",
                "source": "none"
            }
            self.cache_manager.set_cached_data("ip", ip, result)
            return result
        
        # 4. 结果融合与验证
        fused_result = self._fuse_ip_results(results)
        self.cache_manager.set_cached_data("ip", ip, fused_result)
        return fused_result

    async def _query_ip_api(self, api_config, ip):
        """查询单个IP信息API"""
        try:
            url = api_config["url"].format(target=ip)
            async with self.session.get(url, timeout=api_config["timeout"]) as response:
                if response.status != 200:
                    return None
                    
                data = await response.json()
                
                # 检查API特定的成功条件
                if "success_key" in api_config:
                    if data.get(api_config["success_key"]) != api_config["success_value"]:
                        return None
                
                # 提取数据
                result = {}
                mapping = api_config["mapping"]
                
                # 如果API返回的数据嵌套在特定键下
                if "data_key" in api_config:
                    data = data.get(api_config["data_key"], {})
                
                # 映射字段
                for key, source in mapping.items():
                    if callable(source):
                        result[key] = source(data)
                    elif source is not None:
                        result[key] = data.get(source, "未知")
                    else:
                        result[key] = "未知"
                
                # 确保IP字段存在
                if "ip" not in result or not result["ip"]:
                    result["ip"] = ip
                    
                result["source"] = api_config["name"]
                return result
                
        except Exception as e:
            logger.error(f"{FIRE_ICONS['error']} IP查询失败: {str(e)}")
            return None

    def _fuse_ip_results(self, results):
        """融合多个API的IP查询结果"""
        # 结果格式模板
        fused = {
            "ip": results[0][0]["ip"],
            "country": [],
            "region": [],
            "city": [],
            "isp": [],
            "org": [],
            "asn": [],
            "as_name": [],
            "sources": []
        }
        
        # 收集所有结果
        for result, api in results:
            fused["sources"].append(api["name"])
            for key in ["country", "region", "city", "isp", "org", "asn", "as_name"]:
                if result.get(key) and result[key] not in ["未知", "", None]:
                    fused[key].append(result[key])
        
        # 按出现频率选择最可能的值
        final = {"ip": fused["ip"], "sources": ", ".join(fused["sources"])}
        for key in ["country", "region", "city", "isp", "org", "asn", "as_name"]:
            if fused[key]:
                # 选择出现次数最多的值
                final[key] = max(set(fused[key]), key=fused[key].count)
            else:
                final[key] = "未知"
        
        return final

    async def 解析域名IP(self, domain):
        """解析域名IP"""
        # 确保会话已初始化
        await self.初始化会话()
        
        # 1. 检查缓存
        cached = self.cache_manager.get_cached_data("dns", domain)
        if cached:
            return cached
        
        # 2. 多方法解析提高准确性
        ips = set()
        
        # 方法1: 使用系统DNS解析
        try:
            addr_info = socket.getaddrinfo(domain, None, socket.AF_INET)
            for info in addr_info:
                ips.add(info[4][0])
        except Exception as e:
            logger.warning(f"{FIRE_ICONS['warning']} DNS解析失败: {str(e)}")
        
        # 3. 处理结果
        ip_list = list(ips) if ips else []
        result = {
            "domain": domain,
            "ips": ip_list,
            "primary_ip": ip_list[0] if ip_list else None,
            "ip_count": len(ip_list),
            "is_cdn": len(ip_list) > 3  # 简单判断是否为CDN
        }
        
        self.cache_manager.set_cached_data("dns", domain, result)
        return result

    async def close(self):
        """关闭会话"""
        if self.session:
            await self.session.close()
            self.session = None

# -------------------------- 扫描核心功能 --------------------------
class URL扫描器:
    """URL扫描器（火焰版）"""
    def __init__(self, cache_manager, enable_icp=True, workers=DEFAULT_WORKERS, timeout=DEFAULT_TIMEOUT):
        self.cache_manager = cache_manager
        self.enable_icp = enable_icp
        self.workers = workers
        self.timeout = timeout
        self.icp查询器 = ICP备案查询器(cache_manager) if enable_icp else None
        self.ip查询器 = IP信息查询器(cache_manager)
        self.results = []

    async def 初始化(self):
        """初始化扫描器"""
        await self.ip查询器.初始化会话()
        if self.enable_icp and self.icp查询器:
            await self.icp查询器.initialize()
        return True

    async def 扫描单个URL(self, url):
        """扫描单个URL"""
        # 标准化URL
        normalized_url = self._标准化URL(url)
        if not normalized_url:
            logger.warning(f"{FIRE_ICONS['warning']} 无效URL: {url}")
            return None

        parsed_url = urlparse(normalized_url)
        hostname = parsed_url.netloc
        
        # 初始化结果
        result = {
            'original_url': url,
            'normalized_url': normalized_url,
            'hostname': hostname,
            'check_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'dns_info': {},
            'ip_info': {},
            'http': {},
            'https': {},
            'icp_info': {}
        }

        # 1. 解析DNS信息
        logger.info(f"{FIRE_ICONS['ip']} 正在解析 {hostname} 的IP地址...")
        dns_info = await self.ip查询器.解析域名IP(hostname)
        result['dns_info'] = dns_info
        
        # 2. 获取IP信息（如果有IP）
        if dns_info['primary_ip']:
            logger.info(f"{FIRE_ICONS['asn']} 正在查询 {dns_info['primary_ip']} 的ASN和运营商信息...")
            ip_info = await self.ip查询器.查询IP信息(dns_info['primary_ip'])
            result['ip_info'] = ip_info
        
        # 3. 检查HTTP和HTTPS可用性
        logger.info(f"{FIRE_ICONS['check']} 正在检查 {hostname} 的连接性...")
        result['http'] = await self._检查URL协议(normalized_url, 'http')
        result['https'] = await self._检查URL协议(normalized_url, 'https')
        
        # 4. 查询ICP备案信息
        if self.enable_icp and self.icp查询器 and hostname:
            logger.info(f"{FIRE_ICONS['icp']} 正在查询 {hostname} 的ICP备案信息...")
            result['icp_info'] = await self.icp查询器.查询域名备案(hostname)

        return result

    def _标准化URL(self, url):
        """标准化URL格式"""
        if not url or not isinstance(url, str):
            return None
            
        url = url.strip()
        parsed = urlparse(url)
        
        # 处理无协议URL
        if not parsed.scheme:
            for scheme in ['https', 'http']:
                test_url = f"{scheme}://{url}"
                if self._验证URL(test_url):
                    return test_url
            return None
            
        if parsed.scheme not in ['http', 'https']:
            return None
            
        return urlunparse(parsed)

    def _验证URL(self, url):
        """验证URL格式是否有效"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    async def _检查URL协议(self, url, protocol):
        """检查指定协议的URL可用性"""
        parsed = urlparse(url)
        target_url = urlunparse((protocol, parsed.netloc, parsed.path, 
                                parsed.params, parsed.query, parsed.fragment))
        
        result = {
            'url': target_url,
            'status_code': None,
            'is_accessible': False,
            'error': None,
            'redirect_count': 0,
            'final_url': target_url,
            'response_time': None
        }
        
        try:
            start_time = time.time()
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    target_url, 
                    timeout=self.timeout, 
                    allow_redirects=True,
                    headers=headers,
                    ssl=False
                ) as response:
                    result['response_time'] = round(time.time() - start_time, 3)
                    result['status_code'] = response.status
                    result['is_accessible'] = response.status == 200
                    result['redirect_count'] = len(response.history)
                    result['final_url'] = str(response.url)
            
        except Exception as e:
            result['error'] = str(e)
            result['response_time'] = round(time.time() - start_time, 3)
            
        return result

    async def 批量扫描(self, urls):
        """批量扫描URL列表"""
        # 初始化扫描器
        await self.初始化()
        
        # 处理URL列表
        valid_urls = [url for url in urls if self._标准化URL(url)]
        if not valid_urls:
            logger.warning(f"{FIRE_ICONS['warning']} 没有有效URL可扫描")
            return []
            
        logger.info(f"{FIRE_ICONS['info']} 开始批量扫描 {len(valid_urls)} 个URL")
        
        # 并发扫描
        tasks = [self.扫描单个URL(url) for url in valid_urls]
        for future in asyncio.as_completed(tasks):
            result = await future
            if result:
                self.results.append(result)
                self._显示扫描进度(result)
                # 添加延迟控制打印速度
                await asyncio.sleep(PRINT_DELAY)
        
        # 保存结果到CSV
        self._保存结果到CSV()
        
        return self.results

    def _显示扫描进度(self, result):
        """显示扫描进度信息"""
        hostname = result['hostname']
        ip = result['dns_info']['primary_ip'] or '未知IP'
        asn = result['ip_info'].get('asn', '未知ASN')
        isp = result['ip_info'].get('isp', '未知运营商')
        
        https_status = f"{FIRE_ICONS['success']}" if result['https']['is_accessible'] else f"{FIRE_ICONS['error']}"
        http_status = f"{FIRE_ICONS['success']}" if result['http']['is_accessible'] else f"{FIRE_ICONS['error']}"
        
        icp_status = "未查询"
        if self.enable_icp and result['icp_info']:
            icp_status = f"{FIRE_ICONS['success']}已备案" if result['icp_info'].get('has_icp') else f"{FIRE_ICONS['warning']}未备案"
        
        # 火焰风格的进度显示
        line = f"{FIRE_ICONS['flame']} {https_status} HTTPS | {http_status} HTTP | {ip} | AS{asn} | {isp} | {hostname} | ICP: {icp_status}"
        print(line)

    def _保存结果到CSV(self):
        """保存扫描结果到CSV文件（修复保存问题）"""
        if not self.results:
            logger.info(f"{FIRE_ICONS['info']} 没有结果可保存")
            return None
            
        # 确保输出目录存在
        if not os.path.exists(CSV_OUTPUT_DIR):
            try:
                os.makedirs(CSV_OUTPUT_DIR, exist_ok=True)
            except Exception as e:
                logger.error(f"{FIRE_ICONS['error']} 无法创建输出目录: {str(e)}")
                return None
        
        # 生成带时间戳的文件名
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        csv_filename = f"fire_scan_result_{timestamp}.csv"
        csv_path = os.path.join(CSV_OUTPUT_DIR, csv_filename)
        
        # 定义CSV字段
        fieldnames = [
            'original_url', 'normalized_url', 'hostname', 
            'primary_ip', 'all_ips', 'is_cdn',
            'ip_country', 'ip_region', 'ip_city', 
            'isp', 'org', 'asn', 'as_name', 'ip_sources',
            'https_url', 'https_status', 'https_accessible', 'https_response_time', 'https_error',
            'http_url', 'http_status', 'http_accessible', 'http_response_time', 'http_error',
            'icp_has_record', 'icp_license', 'icp_unit', 'icp_website_name',
            'icp_update_time', 'icp_source', 'icp_verified', 'icp_message',
            'check_time'
        ]
        
        try:
            with open(csv_path, 'w', newline='', encoding='utf-8-sig') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for result in self.results:
                    icp_info = result.get('icp_info', {})
                    dns_info = result.get('dns_info', {})
                    ip_info = result.get('ip_info', {})
                    
                    writer.writerow({
                        'original_url': result['original_url'],
                        'normalized_url': result['normalized_url'],
                        'hostname': result['hostname'],
                        'primary_ip': dns_info.get('primary_ip', ''),
                        'all_ips': ', '.join(dns_info.get('ips', [])),
                        'is_cdn': dns_info.get('is_cdn', False),
                        'ip_country': ip_info.get('country', ''),
                        'ip_region': ip_info.get('region', ''),
                        'ip_city': ip_info.get('city', ''),
                        'isp': ip_info.get('isp', ''),
                        'org': ip_info.get('org', ''),
                        'asn': ip_info.get('asn', ''),
                        'as_name': ip_info.get('as_name', ''),
                        'ip_sources': ip_info.get('sources', ''),
                        'https_url': result['https']['url'],
                        'https_status': result['https']['status_code'] or '',
                        'https_accessible': result['https']['is_accessible'],
                        'https_response_time': result['https']['response_time'],
                        'https_error': result['https']['error'] or '',
                        'http_url': result['http']['url'],
                        'http_status': result['http']['status_code'] or '',
                        'http_accessible': result['http']['is_accessible'],
                        'http_response_time': result['http']['response_time'],
                        'http_error': result['http']['error'] or '',
                        'icp_has_record': icp_info.get('has_icp', False),
                        'icp_license': icp_info.get('license', ''),
                        'icp_unit': icp_info.get('unit', ''),
                        'icp_website_name': icp_info.get('website_name', ''),
                        'icp_update_time': icp_info.get('update_time', ''),
                        'icp_source': icp_info.get('source', ''),
                        'icp_verified': icp_info.get('verified', ''),
                        'icp_message': icp_info.get('message', ''),
                        'check_time': result['check_time']
                    })
            
            logger.info(f"{FIRE_ICONS['csv']} 扫描结果已保存到: {csv_path}")
            return csv_path
            
        except PermissionError:
            logger.error(f"{FIRE_ICONS['error']} 没有权限写入文件: {csv_path}")
            return None
        except Exception as e:
            logger.error(f"{FIRE_ICONS['error']} 保存CSV文件失败: {str(e)}")
            return None

    async def 关闭(self):
        """关闭扫描器资源（修复事件循环错误）"""
        # 确保所有会话都正确关闭
        if self.icp查询器:
            await self.icp查询器.close()
        await self.ip查询器.close()
        self.cache_manager.save_all_caches()

# -------------------------- 主程序入口 --------------------------
def 读取URL文件(file_path):
    """从文件读取URL列表"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"{FIRE_ICONS['error']} 读取URL文件失败: {str(e)}")
        return []

async def 安全主流程():
    """安全的主流程包装，防止事件循环错误"""
    # 打印火焰Banner
    打印火焰Banner()
    
    # 初始化缓存管理器
    cache_manager = CacheManager()
    
    # 询问用户是否启用ICP查询
    icp_choice = input(f"{FIRE_ICONS['icp']} 是否查询ICP备案信息? (y/n，默认y): ").strip().lower()
    enable_icp = icp_choice != 'n'  # 默认启用
    
    # 选择扫描模式
    print("\n请选择扫描模式:")
    print("1. 批量URL扫描（从文件读取）")
    print("2. 单个URL扫描")
    
    choice = input("请选择 (1/2): ").strip()
    
    # 初始化扫描器
    scanner = URL扫描器(cache_manager, enable_icp=enable_icp)
    
    try:
        if choice == '1':
            # 批量扫描
            file_path = input("请输入包含URL的文件路径: ").strip()
            if not os.path.exists(file_path):
                logger.error(f"{FIRE_ICONS['error']} 文件不存在: {file_path}")
                return
                
            urls = 读取URL文件(file_path)
            if not urls:
                logger.error(f"{FIRE_ICONS['error']} 未从文件中读取到有效URL")
                return
                
            await scanner.批量扫描(urls)
            
        elif choice == '2':
            # 单个URL扫描
            url = input("请输入要扫描的URL: ").strip()
            if not url:
                logger.error(f"{FIRE_ICONS['error']} URL不能为空")
                return
                
            result = await scanner.扫描单个URL(url)
            if result:
                scanner.results.append(result)
                scanner._保存结果到CSV()
                
        else:
            logger.error(f"{FIRE_ICONS['error']} 无效选择")
            return
            
        # 显示扫描总结
        print(f"\n{FIRE_SEPARATOR}{FIRE_COLORS['reset']}")
        print(f"{FIRE_ICONS['info']} 扫描完成:")
        print(f"总URL数: {len(scanner.results)}")
        
        https_ok = sum(1 for r in scanner.results if r['https']['is_accessible'])
        http_ok = sum(1 for r in scanner.results if r['http']['is_accessible'])
        print(f"可访问URL数: {https_ok + http_ok} (HTTPS: {https_ok}, HTTP: {http_ok})")
        
        if enable_icp:
            icp_count = sum(1 for r in scanner.results if r['icp_info'].get('has_icp', False))
            print(f"已备案域名数: {icp_count}")
        
        cdn_count = sum(1 for r in scanner.results if r['dns_info'].get('is_cdn', False))
        print(f"疑似CDN加速域名数: {cdn_count}")
        
        print(f"\n{FIRE_ICONS['author']} 工具作者: {AUTHOR}")
        print(f"{FIRE_SEPARATOR}{FIRE_COLORS['reset']}")
        
    finally:
        # 确保资源正确释放
        await scanner.关闭()

def 主函数():
    """主函数，处理事件循环"""
    try:
        # 使用合适的事件循环策略
        if sys.platform.startswith('win'):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
        asyncio.run(安全主流程())
        
    except KeyboardInterrupt:
        logger.info(f"\n{FIRE_ICONS['info']} 用户中断操作")
    except Exception as e:
        logger.error(f"{FIRE_ICONS['error']} 程序异常退出: {str(e)}")
    sys.exit(0)

if __name__ == "__main__":
    主函数()
    
