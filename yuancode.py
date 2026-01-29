#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FOFA源码扫描工具 v2.0
功能：通过FOFA搜索关键词 -> 发现网站 -> 爬取源码 -> 检测敏感信息
作者：Security Researcher
"""

import sys
import os
import sys
import os
import re
import json
import time
import base64
import hashlib
import argparse
import configparser
import concurrent.futures
from urllib.parse import urlparse, urljoin, quote
from datetime import datetime
from typing import List, Dict, Set, Optional, Tuple
import threading

# 第三方库导入
try:
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError as e:
    print(f"缺少依赖库: {e}")
    print("请安装: pip install requests colorama")
    sys.exit(1)

# 尝试导入代理支持
try:
    import socks
    import socket
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False
    print(f"{Fore.YELLOW}[!] 未安装socks支持，如需代理请: pip install PySocks")

class Config:
    """配置文件"""
    def __init__(self):
        self.config_parser = configparser.ConfigParser()
        config_path = os.path.join(os.path.dirname(__file__), 'config.ini')
        
        if os.path.exists(config_path):
            self.config_parser.read(config_path, encoding='utf-8')
        else:
            # 如果配置文件不存在，使用默认值
            self._set_defaults()
        
        # FOFA API配置
        self.FOFA_API_URL = "https://fofa.info/api/v1/search/all"
        self.FOFA_BATCH_SIZE = 100  # 每次查询数量
        self.FOFA_MAX_PAGES = self.config_parser.getint('yuancode_config', 'fofa_max_pages', fallback=10)    # 最大查询页数
        
        # 爬虫配置
        self.REQUEST_TIMEOUT = 15
        self.MAX_RETRIES = 3
        self.RETRY_DELAY = 1
        self.REQUEST_DELAY = 0.5   # 请求间隔
        
        # 线程配置
        self.DEFAULT_THREADS = 5
        self.MAX_THREADS = 20
        
        # 输出配置
        self.OUTPUT_DIR = self.config_parser.get('yuancode_config', 'output_dir', fallback="fofa_results")
        self.SOURCE_DIR = self.config_parser.get('yuancode_config', 'source_dir', fallback="sources")
        self.RESULT_FILE = self.config_parser.get('yuancode_config', 'result_file', fallback="sources.txt")
        
        # 关键词配置
        keywords_str = self.config_parser.get('yuancode_config', 'default_keywords', fallback="登录,系统,有限公司,技术支持")
        self.DEFAULT_KEYWORDS = [kw.strip() for kw in keywords_str.split(',')]
    
    def _set_defaults(self):
        """设置默认配置"""
        self.config_parser['yuancode_config'] = {}
        self.config_parser['yuancode_config']['fofa_email'] = ''
        self.config_parser['yuancode_config']['fofa_key'] = 'your_fofa_api_key_here'
        self.config_parser['yuancode_config']['fofa_api_url'] = 'https://fofa.info/api/v1/search/all'
        self.config_parser['yuancode_config']['fofa_max_pages'] = '10'
        self.config_parser['yuancode_config']['dict_file_path'] = 'dicts/common_paths.txt'
        self.config_parser['yuancode_config']['default_keywords'] = '登录,系统,有限公司,技术支持'
        self.config_parser['yuancode_config']['output_dir'] = 'fofa_results'
        self.config_parser['yuancode_config']['source_dir'] = 'sources'
        self.config_parser['yuancode_config']['result_file'] = 'sources.txt'
    
    @property
    def fofa_email(self):
        return self.config_parser.get('yuancode_config', 'fofa_email', fallback=None)
    
    @property
    def fofa_key(self):
        return self.config_parser.get('yuancode_config', 'fofa_key', fallback=None)
    
    @property
    def fofa_api_url(self):
        return self.config_parser.get('yuancode_config', 'fofa_api_url', fallback='https://fofa.info/api/v1/search/all')
    
    @property
    def fofa_max_pages(self):
        return int(self.config_parser.get('yuancode_config', 'fofa_max_pages', fallback=10))
    
    @property
    def dict_file_path(self):
        return self.config_parser.get('yuancode_config', 'dict_file_path', fallback=None)

class FOFAAPI:
    """FOFA API客户端"""
    
    def __init__(self, email: str, key: str, proxy: str = None):
        self.email = email
        self.key = key
        self.proxy = proxy
        self.FOFA_API_URL = CONFIG.fofa_api_url if hasattr(CONFIG, 'fofa_api_url') else "https://fofa.info/api/v1/search/all"
        self.session = self._create_session()
        
    def _create_session(self) -> requests.Session:
        """创建HTTP会话"""
        session = requests.Session()
        
        # 配置重试策略
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # 设置代理
        if self.proxy and self.proxy.startswith("socks5://"):
            if SOCKS_AVAILABLE:
                proxy_parts = self.proxy[9:].split(":")
                if len(proxy_parts) >= 2:
                    host = proxy_parts[0]
                    port = int(proxy_parts[1])
                    socks.set_default_proxy(socks.SOCKS5, host, port)
                    socket.socket = socks.socksocket
            else:
                print(f"{Fore.RED}[!] SOCKS5代理需要PySocks库")
        
        # 设置请求头
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        return session
    
    def search(self, query: str, size: int = 100, page: int = 1, 
               fields: str = "host,port,title,server,country,city") -> List[Dict]:
        """
        执行FOFA搜索
        """
        try:
            # 编码查询语句
            query_base64 = base64.b64encode(query.encode()).decode()
            
            # 构建参数
            params = {
                'email': self.email,
                'key': self.key,
                'qbase64': query_base64,
                'size': size,
                'page': page,
                'fields': fields,
                'full': 'true'
            }
            
            # 发送请求
            response = self.session.get(
                self.FOFA_API_URL,
                params=params,
                timeout=CONFIG.REQUEST_TIMEOUT,
                verify=True
            )
            
            # 检查响应
            if response.status_code != 200:
                print(f"{Fore.RED}[!] FOFA API错误: HTTP {response.status_code}")
                return []
            
            data = response.json()
            
            if data.get('error'):
                print(f"{Fore.RED}[!] FOFA API返回错误: {data.get('errmsg')}")
                return []
            
            # 解析结果
            results = []
            for item in data.get('results', []):
                if len(item) >= 2:
                    host, port = item[0], item[1]
                    results.append({
                        'host': host,
                        'port': port,
                        'title': item[2] if len(item) > 2 else '',
                        'server': item[3] if len(item) > 3 else '',
                        'country': item[4] if len(item) > 4 else '',
                        'city': item[5] if len(item) > 5 else '',
                        'url': self._build_url(host, port)
                    })
            
            return results
            
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[!] FOFA请求失败: {e}")
            return []
        except json.JSONDecodeError:
            print(f"{Fore.RED}[!] FOFA响应解析失败")
            return []
        except Exception as e:
            print(f"{Fore.RED}[!] FOFA搜索异常: {e}")
            return []
    
    def _build_url(self, host: str, port: str) -> str:
        """构建完整URL"""
        try:
            # 处理IPv6地址
            if ':' in host and not host.startswith('['):
                host = f'[{host}]'
            
            # 确定协议和端口
            port_int = int(port) if port.isdigit() else 80
            
            if port_int == 443:
                return f'https://{host}'
            elif port_int == 80:
                return f'http://{host}'
            else:
                # 尝试HTTPS，如果失败再尝试HTTP
                return f'https://{host}:{port}'
                
        except Exception:
            return f'http://{host}:{port}'
    
    def batch_search(self, queries: List[str], max_results: int = 1000) -> List[Dict]:
        """批量搜索"""
        all_results = []
        seen_urls = set()
        
        for query in queries:
            print(f"{Fore.CYAN}[*] 搜索: {query}")
            
            for page in range(1, CONFIG.FOFA_MAX_PAGES + 1):
                if len(all_results) >= max_results:
                    break
                    
                results = self.search(query, CONFIG.FOFA_BATCH_SIZE, page)
                
                for result in results:
                    url = result['url']
                    if url not in seen_urls:
                        seen_urls.add(url)
                        all_results.append(result)
                
                print(f"  {Fore.GREEN}[+] 第{page}页获取 {len(results)} 条结果")
                time.sleep(1)  # 避免请求过快
                
                if len(results) < CONFIG.FOFA_BATCH_SIZE:
                    break
        
        return all_results[:max_results]

class SourceCrawler:
    """源码爬取器"""
    
    def __init__(self, proxy: str = None, threads: int = 5):
        self.proxy = proxy
        self.threads = threads
        self.session = self._create_session()
        self.found_sources = []
        self.lock = threading.Lock()
        
        # 源码文件扩展名
        self.source_extensions = [
            '.php', '.jsp', '.asp', '.aspx', '.do', '.action',
            '.py', '.rb', '.pl', '.cgi', '.sh',
            '.xml', '.json', '.yaml', '.yml',
            '.conf', '.config', '.properties', '.ini',
            '.sql',  '.log'
        ]
        
        # 排除的文件类型
        self.exclude_extensions = [
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg',
            '.mp4', '.mp3', '.avi', '.mov', '.wmv', '.flv',
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
            '.exe', '.dll', '.so', '.dylib', '.bin',
            '.woff', '.woff2', '.ttf', '.otf', '.eot'
        ]
        
        # 常见源码路径
        self.common_source_paths = [
            '/', '/index', '/admin', '/login', '/config',
            '/api', '/test', '/debug', '/phpinfo',
            '/WEB-INF', '/META-INF', '/.git', '/.svn',
            '/.env', '/config.php', '/info.php',
            '/admin.php', '/login.php', '/test.php'
        ]
        
        # 敏感信息模式
        self.sensitive_patterns = {
            'password': r'(?:password|passwd|pwd)\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
            'api_key': r'(?:api[_-]?key|secret[_-]?key)\s*[:=]\s*[\'"]([a-zA-Z0-9]{20,50})[\'"]',
            'jwt': r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'1[3-9]\d{9}|\d{3,4}-\d{7,8}',
            'ip': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'database': r'(?:mysql|postgresql|mongodb|redis)://[^\s"\']+',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'private_key': r'-----BEGIN (?:RSA|DSA|EC) PRIVATE KEY-----',
        }
    
    def _create_session(self) -> requests.Session:
        """创建爬虫会话"""
        session = requests.Session()
        
        # 配置重试
        retry_strategy = Retry(
            total=CONFIG.MAX_RETRIES,
            backoff_factor=CONFIG.RETRY_DELAY,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # 设置代理
        if self.proxy:
            if self.proxy.startswith("socks5://"):
                if SOCKS_AVAILABLE:
                    # SOCKS5代理需要特殊处理
                    pass
                else:
                    print(f"{Fore.YELLOW}[!] SOCKS5代理需要PySocks库")
            else:
                session.proxies = {
                    'http': self.proxy,
                    'https': self.proxy
                }
        
        # 请求头
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        return session
    
    def is_source_file(self, url: str) -> bool:
        """判断是否为源码文件"""
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # 检查排除扩展名
        for ext in self.exclude_extensions:
            if path.endswith(ext):
                return False
        
        # 检查源码扩展名
        for ext in self.source_extensions:
            if path.endswith(ext):
                return True
        
        # 检查常见源码路径
        for source_path in self.common_source_paths:
            if source_path in path:
                return True
        
        # 检查查询参数
        query = parsed.query.lower()
        if any(keyword in query for keyword in ['php', 'jsp', 'asp', 'action', 'do']):
            return True
        
        return False
    
    def crawl_url(self, url: str, depth: int = 2, max_pages: int = 50) -> List[str]:
        """
        爬取单个URL，返回发现的源码URL列表
        """
        try:
            # 规范化URL
            if not url.startswith(('http://', 'https://')):
                url = f'http://{url}'
            
            print(f"{Fore.CYAN}[*] 爬取: {url}")
            
            visited = set()
            to_visit = [(url, 0)]
            found_sources = []
            
            while to_visit and len(visited) < max_pages:
                current_url, current_depth = to_visit.pop(0)
                
                # 检查深度
                if current_depth > depth:
                    continue
                
                # 检查是否已访问
                if current_url in visited:
                    continue
                
                visited.add(current_url)
                
                # 判断是否为源码文件
                if self.is_source_file(current_url):
                    source_content = self.download_source(current_url)
                    if source_content:
                        found_sources.append(current_url)
                        self.save_source(current_url, source_content)
                        print(f"{Fore.GREEN}[+] 发现源码: {current_url}")
                
                # 如果是HTML页面，提取链接
                if current_depth < depth:
                    try:
                        response = self.session.get(
                            current_url,
                            timeout=CONFIG.REQUEST_TIMEOUT,
                            allow_redirects=True,
                            stream=False
                        )
                        
                        if response.status_code == 200:
                            content_type = response.headers.get('Content-Type', '').lower()
                            if 'text/html' in content_type:
                                links = self.extract_links(response.text, current_url)
                                for link in links:
                                    if link not in visited:
                                        to_visit.append((link, current_depth + 1))
                    
                    except Exception:
                        pass
                
                # 延迟
                time.sleep(CONFIG.REQUEST_DELAY)
            
            return found_sources
            
        except Exception as e:
            print(f"{Fore.RED}[!] 爬取失败 {url}: {e}")
            return []
    
    def download_source(self, url: str) -> Optional[str]:
        """下载源码内容"""
        try:
            response = self.session.get(
                url,
                timeout=CONFIG.REQUEST_TIMEOUT,
                allow_redirects=True,
                stream=False
            )
            
            if response.status_code == 200:
                # 检查内容类型
                content_type = response.headers.get('Content-Type', '').lower()
                
                # 如果是文本类型，返回内容
                if any(text_type in content_type for text_type in 
                      ['text/', 'application/json', 'application/xml', 'application/javascript']):
                    return response.text
                else:
                    # 尝试解码为文本
                    try:
                        return response.text
                    except:
                        return None
            
            return None
            
        except Exception as e:
            print(f"{Fore.RED}[!] 下载失败 {url}: {e}")
            return None
    
    def extract_links(self, html: str, base_url: str) -> List[str]:
        """从HTML提取链接"""
        links = set()
        
        # 正则匹配
        patterns = [
            r'href\s*=\s*["\']([^"\']+)["\']',
            r'src\s*=\s*["\']([^"\']+)["\']',
            r'action\s*=\s*["\']([^"\']+)["\']',
            r'url\s*\(\s*["\']?([^"\'\)]+)["\']?\s*\)',
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, html, re.IGNORECASE)
            for match in matches:
                link = match.group(1).strip()
                
                # 跳过空链接和特殊协议
                if not link or link.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                    continue
                
                # 转换为绝对URL
                full_url = urljoin(base_url, link)
                
                # 添加到集合
                links.add(full_url)
        
        return list(links)
    
    def save_source(self, url: str, content: str) -> bool:
        """保存源码到文件"""
        try:
            # 创建目录
            os.makedirs(CONFIG.SOURCE_DIR, exist_ok=True)
            
            # 生成安全文件名
            parsed = urlparse(url)
            domain = parsed.netloc.replace(':', '_')
            path = parsed.path.replace('/', '_')
            
            if not path.strip('_'):
                path = 'index'
            
            # 限制文件名长度
            if len(path) > 100:
                path_hash = hashlib.md5(path.encode()).hexdigest()[:8]
                path = path[:50] + '_' + path_hash
            
            # 添加扩展名
            filename = f"{domain}_{path}"
            for ext in self.source_extensions:
                if url.endswith(ext):
                    filename += ext
                    break
            else:
                filename += '.txt'
            
            # 清理文件名
            filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
            
            # 保存文件
            filepath = os.path.join(CONFIG.SOURCE_DIR, filename)
            with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(f"URL: {url}\n")
                f.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n\n")
                f.write(content)
            
            # 添加到结果列表
            with self.lock:
                self.found_sources.append(url)
            
            return True
            
        except Exception as e:
            print(f"{Fore.RED}[!] 保存失败 {url}: {e}")
            return False
    
    def analyze_sensitive_info(self, url: str, content: str):
        """分析源码中的敏感信息"""
        findings = []
        
        for info_type, pattern in self.sensitive_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                matched_text = match.group(0)
                if len(matched_text) > 100:
                    matched_text = matched_text[:100] + "..."
                
                findings.append({
                    'type': info_type,
                    'content': matched_text,
                    'url': url
                })
        
        if findings:
            print(f"{Fore.YELLOW}[!] 发现敏感信息 ({len(findings)}处)")
            for finding in findings[:3]:  # 显示前3个
                print(f"  {Fore.RED}{finding['type']}: {finding['content']}")
    
    def batch_crawl(self, urls: List[str], depth: int = 2) -> List[str]:
        """批量爬取URL"""
        all_sources = []
        
        print(f"{Fore.CYAN}[*] 开始批量爬取 {len(urls)} 个URL")
        print(f"{Fore.CYAN}[*] 线程数: {self.threads}, 爬取深度: {depth}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            # 提交任务
            future_to_url = {
                executor.submit(self.crawl_url, url, depth): url 
                for url in urls
            }
            
            # 处理结果
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    sources = future.result(timeout=300)
                    all_sources.extend(sources)
                    print(f"{Fore.GREEN}[√] 完成: {url} (发现{len(sources)}个源码)")
                except Exception as e:
                    print(f"{Fore.RED}[!] 失败: {url} - {e}")
        
        return all_sources

class SourceScanner:
    """源码扫描主类"""
    
    def __init__(self, fofa_email: str = None, fofa_key: str = None):
        self.fofa_email = fofa_email or CONFIG.fofa_email
        self.fofa_key = fofa_key or CONFIG.fofa_key
        self.fofa_client = None
        
        # 创建输出目录
        os.makedirs(CONFIG.OUTPUT_DIR, exist_ok=True)
        os.makedirs(CONFIG.SOURCE_DIR, exist_ok=True)
    
    def init_fofa(self, email: str, key: str):
        """初始化FOFA客户端"""
        self.fofa_email = email
        self.fofa_key = key
        self.fofa_client = FOFAAPI(email, key)
    
    def search_from_fofa(self, keywords: List[str] = None, max_results: int = 1000) -> List[str]:
        """从FOFA搜索目标"""
        if not self.fofa_client:
            print(f"{Fore.RED}[!] 未初始化FOFA客户端")
            return []
        
        if not keywords:
            keywords = CONFIG.DEFAULT_KEYWORDS
        
        # 构建查询语句
        queries = []
        for keyword in keywords:
            query = f'title="{keyword}" || body="{keyword}" || header="{keyword}"'
            queries.append(query)
        
        # 执行搜索
        results = self.fofa_client.batch_search(queries, max_results)
        
        # 提取URL
        urls = [result['url'] for result in results]
        
        print(f"{Fore.GREEN}[+] FOFA搜索完成，发现 {len(urls)} 个目标")
        
        # 保存目标列表
        self.save_targets(urls, "fofa_targets.txt")
        
        return urls
    
    def load_urls_from_file(self, filepath: str) -> List[str]:
        """从文件加载URL"""
        urls = []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        urls.append(line)
            
            print(f"{Fore.GREEN}[+] 从文件加载 {len(urls)} 个URL: {filepath}")
            return urls
            
        except Exception as e:
            print(f"{Fore.RED}[!] 加载文件失败 {filepath}: {e}")
            return []
    
    def load_dict_from_file(self, filepath: str) -> List[str]:
        """从字典文件加载路径"""
        paths = []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        paths.append(line)
            
            print(f"{Fore.GREEN}[+] 从字典加载 {len(paths)} 个路径: {filepath}")
            return paths
            
        except Exception as e:
            print(f"{Fore.RED}[!] 加载字典失败 {filepath}: {e}")
            return []
    
    def generate_urls_from_dict(self, base_urls: List[str], dict_paths: List[str]) -> List[str]:
        """使用字典生成完整URL"""
        all_urls = []
        
        for base_url in base_urls:
            # 确保base_url以/结尾
            if not base_url.endswith('/'):
                base_url += '/'
            
            for path in dict_paths:
                # 移除path开头的/
                if path.startswith('/'):
                    path = path[1:]
                
                # 构建完整URL
                full_url = base_url + path
                all_urls.append(full_url)
        
        return all_urls
    
    def save_targets(self, urls: List[str], filename: str = "targets.txt"):
        """保存目标URL到文件"""
        try:
            filepath = os.path.join(CONFIG.OUTPUT_DIR, filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                for url in urls:
                    f.write(url + '\n')
            
            print(f"{Fore.GREEN}[+] 目标保存至: {filepath}")
            return filepath
            
        except Exception as e:
            print(f"{Fore.RED}[!] 保存目标失败: {e}")
            return None
    
    def save_results(self, sources: List[str], filename: str = None):
        """保存结果到文件"""
        if not filename:
            filename = CONFIG.RESULT_FILE
        
        filepath = os.path.join(CONFIG.OUTPUT_DIR, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                for source in sources:
                    f.write(source + '\n')
            
            print(f"{Fore.GREEN}[+] 结果保存至: {filepath}")
            print(f"{Fore.GREEN}[+] 共发现 {len(sources)} 个源码文件")
            return filepath
            
        except Exception as e:
            print(f"{Fore.RED}[!] 保存结果失败: {e}")
            return None
    
    def run(self, args):
        """运行扫描"""
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}       FOFA源码扫描工具 v2.0")
        print(f"{Fore.CYAN}{'='*60}")
        
        urls = []
        
        # 1. 处理URL输入
        if args.url:
            urls.append(args.url)
            print(f"{Fore.GREEN}[+] 单URL模式: {args.url}")
        
        if args.list:
            file_urls = self.load_urls_from_file(args.list)
            urls.extend(file_urls)
        
        # 2. FOFA搜索
        if args.fofa:
            # 使用配置中的默认值作为备用
            email = getattr(self, 'fofa_email', None) or CONFIG.fofa_email
            key = getattr(self, 'fofa_key', None) or CONFIG.fofa_key
            if not self.fofa_client and email and key:
                self.init_fofa(email, key)
            
            fofa_urls = self.search_from_fofa(max_results=args.max_results)
            urls.extend(fofa_urls)
        
        # 3. 应用字典
        dict_file_to_use = args.dict_file
        if not dict_file_to_use and CONFIG.dict_file_path:
            # 如果命令行没有指定字典文件但配置文件中有，则使用配置文件中的
            dict_file_to_use = CONFIG.dict_file_path
        
        if dict_file_to_use:
            dict_paths = self.load_dict_from_file(dict_file_to_use)
            if dict_paths:
                # 去重URL
                base_urls = list(set(urls))
                urls = self.generate_urls_from_dict(base_urls, dict_paths)
                print(f"{Fore.GREEN}[+] 应用字典后生成 {len(urls)} 个URL")
        
        # 去重
        urls = list(set(urls))
        
        if not urls:
            print(f"{Fore.RED}[!] 未发现任何目标URL")
            return
        
        print(f"{Fore.GREEN}[+] 总目标数: {len(urls)}")
        
        # 4. 创建爬虫
        crawler = SourceCrawler(
            proxy=args.proxy,
            threads=args.threads
        )
        
        # 5. 批量爬取
        found_sources = crawler.batch_crawl(urls[:args.max_targets], args.depth)
        
        # 6. 保存结果
        if found_sources:
            self.save_results(found_sources, args.output)
            
            # 显示统计信息
            self.show_statistics(found_sources)
        else:
            print(f"{Fore.YELLOW}[!] 未发现任何源码文件")
    
    def show_statistics(self, sources: List[str]):
        """显示统计信息"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}           扫描统计")
        print(f"{Fore.CYAN}{'='*60}")
        
        # 按扩展名统计
        ext_stats = {}
        domain_stats = {}
        
        for source in sources:
            parsed = urlparse(source)
            
            # 域名统计
            domain = parsed.netloc
            domain_stats[domain] = domain_stats.get(domain, 0) + 1
            
            # 扩展名统计
            path = parsed.path.lower()
            for ext in ['.php', '.jsp', '.asp', '.aspx', '.html', '.js', '.json', '.xml', '.txt']:
                if path.endswith(ext):
                    ext_stats[ext] = ext_stats.get(ext, 0) + 1
                    break
            else:
                ext_stats['other'] = ext_stats.get('other', 0) + 1
        
        print(f"{Fore.GREEN}源码总数: {len(sources)}")
        print(f"\n{Fore.YELLOW}按域名统计 (前10):")
        for domain, count in sorted(domain_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {domain}: {count}")
        
        print(f"\n{Fore.YELLOW}按文件类型统计:")
        for ext, count in sorted(ext_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"  {ext}: {count}")
        
        # 输出结果文件位置
        result_file = os.path.join(CONFIG.OUTPUT_DIR, CONFIG.RESULT_FILE)
        if os.path.exists(result_file):
            print(f"\n{Fore.GREEN}结果文件: {os.path.abspath(result_file)}")
            print(f"{Fore.GREEN}源码目录: {os.path.abspath(CONFIG.SOURCE_DIR)}")

# Initialize global config
CONFIG = Config()

def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='FOFA源码扫描工具 - 通过FOFA搜索并爬取网站源码',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  %(prog)s --fofa --email user@example.com --key API_KEY
  %(prog)s -u http://example.com -t 10
  %(prog)s -l targets.txt -f dict.txt -o results.txt
  %(prog)s --fofa --dict-file common_paths.txt --proxy socks5://127.0.0.1:1080
        '''
    )
    
    # 输入选项
    input_group = parser.add_argument_group('输入选项')
    input_group.add_argument('-u', '--url', help='单个目标URL')
    input_group.add_argument('-l', '--list', help='批量URL文件 (每行一个URL)')
    input_group.add_argument('--fofa', action='store_true', help='使用FOFA搜索')
    
    # FOFA配置
    fofa_group = parser.add_argument_group('FOFA配置')
    fofa_group.add_argument('--email', help='FOFA邮箱')
    fofa_group.add_argument('--key', help='FOFA API Key')
    fofa_group.add_argument('--keywords', nargs='+', default=CONFIG.DEFAULT_KEYWORDS,
                           help=f'搜索关键词 (默认: {CONFIG.DEFAULT_KEYWORDS})')
    
    # 爬取选项
    crawl_group = parser.add_argument_group('爬取选项')
    crawl_group.add_argument('-d', '--dict', dest='dict_file', help='路径字典文件 (兼容性)')
    crawl_group.add_argument('-f', '--dict-file', dest='dict_file', help='路径字典文件')
    crawl_group.add_argument('--depth', type=int, default=2, help='爬取深度 (默认: 2)')
    crawl_group.add_argument('--max-targets', type=int, default=50, help='最大目标数 (默认: 50)')
    crawl_group.add_argument('--max-results', type=int, default=200, help='FOFA最大结果数 (默认: 200)')
    
    # 输出选项
    output_group = parser.add_argument_group('输出选项')
    output_group.add_argument('-o', '--output', default='sources.txt',
                            help='输出文件 (默认: sources.txt)')
    
    # 性能选项
    perf_group = parser.add_argument_group('性能选项')
    perf_group.add_argument('-t', '--threads', type=int, default=CONFIG.DEFAULT_THREADS,
                           help=f'线程数 (默认: {CONFIG.DEFAULT_THREADS})')
    perf_group.add_argument('-p', '--proxy', help='代理服务器 (支持socks5://)')
    perf_group.add_argument('--timeout', type=int, default=CONFIG.REQUEST_TIMEOUT,
                           help=f'请求超时 (默认: {CONFIG.REQUEST_TIMEOUT}秒)')
    
    # 其他选项
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')
    parser.add_argument('--version', action='version', version='FOFA Source Scanner v2.0')
    
    args = parser.parse_args()
    
    # 验证参数
    if not any([args.url, args.list, args.fofa]):
        parser.print_help()
        print(f"\n{Fore.RED}[!] 必须指定目标来源: -u, -l, 或 --fofa")
        sys.exit(1)
    
    if args.fofa and (not args.email or not args.key):
        # 尝试从环境变量或配置文件读取
        if not args.email:
            args.email = os.getenv('FOFA_EMAIL') or CONFIG.fofa_email
        if not args.key:
            args.key = os.getenv('FOFA_KEY') or CONFIG.fofa_key
        
        # 对于某些FOFA接口，可能只需要key不需要email
        if not args.key:
            print(f"{Fore.RED}[!] FOFA模式至少需要API key参数")
            print(f"{Fore.YELLOW}[!] 或设置环境变量: FOFA_KEY")
            print(f"{Fore.YELLOW}[!] 或在 config.ini 中配置 fofa_key")
            sys.exit(1)
    
    if args.threads > CONFIG.MAX_THREADS:
        print(f"{Fore.YELLOW}[!] 线程数超过最大限制 {CONFIG.MAX_THREADS}, 已调整")
        args.threads = CONFIG.MAX_THREADS
    
    # 更新配置
    if args.timeout:
        CONFIG.REQUEST_TIMEOUT = args.timeout
    
    # 运行扫描
    scanner = SourceScanner()
    
    if args.fofa:
        # 初始化扫描器时已经设置了FOFA凭据，但如果提供了命令行参数，则覆盖
        if args.email or args.key:
            email = args.email or scanner.fofa_email
            key = args.key or scanner.fofa_key
            scanner.init_fofa(email, key)
    
    try:
        scanner.run(args)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] 用户中断")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] 程序异常: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()