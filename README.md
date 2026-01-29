# FOFA源码扫描工具 (yuancode.py)

一款功能强大的源码泄露扫描工具，支持FOFA搜索和自定义字典扫描，可自动识别并下载网站源码压缩包。

## 功能特性

- **FOFA集成搜索**：通过FOFA API搜索潜在的目标网站
- **自定义字典扫描**：支持导入自定义路径字典进行扫描
- **多模式支持**：支持单URL、批量URL列表、FOFA搜索等多种输入方式
- **并发扫描**：支持多线程并发扫描，提高效率
- **代理支持**：支持SOCKS5等代理配置
- **配置化管理**：所有配置项可通过config.ini统一管理

## 安装依赖

```bash
pip install requests retrying colorama
```

## 配置文件

首先在 `config.ini` 文件中配置相关参数：

```ini
[yuancode_config]
# FOFA配置
fofa_email = your_fofa_email@example.com
fofa_key = your_fofa_api_key_here
fofa_api_url = https://fofa.info/api/v1/search/all
fofa_max_pages = 10

# 字典配置
dict_file_path = dicts/common_paths.txt

# 默认搜索关键词
default_keywords = 登录,系统,有限公司,技术支持

# 输出配置
output_dir = fofa_results
source_dir = sources
result_file = sources.txt
```

## 使用方法

### 基本语法

```bash
python yuancode.py [选项]
```

### 参数说明

#### 输入选项
- `-u, --url URL`：指定单个目标URL
- `-l, --list FILE`：指定包含多个URL的文件（每行一个URL）
- `--fofa`：启用FOFA搜索模式

#### FOFA配置
- `--email EMAIL`：FOFA邮箱（可选，优先使用config.ini配置）
- `--key KEY`：FOFA API密钥（可选，优先使用config.ini配置）
- `--keywords KEYWORDS`：自定义搜索关键词

#### 爬取选项
- `-d, --dict FILE`：路径字典文件（兼容性选项）
- `-f, --dict-file FILE`：路径字典文件
- `--depth DEPTH`：爬取深度（默认：2）
- `--max-targets NUM`：最大目标数（默认：50）
- `--max-results NUM`：FOFA最大结果数（默认：200）

#### 输出选项
- `-o, --output FILE`：输出文件（默认：sources.txt）

#### 性能选项
- `-t, --threads NUM`：线程数（默认：5）
- `-p, --proxy PROXY`：代理服务器（支持socks5://）
- `--timeout SEC`：请求超时时间（默认：15秒）

### 使用示例

#### 1. FOFA搜索 + 字典扫描（推荐）
```bash
# 使用配置文件中的FOFA凭证进行搜索，并使用指定字典扫描
python yuancode.py --fofa -f dicts/common_paths.txt -o results.txt

# 使用配置文件中的FOFA凭证和默认字典
python yuancode.py --fofa --max-results 100 -t 10
```

#### 2. 单URL扫描
```bash
# 扫描单个URL
python yuancode.py -u https://example.com -f dicts/common_paths.txt -t 5

# 使用自定义输出文件
python yuancode.py -u https://example.com -f dicts/common_paths.txt -o custom_output.txt
```

#### 3. 批量URL扫描
```bash
# 批量扫描URL列表
python yuancode.py -l urls.txt -f dicts/common_paths.txt -t 10
```

#### 4. 高级用法
```bash
# 使用代理扫描
python yuancode.py --fofa -f dicts/common_paths.txt -p socks5://127.0.0.1:1080

# 自定义搜索关键词
python yuancode.py --fofa --keywords "后台管理" "管理系统" -f dicts/common_paths.txt
```

## 字典文件格式

字典文件应包含要扫描的路径，每行一个：

```
/.git/config
/.svn/entries
/WEB-INF/web.xml
/backup.zip
/config.php
/admin
/admin.php
/login
/login.php
```

## 输出结果

- **结果文件**：扫描结果保存在 `fofa_results/sources.txt` 中
- **源码文件**：发现的源码文件保存在 `sources/` 目录下
- **统计信息**：显示扫描进度和结果统计

## 注意事项

1. **FOFA API限制**：注意FOFA API调用频率限制，避免被封禁
2. **网络环境**：国内访问FOFA可能需要代理
3. **扫描速度**：合理设置线程数，避免对目标服务器造成过大压力
4. **法律合规**：仅用于授权测试，请遵守相关法律法规

## 常见问题

Q: 如何获取FOFA API密钥？
A: 访问 https://fofa.info/ 注册账户并获取API密钥

Q: 扫描结果为空怎么办？
A: 检查网络连接、FOFA凭证、字典内容是否合适

Q: 如何提高扫描效率？
A: 合理设置线程数，使用高质量的字典文件