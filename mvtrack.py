#!/usr/bin/env python3
from utils.banners import print_random_banner
import os
import subprocess
import yara
import re
import requests
import time
import sys
import hashlib
import argparse
import json
import logging
import base64
import tempfile
import psutil
from scapy.all import sniff, IP, TCP
from dotenv import load_dotenv
from colorama import Fore, Style, init
import magic
from shlex import split
from urllib.parse import unquote
from binascii import unhexlify

# Load configuration and initialize
load_dotenv()
init(autoreset=True)

# Configuration constants
DEFAULT_CONFIG = {
    "max_file_size": 32 * 1024 * 1024,  # 32MB
    "scan_timeout": 3600,  # 1 hour
    "allowed_nmap_flags": ["-sV", "--script", "vuln", "-O", "-T4"],
    "api_rate_limit_delay": 1,  # seconds
    "network_scan_timeout": 30,  # seconds for network sniffing
    "max_encoding_layers": 5  # Maximum encoding layers to check
}

# Environment variables
VT_API_KEY = os.getenv("VT_API_KEY")
NVD_API_KEY = os.getenv("NVD_API_KEY")

def setup_logging():
    """Configure secure logging"""
    logging.basicConfig(
        filename="mvtrack.log",
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filemode='a'
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)

def colored_print(text, status="info"):
    """Print colored output with status indicators"""
    color_map = {
        "ok": Fore.GREEN,
        "warn": Fore.YELLOW,
        "err": Fore.RED,
        "blue": Fore.CYAN,
        "info": Style.RESET_ALL
    }
    print(color_map.get(status, "") + text + Style.RESET_ALL)

def verify_file_type(file_path, expected_types=None):
    """Verify file type using magic numbers with broader malware support"""
    if expected_types is None:
        expected_types = [
            'text/', 
            'application/x-executable', 
            'application/x-sharedlib',
            'application/x-dosexec',  # Windows PE files
            'application/x-mach-binary',  # Mac OS X
            'application/x-msdownload',  # Windows DLL
            'application/octet-stream',  # Generic binary
            'application/x-elf'  # Linux ELF
        ]
    
    try:
        file_type = magic.from_file(file_path, mime=True)
        raw_type = magic.from_file(file_path)
        
        # Additional checks for binary files
        if file_type == 'application/octet-stream':
            if any(x in raw_type.lower() for x in ['executable', 'binary', 'pe32', 'elf', 'mach-o']):
                return True
        
        return any(file_type.startswith(t) for t in expected_types)
    except Exception:
        # Fallback to extension check if magic fails
        ext = os.path.splitext(file_path)[1].lower()
        return ext in ['.exe', '.dll', '.bin', '.so', '.dylib', '']

def detect_encoded_payloads(content):
    """Detect multi-layer encoded payloads (URL, Base64, Hex, ROT13, etc.)"""
    detections = []
    encoding_checks = [
        ('URL', lambda x: unquote(x)),
        ('Base64', lambda x: base64.b64decode(x).decode('utf-8', errors='ignore')),
        ('Hex', lambda x: bytes.fromhex(x).decode('utf-8', errors='ignore')),
        ('ROT13', lambda x: x.translate(str.maketrans(
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')))
    ]
    
    for layers in range(1, DEFAULT_CONFIG['max_encoding_layers'] + 1):
        decoded = content
        encoding_types = []
        
        try:
            for _ in range(layers):
                for enc_name, dec_func in encoding_checks:
                    try:
                        temp_decoded = dec_func(decoded)
                        if temp_decoded != decoded:
                            encoding_types.append(enc_name)
                            decoded = temp_decoded
                            break
                    except:
                        continue
            
            malicious_patterns = [
                r"(?:bash|sh|cmd\.exe|powershell)\s+-[cC]\s+",
                r"(?:system|exec|eval|passthru|shell_exec)\(",
                r"/dev/(?:tcp|udp)/",
                r"Runtime\.getRuntime\(\)\.exec\(",
                r"Process\.Start\(",
                r"new\s+ActiveXObject\(",
                r"<\?php\s+.*system\s*\(",
                r"document\.write\(unescape\("
            ]
            
            for pattern in malicious_patterns:
                if re.search(pattern, decoded, re.IGNORECASE):
                    detections.append({
                        'encoding_layers': layers,
                        'encoding_types': encoding_types,
                        'decoded_sample': decoded[:100] + ("..." if len(decoded) > 100 else ""),
                        'pattern_found': pattern
                    })
                    break
                    
        except Exception:
            continue
            
    return detections

def analyze_uploaded_file(file_content, filename, verbose=False):
    """Analyze uploaded file content directly"""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(file_content)
        temp_path = temp_file.name
    
    try:
        report = analyze_file(temp_path, verbose=verbose)
        report['original_filename'] = filename
        return report
    finally:
        os.unlink(temp_path)

def scan_process_memory(pid=None, verbose=False):
    """Scan running process memory for malware patterns"""
    results = []
    try:
        if pid is None:
            processes = [p for p in psutil.process_iter(['pid', 'name'])]
        else:
            processes = [psutil.Process(pid)]
            
        for proc in processes:
            try:
                memory_maps = proc.memory_maps()
                for mmap in memory_maps:
                    if os.path.exists(mmap.path):
                        yara_matches = run_yara_scan(mmap.path, verbose)
                        if yara_matches:
                            results.append({
                                'pid': proc.pid,
                                'name': proc.name(),
                                'path': mmap.path,
                                'matches': yara_matches
                            })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
    except Exception as e:
        if verbose:
            colored_print(f"[ERROR] Memory scan failed: {e}", "err")
    return results

def analyze_network_traffic(timeout=30, verbose=False):
    """Analyze network traffic for suspicious patterns"""
    suspicious_packets = []
    
    def packet_callback(packet):
        if packet.haslayer(TCP):
            payload = str(packet[TCP].payload)
            patterns = [
                r"/bin/sh",
                r"bash -i",
                r"nc -e",
                r"powershell -enc",
                r"eval\(base64_decode\(",
                r"\\x[0-9a-f]{2}",  # Hex encoded
                r"%[0-9a-f]{2}",    # URL encoded
            ]
            for pattern in patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    suspicious_packets.append({
                        'src': packet[IP].src,
                        'dst': packet[IP].dst,
                        'sport': packet[TCP].sport,
                        'dport': packet[TCP].dport,
                        'pattern': pattern,
                        'payload_sample': payload[:100]
                    })
                    break

    try:
        sniff(timeout=timeout, prn=packet_callback, store=0)
    except Exception as e:
        if verbose:
            colored_print(f"[ERROR] Network capture failed: {e}", "err")
    return suspicious_packets

def detect_malware_encoders(file_path, verbose=False):
    """Detects specific malware encoders and obfuscation techniques"""
    encoder_patterns = {
        'x86/shikata_ga_nai': [
            rb"\xD9\xEE\xD9\x74\x24\xF4\x5B\x81\x73\x13",
            rb"\x31\xC9\x83\xE9",
            rb"\x0F\xBE\x04\x0C\x30\x04\x08"
        ],
        'x86/call4_dword_xor': [
            rb"\xE8....\x81\x34\x24....",
            rb"\xE8....\x81\x34\x24....\x5B"
        ],
        'x86/jmp_call_additive': [
            rb"\xEB.\x90\x90",
            rb"\xE8....\xC3",
            rb"\xEB.\xE8....\xC3"
        ],
        'x86/nonalpha': [
            rb"[^a-zA-Z0-9]{50,}",
            rb"\x21-\x2F[\x3A-\x40]{10,}"
        ],
        'x64/xor': [
            rb"\x48\x31\xC9\x48\x81\xE9",
            rb"\x48\x31\xD2\x48\x81\xEA"
        ],
        'x86/countdown': [
            rb"\xB9....\x83\xE9\x01",
            rb"\x31\xC9\x49"
        ],
        'cmd/powershell_base64': [
            rb"powershell\s+-[eE][nN]?[cC]?\s+[A-Za-z0-9+/=]{100,}",
            rb"powershell\s+-[cC][mM][dD]\s+.+[A-Za-z0-9+/=]{100,}"
        ],
        'cmd/echo': [
            rb"echo\s+[0-9A-F]{2}[ \t]+[0-9A-F]{2}",
            rb"echo\s+[0-9A-F]{2}>>[a-zA-Z]\.\w{2,3}"
        ]
    }
    
    detection_results = {}
    
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            
            for encoder_name, patterns in encoder_patterns.items():
                matches = []
                for pattern in patterns:
                    if re.search(pattern, content):
                        matches.append(pattern)
                
                if matches:
                    detection_results[encoder_name] = {
                        'patterns_found': [m.hex() for m in matches],
                        'confidence': min(100, len(matches) * 20)
                    }
                    
                    if verbose:
                        colored_print(f"[DEBUG] Detected {encoder_name} - Patterns: {matches}", "warn")
    
    except Exception as e:
        if verbose:
            colored_print(f"[ERROR] Failed to scan for encoders: {e}", "err")
        return {"error": str(e)}
    
    return detection_results

def detect_webshells(file_path, verbose=False):
    """Specialized detection for obfuscated webshells"""
    webshell_patterns = [
        (r"%3C%3Fphp.*%24_(?:GET|POST|REQUEST|COOKIE).*%3F%3E", "URL-encoded PHP webshell"),
        (r"<\?php\s+.*(?:system|exec|passthru|shell_exec)\s*\(.*\$_(?:GET|POST|REQUEST|COOKIE)", "PHP command execution webshell"),
        (r"<form[^>]*method\s*=[^>]*>.*<input[^>]*name\s*=[^>]*>.*<\?php.*system\s*\(", "Form-based PHP webshell"),
        (r"@\?>\s*<form.*<\?php.*if\(isset\(\$_(?:GET|POST)\).*system\(", "Obfuscated form webshell"),
        (r"%253Chtml%253E.*%253Cform.*%253C%253Fphp.*system%2528%2524_GET.*%253C%252Fhtml%253E", "Multi-layer URL-encoded webshell"),
        (r"eval\(base64_decode\(", "Base64 encoded PHP webshell"),
        (r"document\.write\(unescape\(", "JavaScript encoded webshell")
    ]
    
    detections = []
    try:
        with open(file_path, 'rb') as f:
            content = f.read().decode('utf-8', errors='ignore')
            
            # Check for URL-encoded content
            url_decoded = content
            for _ in range(DEFAULT_CONFIG['max_encoding_layers']):
                try:
                    url_decoded = unquote(url_decoded)
                except:
                    break
                
                for pattern, description in webshell_patterns:
                    if re.search(pattern, url_decoded, re.IGNORECASE | re.DOTALL):
                        detections.append({
                            'type': 'webshell',
                            'variant': description,
                            'confidence': 90,
                            'match': pattern[:50] + "..." if len(pattern) > 50 else pattern
                        })
                        if verbose:
                            colored_print(f"[WEBSHELL] Detected {description}: {pattern[:100]}...", "err")
            
            # Check original content
            for pattern, description in webshell_patterns:
                if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                    detections.append({
                        'type': 'webshell',
                        'variant': description,
                        'confidence': 80,
                        'match': pattern[:50] + "..." if len(pattern) > 50 else pattern
                    })
                    if verbose:
                        colored_print(f"[WEBSHELL] Detected {description}: {pattern[:100]}...", "err")
                        
    except Exception as e:
        if verbose:
            colored_print(f"[ERROR] Webshell detection failed: {e}", "err")
        return []
    
    return detections

def run_yara_scan(target_file, verbose=False):
    """Run YARA rules against target file with dynamic rule loading"""
    try:
        yara_path = 'utils/yara_rules/'
        if not os.path.exists(yara_path):
            return ["[!] YARA rules directory not found."]
        
        if not verify_file_type(target_file):
            return ["[!] File type not supported for YARA scanning"]
            
        # Compile all YARA rules in the directory
        yara_files = [os.path.join(yara_path, f) for f in os.listdir(yara_path) 
                     if f.endswith('.yar') or f.endswith('.yara')]
        rules = yara.compile(filepaths={f: f for f in yara_files})
        
        matches = rules.match(target_file)
        if verbose:
            colored_print(f"[DEBUG] YARA matched: {matches}", "warn")
        return [str(match) for match in matches]
    except yara.YaraError as e:
        return [f"YARA Error: {e}"]

def detect_windows_reverse_shell(content):
    """Specialized detection for Windows C/C++ reverse shells"""
    indicators = [
        ("WSAStartup", r"WSAStartup\(|%57%53%41%53%74%61%72%74%75%70"),
        ("WSASocket", r"WSASocket\(|%57%53%41%53%6f%63%6b%65%74"),
        ("WSAConnect", r"WSAConnect\(|%57%53%41%43%6f%6e%6e%65%63%74"),
        ("CreateProcess", r"CreateProcess\(|%43%72%65%61%74%65%50%72%6f%63%65%73%73"),
        ("cmd.exe", r"cmd\.exe|%63%6d%64%2e%65%78%65"),
        ("Standard handle redirection", r"hStdInput.*hStdOutput|%68%53%74%64%49%6e%70%75%74")
    ]
    
    detections = []
    for name, pattern in indicators:
        if re.search(pattern, content, re.IGNORECASE):
            detections.append(name)
    return detections

def detect_reverse_shell_code(file_path, verbose=False):
    """Comprehensive reverse shell detection covering all specified languages and shell types"""
    shell_types = {
        'sh': [
            r'\bsh\s+-i\b',
            r'\bsh\s+-c\b',
            r'/bin/sh\s+-i',
            r'/bin/sh\s+-c',
            r'==\s*\$0',
            r'\b(sh|/bin/sh)\s.*?\d>&\d'
        ],
        'bash': [
            r'\bbash\s+-i\b',
            r'\bbash\s+-c\b',
            r'/bin/bash\s+-i',
            r'/bin/bash\s+-c',
            r'\b(bash|/bin/bash)\s.*?\d>&\d',
            r'exec\s+\d<>/dev/(tcp|udp)/'
        ],
        'cmd': [
            r'\bcmd\.exe\s+/c\b',
            r'cmd\s+/c',
            r'start\s+cmd\s+/c'
        ],
        'powershell': [
            r'powershell\s+-nop\s+-c',
            r'powershell\s+-enc\b',
            r'pwsh\s+-nop\s+-c',
            r'pwsh\s+-enc\b'
        ],
        'ash': [r'\bash\s+-c\b', r'/bin/ash\s+-c'],
        'bsh': [r'\bbsh\s+-c\b', r'/bin/bsh\s+-c'],
        'csh': [r'\bcsh\s+-c\b', r'/bin/csh\s+-c'],
        'ksh': [r'\bksh\s+-c\b', r'/bin/ksh\s+-c'],
        'zsh': [r'\bzsh\s+-c\b', r'/bin/zsh\s+-c'],
        'pdksh': [r'\bpdksh\s+-c\b', r'/bin/pdksh\s+-c'],
        'tcsh': [r'\btcsh\s+-c\b', r'/bin/tcsh\s+-c'],
        'mksh': [r'\bmksh\s+-c\b', r'/bin/mksh\s+-c'],
        'dash': [r'\bdash\s+-c\b', r'/bin/dash\s+-c'],
        
        'socket_redirection': [
            r'\d<>/dev/(tcp|udp)/',
            r'exec\s+\d<>/dev/(tcp|udp)/',
            r'\d>\s*&/dev/(tcp|udp)/'
        ],
        'pipe_redirection': [
            r'\|\s*(sh|bash|cmd)',
            r'\|\s*/bin/(sh|bash)',
            r'\d>\s*&\d',
            r'\d<\s*&\d'
        ],
        'nc_variants': [
            r'nc\s+-e\s+/bin/(sh|bash)',
            r'ncat\s+-e\s+/bin/(sh|bash)',
            r'netcat\s+-e\s+/bin/(sh|bash)',
            r'nc\s+-c\s+/bin/(sh|bash)'
        ]
    }

    language_patterns = {
        'python': [
            r'python(?:3)?\s+-c\s+.*socket\.connect\(.*?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            r'import\s+socket,subprocess,os\s*;',
            r'pty\.spawn\(["\']/bin/(bash|sh)'
        ],
        'perl': [
            r'perl\s+-e\s+\$p=fork',
            r'perl\s+-MIO\s+-e\s+\$p=fork',
            r'perl\s+-MSocket\s+-e'
        ],
        'php': [
            r'php\s+-r\s+\$sock=fsockopen',
            r'<\?php\s+system\("nc\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d+"\)',
            r'<\?php\s+exec\("/bin/sh\s+-i"\)'
        ],
        'ruby': [
            r'ruby\s+-rsocket\s+-e',
            r'exec\s+"/bin/sh\s+-i"'
        ],
        'java': [
            r'Runtime\.getRuntime\(\)\.exec\(["\']/bin/(bash|sh)',
            r'new\s+ProcessBuilder\(["\']/bin/(bash|sh)'
        ],
        'csharp': [
            r'TcpClient\(.*?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*?\d+',
            r'Process\.Start\(["\']cmd\.exe["\']'
        ],
        'go': [
            r'exec\.Command\(["\']/bin/(bash|sh)',
            r'net\.Dial\(["\']tcp["\'],'
        ],
        'lua': [
            r'os\.execute\(["\']/bin/(bash|sh)',
            r'require\("socket"\)\.connect\('
        ],
        'awk': [
            r'awk\s+\'BEGIN\s*\{s\s*=\s*"/inet/tcp/0/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+"'
        ],
        'dart': [
            r'Process\.run\(["\']/bin/(bash|sh)',
            r'Socket\.connect\('
        ],
        'rust': [
            r'std::process::Command::new\(["\']/bin/(bash|sh)',
            r'TcpStream::connect\('
        ],
        'elixir': [
            r'Port\.open\(["\']/bin/(bash|sh)',
            r':gen_tcp\.connect\('
        ],
        'groovy': [
            r'["\']/bin/(bash|sh)["\']\.execute\(\)',
            r'new\s+Socket\(["\']\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}["\'],\s*\d+\)'
        ],
        'haskell': [
            r'callCommand\s+["\']/bin/(bash|sh)',
            r'connectTo\s+"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"\s+PortNumber'
        ],
        'nodejs': [
            r'require\(["\']child_process["\']\)\.exec\(["\']/bin/(bash|sh)',
            r'require\(["\']net["\']\)\.createConnection\('
        ],
        'crystal': [
            r'Process\.run\(["\']/bin/(bash|sh)',
            r'TCPSocket\.new\('
        ],
        'vlang': [
            r'os\.exec\(["\']/bin/(bash|sh)',
            r'net\.tcp_connect\('
        ],
        'openssl': [
            r'openssl\s+s_client\s+-connect\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+',
            r'openssl\s+req\s+-newkey\s+-x509\s+-nodes\s+-subj'
        ],
        'telnet': [
            r'telnet\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d+\s*\|',
            r'telnet\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d+\s*>\s*&'
        ],
        'webshells': [
            r'<\?php\s+@?eval\(\$_(GET|POST|REQUEST|COOKIE)',
            r'p0wny@shell',
            r'assert\(\$_(GET|POST|REQUEST|COOKIE)'
        ],
        'windows': [
            r'WSAStartup\(MAKEWORD',
            r'WSASocket\(AF_INET',
            r'CreateProcessA?\(',
            r'cmd\.exe\s+/c\s+',
            r'powershell\s+-EncodedCommand'
        ]
    }

    ip_port_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[:/]\d{1,5}\b'

    encoding_patterns = {
        'double_url': r'%25[0-9a-fA-F]{2}',
        'single_url': r'%[0-9a-fA-F]{2}',
        'base64': r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
        'hex': r'(?:\\x[0-9a-fA-F]{2}|[0-9a-fA-F]{2}\s*)+',
        'unicode': r'\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}',
        'rot13': r'[a-zA-Z]{13,}'
    }

    binary_patterns = [
        b"\x2f\x62\x69\x6e\x2f\x73\x68",
        b"\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68",
        b"\x65\x78\x65\x63\x28\x27\x2f\x62\x69\x6e\x2f\x73\x68\x27",
        b"\x73\x6f\x63\x6b\x65\x74\x2e\x63\x6f\x6e\x6e\x65\x63\x74",
        b"\x57\x53\x41\x53\x74\x61\x72\x74\x75\x70"
    ]

    matches = []
    try:
        if not os.access(file_path, os.R_OK):
            return ["[!] No read permissions for file"]
            
        with open(file_path, 'rb') as f:
            content = f.read()
            text_content = content.decode('utf-8', errors='ignore')
            
            decoded_content = text_content
            encoding_types = []
            
            for _ in range(DEFAULT_CONFIG['max_encoding_layers']):
                layer_decoded = False
                
                if re.search(encoding_patterns['double_url'], decoded_content):
                    temp_decoded = unquote(unquote(decoded_content))
                    if temp_decoded != decoded_content:
                        encoding_types.append('double_url')
                        decoded_content = temp_decoded
                        layer_decoded = True
                
                if not layer_decoded and re.search(encoding_patterns['single_url'], decoded_content):
                    temp_decoded = unquote(decoded_content)
                    if temp_decoded != decoded_content:
                        encoding_types.append('single_url')
                        decoded_content = temp_decoded
                        layer_decoded = True
                
                if not layer_decoded:
                    b64_matches = re.findall(encoding_patterns['base64'], decoded_content)
                    for match in b64_matches:
                        try:
                            temp_decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                            if temp_decoded and len(temp_decoded) > 3:
                                encoding_types.append('base64')
                                decoded_content = decoded_content.replace(match, temp_decoded)
                                layer_decoded = True
                                break
                        except:
                            continue
                
                if not layer_decoded and re.search(encoding_patterns['hex'], decoded_content):
                    hex_matches = re.findall(encoding_patterns['hex'], decoded_content)
                    for match in hex_matches:
                        try:
                            clean_hex = re.sub(r'\\x|\s', '', match)
                            temp_decoded = unhexlify(clean_hex).decode('utf-8', errors='ignore')
                            if temp_decoded and len(temp_decoded) > 3:
                                encoding_types.append('hex')
                                decoded_content = decoded_content.replace(match, temp_decoded)
                                layer_decoded = True
                                break
                        except:
                            continue
                
                if not layer_decoded:
                    break
            
            if encoding_types:
                matches.append(f"ENCODING:{'->'.join(encoding_types)}")
            
            for shell, patterns in shell_types.items():
                for pattern in patterns:
                    if re.search(pattern, decoded_content, re.IGNORECASE | re.DOTALL):
                        matches.append(f"SHELL:{shell.upper()}:{pattern[:50]}...")
            
            for lang, patterns in language_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, decoded_content, re.IGNORECASE | re.DOTALL):
                        matches.append(f"LANG:{lang.upper()}:{pattern[:50]}...")
            
            if re.search(ip_port_pattern, decoded_content):
                matches.append("NETWORK:IP:PORT detected")
            
            for pattern in binary_patterns:
                if content.find(pattern) != -1:
                    matches.append(f"BINARY:{pattern.hex()[:20]}...")
            
            if verbose and matches:
                colored_print(f"[DEBUG] Shell matches: {matches}", "warn")
                
    except Exception as e:
        matches.append(f"[ERROR reading file: {e}]")
    
    return matches

def get_file_sha256(file_path):
    """Calculate SHA256 hash of file"""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)
    return sha256.hexdigest()

def get_vt_result_by_hash(file_hash):
    """Check VirusTotal for existing scan results"""
    time.sleep(DEFAULT_CONFIG['api_rate_limit_delay'])
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {'x-apikey': VT_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()["data"]["attributes"]["last_analysis_stats"]
        return {"error": f"Hash lookup failed: {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Hash lookup error: {e}"}

def scan_file_virustotal(file_path, verbose=False, force_upload=False):
    """Scan file with VirusTotal"""
    if os.path.getsize(file_path) > DEFAULT_CONFIG['max_file_size']:
        return {"error": f"File too large for VirusTotal (limit: {DEFAULT_CONFIG['max_file_size']//(1024*1024)}MB)"}

    file_hash = get_file_sha256(file_path)

    if not force_upload:
        result = get_vt_result_by_hash(file_hash)
        if isinstance(result, dict) and "error" not in result:
            if verbose:
                colored_print(f"[DEBUG] VT cache result used for hash: {file_hash}", "warn")
            return result

    url = 'https://www.virustotal.com/api/v3/files'
    headers = {'x-apikey': VT_API_KEY}
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            response = requests.post(url, headers=headers, files=files, timeout=30)

        if response.status_code in [200, 202]:
            analysis_id = response.json()['data']['id']
            return get_vt_analysis_result(analysis_id, verbose=verbose)
        return {"error": f"Upload failed. Status: {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"error": f"VirusTotal Upload Error: {e}"}

def get_vt_analysis_result(analysis_id, max_attempts=5, verbose=False):
    """Check VirusTotal analysis result"""
    url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
    headers = {'x-apikey': VT_API_KEY}
    for attempt in range(1, max_attempts + 1):
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                result = response.json()
                status = result['data']['attributes']['status']
                if status == 'completed':
                    return result['data']['attributes']['stats']
                if verbose:
                    colored_print(f"[DEBUG] VT Status: {status} (attempt {attempt}/{max_attempts})", "warn")
            time.sleep(15)
        except requests.exceptions.RequestException:
            time.sleep(15)
    return {"error": f"Scan not completed after {max_attempts} attempts"}

def get_cve_info(keyword):
    """Search for CVEs in NVD database with proper API key usage"""
    if not re.match(r'^[\w\s-]+$', keyword):
        return [{"error": "Invalid search keyword"}]
    
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    params = {
        'keywordSearch': keyword, 
        'resultsPerPage': 5,
        'startIndex': 0
    }
    
    headers = {}
    if NVD_API_KEY:
        headers = {'apiKey': NVD_API_KEY}
        colored_print("[*] Using NVD API key for authenticated requests", "blue")
    else:
        colored_print("[!] Warning: No NVD API key - using unauthenticated requests (limited to 5 requests/min)", "warn")
        time.sleep(6)
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 403:
            return [{"error": "NVD API rate limit exceeded - try again later or add API key"}]
        if response.status_code == 429:
            retry_after = int(response.headers.get('Retry-After', 30))
            colored_print(f"[!] Rate limited - waiting {retry_after} seconds", "warn")
            time.sleep(retry_after)
            return get_cve_info(keyword)
            
        response.raise_for_status()
        
        cves = response.json().get("vulnerabilities", [])
        return [{
            'id': cve['cve']['id'],
            'score': cve['cve'].get('metrics', {}),
            'desc': cve['cve']['descriptions'][0]['value'],
            'published': cve['cve'].get('published', ''),
            'severity': cve['cve'].get('impact', {}).get('baseSeverity', 'N/A')
        } for cve in cves]
        
    except requests.exceptions.RequestException as e:
        return [{"error": f"Request failed: {str(e)}"}]

def analyze_file(file_path, verbose=False, force_upload=False):
    """Enhanced file analysis with Windows reverse shell detection"""
    if not os.path.exists(file_path):
        colored_print("[!] File not found", "err")
        return None
        
    if not force_upload and not verify_file_type(file_path):
        colored_print("[!] File type not recognized, use --force to analyze anyway", "warn")
        return None

    report = {
        "file": file_path,
        "file_type": magic.from_file(file_path),
        "sha256": get_file_sha256(file_path),
        "windows_reverse_shell": False,
        "windows_reverse_shell_indicators": [],
        "malware_signatures": [],
        "reverse_shell_patterns": [],
        "webshell_detection": [],
        "encoder_detection": [],
        "virustotal_result": {}
    }

    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            text_content = content.decode('utf-8', errors='ignore')
            decoded_content = unquote(text_content)
            
            windows_indicators = [
                ("WSAStartup", r"WSAStartup\(|%57%53%41%53%74%61%72%74%75%70"),
                ("WSASocket", r"WSASocket\(|%57%53%41%53%6f%63%6b%65%74"),
                ("WSAConnect", r"WSAConnect\(|%57%53%41%43%6f%6e%6e%65%63%74"),
                ("CreateProcess", r"CreateProcess\(|%43%72%65%61%74%65%50%72%6f%63%65%73%73"),
                ("cmd.exe", r"cmd\.exe|%63%6d%64%2e%65%78%65"),
                ("Standard handle redirection", r"hStdInput.*hStdOutput|%68%53%74%64%49%6e%70%75%74")
            ]
            
            detected_indicators = []
            for name, pattern in windows_indicators:
                if (re.search(pattern, text_content, re.IGNORECASE) or 
                    re.search(pattern, decoded_content, re.IGNORECASE)):
                    detected_indicators.append(name)
            
            if detected_indicators:
                report["windows_reverse_shell"] = True
                report["windows_reverse_shell_indicators"] = detected_indicators
                if verbose:
                    colored_print(f"[!] Detected Windows reverse shell indicators: {detected_indicators}", "err")

            report.update({
                "malware_signatures": run_yara_scan(file_path, verbose),
                "reverse_shell_patterns": detect_reverse_shell_code(file_path, verbose),
                "webshell_detection": detect_webshells(file_path, verbose),
                "encoder_detection": detect_malware_encoders(file_path, verbose),
                "virustotal_result": scan_file_virustotal(file_path, verbose, force_upload)
            })

    except Exception as e:
        colored_print(f"[!] Error analyzing file: {e}", "err")
        return None

    vt_result = report['virustotal_result']
    vt_malicious = vt_result.get('malicious', 'N/A') if isinstance(vt_result, dict) else 'N/A'
    
    summary = [
        f"YARA: {len(report['malware_signatures'])} matches",
        f"Reverse Shells: {len(report['reverse_shell_patterns'])}",
        f"Windows Shell: {'Yes' if report['windows_reverse_shell'] else 'No'}",
        f"Webshells: {len(report['webshell_detection'])}",
        f"Encoders: {len(report['encoder_detection'])}",
        f"VT Malicious: {vt_malicious}"
    ]
    
    colored_print("\n[SUMMARY] " + " | ".join(summary), "blue")
    
    if report["windows_reverse_shell"] and verbose:
        colored_print("\n[!] Windows Reverse Shell Indicators Found:", "err")
        for indicator in report["windows_reverse_shell_indicators"]:
            colored_print(f"  - {indicator}", "warn")
    
    return report

def save_report_to_file(report, filename="scan_report.json"):
    """Save scan report to file"""
    try:
        with open(filename, "w") as f:
            json.dump(report, f, indent=2)
        colored_print(f"[✔] Report saved to {filename}", "ok")
    except Exception as e:
        colored_print(f"[!] Failed to save report: {e}", "err")

def extract_and_fetch_cves(scan_output, verbose=False):
    """Extract CVEs from scan output and fetch details"""
    cve_ids = set(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", scan_output))
    if not cve_ids:
        colored_print("[-] No CVEs found in scan output.", "warn")
        return

    colored_print("\n[+] Fetching CVE details from NVD...", "blue")
    for cve_id in cve_ids:
        cve_data = get_cve_info(cve_id)
        for cve in cve_data:
            if 'error' in cve:
                colored_print(f"[-] {cve['error']}", "err")
            else:
                colored_print(f"\nCVE ID: {cve['id']}", "ok")
                colored_print(f"Published: {cve.get('published', 'Unknown')}", "blue")
                colored_print(f"Severity: {cve.get('severity', 'N/A')}", 
                            "err" if cve.get('severity', '').lower() == 'high' else 
                            "warn" if cve.get('severity', '').lower() == 'medium' else 
                            "ok")
                colored_print(f"Description: {cve['desc']}", "blue")
                
                if 'score' in cve and cve['score']:
                    metrics = cve['score']
                    if 'cvssMetricV31' in metrics:
                        cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                        colored_print(f"CVSS v3.1 Score: {cvss_data['baseScore']} ({cvss_data['baseSeverity']})", "blue")

def analyze_host(ip, verbose=False):
    colored_print(f"[1/3] Target IP: {ip}", "blue")
    custom_flags = input("Enter custom Nmap scan options (default: -sV --script vuln): ").strip()
    if not custom_flags:
        custom_flags = "-sV --script vuln"
    command = ["nmap", "--stats-every", "2s"] + custom_flags.split() + [ip]
    colored_print(f"[2/3] Running Nmap with: {' '.join(command)}", "blue")
    scan_output = []
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            line = line.strip()
            scan_output.append(line)
            match = re.search(r"(\d+)% done", line)
            if match:
                percent = int(match.group(1))
                bar = "█" * (percent // 4) + '-' * (25 - percent // 4)
                sys.stdout.write(f"\r    [Nmap Progress] |{bar}| {percent}%")
                sys.stdout.flush()
            print(line)
        process.wait()
        print("\n[✔] Nmap scan complete.")
        colored_print("[3/3] Vulnerability Scan Report:\n", "blue")
        print("\n".join(scan_output))
        extract_and_fetch_cves("\n".join(scan_output), verbose=verbose)
    except Exception as e:
        colored_print(f"[!] Error during scan: {e}", "err")

                        
def cli_interface():
    """Handle command line arguments"""
    parser = argparse.ArgumentParser(description="🔍 MVTRACK - Malware & Vulnerability Tracker")
    parser.add_argument("-f", "--file", help="File to analyze for malware/reverse shells")
    parser.add_argument("-u", "--upload", help="Analyze uploaded file content (base64 encoded)")
    parser.add_argument("-i", "--ip", help="IP to scan with Nmap")
    parser.add_argument("-k", "--keyword", help="Keyword to search CVEs from NVD")
    parser.add_argument("-o", "--output", help="Output report file (JSON)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--force", "--force-upload", dest="force_upload", action="store_true", 
                       help="Force upload to VirusTotal even if cached result exists")
    parser.add_argument("--memory", action="store_true", help="Scan process memory")
    parser.add_argument("--network", action="store_true", help="Analyze network traffic")
    parser.add_argument("--pid", type=int, help="Specific process ID to scan")
    return parser.parse_args()

if __name__ == '__main__':
    setup_logging()
    args = cli_interface()

    # Validate API keys
    if not VT_API_KEY or len(VT_API_KEY) != 64:
        colored_print("[!] Invalid or missing VirusTotal API key", "err")
        sys.exit(1)

    print_random_banner()
    colored_print("\n[+] MVTRACK Analyzer Started", "blue")
    logging.info(f"Scan started with args: {vars(args)}")

    if args.file:
        if os.path.exists(args.file):
            colored_print(f"[1/3] Scanning file: {args.file}", "blue")
            file_report = analyze_file(args.file, verbose=args.verbose, force_upload=args.force_upload)

            if file_report and args.output:
                save_report_to_file(file_report, args.output)
        else:
            colored_print("[-] File not found.", "err")

    if args.upload:
        try:
            file_content = base64.b64decode(args.upload)
            colored_print("[1/3] Scanning uploaded file", "blue")
            upload_report = analyze_uploaded_file(file_content, "uploaded_file", verbose=args.verbose)
            
            if upload_report and args.output:
                save_report_to_file(upload_report, args.output)
        except Exception as e:
            colored_print(f"[!] Failed to process uploaded file: {e}", "err")

    if args.ip:
        analyze_host(args.ip, verbose=args.verbose)

    if args.keyword:
        cve_list = get_cve_info(args.keyword)
        colored_print("\n[+] CVE Results from NVD:", "blue")
        for cve in cve_list:
            if 'error' in cve:
                colored_print(f"[-] {cve['error']}", "err")
            else:
                colored_print(f"ID: {cve['id']}", "ok")
                colored_print(f"Description: {cve['desc']}", "blue")

    if args.memory:
        colored_print("\n[+] Scanning process memory", "blue")
        memory_results = scan_process_memory(pid=args.pid, verbose=args.verbose)
        if memory_results:
            colored_print("[+] Memory scan results:", "ok")
            for result in memory_results:
                colored_print(f"PID: {result['pid']} - {result['name']}", "blue")
                for match in result['matches']:
                    colored_print(f"  {match}", "warn")
        else:
            colored_print("[-] No suspicious memory patterns found", "ok")

    if args.network:
        colored_print("\n[+] Analyzing network traffic", "blue")
        network_results = analyze_network_traffic(
            timeout=DEFAULT_CONFIG['network_scan_timeout'],
            verbose=args.verbose
        )
        if network_results:
            colored_print("[+] Suspicious network traffic detected:", "err")
            for packet in network_results:
                colored_print(f"{packet['src']}:{packet['sport']} -> {packet['dst']}:{packet['dport']}", "blue")
                colored_print(f"Pattern: {packet['pattern']}", "warn")
                colored_print(f"Sample: {packet['payload_sample']}", "info")
        else:
            colored_print("[-] No suspicious network traffic found", "ok")

    logging.info("Scan completed")
