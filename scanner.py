"""
局域网IP扫描工具 — 后端扫描引擎
双击 启动扫描工具.bat 即可使用，无需直接运行本文件。
"""

import socket
import subprocess
import threading
import re
import time
import queue
import json
from ipaddress import IPv4Network, IPv4Address, ip_address
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, Response, render_template_string, request

app = Flask(__name__)

# ═══════════════════════════════════════════
# OUI 厂商数据库（MAC地址前6位 → 厂商名 + 设备类型）
# ═══════════════════════════════════════════
OUI_DB = {
    # 手机厂商
    "F0:98:9D": "Apple iPhone", "A4:B1:E9": "Apple iPhone", "8C:7B:9D": "Apple iPhone",
    "E0:B5:5F": "Apple iPhone", "3C:BD:3E": "Apple iPhone", "A8:88:08": "Apple iPhone",
    "B0:34:95": "Apple iPhone", "2C:BE:08": "Apple iPhone", "58:1F:AA": "Apple",  # Apple 通用
    "A4:D1:D2": "Apple", "AC:BC:32": "Apple", "A8:86:DD": "Apple",
    "F0:DB:E2": "Apple", "F8:FF:C2": "Apple", "A0:78:17": "Apple",
    "AC:CF:5C": "Apple", "B0:9F:BA": "Apple", "40:30:04": "Apple",
    "88:86:03": "Samsung", "8C:F5:A3": "Samsung", "50:FC:9F": "Samsung",
    "38:01:46": "Samsung", "CC:3D:82": "Samsung", "B8:D7:AF": "Samsung",
    "08:21:EF": "Samsung", "5C:F5:DA": "Samsung", "38:8D:28": "Samsung",
    "48:0E:EC": "Huawei", "70:D5:E7": "Huawei", "A4:4B:D5": "Huawei",
    "8C:F7:10": "Huawei", "A8:5B:F7": "Huawei", "2C:D0:5A": "Huawei",
    "28:6E:D4": "Huawei", "08:6D:41": "Huawei", "54:26:96": "Huawei",
    "F4:60:E2": "Xiaomi", "64:09:80": "Xiaomi", "8C:17:59": "Xiaomi",
    "D8:0D:17": "Xiaomi", "C4:6A:B3": "Xiaomi", "A4:5C:27": "Xiaomi",
    "28:6C:07": "Xiaomi", "18:9E:FC": "Xiaomi", "34:1C:F0": "Xiaomi",
    "B0:68:E6": "OPPO", "8C:64:A2": "OPPO", "24:16:6D": "OPPO",
    "38:A2:8C": "OPPO", "E4:98:D1": "OPPO", "20:13:11": "OPPO",
    "48:F1:7F": "vivo", "C4:48:E7": "vivo", "80:08:6E": "vivo",
    "D8:C4:6A": "OnePlus", "18:8B:0D": "Motorola", "14:B9:68": "Motorola",
    "A4:34:F1": "nubia", "00:1B:B3": "Meizu", "FC:F8:AE": "ZTE",

    # 电脑厂商
    "D0:94:66": "Dell", "B0:83:FE": "Dell", "18:DB:F2": "Dell",
    "A4:BA:DB": "Dell", "54:BF:64": "Dell", "24:B6:FD": "Dell",
    "C8:1F:66": "Dell", "28:F1:0E": "Dell", "B8:AC:6F": "Dell",
    "2C:59:E5": "HP", "38:63:BB": "HP", "64:51:06": "HP",
    "80:C1:6E": "HP", "A0:D3:C1": "HP", "D8:9D:67": "HP",
    "D4:85:64": "HP", "B0:5C:DA": "HP", "98:3B:8F": "HP",
    "F8:B1:56": "Lenovo", "30:CD:A7": "Lenovo", "C8:5B:76": "Lenovo",
    "B0:10:41": "Lenovo", "74:78:A6": "Lenovo", "98:EE:CB": "Lenovo",
    "8C:89:A5": "Lenovo", "2C:FA:A2": "Lenovo", "50:7B:9D": "ASUS",
    "38:D5:47": "ASUS", "04:D9:F5": "ASUS", "1C:B7:2C": "ASUS",
    "E0:CB:4E": "ASUS", "70:85:C2": "ASUS", "A8:5E:45": "ASUS",
    "E8:9C:25": "Acer", "08:ED:B9": "Acer", "EC:08:6B": "Acer",
    "7C:B7:7B": "Acer", "1C:39:47": "Acer", "04:0E:3C": "MSI",
    "D8:D3:85": "MSI", "30:9C:23": "MSI", "44:8A:5B": "MSI",

    # 路由器/网络设备厂商
    "C4:E9:84": "TP-Link", "D8:47:32": "TP-Link", "14:CC:20": "TP-Link",
    "50:C7:BF": "TP-Link", "B0:BE:76": "TP-Link", "34:E8:94": "TP-Link",
    "C8:3A:35": "Tenda", "B0:DF:C1": "Tenda", "00:B0:0C": "Tenda",
    "14:D6:4D": "D-Link", "C8:D3:A3": "D-Link", "28:10:7B": "D-Link",
    "F8:1A:67": "D-Link", "38:A2:8C": "D-Link", "D8:FE:E3": "D-Link",
    "00:1F:33": "Netgear", "E0:46:9A": "Netgear", "2C:B0:5D": "Netgear",
    "B0:39:56": "Netgear", "28:C6:8E": "Netgear", "C4:04:15": "Netgear",
    "D4:21:22": "Cisco", "00:25:45": "Cisco", "58:97:BD": "Cisco",
    "00:3A:99": "Cisco", "70:81:05": "Cisco", "F4:CF:E2": "Cisco",
    "A8:70:5D": "Xiaomi Router", "58:F3:9C": "Xiaomi Router",
    "34:47:06": "ASUS Router", "60:45:BD": "ASUS Router",
    "00:08:22": "MikroTik", "B8:69:F4": "MikroTik",
    "DC:FE:18": "Ubiquiti", "F0:9F:C2": "Ubiquiti",
    "E8:DE:27": "Huawei Router", "44:67:47": "Huawei Router",
    "58:6D:8F": "H3C", "A4:5E:60": "H3C", "98:01:A7": "H3C",

    # 打印机厂商
    "00:1E:0B": "HP Printer", "3C:52:82": "HP Printer", "D8:1C:79": "HP Printer",
    "84:2B:2B": "Canon", "00:1E:8F": "Canon", "C8:6C:87": "Canon",
    "00:26:AB": "Epson", "A4:EE:57": "Epson", "9C:AE:D3": "Epson",
    "00:80:77": "Brother", "00:1B:A9": "Brother", "30:05:5C": "Brother",
    "88:6B:0F": "Xerox", "00:00:AA": "Xerox", "9C:93:4E": "Xerox",

    # 智能设备厂商
    "A0:02:DC": "Amazon Echo", "F0:27:2D": "Amazon Echo", "74:75:48": "Amazon",
    "34:29:12": "Google Nest", "18:B4:30": "Google Nest", "98:84:E3": "Google",
    "68:57:2D": "Ring", "0C:3C:65": "Ring",
    "80:7D:3A": "Shelly", "C8:2B:96": "Sonoff", "BC:DD:C2": "Tuya",

    # 更多国产品牌手机
    "72:54:D2": "Huawei Mobile", "A4:3E:51": "Huawei Mobile",
    "F8:87:F1": "Huawei Mobile", "E0:05:C5": "Huawei Mobile",
    "F4:72:0F": "Redmi", "A4:93:3F": "Redmi", "C8:FD:19": "Redmi",
    "E0:B1:CE": "Redmi", "78:46:5E": "Redmi", "68:DF:DD": "Redmi",
    "08:3F:BC": "Redmi", "5C:87:30": "Redmi",
    "90:78:B2": "OnePlus", "68:AB:1E": "OnePlus",
    "B4:90:CE": "Realme", "48:E1:E9": "Realme",
    "C4:B5:99": "Meizu", "8C:2D:AA": "Meizu",
    "60:83:34": "ZTE", "F8:1E:DF": "ZTE", "18:28:61": "ZTE",
    "64:EE:B5": "TCL", "48:70:1F": "TCL",
    "30:FD:38": "Black Shark", "A8:C3:F7": "Black Shark",
    "84:2B:B6": "Nokia", "38:D2:CA": "Nokia",
    "C0:91:0E": "HTC", "F8:0B:CE": "HTC",
    "4C:49:6C": "Sony", "B8:09:8A": "Sony",

    # 海尔 / 海信 / 长虹 / 康佳等家电
    "D8:E2:3F": "Haier IoT", "24:15:91": "Haier",
    "E8:FD:F8": "Dalen/DAREN", "DC:4E:DE": "Dalen",
    "AC:1F:6B": "Hisense", "C0:D3:91": "Hisense",
    "84:90:FE": "Changhong", "C8:7F:00": "Konka",
    "C8:0F:09": "TCL Smart", "50:1B:32": "TCL Smart",
    "B4:7B:7C": "Skyworth", "F0:2B:CB": "Skyworth",
    "C8:DB:26": "Midea", "B0:F1:EC": "Midea",
    "F4:93:9F": "Gree", "84:26:0C": "Gree",
    "98:F4:2A": "Roku", "C0:2B:FC": "Roku",
    "B8:A7:C6": "Suning", "58:20:D1": "XiaoVV",

    # 更多智能家居/IoT
    "A4:CF:12": "Espressif", "60:01:94": "Espressif",
    "EC:FA:BC": "Espressif", "24:0A:C4": "Espressif",
    "84:F3:EB": "Espressif", "08:3A:8D": "Espressif",
    "BC:FF:4D": "Espressif", "D8:F1:5B": "Espressif",
    "F4:CF:A2": "Espressif", "DC:4F:22": "Espressif",
    "2C:3A:E8": "Espressif", "A0:20:A6": "Espressif",
    "C8:C9:A3": "Espressif", "FC:F5:C4": "Espressif",
    "50:02:91": "Espressif", "08:F9:E0": "Espressif",
    "18:FE:34": "Espressif", "84:CC:A8": "Espressif",
    "B4:E6:2D": "Espressif", "5C:CF:7F": "Espressif",
    "40:F5:20": "Espressif", "30:AE:A4": "Espressif",
    "3C:71:BF": "Espressif", "80:7D:3A": "Espressif",

    # 常见虚拟/其他
    "00:0C:29": "VMware", "00:50:56": "VMware",
    "00:1C:42": "Parallels", "00:15:5D": "Hyper-V",
    "08:00:27": "VirtualBox",
    "00:FF:CA": "Unknown USB", "00:E0:4C": "Realtek",
}

def lookup_oui(mac):
    """根据MAC地址查询厂商信息，识别随机MAC"""
    if not mac:
        return "未知", "其他设备", True
    randomized = is_randomized_mac(mac)
    prefix = mac.upper()[:8]
    if randomized and prefix not in OUI_DB:
        return "随机MAC (隐私地址)", "手机/移动设备", True
    if prefix in OUI_DB:
        return OUI_DB[prefix], "设备", randomized
    if randomized:
        return "随机MAC (隐私地址)", "手机/移动设备", True
    return "未知厂商", "其他设备", randomized


def is_randomized_mac(mac):
    """
    检测 MAC 是否为本地随机地址（隐私保护功能）。
    第一个字节的 bit 1 = 1 表示本地管理地址。
    常见: x2:x?:xx, x6:x?:xx, xA:x?:xx, xE:x?:xx
    """
    if not mac or mac == "-":
        return False
    try:
        first_byte = int(mac.split(":")[0], 16)
        return (first_byte & 0x02) != 0
    except (ValueError, IndexError):
        return False


def infer_device_type(mac, hostname, ip_str, vendor_name):
    """综合MAC厂商、主机名、IP推断设备类型"""
    host_lower = (hostname or "").lower()
    vendor_lower = (vendor_name or "").lower()
    last_octet = int(ip_str.split(".")[-1])

    # 规则1：IP为.1或.254 → 路由器/网关
    if last_octet in (1, 254):
        return "路由器/网关"

    # 规则2：厂商关键字匹配
    router_keywords = ["router", "tplink", "tp-link", "dlink", "d-link", "netgear",
                       "cisco", "tenda", "mikrotik", "ubiquiti", "h3c"]
    for kw in router_keywords:
        if kw in vendor_lower:
            return "路由器/网关"

    printer_keywords = ["printer", "canon", "epson", "brother", "xerox", "laser"]
    for kw in printer_keywords:
        if kw in vendor_lower:
            return "打印机"

    phone_keywords = ["iphone", "samsung", "huawei", "xiaomi", "oppo", "vivo",
                      "oneplus", "motorola", "nubia", "meizu", "zte"]
    for kw in phone_keywords:
        if kw in vendor_lower and "router" not in vendor_lower:
            return "手机"

    pc_keywords = ["dell", "lenovo", "asus", "acer", "hp ", "msi", "thinkpad",
                   "thinkcentre", "ideacentre", "inspiron", "latitude", "precision"]
    for kw in pc_keywords:
        if kw in vendor_lower:
            return "电脑"

    smart_keywords = ["echo", "nest", "ring", "shelly", "sonoff", "tuya",
                      "google", "amazon", "alexa"]
    for kw in smart_keywords:
        if kw in vendor_lower:
            return "智能设备"

    # 规则3：主机名关键字匹配
    if any(kw in host_lower for kw in ["phone", "iphone", "mobile", "android"]):
        return "手机"
    if any(kw in host_lower for kw in ["pc", "desktop", "laptop", "computer",
                                        "notebook", "macbook", "imac"]):
        return "电脑"
    if any(kw in host_lower for kw in ["printer", "print", "mfp"]):
        return "打印机"
    if any(kw in host_lower for kw in ["router", "gateway", "ap", "mesh"]):
        return "路由器/网关"

    # 规则4：Apple但无法确定是iPhone还是Mac
    if vendor_lower == "apple":
        return "电脑/手机"  # 可能是Mac或iPhone

    return "其他设备"


def get_local_network():
    """
    自动检测本机局域网网段。
    通过 ipconfig 获取所有适配器的 IP 和子网掩码，
    优先选择真实局域网网段（192.168.x.x / 10.x.x.x / 172.16-31.x.x），
    排除自动配置地址（169.254.x.x）和回环地址（127.x.x.x）。
    """
    try:
        result = subprocess.run(
            ["ipconfig"], capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        )
        output = result.stdout

        candidates = []  # [(ip, mask), ...]
        ip_match = None
        mask_match = None
        lines = output.split("\n")

        for i, line in enumerate(lines):
            m = re.search(r"IPv4 Address[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)", line)
            if not m:
                m = re.search(r"IP Address[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                ip_match = m.group(1)
                if ip_match.startswith("127."):
                    ip_match = None
                    continue
                for j in range(max(0, i - 2), min(len(lines), i + 4)):
                    sm = re.search(r"Subnet Mask[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)", lines[j])
                    if sm:
                        mask_match = sm.group(1)
                        candidates.append((ip_match, mask_match))
                        break

        if not candidates:
            return _fallback_network()

        # 优先选择真实局域网网段
        # 优先级: 192.168.x.x > 10.x.x.x > 172.16-31.x.x > 其他
        def priority(entry):
            ip_str, _ = entry
            first = int(ip_str.split(".")[0])
            second = int(ip_str.split(".")[1])
            if first == 192 and second == 168:
                return 0
            elif first == 10:
                return 1
            elif first == 172 and 16 <= second <= 31:
                return 2
            elif first == 169 and second == 254:
                return 99  # APIPA，最低优先级
            else:
                return 50

        candidates.sort(key=priority)
        ip_match, mask_match = candidates[0]

        # 通过 IP 和掩码计算网络地址
        ip_parts = [int(x) for x in ip_match.split(".")]
        mask_parts = [int(x) for x in mask_match.split(".")]
        net_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]

        mask_bin = "".join(f"{x:08b}" for x in mask_parts)
        prefix_len = mask_bin.count("1")

        return f"{net_parts[0]}.{net_parts[1]}.{net_parts[2]}.0/{prefix_len}"
    except Exception as e:
        print(f"[WARN] 网段检测失败: {e}")
        return _fallback_network()


def _fallback_network():
    """备用方案：通过路由表推断局域网网段"""
    try:
        local_ip = None
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        except Exception:
            pass
        finally:
            s.close()

        if not local_ip or local_ip.startswith("127."):
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)

        if local_ip and not local_ip.startswith("127."):
            parts = local_ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        pass
    return None


def ping_ip(ip_str, timeout_ms=500):
    """
    使用系统 ping 检测单个 IP 是否在线。
    Windows: ping -n 1 -w timeout ip
    返回 True/False
    """
    try:
        creationflag = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        result = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), ip_str],
            capture_output=True, text=True, timeout=max(2, timeout_ms / 500),
            creationflags=creationflag
        )
        # 检查输出中是否包含 "TTL=" 表示响应
        if "TTL=" in result.stdout.upper() or "TTL=" in result.stdout:
            return True
        # 也检查 "Reply from" (Windows ping 响应格式)
        if "Reply from" in result.stdout or "回复自" in result.stdout:
            return True
        return False
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False


def get_mac_from_arp(ip_str):
    """从系统 ARP 表获取 IP 对应的 MAC 地址"""
    try:
        creationflag = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        result = subprocess.run(
            ["arp", "-a", ip_str],
            capture_output=True, text=True, timeout=5,
            creationflags=creationflag
        )
        output = result.stdout
        # 匹配 MAC 地址格式: xx-xx-xx-xx-xx-xx 或 xx:xx:xx:xx:xx:xx
        m = re.search(r"([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})", output)
        if m:
            mac = m.group(1).replace("-", ":").upper()
            # 过滤掉广播地址
            if mac != "FF:FF:FF:FF:FF:FF":
                return mac
        return None
    except Exception:
        return None


def get_hostname(ip_str):
    """反向 DNS 解析获取主机名"""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_str)
        return hostname
    except socket.herror:
        return None
    except Exception:
        return None


def bulk_arp_lookup():
    """一次性获取整个 ARP 表（比逐个查询快得多）"""
    arp_table = {}
    try:
        creationflag = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True, text=True, timeout=5,
            creationflags=creationflag
        )
        output = result.stdout
        # 解析 arp -a 输出格式
        # 每行格式: 192.168.1.5          xx-xx-xx-xx-xx-xx     动态/静态
        for line in output.split("\n"):
            m = re.search(
                r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})",
                line
            )
            if m:
                ip = m.group(1)
                mac = m.group(2).replace("-", ":").upper()
                if mac != "FF:FF:FF:FF:FF:FF":
                    arp_table[ip] = mac
    except Exception:
        pass
    return arp_table


def scan_network(progress_callback=None, result_callback=None):
    """
    主扫描函数。
    多线程并发 ping 所有 IP，然后查询 ARP 表获取 MAC 地址。

    参数:
        progress_callback(current, total, found) - 进度回调
        result_callback(device_dict) - 每发现一个设备时回调
    """
    network_cidr = get_local_network()
    if not network_cidr:
        return {"error": "无法检测本机网络", "devices": [], "unused": []}

    network = IPv4Network(network_cidr, strict=False)
    local_ip = socket.gethostbyname(socket.gethostname())

    # 生成目标 IP 列表（排除网络地址、广播地址、本机）
    all_hosts = [str(ip) for ip in network.hosts()]
    targets = [ip for ip in all_hosts if ip != local_ip]
    total = len(targets)

    alive_ips = []
    scanned = 0
    found = 0
    lock = threading.Lock()

    # 第一步：多线程并发 ping
    def ping_and_track(ip):
        nonlocal scanned, found
        alive = ping_ip(ip)
        with lock:
            scanned += 1
            if alive:
                found += 1
                alive_ips.append(ip)
            if progress_callback:
                progress_callback(scanned, total, found)
        return ip, alive

    progress_callback(0, total, 0)

    # 50线程并发扫描
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(ping_and_track, ip): ip for ip in targets}
        for future in as_completed(futures):
            pass  # 回调已在 ping_and_track 中调用

    # 第二步：批量获取ARP表
    progress_callback(total, total, found)  # ping完成
    arp_table = bulk_arp_lookup()

    # 从 ARP 表补充 ping 未回复的设备（省电策略导致不响应 ICMP）
    alive_set = set(alive_ips)
    arp_only_ips = []
    for ip_str in targets:
        if ip_str not in alive_set and ip_str in arp_table:
            arp_only_ips.append(ip_str)
            alive_set.add(ip_str)
    if arp_only_ips:
        found += len(arp_only_ips)

    # 第三步：整理设备信息（ping发现的 + ARP补充的）
    devices = []

    def build_device(ip_str, is_arp_only):
        mac = arp_table.get(ip_str) or get_mac_from_arp(ip_str)
        vendor_name = "未知厂商"
        randomized = False
        if mac:
            vendor_name, _, randomized = lookup_oui(mac)
        hostname = get_hostname(ip_str)
        device_type = infer_device_type(mac, hostname, ip_str, vendor_name)
        device = {
            "ip": ip_str,
            "mac": mac or "-",
            "hostname": hostname or "-",
            "device_type": device_type,
            "vendor": vendor_name,
            "randomized_mac": randomized,
            "ping_reply": not is_arp_only,
        }
        devices.append(device)
        if result_callback:
            result_callback(device)

    for ip_str in alive_ips:
        build_device(ip_str, False)
    for ip_str in arp_only_ips:
        build_device(ip_str, True)

    # 第四步：汇总空闲IP（排除所有已发现的 IP）
    unused_set = set(targets) - alive_set
    unused_ranges = _merge_ip_ranges(sorted(unused_set, key=lambda ip: [int(x) for x in ip.split(".")]))

    return {
        "network": network_cidr,
        "local_ip": local_ip,
        "total_scanned": total,
        "alive_count": len(devices),
        "unused_count": len(unused_set),
        "devices": devices,
        "unused": unused_ranges,
    }


def _merge_ip_ranges(sorted_ips):
    """将排序后的IP列表合并为连续区间字符串"""
    if not sorted_ips:
        return []

    ranges = []
    start = sorted_ips[0]
    prev = sorted_ips[0]
    prev_last = int(start.split(".")[-1])

    for ip in sorted_ips[1:]:
        current_last = int(ip.split(".")[-1])
        if current_last == prev_last + 1:
            prev = ip
            prev_last = current_last
        else:
            ranges.append((start, prev))
            start = ip
            prev = ip
            prev_last = current_last

    ranges.append((start, prev))

    result = []
    for s, e in ranges:
        if s == e:
            result.append(s)
        else:
            s_last = int(s.split(".")[-1])
            e_last = int(e.split(".")[-1])
            count = e_last - s_last + 1
            prefix = ".".join(s.split(".")[:3])
            result.append(f"{prefix}.{s_last}-{e_last} ({count}个)")

    return result


# ═══════════════════════════════════════════
# Flask Web 服务
# ═══════════════════════════════════════════

# 存储最新扫描结果（用于页面刷新后查看）
last_result = {"devices": [], "unused": [], "network": "", "local_ip": "", "total_scanned": 0, "alive_count": 0, "unused_count": 0}
scan_lock = threading.Lock()


@app.route("/")
def index():
    """返回前端页面"""
    with open("templates/index.html", "r", encoding="utf-8") as f:
        return render_template_string(f.read())


@app.route("/api/scan")
def api_scan():
    """
    启动扫描，通过 SSE (Server-Sent Events) 实时推送进度和结果。
    """
    def generate():
        global last_result
        result_queue = queue.Queue()

        def progress_cb(current, total, found):
            data = json.dumps({"type": "progress", "current": current, "total": total, "found": found}, ensure_ascii=False)
            result_queue.put(data)

        def result_cb(device):
            data = json.dumps({"type": "result", "device": device}, ensure_ascii=False)
            result_queue.put(data)

        # 在后台线程运行扫描
        scan_output = {}

        def run_scan():
            try:
                output = scan_network(progress_cb, result_cb)
                scan_output.update(output)
            except Exception as e:
                scan_output["error"] = str(e)
            finally:
                result_queue.put("__DONE__")

        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()

        # SSE 流式输出
        while True:
            try:
                msg = result_queue.get(timeout=30)
            except queue.Empty:
                # 30秒无新消息，发送心跳
                yield "event: heartbeat\ndata: ping\n\n"
                continue

            if msg == "__DONE__":
                break

            yield f"event: update\ndata: {msg}\n\n"

        # 发送完成事件
        with scan_lock:
            last_result = scan_output
        complete_data = json.dumps({
            "type": "complete",
            "devices": scan_output.get("devices", []),
            "unused": scan_output.get("unused", []),
            "network": scan_output.get("network", ""),
            "local_ip": scan_output.get("local_ip", ""),
            "total_scanned": scan_output.get("total_scanned", 0),
            "alive_count": scan_output.get("alive_count", 0),
            "unused_count": scan_output.get("unused_count", 0),
        }, ensure_ascii=False)
        yield f"event: complete\ndata: {complete_data}\n\n"

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        }
    )


@app.route("/api/last-result")
def api_last_result():
    """返回最近一次扫描结果（用于页面刷新后恢复）"""
    return {
        "has_result": bool(last_result.get("devices")),
        **last_result
    }


if __name__ == "__main__":
    print("=" * 50)
    print("  局域网IP扫描工具 v1.0")
    print("  浏览器访问: http://127.0.0.1:5000")
    print("  按 Ctrl+C 退出")
    print("=" * 50)
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
