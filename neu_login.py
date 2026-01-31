"""
东北大学校园网自动登录 - Python版本
基于Scriptable脚本逻辑改写，支持深澜(srun)认证
"""

import re
import json
import time
import hashlib
import hmac
import requests
from urllib.parse import urlencode, quote


class NEULogin:
    """东北大学校园网登录类"""
    
    # 基础配置
    BASE_URL = "https://pass.neu.edu.cn"
    LOGIN_POINT = f"{BASE_URL}/tpass/login"
    # 深澜认证相关URL
    SRUN_PORTAL = "http://ipgw.neu.edu.cn"
    SRUN_API = f"{SRUN_PORTAL}/cgi-bin/srun_portal"
    SRUN_GET_CHALLENGE = f"{SRUN_PORTAL}/cgi-bin/get_challenge"
    SRUN_RAD_USER_INFO = f"{SRUN_PORTAL}/cgi-bin/rad_user_info"
    # SSO认证URL (注意是v1路径)
    SRUN_SSO_URL = f"{SRUN_PORTAL}/v1/srun_portal_sso"
    AC_ID = "16"  # 校园网ac_id
    N = "200"
    TYPE = "1"
    ENC = "srun_bx1"
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(self._default_headers())
        self.session.verify = False  # 允许不安全请求
        self.session.timeout = 30
        self.token = ""
        self.ip = ""
    
    @staticmethod
    def _default_headers():
        """默认请求头"""
        return {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
    
    def _parse_field(self, html: str, name: str) -> str | None:
        """解析HTML中的隐藏字段值"""
        patterns = [
            rf'name="{name}"\s+value="([^"]+)"',
            rf"name='{name}'\s+value='([^']+)'"
        ]
        for pattern in patterns:
            match = re.search(pattern, html)
            if match:
                return match.group(1)
        return None
    
    def _extract_lt_execution(self, html: str) -> tuple[str, str]:
        """解析lt和execution参数"""
        lt = self._parse_field(html, "lt")
        execution = self._parse_field(html, "execution")
        
        if not lt or not execution:
            raise Exception(f"无法获取登录参数 - lt:{bool(lt)}, execution:{bool(execution)}")
        
        return lt, execution
    
    def _extract_ticket_from_url(self, url: str) -> str | None:
        """从URL中提取ticket"""
        match = re.search(r'ticket=([^&]+)', url)
        return match.group(1) if match else None
    
    def _ensure_not_error_page(self, html: str):
        """检查是否为错误页面"""
        if "404" in html or "403" in html:
            raise Exception("服务器返回错误页面")
    
    # =============== 深澜认证加密算法 ===============
    
    def _get_xencode(self, msg, key):
        """XEncode加密"""
        if msg == "":
            return ""
        
        pwd = []
        for i in range(len(msg)):
            pwd.append(ord(msg[i]))
        
        if len(key) < 4:
            key = key + [0] * (4 - len(key))
        
        n = len(pwd) - 1
        z = pwd[n]
        c = 0x86014019 | 0x183639A0
        q = 6 + 52 // (n + 1)
        d = 0
        
        while q > 0:
            d = (d + 0x9E3779B9) & 0xFFFFFFFF
            e = (d >> 2) & 3
            for p in range(n):
                y = pwd[p + 1]
                m = (z >> 5) ^ (y << 2)
                m += ((y >> 3) ^ (z << 4)) ^ (d ^ y)
                m += key[(p & 3) ^ e] ^ z
                pwd[p] = (pwd[p] + m) & 0xFFFFFFFF
                z = pwd[p]
            
            y = pwd[0]
            m = (z >> 5) ^ (y << 2)
            m += ((y >> 3) ^ (z << 4)) ^ (d ^ y)
            m += key[(n & 3) ^ e] ^ z
            pwd[n] = (pwd[n] + m) & 0xFFFFFFFF
            z = pwd[n]
            q -= 1
        
        return self._encode(pwd, False)
    
    def _encode(self, msg, flag):
        """编码"""
        if flag:
            s = []
            for i in msg:
                s.append(ord(i))
            return s
        
        l = len(msg)
        ll = (l - 1) << 2
        
        if msg[l - 1] == 0:
            return ""
        
        m = (msg[l - 1])
        if m < ll - 3 or m > ll:
            return ""
        ll = m
        
        s = ""
        for i in range(l):
            s += chr(msg[i] & 0xff)
            s += chr((msg[i] >> 8) & 0xff)
            s += chr((msg[i] >> 16) & 0xff)
            s += chr((msg[i] >> 24) & 0xff)
        
        return s[:ll]
    
    def _s(self, msg, flag):
        """编码转换"""
        if flag:
            s = []
            for i in range(0, len(msg), 4):
                val = 0
                for j in range(4):
                    if i + j < len(msg):
                        val |= ord(msg[i + j]) << (8 * j)
                s.append(val)
            return s
        else:
            s = ""
            for w in msg:
                s += chr(w & 0xff)
                s += chr((w >> 8) & 0xff)
                s += chr((w >> 16) & 0xff)
                s += chr((w >> 24) & 0xff)
            return s
    
    def _get_base64(self, msg):
        """Base64编码"""
        import base64
        return base64.b64encode(msg.encode('latin-1')).decode()
    
    def _get_md5(self, password, token):
        """MD5加密"""
        return hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()
    
    def _get_sha1(self, value):
        """SHA1加密"""
        return hashlib.sha1(value.encode()).hexdigest()
    
    def _get_info(self, username, password, ip):
        """生成info参数"""
        info = {
            "username": username,
            "password": password,
            "ip": ip,
            "acid": self.AC_ID,
            "enc_ver": self.ENC
        }
        return "{SRBX1}" + self._get_base64(self._get_xencode(json.dumps(info, separators=(',', ':')), self._s(self.token, True)))
    
    def _get_chksum(self, username, hmd5, ip, info):
        """生成校验和"""
        chkstr = self.token + username
        chkstr += self.token + hmd5
        chkstr += self.token + self.AC_ID
        chkstr += self.token + ip
        chkstr += self.token + self.N
        chkstr += self.token + self.TYPE
        chkstr += self.token + info
        return self._get_sha1(chkstr)
    
    def login(self, username: str, password: str) -> dict:
        """
        执行登录操作 - CAS统一身份认证 -> IPGW SSO
        
        Args:
            username: 用户名（学号）
            password: 密码
            
        Returns:
            包含登录结果的字典
        """
        try:
            if not username or not password:
                raise Exception("用户名或密码不能为空")
            
            print("开始登录流程...")
            
            # ========== 第一步：访问校园网页面，获取SSO登录入口 ==========
            print("\n===== 步骤1: 获取SSO登录入口 =====")
            
            # 访问校园网首页
            portal_resp = self.session.get(self.SRUN_PORTAL, allow_redirects=True)
            print(f"校园网页面状态: {portal_resp.status_code}")
            
            # 检查是否已经在线
            if 'success' in portal_resp.text and '网络已连接' in portal_resp.text:
                print("✅ 已经在线！")
                return {"success": True, "message": "校园网已连接（之前已登录）", "data": {}}
            
            # ========== 第二步：构建CAS登录URL（模拟点击"连接网络"按钮） ==========
            print("\n===== 步骤2: CAS统一身份认证 =====")
            
            # CAS登录URL - service指向校园网SSO回调
            # 这是"连接网络"按钮跳转的URL
            cas_service_url = "http://ipgw.neu.edu.cn/srun_portal_sso?ac_id=1"
            cas_login_url = f"{self.LOGIN_POINT}?service={quote(cas_service_url, safe='')}"
            
            print(f"CAS登录URL: {cas_login_url}")
            
            # 获取CAS登录页面
            cas_resp = self.session.get(cas_login_url, allow_redirects=True)
            print(f"CAS页面状态: {cas_resp.status_code}")
            print(f"CAS当前URL: {cas_resp.url}")
            
            # 检查是否已经有CAS会话（直接跳转到了校园网）
            if 'ipgw.neu.edu.cn' in cas_resp.url:
                print("✅ 已有CAS会话，直接跳转到校园网")
                # 检查是否登录成功
                if 'success' in cas_resp.text or '网络已连接' in cas_resp.text:
                    print("✅ 登录成功！")
                    return {"success": True, "message": "校园网登录成功", "data": {}}
                
                # 检查URL中是否有ticket，如果有则直接进行SSO认证
                if 'ticket=' in cas_resp.url:
                    ticket = self._extract_ticket_from_url(cas_resp.url)
                    print(f"✅ 从重定向URL获取到ticket: {ticket}")
                    
                    # 访问v1 SSO接口
                    sso_url = f"{self.SRUN_SSO_URL}?ac_id=1&ticket={ticket}"
                    print(f"SSO URL: {sso_url}")
                    
                    sso_resp = self.session.get(sso_url, allow_redirects=True)
                    print(f"SSO响应状态: {sso_resp.status_code}")
                    
                    # 检查SSO认证结果
                    if 'success' in sso_resp.text or '网络已连接' in sso_resp.text:
                        print("✅ SSO认证成功！")
                        return {"success": True, "message": "校园网登录成功", "data": {}}
                    
                    # 使用rad_user_info检查在线状态
                    import time as t
                    t.sleep(0.5)
                    status = self.get_status()
                    if status.get("online"):
                        print("✅ 确认登录成功！")
                        return {"success": True, "message": "校园网登录成功", "data": status.get("data", {})}
                    
                    # 如果SSO认证后仍未在线，继续尝试常规登录流程
                    print("⚠️ SSO认证后未检测到在线状态，尝试重新获取CAS登录页面...")
                    
                    # 清除可能的过期cookie，重新获取登录页面
                    self.session.cookies.clear()
                    cas_resp = self.session.get(cas_login_url, allow_redirects=True)
                    print(f"重新获取CAS页面状态: {cas_resp.status_code}")
                    print(f"CAS当前URL: {cas_resp.url}")
                    
                    # 如果仍然直接跳转，说明CAS会话有效但ticket可能已过期
                    if 'ipgw.neu.edu.cn' in cas_resp.url and 'ticket=' in cas_resp.url:
                        # 尝试使用新的ticket
                        new_ticket = self._extract_ticket_from_url(cas_resp.url)
                        print(f"✅ 获取新ticket: {new_ticket}")
                        sso_url = f"{self.SRUN_SSO_URL}?ac_id=1&ticket={new_ticket}"
                        sso_resp = self.session.get(sso_url, allow_redirects=True)
                        
                        t.sleep(0.5)
                        status = self.get_status()
                        if status.get("online"):
                            print("✅ 使用新ticket登录成功！")
                            return {"success": True, "message": "校园网登录成功", "data": status.get("data", {})}
            
            # 需要进行CAS登录
            cas_page = cas_resp.text
            self._ensure_not_error_page(cas_page)
            
            # 检查页面是否包含登录表单（lt和execution字段）
            lt = self._parse_field(cas_page, "lt")
            execution = self._parse_field(cas_page, "execution")
            
            if not lt or not execution:
                # 如果页面不是CAS登录页面，可能是其他情况
                print(f"⚠️ 当前页面不是CAS登录页面，URL: {cas_resp.url}")
                print(f"页面内容预览: {cas_page[:500]}")
                raise Exception("无法获取CAS登录表单，请检查网络或重试")
            
            print(f"✅ lt: {lt[:40]}...")
            print(f"✅ execution: {execution}")
            
            # ========== 第三步：提交CAS登录表单 ==========
            print("\n===== 步骤3: 提交CAS登录 =====")
            
            payload = {
                "rsa": username + password + lt,
                "ul": str(len(username)),
                "pl": str(len(password)),
                "lt": lt,
                "execution": execution,
                "_eventId": "submit"
            }
            
            headers = {
                **self._default_headers(),
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": cas_login_url,
                "Origin": self.BASE_URL
            }
            
            # 提交登录，允许重定向
            login_resp = self.session.post(cas_login_url, data=payload, headers=headers, allow_redirects=True)
            
            print(f"登录响应状态: {login_resp.status_code}")
            print(f"登录后URL: {login_resp.url}")
            
            # 检查是否登录成功
            if 'success' in login_resp.text or '网络已连接' in login_resp.text:
                print("✅ 登录成功！")
                return {"success": True, "message": "校园网登录成功", "data": {"url": login_resp.url}}
            
            # 检查是否有错误信息
            if '密码' in login_resp.text and '错误' in login_resp.text:
                raise Exception("用户名或密码错误")
            if 'error' in login_resp.text.lower():
                print(f"页面内容: {login_resp.text[:500]}")
                
            # ========== 第四步：如果还没成功，尝试访问SSO URL ==========
            print("\n===== 步骤4: 尝试SSO认证 =====")
            
            # 检查URL中是否有ticket
            if 'ticket=' in login_resp.url:
                ticket = self._extract_ticket_from_url(login_resp.url)
                print(f"获取到ticket: {ticket}")
                
                # 访问v1 SSO接口
                sso_url = f"{self.SRUN_SSO_URL}?ac_id=1&ticket={ticket}"
                print(f"SSO URL: {sso_url}")
                
                sso_resp = self.session.get(sso_url, allow_redirects=True)
                print(f"SSO响应状态: {sso_resp.status_code}")
                
                # 再次检查页面
                if 'success' in sso_resp.text or '网络已连接' in sso_resp.text:
                    print("✅ SSO认证成功！")
                    return {"success": True, "message": "校园网登录成功", "data": {}}
            
            # ========== 第五步：最后检查在线状态 ==========
            print("\n===== 步骤5: 检查在线状态 =====")
            
            # 等待一下
            import time as t
            t.sleep(1)
            
            # 再次访问校园网首页检查
            check_resp = self.session.get(self.SRUN_PORTAL, allow_redirects=True)
            if 'success' in check_resp.text or '网络已连接' in check_resp.text:
                print("✅ 确认登录成功！")
                return {"success": True, "message": "校园网登录成功", "data": {}}
            
            # 使用rad_user_info检查
            status = self.get_status()
            if status.get("online"):
                return {"success": True, "message": "校园网登录成功", "data": status.get("data", {})}
            
            # 登录失败
            raise Exception("登录流程完成但未检测到在线状态，请检查账号密码或网络")
            
        except Exception as e:
            print(f"❌ 登录失败: {str(e)}")
            return {"success": False, "message": f"登录失败: {str(e)}"}
    
    def logout(self) -> dict:
        """
        执行下线操作 - 使用深澜认证
        
        Returns:
            包含下线结果的字典
        """
        try:
            print("开始下线流程...")
            
            # 先获取当前用户信息
            rad_resp = self.session.get(self.SRUN_RAD_USER_INFO, params={"callback": "jsonp"})
            json_match = re.search(r'\((\{.*\})\)', rad_resp.text)
            
            username = ""
            ip = ""
            
            if json_match:
                try:
                    user_info = json.loads(json_match.group(1))
                    username = user_info.get("user_name", "")
                    ip = user_info.get("online_ip", "")
                    print(f"当前用户: {username}, IP: {ip}")
                except:
                    pass
            
            if not ip:
                # 尝试获取IP
                init_resp = self.session.get(self.SRUN_PORTAL)
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', init_resp.text)
                if ip_match:
                    ip = ip_match.group(1)
            
            # 发送下线请求
            callback = f"jsonp_{int(time.time() * 1000)}"
            logout_params = {
                "callback": callback,
                "action": "logout",
                "username": username,
                "ip": ip,
                "ac_id": self.AC_ID,
                "_": int(time.time() * 1000)
            }
            
            logout_resp = self.session.get(self.SRUN_API, params=logout_params)
            logout_text = logout_resp.text
            
            print(f"下线响应: {logout_text}")
            
            # 解析响应
            json_match = re.search(r'\((\{.*\})\)', logout_text)
            if json_match:
                result = json.loads(json_match.group(1))
                if result.get("error") == "ok":
                    return {"success": True, "message": "校园网下线成功", "data": result}
                else:
                    error_msg = result.get("error_msg", result.get("error", "未知错误"))
                    return {"success": False, "message": f"下线失败: {error_msg}"}
            
            return {"success": True, "message": "下线请求已发送", "data": {"response": logout_text}}
                
        except Exception as e:
            print(f"❌ 下线失败: {str(e)}")
            return {"success": False, "message": f"下线失败: {str(e)}"}
    
    def get_status(self) -> dict:
        """
        获取当前网络状态
        
        Returns:
            包含网络状态的字典
        """
        try:
            # 检查深澜认证状态
            rad_resp = self.session.get(self.SRUN_RAD_USER_INFO, params={"callback": "jsonp"}, timeout=5)
            print(f"状态检查响应: {rad_resp.text[:500]}")
            
            json_match = re.search(r'\((\{.*\})\)', rad_resp.text)
            
            if json_match:
                try:
                    user_info = json.loads(json_match.group(1))
                    print(f"用户信息: {user_info}")
                    username = user_info.get("user_name", "")
                    online_ip = user_info.get("online_ip", "")
                    
                    if username and online_ip:
                        return {
                            "success": True, 
                            "online": True, 
                            "message": f"已登录 - 用户: {username}, IP: {online_ip}",
                            "data": user_info
                        }
                except Exception as e:
                    print(f"解析用户信息失败: {e}")
            
            return {"success": True, "online": False, "message": "未登录校园网"}
                
        except Exception as e:
            return {"success": True, "online": False, "message": f"网络状态未知: {str(e)}"}


# 禁用不安全请求警告
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


if __name__ == "__main__":
    # 测试登录
    login = NEULogin()
    
    # 测试用例
    username = input("请输入学号: ")
    password = input("请输入密码: ")
    
    result = login.login(username, password)
    print(result)
