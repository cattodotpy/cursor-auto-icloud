import os
import json
import sys

os.environ["PYTHONVERBOSE"] = "0"
os.environ["PYINSTALLER_VERBOSE"] = "0"

from enum import Enum
from typing import Optional

from src.core.exit_cursor import ExitCursor
import src.core.go_cursor_help as go_cursor_help
import src.auth.patch_cursor_get_machine_id as patch_cursor_get_machine_id
from src.auth.reset_machine import MachineIDResetter
from src.icloud.generate_email import generate_icloud_email

import time
import random
from src.auth.cursor_auth_manager import CursorAuthManager
import os
from src.utils.logger import logging
from src.utils.browser_utils import BrowserManager
from src.utils.get_email_code import EmailVerificationHandler
from src.utils.config import Config
from DrissionPage.items import MixTab, ChromiumElement, SessionElement

# 定义 EMOJI 字典
EMOJI = {"ERROR": "❌", "WARNING": "⚠️", "INFO": "ℹ️"}


class VerificationStatus(Enum):
    """验证状态枚举"""

    PASSWORD_PAGE = "@name=password"
    CAPTCHA_PAGE = "@data-index=0"
    ACCOUNT_SETTINGS = "Account Settings"


class TurnstileError(Exception):
    """Turnstile 验证相关异常"""

    pass


class CursorRegistrationHandler:
    """Handles the Cursor registration process including Turnstile verification and account signup"""

    def __init__(self, tab: MixTab):
        """Initialize the registration handler"""

        self.tab = tab

    def save_screenshot(self, stage: str, timestamp: bool = True) -> None:
        """
        保存页面截图

        Args:
            stage: 截图阶段标识
            timestamp: 是否添加时间戳
        """
        try:
            # 创建 screenshots 目录
            screenshot_dir = "screenshots"
            if not os.path.exists(screenshot_dir):
                os.makedirs(screenshot_dir)

            # 生成文件名
            if timestamp:
                filename = f"turnstile_{stage}_{int(time.time())}.png"
            else:
                filename = f"turnstile_{stage}.png"

            filepath = os.path.join(screenshot_dir, filename)

            # 保存截图
            self.tab.get_screenshot(filepath)
            logging.debug(f"截图已保存: {filepath}")
        except Exception as e:
            logging.warning(f"截图保存失败: {str(e)}")

    def check_verification_success(self) -> Optional[VerificationStatus]:
        """
        检查验证是否成功

        Returns:
            VerificationStatus: 验证成功时返回对应状态，失败返回 None
        """
        for status in VerificationStatus:
            if self.tab.ele(status.value):
                logging.info(f"验证成功 - 已到达{status.name}页面")
                return status
        return None

    def handle_turnstile(
        self, max_retries: int = 2, retry_interval: tuple = (1, 2)
    ) -> bool:
        """
        处理 Turnstile 验证

        Args:
            max_retries: 最大重试次数
            retry_interval: 重试间隔时间范围(最小值, 最大值)

        Returns:
            bool: 验证是否成功

        Raises:
            TurnstileError: 验证过程中出现异常
        """
        logging.info("正在检测 Turnstile 验证...")
        self.save_screenshot("start")

        retry_count = 0

        try:
            while retry_count < max_retries:
                retry_count += 1
                logging.debug(f"第 {retry_count} 次尝试验证")

                try:
                    # 定位验证框元素
                    # challenge_check = (
                    #     self.tab.ele("@id=cf-turnstile", timeout=2)
                    #     .child(ele_only=True)
                    #     .shadow_root.ele("tag:iframe")
                    #     .ele("tag:body")
                    #     .sr("tag:input")
                    # )
                    challenge_element = self.tab.ele("@id=cf-turnstile", timeout=2).child()
                    
                    if isinstance(challenge_element, str):
                        logging.debug("未找到验证框元素，继续尝试...")
                        continue
                    
                    challenge_check = (
                        challenge_element.shadow_root.ele("tag:iframe") # type: ignore
                        .ele("tag:body")
                        .sr("tag:input")
                    )
                    

                    if challenge_check:
                        logging.info("检测到 Turnstile 验证框，开始处理...")
                        # 随机延时后点击验证
                        time.sleep(random.uniform(1, 3))
                        challenge_check.click()
                        time.sleep(2)

                        # 保存验证后的截图
                        self.save_screenshot("clicked")

                        # 检查验证结果
                        if self.check_verification_success():
                            logging.info("Turnstile 验证通过")
                            self.save_screenshot("success")
                            return True

                except Exception as e:
                    logging.debug(f"当前尝试未成功: {str(e)}")

                # 检查是否已经验证成功
                if self.check_verification_success():
                    return True

                # 随机延时后继续下一次尝试
                time.sleep(random.uniform(*retry_interval))

            # 超出最大重试次数
            logging.error(f"验证失败 - 已达到最大重试次数 {max_retries}")
            logging.error(
                "请前往开源项目查看更多信息：https://github.com/Ryan0204/cursor-auto-icloud"
            )
            self.save_screenshot("failed")
            return False

        except Exception as e:
            error_msg = f"Turnstile 验证过程发生异常: {str(e)}"
            logging.error(error_msg)
            self.save_screenshot("error")
            raise TurnstileError(error_msg)

    def get_cursor_session_token(
        self, max_attempts: int = 3, retry_interval: int = 2
    ) -> Optional[str]:
        """
        获取Cursor会话token，带有重试机制
        :param max_attempts: 最大尝试次数
        :param retry_interval: 重试间隔(秒)
        :return: session token 或 None
        """
        logging.info("开始获取cookie")
        attempts = 0

        while attempts < max_attempts:
            try:
                cookies = self.tab.cookies()
                for cookie in cookies:
                    if cookie.get("name") == "WorkosCursorSessionToken":
                        return cookie["value"].split("%3A%3A")[1]

                attempts += 1
                if attempts < max_attempts:
                    logging.warning(
                        f"第 {attempts} 次尝试未获取到CursorSessionToken，{retry_interval}秒后重试..."
                    )
                    time.sleep(retry_interval)
                else:
                    logging.error(
                        f"已达到最大尝试次数({max_attempts})，获取CursorSessionToken失败"
                    )

            except Exception as e:
                logging.error(f"获取cookie失败: {str(e)}")
                attempts += 1
                if attempts < max_attempts:
                    logging.info(f"将在 {retry_interval} 秒后重试...")
                    time.sleep(retry_interval)

        return None

    def update_cursor_auth(
        self, email: str | None = None, access_token: str | None = None, refresh_token: str | None = None
    ) -> bool:
        """
        更新Cursor的认证信息的便捷函数
        """
        auth_manager = CursorAuthManager()
        return auth_manager.update_auth(email, access_token, refresh_token)

    def sign_up_account(
        self,
        sign_up_url: str,
        settings_url: str,
        first_name: str,
        last_name: str,
        account: str,
        password: str,
        email_handler: EmailVerificationHandler,
    ) -> bool:
        """
        Handle the account sign-up process

        Args:
            sign_up_url: URL for the signup page
            settings_url: URL for the settings page
            first_name: First name for the account
            last_name: Last name for the account
            account: Email account
            password: Password for the account
            email_handler: Email verification handler

        Returns:
            bool: True if signup was successful, False otherwise
        """
        logging.info("=== 开始注册账号流程 ===")
        logging.info(f"正在访问注册页面: {sign_up_url}")
        self.tab.get(sign_up_url)

        try:
            if self.tab.ele("@name=first_name"):
                logging.info("正在填写个人信息...")
                self.tab.actions.click("@name=first_name").input(first_name)
                logging.info(f"已输入名字: {first_name}")
                time.sleep(random.uniform(1, 3))

                self.tab.actions.click("@name=last_name").input(last_name)
                logging.info(f"已输入姓氏: {last_name}")
                time.sleep(random.uniform(1, 3))

                self.tab.actions.click("@name=email").input(account)
                logging.info(f"已输入邮箱: {account}")
                time.sleep(random.uniform(1, 3))

                logging.info("提交个人信息...")
                self.tab.actions.click("@type=submit")

        except Exception as e:
            logging.error(f"注册页面访问失败: {str(e)}")
            return False

        self.handle_turnstile()

        try:
            if self.tab.ele("@name=password"):
                logging.info("正在设置密码...")
                self.tab.ele("@name=password").input(password) # type: ignore
                time.sleep(random.uniform(1, 3))

                logging.info("提交密码...")
                self.tab.ele("@type=submit").click() # type: ignore
                logging.info("密码设置完成，等待系统响应...")

        except Exception as e:
            logging.error(f"密码设置失败: {str(e)}")
            return False

        if self.tab.ele("This email is not available."):
            logging.error("注册失败：邮箱已被使用")
            return False

        self.handle_turnstile()

        while True:
            try:
                if self.tab.ele("Account Settings"):
                    logging.info("注册成功 - 已进入账户设置页面")
                    break
                if self.tab.ele("@data-index=0"):
                    logging.info("正在获取邮箱验证码...")
                    code = email_handler.get_verification_code()
                    if not code:
                        logging.error("获取验证码失败")
                        return False

                    logging.info(f"成功获取验证码: {code}")
                    logging.info("正在输入验证码...")
                    i = 0
                    for digit in code:
                        self.tab.ele(f"@data-index={i}").input(digit) # type: ignore
                        time.sleep(random.uniform(0.1, 0.3))
                        i += 1
                    logging.info("验证码输入完成")
                    break
            except Exception as e:
                logging.error(f"验证码处理过程出错: {str(e)}")

        self.handle_turnstile()
        wait_time = random.randint(3, 6)
        for i in range(wait_time):
            logging.info(f"等待系统处理中... 剩余 {wait_time-i} 秒")
            time.sleep(1)

        logging.info("正在获取账户信息...")
        self.tab.get(settings_url)
        try:
            usage_selector = (
                "css:div.col-span-2 > div > div > div > div > "
                "div:nth-child(1) > div.flex.items-center.justify-between.gap-2 > "
                "span.font-mono.text-sm\\/\\[0\\.875rem\\]"
            )
            usage_ele = self.tab.ele(usage_selector)
            if usage_ele:
                usage_info = usage_ele.text
                total_usage = usage_info.split("/")[-1].strip()
                logging.info(f"账户可用额度上限: {total_usage}")
                logging.info(
                    "请前往开源项目查看更多信息：https://github.com/Ryan0204/cursor-auto-icloud"
                )
        except Exception as e:
            logging.error(f"获取账户额度信息失败: {str(e)}")

        logging.info("\n=== 注册完成 ===")
        account_info = f"Cursor 账号信息:\n邮箱: {account}\n密码: {password}"
        logging.info(account_info)
        time.sleep(5)
        return True


class EmailGenerator:
    def __init__(
        self,
        password="".join(
            random.choices(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*",
                k=12,
            )
        ),
        use_icloud=False,
    ):
        config_instance = Config()
        config_instance.print_config()
        self.names = self.load_names()
        self.default_password = password
        self.default_first_name = self.generate_random_name()
        self.default_last_name = self.generate_random_name()
        self.use_icloud = use_icloud
        self.generate_icloud_email = None

        # Try to import iCloud email generator if use_icloud is True
        if self.use_icloud:
            self.generate_icloud_email = generate_icloud_email
            logging.info("已启用 iCloud 隐藏邮箱功能")

    def load_names(self):
        """Load names from names-dataset.txt file"""
        # Look for the file in the project root directory
        names_file_path = os.path.join(
            os.path.dirname(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            ),
            "data",
            "names-dataset.txt",
        )

        try:
            with open(names_file_path, "r") as file:
                return file.read().split()
        except FileNotFoundError:
            logging.error(f"Names dataset file not found at {names_file_path}")
            # Return a small set of default names as fallback
            return ["John", "Jane", "Michael", "Emma", "Robert", "Olivia"]

    def generate_random_name(self):
        """生成随机用户名"""
        return random.choice(self.names)

    def generate_email(self):
        """
        生成随机邮箱地址，如果启用了 iCloud 功能则使用 iCloud 隐藏邮箱
        """
        # If iCloud is enabled, try to generate an iCloud email
        if self.use_icloud:
            try:
                emails = self.generate_icloud_email(1, True) # type: ignore
                if emails and len(emails) > 0:
                    return emails[0]
                else:
                    logging.warning("iCloud 邮箱生成失败，将使用本地邮箱列表")
            except Exception as e:
                logging.error(f"iCloud 邮箱生成失败: {str(e)}")
                logging.warning("将使用本地邮箱列表")

        # If iCloud failed or not enabled, use local email list
        # Define the path to the emails.txt file
        emails_file_path = os.path.join(
            os.path.dirname(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            ),
            "data",
            "emails.txt",
        )

        # Ensure the data directory exists
        data_dir = os.path.dirname(emails_file_path)
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)

        # Check if emails.txt exists
        if not os.path.exists(emails_file_path):
            logging.warning(
                f"Email list file not found at {emails_file_path}. Generating random email."
            )
            logging.warning("邮箱列表为空，程序执行完毕")
            sys.exit(1)

        # Read first email and remove it from file
        try:
            with open(emails_file_path, "r") as f:
                lines = f.readlines()
                if len(lines) == 0:
                    logging.warning("邮箱列表为空，程序执行完毕")
                    sys.exit(1)

            first_email = lines[0].strip()

            # Write remaining emails back to file
            with open(emails_file_path, "w") as f:
                f.writelines(lines[1:])

            return first_email
        except Exception as e:
            logging.error(f"Error reading email file: {str(e)}")
            logging.warning("邮箱列表为空，程序执行完毕")
            sys.exit(1)

    def get_account_info(self):
        """获取完整的账号信息"""
        return {
            "email": self.generate_email(),
            "password": self.default_password,
            "first_name": self.default_first_name,
            "last_name": self.default_last_name,
        }


def get_user_agent():
    """获取user_agent"""
    try:
        # 使用JavaScript获取user agent
        browser_manager = BrowserManager()
        browser = browser_manager.init_browser()
        user_agent = browser.latest_tab.run_js("return navigator.userAgent") # type: ignore
        browser_manager.quit()
        return user_agent
    except Exception as e:
        logging.error(f"获取user agent失败: {str(e)}")
        return None


def check_cursor_version():
    """检查cursor版本"""
    pkg_path, _ = patch_cursor_get_machine_id.get_cursor_paths()
    with open(pkg_path, "r", encoding="utf-8") as f:
        version = json.load(f)["version"]
    return patch_cursor_get_machine_id.version_check(version, min_version="0.45.0")


def reset_machine_id(greater_than_0_45):
    if greater_than_0_45:
        # 提示请手动执行脚本 https://github.com/Ryan0204/cursor-auto-icloud/blob/main/patch_cursor_get_machine_id.py
        go_cursor_help.go_cursor_help()
    else:
        MachineIDResetter().reset_machine_ids()


def print_end_message():
    logging.info("\n\n\n\n\n")
    logging.info("=" * 30)
    logging.info("所有操作已完成")
    logging.info("\n=== 获取更多信息 ===")
    logging.info(
        "请前往开源项目查看更多信息：https://github.com/Ryan0204/cursor-auto-icloud"
    )


def main():
    """Main function for the Cursor Pro Keep Alive application."""
    greater_than_0_45 = check_cursor_version()
    browser_manager = None

    # Define URLs used in the program
    login_url = "https://authenticator.cursor.sh"
    sign_up_url = "https://authenticator.cursor.sh/sign-up"
    settings_url = "https://www.cursor.com/settings"

    try:
        logging.info("\n=== 初始化程序 ===")
        ExitCursor()

        # 提示用户选择操作模式
        print("\n请选择操作模式:")
        print("1. 仅重置机器码")
        print("2. 完整注册流程")
        print("3. 生成 iCloud 隐藏邮箱")
        print("4. 完整注册流程（使用 iCloud 隐藏邮箱）")

        while True:
            try:
                choice = int(input("请输入选项 (1-4): ").strip())
                if choice in [1, 2, 3, 4]:
                    break
                else:
                    print("无效的选项,请重新输入")
            except ValueError:
                print("请输入有效的数字")

        if choice == 1:
            # 仅执行重置机器码
            reset_machine_id(greater_than_0_45)
            logging.info("机器码重置完成")
            print_end_message()
            sys.exit(0)

        elif choice == 3:
            # 生成 iCloud 隐藏邮箱
            try:
                count = int(input("请输入要生成的邮箱数量: ").strip())
                if count <= 0:
                    logging.error("邮箱数量必须大于0")
                    sys.exit(1)

                # Import the iCloud email generator
                emails = generate_icloud_email(count, True)

                if emails:
                    print(f"成功生成 {len(emails)} 个邮箱地址:")
                    for email in emails:
                        print(email)
                else:
                    print("未生成任何邮箱地址")
            except ValueError:
                logging.error("无效的数量")
                sys.exit(1)

        logging.info("正在初始化浏览器...")

        # 获取user_agent
        user_agent = get_user_agent()
        if not user_agent:
            logging.error("获取user agent失败，使用默认值")
            user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

        # 剔除user_agent中的"HeadlessChrome"
        user_agent = user_agent.replace("HeadlessChrome", "Chrome")

        browser_manager = BrowserManager()
        browser = browser_manager.init_browser(user_agent)

        # 获取并打印浏览器的user-agent
        user_agent = browser.latest_tab.run_js("return navigator.userAgent") # type: ignore

        logging.info(
            "请前往开源项目查看更多信息：https://github.com/Ryan0204/cursor-auto-icloud"
        )
        logging.info("\n=== 配置信息 ===")

        logging.info("正在生成随机账号信息...")

        # 使用 iCloud 隐藏邮箱 if choice is 4
        use_icloud = choice == 4
        email_generator = EmailGenerator(use_icloud=use_icloud)
        first_name = email_generator.default_first_name
        last_name = email_generator.default_last_name
        account = email_generator.generate_email()
        password = email_generator.default_password

        logging.info(f"生成的邮箱账号: {account}")

        logging.info("正在初始化邮箱验证模块...")
        email_handler = EmailVerificationHandler(account)

        tab = browser.latest_tab

        tab.run_js("try { turnstile.reset() } catch(e) { }") # type: ignore

        logging.info("\n=== 开始注册流程 ===")
        logging.info(f"正在访问登录页面: {login_url}")
        tab.get(login_url) # type: ignore

        handler = CursorRegistrationHandler(
            tab=tab, # type: ignore
        )

        if handler.sign_up_account(
            sign_up_url,
            settings_url,
            first_name,
            last_name,
            account,
            password,
            email_handler,
        ):
            logging.info("正在获取会话令牌...")
            token = handler.get_cursor_session_token()
            if token:
                logging.info("更新认证信息...")
                handler.update_cursor_auth(
                    email=account, access_token=token, refresh_token=token
                )
                logging.info(
                    "请前往开源项目查看更多信息：https://github.com/Ryan0204/cursor-auto-icloud"
                )
                logging.info("重置机器码...")
                reset_machine_id(greater_than_0_45)
                logging.info("所有操作已完成")
                print_end_message()
            else:
                logging.error("获取会话令牌失败，注册流程未完成")

    except Exception as e:
        logging.error(f"程序执行出现错误: {str(e)}")
        import traceback

        logging.error(traceback.format_exc())
    finally:
        if browser_manager:
            browser_manager.quit()
        input("\n程序执行完毕，按回车键退出...")


# If this script is run directly, execute the main function
if __name__ == "__main__":
    main()
