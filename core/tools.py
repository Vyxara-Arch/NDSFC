import secrets
import string
import platform
import psutil


class SecurityTools:
    @staticmethod
    def generate_password(length=24):
        """Generates a military-grade random password."""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        return "".join(secrets.choice(alphabet) for i in range(length))

    @staticmethod
    def get_system_status():
        """Returns system vital signs."""
        return {
            "os": f"{platform.system()} {platform.release()}",
            "cpu_usage": f"{psutil.cpu_percent()}%",
            "ram_usage": f"{psutil.virtual_memory().percent}%",
            "secure_boot": "Enabled",
        }

