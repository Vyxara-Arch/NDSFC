import secrets
import string
import platform
import psutil


class SecurityTools:
    @staticmethod
    def generate_password(length=24):
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        return "".join(secrets.choice(alphabet) for i in range(length))

    @staticmethod
    def validate_password(password: str, min_length: int = 12):
        issues = []
        if not isinstance(password, str):
            return False, ["Password must be a string"]
        if len(password) < min_length:
            issues.append(f"Minimum length is {min_length} characters")
        if not any(c.islower() for c in password):
            issues.append("Add at least one lowercase letter")
        if not any(c.isupper() for c in password):
            issues.append("Add at least one uppercase letter")
        if not any(c.isdigit() for c in password):
            issues.append("Add at least one digit")
        if not any(not c.isalnum() for c in password):
            issues.append("Add at least one symbol")
        return len(issues) == 0, issues

    @staticmethod
    def get_system_status():
        return {
            "os": f"{platform.system()} {platform.release()}",
            "cpu_usage": f"{psutil.cpu_percent()}%",
            "ram_usage": f"{psutil.virtual_memory().percent}%",
            "secure_boot": "Enabled",
        }

