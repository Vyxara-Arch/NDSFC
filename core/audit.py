import datetime


class AuditLog:
    _logs = []

    @staticmethod
    def log(action: str, details: str, level: str = "INFO"):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] [{level}] {action}: {details}"
        print(entry)  # For CLI debug
        AuditLog._logs.append(entry)

    @staticmethod
    def get_logs():
        return AuditLog._logs
