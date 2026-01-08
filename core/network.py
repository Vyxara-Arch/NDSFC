import paramiko
import socks  # Требуется pip install pysocks
import socket


class GhostLink:
    def __init__(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.sftp = None
        self.transport = None

    def connect(
        self,
        host,
        port,
        user,
        password=None,
        key_file=None,
        proxy_host=None,
        proxy_port=None,
    ):
        try:
            # Настройка сокета (напрямую или через Proxy/Tor)
            sock = None
            if proxy_host and proxy_port:
                sock = socks.socksocket()
                sock.set_proxy(socks.SOCKS5, proxy_host, int(proxy_port))
                sock.connect((host, int(port)))

            # Подключение
            self.client.connect(
                hostname=host,
                port=port,
                username=user,
                password=password,
                key_filename=key_file,
                sock=sock,
                timeout=15,
                banner_timeout=15,
            )

            self.sftp = self.client.open_sftp()
            return True, "Secure Link Established" + (" (via Proxy)" if sock else "")
        except Exception as e:
            return False, f"Connection Failed: {str(e)}"

    def upload(self, local_path, remote_path):
        if not self.sftp:
            return False, "Not Connected"
        try:
            self.sftp.put(local_path, remote_path)
            return True, "Upload Complete"
        except Exception as e:
            return False, str(e)

    def close(self):
        if self.sftp:
            self.sftp.close()
        self.client.close()
