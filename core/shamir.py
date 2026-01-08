from Crypto.Protocol.SecretSharing import Shamir
from binascii import hexlify, unhexlify


class ShamirVault:
    @staticmethod
    def split_secret(secret_bytes: bytes, threshold: int, num_shares: int):
        """
        Splits a secret into num_shares, requiring threshold to recover.
        Returns list of tuples (index, share_hex).
        """
        shares = Shamir.split(threshold, num_shares, secret_bytes)
        return [(idx, hexlify(share).decode()) for idx, share in shares]

    @staticmethod
    def combine_shares(shares_list):
        """
        shares_list: list of tuples (index, share_hex_string)
        """
        formatted_shares = []
        for idx, share_hex in shares_list:
            formatted_shares.append((int(idx), unhexlify(share_hex)))

        return Shamir.combine(formatted_shares)
