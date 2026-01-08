from PIL import Image
import struct
import os


class StegoEngine:
    @staticmethod
    def encode(cover_path, secret_path, output_path):
        img = Image.open(cover_path).convert("RGB")
        pixels = img.load()
        width, height = img.size

        with open(secret_path, "rb") as f:
            data = f.read()


        data = struct.pack(">I", len(data)) + data

        if len(data) * 8 > width * height * 3:
            raise ValueError("File too large for this image. Need bigger image.")

        data_idx = 0
        bit_idx = 0

        def pixel_gen():
            for y in range(height):
                for x in range(width):
                    yield x, y

        pg = pixel_gen()

        for x, y in pg:
            r, g, b = pixels[x, y]
            rgb = [r, g, b]

            for i in range(3):
                if data_idx < len(data):
                    bit = (data[data_idx] >> (7 - bit_idx)) & 1
                    rgb[i] = (rgb[i] & ~1) | bit
                    bit_idx += 1
                    if bit_idx == 8:
                        bit_idx = 0
                        data_idx += 1
                else:
                    break

            pixels[x, y] = tuple(rgb)
            if data_idx >= len(data):
                break

        img.save(output_path, "PNG")

    @staticmethod
    def decode(stego_path, output_path):
        img = Image.open(stego_path).convert("RGB")
        pixels = img.load()
        width, height = img.size

        data_bytes = bytearray()


        len_bits = []

        def bit_generator():
            for y in range(height):
                for x in range(width):
                    r, g, b = pixels[x, y]
                    yield r & 1
                    yield g & 1
                    yield b & 1

        bg = bit_generator()

        for _ in range(32):
            len_bits.append(next(bg))

        length_val = 0
        for bit in len_bits:
            length_val = (length_val << 1) | bit


        if length_val > width * height * 3:
            raise ValueError("Corrupted Stego Header or No Data")

        for _ in range(length_val):
            byte_val = 0
            for _ in range(8):
                byte_val = (byte_val << 1) | next(bg)
            data_bytes.append(byte_val)

        with open(output_path, "wb") as f:
            f.write(data_bytes)

