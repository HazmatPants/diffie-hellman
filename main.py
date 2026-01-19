#!/usr/bin/env python

import asyncio
import secrets
import base64
import socket
import time
import json

CRYPT_KEY: bytes = None

host = "127.0.0.1"
port = 9999

secret_size = 1000000

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

async def main():
    choice = input("(c)lient or (s)erver?: ")
    if choice.lower() == "c":
        base = secrets.randbelow(secret_size)
        mod = secrets.randbelow(secret_size)
        secret = secrets.randbelow(secret_size)

        data: dict = {
            "b": base,
            "m": mod
        }

        print("Negotiating encryption key...")

        print(f"Chose base {base} and modulus {mod}")

        send_json(data, (host, port))

        print(f"Sent base and modulus to {host}:{port}")

        bm = pow(base, secret, mod)

        send_str(str(bm), (host, port))
        data = await recv_str()
        client_bm = int(data)
        
        print("Generating key...")
        key = (client_bm ** secret) % mod
        CRYPT_KEY = key.to_bytes((key.bit_length() + 7) // 8, "big")
        key_str = base64.b64encode(CRYPT_KEY).decode()
        print(f"key: {key_str}")
        print("Successfully negotiated key!")

        send_crypt_str("TEST_TEST_TEST_123", (host, port), CRYPT_KEY)
        print("Testing encryption...")

        data = await recv_crypt_str(CRYPT_KEY)

        if data == "OK":
            print("Encryption handshake success!")

        while True:
            try:
                data = input(">>> ")
                send_crypt_str(data, (host, port), CRYPT_KEY)
                print(f"Sent: {data}")
                if data == "goodbye":
                    s.close()
                    exit()
            except Exception as err:
                print(f"ERROR: {err}")
                s.close()
                exit()

    elif choice.lower() == "s":
        s.bind((host, port))
        print(f"Server listening on {host}:{port}")
        data, addr = recv_json()
        print("Negotiating encryption key...")
        base = data["b"]
        mod = data["m"]
        print(f"Received base {base} and modulus {mod}")

        secret = secrets.randbelow(secret_size)

        bm = pow(base, secret, mod)

        data = await recv_str()
        client_bm = int(data)
        send_str(str(bm), addr)

        print("Generating key...")
        key = (client_bm ** secret) % mod
        CRYPT_KEY = key.to_bytes((key.bit_length() + 7) // 8, "big")
        key_str = base64.b64encode(CRYPT_KEY).decode()
        print(f"key: {key_str}")
        print("Successfully negotiated key!")

        data = await recv_crypt_str(CRYPT_KEY)

        if data == "TEST_TEST_TEST_123":
            print("Encryption handshake success!")
            send_crypt_str("OK", addr, CRYPT_KEY)

        while True:
            try:
                data = await recv_crypt_str(CRYPT_KEY)
                print(f"Received: {data}")

                if data == "goodbye":
                    print("Goodbye client")
                    s.close()
                    exit()
            except Exception as err:
                print(f"ERROR: {err}")
                s.close()
                exit()

def recv_json():
    data, addr = s.recvfrom(1024)
    data = json.loads(data.decode("utf-8"))
    return data, addr

async def recv_str():
    data, addr = s.recvfrom(1024)
    return data.decode("utf-8")

async def recv_crypt_str(key):
    data, addr = s.recvfrom(1024)
    ciphertext = bytes.fromhex(data.decode("utf-8"))
    print(f"Received encrypted string: {ciphertext}")
    text = xor_crypt(ciphertext, key)
    return text.decode("utf-8")

def send_crypt_str(text: str, addr, key):
    plain = text.encode("utf-8")
    ciphertext = xor_crypt(plain, key)
    send_str(ciphertext.hex(), addr)

def send_json(data: dict, addr):
    payload = json.dumps(data)
    s.sendto(payload.encode("utf-8"), addr)

def send_str(data: str, addr):
    payload = data
    s.sendto(payload.encode("utf-8"), addr)

def xor_crypt(data: bytes, key: bytes) -> bytes:
    return bytes(
        data[i] ^ key[i % len(key)]
        for i in range(len(data))
    )

if __name__ == "__main__":
    asyncio.run(main())
