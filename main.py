#!/usr/bin/env python

import argparse
import asyncio
import secrets
import base64
import socket
import time
import json

parser = argparse.ArgumentParser(
                    prog='diffie-hellam',
                    description='Diffie-Hellman Key Exchange',
                    epilog='Text at the bottom of help')

parser.add_argument("-v", "--verbose", action="store_true")

args = parser.parse_args()

CRYPT_KEY: bytes = None

host = "127.0.0.1"
port = 9999

secret_size = 256
MODULUS = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
BASE = 2


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

async def main():
    choice = input("(c)lient or (s)erver?: ")
    if choice.lower() == "c":
        s.settimeout(5)
        base = BASE
        mod = MODULUS
        secret = secrets.randbelow(secret_size)

        data: dict = {
            "b": base,
            "m": mod
        }

        log("Negotiating encryption key...", False)

        log(f"Chose base {base} and modulus {mod}")

        send_json(data, (host, port))

        log(f"Sent base and modulus to {host}:{port}")

        bm = pow(base, secret, mod)

        send_str(str(bm), (host, port))
        try:
            data = await recv_str()
        except socket.timeout:
            print("Connection timed out.")
            s.close()
            exit()

        client_bm = int(data)
        
        log("Generating key...")
        key = (client_bm ** secret) % mod
        CRYPT_KEY = key.to_bytes((key.bit_length() + 7) // 8, "big")
        key_str = base64.b64encode(CRYPT_KEY).decode()
        log(f"key: {key_str}")
        log("Successfully negotiated key!")

        send_crypt_str("TEST_TEST_TEST_123", (host, port), CRYPT_KEY)
        log("Testing encryption...")

        data = await recv_crypt_str(CRYPT_KEY)

        if data == "OK":
            log("Encryption handshake success!", False)

        log("Send 'goodbye' to disconnect.", False)

        while True:
            try:
                data = input(">>> ")
                send_crypt_str(data, (host, port), CRYPT_KEY)
                log(f"Sent: {data}", False)
                if data == "goodbye":
                    s.close()
                    exit()
            except KeyboardInterrupt:
                print("\nExiting...")
                s.close()
                exit()
            except Exception as err:
                print(f"ERROR: {err}")
                s.close()
                exit()

    elif choice.lower() == "s":
        s.bind((host, port))
        log(f"Server listening on {host}:{port}", False)
        data, addr = recv_json()
        log("Negotiating encryption key...", False)
        base = data["b"]
        mod = data["m"]
        log(f"Received base {base} and modulus {mod}")

        secret = secrets.randbelow(secret_size)

        bm = pow(base, secret, mod)

        data = await recv_str()
        client_bm = int(data)
        send_str(str(bm), addr)

        log("Generating key...")
        key = (client_bm ** secret) % mod
        CRYPT_KEY = key.to_bytes((key.bit_length() + 7) // 8, "big")
        key_str = base64.b64encode(CRYPT_KEY).decode()
        log(f"key: {key_str}")
        log("Successfully negotiated key!")

        data = await recv_crypt_str(CRYPT_KEY)

        if data == "TEST_TEST_TEST_123":
            log("Encryption handshake success!", False)
            send_crypt_str("OK", addr, CRYPT_KEY)

        while True:
            try:
                data = await recv_crypt_str(CRYPT_KEY)
                log(f"Received: {data}", False)

                if data == "goodbye":
                    log("Goodbye client", False)
                    s.close()
                    exit()
            except Exception as err:
                log(f"ERROR: {err}", False)
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
    log(f"Received encrypted string: {ciphertext}")
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

def log(text: str, verbose: bool=True):
    localtime = time.localtime()
    timestamp = time.strftime("%m-%d-%Y, %H:%M:%S", localtime)
    if verbose and args.verbose:
        print(f"[{timestamp}] {text}")
    elif not verbose:
        print(f"[{timestamp}] {text}")
if __name__ == "__main__":
    asyncio.run(main())
