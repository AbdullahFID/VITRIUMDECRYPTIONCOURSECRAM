# ═══════════════════════════════════════════════════════
#  PASTE YOUR VALUES HERE
# ═══════════════════════════════════════════════════════

DOC_ID = "vhbPNQ"  # the code from the URL, e.g. webviewer.prep101.com/XXXXX

DT = ""  # paste DT cookie value here

WVS = ""  # paste WVS cookie value here

CID = ""  # paste CID cookie value here

OUTPUT = "decrypted.pdf"  # output filename

# ═══════════════════════════════════════════════════════
#  DON'T TOUCH BELOW THIS LINE
# ═══════════════════════════════════════════════════════

import base64, hashlib, json, requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import pikepdf

KEY = bytes([0x03,0xc0,0x3b,0xc2,0x27,0x2d,0xc1,0x4f,
             0x8c,0x97,0x79,0x28,0x01,0x4b,0x09,0xe3])

def aes_cbc(key, iv, data):
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    p = padding.PKCS7(128).unpadder()
    return p.update(d.update(data) + d.finalize()) + p.finalize()

def main():
    cookie = f"DT={DT}; WVS={WVS}; CID={CID}; vitrium_auth=53871"
    hdrs = {"Cookie": cookie, "User-Agent": "Mozilla/5.0"}
    base = "https://webviewer.prep101.com"

    # 1. Fetch + decrypt config
    print("[*] Fetching config...")
    blob = requests.get(f"{base}/api/doc/{DOC_ID}/info?contentType=pdf&count=0", headers=hdrs).text
    iv_b64, ct_b64 = blob.split(",", 1)
    config = json.loads(aes_cbc(KEY, base64.b64decode(iv_b64), base64.b64decode(ct_b64)))
    print(f"[+] Title: {config['document']['title']}")

    # 2. Decrypt ep → derive password
    ep = config["document"]["ep"]
    enc_b64, key_b64 = ep.split(",")
    dec_ep = aes_cbc(base64.b64decode(key_b64), bytes(16), base64.b64decode(enc_b64))
    half = len(dec_ep) // 2 + (len(dec_ep) % 2)
    pw = base64.b64encode(hashlib.pbkdf2_hmac(
        "sha1", dec_ep[:half], hashlib.sha256(dec_ep).digest(), 1000, 32
    )).decode()
    print(f"[+] Password: {pw}")

    # 3. Download encrypted PDF
    print("[*] Downloading PDF...")
    r = requests.get(f"{base}/api/doc/{DOC_ID}/package?contentType=pdf&timestamp=0", headers=hdrs)
    enc_path = OUTPUT + ".enc"
    with open(enc_path, "wb") as f:
        f.write(r.content)
    print(f"[+] Downloaded: {len(r.content) / 1024 / 1024:.1f} MB")

    # 4. Decrypt + save
    pdf = pikepdf.open(enc_path, password=pw)
    pdf.save(OUTPUT)
    print(f"[+] Saved: {OUTPUT} ({len(pdf.pages)} pages)")

    import os
    os.remove(enc_path)
    print("[+] Done!")

if __name__ == "__main__":
    main()
