from phe import paillier
import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
PRIVATE_KEY_FILE = BASE_DIR / "private_key.json"
RESULT_FILE = BASE_DIR / "result.json"
REQUEST_FILE = BASE_DIR / "request.json"

# Read private key 
with PRIVATE_KEY_FILE.open("r", encoding="utf-8") as file:
    key_data = json.load(file)

public_key = paillier.PaillierPublicKey(
    int(key_data["n"])
)

private_key = paillier.PaillierPrivateKey(
    public_key,
    int(key_data["p"]),
    int(key_data["q"])
)

# Read the encrypted from the cloud
with RESULT_FILE.open("r", encoding="utf-8") as file:
    result_data = json.load(file)

encrypted_total = paillier.EncryptedNumber(
    public_key,
    int(result_data["encrypted_total"]),
    result_data["exponent"]
)

# Decrypt the final encrypted total
decrypted_total = private_key.decrypt(encrypted_total)

# Convert to Riyal
final_bill = decrypted_total / 100000

with REQUEST_FILE.open("r", encoding="utf-8") as file:
    request_data = json.load(file)

print("Selected date:", request_data.get("selected_date", "N/A"))
print("Number of hourly readings:", result_data.get("number_of_readings", "N/A"))
print("Decrypted total:", decrypted_total)
print("Final bill:", round(final_bill, 2), "SAR")
