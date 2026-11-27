from phe import paillier
import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
REQUEST_FILE = BASE_DIR / "request.json"
RESULT_FILE = BASE_DIR / "result.json"

# Read the encrypted request
with REQUEST_FILE.open("r", encoding="utf-8") as file:
    request_data = json.load(file)

# Reconstruct the public key
public_key_n = int(request_data["public_key"]["n"])
public_key = paillier.PaillierPublicKey(public_key_n)

rate = request_data["rate_halala_per_kwh"]

encrypted_total = None

# Process encrypted readings only
for reading in request_data["readings"]:

    ciphertext = int(reading["ciphertext"])
    exponent = reading["exponent"]

    encrypted_reading = paillier.EncryptedNumber(
        public_key,
        ciphertext,
        exponent
    )

    # Homomorphic multiplication by the public rate
    encrypted_cost = encrypted_reading * rate

    # Homomorphic addition
    if encrypted_total is None:
        encrypted_total = encrypted_cost
    else:
        encrypted_total += encrypted_cost

# Save the encrypted result
result_data = {
    "selected_date": request_data.get("selected_date"),
    "unit": "halala",
    "number_of_readings": len(request_data["readings"]),
    "encrypted_total": str(
        encrypted_total.ciphertext(False)
    ),
    "exponent": encrypted_total.exponent
}

with RESULT_FILE.open("w", encoding="utf-8") as file:
    json.dump(result_data, file, indent=4)

print("Cloud processed encrypted readings only.")
print("Number of readings:", len(request_data["readings"]))
print("result.json created successfully.")
