import base64
import json
import hmac
import hashlib

def base64url_decode(data: str) -> bytes:
    """Decodes Base64 URL–encoded data."""
    padding_needed = 4 - (len(data) % 4)
    if padding_needed and padding_needed < 4:
        data += '=' * padding_needed
    return base64.urlsafe_b64decode(data)

def base64url_encode(data: bytes) -> str:
    """Encodes data to Base64 URL format."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def verify_signature(header_b64, payload_b64, signature_b64, secret, algorithm):
    """
    Verifies the JWT signature using the given secret and algorithm.
    """
    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
    signature_bytes = base64url_decode(signature_b64)

    if algorithm == "HS256":
        expected_signature = hmac.new(
            secret.encode('utf-8'),
            signing_input,
            hashlib.sha256
        ).digest()
    elif algorithm == "HS384":
        expected_signature = hmac.new(
            secret.encode('utf-8'),
            signing_input,
            hashlib.sha384
        ).digest()
    elif algorithm == "HS512":
        expected_signature = hmac.new(
            secret.encode('utf-8'),
            signing_input,
            hashlib.sha512
        ).digest()
    else:
        return False, f"Unsupported algorithm: {algorithm}"

    return hmac.compare_digest(signature_bytes, expected_signature), None

def main():
    # Prompt user for a JWT token
    jwt_token = input("Please enter a JWT token: ").strip()

    # Split the token into 3 parts
    parts = jwt_token.split('.')
    if len(parts) != 3:
        print("Error: This doesn't look like a valid JWT (not 3 parts).")
        return

    header_b64, payload_b64, signature_b64 = parts

    # Decode header (JSON)
    try:
        header_bytes = base64url_decode(header_b64)
        header_json = json.loads(header_bytes)
    except Exception as e:
        print("Error decoding header:", e)
        return

    # Decode payload (JSON)
    try:
        payload_bytes = base64url_decode(payload_b64)
        payload_json = json.loads(payload_bytes)
    except Exception as e:
        print("Error decoding payload:", e)
        return

    # Decode signature (not JSON—just raw bytes)
    try:
        signature_bytes = base64url_decode(signature_b64)
    except Exception as e:
        print("Error decoding signature:", e)
        return

    # Print the decoded results
    print("\nDecoded Header (JSON):")
    print(json.dumps(header_json, indent=4))

    print("\nDecoded Payload (JSON):")
    print(json.dumps(payload_json, indent=4))

    # Signature as hex
    print("\nSignature (raw bytes in hex):")
    print(signature_bytes.hex())

    # Highlight algorithm and verify signature
    alg = header_json.get("alg", None)
    if alg:
        print(f"\nAlgorithm used for signature: {alg}")
        secret = input("Enter the secret phrase to verify the signature: ")

        is_valid, error = verify_signature(header_b64, payload_b64, signature_b64, secret, alg)
        if error:
            print(f"Verification error: {error}")
        else:
            if is_valid:
                print("Signature verification: ✅ VALID")
            else:
                print("Signature verification: ❌ INVALID")
    else:
        print("\nNo 'alg' field was found in the header.")

if __name__ == "__main__":
    main()
