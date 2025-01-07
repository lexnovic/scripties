import base64
import json
import hmac
import hashlib

def base64url_decode(data):
    """
    Decodes a Base64 URL–encoded string into raw bytes.
    Handles missing padding by adding '=' if necessary.
    """
    padding_needed = 4 - (len(data) % 4)
    if padding_needed and padding_needed < 4:
        data += '=' * padding_needed
    return base64.urlsafe_b64decode(data)

def base64url_encode(data):
    """
    Encodes raw bytes into Base64 URL format (no padding).
    """
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def verify_signature(header_b64, payload_b64, signature_b64, secret, alg):
    """
    Verifies the signature of the JWT using the provided secret.
    """
    signing_input = f"{header_b64}.{payload_b64}"

    if alg == "HS256":
        expected_signature = hmac.new(
            secret.encode('utf-8'),
            signing_input.encode('utf-8'),
            hashlib.sha256
        ).digest()
    elif alg == "HS384":
        expected_signature = hmac.new(
            secret.encode('utf-8'),
            signing_input.encode('utf-8'),
            hashlib.sha384
        ).digest()
    elif alg == "HS512":
        expected_signature = hmac.new(
            secret.encode('utf-8'),
            signing_input.encode('utf-8'),
            hashlib.sha512
        ).digest()
    else:
        print(f"Unsupported algorithm: {alg}")
        return False

    # Compare the provided signature with the expected one
    expected_signature_b64 = base64url_encode(expected_signature)
    return expected_signature_b64 == signature_b64

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

    # Print the decoded header and payload
    print("\nDecoded Header (JSON):")
    print(json.dumps(header_json, indent=4))

    print("\nDecoded Payload (JSON):")
    print(json.dumps(payload_json, indent=4))

    # Signature in hex
    print("\nSignature (raw bytes in hex):")
    print(signature_bytes.hex())

    # Highlight algorithm
    alg = header_json.get("alg", None)
    if alg:
        print(f"\nAlgorithm used for signature: {alg}")
    else:
        print("\nNo 'alg' field was found in the header.")
        return

    # Prompt for the secret key
    secret = input("\nEnter the secret key to verify the token: ").strip()

    # Verify the token
    is_valid = verify_signature(header_b64, payload_b64, signature_b64, secret, alg)
    if is_valid:
        print("\n✅ The JWT signature is valid.")
    else:
        print("\n❌ The JWT signature is invalid. The token may have been tampered with or the secret is incorrect.")

if __name__ == "__main__":
    main()
