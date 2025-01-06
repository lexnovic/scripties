import base64
import json

def base64url_decode(data: str) -> bytes:
    """
    Decodes a Base64 URL–encoded string into raw bytes.
    Handles missing padding by adding '=' if necessary.
    """
    padding_needed = 4 - (len(data) % 4)
    if padding_needed and padding_needed < 4:
        data += '=' * padding_needed
    return base64.urlsafe_b64decode(data)

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

    # Print the results
    print("\nDecoded Header (JSON):")
    print(json.dumps(header_json, indent=4))

    print("\nDecoded Payload (JSON):")
    print(json.dumps(payload_json, indent=4))

    # Signature is typically binary data; we'll show it in hex for readability
    print("\nSignature (raw bytes in hex):")
    print(signature_bytes.hex())

    # Highlight the algorithm from the header if present
    alg = header_json.get("alg", None)
    if alg:
        print(f"\nAlgorithm used for signature: {alg}")
    else:
        print("\nNo 'alg' field was found in the header.")

if __name__ == "__main__":
    main()
