import base64
import hmac
import hashlib

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def create_jwt(header_json: str, payload_json: str, secret: str) -> str:
    # Encode header and payload to Base64 URL format
    encoded_header = base64url_encode(header_json.encode('utf-8'))
    encoded_payload = base64url_encode(payload_json.encode('utf-8'))

    # Concatenate the parts to sign
    signing_input = f"{encoded_header}.{encoded_payload}"

    # Create the HMAC-SHA256 signature
    signature = hmac.new(
        secret.encode('utf-8'),
        signing_input.encode('utf-8'),
        hashlib.sha256
    ).digest()

    # Base64 URL encode the signature
    encoded_signature = base64url_encode(signature)

    # Return the final JWT
    return f"{signing_input}.{encoded_signature}"

def main():
    # Prompt for inputs
    header = input("Enter the JWT header (in JSON format): ")
    payload = input("Enter the JWT payload (in JSON format): ")
    secret = input("Enter the secret key: ")

    # Create and print the JWT
    jwt_token = create_jwt(header, payload, secret)
    print("Your generated JWT token is:\n")
    print(jwt_token)

if __name__ == "__main__":
    main()
