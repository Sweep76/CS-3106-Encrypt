from flask import Flask, render_template, request, send_file
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import mimetypes
from docx import Document

app = Flask(__name__)

def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open('private_key.pem', 'wb') as private_key_file:
        private_key_file.write(private_key)
    with open('public_key.pem', 'wb') as public_key_file:
        public_key_file.write(public_key)

def encrypt_file(file_path, key_path, output_file_path):
    with open(key_path, 'rb') as key_file:
        key = RSA.import_key(key_file.read())

    # Generate a random symmetric key for file encryption
    symmetric_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(key)
    enc_symmetric_key = cipher_rsa.encrypt(symmetric_key)

    # Use AES to encrypt the file content with the symmetric key
    cipher_aes = AES.new(symmetric_key, AES.MODE_EAX)

    with open(file_path, 'rb') as file:
        plaintext = file.read()
        ciphertext, tag = cipher_aes.encrypt_and_digest(pad(plaintext, AES.block_size))

    # Write the encrypted symmetric key and the encrypted file content to the output file
    with open(output_file_path, 'wb') as encrypted_file:
        encrypted_file.write(enc_symmetric_key)
        encrypted_file.write(cipher_aes.nonce)
        encrypted_file.write(tag)
        encrypted_file.write(ciphertext)

def decrypt_file(file_path, key_path, output_file_path):
    with open(key_path, 'rb') as key_file:
        key = RSA.import_key(key_file.read())

    # Read the encrypted symmetric key and file content from the input file
    with open(file_path, 'rb') as encrypted_file:
        enc_symmetric_key = encrypted_file.read(256)  # Assuming a 2048-bit RSA key
        nonce = encrypted_file.read(16)
        tag = encrypted_file.read(16)
        ciphertext = encrypted_file.read()

    # Decrypt the symmetric key using RSA
    cipher_rsa = PKCS1_OAEP.new(key)
    symmetric_key = cipher_rsa.decrypt(enc_symmetric_key)

    # Use AES to decrypt the file content with the symmetric key
    cipher_aes = AES.new(symmetric_key, AES.MODE_EAX, nonce=nonce)
    decrypted_bytes = unpad(cipher_aes.decrypt_and_verify(ciphertext, tag), AES.block_size)

    # Write the decrypted file content to the output file
    with open(output_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_bytes)

# ... (rest of the code)

    with open(key_path, 'rb') as key_file:
        key = RSA.import_key(key_file.read())

    cipher = PKCS1_OAEP.new(key)

    with open(file_path, 'rb') as encrypted_file:
        ciphertext = encrypted_file.read()

        try:
            decrypted_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
            with open(output_file_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_bytes)
            print(f"File decrypted and saved to '{output_file_path}'")
        except Exception as e:
            print(f"Error: {e}")

# ... (rest of the code)

    with open(key_path, 'rb') as key_file:
        key = RSA.import_key(key_file.read())

    cipher = PKCS1_OAEP.new(key)

    with open(file_path, 'rb') as encrypted_file:
        ciphertext = encrypted_file.read()

        try:
            if file_path.endswith('.txt'):
                decrypted_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
                decrypted_text = decrypted_bytes.decode('utf-8', errors='replace')
                with open(output_file_path, 'w', encoding='utf-8') as decrypted_file:
                    decrypted_file.write(decrypted_text)
            elif file_path.endswith('.docx'):
                plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
                document = Document()
                for line in plaintext.split('\n'):
                    document.add_paragraph(line)
                document.save(output_file_path)
            else:
                raise ValueError("Unsupported file format")

            print(f"File decrypted and saved to '{output_file_path}'")
        except Exception as e:
            print(f"Error: {e}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    operation = request.form['operation']
    file = request.files['file']
    filename = 'uploaded_file' + os.path.splitext(file.filename)[-1]
    file_path = os.path.join('uploads', filename)
    file.save(file_path)

    if operation == 'encrypt':
        output_filename = 'encrypted_file' + os.path.splitext(file.filename)[-1]
        output_file_path = os.path.join('uploads', output_filename)
        encrypt_file(file_path, 'public_key.pem', output_file_path)
    elif operation == 'decrypt':
        output_filename = 'decrypted_file' + os.path.splitext(file.filename)[-1]
        output_file_path = os.path.join('uploads', output_filename)
        decrypt_file(file_path, 'private_key.pem', output_file_path)

    return render_template('result.html', operation=operation, filename=output_filename)

@app.route('/download/<filename>')
def download(filename):
    return send_file(os.path.join('uploads', filename), as_attachment=True)

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    generate_key_pair()
    app.run(debug=True)
