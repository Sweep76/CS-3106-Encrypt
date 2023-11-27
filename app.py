from flask import Flask, render_template, request, send_file
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
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

    cipher = PKCS1_OAEP.new(key)

    if file_path.endswith('.txt'):
        with open(file_path, 'rb') as file:
            plaintext = file.read()
            ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    elif file_path.endswith('.docx'):
        document = Document(file_path)
        plaintext = '\n'.join([paragraph.text for paragraph in document.paragraphs])
        ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    else:
        raise ValueError("Unsupported file format")

    with open(output_file_path, 'wb') as encrypted_file:
        encrypted_file.write(ciphertext)

def decrypt_file(file_path, key_path, output_file_path):
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
