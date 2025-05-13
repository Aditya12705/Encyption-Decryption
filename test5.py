import streamlit as st
import fitz  # PyMuPDF
import zstandard as zstd
import lzma
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend
import io
import hashlib
import streamlit.components.v1 as components
import zipfile
import shutil
from docx import Document  # Corrected import
import csv
import xml.etree.ElementTree as ET
import time

# Set page configuration as the first Streamlit command
st.set_page_config(page_title="File Encoder/Decoder (RSA-4096)", page_icon="🔒", layout="wide")

# Initialize session state
if 'attempts' not in st.session_state:
    st.session_state.attempts = {}
if 'reset' not in st.session_state:
    st.session_state.reset = False
if 'encode_key_displayed' not in st.session_state:
    st.session_state.encode_key_displayed = False
if 'private_keys' not in st.session_state:
    st.session_state.private_keys = []  # List for multiple private keys
if 'encoded_files_data' not in st.session_state:
    st.session_state.encoded_files_data = []  # List for multiple encoded files
if 'encoded_file_names' not in st.session_state:
    st.session_state.encoded_file_names = []  # List for multiple file names

# Core functionality (unchanged functions)
def generate_rsa_key_pair():
    """Generate a 4096-bit RSA key pair without BEGIN/END headers."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    private_lines = private_pem.splitlines()
    stripped_private = "\n".join(line for line in private_lines if not line.startswith("-----"))
    return stripped_private, public_pem

def generate_aes_key():
    """Generate a random 32-byte key for AES-256."""
    return os.urandom(32)

def get_compression_params(file_type, strength):
    """Return compression parameters based on file type and strength."""
    if file_type in ["pdf", "txt", "docx"]:
        return {"compressor": "lzma", "level": 9, "filters": [{"id": lzma.FILTER_LZMA2, "preset": 9}]}
    else:  # csv with hybrid compression (zstd + lzma)
        if strength == "Light":
            return {
                "compressor": "hybrid",
                "zstd_level": 3,
                "zstd_params": zstd.ZstdCompressionParameters(compression_level=3, window_log=20),
                "lzma_filters": [{"id": lzma.FILTER_LZMA2, "preset": 6}]
            }
        elif strength == "Medium":
            return {
                "compressor": "hybrid",
                "zstd_level": 5,
                "zstd_params": zstd.ZstdCompressionParameters(compression_level=5, window_log=21),
                "lzma_filters": [{"id": lzma.FILTER_LZMA2, "preset": 7}]
            }
        else:  # Heavy
            return {
                "compressor": "hybrid",
                "zstd_level": 7,
                "zstd_params": zstd.ZstdCompressionParameters(compression_level=7, window_log=22),
                "lzma_filters": [{"id": lzma.FILTER_LZMA2, "preset": 9}]
            }

def encode_file_to_binary(file_bytes, file_type, compression_strength, progress_callback):
    try:
        start_time = time.time()
        progress_callback(10, f"Opening {file_type} file...")
        original_size = len(file_bytes) / 1024
        
        if file_type == "pdf":
            progress_callback(20, "Processing PDF images...")
            pdf_document = fitz.open(stream=file_bytes, filetype="pdf")
            image_count = 0
            for page in pdf_document:
                images = page.get_images(full=True)
                image_count += len(images)
                for img in images:
                    xref = img[0]
                    pix = fitz.Pixmap(pdf_document, xref)
                    if pix.n > 4:
                        pix = fitz.Pixmap(fitz.csRGB, pix)
                    pix.shrink(3)
                    # Save pixmap as JPEG bytes directly
                    jpeg_data = pix.tobytes("jpeg", jpg_quality=20)
                    pdf_document.update_stream(xref, jpeg_data)
            progress_callback(30, "Optimizing PDF fonts...")
            for page_num in range(len(pdf_document)):
                page = pdf_document[page_num]
                fonts = page.get_fonts()
                for font in fonts:
                    xref = font[0]
                    pdf_document.subset_fonts([xref])
            pdf_document.set_metadata({})
            progress_callback(40, "Saving temporary PDF...")
            pdf_document.save(
                "temp.pdf",
                deflate=True,
                garbage=4,
                clean=True,
                linear=True,
                expand=0,
                no_new_id=True
            )
            pdf_document.close()
            pdf_document = fitz.open("temp.pdf")
            processed_bytes = pdf_document.write()
            pdf_document.close()
            os.remove("temp.pdf")
        elif file_type == "docx":
            progress_callback(20, "Processing Word document...")
            processed_bytes = file_bytes
        else:  # txt, csv
            progress_callback(20, f"Preparing {file_type} file...")
            processed_bytes = file_bytes

        preprocessed_size = len(processed_bytes) / 1024
        st.write(f"Preprocessing time: {time.time() - start_time:.2f} seconds")

        progress_callback(50, "Compressing data...")
        compress_start = time.time()
        compression_params = get_compression_params(file_type, compression_strength)
        if compression_params["compressor"] == "lzma":
            compressed_bytes = lzma.compress(
                processed_bytes,
                format=lzma.FORMAT_XZ,
                filters=compression_params["filters"]
            )
        else:  # hybrid compression for csv
            progress_callback(55, "Applying zstd compression (Stage 1)...")
            cctx = zstd.ZstdCompressor(compression_params=compression_params["zstd_params"])
            zstd_data = io.BytesIO()
            chunk_size = 32 * 1024 * 1024  # 32 MB chunks
            for i in range(0, len(processed_bytes), chunk_size):
                chunk = processed_bytes[i:i + chunk_size]
                compressed_chunk = cctx.compress(chunk)
                zstd_data.write(compressed_chunk)
            zstd_data.write(cctx.compress(b''))
            zstd_data.seek(0)
            zstd_compressed = zstd_data.getvalue()
            progress_callback(65, "Applying LZMA compression (Stage 2)...")
            compressed_bytes = lzma.compress(
                zstd_compressed,
                format=lzma.FORMAT_XZ,
                filters=compression_params["lzma_filters"]
            )
        st.write(f"Compression time: {time.time() - compress_start:.2f} seconds")

        progress_callback(70, "Encrypting data with AES...")
        encrypt_start = time.time()
        aes_key = generate_aes_key()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padding_length = 16 - (len(compressed_bytes) % 16)
        padded_data = compressed_bytes + bytes([padding_length] * padding_length)
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        st.write(f"AES encryption time: {time.time() - encrypt_start:.2f} seconds")

        progress_callback(80, "Encrypting AES key with RSA-4096...")
        rsa_start = time.time()
        private_pem, public_pem = generate_rsa_key_pair()
        public_key = serialization.load_pem_public_key(public_pem.encode('utf-8'), backend=default_backend())
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        st.write(f"RSA encryption time: {time.time() - rsa_start:.2f} seconds")

        file_type_bytes = file_type.encode('utf-8')
        final_data = file_type_bytes + b':' + iv + len(encrypted_aes_key).to_bytes(2, 'big') + encrypted_aes_key + encrypted_data

        final_size = len(final_data) / 1024
        size_reduction_percent = ((original_size - final_size) / original_size) * 100 if original_size > 0 else 0
        total_time = time.time() - start_time
        st.write(f"Total processing time: {total_time:.2f} seconds")

        progress_callback(100, "Complete!")
        return final_data, private_pem, {
            "original_size": original_size,
            "final_size": final_size,
            "size_reduction_percent": size_reduction_percent,
            "image_count": 0 if file_type != "pdf" else image_count,
            "preprocessed_size": preprocessed_size
        }
    except Exception as e:
        raise Exception(f"Encoding failed: {str(e)}")

def decode_binary_to_file(encrypted_data, private_pem, progress_callback):
    try:
        start_time = time.time()
        file_type_end = encrypted_data.find(b':')
        file_type = encrypted_data[:file_type_end].decode('utf-8')
        encrypted_data = encrypted_data[file_type_end + 1:]

        progress_callback(20, "Decrypting AES key with RSA-4096...")
        rsa_start = time.time()
        pem_with_headers = f"-----BEGIN PRIVATE KEY-----\n{private_pem.strip()}\n-----END PRIVATE KEY-----"
        private_key = serialization.load_pem_private_key(pem_with_headers.encode('utf-8'), password=None, backend=default_backend())
        iv = encrypted_data[:16]
        key_length = int.from_bytes(encrypted_data[16:18], 'big')
        encrypted_aes_key = encrypted_data[18:18 + key_length]
        ciphertext = encrypted_data[18 + key_length:]
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        st.write(f"RSA decryption time: {time.time() - rsa_start:.2f} seconds")

        progress_callback(40, "Decrypting data with AES...")
        decrypt_start = time.time()
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        padding_length = padded_data[-1]
        compressed_data = padded_data[:-padding_length]
        st.write(f"AES decryption time: {time.time() - decrypt_start:.2f} seconds")

        progress_callback(60, "Decompressing data...")
        decompress_start = time.time()
        if file_type in ["pdf", "txt", "docx"]:
            processed_bytes = lzma.decompress(compressed_data)
        else:  # csv with hybrid decompression
            progress_callback(65, "Decompressing LZMA (Stage 1)...")
            lzma_decompressed = lzma.decompress(compressed_data)
            progress_callback(70, "Decompressing zstd (Stage 2)...")
            dctx = zstd.ZstdDecompressor()
            processed_bytes = dctx.decompress(lzma_decompressed)
        st.write(f"Decompression time: {time.time() - decompress_start:.2f} seconds")

        if file_type == "pdf":
            if not processed_bytes.startswith(b'%PDF'):
                raise Exception("Decoded data is not a valid PDF")
            file_bytes = processed_bytes
        elif file_type == "docx":
            file_bytes = processed_bytes
        else:  # txt, csv
            file_bytes = processed_bytes

        total_time = time.time() - start_time
        st.write(f"Total decoding time: {total_time:.2f} seconds")
        progress_callback(100, "Complete!")
        return file_bytes, file_type
    except Exception as e:
        raise Exception(f"Decoding failed: {str(e)}")

def auto_download(file_data, file_name, mime_type):
    """Save the file to disk and trigger an auto-download using JavaScript."""
    temp_file_path = f"temp_{file_name}"
    with open(temp_file_path, "wb") as f:
        f.write(file_data)
    with open(temp_file_path, "rb") as f:
        file_bytes = f.read()
    b64 = base64.b64encode(file_bytes).decode()
    js = f"""
    <script>
    var link = document.createElement('a');
    link.href = 'data:{mime_type};base64,{b64}';
    link.download = '{file_name}';
    link.click();
    </script>
    """
    components.html(js, height=0)
    os.remove(temp_file_path)

def create_zip_archive(encoded_files_data, encoded_file_names):
    """Create a ZIP file containing all encoded files."""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for data, name in zip(encoded_files_data, encoded_file_names):
            zip_file.writestr(name, data)
    zip_buffer.seek(0)
    return zip_buffer.getvalue()

# Streamlit UI
header = st.container()
header.title("File Encoder/Decoder (RSA-4096)")
header.markdown("Securely compress and encrypt files (PDF, TXT, DOCX, CSV) into binary files with AES-256, protected by RSA-4096 encryption. Max file size: 500 MB per file.")

main = st.container()
tabs = main.tabs(["Encode Files", "Decode Binary"])

with tabs[0]:
    st.subheader("Encode Files to Binary")
    col1, col2 = st.columns([3, 1])
    with col1:
        file_types = ["pdf", "txt", "docx", "csv"]
        uploaded_files = st.file_uploader("Upload Files", type=file_types, key="encode_uploader", accept_multiple_files=True)
        output_prefix = st.text_input("Output Binary Name Prefix", value="encoded", key="encode_name")
    with col2:
        compression_strength = st.selectbox("Compression Strength", ["Light", "Medium", "Heavy"], index=1, key="encode_strength")

    encode_button = st.button("Encode", key="encode_button")

    if uploaded_files and output_prefix and encode_button:
        total_files = len(uploaded_files)
        if total_files == 0:
            st.error("No files uploaded!")
        else:
            progress_bar = st.progress(0)
            status_text = st.empty()
            error_expander = st.expander("Error Details", expanded=False)
            st.session_state.private_keys = []
            st.session_state.encoded_files_data = []
            st.session_state.encoded_file_names = []

            def update_progress(value, text):
                progress_bar.progress(value)
                status_text.text(text)

            with st.spinner(f"Processing {total_files} file(s)..."):
                for idx, uploaded_file in enumerate(uploaded_files):
                    file_size_mb = len(uploaded_file.read()) / (1024 * 1024)
                    uploaded_file.seek(0)
                    if file_size_mb > 500:
                        st.error(f"File '{uploaded_file.name}' exceeds 500 MB limit!")
                        continue

                    file_bytes = uploaded_file.read()
                    file_type = uploaded_file.name.split('.')[-1].lower()
                    try:
                        if file_type not in file_types:
                            raise ValueError("Unsupported file type")
                        if file_type == "pdf" and not file_bytes.startswith(b'%PDF'):
                            raise ValueError("Invalid PDF file")

                        # Adjust progress for multiple files
                        base_progress = (idx / total_files) * 100
                        def file_progress(sub_value, text):
                            adjusted_value = int(base_progress + (sub_value / total_files))
                            update_progress(min(adjusted_value, 100), f"Processing {uploaded_file.name}: {text}")

                        encrypted_data, private_pem, stats = encode_file_to_binary(file_bytes, file_type, compression_strength, file_progress)
                        final_output_name = f"{output_prefix}_{idx + 1}.bin" if total_files > 1 else f"{output_prefix}.bin"
                        st.session_state.private_keys.append(private_pem)
                        st.session_state.encoded_files_data.append(encrypted_data)
                        st.session_state.encoded_file_names.append(final_output_name)

                        st.success(f"Encoded '{uploaded_file.name}' successfully! Size reduced by {stats['size_reduction_percent']:.2f}%")
                        st.write(f"Original size: {stats['original_size']:.2f} KB, Final size: {stats['final_size']:.2f} KB")

                    except Exception as e:
                        st.error(f"Encoding failed for '{uploaded_file.name}'!")
                        with error_expander:
                            st.write(str(e))

                # Display results
                if st.session_state.encoded_files_data:
                    st.session_state.encode_key_displayed = True
                    for i, (private_pem, encrypted_data, final_output_name) in enumerate(zip(st.session_state.private_keys, st.session_state.encoded_files_data, st.session_state.encoded_file_names)):
                        with st.expander(f"RSA-4096 Private Key for File {i + 1} (No Headers)", expanded=True):
                            st.code(private_pem, language="text")
                            if st.button(f"Copy Key {i + 1}", key=f"copy_key_button_{i}"):
                                js = f"""
                                <script>
                                function copyToClipboard() {{
                                    var text = `{private_pem}`;
                                    navigator.clipboard.writeText(text).then(function() {{
                                        document.getElementById('copied-message-{i}').style.display = 'block';
                                        setTimeout(function() {{
                                            document.getElementById('copied-message-{i}').style.display = 'none';
                                        }}, 2000);
                                    }});
                                }}
                                </script>
                                <button onclick="copyToClipboard()">Copy Key</button>
                                <span id="copied-message-{i}" style="display:none; color:green; font-size:small; margin-left:10px;">Copied</span>
                                """
                                components.html(js, height=50)

                        st.download_button(
                            label=f"Download {final_output_name}",
                            data=encrypted_data,
                            file_name=final_output_name,
                            mime="application/octet-stream",
                            key=f"download_button_{i}"
                        )
                        auto_download(encrypted_data, final_output_name, "application/octet-stream")

                    # Option to download all as ZIP
                    if len(st.session_state.encoded_files_data) > 1:
                        zip_data = create_zip_archive(st.session_state.encoded_files_data, st.session_state.encoded_file_names)
                        st.download_button(
                            label="Download All as ZIP",
                            data=zip_data,
                            file_name=f"{output_prefix}_all.zip",
                            mime="application/zip",
                            key="download_zip_button"
                        )

with tabs[1]:
    st.subheader("Decode Binary to File")
    col1, col2 = st.columns([3, 1])
    with col1:
        bin_file = st.file_uploader("Upload Binary", type=["bin"], key="decode_uploader")
        output_name = st.text_input("Output File Name", value="decoded", key="decode_name")
    with col2:
        private_pem = st.text_area("RSA-4096 Private Key (No Headers)", height=150, key="decode_key")

    decode_button = st.button("Decode", key="decode_button")
    
    if bin_file and output_name and private_pem and decode_button:
        file_size_mb = len(bin_file.read()) / (1024 * 1024)
        bin_file.seek(0)
        if file_size_mb > 500:
            st.error("File size exceeds 500 MB limit!")
        else:
            progress_bar = st.progress(0)
            status_text = st.empty()
            error_expander = st.expander("Error Details", expanded=False)
            
            def update_progress(value, text):
                progress_bar.progress(value)
                status_text.text(text)

            file_hash = hashlib.sha256(bin_file.read()).hexdigest()
            bin_file.seek(0)
            if file_hash not in st.session_state.attempts:
                st.session_state.attempts[file_hash] = 0
            st.session_state.attempts[file_hash] += 1

            if st.session_state.attempts[file_hash] > 2:
                st.error("Maximum attempts exceeded! This file is now locked.")
            else:
                with st.spinner("Processing..."):
                    encrypted_data = bin_file.read()
                    try:
                        file_bytes, file_type = decode_binary_to_file(encrypted_data, private_pem, update_progress)
                        st.success("Decoded successfully!")
                        
                        mime_types = {
                            "pdf": "application/pdf",
                            "txt": "text/plain",
                            "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            "csv": "text/csv"
                        }
                        final_output_name = output_name if output_name.endswith(f'.{file_type}') else f"{output_name}.{file_type}"
                        
                        st.download_button(
                            label="Download Decoded File",
                            data=file_bytes,
                            file_name=final_output_name,
                            mime=mime_types[file_type]
                        )
                        st.session_state.attempts.pop(file_hash, None)
                        st.session_state.reset = True
                        st.query_params.clear()
                    except Exception as e:
                        remaining = 2 - st.session_state.attempts[file_hash]
                        st.error(f"Decoding failed! {remaining} attempt(s) remaining.")
                        with error_expander:
                            st.write(str(e))
                        if st.session_state.attempts[file_hash] >= 2:
                            st.warning("File locked due to repeated failed attempts.")

footer = st.container()
footer.markdown("---")
footer.markdown("© 2025 ADIRON")

if st.session_state.reset:
    st.session_state.reset = False
    st.query_params.clear()