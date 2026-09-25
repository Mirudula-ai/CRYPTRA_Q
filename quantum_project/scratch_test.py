import sys
import os

# Add cryptraq to path
sys.path.insert(0, os.path.abspath('.'))

import json
from cryptraq.encryption.steganography import SteganographyManager
from cryptraq.pdf_security import build_encrypted_mission_pdf
import fitz
from PIL import Image
import io
import numpy as np

def test():
    token = "test-token"
    public_key_hex = "0"*64
    hmac_tag = "0"*80
    expiration = 1234567890
    session_id = "test-session"
    session_key = "12345678901234567890123456789012"
    user_password = "password"
    encrypted_payload = "enc_payload_here_something_long_enough"

    print("Generating PDF...")
    pdf_bytes, otc = build_encrypted_mission_pdf(
        token, public_key_hex, hmac_tag, expiration, session_id, session_key, user_password, encrypted_payload
    )
    
    print("PDF generated. Extracting image...")
    # Simulate receiver
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    doc.authenticate(user_password)
    img_pil = None
    extracted_data = None
    for page_index in range(len(doc)):
        page = doc[page_index]
        image_list = page.get_images(full=True)
        for img_info in image_list:
            xref = img_info[0]
            base_image = doc.extract_image(xref)
            image_bytes = base_image["image"]
            try:
                tmp_pil = Image.open(io.BytesIO(image_bytes)).convert('RGB')
                tmp_array = np.array(tmp_pil)
                ext = SteganographyManager.extract_data(tmp_array)
                if ext:
                    img_pil = tmp_pil
                    extracted_data = ext.decode('utf-8')
                    break
            except Exception as e:
                print(e)
                pass
        if img_pil:
            break
            
    if extracted_data:
        print("Extracted Data:", extracted_data)
        steg_dict = json.loads(extracted_data)
        print("Success! e =", steg_dict.get('e'))
    else:
        print("Failed to extract steganographic data from PDF.")

test()
