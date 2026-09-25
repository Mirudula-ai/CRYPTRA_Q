import numpy as np
import cv2
from PIL import Image
import io
import json

def embed(img, data, block_size=4, delta=30):
    bits = ''.join(f"{b:08b}" for b in data)
    
    needed_pixels = len(bits) * 2 * block_size * block_size
    if needed_pixels > img.shape[0] * img.shape[1] * img.shape[2]:
        print("Image too small!")
        return None
        
    out_img = img.copy().astype(np.float32)
    H, W, _ = img.shape
    b_size = block_size
    
    bit_idx = 0
    for y in range(0, H - b_size + 1, b_size):
        if bit_idx >= len(bits): break
        for x in range(0, W - 2*b_size + 1, 2*b_size):
            if bit_idx >= len(bits): break
            
            blockA = out_img[y:y+b_size, x:x+b_size, 2] # Blue channel
            blockB = out_img[y:y+b_size, x+b_size:x+2*b_size, 2]
            
            meanA = np.mean(blockA)
            meanB = np.mean(blockB)
            
            bit = int(bits[bit_idx])
            if bit == 1:
                diff = meanA - meanB
                if diff < delta:
                    shift = (delta - diff) / 2
                    out_img[y:y+b_size, x:x+b_size, 2] += shift
                    out_img[y:y+b_size, x+b_size:x+2*b_size, 2] -= shift
            else:
                diff = meanB - meanA
                if diff < delta:
                    shift = (delta - diff) / 2
                    out_img[y:y+b_size, x+b_size:x+2*b_size, 2] += shift
                    out_img[y:y+b_size, x:x+b_size, 2] -= shift
                    
            bit_idx += 1
            
    out_img = np.clip(out_img, 0, 255).astype(np.uint8)
    return out_img

def extract(img, expected_bytes, block_size=4):
    bits = ""
    H, W, _ = img.shape
    b_size = block_size
    
    total_bits = expected_bytes * 8
    
    for y in range(0, H - b_size + 1, b_size):
        if len(bits) >= total_bits: break
        for x in range(0, W - 2*b_size + 1, 2*b_size):
            if len(bits) >= total_bits: break
            
            blockA = img[y:y+b_size, x:x+b_size, 2]
            blockB = img[y:y+b_size, x+b_size:x+2*b_size, 2]
            
            meanA = np.mean(blockA)
            meanB = np.mean(blockB)
            
            if meanA > meanB:
                bits += "1"
            else:
                bits += "0"
                
    data = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
    return data

img = np.zeros((500, 500, 3), dtype=np.uint8)
for y in range(500):
    for x in range(500):
        img[y, x] = [int(255 * x / 500), int(255 * y / 500), 128]

payload = b"STEG" + (500).to_bytes(4, 'big') + b"A"*500
print(f"Payload size: {len(payload)} bytes")

embedded = embed(img, payload, block_size=4, delta=30)
if embedded is None:
    print("FAILED TO EMBED")
    exit(1)

pil_img = Image.fromarray(embedded)
buf = io.BytesIO()
pil_img.save(buf, format="JPEG", quality=95)
jpg_bytes = buf.getvalue()

pil_jpg = Image.open(io.BytesIO(jpg_bytes))
jpg_array = np.array(pil_jpg)

extracted = extract(jpg_array, len(payload), block_size=4)
if extracted == payload:
    print("Success!")
else:
    print("Failed! Found", extracted[:20])
