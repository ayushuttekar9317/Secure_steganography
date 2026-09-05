import io
import json
import os
from typing import Optional
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from PIL import Image

from core import (
    TYPE_TEXT,
    TYPE_FILE,
    HEADER_SIZE,
    GCM_TAG_LEN,
    image_capacity_bytes,
    build_payload,
    embed_payload,
    extract_payload,
    decode_payload,
    calculate_mse,
    calculate_psnr,
    calculate_lsb_balance,
)

app = FastAPI(title="Secure Image Steganography API")

# Mount static frontend
os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    with open("static/index.html", "r", encoding="utf-8") as f:
        return f.read()


@app.post("/api/capacity")
async def check_capacity(image: UploadFile = File(...)):
    try:
        contents = await image.read()
        img = Image.open(io.BytesIO(contents))
        capacity = image_capacity_bytes(img)
        return {
            "width": img.width,
            "height": img.height,
            "capacity_bytes": capacity,
            "capacity_kb": round(capacity / 1024, 2),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/encode")
async def encode_endpoint(
    image: UploadFile = File(...),
    password: str = Form(...),
    payload_type: str = Form(...),  # 'text' or 'file'
    secret_text: Optional[str] = Form(None),
    secret_file: Optional[UploadFile] = File(None),
):
    try:
        img_bytes = await image.read()
        cover_image = Image.open(io.BytesIO(img_bytes))

        if payload_type == "text":
            if not secret_text:
                raise ValueError("Secret text cannot be empty.")
            data = secret_text.encode("utf-8")
            p_type = TYPE_TEXT
            filename = ""
        elif payload_type == "file":
            if not secret_file:
                raise ValueError("Secret file was not uploaded.")
            data = await secret_file.read()
            p_type = TYPE_FILE
            filename = secret_file.filename or "secret_file"
        else:
            raise ValueError("Invalid payload type.")

        capacity = image_capacity_bytes(cover_image)
        expected_size = HEADER_SIZE + len(filename.encode("utf-8")) + len(data) + GCM_TAG_LEN

        if expected_size > capacity:
            raise ValueError(
                f"Payload too large. Required: {expected_size:,} bytes, Available: {capacity:,} bytes"
            )

        payload = build_payload(data, password, p_type, filename)
        stego_image = embed_payload(cover_image, payload)

        output_io = io.BytesIO()
        stego_image.save(output_io, format="PNG")
        output_io.seek(0)

        out_name = f"{os.path.splitext(image.filename)[0]}_stego.png"
        return StreamingResponse(
            output_io,
            media_type="image/png",
            headers={"Content-Disposition": f'attachment; filename="{out_name}"'},
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/decode")
async def decode_endpoint(
    image: UploadFile = File(...),
    password: str = Form(...),
):
    try:
        img_bytes = await image.read()
        stego_image = Image.open(io.BytesIO(img_bytes))

        payload, meta = extract_payload(stego_image)
        plaintext, filename = decode_payload(payload, meta, password)

        if meta["payload_type"] == TYPE_TEXT:
            return JSONResponse({
                "type": "text",
                "content": plaintext.decode("utf-8"),
                "size_bytes": len(plaintext),
            })
        else:
            file_io = io.BytesIO(plaintext)
            file_io.seek(0)
            return StreamingResponse(
                file_io,
                media_type="application/octet-stream",
                headers={"Content-Disposition": f'attachment; filename="{filename or "extracted_file"}"'},
            )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/analyze")
async def analyze_endpoint(
    original: UploadFile = File(...),
    stego: UploadFile = File(...),
):
    try:
        orig_bytes = await original.read()
        stego_bytes = await stego.read()

        orig_img = Image.open(io.BytesIO(orig_bytes))
        stego_img = Image.open(io.BytesIO(stego_bytes))

        if orig_img.size != stego_img.size:
            raise ValueError(f"Image dimension mismatch: {orig_img.size} vs {stego_img.size}")

        mse = calculate_mse(orig_img, stego_img)
        psnr = calculate_psnr(mse)
        lsb_orig = calculate_lsb_balance(orig_img)
        lsb_stego = calculate_lsb_balance(stego_img)

        return {
            "dimensions": f"{orig_img.width} × {orig_img.height}",
            "original_file_size": len(orig_bytes),
            "stego_file_size": len(stego_bytes),
            "mse": round(mse, 8),
            "psnr": "∞" if math.isinf(psnr) else f"{psnr:.4f} dB",
            "original_lsb_balance": round(lsb_orig, 4),
            "stego_lsb_balance": round(lsb_stego, 4),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    from core import MAGIC, TYPE_TEXT, HEADER_SIZE, extract_bytes, parse_header
@app.post("/api/detect")
async def detect_endpoint(image: UploadFile = File(...)):
    # 1. Imports placed locally to guarantee they exist
    from core import MAGIC, TYPE_TEXT, HEADER_SIZE, extract_bytes, parse_header, calculate_lsb_balance
    import io
    from PIL import Image
    
    try:
        img_bytes = await image.read()
        img = Image.open(io.BytesIO(img_bytes))
        
        lsb_balance = calculate_lsb_balance(img)
        has_payload = False
        details = "No recognizable payload found."
        
        # 2. Extract header without swallowing critical errors
        try:
            header = extract_bytes(img, HEADER_SIZE)
            
            if header.startswith(MAGIC):
                has_payload = True
                try:
                    meta = parse_header(header)
                    p_type = "Text Message" if meta["payload_type"] == TYPE_TEXT else "File"
                    details = f"CryptoSteg Payload Detected! Type: {p_type} | Encrypted Size: {meta['ciphertext_len']} bytes."
                except Exception:
                    details = "CryptoSteg Magic Header found, but metadata is corrupted."
                    
        except ValueError:
            # It is safe to ignore ValueError here (happens only if image is smaller than 40 bytes)
            pass
            
        suspicious = False
        if 48.0 <= lsb_balance <= 52.0 and not has_payload:
            suspicious = True
            
        return {
            "has_payload": has_payload,
            "details": details,
            "lsb_balance": round(lsb_balance, 2),
            "suspicious": suspicious
        }
    except Exception as e:
        # 3. If there is a real error, push it to the frontend UI as a red alert
        raise HTTPException(status_code=400, detail=f"Detection Error: {str(e)}")