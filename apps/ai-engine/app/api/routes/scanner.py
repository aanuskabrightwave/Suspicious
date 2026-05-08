from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.services.phishing_detector import analyze_url
from app.services.ocr_service import extract_text_from_image

# ======================================
# AYUSH WORK AREA
# Define API endpoints for the backend to consume
# Validate inputs using Pydantic schemas
# ======================================

router = APIRouter()

class UrlScanRequest(BaseModel):
    url: str

class ImageScanRequest(BaseModel):
    image_base64: str

@router.post("/url")
async def scan_url(request: UrlScanRequest):
    try:
        result = await analyze_url(request.url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/qr")
async def scan_qr(request: ImageScanRequest):
    # TODO: Pass image to OCR service, then to phishing detector
    extracted_text = extract_text_from_image(request.image_base64)
    # result = await analyze_url(extracted_text)
    return {"status": "pending", "extracted": extracted_text}
