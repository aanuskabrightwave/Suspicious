# import pytesseract
# from PIL import Image
# import io
# import base64

# ======================================
# AYUSH WORK AREA
# Implement OCR using Tesseract or Google Cloud Vision
# Decode base64 images and extract text for scam analysis
# ======================================

def extract_text_from_image(image_base64: str) -> str:
    """
    Extracts text from a base64 encoded image string.
    """
    try:
        # Starter stub:
        # image_data = base64.b64decode(image_base64)
        # image = Image.open(io.BytesIO(image_data))
        # text = pytesseract.image_to_string(image)
        # return text
        
        return "mock_extracted_text_from_image"
    except Exception as e:
        print(f"OCR Error: {e}")
        return ""
