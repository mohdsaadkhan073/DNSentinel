import os
from fastapi import APIRouter, UploadFile, File, HTTPException

from config import UPLOAD_DIR
from schemas import PassiveUploadResult
from services.passive_service import mock_pcap_result

router = APIRouter(prefix="/api/v1/passive", tags=["passive"])

ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".tsv"}


@router.post("/upload-pcap", response_model=PassiveUploadResult)
async def upload_pcap(file: UploadFile = File(...)):
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Unsupported file type '{ext}'. Allowed: .pcap, .pcapng, .tsv")

    dest_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(dest_path, "wb") as f:
        while chunk := await file.read(1024 * 1024):
            f.write(chunk)

    # TODO(Member 5): replace mock_pcap_result with the real passive analyzer output.
    return mock_pcap_result(file.filename)
