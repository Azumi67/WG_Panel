
import re
import requests
from . import service as s

MAX_PHOTO=5*1024*1024

def fetch_photo(order_id):
    from .worker import telegram
    receipt=s.setting('receipt_photo:'+str(order_id))
    if receipt and receipt.get('source') == 'workspace':
        from .models import OrderReceipt
        from models import db
        stored = db.session.get(OrderReceipt, order_id)
        if not stored:
            raise ValueError('Receipt image is unavailable.')
        return s.cipher().decrypt(stored.image_enc), stored.mime
    encrypted=s.setting('bot_token')
    if not receipt or not encrypted:raise ValueError('Receipt image is unavailable.')
    token=s.decrypt(encrypted)
    try:
        info=telegram(token,'getFile',{'file_id':receipt['file_id']})
        path=str(info.get('file_path',''))
        if not re.fullmatch(r'photos/[A-Za-z0-9_-]+\.(?:jpg|jpeg|png)',path) or int(info.get('file_size',0))>MAX_PHOTO:
            raise ValueError('Unsupported receipt image.')
        with requests.get('https://api.telegram.org/file/bot'+token+'/'+path,timeout=(5,15),stream=True,allow_redirects=False) as response:
            if response.status_code!=200:raise ValueError('Receipt could not be retrieved. Try again later.')
            data=bytearray()
            for chunk in response.iter_content(65536):
                data.extend(chunk)
                if len(data)>MAX_PHOTO:raise ValueError('Receipt exceeds the image size limit.')
        mime='image/jpeg' if data.startswith(b'\xff\xd8\xff') else 'image/png' if data.startswith(b'\x89PNG\r\n\x1a\n') else None
        if not mime:raise ValueError('Unsupported receipt image.')
        return bytes(data),mime
    except (requests.RequestException,RuntimeError,KeyError,TypeError):
        raise ValueError('Telegram receipt is temporarily unavailable. Please retry later.') from None


def photo_response(oid):
    from flask import Response
    data, mime = fetch_photo(oid)
    return Response(data, mimetype=mime, headers={'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff',
                    'Content-Disposition':'inline; filename="receipt"', 'Content-Security-Policy':"default-src 'none'; sandbox"})
