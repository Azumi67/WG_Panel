from qrcode.image.pure import PyPNGImage


class PNGImage(PyPNGImage):
    def save(self, stream, format=None, kind=None, **kwargs):
        selected = format or kind or 'PNG'
        if selected.upper() != 'PNG':
            raise ValueError('Only PNG output is supported')
        return super().save(stream, kind='PNG')
