from .regional import display

_DIGITS = str.maketrans('0123456789.,', '۰۱۲۳۴۵۶۷۸۹٫٬')
_CURRENCIES = {'IRR':'ریال', 'IRT':'تومان', 'TOMAN':'تومان', 'USD':'دلار'}


def number(value):
    return str(value).translate(_DIGITS)


def isolated(value):
    return '\u2068' + str(value) + '\u2069'


def rtl_lines(text):
    return '\n'.join('\u200f' + line if line else '' for line in text.split('\n'))


def persian_price(amount, currency):
    return number(amount) + ' ' + _CURRENCIES.get(currency, isolated(currency))


def persian_time(value):
    date, sep, zone = display(value).rpartition(' ')
    return isolated(number(date)) + ' (' + isolated(zone) + ')' if sep else display(value)
