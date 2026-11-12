import logging
import re
import whois
from datetime import datetime, timezone
from urllib.parse import urlparse
THAI_BLACKLIST = {
    'faepass.cc',
    'th-post-verify.com',
    'kbank-secure.xyz',
}

# ============================================
# CONFIG
# ============================================

SUSPICIOUS_TLDS = [
    '.xyz', '.tk', '.ml', '.ga', '.cf', '.top',
    '.click', '.link', '.site', '.online', '.fun',
    '.cc', '.cn', '.asia'    
]

SHORT_URL_DOMAINS = [
    'cutt.ly', 'bit.ly', 'rls.my', 'lihi.cc',
    'go123.co', 'shorturl.asia', 'sourl.cn',
    'linkbio.co', 'url.in.th', 'tmn.co',
    'ttid.co', 'ss.true.th', 'iservice.page.link'
]

BRAND_KEYWORDS = {
    'kbank': 'KBANK (กสิกรไทย)',
    'kasikorn': 'KBANK (กสิกรไทย)',
    'scb': 'SCB (ไทยพาณิชย์)',
    'bangkokbank': 'Bangkok Bank',
    'bbl': 'Bangkok Bank',
    'ktb': 'KTB (กรุงไทย)',
    'krungthai': 'KTB (กรุงไทย)',
    'tmb': 'TMB (ทหารไทย)',
    'gsb': 'GSB (ออมสิน)',
    'baac': 'BAAC (ธกส.)',
    'ttb': 'TTB (ทหารไทยธนชาต)',
    'thaipost': 'ไปรษณีย์ไทย',
    'thailandpost': 'ไปรษณีย์ไทย',
    'th-post': 'ไปรษณีย์ไทย',
    'dsi': 'DSI (กรมสอบสวน)',
    'revenue': 'กรมสรรพากร',
    'rd.go': 'กรมสรรพากร',
    'sso.go': 'ประกันสังคม',
    'apple': 'Apple',
    'tiktok': 'TikTok',
    'line': 'LINE',
    'facebook': 'Facebook',
    'lazada': 'Lazada',
    'shopee': 'Shopee',
    'truemoney': 'TrueMoney',
    'promptpay': 'PromptPay',
    'tidlor': 'Tidlor',
}

# Short or common-word keywords: only count them when they are a whole
# part of the domain (split on "." and "-"). Otherwise "line" would match
# "myonline-shop.com" and "apple" would match "pineapple.com".
BRAND_WHOLE_WORD_ONLY = {
    'scb', 'bbl', 'ktb', 'tmb', 'gsb', 'baac', 'ttb', 'dsi',
    'line', 'apple', 'revenue',
}

OFFICIAL_DOMAINS = [
    'kasikornbank.com', 'kbank.co.th',
    'scb.co.th', 'bangkokbank.com',
    'ktb.co.th', 'gsb.or.th',
    'thailandpost.co.th', 'rd.go.th',
    'sso.go.th', 'lazada.co.th',
    'shopee.co.th', 'line.me',
    'apple.com', 'tiktok.com',
    'tidlor.com',
]

CREDENTIAL_KEYWORDS = [
    'verify', 'login', 'signin', 'password', 'confirm',
    'otp', 'secure', 'account', 'banking', 'wallet',
    'credential', 'pin', 'atm', 'update', 'validate',
    'register', 'withdraw', 'deposit', 'bonus'
]

# Same idea as BRAND_WHOLE_WORD_ONLY: "pin" is inside "opinion",
# "atm" inside "atmosphere", "otp" inside "hotpot".
CREDENTIAL_WHOLE_WORD_ONLY = {'pin', 'atm', 'otp'}

# ============================================
# SCORE CONSTANTS
# ============================================

SCORE_SHORT_URL = 25
SCORE_DOMAIN_VERY_NEW = 35
SCORE_DOMAIN_YOUNG = 15
SCORE_DOMAIN_UNKNOWN = 20
SCORE_BRAND_IMPERSONATION = 35
SCORE_TLD_CC = 35
SCORE_TLD_SUSPICIOUS = 25
SCORE_CREDENTIAL_MULTI = 20
SCORE_CREDENTIAL_SINGLE = 8
SCORE_BLACKLIST = 40
SCORE_COMBO_BRAND_FORM = 15
SCORE_COMBO_BRAND_UNKNOWN_DOMAIN = 15
SCORE_COMBO_SHORT_URL = 15

RISK_MAX = 100
RISK_THRESHOLD_DANGER = 70
RISK_THRESHOLD_WARN = 25

DOMAIN_AGE_VERY_NEW_DAYS = 30
DOMAIN_AGE_YOUNG_DAYS = 180
CREDENTIAL_MULTI_MIN = 2

WHOIS_TIMEOUT_SECONDS = 5

# ============================================
# HELPERS
# ============================================

def _tokens(text: str) -> list[str]:
    """Split a domain or path into its word parts: 'th-post.verify.com' -> ['th', 'post', 'verify', 'com']."""
    return [t for t in re.split(r'[^a-z0-9]+', text.lower()) if t]


def _keyword_found(keyword: str, text: str, whole_word_only: set) -> bool:
    if keyword in whole_word_only:
        return keyword in _tokens(text)
    return keyword in text


def _is_domain_or_subdomain(domain: str, base: str) -> bool:
    """True for 'kbank.co.th' or 'www.kbank.co.th', but NOT 'fakekbank.co.th'."""
    return domain == base or domain.endswith('.' + base)

# ============================================
# MAIN FUNCTION
# ============================================

def _normalize_url(url: str) -> tuple[str, str, str]:
    """Return (normalized_url, domain, path)."""
    url = url.strip()
    # case-insensitive: "HTTPS://..." must not become "https://HTTPS://..."
    if not re.match(r'^https?://', url, re.IGNORECASE):
        url = 'https://' + url
    parsed = urlparse(url)
    # .hostname (not .netloc) drops any port and "user@" part, so
    # "https://kbank.co.th@evil.xyz" is read as evil.xyz — where it really goes.
    domain = (parsed.hostname or '').lower()
    return url, domain, parsed.path.lower()


def _calculate_score(short_result, age_result, brand_result, tld_result, form_result, phish_result) -> int:
    """Apply base scores and combo bonuses, return capped risk score."""
    score = (
        short_result['score']
        + age_result['score']
        + brand_result['score']
        + tld_result['score']
        + form_result['score']
        + (phish_result['score'] if phish_result else 0)
    )

    if brand_result['score'] > 0 and form_result['score'] > 0:
        score += SCORE_COMBO_BRAND_FORM
    if brand_result['score'] > 0 and age_result['score'] == SCORE_DOMAIN_UNKNOWN:
        score += SCORE_COMBO_BRAND_UNKNOWN_DOMAIN
    # Short URL alone is low risk; short URL + other signals earns bonus
    if short_result['score'] > 0 and score > SCORE_SHORT_URL:
        score += SCORE_COMBO_SHORT_URL

    # A confirmed phishing domain is always dangerous, even with no other signals
    if phish_result:
        score = max(score, RISK_THRESHOLD_DANGER)

    return min(score, RISK_MAX)


def _get_verdict(risk: int, checks: list) -> tuple[str, str]:
    """Return (verdict_type, verdict_label) from risk score."""
    if risk >= RISK_THRESHOLD_DANGER:
        return 'danger', get_danger_label(checks)
    if risk >= RISK_THRESHOLD_WARN:
        return 'warn', 'น่าสงสัย — ควรระวัง'
    return 'safe', 'ปลอดภัย — ไม่พบสัญญาณอันตราย'


def scan_url(url: str) -> dict:
    url, domain, path = _normalize_url(url)

    short_result = check_short_url(domain)
    age_result = check_domain_age(domain)
    brand_result = check_brand_impersonation(domain)
    tld_result = check_suspicious_tld(domain)
    form_result = check_credential_keywords(domain, path)
    phish_result = check_phishing_db(domain)

    checks = [r['check'] for r in (short_result, age_result, brand_result, tld_result, form_result)]
    if phish_result:
        checks.append(phish_result['check'])

    risk = _calculate_score(short_result, age_result, brand_result, tld_result, form_result, phish_result)
    verdict_type, verdict_label = _get_verdict(risk, checks)

    return {
        'url': url,
        'risk': risk,
        'verdict': verdict_label,
        'type': verdict_type,
        'checks': checks
    }

# ============================================
# CHECK FUNCTIONS
# ============================================
def check_short_url(domain) -> dict:
    for short in SHORT_URL_DOMAINS:
        if _is_domain_or_subdomain(domain, short):
            return {
                'score': SCORE_SHORT_URL,
                'check': {
                    'kind': 'warn',
                    'title': 'Short URL',
                    'sub': 'ลิงก์ย่อซ่อนปลายทางจริง ไม่รู้ว่าจะพาไปไหน',
                    'val': 'Hidden'
                }
            }
    return {
        'score': 0,
        'check': {
            'kind': 'ok',
            'title': 'Short URL',
            'sub': 'ไม่ใช่ลิงก์ย่อ สามารถเห็นปลายทางได้',
            'val': 'ปกติ'
        }
    }


def check_domain_age(domain) -> dict:
    try:
        # a slow WHOIS server must not hold the request thread for long
        w = whois.whois(domain, timeout=WHOIS_TIMEOUT_SECONDS)
        creation = getattr(w, 'creation_date', None)
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            # make aware both before comparing
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - creation).days
            if age_days < DOMAIN_AGE_VERY_NEW_DAYS:
                return {
                    'score': SCORE_DOMAIN_VERY_NEW,
                    'check': {
                        'kind': 'bad',
                        'title': 'Domain Age',
                        'sub': f'จดทะเบียนเมื่อ {age_days} วันที่แล้ว',
                        'val': f'{age_days} วัน'
                    }
                }
            elif age_days < DOMAIN_AGE_YOUNG_DAYS:
                return {
                    'score': SCORE_DOMAIN_YOUNG,
                    'check': {
                        'kind': 'warn',
                        'title': 'Domain Age',
                        'sub': f'domain อายุน้อย ({age_days} วัน)',
                        'val': f'{age_days} วัน'
                    }
                }
            else:
                years = age_days // 365
                return {
                    'score': 0,
                    'check': {
                        'kind': 'ok',
                        'title': 'Domain Age',
                        'sub': f'จดทะเบียนมานานแล้ว น่าเชื่อถือ',
                        'val': f'{years} ปี'
                    }
                }
    except Exception as e:
        logging.warning("Domain age check failed for %s: %s", domain, e)

    return {
        'score': SCORE_DOMAIN_UNKNOWN,
        'check': {
            'kind': 'warn',
            'title': 'Domain Age',
            'sub': 'ไม่พบข้อมูล domain — อาจเป็น domain ใหม่หรือซ่อนข้อมูล WHOIS',
            'val': 'ไม่ทราบ'
        }
    }


def check_brand_impersonation(domain) -> dict:
    for keyword, brand_name in BRAND_KEYWORDS.items():
        if _keyword_found(keyword, domain, BRAND_WHOLE_WORD_ONLY):
            is_official = any(_is_domain_or_subdomain(domain, od) for od in OFFICIAL_DOMAINS)
            if not is_official:
                return {
                    'score': SCORE_BRAND_IMPERSONATION,
                    'check': {
                        'kind': 'bad',
                        'title': 'Brand Impersonation',
                        'sub': f'ใช้ชื่อ {brand_name} โดยไม่ได้รับอนุญาต',
                        'val': brand_name.split()[0]
                    }
                }

    return {
        'score': 0,
        'check': {
            'kind': 'ok',
            'title': 'Brand Impersonation',
            'sub': 'ไม่พบการแอบอ้างแบรนด์',
            'val': 'ปกติ'
        }
    }


def check_suspicious_tld(domain) -> dict:
    for tld in SUSPICIOUS_TLDS:
        # only the real ending counts: "www.cnn.com" must not match ".cn",
        # "linkedin.com" must not match ".link"
        if domain.endswith(tld):
            score = SCORE_TLD_CC if tld == '.cc' else SCORE_TLD_SUSPICIOUS
            return {
                'score': score,
                'check': {
                    'kind': 'bad',
                    'title': 'TLD Suspicious',
                    'sub': f'{tld} ถูกใช้ใน scam บ่อยมาก',
                    'val': tld
                        }
                    }

    return {
        'score': 0,
        'check': {
            'kind': 'ok',
            'title': 'TLD Suspicious',
            'sub': 'TLD ปกติ ไม่น่าสงสัย',
            'val': 'ปกติ'
        }
    }


def check_credential_keywords(domain, path) -> dict:
    full = domain + path
    found = [kw for kw in CREDENTIAL_KEYWORDS
             if _keyword_found(kw, full, CREDENTIAL_WHOLE_WORD_ONLY)]
    if len(found) >= CREDENTIAL_MULTI_MIN:
        return {
            'score': SCORE_CREDENTIAL_MULTI,
            'check': {
                'kind': 'bad',
                'title': 'Form Analysis',
                'sub': f'พบ keyword น่าสงสัย: {", ".join(found[:3])}',
                'val': 'Credential'
            }
        }
    elif len(found) == 1:
        return {
            'score': SCORE_CREDENTIAL_SINGLE,
            'check': {
                'kind': 'warn',
                'title': 'Form Analysis',
                'sub': f'พบ keyword: {found[0]}',
                'val': 'ระวัง'
            }
        }

    return {
        'score': 0,
        'check': {
            'kind': 'ok',
            'title': 'Form Analysis',
            'sub': 'ไม่พบ keyword ที่น่าสงสัย',
            'val': 'ปกติ'
        }
    }

def check_phishing_db(domain: str) -> dict | None:
    if any(_is_domain_or_subdomain(domain, bad) for bad in THAI_BLACKLIST):
        return {
            'score': SCORE_BLACKLIST,
            'check': {
                'kind': 'bad',
                'title': 'Blacklist DB',
                'sub': 'พบใน CyberSense Threat Database',
                'val': 'MATCH'
            }
        }
    return None

def get_danger_label(checks) -> str:
    for c in checks:
        if c.get('title') == 'Brand Impersonation' and c.get('kind') == 'bad':
            val = c.get('val', '')
            if any(b in val for b in ['KBANK', 'SCB', 'KTB', 'BBL', 'GSB']):
                return 'อันตราย — Banking Phishing'
            return f'อันตราย — แอบอ้าง {val}'
    return 'อันตราย — Phishing Site'

# ============================================
# TEST url_scanner
# ============================================
if __name__ == "__main__":
    import json
    test_url = "cutt.ly/9xbb"
    result = scan_url(test_url)
    print(json.dumps(result, ensure_ascii=False, indent=2))