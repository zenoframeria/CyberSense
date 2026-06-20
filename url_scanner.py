import logging
import whois
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests

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

# ============================================
# MAIN FUNCTION
# ============================================

def scan_url(url: str) -> dict:
    """
    Input:  URL string
    Output: dict along structure that Frontend want
    """

    # normalize URL
    if not url.startswith('http'):
        url = 'https://' + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    checks = []
    risk_score = 0

    # CHECK 0: Short URL
    short_result = check_short_url(domain)
    checks.append(short_result['check'])
    risk_score += short_result['score']

    # CHECK 1: Domain Age
    age_result = check_domain_age(domain)
    checks.append(age_result['check'])
    risk_score += age_result['score']

    # CHECK 2: Brand Impersonation
    brand_result = check_brand_impersonation(domain)
    checks.append(brand_result['check'])
    risk_score += brand_result['score']

    # CHECK 3: TLD Suspicious
    tld_result = check_suspicious_tld(domain)
    checks.append(tld_result['check'])
    risk_score += tld_result['score']

    # CHECK 4: Form / Credential Analysis (meaning:This URL contains words that indicate it will request important information from us.)
    form_result = check_credential_keywords(domain, path)
    checks.append(form_result['check'])
    risk_score += form_result['score']

    # CHECK 5: PhishTank DB
    phish_result = check_phishing_db(url)
    if phish_result:
        checks.append(phish_result['check'])
        risk_score += phish_result['score']

    # cal final risk and verdict
    # Brand + Form keyword
    if brand_result['score'] > 0 and form_result['score'] > 0:
        risk_score += 15

    # Brand + Domain Unknown
    if brand_result['score'] > 0 and age_result['score'] == 20:
        risk_score += 15

    risk = min(risk_score, 99)  # <= 99 like SMS

    if short_result['score'] > 0 and risk_score == 25:
        # A single short URL with no other signals = warn, but low risk (25 is okay).
        pass  

    elif short_result['score'] > 0 and risk_score > 25:
        # Short URL + have another signals  = more danger (+bonus)
        risk_score += 15

    if risk >= 70:
        verdict_type = 'danger'
        verdict_label = get_danger_label(checks)
    elif risk >= 25:
        verdict_type = 'warn'
        verdict_label = 'น่าสงสัย — ควรระวัง'
    else:
        verdict_type = 'safe'
        verdict_label = 'ปลอดภัย — ไม่พบสัญญาณอันตราย'

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
        if short in domain:
            return {
                'score': 25,
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
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            # make aware both before comparing
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - creation).days
            if age_days < 30:
                return {
                    'score': 35,
                    'check': {
                        'kind': 'bad',
                        'title': 'Domain Age',
                        'sub': f'จดทะเบียนเมื่อ {age_days} วันที่แล้ว',
                        'val': f'{age_days} วัน'
                    }
                }
            elif age_days < 180:
                return {
                    'score': 15,
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
        'score': 20,
        'check': {
            'kind': 'warn',
            'title': 'Domain Age',
            'sub': 'ไม่พบข้อมูล domain — อาจเป็น domain ใหม่หรือซ่อนข้อมูล WHOIS',
            'val': 'ไม่ทราบ'
        }
    }


def check_brand_impersonation(domain) -> dict:
    for keyword, brand_name in BRAND_KEYWORDS.items():
        if keyword in domain:
            is_official = any(domain.endswith(od) for od in OFFICIAL_DOMAINS)
            if not is_official:
                return {
                    'score': 35,
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
        if domain.endswith(tld) or ('.' + tld.strip('.')) in domain:
            score = 35 if tld == '.cc' else 25  # .cc gets higher score
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
    found = [kw for kw in CREDENTIAL_KEYWORDS if kw in full]
    if len(found) >= 2:
        return {
            'score': 20,
            'check': {
                'kind': 'bad',
                'title': 'Form Analysis',
                'sub': f'พบ keyword น่าสงสัย: {", ".join(found[:3])}',
                'val': 'Credential'
            }
        }
    elif len(found) == 1:
        return {
            'score': 8,
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

def check_phishing_db(url: str) -> dict | None:
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    if domain in THAI_BLACKLIST:
        return {
            'score': 40,
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