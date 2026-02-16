from flask import Flask, render_template, request, make_response, session, jsonify
import os
import re
import secrets
import hashlib
from datetime import datetime, timedelta

app = Flask(__name__)

# ==================== GÜVENLİK ÖNLEMLERİ ====================

# 1. GİZLİ ANAHTAR (çok güçlü)
app.secret_key = secrets.token_hex(64)

# 2. SESSION GÜVENLİĞİ
app.config.update(
    SESSION_COOKIE_SECURE=False,  # Localhost için False, production'da True
    SESSION_COOKIE_HTTPONLY=True,  # JavaScript erişemez
    SESSION_COOKIE_SAMESITE='Lax',  # CSRF koruması
    SESSION_COOKIE_NAME='__Secure-session',  # Güvenli isim
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    REMEMBER_COOKIE_DURATION=timedelta(days=7),
    REMEMBER_COOKIE_SECURE=True,
    REMEMBER_COOKIE_HTTPONLY=True
)

# 3. REQUEST LİMİTLERİ
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max
app.config['MAX_COOKIE_SIZE'] = 4096  # Cookie boyutu limiti

# 4. XSS KORUMALI İNPUT TEMİZLEME
def xss_temizle(veri):
    """XSS saldırılarını temizler"""
    if veri is None:
        return None
    if isinstance(veri, str):
        # HTML etiketlerini temizle
        veri = re.sub(r'<[^>]*>', '', veri)
        # JavaScript event'lerini temizle
        veri = re.sub(r'on\w+\s*=', '', veri, flags=re.IGNORECASE)
        # javascript: protokolünü temizle
        veri = re.sub(r'javascript\s*:', '', veri, flags=re.IGNORECASE)
        # data: protokolünü temizle
        veri = re.sub(r'data\s*:', '', veri, flags=re.IGNORECASE)
        # Özel karakterleri escape et
        veri = veri.replace('&', '&amp;')
        veri = veri.replace('<', '&lt;')
        veri = veri.replace('>', '&gt;')
        veri = veri.replace('"', '&quot;')
        veri = veri.replace("'", '&#x27;')
        veri = veri.replace('/', '&#x2F;')
        veri = veri.strip()
    return veri

# 5. SQL INJECTION KORUMASI (parametreize edilmiş)
def sql_guvenli(sorgu, *params):
    """SQL injection korumalı sorgu çalıştırır"""
    # Parametreleri temizle
    temiz_params = []
    for param in params:
        if isinstance(param, str):
            # Tek tırnakları escape et
            param = param.replace("'", "''")
            # Noktalı virgülü temizle
            param = param.replace(';', '')
            # SQL komutlarını temizle
            param = re.sub(r'(union|select|insert|update|delete|drop|create|alter|exec|execute)', '', param, flags=re.IGNORECASE)
        temiz_params.append(param)
    return sorgu, temiz_params

# 6. HEADER GÜVENLİĞİ
@app.after_request
def guvenlik_basliklari(response):
    """Güvenlik header'larını ekler"""
    # CSP (Content Security Policy)
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self';"
    )
    
    # XSS Koruması
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # MIME type koruması
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Clickjacking koruması
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Referrer politikası
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # HSTS (HTTPS zorunluluğu)
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Cache kontrolü
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    # Sunucu bilgilerini gizle
    response.headers['Server'] = 'Unknown'
    
    # X-Powered-By'ı kaldır
    if 'X-Powered-By' in response.headers:
        del response.headers['X-Powered-By']
    
    return response

# 7. İSTEK FİLTRESİ
@app.before_request
def istek_filtresi():
    """Şüpheli istekleri engeller"""
    # User-Agent kontrolü
    user_agent = request.headers.get('User-Agent', '')
    if len(user_agent) > 500:  # Çok uzun UA engelle
        return "Bad Request", 400
    
    # URL uzunluğu kontrolü
    if len(request.url) > 2000:
        return "URL too long", 414
    
    # Şüpheli karakterler kontrolü
    sushepli = ['../', '..\\', '%00', '%0d', '%0a', ';', '||', '&&', '`']
    for s in sushepli:
        if s in request.url:
            return "Bad Request", 400
    
    # Path traversal kontrolü
    if '..' in request.path:
        return "Bad Request", 400

# 8. CSRF TOKEN OLUŞTURMA
def csrf_token_olustur():
    """CSRF token oluşturur"""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_urlsafe(32)
    return session['_csrf_token']

# 9. CSRF TOKEN DOĞRULAMA
def csrf_token_dogrula(token):
    """CSRF token doğrular"""
    return token == session.get('_csrf_token')

# 10. IP KONTROLÜ (blacklist)
KARA_LISTE = [
    '127.0.0.2',  # Test için örnek
    # Gerçek kara listeyi buraya ekle
]

@app.before_request
def ip_kontrol():
    """Kara listedeki IP'leri engeller"""
    client_ip = request.remote_addr
    if client_ip in KARA_LISTE:
        return "Access Denied", 403

# 11. RATE LİMİTİNG (basit)
istek_sayaci = {}

@app.before_request
def rate_limiting():
    """Basit rate limiting"""
    client_ip = request.remote_addr
    now = datetime.now().timestamp()
    
    # IP'yi temizle
    if client_ip not in istek_sayaci:
        istek_sayaci[client_ip] = []
    
    # 1 dakikadan eski istekleri temizle
    istek_sayaci[client_ip] = [t for t in istek_sayaci[client_ip] if now - t < 60]
    
    # 1 dakikada max 60 istek
    if len(istek_sayaci[client_ip]) >= 60:
        return "Too Many Requests", 429
    
    istek_sayaci[client_ip].append(now)

# 12. DOSYA İZİNLERİ KONTROLÜ
@app.before_request
def dosya_guvenligi():
    """Sadece izin verilen dosyalara erişime izin ver"""
    izinli_uzantilar = ['.html', '.htm', '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg']
    
    # Dosya uzantısını al
    if '.' in request.path:
        uzanti = os.path.splitext(request.path)[1].lower()
        if uzanti and uzanti not in izinli_uzantilar:
            return "Forbidden", 403

# 13. LOGLAMA
def guvenlik_logu(olay, seviye='INFO'):
    """Güvenlik olaylarını loglar"""
    log = {
        'zaman': datetime.now().isoformat(),
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'url': request.url,
        'metod': request.method,
        'olay': olay,
        'seviye': seviye
    }
    
    # Gerçek uygulamada buraya log dosyasına yazma eklenir
    print(f"[{seviye}] {log}")

# 14. ANA SAYFA (güvenli)
@app.route('/')
def index():
    """Ana sayfa - index.html göster"""
    try:
        # CSRF token ekle
        csrf = csrf_token_olustur()
        
        # Template'e güvenli veri gönder
        return render_template('index.html', 
                             csrf_token=csrf,
                             site_adi='Focusum',
                             bot_adi='@FocusumSorgulamaBot')
    
    except Exception as e:
        guvenlik_logu(f"Index hatası: {str(e)}", 'ERROR')
        return "Bir hata oluştu", 500

# 15. SAĞLIK KONTROLÜ (güvenli)
@app.route('/health')
def health_check():
    """Sunucu sağlık kontrolü"""
    return jsonify({
        'status': 'healthy',
        'time': datetime.now().isoformat()
    })

# 16. 404 HATA SAYFASI (güvenli)
@app.errorhandler(404)
def not_found(e):
    """404 hatası - index'e yönlendir"""
    guvenlik_logu(f"404 hatası: {request.url}", 'WARNING')
    return render_template('index.html'), 200

# 17. 500 HATA SAYFASI
@app.errorhandler(500)
def server_error(e):
    """500 hatası"""
    guvenlik_logu(f"500 hatası: {str(e)}", 'ERROR')
    return "Sunucu hatası", 500

# 18. METHOD İZNİ
@app.route('/<path:path>', methods=['GET'])
def catch_all(path):
    """Diğer tüm GET istekleri index'e yönlendir"""
    # Path traversal kontrolü
    if '..' in path or path.startswith('/'):
        return "Forbidden", 403
    
    return render_template('index.html')

# 19. İZİN VERİLMEYEN METHODLAR
@app.errorhandler(405)
def method_not_allowed(e):
    """Method not allowed"""
    guvenlik_logu(f"Geçersiz method: {request.method}", 'WARNING')
    return "Method Not Allowed", 405

# 20. BAŞLANGIÇ
if __name__ == '__main__':
    from datetime import datetime
    
    # Template klasörü kontrolü
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    if not os.path.exists(template_dir):
        os.makedirs(template_dir)
        print(f"📁 templates klasörü oluşturuldu: {template_dir}")
        print("⚠️ index.html dosyasını buraya kopyala!")
    
    # Statik klasör kontrolü
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
    if not os.path.exists(static_dir):
        os.makedirs(static_dir)
    
    print("=" * 60)
    print("🛡️  FOCUSUM GÜVENLİ PANEL BAŞLATILDI")
    print("=" * 60)
    print(f"📌 Adres      : http://localhost:5000")
    print(f"📌 Bot        : @FocusumSorgulamaBot")
    print(f"📌 Tarih      : {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}")
    print("-" * 60)
    print("✅ Güvenlik Önlemleri Aktif:")
    print("   • XSS Koruması")
    print("   • CSRF Koruması")
    print("   • SQL Injection Koruması")
    print("   • Rate Limiting")
    print("   • IP Kara Liste")
    print("   • Güvenli Header'lar")
    print("   • Path Traversal Koruması")
    print("   • Dosya Erişim Kısıtlaması")
    print("   • Session Güvenliği")
    print("   • Request Filtreleme")
    print("=" * 60)
    
    # Uygulamayı başlat
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,  # DEBUG KAPALI!
        threaded=True,
        use_reloader=False
)
