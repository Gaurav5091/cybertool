SQL_PAYLOADS = ["' OR 1=1 --", "'; DROP TABLE users; --", "1' OR '1'='1", "1; SELECT * FROM users --"]
XSS_PAYLOADS = ["<script>alert('xss')</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"]
CSRF_PAYLOAD = "<form action='{}' method='POST'><input type='submit'></form>"
REDIRECT_PAYLOADS = ["http://evil.com", "//evil.com", "javascript:alert(1)"]
WEAK_PASSWORDS = ["admin", "password", "123456"]
TIMEOUT = 5
ADVANCED_TIMEOUT = 10
SUBDOMAIN_FILE = "wordlists/subdomains.txt"
DIR_FILE = "wordlists/directories.txt"
MSF_HOST = "127.0.0.1"
MSF_PORT = 55552
MSF_PASSWORD = "p@ssw0rd"
