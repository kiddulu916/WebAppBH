# workers/info_gathering/tools/dork_patterns.py
"""Curated Google Dork pattern library organized by category.

Each category contains template strings with {domain} placeholder.
Based on GHDB (Google Hacking Database) and OWASP WSTG-INFO-01 guidance.
"""

DORK_CATEGORIES: dict[str, list[str]] = {
    "exposed_files": [
        'site:{domain} filetype:pdf',
        'site:{domain} filetype:doc',
        'site:{domain} filetype:docx',
        'site:{domain} filetype:xls',
        'site:{domain} filetype:xlsx',
        'site:{domain} filetype:ppt',
        'site:{domain} filetype:pptx',
        'site:{domain} filetype:csv',
        'site:{domain} filetype:txt',
        'site:{domain} filetype:log',
        'site:{domain} filetype:xml',
        'site:{domain} filetype:json',
    ],
    "admin_panels": [
        'site:{domain} inurl:admin',
        'site:{domain} inurl:administrator',
        'site:{domain} inurl:cpanel',
        'site:{domain} inurl:wp-admin',
        'site:{domain} inurl:dashboard',
        'site:{domain} inurl:manage',
        'site:{domain} inurl:control',
        'site:{domain} intitle:"admin panel"',
        'site:{domain} intitle:"dashboard"',
        'site:{domain} intitle:"control panel"',
    ],
    "sensitive_dirs": [
        'site:{domain} intitle:"index of"',
        'site:{domain} intitle:"index of" "parent directory"',
        'site:{domain} intitle:"index of" ".git"',
        'site:{domain} intitle:"index of" ".svn"',
        'site:{domain} intitle:"index of" "backup"',
        'site:{domain} inurl:/.git/',
        'site:{domain} inurl:/.svn/',
        'site:{domain} inurl:/.env',
        'site:{domain} inurl:/wp-content/uploads/',
    ],
    "config_leaks": [
        'site:{domain} filetype:env',
        'site:{domain} filetype:cfg',
        'site:{domain} filetype:conf',
        'site:{domain} filetype:ini',
        'site:{domain} filetype:yml',
        'site:{domain} filetype:yaml',
        'site:{domain} filetype:toml',
        'site:{domain} filetype:properties',
        'site:{domain} "DB_PASSWORD"',
        'site:{domain} "database_password"',
        'site:{domain} "AWS_SECRET_ACCESS_KEY"',
        'site:{domain} "api_key" filetype:json',
    ],
    "error_pages": [
        'site:{domain} intext:"sql syntax near"',
        'site:{domain} intext:"mysql_fetch_array"',
        'site:{domain} intext:"Warning: pg_connect"',
        'site:{domain} intext:"Fatal error" filetype:php',
        'site:{domain} intext:"Traceback (most recent call last)"',
        'site:{domain} intext:"Stack Trace"',
        'site:{domain} intext:"Server Error in"',
        'site:{domain} intitle:"500 Internal Server Error"',
    ],
    "login_pages": [
        'site:{domain} inurl:login',
        'site:{domain} inurl:signin',
        'site:{domain} inurl:auth',
        'site:{domain} inurl:sso',
        'site:{domain} intitle:"login"',
        'site:{domain} intitle:"sign in"',
        'site:{domain} inurl:oauth',
        'site:{domain} inurl:register',
    ],
    "api_endpoints": [
        'site:{domain} inurl:api',
        'site:{domain} inurl:/api/v1/',
        'site:{domain} inurl:/api/v2/',
        'site:{domain} inurl:graphql',
        'site:{domain} inurl:rest',
        'site:{domain} inurl:swagger',
        'site:{domain} inurl:openapi',
        'site:{domain} filetype:wsdl',
    ],
    "backup_files": [
        'site:{domain} filetype:bak',
        'site:{domain} filetype:old',
        'site:{domain} filetype:backup',
        'site:{domain} filetype:sql',
        'site:{domain} filetype:dump',
        'site:{domain} filetype:tar',
        'site:{domain} filetype:gz',
        'site:{domain} filetype:zip',
        'site:{domain} filetype:7z',
        'site:{domain} ext:sql intext:INSERT',
    ],
}


def get_dorks_for_domain(domain: str) -> list[str]:
    """Interpolate domain into all dork templates and return a flat list."""
    dorks = []
    for templates in DORK_CATEGORIES.values():
        for template in templates:
            dorks.append(template.format(domain=domain))
    return dorks
