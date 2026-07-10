"""
===============================================================================
VULNERABILITY RULES MODULE (STATIC APPLICATION SECURITY TESTING - SAST)
===============================================================================

LOGIC & ARCHITECTURE EXPLANATION:
---------------------------------
This file acts as the "Brain" of the security scanner. It contains a dictionary
of Regular Expressions (Regex).

How the engine uses this logic:
1. The Core Engine opens every readable file (.xml, .java, .js, .txt) inside the APK.
2. It reads the entire file content as a single giant text block.
3. It loops through every Regex rule defined in 'VULNERABILITY_RULES' below.
4. Using 'pattern.findall()', it scans the text block for specific data shapes
   (e.g., a string starting with 'AKIA' followed by 16 characters represents an AWS Key).
5. If a match is found, it is recorded along with the file path and categorized
   based on the dictionary key (e.g., "Cloud_AWS", "Hardcoded_Secrets").

Adding new rules: Simply add a new 're.compile()' entry under the relevant category.
===============================================================================
"""

import re

VULNERABILITY_RULES = {
    # --- 1. Cloud & Infrastructure Services ---
    "Cloud_AWS": [
        re.compile(r'(?i)AKIA[0-9A-Z]{16}'),  # AWS Access Key ID (Long-term credentials)
        re.compile(r'(?i)ASIA[0-9A-Z]{16}'),  # AWS Access Key ID (Temporary/Session credentials)
        re.compile(r'(?i)aws_secret_access_key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})'),  # AWS Secret Access Key
        re.compile(r'sg-[a-zA-Z0-9]{8,17}'),  # AWS Security Group ID
        re.compile(r'(?i)(https?://[a-zA-Z0-9-]+\.s3(?:-[a-z0-9-]+)?\.amazonaws\.com)'),  # AWS S3 Bucket URL
        re.compile(r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')  # AWS MWS Auth Token
    ],
    "Cloud_Azure": [
        re.compile(r'(?i)Endpoint=sb://[a-zA-Z0-9-]+\.servicebus\.windows\.net'),  # Azure Service Bus Connection String
        re.compile(r'(?i)AccountName=[a-zA-Z0-9]+;AccountKey=[a-zA-Z0-9+/=]+')  # Azure Storage Account Key
    ],
    "Cloud_GCP": [
        re.compile(r'AIza[0-9A-Za-z_-]{35}'),  # Google Cloud / Google Maps API Key
        re.compile(
            r'(?i)(?:google|gcp|youtube|drive|auth)[-_]?(?:api|key|token)["\']?\s*[:=]\s*["\']?(AIza[0-9A-Za-z_-]{35})["\']?'),
        re.compile(r'[0-9]+-[a-zA-Z0-9_]{32}\.apps\.googleusercontent\.com'),  # Google OAuth 2.0 Client ID
        re.compile(r'1:[0-9]+:(?:android|ios):[0-9a-f]+')  # Google Firebase Mobile App ID
    ],
    "Cloud_Other": [
        re.compile(
            r'(?i)heroku[_-]?api[_-]?key["\']?\s*[:=]\s*["\']?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})'),
        re.compile(r'dop_v1_[a-f0-9]{64}'),  # DigitalOcean Personal Access Token
        re.compile(r'vultr-api-key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{36})')  # Vultr API Key
    ],

    # --- 2. AI Providers (LLMs & ML Services) ---
    "AI_Providers": [
        re.compile(r'sk-[a-zA-Z0-9_-]{20,}'),  # Matches OpenAI, DeepSeek, and generic 'sk-' keys
        re.compile(r'sk-ant-api[a-zA-Z0-9-_]{10,}'),  # Anthropic (Claude) API Key
        re.compile(r'gemini-[a-zA-Z0-9_-]{35,}'),  # Google Gemini API Key
        re.compile(r'hf_[a-zA-Z]{27,}'),  # Hugging Face Access Token
        re.compile(r'(?i)cohere[_-]?api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{40})["\']?')  # Cohere API Key
    ],

    # --- 3. Payment & FinTech Systems ---
    "Payment_Stripe": [
        re.compile(r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}'),  # Stripe Secret/Publishable Key
        re.compile(r'rk_(?:live|test)_[0-9a-zA-Z]{24,}')  # Stripe Restricted Key
    ],
    "Payment_Other": [
        re.compile(r'(?i)paypal[_-]?(?:client[_-]?id|secret)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_]{16,})'),
        re.compile(r'sq0(?:atp|csp)-[0-9A-Za-z\-_]{22,43}'),  # Square Access Token
        re.compile(r'access_token\$production\$[0-9a-z]{16,}\$[0-9a-z]{32}'),  # Braintree Access Token
        re.compile(r'rzp_(?:live|test)_[a-zA-Z0-9]{14}')  # Razorpay API Key
    ],

    # --- 4. Database & Backend-as-a-Service (BaaS) ---
    "Database_BaaS": [
        re.compile(r'(?i)(https?://[a-zA-Z0-9-]+\.firebaseio\.com)'),  # Firebase Realtime DB URL
        re.compile(r'(?i)(https?://[a-zA-Z0-9-]+\.supabase\.co)'),  # Supabase Endpoint URL
        re.compile(r'mongodb(?:\+srv)?://[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+/?'),
        # MongoDB Connection String
        re.compile(r'redis://[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+:[0-9]+'),  # Redis Connection String
        re.compile(
            r'(?i)(?:postgres|postgresql|mysql|mssql|mariadb)://[a-zA-Z0-9_-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+:[0-9]+/[a-zA-Z0-9_.-]+'),
        re.compile(r'pscale_pw_[a-zA-Z0-9\-_]{43}')  # PlanetScale Password
    ],
    "Database_SQL_Queries": [
        re.compile(r'(?i)\bSELECT\s+.+\s+FROM\s+[a-zA-Z0-9_]+\b'),  # Detects hardcoded SELECT queries
        re.compile(r'(?i)\bINSERT\s+INTO\s+[a-zA-Z0-9_]+\s*\('),  # Detects hardcoded INSERT queries
        re.compile(r'(?i)\bUPDATE\s+[a-zA-Z0-9_]+\s+SET\b'),  # Detects hardcoded UPDATE queries
        re.compile(r'(?i)\bDELETE\s+FROM\s+[a-zA-Z0-9_]+\b')  # Detects hardcoded DELETE queries
    ],

    # --- 5. Communication, Social Media & DevOps Tools ---
    "Comm_Messaging": [
        re.compile(r'xox[baprs]-([0-9a-zA-Z]{10,48})'),  # Slack Token
        re.compile(r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}'),
        re.compile(r'AC[a-zA-Z0-9]{32}'),  # Twilio Account SID
        re.compile(
            r'(?i)discord[_-]?bot[_-]?token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{24}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27})'),
        re.compile(r'[0-9]{9,10}:[a-zA-Z0-9_-]{35}')  # Telegram Bot Token
    ],
    "Comm_Email": [
        re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'),  # SendGrid API Key
        re.compile(r'key-[0-9a-zA-Z]{32}'),  # Mailgun API Key
        re.compile(r'[0-9a-f]{32}-us[0-9]{1,2}')  # Mailchimp API Key
    ],
    "DevOps_Git_And_CI": [
        re.compile(r'gh[pousr]_[a-zA-Z0-9]{36}'),  # GitHub Access Tokens
        re.compile(r'glpat-[a-zA-Z0-9\-_=]{20}'),  # GitLab Personal Access Token
        re.compile(r'(?i)appcenter[_-]?(?:api)?[_-]?token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{40})["\']?')
    ],

    # --- 6. Generic Authentication & Cryptography ---
    "Auth_JWT": [
        re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}')  # JSON Web Token (JWT)
    ],
    "Auth_Social_Media": [
        re.compile(
            r'(?i)(?:facebook|fb)[_-]?(?:app|client)[_-]?(?:id|secret)["\']?\s*[:=]\s*["\']?([0-9a-fA-F]{15,32})["\']?'),
        re.compile(
            r'(?i)(?:twitter|tw)[_-]?(?:api|client|consumer)[_-]?(?:key|secret)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{15,50})["\']?')
    ],
    "Crypto_Keys": [
        re.compile(r'-----BEGIN (?:RSA|OPENSSH|EC) PRIVATE KEY-----')  # Hardcoded Private Cryptographic Keys
    ],
    "Crypto_Base64_Keys": [
        re.compile(r'MII[a-zA-Z0-9+/{}\-_]{100,}={0,2}')  # Base64 encoded ASN.1/DER/PEM Keys
    ],

    # --- 7. NEW: Hardcoded Vulnerabilities (Credentials, Weak Crypto, Insecure Networks) ---
    "Hardcoded_Secrets": [
        re.compile(
            r'(?i)(?:api_key|apikey|secret|token|password|passwd|pwd|auth_key|client_id|client_secret|access_token|bearer_token|private_key|public_key|hash|salt|signature)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_.\-+/=]{15,})["\']?'),
        re.compile(r'(?i)(?:password|passwd|pwd|pass)\s*[:=]\s*["\']?([a-zA-Z0-9!@#$%^&*()_+\-]{8,})["\']?')
    ],
    "Hardcoded_Test_Credentials": [
        # Catches emails often used by developers for hardcoded test logins
        re.compile(r'(?i)(?:test|admin|demo|guest|developer)@[a-zA-Z0-9_.-]+\.[a-zA-Z]+')
    ],
    "Hardcoded_Insecure_Crypto": [
        # Detects the usage of outdated/broken encryption algorithms hardcoded in Java/Kotlin
        re.compile(r'(?i)["\'](?:DES|AES)/ECB/[a-zA-Z0-9]+Padding["\']'),
        re.compile(r'(?i)["\']MD5["\']'),
        re.compile(r'(?i)["\']SHA-?1["\']')
    ],

    # --- 8. Business Logic & Hardcoded Configurations ---
    "Business_Logic_Constants": [
        re.compile(
            r'(?i)(?:public\s+static\s+final\s+String|val|var)\s+[a-zA-Z0-9_]*(?:price|cost|fee|amount|currency|endpoint|url)[a-zA-Z0-9_]*\s*=\s*["\']([^"\']+)["\']')
    ],

    # --- 9. Network, Infrastructure & App Routing ---
    "Network_Insecure_HTTP": [
        # Detects hardcoded HTTP (unencrypted) URLs. Attackers look for these to perform Man-In-The-Middle (MITM) attacks.
        re.compile(r'(?i)http://[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]*)*')
    ],
    "Network_Internal_Infra": [
        re.compile(r'(?i)https?://(?:localhost|127\.0\.0\.1)(?::[0-9]{1,5})?[/\w.-]*'),
        re.compile(r'(?i)(?:[a-zA-Z]:\\(?:Users|Program Files|Windows)|/(?:Users|home|var/log|etc)/)[a-zA-Z0-9_.-]+')
    ],
    "Network_DeepLinks": [
        re.compile(r'(?i)[a-z0-9]+://[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]*)*')
    ],
    "Network_Mapping_Services": [
        re.compile(r'pk\.[a-zA-Z0-9]{60}\.[a-zA-Z0-9]{22}')  # Mapbox Public Access Token
    ],

    # --- 10. Analytics & Crash Reporting Tools ---
    "Cloud_Analytics": [
        re.compile(r'(?i)https://[a-zA-Z0-9]+@[a-zA-Z0-9]+\.ingest\.sentry\.io/[0-9]+'),
        re.compile(r'(?i)mixpanel[_-]?(?:api|project|token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{32})["\']?')
    ]
}