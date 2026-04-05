"""
Extended Security Playbooks

Comprehensive playbooks for common security vulnerabilities.
These replace LLM calls with proven fix patterns.
"""

from typing import Dict, List, Any
from datetime import datetime

from .engine import (
    FixPlaybook,
    FixStrategy,
    ContextConstraints,
    SuccessMetrics,
    ApprovalPolicy,
)


def get_extended_playbooks() -> List[FixPlaybook]:
    """
    Get extended security playbooks.
    
    Returns a comprehensive list of playbooks for various
    security vulnerabilities across different languages.
    """
    return [
        # =========================================
        # INJECTION VULNERABILITIES
        # =========================================
        
        # SQL Injection - Python
        FixPlaybook(
            playbook_id="PB-SQLI-PYTHON-DJANGO-001",
            finding_type="SQL_INJECTION",
            language="python",
            framework="django",
            context_constraints=ContextConstraints(
                languages=["python"],
                frameworks=["django", "flask", "fastapi"],
                orms=["django_orm", "sqlalchemy", "peewee"],
            ),
            fix_strategy=FixStrategy(
                description="Use Django ORM querysets or parameterized raw SQL",
                code_pattern="django_orm_query",
                fix_template='''
# BAD: String interpolation
# cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# GOOD: Parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])

# BETTER: Use ORM
User.objects.filter(id=user_id)
''',
                test_requirements=["sql_injection_test", "orm_query_test"],
            ),
            confidence=0.93,
            approval_policy=ApprovalPolicy.AUTO_APPLY,
            source="extended",
        ),
        
        # SQL Injection - Java
        FixPlaybook(
            playbook_id="PB-SQLI-JAVA-SPRING-001",
            finding_type="SQL_INJECTION",
            language="java",
            framework="spring",
            context_constraints=ContextConstraints(
                languages=["java", "kotlin"],
                frameworks=["spring", "spring-boot", "hibernate"],
            ),
            fix_strategy=FixStrategy(
                description="Use JPA/Hibernate named parameters or PreparedStatement",
                code_pattern="prepared_statement",
                fix_template='''
// BAD: String concatenation
// String query = "SELECT * FROM users WHERE id = " + userId;

// GOOD: PreparedStatement
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);

// BETTER: JPA with named parameters
@Query("SELECT u FROM User u WHERE u.id = :userId")
User findById(@Param("userId") Long userId);
''',
                test_requirements=["sql_injection_test", "jpa_query_test"],
            ),
            confidence=0.92,
            approval_policy=ApprovalPolicy.AUTO_APPLY,
            source="extended",
        ),
        
        # NoSQL Injection
        FixPlaybook(
            playbook_id="PB-NOSQLI-NODE-MONGO-001",
            finding_type="NOSQL_INJECTION",
            language="nodejs",
            framework="express",
            context_constraints=ContextConstraints(
                languages=["nodejs", "javascript", "typescript"],
                databases=["mongodb"],
            ),
            fix_strategy=FixStrategy(
                description="Sanitize user input and use MongoDB query operators safely",
                code_pattern="mongo_sanitize",
                fix_template='''
// BAD: Direct user input
// const user = await User.findOne({ username: req.body.username })

// GOOD: Validate and sanitize
const mongo = require('mongo-sanitize');
const username = mongo(req.body.username);
const user = await User.findOne({ username: String(username) });

// Also check for $where operator injection
if (typeof req.body.filter === 'object') {
    throw new Error('Invalid filter');
}
''',
                test_requirements=["nosql_injection_test"],
            ),
            confidence=0.88,
            approval_policy=ApprovalPolicy.HUMAN_REVIEW,
            source="extended",
        ),
        
        # Command Injection - Python
        FixPlaybook(
            playbook_id="PB-CMDI-PYTHON-001",
            finding_type="COMMAND_INJECTION",
            language="python",
            framework="any",
            context_constraints=ContextConstraints(
                languages=["python"],
            ),
            fix_strategy=FixStrategy(
                description="Use subprocess with shell=False and explicit args list",
                code_pattern="subprocess_safe",
                fix_template='''
# BAD: shell=True with user input
# subprocess.run(f"ls {user_path}", shell=True)

# GOOD: shell=False with args list
import shlex
subprocess.run(["ls", user_path], shell=False)

# For complex commands, use shlex.split
args = shlex.split(f"command --option {shlex.quote(user_input)}")
subprocess.run(args, shell=False)
''',
                test_requirements=["command_injection_test", "subprocess_test"],
            ),
            confidence=0.91,
            approval_policy=ApprovalPolicy.HUMAN_REVIEW,
            source="extended",
        ),
        
        # LDAP Injection
        FixPlaybook(
            playbook_id="PB-LDAPI-001",
            finding_type="LDAP_INJECTION",
            language="any",
            framework="any",
            fix_strategy=FixStrategy(
                description="Escape special LDAP characters in user input",
                code_pattern="ldap_escape",
                fix_template='''
def escape_ldap(input_string):
    """Escape special LDAP characters."""
    escape_chars = {
        '\\\\': r'\\5c',
        '*': r'\\2a',
        '(': r'\\28',
        ')': r'\\29',
        '\\0': r'\\00',
    }
    for char, escaped in escape_chars.items():
        input_string = input_string.replace(char, escaped)
    return input_string
''',
                test_requirements=["ldap_injection_test"],
            ),
            confidence=0.85,
            approval_policy=ApprovalPolicy.HUMAN_REVIEW,
            source="extended",
        ),
        
        # =========================================
        # XSS VULNERABILITIES
        # =========================================
        
        # XSS - Vue.js
        FixPlaybook(
            playbook_id="PB-XSS-VUE-001",
            finding_type="XSS",
            language="javascript",
            framework="vue",
            context_constraints=ContextConstraints(
                languages=["javascript", "typescript"],
                frameworks=["vue", "nuxt"],
            ),
            fix_strategy=FixStrategy(
                description="Use v-text instead of v-html, sanitize content",
                code_pattern="vue_sanitize",
                fix_template='''
<!-- BAD: v-html with user content -->
<!-- <div v-html="userContent"></div> -->

<!-- GOOD: Use v-text for plain text -->
<div v-text="userContent"></div>

<!-- If HTML is required, sanitize first -->
import DOMPurify from 'dompurify';
computed: {
    safeContent() {
        return DOMPurify.sanitize(this.userContent);
    }
}
''',
                test_requirements=["xss_test", "dom_sanitize_test"],
            ),
            confidence=0.90,
            approval_policy=ApprovalPolicy.AUTO_APPLY,
            source="extended",
        ),
        
        # XSS - Angular
        FixPlaybook(
            playbook_id="PB-XSS-ANGULAR-001",
            finding_type="XSS",
            language="typescript",
            framework="angular",
            context_constraints=ContextConstraints(
                languages=["typescript"],
                frameworks=["angular"],
            ),
            fix_strategy=FixStrategy(
                description="Use DomSanitizer and avoid bypassSecurityTrust methods",
                code_pattern="angular_sanitize",
                fix_template='''
// BAD: Bypassing security
// this.sanitizer.bypassSecurityTrustHtml(userInput)

// GOOD: Let Angular sanitize automatically
this.sanitizer.sanitize(SecurityContext.HTML, userInput);

// Or use textContent for plain text
element.nativeElement.textContent = userInput;
''',
                test_requirements=["xss_test", "angular_security_test"],
            ),
            confidence=0.89,
            approval_policy=ApprovalPolicy.AUTO_APPLY,
            source="extended",
        ),
        
        # =========================================
        # AUTHENTICATION/AUTHORIZATION
        # =========================================
        
        # Broken Authentication
        FixPlaybook(
            playbook_id="PB-AUTH-WEAK-PASSWORD-001",
            finding_type="WEAK_PASSWORD_POLICY",
            language="any",
            framework="any",
            fix_strategy=FixStrategy(
                description="Implement strong password policy with proper hashing",
                code_pattern="password_policy",
                fix_template='''
import re
import bcrypt

def validate_password(password: str) -> bool:
    """Validate password meets security requirements."""
    if len(password) < 12:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\\d', password):
        return False
    if not re.search(r'[!@#$%^&*]', password):
        return False
    return True

def hash_password(password: str) -> str:
    """Hash password with bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()
''',
                test_requirements=["password_policy_test", "hash_test"],
            ),
            confidence=0.94,
            approval_policy=ApprovalPolicy.HUMAN_REVIEW,
            source="extended",
        ),
        
        # Insecure Direct Object Reference (IDOR)
        FixPlaybook(
            playbook_id="PB-IDOR-001",
            finding_type="INSECURE_DIRECT_OBJECT_REFERENCE",
            language="any",
            framework="any",
            fix_strategy=FixStrategy(
                description="Add authorization checks for resource access",
                code_pattern="authz_check",
                fix_template='''
async def get_document(document_id: str, current_user: User):
    """Get document with authorization check."""
    document = await Document.get(document_id)
    
    if not document:
        raise NotFoundError("Document not found")
    
    # CRITICAL: Authorization check
    if document.owner_id != current_user.id:
        if not await has_permission(current_user, document, "read"):
            raise ForbiddenError("Access denied")
    
    return document
''',
                test_requirements=["authorization_test", "idor_test"],
            ),
            confidence=0.87,
            approval_policy=ApprovalPolicy.HUMAN_REVIEW,
            source="extended",
        ),
        
        # JWT Vulnerabilities
        FixPlaybook(
            playbook_id="PB-JWT-WEAK-001",
            finding_type="INSECURE_JWT",
            language="any",
            framework="any",
            fix_strategy=FixStrategy(
                description="Use strong algorithm, validate claims, short expiry",
                code_pattern="jwt_secure",
                fix_template='''
import jwt
from datetime import datetime, timedelta

def create_token(user_id: str, secret: str) -> str:
    """Create secure JWT."""
    payload = {
        "sub": user_id,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1),  # Short expiry
        "iss": "your-app",  # Issuer
    }
    # Use RS256 (asymmetric) or HS256 with strong secret
    return jwt.encode(payload, secret, algorithm="HS256")

def verify_token(token: str, secret: str) -> dict:
    """Verify JWT with all checks."""
    return jwt.decode(
        token,
        secret,
        algorithms=["HS256"],  # Explicit algorithm
        options={
            "require": ["exp", "iat", "sub"],
            "verify_exp": True,
        }
    )
''',
                test_requirements=["jwt_test", "token_expiry_test"],
            ),
            confidence=0.92,
            approval_policy=ApprovalPolicy.HUMAN_REVIEW,
            source="extended",
        ),
        
        # =========================================
        # CRYPTOGRAPHY
        # =========================================
        
        # Weak Encryption
        FixPlaybook(
            playbook_id="PB-CRYPTO-WEAK-001",
            finding_type="WEAK_CRYPTOGRAPHY",
            language="python",
            framework="any",
            context_constraints=ContextConstraints(
                languages=["python"],
            ),
            fix_strategy=FixStrategy(
                description="Use modern cryptography library with strong algorithms",
                code_pattern="modern_crypto",
                fix_template='''
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64

def derive_key(password: str, salt: bytes = None) -> bytes:
    """Derive encryption key from password."""
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,  # High iterations
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt data with Fernet (AES)."""
    f = Fernet(key)
    return f.encrypt(data)
''',
                test_requirements=["encryption_test", "key_derivation_test"],
            ),
            confidence=0.90,
            approval_policy=ApprovalPolicy.HUMAN_REVIEW,
            source="extended",
        ),
        
        # Hardcoded Secrets - Various
        FixPlaybook(
            playbook_id="PB-SECRET-ENV-001",
            finding_type="HARDCODED_SECRET",
            language="any",
            framework="any",
            fix_strategy=FixStrategy(
                description="Move secrets to environment variables or secret manager",
                code_pattern="env_secrets",
                fix_template='''
# BAD: Hardcoded secret
# API_KEY = "sk-1234567890abcdef"

# GOOD: Environment variable
import os
API_KEY = os.environ.get("API_KEY")
if not API_KEY:
    raise ValueError("API_KEY environment variable required")

# BETTER: Secret manager
from secretmanager import SecretManager
sm = SecretManager()
API_KEY = sm.get_secret("api-key")

# Add to .env.example (not .env!)
# API_KEY=your-api-key-here
''',
                test_requirements=["secret_scan", "env_config_test"],
            ),
            confidence=0.96,
            approval_policy=ApprovalPolicy.HUMAN_REVIEW,
            source="extended",
        ),
        
        # =========================================
        # INFRASTRUCTURE SECURITY
        # =========================================
        
        # SSRF
        FixPlaybook(
            playbook_id="PB-SSRF-001",
            finding_type="SSRF",
            language="python",
            framework="any",
            fix_strategy=FixStrategy(
                description="Validate and whitelist URLs, block internal ranges",
                code_pattern="ssrf_protection",
                fix_template='''
import ipaddress
from urllib.parse import urlparse

BLOCKED_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
]

def is_safe_url(url: str) -> bool:
    """Check if URL is safe to request."""
    parsed = urlparse(url)
    
    # Only allow http/https
    if parsed.scheme not in ['http', 'https']:
        return False
    
    # Resolve hostname
    import socket
    try:
        ip = socket.gethostbyname(parsed.hostname)
        ip_obj = ipaddress.ip_address(ip)
        
        for blocked in BLOCKED_RANGES:
            if ip_obj in blocked:
                return False
    except socket.gaierror:
        return False
    
    return True
''',
                test_requirements=["ssrf_test", "url_validation_test"],
            ),
            confidence=0.86,
            approval_policy=ApprovalPolicy.HUMAN_REVIEW,
            source="extended",
        ),
        
        # Path Traversal
        FixPlaybook(
            playbook_id="PB-PATH-TRAVERSAL-001",
            finding_type="PATH_TRAVERSAL",
            language="python",
            framework="any",
            fix_strategy=FixStrategy(
                description="Validate and canonicalize file paths",
                code_pattern="path_validation",
                fix_template='''
import os
from pathlib import Path

ALLOWED_BASE = Path("/app/uploads")

def safe_file_path(user_path: str) -> Path:
    """Validate file path is within allowed directory."""
    # Remove path traversal attempts
    user_path = user_path.lstrip('/')
    
    # Resolve to absolute path
    full_path = (ALLOWED_BASE / user_path).resolve()
    
    # Verify it's within allowed base
    try:
        full_path.relative_to(ALLOWED_BASE)
    except ValueError:
        raise ValueError("Invalid file path")
    
    return full_path
''',
                test_requirements=["path_traversal_test", "file_access_test"],
            ),
            confidence=0.91,
            approval_policy=ApprovalPolicy.AUTO_APPLY,
            source="extended",
        ),
        
        # =========================================
        # DATA PROTECTION
        # =========================================
        
        # Sensitive Data Exposure
        FixPlaybook(
            playbook_id="PB-DATA-EXPOSURE-001",
            finding_type="SENSITIVE_DATA_EXPOSURE",
            language="any",
            framework="any",
            fix_strategy=FixStrategy(
                description="Mask sensitive data in logs and responses",
                code_pattern="data_masking",
                fix_template='''
import re
from typing import Any, Dict

SENSITIVE_FIELDS = ['password', 'ssn', 'credit_card', 'api_key', 'token']
MASK_PATTERN = re.compile(r'(password|ssn|api_key|token)["\\'\\s:=]+["\\'\\s]*([^"\\',\\s]+)', re.I)

def mask_sensitive(data: Dict[str, Any]) -> Dict[str, Any]:
    """Mask sensitive fields in dictionary."""
    masked = data.copy()
    for field in SENSITIVE_FIELDS:
        if field in masked:
            value = str(masked[field])
            masked[field] = value[:2] + '*' * (len(value) - 4) + value[-2:] if len(value) > 4 else '****'
    return masked

def mask_log_message(message: str) -> str:
    """Mask sensitive data in log messages."""
    return MASK_PATTERN.sub(r'\\1=****', message)
''',
                test_requirements=["data_masking_test", "log_sanitization_test"],
            ),
            confidence=0.88,
            approval_policy=ApprovalPolicy.AUTO_APPLY,
            source="extended",
        ),
        
        # Insecure Deserialization - Python
        FixPlaybook(
            playbook_id="PB-DESERIAL-PYTHON-001",
            finding_type="INSECURE_DESERIALIZATION",
            language="python",
            framework="any",
            context_constraints=ContextConstraints(
                languages=["python"],
            ),
            fix_strategy=FixStrategy(
                description="Use JSON instead of pickle, or yaml.safe_load",
                code_pattern="safe_deserialization",
                fix_template='''
# BAD: Using pickle with untrusted data
# data = pickle.loads(user_input)

# BAD: Using yaml.load without Loader
# data = yaml.load(user_input)

# GOOD: Use JSON for untrusted data
import json
data = json.loads(user_input)

# GOOD: Use yaml.safe_load
import yaml
data = yaml.safe_load(user_input)

# If pickle is needed, use restricted unpickler
import pickle
import io

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        # Only allow safe classes
        if module not in ['builtins'] or name not in ['dict', 'list', 'str']:
            raise pickle.UnpicklingError(f"Forbidden: {module}.{name}")
        return getattr(__import__(module), name)
''',
                test_requirements=["deserialization_test", "pickle_test"],
            ),
            confidence=0.93,
            approval_policy=ApprovalPolicy.HUMAN_REVIEW,
            source="extended",
        ),
        
        # =========================================
        # INFRASTRUCTURE AS CODE
        # =========================================
        
        # S3 Bucket Public Access
        FixPlaybook(
            playbook_id="PB-S3-PUBLIC-001",
            finding_type="S3_BUCKET_PUBLIC",
            language="terraform",
            framework="aws",
            fix_strategy=FixStrategy(
                description="Block public access and enable encryption",
                code_pattern="s3_secure",
                fix_template='''
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-bucket"
}

resource "aws_s3_bucket_public_access_block" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
''',
                test_requirements=["terraform_validate", "s3_security_scan"],
            ),
            confidence=0.95,
            approval_policy=ApprovalPolicy.AUTO_APPLY,
            source="extended",
        ),
        
        # Security Group Open to World
        FixPlaybook(
            playbook_id="PB-SG-OPEN-001",
            finding_type="SECURITY_GROUP_OPEN",
            language="terraform",
            framework="aws",
            fix_strategy=FixStrategy(
                description="Restrict security group rules to specific IPs/ranges",
                code_pattern="sg_restrict",
                fix_template='''
resource "aws_security_group" "restricted" {
  name        = "restricted-sg"
  description = "Restricted security group"
  vpc_id      = var.vpc_id

  # BAD: Open to world
  # ingress {
  #   from_port   = 22
  #   to_port     = 22
  #   protocol    = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"]
  # }

  # GOOD: Restrict to specific IPs
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip_range]  # e.g., "10.0.0.0/8"
    description = "SSH from admin network only"
  }
}
''',
                test_requirements=["terraform_validate", "sg_security_scan"],
            ),
            confidence=0.94,
            approval_policy=ApprovalPolicy.HUMAN_REVIEW,
            source="extended",
        ),
    ]


# Convenience function
def load_extended_playbooks_into_engine(engine) -> int:
    """Load all extended playbooks into a PlaybookEngine."""
    playbooks = get_extended_playbooks()
    for playbook in playbooks:
        engine.add_playbook(playbook)
    return len(playbooks)
