# superset_config.py
import os
import datetime
import logging
import json
import traceback
from flask import request, redirect, url_for, g, Blueprint
from superset.security import SupersetSecurityManager
import hmac
import hashlib
import base64
import requests

# redis and celery
import os
from cachelib.redis import RedisCache
 
# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logging.getLogger('flask_jwt_extended').setLevel(logging.DEBUG)
logging.getLogger('jwt').setLevel(logging.DEBUG)
logging.getLogger('superset').setLevel(logging.DEBUG)
logging.getLogger('werkzeug').setLevel(logging.DEBUG)
jwt_logger = logging.getLogger('superset.jwt')
jwt_logger.setLevel(logging.DEBUG)
 
SECRET_KEY = os.getenv("SUPERSET_SECRET_KEY")
SQLALCHEMY_DATABASE_URI = os.getenv("SUPERSET_DB_URI")
 
if not SQLALCHEMY_DATABASE_URI:
    raise RuntimeError(
        "The SUPERSET_DB_URI environment variable is not set! "
        "Please ensure it's defined in your .env file and passed "
        "correctly to the Docker container."
    )

# Redis & Celery configuration
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")
REDIS_DB = os.getenv("REDIS_CELERY_DB", "0")
REDIS_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"

# Celery config
class CeleryConfig:
    broker_url = REDIS_URL
    result_backend = REDIS_URL
    imports = ("superset.sql_lab",)
    task_annotations = {"tasks.add": {"rate_limit": "10/s"}}
    task_acks_late = True
    task_reject_on_worker_lost = True
    worker_prefetch_multiplier = 1
    task_soft_time_limit = 300
    task_time_limit = 600
    timezone = "UTC"

CELERY_CONFIG = CeleryConfig

# Caching config
CACHE_CONFIG = {
    "CACHE_TYPE": "RedisCache",
    "CACHE_DEFAULT_TIMEOUT": 300,
    "CACHE_KEY_PREFIX": "superset_",
    "CACHE_REDIS_HOST": REDIS_HOST,
    "CACHE_REDIS_PORT": REDIS_PORT,
    "CACHE_REDIS_DB": 1,
    "CACHE_REDIS_URL": f"redis://{REDIS_HOST}:{REDIS_PORT}/1",
}
DATA_CACHE_CONFIG = CACHE_CONFIG

# Async SQL Lab
RESULTS_BACKEND = RedisCache(
    host=REDIS_HOST,
    port=int(REDIS_PORT),
    key_prefix="superset_results",
    db=2
)

# Replay protection cache for JWT jti values
REPLAY_CACHE = RedisCache(
    host=REDIS_HOST,
    port=int(REDIS_PORT),
    key_prefix="superset_jti_",
    db=3
)

# Visual Customizations (Modern Method)
FAVICONS = [{"href": "/static/assets/custom/RMC_100.png"}]
APP_FAB_UI_BRAND_INFO = {
    "logo_icon": "/static/assets/custom/RMC_100.png",
    "logo_icon_width": 200,
    "logo_icon_target_path": "http://www.rockymountaincare.com/",
    "logo_icon_tooltip": "rockymountaincare.com",
    "brand_text": "RMC SUPERSET APP",
}

SQL_MAX_ROW = 50000
VIZ_ROW_LIMIT = 50000
 
# Customizations for the Superset UI to run stored procedures.
ALLOW_DML = True
 
# Enable Security views in Superset UI.
FAB_ADD_SECURITY_VIEWS = True

# Set MapBox API Key
MAPBOX_API_KEY = os.getenv("MAPBOX_API_KEY")

# Debug MapBox API Key load
print(f"Attempting to get MAPBOX_API_KEY from environment...")
mapbox_key_value = os.getenv("MAPBOX_API_KEY")
# Add a check for None or empty string
if mapbox_key_value:
    print(f"Value FOUND for os.getenv('MAPBOX_API_KEY'): '{mapbox_key_value[:5]}...'") # Print first 5 chars
else:
    print(f"Value NOT FOUND or EMPTY for os.getenv('MAPBOX_API_KEY')")

 
from flask_appbuilder.security.manager import AUTH_OAUTH
from flask_appbuilder.security.manager import AUTH_DB
AUTH_TYPE = AUTH_DB 
AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = "myportaluser"

PUBLIC_ROLE_LIKE = None  # Disable anonymous/public access
AUTH_ROLE_PUBLIC = 'myportaluser'  # Use myportaluser as public role for iframe embedding

# Production security settings
ENABLE_PROXY_FIX = True  # Handle reverse proxy headers
WTF_CSRF_ENABLED = False  # CSRF disabled for WordPress external auth
WTF_CSRF_CHECK_DEFAULT = False  # Disable CSRF checking by default
CSRF_ENABLED = False  # Legacy CSRF setting

# Azure AD Configuration for OBO Token Validation
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID", "9b461294-9d11-4314-928e-277398086f19")
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID", "39ad4e02-9a76-4464-810b-eac74dbc0950")
AZURE_AD_CONFIG = {
    "tenant_id": AZURE_TENANT_ID,
    "client_id": AZURE_CLIENT_ID,
    "jwks_url": f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/discovery/v2.0/keys",
    "issuer": f"https://sts.windows.net/{AZURE_TENANT_ID}/",
    "audience": f"api://{AZURE_CLIENT_ID}",
    "leeway": 10,  # 10 seconds clock skew tolerance
    "cache_ttl": 24 * 3600,  # 24 hours
    "refresh_threshold": 0.75,  # Refresh at 75% TTL
}

# JWT Processing Configuration
JWT_IDENTITY_CLAIM = 'upn'
JWT_QUERY_STRING_NAME = 'proof'

# Legacy JWT settings (kept for compatibility)
FLASK_ENV = 'development'
FLASK_DEBUG = True

# Azure AD Token Validator
import jwt
import requests
import redis
import json
import time
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class AzureADTokenValidator:
    def __init__(self, config):
        self.config = config
        self.redis_client = None
        try:
            self.redis_client = redis.Redis.from_url(os.getenv('REDIS_URL', 'redis://redis:6379/0'))
            self.redis_client.ping()  # Test connection
            logging.info("Azure AD Token Validator: Redis connection established")
        except Exception as e:
            logging.warning(f"Azure AD Token Validator: Redis unavailable, using memory cache: {e}")
            self._memory_cache = {}
    
    def _get_cache_key(self):
        return f"azure_ad_keys:{self.config['tenant_id']}"
    
    def _get_cached_keys(self):
        """Get JWKS keys from cache (Redis or memory fallback)"""
        if self.redis_client:
            try:
                cached_data = self.redis_client.get(self._get_cache_key())
                if cached_data:
                    return json.loads(cached_data)
            except Exception as e:
                logging.warning(f"Redis cache read failed: {e}")
        
        # Memory fallback
        if hasattr(self, '_memory_cache'):
            return self._memory_cache.get(self._get_cache_key())
        
        return None
    
    def _set_cached_keys(self, keys_data):
        """Set JWKS keys in cache with TTL"""
        cache_data = {
            "keys": keys_data,
            "cached_at": time.time(),
            "expires_at": time.time() + self.config['cache_ttl']
        }
        
        if self.redis_client:
            try:
                self.redis_client.setex(
                    self._get_cache_key(),
                    self.config['cache_ttl'],
                    json.dumps(cache_data)
                )
                return
            except Exception as e:
                logging.warning(f"Redis cache write failed: {e}")
        
        # Memory fallback
        if hasattr(self, '_memory_cache'):
            self._memory_cache[self._get_cache_key()] = cache_data
    
    def _fetch_jwks_keys(self):
        """Fetch JWKS keys from Microsoft with retry logic"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = requests.get(
                    self.config['jwks_url'],
                    timeout=10,
                    headers={'User-Agent': 'Superset-Azure-AD-Validator/1.0'}
                )
                response.raise_for_status()
                jwks_data = response.json()
                
                # Parse and cache RSA keys
                parsed_keys = {}
                for key_data in jwks_data.get('keys', []):
                    if key_data.get('kty') == 'RSA' and key_data.get('use') == 'sig':
                        kid = key_data.get('kid')
                        if kid:
                            parsed_keys[kid] = key_data
                
                logging.info(f"Fetched {len(parsed_keys)} JWKS keys from Azure AD")
                self._set_cached_keys(parsed_keys)
                return parsed_keys
                
            except Exception as e:
                logging.warning(f"JWKS fetch attempt {attempt + 1}/{max_retries} failed: {e}")
                if attempt == max_retries - 1:
                    raise
                time.sleep(2 ** attempt)  # Exponential backoff
        
        return {}
    
    def _get_signing_keys(self):
        """Get signing keys with caching and refresh logic"""
        cached_data = self._get_cached_keys()
        
        if cached_data:
            expires_at = cached_data.get('expires_at', 0)
            refresh_time = expires_at - (self.config['cache_ttl'] * (1 - self.config['refresh_threshold']))
            
            # Use cached keys if still valid
            if time.time() < expires_at:
                # Background refresh if approaching expiration
                if time.time() > refresh_time:
                    try:
                        self._fetch_jwks_keys()  # Background refresh
                    except Exception as e:
                        logging.warning(f"Background JWKS refresh failed: {e}")
                
                return cached_data['keys']
            else:
                logging.warning("Cached JWKS keys expired, fetching fresh keys")
        
        # Fetch fresh keys if cache miss or expired
        try:
            return self._fetch_jwks_keys()
        except Exception as e:
            logging.error(f"Failed to fetch JWKS keys: {e}")
            
            # Return expired cached keys as last resort
            if cached_data and cached_data.get('keys'):
                logging.warning("Using expired JWKS keys as fallback")
                return cached_data['keys']
            
            raise Exception("No JWKS keys available")
    
    def validate_token(self, token):
        """Validate Azure AD OBO token and return claims"""
        logging.critical(f"[JWT Debug] validate_token called with token length: {len(token) if token else 0}")
        try:
            # Decode header to get key ID
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get('kid')
            
            if not kid:
                raise ValueError("Token missing 'kid' (key ID) in header")
            
            # Get signing keys
            signing_keys = self._get_signing_keys()
            
            if kid not in signing_keys:
                raise ValueError(f"Unknown key ID: {kid}")
            
            # Convert JWK to PEM format for PyJWT
            key_data = signing_keys[kid]
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_data))
            
            # Validate token with full verification
            decoded_token = jwt.decode(
                token,
                public_key,
                algorithms=['RS256'],
                audience=self.config['audience'],
                issuer=self.config['issuer'],
                leeway=self.config['leeway']
            )
            
            logging.info(f"Token validated successfully for user: {decoded_token.get('upn', 'unknown')}")
            return decoded_token
            
        except jwt.ExpiredSignatureError:
            logging.warning("Token validation failed: Token expired")
            raise ValueError("Token expired")
        except jwt.InvalidAudienceError:
            logging.warning(f"Token validation failed: Invalid audience (expected: {self.config['audience']})")
            raise ValueError("Invalid token audience")
        except jwt.InvalidIssuerError:
            logging.warning(f"Token validation failed: Invalid issuer (expected: {self.config['issuer']})")
            raise ValueError("Invalid token issuer")
        except jwt.InvalidTokenError as e:
            logging.warning(f"Token validation failed: Invalid token - {e}")
            raise ValueError(f"Invalid token: {e}")
        except Exception as e:
            logging.error(f"Token validation error: {e}")
            raise ValueError(f"Token validation failed: {e}")

# Initialize global token validator
azure_token_validator = AzureADTokenValidator(AZURE_AD_CONFIG)

class UnifiedSecurityManager(SupersetSecurityManager):
    def __init__(self, appbuilder):
        super(UnifiedSecurityManager, self).__init__(appbuilder)
        logging.info("Unified Security Manager initialized - JWT authentication enabled")
        self.auth_user_jwt_username_key = JWT_IDENTITY_CLAIM
 

    def _get_user_groups_from_graph(self, access_token):
        """
        Get user groups from Microsoft Graph API - used by JWT when OBO token lacks groups
        """
        import time
        
        if not access_token:
            logging.warning("No access token available for Graph API call")
            return []
            
        headers = {'Authorization': f'Bearer {access_token}'}
        url = 'https://graph.microsoft.com/v1.0/me/memberOf'
        
        # Retry logic with exponential backoff
        max_retries = 3
        base_delay = 1
        
        for attempt in range(max_retries):
            try:
                response = requests.get(url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    groups_data = response.json()
                    group_ids = [group['id'] for group in groups_data.get('value', [])]
                    logging.info(f"Retrieved {len(group_ids)} groups from Graph API")
                    return group_ids
                    
                elif response.status_code in [429, 503, 502, 504]:  # Retryable errors
                    delay = base_delay * (2 ** attempt)
                    if attempt < max_retries - 1:
                        time.sleep(delay)
                        continue
                    
                else:  # Non-retryable errors
                    logging.error(f"Graph API error: {response.status_code}")
                    return []
                    
            except requests.exceptions.Timeout:
                delay = base_delay * (2 ** attempt)
                if attempt < max_retries - 1:
                    time.sleep(delay)
                    continue
                    
            except Exception as e:
                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    time.sleep(delay)
                    continue
        
        logging.warning("Graph API failed after all retry attempts")
        return []

    def auth_user_jwt(self, token):
        """
        JWT authentication path - called when WordPress provides OBO token
        This creates the same user identity as OAuth authentication for session continuity
        """
        try:
            decoded_token = azure_token_validator.validate_token(token)
           
            # Replay protection
            try:
                jti = decoded_token.get('jti')
                exp = decoded_token.get('exp')
                if not jti or not exp:
                    logging.warning("JWT missing jti or exp claims - replay protection not possible")
                    return None
                    
                if REPLAY_CACHE.get(jti):
                    logging.critical(f"SECURITY VIOLATION: JWT replay attack detected")
                    return None
                    
                ttl = max(int(exp - datetime.datetime.now().timestamp()), 60)
                REPLAY_CACHE.set(jti, 1, timeout=ttl)
                
            except Exception as replay_err:
                logging.critical(f"SECURITY ERROR: Replay cache failure - denying authentication")
                return None  
                
            # Extract user identity and groups
            user_id = decoded_token.get(self.auth_user_jwt_username_key)
            azure_groups = decoded_token.get('groups', [])
            
            # If no groups in token, try Graph API
            if not azure_groups:
                try:
                    azure_groups = self._get_user_groups_from_graph(token)
                except Exception:
                    azure_groups = []
            
            if not user_id:
                logging.warning("No user identifier found in JWT token")
                return None
                
            # Create user with Azure groups for role mapping
            return self._create_or_update_user(
                user_id=user_id,
                user_info={
                    'name': decoded_token.get('name') or user_id,
                    'email': user_id,
                    'given_name': decoded_token.get('given_name', ''),
                    'family_name': decoded_token.get('family_name', ''),
                    'groups': azure_groups
                },
                auth_source='jwt'
            )
            
        except Exception as e:
            logging.error(f"JWT authentication failed: {str(e)}")
            return None
    
    def _create_or_update_user(self, user_id, user_info, auth_source):
        """
        Unified user creation/update logic used by both OAuth and JWT authentication
        Ensures consistent user identity and role assignment regardless of auth path
        """
        user = self.find_user(username=user_id)
        if not user:
            user_name = user_info['name']
            email = user_info['email']
            first_name = user_info.get('given_name') or ''
            last_name = user_info.get('family_name') or ''
            
            if not first_name and not last_name:
                try:
                    first_name, last_name = user_name.split(" ", 1)
                except (ValueError, AttributeError):
                    first_name = user_id.split('@')[0]
                    last_name = ""
                
            try:
                user = self.add_user(
                    username=user_id,
                    first_name=first_name,
                    last_name=last_name,
                    email=email,
                    role=self.find_role('Public')
                )
                if user:
                    logging.info(f"Created new user: {user.username}")
                else:
                    logging.error(f"User creation failed for {user_id}")
                    return None
            except Exception as user_create_error:
                logging.error(f"Error creating user {user_id}: {str(user_create_error)}")
                return None

        if not user:
            logging.error("User creation/lookup failed")
            return None

        superset_roles = []

        resolved_role_names: list[str] = []
        try:
            azure_groups = user_info.get('groups', [])
            if not isinstance(azure_groups, list):
                azure_groups = []
            mapping_db_uri = os.getenv('AZURE_SQL_CONNECTION_STRING')
            mapping_table = os.getenv('AZURE_ROLE_MAPPING_TABLE', 'dbo.ActiveEntraGroups')
            mapping_group_col = os.getenv('AZURE_ROLE_MAPPING_GROUP_COL', 'GroupId')
            mapping_role_col = os.getenv('AZURE_ROLE_MAPPING_ROLE_COL', 'DisplayName')
            
            if mapping_db_uri and azure_groups:
                from sqlalchemy import create_engine, text
                engine = create_engine(mapping_db_uri, pool_pre_ping=True)
                chunk_size = int(os.getenv('AZURE_ROLE_MAPPING_CHUNK', '100'))
                for i in range(0, len(azure_groups), chunk_size):
                    chunk = azure_groups[i:i+chunk_size]
                    placeholders = ','.join([f":g{j}" for j in range(len(chunk))])
                    sql = text(
                        f"SELECT {mapping_role_col} AS role_name FROM {mapping_table} WHERE {mapping_group_col} IN ({placeholders})"
                    )
                    params = {f"g{j}": chunk[j] for j in range(len(chunk))}
                    with engine.connect() as conn:
                        rows = conn.execute(sql, params).fetchall()
                        chunk_roles = [r.role_name for r in rows if r.role_name is not None]
                        resolved_role_names.extend(chunk_roles)
                        
                logging.info(f"Mapped {len(resolved_role_names)} Azure groups to roles")
                
            # If no DB mapping, use Azure group GUIDs as role names
            if not resolved_role_names and azure_groups:
                resolved_role_names = list(azure_groups)
                
        except Exception as map_err:
            logging.error(f"Azure role mapping failed: {str(map_err)}")

        # Apply naming filters: keep roles that start with 'dashboard' or contain 'myportal' / 'beta myportal'
        try:
            filtered: list[str] = []
            for rn in resolved_role_names:
                lower = (rn or '').lower()
                if lower.startswith('dashboard') or ('myportal' in lower) or ('beta myportal' in lower):
                    filtered.append(rn)
            if filtered:
                resolved_role_names = filtered
        except Exception as _:
            pass

        # Ensure default myportaluser
        default_role_name = os.getenv('DEFAULT_PORTAL_ROLE', 'myportaluser')
        if default_role_name not in resolved_role_names:
            resolved_role_names.append(default_role_name)

        # Create/attach roles
        for role_name in resolved_role_names:
            try:
                if not role_name or role_name.strip() == '':
                    logging.warning(f"Skipping invalid role name: {repr(role_name)}")
                    continue
                    
                role = self.find_role(role_name)
                if not role:
                    role = self.add_role(role_name)
                superset_roles.append(role)
            except Exception as role_error:
                logging.error(f"Error ensuring role {role_name}: {str(role_error)}")
        
        public_role = self.find_role('Public')
        if public_role and public_role not in superset_roles:
            superset_roles.append(public_role)
 
        try:
            user.roles = superset_roles
            self.update_user(user)  
            logging.info(f"User {user.username} assigned {len(superset_roles)} roles")
        except Exception as role_update_error:
            logging.error(f"Error updating user roles: {str(role_update_error)}")
            return None
        
        try:
            from flask_login import login_user
            login_user(user, remember=True)
            logging.info(f"User {user.username} authenticated successfully")
        except Exception as login_error:
            logging.error(f"Flask login failed: {str(login_error)}")
        
        return user
 
    def handle_invalid_token(self, error_string=None):
        """Handle JWT token errors more gracefully."""
        logging.warning(f"Invalid JWT token: {error_string}")
        return None
    
    def unauthorized(self):
        from flask import redirect, url_for
        
        try:
            custom_oauth_url = url_for('microsoft_auth')
            return redirect(custom_oauth_url)
        except Exception as e:
            logging.warning(f"Custom OAuth redirect failed, using fallback: {str(e)}")
            return redirect("/auth/microsoft")

    def login_url(self, next_url=None):
        """
        Always return Microsoft login URL - never return /login/
        """        
        tenant_id = AZURE_TENANT_ID
        client_id = AZURE_CLIENT_ID
        
        microsoft_login_url = (
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
            f"?client_id={client_id}"
            f"&response_type=code"
            f"&redirect_uri=https://stg-dashboards.rmcare.com/"
            f"&scope=openid%20email%20profile%20User.Read"
            f"&response_mode=query"
        )
        
        if next_url:
            microsoft_login_url += f"&state={next_url}"
            
        return microsoft_login_url

 
CUSTOM_SECURITY_MANAGER = UnifiedSecurityManager
 
# Set feature flags (enable the use of async queries, Dashboard RBAC)
FEATURE_FLAGS = {
    'ENABLE_TEMPLATE_PROCESSING': True,  # Enables Jinja templating
    'ALLOW_RUN_ASYNC': True,  # Enables async queries
    'DASHBOARD_RBAC': True, # Enables dashboard-level permissions
    "HORIZONTAL_FILTER_BAR": True # Enables switching of dashboard filters from left side to top
}
 
def yesterday_date():
    import datetime
    return (datetime.datetime.now() - datetime.timedelta(days=1)).strftime('%Y-%m-%d')
 
def date_calc(days_offset=0, date_format='%Y-%m-%d', base_date=None):
    import datetime
    if base_date:
        try:
            base_dt = datetime.datetime.strptime(base_date, '%Y-%m-%d').date()
        except ValueError:
            raise ValueError("Invalid base_date format. Must be YYYY-MM-DD.")
    else:
        base_dt = datetime.datetime.utcnow().date()
    
    target_dt = base_dt + datetime.timedelta(days=days_offset)
    return target_dt.strftime(date_format)
 
def current_username():
    import logging
    from flask import request, g
    
    if hasattr(g, 'user') and g.user and hasattr(g.user, 'username'):
        return g.user.username
    
    token = request.args.get('proof')
    if not token and 'Proof' in request.headers:
        token = request.headers.get('Proof')
    if not token and 'Authorization' in request.headers:
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
    
    if token:
        try:
            decoded = azure_token_validator.validate_token(token)
            return decoded.get(JWT_IDENTITY_CLAIM)
        except Exception:
            pass
    
    return None
 
def current_user_id():
    import logging
    from flask import request, g
    
    if hasattr(g, 'user') and g.user and hasattr(g.user, 'id'):
        return g.user.id
    
    token = request.args.get('proof')
    if not token and 'Proof' in request.headers:
        token = request.headers.get('Proof')
    if not token and 'Authorization' in request.headers:
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
    
    if token:
        try:
            decoded = azure_token_validator.validate_token(token)
            return decoded.get('sub')
        except Exception:
            pass
    
    return None
 
def current_user_role():
    from flask import g
    
    if hasattr(g, 'user') and g.user and hasattr(g.user, 'roles'):
        return [r.name for r in g.user.roles]
    
    return []
 
JINJA_CONTEXT_ADDONS = {
    'yesterday': yesterday_date,
    'date_calc': date_calc,
    'current_username': current_username,
    'current_user_id': current_user_id,
    'current_user_role': current_user_role
}

# This new flag sets the horizontal layout as the default for all NEW dashboards
DASHBOARD_HORIZONTAL_FILTER_BAR_DEFAULT = True
 
# MyPortal Configuration
TALISMAN_CONFIG = {
    'content_security_policy': {
        'frame-ancestors': ["'self'", "https://beta.myportal.rmcare.com", "https://myportal.rmcare.com", "https://stg-dashboards.rmcare.com"],
    },
    'force_https': False,
    'session_cookie_secure': False,
}
ENABLE_CORS = True
CORS_OPTIONS = {
  'supports_credentials': True,
  'allow_headers': ['Content-Type', 'Authorization', 'X-Requested-With'],
  'expose_headers': ['Set-Cookie'],
  'resources': {'*': {'origins': ['https://beta.myportal.rmcare.com', 'https://myportal.rmcare.com', 'https://stg-dashboards.rmcare.com']}},
}

# Session Configuration for Cross-Domain Support
SESSION_COOKIE_DOMAIN = '.rmcare.com'  # Shared across WordPress and Superset
SESSION_COOKIE_SECURE = True  # HTTPS only in production
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'None'  # Required for iframe embedding
SESSION_PERMANENT = False
PERMANENT_SESSION_LIFETIME = 3600  # 1 hour session timeout
 
# Colors schemes
EXTRA_CATEGORICAL_COLOR_SCHEMES = [
{
"id": 'Rocky_Mountain_BI_Colors_Contrast_c16',
"description": '',
"label": 'Rocky Mountain BI Colors Contrast c16',
"colors": ['#063457', '#3d3f6c', '#6b4879', '#98507b', '#bd5d75', '#d87168', '#e58e5b', '#e5af55', '#42638a', '#706d98', '#98789f', '#bb85a0', '#d6969e', '#e8ab9d', '#f1c3a1', '#f3ddad']
},
{
"id": 'Rocky_Mountain_BI_Colors_Contrast_c14_Shuffled',
"description": '',
"label": 'Rocky Mountain BI Colors Contrast c14 Shuffled',
"colors": ['#063457', '#7b4a7b', '#d0696d', '#e5af55', '#45416f', '#ab5579', '#e4895d', '#42638a', '#a57ca0', '#e3a39d', '#f3ddad', '#776f9a', '#ca8d9f', '#f0bfa0']
},
{
"id": 'Rocky_Mountain_BI_Colors_Contrast_c12',
"description": '',
"label": 'Rocky Mountain BI Colors Contrast c12',
"isDefault": True,
"colors": ['#063457', '#504373', '#8f4e7c', '#c36073', '#e28260', '#e5af55', '#42638a', '#80729c', '#b582a0', '#da9a9e', '#eeb99e', '#f3ddad']
},
{
"id": 'Rocky_Mountain_BI_Colors_Contrast_c08',
"description": '',
"label": 'Rocky Mountain BI Colors Contrast c8',
"colors": ['#063457', '#7b4a7b', '#d0696d', '#e5af55', '#42638a', '#a57ca0', '#e3a39d', '#f3ddad']
}]
 
EXTRA_SEQUENTIAL_COLOR_SCHEMES = [
{
"id": 'Rocky_Mountain_BI_Colors_Divergent_Universal',
"description": '',
"label": 'Rocky Mountain BI Colors Divergent Universal',
"idDiverging": True,
"colors": ['#00446a', '#5f7995', '#a7b3c2', '#f1f1f1', '#cfb2a8', '#aa7764', '#813e27']
},
{
"id": 'Rocky_Mountain_BI_Colors_Sequential',
"description": '',
"label": 'Rocky Mountain BI Colors Sequential',
"idDiverging": False,
"colors": ['#e5af55', '#e58e5b', '#d87168', '#bd5d75', '#98507b', '#6b4879', '#3d3f6c', '#063457']
}]
 
def flask_app_mutator(app):
    try:
        security_manager = app.appbuilder.sm
        roles_to_create = ["myportaluser"]  # Only create default role - Azure groups handle the rest
       
        for role_name in roles_to_create:
            if not security_manager.find_role(role_name):
                logging.info(f"Creating missing role: {role_name}")
                security_manager.add_role(role_name)
            else:
                logging.info(f"Role already exists: {role_name}")
               
        logging.info("Finished checking/creating roles")
    except Exception as e:
        logging.exception(f"Error creating roles: {e}")
       
    @app.before_request
    def process_jwt_for_every_request():
        path = request.path
        logging.critical(f"BEFORE_REQUEST FIRED: {path}")
       
        if path.startswith('/static/') or path.startswith('/healthz'):
            return None
        token = request.args.get('proof')
        if not token and 'Proof' in request.headers:
            token = request.headers.get('Proof')
        if not token and 'Authorization' in request.headers:
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
       
        if token:
            logging.critical(f"TOKEN FOUND IN REQUEST: {path}")
           
            try:
                decoded = azure_token_validator.validate_token(token)
                username = decoded.get(JWT_IDENTITY_CLAIM)  # Use 'upn' not 'username'
               
                if username:
                    logging.critical(f"TOKEN USERNAME: {username}")
                   
                    try:
                        from flask_appbuilder.security.sqla.models import User
                        db = app.appbuilder.get_session
                        existing_user = db.query(User).filter_by(username=username).first()
                       
                        if existing_user:
                            logging.critical(f"USER EXISTS IN DB: {username}")
                        else:
                            logging.critical(f"USER DOES NOT EXIST IN DB, CREATING: {username}")
                    except ImportError as e:
                        logging.critical(f"Import error: {str(e)}")
                        existing_user = app.appbuilder.sm.find_user(username=username)
                        if existing_user:
                            logging.critical(f"USER EXISTS (via SM): {username}")
                        else:
                            logging.critical(f"USER DOES NOT EXIST (via SM): {username}")
                       
                        user_name = decoded.get('user_name', '')
                        email = decoded.get('email', username)
                        roles = decoded.get('roles', [])
                        name_parts = user_name.split(' ', 1)
                        first_name = name_parts[0] if len(name_parts) > 0 else ''
                        last_name = name_parts[1] if len(name_parts) > 1 else ''
                       
                        try:
                            sm = app.appbuilder.sm
                            role_objects = []
                            for role_name in roles:
                                role = sm.find_role(role_name)
                                if not role:
                                    role = sm.add_role(role_name)
                                    logging.critical(f"Created role: {role_name}")
                                role_objects.append(role)
                           
                            public_role = sm.find_role('myportaluser')
                            if public_role and public_role not in role_objects:
                                role_objects.append(public_role)
 
                            # Find or create the user
                            user = sm.find_user(username=username)
                            if not user:
                                user = sm.add_user(
                                    username=username,
                                    first_name=first_name,
                                    last_name=last_name,
                                    email=email,
                                    role=role_objects[0] if role_objects else None # First role is primary
                                )
 
                                logging.critical(f"Created user: {username}")
                                # Add additional roles
                                for role in role_objects[1:]:
                                    sm.add_user_role(new_user, role)
                            else:
                                logging.critical(f"User already exists: {username}")
                                # Update user roles. Important for role changes in the JWT.
                                user.roles = role_objects
                                logging.critical(f"Updated roles for user: {username} with {len(role_objects)} roles")
 
                           # *** CRITICAL: Set the user in the Flask login context ***
                            sm.set_flask_login_user(new_user)
                            logging.critical(f"Auto-logged in new user: {username}")
                           
                        except Exception as user_create_error:
                            logging.critical(f"Error creating user: {str(user_create_error)}")
                            logging.critical(traceback.format_exc())
                   
                    if not g.get('user') or not g.get('user').is_authenticated:
                        try:
                            user = app.appbuilder.sm.auth_user_jwt(token)
                            if user:
                                logging.critical(f"USER AUTHENTICATED: {user.username}")
                        except Exception as auth_error:
                            logging.critical(f"AUTH ERROR: {str(auth_error)}")
               
            except Exception as e:
                logging.critical(f"JWT PROCESSING ERROR: {str(e)}")
                logging.critical(traceback.format_exc())

    @app.route('/api/rmc/sso/init', methods=['POST'])
    def rmc_sso_init():
        try:
            data = request.get_json(silent=True) or {}
            payload_b64 = data.get('payload')
            sig = data.get('sig')
            if not payload_b64 or not sig:
                return (json.dumps({'error': 'missing payload or sig'}), 400, {'Content-Type': 'application/json'})

            # Get shared secret from environment variable (must match WordPress wp-config.php)
            shared = os.getenv('RMC_AUTH_KEY')
            if not shared:
                logging.critical("CRITICAL ERROR: RMC_AUTH_KEY not found in environment variables!")
                return (json.dumps({'error': 'server configuration error'}), 500, {'Content-Type': 'application/json'})

            try:
                payload_json = base64.urlsafe_b64decode(payload_b64 + '===').decode('utf-8')
            except Exception as e:
                logging.critical(f"Payload decode error before signature check: {str(e)}")
                return (json.dumps({'error': 'bad payload encoding'}), 400, {'Content-Type': 'application/json'})

            computed = hmac.new(shared.encode('utf-8'), payload_json.encode('utf-8'), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(computed, sig):
                return (json.dumps({'error': 'invalid signature'}), 401, {'Content-Type': 'application/json'})

            pointer = json.loads(payload_json)

            upn = pointer.get('upn') or pointer.get('email')
            name = pointer.get('name') or upn
            email = pointer.get('email') or upn
            if not upn:
                return (json.dumps({'error': 'missing upn'}), 400, {'Content-Type': 'application/json'})

            exchange_url = os.getenv('WP_SSO_EXCHANGE_URL', '')
            if exchange_url:
                try:
                    resp = requests.post(exchange_url, json={'payload': payload_b64, 'sig': sig}, timeout=5)
                    if resp.status_code == 200:
                        extra = resp.json()
                        upn = extra.get('upn', upn)
                        name = extra.get('name', name)
                        email = extra.get('email', email)
                except Exception as ex_err:
                    logging.critical(f"WP exchange error: {str(ex_err)}")

            resolved_role_names: list[str] = []
            try:
                mapping_db_uri = os.getenv('AZURE_SQL_CONNECTION_STRING')
                if mapping_db_uri:
                    from sqlalchemy import create_engine, text
                    engine = create_engine(mapping_db_uri, pool_pre_ping=True)
                    groups = pointer.get('groups') or []
                    if isinstance(groups, list) and groups:
                        # Map GUIDs to DisplayName
                        group_table = os.getenv('AZURE_ROLE_MAPPING_TABLE', 'dbo.ActiveEntraGroups')
                        group_id_col = os.getenv('AZURE_ROLE_MAPPING_GROUP_COL', 'GroupId')
                        group_name_col = os.getenv('AZURE_ROLE_MAPPING_ROLE_COL', 'DisplayName')
                        placeholders = ','.join([f":g{j}" for j in range(len(groups))])
                        sql = text(
                            f"SELECT {group_name_col} AS role_name FROM {group_table} WHERE {group_id_col} IN ({placeholders})"
                        )
                        params = {f"g{j}": groups[j] for j in range(len(groups))}
                        with engine.connect() as conn:
                            rows = conn.execute(sql, params).fetchall()
                            resolved_role_names.extend([r.role_name for r in rows if r.role_name])
                    else:
                        # Fallback to UPN→role mapping view
                        upn_table = os.getenv('AZURE_UPN_ROLE_VIEW', 'UserGroupMembershipView')
                        upn_col = os.getenv('AZURE_ROLE_MAPPING_UPN_COL', 'upn')
                        role_col = os.getenv('AZURE_ROLE_MAPPING_ROLE_COL', 'role_name')
                        sql = text(
                            f"SELECT {role_col} AS role_name FROM {upn_table} WHERE {upn_col} = :upn"
                        )
                        with engine.connect() as conn:
                            rows = conn.execute(sql, {'upn': upn}).fetchall()
                            resolved_role_names.extend([r.role_name for r in rows if r.role_name])
            except Exception as map_err:
                logging.critical(f"UPN role mapping error: {str(map_err)}")

            default_role_name = os.getenv('DEFAULT_PORTAL_ROLE', 'myportaluser')
            if default_role_name not in resolved_role_names:
                resolved_role_names.append(default_role_name)

            # Apply naming filters: startwith 'dashboard' or contains 'myportal'/'beta myportal'
            try:
                filtered: list[str] = []
                for rn in resolved_role_names:
                    lower = (rn or '').lower()
                    if lower.startswith('dashboard') or ('myportal' in lower) or ('beta myportal' in lower):
                        filtered.append(rn)
                if filtered:
                    resolved_role_names = filtered
            except Exception as _:
                pass

            # Ensure user and roles
            try:
                sm = app.appbuilder.sm
                user = sm.find_user(username=upn)
                first_name = name.split(' ', 1)[0] if name else upn
                last_name = name.split(' ', 1)[1] if name and ' ' in name else ''
                role_objects = []
                for rn in resolved_role_names:
                    role = sm.find_role(rn)
                    if not role:
                        role = sm.add_role(rn)
                        logging.critical(f"Created role: {rn}")
                    role_objects.append(role)
                if not user:
                    user = sm.add_user(
                        username=upn,
                        first_name=first_name,
                        last_name=last_name,
                        email=email,
                        role=role_objects[0] if role_objects else None
                    )
                else:
                    user.roles = role_objects
                    sm.update_user(user)
                # Log in
                from flask_login import login_user
                login_user(user)
                return (json.dumps({'status': 'ok', 'user': upn, 'roles': [r.name for r in user.roles]}), 200, {'Content-Type': 'application/json'})
            except Exception as user_err:
                logging.critical(f"User setup error: {str(user_err)}")
                return (json.dumps({'error': 'user setup failed'}), 500, {'Content-Type': 'application/json'})
        except Exception as e:
            logging.critical(f"SSO init error: {str(e)}")
            return (json.dumps({'error': 'server error'}), 500, {'Content-Type': 'application/json'})

    @app.route('/debug-jwt')
    def debug_jwt():
        token = request.args.get('proof')
        result = {"received_token": False}
        if token:
            result["received_token"] = True
            result["token_length"] = len(token)
            try:
                decoded = azure_token_validator.validate_token(token)
                result["payload"] = decoded
                current_timestamp = datetime.datetime.now().timestamp()
                if 'exp' in decoded:
                    exp_timestamp = decoded['exp']
                    result["token_expiration"] = {
                        "expires_at": exp_timestamp,
                        "current_time": current_timestamp,
                        "seconds_until_expiry": exp_timestamp - current_timestamp,
                        "is_expired": exp_timestamp <= current_timestamp
                    }
                configured_claim_present = JWT_IDENTITY_CLAIM in decoded
                result["token_identity"] = {
                    "has_username": "username" in decoded,
                    "has_sub": "sub" in decoded,
                    "configured_identity_claim": JWT_IDENTITY_CLAIM,
                    "configured_claim_present": configured_claim_present,
                    "identity_value": decoded.get(JWT_IDENTITY_CLAIM)
                }
                if not configured_claim_present:
                    result["identity_warning"] = f"The configured identity claim '{JWT_IDENTITY_CLAIM}' is missing from token!"
                    alternative_claims = []
                    if "username" in decoded and JWT_IDENTITY_CLAIM != "username":
                        alternative_claims.append("username")
                    if "sub" in decoded and JWT_IDENTITY_CLAIM != "sub":
                        alternative_claims.append("sub")
                    if alternative_claims:
                        result["identity_suggestion"] = f"Consider changing JWT_IDENTITY_CLAIM to one of these available claims: {alternative_claims}"
                logging.info(f"Successfully decoded token with payload: {json.dumps(decoded)}")
            except Exception as e:
                result["decode_error"] = str(e)
                logging.error(f"Error decoding token: {str(e)}")
        return json.dumps(result, indent=2)
 
    @app.route('/jwt-debug-status')
    def jwt_debug_status():
        result = {
            "before_request_registered": True,
            "app_name": app.name,
            "auth_type": app.config.get('AUTH_TYPE'),
            "jwt_settings": {
                "token_location": app.config.get('JWT_TOKEN_LOCATION'),
                "query_string_name": app.config.get('JWT_QUERY_STRING_NAME'),
                "identity_claim": app.config.get('JWT_IDENTITY_CLAIM')
            },
            "custom_sm_active": isinstance(app.appbuilder.sm, CustomSecurityManager),
            "username_key": app.appbuilder.sm.auth_user_jwt_username_key if hasattr(app.appbuilder.sm, 'auth_user_jwt_username_key') else None,
        }
       
        test_token = request.args.get('proof')
        if test_token:
            try:
                decoded = azure_token_validator.validate_token(test_token)
                result["token_test"] = {
                    "decoded": True,
                    "username": decoded.get('username'),
                    "roles": decoded.get('roles')
                }
               
                try:
                    auth_result = app.appbuilder.sm.auth_user_jwt(test_token)
                    result["auth_test"] = {
                        "success": auth_result is not None,
                        "username": auth_result.username if auth_result else None
                    }
                except Exception as auth_e:
                    result["auth_test"] = {
                        "success": False,
                        "error": str(auth_e)
                    }
            except Exception as e:
                result["token_test"] = {
                    "decoded": False,
                    "error": str(e)
                }
       
        return json.dumps(result, indent=2)
 
    @app.route('/check-roles')
    def check_roles():
        if not g.user or not g.user.is_authenticated:
            return json.dumps({"error": "Not authenticated", "status": "Please login with JWT token"})
       
        try:
            roles = [r.name for r in g.user.roles]
            permissions = list(g.user.permissions)
           
            return json.dumps({
                "username": g.user.username,
                "full_name": f"{g.user.first_name} {g.user.last_name}",
                "email": g.user.email,
                "roles": roles,
                "is_admin": g.user.is_admin(),
                "permissions": permissions
            }, indent=2)
        except Exception as e:
            return json.dumps({
                "error": "Error getting user details",
                "message": str(e),
                "traceback": traceback.format_exc()
            }, indent=2)

    @app.route('/test-template-functions')
    def test_template_functions():
        from superset import jinja_context
        import inspect
        import json
        
        result = {
            "available_functions": [],
            "test_results": {}
        }
        
        for name, func in inspect.getmembers(jinja_context, inspect.isfunction):
            result["available_functions"].append(name)
        
        if hasattr(jinja_context, 'current_username'):
            try:
                result["test_results"]["current_username"] = jinja_context.current_username()
            except Exception as e:
                result["test_results"]["current_username_error"] = str(e)
        else:
            result["test_results"]["current_username_error"] = "Function not found in jinja_context"
            
        if hasattr(jinja_context, 'current_user_id'):
            try:
                result["test_results"]["current_user_id"] = jinja_context.current_user_id()
            except Exception as e:
                result["test_results"]["current_user_id_error"] = str(e)
        else:
            result["test_results"]["current_user_id_error"] = "Function not found in jinja_context"
        
        result["jinja_context_addons"] = {k: str(v) for k, v in app.config.get('JINJA_CONTEXT_ADDONS', {}).items()}
        
        return json.dumps(result, indent=2)

    # Global request interceptor - handles ALL requests before route processing
    @app.before_request
    def intercept_authentication_requests():
        """
        Intercept root and login URLs and redirect to Microsoft authentication
        This runs BEFORE any route handler, ensuring it always executes
        """
        from flask import request, redirect, url_for
        from flask_login import current_user
        
        # Get the request path
        path = request.path
        
        # Only intercept root and login paths for unauthenticated users
        if path in ['/', '/login', '/login/']:
            # If user is already authenticated, let them continue
            if current_user and current_user.is_authenticated:
                return None  # Continue with normal request processing
            
            # User not authenticated - redirect to Microsoft OAuth
            return redirect(url_for('microsoft_auth'))
        
        # For all other requests, continue normal processing
        return None
    
    @app.route('/auth/microsoft')
    def microsoft_auth():
        """
        Custom Microsoft OAuth initiation - bypasses Flask-AppBuilder OAuth system
        Redirects directly to Microsoft authentication with proper callback URL
        """
        import secrets
        from flask import session, redirect
        
        # Generate state and nonce for security
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        
        # Store in session for validation
        session['oauth_state'] = state
        session['oauth_nonce'] = nonce
        
        # Build Microsoft OAuth URL with correct parameters
        tenant_id = AZURE_TENANT_ID
        client_id = AZURE_CLIENT_ID
        redirect_uri = "https://stg-dashboards.rmcare.com/auth/callback"
        
        microsoft_url = (
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
            f"?client_id={client_id}"
            f"&response_type=code"
            f"&redirect_uri={redirect_uri}"
            f"&scope=openid%20email%20profile%20User.Read%20Group.Read.All"
            f"&state={state}"
            f"&nonce={nonce}"
            f"&response_mode=query"
        )
        
        logging.critical(f"[CUSTOM OAUTH] Redirecting to Microsoft: {microsoft_url}")
        
        # Use JavaScript redirect to bypass reverse proxy URL interception
        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Redirecting to Microsoft...</title>
        </head>
        <body>
            <p>Redirecting to Microsoft authentication...</p>
            <script>
                window.location.href = "{microsoft_url}";
            </script>
        </body>
        </html>
        '''
    
    @app.route('/auth/callback')
    def microsoft_callback():
        """
        Custom Microsoft OAuth callback - handles the response from Microsoft
        Uses same unified user creation logic as WordPress JWT authentication
        """
        from flask import session, redirect, request
        import requests
        import traceback
        
        try:
            # Validate state parameter for security
            received_state = request.args.get('state')
            stored_state = session.get('oauth_state')
            
            if not received_state or not stored_state or received_state != stored_state:
                logging.error(f"OAuth state mismatch - security violation")
                return "Authentication failed: Invalid state parameter", 400
            
            # Get authorization code
            auth_code = request.args.get('code')
            if not auth_code:
                error = request.args.get('error')
                error_description = request.args.get('error_description')
                logging.error(f"OAuth error: {error} - {error_description}")
                return f"Authentication failed: {error_description or error}", 400
            
            # Exchange code for access token
            token_url = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/oauth2/v2.0/token"
            token_data = {
                'client_id': AZURE_CLIENT_ID,
                'client_secret': os.getenv('AZURE_CLIENT_SECRET', 'y1p8Q~fG~hGudO7N6s56Wj~82j0c56P5wfsnJb2a'),
                'code': auth_code,
                'grant_type': 'authorization_code',
                'redirect_uri': 'https://stg-dashboards.rmcare.com/auth/callback'
            }
            
            token_response = requests.post(token_url, data=token_data, timeout=10)
            if token_response.status_code != 200:
                logging.error(f"Token exchange failed: {token_response.status_code}")
                return "Authentication failed: Could not exchange code for token", 400
            
            token_info = token_response.json()
            access_token = token_info.get('access_token')
            
            if not access_token:
                logging.error("No access token in response")
                return "Authentication failed: No access token received", 400
            
            # Get user info from Microsoft Graph
            headers = {'Authorization': f'Bearer {access_token}'}
            
            # Get user profile
            user_response = requests.get('https://graph.microsoft.com/v1.0/me', headers=headers, timeout=10)
            if user_response.status_code != 200:
                logging.error(f"Failed to get user profile: {user_response.status_code}")
                return "Authentication failed: Could not retrieve user profile", 400
            
            user_data = user_response.json()
            user_id = user_data.get('userPrincipalName') or user_data.get('mail')
            display_name = user_data.get('displayName', user_id)
            
            # Get user groups
            groups_response = requests.get('https://graph.microsoft.com/v1.0/me/memberOf', headers=headers, timeout=10)
            group_ids = []
            if groups_response.status_code == 200:
                groups_data = groups_response.json()
                group_ids = [group['id'] for group in groups_data.get('value', [])]
                logging.info(f"Retrieved {len(group_ids)} Azure group GUIDs")
            else:
                logging.warning(f"Failed to get groups: {groups_response.status_code}")
            
            if not user_id:
                logging.error("No user identifier found in Microsoft response")
                return "Authentication failed: No user identifier found", 400
            
            # Azure group mapping
            resolved_role_names: list[str] = []
            try:
                mapping_db_uri = os.getenv('AZURE_SQL_CONNECTION_STRING')
                if not mapping_db_uri:
                    logging.critical("WARNING: No AZURE_SQL_CONNECTION_STRING found, skipping group mapping")
                else:
                    logging.critical(f"STEP 9: Azure SQL connection string found, length: {len(mapping_db_uri)}")
                    from sqlalchemy import create_engine, text
                    engine = create_engine(mapping_db_uri, pool_pre_ping=True)
                    
                    if isinstance(group_ids, list) and group_ids:
                        # Map GUIDs to DisplayName
                        group_table = os.getenv('AZURE_ROLE_MAPPING_TABLE', 'dbo.ActiveEntraGroups')
                        group_id_col = os.getenv('AZURE_ROLE_MAPPING_GROUP_COL', 'GroupId')
                        group_name_col = os.getenv('AZURE_ROLE_MAPPING_ROLE_COL', 'DisplayName')
                        logging.critical(f"STEP 10: Using Azure SQL table: {group_table}, Group ID column: {group_id_col}, Name column: {group_name_col}")
                        
                        placeholders = ','.join([f":g{j}" for j in range(len(group_ids))])
                        sql = text(
                            f"SELECT {group_name_col} AS role_name FROM {group_table} WHERE {group_id_col} IN ({placeholders})"
                        )
                        params = {f"g{j}": group_ids[j] for j in range(len(group_ids))}
                        logging.critical(f"STEP 11: Executing SQL query with {len(params)} parameters")
                        
                        with engine.connect() as conn:
                            rows = conn.execute(sql, params).fetchall()
                            logging.critical(f"STEP 12: Azure SQL query returned {len(rows)} rows")
                            for i, row in enumerate(rows):
                                logging.critical(f"STEP 12a: Row {i+1}: role_name = '{row.role_name}'")
                            resolved_role_names.extend([r.role_name for r in rows if r.role_name])
                            none_count = sum(1 for r in rows if r.role_name is None)
                            if none_count > 0:
                                logging.critical(f"WARNING: Found {none_count} NULL role names in Azure SQL results")
                        
                        logging.critical(f"STEP 13: After Azure SQL mapping, resolved {len(resolved_role_names)} role names: {resolved_role_names}")
                    else:
                        logging.critical("STEP 10b: No Azure group GUIDs found, falling back to UPN-based mapping")
                        # Fallback to UPN→role mapping view
                        upn_table = os.getenv('AZURE_UPN_ROLE_VIEW', 'UserGroupMembershipView')
                        upn_col = os.getenv('AZURE_ROLE_MAPPING_UPN_COL', 'upn')
                        role_col = os.getenv('AZURE_ROLE_MAPPING_ROLE_COL', 'role_name')
                        
                        sql = text(
                            f"SELECT {role_col} AS role_name FROM {upn_table} WHERE {upn_col} = :upn"
                        )
                        with engine.connect() as conn:
                            rows = conn.execute(sql, {'upn': user_id}).fetchall()
                            logging.critical(f"STEP 11b: UPN fallback query returned {len(rows)} rows")
                            resolved_role_names.extend([r.role_name for r in rows if r.role_name])
            except Exception as map_err:
                logging.error(f"Azure role mapping error: {str(map_err)}")
            
            # Role filtering
            default_role_name = os.getenv('DEFAULT_PORTAL_ROLE', 'myportaluser')
            
            # Apply naming filters: startwith 'dashboard' or contains 'myportal'/'beta myportal'
            try:
                filtered: list[str] = []
                for rn in resolved_role_names:
                    lower = (rn or '').lower()
                    if lower.startswith('dashboard') or ('myportal' in lower) or ('beta myportal' in lower):
                        filtered.append(rn)
                        logging.critical(f"STEP 15a: Role '{rn}' passed filter (matches dashboard/myportal criteria)")
                    else:
                        logging.critical(f"STEP 15b: Role '{rn}' FILTERED OUT (does not match dashboard/myportal criteria)")
                
                if filtered:
                    resolved_role_names = filtered
                    logging.critical(f"STEP 16: After filtering, kept {len(resolved_role_names)} roles: {resolved_role_names}")
                else:
                    logging.critical("STEP 16: No roles passed filter, keeping original list")
            except Exception as filter_err:
                logging.critical(f"ERROR: Role filtering error: {str(filter_err)}")
            
            if default_role_name not in resolved_role_names:
                resolved_role_names.append(default_role_name)
                logging.critical(f"STEP 17: Added default role '{default_role_name}' to role list")
            
            logging.critical(f"STEP 18: FINAL ROLE LIST for user {user_id}: {resolved_role_names}")
            
            # Prepare user info in same format as JWT authentication
            user_info = {
                'email': user_id,
                'name': display_name,
                'given_name': user_data.get('givenName', ''),
                'family_name': user_data.get('surname', ''),
                'groups': group_ids  # Use same key as WordPress authentication
            }
            
            # User creation and role assignment
            security_manager = app.appbuilder.sm
            user = security_manager._create_or_update_user(user_id, user_info, 'microsoft_oauth')
            
            if user:
                logging.info(f"Microsoft OAuth authentication successful for {user_id}")
                
                # Log the user in using Flask-Login
                from flask_login import login_user
                login_user(user)
                
                # Store authentication method in session
                session['auth_method'] = 'microsoft_oauth'
                session['azure_user_email'] = user_id
                
                # Clean up OAuth session data
                session.pop('oauth_state', None)
                session.pop('oauth_nonce', None)
                
                # Redirect to Superset dashboard
                return redirect('/')
            else:
                logging.error(f"Failed to create/update user for {user_id}")
                return "Authentication failed: Could not create user account", 500
                
        except Exception as e:
            logging.error(f"Microsoft OAuth callback error: {str(e)}")
            return "Authentication failed: Internal error", 500
 
    return app
 
FLASK_APP_MUTATOR = flask_app_mutator
RECAPTCHA_PUBLIC_KEY = ""

# Global request logging to debug WordPress-to-Superset connectivity
def log_all_requests(app):
    @app.before_request
    def before_request():
        # Security check: Block direct dashboard access for unauthenticated users
        # Allow WordPress iframe embedding with ?standalone=1
        if request.path.startswith('/superset/dashboard/'):
            is_standalone = request.args.get('standalone') == '1'
            
            # If NOT standalone mode (direct access), check authentication
            if not is_standalone:
                from flask import g, redirect, url_for, current_app
                
                # Check if user only has public role (unauthenticated)
                if hasattr(g, 'user') and g.user and hasattr(g.user, 'roles'):
                    user_roles = [role.name for role in g.user.roles] if g.user.roles else []
                    public_role_name = current_app.config.get('AUTH_ROLE_PUBLIC', 'Public')
                    
                    # If user only has public role, they need to authenticate for direct access
                    if len(user_roles) == 1 and public_role_name in user_roles:
                        logging.info(f"Blocking direct dashboard access - user has only public role")
                        return redirect('/auth/microsoft')
    
    return app

# Apply request logging
if not hasattr(FLASK_APP_MUTATOR, '__wrapped__'):
    original_mutator = FLASK_APP_MUTATOR
    def enhanced_mutator(app):
        app = original_mutator(app)
        app = log_all_requests(app)
        return app
    FLASK_APP_MUTATOR = enhanced_mutator