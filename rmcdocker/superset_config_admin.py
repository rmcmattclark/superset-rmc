# superset_config_admin.py
# Standard Superset configuration for admin access via port 8090
# Uses default Flask-AppBuilder authentication (AUTH_DB) with admin credentials

import os
import logging

# Setup basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Core database configuration (shared with main container)
SECRET_KEY = os.getenv("SUPERSET_SECRET_KEY")
SQLALCHEMY_DATABASE_URI = os.getenv("SUPERSET_DB_URI")

if not SQLALCHEMY_DATABASE_URI:
    raise RuntimeError(
        "The SUPERSET_DB_URI environment variable is not set! "
        "Please ensure it's defined in your .env file and passed "
        "correctly to the Docker container."
    )

# Standard database authentication (no custom security manager)
from flask_appbuilder.security.manager import AUTH_DB
AUTH_TYPE = AUTH_DB
AUTH_USER_REGISTRATION = False  # Disable self-registration for security
AUTH_USER_REGISTRATION_ROLE = "Public"

# Security settings
WTF_CSRF_ENABLED = False  # Disable CSRF to match staging environment
WTF_CSRF_CHECK_DEFAULT = False
CSRF_ENABLED = False
ENABLE_PROXY_FIX = True

# Redis & Celery configuration (shared with main container)
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")
REDIS_DB = os.getenv("REDIS_CELERY_DB", "0")
REDIS_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"

# Celery config (for background tasks)
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

# Caching config (shared Redis instance)
CACHE_CONFIG = {
    "CACHE_TYPE": "RedisCache",
    "CACHE_DEFAULT_TIMEOUT": 300,
    "CACHE_KEY_PREFIX": "superset_admin_",
    "CACHE_REDIS_HOST": REDIS_HOST,
    "CACHE_REDIS_PORT": REDIS_PORT,
    "CACHE_REDIS_DB": 1,
    "CACHE_REDIS_URL": f"redis://{REDIS_HOST}:{REDIS_PORT}/1",
}
DATA_CACHE_CONFIG = CACHE_CONFIG

# Visual Customizations (same as main container)
FAVICONS = [{"href": "/static/assets/custom/RMC_100.png"}]
APP_FAB_UI_BRAND_INFO = {
    "logo_icon": "/static/assets/custom/RMC_100.png",
    "logo_icon_width": 200,
    "logo_icon_target_path": "http://www.rockymountaincare.com/",
    "logo_icon_tooltip": "rockymountaincare.com",
    "brand_text": "RMC SUPERSET ADMIN",
}

# Database query limits
SQL_MAX_ROW = 50000
VIZ_ROW_LIMIT = 50000

# Enable SQL Lab and stored procedures
ALLOW_DML = True

# Enable Security views in Superset UI
FAB_ADD_SECURITY_VIEWS = True

# MapBox API Key (shared configuration)
MAPBOX_API_KEY = os.getenv("MAPBOX_API_KEY")

# Feature flags (enable standard Superset features)
FEATURE_FLAGS = {
    'ENABLE_TEMPLATE_PROCESSING': True,
    'ALLOW_RUN_ASYNC': True,
    'DASHBOARD_RBAC': True,
    "HORIZONTAL_FILTER_BAR": True
}

# Colors schemes (same as main container)
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

# Session Configuration - Match main container for user compatibility
SESSION_COOKIE_DOMAIN = '.rmcare.com'  # Same as main container for shared sessions
SESSION_COOKIE_SECURE = True  # HTTPS only in production
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'None'  # Match main container settings
SESSION_PERMANENT = False
PERMANENT_SESSION_LIFETIME = 3600  # 1 hour session timeout

# This new flag sets the horizontal layout as the default for all NEW dashboards
DASHBOARD_HORIZONTAL_FILTER_BAR_DEFAULT = True

# No custom Flask app mutator - use standard Superset behavior
def flask_app_mutator(app):
    """
    App mutator that ensures required roles exist and logs user information
    """
    try:
        security_manager = app.appbuilder.sm
        
        # Ensure basic roles exist
        required_roles = ["Admin", "Alpha", "Gamma", "Public"]
        
        for role_name in required_roles:
            if not security_manager.find_role(role_name):
                logging.info(f"Creating missing role: {role_name}")
                security_manager.add_role(role_name)
            else:
                logging.info(f"Role already exists: {role_name}")
        
        # Debug: List existing users and their roles
        try:
            users = security_manager.get_all_users()
            logging.info(f"Found {len(users)} users in database:")
            for user in users[:10]:  # Limit to first 10 users for log readability
                roles = [role.name for role in user.roles] if user.roles else []
                logging.info(f"  User: {user.username} | Email: {user.email} | Roles: {roles}")
        except Exception as user_debug_error:
            logging.warning(f"Could not debug users: {user_debug_error}")
        
        logging.info("Admin container initialization complete")
        
    except Exception as e:
        logging.exception(f"Error in admin app mutator: {e}")

FLASK_APP_MUTATOR = flask_app_mutator

# Disable reCAPTCHA
RECAPTCHA_PUBLIC_KEY = ""

logging.info("========== ADMIN CONTAINER CONFIGURATION LOADED ==========")
logging.info("Using standard Flask-AppBuilder AUTH_DB authentication")
logging.info("Admin access available on port 8090")
logging.info("Login page: http://wx-rpt-02l.rmcare.com:8090/login/")