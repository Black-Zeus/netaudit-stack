"""
Netbox Configuration for NetAudit HomeStack
"""

import os

# CRITICAL: Required parameters
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '*').split(' ')

# Database configuration
DATABASE = {
    'NAME': os.environ.get('DB_NAME', 'netbox'),
    'USER': os.environ.get('DB_USER', 'netbox'),
    'PASSWORD': os.environ.get('DB_PASSWORD', ''),
    'HOST': os.environ.get('DB_HOST', 'postgres'),
    'PORT': os.environ.get('DB_PORT', '5432'),
    'CONN_MAX_AGE': 300,
}

# Redis configuration
REDIS = {
    'tasks': {
        'HOST': os.environ.get('REDIS_HOST', 'redis'),
        'PORT': int(os.environ.get('REDIS_PORT', 6379)),
        'PASSWORD': os.environ.get('REDIS_PASSWORD', ''),
        'DATABASE': int(os.environ.get('REDIS_DATABASE', 0)),
        'SSL': False,
    },
    'caching': {
        'HOST': os.environ.get('REDIS_CACHE_HOST', 'redis-cache'),
        'PORT': int(os.environ.get('REDIS_CACHE_PORT', 6379)),
        'PASSWORD': os.environ.get('REDIS_CACHE_PASSWORD', ''),
        'DATABASE': int(os.environ.get('REDIS_CACHE_DATABASE', 1)),
        'SSL': False,
    }
}

# Secret key
SECRET_KEY = os.environ.get('SECRET_KEY', '')

# Permitir registrar IPs duplicadas
ENFORCE_GLOBAL_UNIQUE = False

# Permitir subnets superpuestas
ALLOW_DUPLICATE_SUBNETS = True

# Configuración de autenticación
LOGIN_REQUIRED = True
LOGIN_TIMEOUT = 1209600  # 2 semanas

# Paginación
PAGINATE_COUNT = 50
MAX_PAGE_SIZE = 1000

# Banner personalizado
BANNER_TOP = ''
BANNER_BOTTOM = ''
BANNER_LOGIN = 'NetAudit HomeStack - Sistema de Auditoría de Red'

# Configuración de tiempo
TIME_ZONE = os.environ.get('TZ', 'America/Santiago')
DATE_FORMAT = 'Y-m-d'
SHORT_DATE_FORMAT = 'Y-m-d'
TIME_FORMAT = 'H:i:s'
SHORT_TIME_FORMAT = 'H:i'
DATETIME_FORMAT = 'Y-m-d H:i:s'
SHORT_DATETIME_FORMAT = 'Y-m-d H:i'

# Preferencias de la aplicación
PREFER_IPV4 = True

# Changelog retention (días que se guardan los cambios)
CHANGELOG_RETENTION = 90

# Job result retention (días que se guardan resultados de jobs)
JOBRESULT_RETENTION = 90

# Habilitar GraphQL
GRAPHQL_ENABLED = True

# Configuración de plugins
PLUGINS = []
PLUGINS_CONFIG = {}