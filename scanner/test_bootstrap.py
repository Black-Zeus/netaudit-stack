#!/usr/bin/env python3
"""
Script de prueba para el módulo de Bootstrap de Netbox
Ejecutar con: python test_bootstrap.py
"""

import os
import sys
from dotenv import load_dotenv

# Añadir directorio padre al path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import setup_logger, NetboxBootstrap

# Cargar variables de entorno
load_dotenv()

# Configurar logging
logger = setup_logger('test_bootstrap', level='INFO')


def main():
    """Prueba el sistema de bootstrap"""
    
    logger.info("=" * 70)
    logger.info("🧪 TEST - NetAudit Netbox Bootstrap")
    logger.info("=" * 70)
    logger.info("")
    
    # Configuración
    netbox_url = os.getenv('NETBOX_URL', 'http://192.168.3.251:8100')
    netbox_token = os.getenv('NETBOX_TOKEN', '')
    config_dir = '/app/config'
    
    if not netbox_token:
        logger.error("❌ NETBOX_TOKEN no está configurado en .env")
        sys.exit(1)
    
    logger.info(f"Netbox URL: {netbox_url}")
    logger.info(f"Config dir: {config_dir}")
    logger.info("")
    
    try:
        # 1. Crear instancia de bootstrap
        bootstrap = NetboxBootstrap(
            netbox_url=netbox_url,
            netbox_token=netbox_token,
            config_dir=config_dir
        )
        
        # 2. Verificar si debe ejecutarse
        should_run = bootstrap.should_bootstrap()
        logger.info(f"¿Debe ejecutar bootstrap?: {'✅ Sí' if should_run else '❌ No'}")
        logger.info("")
        
        if not should_run:
            logger.info("ℹ️  Bootstrap ya fue ejecutado previamente")
            logger.info("   Para forzar ejecución: export FORCE_BOOTSTRAP=true")
            logger.info("")
            
            # Mostrar qué haría si se ejecutara
            logger.info("📋 Vista previa de configuración:")
            config = bootstrap.load_config()
            return
        
        # 3. Ejecutar bootstrap
        stats = bootstrap.run()
        
        # 4. Verificar resultados
        logger.info("")
        logger.info("=" * 70)
        logger.info("✅ TEST COMPLETADO EXITOSAMENTE")
        logger.info("=" * 70)
        logger.info("")
        logger.info("Puedes verificar los objetos creados en:")
        logger.info(f"  {netbox_url}")
        logger.info("")
        logger.info("Secciones a revisar:")
        logger.info("  - Organization → Sites")
        logger.info("  - Devices → Manufacturers")
        logger.info("  - Devices → Device Types")
        logger.info("  - Devices → Device Roles")
        logger.info("  - Other → Tags")
        logger.info("")
        
    except KeyboardInterrupt:
        logger.warning("\n⚠️  Test interrumpido por el usuario")
        sys.exit(1)
    except Exception as e:
        logger.error(f"\n❌ Error durante el test: {e}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()