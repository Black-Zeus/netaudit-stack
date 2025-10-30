"""
Módulo de configuración de logging
"""

import logging
import os
from pathlib import Path
from datetime import datetime
import colorlog

def setup_logger(name: str = 'netaudit', log_file: str = None, level: str = None) -> logging.Logger:
    """
    Configura el sistema de logging con colores y archivo
    
    Args:
        name: Nombre del logger
        log_file: Ruta del archivo de log (opcional)
        level: Nivel de log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        
    Returns:
        Logger configurado
    """
    
    # Obtener nivel de log desde env o usar INFO por defecto
    if not level:
        level = os.getenv('LOG_LEVEL', 'INFO').upper()
    
    # Obtener archivo de log desde env si no se especificó
    if not log_file:
        log_file = os.getenv('LOG_FILE', '/app/logs/scanner.log')
    
    # Crear directorio de logs si no existe
    log_dir = Path(log_file).parent
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Crear logger
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level))
    
    # Limpiar handlers existentes
    logger.handlers.clear()
    
    # Formato para consola con colores
    console_formatter = colorlog.ColoredFormatter(
        '%(log_color)s%(levelname)-8s%(reset)s %(cyan)s%(name)s%(reset)s - %(message)s',
        log_colors={
            'DEBUG': 'white',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'bold_red',
        }
    )
    
    # Formato para archivo (sin colores)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Handler para consola
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, level))
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # Handler para archivo
    try:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(getattr(logging, level))
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        logger.warning(f"No se pudo crear el archivo de log: {e}")
    
    # No propagar a root logger
    logger.propagate = False
    
    return logger

def get_logger(name: str = 'netaudit') -> logging.Logger:
    """
    Obtiene un logger existente o crea uno nuevo
    
    Args:
        name: Nombre del logger
        
    Returns:
        Logger
    """
    logger = logging.getLogger(name)
    
    # Si no tiene handlers, configurarlo
    if not logger.handlers:
        return setup_logger(name)
    
    return logger
