"""
Módulo de Bootstrap de Netbox - Configuración Base desde YAML
Carga configuración desde archivos YAML y crea objetos en Netbox de forma idempotente
"""

import os
import logging
from pathlib import Path
from typing import Dict, List, Optional
import yaml
import pynetbox

logger = logging.getLogger(__name__)


class NetboxBootstrap:
    """Gestiona la configuración inicial de Netbox desde archivos YAML"""
    
    def __init__(self, netbox_url: str, netbox_token: str, config_dir: str = '/app/config'):
        """
        Inicializa el bootstrap
        
        Args:
            netbox_url: URL de Netbox
            netbox_token: Token de API
            config_dir: Directorio con archivos YAML
        """
        self.nb = pynetbox.api(netbox_url, token=netbox_token)
        self.config_dir = Path(config_dir)
        
        # Archivos de configuración
        self.base_config_file = self.config_dir / 'netbox_bootstrap.yaml'
        self.custom_config_file = self.config_dir / 'netbox_custom.yaml'
        
        # Configuración cargada y mergeada
        self.config = {}
        
        # Estadísticas de creación
        self.stats = {
            'sites': {'created': 0, 'existing': 0},
            'manufacturers': {'created': 0, 'existing': 0},
            'device_types': {'created': 0, 'existing': 0},
            'device_roles': {'created': 0, 'existing': 0},
            'tags': {'created': 0, 'existing': 0},
        }
        
        # Cache de objetos creados (por slug)
        self.cache = {
            'sites': {},
            'manufacturers': {},
            'device_types': {},
            'device_roles': {},
            'tags': {},
        }
    
    def should_bootstrap(self) -> bool:
        """
        Determina si se debe ejecutar el bootstrap
        
        Criterios:
        1. Primera ejecución (no hay tags de estado)
        2. Forzado por variable de entorno
        3. Archivos YAML modificados recientemente
        
        Returns:
            True si debe ejecutarse bootstrap
        """
        # Verificar variable de entorno
        force_bootstrap = os.getenv('FORCE_BOOTSTRAP', 'false').lower() == 'true'
        if force_bootstrap:
            logger.info("Bootstrap forzado por FORCE_BOOTSTRAP=true")
            return True
        
        try:
            # Verificar si existen los tags de estado
            # Si no existen, es primera ejecución
            state_tags = ['descubierto', 'escaneando', 'completado', 'error']
            existing_tags = [self.nb.extras.tags.get(slug=slug) for slug in state_tags]
            
            if not all(existing_tags):
                logger.info("Tags de estado no encontrados - Primera ejecución detectada")
                return True
            
            # Si ya hay tags, no hacer bootstrap a menos que se fuerce
            logger.info("Bootstrap ya ejecutado previamente")
            return False
            
        except Exception as e:
            logger.warning(f"Error verificando estado de bootstrap: {e}")
            # En caso de error, ejecutar bootstrap por seguridad
            return True
    
    def load_config(self) -> Dict:
        """
        Carga y mergea configuraciones desde YAML
        
        Orden de carga:
        1. netbox_bootstrap.yaml (base)
        2. netbox_custom.yaml (usuario - sobrescribe/añade)
        
        Returns:
            Configuración mergeada
        """
        logger.info("=" * 60)
        logger.info("📋 Cargando configuración de bootstrap")
        logger.info("=" * 60)
        logger.info("")
        
        config = {}
        
        # 1. Cargar configuración base
        if self.base_config_file.exists():
            logger.info(f"  ✓ Cargando: {self.base_config_file.name}")
            with open(self.base_config_file, 'r', encoding='utf-8') as f:
                base_config = yaml.safe_load(f) or {}
                config = base_config.copy()
            logger.info(f"    - Versión: {config.get('version', 'N/A')}")
        else:
            logger.warning(f"  ⚠ No encontrado: {self.base_config_file.name}")
        
        # 2. Cargar configuración custom y mergear
        if self.custom_config_file.exists():
            logger.info(f"  ✓ Cargando: {self.custom_config_file.name}")
            with open(self.custom_config_file, 'r', encoding='utf-8') as f:
                custom_config = yaml.safe_load(f) or {}
                
            # Mergear: custom añade/sobrescribe base
            config = self._merge_configs(config, custom_config)
            logger.info(f"    - Configuraciones mergeadas exitosamente")
        else:
            logger.info(f"  ○ No encontrado: {self.custom_config_file.name} (opcional)")
        
        logger.info("")
        logger.info("📊 Resumen de configuración:")
        logger.info(f"  - Sites: {len(config.get('sites', []))}")
        logger.info(f"  - Manufacturers: {len(config.get('manufacturers', []))}")
        logger.info(f"  - Device Types: {len(config.get('device_types', []))}")
        logger.info(f"  - Device Roles: {len(config.get('device_roles', []))}")
        logger.info(f"  - Tags: {len(config.get('tags', []))}")
        logger.info("")
        
        self.config = config
        return config
    
    def _merge_configs(self, base: Dict, custom: Dict) -> Dict:
        """
        Mergea configuración custom sobre base
        
        Estrategia:
        - Para listas (sites, manufacturers, etc): añade items nuevos, sobrescribe por slug
        - Items sin slug: se añaden al final
        
        Args:
            base: Configuración base
            custom: Configuración custom
            
        Returns:
            Configuración mergeada
        """
        merged = base.copy()
        
        # Categorías que son listas de objetos
        list_categories = ['sites', 'manufacturers', 'device_types', 'device_roles', 'tags']
        
        for category in list_categories:
            if category not in custom:
                continue
            
            base_items = merged.get(category, [])
            custom_items = custom.get(category, [])
            
            # Crear índice de items base por slug
            base_by_slug = {item.get('slug'): item for item in base_items if 'slug' in item}
            
            # Procesar items custom
            for custom_item in custom_items:
                slug = custom_item.get('slug')
                
                if slug and slug in base_by_slug:
                    # Sobrescribir item existente
                    idx = next(i for i, item in enumerate(base_items) if item.get('slug') == slug)
                    base_items[idx] = custom_item
                    logger.debug(f"  → Sobrescrito {category}/{slug}")
                else:
                    # Añadir nuevo item
                    base_items.append(custom_item)
                    logger.debug(f"  → Añadido {category}/{slug if slug else 'sin-slug'}")
            
            merged[category] = base_items
        
        # Otras configuraciones (no listas): custom sobrescribe
        for key, value in custom.items():
            if key not in list_categories:
                merged[key] = value
        
        return merged
    
    def run(self) -> Dict:
        """
        Ejecuta el proceso completo de bootstrap
        
        Returns:
            Estadísticas de objetos creados
        """
        logger.info("=" * 60)
        logger.info("🚀 Iniciando Bootstrap de Netbox")
        logger.info("=" * 60)
        logger.info("")
        
        try:
            # 1. Cargar configuración
            self.load_config()
            
            # 2. Verificar conexión con Netbox
            logger.info("🔌 Verificando conexión con Netbox...")
            try:
                self.nb.status()
                logger.info("  ✓ Conexión exitosa")
                logger.info("")
            except Exception as e:
                logger.error(f"  ✗ Error de conexión: {e}")
                raise
            
            # 3. Crear objetos en orden de dependencias
            logger.info("📦 Creando objetos en Netbox...")
            logger.info("")
            
            self._create_sites()
            self._create_manufacturers()
            self._create_device_types()
            self._create_device_roles()
            self._create_tags()
            
            # 4. Mostrar resumen
            self._print_summary()
            
            return self.stats
            
        except Exception as e:
            logger.error(f"❌ Error durante bootstrap: {e}")
            raise
    
    def _create_sites(self):
        """Crea Sites en Netbox"""
        sites = self.config.get('sites', [])
        if not sites:
            return
        
        logger.info("📍 Creando Sites...")
        
        for site_data in sites:
            slug = site_data.get('slug')
            name = site_data.get('name')
            
            try:
                # Buscar si existe
                existing = self.nb.dcim.sites.get(slug=slug)
                
                if existing:
                    logger.info(f"  ○ Ya existe: {name} ({slug})")
                    self.stats['sites']['existing'] += 1
                    self.cache['sites'][slug] = existing
                else:
                    # Crear nuevo
                    site = self.nb.dcim.sites.create(
                        name=name,
                        slug=slug,
                        description=site_data.get('description', ''),
                        status=site_data.get('status', 'active')
                    )
                    logger.info(f"  ✓ Creado: {name} ({slug})")
                    self.stats['sites']['created'] += 1
                    self.cache['sites'][slug] = site
                    
            except Exception as e:
                logger.error(f"  ✗ Error creando site {slug}: {e}")
        
        logger.info("")
    
    def _create_manufacturers(self):
        """Crea Manufacturers en Netbox"""
        manufacturers = self.config.get('manufacturers', [])
        if not manufacturers:
            return
        
        logger.info("🏭 Creando Manufacturers...")
        
        for mfg_data in manufacturers:
            slug = mfg_data.get('slug')
            name = mfg_data.get('name')
            
            try:
                # Buscar si existe
                existing = self.nb.dcim.manufacturers.get(slug=slug)
                
                if existing:
                    logger.info(f"  ○ Ya existe: {name} ({slug})")
                    self.stats['manufacturers']['existing'] += 1
                    self.cache['manufacturers'][slug] = existing
                else:
                    # Crear nuevo
                    mfg = self.nb.dcim.manufacturers.create(
                        name=name,
                        slug=slug,
                        description=mfg_data.get('description', '')
                    )
                    logger.info(f"  ✓ Creado: {name} ({slug})")
                    self.stats['manufacturers']['created'] += 1
                    self.cache['manufacturers'][slug] = mfg
                    
            except Exception as e:
                logger.error(f"  ✗ Error creando manufacturer {slug}: {e}")
        
        logger.info("")
    
    def _create_device_types(self):
        """Crea Device Types en Netbox"""
        device_types = self.config.get('device_types', [])
        if not device_types:
            return
        
        logger.info("📱 Creando Device Types...")
        
        for dt_data in device_types:
            slug = dt_data.get('slug')
            model = dt_data.get('model')
            mfg_slug = dt_data.get('manufacturer_slug')
            
            try:
                # Buscar si existe
                existing = self.nb.dcim.device_types.get(slug=slug)
                
                if existing:
                    logger.info(f"  ○ Ya existe: {model} ({slug})")
                    self.stats['device_types']['existing'] += 1
                    self.cache['device_types'][slug] = existing
                else:
                    # Obtener manufacturer
                    mfg = self.cache.get('manufacturers', {}).get(mfg_slug)
                    if not mfg:
                        mfg = self.nb.dcim.manufacturers.get(slug=mfg_slug)
                    
                    if not mfg:
                        logger.warning(f"  ⚠ Manufacturer {mfg_slug} no encontrado para {model}")
                        continue
                    
                    # Crear nuevo
                    dt = self.nb.dcim.device_types.create(
                        manufacturer=mfg.id,
                        model=model,
                        slug=slug
                    )
                    logger.info(f"  ✓ Creado: {model} ({slug})")
                    self.stats['device_types']['created'] += 1
                    self.cache['device_types'][slug] = dt
                    
            except Exception as e:
                logger.error(f"  ✗ Error creando device type {slug}: {e}")
        
        logger.info("")
    
    def _create_device_roles(self):
        """Crea Device Roles en Netbox"""
        device_roles = self.config.get('device_roles', [])
        if not device_roles:
            return
        
        logger.info("🎭 Creando Device Roles...")
        
        for role_data in device_roles:
            slug = role_data.get('slug')
            name = role_data.get('name')
            
            try:
                # Buscar si existe
                existing = self.nb.dcim.device_roles.get(slug=slug)
                
                if existing:
                    logger.info(f"  ○ Ya existe: {name} ({slug})")
                    self.stats['device_roles']['existing'] += 1
                    self.cache['device_roles'][slug] = existing
                else:
                    # Crear nuevo
                    role = self.nb.dcim.device_roles.create(
                        name=name,
                        slug=slug,
                        color=role_data.get('color', '9e9e9e'),
                        description=role_data.get('description', '')
                    )
                    logger.info(f"  ✓ Creado: {name} ({slug})")
                    self.stats['device_roles']['created'] += 1
                    self.cache['device_roles'][slug] = role
                    
            except Exception as e:
                logger.error(f"  ✗ Error creando device role {slug}: {e}")
        
        logger.info("")
    
    def _create_tags(self):
        """Crea Tags en Netbox"""
        tags = self.config.get('tags', [])
        if not tags:
            return
        
        logger.info("🏷️  Creando Tags...")
        
        for tag_data in tags:
            slug = tag_data.get('slug')
            name = tag_data.get('name')
            
            try:
                # Buscar si existe
                existing = self.nb.extras.tags.get(slug=slug)
                
                if existing:
                    logger.info(f"  ○ Ya existe: {name} ({slug})")
                    self.stats['tags']['existing'] += 1
                    self.cache['tags'][slug] = existing
                else:
                    # Crear nuevo
                    tag = self.nb.extras.tags.create(
                        name=name,
                        slug=slug,
                        color=tag_data.get('color', '9e9e9e'),
                        description=tag_data.get('description', '')
                    )
                    logger.info(f"  ✓ Creado: {name} ({slug})")
                    self.stats['tags']['created'] += 1
                    self.cache['tags'][slug] = tag
                    
            except Exception as e:
                logger.error(f"  ✗ Error creando tag {slug}: {e}")
        
        logger.info("")
    
    def _print_summary(self):
        """Imprime resumen de objetos creados"""
        logger.info("=" * 60)
        logger.info("📊 RESUMEN DEL BOOTSTRAP")
        logger.info("=" * 60)
        logger.info("")
        
        total_created = sum(s['created'] for s in self.stats.values())
        total_existing = sum(s['existing'] for s in self.stats.values())
        
        logger.info(f"{'Categoría':<20} {'Creados':<10} {'Existentes':<10}")
        logger.info("-" * 40)
        
        for category, counts in self.stats.items():
            cat_name = category.replace('_', ' ').title()
            logger.info(f"{cat_name:<20} {counts['created']:<10} {counts['existing']:<10}")
        
        logger.info("-" * 40)
        logger.info(f"{'TOTAL':<20} {total_created:<10} {total_existing:<10}")
        logger.info("")
        
        if total_created > 0:
            logger.info(f"✅ Bootstrap completado: {total_created} objetos creados")
        else:
            logger.info(f"✅ Bootstrap verificado: todos los objetos ya existían")
        
        logger.info("=" * 60)
        logger.info("")
    
    def get_cached_object(self, category: str, slug: str):
        """
        Obtiene un objeto del cache o lo busca en Netbox
        
        Args:
            category: Categoría (sites, manufacturers, etc)
            slug: Slug del objeto
            
        Returns:
            Objeto de Netbox o None
        """
        # Buscar en cache
        if slug in self.cache.get(category, {}):
            return self.cache[category][slug]
        
        # Buscar en Netbox según categoría
        try:
            if category == 'sites':
                obj = self.nb.dcim.sites.get(slug=slug)
            elif category == 'manufacturers':
                obj = self.nb.dcim.manufacturers.get(slug=slug)
            elif category == 'device_types':
                obj = self.nb.dcim.device_types.get(slug=slug)
            elif category == 'device_roles':
                obj = self.nb.dcim.device_roles.get(slug=slug)
            elif category == 'tags':
                obj = self.nb.extras.tags.get(slug=slug)
            else:
                return None
            
            # Guardar en cache
            if obj:
                if category not in self.cache:
                    self.cache[category] = {}
                self.cache[category][slug] = obj
            
            return obj
            
        except Exception as e:
            logger.debug(f"Error buscando {category}/{slug}: {e}")
            return None