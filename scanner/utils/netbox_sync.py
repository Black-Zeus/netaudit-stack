"""
Módulo de sincronización con Netbox - VERSIÓN CORREGIDA
"""

import pynetbox
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

class NetboxSync:
    """Sincroniza dispositivos descubiertos con Netbox"""
    
    def __init__(self, url: str, token: str):
        """
        Inicializa la conexión con Netbox
        
        Args:
            url: URL de Netbox
            token: Token de API
        """
        self.nb = pynetbox.api(url, token=token)
        self.stats = {
            'created': 0,
            'updated': 0,
            'unchanged': 0,
            'errors': 0
        }
        
        # Cache de objetos para evitar consultas repetidas
        self.cache = {
            'site': None,
            'manufacturer': None,
            'device_types': {},
            'device_roles': {},
            'tags': {}
        }
    
    def test_connection(self) -> bool:
        """Prueba la conexión con Netbox"""
        try:
            # Intentar obtener el status de Netbox
            self.nb.status()
            return True
        except Exception as e:
            logger.error(f"No se pudo conectar con Netbox: {e}")
            return False
    
    def sync_devices(self, devices: List[Dict]) -> Dict:
        """
        Sincroniza lista de dispositivos con Netbox
        
        Args:
            devices: Lista de dispositivos descubiertos
            
        Returns:
            Estadísticas de sincronización
        """
        logger.info(f"Sincronizando {len(devices)} dispositivos con Netbox...")
        logger.info("")
        
        # Reiniciar estadísticas
        self.stats = {'created': 0, 'updated': 0, 'unchanged': 0, 'errors': 0}
        
        # Asegurar que existen los objetos base en Netbox
        self._ensure_base_objects()
        
        for idx, device in enumerate(devices, 1):
            try:
                logger.info(f"[{idx}/{len(devices)}] Sincronizando {device['ip']}...")
                self._sync_device(device)
            except Exception as e:
                logger.error(f"  ✗ Error sincronizando {device['ip']}: {e}")
                self.stats['errors'] += 1
        
        logger.info("")
        return self.stats
    
    def _ensure_base_objects(self):
        """Asegura que existen los objetos base necesarios en Netbox"""
        
        logger.info("Verificando objetos base en Netbox...")
        
        # Site por defecto
        try:
            site = self.nb.dcim.sites.get(slug='homelab')
            if not site:
                logger.info("  → Creando site 'homelab'...")
                site = self.nb.dcim.sites.create(
                    name='HomeLab',
                    slug='homelab',
                    description='Red doméstica'
                )
            self.cache['site'] = site
            logger.info(f"  ✓ Site: {site.name}")
        except Exception as e:
            logger.error(f"  ✗ Error con site: {e}")
            raise
        
        # Manufacturer genérico
        try:
            mfg = self.nb.dcim.manufacturers.get(slug='generic')
            if not mfg:
                logger.info("  → Creando manufacturer 'generic'...")
                mfg = self.nb.dcim.manufacturers.create(
                    name='Generic',
                    slug='generic'
                )
            self.cache['manufacturer'] = mfg
            logger.info(f"  ✓ Manufacturer: {mfg.name}")
        except Exception as e:
            logger.error(f"  ✗ Error con manufacturer: {e}")
            raise
        
        # Device types básicos
        device_types = [
            'Router', 'Switch', 'Access Point', 'Server', 'NAS',
            'Computer', 'Laptop', 'Smart TV', 'IoT Device', 
            'Mobile Device', 'Printer', 'IP Camera', 'Unknown',
            'Network Device'  # Agregar este tipo adicional
        ]
        
        for dt_name in device_types:
            try:
                dt_slug = dt_name.lower().replace(' ', '-')
                dt = self.nb.dcim.device_types.get(slug=dt_slug)
                if not dt:
                    logger.info(f"  → Creando device type '{dt_name}'...")
                    dt = self.nb.dcim.device_types.create(
                        manufacturer=self.cache['manufacturer'].id,
                        model=dt_name,
                        slug=dt_slug
                    )
                self.cache['device_types'][dt_slug] = dt
            except Exception as e:
                logger.warning(f"  ⚠ Error con device type {dt_name}: {e}")
        
        logger.info(f"  ✓ Device Types: {len(self.cache['device_types'])}")
        
        # Device roles - IMPORTANTE: crear TODOS incluyendo Unknown
        roles = [
            ('Infrastructure', 'infrastructure', 'ff5722'),
            ('Service', 'service', '2196f3'),
            ('Workstation', 'workstation', '4caf50'),
            ('Entertainment', 'entertainment', '9c27b0'),
            ('IoT', 'iot', 'ff9800'),
            ('Mobile', 'mobile', '00bcd4'),
            ('Peripheral', 'peripheral', '795548'),
            ('Unknown', 'unknown', '9e9e9e'),  # MUY IMPORTANTE
        ]
        
        for role_name, role_slug, role_color in roles:
            try:
                role = self.nb.dcim.device_roles.get(slug=role_slug)
                if not role:
                    logger.info(f"  → Creando device role '{role_name}'...")
                    role = self.nb.dcim.device_roles.create(
                        name=role_name,
                        slug=role_slug,
                        color=role_color
                    )
                self.cache['device_roles'][role_slug] = role
            except Exception as e:
                logger.warning(f"  ⚠ Error con device role {role_name}: {e}")
        
        logger.info(f"  ✓ Device Roles: {len(self.cache['device_roles'])}")
        
        # Tags para categorías
        categories = ['Domotica', 'Trabajo', 'Entretenimiento', 'ISP', 'Infrastructure']
        for cat in categories:
            try:
                tag = self.nb.extras.tags.get(slug=cat.lower())
                if not tag:
                    logger.info(f"  → Creando tag '{cat}'...")
                    tag = self.nb.extras.tags.create(
                        name=cat,
                        slug=cat.lower()
                    )
                self.cache['tags'][cat.lower()] = tag
            except Exception as e:
                logger.warning(f"  ⚠ Error con tag {cat}: {e}")
        
        logger.info(f"  ✓ Tags: {len(self.cache['tags'])}")
        logger.info("")
    
    def _get_or_create_device_type(self, type_name: str):
        """Obtiene o crea un device type"""
        type_slug = type_name.lower().replace(' ', '-')
        
        # Buscar en cache
        if type_slug in self.cache['device_types']:
            return self.cache['device_types'][type_slug]
        
        # Buscar en Netbox
        dt = self.nb.dcim.device_types.get(slug=type_slug)
        if dt:
            self.cache['device_types'][type_slug] = dt
            return dt
        
        # Crear si no existe
        try:
            logger.info(f"  → Creando device type '{type_name}' sobre la marcha...")
            dt = self.nb.dcim.device_types.create(
                manufacturer=self.cache['manufacturer'].id,
                model=type_name,
                slug=type_slug
            )
            self.cache['device_types'][type_slug] = dt
            return dt
        except Exception as e:
            logger.error(f"  ✗ Error creando device type {type_name}: {e}")
            # Retornar 'Unknown' como fallback
            return self.cache['device_types'].get('unknown')
    
    def _get_or_create_device_role(self, role_name: str):
        """Obtiene o crea un device role"""
        role_slug = role_name.lower().replace(' ', '-')
        
        # Buscar en cache
        if role_slug in self.cache['device_roles']:
            return self.cache['device_roles'][role_slug]
        
        # Buscar en Netbox
        role = self.nb.dcim.device_roles.get(slug=role_slug)
        if role:
            self.cache['device_roles'][role_slug] = role
            return role
        
        # Crear si no existe
        try:
            logger.info(f"  → Creando device role '{role_name}' sobre la marcha...")
            role = self.nb.dcim.device_roles.create(
                name=role_name,
                slug=role_slug,
                color='9e9e9e'  # Gris por defecto
            )
            self.cache['device_roles'][role_slug] = role
            return role
        except Exception as e:
            logger.error(f"  ✗ Error creando device role {role_name}: {e}")
            # Retornar 'Unknown' como fallback
            return self.cache['device_roles'].get('unknown')
    
    def _sync_device(self, device: Dict):
        """Sincroniza un dispositivo individual con Netbox"""
        
        ip = device['ip']
        
        # Buscar si ya existe la IP
        existing_ip = self.nb.ipam.ip_addresses.get(address=f"{ip}/32")
        
        if existing_ip:
            # Actualizar IP existente
            changed = self._update_ip(existing_ip, device)
            if changed:
                self.stats['updated'] += 1
                logger.info(f"  ✓ Actualizado: {ip}")
            else:
                self.stats['unchanged'] += 1
        else:
            # Crear nueva IP
            self._create_ip(device)
            self.stats['created'] += 1
            logger.info(f"  ✓ Creado: {ip}")
    
    def _create_ip(self, device: Dict):
        """Crea una nueva IP en Netbox con toda la información"""
        
        ip = device['ip']
        
        # Preparar descripción detallada
        description_parts = []
        
        if device.get('hostname'):
            description_parts.append(f"Hostname: {device['hostname']}")
        
        if device.get('mac'):
            description_parts.append(f"MAC: {device['mac']}")
        
        if device.get('vendor'):
            description_parts.append(f"Vendor: {device['vendor']}")
        
        if device.get('os'):
            os_str = device['os']
            if device.get('os_accuracy'):
                os_str += f" ({device['os_accuracy']}% confianza)"
            description_parts.append(f"OS: {os_str}")
        
        if device.get('device_type'):
            description_parts.append(f"Tipo: {device['device_type']}")
        
        if device.get('device_role'):
            description_parts.append(f"Rol: {device['device_role']}")
        
        if device.get('ports'):
            ports_str = ', '.join(map(str, sorted(device['ports'])[:10]))  # Primeros 10
            if len(device['ports']) > 10:
                ports_str += f"... (+{len(device['ports']) - 10} más)"
            description_parts.append(f"Puertos: {ports_str}")
        
        if device.get('snmp_enabled'):
            description_parts.append("SNMP: Habilitado")
            if device.get('snmp_sysName'):
                description_parts.append(f"SNMP Name: {device['snmp_sysName']}")
        
        if device.get('proxmox_vm'):
            description_parts.append(f"Proxmox: {device.get('proxmox_type')} - {device.get('proxmox_name')}")
        
        description = ' | '.join(description_parts)
        
        # Obtener o crear tags
        tags = []
        if device.get('category'):
            tag_slug = device['category'].lower()
            if tag_slug in self.cache['tags']:
                tags.append(self.cache['tags'][tag_slug].id)
        
        # Crear la IP en IPAM
        try:
            ip_obj = self.nb.ipam.ip_addresses.create(
                address=f"{ip}/32",
                status='active',
                description=description[:200] if description else '',  # Netbox tiene límite de caracteres
                tags=tags if tags else [],
                dns_name=device.get('hostname', '')[:255] if device.get('hostname') else '',
                comments=self._build_comments(device)
            )
            
            logger.debug(f"    IP creada con ID: {ip_obj.id}")
            
        except Exception as e:
            logger.error(f"    Error creando IP {ip}: {e}")
            raise
    
    def _update_ip(self, existing_ip, device: Dict) -> bool:
        """Actualiza una IP existente"""
        
        changed = False
        
        try:
            # Actualizar descripción
            new_description = f"MAC: {device.get('mac', 'Unknown')} | Tipo: {device.get('device_type', 'Unknown')}"
            if existing_ip.description != new_description:
                existing_ip.description = new_description[:200]
                changed = True
            
            # Actualizar hostname
            new_dns_name = device.get('hostname', '')[:255]
            if new_dns_name and existing_ip.dns_name != new_dns_name:
                existing_ip.dns_name = new_dns_name
                changed = True
            
            # Actualizar comentarios
            new_comments = self._build_comments(device)
            if existing_ip.comments != new_comments:
                existing_ip.comments = new_comments
                changed = True
            
            # Actualizar tags
            if device.get('category'):
                tag_slug = device['category'].lower()
                if tag_slug in self.cache['tags']:
                    tag_id = self.cache['tags'][tag_slug].id
                    current_tag_ids = [t.id for t in existing_ip.tags]
                    if tag_id not in current_tag_ids:
                        existing_ip.tags = current_tag_ids + [tag_id]
                        changed = True
            
            if changed:
                existing_ip.save()
            
        except Exception as e:
            logger.error(f"    Error actualizando IP {device['ip']}: {e}")
            raise
        
        return changed
    
    def _build_comments(self, device: Dict) -> str:
        """Construye el campo de comentarios con información detallada"""
        lines = []
        
        lines.append(f"IP: {device['ip']}")
        
        if device.get('mac'):
            lines.append(f"MAC: {device['mac']}")
        
        if device.get('vendor'):
            lines.append(f"Vendor: {device['vendor']}")
        
        if device.get('os'):
            accuracy = device.get('os_accuracy', '')
            lines.append(f"OS: {device['os']} ({accuracy}% confianza)" if accuracy else f"OS: {device['os']}")
        
        if device.get('device_type'):
            lines.append(f"Tipo: {device['device_type']} ({device.get('confidence', 0)}% confianza)")
        
        if device.get('device_role'):
            lines.append(f"Rol: {device['device_role']}")
        
        if device.get('category'):
            lines.append(f"Categoría: {device['category']}")
        
        if device.get('ports'):
            ports_str = ', '.join(map(str, sorted(device['ports'])))
            lines.append(f"Puertos abiertos: {ports_str}")
        
        if device.get('services'):
            lines.append(f"\nServicios detectados ({len(device['services'])}):")
            for service in device['services'][:10]:  # Primeros 10
                svc_line = f"  - {service['port']}/{service['protocol']}: {service['service']}"
                if service.get('product'):
                    svc_line += f" ({service['product']}"
                    if service.get('version'):
                        svc_line += f" {service['version']}"
                    svc_line += ")"
                lines.append(svc_line)
        
        if device.get('snmp_enabled'):
            lines.append("\nSNMP: Habilitado")
            if device.get('snmp_sysName'):
                lines.append(f"  sysName: {device['snmp_sysName']}")
            if device.get('snmp_sysDescr'):
                lines.append(f"  sysDescr: {device['snmp_sysDescr'][:100]}")
        
        if device.get('proxmox_vm'):
            lines.append(f"\nProxmox: {device.get('proxmox_type').upper()}")
            lines.append(f"  Nombre: {device.get('proxmox_name')}")
            lines.append(f"  Nodo: {device.get('proxmox_node')}")
            lines.append(f"  Estado: {device.get('proxmox_status')}")
        
        lines.append(f"\nÚltimo escaneo: {device.get('scan_time', 'Unknown')}")
        
        return '\n'.join(lines)