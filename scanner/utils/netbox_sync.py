"""
Módulo de sincronización con Netbox
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
        
        # Reiniciar estadísticas
        self.stats = {'created': 0, 'updated': 0, 'unchanged': 0, 'errors': 0}
        
        # Asegurar que existen los objetos base en Netbox
        self._ensure_base_objects()
        
        for device in devices:
            try:
                self._sync_device(device)
            except Exception as e:
                logger.error(f"Error sincronizando {device['ip']}: {e}")
                self.stats['errors'] += 1
        
        return self.stats
    
    def _ensure_base_objects(self):
        """Asegura que existen los objetos base necesarios en Netbox"""
        
        # Site por defecto
        try:
            site = self.nb.dcim.sites.get(slug='homelab')
            if not site:
                logger.info("Creando site 'homelab'...")
                self.nb.dcim.sites.create(
                    name='HomeLab',
                    slug='homelab',
                    description='Red doméstica'
                )
        except Exception as e:
            logger.warning(f"Error verificando site: {e}")
        
        # Manufacturer genérico
        try:
            mfg = self.nb.dcim.manufacturers.get(slug='generic')
            if not mfg:
                logger.info("Creando manufacturer 'generic'...")
                self.nb.dcim.manufacturers.create(
                    name='Generic',
                    slug='generic'
                )
        except Exception as e:
            logger.warning(f"Error verificando manufacturer: {e}")
        
        # Device types básicos
        device_types = [
            'Router', 'Switch', 'Access Point', 'Server', 'NAS',
            'Computer', 'Laptop', 'Smart TV', 'IoT Device', 
            'Mobile Device', 'Printer', 'IP Camera', 'Unknown'
        ]
        
        for dt_name in device_types:
            try:
                dt_slug = dt_name.lower().replace(' ', '-')
                dt = self.nb.dcim.device_types.get(slug=dt_slug)
                if not dt:
                    logger.info(f"Creando device type '{dt_name}'...")
                    mfg = self.nb.dcim.manufacturers.get(slug='generic')
                    self.nb.dcim.device_types.create(
                        manufacturer=mfg.id,
                        model=dt_name,
                        slug=dt_slug
                    )
            except Exception as e:
                logger.warning(f"Error verificando device type {dt_name}: {e}")
        
        # Device roles
        roles = [
            ('Infrastructure', 'infrastructure', 'ff5722'),
            ('Service', 'service', '2196f3'),
            ('Workstation', 'workstation', '4caf50'),
            ('Entertainment', 'entertainment', '9c27b0'),
            ('IoT', 'iot', 'ff9800'),
            ('Mobile', 'mobile', '00bcd4'),
            ('Peripheral', 'peripheral', '795548'),
            ('Unknown', 'unknown', '9e9e9e'),
        ]
        
        for role_name, role_slug, role_color in roles:
            try:
                role = self.nb.dcim.device_roles.get(slug=role_slug)
                if not role:
                    logger.info(f"Creando device role '{role_name}'...")
                    self.nb.dcim.device_roles.create(
                        name=role_name,
                        slug=role_slug,
                        color=role_color
                    )
            except Exception as e:
                logger.warning(f"Error verificando device role {role_name}: {e}")
        
        # Tags para categorías
        categories = ['Domotica', 'Trabajo', 'Entretenimiento', 'ISP', 'Infrastructure']
        for cat in categories:
            try:
                tag = self.nb.extras.tags.get(slug=cat.lower())
                if not tag:
                    logger.info(f"Creando tag '{cat}'...")
                    self.nb.extras.tags.create(
                        name=cat,
                        slug=cat.lower()
                    )
            except Exception as e:
                logger.warning(f"Error verificando tag {cat}: {e}")
    
    def _sync_device(self, device: Dict):
        """Sincroniza un dispositivo individual con Netbox"""
        
        ip = device['ip']
        
        # Buscar si ya existe el dispositivo por IP
        existing_ip = self.nb.ipam.ip_addresses.get(address=f"{ip}/32")
        
        if existing_ip:
            # Actualizar dispositivo existente
            changed = self._update_device(existing_ip, device)
            if changed:
                self.stats['updated'] += 1
                logger.info(f"  ✓ Actualizado: {ip}")
            else:
                self.stats['unchanged'] += 1
        else:
            # Crear nuevo dispositivo
            self._create_device(device)
            self.stats['created'] += 1
            logger.info(f"  ✓ Creado: {ip}")
    
    def _create_device(self, device: Dict):
        """Crea un nuevo dispositivo en Netbox"""
        
        # Obtener objetos necesarios
        site = self.nb.dcim.sites.get(slug='homelab')
        
        device_type_name = device.get('device_type', 'Unknown')
        device_type_slug = device_type_name.lower().replace(' ', '-')
        device_type = self.nb.dcim.device_types.get(slug=device_type_slug)
        
        device_role_name = device.get('device_role', 'Unknown')
        device_role_slug = device_role_name.lower().replace(' ', '-')
        device_role = self.nb.dcim.device_roles.get(slug=device_role_slug)
        
        # Nombre del dispositivo
        device_name = device.get('hostname') or f"device-{device['ip'].replace('.', '-')}"
        
        # Crear dispositivo en Netbox
        nb_device = self.nb.dcim.devices.create(
            name=device_name,
            device_type=device_type.id,
            device_role=device_role.id,
            site=site.id,
            comments=self._build_comments(device)
        )
        
        # Agregar tags
        if device.get('category'):
            tag = self.nb.extras.tags.get(slug=device['category'].lower())
            if tag:
                nb_device.tags = [tag.id]
                nb_device.save()
        
        # Crear IP address
        ip_addr = self.nb.ipam.ip_addresses.create(
            address=f"{device['ip']}/32",
            status='active',
            assigned_object_type='dcim.device',
            assigned_object_id=nb_device.id,
            description=f"MAC: {device.get('mac', 'Unknown')}"
        )
        
        # Marcar como primary IP
        nb_device.primary_ip4 = ip_addr.id
        nb_device.save()
    
    def _update_device(self, existing_ip, device: Dict) -> bool:
        """
        Actualiza un dispositivo existente
        
        Returns:
            True si hubo cambios, False si no
        """
        changed = False
        
        # Obtener el dispositivo asociado a la IP
        if not existing_ip.assigned_object:
            return False
        
        nb_device = self.nb.dcim.devices.get(existing_ip.assigned_object.id)
        if not nb_device:
            return False
        
        # Actualizar hostname si cambió
        new_hostname = device.get('hostname')
        if new_hostname and nb_device.name != new_hostname:
            nb_device.name = new_hostname
            changed = True
        
        # Actualizar comentarios
        new_comments = self._build_comments(device)
        if nb_device.comments != new_comments:
            nb_device.comments = new_comments
            changed = True
        
        # Actualizar tags de categoría
        if device.get('category'):
            tag = self.nb.extras.tags.get(slug=device['category'].lower())
            if tag:
                current_tags = [t.id for t in nb_device.tags]
                if tag.id not in current_tags:
                    nb_device.tags = current_tags + [tag.id]
                    changed = True
        
        if changed:
            nb_device.save()
        
        return changed
    
    def _build_comments(self, device: Dict) -> str:
        """Construye el campo de comentarios con información del dispositivo"""
        lines = []
        
        lines.append(f"IP: {device['ip']}")
        
        if device.get('mac'):
            lines.append(f"MAC: {device['mac']}")
        
        if device.get('vendor'):
            lines.append(f"Vendor: {device['vendor']}")
        
        if device.get('os'):
            accuracy = device.get('os_accuracy', '')
            lines.append(f"OS: {device['os']} ({accuracy}% confidence)" if accuracy else f"OS: {device['os']}")
        
        if device.get('ports'):
            ports_str = ', '.join(map(str, sorted(device['ports'])))
            lines.append(f"Open Ports: {ports_str}")
        
        if device.get('snmp_enabled'):
            lines.append("SNMP: Enabled")
            if device.get('snmp_sysName'):
                lines.append(f"SNMP Name: {device['snmp_sysName']}")
        
        if device.get('proxmox_vm'):
            lines.append(f"Proxmox VM: {device.get('proxmox_name')} ({device.get('proxmox_type')})")
        
        lines.append(f"\nLast scanned: {device.get('scan_time', 'Unknown')}")
        lines.append(f"Classification confidence: {device.get('confidence', 0)}%")
        
        return '\n'.join(lines)
