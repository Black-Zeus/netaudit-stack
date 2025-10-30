"""
Módulo de sincronización con Netbox - VERSIÓN CON SINCRONIZACIÓN INCREMENTAL
Permite actualizar IPs en tiempo real durante el escaneo
"""

import pynetbox
import logging
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class NetboxSync:
    """Sincroniza dispositivos descubiertos con Netbox - Con soporte incremental"""
    
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
        
        # Referencia al bootstrap (se asigna desde scan.py)
        self.bootstrap = None
    
    def test_connection(self) -> bool:
        """Prueba la conexión con Netbox"""
        try:
            self.nb.status()
            return True
        except Exception as e:
            logger.error(f"No se pudo conectar con Netbox: {e}")
            return False
    
    # ========================================================================
    # MÉTODOS DE SINCRONIZACIÓN INCREMENTAL (NUEVOS)
    # ========================================================================
    
    def create_placeholder_ip(self, ip: str, hostname: str = '', mac: str = '') -> Optional[object]:
        """
        Crea un placeholder de IP con tag "Descubierto"
        Se ejecuta inmediatamente después del ping scan
        
        Args:
            ip: Dirección IP
            hostname: Hostname (opcional)
            mac: MAC address (opcional)
            
        Returns:
            Objeto IP de Netbox o None
        """
        try:
            # Verificar si ya existe
            existing = self.nb.ipam.ip_addresses.get(address=f"{ip}/32")
            if existing:
                logger.debug(f"  ○ IP {ip} ya existe, actualizando...")
                return self._update_placeholder(existing, ip, hostname, mac)
            
            # Obtener tag "descubierto"
            tag = self._get_tag('descubierto')
            if not tag:
                logger.warning(f"  ⚠ Tag 'descubierto' no encontrado")
                tag_ids = []
            else:
                tag_ids = [tag.id]
            
            # Descripción mínima
            description = f"Host activo detectado"
            if mac:
                description += f" | MAC: {mac}"
            
            # Crear IP placeholder
            ip_obj = self.nb.ipam.ip_addresses.create(
                address=f"{ip}/32",
                status='active',
                description=description[:200],
                dns_name=hostname[:255] if hostname else '',
                tags=tag_ids,
                comments=f"Descubierto: {datetime.now().isoformat()}\nEstado: Pendiente de escaneo completo"
            )
            
            logger.debug(f"  ✓ Placeholder creado: {ip}")
            self.stats['created'] += 1
            return ip_obj
            
        except Exception as e:
            logger.error(f"  ✗ Error creando placeholder {ip}: {e}")
            self.stats['errors'] += 1
            return None
    
    def _update_placeholder(self, ip_obj, ip: str, hostname: str, mac: str) -> object:
        """Actualiza un placeholder existente"""
        try:
            changed = False
            
            # Actualizar hostname si es nuevo
            if hostname and not ip_obj.dns_name:
                ip_obj.dns_name = hostname[:255]
                changed = True
            
            # Actualizar descripción con MAC si hay
            if mac and 'MAC:' not in (ip_obj.description or ''):
                ip_obj.description = f"Host activo | MAC: {mac}"[:200]
                changed = True
            
            # Asegurar tag "descubierto"
            tag = self._get_tag('descubierto')
            if tag:
                current_tag_ids = [t.id for t in ip_obj.tags]
                if tag.id not in current_tag_ids:
                    ip_obj.tags = current_tag_ids + [tag.id]
                    changed = True
            
            if changed:
                ip_obj.save()
                self.stats['updated'] += 1
            else:
                self.stats['unchanged'] += 1
            
            return ip_obj
            
        except Exception as e:
            logger.error(f"  ✗ Error actualizando placeholder {ip}: {e}")
            return ip_obj
    
    def update_ip_ports(self, ip: str, tcp_ports: List[int], udp_ports: List[int] = None) -> bool:
        """
        Actualiza una IP con los puertos detectados y cambia tag a "Puertos"
        
        Args:
            ip: Dirección IP
            tcp_ports: Lista de puertos TCP abiertos
            udp_ports: Lista de puertos UDP abiertos (opcional)
            
        Returns:
            True si se actualizó correctamente
        """
        try:
            # Buscar IP
            ip_obj = self.nb.ipam.ip_addresses.get(address=f"{ip}/32")
            if not ip_obj:
                logger.warning(f"  ⚠ IP {ip} no encontrada para actualizar puertos")
                return False
            
            # Construir descripción con puertos
            tcp_str = ', '.join(map(str, sorted(tcp_ports)[:20]))  # Primeros 20
            if len(tcp_ports) > 20:
                tcp_str += f"... (+{len(tcp_ports) - 20} más)"
            
            description = f"TCP: {tcp_str}"
            
            if udp_ports:
                udp_str = ', '.join(map(str, sorted(udp_ports)[:10]))
                if len(udp_ports) > 10:
                    udp_str += f"... (+{len(udp_ports) - 10} más)"
                description += f" | UDP: {udp_str}"
            
            # Actualizar
            ip_obj.description = description[:200]
            
            # Cambiar tag a "puertos"
            tag = self._get_tag('puertos')
            if tag:
                ip_obj.tags = [tag.id]
            
            # Actualizar comentarios
            comments = ip_obj.comments or ''
            comments += f"\n\nPuertos detectados: {datetime.now().isoformat()}"
            comments += f"\nTCP ({len(tcp_ports)}): {', '.join(map(str, sorted(tcp_ports)))}"
            if udp_ports:
                comments += f"\nUDP ({len(udp_ports)}): {', '.join(map(str, sorted(udp_ports)))}"
            ip_obj.comments = comments
            
            ip_obj.save()
            logger.debug(f"  ✓ Puertos actualizados: {ip}")
            self.stats['updated'] += 1
            return True
            
        except Exception as e:
            logger.error(f"  ✗ Error actualizando puertos de {ip}: {e}")
            self.stats['errors'] += 1
            return False
    
    def update_ip_services(self, ip: str, services: List[Dict]) -> bool:
        """
        Actualiza una IP con los servicios identificados y cambia tag a "Servicios"
        
        Args:
            ip: Dirección IP
            services: Lista de servicios detectados
            
        Returns:
            True si se actualizó correctamente
        """
        try:
            # Buscar IP
            ip_obj = self.nb.ipam.ip_addresses.get(address=f"{ip}/32")
            if not ip_obj:
                logger.warning(f"  ⚠ IP {ip} no encontrada para actualizar servicios")
                return False
            
            # Cambiar tag a "servicios"
            tag = self._get_tag('servicios')
            if tag:
                ip_obj.tags = [tag.id]
            
            # Actualizar comentarios con servicios
            comments = ip_obj.comments or ''
            comments += f"\n\nServicios identificados: {datetime.now().isoformat()}"
            
            for svc in services[:15]:  # Primeros 15 servicios
                port = svc.get('port')
                protocol = svc.get('protocol', 'tcp')
                service = svc.get('service', 'unknown')
                product = svc.get('product', '')
                version = svc.get('version', '')
                
                svc_line = f"\n  {port}/{protocol}: {service}"
                if product:
                    svc_line += f" ({product}"
                    if version:
                        svc_line += f" {version}"
                    svc_line += ")"
                
                comments += svc_line
            
            if len(services) > 15:
                comments += f"\n  ... y {len(services) - 15} servicios más"
            
            ip_obj.comments = comments
            ip_obj.save()
            
            logger.debug(f"  ✓ Servicios actualizados: {ip}")
            self.stats['updated'] += 1
            return True
            
        except Exception as e:
            logger.error(f"  ✗ Error actualizando servicios de {ip}: {e}")
            self.stats['errors'] += 1
            return False
    
    def update_ip_complete(self, ip: str, device_info: Dict) -> bool:
        """
        Actualiza una IP con toda la información completa y cambia tag a "Completado"
        
        Args:
            ip: Dirección IP
            device_info: Diccionario con toda la información del dispositivo
            
        Returns:
            True si se actualizó correctamente
        """
        try:
            # Buscar IP
            ip_obj = self.nb.ipam.ip_addresses.get(address=f"{ip}/32")
            if not ip_obj:
                logger.warning(f"  ⚠ IP {ip} no encontrada para completar")
                return False
            
            # Actualizar descripción completa
            description_parts = []
            
            if device_info.get('hostname'):
                ip_obj.dns_name = device_info['hostname'][:255]
            
            if device_info.get('mac'):
                description_parts.append(f"MAC: {device_info['mac']}")
            
            if device_info.get('vendor'):
                description_parts.append(f"Vendor: {device_info['vendor']}")
            
            if device_info.get('os'):
                os_str = device_info['os']
                if device_info.get('os_accuracy'):
                    os_str += f" ({device_info['os_accuracy']}%)"
                description_parts.append(f"OS: {os_str}")
            
            if device_info.get('device_type'):
                description_parts.append(f"Tipo: {device_info['device_type']}")
            
            ip_obj.description = ' | '.join(description_parts)[:200]
            
            # Cambiar tag a "completado"
            tag_completado = self._get_tag('completado')
            tags = [tag_completado.id] if tag_completado else []
            
            # Agregar tag de categoría si existe
            if device_info.get('category'):
                tag_category = self._get_tag(device_info['category'].lower())
                if tag_category:
                    tags.append(tag_category.id)
            
            ip_obj.tags = tags
            
            # Actualizar comentarios con info completa
            ip_obj.comments = self._build_complete_comments(device_info)
            
            ip_obj.save()
            
            logger.debug(f"  ✓ Completado: {ip}")
            self.stats['updated'] += 1
            return True
            
        except Exception as e:
            logger.error(f"  ✗ Error completando {ip}: {e}")
            self.stats['errors'] += 1
            return False
    
    def update_ip_error(self, ip: str, error_msg: str) -> bool:
        """
        Marca una IP con error y cambia tag a "Error"
        
        Args:
            ip: Dirección IP
            error_msg: Mensaje de error
            
        Returns:
            True si se actualizó correctamente
        """
        try:
            # Buscar IP
            ip_obj = self.nb.ipam.ip_addresses.get(address=f"{ip}/32")
            if not ip_obj:
                logger.warning(f"  ⚠ IP {ip} no encontrada para marcar error")
                return False
            
            # Cambiar tag a "error"
            tag = self._get_tag('error')
            if tag:
                ip_obj.tags = [tag.id]
            
            # Actualizar comentarios con error
            comments = ip_obj.comments or ''
            comments += f"\n\n❌ Error: {datetime.now().isoformat()}"
            comments += f"\n{error_msg}"
            ip_obj.comments = comments
            
            ip_obj.save()
            
            logger.debug(f"  ✗ Error marcado: {ip}")
            self.stats['updated'] += 1
            return True
            
        except Exception as e:
            logger.error(f"  ✗ Error marcando error en {ip}: {e}")
            self.stats['errors'] += 1
            return False
    
    # ========================================================================
    # MÉTODOS AUXILIARES
    # ========================================================================
    
    def _get_tag(self, tag_slug: str) -> Optional[object]:
        """
        Obtiene un tag desde cache de bootstrap o Netbox
        
        Args:
            tag_slug: Slug del tag
            
        Returns:
            Objeto tag de Netbox o None
        """
        # Buscar en cache local
        if tag_slug in self.cache['tags']:
            return self.cache['tags'][tag_slug]
        
        # Buscar en cache de bootstrap
        if self.bootstrap:
            tag = self.bootstrap.get_cached_object('tags', tag_slug)
            if tag:
                self.cache['tags'][tag_slug] = tag
                return tag
        
        # Buscar en Netbox
        try:
            tag = self.nb.extras.tags.get(slug=tag_slug)
            if tag:
                self.cache['tags'][tag_slug] = tag
            return tag
        except Exception as e:
            logger.debug(f"Tag {tag_slug} no encontrado: {e}")
            return None
    
    def _build_complete_comments(self, device: Dict) -> str:
        """Construye el campo de comentarios con información completa"""
        lines = []
        
        lines.append(f"=== Escaneo Completo ===")
        lines.append(f"Fecha: {device.get('scan_time', datetime.now().isoformat())}")
        lines.append(f"IP: {device['ip']}")
        lines.append("")
        
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
            tcp_ports = [p for p in device['ports'] if isinstance(p, int)]
            udp_ports = [p.replace('udp/', '') for p in device['ports'] if isinstance(p, str) and 'udp/' in p]
            
            if tcp_ports:
                lines.append(f"\nPuertos TCP ({len(tcp_ports)}): {', '.join(map(str, sorted(tcp_ports)))}")
            if udp_ports:
                lines.append(f"Puertos UDP ({len(udp_ports)}): {', '.join(udp_ports)}")
        
        if device.get('services'):
            lines.append(f"\n=== Servicios Detectados ({len(device['services'])}) ===")
            for service in device['services'][:15]:
                svc_line = f"{service['port']}/{service['protocol']}: {service['service']}"
                if service.get('product'):
                    svc_line += f" ({service['product']}"
                    if service.get('version'):
                        svc_line += f" {service['version']}"
                    svc_line += ")"
                lines.append(svc_line)
            
            if len(device['services']) > 15:
                lines.append(f"... y {len(device['services']) - 15} servicios más")
        
        if device.get('snmp_enabled'):
            lines.append("\n=== SNMP ===")
            lines.append("Estado: Habilitado")
            if device.get('snmp_sysName'):
                lines.append(f"sysName: {device['snmp_sysName']}")
            if device.get('snmp_sysDescr'):
                lines.append(f"sysDescr: {device['snmp_sysDescr'][:100]}")
        
        if device.get('proxmox_vm'):
            lines.append(f"\n=== Proxmox ===")
            lines.append(f"Tipo: {device.get('proxmox_type', '').upper()}")
            lines.append(f"Nombre: {device.get('proxmox_name')}")
            lines.append(f"Nodo: {device.get('proxmox_node')}")
            lines.append(f"Estado: {device.get('proxmox_status')}")
        
        return '\n'.join(lines)
    
    # ========================================================================
    # MÉTODO LEGACY (para compatibilidad)
    # ========================================================================
    
    def sync_devices(self, devices: List[Dict]) -> Dict:
        """
        Sincroniza lista de dispositivos con Netbox (método legacy)
        NOTA: Este método crea/actualiza todo al final
        Para sincronización incremental, usar los métodos update_ip_*
        
        Args:
            devices: Lista de dispositivos descubiertos
            
        Returns:
            Estadísticas de sincronización
        """
        logger.info(f"Sincronizando {len(devices)} dispositivos con Netbox (modo legacy)...")
        logger.info("")
        
        # Reiniciar estadísticas
        self.stats = {'created': 0, 'updated': 0, 'unchanged': 0, 'errors': 0}
        
        for idx, device in enumerate(devices, 1):
            try:
                logger.info(f"[{idx}/{len(devices)}] Sincronizando {device['ip']}...")
                
                # Usar método de actualización completa
                ip_obj = self.nb.ipam.ip_addresses.get(address=f"{device['ip']}/32")
                if ip_obj:
                    # Ya existe, actualizar
                    self.update_ip_complete(device['ip'], device)
                else:
                    # No existe, crear completo
                    self.update_ip_complete(device['ip'], device)
                    
            except Exception as e:
                logger.error(f"  ✗ Error sincronizando {device['ip']}: {e}")
                self.stats['errors'] += 1
        
        logger.info("")
        return self.stats