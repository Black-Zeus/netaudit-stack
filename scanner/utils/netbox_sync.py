"""
Módulo de sincronización con Netbox - VERSIÓN CON SINCRONIZACIÓN POR FASES
Permite actualizar IPs en tiempo real durante cada fase del escaneo
"""

import pynetbox
import logging
from typing import List, Dict, Optional
from datetime import datetime
import time  # ← AGREGAR ESTE IMPORT
from pynetbox.core.query import RequestError  # ← AGREGAR ESTE IMPORT

logger = logging.getLogger(__name__)


class NetboxSync:
    """Sincroniza dispositivos descubiertos con Netbox - Con soporte por fases"""
    
    def __init__(self, url: str, token: str):
        """
        Inicializa la conexión con Netbox
        
        Args:
            url: URL de Netbox
            token: Token de API
        """
        self.nb = pynetbox.api(url, token=token)
        
        # ← AGREGAR CONFIGURACIÓN DE RETRY
        self.max_retries = 3
        self.retry_delay = 2  # segundos
        
        self.stats = {
            'created': 0,
            'updated': 0,
            'unchanged': 0,
            'errors': 0,
            'retries': 0,  # ← AGREGAR CONTADOR DE RETRIES
            'phase1': 0,
            'phase2': 0,
            'phase3': 0,
            'phase4': 0,
            'phase5': 0
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
    # ← AGREGAR ESTE MÉTODO NUEVO
    # ========================================================================
    
    def _safe_api_call(self, func, operation_name: str = "API call"):
        """
        Wrapper para llamadas API con retry automático en caso de rate limiting
        
        Args:
            func: Función lambda que contiene la llamada API
            operation_name: Nombre de la operación para logging
            
        Returns:
            Resultado de la función o None si falla después de todos los retries
        """
        for attempt in range(self.max_retries):
            try:
                return func()
                
            except RequestError as e:
                # Error de pynetbox
                if hasattr(e, 'req') and hasattr(e.req, 'status_code'):
                    status_code = e.req.status_code
                    
                    # Rate limiting (429 Too Many Requests)
                    if status_code == 429:
                        wait_time = self.retry_delay * (2 ** attempt)  # Exponential backoff
                        logger.warning(
                            f"⏳ Rate limited en {operation_name}, "
                            f"esperando {wait_time}s (intento {attempt + 1}/{self.max_retries})"
                        )
                        time.sleep(wait_time)
                        self.stats['retries'] += 1
                        continue
                    
                    # Otros errores HTTP
                    elif status_code >= 500:
                        # Error de servidor, reintentar
                        wait_time = self.retry_delay * (2 ** attempt)
                        logger.warning(
                            f"⚠️ Error de servidor ({status_code}) en {operation_name}, "
                            f"reintentando en {wait_time}s"
                        )
                        time.sleep(wait_time)
                        self.stats['retries'] += 1
                        continue
                    
                    else:
                        # Error de cliente (400, 404, etc.), no reintentar
                        logger.error(f"❌ Error en {operation_name}: {e}")
                        raise
                else:
                    # Error sin status code, reintentar
                    logger.warning(f"⚠️ Error en {operation_name}: {e}, reintentando...")
                    time.sleep(self.retry_delay)
                    self.stats['retries'] += 1
                    continue
            
            except Exception as e:
                # Otros tipos de excepciones
                logger.error(f"❌ Error inesperado en {operation_name}: {e}")
                raise
        
        # Si llegamos aquí, agotamos todos los retries
        logger.error(f"❌ Max retries alcanzado para {operation_name}")
        return None
    
    # ========================================================================
    # SINCRONIZACIÓN POR FASES
    # ========================================================================
    
    def sync_phase1_ip_discovered(self, ip: str, discovery_method: str = '') -> bool:
        """
        FASE 1: Sincroniza IP descubierta como activa
        Tag: "fase-1-ip-viva"
        """
        try:
            # Buscar si ya existe - CON RETRY
            ip_obj = self._safe_api_call(
                lambda: self.nb.ipam.ip_addresses.get(address=f"{ip}/32"),
                f"buscar IP {ip}"
            )
            
            # Obtener tag de fase 1 - CON RETRY
            tag = self._get_tag('fase-1-ip-viva')
            if not tag:
                logger.warning(f"  ⚠️ Tag 'fase-1-ip-viva' no encontrado")
                tag_ids = []
            else:
                tag_ids = [tag.id]
            
            timestamp = datetime.now().isoformat()
            
            if ip_obj:
                # Actualizar existente
                ip_obj.status = 'active'
                ip_obj.tags = tag_ids
                
                comments = ip_obj.comments or ''
                comments += f"\n\n=== FASE 1: IP Viva ===\n"
                comments += f"Timestamp: {timestamp}\n"
                if discovery_method:
                    comments += f"Método: {discovery_method}\n"
                comments += f"Estado: Host activo detectado"
                ip_obj.comments = comments
                
                # Guardar - CON RETRY
                self._safe_api_call(
                    lambda: ip_obj.save(),
                    f"actualizar IP {ip} Fase 1"
                )
                
                logger.debug(f"  ✓ Fase 1 actualizada: {ip}")
                self.stats['updated'] += 1
            else:
                # Crear nueva IP - CON RETRY
                description = f"Host activo ({discovery_method})" if discovery_method else "Host activo"
                
                ip_obj = self._safe_api_call(
                    lambda: self.nb.ipam.ip_addresses.create(
                        address=f"{ip}/32",
                        status='active',
                        description=description[:200],
                        tags=tag_ids,
                        comments=f"=== FASE 1: IP Viva ===\nTimestamp: {timestamp}\nEstado: Host detectado como activo"
                    ),
                    f"crear IP {ip} Fase 1"
                )
                
                if ip_obj:
                    logger.debug(f"  ✓ Fase 1 creada: {ip}")
                    self.stats['created'] += 1
                else:
                    logger.error(f"  ✗ No se pudo crear IP {ip} después de retries")
                    self.stats['errors'] += 1
                    return False
            
            self.stats['phase1'] += 1
            return True
            
        except Exception as e:
            logger.error(f"  ✗ Error en Fase 1 para {ip}: {e}")
            self.stats['errors'] += 1
            return False
    
    def sync_phase2_tcp_ports(self, ip: str, tcp_ports: List[int], overwrite_comments: bool = False) -> bool:
        """
        FASE 2: Sincroniza puertos TCP detectados
        Tag: "fase-2-puertos-tcp"
        
        Args:
            ip: Dirección IP
            tcp_ports: Lista de puertos TCP abiertos
            
        Returns:
            True si se sincronizó correctamente
        """
        try:
            # Buscar IP
            ip_obj = self.nb.ipam.ip_addresses.get(address=f"{ip}/32")
            if not ip_obj:
                logger.warning(f"  ⚠️ IP {ip} no encontrada para Fase 2")
                return False
            
            # Actualizar tag a fase 2
            tag = self._get_tag('fase-2-puertos-tcp')
            if tag:
                ip_obj.tags = [tag.id]
            
            # Construir descripción con puertos TCP
            if tcp_ports:
                tcp_str = ', '.join(map(str, sorted(tcp_ports)[:20]))
                if len(tcp_ports) > 20:
                    tcp_str += f"... (+{len(tcp_ports) - 20} más)"
                
                ip_obj.description = f"TCP ({len(tcp_ports)}): {tcp_str}"[:200]
            else:
                ip_obj.description = "Sin puertos TCP abiertos"
            
            # Actualizar comentarios
            timestamp = datetime.now().isoformat()
            
            if overwrite_comments:
                comments = ""
            else:
                comments = ip_obj.comments or ''
        
            comments += f"\n\n=== FASE 2: Puertos TCP ===\n"
            comments += f"Timestamp: {timestamp}\n"
            comments += f"Total puertos TCP abiertos: {len(tcp_ports)}\n"
            
            if tcp_ports:
                comments += f"Puertos: {', '.join(map(str, sorted(tcp_ports)))}\n"
            else:
                comments += "No se detectaron puertos TCP abiertos\n"
            
            ip_obj.comments = comments
            ip_obj.save()
            
            logger.debug(f"  ✓ Fase 2 sincronizada: {ip} ({len(tcp_ports)} puertos TCP)")
            self.stats['updated'] += 1
            self.stats['phase2'] += 1
            return True
            
        except Exception as e:
            logger.error(f"  ✗ Error en Fase 2 para {ip}: {e}")
            self.stats['errors'] += 1
            return False
    
    def sync_phase3_udp_ports(self, ip: str, udp_ports: List[int]) -> bool:
        """
        FASE 3: Sincroniza puertos UDP detectados
        Tag: "fase-3-puertos-udp"
        
        Args:
            ip: Dirección IP
            udp_ports: Lista de puertos UDP abiertos
            
        Returns:
            True si se sincronizó correctamente
        """
        try:
            # Buscar IP
            ip_obj = self.nb.ipam.ip_addresses.get(address=f"{ip}/32")
            if not ip_obj:
                logger.warning(f"  ⚠️ IP {ip} no encontrada para Fase 3")
                return False
            
            # Actualizar tag a fase 3
            tag = self._get_tag('fase-3-puertos-udp')
            if tag:
                ip_obj.tags = [tag.id]
            
            # Actualizar descripción añadiendo UDP
            current_desc = ip_obj.description or ''
            
            if udp_ports:
                udp_str = ', '.join(map(str, sorted(udp_ports)[:10]))
                if len(udp_ports) > 10:
                    udp_str += f"... (+{len(udp_ports) - 10} más)"
                
                new_desc = f"{current_desc} | UDP ({len(udp_ports)}): {udp_str}"
                ip_obj.description = new_desc[:200]
            else:
                ip_obj.description = f"{current_desc} | Sin UDP"[:200]
            
            # Actualizar comentarios
            timestamp = datetime.now().isoformat()
            comments = ip_obj.comments or ''
            comments += f"\n\n=== FASE 3: Puertos UDP ===\n"
            comments += f"Timestamp: {timestamp}\n"
            comments += f"Total puertos UDP abiertos: {len(udp_ports)}\n"
            
            if udp_ports:
                comments += f"Puertos: {', '.join(map(str, sorted(udp_ports)))}\n"
            else:
                comments += "No se detectaron puertos UDP abiertos\n"
            
            ip_obj.comments = comments
            ip_obj.save()
            
            logger.debug(f"  ✓ Fase 3 sincronizada: {ip} ({len(udp_ports)} puertos UDP)")
            self.stats['updated'] += 1
            self.stats['phase3'] += 1
            return True
            
        except Exception as e:
            logger.error(f"  ✗ Error en Fase 3 para {ip}: {e}")
            self.stats['errors'] += 1
            return False
    
    def sync_phase4_services(self, ip: str, services: Dict) -> bool:
        """
        FASE 4: Sincroniza servicios identificados
        Tag: "fase-4-servicios"
        
        Args:
            ip: Dirección IP
            services: Dict con servicios {'tcp': {...}, 'udp': {...}}
            
        Returns:
            True si se sincronizó correctamente
        """
        try:
            # Buscar IP
            ip_obj = self.nb.ipam.ip_addresses.get(address=f"{ip}/32")
            if not ip_obj:
                logger.warning(f"  ⚠️ IP {ip} no encontrada para Fase 4")
                return False
            
            # Actualizar tag a fase 4
            tag = self._get_tag('fase-4-servicios')
            if tag:
                ip_obj.tags = [tag.id]
            
            # Contar servicios
            tcp_services = services.get('tcp', {})
            udp_services = services.get('udp', {})
            total_services = len(tcp_services) + len(udp_services)
            
            # Actualizar comentarios con servicios
            timestamp = datetime.now().isoformat()
            comments = ip_obj.comments or ''
            comments += f"\n\n=== FASE 4: Servicios ===\n"
            comments += f"Timestamp: {timestamp}\n"
            comments += f"Total servicios identificados: {total_services}\n"
            
            # Servicios TCP
            if tcp_services:
                comments += f"\n--- Servicios TCP ({len(tcp_services)}) ---\n"
                for port, svc in list(tcp_services.items())[:15]:
                    service_name = svc.get('service', 'unknown')
                    product = svc.get('product', '')
                    version = svc.get('version', '')
                    
                    svc_line = f"  {port}/tcp: {service_name}"
                    if product:
                        svc_line += f" ({product}"
                        if version:
                            svc_line += f" {version}"
                        svc_line += ")"
                    
                    comments += svc_line + "\n"
                
                if len(tcp_services) > 15:
                    comments += f"  ... y {len(tcp_services) - 15} servicios TCP más\n"
            
            # Servicios UDP
            if udp_services:
                comments += f"\n--- Servicios UDP ({len(udp_services)}) ---\n"
                for port, svc in list(udp_services.items())[:10]:
                    service_name = svc.get('service', 'unknown')
                    product = svc.get('product', '')
                    
                    svc_line = f"  {port}/udp: {service_name}"
                    if product:
                        svc_line += f" ({product})"
                    
                    comments += svc_line + "\n"
                
                if len(udp_services) > 10:
                    comments += f"  ... y {len(udp_services) - 10} servicios UDP más\n"
            
            ip_obj.comments = comments
            ip_obj.save()
            
            logger.debug(f"  ✓ Fase 4 sincronizada: {ip} ({total_services} servicios)")
            self.stats['updated'] += 1
            self.stats['phase4'] += 1
            return True
            
        except Exception as e:
            logger.error(f"  ✗ Error en Fase 4 para {ip}: {e}")
            self.stats['errors'] += 1
            return False
    
    def sync_phase5_complete(self, ip: str, audit_data: Dict, 
                            classification: Dict = None) -> bool:
        """
        FASE 5: Sincroniza auditoría completa
        Tag: "fase-5-completado"
        
        Args:
            ip: Dirección IP
            audit_data: Dict con OS, MAC, hostname, etc.
            classification: Dict con clasificación del dispositivo (opcional)
            
        Returns:
            True si se sincronizó correctamente
        """
        try:
            # Buscar IP
            ip_obj = self.nb.ipam.ip_addresses.get(address=f"{ip}/32")
            if not ip_obj:
                logger.warning(f"  ⚠️ IP {ip} no encontrada para Fase 5")
                return False
            
            # Actualizar hostname
            if audit_data.get('hostname'):
                ip_obj.dns_name = audit_data['hostname'][:255]
            
            # Construir descripción completa
            description_parts = []
            
            if audit_data.get('mac'):
                description_parts.append(f"MAC: {audit_data['mac']}")
            
            if audit_data.get('vendor'):
                description_parts.append(f"{audit_data['vendor']}")
            
            if audit_data.get('os'):
                os_str = audit_data['os']
                if audit_data.get('os_accuracy'):
                    os_str += f" ({audit_data['os_accuracy']}%)"
                description_parts.append(f"OS: {os_str}")
            
            # Agregar tipo de dispositivo si se clasificó
            if classification and classification.get('device_type'):
                description_parts.append(f"Tipo: {classification['device_type']}")
            
            ip_obj.description = ' | '.join(description_parts)[:200]
            
            # Actualizar tags
            tag_completado = self._get_tag('fase-5-completado')
            tags = [tag_completado.id] if tag_completado else []
            
            # Agregar tag de categoría si existe
            if classification and classification.get('category'):
                tag_category = self._get_tag(classification['category'].lower())
                if tag_category:
                    tags.append(tag_category.id)
            
            ip_obj.tags = tags
            
            # Actualizar comentarios con info completa
            timestamp = datetime.now().isoformat()
            comments = ip_obj.comments or ''
            comments += f"\n\n=== FASE 5: Auditoría Completa ===\n"
            comments += f"Timestamp: {timestamp}\n"
            comments += f"Estado: Escaneo completado exitosamente\n\n"
            
            # Información del host
            comments += "--- Información del Host ---\n"
            if audit_data.get('hostname'):
                comments += f"Hostname: {audit_data['hostname']}\n"
            
            if audit_data.get('mac'):
                comments += f"MAC Address: {audit_data['mac']}\n"
                if audit_data.get('vendor'):
                    comments += f"Vendor: {audit_data['vendor']}\n"
            
            if audit_data.get('os'):
                comments += f"Sistema Operativo: {audit_data['os']}\n"
                comments += f"Confianza OS: {audit_data.get('os_accuracy', 0)}%\n"
                
                # OS alternatives si hay
                if audit_data.get('os_details'):
                    comments += f"\nAlternativas de OS:\n"
                    for os_detail in audit_data['os_details'][:3]:
                        comments += f"  - {os_detail['name']} ({os_detail['accuracy']}%)\n"
            
            if audit_data.get('uptime'):
                comments += f"Uptime: {audit_data['uptime']}\n"
            
            # Clasificación si existe
            if classification:
                comments += f"\n--- Clasificación ---\n"
                comments += f"Tipo: {classification.get('device_type', 'Unknown')}\n"
                comments += f"Rol: {classification.get('device_role', 'Unknown')}\n"
                comments += f"Categoría: {classification.get('category', 'Unknown')}\n"
                comments += f"Confianza: {classification.get('confidence', 0)}%\n"
            
            ip_obj.comments = comments
            ip_obj.save()
            
            logger.debug(f"  ✓ Fase 5 sincronizada: {ip} (completado)")
            self.stats['updated'] += 1
            self.stats['phase5'] += 1
            return True
            
        except Exception as e:
            logger.error(f"  ✗ Error en Fase 5 para {ip}: {e}")
            self.stats['errors'] += 1
            return False
    
    def sync_phase_error(self, ip: str, phase: int, error_msg: str) -> bool:
        """
        Marca una IP con error en alguna fase
        Tag: "error-escaneo"
        
        Args:
            ip: Dirección IP
            phase: Número de fase donde ocurrió el error (1-5)
            error_msg: Mensaje de error
            
        Returns:
            True si se sincronizó correctamente
        """
        try:
            # Buscar IP
            ip_obj = self.nb.ipam.ip_addresses.get(address=f"{ip}/32")
            if not ip_obj:
                logger.warning(f"  ⚠️ IP {ip} no encontrada para marcar error")
                return False
            
            # Cambiar tag a error
            tag = self._get_tag('error-escaneo')
            if tag:
                ip_obj.tags = [tag.id]
            
            # Actualizar comentarios con error
            timestamp = datetime.now().isoformat()
            comments = ip_obj.comments or ''
            comments += f"\n\n❌ ERROR EN FASE {phase}\n"
            comments += f"Timestamp: {timestamp}\n"
            comments += f"Mensaje: {error_msg}\n"
            
            ip_obj.comments = comments
            ip_obj.save()
            
            logger.debug(f"  ✗ Error marcado en Fase {phase}: {ip}")
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
    
    def get_phase_stats(self) -> Dict:
        """
        Retorna estadísticas por fase
        
        Returns:
            Dict con contadores por fase
        """
        return {
            'phase1_ips_discovered': self.stats['phase1'],
            'phase2_tcp_scanned': self.stats['phase2'],
            'phase3_udp_scanned': self.stats['phase3'],
            'phase4_services_identified': self.stats['phase4'],
            'phase5_complete': self.stats['phase5'],
            'total_created': self.stats['created'],
            'total_updated': self.stats['updated'],
            'total_errors': self.stats['errors']
        }
    
    def reset_stats(self):
        """Reinicia estadísticas"""
        self.stats = {
            'created': 0,
            'updated': 0,
            'unchanged': 0,
            'errors': 0,
            'phase1': 0,
            'phase2': 0,
            'phase3': 0,
            'phase4': 0,
            'phase5': 0
        }
    
    # ========================================================================
    # MÉTODOS BATCH (para operaciones masivas)
    # ========================================================================
    
    def batch_sync_phase1(self, ips: List[str], discovery_method: str = '') -> int:
        """
        Sincroniza múltiples IPs en Fase 1
        
        Args:
            ips: Lista de IPs descubiertas
            discovery_method: Método de descubrimiento
            
        Returns:
            Número de IPs sincronizadas exitosamente
        """
        success_count = 0
        
        logger.info(f"  📝 Sincronizando {len(ips)} IPs en Fase 1...")
        
        for ip in ips:
            if self.sync_phase1_ip_discovered(ip, discovery_method):
                success_count += 1
        
        logger.info(f"  ✓ {success_count}/{len(ips)} IPs sincronizadas en Fase 1")
        
        return success_count
    
    # ========================================================================
    # MÉTODOS LEGACY (para compatibilidad)
    # ========================================================================
    
    def create_placeholder_ip(self, ip: str, hostname: str = '', mac: str = '') -> Optional[object]:
        """
        [LEGACY] Crea un placeholder de IP
        Ahora usa sync_phase1_ip_discovered internamente
        """
        logger.warning("create_placeholder_ip es LEGACY, usar sync_phase1_ip_discovered")
        
        discovery_method = 'legacy'
        if self.sync_phase1_ip_discovered(ip, discovery_method):
            return self.nb.ipam.ip_addresses.get(address=f"{ip}/32")
        return None
    
    def update_ip_ports(self, ip: str, tcp_ports: List[int], udp_ports: List[int] = None) -> bool:
        """
        [LEGACY] Actualiza puertos
        Ahora usa sync_phase2_tcp_ports y sync_phase3_udp_ports
        """
        logger.warning("update_ip_ports es LEGACY, usar sync_phase2/3")
        
        success = True
        if tcp_ports:
            success = success and self.sync_phase2_tcp_ports(ip, tcp_ports)
        if udp_ports:
            success = success and self.sync_phase3_udp_ports(ip, udp_ports)
        
        return success
    
    def update_ip_services(self, ip: str, services: List[Dict]) -> bool:
        """
        [LEGACY] Actualiza servicios
        Ahora usa sync_phase4_services
        """
        logger.warning("update_ip_services es LEGACY, usar sync_phase4_services")
        
        # Convertir formato legacy a formato por fases
        services_dict = {'tcp': {}, 'udp': {}}
        for svc in services:
            port = svc.get('port')
            protocol = svc.get('protocol', 'tcp')
            
            if protocol == 'tcp':
                services_dict['tcp'][port] = svc
            elif protocol == 'udp':
                services_dict['udp'][port] = svc
        
        return self.sync_phase4_services(ip, services_dict)
    
    def update_ip_complete(self, ip: str, device_info: Dict) -> bool:
        """
        [LEGACY] Actualiza info completa
        Ahora usa sync_phase5_complete
        """
        logger.warning("update_ip_complete es LEGACY, usar sync_phase5_complete")
        
        # Extraer audit_data del device_info
        audit_data = {
            'hostname': device_info.get('hostname', ''),
            'mac': device_info.get('mac', ''),
            'vendor': device_info.get('vendor', ''),
            'os': device_info.get('os', ''),
            'os_accuracy': device_info.get('os_accuracy', 0),
            'uptime': device_info.get('uptime', '')
        }
        
        # Extraer clasificación
        classification = {
            'device_type': device_info.get('device_type', ''),
            'device_role': device_info.get('device_role', ''),
            'category': device_info.get('category', ''),
            'confidence': device_info.get('confidence', 0)
        }
        
        return self.sync_phase5_complete(ip, audit_data, classification)
    
    def update_ip_error(self, ip: str, error_msg: str) -> bool:
        """
        [LEGACY] Marca error
        Ahora usa sync_phase_error
        """
        logger.warning("update_ip_error es LEGACY, usar sync_phase_error")
        return self.sync_phase_error(ip, 0, error_msg)
    
    def sync_devices(self, devices: List[Dict]) -> Dict:
        """
        [LEGACY] Sincroniza lista de dispositivos
        Mantenido solo para compatibilidad
        """
        logger.warning("sync_devices es LEGACY, usar métodos sync_phase* individuales")
        
        for device in devices:
            ip = device['ip']
            
            # Simular flujo completo
            self.sync_phase1_ip_discovered(ip)
            
            if device.get('ports'):
                tcp_ports = [p for p in device['ports'] if isinstance(p, int)]
                self.sync_phase2_tcp_ports(ip, tcp_ports)
            
            if device.get('services'):
                services_dict = {'tcp': {}, 'udp': {}}
                for svc in device['services']:
                    port = svc.get('port')
                    protocol = svc.get('protocol', 'tcp')
                    if protocol == 'tcp':
                        services_dict['tcp'][port] = svc
                
                self.sync_phase4_services(ip, services_dict)
            
            # Fase 5
            audit_data = {
                'hostname': device.get('hostname', ''),
                'mac': device.get('mac', ''),
                'vendor': device.get('vendor', ''),
                'os': device.get('os', ''),
                'os_accuracy': device.get('os_accuracy', 0)
            }
            
            classification = {
                'device_type': device.get('device_type', ''),
                'device_role': device.get('device_role', ''),
                'category': device.get('category', ''),
                'confidence': device.get('confidence', 0)
            }
            
            self.sync_phase5_complete(ip, audit_data, classification)
        
        return self.get_phase_stats()