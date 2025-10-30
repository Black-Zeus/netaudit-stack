#!/usr/bin/env python3
"""
NetAudit HomeStack - Network Scanner con Escaneo por Fases
Script principal de escaneo de red

FLUJO DE ESCANEO EN 5 FASES:
1. Descubrimiento de IPs → Sincroniza a Netbox con tag "fase-1-ip-viva"
2. Detección de puertos TCP → Sincroniza con tag "fase-2-puertos-tcp"
3. Detección de puertos UDP → Sincroniza con tag "fase-3-puertos-udp"
4. Identificación de servicios → Sincroniza con tag "fase-4-servicios"
5. Auditoría completa (OS, MAC, hostname) → Sincroniza con tag "fase-5-completado"

Cada fase sincroniza inmediatamente con Netbox para visibilidad en tiempo real.
"""

import os
import sys
from datetime import datetime
from dotenv import load_dotenv
import time
from utils.nmap_phased_scanner import NmapPhasedScanner
from concurrent.futures import ThreadPoolExecutor, as_completed  # ← AGREGAR ESTO


# Importar módulos propios
from utils import (
    setup_logger,
    DeviceClassifier,
    NetboxSync,
    NetboxBootstrap,
    ProxmoxIntegration,
    SNMPDiscovery
)

# Importar el nuevo scanner por fases
from utils.nmap_phased_scanner import NmapPhasedScanner

# Cargar variables de entorno
load_dotenv()

# Configurar logging
logger = setup_logger('netaudit')


class NetAuditPhasedScanner:
    """Orquestador principal del escaneo de red por fases"""
    
    def __init__(self):
        """Inicializa el scanner con configuración desde env"""
        
        # Configuración de Netbox
        self.netbox_url = os.getenv('NETBOX_URL', 'http://netbox:8080')
        self.netbox_token = os.getenv('NETBOX_TOKEN', '')
        
        # Redes a escanear
        networks_str = os.getenv('SCAN_NETWORKS', '192.168.3.0/24')
        self.networks = [n.strip() for n in networks_str.split(',')]
        
        # Configuración de escaneo
        self.nmap_timing = os.getenv('NMAP_TIMING', 'T2')
        self.min_rate = int(os.getenv('MIN_RATE', '5000'))
        self.udp_top_ports = int(os.getenv('UDP_TOP_PORTS', '1000'))
        
        # Configuración de SNMP
        self.snmp_enabled = os.getenv('ENABLE_SNMP', 'true').lower() == 'true'
        self.snmp_community = os.getenv('SNMP_COMMUNITY', 'public')
        
        # Configuración de Proxmox (opcional)
        self.proxmox_enabled = os.getenv('ENABLE_PROXMOX', 'false').lower() == 'true'
        self.proxmox_host = os.getenv('PROXMOX_HOST', '')
        self.proxmox_user = os.getenv('PROXMOX_USER', '')
        self.proxmox_password = os.getenv('PROXMOX_PASSWORD', '')
    
        # ← AGREGAR CONFIGURACIÓN DE PARALELIZACIÓN
        self.parallel_enabled = os.getenv('ENABLE_PARALLEL_SCAN', 'false').lower() == 'true'
        self.max_workers = int(os.getenv('MAX_PARALLEL_WORKERS', '5'))
        
        # Inicializar componentes
        self.phased_scanner = None
        self.snmp_discovery = None
        self.classifier = None
        self.netbox_sync = None
        self.bootstrap = None
        self.proxmox = None
        
        # Estadísticas globales
        self.stats = {
            'networks_scanned': 0,
            'total_hosts_discovered': 0,
            'total_hosts_completed': 0,
            'total_tcp_ports': 0,
            'total_udp_ports': 0,
            'total_services': 0,
            'scan_duration': 0,
            'phase_durations': {
                'phase1': 0,
                'phase2': 0,
                'phase3': 0,
                'phase4': 0,
                'phase5': 0
            }
        }
        
        # Diccionario para almacenar resultados por IP
        self.scan_results = {}
    
    def validate_config(self) -> bool:
        """Valida la configuración antes de iniciar"""
        
        logger.info("=" * 70)
        logger.info("NetAudit HomeStack - Network Scanner (Phased)")
        logger.info("=" * 70)
        logger.info("")
        
        # Validar Netbox
        if not self.netbox_token:
            logger.error("❌ NETBOX_TOKEN no está configurado")
            return False
        
        logger.info(f"✓ Netbox URL: {self.netbox_url}")
        logger.info(f"✓ Redes a escanear: {', '.join(self.networks)}")
        logger.info(f"✓ Timing: {self.nmap_timing}")
        logger.info(f"✓ Min rate: {self.min_rate} pps")
        logger.info(f"✓ UDP top ports: {self.udp_top_ports}")
        logger.info(f"✓ SNMP: {'Sí' if self.snmp_enabled else 'No'}")
        logger.info(f"✓ Proxmox: {'Sí' if self.proxmox_enabled else 'No'}")
        logger.info("")
        
        return True
    
    def run_bootstrap(self) -> bool:
        """
        Ejecuta el bootstrap de Netbox si es necesario
        
        Returns:
            True si el bootstrap se ejecutó o ya estaba listo
        """
        logger.info("=" * 70)
        logger.info("🔧 Verificando configuración de Netbox")
        logger.info("=" * 70)
        logger.info("")
        
        try:
            # Crear instancia de bootstrap
            self.bootstrap = NetboxBootstrap(
                netbox_url=self.netbox_url,
                netbox_token=self.netbox_token,
                config_dir='/app/config'
            )
            
            # Verificar si debe ejecutarse
            if self.bootstrap.should_bootstrap():
                logger.info("⚙️  Primera ejecución detectada")
                logger.info("📦 Ejecutando bootstrap de Netbox...")
                logger.info("")
                
                # Ejecutar bootstrap
                bootstrap_stats = self.bootstrap.run()
                
                logger.info("")
                logger.info("✅ Bootstrap completado exitosamente")
                logger.info("")
                
            else:
                logger.info("✓ Bootstrap ya ejecutado previamente")
                # Cargar configuración para tener cache disponible
                self.bootstrap.load_config()
                logger.info("")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Error durante bootstrap: {e}")
            logger.warning("⚠️  Continuando sin bootstrap (puede causar errores)")
            return False
    
    def initialize_components(self):
        """Inicializa todos los componentes necesarios"""
        
        logger.info("📦 Inicializando componentes...")
        
        # Nmap Phased Scanner
        self.phased_scanner = NmapPhasedScanner(
            timing=self.nmap_timing,
            min_rate=self.min_rate
        )
        logger.info("  ✓ Nmap Phased Scanner inicializado")
        
        # SNMP Discovery
        if self.snmp_enabled:
            self.snmp_discovery = SNMPDiscovery(
                community=self.snmp_community,
                timeout=2,
                retries=1
            )
            logger.info("  ✓ SNMP Discovery inicializado")
        
        # Device Classifier
        self.classifier = DeviceClassifier()
        logger.info("  ✓ Device Classifier inicializado")
        
        # Netbox Sync
        self.netbox_sync = NetboxSync(
            url=self.netbox_url,
            token=self.netbox_token
        )
        
        # Verificar conexión con Netbox
        if not self.netbox_sync.test_connection():
            logger.error("❌ No se pudo conectar con Netbox")
            sys.exit(1)
        
        logger.info("  ✓ Netbox Sync inicializado y conectado")
        
        # Pasar referencia de bootstrap a netbox_sync para usar cache
        if self.bootstrap:
            self.netbox_sync.bootstrap = self.bootstrap
        
        # Proxmox Integration (opcional)
        if self.proxmox_enabled and self.proxmox_host:
            try:
                self.proxmox = ProxmoxIntegration(
                    host=self.proxmox_host,
                    user=self.proxmox_user,
                    password=self.proxmox_password
                )
                if self.proxmox.connected:
                    logger.info("  ✓ Proxmox Integration inicializada")
            except Exception as e:
                logger.warning(f"  ⚠ Proxmox no disponible: {e}")
                self.proxmox = None
        
        logger.info("")
    
    # ========================================================================
    # FASE 1: DESCUBRIMIENTO DE IPs
    # ========================================================================
    
    def execute_phase1(self, network: str) -> list:
        """
        FASE 1: Descubre hosts activos y sincroniza inmediatamente
        
        Args:
            network: Red en formato CIDR
            
        Returns:
            Lista de IPs activas
        """
        logger.info("=" * 70)
        logger.info("🔍 FASE 1: DESCUBRIMIENTO DE HOSTS")
        logger.info("=" * 70)
        logger.info("")
        
        phase_start = time.time()
        
        # Ejecutar descubrimiento
        active_ips = self.phased_scanner.phase1_discover_hosts(network)
        
        # SINCRONIZACIÓN INMEDIATA A NETBOX
        if active_ips:
            logger.info(f"📝 Sincronizando {len(active_ips)} hosts a Netbox (Fase 1)...")
            self.netbox_sync.batch_sync_phase1(active_ips, discovery_method='multi-technique')
            logger.info(f"✅ Sincronización Fase 1 completada")
            logger.info(f"🌐 Ver en Netbox: {self.netbox_url}/ipam/ip-addresses/")
            logger.info("")
        
        phase_duration = time.time() - phase_start
        self.stats['phase_durations']['phase1'] = phase_duration
        self.stats['total_hosts_discovered'] = len(active_ips)
        
        # Inicializar resultados para cada IP
        for ip in active_ips:
            self.scan_results[ip] = {
                'ip': ip,
                'tcp_ports': [],
                'udp_ports': [],
                'services': {'tcp': {}, 'udp': {}},
                'audit_data': {},
                'classification': {}
            }
        
        logger.info(f"⏱️  Fase 1 completada en {phase_duration:.1f}s")
        logger.info("")
        
        return active_ips
    
    # ========================================================================
    # FASE 2: DETECCIÓN DE PUERTOS TCP
    # ========================================================================
    
    def execute_phase2(self, ips: list):
        """
        FASE 2: Escanea puertos TCP de cada host y sincroniza
        Soporta modo paralelo para mayor velocidad
        
        Args:
            ips: Lista de IPs a escanear
        """
        logger.info("=" * 70)
        logger.info("🔌 FASE 2: DETECCIÓN DE PUERTOS TCP")
        logger.info("=" * 70)
        logger.info("")
        
        if self.parallel_enabled:
            logger.info(f"⚡ Modo paralelo activado (max {self.max_workers} workers)")
        else:
            logger.info(f"⏭️  Modo secuencial (usar ENABLE_PARALLEL_SCAN=true para paralelizar)")
        logger.info("")
        
        phase_start = time.time()
        total_tcp_ports = 0
        completed = 0
        
        if self.parallel_enabled:
            # ========== MODO PARALELO ==========
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Enviar todas las tareas
                future_to_ip = {
                    executor.submit(self._scan_single_host_phase2, ip): ip 
                    for ip in ips
                }
                
                # Procesar resultados a medida que completan
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    completed += 1
                    
                    try:
                        tcp_ports = future.result()
                        self.scan_results[ip]['tcp_ports'] = tcp_ports
                        total_tcp_ports += len(tcp_ports)
                        
                        # Log de progreso cada 10 hosts
                        if completed % 10 == 0 or completed == len(ips):
                            logger.info(f"  📊 Progreso: {completed}/{len(ips)} hosts escaneados")
                        
                    except Exception as e:
                        logger.error(f"  ❌ Error en Fase 2 para {ip}: {e}")
                        self.netbox_sync.sync_phase_error(ip, 2, str(e))
        
        else:
            # ========== MODO SECUENCIAL (original) ==========
            for idx, ip in enumerate(ips, 1):
                # Log cada 10 hosts
                if idx % 10 == 0 or idx == len(ips):
                    logger.info(f"  📊 Progreso: {idx}/{len(ips)} hosts")
                
                logger.debug(f"[{idx}/{len(ips)}] Escaneando puertos TCP: {ip}")
                
                try:
                    tcp_ports = self.phased_scanner.phase2_scan_tcp_ports(ip)
                    self.scan_results[ip]['tcp_ports'] = tcp_ports
                    total_tcp_ports += len(tcp_ports)
                    self.netbox_sync.sync_phase2_tcp_ports(ip, tcp_ports)
                    
                except Exception as e:
                    logger.error(f"  ❌ Error en Fase 2 para {ip}: {e}")
                    self.netbox_sync.sync_phase_error(ip, 2, str(e))
        
        phase_duration = time.time() - phase_start
        self.stats['phase_durations']['phase2'] = phase_duration
        self.stats['total_tcp_ports'] = total_tcp_ports
        
        logger.info("")
        logger.info(f"✅ Fase 2 completada: {total_tcp_ports} puertos TCP totales")
        logger.info(f"⏱️  Duración: {phase_duration:.1f}s ({phase_duration/60:.1f}m)")
        logger.info("")

    def _scan_single_host_phase2(self, ip: str) -> List[int]:
        """
        Escanea un solo host en Fase 2 (para uso en paralelización)
        
        Args:
            ip: IP a escanear
            
        Returns:
            Lista de puertos TCP abiertos
        """
        try:
            logger.debug(f"  🔍 Escaneando TCP: {ip}")
            tcp_ports = self.phased_scanner.phase2_scan_tcp_ports(ip)
            
            # Sincronizar con Netbox
            self.netbox_sync.sync_phase2_tcp_ports(ip, tcp_ports)
            
            return tcp_ports
            
        except Exception as e:
            logger.error(f"  ✗ Error en TCP scan de {ip}: {e}")
            self.netbox_sync.sync_phase_error(ip, 2, str(e))
            return []
        
    # ========================================================================
    # FASE 3: DETECCIÓN DE PUERTOS UDP
    # ========================================================================
    
    def execute_phase3(self, ips: list):
        """
        FASE 3: Escanea puertos UDP de cada host y sincroniza
        Soporta modo paralelo para mayor velocidad
        
        Args:
            ips: Lista de IPs a escanear
        """
        logger.info("=" * 70)
        logger.info("🔌 FASE 3: DETECCIÓN DE PUERTOS UDP")
        logger.info("=" * 70)
        logger.info("")
        
        if self.parallel_enabled:
            logger.info(f"⚡ Modo paralelo activado (max {self.max_workers} workers)")
        else:
            logger.info(f"⏭️  Modo secuencial")
        logger.info("")
        
        phase_start = time.time()
        total_udp_ports = 0
        completed = 0
        
        if self.parallel_enabled:
            # ========== MODO PARALELO ==========
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_ip = {
                    executor.submit(self._scan_single_host_phase3, ip): ip 
                    for ip in ips
                }
                
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    completed += 1
                    
                    try:
                        udp_ports = future.result()
                        self.scan_results[ip]['udp_ports'] = udp_ports
                        total_udp_ports += len(udp_ports)
                        
                        if completed % 10 == 0 or completed == len(ips):
                            logger.info(f"  📊 Progreso: {completed}/{len(ips)} hosts escaneados")
                        
                    except Exception as e:
                        logger.error(f"  ❌ Error en Fase 3 para {ip}: {e}")
                        self.netbox_sync.sync_phase_error(ip, 3, str(e))
        
        else:
            # ========== MODO SECUENCIAL ==========
            for idx, ip in enumerate(ips, 1):
                if idx % 10 == 0 or idx == len(ips):
                    logger.info(f"  📊 Progreso: {idx}/{len(ips)} hosts")
                
                logger.debug(f"[{idx}/{len(ips)}] Escaneando puertos UDP: {ip}")
                
                try:
                    udp_ports = self.phased_scanner.phase3_scan_udp_ports(
                        ip, top_ports=self.udp_top_ports
                    )
                    self.scan_results[ip]['udp_ports'] = udp_ports
                    total_udp_ports += len(udp_ports)
                    self.netbox_sync.sync_phase3_udp_ports(ip, udp_ports)
                    
                except Exception as e:
                    logger.error(f"  ❌ Error en Fase 3 para {ip}: {e}")
                    self.netbox_sync.sync_phase_error(ip, 3, str(e))
        
        phase_duration = time.time() - phase_start
        self.stats['phase_durations']['phase3'] = phase_duration
        self.stats['total_udp_ports'] = total_udp_ports
        
        logger.info("")
        logger.info(f"✅ Fase 3 completada: {total_udp_ports} puertos UDP totales")
        logger.info(f"⏱️  Duración: {phase_duration:.1f}s ({phase_duration/60:.1f}m)")
        logger.info("")

    def _scan_single_host_phase3(self, ip: str) -> List[int]:
        """
        Escanea un solo host en Fase 3 (para uso en paralelización)
        
        Args:
            ip: IP a escanear
            
        Returns:
            Lista de puertos UDP abiertos
        """
        try:
            logger.debug(f"  🔍 Escaneando UDP: {ip}")
            udp_ports = self.phased_scanner.phase3_scan_udp_ports(
                ip, top_ports=self.udp_top_ports
            )
            
            # Sincronizar con Netbox
            self.netbox_sync.sync_phase3_udp_ports(ip, udp_ports)
            
            return udp_ports
            
        except Exception as e:
            logger.error(f"  ✗ Error en UDP scan de {ip}: {e}")
            self.netbox_sync.sync_phase_error(ip, 3, str(e))
            return []
        
    # ========================================================================
    # FASE 4: IDENTIFICACIÓN DE SERVICIOS
    # ========================================================================
    
    def execute_phase4(self, ips: list):
        """
        FASE 4: Identifica servicios en puertos abiertos y sincroniza
        
        Args:
            ips: Lista de IPs a escanear
        """
        logger.info("=" * 70)
        logger.info("⚙️ FASE 4: IDENTIFICACIÓN DE SERVICIOS")
        logger.info("=" * 70)
        logger.info("")
        
        phase_start = time.time()
        total_services = 0
        
        for idx, ip in enumerate(ips, 1):
            logger.info(f"[{idx}/{len(ips)}] Identificando servicios: {ip}")
            
            try:
                tcp_ports = self.scan_results[ip]['tcp_ports']
                udp_ports = self.scan_results[ip]['udp_ports']

                # Saltar si no hay puertos abiertos
                if not tcp_ports and not udp_ports:
                    logger.info(f"  ⊘ Sin puertos abiertos, saltando fase 4")
                    # Aún así sincronizar con servicios vacíos
                    self.netbox_sync.sync_phase4_services(ip, {'tcp': {}, 'udp': {}})
                    continue

                # Identificar servicios
                services = self.phased_scanner.phase4_identify_services(
                    ip, tcp_ports, udp_ports
                )
                
                # Guardar resultados
                self.scan_results[ip]['services'] = services
                total_services += len(services.get('tcp', {})) + len(services.get('udp', {}))
                
                # SINCRONIZACIÓN INMEDIATA A NETBOX
                self.netbox_sync.sync_phase4_services(ip, services)
                
            except Exception as e:
                logger.error(f"  ❌ Error en Fase 4 para {ip}: {e}")
                self.netbox_sync.sync_phase_error(ip, 4, str(e))
            
            logger.info("")
        
        phase_duration = time.time() - phase_start
        self.stats['phase_durations']['phase4'] = phase_duration
        self.stats['total_services'] = total_services
        
        logger.info(f"✅ Fase 4 completada: {total_services} servicios identificados")
        logger.info(f"⏱️  Duración: {phase_duration:.1f}s ({phase_duration/60:.1f}m)")
        logger.info("")
    
    # ========================================================================
    # FASE 5: AUDITORÍA COMPLETA
    # ========================================================================
    
    def execute_phase5(self, ips: list):
        """
        FASE 5: Auditoría completa (OS, MAC, hostname) + clasificación
        
        Args:
            ips: Lista de IPs a escanear
        """
        logger.info("=" * 70)
        logger.info("🎯 FASE 5: AUDITORÍA COMPLETA")
        logger.info("=" * 70)
        logger.info("")
        
        phase_start = time.time()
        completed_hosts = 0
        
        for idx, ip in enumerate(ips, 1):
            logger.info(f"[{idx}/{len(ips)}] Auditoría completa: {ip}")
            
            try:
                # Auditoría completa con nmap
                audit_data = self.phased_scanner.phase5_full_audit(ip)
                
                # Enriquecer con SNMP si está habilitado
                if self.snmp_enabled and self.snmp_discovery:
                    logger.info(f"  🔍 Consultando SNMP...")
                    snmp_info = self.snmp_discovery.query_device(ip)
                    if snmp_info:
                        audit_data.update(snmp_info)
                        logger.info(f"  ✓ SNMP: {snmp_info.get('snmp_sysName', 'Sin nombre')}")
                
                # Clasificar dispositivo
                logger.info(f"  🏷️  Clasificando dispositivo...")
                
                # Construir dict para clasificación
                device_data = {
                    'ip': ip,
                    'hostname': audit_data.get('hostname', ''),
                    'mac': audit_data.get('mac', ''),
                    'vendor': audit_data.get('vendor', ''),
                    'os': audit_data.get('os', ''),
                    'ports': self.scan_results[ip]['tcp_ports'],
                    'services': self._convert_services_to_list(
                        self.scan_results[ip]['services']
                    )
                }
                
                # Agregar SNMP si existe
                if audit_data.get('snmp_enabled'):
                    device_data['snmp_enabled'] = True
                    device_data['snmp_sysDescr'] = audit_data.get('snmp_sysDescr', '')
                
                classification = self.classifier.classify(device_data)
                
                logger.info(f"  ✓ Tipo: {classification['device_type']} "
                          f"({classification['confidence']}%)")
                logger.info(f"  ✓ Rol: {classification['device_role']}")
                logger.info(f"  ✓ Categoría: {classification['category']}")
                
                # Guardar resultados
                self.scan_results[ip]['audit_data'] = audit_data
                self.scan_results[ip]['classification'] = classification
                
                # SINCRONIZACIÓN INMEDIATA A NETBOX
                self.netbox_sync.sync_phase5_complete(ip, audit_data, classification)
                
                completed_hosts += 1
                
            except Exception as e:
                logger.error(f"  ❌ Error en Fase 5 para {ip}: {e}")
                self.netbox_sync.sync_phase_error(ip, 5, str(e))
            
            logger.info("")
        
        phase_duration = time.time() - phase_start
        self.stats['phase_durations']['phase5'] = phase_duration
        self.stats['total_hosts_completed'] = completed_hosts
        
        logger.info("  🧹 Limpiando archivos temporales...")
        self.phased_scanner.cleanup_temp_files()
    
        logger.info(f"✅ Fase 5 completada: {completed_hosts} hosts completados")
        logger.info(f"⏱️  Duración: {phase_duration:.1f}s ({phase_duration/60:.1f}m)")
        logger.info("")
    
    def _convert_services_to_list(self, services_dict: Dict) -> List[Dict]:
        """Convierte dict de servicios a lista para el clasificador"""
        services_list = []
        
        for port, svc in services_dict.get('tcp', {}).items():
            services_list.append({
                'port': port,
                'protocol': 'tcp',
                'service': svc.get('service', ''),
                'product': svc.get('product', ''),
                'version': svc.get('version', '')
            })
        
        for port, svc in services_dict.get('udp', {}).items():
            services_list.append({
                'port': port,
                'protocol': 'udp',
                'service': svc.get('service', ''),
                'product': svc.get('product', '')
            })
        
        return services_list
    
    # ========================================================================
    # INTEGRACIÓN CON PROXMOX
    # ========================================================================
    
    def integrate_proxmox(self):
        """Integra información de Proxmox si está disponible"""
        
        if not self.proxmox or not self.proxmox.connected:
            return
        
        logger.info("=" * 70)
        logger.info("🖥️  INTEGRACIÓN CON PROXMOX")
        logger.info("=" * 70)
        logger.info("")
        
        try:
            # Obtener VMs y LXCs de Proxmox
            proxmox_devices = self.proxmox.get_all_devices()
            
            logger.info(f"✓ Encontradas {len(proxmox_devices)} VMs/LXCs en Proxmox")
            
            # Crear índice por IP
            proxmox_by_ip = {d['ip']: d for d in proxmox_devices if 'ip' in d}
            
            # Enriquecer dispositivos escaneados con info de Proxmox
            for ip, result in self.scan_results.items():
                if ip in proxmox_by_ip:
                    px_info = proxmox_by_ip[ip]
                    result['proxmox_vm'] = True
                    result['proxmox_type'] = px_info['type']
                    result['proxmox_name'] = px_info['name']
                    result['proxmox_node'] = px_info['node']
                    result['proxmox_status'] = px_info['status']
                    
                    logger.info(f"  ✓ {ip} es {px_info['type']}: {px_info['name']}")
            
            logger.info("")
            
        except Exception as e:
            logger.error(f"❌ Error integrando Proxmox: {e}")
    
    # ========================================================================
    # RESUMEN Y ESTADÍSTICAS
    # ========================================================================
    
    def print_summary(self):
        """Imprime resumen final del escaneo"""
        
        logger.info("")
        logger.info("=" * 70)
        logger.info("📈 RESUMEN FINAL DEL ESCANEO")
        logger.info("=" * 70)
        logger.info("")
        
        # Estadísticas generales
        logger.info("📊 Estadísticas Generales:")
        logger.info(f"  Redes escaneadas:           {self.stats['networks_scanned']}")
        logger.info(f"  Hosts descubiertos:         {self.stats['total_hosts_discovered']}")
        logger.info(f"  Hosts completados:          {self.stats['total_hosts_completed']}")
        logger.info(f"  Total puertos TCP:          {self.stats['total_tcp_ports']}")
        logger.info(f"  Total puertos UDP:          {self.stats['total_udp_ports']}")
        logger.info(f"  Total servicios:            {self.stats['total_services']}")
        logger.info("")
        
        # Duración por fase
        logger.info("⏱️  Duración por Fase:")
        for phase, duration in self.stats['phase_durations'].items():
            minutes = int(duration / 60)
            seconds = int(duration % 60)
            logger.info(f"  {phase.upper():<10} {duration:>6.1f}s ({minutes}m {seconds}s)")
        
        total_duration = self.stats['scan_duration']
        total_minutes = int(total_duration / 60)
        total_seconds = int(total_duration % 60)
        logger.info(f"  {'TOTAL':<10} {total_duration:>6.1f}s ({total_minutes}m {total_seconds}s)")
        logger.info("")
        
        # Estadísticas de Netbox
        netbox_stats = self.netbox_sync.get_phase_stats()
        logger.info("📝 Estadísticas de Sincronización Netbox:")
        logger.info(f"  Fase 1 (IPs descubiertas):  {netbox_stats['phase1_ips_discovered']}")
        logger.info(f"  Fase 2 (TCP escaneado):     {netbox_stats['phase2_tcp_scanned']}")
        logger.info(f"  Fase 3 (UDP escaneado):     {netbox_stats['phase3_udp_scanned']}")
        logger.info(f"  Fase 4 (Servicios):         {netbox_stats['phase4_services_identified']}")
        logger.info(f"  Fase 5 (Completados):       {netbox_stats['phase5_complete']}")
        logger.info(f"  ---")
        logger.info(f"  Total creados:              {netbox_stats['total_created']}")
        logger.info(f"  Total actualizados:         {netbox_stats['total_updated']}")
        logger.info(f"  Errores:                    {netbox_stats['total_errors']}")
        logger.info("")
        
        # Estadísticas del scanner
        scanner_stats = self.phased_scanner.get_stats()
        logger.info("🔍 Estadísticas del Scanner:")
        logger.info(f"  Hosts con TCP:              {scanner_stats['phase2_hosts_with_tcp']}")
        logger.info(f"  Hosts con UDP:              {scanner_stats['phase3_hosts_with_udp']}")
        logger.info(f"  Hosts con servicios:        {scanner_stats['phase4_hosts_with_services']}")
        logger.info(f"  Auditorías completas:       {scanner_stats['phase5_hosts_complete']}")
        logger.info(f"  Errores:                    {scanner_stats['errors']}")
        logger.info("")
        
        logger.info("✅ Escaneo completado exitosamente")
        logger.info("")
        logger.info(f"🌐 Ver resultados en: {self.netbox_url}/ipam/ip-addresses/")
        logger.info("   Filtrar por tags: fase-1-ip-viva, fase-2-puertos-tcp, etc.")
        logger.info("")
        logger.info("=" * 70)
    
    # ========================================================================
    # MÉTODO PRINCIPAL
    # ========================================================================
    
    def run(self):
        """Ejecuta el escaneo completo por fases con sincronización incremental"""
        
        start_time = datetime.now()
        
        try:
            # 1. Validar configuración
            if not self.validate_config():
                sys.exit(1)
            
            # 2. Bootstrap de Netbox
            if not self.run_bootstrap():
                logger.warning("⚠️  Bootstrap falló pero continuando...")
            
            # 3. Inicializar componentes
            self.initialize_components()
            
            # 4. Escanear cada red configurada
            for network in self.networks:
                logger.info("")
                logger.info("=" * 70)
                logger.info(f"🌐 ESCANEANDO RED: {network}")
                logger.info("=" * 70)
                logger.info("")
                
                # FASE 1: Descubrimiento
                active_ips = self.execute_phase1(network)
                
                if not active_ips:
                    logger.warning(f"⚠️  No se encontraron hosts activos en {network}")
                    continue
                
                # FASE 2: Puertos TCP
                self.execute_phase2(active_ips)
                
                # FASE 3: Puertos UDP
                self.execute_phase3(active_ips)
                
                # FASE 4: Servicios
                self.execute_phase4(active_ips)
                
                # FASE 5: Auditoría completa
                self.execute_phase5(active_ips)
                
                self.stats['networks_scanned'] += 1
            
            # 5. Integrar con Proxmox (opcional)
            self.integrate_proxmox()
            
            # 6. Limpiar archivos temporales
            self.phased_scanner.cleanup_temp_files()
            
            # 7. Calcular duración total y mostrar resumen
            end_time = datetime.now()
            self.stats['scan_duration'] = (end_time - start_time).total_seconds()
            self.print_summary()
            
        except KeyboardInterrupt:
            logger.warning("\n⚠️  Escaneo interrumpido por el usuario")
            sys.exit(1)
        except Exception as e:
            logger.error(f"\n❌ Error fatal durante el escaneo: {e}")
            import traceback
            logger.error(traceback.format_exc())
            sys.exit(1)


def main():
    """Punto de entrada principal"""
    scanner = NetAuditPhasedScanner()
    scanner.run()


if __name__ == '__main__':
    main()
