"""
Módulo de escaneo de red usando Nmap - VERSIÓN VERBOSE
Incluye progreso en tiempo real y logs detallados
"""

import nmap
import logging
from typing import List, Dict, Optional
import time

logger = logging.getLogger('netaudit')


class NetworkScanner:
    """Escáner de red usando Nmap con soporte de progreso"""
    
    def __init__(self, timing='T2', enable_os_detection=True, 
                 enable_service_version=True, max_ports=1000):
        """
        Inicializa el escáner
        
        Args:
            timing: Timing template de nmap (T0-T5)
            enable_os_detection: Activar detección de OS
            enable_service_version: Activar detección de versiones de servicio
            max_ports: Número máximo de puertos a escanear
        """
        self.nm = nmap.PortScanner()
        self.timing = timing
        self.enable_os_detection = enable_os_detection
        self.enable_service_version = enable_service_version
        self.max_ports = max_ports
        
        # Estadísticas de progreso
        self.progress = {
            'current_host': '',
            'hosts_total': 0,
            'hosts_scanned': 0,
            'hosts_up': 0,
            'start_time': 0
        }
    
    def scan_network(self, network: str) -> List[Dict]:
        """
        Escanea una red completa
        
        Args:
            network: Red en formato CIDR (ej: 192.168.1.0/24)
            
        Returns:
            Lista de dispositivos encontrados
        """
        logger.info(f"Iniciando escaneo de {network}")
        logger.info(f"Configuración: Timing={self.timing}, Max Ports={self.max_ports}")
        
        devices = []
        
        try:
            # ==========================================
            # FASE 1: PING SCAN (Descubrimiento rápido)
            # ==========================================
            logger.info("  🔍 Paso 1/2: Descubrimiento rápido de hosts (ping scan)...")
            self.progress['start_time'] = time.time()
            
            # Calcular número aproximado de hosts
            import ipaddress
            net = ipaddress.ip_network(network, strict=False)
            self.progress['hosts_total'] = net.num_addresses - 2  # Sin network/broadcast
            
            logger.info(f"  📊 Escaneando hasta {self.progress['hosts_total']} direcciones IP...")
            
            # Ping scan (-sn: no port scan)
            ping_args = f'-sn -{self.timing}'
            
            self.nm.scan(hosts=network, arguments=ping_args)
            
            hosts_up = []
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    hosts_up.append(host)
                    self.progress['hosts_up'] += 1
            
            # ✨ NUEVO: Mostrar lista de hosts encontrados
            logger.info(f"  ✓ Encontrados {len(hosts_up)} hosts activos")
            logger.info("")
            logger.info("  📋 Hosts activos detectados:")
            for idx, host in enumerate(hosts_up, 1):
                hostname = ""
                if 'hostnames' in self.nm[host]:
                    hostnames = self.nm[host]['hostnames']
                    if hostnames and len(hostnames) > 0:
                        hostname = f" ({hostnames[0].get('name', '')})"
                logger.info(f"     {idx:2d}. {host}{hostname}")
            logger.info("")
            
            if not hosts_up:
                logger.warning("  ⚠ No se encontraron hosts activos en la red")
                return devices
            
            # ==========================================
            # FASE 2: ESCANEO DETALLADO
            # ==========================================
            logger.info(f"  🔍 Paso 2/2: Escaneo detallado de {len(hosts_up)} hosts activos...")
            logger.info(f"  ⏱  Esto puede tomar varios minutos...")
            logger.info("")
            
            # Resetear progreso para segunda fase
            self.progress['hosts_total'] = len(hosts_up)
            self.progress['hosts_scanned'] = 0
            self.progress['start_time'] = time.time()
            
            # Construir argumentos de escaneo
            scan_args = self._build_scan_args()
            
            # Escanear cada host activo
            for idx, host in enumerate(hosts_up, 1):
                try:
                    # Calcular tiempo estimado
                    elapsed = time.time() - self.progress['start_time']
                    if idx > 1:
                        avg_time = elapsed / (idx - 1)
                        remaining = (len(hosts_up) - idx + 1) * avg_time
                        eta_mins = int(remaining / 60)
                        eta_secs = int(remaining % 60)
                        eta_str = f" | ETA: {eta_mins}m {eta_secs}s"
                    else:
                        eta_str = ""
                    
                    logger.info(f"  [{idx}/{len(hosts_up)}] Escaneando {host}...{eta_str}")
                    
                    # Escanear host individual
                    scan_start = time.time()
                    self.nm.scan(hosts=host, arguments=scan_args)
                    scan_duration = time.time() - scan_start
                    
                    if host in self.nm.all_hosts():
                        device_info = self._parse_host(host)
                        if device_info:
                            devices.append(device_info)
                            
                            # ✨ NUEVO: Mostrar info resumida del host
                            hostname = device_info.get('hostname', 'Sin nombre')
                            ports_count = len(device_info.get('ports', []))
                            os_info = device_info.get('os', 'Desconocido')
                            
                            logger.info(f"    ✓ {host} - {hostname}")
                            logger.info(f"       OS: {os_info}")
                            logger.info(f"       Puertos abiertos: {ports_count}")
                            
                            if device_info.get('services'):
                                # Mostrar primeros 3 servicios
                                services = device_info['services'][:3]
                                logger.info(f"       Servicios destacados:")
                                for svc in services:
                                    svc_name = svc.get('service', 'unknown')
                                    svc_port = svc.get('port')
                                    svc_product = svc.get('product', '')
                                    if svc_product:
                                        logger.info(f"         - {svc_port}/{svc_name}: {svc_product}")
                                    else:
                                        logger.info(f"         - {svc_port}/{svc_name}")
                            
                            logger.info(f"       Tiempo: {scan_duration:.1f}s")
                            logger.info("")
                    
                    # Actualizar progreso
                    self.progress['hosts_scanned'] = idx
                    
                except Exception as e:
                    logger.warning(f"    ⚠ Error escaneando {host}: {e}")
                    logger.info("")
                    continue
            
            elapsed = time.time() - self.progress['start_time']
            logger.info(f"  ⏱  Tiempo total de escaneo detallado: {elapsed:.1f} segundos ({elapsed/60:.1f} minutos)")
            logger.info("")
            
        except Exception as e:
            logger.error(f"Error durante el escaneo: {e}")
            raise
        
        return devices
    
    def _build_scan_args(self) -> str:
        """Construye los argumentos de escaneo de nmap"""
        args = [f'-{self.timing}']
        
        # Top ports (más rápido que escaneo completo)
        args.append(f'--top-ports {self.max_ports}')
        
        # Detección de versión de servicios
        if self.enable_service_version:
            args.append('-sV')
        
        # Detección de OS (requiere root)
        if self.enable_os_detection:
            args.append('-O')
            args.append('--osscan-guess')
        
        # Extras útiles
        args.append('--host-timeout 5m')  # Timeout por host
        args.append('-Pn')  # Skip ping (ya sabemos que está up)
        
        return ' '.join(args)
    
    def _parse_host(self, host: str) -> Optional[Dict]:
        """
        Parsea la información de un host escaneado
        
        Args:
            host: IP del host
            
        Returns:
            Diccionario con información del dispositivo
        """
        try:
            host_info = self.nm[host]
            
            device = {
                'ip': host,
                'state': host_info.state(),
                'hostname': '',
                'mac': '',
                'vendor': '',
                'os': '',
                'os_accuracy': 0,
                'ports': [],
                'services': []
            }
            
            # Hostname
            if 'hostnames' in host_info:
                hostnames = host_info['hostnames']
                if hostnames and len(hostnames) > 0:
                    device['hostname'] = hostnames[0].get('name', '')
            
            # MAC Address y Vendor
            if 'addresses' in host_info:
                if 'mac' in host_info['addresses']:
                    device['mac'] = host_info['addresses']['mac']
                
            if 'vendor' in host_info:
                vendors = host_info['vendor']
                if vendors:
                    # El vendor viene como {mac: vendor_name}
                    device['vendor'] = list(vendors.values())[0] if vendors.values() else ''
            
            # OS Detection
            if 'osmatch' in host_info:
                os_matches = host_info['osmatch']
                if os_matches and len(os_matches) > 0:
                    best_match = os_matches[0]
                    device['os'] = best_match.get('name', '')
                    device['os_accuracy'] = int(best_match.get('accuracy', 0))
            
            # Puertos y servicios abiertos
            if 'tcp' in host_info:
                for port, port_info in host_info['tcp'].items():
                    if port_info['state'] == 'open':
                        device['ports'].append(port)
                        
                        service = {
                            'port': port,
                            'protocol': 'tcp',
                            'service': port_info.get('name', ''),
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', '')
                        }
                        device['services'].append(service)
            
            if 'udp' in host_info:
                for port, port_info in host_info['udp'].items():
                    if port_info['state'] == 'open':
                        device['ports'].append(f"udp/{port}")
                        
                        service = {
                            'port': port,
                            'protocol': 'udp',
                            'service': port_info.get('name', ''),
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', '')
                        }
                        device['services'].append(service)
            
            return device
            
        except Exception as e:
            logger.error(f"Error parseando host {host}: {e}")
            return None
    
    def scan_single_host(self, ip: str) -> Optional[Dict]:
        """
        Escanea un solo host
        
        Args:
            ip: Dirección IP del host
            
        Returns:
            Información del dispositivo o None
        """
        logger.info(f"Escaneando host individual: {ip}")
        
        try:
            args = self._build_scan_args()
            self.nm.scan(hosts=ip, arguments=args)
            
            if ip in self.nm.all_hosts():
                return self._parse_host(ip)
            else:
                logger.warning(f"Host {ip} no responde")
                return None
                
        except Exception as e:
            logger.error(f"Error escaneando {ip}: {e}")
            return None