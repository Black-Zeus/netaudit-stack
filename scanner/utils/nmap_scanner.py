"""
Módulo de escaneo de red usando Nmap
Incluye progreso en tiempo real y callbacks
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
    
    def _progress_callback(self, host, result):
        """Callback para mostrar progreso del escaneo"""
        self.progress['hosts_scanned'] += 1
        self.progress['current_host'] = host
        
        scanned = self.progress['hosts_scanned']
        total = self.progress['hosts_total']
        percentage = (scanned / total * 100) if total > 0 else 0
        
        # Calcular tiempo estimado
        elapsed = time.time() - self.progress['start_time']
        if scanned > 0:
            avg_time = elapsed / scanned
            remaining = (total - scanned) * avg_time
            eta_mins = int(remaining / 60)
            eta_secs = int(remaining % 60)
            
            logger.info(
                f"  ⏳ Progreso: {scanned}/{total} hosts ({percentage:.1f}%) "
                f"| Activos: {self.progress['hosts_up']} "
                f"| ETA: {eta_mins}m {eta_secs}s"
            )
        else:
            logger.info(f"  ⏳ Escaneando host {scanned}/{total} ({percentage:.1f}%)")
    
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
            # Primero: ping scan rápido para descubrir hosts
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
            
            logger.info(f"  ✓ Encontrados {len(hosts_up)} hosts activos")
            
            if not hosts_up:
                logger.warning("  ⚠ No se encontraron hosts activos en la red")
                return devices
            
            # Segundo: escaneo detallado de hosts activos
            logger.info(f"  🔍 Paso 2/2: Escaneo detallado de {len(hosts_up)} hosts activos...")
            logger.info(f"  ⏱  Esto puede tomar varios minutos...")
            
            # Resetear progreso para segunda fase
            self.progress['hosts_total'] = len(hosts_up)
            self.progress['hosts_scanned'] = 0
            self.progress['start_time'] = time.time()
            
            # Construir argumentos de escaneo
            scan_args = self._build_scan_args()
            
            # Escanear cada host activo
            for idx, host in enumerate(hosts_up, 1):
                try:
                    logger.info(f"  [{idx}/{len(hosts_up)}] Escaneando {host}...")
                    
                    # Escanear host individual
                    self.nm.scan(hosts=host, arguments=scan_args)
                    
                    if host in self.nm.all_hosts():
                        device_info = self._parse_host(host)
                        if device_info:
                            devices.append(device_info)
                            logger.info(f"    ✓ {host} - {device_info.get('hostname', 'Sin nombre')}")
                    
                    # Actualizar progreso
                    self.progress['hosts_scanned'] = idx
                    
                except Exception as e:
                    logger.warning(f"    ⚠ Error escaneando {host}: {e}")
                    continue
            
            elapsed = time.time() - self.progress['start_time']
            logger.info(f"  ⏱  Tiempo total de escaneo: {elapsed:.1f} segundos")
            
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