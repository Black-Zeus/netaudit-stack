"""
Módulo de escaneo por fases usando comandos nmap nativos
Implementa el escaneo en 5 fases con sincronización incremental a Netbox

FASES:
1. Descubrimiento de IPs (ping scan + técnicas múltiples)
2. Detección de puertos TCP (escaneo SYN completo)
3. Detección de puertos UDP (top ports)
4. Identificación de servicios (version detection)
5. Auditoría completa (OS, MAC, hostname, fingerprinting)
"""

import subprocess
import re
import logging
import time
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional, Set, Tuple
from pathlib import Path
import tempfile

logger = logging.getLogger('netaudit')


class NmapPhasedScanner:
    """Scanner de red en 5 fases con comandos nmap nativos"""
    
    def __init__(self, timing='T2', min_rate=5000):
        """
        Inicializa el scanner por fases
        
        Args:
            timing: Timing template de nmap (T0-T5)
            min_rate: Paquetes mínimos por segundo para escaneo rápido
        """
        self.timing = timing
        self.min_rate = min_rate
        
        # Verificar que nmap está disponible
        self._verify_nmap()
        
        # Directorio temporal para archivos de salida
        self.temp_dir = Path(tempfile.gettempdir()) / 'netaudit_scans'
        self.temp_dir.mkdir(exist_ok=True)
        
        # Estadísticas por fase
        self.stats = {
            'phase1_hosts': 0,
            'phase2_hosts_with_tcp': 0,
            'phase3_hosts_with_udp': 0,
            'phase4_hosts_with_services': 0,
            'phase5_hosts_complete': 0,
            'total_tcp_ports': 0,
            'total_udp_ports': 0,
            'total_services': 0,
            'errors': 0
        }
    
    def _verify_nmap(self):
        """Verifica que nmap está instalado y accesible"""
        try:
            result = subprocess.run(
                ['nmap', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                version = result.stdout.split('\n')[0]
                logger.info(f"✓ Nmap detectado: {version}")
            else:
                raise Exception("Nmap no responde correctamente")
        except Exception as e:
            logger.error(f"❌ Nmap no está disponible: {e}")
            raise
    
    def _run_nmap_command(self, args: List[str], timeout: int = 300) -> Tuple[str, str, int]:
        """
        Ejecuta un comando nmap y retorna la salida
        
        Args:
            args: Lista de argumentos para nmap
            timeout: Timeout en segundos
            
        Returns:
            (stdout, stderr, returncode)
        """
        cmd = ['nmap'] + args
        logger.debug(f"Ejecutando: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            logger.error(f"⏱️ Timeout ejecutando nmap después de {timeout}s")
            return '', f'Timeout after {timeout}s', 1
        except Exception as e:
            logger.error(f"❌ Error ejecutando nmap: {e}")
            return '', str(e), 1
    
    # ========================================================================
    # FASE 1: DESCUBRIMIENTO DE IPs
    # ========================================================================
    
    def phase1_discover_hosts(self, network: str) -> List[str]:
        """
        FASE 1: Descubre hosts activos en la red usando múltiples técnicas
        
        Técnicas:
        - ICMP Echo (ping estándar)
        - TCP SYN a puertos 80,443
        - TCP ACK a puertos 80,443
        
        Args:
            network: Red en formato CIDR (ej: 192.168.3.0/24)
            
        Returns:
            Lista de IPs activas
        """
        logger.info("=" * 70)
        logger.info("🔍 FASE 1: Descubrimiento de Hosts")
        logger.info("=" * 70)
        logger.info(f"Red objetivo: {network}")
        logger.info("")
        
        active_hosts = set()
        
        # Técnica 1: Ping scan básico
        logger.info("  📡 Técnica 1: ICMP Echo Request (ping)")
        hosts_ping = self._discover_with_ping(network)
        active_hosts.update(hosts_ping)
        logger.info(f"    → {len(hosts_ping)} hosts responden a ping")
        
        # Técnica 2: TCP SYN
        logger.info("  📡 Técnica 2: TCP SYN a puertos 80,443")
        hosts_syn = self._discover_with_tcp_syn(network)
        active_hosts.update(hosts_syn)
        logger.info(f"    → {len(hosts_syn)} hosts responden a TCP SYN")
        
        # Técnica 3: TCP ACK
        logger.info("  📡 Técnica 3: TCP ACK a puertos 80,443")
        hosts_ack = self._discover_with_tcp_ack(network)
        active_hosts.update(hosts_ack)
        logger.info(f"    → {len(hosts_ack)} hosts responden a TCP ACK")
        
        active_hosts_list = sorted(active_hosts, key=lambda ip: tuple(map(int, ip.split('.'))))
        
        logger.info("")
        logger.info(f"✅ Total de hosts activos encontrados: {len(active_hosts_list)}")
        logger.info("")
        
        # Mostrar lista de hosts
        if active_hosts_list:
            logger.info("📋 Hosts activos detectados:")
            for idx, ip in enumerate(active_hosts_list, 1):
                logger.info(f"  {idx:3d}. {ip}")
            logger.info("")
        
        self.stats['phase1_hosts'] = len(active_hosts_list)
        
        return active_hosts_list
    
    def _discover_with_ping(self, network: str) -> Set[str]:
        """Descubrimiento con ping scan estándar"""
        args = [
            '-sn',  # Ping scan (no port scan)
            f'-{self.timing}',
            network
        ]
        
        stdout, stderr, returncode = self._run_nmap_command(args, timeout=120)
        
        if returncode != 0:
            logger.warning(f"  ⚠️ Ping scan falló: {stderr}")
            return set()
        
        return self._parse_host_discovery(stdout)
    
    def _discover_with_tcp_syn(self, network: str) -> Set[str]:
        """Descubrimiento con TCP SYN a puertos comunes"""
        args = [
            '-sn',  # No port scan
            '-PS80,443',  # TCP SYN a puertos 80,443
            f'-{self.timing}',
            network
        ]
        
        stdout, stderr, returncode = self._run_nmap_command(args, timeout=120)
        
        if returncode != 0:
            logger.warning(f"  ⚠️ TCP SYN scan falló: {stderr}")
            return set()
        
        return self._parse_host_discovery(stdout)
    
    def _discover_with_tcp_ack(self, network: str) -> Set[str]:
        """Descubrimiento con TCP ACK a puertos comunes"""
        args = [
            '-sn',  # No port scan
            '-PA80,443',  # TCP ACK a puertos 80,443
            f'-{self.timing}',
            network
        ]
        
        stdout, stderr, returncode = self._run_nmap_command(args, timeout=120)
        
        if returncode != 0:
            logger.warning(f"  ⚠️ TCP ACK scan falló: {stderr}")
            return set()
        
        return self._parse_host_discovery(stdout)
    
    def _parse_host_discovery(self, nmap_output: str) -> Set[str]:
        """
        Parsea la salida de nmap para extraer hosts activos
        
        Busca líneas como:
        - "Nmap scan report for 192.168.3.1"
        - "Host is up"
        """
        hosts = set()
        
        lines = nmap_output.split('\n')
        current_ip = None
        
        for line in lines:
            # Buscar IP en línea "Nmap scan report for X.X.X.X"
            if 'Nmap scan report for' in line:
                ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
                if ip_match:
                    current_ip = ip_match.group(1)
            
            # Si la siguiente línea dice "Host is up", agregar IP
            if current_ip and 'Host is up' in line:
                hosts.add(current_ip)
                current_ip = None
        
        return hosts
    
    # ========================================================================
    # FASE 2: DETECCIÓN DE PUERTOS TCP
    # ========================================================================

    def phase2_scan_tcp_ports(self, ip: str) -> List[int]:
        """
        FASE 2: Escanea TODOS los puertos TCP (1-65535) de forma rápida
        
        Comando equivalente:
        nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 192.168.3.X -oG allPorts
        
        Args:
            ip: Dirección IP a escanear
            
        Returns:
            Lista de puertos TCP abiertos
        """
        logger.info(f"  🔌 FASE 2: Escaneando puertos TCP de {ip}")
        
        # Archivo de salida temporal
        output_file = self.temp_dir / f'tcp_ports_{ip.replace(".", "_")}.gnmap'
        
        args = [
            '-p-',  # Todos los puertos (1-65535)
            '--open',  # Solo puertos abiertos
            '-sS',  # TCP SYN scan
            f'--min-rate={self.min_rate}',  # Velocidad mínima
            '-vvv',  # Muy verbose
            '-n',  # No DNS resolution
            '-Pn',  # No ping (ya sabemos que está up)
            f'-{self.timing}',
            '-oG', str(output_file),  # Output grepable
            ip
        ]
        
        start_time = time.time()
        
        # Calcular timeout dinámico basado en min_rate
        # Fórmula: (65535 puertos / min_rate) + margen de 60s
        estimated_time = (65535 / self.min_rate) + 60
        timeout = min(int(estimated_time), 600)  # Máximo 10 minutos
        
        logger.debug(f"    Timeout calculado: {timeout}s (basado en min_rate={self.min_rate})")
        
        stdout, stderr, returncode = self._run_nmap_command(args, timeout=timeout)
        duration = time.time() - start_time
        
        if returncode != 0:
            logger.warning(f"    ⚠️ Escaneo TCP falló: {stderr}")
            self.stats['errors'] += 1
            return []
        
        # Parsear archivo grepable
        ports = self._parse_grepable_ports(output_file)
        
        if ports:
            logger.info(f"    ✅ {len(ports)} puertos TCP abiertos ({duration:.1f}s)")
            logger.info(f"       Puertos: {self._format_port_list(ports)}")
            self.stats['phase2_hosts_with_tcp'] += 1
            self.stats['total_tcp_ports'] += len(ports)
        else:
            logger.info(f"    ○ No se encontraron puertos TCP abiertos")
        
        return ports

    def _parse_grepable_ports(self, gnmap_file: Path) -> List[int]:
        """
        Parsea archivo grepable de nmap para extraer puertos
        
        Busca líneas como:
        Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
        
        Equivalente a:
        grep -oP '\d+/open' allPorts | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//'
        """
        ports = []
        
        try:
            with open(gnmap_file, 'r') as f:
                content = f.read()
            
            # Buscar todos los patrones puerto/open/tcp
            # Asegurar que solo capturamos puertos TCP
            matches = re.findall(r'(\d+)/open/tcp', content)
            ports = [int(p) for p in matches]
            ports.sort()
            
        except FileNotFoundError:
            logger.error(f"Archivo no encontrado: {gnmap_file}")
        except Exception as e:
            logger.error(f"Error parseando {gnmap_file}: {e}")
        
        return ports
    
    # ========================================================================
    # FASE 3: DETECCIÓN DE PUERTOS UDP (1000 PUERTOS)
    # ========================================================================

    def phase3_scan_udp_ports(self, ip: str, top_ports: int = 1000) -> List[int]:
        """
        FASE 3: Escanea los 1000 puertos UDP más comunes (ajustable)
        
        Comando equivalente:
        sudo nmap -sU --top-ports 1000 -n -Pn 192.168.3.X
        
        NOTA: Escanear UDP es MUY lento. Con 1000 puertos puede tomar
        5-10 minutos por host dependiendo del timing.
        
        Args:
            ip: Dirección IP a escanear
            top_ports: Número de puertos UDP más comunes a escanear (default: 1000)
            
        Returns:
            Lista de puertos UDP abiertos
        """
        logger.info(f"  🔌 FASE 3: Escaneando top {top_ports} puertos UDP de {ip}")
        
        output_file = self.temp_dir / f'udp_ports_{ip.replace(".", "_")}.gnmap'
        
        args = [
            '-sU',  # UDP scan
            f'--top-ports={top_ports}',  # Top N puertos más comunes
            '--open',  # Solo puertos abiertos
            '-n',  # No DNS resolution
            '-Pn',  # No ping
            f'-{self.timing}',
            '-oG', str(output_file),
            ip
        ]
        
        start_time = time.time()
        
        # UDP es MUCHO más lento - ajustar timeout según cantidad de puertos
        # Estimación: ~1-2 segundos por puerto con T2
        if self.timing == 'T2':
            timeout = min(top_ports * 2 + 60, 1800)  # Máximo 30 minutos
        elif self.timing == 'T3':
            timeout = min(top_ports * 1.5 + 60, 1200)  # Máximo 20 minutos
        else:  # T4 o superior
            timeout = min(top_ports + 60, 900)  # Máximo 15 minutos
        
        logger.debug(f"    Timeout calculado: {timeout}s para {top_ports} puertos UDP")
        logger.info(f"    ⏳ Esto puede tomar varios minutos...")
        
        stdout, stderr, returncode = self._run_nmap_command(args, timeout=int(timeout))
        duration = time.time() - start_time
        
        if returncode != 0:
            logger.warning(f"    ⚠️ Escaneo UDP falló: {stderr}")
            self.stats['errors'] += 1
            return []
        
        # Parsear puertos UDP
        ports = self._parse_grepable_udp_ports(output_file)
        
        if ports:
            logger.info(f"    ✅ {len(ports)} puertos UDP abiertos ({duration:.1f}s / {duration/60:.1f}m)")
            logger.info(f"       Puertos: {self._format_port_list(ports, max_show=15)}")
            self.stats['phase3_hosts_with_udp'] += 1
            self.stats['total_udp_ports'] += len(ports)
        else:
            logger.info(f"    ○ No se encontraron puertos UDP abiertos")
        
        return ports

    def _parse_grepable_udp_ports(self, gnmap_file: Path) -> List[int]:
        """
        Parsea archivo grepable de nmap para extraer puertos UDP
        
        Busca líneas como:
        Ports: 53/open/udp//domain///, 161/open/udp//snmp///
        """
        ports = []
        
        try:
            with open(gnmap_file, 'r') as f:
                content = f.read()
            
            # Buscar patrones puerto/open/udp
            matches = re.findall(r'(\d+)/open/udp', content)
            ports = [int(p) for p in matches]
            ports.sort()
            
        except FileNotFoundError:
            logger.error(f"Archivo no encontrado: {gnmap_file}")
        except Exception as e:
            logger.error(f"Error parseando {gnmap_file}: {e}")
        
        return ports
    
    # ========================================================================
    # FASE 4: IDENTIFICACIÓN DE SERVICIOS
    # ========================================================================

    def phase4_identify_services(self, ip: str, tcp_ports: List[int], 
                                udp_ports: List[int]) -> Dict:
        """
        FASE 4: Identifica servicios en puertos abiertos
        
        Comando equivalente:
        nmap -sV -p <puertos> -Pn 192.168.3.X -oN serviceScan.txt
        
        Args:
            ip: Dirección IP
            tcp_ports: Lista de puertos TCP abiertos
            udp_ports: Lista de puertos UDP abiertos
            
        Returns:
            Diccionario con servicios detectados
        """
        logger.info(f"  ⚙️ FASE 4: Identificando servicios de {ip}")
        
        services = {
            'tcp': {},
            'udp': {}
        }
        
        # Validar si hay puertos para escanear
        if not tcp_ports and not udp_ports:
            logger.info(f"    ⊘ Sin puertos abiertos, saltando identificación de servicios")
            return services
        
        # Escanear servicios TCP
        if tcp_ports:
            logger.debug(f"    Identificando {len(tcp_ports)} servicios TCP...")
            tcp_services = self._identify_services_on_ports(
                ip, tcp_ports, protocol='tcp'
            )
            services['tcp'] = tcp_services
        
        # Escanear servicios UDP
        if udp_ports:
            logger.debug(f"    Identificando {len(udp_ports)} servicios UDP...")
            udp_services = self._identify_services_on_ports(
                ip, udp_ports, protocol='udp'
            )
            services['udp'] = udp_services
        
        total_services = len(services['tcp']) + len(services['udp'])
        
        if total_services > 0:
            logger.info(f"    ✅ {total_services} servicios identificados")
            self._log_services_summary(services)
            self.stats['phase4_hosts_with_services'] += 1
            self.stats['total_services'] += total_services
        else:
            logger.info(f"    ○ No se pudieron identificar servicios")
        
        return services

    def _identify_services_on_ports(self, ip: str, ports: List[int], 
                                    protocol: str = 'tcp') -> Dict:
        """
        Identifica servicios en puertos específicos
        
        Args:
            ip: IP a escanear
            ports: Lista de puertos
            protocol: 'tcp' o 'udp'
            
        Returns:
            Dict con info de servicios {puerto: {service, product, version, ...}}
        """
        if not ports:
            return {}
        
        # Construir lista de puertos
        port_list = ','.join(map(str, ports))
        
        output_file = self.temp_dir / f'{protocol}_services_{ip.replace(".", "_")}.xml'
        
        args = [
            '-sV',  # Version detection
            '-p', port_list,
            '-Pn',  # No ping
            f'-{self.timing}',
        ]
        
        # Para UDP, agregar flag -sU
        if protocol == 'udp':
            args.insert(1, '-sU')
        
        args.extend(['-oX', str(output_file), ip])
        
        # Timeout basado en cantidad de puertos
        # Version detection es lento: ~5s por puerto
        timeout = min(len(ports) * 5 + 60, 900)  # Máximo 15 minutos
        
        stdout, stderr, returncode = self._run_nmap_command(args, timeout=timeout)
        
        if returncode != 0:
            logger.warning(f"    ⚠️ Service scan {protocol.upper()} falló: {stderr}")
            return {}
        
        # Parsear XML
        return self._parse_service_xml(output_file)

    def _parse_service_xml(self, xml_file: Path) -> Dict:
        """
        Parsea archivo XML de nmap para extraer información de servicios
        
        Returns:
            Dict {puerto: {service, product, version, extrainfo, ...}}
        """
        services = {}
        
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Buscar todos los puertos
            for port_elem in root.findall('.//port'):
                port_id = port_elem.get('portid')
                protocol = port_elem.get('protocol')
                
                state = port_elem.find('state')
                if state is None or state.get('state') != 'open':
                    continue
                
                service_elem = port_elem.find('service')
                if service_elem is not None:
                    services[int(port_id)] = {
                        'port': int(port_id),
                        'protocol': protocol,
                        'service': service_elem.get('name', ''),
                        'product': service_elem.get('product', ''),
                        'version': service_elem.get('version', ''),
                        'extrainfo': service_elem.get('extrainfo', ''),
                        'ostype': service_elem.get('ostype', ''),
                        'method': service_elem.get('method', ''),
                        'conf': service_elem.get('conf', '')
                    }
                else:
                    # Puerto abierto pero sin info de servicio
                    services[int(port_id)] = {
                        'port': int(port_id),
                        'protocol': protocol,
                        'service': 'unknown',
                        'product': '',
                        'version': '',
                        'extrainfo': '',
                        'ostype': '',
                        'method': 'unknown',
                        'conf': '0'
                    }
        
        except FileNotFoundError:
            logger.error(f"Archivo XML no encontrado: {xml_file}")
        except ET.ParseError as e:
            logger.error(f"Error parseando XML {xml_file}: {e}")
        except Exception as e:
            logger.error(f"Error inesperado parseando XML {xml_file}: {e}")
        
        return services

    def _log_services_summary(self, services: Dict):
        """Muestra resumen de servicios detectados"""
        
        # Servicios TCP más relevantes
        tcp_services = services.get('tcp', {})
        if tcp_services:
            logger.info(f"       TCP Services:")
            for port, svc in list(tcp_services.items())[:5]:  # Primeros 5
                product = svc.get('product', '')
                version = svc.get('version', '')
                info = f"{product} {version}".strip() if product else svc.get('service', 'unknown')
                logger.info(f"         {port}: {info}")
            
            if len(tcp_services) > 5:
                logger.info(f"         ... y {len(tcp_services) - 5} servicios más")
        
        # Servicios UDP si hay
        udp_services = services.get('udp', {})
        if udp_services:
            logger.info(f"       UDP Services:")
            for port, svc in list(udp_services.items())[:3]:
                product = svc.get('product', '')
                info = product if product else svc.get('service', 'unknown')
                logger.info(f"         {port}: {info}")
            
            if len(udp_services) > 3:
                logger.info(f"         ... y {len(udp_services) - 3} servicios más")
                
    # ========================================================================
    # FASE 5: AUDITORÍA COMPLETA
    # ========================================================================

    def phase5_full_audit(self, ip: str) -> Dict:
        """
        FASE 5: Auditoría completa con detección de OS, MAC, hostname
        
        Comando equivalente:
        sudo nmap -A -O -sS -sU -sV -Pn 192.168.3.X -oN fullAudit.txt
        
        Args:
            ip: Dirección IP
            
        Returns:
            Dict con información completa del host
        """
        logger.info(f"  🎯 FASE 5: Auditoría completa de {ip}")
        
        output_file = self.temp_dir / f'full_audit_{ip.replace(".", "_")}.xml'
        
        args = [
            '-A',  # Aggressive scan (OS, version, script, traceroute)
            '-O',  # OS detection
            '-sS',  # TCP SYN
            '-sU',  # UDP scan
            '--top-ports=20',  # Solo top 20 UDP para no demorar mucho
            '-sV',  # Version detection
            '-Pn',  # No ping
            f'-{self.timing}',
            '-oX', str(output_file),
            ip
        ]
        
        start_time = time.time()
        
        # Auditoría completa puede tomar tiempo
        timeout = 900  # 15 minutos máximo
        
        logger.info(f"    ⏳ Ejecutando auditoría completa (puede tomar varios minutos)...")
        
        stdout, stderr, returncode = self._run_nmap_command(args, timeout=timeout)
        duration = time.time() - start_time
        
        if returncode != 0:
            logger.warning(f"    ⚠️ Auditoría completa falló: {stderr}")
            logger.info(f"    Intentando recuperar datos parciales del XML...")
            # Continuar e intentar parsear lo que se haya generado
        
        # Parsear XML completo
        audit_data = self._parse_full_audit_xml(output_file)
        
        if audit_data and any(audit_data.values()):
            logger.info(f"    ✅ Auditoría completada ({duration:.1f}s / {duration/60:.1f}m)")
            self._log_audit_summary(audit_data)
            self.stats['phase5_hosts_complete'] += 1
        else:
            logger.info(f"    ⚠️ Auditoría parcial - datos limitados disponibles")
        
        return audit_data

    def _parse_full_audit_xml(self, xml_file: Path) -> Dict:
        """
        Parsea XML de auditoría completa
        
        Returns:
            Dict con OS, MAC, hostname, etc.
        """
        data = {
            'hostname': '',
            'mac': '',
            'vendor': '',
            'os': '',
            'os_accuracy': 0,
            'os_details': [],
            'uptime': '',
            'tcp_sequence': {},
            'ip_id_sequence': {}
        }
        
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            host = root.find('host')
            if host is None:
                logger.debug("No se encontró elemento 'host' en el XML")
                return data
            
            # Hostname
            hostnames = host.find('hostnames')
            if hostnames is not None:
                hostname_elem = hostnames.find('hostname')
                if hostname_elem is not None:
                    data['hostname'] = hostname_elem.get('name', '')
            
            # MAC Address y Vendor
            address_elem = host.find(".//address[@addrtype='mac']")
            if address_elem is not None:
                data['mac'] = address_elem.get('addr', '')
                data['vendor'] = address_elem.get('vendor', '')
            
            # OS Detection
            os_elem = host.find('os')
            if os_elem is not None:
                osmatch = os_elem.find('osmatch')
                if osmatch is not None:
                    data['os'] = osmatch.get('name', '')
                    data['os_accuracy'] = int(osmatch.get('accuracy', 0))
                
                # Múltiples matches (top 3)
                for match in os_elem.findall('osmatch')[:3]:
                    data['os_details'].append({
                        'name': match.get('name', ''),
                        'accuracy': int(match.get('accuracy', 0))
                    })
            
            # Uptime
            uptime_elem = host.find('uptime')
            if uptime_elem is not None:
                seconds = int(uptime_elem.get('seconds', '0'))
                data['uptime'] = self._format_uptime(seconds)
            
            # TCP Sequence (para fingerprinting avanzado)
            tcpsequence_elem = host.find('tcpsequence')
            if tcpsequence_elem is not None:
                data['tcp_sequence'] = {
                    'index': tcpsequence_elem.get('index', ''),
                    'difficulty': tcpsequence_elem.get('difficulty', ''),
                    'values': tcpsequence_elem.get('values', '')
                }
            
            # IP ID Sequence
            ipidsequence_elem = host.find('ipidsequence')
            if ipidsequence_elem is not None:
                data['ip_id_sequence'] = {
                    'class': ipidsequence_elem.get('class', ''),
                    'values': ipidsequence_elem.get('values', '')
                }
        
        except FileNotFoundError:
            logger.error(f"Archivo XML no encontrado: {xml_file}")
        except ET.ParseError as e:
            logger.error(f"Error parseando audit XML {xml_file}: {e}")
        except Exception as e:
            logger.error(f"Error inesperado en parse_full_audit_xml: {e}")
        
        return data

    def _format_uptime(self, seconds: int) -> str:
        """Formatea uptime en formato legible"""
        if seconds == 0:
            return 'Unknown'
        
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        minutes = (seconds % 3600) // 60
        
        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        
        return ' '.join(parts) if parts else '< 1m'

    def _log_audit_summary(self, data: Dict):
        """Muestra resumen de auditoría completa"""
        if data.get('hostname'):
            logger.info(f"       Hostname: {data['hostname']}")
        
        if data.get('mac'):
            logger.info(f"       MAC: {data['mac']}")
            if data.get('vendor'):
                logger.info(f"       Vendor: {data['vendor']}")
        
        if data.get('os'):
            logger.info(f"       OS: {data['os']} ({data['os_accuracy']}% confianza)")
            
            # Mostrar alternativas si la confianza es baja
            if data['os_accuracy'] < 90 and data.get('os_details'):
                logger.info(f"       Alternativas:")
                for alt in data['os_details'][:2]:
                    if alt['name'] != data['os']:
                        logger.info(f"         - {alt['name']} ({alt['accuracy']}%)")
        
        if data.get('uptime'):
            logger.info(f"       Uptime: {data['uptime']}")
            
    # ========================================================================
    # UTILIDADES
    # ========================================================================
    
    def _format_port_list(self, ports: List[int], max_show: int = 20) -> str:
        """Formatea lista de puertos para logging"""
        if not ports:
            return "ninguno"
        
        if len(ports) <= max_show:
            return ', '.join(map(str, ports))
        else:
            shown = ', '.join(map(str, ports[:max_show]))
            return f"{shown}... (+{len(ports) - max_show} más)"
    
    def get_stats(self) -> Dict:
        """Retorna estadísticas del escaneo"""
        return self.stats.copy()
    
    def cleanup_temp_files(self):
        """Limpia archivos temporales antiguos"""
        try:
            import time
            current_time = time.time()
            
            for file in self.temp_dir.iterdir():
                if file.is_file():
                    # Eliminar archivos más antiguos de 24 horas
                    if current_time - file.stat().st_mtime > 86400:
                        file.unlink()
                        logger.debug(f"Archivo temporal eliminado: {file.name}")
        
        except Exception as e:
            logger.warning(f"Error limpiando archivos temporales: {e}")