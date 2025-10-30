#!/usr/bin/env python3
"""
NetAudit HomeStack - Network Scanner
Script principal de escaneo de red

Funcionalidad:
1. Carga configuración desde variables de entorno
2. Escanea redes configuradas con Nmap
3. Descubre información adicional por SNMP
4. Clasifica dispositivos inteligentemente
5. Sincroniza resultados con Netbox
6. Integra con Proxmox (opcional)
"""

import os
import sys
from datetime import datetime
from dotenv import load_dotenv

# Importar módulos propios
from utils import (
    setup_logger,
    NetworkScanner,
    SNMPDiscovery,
    DeviceClassifier,
    NetboxSync,
    ProxmoxIntegration
)

# Cargar variables de entorno
load_dotenv()

# Configurar logging
logger = setup_logger('netaudit')


class NetAuditScanner:
    """Orquestador principal del escaneo de red"""
    
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
        self.max_ports = int(os.getenv('MAX_PORTS', '1000'))
        self.enable_os_detection = os.getenv('ENABLE_OS_DETECTION', 'true').lower() == 'true'
        self.enable_service_version = os.getenv('ENABLE_SERVICE_VERSION', 'true').lower() == 'true'
        
        # Configuración de SNMP
        self.snmp_enabled = os.getenv('ENABLE_SNMP', 'true').lower() == 'true'
        self.snmp_community = os.getenv('SNMP_COMMUNITY', 'public')
        
        # Configuración de Proxmox (opcional)
        self.proxmox_enabled = os.getenv('ENABLE_PROXMOX', 'false').lower() == 'true'
        self.proxmox_host = os.getenv('PROXMOX_HOST', '')
        self.proxmox_user = os.getenv('PROXMOX_USER', '')
        self.proxmox_password = os.getenv('PROXMOX_PASSWORD', '')
        
        # Inicializar componentes
        self.nmap_scanner = None
        self.snmp_discovery = None
        self.classifier = None
        self.netbox_sync = None
        self.proxmox = None
        
        # Estadísticas
        self.stats = {
            'networks_scanned': 0,
            'devices_found': 0,
            'devices_with_snmp': 0,
            'proxmox_vms': 0,
            'scan_duration': 0
        }
    
    def validate_config(self) -> bool:
        """Valida la configuración antes de iniciar"""
        
        logger.info("=" * 60)
        logger.info("NetAudit HomeStack - Network Scanner")
        logger.info("=" * 60)
        logger.info("")
        
        # Validar Netbox
        if not self.netbox_token:
            logger.error("❌ NETBOX_TOKEN no está configurado")
            return False
        
        logger.info(f"✓ Netbox URL: {self.netbox_url}")
        logger.info(f"✓ Redes a escanear: {', '.join(self.networks)}")
        logger.info(f"✓ Timing: {self.nmap_timing}")
        logger.info(f"✓ Max ports: {self.max_ports}")
        logger.info(f"✓ OS Detection: {'Sí' if self.enable_os_detection else 'No'}")
        logger.info(f"✓ Service Version: {'Sí' if self.enable_service_version else 'No'}")
        logger.info(f"✓ SNMP: {'Sí' if self.snmp_enabled else 'No'}")
        logger.info(f"✓ Proxmox: {'Sí' if self.proxmox_enabled else 'No'}")
        logger.info("")
        
        return True
    
    def initialize_components(self):
        """Inicializa todos los componentes necesarios"""
        
        logger.info("📦 Inicializando componentes...")
        
        # Nmap Scanner
        self.nmap_scanner = NetworkScanner(
            timing=self.nmap_timing,
            enable_os_detection=self.enable_os_detection,
            enable_service_version=self.enable_service_version,
            max_ports=self.max_ports
        )
        logger.info("  ✓ Nmap Scanner inicializado")
        
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
    
    def scan_networks(self) -> list:
        """Escanea todas las redes configuradas"""
        
        all_devices = []
        
        for network in self.networks:
            logger.info("=" * 60)
            logger.info(f"🌐 Escaneando red: {network}")
            logger.info("=" * 60)
            logger.info("")
            
            try:
                # Escaneo con Nmap
                devices = self.nmap_scanner.scan_network(network)
                
                logger.info(f"✓ Escaneo completado: {len(devices)} dispositivos encontrados")
                logger.info("")
                
                all_devices.extend(devices)
                self.stats['networks_scanned'] += 1
                self.stats['devices_found'] += len(devices)
                
            except Exception as e:
                logger.error(f"❌ Error escaneando {network}: {e}")
                continue
        
        return all_devices
    
    def enrich_devices(self, devices: list) -> list:
        """Enriquece información de dispositivos con SNMP y clasificación"""
        
        logger.info("=" * 60)
        logger.info("🔍 Enriqueciendo información de dispositivos")
        logger.info("=" * 60)
        logger.info("")
        
        enriched_devices = []
        
        for idx, device in enumerate(devices, 1):
            logger.info(f"[{idx}/{len(devices)}] Procesando {device['ip']}...")
            logger.info(f"  Hostname: {device.get('hostname', 'N/A')}")
            logger.info(f"  MAC: {device.get('mac', 'N/A')}")
            logger.info(f"  Vendor: {device.get('vendor', 'N/A')}")
            
            try:
                # Agregar timestamp
                device['scan_time'] = datetime.now().isoformat()
                
                # Descubrimiento SNMP
                if self.snmp_enabled and self.snmp_discovery:
                    logger.info(f"  Probando SNMP...")
                    snmp_info = self.snmp_discovery.query_device(device['ip'])
                    if snmp_info:
                        device.update(snmp_info)
                        self.stats['devices_with_snmp'] += 1
                        logger.info(f"  ✓ SNMP activo - {snmp_info.get('snmp_sysName', 'Sin nombre')}")
                    else:
                        logger.info(f"  ○ SNMP no disponible")
                
                # Clasificación inteligente
                logger.info(f"  Clasificando dispositivo...")
                classification = self.classifier.classify(device)
                device.update(classification)
                
                logger.info(f"  ✓ Clasificado como: {classification['device_type']} "
                          f"({classification['confidence']}% confianza)")
                logger.info(f"  ✓ Rol: {classification['device_role']}")
                logger.info(f"  ✓ Categoría: {classification['category']}")
                
                enriched_devices.append(device)
                
            except Exception as e:
                logger.warning(f"  ⚠ Error procesando {device['ip']}: {e}")
                enriched_devices.append(device)  # Agregar de todas formas
            
            logger.info("")
        
        return enriched_devices
    
    def integrate_proxmox(self, devices: list) -> list:
        """Integra información de Proxmox si está disponible"""
        
        if not self.proxmox or not self.proxmox.connected:
            return devices
        
        logger.info("=" * 60)
        logger.info("🖥️  Integrando información de Proxmox")
        logger.info("=" * 60)
        logger.info("")
        
        try:
            # Obtener VMs y LXCs de Proxmox
            proxmox_devices = self.proxmox.get_all_devices()
            self.stats['proxmox_vms'] = len(proxmox_devices)
            
            logger.info(f"✓ Encontradas {len(proxmox_devices)} VMs/LXCs en Proxmox")
            
            # Crear índice por IP
            proxmox_by_ip = {d['ip']: d for d in proxmox_devices if 'ip' in d}
            
            # Enriquecer dispositivos escaneados con info de Proxmox
            for device in devices:
                if device['ip'] in proxmox_by_ip:
                    px_info = proxmox_by_ip[device['ip']]
                    device['proxmox_vm'] = True
                    device['proxmox_type'] = px_info['type']
                    device['proxmox_name'] = px_info['name']
                    device['proxmox_node'] = px_info['node']
                    device['proxmox_status'] = px_info['status']
                    
                    logger.info(f"  ✓ {device['ip']} es {px_info['type']}: {px_info['name']}")
            
            logger.info("")
            
        except Exception as e:
            logger.error(f"❌ Error integrando Proxmox: {e}")
        
        return devices
    
    def sync_to_netbox(self, devices: list):
        """Sincroniza dispositivos con Netbox"""
        
        logger.info("=" * 60)
        logger.info("📊 Sincronizando con Netbox")
        logger.info("=" * 60)
        logger.info("")
        
        try:
            sync_stats = self.netbox_sync.sync_devices(devices)
            
            logger.info("")
            logger.info("Resultados de sincronización:")
            logger.info(f"  ✓ Creados: {sync_stats['created']}")
            logger.info(f"  ✓ Actualizados: {sync_stats['updated']}")
            logger.info(f"  ✓ Sin cambios: {sync_stats['unchanged']}")
            if sync_stats['errors'] > 0:
                logger.warning(f"  ⚠ Errores: {sync_stats['errors']}")
            
        except Exception as e:
            logger.error(f"❌ Error sincronizando con Netbox: {e}")
            raise
    
    def print_summary(self):
        """Imprime resumen final del escaneo"""
        
        logger.info("")
        logger.info("=" * 60)
        logger.info("📈 RESUMEN DEL ESCANEO")
        logger.info("=" * 60)
        logger.info("")
        logger.info(f"Redes escaneadas:      {self.stats['networks_scanned']}")
        logger.info(f"Dispositivos encontrados: {self.stats['devices_found']}")
        logger.info(f"Con SNMP activo:       {self.stats['devices_with_snmp']}")
        if self.proxmox:
            logger.info(f"VMs/LXCs Proxmox:      {self.stats['proxmox_vms']}")
        logger.info(f"Duración:              {self.stats['scan_duration']:.1f} segundos")
        logger.info("")
        logger.info("✅ Escaneo completado exitosamente")
        logger.info("")
        logger.info(f"🌐 Ver resultados en: {self.netbox_url}")
        logger.info("=" * 60)
    
    def run(self):
        """Ejecuta el escaneo completo"""
        
        start_time = datetime.now()
        
        try:
            # 1. Validar configuración
            if not self.validate_config():
                sys.exit(1)
            
            # 2. Inicializar componentes
            self.initialize_components()
            
            # 3. Escanear redes
            devices = self.scan_networks()
            
            if not devices:
                logger.warning("⚠ No se encontraron dispositivos")
                return
            
            # 4. Enriquecer con SNMP y clasificación
            devices = self.enrich_devices(devices)
            
            # 5. Integrar con Proxmox (opcional)
            devices = self.integrate_proxmox(devices)
            
            # 6. Sincronizar con Netbox
            self.sync_to_netbox(devices)
            
            # 7. Calcular duración y mostrar resumen
            end_time = datetime.now()
            self.stats['scan_duration'] = (end_time - start_time).total_seconds()
            self.print_summary()
            
        except KeyboardInterrupt:
            logger.warning("\n⚠ Escaneo interrumpido por el usuario")
            sys.exit(1)
        except Exception as e:
            logger.error(f"\n❌ Error fatal durante el escaneo: {e}")
            import traceback
            logger.error(traceback.format_exc())
            sys.exit(1)


def main():
    """Punto de entrada principal"""
    scanner = NetAuditScanner()
    scanner.run()


if __name__ == '__main__':
    main()