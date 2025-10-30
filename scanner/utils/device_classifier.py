"""
Módulo de clasificación inteligente de dispositivos
"""

import os
import logging
from typing import Dict
import re

logger = logging.getLogger(__name__)

class DeviceClassifier:
    """Clasifica dispositivos según múltiples criterios"""
    
    # Vendors conocidos por MAC OUI
    VENDOR_TYPES = {
        'apple': 'Computer',
        'dell': 'Computer',
        'hp': 'Computer',
        'lenovo': 'Computer',
        'asus': 'Computer',
        'microsoft': 'Computer',
        'intel': 'Computer',
        'samsung': 'Smart TV',
        'lg electronics': 'Smart TV',
        'sony': 'Smart TV',
        'xiaomi': 'IoT Device',
        'tuya': 'IoT Device',
        'espressif': 'IoT Device',
        'raspberry': 'IoT Device',
        'shenzhen': 'IoT Device',
        'tp-link': 'Network Device',
        'ubiquiti': 'Network Device',
        'cisco': 'Network Device',
        'huawei': 'Network Device',
        'mikrotik': 'Router',
        'netgear': 'Network Device',
        'synology': 'NAS',
        'qnap': 'NAS',
        'google': 'Smart Device',
        'amazon': 'Smart Device',
        'sonos': 'Media Device',
        'roku': 'Media Device',
    }
    
    # Puertos que identifican tipos de dispositivos
    PORT_SIGNATURES = {
        'Server': [22, 80, 443, 8080, 3000],
        'NAS': [139, 445, 2049, 5000, 5001],
        'Printer': [631, 9100, 515],
        'Camera': [554, 8000, 8080],
        'Router': [80, 443, 22, 23],
        'Smart TV': [8001, 8002, 9080],
        'Game Console': [3074, 3075, 9293],
    }
    
    def __init__(self):
        """Inicializa el clasificador con rangos de IP configurados"""
        self.ip_ranges = self._load_ip_ranges()
    
    def _load_ip_ranges(self) -> Dict:
        """Carga los rangos de IP desde variables de entorno"""
        ranges = {}
        
        env_ranges = {
            'Infrastructure': os.getenv('RANGE_INFRASTRUCTURE', '192.168.3.1-192.168.3.9'),
            'Domotica': os.getenv('RANGE_DOMOTICA', '192.168.3.10-192.168.3.50'),
            'Trabajo': os.getenv('RANGE_TRABAJO', '192.168.3.51-192.168.3.150'),
            'Entretenimiento': os.getenv('RANGE_ENTRETENIMIENTO', '192.168.3.151-192.168.3.254'),
            'ISP': os.getenv('RANGE_ISP', '192.168.100.0-192.168.100.254'),
        }
        
        for category, range_str in env_ranges.items():
            try:
                start, end = range_str.split('-')
                ranges[category] = (self._ip_to_int(start.strip()), 
                                   self._ip_to_int(end.strip()))
            except Exception as e:
                logger.warning(f"Error parseando rango {category}: {e}")
        
        return ranges
    
    def _ip_to_int(self, ip: str) -> int:
        """Convierte IP string a entero para comparación"""
        parts = ip.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + \
               (int(parts[2]) << 8) + int(parts[3])
    
    def _get_category_by_ip(self, ip: str) -> str:
        """Determina la categoría basándose en el rango de IP"""
        ip_int = self._ip_to_int(ip)
        
        for category, (start, end) in self.ip_ranges.items():
            if start <= ip_int <= end:
                return category
        
        return 'Unknown'
    
    def classify(self, device: Dict) -> Dict:
        """
        Clasifica un dispositivo según múltiples criterios
        
        Args:
            device: Diccionario con información del dispositivo
            
        Returns:
            Diccionario con clasificación agregada
        """
        classification = {
            'device_type': 'Unknown',
            'device_role': 'Unknown',
            'category': 'Unknown',
            'confidence': 0
        }
        
        # Clasificación por rango de IP
        classification['category'] = self._get_category_by_ip(device['ip'])
        
        # Clasificación por tipo
        device_type, confidence = self._classify_type(device)
        classification['device_type'] = device_type
        classification['confidence'] = confidence
        
        # Determinar rol
        classification['device_role'] = self._determine_role(device, device_type)
        
        return classification
    
    def _classify_type(self, device: Dict) -> tuple:
        """
        Clasifica el tipo de dispositivo
        
        Returns:
            (tipo, nivel_de_confianza)
        """
        scores = {}
        
        # 1. Clasificación por información SNMP (máxima confianza)
        if device.get('snmp_enabled') and device.get('snmp_sysDescr'):
            snmp_type = self._classify_by_snmp(device)
            if snmp_type != 'Unknown':
                return (snmp_type, 95)
        
        # 2. Clasificación por sistema operativo
        if device.get('os'):
            os_type = self._classify_by_os(device['os'])
            scores[os_type] = scores.get(os_type, 0) + 30
        
        # 3. Clasificación por vendor (MAC)
        if device.get('vendor'):
            vendor_type = self._classify_by_vendor(device['vendor'])
            scores[vendor_type] = scores.get(vendor_type, 0) + 25
        
        # 4. Clasificación por puertos abiertos
        if device.get('ports'):
            port_types = self._classify_by_ports(device['ports'])
            for ptype in port_types:
                scores[ptype] = scores.get(ptype, 0) + 20
        
        # 5. Clasificación por servicios
        if device.get('services'):
            service_types = self._classify_by_services(device['services'])
            for stype in service_types:
                scores[stype] = scores.get(stype, 0) + 15
        
        # 6. Clasificación por hostname
        if device.get('hostname'):
            hostname_type = self._classify_by_hostname(device['hostname'])
            scores[hostname_type] = scores.get(hostname_type, 0) + 10
        
        # Seleccionar el tipo con mayor puntuación
        if scores:
            best_type = max(scores, key=scores.get)
            confidence = min(scores[best_type], 100)
            return (best_type, confidence)
        
        return ('Unknown', 0)
    
    def _classify_by_snmp(self, device: Dict) -> str:
        """Clasifica por información SNMP"""
        descr = device.get('snmp_sysDescr', '').lower()
        
        if 'router' in descr:
            return 'Router'
        elif 'switch' in descr:
            return 'Switch'
        elif 'access point' in descr or 'ap' in descr:
            return 'Access Point'
        elif 'printer' in descr:
            return 'Printer'
        elif 'nas' in descr or 'storage' in descr:
            return 'NAS'
        elif 'camera' in descr or 'ipcam' in descr:
            return 'IP Camera'
        
        return 'Unknown'
    
    def _classify_by_os(self, os_str: str) -> str:
        """Clasifica por sistema operativo detectado"""
        os_lower = os_str.lower()
        
        if 'linux' in os_lower:
            if 'embedded' in os_lower or 'openwrt' in os_lower:
                return 'Router'
            return 'Server'
        elif 'windows server' in os_lower:
            return 'Server'
        elif 'windows' in os_lower:
            return 'Computer'
        elif 'android' in os_lower:
            if 'tv' in os_lower:
                return 'Smart TV'
            return 'Mobile Device'
        elif 'ios' in os_lower or 'iphone' in os_lower:
            return 'Mobile Device'
        elif 'macos' in os_lower:
            return 'Computer'
        
        return 'Unknown'
    
    def _classify_by_vendor(self, vendor: str) -> str:
        """Clasifica por vendor del MAC address"""
        vendor_lower = vendor.lower()
        
        for key, device_type in self.VENDOR_TYPES.items():
            if key in vendor_lower:
                return device_type
        
        return 'Unknown'
    
    def _classify_by_ports(self, ports: list) -> list:
        """Clasifica por puertos abiertos"""
        types = []
        
        for device_type, signature_ports in self.PORT_SIGNATURES.items():
            matches = sum(1 for port in signature_ports if port in ports)
            if matches >= 2:  # Al menos 2 puertos coinciden
                types.append(device_type)
        
        return types
    
    def _classify_by_services(self, services: Dict) -> list:
        """Clasifica por servicios detectados"""
        types = []
        
        service_names = [s.get('name', '').lower() for s in services.values()]
        
        if 'http' in service_names or 'https' in service_names:
            types.append('Server')
        if 'ssh' in service_names:
            types.append('Server')
        if 'smb' in service_names or 'microsoft-ds' in service_names:
            types.append('NAS')
        if 'rtsp' in service_names:
            types.append('IP Camera')
        if 'printer' in ' '.join(service_names):
            types.append('Printer')
        
        return types
    
    def _classify_by_hostname(self, hostname: str) -> str:
        """Clasifica por hostname"""
        hostname_lower = hostname.lower()
        
        keywords = {
            'Router': ['router', 'gw', 'gateway'],
            'Switch': ['switch', 'sw'],
            'Access Point': ['ap', 'access'],
            'Server': ['server', 'srv', 'host'],
            'NAS': ['nas', 'storage'],
            'Printer': ['printer', 'print'],
            'IP Camera': ['cam', 'camera', 'ipcam'],
            'IoT Device': ['esp', 'sensor', 'lamp', 'light', 'bulb'],
        }
        
        for device_type, keys in keywords.items():
            if any(key in hostname_lower for key in keys):
                return device_type
        
        return 'Unknown'
    
    def _determine_role(self, device: Dict, device_type: str) -> str:
        """Determina el rol del dispositivo en la red"""
        
        # Roles específicos por tipo
        if device_type in ['Router', 'Switch', 'Access Point']:
            return 'Infrastructure'
        elif device_type in ['Server', 'NAS']:
            return 'Service'
        elif device_type in ['Computer', 'Laptop']:
            return 'Workstation'
        elif device_type in ['Smart TV', 'Media Device', 'Game Console']:
            return 'Entertainment'
        elif device_type in ['IoT Device', 'Smart Device', 'IP Camera']:
            return 'IoT'
        elif device_type == 'Mobile Device':
            return 'Mobile'
        elif device_type == 'Printer':
            return 'Peripheral'
        
        return 'Unknown'
