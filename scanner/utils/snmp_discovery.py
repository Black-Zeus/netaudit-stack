"""
Módulo de descubrimiento SNMP
"""

import logging
from pysnmp.hlapi import *

logger = logging.getLogger(__name__)

class SNMPDiscovery:
    """Descubrimiento de dispositivos mediante SNMP"""
    
    # OIDs comunes para información del sistema
    OIDS = {
        'sysDescr': '1.3.6.1.2.1.1.1.0',      # Descripción del sistema
        'sysObjectID': '1.3.6.1.2.1.1.2.0',   # Object ID del sistema
        'sysUpTime': '1.3.6.1.2.1.1.3.0',     # Uptime
        'sysContact': '1.3.6.1.2.1.1.4.0',    # Contacto
        'sysName': '1.3.6.1.2.1.1.5.0',       # Nombre del sistema
        'sysLocation': '1.3.6.1.2.1.1.6.0',   # Ubicación
    }
    
    def __init__(self, community='public', timeout=2, retries=1):
        """
        Inicializa el descubridor SNMP
        
        Args:
            community: Community string SNMP
            timeout: Timeout en segundos
            retries: Número de reintentos
        """
        self.community = CommunityData(community)
        self.timeout = timeout
        self.retries = retries
    
    def query_device(self, ip: str) -> dict:
        """
        Consulta información SNMP de un dispositivo
        
        Args:
            ip: Dirección IP del dispositivo
            
        Returns:
            Diccionario con información SNMP o None si no responde
        """
        snmp_info = {}
        
        try:
            # Intentar obtener sysDescr para verificar si SNMP está activo
            errorIndication, errorStatus, errorIndex, varBinds = next(
                getCmd(SnmpEngine(),
                      self.community,
                      UdpTransportTarget((ip, 161), timeout=self.timeout, retries=self.retries),
                      ContextData(),
                      ObjectType(ObjectIdentity(self.OIDS['sysDescr'])))
            )
            
            if errorIndication or errorStatus:
                return None
            
            # Si responde, obtener toda la información
            for name, oid in self.OIDS.items():
                try:
                    errorIndication, errorStatus, errorIndex, varBinds = next(
                        getCmd(SnmpEngine(),
                              self.community,
                              UdpTransportTarget((ip, 161), timeout=self.timeout, retries=self.retries),
                              ContextData(),
                              ObjectType(ObjectIdentity(oid)))
                    )
                    
                    if not errorIndication and not errorStatus:
                        value = varBinds[0][1].prettyPrint()
                        if value and value != '':
                            snmp_info[f'snmp_{name}'] = value
                
                except Exception as e:
                    logger.debug(f"No se pudo obtener {name} de {ip}: {e}")
                    continue
            
            if snmp_info:
                snmp_info['snmp_enabled'] = True
                return snmp_info
            
        except Exception as e:
            logger.debug(f"SNMP no disponible en {ip}: {e}")
        
        return None
    
    def walk_interfaces(self, ip: str) -> list:
        """
        Obtiene lista de interfaces de red del dispositivo
        
        Args:
            ip: Dirección IP
            
        Returns:
            Lista de interfaces
        """
        interfaces = []
        
        try:
            # OID base para interfaces
            if_descr_oid = '1.3.6.1.2.1.2.2.1.2'  # ifDescr
            
            for (errorIndication,
                 errorStatus,
                 errorIndex,
                 varBinds) in nextCmd(SnmpEngine(),
                                     self.community,
                                     UdpTransportTarget((ip, 161), timeout=self.timeout),
                                     ContextData(),
                                     ObjectType(ObjectIdentity(if_descr_oid)),
                                     lexicographicMode=False):
                
                if errorIndication or errorStatus:
                    break
                
                for varBind in varBinds:
                    interfaces.append(varBind[1].prettyPrint())
        
        except Exception as e:
            logger.debug(f"No se pudieron obtener interfaces de {ip}: {e}")
        
        return interfaces
    
    def get_device_type(self, snmp_info: dict) -> str:
        """
        Determina el tipo de dispositivo basándose en información SNMP
        
        Args:
            snmp_info: Diccionario con datos SNMP
            
        Returns:
            Tipo de dispositivo estimado
        """
        if not snmp_info:
            return 'Unknown'
        
        sys_descr = snmp_info.get('snmp_sysDescr', '').lower()
        
        # Detectar por descripción
        if 'router' in sys_descr or 'mikrotik' in sys_descr:
            return 'Router'
        elif 'switch' in sys_descr:
            return 'Switch'
        elif 'access point' in sys_descr or 'ap' in sys_descr:
            return 'Access Point'
        elif 'printer' in sys_descr:
            return 'Printer'
        elif 'nas' in sys_descr or 'storage' in sys_descr:
            return 'NAS'
        elif 'linux' in sys_descr:
            return 'Server'
        elif 'windows' in sys_descr:
            return 'Computer'
        
        return 'Network Device'
