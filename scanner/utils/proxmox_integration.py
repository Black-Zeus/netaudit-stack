"""
Módulo de integración con Proxmox
"""

import logging
from proxmoxer import ProxmoxAPI
from typing import List, Dict
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

class ProxmoxIntegration:
    """Integración con Proxmox VE para obtener información de VMs y LXCs"""
    
    def __init__(self, host: str, user: str, password: str, verify_ssl: bool = False):
        """
        Inicializa la conexión con Proxmox
        
        Args:
            host: IP o hostname de Proxmox
            user: Usuario (formato: user@pam o user@pve)
            password: Contraseña
            verify_ssl: Verificar certificado SSL
        """
        try:
            self.proxmox = ProxmoxAPI(
                host,
                user=user,
                password=password,
                verify_ssl=verify_ssl,
                port=8006,      # Puerto explícito
                timeout=10      # Timeout de 10 segundos
            )
            # Verificar que la conexión funciona
            self.proxmox.version.get()
            self.connected = True
            logger.info(f"Conectado a Proxmox en {host}:8006")
        except Exception as e:
            logger.error(f"No se pudo conectar a Proxmox: {e}")
            self.connected = False
            self.proxmox = None
    
    def get_all_devices(self) -> List[Dict]:
        """
        Obtiene todos los dispositivos (VMs y LXCs) de Proxmox
        
        Returns:
            Lista de dispositivos con su información
        """
        if not self.connected:
            return []
        
        devices = []
        
        try:
            # Obtener todos los nodos
            nodes = self.proxmox.nodes.get()
            
            for node in nodes:
                node_name = node['node']
                logger.info(f"Escaneando node: {node_name}")
                
                # Obtener VMs (QEMU)
                try:
                    vms = self.proxmox.nodes(node_name).qemu.get()
                    for vm in vms:
                        device = self._parse_vm(vm, node_name)
                        if device:
                            devices.append(device)
                except Exception as e:
                    logger.warning(f"Error obteniendo VMs de {node_name}: {e}")
                
                # Obtener LXCs (containers)
                try:
                    lxcs = self.proxmox.nodes(node_name).lxc.get()
                    for lxc in lxcs:
                        device = self._parse_lxc(lxc, node_name)
                        if device:
                            devices.append(device)
                except Exception as e:
                    logger.warning(f"Error obteniendo LXCs de {node_name}: {e}")
        
        except Exception as e:
            logger.error(f"Error obteniendo dispositivos de Proxmox: {e}")
        
        return devices
    
    def _parse_vm(self, vm: Dict, node: str) -> Dict:
        """
        Parsea información de una VM
        
        Args:
            vm: Diccionario con datos de la VM
            node: Nombre del nodo
            
        Returns:
            Dispositivo normalizado
        """
        try:
            # Obtener configuración detallada de la VM
            vmid = vm['vmid']
            config = self.proxmox.nodes(node).qemu(vmid).config.get()
            
            device = {
                'type': 'vm',
                'name': vm.get('name', f'vm-{vmid}'),
                'vmid': vmid,
                'node': node,
                'status': vm.get('status', 'unknown'),
                'cpu': vm.get('cpus', 0),
                'memory': vm.get('maxmem', 0) // (1024 * 1024),  # Convertir a MB
                'disk': vm.get('maxdisk', 0) // (1024 * 1024 * 1024),  # Convertir a GB
                'uptime': vm.get('uptime', 0),
            }
            
            # Intentar obtener IP address
            ip = self._get_vm_ip(node, vmid)
            if ip:
                device['ip'] = ip
            
            return device
        
        except Exception as e:
            logger.warning(f"Error parseando VM {vm.get('vmid')}: {e}")
            return None
    
    def _parse_lxc(self, lxc: Dict, node: str) -> Dict:
        """
        Parsea información de un LXC
        
        Args:
            lxc: Diccionario con datos del LXC
            node: Nombre del nodo
            
        Returns:
            Dispositivo normalizado
        """
        try:
            vmid = lxc['vmid']
            
            device = {
                'type': 'lxc',
                'name': lxc.get('name', f'lxc-{vmid}'),
                'vmid': vmid,
                'node': node,
                'status': lxc.get('status', 'unknown'),
                'cpu': lxc.get('cpus', 0),
                'memory': lxc.get('maxmem', 0) // (1024 * 1024),  # Convertir a MB
                'disk': lxc.get('maxdisk', 0) // (1024 * 1024 * 1024),  # Convertir a GB
                'uptime': lxc.get('uptime', 0),
            }
            
            # Intentar obtener IP address
            ip = self._get_lxc_ip(node, vmid)
            if ip:
                device['ip'] = ip
            
            return device
        
        except Exception as e:
            logger.warning(f"Error parseando LXC {lxc.get('vmid')}: {e}")
            return None
    
    def _get_vm_ip(self, node: str, vmid: int) -> str:
        """
        Obtiene la IP de una VM mediante qemu-agent
        
        Args:
            node: Nodo de Proxmox
            vmid: ID de la VM
            
        Returns:
            IP address o None
        """
        try:
            # Intentar obtener interfaces de red via qemu-agent
            interfaces = self.proxmox.nodes(node).qemu(vmid).agent('network-get-interfaces').get()
            
            if interfaces and 'result' in interfaces:
                for iface in interfaces['result']:
                    if iface.get('name') in ['eth0', 'ens18', 'ens3']:
                        if 'ip-addresses' in iface:
                            for ip_info in iface['ip-addresses']:
                                if ip_info.get('ip-address-type') == 'ipv4':
                                    ip = ip_info.get('ip-address')
                                    if ip and not ip.startswith('127.'):
                                        return ip
        except Exception as e:
            logger.debug(f"No se pudo obtener IP de VM {vmid}: {e}")
        
        return None
    
    def _get_lxc_ip(self, node: str, vmid: int) -> str:
        """
        Obtiene la IP de un LXC
        
        Args:
            node: Nodo de Proxmox
            vmid: ID del LXC
            
        Returns:
            IP address o None
        """
        try:
            # Obtener configuración del LXC
            config = self.proxmox.nodes(node).lxc(vmid).config.get()
            
            # Buscar net0, net1, etc.
            for key in config.keys():
                if key.startswith('net'):
                    net_config = config[key]
                    # Parsear configuración de red
                    # Formato: name=eth0,bridge=vmbr0,ip=192.168.1.100/24,gw=192.168.1.1
                    if 'ip=' in net_config:
                        parts = net_config.split(',')
                        for part in parts:
                            if part.startswith('ip='):
                                ip_cidr = part.split('=')[1]
                                ip = ip_cidr.split('/')[0]
                                if ip and ip != 'dhcp' and not ip.startswith('127.'):
                                    return ip
        except Exception as e:
            logger.debug(f"No se pudo obtener IP de LXC {vmid}: {e}")
        
        return None
    
    def get_node_info(self, node_name: str) -> Dict:
        """
        Obtiene información de un nodo de Proxmox
        
        Args:
            node_name: Nombre del nodo
            
        Returns:
            Información del nodo
        """
        if not self.connected:
            return {}
        
        try:
            status = self.proxmox.nodes(node_name).status.get()
            return {
                'name': node_name,
                'cpu': status.get('cpu', 0) * 100,  # Convertir a porcentaje
                'memory_used': status.get('memory', 0) // (1024 * 1024),  # MB
                'memory_total': status.get('maxmem', 0) // (1024 * 1024),  # MB
                'disk_used': status.get('rootfs', {}).get('used', 0) // (1024 * 1024 * 1024),  # GB
                'disk_total': status.get('rootfs', {}).get('total', 0) // (1024 * 1024 * 1024),  # GB
                'uptime': status.get('uptime', 0),
            }
        except Exception as e:
            logger.error(f"Error obteniendo info del nodo {node_name}: {e}")
            return {}
