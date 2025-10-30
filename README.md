# NetAudit HomeStack 🏠🔍

Stack completo de auditoría y gestión de red doméstica con Netbox, descubrimiento automatizado y backup de configuraciones.

## 📋 Componentes

- **Netbox** - Sistema de inventario y gestión de red (IPAM/DCIM)
- **Scanner** - Script Python personalizado para descubrimiento automático
- **Ofelia** - Gestor de tareas programadas con interfaz web
- **Oxidized** - Backup automático de configuraciones de routers
- **PostgreSQL** - Base de datos para Netbox
- **Redis** - Cache para Netbox

## ✨ Características

### Descubrimiento Automático
- ✅ Escaneo completo con nmap (OS detection, service versioning)
- ✅ Descubrimiento SNMP automático
- ✅ Clasificación inteligente de dispositivos
- ✅ Soporte multi-subnet
- ✅ Integración opcional con Proxmox VE
- ✅ Ejecución programada o manual

### Gestión en Netbox
- ✅ Inventario completo de dispositivos
- ✅ Gestión de IPs (IPAM)
- ✅ Diagramas de topología
- ✅ Clasificación por categorías (Domótica/Trabajo/Entretenimiento)
- ✅ Historial de cambios
- ✅ API REST completa

### Backup de Routers
- ✅ Backup automático de configuraciones
- ✅ Versionado con Git
- ✅ Interfaz web para ver cambios
- ✅ Soporte para múltiples vendors

## 🚀 Instalación

### Requisitos Previos

- Docker y Docker Compose instalados
- Sistema Linux (LXC en Proxmox recomendado)
- Mínimo 4GB RAM, 20GB storage
- Acceso a la red 192.168.3.0/24

### Paso 1: Clonar o Copiar los Archivos

```bash
# Si tienes git
git clone <repo-url> /opt/netaudit-stack
cd /opt/netaudit-stack

# O copiar manualmente la carpeta netaudit-stack a /opt/
```

### Paso 2: Configurar Variables de Entorno

```bash
# Copiar el archivo de ejemplo
cp .env.example .env

# Editar con tu editor favorito
nano .env
```

**Configuraciones CRÍTICAS que DEBES cambiar:**

```bash
# 1. Secret Key de Netbox (generar uno aleatorio)
SECRET_KEY=$(openssl rand -base64 32)

# 2. Contraseñas de base de datos
DB_PASSWORD=tu_password_seguro_aqui
POSTGRES_PASSWORD=tu_password_seguro_aqui  # Debe ser el mismo

# 3. Credenciales de administrador de Netbox
SUPERUSER_PASSWORD=tu_password_admin

# 4. Token de API de Netbox (generar uno aleatorio)
SUPERUSER_API_TOKEN=$(openssl rand -hex 20)
NETBOX_TOKEN=$(openssl rand -hex 20)  # Debe ser el mismo

# 5. Redes a escanear (ajustar si es necesario)
SCAN_NETWORKS=192.168.3.0/24,192.168.100.0/24

# 6. Credenciales de routers (para Oxidized)
ROUTER_USERNAME=admin
ROUTER_PASSWORD=tu_password_routers

# 7. (OPCIONAL) Integración con Proxmox
PROXMOX_HOST=192.168.3.251
PROXMOX_USER=root@pam
PROXMOX_PASSWORD=tu_password_proxmox
```

### Paso 3: Configurar Oxidized (Backup de Routers)

Editar el archivo de routers:

```bash
nano oxidized/router.db
```

Descomentar y configurar tus routers:

```
# Router ISP
huawei-isp:http:192.168.100.1:admin:tu_password

# Router Principal
huawei-ax3:http:192.168.3.1:admin:tu_password
```

**Nota sobre protocolos:**
- Si tus routers tienen SSH habilitado, cambia `http` por `ssh`
- Si solo tienen Telnet, cambia `http` por `telnet`
- HTTP es el protocolo web estándar de gestión Huawei

### Paso 4: Ajustar Rangos de Clasificación (Opcional)

En `.env`, ajusta los rangos de IP para tus categorías:

```bash
# Infraestructura (routers, switches, firewalls)
RANGE_INFRASTRUCTURE=192.168.3.1-192.168.3.9

# Domótica (IoT, sensores, smart home)
RANGE_DOMOTICA=192.168.3.10-192.168.3.50

# Trabajo (PCs, laptops, servidores)
RANGE_TRABAJO=192.168.3.51-192.168.3.150

# Entretenimiento (TVs, consolas, streaming)
RANGE_ENTRETENIMIENTO=192.168.3.151-192.168.3.254
```

### Paso 5: Iniciar el Stack

```bash
# Construir las imágenes
docker-compose build

# Iniciar los servicios
docker-compose up -d

# Ver los logs
docker-compose logs -f
```

### Paso 6: Configuración Inicial de Netbox

1. Esperar ~30 segundos a que Netbox inicie completamente
2. Acceder a: `http://192.168.3.251:8000`
3. Login con:
   - Usuario: `admin` (o el que configuraste en SUPERUSER_NAME)
   - Password: el que configuraste en SUPERUSER_PASSWORD

### Paso 7: Ejecutar el Primer Escaneo

**Opción A: Desde Ofelia (Web UI)**

1. Acceder a: `http://192.168.3.251:8080`
2. Buscar el job `scan-network`
3. Click en "Run Now"

**Opción B: Manualmente**

```bash
docker-compose exec scanner python /app/scan.py
```

## 📊 Uso

### Acceder a las Interfaces Web

| Servicio | URL | Descripción |
|----------|-----|-------------|
| Netbox | http://192.168.3.251:8000 | Inventario y gestión de red |
| Ofelia | http://192.168.3.251:8080 | Gestor de tareas programadas |
| Oxidized | http://192.168.3.251:8888 | Backup de configuraciones |

### Programación de Escaneos

Por defecto, el escaneo se ejecuta **diariamente a medianoche** (configurado en docker-compose.yml).

Para cambiar la programación, editar `docker-compose.yml`:

```yaml
labels:
  ofelia.job-exec.scan-network.schedule: "0 0 0 * * *"  # Formato: seg min hora día mes día_semana
```

Ejemplos:
- Cada 6 horas: `0 0 */6 * * *`
- Cada 12 horas: `0 0 */12 * * *`
- Cada hora: `0 0 * * * *`
- Lunes a viernes a las 9am: `0 0 9 * * 1-5`

Reiniciar Ofelia después de cambios:

```bash
docker-compose restart ofelia
```

### Ejecutar Escaneo Manual

```bash
# Desde línea de comandos
docker-compose exec scanner python /app/scan.py

# O desde Ofelia Web UI
# http://192.168.3.251:8080 → Run Now
```

### Ver Logs del Escaneo

```bash
# Logs en tiempo real
docker-compose logs -f scanner

# Logs guardados
docker-compose exec scanner cat /app/logs/scanner.log
```

## 📁 Estructura de Datos en Netbox

### Sites
- **homelab** - Tu red doméstica principal

### Device Types
- Router, Switch, Access Point
- Server, NAS, Computer, Laptop
- Smart TV, IoT Device, Mobile Device
- IP Camera, Printer, Unknown

### Device Roles
- Infrastructure (routers, switches, APs)
- Service (servers, NAS)
- Workstation (PCs, laptops)
- Entertainment (TVs, consolas, media)
- IoT (dispositivos smart home)
- Mobile (smartphones, tablets)
- Peripheral (impresoras, scanners)

### Tags / Categorías
- Domotica
- Trabajo
- Entretenimiento
- ISP
- Infrastructure

## 🔧 Configuración Avanzada

### Habilitar SNMP en Dispositivos

Para obtener más información de tus dispositivos, habilita SNMP v2c:

**En routers Huawei (si soportado):**
```
# Acceder vía SSH o Telnet
snmp-agent community read public
snmp-agent sys-info version v2c
```

**En Proxmox:**
```bash
# Instalar snmpd
apt-get install snmpd

# Configurar /etc/snmp/snmpd.conf
rocommunity public 192.168.3.0/24
syslocation "HomeLab"
syscontact "admin@homelab.local"

# Reiniciar
systemctl restart snmpd
```

**En OpenMediaVault (OMV):**
- GUI: Services → SNMP → Enable
- Community: `public`

### Integración con Proxmox

Si configuraste las variables de Proxmox en `.env`, el scanner automáticamente:
- Detectará VMs y LXCs
- Obtendrá sus IPs
- Agregará información adicional en Netbox

### Ajustar Velocidad de Escaneo

En `.env`:

```bash
# T1: Paranoid - Muy lento, sigiloso
# T2: Sneaky - Lento, poco intrusivo (RECOMENDADO)
# T3: Normal - Balance
# T4: Aggressive - Rápido
# T5: Insane - Muy rápido, muy ruidoso
NMAP_TIMING=T2
```

### Modificar Puertos Escaneados

```bash
# Número de puertos top a escanear (por defecto 1000)
MAX_PORTS=1000

# Para escaneo completo (65535 puertos) - MUY LENTO
MAX_PORTS=65535

# Para escaneo rápido (100 puertos más comunes)
MAX_PORTS=100
```

## 🐛 Troubleshooting

### Netbox no inicia

```bash
# Ver logs
docker-compose logs netbox

# Verificar que postgres está listo
docker-compose logs postgres

# Recrear la base de datos
docker-compose down -v
docker-compose up -d
```

### Scanner no encuentra dispositivos

```bash
# Verificar conectividad
docker-compose exec scanner ping 192.168.3.1

# Ejecutar scan manual con logs
docker-compose exec scanner python /app/scan.py

# Verificar configuración de red
docker-compose exec scanner cat /proc/net/route
```

### Oxidized no puede conectarse a routers

```bash
# Ver logs de Oxidized
docker-compose logs oxidized

# Verificar conectividad
docker-compose exec oxidized ping 192.168.3.1

# Verificar credenciales en router.db
cat oxidized/router.db

# Probar acceso manual
telnet 192.168.3.1
# o
ssh admin@192.168.3.1
```

### Ofelia no ejecuta el escaneo

```bash
# Ver logs de Ofelia
docker-compose logs ofelia

# Verificar que el contenedor scanner existe
docker ps -a | grep scanner

# Reiniciar Ofelia
docker-compose restart ofelia
```

## 📈 Mantenimiento

### Backup de Datos

```bash
# Backup de Netbox (PostgreSQL)
docker-compose exec postgres pg_dump -U netbox netbox > backup_netbox_$(date +%Y%m%d).sql

# Backup de configuraciones de Oxidized (ya versionadas con Git)
tar -czf backup_oxidized_$(date +%Y%m%d).tar.gz oxidized/

# Backup completo
tar -czf backup_netaudit_$(date +%Y%m%d).tar.gz \
  .env \
  netbox/configuration/ \
  oxidized/ \
  scanner/config/
```

### Actualizar el Stack

```bash
# Detener servicios
docker-compose down

# Actualizar imágenes
docker-compose pull

# Reconstruir scanner si hubo cambios
docker-compose build scanner

# Iniciar
docker-compose up -d
```

### Limpiar Logs Antiguos

```bash
# Dentro del contenedor scanner
docker-compose exec scanner sh -c "find /app/logs -name '*.log' -mtime +30 -delete"
```

## 🔒 Seguridad

### Recomendaciones

1. **Cambiar todas las contraseñas por defecto**
2. **Restringir acceso a las interfaces web:**
   ```bash
   # En docker-compose.yml, cambiar:
   ports:
     - "127.0.0.1:8000:8080"  # Solo localhost
   ```
3. **Habilitar HTTPS** con nginx reverse proxy
4. **No exponer** los puertos al internet público
5. **Backup regular** de la base de datos

### Configurar Reverse Proxy (Opcional)

Si usas nginx o Traefik, puedes configurar HTTPS con DuckDNS.

## 📚 Recursos

- [Documentación de Netbox](https://docs.netbox.dev/)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [Oxidized Documentation](https://github.com/ytti/oxidized)
- [Ofelia Documentation](https://github.com/mcuadros/ofelia)

## 🆘 Soporte

Para problemas o preguntas:
1. Revisar los logs: `docker-compose logs`
2. Verificar configuración en `.env`
3. Consultar la sección de Troubleshooting

## 📝 Licencia

Proyecto personal para uso en homelab.

---

**¡Disfruta de tu red completamente auditada y documentada! 🎉**
