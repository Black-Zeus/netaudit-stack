# 🚀 QUICKSTART - NetAudit HomeStack

Guía rápida de 5 minutos para poner en marcha tu auditoría de red.

## ⚡ Instalación Express

```bash
# 1. Copiar archivos a tu servidor
scp -r netaudit-stack/ root@192.168.3.251:/opt/

# 2. Conectar al servidor
ssh root@192.168.3.251

# 3. Ir al directorio
cd /opt/netaudit-stack

# 4. Ejecutar setup automático
chmod +x scripts/setup.sh
./scripts/setup.sh
```

El script te guiará por la configuración inicial.

## ⚙️ Configuración Mínima Requerida

Edita `.env` y cambia **SOLO** estos valores:

```bash
# Contraseña de admin de Netbox
SUPERUSER_PASSWORD=TuPasswordSeguro123

# Credenciales de tus routers
ROUTER_USERNAME=admin
ROUTER_PASSWORD=PasswordDelosRouters
```

Edita `oxidized/router.db` y descomenta tus routers:

```bash
huawei-isp:http:192.168.100.1:admin:password_router_isp
huawei-ax3:http:192.168.3.1:admin:password_router_principal
```

## 🎯 Primer Escaneo

```bash
# Opción 1: Manual
docker-compose exec scanner python /app/scan.py

# Opción 2: Desde web
# Acceder a http://192.168.3.251:8080
# Click en "Run Now" en el job scan-network
```

## 🌐 Acceder a la Interfaz

```bash
# Netbox (Inventario)
http://192.168.3.251:8000
Usuario: admin
Password: (el que configuraste)

# Ofelia (Gestor de tareas)
http://192.168.3.251:8080

# Oxidized (Backups)
http://192.168.3.251:8888
```

## 📊 Comandos Útiles

```bash
# Ver todos los logs
docker-compose logs -f

# Ver solo logs del scanner
docker-compose logs -f scanner

# Reiniciar todo
docker-compose restart

# Detener todo
docker-compose down

# Iniciar todo
docker-compose up -d

# Backup completo
./scripts/backup.sh

# Ver estado de contenedores
docker-compose ps
```

## 🔧 Si Algo Sale Mal

```bash
# 1. Ver qué está pasando
docker-compose logs

# 2. Verificar que todos los servicios están arriba
docker-compose ps

# 3. Reiniciar servicios problemáticos
docker-compose restart netbox scanner ofelia

# 4. Empezar de cero (CUIDADO: borra todo)
docker-compose down -v
docker-compose up -d
```

## 📝 Checklist de Verificación

- [ ] Todos los servicios están running: `docker-compose ps`
- [ ] Puedes acceder a Netbox: http://192.168.3.251:8000
- [ ] Puedes hacer login en Netbox con admin
- [ ] El primer escaneo se ejecutó sin errores
- [ ] Ves dispositivos en Netbox → Devices
- [ ] Oxidized puede acceder a tus routers (revisar logs)

## 🎓 Próximos Pasos

1. **Explora Netbox:**
   - Devices → Ver dispositivos descubiertos
   - IPAM → IP Addresses → Ver todas las IPs
   - Organization → Sites → Ver tu site "homelab"

2. **Personaliza la Clasificación:**
   - Edita los rangos de IP en `.env`
   - Reinicia el scanner: `docker-compose restart scanner`

3. **Habilita SNMP:**
   - En tus routers, NAS, servidores
   - Community string: `public`
   - Vuelve a escanear para obtener más info

4. **Programa Backups:**
   - Agregar a cron: `crontab -e`
   - Agregar línea: `0 2 * * * /opt/netaudit-stack/scripts/backup.sh`

## 🆘 Ayuda Rápida

**Netbox no carga:**
```bash
docker-compose logs netbox | grep -i error
docker-compose restart netbox
```

**Scanner no encuentra dispositivos:**
```bash
# Verificar network mode
docker-compose exec scanner ip addr
# Debe mostrar la red 192.168.3.0/24
```

**Oxidized no puede conectar a routers:**
```bash
# Verificar credenciales
cat oxidized/router.db
# Verificar logs
docker-compose logs oxidized | tail -20
```

---

**¿Problemas? Revisa el README.md completo para documentación detallada.**

**¿Todo funciona? ¡Disfruta de tu red completamente auditada! 🎉**
