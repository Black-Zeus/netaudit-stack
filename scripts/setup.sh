#!/bin/bash

# NetAudit HomeStack - Setup Script
# Script de inicialización y configuración

set -e

echo "=================================================="
echo "   NetAudit HomeStack - Setup & Installation"
echo "=================================================="
echo ""

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Funciones de utilidad
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "ℹ $1"
}

# Verificar requisitos
check_requirements() {
    echo "Verificando requisitos..."
    
    # Docker
    if command -v docker &> /dev/null; then
        print_success "Docker instalado: $(docker --version | cut -d' ' -f3)"
    else
        print_error "Docker no está instalado"
        exit 1
    fi
    
    # Docker Compose
    if command -v docker-compose &> /dev/null; then
        print_success "Docker Compose instalado: $(docker-compose --version | cut -d' ' -f4)"
    else
        print_error "Docker Compose no está instalado"
        exit 1
    fi
    
    echo ""
}

# Configurar .env
setup_env() {
    echo "Configurando variables de entorno..."
    
    if [ -f .env ]; then
        print_warning ".env ya existe. ¿Deseas sobrescribirlo? (s/n)"
        read -r response
        if [[ ! "$response" =~ ^[Ss]$ ]]; then
            print_info "Manteniendo .env existente"
            return
        fi
    fi
    
    cp .env.example .env
    
    # Generar valores aleatorios
    SECRET_KEY=$(openssl rand -base64 32)
    DB_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
    API_TOKEN=$(openssl rand -hex 20)
    
    # Reemplazar en .env
    sed -i "s/changeme_generate_random_secret_key_here/$SECRET_KEY/" .env
    sed -i "s/netbox_secure_password_changeme/$DB_PASSWORD/g" .env
    sed -i "s/0123456789abcdef0123456789abcdef01234567/$API_TOKEN/g" .env
    
    print_success ".env configurado con valores aleatorios seguros"
    print_warning "IMPORTANTE: Edita .env y configura:"
    print_warning "  - SUPERUSER_PASSWORD"
    print_warning "  - ROUTER_USERNAME y ROUTER_PASSWORD"
    print_warning "  - (Opcional) Credenciales de Proxmox"
    echo ""
}

# Configurar Oxidized
setup_oxidized() {
    echo "Configurando Oxidized..."
    
    if [ ! -f oxidized/router.db ]; then
        print_error "oxidized/router.db no existe"
        return 1
    fi
    
    print_info "Edita oxidized/router.db y descomenta tus routers"
    print_info "Formato: nombre:modelo:ip:usuario:password"
    echo ""
}

# Construir imágenes
build_images() {
    echo "Construyendo imágenes Docker..."
    docker-compose build
    print_success "Imágenes construidas exitosamente"
    echo ""
}

# Iniciar servicios
start_services() {
    echo "Iniciando servicios..."
    docker-compose up -d
    print_success "Servicios iniciados"
    echo ""
}

# Esperar a que Netbox esté listo
wait_for_netbox() {
    echo "Esperando a que Netbox esté listo..."
    
    max_attempts=30
    attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if docker-compose exec -T netbox curl -s http://localhost:8080 > /dev/null 2>&1; then
            print_success "Netbox está listo"
            echo ""
            return 0
        fi
        
        attempt=$((attempt + 1))
        echo -n "."
        sleep 2
    done
    
    print_error "Timeout esperando a Netbox"
    return 1
}

# Mostrar información de acceso
show_access_info() {
    IP=$(hostname -I | awk '{print $1}')
    
    echo "=================================================="
    echo "   Instalación Completada"
    echo "=================================================="
    echo ""
    echo "Acceso a servicios:"
    echo ""
    echo "  🌐 Netbox (Inventario de Red)"
    echo "     URL: http://$IP:8000"
    echo "     Usuario: admin"
    echo "     Password: (el configurado en .env)"
    echo ""
    echo "  ⏰ Ofelia (Gestor de Tareas)"
    echo "     URL: http://$IP:8080"
    echo ""
    echo "  💾 Oxidized (Backup de Configs)"
    echo "     URL: http://$IP:8888"
    echo ""
    echo "Comandos útiles:"
    echo ""
    echo "  Ver logs:              docker-compose logs -f"
    echo "  Escanear manualmente:  docker-compose exec scanner python /app/scan.py"
    echo "  Detener servicios:     docker-compose down"
    echo "  Reiniciar servicios:   docker-compose restart"
    echo ""
    echo "Próximos pasos:"
    echo ""
    echo "  1. Accede a Netbox y familiarízate con la interfaz"
    echo "  2. Ejecuta el primer escaneo manualmente"
    echo "  3. Revisa los resultados en Netbox"
    echo "  4. Configura Oxidized editando oxidized/router.db"
    echo ""
    echo "=================================================="
}

# Script principal
main() {
    check_requirements
    setup_env
    setup_oxidized
    
    echo ""
    print_info "¿Deseas construir e iniciar los servicios ahora? (s/n)"
    read -r response
    
    if [[ "$response" =~ ^[Ss]$ ]]; then
        build_images
        start_services
        wait_for_netbox
        show_access_info
    else
        print_info "Puedes iniciar los servicios manualmente con:"
        print_info "  docker-compose build"
        print_info "  docker-compose up -d"
    fi
    
    echo ""
    print_success "Setup completado"
}

# Ejecutar
main
