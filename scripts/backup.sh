#!/bin/bash

# NetAudit HomeStack - Backup Script
# Script para realizar backups del sistema

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "ℹ $1"
}

# Configuración
BACKUP_DIR="/opt/netaudit-backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="netaudit_backup_$DATE"

# Crear directorio de backups
mkdir -p "$BACKUP_DIR"

echo "=================================================="
echo "   NetAudit HomeStack - Backup"
echo "=================================================="
echo ""

# Backup de PostgreSQL
backup_database() {
    print_info "Realizando backup de PostgreSQL..."
    
    docker-compose exec -T postgres pg_dump -U netbox netbox > "$BACKUP_DIR/${BACKUP_NAME}_database.sql"
    
    if [ -f "$BACKUP_DIR/${BACKUP_NAME}_database.sql" ]; then
        SIZE=$(du -h "$BACKUP_DIR/${BACKUP_NAME}_database.sql" | cut -f1)
        print_success "Database backup creado: $SIZE"
    else
        print_error "Error al crear database backup"
        return 1
    fi
}

# Backup de configuraciones
backup_configs() {
    print_info "Realizando backup de configuraciones..."
    
    tar -czf "$BACKUP_DIR/${BACKUP_NAME}_configs.tar.gz" \
        .env \
        netbox/configuration/ \
        oxidized/ \
        scanner/config/ \
        docker-compose.yml \
        2>/dev/null || true
    
    if [ -f "$BACKUP_DIR/${BACKUP_NAME}_configs.tar.gz" ]; then
        SIZE=$(du -h "$BACKUP_DIR/${BACKUP_NAME}_configs.tar.gz" | cut -f1)
        print_success "Configs backup creado: $SIZE"
    else
        print_error "Error al crear configs backup"
        return 1
    fi
}

# Backup de volúmenes Docker
backup_volumes() {
    print_info "Realizando backup de volúmenes Docker..."
    
    # Netbox media
    docker run --rm \
        -v netaudit-stack_netbox-media:/data \
        -v "$BACKUP_DIR":/backup \
        alpine tar czf /backup/${BACKUP_NAME}_netbox_media.tar.gz -C /data . \
        2>/dev/null || true
    
    # Oxidized configs
    docker run --rm \
        -v netaudit-stack_oxidized-data:/data \
        -v "$BACKUP_DIR":/backup \
        alpine tar czf /backup/${BACKUP_NAME}_oxidized_data.tar.gz -C /data . \
        2>/dev/null || true
    
    print_success "Volúmenes backup creados"
}

# Comprimir todo
create_full_backup() {
    print_info "Creando backup completo..."
    
    cd "$BACKUP_DIR"
    tar -czf "${BACKUP_NAME}_FULL.tar.gz" ${BACKUP_NAME}_*.sql ${BACKUP_NAME}_*.tar.gz 2>/dev/null || true
    
    # Limpiar archivos individuales
    rm -f ${BACKUP_NAME}_*.sql
    rm -f ${BACKUP_NAME}_*.tar.gz
    
    if [ -f "${BACKUP_NAME}_FULL.tar.gz" ]; then
        SIZE=$(du -h "${BACKUP_NAME}_FULL.tar.gz" | cut -f1)
        print_success "Backup completo: ${BACKUP_NAME}_FULL.tar.gz ($SIZE)"
    fi
}

# Limpiar backups antiguos (mantener últimos 7)
cleanup_old_backups() {
    print_info "Limpiando backups antiguos..."
    
    cd "$BACKUP_DIR"
    ls -t netaudit_backup_*_FULL.tar.gz | tail -n +8 | xargs -r rm
    
    COUNT=$(ls -1 netaudit_backup_*_FULL.tar.gz 2>/dev/null | wc -l)
    print_success "Manteniendo últimos $COUNT backups"
}

# Restaurar desde backup
restore_backup() {
    BACKUP_FILE=$1
    
    if [ -z "$BACKUP_FILE" ]; then
        print_error "Uso: $0 restore <archivo_backup>"
        exit 1
    fi
    
    if [ ! -f "$BACKUP_FILE" ]; then
        print_error "Archivo no encontrado: $BACKUP_FILE"
        exit 1
    fi
    
    echo "=================================================="
    echo "   RESTAURANDO BACKUP"
    echo "=================================================="
    echo ""
    print_info "ADVERTENCIA: Esto sobrescribirá la configuración actual"
    print_info "¿Deseas continuar? (escribe 'yes' para confirmar)"
    read -r response
    
    if [ "$response" != "yes" ]; then
        print_info "Restauración cancelada"
        exit 0
    fi
    
    # Extraer backup
    TEMP_DIR=$(mktemp -d)
    tar -xzf "$BACKUP_FILE" -C "$TEMP_DIR"
    
    # Restaurar database
    print_info "Restaurando base de datos..."
    docker-compose down
    docker-compose up -d postgres
    sleep 5
    
    cat "$TEMP_DIR"/*_database.sql | docker-compose exec -T postgres psql -U netbox netbox
    
    # Restaurar configs
    print_info "Restaurando configuraciones..."
    tar -xzf "$TEMP_DIR"/*_configs.tar.gz -C .
    
    # Reiniciar servicios
    print_info "Reiniciando servicios..."
    docker-compose up -d
    
    rm -rf "$TEMP_DIR"
    
    print_success "Restauración completada"
}

# Lista backups disponibles
list_backups() {
    echo "Backups disponibles:"
    echo ""
    ls -lh "$BACKUP_DIR"/netaudit_backup_*_FULL.tar.gz 2>/dev/null | awk '{print $9, "(" $5 ")"}'
}

# Menú principal
case "${1:-backup}" in
    backup)
        backup_database
        backup_configs
        backup_volumes
        create_full_backup
        cleanup_old_backups
        echo ""
        echo "=================================================="
        print_success "Backup completado exitosamente"
        echo "Ubicación: $BACKUP_DIR/${BACKUP_NAME}_FULL.tar.gz"
        echo "=================================================="
        ;;
    restore)
        restore_backup "$2"
        ;;
    list)
        list_backups
        ;;
    *)
        echo "Uso: $0 {backup|restore <archivo>|list}"
        exit 1
        ;;
esac
