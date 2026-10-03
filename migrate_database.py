#!/usr/bin/env python3
"""
Script de migración para actualizar la base de datos NOVUS
Agrega columnas faltantes a tablas existentes
"""

import sqlite3
import os

def migrate_database():
    """Ejecuta migraciones necesarias en la base de datos"""
    db_path = "./novus_vault_v2.db"
    
    if not os.path.exists(db_path):
        print("Base de datos no encontrada, se creará nueva.")
        return
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Verificar si la tabla alertas existe
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alertas'")
        alertas_exists = cursor.fetchone()
        
        if alertas_exists:
            # Verificar columnas existentes en alertas
            cursor.execute("PRAGMA table_info(alertas)")
            columns = [row[1] for row in cursor.fetchall()]
            
            # Agregar columnas faltantes si no existen
            if 'ip_afectada' not in columns:
                cursor.execute("ALTER TABLE alertas ADD COLUMN ip_afectada TEXT")
                print("Columna ip_afectada agregada a alertas")
            
            if 'recomendacion' not in columns:
                cursor.execute("ALTER TABLE alertas ADD COLUMN recomendacion TEXT")
                print("Columna recomendacion agregada a alertas")
        
        # Verificar tabla vulnerabilidades
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vulnerabilidades'")
        vulns_exists = cursor.fetchone()
        
        if vulns_exists:
            # Verificar columnas existentes en vulnerabilidades
            cursor.execute("PRAGMA table_info(vulnerabilidades)")
            columns = [row[1] for row in cursor.fetchall()]
            
            # Agregar columnas faltantes
            if 'titulo' not in columns and 'nombre' in columns:
                # Renombrar nombre a titulo si existe
                cursor.execute("ALTER TABLE vulnerabilidades RENAME COLUMN nombre TO titulo")
                print("Columna nombre renombrada a titulo en vulnerabilidades")
            
            if 'descripcion' not in columns:
                cursor.execute("ALTER TABLE vulnerabilidades ADD COLUMN descripcion TEXT")
                print("Columna descripcion agregada a vulnerabilidades")
            
            if 'nivel' not in columns:
                cursor.execute("ALTER TABLE vulnerabilidades ADD COLUMN nivel TEXT DEFAULT 'medium'")
                print("Columna nivel agregada a vulnerabilidades")
            
            if 'componente' not in columns:
                cursor.execute("ALTER TABLE vulnerabilidades ADD COLUMN componente TEXT")
                print("Columna componente agregada a vulnerabilidades")
        
        conn.commit()
        conn.close()
        
        print("Migración completada exitosamente")
        
    except Exception as e:
        print(f"Error en migración: {e}")

if __name__ == "__main__":
    migrate_database()
