from sqlalchemy import Column, Integer, String, create_engine, Boolean, Text, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from typing import Optional

Base = declarative_base()

# --- MODELO DE USUARIOS ---
class Usuario(Base):
    __tablename__ = "usuarios"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    intentos_fallidos = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    is_temporal = Column(Boolean, default=False)
    trial_expiry = Column(String, nullable=True)
    sector = Column(String, nullable=True)
    nit_pyme = Column(String, nullable=True)

# --- MODELO DE SEGURIDAD (Para Centro de Amenazas / IPS Bloqueadas) ---
class IPBloqueada(Base):
    __tablename__ = "ips_bloqueadas"
    id = Column(Integer, primary_key=True, index=True)
    direccion_ip = Column(String, unique=True)
    razon = Column(String, nullable=True)

# --- NUEVO: MODELO DE VULNERABILIDADES ---
class Vulnerabilidad(Base):
    __tablename__ = "vulnerabilidades"
    id = Column(Integer, primary_key=True, index=True)
    titulo = Column(String) # Cambiado de nombre a titulo para consistencia
    descripcion = Column(Text, nullable=True)
    nivel = Column(String, default="medium") # low, medium, high, critical
    severidad = Column(String, default="media") # Crítica, Alta, Media, Baja
    estado = Column(String, default="abierto") # abierto, cerrado, mitigado
    componente = Column(String, nullable=True) # componente afectado
    fecha = Column(String, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# --- NUEVO: MODELO DE ALERTAS (Para el Historial de Alertas) ---
class Alerta(Base):
    __tablename__ = "alertas"
    id = Column(Integer, primary_key=True, index=True)
    titulo = Column(String)
    descripcion = Column(Text)
    nivel = Column(String) # Info, Warning, Critical
    fecha = Column(String, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    ip_afectada = Column(String, nullable=True) # IP asociada a la alerta
    recomendacion = Column(Text, nullable=True) # Recomendación de seguridad

# --- MODELO DE ACCESO POR SECTOR ---
class SectorAcceso(Base):
    __tablename__ = "sector_acceso"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True)
    sector = Column(String, index=True)
    dispositivo_id = Column(String, index=True)
    dispositivo_fingerprint = Column(String)
    fecha_registro = Column(String, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M"))
    ultimo_acceso = Column(String, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M"))
    is_active = Column(Boolean, default=True)

# --- MODELO DE DISPOSITIVOS CONFIADOS ---
class DispositivoConfiado(Base):
    __tablename__ = "dispositivos_confiados"
    id = Column(Integer, primary_key=True, index=True)
    usuario_email = Column(String, index=True)
    dispositivo_id = Column(String, unique=True, index=True)
    fingerprint = Column(String)
    user_agent = Column(String)
    ip_address = Column(String)
    fecha_registro = Column(String, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M"))
    is_active = Column(Boolean, default=True)

# --- MODELO DE INTENTOS DE ACCESO NO AUTORIZADOS ---
class IntentoAcceso(Base):
    __tablename__ = "intentos_acceso"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String)
    sector_intentado = Column(String)
    dispositivo_id = Column(String)
    ip_address = Column(String)
    user_agent = Column(String)
    fecha = Column(String, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M"))
    razon_bloqueo = Column(String)
    alerta_generada = Column(Boolean, default=False)

# --- MODELO DE AUDITORÍA ---
class Log(Base):
    __tablename__ = "logs"
    id = Column(Integer, primary_key=True, index=True)
    evento = Column(String)
    detalle = Column(String) 
    fecha = Column(String, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M"))

# Configuración del motor NOVUS
DATABASE_URL = "sqlite:///./novus_vault_v2.db" 
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def inicializar_db():
    """Crea todas las tablas en la base de datos"""
    try:
        Base.metadata.create_all(bind=engine)
        print("[OK] Base de datos inicializada correctamente")
    except Exception as e:
        print(f"[ERROR] Error inicializando base de datos: {e}")

def ensure_tables_exist():
    """Asegura que todas las tablas existan, las crea si faltan"""
    try:
        # Crear todas las tablas (esto agrega columnas faltantes)
        Base.metadata.create_all(bind=engine)
        
        # Verificar tablas críticas sin hacer consultas que fallen
        db = SessionLocal()
        try:
            # Verificar si podemos acceder a las tablas
            db.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
            
            print("Base de datos verificada correctamente")
            
        except Exception as e:
            print(f"Error verificando tablas: {e}")
        finally:
            db.close()
            
    except Exception as e:
        print(f"Error asegurando tablas: {e}")
        Base.metadata.create_all(bind=engine)

def registrar_log_seguridad(db, evento: str, detalle: str, vault=None, fecha: Optional[str] = None):
    """
    Registra un evento de seguridad en la tabla de auditoria.
    Si se proporciona vault, cifra el detalle antes de almacenarlo.
    """
    if vault:
        try:
            detalle = vault.proteger(detalle)
        except Exception:
            # Fallback seguro en caso de falla de cifrado.
            detalle = "[ERROR_CIFRADO_LOG]"
    log = Log(
        evento=evento,
        detalle=detalle,
        fecha=fecha or datetime.now().strftime("%Y-%m-%d %H:%M")
    )
    db.add(log)
    return log