"""
Capa de datos reales para NOVUS.
Centraliza consultas a psutil, SQLite, escáneres y métricas del sistema.
"""

import os
import socket
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import psutil
from werkzeug.security import check_password_hash, generate_password_hash

from database import (
    Alerta,
    Log,
    SessionLocal,
    Usuario,
    Vulnerabilidad,
    ensure_tables_exist,
    inicializar_db,
    registrar_log_seguridad,
)

DEFAULT_ADMIN_EMAIL = os.environ.get("NOVUS_ADMIN_EMAIL", "admin@novus.com")
DEFAULT_ADMIN_PASSWORD = os.environ.get("NOVUS_ADMIN_PASSWORD", "123456")
APP_PORT = int(os.environ.get("NOVUS_PORT", "5000"))


def init_app_data() -> None:
    """Inicializa base de datos y servicios de monitoreo."""
    inicializar_db()
    ensure_tables_exist()
    ensure_default_admin()
    _start_threat_monitoring()


def _start_threat_monitoring() -> None:
    try:
        from threat_detector import threat_detector

        if not threat_detector.monitoring:
            threat_detector.start_monitoring()
    except Exception as exc:
        print(f"[DATA] Monitor de amenazas no disponible: {exc}")


def ensure_default_admin() -> None:
    db = SessionLocal()
    try:
        admin = db.query(Usuario).filter(Usuario.email == DEFAULT_ADMIN_EMAIL).first()
        if not admin:
            admin = Usuario(
                email=DEFAULT_ADMIN_EMAIL,
                hashed_password=generate_password_hash(DEFAULT_ADMIN_PASSWORD),
                is_active=True,
                sector="ciberseguridad",
            )
            db.add(admin)
            db.commit()
            registrar_log_seguridad(db, "INIT", "Usuario administrador inicial creado")
            db.commit()
    finally:
        db.close()


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "Sin datos disponibles"


def get_user_context(user: Any) -> Dict[str, str]:
    hostname = socket.gethostname()
    if user is None or not getattr(user, "is_authenticated", False):
        return {
            "nombre": "Sin sesión",
            "rol": "—",
            "nodo": hostname,
            "sector": "Sin datos disponibles",
            "acceso": "—",
        }

    sector = getattr(user, "sector", None) or "Sin datos disponibles"
    email = getattr(user, "email", "usuario")
    return {
        "nombre": email.split("@")[0],
        "rol": getattr(user, "role", "user"),
        "nodo": hostname,
        "sector": sector,
        "acceso": "Autenticado",
    }


def authenticate_user(email: str, password: str) -> Optional[Dict[str, Any]]:
    db = SessionLocal()
    try:
        usuario = db.query(Usuario).filter(Usuario.email == email).first()
        if not usuario or not usuario.is_active:
            registrar_log_seguridad(db, "LOGIN_FAIL", f"Intento fallido: {email}")
            db.commit()
            return None
        if not check_password_hash(usuario.hashed_password, password):
            usuario.intentos_fallidos = (usuario.intentos_fallidos or 0) + 1
            registrar_log_seguridad(db, "LOGIN_FAIL", f"Credencial inválida: {email}")
            db.commit()
            return None
        usuario.intentos_fallidos = 0
        registrar_log_seguridad(db, "LOGIN_OK", f"Sesión iniciada: {email}")
        db.commit()
        return {
            "id": usuario.id,
            "email": usuario.email,
            "role": "admin" if email == DEFAULT_ADMIN_EMAIL else "user",
            "sector": usuario.sector or "Sin datos disponibles",
        }
    finally:
        db.close()


def load_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    db = SessionLocal()
    try:
        usuario = db.query(Usuario).filter(Usuario.id == user_id, Usuario.is_active.is_(True)).first()
        if not usuario:
            return None
        return {
            "id": usuario.id,
            "email": usuario.email,
            "role": "admin" if usuario.email == DEFAULT_ADMIN_EMAIL else "user",
            "sector": usuario.sector or "Sin datos disponibles",
        }
    finally:
        db.close()


def get_system_metrics() -> Dict[str, Any]:
    hostname = socket.gethostname()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        cpu = float(psutil.cpu_percent(interval=0.5))
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage(".")
        network = psutil.net_io_counters()
        boot_time = psutil.boot_time()
        uptime = time.time() - boot_time

        try:
            processes_count = len(list(psutil.process_iter()))
        except (psutil.Error, OSError):
            processes_count = 0

        try:
            users_count = len(psutil.users())
        except (psutil.Error, OSError):
            users_count = 0

        try:
            connections = len(psutil.net_connections())
        except (psutil.Error, OSError, PermissionError):
            connections = 0

        cpu_freq = psutil.cpu_freq()
        freq_label = (
            f"{cpu_freq.current / 1000:.1f} GHz"
            if cpu_freq and cpu_freq.current
            else "Sin datos disponibles"
        )

        return {
            "cpu_load": cpu,
            "ram_load": memory.percent,
            "disk_load": disk.percent,
            "nodos_activos": connections,
            "status_ia": "ACTIVO",
            "ram_total": f"{memory.total / (1024**3):.1f} GB",
            "ram_usada": f"{memory.used / (1024**3):.1f} GB",
            "ram_disponible": f"{memory.available / (1024**3):.1f} GB",
            "disk_total": f"{disk.total / (1024**3):.1f} GB",
            "disk_usado": f"{disk.used / (1024**3):.1f} GB",
            "disk_free": f"{disk.free / (1024**3):.1f} GB",
            "network_bytes_sent": f"{network.bytes_sent / (1024**2):.1f} MB",
            "network_bytes_recv": f"{network.bytes_recv / (1024**2):.1f} MB",
            "network_traffic_mb": round((network.bytes_sent + network.bytes_recv) / (1024**2), 2),
            "procesos_activos": processes_count,
            "usuarios_conectados": users_count,
            "uptime_horas": f"{uptime / 3600:.1f}h",
            "uptime_dias": f"{uptime / 86400:.1f}d",
            "cpu_cores": psutil.cpu_count(),
            "frecuencia_cpu": freq_label,
            "timestamp_actual": timestamp,
            "hostname": hostname,
            "local_ip": get_local_ip(),
        }
    except Exception as exc:
        print(f"[DATA] Error obteniendo métricas: {exc}")
        return {
            "cpu_load": 0,
            "ram_load": 0,
            "disk_load": 0,
            "nodos_activos": 0,
            "status_ia": "ERROR",
            "network_traffic_mb": 0,
            "procesos_activos": 0,
            "usuarios_conectados": 0,
            "timestamp_actual": timestamp,
            "hostname": hostname,
            "local_ip": get_local_ip(),
        }


def get_node_health_percent() -> float:
    metrics = get_system_metrics()
    cpu = float(metrics.get("cpu_load", 0))
    ram = float(metrics.get("ram_load", 0))
    return round(max(0.0, min(100.0, 100 - (cpu + ram) / 2)), 1)


def get_network_nodes_from_cache(network_cache: Dict[str, Any]) -> List[Dict[str, Any]]:
    return network_cache.get("nodes", [])


def get_alerts_from_db(limit: int = 50) -> List[Dict[str, Any]]:
    db = SessionLocal()
    try:
        alertas = db.query(Alerta).order_by(Alerta.id.desc()).limit(limit).all()
        return [
            {
                "id": f"ALT-{a.id}",
                "dispositivo": a.titulo,
                "ip": a.ip_afectada or "Sin datos disponibles",
                "amenaza": a.descripcion,
                "sector_focus": "SISTEMA",
                "gravedad": (a.nivel or "INFO").upper(),
                "timestamp": a.fecha,
            }
            for a in alertas
        ]
    finally:
        db.close()


def get_incidents_from_db(limit: int = 50) -> Dict[str, Any]:
    db = SessionLocal()
    try:
        alertas = db.query(Alerta).order_by(Alerta.id.desc()).limit(limit).all()
        incidentes = [
            {
                "id": f"INC-{a.id}",
                "ip": a.ip_afectada or "Sin datos disponibles",
                "tipo": a.titulo,
                "descripcion": a.descripcion or "Sin descripción",
                "gravedad": (a.nivel or "INFO").upper(),
                "timestamp": a.fecha,
            }
            for a in alertas
        ]
        criticos = sum(1 for a in alertas if (a.nivel or "").upper() in {"CRITICAL", "CRÍTICO", "HIGH", "ALTA"})
        return {"incidentes": incidentes, "total_criticos": criticos}
    finally:
        db.close()


def get_siem_logs(limit: int = 15) -> List[Dict[str, str]]:
    db = SessionLocal()
    try:
        logs_db = db.query(Log).order_by(Log.id.desc()).limit(limit).all()
        if logs_db:
            return [
                {
                    "time": log.fecha,
                    "msg": f"{log.evento}: {log.detalle}",
                }
                for log in logs_db
            ]
    finally:
        db.close()

    logs = []
    try:
        for conn in psutil.net_connections()[:limit]:
            ip = conn.laddr.ip if conn.laddr else "0.0.0.0"
            logs.append(
                {
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "msg": f"Conexión {conn.type} {ip} [{conn.status}]",
                }
            )
    except (psutil.AccessDenied, PermissionError):
        pass

    return logs or [
        {
            "time": datetime.now().strftime("%H:%M:%S"),
            "msg": "Sin datos disponibles — no hay eventos registrados",
        }
    ]


def scan_vulnerabilities() -> Dict[str, Any]:
    try:
        from vulnerability_scanner import vulnerability_scanner

        return vulnerability_scanner.scan_all_vulnerabilities()
    except Exception as exc:
        print(f"[DATA] Escaneo de vulnerabilidades falló: {exc}")
        return {
            "total_vulnerabilities": 0,
            "vulnerabilities": [],
            "severity_breakdown": {"low": 0, "medium": 0, "high": 0, "critical": 0},
            "risk_score": 0,
        }


def get_vulnerabilities_template_data() -> Dict[str, Any]:
    scan = scan_vulnerabilities()
    vulns = scan.get("vulnerabilities", [])
    total = scan.get("total_vulnerabilities", 0)
    severity = scan.get("severity_breakdown", {})
    critical = severity.get("critical", 0) + severity.get("high", 0)

    hallazgos = []
    local_ip = get_local_ip()
    for idx, vuln in enumerate(vulns):
        hallazgos.append(
            {
                "ip": local_ip,
                "cve_id": vuln.get("cve", vuln.get("type", f"VULN-{idx + 1}")),
                "descripcion": vuln.get("description", "Sin descripción"),
                "nivel": vuln.get("severity", "medium").upper(),
            }
        )

    mitigados = db_count_mitigated_vulnerabilities()
    objetivo = max(total, 1)
    realizadas = total
    progreso = min(100, int((realizadas / objetivo) * 100)) if objetivo else 0
    porcentaje_mitigado = round((mitigados / objetivo) * 100, 1) if objetivo else 0

    return {
        "progreso": progreso,
        "realizadas": realizadas,
        "objetivo": objetivo,
        "total_criticas": critical,
        "porcentaje_mitigado": porcentaje_mitigado,
        "hallazgos": hallazgos,
        "stats": get_system_metrics(),
    }


def db_count_mitigated_vulnerabilities() -> int:
    db = SessionLocal()
    try:
        return db.query(Vulnerabilidad).filter(Vulnerabilidad.estado == "mitigado").count()
    finally:
        db.close()


def get_endpoints_from_network(network_cache: Dict[str, Any]) -> List[Dict[str, Any]]:
    nodes = get_network_nodes_from_cache(network_cache)
    if nodes:
        return [
            {
                "nombre": node.get("name", "Desconocido"),
                "ip": node.get("ip", "Sin datos disponibles"),
                "mac": node.get("mac", "Sin datos disponibles"),
                "tipo": node.get("type", "dispositivo"),
                "icono": "fa-laptop",
                "vulnerabilidades": 0,
                "estado": node.get("status", "Online"),
            }
            for node in nodes
        ]

    hostname = socket.gethostname()
    try:
        ip = socket.gethostbyname(hostname)
    except OSError:
        ip = get_local_ip()

    return [
        {
            "nombre": hostname,
            "ip": ip,
            "mac": "Sin datos disponibles",
            "tipo": "host_local",
            "icono": "fa-server",
            "vulnerabilidades": 0,
            "estado": "Activo",
        }
    ]


def get_report_data(network_cache: Dict[str, Any]) -> Dict[str, Any]:
    metrics = get_system_metrics()
    nodes = get_network_nodes_from_cache(network_cache)
    scan = scan_vulnerabilities()
    db = SessionLocal()
    try:
        alertas_bloqueadas = db.query(Alerta).count()
        logs_count = db.query(Log).count()
    finally:
        db.close()

    cpu = float(metrics.get("cpu_load", 0))
    ram = float(metrics.get("ram_load", 0))
    if cpu > 80 or ram > 80:
        nivel_riesgo = "ALTO"
    elif cpu > 50 or ram > 60:
        nivel_riesgo = "MEDIO"
    else:
        nivel_riesgo = "BAJO"

    historial = []
    if logs_count:
        historial.append(
            {
                "id": "log-audit",
                "tipo": "Auditoría de Seguridad",
                "fecha": datetime.now().strftime("%Y-%m-%d %H:%M"),
            }
        )
    if scan.get("total_vulnerabilities", 0):
        historial.append(
            {
                "id": "vuln-scan",
                "tipo": "Informe de Vulnerabilidades",
                "fecha": datetime.now().strftime("%Y-%m-%d %H:%M"),
            }
        )

    return {
        "resumen": {
            "dispositivos_protegidos": len(nodes),
            "pruebas_pentesting": scan.get("total_vulnerabilities", 0),
            "amenazas_bloqueadas": alertas_bloqueadas,
            "nivel_riesgo": nivel_riesgo,
            "uso_cpu": f"{cpu:.1f}%",
            "uso_ram": f"{ram:.1f}%",
            "uso_disco": f"{metrics.get('disk_load', 0):.1f}%",
            "eficiencia": f"{100 - cpu:.1f}%",
            "procesos_activos": metrics.get("procesos_activos", 0),
            "usuarios_conectados": metrics.get("usuarios_conectados", 0),
            "network_bytes_sent": metrics.get("network_bytes_sent", "0 MB"),
            "network_bytes_recv": metrics.get("network_bytes_recv", "0 MB"),
            "uptime": metrics.get("uptime_horas", "0h"),
            "periodo": datetime.now().strftime("%B %Y"),
            "estado_sistema": "ÓPTIMO" if nivel_riesgo == "BAJO" else "CARGA",
            "nivel_critico": nivel_riesgo,
        },
        "historial": historial,
    }


def get_xdr_data() -> Dict[str, Any]:
    metrics = get_system_metrics()
    local_ip = get_local_ip()
    alertas_db = get_alerts_from_db(15)

    if alertas_db:
        return {
            "resumen": _build_xdr_summary(metrics),
            "eventos": alertas_db,
        }

    procesos = list(psutil.process_iter(["pid", "name", "cpu_percent", "status"]))
    procesos_activos = [p for p in procesos if p.info.get("status") == "running"]
    alertas = []

    for proc in procesos_activos:
        cpu_pct = proc.info.get("cpu_percent") or 0
        if cpu_pct > 50:
            alertas.append(
                {
                    "id": f"CPU-{proc.info['pid']}",
                    "dispositivo": proc.info.get("name", "Unknown"),
                    "ip": local_ip,
                    "amenaza": f"Alto consumo CPU: {cpu_pct:.1f}%",
                    "sector_focus": "SISTEMA",
                    "gravedad": "CRITICAL" if cpu_pct > 80 else "HIGH",
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                }
            )

    mem = float(metrics.get("ram_load", 0))
    if mem > 75:
        alertas.append(
            {
                "id": "MEM-CRITICAL",
                "dispositivo": "Sistema Operativo",
                "ip": local_ip,
                "amenaza": f"Uso de memoria crítico: {mem:.1f}%",
                "sector_focus": "SISTEMA",
                "gravedad": "CRITICAL",
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            }
        )

    return {
        "resumen": _build_xdr_summary(metrics, len(alertas)),
        "eventos": alertas,
    }


def _build_xdr_summary(metrics: Dict[str, Any], critical_count: Optional[int] = None) -> Dict[str, Any]:
    cpu = float(metrics.get("cpu_load", 0))
    mem = float(metrics.get("ram_load", 0))
    connections = int(metrics.get("nodos_activos", 0))
    processes = int(metrics.get("procesos_activos", 0))
    critical = critical_count if critical_count is not None else (2 if cpu > 80 or mem > 80 else 1 if cpu > 50 else 0)

    return {
        "total_eventos": connections + processes,
        "conexiones_activas": connections,
        "procesos_activos": processes,
        "cpu_actual": f"{cpu:.1f}%",
        "memoria_usada": f"{mem:.1f}%",
        "nivel_critico": critical,
        "nivel_critico_texto": "CRÍTICO" if critical >= 2 else "MEDIO" if critical == 1 else "NORMAL",
        "salud_nodo": get_node_health_percent(),
        "estado": "ACTIVO",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def get_config_data(user: Any, app_debug: bool) -> Dict[str, Any]:
    return {
        "config": {
            "modo_desarrollo": "ACTIVO (Debug On)" if app_debug else "PRODUCCIÓN",
            "puerto_escucha": APP_PORT,
            "ip_servidor": get_local_ip(),
            "sector": getattr(user, "sector", None) or "Sin datos disponibles",
            "intensidad_pentesting": "Sin datos disponibles",
            "alertas_whatsapp": "Sin datos disponibles",
            "alertas_email": "Sin datos disponibles",
            "sector_activo": None,
        },
        "sectores": [],
        "stats": {
            "uso_cpu_kernel": f"{psutil.cpu_percent()}%",
            "procesos_novus": len([p for p in psutil.process_iter() if "python" in p.name().lower()]),
            "uptime_sistema": f"{round((time.time() - psutil.boot_time()) / 3600, 1)} Horas",
        },
    }


def register_company(form_data: Dict[str, str], remote_addr: str, user_agent: str) -> bool:
    db = SessionLocal()
    try:
        email = form_data.get("email_usuario") or form_data.get("email", "")
        existing = db.query(Usuario).filter(Usuario.email == email).first()
        password = form_data.get("password", "")
        if existing:
            return False
        usuario = Usuario(
            email=email,
            hashed_password=generate_password_hash(password),
            is_active=True,
            is_temporal=True,
            sector=form_data.get("sector", "Sin datos disponibles"),
            nit_pyme=form_data.get("nit", ""),
        )
        db.add(usuario)
        registrar_log_seguridad(
            db,
            "REGISTRO_EMPRESA",
            f"Empresa {form_data.get('empresa', form_data.get('nombre', ''))} | IP {remote_addr} | UA {user_agent[:80]}",
        )
        db.commit()
        return True
    except Exception as exc:
        print(f"[DATA] Error registrando empresa: {exc}")
        db.rollback()
        return False
    finally:
        db.close()


def analyze_file(path: str) -> Dict[str, Any]:
    size = os.path.getsize(path)
    return {
        "tamaño": f"{round(size / 1024, 2)} KB",
        "seguro": None,
        "detectado": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "nota": "Análisis de malware no configurado — solo metadatos del archivo",
    }


def get_automation_stats(reglas: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = 0
    for regla in reglas:
        value = regla.get("ejecuciones_mes", 0)
        try:
            total += int(value)
        except (TypeError, ValueError):
            pass
    return {"ejecuciones_mes": total}
