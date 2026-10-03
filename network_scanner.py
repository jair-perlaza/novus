"""
Escáner de Red Real para NOVUS
Detecta dispositivos activos en la red local y conexiones entrantes
"""

import socket
import subprocess
import platform
import ipaddress
import threading
import time
from datetime import datetime
from typing import List, Dict, Optional
import psutil
import logging

logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self):
        self.active_devices = []
        self.active_connections = []
        self.scan_running = False
        self.local_ip = self.get_local_ip()
        self.network_range = self.get_network_range()
    
    def get_local_ip(self) -> str:
        """Obtiene la IP local de la máquina"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def get_network_range(self) -> str:
        """Calcula el rango de red local"""
        try:
            ip_parts = self.local_ip.split('.')
            network_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            return network_range
        except:
            return "192.168.1.0/24"
    
    def ping_host(self, ip: str) -> bool:
        """Verifica si un host está activo usando ping"""
        try:
            if platform.system().lower() == "windows":
                cmd = ['ping', '-n', '1', '-w', '500', ip]
            else:
                cmd = ['ping', '-c', '1', '-W', '0.5', ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            return result.returncode == 0
        except:
            return False
    
    def get_hostname(self, ip: str) -> str:
        """Intenta obtener el hostname de una IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Desconocido"
    
    def get_open_ports(self, ip: str, ports: List[int] = None) -> List[int]:
        """Escanea puertos abiertos en un host"""
        if ports is None:
            ports = [22, 23, 53, 80, 135, 139, 443, 445, 993, 995, 8080, 8443]
        
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        return open_ports
    
    def scan_network(self) -> List[Dict]:
        """Escanea la red local en busca de dispositivos activos"""
        devices = []
        network = ipaddress.ip_network(self.network_range, strict=False)
        
        logger.info(f"Escaneando red: {self.network_range}")
        
        # Escanear en paralelo
        threads = []
        results = []
        
        def scan_ip(ip_str):
            if self.ping_host(ip_str):
                hostname = self.get_hostname(ip_str)
                open_ports = self.get_open_ports(ip_str)
                
                device = {
                    "ip": ip_str,
                    "hostname": hostname,
                    "status": "active",
                    "ports": open_ports,
                    "last_seen": datetime.now().isoformat(),
                    "device_type": self.classify_device(hostname, open_ports),
                    "is_local": ip_str == self.local_ip
                }
                results.append(device)
        
        # Limitar a 50 hilos simultáneos para no sobrecargar
        ip_list = [str(ip) for ip in network.hosts()][:254]  # Limitar a /24
        
        for i in range(0, len(ip_list), 50):
            batch = ip_list[i:i+50]
            threads = []
            
            for ip in batch:
                thread = threading.Thread(target=scan_ip, args=(ip,))
                thread.start()
                threads.append(thread)
            
            for thread in threads:
                thread.join()
        
        self.active_devices = results
        logger.info(f"Escaneo completado: {len(results)} dispositivos encontrados")
        return results
    
    def classify_device(self, hostname: str, open_ports: List[int]) -> str:
        """Clasifica el tipo de dispositivo basado en hostname y puertos"""
        hostname_lower = hostname.lower()
        
        if any(port in open_ports for port in [80, 443, 8080, 8443]):
            if "router" in hostname_lower or "gateway" in hostname_lower:
                return "router"
            elif "server" in hostname_lower:
                return "server"
            else:
                return "web_device"
        
        if 22 in open_ports:
            return "linux_device"
        elif 135 in open_ports or 445 in open_ports:
            return "windows_device"
        elif 53 in open_ports:
            return "dns_server"
        else:
            return "unknown"
    
    def get_active_connections(self) -> List[Dict]:
        """Obtiene conexiones de red activas desde psutil."""
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                local = conn.laddr
                remote = conn.raddr
                connections.append({
                    "local_address": f"{local.ip}:{local.port}" if local else "Sin datos disponibles",
                    "remote_address": (
                        f"{remote.ip}:{remote.port}" if remote else "Sin datos disponibles"
                    ),
                    "status": conn.status or "UNKNOWN",
                    "process": self._process_name(conn.pid),
                    "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                    "timestamp": datetime.now().isoformat(),
                })
        except (psutil.AccessDenied, PermissionError) as exc:
            logger.warning(f"Permisos insuficientes para leer conexiones: {exc}")
        except Exception as exc:
            logger.error(f"Error obteniendo conexiones: {exc}")

        self.active_connections = connections
        return connections

    def _process_name(self, pid: Optional[int]) -> str:
        if not pid:
            return "Sin datos disponibles"
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "Sin datos disponibles"
    
    def detect_ngrok_connections(self) -> List[Dict]:
        """Detecta procesos de túnel ngrok activos en el sistema."""
        ngrok_connections = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                name = (proc.info.get('name') or '').lower()
                cmdline = ' '.join(proc.info.get('cmdline') or []).lower()
                if 'ngrok' in name or 'ngrok' in cmdline:
                    ngrok_connections.append({
                        "remote_ip": "Sin datos disponibles",
                        "remote_port": 0,
                        "local_port": 0,
                        "status": "ngrok_process_detected",
                        "process": proc.info.get('name', 'ngrok'),
                        "timestamp": datetime.now().isoformat(),
                        "country": "Sin datos disponibles",
                    })
        except (psutil.AccessDenied, PermissionError):
            pass
        except Exception as exc:
            logger.error(f"Error detectando ngrok: {exc}")

        return ngrok_connections
    
    def get_country_from_ip(self, ip: str) -> str:
        """Intenta obtener el país de una IP (simplificado)"""
        # En una implementación real, usaríamos una API de geolocalización
        # Por ahora, devolvemos una clasificación básica
        try:
            # IPs comunes de ngrok
            if any(ip.startswith(prefix) for prefix in ['52.', '54.', '18.', '13.']):
                return "US"
            elif ip.startswith('35.'):
                return "US"
            else:
                return "Unknown"
        except:
            return "Unknown"
    
    def continuous_scan(self, interval: int = 30):
        """Escaneo continuo de la red"""
        self.scan_running = True
        
        while self.scan_running:
            try:
                # Escanear red
                devices = self.scan_network()
                
                # Obtener conexiones activas
                connections = self.get_active_connections()
                
                # Detectar conexiones ngrok
                ngrok_conns = self.detect_ngrok_connections()
                
                # Combinar toda la información - asegurar formato correcto
                network_data = {
                    "timestamp": datetime.now().isoformat(),
                    "devices": devices,  # Lista de diccionarios con strings como keys
                    "connections": connections,
                    "ngrok_connections": ngrok_conns,
                    "local_ip": self.local_ip,
                    "network_range": self.network_range
                }
                
                # Devolver diccionario directamente, no usar yield
                return network_data
                
                time.sleep(interval)
                
            except Exception as e:
                logger.error(f"Error en escaneo continuo: {e}")
                time.sleep(interval)
    
    def get_network_data(self):
        """Obtiene datos de red actuales (formato seguro para JSON)"""
        try:
            devices = self.scan_network()
            connections = self.get_active_connections()
            ngrok_conns = self.detect_ngrok_connections()
            
            return {
                "timestamp": datetime.now().isoformat(),
                "devices": devices,
                "connections": connections,
                "ngrok_connections": ngrok_conns,
                "local_ip": self.local_ip,
                "network_range": self.network_range
            }
        except Exception as e:
            logger.error(f"Error obteniendo datos de red: {e}")
            return {
                "timestamp": datetime.now().isoformat(),
                "devices": [],
                "connections": [],
                "ngrok_connections": [],
                "local_ip": "unknown",
                "network_range": "unknown",
                "error": str(e)
            }
    
    def stop_scan(self):
        """Detiene el escaneo continuo"""
        self.scan_running = False

# Instancia global del escáner
network_scanner = NetworkScanner()
