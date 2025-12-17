import socket
import nmap
import csv
import sqlite3
import base64
from datetime import datetime
from io import BytesIO
import matplotlib
import numpy as np
from reportlab.lib.enums import TA_CENTER
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
import threading
from contextlib import contextmanager
import queue
import time
import logging
import random

matplotlib.use('Agg')
import matplotlib.pyplot as plt
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
import os
from reportlab.lib.units import cm
from reportlab.lib import colors
from ipaddress import ip_network
from reportlab.lib.styles import ParagraphStyle

# ========== CONFIGURACIÓN GLOBAL Y LOGGING ==========
DATABASE = 'scan_results.db'
_DB_LOCK = threading.Lock()
_CONNECTION_POOL = queue.Queue(maxsize=20)
_DNS_CACHE = {}
_DNS_CACHE_LOCK = threading.Lock()
_PORT_CACHE = {}
_PORT_CACHE_LOCK = threading.Lock()
_CACHE_TIMEOUT = 300  # 5 minutos

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# ========== BASE DE DATOS OPTIMIZADA ==========
@contextmanager
def get_db_connection():
    """Pool de conexiones para mejorar rendimiento con múltiples hilos"""
    try:
        conn = _CONNECTION_POOL.get_nowait()
    except queue.Empty:
        conn = sqlite3.connect(DATABASE, check_same_thread=False, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA cache_size = -2000")
    try:
        yield conn
    finally:
        _CONNECTION_POOL.put(conn)

def init_db():
    """Inicializa la base de datos con índices para mejor rendimiento"""
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                hostname TEXT,
                port INTEGER,
                state TEXT,
                service TEXT,
                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        c.execute('CREATE INDEX IF NOT EXISTS idx_ip ON scan_results(ip)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_ip_date ON scan_results(ip, scan_date)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_state ON scan_results(state)')
        conn.commit()
    
    for _ in range(5):
        conn = sqlite3.connect(DATABASE, check_same_thread=False, timeout=10)
        _CONNECTION_POOL.put(conn)
    
    logger.info(f"Base de datos inicializada: {DATABASE}")

def save_to_db_batch(entries):
    """Guarda múltiples entradas en lote para reducir I/O"""
    if not entries:
        return
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.executemany("""
                INSERT INTO scan_results (ip, hostname, port, state, service, scan_date)
                VALUES (?, ?, ?, ?, ?, ?)
            """, entries)
            conn.commit()
            logger.debug(f"Batch guardado: {len(entries)} registros")
    except sqlite3.Error as e:
        logger.error(f"Error batch save: {e}")

def save_to_db(ip, hostname, port, state, service, scan_date=None):
    """Versión individual para compatibilidad"""
    if scan_date is None:
        scan_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO scan_results (ip, hostname, port, state, service, scan_date)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (ip, hostname, port, state, service, scan_date))
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Error saving to DB: {e}")

# ========== FUNCIONES UTILITARIAS OPTIMIZADAS ==========
def nslookup(ip):
    """Con caché para evitar consultas DNS repetidas"""
    with _DNS_CACHE_LOCK:
        if ip in _DNS_CACHE:
            entry = _DNS_CACHE[ip]
            if time.time() - entry['timestamp'] < _CACHE_TIMEOUT:
                return entry['hostname']
    
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        hostname = ''
    except Exception as e:
        logger.debug(f"Error DNS para {ip}: {e}")
        hostname = ''
    
    with _DNS_CACHE_LOCK:
        _DNS_CACHE[ip] = {
            'hostname': hostname,
            'timestamp': time.time()
        }
    
    return hostname

def check_single_port(ip, port, timeout=0.5):
    """Versión optimizada con caché y timeout más bajo"""
    cache_key = f"{ip}:{port}"
    
    with _PORT_CACHE_LOCK:
        if cache_key in _PORT_CACHE:
            entry = _PORT_CACHE[cache_key]
            if time.time() - entry['timestamp'] < 60:
                return entry['state']
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        result = sock.connect_ex((ip, port))
        state = 'ABIERTO' if result == 0 else 'CERRADO'
    except socket.timeout:
        state = 'CERRADO'
    except Exception as e:
        logger.debug(f"Error check port {ip}:{port}: {e}")
        state = 'CERRADO'
    finally:
        sock.close()
    
    with _PORT_CACHE_LOCK:
        _PORT_CACHE[cache_key] = {
            'state': state,
            'timestamp': time.time()
        }
    
    return state

def parse_nmap_output(nm, ip):
    """Versión más eficiente de parsing de resultados Nmap"""
    ports = []
    try:
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                port_data = nm[ip][proto]
                for port, info in port_data.items():
                    ports.append({
                        'port': port,
                        'state': info['state'],
                        'service': info['name']
                    })
    except Exception as e:
        logger.debug(f"Error parseando Nmap output para {ip}: {e}")
    
    return ports

def get_latest_ports_for_ip(ip):
    """Recupera el estado más reciente de cada puerto escaneado para la IP dada"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute(
                "SELECT port, state FROM scan_results "
                "WHERE ip=? ORDER BY scan_date DESC",
                (ip,)
            )
            rows = c.fetchall()
        
        seen = set()
        latest = []
        for port, state in rows:
            if port not in seen:
                seen.add(port)
                latest.append((port, state))
        return latest
    except Exception as e:
        logger.error(f"Error obteniendo puertos para {ip}: {e}")
        return []

# ========== CONFIGURACIÓN NMAP OPTIMIZADA ==========
class NmapConfig:
    """Configuración optimizada para Nmap según tipo de escaneo"""
    
    @staticmethod
    def get_arguments(scan_type='normal'):
        """
        Devuelve parámetros Nmap optimizados
        
        scan_type: 'normal', 'full', 'aggressive', 'stealth'
        """
        base_args = '-Pn -n --open'  # Comandos base siempre presentes
        
        if scan_type == 'normal':
            # Equilibrio entre velocidad y precisión
            return f"{base_args} -sS -T4 --max-retries=1 --host-timeout=30s --min-rate=100 --max-rate=500 --top-ports 100"
        
        elif scan_type == 'full':
            # Escaneo completo - más lento pero exhaustivo
            return f"{base_args} -sS -T3 --max-retries=2 --host-timeout=90s --min-rate=50 --max-rate=200 --max-scan-delay 10ms"
        
        elif scan_type == 'aggressive':
            # Máxima velocidad (solo para redes confiables)
            return f"{base_args} -sS -T5 --max-retries=0 --host-timeout=15s --min-rate=500 --max-rate=2000 --top-ports 50"
        
        elif scan_type == 'stealth':
            # Escaneo sigiloso
            return f"{base_args} -sS -T2 --max-retries=3 --host-timeout=60s --scan-delay 100ms --max-rate=100"
        
        else:
            return f"{base_args} -sS -T4 --max-retries=1 --host-timeout=30s"
    
    @staticmethod
    def get_port_range(full_scan=False, adaptive=True):
        """Devuelve rango de puertos optimizado"""
        if full_scan:
            if adaptive:
                # Estrategia adaptativa: priorizar puertos comunes
                # 1. Puertos bien conocidos (0-1023)
                # 2. Puertos registrados comunes (1024-10000)
                # 3. El resto si es necesario
                return '1-1000'  # Primera fase
            else:
                return '1-65535'  # Todos los puertos
        else:
            return '1-1024'  # Puertos bien conocidos
    
    @staticmethod
    def get_timeout(full_scan=False):
        """Devuelve timeout apropiado"""
        return 120 if full_scan else 45

# ========== NÚCLEO DEL ESCANEO MULTIHILO OPTIMIZADO ==========
def scan_ips(ips, specific_port=10050, run_nmap_scan=False, 
             full_nmap_scan=False, max_threads=100, batch_size=100, progress_callback=None):
    """
    Escaneo multihilo optimizado con NMAP configurado correctamente
    """
    results = []
    db_batch = []
    db_lock = threading.Lock()
    
    # Control de concurrencia para Nmap
    nmap_concurrent_limit = 10  # Máximo 10 escaneos Nmap simultáneos
    nmap_semaphore = threading.Semaphore(nmap_concurrent_limit)
    
    # Estadísticas para ajuste dinámico
    stats = {
        'total': 0,
        'nmap_success': 0,
        'nmap_timeout': 0,
        'nmap_errors': 0,
        'start_time': time.time()
    }
    stats_lock = threading.Lock()
    
    def process_ip(ip):
        """Procesa una IP individual"""
        nonlocal db_batch, stats
        
        scan_ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        entry = {'ip': ip, 'hostname': '', 'ports': [], 'scan_date': scan_ts}

        
        try:
            # 1. Resolución DNS
            hostname = nslookup(ip)
            entry['hostname'] = hostname
            
            # 2. Escaneo de puerto específico
            if specific_port is not None:
                state = check_single_port(ip, specific_port, timeout=0.5)
                port_entry = {
                    'port': specific_port,
                    'state': state,
                    'service': 'zabbix-agent'
                }
                entry['ports'].append(port_entry)
                
                with db_lock:
                    db_batch.append((
                        ip, hostname, specific_port, 
                        state, 'zabbix-agent', 
                        scan_ts)
                    )
            
            # 3. Escaneo Nmap (si está habilitado)
            if run_nmap_scan or full_nmap_scan:
                # Control estricto de concurrencia Nmap
                with nmap_semaphore:
                    # Delay inteligente basado en estadísticas
                    with stats_lock:
                        total_nmap = stats['nmap_success'] + stats['nmap_timeout'] + stats['nmap_errors']
                        if total_nmap > 0:
                            error_rate = (stats['nmap_timeout'] + stats['nmap_errors']) / total_nmap
                            if error_rate > 0.3:
                                time.sleep(0.3)  # Más delay si hay errores
                            elif error_rate > 0.1:
                                time.sleep(0.1)
                    
                    # Crear instancia Nmap
                    nm = nmap.PortScanner()
                    
                    # Configurar parámetros según tipo de escaneo
                    scan_type = 'full' if full_nmap_scan else 'normal'
                    nmap_args = NmapConfig.get_arguments(scan_type)
                    port_range = NmapConfig.get_port_range(full_nmap_scan, adaptive=True)
                    nmap_timeout = NmapConfig.get_timeout(full_nmap_scan)
                    
                    try:
                        # EJECUCIÓN CORRECTA DE NMAP
                        logger.debug(f"Escaneando {ip} con Nmap ({port_range} puertos)")
                        
                        nm.scan(
                            hosts=ip,
                            ports=port_range,
                            arguments=nmap_args,
                            timeout=nmap_timeout
                        )
                        
                        with stats_lock:
                            stats['nmap_success'] += 1
                        
                        # Procesar resultados
                        if ip in nm.all_hosts():
                            ports_found = parse_nmap_output(nm, ip)
                            
                            for port_info in ports_found:
                                # Evitar duplicar puerto específico
                                if specific_port is not None and port_info['port'] == specific_port:
                                    continue
                                
                                entry['ports'].append(port_info)
                                
                                with db_lock:
                                    db_batch.append((
                                        ip, hostname, port_info['port'],
                                        port_info['state'], port_info['service'],
                                        scan_ts
                                    ))
                        
                    except nmap.PortScannerError as e:
                        error_msg = str(e)
                        with stats_lock:
                            if 'Timeout' in error_msg:
                                stats['nmap_timeout'] += 1
                                logger.debug(f"Timeout Nmap para {ip} (continúa)")
                            else:
                                stats['nmap_errors'] += 1
                                logger.warning(f"Error Nmap para {ip}: {error_msg[:80]}")
                    
                    except Exception as e:
                        with stats_lock:
                            stats['nmap_errors'] += 1
                        logger.warning(f"Error general Nmap para {ip}: {str(e)[:80]}")
            
            with stats_lock:
                stats['total'] += 1
                done = stats['total']
            if progress_callback:
                try:
                    progress_callback(done, total_ips, ip)
                except Exception as e:
                    logger.warning(f"Error en callback de progreso: {e}")

            
            return entry
            
        except Exception as e:
            logger.error(f"Error procesando {ip}: {e}")
            return entry
    
    def batch_processor(ip_batch, batch_num):
        """Procesa un lote de IPs"""
        batch_results = []
        
        # Calcular workers óptimos para este lote
        workers = min(max_threads, len(ip_batch))
        
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_ip = {executor.submit(process_ip, ip): ip for ip in ip_batch}
            
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result(timeout=90)
                    batch_results.append(result)
                    
                    # Guardar batch periódicamente
                    with db_lock:
                        if len(db_batch) >= batch_size:
                            save_to_db_batch(db_batch[:])
                            db_batch.clear()
                            
                except concurrent.futures.TimeoutError:
                    logger.warning(f"Timeout procesando {ip} (batch {batch_num})")
                except Exception as e:
                    logger.error(f"Error procesando {ip}: {e}")
        
        return batch_results
    
    # ========== INICIO DEL ESCANEO ==========
    total_ips = len(ips)
    
    # Log de configuración
    scan_mode = "COMPLETO" if full_nmap_scan else ("NORMAL" if run_nmap_scan else "ESPECÍFICO")
    logger.info(f"🚀 INICIANDO ESCANEO {scan_mode}")
    logger.info(f"📊 Configuración: {total_ips} IPs, {max_threads} hilos, "
                f"Nmap: {'SI' if run_nmap_scan else 'NO'}, Completo: {'SI' if full_nmap_scan else 'NO'}")
    
    start_time = time.time()
    
    # Ordenar IPs para distribución uniforme
    try:
        sorted_ips = sorted(ips, key=lambda x: tuple(map(int, x.split('.'))))
    except:
        sorted_ips = ips
    
    # Calcular tamaño de lotes dinámico
    if total_ips <= 100:
        batch_size_ips = total_ips
        num_batches = 1
    else:
        num_batches = min(10, total_ips // 25)
        batch_size_ips = total_ips // num_batches
    
    logger.info(f"📦 Procesando en {num_batches} lotes de ~{batch_size_ips} IPs cada uno")
    
    # Procesar por lotes
    for i in range(0, total_ips, batch_size_ips):
        batch_num = (i // batch_size_ips) + 1
        ip_batch = sorted_ips[i:i + batch_size_ips]
        
        ips_remaining = total_ips - i - len(ip_batch)
        logger.info(f"🔧 Lote {batch_num}/{num_batches}: {len(ip_batch)} IPs "
                   f"(Restantes: {ips_remaining})")
        
        batch_start = time.time()
        batch_results = batch_processor(ip_batch, batch_num)
        results.extend(batch_results)
        
        elapsed_batch = time.time() - batch_start
        logger.info(f"✅ Lote {batch_num} completado en {elapsed_batch:.2f}s "
                   f"({len(batch_results)} resultados)")
        
        # Pausa estratégica entre lotes
        if ips_remaining > 0:
            pause_time = min(1.0, 0.1 * batch_num)  # Pausa progresiva
            time.sleep(pause_time)
    
    # Guardar registros pendientes
    with db_lock:
        if db_batch:
            logger.info(f"💾 Guardando {len(db_batch)} registros pendientes")
            save_to_db_batch(db_batch)
    
    # ========== ESTADÍSTICAS FINALES ==========
    total_time = time.time() - start_time
    ips_per_second = total_ips / total_time if total_time > 0 else 0
    
    logger.info("=" * 70)
    logger.info(f"🎉 ESCANEO {scan_mode} COMPLETADO")
    logger.info(f"⏱️  Tiempo total: {total_time:.2f}s ({ips_per_second:.2f} IPs/segundo)")
    logger.info(f"📈 IPs procesadas: {stats['total']}/{total_ips}")
    
    if run_nmap_scan or full_nmap_scan:
        total_nmap = stats['nmap_success'] + stats['nmap_timeout'] + stats['nmap_errors']
        if total_nmap > 0:
            success_rate = (stats['nmap_success'] / total_nmap) * 100
            logger.info(f"🔍 Estadísticas Nmap:")
            logger.info(f"   ✓ Éxitos: {stats['nmap_success']} ({success_rate:.1f}%)")
            logger.info(f"   ⏰ Timeouts: {stats['nmap_timeout']}")
            logger.info(f"   ✗ Errores: {stats['nmap_errors']}")
    
    # Resumen de puertos encontrados
    total_ports = sum(len(entry['ports']) for entry in results)
    open_ports = sum(1 for entry in results for p in entry['ports'] if p['state'] in ['open', 'ABIERTO'])
    
    logger.info(f"🔓 Puertos abiertos encontrados: {open_ports}/{total_ports}")
    logger.info(f"📋 Resultados totales: {len(results)}")
    logger.info("=" * 70)
    
    return results

# ========== VERSIÓN DE ESCANEO POR ETAPAS ==========
def scan_ips_staged(ips, specific_port=10050, run_nmap_scan=False, 
                   full_nmap_scan=False, max_threads=100):
    """
    Escaneo por etapas: primero puertos específicos, luego Nmap para hosts activos
    Más eficiente para redes grandes
    """
    logger.info("🔄 Iniciando escaneo por etapas")
    
    # Etapa 1: Escanear solo puerto específico (muy rápido)
    logger.info("📡 Etapa 1: Escaneando puerto específico en todas las IPs")
    
    stage1_results = []
    active_hosts = []
    
    def stage1_worker(ip):
        """Trabajador para etapa 1"""
        scan_ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        entry = {'ip': ip, 'hostname': '', 'ports': [], 'scan_date': scan_ts}

        
        if specific_port is not None:
            state = check_single_port(ip, specific_port, timeout=0.3)
            if state == 'ABIERTO':
                active_hosts.append(ip)
                logger.debug(f"Host activo encontrado: {ip}")
            
            entry['ports'].append({
                'port': specific_port,
                'state': state,
                'service': 'zabbix-agent'
            })
            
            save_to_db(ip, entry['hostname'], specific_port, state, 'zabbix-agent')
        
        return entry
    
    # Ejecutar etapa 1 con muchos hilos
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(stage1_worker, ip) for ip in ips]
        for future in concurrent.futures.as_completed(futures):
            try:
                stage1_results.append(future.result(timeout=10))
            except Exception as e:
                logger.error(f"Error etapa 1: {e}")
    
    logger.info(f"✅ Etapa 1 completada: {len(active_hosts)} hosts activos encontrados")
    
    # Etapa 2: Escaneo Nmap solo para hosts activos
    if run_nmap_scan and active_hosts:
        logger.info(f"🔍 Etapa 2: Escaneo Nmap para {len(active_hosts)} hosts activos")
        
        # Usar menos hilos para Nmap (más intensivo)
        nmap_threads = min(20, len(active_hosts))
        
        # Configurar escaneo
        scan_type = 'full' if full_nmap_scan else 'normal'
        nmap_args = NmapConfig.get_arguments(scan_type)
        port_range = NmapConfig.get_port_range(full_nmap_scan)
        
        def stage2_worker(ip):
            """Trabajador para etapa 2 (Nmap)"""
            nm = nmap.PortScanner()
            
            try:
                logger.debug(f"Escaneando {ip} con Nmap")
                nm.scan(
                    hosts=ip,
                    ports=port_range,
                    arguments=nmap_args,
                    timeout=60 if full_nmap_scan else 30
                )
                
                # Actualizar resultados de etapa 1
                for entry in stage1_results:
                    if entry['ip'] == ip and ip in nm.all_hosts():
                        ports = parse_nmap_output(nm, ip)
                        for port_info in ports:
                            if port_info['port'] != specific_port:
                                entry['ports'].append(port_info)
                                save_to_db(
                                    ip, entry['hostname'],
                                    port_info['port'], port_info['state'],
                                    port_info['service']
                                )
                
            except Exception as e:
                logger.debug(f"Nmap omitido para {ip}: {str(e)[:50]}")
        
        # Ejecutar etapa 2
        with ThreadPoolExecutor(max_workers=nmap_threads) as executor:
            futures = [executor.submit(stage2_worker, ip) for ip in active_hosts]
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result(timeout=120)
                except Exception as e:
                    logger.error(f"Error etapa 2: {e}")
        
        logger.info("✅ Etapa 2 completada")
    
    return stage1_results

# ========== FUNCIONES DE EXPORTACIÓN ==========
def export_to_txt(results, filename, from_date=None, to_date=None):
    """Exporta resultados a TXT con filtro opcional por fechas"""
    def in_date_range(scan_date):
        if not from_date and not to_date:
            return True
        try:
            dt = datetime.strptime(scan_date.split('.')[0], '%Y-%m-%d %H:%M:%S')
            after_from = True if not from_date else dt >= from_date
            before_to = True if not to_date else dt <= to_date
            return after_from and before_to
        except:
            return False

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            for entry in results:
                scan_date = entry.get('scan_date', 'Fecha no disponible')
                if from_date or to_date:
                    if not in_date_range(scan_date):
                        continue

                f.write(f"IP: {entry['ip']} ({entry['hostname']})\n")
                for p in entry['ports']:
                    f.write(f"  Port {p['port']}: {p['state']} ({p['service']})\n")
                f.write('\n')
        logger.info(f"Resultados exportados a TXT: {filename}")
        return True
    except Exception as e:
        logger.error(f"Error exportando a TXT: {e}")
        return False

def export_to_csv(results, filename, from_date=None, to_date=None):
    """Exporta resultados a CSV con filtro opcional por fechas"""
    def in_date_range(scan_date):
        if not from_date and not to_date:
            return True
        try:
            dt = datetime.strptime(scan_date.split('.')[0], '%Y-%m-%d %H:%M:%S')
            after_from = True if not from_date else dt >= from_date
            before_to = True if not to_date else dt <= to_date
            return after_from and before_to
        except:
            return False

    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['IP', 'Hostname', 'Puerto', 'Estado', 'Servicio', 'Fecha'])

            rows_exported = 0
            for entry in results:
                scan_date = entry.get('scan_date', 'Fecha no disponible')
                if from_date or to_date:
                    if not in_date_range(scan_date):
                        continue

                for p in entry['ports']:
                    writer.writerow([
                        entry['ip'],
                        entry['hostname'],
                        p['port'],
                        p['state'],
                        p['service'],
                        scan_date
                    ])
                    rows_exported += 1
            
        logger.info(f"Resultados exportados a CSV: {filename} ({rows_exported} filas)")
        return True
    except Exception as e:
        logger.error(f"Error exportando a CSV: {e}")
        return False

def generate_pdf(results, filename_or_buffer, from_date=None, to_date=None):
    """Genera PDF con logo, título y tabla con filtro opcional por fechas"""
    def in_date_range(scan_date):
        if not from_date and not to_date:
            return True
        if not scan_date:
            return False

        if isinstance(scan_date, datetime):
            dt = scan_date
        else:
            try:
                clean_str = scan_date.split('.')[0]
                dt = datetime.strptime(clean_str, '%Y-%m-%d %H:%M:%S')
            except Exception:
                return False

        after_from = True if not from_date else dt >= from_date
        before_to = True if not to_date else dt <= to_date
        return after_from and before_to

    try:
        doc = SimpleDocTemplate(filename_or_buffer, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()

        logo_path = os.path.join(os.path.dirname(__file__), 'static', 'logo_usfq.png')
        if os.path.exists(logo_path):
            logo = Image(logo_path, width=5 * cm, height=1.5 * cm)
            logo.hAlign = 'CENTER'
            story.append(logo)
            story.append(Spacer(1, 12))

        title_style = ParagraphStyle(
            'TitleCentered',
            parent=styles['Title'],
            alignment=TA_CENTER,
            fontSize=16,
            spaceAfter=12
        )
        story.append(Paragraph("Resultados del Escaneo de Puertos", title_style))
        story.append(Spacer(1, 12))

        data = [['IP', 'Hostname', 'Puerto', 'Estado', 'Servicio', 'Fecha']]
        rows_added = 0
        
        for entry in results:
            raw_scan_date = entry.get('scan_date')

            if isinstance(raw_scan_date, datetime):
                display_date = raw_scan_date.strftime('%Y-%m-%d %H:%M:%S')
            elif raw_scan_date:
                display_date = raw_scan_date.split('.')[0]
            else:
                display_date = 'Fecha no disponible'

            if from_date or to_date:
                if not in_date_range(raw_scan_date):
                    continue

            ip = entry.get('ip', '')
            hostname = entry.get('hostname', '')
            for p in entry.get('ports', []):
                data.append([
                    ip,
                    hostname,
                    str(p.get('port', '')),
                    p.get('state', ''),
                    p.get('service', ''),
                    display_date
                ])
                rows_added += 1

        table = Table(data, repeatRows=1, hAlign='LEFT')
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4CAF50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
        ]))
        story.append(table)

        doc.build(story)
        logger.info(f"PDF generado: {filename_or_buffer} ({rows_added} filas)")
        return True
    except Exception as e:
        logger.error(f"Error generando PDF: {e}")
        return False

# ========== ESTADÍSTICAS Y GRÁFICOS ==========
def get_port_stats():
    """Obtiene estadísticas de puertos desde la BD"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM scan_results")
            total = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM scan_results WHERE state='ABIERTO'")
            open_ports = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM scan_results WHERE state='CERRADO'")
            closed_ports = c.fetchone()[0]
            c.execute(
                "SELECT port, service, COUNT(*) as cnt "
                "FROM scan_results WHERE state='ABIERTO' "
                "GROUP BY port, service ORDER BY cnt DESC LIMIT 10"
            )
            top = c.fetchall()
        
        return {
            'total_ports': total,
            'open_ports': open_ports,
            'closed_ports': closed_ports,
            'top_ports': top
        }
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas: {e}")
        return {
            'total_ports': 0,
            'open_ports': 0,
            'closed_ports': 0,
            'top_ports': []
        }

def create_port_chart():
    """Crea gráfico circular de estadísticas de puertos"""
    try:
        stats = get_port_stats()
        labels = ['Abiertos', 'Cerrados']
        sizes = [stats['open_ports'], stats['closed_ports']]
        
        if sum(sizes) == 0:
            fig, ax = plt.subplots(figsize=(6, 6))
            ax.text(0.5, 0.5, 'No hay datos\nde puertos', 
                   ha='center', va='center', fontsize=14, color='gray')
            ax.axis('off')
        else:
            fig, ax = plt.subplots(figsize=(8, 8))
            colors = ['#4CAF50', '#F44336']
            ax.pie(sizes, labels=labels, autopct='%1.1f%%', colors=colors, 
                  startangle=90, shadow=True)
            ax.axis('equal')
            plt.title('Estadísticas de Puertos', fontsize=16)
        
        buf = BytesIO()
        plt.tight_layout()
        fig.savefig(buf, format='png', dpi=100, bbox_inches='tight')
        buf.seek(0)
        plt.close(fig)
        
        img_data = base64.b64encode(buf.read()).decode('utf-8')
        buf.close()
        return img_data
    except Exception as e:
        logger.error(f"Error creando gráfico circular: {e}")
        return ""

def create_bar_chart(ip, ports=None, scan_date=None):
    """Dibuja barras para una IP específica"""
    try:
        if ports is not None:
            all_ports = [(p['port'], p['state']) for p in ports]
        else:
            if scan_date:
                with get_db_connection() as conn:
                    c = conn.cursor()
                    c.execute("""
                        SELECT port, state FROM scan_results
                        WHERE ip = ? AND scan_date LIKE ?
                        ORDER BY port
                    """, (ip, f"{scan_date}%"))
                    all_ports = c.fetchall()
            else:
                all_ports = get_latest_ports_for_ip(ip)
    except Exception as e:
        logger.error(f"Error obteniendo puertos para gráfico de {ip}: {e}")
        all_ports = []

    filtered = all_ports[:10]

    fig, ax = plt.subplots(figsize=(10, 6))
    if not filtered:
        ax.text(0.5, 0.5, f'No hay puertos para {ip}', 
               ha='center', va='center', fontsize=14, color='gray')
        ax.axis('off')
    else:
        ports_list, states_list = zip(*filtered) if filtered else ([], [])
        labels = [f"{p}\n{s}" for p, s in filtered]
        
        bar_colors = []
        for state in states_list:
            if state == 'ABIERTO':
                bar_colors.append('#4CAF50')
            elif state == 'CERRADO':
                bar_colors.append('#F44336')
            else:
                bar_colors.append('#FFC107')
        
        y_pos = range(len(labels))
        ax.barh(y_pos, [1]*len(labels), color=bar_colors)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(labels, fontsize=11)
        ax.set_xlabel('Estado', fontsize=12)
        ax.set_title(f'Puertos escaneados - {ip}', fontsize=16, pad=20)
        ax.set_xlim([0, 1.2])
        
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor='#4CAF50', label='Abierto'),
            Patch(facecolor='#F44336', label='Cerrado'),
            Patch(facecolor='#FFC107', label='Otro')
        ]
        ax.legend(handles=legend_elements, loc='upper right')
        
        plt.tight_layout(pad=3.0)

    buf = BytesIO()
    fig.savefig(buf, format='png', dpi=100, bbox_inches='tight')
    buf.seek(0)
    img_b64 = base64.b64encode(buf.read()).decode('utf-8')
    buf.close()
    plt.close(fig)
    return img_b64

# ========== FUNCIONES AUXILIARES ==========
def generate_ip_range(subnet):
    """Genera todas las IPs de una subred CIDR"""
    try:
        network = ip_network(subnet, strict=False)
        ips = [str(ip) for ip in network.hosts()]
        logger.info(f"Generado rango: {subnet} -> {len(ips)} IPs")
        return ips
    except Exception as e:
        logger.error(f"Error generando rango IP {subnet}: {e}")
        return []

def validate_ip(ip):
    """Valida si una dirección IP es válida"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def check_nmap_availability():
    """Verifica que nmap esté disponible en el sistema"""
    try:
        nm = nmap.PortScanner()
        nm.scan('127.0.0.1', '22', arguments='-Pn')
        logger.info("Nmap está disponible y funcionando")
        return True
    except nmap.PortScannerError as e:
        logger.error(f"Nmap no disponible: {e}")
        return False
    except Exception as e:
        logger.error(f"Error verificando Nmap: {e}")
        return False

# ========== INICIALIZACIÓN ==========
def initialize_scanner():
    """Inicializa todos los componentes del escáner"""
    init_db()
    
    if not check_nmap_availability():
        logger.error("Nmap no está disponible. Instálalo con:")
        logger.error("  Ubuntu/Debian: sudo apt-get install nmap")
        logger.error("  CentOS/RHEL: sudo yum install nmap")
        logger.error("  macOS: brew install nmap")
        return False
    
    logger.info("Escáner inicializado correctamente")
    return True

# ========== EJEMPLOS DE USO ==========
if __name__ == "__main__":
    # Inicializar el escáner
    if not initialize_scanner():
        exit(1)
    
    print("=" * 70)
    print("🚀 ESCÁNER DE PUERTOS MULTIHILO OPTIMIZADO")
    print("=" * 70)
    
    # Ejemplo 1: Escaneo normal (recomendado para redes grandes)
    print("\n📋 EJEMPLO 1: Escaneo normal (puerto 10050 + puertos comunes)")
    print("""
    ips = generate_ip_range('192.168.1.0/24')
    results = scan_ips(
        ips=ips,
        specific_port=10050,
        run_nmap_scan=True,
        full_nmap_scan=False,
        max_threads=50,
        batch_size=100
    )
    """)
    
    # Ejemplo 2: Escaneo completo (solo redes pequeñas)
    print("\n📋 EJEMPLO 2: Escaneo completo (solo para redes pequeñas)")
    print("""
    ips = generate_ip_range('10.0.0.0/28')  # Solo 14 IPs
    results = scan_ips(
        ips=ips,
        specific_port=10050,
        run_nmap_scan=True,
        full_nmap_scan=True,  # ¡Cuidado! Esto es lento
        max_threads=20,
        batch_size=50
    )
    """)
    
    # Ejemplo 3: Escaneo por etapas (más eficiente)
    print("\n📋 EJEMPLO 3: Escaneo por etapas (óptimo para redes grandes)")
    print("""
    ips = generate_ip_range('172.21.0.0/24')
    results = scan_ips_staged(
        ips=ips,
        specific_port=10050,
        run_nmap_scan=True,
        full_nmap_scan=False,
        max_threads=100
    )
    """)
