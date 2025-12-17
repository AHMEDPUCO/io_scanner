import base64
import os
from datetime import datetime
import sqlite3
from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from werkzeug.utils import secure_filename
import math
from io import BytesIO
import ipaddress  # <-- ¡Nuevo!
import uuid
import threading
from flask import jsonify


from vlan_classifier import (
    crear_base_datos,
    insertar_ips,
    obtener_vlans_disponibles,
    filtrar_ips_por_vlan_tipo
)
from web_scanner import (
    init_db,
    scan_ips,
    save_to_db,
    export_to_txt,
    export_to_csv,
    generate_pdf,
    get_port_stats,
    create_bar_chart,
    create_port_chart,
    DATABASE
)

# --- App Setup ---
PAGE_SIZE_DEFAULT = 100
MAX_IPS_ALLOWED = 256  # Límite razonable para evitar sobrecarga
JOBS = {}
JOBS_LOCK = threading.Lock()


app = Flask(__name__)
app.secret_key = 'tu_clave_secreta_aqui'  # Necesario para flash messages
app.config['UPLOAD_FOLDER'] = 'uploads'

app.jinja_env.globals.update(
    create_bar_chart=create_bar_chart,
    create_port_chart=create_port_chart
)


@app.context_processor
def inject_now():
    return {'now': datetime.now()}


# --- Función crítica: expandir y validar IPs/CIDR ---
def expand_and_validate_ips(raw_input_list):
    """
    Toma una lista de strings (IPs o rangos CIDR) y devuelve una lista de IPs individuales válidas.
    Lanza ValueError si hay entradas inválidas o exceso de IPs.
    """
    expanded = []
    for item in raw_input_list:
        item = item.strip()
        if not item:
            continue
        try:
            # Intentar como red CIDR
            net = ipaddress.ip_network(item, strict=False)
            # Evitar redes demasiado grandes
            if net.num_addresses > MAX_IPS_ALLOWED:
                raise ValueError(
                    f"Rango demasiado grande: {item} ({net.num_addresses} direcciones). Máx. permitido: {MAX_IPS_ALLOWED}")
            # Excluir red y broadcast (hosts)
            ips_in_net = [str(ip) for ip in net.hosts()]
            expanded.extend(ips_in_net)
        except ValueError:
            # Si no es red, intentar como IP individual
            try:
                ipaddress.ip_address(item)
                expanded.append(item)
            except ValueError:
                raise ValueError(f"Entrada inválida (no es IP ni rango CIDR): {item}")

    if len(expanded) == 0:
        raise ValueError("No se encontraron IPs válidas.")
    if len(expanded) > MAX_IPS_ALLOWED:
        raise ValueError(f"Demasiadas IPs generadas: {len(expanded)}. Máximo permitido: {MAX_IPS_ALLOWED}")

    return expanded


# --- Inicialización de bases de datos ---
init_db()
db_file = 'ip_database.db'
if os.path.exists(db_file):
    os.remove(db_file)
crear_base_datos()


def ensure_indexes():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("CREATE INDEX IF NOT EXISTS idx_scan_ip ON scan_results(ip)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_scan_date ON scan_results(scan_date)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_scan_ip_date ON scan_results(ip, scan_date)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_scan_state ON scan_results(state)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_scan_service ON scan_results(service)")
    conn.commit()
    conn.close()


ensure_indexes()


# --- Funciones auxiliares ---
def get_pagination():
    try:
        page = int(request.args.get('page', 1))
    except:
        page = 1
    try:
        per_page = int(request.args.get('per_page', PAGE_SIZE_DEFAULT))
    except:
        per_page = PAGE_SIZE_DEFAULT
    page = max(1, page)
    per_page = max(5, min(per_page, 500))
    offset = (page - 1) * per_page
    return page, per_page, offset


def fetch_stats():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    # ... (tu función fetch_stats() original, sin cambios)
    # [Mantén todo igual aquí]
    c.execute("SELECT COUNT(DISTINCT ip) FROM scan_results")
    total_hosts = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM scan_results")
    total_registros = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM scan_results WHERE state = 'ABIERTO'")
    total_abiertos = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM scan_results WHERE state = 'CERRADO'")
    total_cerrados = c.fetchone()[0] or 0
    c.execute("""
              SELECT port, COUNT(*) as cnt
              FROM scan_results
              WHERE state IN ('ABIERTO', 'open')
              GROUP BY port
              ORDER BY cnt DESC LIMIT 10
              """)
    top_ports_open = [tuple(row) for row in c.fetchall()]
    c.execute("""
              SELECT port, COUNT(*) as cnt
              FROM scan_results
              GROUP BY port
              ORDER BY cnt DESC LIMIT 10
              """)
    top_ports_all = [tuple(row) for row in c.fetchall()]
    c.execute("""
              SELECT COALESCE(service, '(desconocido)') AS svc,
                     COUNT(*)                           AS cnt
              FROM scan_results
              WHERE state IN ('ABIERTO', 'open')
              GROUP BY svc
              ORDER BY cnt DESC LIMIT 10
              """)
    top_services_open = [tuple(row) for row in c.fetchall()]
    c.execute("""
              SELECT COALESCE(service, '(desconocido)') as svc, COUNT(*) as cnt
              FROM scan_results
              GROUP BY svc
              ORDER BY cnt DESC LIMIT 10
              """)
    top_services_all = [tuple(row) for row in c.fetchall()]
    c.execute("""
              SELECT substr(COALESCE(scan_date, ''), 1, 10) as d, COUNT(DISTINCT ip) as n
              FROM scan_results
              WHERE scan_date IS NOT NULL
                AND scan_date <> ''
              GROUP BY d
              ORDER BY d ASC LIMIT 90
              """)
    per_day = c.fetchall()
    c.execute("""
              WITH last_scans AS (SELECT ip, MAX(scan_date) AS last_dt
                                  FROM scan_results
                                  WHERE scan_date IS NOT NULL
                                    AND scan_date <> ''
                                  GROUP BY ip)
              SELECT AVG(cnt)
              FROM (SELECT r.ip, COUNT(*) as cnt
                    FROM scan_results r
                             JOIN last_scans ls ON r.ip = ls.ip AND r.scan_date = ls.last_dt
                    WHERE r.state = 'ABIERTO'
                    GROUP BY r.ip)
              """)
    avg_open_per_host = c.fetchone()[0] or 0.0
    c.execute("""
              WITH last_scans AS (SELECT ip, MAX(scan_date) AS last_dt
                                  FROM scan_results
                                  WHERE scan_date IS NOT NULL
                                    AND scan_date <> ''
                                  GROUP BY ip),
                   snapshot AS (SELECT r.ip, r.state
                                FROM scan_results r
                                         JOIN last_scans ls ON r.ip = ls.ip AND r.scan_date = ls.last_dt)
              SELECT CASE
                         WHEN LOWER(state) IN ('open', 'abierto') THEN 'ABIERTO'
                         WHEN LOWER(state) IN ('closed', 'cerrado') THEN 'CERRADO'
                         WHEN LOWER(state) IN ('filtered', 'filtrado') THEN 'FILTRADO'
                         ELSE 'OTRO'
                         END AS estado_normalizado,
                     COUNT(*)
              FROM snapshot
              GROUP BY estado_normalizado
              """)
    dist_estado = dict(c.fetchall())
    conn.close()
    return {
        "total_hosts": total_hosts,
        "total_registros": total_registros,
        "total_abiertos": total_abiertos,
        "total_cerrados": total_cerrados,
        "top_ports": top_ports_open,
        "top_services": top_services_open,
        "top_ports_all": top_ports_all,
        "top_services_all": top_services_all,
        "per_day": per_day,
        "avg_open_per_host": round(float(avg_open_per_host), 2),
        "dist_estado": dist_estado
    }


def get_hosts_for_clause(where_clause: str):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    query = f"""
        SELECT DISTINCT ip, COALESCE(hostname, ''), port, state, MAX(scan_date) as last_seen
        FROM scan_results
        WHERE {where_clause}
        GROUP BY ip, hostname, port, state
        ORDER BY ip, port
    """
    c.execute(query)
    rows = c.fetchall()
    conn.close()
    return [
        {
            "ip": r[0],
            "hostname": r[1],
            "port": r[2],
            "state": r[3],
            "last_seen": (r[4] or '')
        }
        for r in rows
    ]


# --- Rutas ---
@app.route('/', methods=['GET', 'POST'])
def index():
    stats = get_port_stats()
    port_chart = create_port_chart()
    if request.method == 'POST':
        data = ''
        if 'file' in request.files and request.files['file'].filename:
            f = request.files['file']
            if not f.filename.endswith('.txt'):
                return render_template('index.html', error='Solo archivos .txt permitidos', stats=stats,
                                       port_chart=port_chart)
            data = f.read().decode('utf-8')
        else:
            data = request.form.get('ips', '')

        raw_ips = [ip.strip() for ip in data.replace(',', '\n').split('\n') if ip.strip()]
        if not raw_ips:
            return render_template('index.html', error='Ingrese al menos una IP o rango CIDR', stats=stats,
                                   port_chart=port_chart)

        try:
            ips = expand_and_validate_ips(raw_ips)
        except ValueError as e:
            return render_template('index.html', error=str(e), stats=stats, port_chart=port_chart)

        try:
            specific_port = int(request.form.get('port', 10050))
        except ValueError:
            specific_port = 10050
        run_nmap = 'run_nmap_scan' in request.form
        full_nmap = 'full_nmap_scan' in request.form

        results = scan_ips(
            ips=ips,
            specific_port=specific_port,
            run_nmap_scan=run_nmap,
            full_nmap_scan=full_nmap,

        )

        for entry in results:
            for p in entry['ports']:
                scan_date = entry.get('scan_date')
                save_to_db(entry['ip'], entry.get('hostname', ''), p['port'], p['state'], p['service'], scan_date=scan_date)
        export_to_txt(results, 'resultados.txt')
        export_to_csv(results, 'resultados.csv')
        generate_pdf(results, 'resultados.pdf')

        return render_template('results.html', results=results)

    return render_template('index.html', stats=stats, port_chart=port_chart)


@app.route('/clasificar_ips', methods=['GET', 'POST'])
def clasificar_ips():
    if request.method == 'GET':
        return render_template('seleccionar_vlan.html', vlans=None)

    ips_list = []
    manual = request.form.get('ips_manual', '').strip()
    if manual:
        ips_list += [ip.strip() for ip in manual.splitlines() if ip.strip()]

    archivo = request.files.get('ips_archivo')
    if archivo and archivo.filename.endswith('.txt'):
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(archivo.filename))
        archivo.save(path)
        with open(path) as f:
            ips_list += [l.strip() for l in f if l.strip()]

    if not ips_list:
        return render_template('seleccionar_vlan.html', error='No se proporcionaron IPs', vlans=None)

    try:
        ips_validas = expand_and_validate_ips(ips_list)
    except ValueError as e:
        return render_template('seleccionar_vlan.html', error=str(e), vlans=None)

    if os.path.exists(db_file):
        os.remove(db_file)
    crear_base_datos()
    insertar_ips(ips_validas)

    vlans = obtener_vlans_disponibles()
    return render_template('seleccionar_vlan.html', vlans=vlans)


@app.route('/escanear', methods=['POST'])
def escanear_vlan():
    vlan = request.form.get('vlan')
    tipo = request.form.get('tipo', 'Ambos')
    do_specific = 'modo_especifico' in request.form
    run_nmap = 'modo_basico' in request.form
    full_nmap = 'modo_completo' in request.form

    specific_port = None
    if do_specific:
        try:
            specific_port = int(request.form.get('puerto_personalizado', 10050))
        except ValueError:
            specific_port = 10050

    ips = filtrar_ips_por_vlan_tipo(int(vlan), tipo)
    app.logger.debug(f"IPs a escanear (VLAN {vlan}, tipo {tipo}): {ips}")

    # ¡Importante! Aunque ya están en la VLAN DB, podrían ser muchas → limitar
    if len(ips) > MAX_IPS_ALLOWED:
        return render_template('results.html',
                               error=f'Demasiadas IPs en la VLAN ({len(ips)}). Máx. permitido: {MAX_IPS_ALLOWED}')

    results = scan_ips(
        ips=ips,
        specific_port=specific_port,
        run_nmap_scan=run_nmap,
        full_nmap_scan=full_nmap
    )

    for entry in results:
        for p in entry['ports']:
            scan_date = entry.get('scan_date')
            save_to_db(entry['ip'], entry.get('hostname', ''), p['port'], p['state'], p['service'], scan_date=scan_date)
    export_to_txt(results, 'resultados.txt')
    export_to_csv(results, 'resultados.csv')
    generate_pdf(results, 'resultados.pdf')

    return render_template('results.html', results=results)


@app.route('/search', methods=['GET', 'POST'])
def search():
    ips_to_search = []
    scan_date_filter = None

    if request.method == 'POST':
        file = request.files.get('ip_file')
        if file and file.filename.endswith('.txt'):
            content = file.read().decode('utf-8')
            raw_ips = [ip.strip() for ip in content.replace(',', '\n').split('\n') if ip.strip()]
        else:
            ip_in = request.form.get('search_ip', '').strip()
            raw_ips = [ip_in] if ip_in else []
    else:
        ip_in = request.args.get('ip', '').strip()
        scan_date_filter = request.args.get('scan_date', None)
        DESCONOCIDOS = {'', 'None', 'null', 'NULL', 'Fecha_Desconocida', 'Fecha no disponible'}
        if scan_date_filter in DESCONOCIDOS:
            scan_date_filter = None
        raw_ips = [ip_in] if ip_in else []

    if not raw_ips:
        return render_template('search.html', error='Ingrese una IP, rango CIDR o archivo válido')

    try:
        ips_to_search = expand_and_validate_ips(raw_ips)
    except ValueError as e:
        return render_template('search.html', error=str(e))

    # Paginación
    page, per_page, offset = get_pagination()
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    results = []
    total = 0

    # Usar chunks si hay muchas IPs (aunque ya están limitadas a 256)
    placeholders = ",".join("?" * len(ips_to_search))
    params_base = ips_to_search.copy()

    if scan_date_filter:
        c.execute(f"""
            SELECT COUNT(*) FROM scan_results
            WHERE ip IN ({placeholders}) AND scan_date LIKE ?
        """, (*params_base, f"{scan_date_filter}%"))
        total = c.fetchone()[0] or 0

        c.execute(f"""
            SELECT ip, hostname, port, state, service, scan_date
            FROM scan_results
            WHERE ip IN ({placeholders}) AND scan_date LIKE ?
            ORDER BY ip, port
            LIMIT ? OFFSET ?
        """, (*params_base, f"{scan_date_filter}%", per_page, offset))
    else:
        c.execute(f"""
            SELECT COUNT(*) FROM scan_results
            WHERE ip IN ({placeholders})
        """, params_base)
        total = c.fetchone()[0] or 0

        c.execute(f"""
            SELECT ip, hostname, port, state, service, scan_date
            FROM scan_results
            WHERE ip IN ({placeholders})
            ORDER BY scan_date DESC, ip ASC, port ASC
            LIMIT ? OFFSET ?
        """, (*params_base, per_page, offset))

    results = c.fetchall()
    conn.close()

    if not results:
        return render_template('search.html', error='No se encontraron resultados')

    pages = max(1, math.ceil(total / per_page))

    # Si es una sola IP y con fecha, vista detallada
    if len(ips_to_search) == 1 and scan_date_filter:
        ip_param = ips_to_search[0]
        hostname = results[0][1] if results else 'Desconocido'
        ports = [{'port': r[2], 'state': r[3], 'service': r[4]} for r in results]
        return render_template(
            'search_results.html',
            ip=ip_param,
            hostname=hostname,
            scan_date=scan_date_filter,
            ports=ports,
            page=page, pages=pages, per_page=per_page, total=total
        )
    else:
        return render_template(
            'search_results.html',
            results=results,
            ip=', '.join(ips_to_search),
            page=page, pages=pages, per_page=per_page, total=total
        )


# --- Rutas restantes (sin cambios en lógica de IPs) ---
@app.route('/chart')
def chart():
    ip = request.args.get('ip')
    scan_date = request.args.get('scan_date')
    ports = []  # ← En una implementación real, deberías obtener los puertos aquí
    img_b64 = create_bar_chart(ip, ports=ports, scan_date=scan_date)
    buf = BytesIO(base64.b64decode(img_b64))
    return send_file(buf, mimetype='image/png', max_age=3600)


@app.route('/download/<filename>')
def download(filename):
    if filename == 'csv':
        return send_file('resultados.csv', as_attachment=True)
    if filename == 'pdf':
        return send_file('resultados.pdf', as_attachment=True)
    return 'Archivo no válido', 404


@app.route("/stats")
def stats():
    selected_tab = request.args.get("tab", "dashboard").lower()
    data = fetch_stats()
    service_lists = {
        "zabbix": get_hosts_for_clause("""
            LOWER(state) IN ('abierto', 'open', 'cerrado', 'close')
            AND (
                LOWER(service) LIKE '%zabbix%'
                OR port = 10050
            )
        """),
        "sql": get_hosts_for_clause("""
            LOWER(state) IN ('abierto', 'open', 'cerrado', 'close')
            AND (
                LOWER(service) LIKE '%mssql%'
                OR LOWER(service) LIKE '%mysql%'
                OR LOWER(service) LIKE '%postgres%'
                OR LOWER(service) LIKE '%oracle%' AND port NOT IN (1521, 2483, 2484)
                OR port IN (1433, 3306, 5432)
            )
            AND LOWER(service) NOT LIKE '%sqlmap%'
            AND LOWER(service) NOT LIKE '%injection%'
        """),
        "oracle": get_hosts_for_clause("""
            LOWER(state) IN ('abierto', 'open', 'cerrado', 'close')
            AND (
                LOWER(service) LIKE '%oracle%'
                OR port IN (1521, 2483, 2484)
            )
        """),
        "http": get_hosts_for_clause("""
            LOWER(state) IN ('abierto', 'open', 'cerrado', 'close')
            AND (
                (LOWER(service) LIKE '%http%' AND LOWER(service) NOT LIKE '%soap%' AND LOWER(service) NOT LIKE '%rtsp%')
                OR port IN (80, 443, 8080, 8443, 8000, 8888)
            )
        """),
        "rpcbind": get_hosts_for_clause("""
            LOWER(state) IN ('abierto', 'open', 'cerrado', 'close')
            AND (
                LOWER(service) LIKE '%rpcbind%'
                OR LOWER(service) LIKE '%portmap%'
                OR LOWER(service) LIKE '%sunrpc%'
                OR port = 111
            )
        """),
        "microsoft-ds": get_hosts_for_clause("""
            LOWER(state) IN ('abierto', 'open', 'cerrado', 'close')
            AND (
                LOWER(service) LIKE '%microsoft-ds%'
                OR port IN (445)
            )
        """),
        "RDP": get_hosts_for_clause("""
            LOWER(state) IN ('abierto', 'open', 'cerrado', 'close')
            AND (
                LOWER(service) LIKE '%RDP%'
                OR port IN (3389)
            )
        """),
        "LDAP": get_hosts_for_clause("""
            LOWER(state) IN ('abierto', 'open', 'cerrado', 'close')
            AND (
                LOWER(service) LIKE '%LDAP%'
                OR port IN (389,636,3268,3269)
            )
        """),
    }
    return render_template(
        "stats.html",
        **data,
        selected_tab=selected_tab,
        service_lists=service_lists,
        now=datetime.now()
    )


@app.route('/download_ip/<path:ip>/<filetype>')
def download_ip(ip, filetype):
    try:
        scan_date_filter = request.args.get('scan_date', None)
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        if scan_date_filter:
            c.execute("""
                      SELECT ip, hostname, port, state, service, scan_date
                      FROM scan_results
                      WHERE ip = ?
                        AND scan_date LIKE ?
                      ORDER BY port
                      """, (ip, f"{scan_date_filter}%"))
        else:
            c.execute("""
                      SELECT s1.ip, s1.hostname, s1.port, s1.state, s1.service, s1.scan_date
                      FROM scan_results s1
                               JOIN (SELECT ip, port, MAX(scan_date) AS max_date
                                     FROM scan_results
                                     WHERE ip = ?
                                     GROUP BY port) s2
                                    ON s1.ip = s2.ip AND s1.port = s2.port AND s1.scan_date = s2.max_date
                      WHERE s1.ip = ?
                      ORDER BY s1.port
                      """, (ip, ip))
        rows = c.fetchall()
        conn.close()
        if not rows:
            return 'No hay resultados', 404
        grouped_results = {}
        for row in rows:
            ip, hostname, port, state, service, scan_date = row
            scan_date_str = scan_date.split('.')[0] if scan_date else 'Fecha no disponible'
            if scan_date_str not in grouped_results:
                grouped_results[scan_date_str] = {
                    'ip': ip,
                    'hostname': hostname,
                    'scan_date': scan_date_str,
                    'ports': []
                }
            grouped_results[scan_date_str]['ports'].append({
                'port': port,
                'state': state,
                'service': service
            })
        results = list(grouped_results.values())
        if filetype == 'csv':
            export_to_csv(results, f'scan_{ip}.csv')
            return send_file(f'scan_{ip}.csv', as_attachment=True)
        if filetype == 'pdf':
            buf = BytesIO()
            generate_pdf(results, buf)
            buf.seek(0)
            return send_file(
                buf,
                as_attachment=True,
                download_name=f'scan_{ip}.pdf',
                mimetype='application/pdf'
            )
        return 'Formato no válido', 400
    except Exception as e:
        return f'Error: {e}', 500

@app.route('/api/scan/start', methods=['POST'])
def api_scan_start():
    # 1) leer ips exactamente como ya haces en index() POST
    data = ''
    if 'file' in request.files and request.files['file'].filename:
        f = request.files['file']
        if not f.filename.endswith('.txt'):
            return jsonify({"ok": False, "error": "Solo archivos .txt permitidos"}), 400
        data = f.read().decode('utf-8')
    else:
        data = request.form.get('ips', '')

    raw_ips = [ip.strip() for ip in data.replace(',', '\n').split('\n') if ip.strip()]
    if not raw_ips:
        return jsonify({"ok": False, "error": "Ingrese al menos una IP o rango CIDR"}), 400

    try:
        ips = expand_and_validate_ips(raw_ips)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    try:
        specific_port = int(request.form.get('port', 10050))
    except ValueError:
        specific_port = 10050

    run_nmap = 'run_nmap_scan' in request.form
    full_nmap = 'full_nmap_scan' in request.form

    job_id = uuid.uuid4().hex

    with JOBS_LOCK:
        JOBS[job_id] = {
            "status": "running",
            "done": 0,
            "total": len(ips),
            "progress": 0,
            "error": None,
            "results": None
        }

    def worker():
        def progress_cb(done, total, ip):
            pct = int((done / max(1, total)) * 100)
            with JOBS_LOCK:
                if job_id in JOBS:
                    JOBS[job_id]["done"] = done
                    JOBS[job_id]["total"] = total
                    JOBS[job_id]["progress"] = min(99, pct)  # 99 hasta terminar

        try:
            results = scan_ips(
                ips=ips,
                specific_port=specific_port,
                run_nmap_scan=run_nmap,
                full_nmap_scan=full_nmap,
                progress_callback=progress_cb
            )

            for entry in results:
                for p in entry['ports']:
                    scan_date = entry.get('scan_date')
                    save_to_db(entry['ip'], entry.get('hostname', ''), p['port'], p['state'], p['service'], scan_date=scan_date)

            export_to_txt(results, 'resultados.txt')
            export_to_csv(results, 'resultados.csv')
            generate_pdf(results, 'resultados.pdf')

            with JOBS_LOCK:
                JOBS[job_id]["results"] = results
                JOBS[job_id]["status"] = "done"
                JOBS[job_id]["progress"] = 100

        except Exception as e:
            with JOBS_LOCK:
                JOBS[job_id]["status"] = "error"
                JOBS[job_id]["error"] = str(e)

    threading.Thread(target=worker, daemon=True).start()

    return jsonify({"ok": True, "job_id": job_id})


@app.route('/api/scan/progress/<job_id>')
def api_scan_progress(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return jsonify({"ok": False, "error": "Job no encontrado"}), 404
        return jsonify({"ok": True, **job})


@app.route('/scan/results/<job_id>')
def scan_results(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return render_template('results.html', error="Job no encontrado")
        if job["status"] == "error":
            return render_template('results.html', error=job["error"])
        if job["status"] != "done":
            return render_template('results.html', error="Aún no termina el escaneo")

        results = job["results"]

    return render_template('results.html', results=results)

@app.route('/history')
def history():
    page, per_page, offset = get_pagination()
    ip = request.args.get('ip', '').strip() or None
    from_date = request.args.get('from_date') or None
    to_date = request.args.get('to_date') or None
    where = []
    params = []
    if ip:
        where.append("ip = ?")
        params.append(ip)
    if from_date:
        where.append("DATE(scan_date) >= DATE(?)")
        params.append(from_date)
    if to_date:
        where.append("DATE(scan_date) <= DATE(?)")
        params.append(to_date)
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    count_sql = f"SELECT COUNT(*) FROM scan_results {where_sql}"
    data_sql = f"""
        SELECT id, ip, hostname, port, state, service, scan_date
        FROM scan_results
        {where_sql}
        ORDER BY COALESCE(scan_date,'') DESC, ip ASC, port ASC
        LIMIT ? OFFSET ?
    """
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute(count_sql, params)
    total = c.fetchone()[0] or 0
    c.execute(data_sql, (*params, per_page, offset))
    scans = c.fetchall()
    conn.close()
    pages = max(1, math.ceil(total / per_page))
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        scan_list = []
        for s in scans:
            scan_list.append({
                'id': s[0],
                'ip': s[1],
                'hostname': s[2] or '—',
                'port': s[3],
                'state': s[4],
                'service': s[5] or 'Desconocido',
                'scan_date': s[6] or '—'
            })
        return {
            'scans': scan_list,
            'page': page,
            'pages': pages,
            'total': total,
            'first_item': ((page - 1) * per_page) + 1 if total > 0 else 0,
            'last_item': min(page * per_page, total) if total > 0 else 0
        }
    return render_template(
        'history.html',
        active_page='history',
        scans=scans,
        page=page, pages=pages, per_page=per_page, total=total,
        ip=ip, from_date=from_date, to_date=to_date
    )


@app.route('/ip/<path:ip>')
def view_ip_results(ip):
    return redirect(url_for('search', ip=ip))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
