from flask import Flask, request, Response, jsonify, session, render_template
import sqlite3
import os
import requests
import secrets
import sys
import socket
import ipaddress
import threading
import time
from functools import wraps
from datetime import datetime
from zoneinfo import ZoneInfo
from urllib.parse import unquote, urlparse, urljoin


app = Flask(__name__)

DATABASE = "/app/data/app.db"

INITIAL_USERNAME = os.environ.get(
    "INITIAL_USERNAME",
    "Admin"
)

INITIAL_API_KEY = os.environ.get(
    "INITIAL_API_KEY"
)

if not INITIAL_API_KEY:
    raise RuntimeError(
        "INITIAL_API_KEY non configurata"
    )

FLASK_SECRET_KEY = os.environ.get(
    "FLASK_SECRET_KEY"
)

if not FLASK_SECRET_KEY:
    raise RuntimeError(
        "FLASK_SECRET_KEY non configurata"
    )

app.secret_key = FLASK_SECRET_KEY

API_KEY_ALPHABET = (
    "ABCDEFGHJKLMNPQRSTUVWXYZ"
    "abcdefghijkmnopqrstuvwxyz"
    "23456789"
)

API_KEY_LENGTH = 9

URL_CHECK_TIMEOUT = 10

USER_AGENT = "URL-Monitor/1.0"


# ============================================================
# SSRF PROTECTION
# ============================================================

MAX_REDIRECTS = 5

MAX_URL_LENGTH = 2048

ALLOWED_URL_PORTS = {
    80,
    443
}


def is_safe_ip(ip_string):
    """
    Restituisce True solamente per IP globalmente instradabili.

    Vengono quindi bloccati:
    - loopback
    - private
    - link-local
    - multicast
    - reserved
    - unspecified
    - altre reti non globali
    """

    try:
        ip = ipaddress.ip_address(
            ip_string
        )

    except ValueError:
        return False

    return ip.is_global


def resolve_hostname(hostname, port):
    """
    Risolve l'hostname e verifica tutti gli indirizzi restituiti.

    L'hostname viene considerato sicuro solamente se tutti gli
    indirizzi risolti sono globalmente instradabili.
    """

    try:
        results = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM
        )

    except socket.gaierror:
        return False

    if not results:
        return False

    for result in results:

        sockaddr = result[4]

        if not sockaddr:
            return False

        ip_address = sockaddr[0]

        if not is_safe_ip(
            ip_address
        ):
            return False

    return True


def validate_monitor_url(url):
    """
    Valida un URL prima che venga utilizzato dal monitor.

    Protegge principalmente contro SSRF verso:
    - localhost
    - loopback
    - reti private
    - link-local
    - multicast
    - reserved
    - reti non globali
    - porte diverse da 80/443
    """

    if not isinstance(url, str):
        return False

    if not url:
        return False

    if len(url) > MAX_URL_LENGTH:
        return False

    try:
        parsed = urlparse(
            url
        )

    except ValueError:
        return False

    if parsed.scheme not in (
        "http",
        "https"
    ):
        return False

    if not parsed.hostname:
        return False

    try:
        hostname = parsed.hostname
        port = parsed.port

    except ValueError:
        return False

    if port is None:
        port = (
            443
            if parsed.scheme == "https"
            else 80
        )

    if port not in ALLOWED_URL_PORTS:
        return False

    # Se l'hostname è direttamente un IP,
    # lo verifichiamo senza DNS.
    try:

        ip_address = ipaddress.ip_address(
            hostname
        )

        return is_safe_ip(
            str(ip_address)
        )

    except ValueError:
        pass

    hostname_lower = hostname.rstrip(
        "."
    ).lower()

    if hostname_lower in (
        "localhost",
        "localhost.localdomain"
    ):
        return False

    # Per gli hostname verifichiamo
    # tutti gli indirizzi restituiti dal DNS.
    return resolve_hostname(
        hostname,
        port
    )


# ============================================================
# RATE LIMITING
# ============================================================

RATE_LIMITS = {
    "login": {
        "limit": 10,
        "window": 60
    },

    "public": {
        "limit": 60,
        "window": 60
    },

    "url_check": {
        "limit": 30,
        "window": 60
    }
}


rate_limit_store = {}

rate_limit_lock = threading.Lock()


def get_rate_limit_key():
    """
    Usa l'indirizzo IP remoto come identificatore.

    Non viene utilizzato X-Forwarded-For per evitare che un client
    possa falsificare direttamente il proprio identificatore.
    """

    return request.remote_addr or "unknown"


def rate_limit(name):
    """
    Rate limiter in-memory con finestra temporale fissa.

    Nota:
    il limiter è locale al processo Python.
    Se vengono utilizzati più worker/processi,
    ogni worker avrà il proprio contatore.
    """

    if name not in RATE_LIMITS:
        raise ValueError(
            f"Rate limit non configurato: {name}"
        )

    config = RATE_LIMITS[name]

    limit = config["limit"]
    window = config["window"]

    def decorator(function):

        @wraps(function)
        def wrapped(*args, **kwargs):

            key = (
                name,
                get_rate_limit_key()
            )

            now = time.monotonic()

            with rate_limit_lock:

                entry = rate_limit_store.get(
                    key
                )

                if entry is None:

                    rate_limit_store[key] = {
                        "start": now,
                        "count": 1
                    }

                else:

                    elapsed = (
                        now - entry["start"]
                    )

                    if elapsed >= window:

                        rate_limit_store[key] = {
                            "start": now,
                            "count": 1
                        }

                    else:

                        if entry["count"] >= limit:

                            retry_after = max(
                                1,
                                int(
                                    window - elapsed
                                )
                            )

                            response = jsonify({
                                "error":
                                    "Rate limit superato"
                            })

                            response.status_code = 429

                            response.headers[
                                "Retry-After"
                            ] = str(
                                retry_after
                            )

                            return response

                        entry["count"] += 1

            return function(
                *args,
                **kwargs
            )

        return wrapped

    return decorator


def cleanup_rate_limit_store():
    """
    Rimuove periodicamente le entry obsolete.
    """

    while True:

        time.sleep(300)

        now = time.monotonic()

        with rate_limit_lock:

            expired_keys = []

            for key, entry in rate_limit_store.items():

                if (
                    now - entry["start"]
                ) > 600:

                    expired_keys.append(
                        key
                    )

            for key in expired_keys:

                rate_limit_store.pop(
                    key,
                    None
                )


rate_limit_cleanup_thread = threading.Thread(
    target=cleanup_rate_limit_store,
    daemon=True
)

rate_limit_cleanup_thread.start()


# ============================================================
# DATABASE
# ============================================================

def get_db():

    os.makedirs(
        os.path.dirname(DATABASE),
        exist_ok=True
    )

    conn = sqlite3.connect(
        DATABASE,
        timeout=30
    )

    conn.row_factory = sqlite3.Row

    return conn


def current_datetime():

    return datetime.now(
        ZoneInfo("Europe/Rome")
    ).strftime(
        "%a %b %d %H:%M:%S %Z %Y"
    )


def initialize_database():

    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            nomeutente TEXT PRIMARY KEY,
            apikey TEXT UNIQUE NOT NULL,
            admin INTEGER NOT NULL DEFAULT 0,
            available INTEGER NOT NULL DEFAULT 1
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS urls (
            url TEXT PRIMARY KEY,
            stato INTEGER NOT NULL DEFAULT 0,
            last_check TEXT
        )
    """)

    conn.execute("""
        INSERT OR IGNORE INTO users
        (
            nomeutente,
            apikey,
            admin,
            available
        )
        VALUES (?, ?, 1, 1)
    """, (
        INITIAL_USERNAME,
        INITIAL_API_KEY
    ))

    conn.commit()

    conn.close()


# ============================================================
# AUTHENTICATION
# ============================================================

def generate_api_key():

    return "".join(
        secrets.choice(API_KEY_ALPHABET)
        for _ in range(API_KEY_LENGTH)
    )


def generate_unique_api_key():

    while True:

        api_key = generate_api_key()

        conn = get_db()

        existing = conn.execute("""
            SELECT 1
            FROM users
            WHERE apikey = ?
        """, (
            api_key,
        )).fetchone()

        conn.close()

        if existing is None:
            return api_key


def get_user_by_api_key(api_key):

    if not api_key:
        return None

    conn = get_db()

    user = conn.execute("""
        SELECT
            nomeutente,
            apikey,
            admin,
            available
        FROM users
        WHERE apikey = ?
    """, (
        api_key,
    )).fetchone()

    conn.close()

    return user


def is_admin():

    return (
        session.get("authenticated") is True
        and session.get("admin") == 1
    )


# ============================================================
# URL CHECK
# ============================================================

def check_url_status(url):
    """
    Controlla un URL applicando SSRF protection
    ad ogni redirect.

    I redirect vengono gestiti manualmente invece di usare
    allow_redirects=True, così ogni destinazione viene
    verificata prima della richiesta successiva.
    """

    current_url = url

    for redirect_number in range(
        MAX_REDIRECTS + 1
    ):

        # ----------------------------------------------------
        # SSRF CHECK
        # ----------------------------------------------------

        if not validate_monitor_url(
            current_url
        ):

            return (
                0,
                current_url
            )

        try:

            response = requests.get(
                current_url,
                timeout=URL_CHECK_TIMEOUT,
                allow_redirects=False,
                headers={
                    "User-Agent": USER_AGENT
                }
            )

            status_code = response.status_code

            # ------------------------------------------------
            # REDIRECT
            # ------------------------------------------------

            if status_code in (
                301,
                302,
                303,
                307,
                308
            ):

                location = response.headers.get(
                    "Location"
                )

                response.close()

                if not location:

                    return (
                        0,
                        current_url
                    )

                try:

                    next_url = urljoin(
                        current_url,
                        location
                    )

                except ValueError:

                    return (
                        0,
                        current_url
                    )

                current_url = next_url

                continue

            online = (
                200 <= status_code < 400
            )

            final_url = response.url

            response.close()

            return (
                1 if online else 0,
                final_url
            )

        except requests.RequestException:

            return (
                0,
                current_url
            )

        except Exception:

            return (
                0,
                current_url
            )

    # Troppi redirect.
    return (
        0,
        current_url
    )


def update_url_result(
    original_url,
    stato,
    final_url,
    last_check
):

    conn = get_db()

    try:

        if (
            final_url
            and final_url != original_url
        ):

            existing = conn.execute("""
                SELECT url
                FROM urls
                WHERE url = ?
            """, (
                final_url,
            )).fetchone()

            if existing is None:

                conn.execute("""
                    UPDATE urls
                    SET
                        url = ?,
                        stato = ?,
                        last_check = ?
                    WHERE url = ?
                """, (
                    final_url,
                    stato,
                    last_check,
                    original_url
                ))

                conn.commit()

                return final_url

        conn.execute("""
            UPDATE urls
            SET
                stato = ?,
                last_check = ?
            WHERE url = ?
        """, (
            stato,
            last_check,
            original_url
        ))

        conn.commit()

        return original_url

    finally:

        conn.close()


def check_single_url(
    url,
    update_database=True
):

    stato, final_url = check_url_status(
        url
    )

    last_check = current_datetime()

    resulting_url = url

    if update_database:

        resulting_url = update_url_result(
            original_url=url,
            stato=stato,
            final_url=final_url,
            last_check=last_check
        )

    return {
        "url": resulting_url,
        "original_url": url,
        "stato": stato,
        "last_check": last_check
    }


def check_all_urls():

    initialize_database()

    conn = get_db()

    rows = conn.execute("""
        SELECT url
        FROM urls
        ORDER BY url
    """).fetchall()

    conn.close()

    for row in rows:

        url = row["url"]

        try:

            check_single_url(
                url
            )

        except Exception as error:

            print(
                f"Errore controllo URL {url}: {error}",
                file=sys.stderr
            )


# ============================================================
# ROOT
# ============================================================

@app.route(
    "/",
    methods=["GET"]
)
@rate_limit("public")
def root():

    if not request.args:

        return render_template(
            "index.html"
        )

    if (
        len(request.args) != 1
        or "api_key" not in request.args
    ):

        return Response(
            "Bad Request",
            status=400,
            mimetype="text/plain"
        )

    api_key = request.args.get(
        "api_key"
    )

    user = get_user_by_api_key(
        api_key
    )

    if user is None:

        return Response(
            "",
            status=202,
            mimetype="text/plain"
        )

    # "available" riguarda esclusivamente
    # la visualizzazione della pagina/API pubblica.
    if user["available"] != 1:

        return Response(
            "",
            status=202,
            mimetype="text/plain"
        )

    conn = get_db()

    rows = conn.execute("""
        SELECT url
        FROM urls
        WHERE stato = 1
        ORDER BY url
    """).fetchall()

    conn.close()

    result = "\n".join(
        row["url"]
        for row in rows
    )

    return Response(
        result,
        status=200,
        mimetype="text/plain"
    )


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/api/login",
    methods=["POST"]
)
@rate_limit("login")
def login():

    data = request.get_json(
        silent=True
    ) or {}

    api_key = data.get(
        "api_key"
    )

    user = get_user_by_api_key(
        api_key
    )

    if user is None:

        return jsonify({
            "error": "API key non valida"
        }), 401

    # available NON viene controllato qui.
    # Un amministratore non disponibile può comunque
    # accedere al pannello amministrativo.

    if user["admin"] != 1:

        return jsonify({
            "error":
                "Accesso amministrativo non autorizzato"
        }), 403

    session.clear()

    session["authenticated"] = True
    session["admin"] = 1
    session["username"] = user["nomeutente"]

    return jsonify({
        "success": True,
        "username": user["nomeutente"]
    })


# ============================================================
# LOGOUT
# ============================================================

@app.route(
    "/api/logout",
    methods=["POST"]
)
def logout():

    session.clear()

    return jsonify({
        "success": True
    })


# ============================================================
# GET URLS
# ============================================================

@app.route(
    "/api/urls",
    methods=["GET"]
)
def get_urls():

    if not is_admin():

        return jsonify({
            "error": "Unauthorized"
        }), 401

    conn = get_db()

    rows = conn.execute("""
        SELECT
            url,
            stato,
            last_check
        FROM urls
        ORDER BY url
    """).fetchall()

    conn.close()

    return jsonify({
        "urls": [
            {
                "url": row["url"],
                "stato": row["stato"],
                "last_check": row["last_check"]
            }
            for row in rows
        ]
    })


# ============================================================
# ADD URL
# ============================================================

@app.route(
    "/api/urls",
    methods=["POST"]
)
def add_url():

    if not is_admin():

        return jsonify({
            "error": "Unauthorized"
        }), 401

    data = request.get_json(
        silent=True
    ) or {}

    url = data.get(
        "url",
        ""
    ).strip()

    if not url:

        return jsonify({
            "error": "URL mancante"
        }), 400

    # --------------------------------------------------------
    # SSRF / URL VALIDATION
    # --------------------------------------------------------

    if not validate_monitor_url(
        url
    ):

        return jsonify({
            "error":
                "URL non valido o non consentito"
        }), 400

    result = check_single_url(
        url,
        update_database=False
    )

    stato = result["stato"]
    final_url = result["url"]
    last_check = result["last_check"]

    conn = get_db()

    try:

        conn.execute("""
            INSERT INTO urls
            (
                url,
                stato,
                last_check
            )
            VALUES (?, ?, ?)
        """, (
            final_url,
            stato,
            last_check
        ))

        conn.commit()

    except sqlite3.IntegrityError:

        conn.close()

        return jsonify({
            "error": "URL già presente"
        }), 409

    conn.close()

    return jsonify({
        "success": True,
        "url": final_url,
        "stato": stato,
        "last_check": last_check
    }), 201


# ============================================================
# DELETE URL
# ============================================================

@app.route(
    "/api/urls/<path:url>",
    methods=["DELETE"]
)
def delete_url(url):

    if not is_admin():

        return jsonify({
            "error": "Unauthorized"
        }), 401

    url = unquote(
        url
    )

    conn = get_db()

    cursor = conn.execute("""
        DELETE FROM urls
        WHERE url = ?
    """, (
        url,
    ))

    conn.commit()
    conn.close()

    if cursor.rowcount == 0:

        return jsonify({
            "error": "URL non trovato"
        }), 404

    return jsonify({
        "success": True
    })


# ============================================================
# CHECK URL
# ============================================================

@app.route(
    "/api/urls/check/<path:url>",
    methods=["POST"]
)
@rate_limit("url_check")
def check_url(url):

    if not is_admin():

        return jsonify({
            "error": "Unauthorized"
        }), 401

    url = unquote(
        url
    )

    conn = get_db()

    row = conn.execute("""
        SELECT url
        FROM urls
        WHERE url = ?
    """, (
        url,
    )).fetchone()

    conn.close()

    if row is None:

        return jsonify({
            "error": "URL non trovato"
        }), 404

    result = check_single_url(
        url
    )

    return jsonify({
        "success": True,
        "url": result["url"],
        "original_url": result["original_url"],
        "stato": result["stato"],
        "last_check": result["last_check"]
    })


# ============================================================
# GET USERS
# ============================================================

@app.route(
    "/api/users",
    methods=["GET"]
)
def get_users():

    if not is_admin():

        return jsonify({
            "error": "Unauthorized"
        }), 401

    conn = get_db()

    rows = conn.execute("""
        SELECT
            nomeutente,
            apikey,
            admin,
            available
        FROM users
        ORDER BY nomeutente
    """).fetchall()

    conn.close()

    current_username = session.get(
        "username"
    )

    users = []

    for row in rows:

        if (
            row["nomeutente"] == current_username
            or row["admin"] == 0
        ):

            api_key = row["apikey"]

        else:

            api_key = "*********"

        users.append({
            "nomeutente": row["nomeutente"],
            "apikey": api_key,
            "admin": row["admin"],
            "available": row["available"]
        })

    return jsonify({
        "users": users
    })


# ============================================================
# ADD USER
# ============================================================

@app.route(
    "/api/users",
    methods=["POST"]
)
def add_user():

    if not is_admin():

        return jsonify({
            "error": "Unauthorized"
        }), 401

    data = request.get_json(
        silent=True
    ) or {}

    username = data.get(
        "username",
        ""
    ).strip()

    admin = data.get(
        "admin",
        0
    )

    available = data.get(
        "available",
        1
    )

    if not username:

        return jsonify({
            "error": "Nome utente mancante"
        }), 400

    if len(username) > 50:

        return jsonify({
            "error":
                "Il nome utente è troppo lungo"
        }), 400

    if admin not in (
        0,
        1,
        True,
        False
    ):

        return jsonify({
            "error":
                "Valore amministratore non valido"
        }), 400

    if available not in (
        0,
        1,
        True,
        False
    ):

        return jsonify({
            "error":
                "Valore disponibilità non valido"
        }), 400

    admin = 1 if admin else 0
    available = 1 if available else 0

    api_key = generate_unique_api_key()

    conn = get_db()

    try:

        conn.execute("""
            INSERT INTO users
            (
                nomeutente,
                apikey,
                admin,
                available
            )
            VALUES (?, ?, ?, ?)
        """, (
            username,
            api_key,
            admin,
            available
        ))

        conn.commit()

    except sqlite3.IntegrityError:

        conn.close()

        return jsonify({
            "error": "Nome utente già presente"
        }), 409

    conn.close()

    return jsonify({
        "success": True,
        "username": username,
        "apikey": api_key,
        "admin": admin,
        "available": available
    }), 201


# ============================================================
# UPDATE USER
# ============================================================

@app.route(
    "/api/users/<path:username>",
    methods=["PATCH"]
)
def update_user(username):

    if not is_admin():

        return jsonify({
            "error": "Unauthorized"
        }), 401

    username = unquote(
        username
    )

    data = request.get_json(
        silent=True
    ) or {}

    if (
        "admin" not in data
        and "available" not in data
    ):

        return jsonify({
            "error": "Nessun valore da modificare"
        }), 400

    conn = get_db()

    user = conn.execute("""
        SELECT
            nomeutente,
            admin,
            available
        FROM users
        WHERE nomeutente = ?
    """, (
        username,
    )).fetchone()

    if user is None:

        conn.close()

        return jsonify({
            "error": "Utente non trovato"
        }), 404

    new_admin = user["admin"]
    new_available = user["available"]

    if "admin" in data:

        admin = data["admin"]

        if admin not in (
            0,
            1,
            True,
            False
        ):

            conn.close()

            return jsonify({
                "error":
                    "Valore amministratore non valido"
            }), 400

        new_admin = 1 if admin else 0

    if "available" in data:

        available = data["available"]

        if available not in (
            0,
            1,
            True,
            False
        ):

            conn.close()

            return jsonify({
                "error":
                    "Valore disponibilità non valido"
            }), 400

        new_available = (
            1 if available else 0
        )

    # ========================================================
    # PROTEZIONE ULTIMO AMMINISTRATORE
    # ========================================================

    if (
        user["admin"] == 1
        and new_admin == 0
    ):

        admin_count = conn.execute("""
            SELECT COUNT(*)
            FROM users
            WHERE admin = 1
        """).fetchone()[0]

        if admin_count <= 1:

            conn.close()

            return jsonify({
                "error":
                    "Non puoi rimuovere "
                    "l'ultimo amministratore"
            }), 400

    conn.execute("""
        UPDATE users
        SET
            admin = ?,
            available = ?
        WHERE nomeutente = ?
    """, (
        new_admin,
        new_available,
        username
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "username": username,
        "admin": new_admin,
        "available": new_available
    })


# ============================================================
# DELETE USER
# ============================================================

@app.route(
    "/api/users/<path:username>",
    methods=["DELETE"]
)
def delete_user(username):

    if not is_admin():

        return jsonify({
            "error": "Unauthorized"
        }), 401

    username = unquote(
        username
    )

    current_username = session.get(
        "username"
    )

    if username == current_username:

        return jsonify({
            "error":
                "Non puoi eliminare l'utente "
                "attualmente autenticato"
        }), 400

    conn = get_db()

    row = conn.execute("""
        SELECT
            nomeutente,
            admin
        FROM users
        WHERE nomeutente = ?
    """, (
        username,
    )).fetchone()

    if row is None:

        conn.close()

        return jsonify({
            "error": "Utente non trovato"
        }), 404

    # Se l'utente da eliminare è admin,
    # controlliamo che non sia l'ultimo.
    if row["admin"] == 1:

        admin_count = conn.execute("""
            SELECT COUNT(*)
            FROM users
            WHERE admin = 1
        """).fetchone()[0]

        if admin_count <= 1:

            conn.close()

            return jsonify({
                "error":
                    "Non puoi eliminare "
                    "l'ultimo amministratore"
            }), 400

    conn.execute("""
        DELETE FROM users
        WHERE nomeutente = ?
    """, (
        username,
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True
    })


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(error):

    return Response(
        "Not Found",
        status=404,
        mimetype="text/plain"
    )


@app.errorhandler(405)
def method_not_allowed(error):

    return Response(
        "Method Not Allowed",
        status=405,
        mimetype="text/plain"
    )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    if (
        len(sys.argv) > 1
        and sys.argv[1] == "--check-urls"
    ):

        check_all_urls()

        sys.exit(0)

    initialize_database()

    app.run(
        host="0.0.0.0",
        port=8000
    )
