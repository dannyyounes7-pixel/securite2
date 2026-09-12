#!/usr/bin/env python3
# ============================================================================
# DataCorp Analytics - app_v2.py
# TP Réel Chapitre 2 (v2 — édition enrichie) - Application INTENTIONNELLEMENT vulnérable
# USAGE PÉDAGOGIQUE UNIQUEMENT — NE JAMAIS DÉPLOYER EN PRODUCTION
#
# Vulnérabilités historiques (v1, inchangées) :
#   V1. SQL Injection / Authentication bypass          -> /login
#   V2. SQL Injection (OR-based, UNION, time-based)     -> /search
#   V3. Reflected XSS                                   -> /search
#   V4. Stored XSS                                       -> /comments, /api/comments
#   V5. CSRF (pas de token)                               -> /export
#   V6. Politique de mot de passe faible                  -> /register
#   V7. Absence de rate limiting (brute force)            -> /login
#   Bonus. Information disclosure (mdp en clair)          -> /api/users
#
# NOUVELLES vulnérabilités (v2) :
#   V8.  IDOR (Insecure Direct Object Reference)          -> /articles/<id>
#   V9.  Path Traversal                                    -> /download
#   V10. Mass Assignment (auto-promotion admin)            -> /register (champ role)
#   V11. Open Redirect                                     -> /login (paramètre next)
# ============================================================================

import os
import sqlite3
import time

from flask import Flask, request, redirect, session, jsonify, Response

app = Flask(__name__)
app.secret_key = "datacorp-dev-secret-2024"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EXPORTS_DIR = os.path.join(BASE_DIR, "exports")


# ----------------------------------------------------------------------------
# Base de données SQLite en mémoire
# ----------------------------------------------------------------------------

DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.row_factory = sqlite3.Row


def _sleep(seconds):
    try:
        time.sleep(min(float(seconds), 10))
    except (TypeError, ValueError):
        pass
    return 0


DB.create_function("SLEEP", 1, _sleep)


def init_db():
    cur = DB.cursor()
    cur.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            role TEXT
        );

        CREATE TABLE articles (
            id INTEGER PRIMARY KEY,
            title TEXT,
            content TEXT,
            author TEXT,
            confidential INTEGER DEFAULT 0
        );

        CREATE TABLE comments (
            id INTEGER PRIMARY KEY,
            name TEXT,
            comment TEXT
        );
        """
    )
    cur.executemany(
        "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
        [
            ("admin", "password123", "admin@datacorp.local", "admin"),
            ("analyst", "123456", "analyst@datacorp.local", "analyst"),
            ("datascientist", "analyst", "ds@datacorp.local", "datascientist"),
        ],
    )
    # --- VULNÉRABLE (V8) : l'article 4 est "confidentiel" mais /articles/<id>
    # ne vérifie ni l'authentification ni le rôle avant de le renvoyer.
    cur.executemany(
        "INSERT INTO articles (title, content, author, confidential) VALUES (?, ?, ?, ?)",
        [
            ("Rapport ventes Q1", "Analyse des ventes du premier trimestre.", "analyst", 0),
            ("Pipeline ingestion", "Notes sur le pipeline d'ingestion de données.", "datascientist", 0),
            ("Audit sécurité", "Résumé de l'audit de sécurité préliminaire.", "admin", 1),
            ("Notes de service", "Accès cloud : identifiants du bucket datacorp-exports en rotation le 30/03. Contact: o.perrin (infra).", "admin", 1),
        ],
    )
    DB.commit()


init_db()


def init_exports_dir():
    """Prépare un répertoire d'exports avec un fichier public légitime,
    pour donner un sens fonctionnel à /download avant de démontrer V9."""
    os.makedirs(EXPORTS_DIR, exist_ok=True)
    public_file = os.path.join(EXPORTS_DIR, "rapport_public.csv")
    if not os.path.exists(public_file):
        with open(public_file, "w") as f:
            f.write("id,title,author\n1,Rapport ventes Q1,analyst\n2,Pipeline ingestion,datascientist\n")


init_exports_dir()


# ----------------------------------------------------------------------------
# Gabarits HTML
# ----------------------------------------------------------------------------

PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>{title}</title></head>
<body>
<h1>DataCorp Analytics</h1>
<nav>
<a href="/dashboard">Dashboard</a> | <a href="/search">Search</a> |
<a href="/comments">Comments</a> | <a href="/export">Export</a> |
<a href="/articles/1">Articles</a> | <a href="/logout">Logout</a>
</nav>
<hr>
{body}
</body></html>"""


def render(title, body):
    return PAGE.format(title=title, body=body)


# ----------------------------------------------------------------------------
# V1 & V7 & V11 (NOUVEAU) : /login
# ----------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    next_url = request.args.get("next", "/dashboard")

    if request.method == "GET":
        return render(
            "Login",
            f"""
            <h2>Connexion</h2>
            <form method="POST">
              <input type="hidden" name="next" value="{next_url}">
              Username: <input name="username"><br>
              Password: <input name="password" type="password"><br>
              <button type="submit">Login</button>
            </form>
            """,
        )

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    # --- VULNÉRABLE (V11 - Open Redirect) : 'next' vient du client et est
    # utilisé tel quel dans la redirection finale, sans vérifier qu'il pointe
    # vers une URL interne à l'application. ---
    next_url = request.form.get("next", "/dashboard")

    # --- VULNÉRABLE (V1) : concaténation directe dans la requête SQL ---
    query = "SELECT * FROM users WHERE username = '{}' AND password = '{}'".format(
        username, password
    )
    try:
        cur = DB.cursor()
        cur.execute(query)
        row = cur.fetchone()
    except sqlite3.Error as e:
        return render("Login", f"<p>Erreur SQL: {e}</p>"), 500

    # --- VULNÉRABLE (V7) : aucune limite de tentatives / verrouillage ---
    if row:
        session["user"] = row["username"]
        session["role"] = row["role"]
        return redirect(next_url)

    return render("Login", "<p>Identifiants invalides.</p>"), 401


# ----------------------------------------------------------------------------
# V6 & V10 (NOUVEAU) : /register — pas de politique de mdp + mass assignment
# ----------------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render(
            "Register",
            """
            <h2>Créer un compte</h2>
            <form method="POST">
              Username: <input name="username"><br>
              Password: <input name="password" type="password"><br>
              Email: <input name="email"><br>
              <button type="submit">S'inscrire</button>
            </form>
            """,
        )

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    email = request.form.get("email", "")
    # --- VULNÉRABLE (V10 - Mass Assignment) : le rôle est accepté depuis le
    # formulaire client sans être filtré. Le formulaire HTML n'expose pas ce
    # champ, mais rien n'empêche un attaquant de l'ajouter à la requête POST
    # directement (curl / Burp), ce qui permet de s'auto-promouvoir admin. ---
    role = request.form.get("role", "user")

    cur = DB.cursor()
    cur.execute(
        "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
        (username, password, email, role),
    )
    DB.commit()
    return redirect("/dashboard"), 302


# ----------------------------------------------------------------------------
# /dashboard
# ----------------------------------------------------------------------------

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")
    return render(
        "Dashboard",
        f"<h2>Bienvenue {session['user']} (role: {session.get('role')})</h2>"
        "<p><a href='/search'>Rechercher des données</a></p>"
        "<p><a href='/comments'>Voir les commentaires</a></p>"
        "<p><a href='/export'>Exporter mes données</a></p>"
        "<p><a href='/articles/1'>Consulter les articles</a></p>",
    )


# ----------------------------------------------------------------------------
# V2 & V3 : /search
# ----------------------------------------------------------------------------

@app.route("/search")
def search():
    q = request.args.get("q", "")

    results_html = ""
    error_html = ""

    if q:
        query = "SELECT id, title, content, author FROM articles WHERE title LIKE '%{}%'".format(q)
        try:
            cur = DB.cursor()
            cur.execute(query)
            rows = cur.fetchall()
            for r in rows:
                results_html += "<li>{} - {} ({})</li>".format(r[1], r[2], r[3])
        except sqlite3.Error as e:
            error_html = f"<p>Erreur SQL: {e}</p>"

    body = f"""
    <h2>Recherche</h2>
    <form method="GET">
      <input name="q" value="{q}">
      <button type="submit">Search</button>
    </form>
    <p>Résultats pour: {q}</p>
    {error_html}
    <ul>
    {results_html}
    </ul>
    """
    return render("Search", body)


# ----------------------------------------------------------------------------
# V4 : /comments et /api/comments
# ----------------------------------------------------------------------------

@app.route("/comments")
def comments_page():
    cur = DB.cursor()
    cur.execute("SELECT name, comment FROM comments ORDER BY id DESC")
    rows = cur.fetchall()
    items = "".join(f"<li><b>{r['name']}</b>: {r['comment']}</li>" for r in rows)
    return render("Comments", f"<h2>Commentaires</h2><ul>{items}</ul>"
                               "<form method='POST' action='/api/comments'>"
                               "Name: <input name='name'><br>"
                               "Comment: <textarea name='comment'></textarea><br>"
                               "<button type='submit'>Poster</button></form>")


@app.route("/api/comments", methods=["GET", "POST"])
def api_comments():
    if request.method == "POST":
        name = request.form.get("name", "anonymous")
        comment = request.form.get("comment", "")
        cur = DB.cursor()
        cur.execute("INSERT INTO comments (name, comment) VALUES (?, ?)", (name, comment))
        DB.commit()
        return redirect("/comments")

    cur = DB.cursor()
    cur.execute("SELECT name, comment FROM comments ORDER BY id DESC")
    rows = [{"name": r["name"], "comment": r["comment"]} for r in cur.fetchall()]
    return jsonify(rows)


# ----------------------------------------------------------------------------
# V5 : /export — CSRF
# ----------------------------------------------------------------------------

@app.route("/export", methods=["GET", "POST"])
def export():
    if request.method == "GET":
        return render(
            "Export",
            """
            <h2>Exporter mes données</h2>
            <form method="POST">
              Format: <select name="format"><option>csv</option><option>json</option></select><br>
              Email de destination: <input name="email"><br>
              <button type="submit">Exporter</button>
            </form>
            """,
        )

    fmt = request.form.get("format", "csv")
    email = request.form.get("email", "")
    return render(
        "Export",
        f"<p>Export Successful: format={fmt}, envoyé à {email}.</p>",
    )


# ----------------------------------------------------------------------------
# NOUVEAU — V8 : /articles/<id> — IDOR
# ----------------------------------------------------------------------------

@app.route("/articles/<int:article_id>")
def article_detail(article_id):
    # --- VULNÉRABLE (V8 - IDOR) : aucune vérification de session ni de rôle.
    # Le flag 'confidential' existe en base mais n'est jamais consulté ici :
    # n'importe quel id (y compris l'article 4, "Notes de service", qui
    # contient des informations internes sensibles) est renvoyé à quiconque
    # devine ou incrémente l'id dans l'URL. ---
    cur = DB.cursor()
    cur.execute("SELECT id, title, content, author, confidential FROM articles WHERE id = ?", (article_id,))
    row = cur.fetchone()
    if not row:
        return render("Article", "<p>Article introuvable.</p>"), 404
    return render(
        "Article",
        f"<h2>{row['title']}</h2><p>{row['content']}</p><p><i>Auteur: {row['author']}</i></p>",
    )


# ----------------------------------------------------------------------------
# NOUVEAU — V9 : /download — Path Traversal
# ----------------------------------------------------------------------------

@app.route("/download")
def download():
    filename = request.args.get("file", "rapport_public.csv")
    # --- VULNÉRABLE (V9 - Path Traversal) : le nom de fichier fourni par le
    # client est concaténé directement au chemin de base, sans normaliser ni
    # vérifier qu'il reste à l'intérieur de EXPORTS_DIR. Un payload du type
    # '../app_v2.py' ou '../../../../etc/passwd' sort du répertoire prévu. ---
    path = os.path.join(EXPORTS_DIR, filename)
    try:
        with open(path, "r", errors="replace") as f:
            content = f.read()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        return render("Download", f"<p>Erreur: {e}</p>"), 404
    return Response(content, mimetype="text/plain")


# ----------------------------------------------------------------------------
# Bonus : /api/users — Information disclosure
# ----------------------------------------------------------------------------

@app.route("/api/users")
def api_users():
    cur = DB.cursor()
    cur.execute("SELECT id, username, password, email, role FROM users")
    rows = [dict(r) for r in cur.fetchall()]
    return jsonify(rows)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/")
def index():
    return redirect("/login")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
