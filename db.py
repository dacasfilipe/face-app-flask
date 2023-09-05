import os
import mysql.connector

def connect():
    """Conecta ao banco de dados MySQL."""
    conn = mysql.connector.connect(
        host=os.environ.get("DB_HOST"),
        user=os.environ.get("DB_USER"),
        password=os.environ.get("DB_PASSWORD"),
        database=os.environ.get("DB_DATABASE"),
    )
    return conn

def query(conn, sql):
    """Executa uma consulta SQL."""
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()

def close(conn):
    """Fecha a conexão com o banco de dados."""
    conn.close()