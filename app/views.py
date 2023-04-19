from app import app
from flask import jsonify
import psycopg2
from psycopg2.extras import DictCursor


@app.route('/', methods=['GET'])
def index():
    return jsonify(info = "Net monitor server")

@app.route('/hosts_info', methods=['GET'])
def change_alias_member():
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=DictCursor) as cursor:
            cursor.execute('SELECT * from host_info order by ip')
            result = []
            for row in cursor:
                resultItem = {}
                resultItem['ip'] = row['ip']
                resultItem['ports'] = row['ports']
                resultItem['dns_name'] = row['dns_name']
                resultItem['os'] = row['os']
                resultItem['mac'] = row['mac']
                resultItem['user_name'] = row['user_name']
                resultItem['cpu'] = row['cpu']
                resultItem['motherboard'] = row['motherboard']
                resultItem['memory'] = row['memory']
                resultItem['disk'] = row['disk']
                resultItem['system_name'] = row['system_name']
                resultItem['description'] = row['description']
                resultItem['warning'] = row['warning']
                resultItem['verification_date'] = row['verification_date'].strftime("%Y-%m-%d %H:%M:%S")
                resultItem['change_date'] = row['change_date'].strftime("%Y-%m-%d %H:%M:%S")

                result.append(resultItem)
            return jsonify(result)

def get_db_connection():
    return psycopg2.connect(dbname=app.config['DATABASE_NAME'], user=app.config['DATABASE_USER'], password=app.config['DATABASE_PASSWORD'], host=app.config['DATABASE_HOST'])
