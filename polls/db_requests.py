import psycopg2
from DreamService import settings
import psycopg2.extras
import os

DB_USER = os.environ["DB_USER"]
DB_PASSWORD = os.environ["DB_PASSWORD"]
DB_NAME = os.environ["DB_NAME"]

def insertIntoTable(table, **kwargs):
    query = "insert into {0} as tabl ({1}) values ({2})".format(table, ', '.join(kwargs.keys()), ', '.join(['%({0})s'.format(key) for key in kwargs.keys()]))
    with psycopg2.connect(user=DB_USER, password=DB_PASSWORD, database=DB_NAME) as conn:
        with conn.cursor() as cursor:
            return '(' + cursor.mogrify(query, kwargs).decode() + ')'


def deleteFromTable(table, id):
    query = "delete from {0} as tabl where id={1}".format(table, id)
    with psycopg2.connect(user=DB_USER, password=DB_PASSWORD, database=DB_NAME) as conn:
        with conn.cursor() as cursor:
            return ('(' + cursor.mogrify(query).decode() + ')').replace("=NULL", " is NULL")


def updateTable(table, id, **kwargs):
    query = "update {0} as tabl set {1} where id={2}".format(table, ', '.join([key+'=%({0})s'.format(key) for key in kwargs.keys()]), id)
    with psycopg2.connect(user=DB_USER, password=DB_PASSWORD, database=DB_NAME) as conn:
        with conn.cursor() as cursor:
            return ('(' + cursor.mogrify(query, kwargs).decode() + ')').replace("=NULL", " is NULL")


def filter(table, **kwargs):
    query = "select * from {0} as tabl".format(table)
    if (kwargs):
        query += " where {0}".format(' and '.join([key+'=%({0})s'.format(key) for key in kwargs.keys()]))
    with psycopg2.connect(user=DB_USER, password=DB_PASSWORD, database=DB_NAME) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            return ('(' + cursor.mogrify(query, kwargs).decode() + ')').replace("=NULL", " is NULL")


def orderBy(table, field):
    query = "select * from {0} as tabl order by {1}".format(table, field)
    with psycopg2.connect(user=DB_USER, password=DB_PASSWORD, database=DB_NAME) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            return '(' + cursor.mogrify(query).decode() + ')'


def search(table, **kwargs):
    query = "select * from {0} as tabl".format(table)
    if (kwargs):
        query += " where {0}".format(' and '.join([key+' like %({0})s'.format(key) for key in kwargs.keys()]))
    with psycopg2.connect(user=DB_USER, password=DB_PASSWORD, database=DB_NAME) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            return '(' + cursor.mogrify(query, kwargs).decode() + ')'


def join(table1, table2, field1, field2):
    query = "select * from {0} as tabl1 join {1} as tabl2 on tabl1.{2} = tabl2.{3}".format(table1, table2, field1, field2)
    with psycopg2.connect(user=DB_USER, password=DB_PASSWORD, database=DB_NAME) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            return '(' + cursor.mogrify(query).decode() + ')'


def groupBy(table, field, expressions):
    query = "select {0}, {1} from {2} as tabl group by {0}".format(field, ', '.join(expressions), table)
    with psycopg2.connect(user=DB_USER, password=DB_PASSWORD, database=DB_NAME) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            return '(' + cursor.mogrify(query).decode() + ')'


def between(table, field, value1, value2):
    query = "select * from {0} as tabl where {1} between %s and %s".format(table, field)
    with psycopg2.connect(user=DB_USER, password=DB_PASSWORD, database=DB_NAME) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            return '(' + cursor.mogrify(query, (value1, value2)).decode() + ')'


def rent(id_user, id_vehicle):
    query = "call rent_vehicle({0}, {1})".format(id_vehicle, id_user)
    with psycopg2.connect(user=DB_USER, password=DB_PASSWORD, database=DB_NAME) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            return '(' + cursor.mogrify(query).decode() + ')'


def stopRent(id_user, id_rent):
    query = "call end_rent({0}, {1})".format(id_user, id_rent)
    with psycopg2.connect(user=DB_USER, password=DB_PASSWORD, database=DB_NAME) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            return '(' + cursor.mogrify(query).decode() + ')'


def review(id_user, id_vehicle, review):
    query = "call add_review({0}, {1}, %s)".format(id_user, id_vehicle)
    with psycopg2.connect(user=DB_USER, password=DB_PASSWORD, database=DB_NAME) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            return '(' + cursor.mogrify(query, (review,)).decode() + ')'


def updatePricesForUser(id_user):
    query = "call update_rent_prices_for_user({0})".format(id_user)
    with psycopg2.connect(user=DB_USER, password=DB_PASSWORD, database=DB_NAME) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            return '(' + cursor.mogrify(query).decode() + ')'


def execQuery(query):
    with psycopg2.connect(user=DB_USER, password=DB_PASSWORD, database=DB_NAME) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(query[1:-1])
            try:
                return cursor.fetchall()
            except:
                return

