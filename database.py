import sqlite3 as sql


class database:
    def __init__(self):
        self._connection = sql.Connection("blog.db")
        self._connection.row_factory = sql.Row
        self._current = self._connection.cursor()

    def __del__(self):
        self._current.close()

    def get_data_where(self, param, value):
        self._current.execute(f"SELECT * FROM links WHERE {param} = '{value}'")
        result = self._current.fetchall()
        if not result:
            return False
        return result

    def sameOne(self,code):
        self._current.execute(f"SELECT COUNT() as 'count' FROM LINKS WHERE code LIKE '{code}'")
        res= self._current.fetchone()
        if res['count'] > 0:
            print("Сайт с таким кодом уже существует")
            return False


db2 = database()