from flask import Flask, render_template, url_for, request, redirect, flash, Markup
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from database import database
import sqlite3 as sql
import requests
import json
import qrcode

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'dfgdfgd6dfgdf6d7856fghfghdfg'
db = SQLAlchemy(app)


class Links(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    longurl = db.Column(db.String(150), nullable=False)
    code = db.Column(db.String(5), nullable=False)

    def __repr__(self):
        return '<Links %r>' % self.id


def security_check(longurl):
    filename = "user_settings.txt"
    myfile = open(filename, mode="w", encoding='Latin-1')

    url = 'https://www.virustotal.com/vtapi/v2/url/report'

    params = {'apikey': '39c90c15d92cee0c924a2bb0878d0d10ba3f42314f71a970feb48d9550fa7bbd',
              'resource': longurl,
              'scan': 1}

    response = requests.get(url, params=params)
    if response.status_code == 200:
        result = json.loads(response.text)
    a = (json.dumps(result, sort_keys=False, indent=4))

    b = ''

    myres = []
    myres.append(result)

    json.dump(myres, myfile)
    myfile.close()

    myfile = open(filename, mode="r", encoding='Latin-1')
    json_data = json.load(myfile)

    for ser in json_data:
        if ser["verbose_msg"].find("Scan request successfully queued, come back later for the report") == -1:
            for res in json_data:
                print("Positives = " + str(res['positives']))

                b = str(res['positives'])

            if 52 >= ord(b) > 48:
                print("Файл может быть подозрительным")
                return '0'
            elif ord(b) == 48:
                print("Файл безопасен")
                return '1'
            elif ord(b) > 52:
                print("Файл опасен")
                return '2'
        else:
            return '4'

    myfile.close()





@app.errorhandler(404)
def pageNotFound(error):
    return render_template('page404.html')


@app.route('/howredirect')
def howRedirect():
    return render_template('howRedirect.html')


@app.route("/", methods=['POST', 'GET'])
def home_page():
    if request.method == "POST":

        if len(request.form['code']) == 5:
            longurl = request.form['longurl']
            code = request.form['code']

            sec_chk = security_check(longurl)

            if sec_chk == '1':  # чистый сайт
                shorts = Links(longurl=longurl, code=code)

                with sql.connect('blog.db') as con:
                    cur = con.cursor()

                    cur.execute("SELECT * FROM links WHERE code = ?", (code,))
                    if cur.fetchone() is not None:
                        flash("Этот код уже был использован! Пожалуйста, введите новый код, который соответствует требованиям", category='error')
                        return render_template("index.html")
                    else:
                        try:
                            db.session.add(shorts)
                            db.session.commit()
                            flash(Markup('Сайт успешно прошёл проверку на безопасность! Код создан успешно! Чтобы использовать ваш код перейдите по ссылке <a href="page?code=' + code + '\">http://127.0.0.1:5000/page?code=' + code + '</a>'), category='success')
                            qr = qrcode.make('http://127.0.0.1:5000/page?code=' + code)
                            qr.save('static\myQR.jpg')
                            return render_template("index2.html")
                        except:
                            return "При добавлении ссылки произошла ошибка"

            elif sec_chk == '0':  # подозрительный сайт
                shorts = Links(longurl=longurl, code=code)

                with sql.connect('blog.db') as con:
                    cur = con.cursor()

                    cur.execute("SELECT * FROM links WHERE code = ?", (code,))
                    if cur.fetchone() is not None:
                        flash("Этот код уже был использован! Пожалуйста, введите новый код, который соответствует требованиям", category='error')
                        return render_template("index.html")
                    else:
                        try:
                            db.session.add(shorts)
                            db.session.commit()
                            flash(Markup('Сайт прошёл проверку безопасности и оказался подозрительным! Код создан успешно! Чтобы использовать ваш код перейдите по ссылке <a href="page?code=' + code + '\">http://127.0.0.1:5000/page?code=' + code + '</a>'), category='error')
                            return render_template("index2.html")
                        except:
                            return "При добавлении ссылки произошла ошибка"

            elif sec_chk == '2':  # сайт опасный
                flash("Сайт прошёл проверку на безопасность, и выявил, что сайт опасный", category='error')  # переписать!!!
                return render_template("index.html")
            elif sec_chk == '4':  # API проверки сдох :(
                flash("Сайт не смог пройти проверку, потому что API проверки достиг лимита.", category='error')
                return render_template("index.html")

        else:
            flash('Ошибка отправки! Следуйте инструкции поля code : количество символов короткого URL должно быть равно 5!', category='error')
            return render_template("index.html")


    else:

        return render_template("index.html")


@app.route('/deleteold')
def deleteold():
    base = sql.connect('blog.db')
    cur = base.cursor()

    q = cur.execute('SELECT date FROM links').fetchall()

    now = str(datetime.now())
    print(now)
    nowYEAR = now[0] + now[1] + now[2] + now[3]
    nowMONTH = now[5] + now[6]
    nowDAY = now[8] + now[9]
    nowSEC = int(nowYEAR) * 31556926 + int(nowMONTH) * 2629743 + int(nowDAY) * 86400
    print("Количество секунд с начала эпохи = ", nowSEC)

    for i in q:
        r = (i[0][0])
        s = (i[0][1])
        t = (i[0][2])
        u = (i[0][3])
        cherta1 = (i[0][4])
        v = (i[0][5])
        w = (i[0][6])
        cherta2 = (i[0][7])
        x = (i[0][8])
        y = (i[0][9])
        probel1 = (i[0][10])
        a1 = (i[0][11])
        a2 = (i[0][12])
        dvetoch1 = (i[0][13])
        b1 = (i[0][14])
        b2 = (i[0][15])
        dvetoch2 = (i[0][16])
        c1 = (i[0][17])
        c2 = (i[0][18])
        c3 = (i[0][19])
        c4 = (i[0][20])
        c5 = (i[0][21])
        c6 = (i[0][22])
        c7 = (i[0][23])
        c8 = (i[0][24])
        c9 = (i[0][25])

        proverka = str(r) + str(s) + str(t) + str(u) + str(cherta1) + str(v) + str(w) + str(cherta2) + str(x) + str(
            y) + str(probel1) + str(a1) + str(a2) + str(dvetoch1) + str(b1) + str(b2) + str(dvetoch2) + str(c1) + str(
            c2) + str(c3) + str(c4) + str(c5) + str(c6) + str(c7) + str(c8) + str(c9)

        year = str(r) + str(s) + str(t) + str(u)
        month = str(v) + str(w)
        day = str(x) + str(y)
        totalSEC = int(year) * 31556926 + int(month) * 2629743 + int(day) * 86400
        sevendaysSEC = 86400 * 7
        if abs(totalSEC - nowSEC) >= sevendaysSEC:
            cur.execute('DELETE from links WHERE date == ?', (proverka,))
            base.commit()
    flash("Записи, которым больше недели, успешно удалены.", category='success')
    return render_template("index.html")


@app.route('/about')
def about():
    pere = 'проверка'
    return render_template("about.html", pere=pere)

    # Изучение Flask / #4 - Отображение данных из БД (4:15,5:55)


@app.route('/page', methods=['GET'])
def page():
    if request.method == "GET":
        code = request.args.get('code')
        if code is None:
            return render_template('howRedirect.html')
        else:
            db2 = database()
            url = db2.get_data_where('code', code)
            if not url:
                return f"<h1>url нет в бд</h1>"
            else:
                if url[0]['longurl'].find("https://") != -1:
                    return redirect(url[0]['longurl'])
                else:
                    temp = "https://"
                    return redirect(temp+url[0]['longurl'])


if __name__ == "__main__":
    app.run(debug=True)




#дописать о нас

