import pymysql

connection = pymysql.connect(host='localhost',
                             user='root',
                             password='',
                             db='passkeeper',
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor)

def get_user(username):
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
        sql = "SELECT * FROM user WHERE username = %s AND disabled = 0"
        cursor.execute(sql,(username))
        result = cursor.fetchone()
    return result

def get_all_list_users():
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
        sql = "SELECT * FROM user WHERE disabled = 0"
        cursor.execute(sql)
        result = cursor.fetchall()
    return result

def get_user_id(username):
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
        sql = "SELECT id FROM user WHERE username = %s"
        cursor.execute(sql,(username))
        result = cursor.fetchone()
    return result

def insert_user_database(username,email,full_name,password,disabled):
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
        sql = "INSERT INTO user VALUES(default, %s, %s, %s, %s, %s)"
        cursor.execute(sql,(username,full_name,email,password,disabled))
        connection.commit()

def insert_keeper_database(id_user,linkname,username,password):
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
        sql = "INSERT INTO passwords VALUES(default, %s, %s, %s, %s, 1)"
        cursor.execute(sql,(id_user,linkname,username,password))
        connection.commit()

def get_all_passkeeper(id_user):
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
        sql = "SELECT * FROM passwords WHERE id_user = %s AND status = 1"
        cursor.execute(sql,(id_user))
        result = cursor.fetchall()
    return result

def get_passkeeper_id_exist_in_user(id_user,id_passkeeper):
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
        sql = "SELECT * FROM passwords WHERE id_user = %s AND id = %s AND status = 1"
        cursor.execute(sql,(id_user,id_passkeeper))
        result = cursor.fetchone()
    return result

def delete_keeper(id_keeper):
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
        sql = "UPDATE passwords SET status = 0 WHERE id = %s"
        cursor.execute(sql,(id_keeper))
        connection.commit()

def delete_user_by_username(username):
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
        sql = "UPDATE user SET disabled = 1 WHERE username = %s"
        cursor.execute(sql,(username))
        connection.commit()