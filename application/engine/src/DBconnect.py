import os
import sys
import subprocess
import commands
import sqlite3

def write_to_db(scan_id,text,vul_id):
	db_name='database.db'
	db = sqlite3.connect(db_name)
	cursor = db.cursor()

	for line in text.splitlines():
		content = line.strip().split(':')
		stripped = map(str.strip,content)
		try:
			a = cursor.execute("""INSERT INTO bugs (scan_id,vul_id,filename,line_no,snippet) VALUES (?,?,?,?,?);""",(scan_id, vul_id, stripped[0], stripped[1], stripped[2]))
			db.commit()
		except Exception,e:
			db.rollback()
			print stripped[1] + '\n'
			print str(e)
	db.close()

def write_permission(perm,scan_id):
	db_name='database.db'
	db = sqlite3.connect(db_name)
	cursor = db.cursor()
	try:
		print (scan_id,perm)
		a = cursor.execute("""INSERT INTO permissions (scan_id,permission) VALUES (?,?);""",(scan_id, perm,))
		db.commit()
	except Exception,e:
		print str(e)
		db.rollback()
	db.close()

def write_receivers(receiver,scan_id):
	db_name='database.db'
	db = sqlite3.connect(db_name)
	cursor = db.cursor()
	try:
		print (scan_id,receiver)
		a = cursor.execute("""INSERT INTO receivers (scan_id,receiver) VALUES (?,?);""",(scan_id, receiver,))
		db.commit()
	except Exception,e:
		print str(e)
		db.rollback()
	db.close()

def progress_update(scan_id,value,content):
	db_name='database.db'
	db = sqlite3.connect(db_name)
	cursor = db.cursor()
	try:
		if (value == 0):
			cursor.execute("""INSERT INTO status (scan_id,value,content,state) VALUES (?,?,?,'started');""",(scan_id,value,content))
		elif value == 100:
			cursor.execute("""UPDATE status SET value = ?,content=?, state='finished'  WHERE scan_id = ? AND state != 'error';""",(value,content,scan_id))
		else:
			cursor.execute("""UPDATE status SET value = ?,content=?  WHERE scan_id = ? AND state != 'error';""",(value,content,scan_id))
		db.commit()
	except Exception,e:
		db.rollback()
		print str(e)
	db.close()

def manifest_update_scan(scan_id,min_sdk,target_sdk,debuggable,backup):
	db_name='database.db'
	db = sqlite3.connect(db_name)
	cursor = db.cursor()
	try:
		cursor.execute("""UPDATE scan_history SET min_sdk = ?, target_sdk = ?, debuggable = ?, backup = ? WHERE scan_id = ?;""",(min_sdk,target_sdk,debuggable,backup,scan_id))
		db.commit()
	except Exception,e:
		db.rollback()
		print str(int(scan_id)) + '\n'
		print str(e)
	db.close()

def manifest_update(scan_id,vul_type,name):
	db_name='database.db'
	db = sqlite3.connect(db_name)
	cursor = db.cursor()
	try:
		cursor.execute("""INSERT INTO manifest (scan_id,type,name) VALUES (?,?,?);""",(scan_id,vul_type,name))
		db.commit()
	except Exception,e:
		db.rollback()
		print str(e)
	db.close()

def custom_update(scan_id,vul_id,filename,snippet):
	db_name='database.db'
	db = sqlite3.connect(db_name)
	cursor = db.cursor()
	try:
		cursor.execute("""INSERT INTO bugs (scan_id,vul_id,filename,snippet) VALUES (?,?,?,?);""",(scan_id,vul_id,filename,snippet))
		db.commit()
	except Exception,e:
		db.rollback()
		print str(e)
	db.close()

def error_update(scan_id,error_message):
	db_name='database.db'
	db = sqlite3.connect(db_name)
	cursor = db.cursor()
	try:
		cursor.execute("""UPDATE status SET state = 'error',content = ? WHERE scan_id = ?;""",(error_message,scan_id))
		db.commit()
	except Exception,e:
		db.rollback()
		print str(e)
	db.close()

def get_hardcode():
	db_name='database.db'
	db = sqlite3.connect(db_name)
	cursor = db.cursor()
	sql = "SELECT * FROM hardcode_conf"
	try:
		cursor.execute(sql)
		results = cursor.fetchall()
		db.close()
		return results
	except Exception,e:
		print str(e)

def get_cursor():
	db_name='database.db'
	db = sqlite3.connect(db_name)
	cursor = db.cursor()

	return cursor
