import flask, time, sys, json, sqlite3, os, sys, random, string, hashlib, subprocess
from flask import render_template, session, jsonify, request, Response
from datetime import datetime

from flask import request, render_template, flash, current_app, jsonify, session, redirect, url_for, send_from_directory
from application import app
from engine.validate_apk import validate, dircreator, dirremover
from subprocess import Popen, PIPE, STDOUT
from flask_oauth import OAuth
from dicttoxml import dicttoxml


reload(sys)
sys.setdefaultencoding('utf8')

app.config.from_object(__name__)

SECRET_KEY = app.config['SECRET_KEY']
DEBUG = app.config['DEBUG']

app.secret_key = SECRET_KEY
    
oauth = OAuth()
 
google = oauth.remote_app(
    app.config['OAUTH_CLIENT'],
    base_url=app.config['BASE_URL'],
    authorize_url=app.config['AUTHORIZE_URL'],
    request_token_url=app.config['REQUEST_TOKEN_URL'],
    request_token_params=app.config['REQUEST_TOKEN_PARAMS'],
    access_token_url=app.config['ACCESS_TOKEN_URL'],
    access_token_method=app.config['ACCESS_TOKEN_METHOD'],
    access_token_params=app.config['ACCESS_TOKEN_PARAMS'],
    consumer_key=app.config['GOOGLE_CLIENT_ID'],
    consumer_secret=app.config['GOOGLE_CLIENT_SECRET']
)

@app.route('/scan_history', methods=['GET'])
def scan_history():
    if not session.get('access_token'):
        return render_template("login.html",message="Please login to continue",category="info"), 403

    oauth_uid = session.get('oauth_uid')

    scan_id = None
    package_name = None
    if request.args.get('id'):
        scan_id = request.args.get('id')
        package_name = get_package_details(scan_id)[0][0]

    scan_results = get_scan_history(oauth_uid,package_name)
    
    scans = []
    for result in scan_results:
        scan = {}
        scan['scan_id'] = result[0]
        scan['package_name'] = result[1]
        scan['package_version'] = result[2]
        scan['time_of_scan'] = result[3]
        scan['status'] = result[4]

        scan_id = scan['scan_id']

        vuln_count_high = get_vuln_count(scan_id,'HIGH')
        vuln_count_medium = get_vuln_count(scan_id,'MEDIUM')
        vuln_count_low = get_vuln_count(scan_id,'LOW')

        scan['results'] = {'high':vuln_count_high[0][0],'medium':vuln_count_medium[0][0],'low':vuln_count_low[0][0]}

        scans.append(scan)
    return jsonify(scans), 200

@app.route('/tnc', methods=['GET'])
def tnc():
    return render_template('tnc.html'), 200

@app.route('/about', methods=['GET'])
def about():
    return render_template('about.html'), 200

@app.route('/roadmap', methods=['GET'])
def roadmap():
    return render_template('roadmap.html'), 200

@app.route('/reporting/', methods=['GET'])
@app.route('/', methods=['GET'])
def index():
    if not session.get('access_token'):
        return render_template("login.html"), 403

    return render_template('index.html',message=" ",category=""), 200

@app.route('/reporting/report', methods=['GET'])
def report():
    if session.get('access_token') is None:
        return render_template("login.html",message="Please login to continue",category="info"), 403

    oauth_uid = session.get('oauth_uid')
    scan_id = request.args.get('id')

    try:
        scan_id = int(scan_id)
    except Exception, ae:
        print ae
        return render_template('index.html',message=" ",category=""), 403

    if not authorized_scan(scan_id,oauth_uid):
        return render_template('index.html',message="User not authorized to view this report",category="danger"), 403

    apk_permissions = get_apk_permissions(scan_id)
    apk_receivers = get_apk_receivers(scan_id)

    vulns_high_level = get_vulns_high_level(oauth_uid,scan_id)
    bugs_results_high = get_bugs_results(scan_id,'HIGH')
    bugs_results_medium = get_bugs_results(scan_id,'MEDIUM')
    bugs_results_low = get_bugs_results(scan_id,'LOW')
    bugs_results_info = get_bugs_results(scan_id,'INFO')

    vuln_count_high = get_vuln_count(scan_id,'HIGH')
    vuln_count_medium = get_vuln_count(scan_id,'MEDIUM')
    vuln_count_low = get_vuln_count(scan_id,'LOW')
    vuln_count_info = get_vuln_count(scan_id,'INFO')

    manifest_analisys_details = get_manifest_analisys(scan_id)

    exported_activities = get_exported_results(scan_id,1)
    exported_providers = get_exported_results(scan_id,2)
    exported_services = get_exported_results(scan_id,3)

    return render_template('report.html',
        apk_permissions=(len(apk_permissions),apk_permissions),
        apk_receivers=(len(apk_receivers),apk_receivers),
        vulns_high_level=vulns_high_level,
        bugs_results_high=bugs_results_high,
        bugs_results_medium=bugs_results_medium,
        bugs_results_low=bugs_results_low,
        bugs_results_info=bugs_results_info,

        vuln_count_high=vuln_count_high,
        vuln_count_medium=vuln_count_medium,
        vuln_count_low=vuln_count_low,
        vuln_count_info=vuln_count_info,

        manifest_analisys_details=manifest_analisys_details,
        exported_activities = (len(exported_activities),exported_activities),
        exported_providers = (len(exported_providers),exported_providers),
        exported_services = (len(exported_services),exported_services),

        all_vulns_details = get_all_vulns(scan_id),

        bugs_by_severity= get_bugs_by_severity(scan_id),
        bugs_by_type= get_bugs_by_type(scan_id),
        scan_id=scan_id
    )

# @app.route('/reporting/bugs', methods=['GET'])
# def bugs():
#     scan_id = request.args.get('id')
#     return jsonify(get_bugs_by_severity(scan_id))

@app.route('/reporting/download', methods=['GET'])
@app.route('/download', methods=['GET'])
def download_report():
    if session.get('access_token') is None:
        return render_template("login.html",message="Please login to continue",category="info"), 403

    oauth_uid = session.get('oauth_uid')
    scan_id = request.args.get('id')

    try:
        scan_id = int(scan_id)
    except Exception, ae:
        print ae
        return render_template('index.html',message=" ",category=""), 403

    if not authorized_scan(scan_id,oauth_uid):
        return render_template('index.html',message="User not authorized to download this report",category="danger"), 403

    format = 'json'
    if request.args.get('format'):
        format = request.args.get('format')

    bugs_results_high = get_bugs_results(scan_id,'HIGH')
    bugs_results_medium = get_bugs_results(scan_id,'MEDIUM')
    bugs_results_low = get_bugs_results(scan_id,'LOW')
    bugs_results_info = get_bugs_results(scan_id,'INFO')

    vuln_count_high = get_vuln_count(scan_id,'HIGH')
    vuln_count_medium = get_vuln_count(scan_id,'MEDIUM')
    vuln_count_low = get_vuln_count(scan_id,'LOW')
    # vuln_count_info = get_vuln_count(scan_id,'INFO')

    manifest_analisys_details = get_manifest_analisys(scan_id)

    exported_activities = get_exported_results(scan_id,1)
    exported_providers = get_exported_results(scan_id,2)
    exported_services = get_exported_results(scan_id,3)

    result = {}
    result['vulns'] = {}

    result['vulns']['total'] = vuln_count_high[0][0] + vuln_count_medium[0][0] + vuln_count_low[0][0]
    
    result['vulns']['high'] = {}
    result['vulns']['high']['total'] = len(bugs_results_high)
    result['vulns']['high']['vulns'] = []

    for vuln in bugs_results_high:
        child_vuln = {}
        child_vuln['name'] = vuln[0]
        child_vuln['path'] = vuln[1]
        child_vuln['line_no'] = vuln[2]
        child_vuln['code_snippet'] = vuln[3]

        result['vulns']['high']['vulns'].append(child_vuln)

    result['vulns']['medium'] = {}
    result['vulns']['medium']['total'] = len(bugs_results_medium)
    result['vulns']['medium']['vulns'] = []

    for vuln in bugs_results_medium:
        child_vuln = {}
        child_vuln['name'] = vuln[0]
        child_vuln['path'] = vuln[1]
        child_vuln['line_no'] = vuln[2]
        child_vuln['code_snippet'] = vuln[3]

        result['vulns']['medium']['vulns'].append(child_vuln)

    result['vulns']['low'] = {}
    result['vulns']['low']['total'] = len(bugs_results_low)
    result['vulns']['low']['vulns'] = []

    for vuln in bugs_results_low:
        child_vuln = {}
        child_vuln['name'] = vuln[0]
        child_vuln['path'] = vuln[1]
        child_vuln['line_no'] = vuln[2]
        child_vuln['code_snippet'] = vuln[3]

        result['vulns']['low']['vulns'].append(child_vuln)

    result['vulns']['info'] = {}
    result['vulns']['info']['total'] = len(bugs_results_low)
    result['vulns']['info']['vulns'] = []

    for vuln in bugs_results_info:
        child_vuln = {}
        child_vuln['name'] = vuln[0]
        child_vuln['path'] = vuln[1]
        child_vuln['line_no'] = vuln[2]
        child_vuln['code_snippet'] = vuln[3]

        result['vulns']['info']['vulns'].append(child_vuln)

    result['manifest_analysis'] = {}
    result['manifest_analysis']['min_sdk'] = manifest_analisys_details[0][0]
    result['manifest_analysis']['target_sdk'] = manifest_analisys_details[0][1]
    result['manifest_analysis']['debuggable'] = manifest_analisys_details[0][2]
    result['manifest_analysis']['backup'] = manifest_analisys_details[0][3]

    result['exported'] = {}
    result['exported']['activities'] = []
    for activity in exported_activities:
        result['exported']['activities'].append(activity[0])

    result['exported']['providers'] = []
    for provider in exported_providers:
        result['exported']['activities'].append(provider[0])
        
    result['exported']['services'] = []
    for service in exported_services:
        result['exported']['activities'].append(service[0])


    if format == "xml":
        xml = dicttoxml(result)
        return Response(xml, 
            mimetype='text/xml',
            headers={'Content-Disposition':'attachment;filename=report_'+str(scan_id)+'.xml'})

    # return jsonify(result)
    return Response(json.dumps(result), 
            mimetype='application/json',
            headers={'Content-Disposition':'attachment;filename=report_'+str(scan_id)+'.json'})



@app.route('/submit_apk', methods=['POST'])
def submit_apk():
    access_token = session.get('access_token')
    if access_token is None:
        return render_template("login.html",message="Please login to continue",category="info"), 403

    if request.method == 'POST' and 'application' in request.files.keys():
        apk_file = request.files['application']
        tempname = apk_file.filename

        if apk_file and allowed_file(tempname):

            path = ''.join(random.choice(string.lowercase) for x in range(6)) #random path for unzipping
            directory_path = current_app.root_path+"/android/"+path

            outputdir = dircreator(directory_path+"/unzipped")

            now = datetime.now()
            filename = os.path.join(current_app.root_path, app.config['UPLOAD_FOLDER'], "%s.%s" % (now.strftime("%Y-%m-%d-%H-%M-%S-%f"), apk_file.filename.rsplit('.', 1)[1]))
            apk_file.save(filename)

            apk_path = filename
            apk_hash = md5(apk_path)
            
            filename = filename.rsplit('/')[-1:][0]
            already_scanned = check_if_already_scanned(apk_hash)
            if already_scanned:
                return already_scanned

            validation = validate(apk_path,outputdir)            
            if validation['valid']:
                apk_details = validation['details']
                package_name = apk_details[0]
                package_version = apk_details[1]
                time_of_scan = apk_details[2]

                oauth_uid = session.get('oauth_uid')

                insert_sql = "INSERT INTO scan_history (oauth_uid, package_name,package_version,time_of_scan,apk_path,apk_hash) VALUES(?,?,?,?,?,?)"
                scan_id = None
            
                db_name='database.db'
                db = sqlite3.connect(db_name)            
                cursor = db.cursor()

                try:
                    cursor.execute(insert_sql,(oauth_uid,package_name,package_version,time_of_scan,apk_path,apk_hash))
                    db.commit()
                    scan_id = cursor.lastrowid

                except Exception, ae:
                    print ae
                    db.rollback()

                db.close()
                if scan_id:
                    command='python '+current_app.root_path+'/engine/main.py '+str(scan_id)+' '+apk_path
                    p = Popen(command, shell=True)
                else:
                    return render_template('index.html',message="Only apk files are allowed", category="warning"), 403    

                dirremover(directory_path)
                return render_template('progress_bar.html',scan_id=scan_id), 200
                # return jsonify({"success": True, 'scan_id': scan_id}), 403

            dirremover(directory_path)
            return render_template('index.html',message="invalid apk file submitted", category="warning"), 200

        else:
            return render_template('index.html',message="Only apk files are allowed", category="warning"), 403    
    
    return render_template('index.html',message="something went wrong", category="warning"), 500

@app.route('/status', methods=['GET'])
def scan_status():
    access_token = session.get('access_token')
    if access_token is None:
        return render_template("login.html",message="Please login to continue",category="info"), 403

    oauth_uid = session.get('oauth_uid')
    scan_id = request.args.get('scan_id')

    if not authorized_scan(scan_id,oauth_uid):
        return render_template('index.html',message="User not authorized to view this report",category="danger"), 403

    if scan_id:
        db_name='database.db'
        db = sqlite3.connect(db_name)
        cursor = db.cursor()

        status_sql = "SELECT value,content,state FROM status WHERE scan_id = ? LIMIT 1"

        cursor.execute(status_sql,(scan_id,))
        results = cursor.fetchall()

        result = {}
        result['value'] = results[0][0]
        result['content'] = str(results[0][1])
        result['state'] = str(results[0][2])

        return jsonify([result])
    return None

@app.route('/compare_reports', methods=['POST','GET'])
def compare_reports():
    access_token = session.get('access_token')
    if access_token is None:
        return render_template("login.html",message="Please login to continue",category="info"), 403

    if request.method == 'GET':
        return render_template("index.html"), 200

    oauth_uid = session.get('oauth_uid')
    args = request.form

    report_ids = []
    packages = {}
    count = 0
    message = None
    max_scans = 3
    for arg in args:
        if 'scan_' in arg:
            count += 1
            if count > max_scans:
                message = "More than "+str(max_scans)+" scans are selected.<br />showing comparison for "+str(max_scans)+" scans only. Ignoring the remaining scans"
                break

            if not authorized_scan(args[arg],oauth_uid):
                return render_template('index.html',message="User not authorized to view these reports",category="danger"), 403
            report_ids.append(int(args[arg]))
            package_details = get_package_details(int(args[arg]))
            packages[int(args[arg])] = package_details[0][0]+' - v'+package_details[0][1]

    if len(report_ids) < 2:
        return render_template("index.html",message="please select atleast 2 (upto 3) scan reports to compare.", category="info"), 403

    vuln_level = []
    unique_vulns = {}
    for report_id in report_ids:
        vulns = get_all_vulns(report_id)
        for ele in vulns:
            vuln = vulns[ele][0][0]
            if vuln not in unique_vulns:
                unique_vulns[vuln] = []

            package_name = packages[report_id]

            if package_name not in unique_vulns[vuln]:
                unique_vulns[vuln].append(package_name)

        vuln_level_new = {}
        vuln_level_new['package'] = str(package_name)
        vuln_level_new['high'] = get_vuln_count(report_id,'HIGH')[0][0]
        vuln_level_new['medium'] = get_vuln_count(report_id,'MEDIUM')[0][0]
        vuln_level_new['low'] = get_vuln_count(report_id,'LOW')[0][0]
        vuln_level_new['info'] = get_vuln_count(report_id,'INFO')[0][0]

        vuln_level.append(vuln_level_new)

    # return jsonify(json.dumps(vuln_level))
    return render_template('compare.html',compare_results=unique_vulns,packages=packages,vuln_level=json.dumps(vuln_level),message=message,category="info"), 200



@app.route('/dashboard', methods=['GET'])
def dashboard():
    if not session.get('access_token'):
        return render_template("login.html",message="Please login to view Dashboard.",category="info"), 403

    dash_board_stats = get_dash_board_stats()

    if not dash_board_stats:
        return render_template("index.html",message="There are no Existing scans found.",category="info"), 200

    recent_scans = dash_board_stats[0]
    scan_ids = dash_board_stats[1]
    last_scan_id = scan_ids[0]

    last_scan_name = get_package_details(last_scan_id)
    last_scan_name = last_scan_name[0][0]+" - v"+str(last_scan_name[0][1])

    last_scan = [last_scan_name,last_scan_id]

    bugs_by_severity = get_bugs_by_severity(last_scan_id)

    # return jsonify(recent_scans)
    return render_template('dashboard.html',message=" ",category="",recent_scans=recent_scans,scan_ids=scan_ids,bugs_by_severity=bugs_by_severity,last_scan=last_scan), 200


with app.test_request_context('/'):
    def get_scan_history(oauth_uid,package_name):
        db_name='database.db'
        db = sqlite3.connect(db_name)
        cursor = db.cursor()

        print package_name
        if package_name:
            sql = "SELECT DISTINCT sh.scan_id,sh.package_name,sh.package_version,sh.time_of_scan,st.state FROM scan_history as sh, status as st WHERE sh.oauth_uid = ? AND sh.package_name = ? AND sh.scan_id = st.scan_id"
            cursor.execute(sql,(oauth_uid,package_name))
        else:
            sql = "SELECT DISTINCT sh.scan_id,sh.package_name,sh.package_version,sh.time_of_scan,st.state FROM scan_history as sh, status as st WHERE sh.oauth_uid = ? AND sh.scan_id = st.scan_id"
            cursor.execute(sql,(oauth_uid,))
         
        try:
            results = cursor.fetchall()
            db.close()

            return results
        except Exception,e:
            print str(e)

        db.close()
        return False


with app.test_request_context('/'):
    def get_apk_permissions(scan_id):
        db_name='database.db'
        db = sqlite3.connect(db_name)
        cursor = db.cursor()

        sql = "SELECT permission FROM permissions WHERE scan_id = ?"
        cursor.execute(sql,(scan_id,))
         
        try:
            results = cursor.fetchall()
            db.close()
            return results

        except Exception,e:
            print str(e)

        db.close()
        return False

with app.test_request_context('/'):
    def get_apk_receivers(scan_id):
        db_name='database.db'
        db = sqlite3.connect(db_name)
        cursor = db.cursor()

        sql = "SELECT receiver FROM receivers WHERE scan_id = ?"
        cursor.execute(sql,(scan_id,))
         
        try:
            results = cursor.fetchall()
            db.close()
            return results

        except Exception,e:
            print str(e)

        db.close()
        return False


with app.test_request_context('/dashboard_reports'):
    def get_dash_board_stats():
        oauth_uid = session.get('oauth_uid')

        scans = get_scan_history(oauth_uid,None)
        print scans
        
        if not len(scans):
            return None

        scans.reverse()
        
        count = 0
        max_scans = 5
        final_scans = []
        ids = []

        all_vulns = []

        while len(scans) > max_scans:
            scans.pop()

        high = {}
        medium = {}
        low = {}
        info = {}

        high['severity'] = 'HIGH'
        medium['severity'] = 'MEDIUM'
        low['severity'] = 'LOW'
        info['severity'] = 'INFO'

        scan_ids = []

        for scan in scans:
            scan = list(scan)

            scan_ids.append(scan[0])

            high['scan_'+str(scan[0])] = get_vuln_count(scan[0],'HIGH')[0][0]
            medium['scan_'+str(scan[0])] = get_vuln_count(scan[0],'MEDIUM')[0][0]
            low['scan_'+str(scan[0])] = get_vuln_count(scan[0],'LOW')[0][0]
            info['scan_'+str(scan[0])] = get_vuln_count(scan[0],'INFO')[0][0]

        return ([high,medium,low],scan_ids)


with app.test_request_context('/'):
    def get_package_details(report_id):
        db_name='database.db'
        db = sqlite3.connect(db_name)
        cursor = db.cursor()

        package_sql = "SELECT package_name, package_version from scan_history where scan_id = ?"

        cursor.execute(package_sql,(report_id,))
        results = cursor.fetchall()

        return results

with app.test_request_context('/'):
    def check_if_already_scanned(apk_hash):
        db_name='database.db'
        db = sqlite3.connect(db_name)
        cursor = db.cursor()

        oauth_uid = session.get('oauth_uid')

        scan_sql = "SELECT * FROM scan_history WHERE oauth_uid = ? AND apk_hash = ? AND scan_id NOT IN (SELECT scan_id FROM status WHERE state = 'error') ORDER BY time_of_scan DESC LIMIT 1"
        cursor.execute(scan_sql,(oauth_uid,apk_hash))
        results = cursor.fetchall()

        if len(results) > 0:
            results = results[0]
            same_scan_id = results[0]
            same_scan_time = results[4]
            time_of_scan = 0
            category = "success"

            return render_template("index.html",already_scanned=True,same_scan_id=same_scan_id,same_scan_time=same_scan_time,category=category)

        
        return False


with app.test_request_context('/'):
    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ['apk']


with app.test_request_context('/'):
    def md5(fname):
        hash_md5 = hashlib.md5()
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

with app.test_request_context('/'):
    def authorized_scan(scan_id,oauth_uid):
        db_name='database.db'
        db = sqlite3.connect(db_name)
        cursor = db.cursor()

        scan_sql = "SELECT count(*) FROM scan_history WHERE scan_id = ? and oauth_uid = ?"
        cursor.execute(scan_sql,(scan_id,oauth_uid))
        results = cursor.fetchall()

        if int(results[0][0]) == 0:
            return False

        return True

with app.test_request_context('/'):
    def get_vulns_high_level(oauth_uid,scan_id):
        db_name='database.db'
        db = sqlite3.connect(db_name)
        cursor = db.cursor()

        vulns_high_level = []

        vul_id_sql = "SELECT DISTINCT vul_id FROM bugs WHERE scan_id = ?"
        try:
            cursor.execute(vul_id_sql,(scan_id,))
            results = cursor.fetchall()

            for row in results:
                vuln = {}
                vul_id = row[0]
                name_sql = "SELECT name FROM vulnerabilities WHERE vul_id=?"
                cursor.execute(name_sql,(str(vul_id),))
                name_result = cursor.fetchall()
                name = name_result[0][0]

                count_sql = "SELECT COUNT(bug_id) as count FROM bugs WHERE scan_id=? AND vul_id=?"
                cursor.execute(count_sql,(scan_id,vul_id))
                count_result = cursor.fetchall()
                
                count = count_result[0][0]

                vuln['vul_id'] = vul_id
                vuln['name'] = name
                vuln['count'] = count

                vulns_high_level.append(vuln)

            db.close()
            return vulns_high_level


        except Exception,e:
            print str(e)

        db.close()
        return vulns_high_level


with app.test_request_context('/'):
    def get_bugs_results(scan_id,severity):
        db_name='database.db'
        db = sqlite3.connect(db_name)
        cursor = db.cursor()

        bugs_sql = "SELECT vulnerabilities.name,bugs.filename,bugs.line_no,bugs.snippet FROM bugs INNER JOIN vulnerabilities ON bugs.vul_id=vulnerabilities.vul_id WHERE bugs.scan_id=? AND vulnerabilities.severity=?"
        
        cursor.execute(bugs_sql,(scan_id,severity))
        results = cursor.fetchall()

        db.close()
        return results

with app.test_request_context('/'):
    def get_vuln_count(scan_id,severity):
        db_name='database.db'
        db = sqlite3.connect(db_name)
        cursor = db.cursor()

        count_sql = "SELECT COUNT(bug_id) as count FROM bugs WHERE vul_id IN (SELECT DISTINCT vul_id FROM vulnerabilities WHERE severity=?) AND scan_id=?"

        cursor.execute(count_sql,(severity,scan_id))
        results = cursor.fetchall()

        db.close()
        return results

with app.test_request_context('/'):
    def get_manifest_analisys(scan_id):
        db_name='database.db'
        db = sqlite3.connect(db_name)
        cursor = db.cursor()

        count_sql = "SELECT min_sdk, target_sdk, debuggable, backup FROM scan_history WHERE scan_id=?"

        cursor.execute(count_sql,(scan_id,))
        results = cursor.fetchall()

        db.close()
        return results

with app.test_request_context('/'):
    def get_exported_results(scan_id,type_data):
        db_name='database.db'
        db = sqlite3.connect(db_name)
        cursor = db.cursor()

        count_sql = "SELECT name FROM manifest WHERE scan_id=? AND type=?"

        cursor.execute(count_sql,(scan_id,type_data))
        results = cursor.fetchall()

        db.close()
        return results


with app.test_request_context('/'):
    def get_all_vulns(scan_id):
        db_name='database.db'
        db = sqlite3.connect(db_name)
        cursor = db.cursor()

        vul_id_sql = "SELECT DISTINCT vul_id FROM bugs WHERE scan_id = ?"
        try:
            cursor.execute(vul_id_sql,(scan_id,))
            results = cursor.fetchall()

            vuln_sql = "SELECT name, description, severity FROM vulnerabilities WHERE vul_id = ?"

            vulns = {}
            for row in results:
                cursor.execute(vuln_sql,(row[0],))
                vulns[row[0]] = cursor.fetchall()
                vulns[row[0]].append(get_vuln_details(scan_id,row[0]))
                

            db.close()
            return vulns
        except Exception, ae:
            print ae

        return None

with app.test_request_context('/'):
    def get_vuln_details(scan_id,vul_id):
        db_name='database.db'
        db = sqlite3.connect(db_name)
        cursor = db.cursor()

        vul_id_sql = "SELECT filename, line_no, snippet FROM bugs WHERE scan_id = ? AND vul_id=?"
        try:
            cursor.execute(vul_id_sql,(scan_id,vul_id))
            results = cursor.fetchall()
            db.close()

            return results
        except Exception, ae:
            print ae

        return None

with app.test_request_context('/'):
    def get_bugs_by_severity(scan_id):
        db_name='database.db'
        db = sqlite3.connect(db_name)
        cursor = db.cursor()

        severe_sql = "SELECT DISTINCT vul_id FROM bugs WHERE scan_id = ? AND vul_id NOT IN (SELECT DISTINCT vul_id FROM vulnerabilities WHERE severity='INFO')"
        
        try:
            cursor.execute(severe_sql,(scan_id,))
            results = cursor.fetchall()

            data = []
            for row in results:
                data_ele = {}

                vul_id = row[0]
                count_sql = "SELECT COUNT(bug_id) as count FROM bugs WHERE scan_id = ? AND vul_id= ? "

                cursor.execute(count_sql,(scan_id,vul_id))
                count = cursor.fetchall()[0][0]

                vuln_sql = "SELECT name, severity FROM vulnerabilities WHERE vul_id = ?"

                cursor.execute(vuln_sql,(vul_id,))
                vulns_details = cursor.fetchall()

                name = vulns_details[0][0]
                sev = vulns_details[0][1]

                if 'HIGH' in sev:
                    size = 30
                    severity = 3

                elif 'MEDIUM' in sev:
                    size = 20
                    severity = 2

                else:
                    size = 10
                    severity = 1

                data_ele['vulnerability'] = str(name)
                data_ele['vulnerabilities'] = str(count)
                data_ele['severityvalue'] = str(sev)
                data_ele['size'] = size
                data_ele['severity'] = severity

                data.append(data_ele)
        
            db.close()
            
            return data            
        except:
            pass

        db.close()
        return None
        
with app.test_request_context('/'):
    def get_bugs_by_type(scan_id):
        db_name='database.db'
        db = sqlite3.connect(db_name)
        cursor = db.cursor()

        type_sql = "SELECT DISTINCT vul_id FROM bugs WHERE scan_id = ? AND vul_id NOT IN (SELECT DISTINCT vul_id FROM vulnerabilities WHERE severity='INFO')"
        
        try:
            cursor.execute(type_sql,(scan_id,))
            results = cursor.fetchall()

            data = []
            for row in results:
                data_ele = {}

                vul_id = row[0]
                count_sql = "SELECT COUNT(bug_id) as count FROM bugs WHERE scan_id = ? AND vul_id= ? "

                cursor.execute(count_sql,(scan_id,vul_id))
                count = cursor.fetchall()[0][0]

                vuln_sql = "SELECT name FROM vulnerabilities WHERE vul_id = ?"

                cursor.execute(vuln_sql,(vul_id,))
                vulns_details = cursor.fetchall()

                name = vulns_details[0][0]
                
                data_ele['category'] = str(name)
                data_ele['column-1'] = str(count)
                data.append(data_ele)
        
            db.close()
            return data            
        except:
            pass

        db.close()
        return None


with app.test_request_context('/'):
    def add_user(sess):
        db_name='database.db'
        db = sqlite3.connect(db_name)
        cursor = db.cursor()
        user_sql = "INSERT into users(oauth_uid,fname,email,gender,picture,created) values(?,?,?,?,?,?)"
        # user_records = 
        try:
            cursor.execute(user_sql,(str(sess['oauth_uid']),str(sess['name']),str(sess['email']),"NA",str(sess['picture']),time.strftime('%Y-%m-%d %H:%M:%S')))
            db.commit()
        except Exception, ae:
            print ae
            db.rollback()

        db.close()

        return True


############ Do not modify these route/functions ############

@app.route('/login', methods=['GET'])
def login():
    callback=url_for('authorized', _external=True)
    return google.authorize(callback=callback)

@app.route('/logout')
def logout():
    session.pop('access_token', None)
    session.pop('oauth_uid', None)
    session.pop('email', None)
    session.pop('name', None)
    session.pop('picture', None)
    session.pop('gender', None)
    session.pop('type', None)
    session.pop('loginType', None)

    return redirect(url_for('index'))


@app.route(app.config['REDIRECT_URI'])
@google.authorized_handler
def authorized(resp):

    access_token = resp['access_token']
    session['access_token'] = access_token, ''

    from urllib2 import Request, urlopen, URLError
 
    headers = {'Authorization': 'OAuth '+access_token}
    req = Request('https://www.googleapis.com/oauth2/v1/userinfo', None, headers)
    try:
        res = urlopen(req)
    except URLError, e:
        if e.code == 401:
            # Unauthorized - bad token
            session.pop('access_token', None)
            return redirect(url_for('login'))

        return res.read()
 
    res = json.loads(res.read())

    if res['email'] not in ['testing.iviz@gmail.com','ankurbhargava87@gmail.com','divya.sj@flipkart.com','anirudh.anand@flipkart.com']:
        redirect_url = "login.html"
        session.pop('access_token', None)
        return render_template(redirect_url,message="User not authorized to view this resource.",category="warning"), 403

    session['email'] = res['email']
    session['name'] = res['name']
    session['picture'] = res['picture']
    session['type'] = 'user'
    session['loginType'] = 'oauth'
    session['verified'] = True
    session['oauth_uid'] = res['id']

    try:
        add_user(session)
    except Exception, le:
        print ae

    if session['access_token']:
        return redirect(url_for('index'))

    return render_template('login.html',message="Something went wrong. Please try again.",category="danger"), 500


@google.tokengetter
def get_access_token():
    return session.get('access_token')


@app.route('/robots.txt')
def robots():
    return send_from_directory(app.static_folder, "robots.txt")

@app.errorhandler(404)
def page_not_found(e):
    redirect = "login.html"

    access_token = session.get('access_token')
    if access_token:
        redirect = "index.html"

    return render_template(redirect,message="404 - Requested resource does not exist.",category="warning"), 404

@app.errorhandler(403)
def server_error_403(e):
    redirect = "login.html"
    
    access_token = session.get('access_token')
    if access_token:
        redirect = "index.html"

    return render_template(redirect,message="User not authorized to view this resource.",category="warning"), 403

# @app.errorhandler(Exception)
@app.errorhandler(500)
def server_error_500(e):
    redirect = "login.html"
    
    access_token = session.get('access_token')
    if access_token:
        redirect = "index.html"

    return render_template(redirect,message="Something went wrong ! Please try again.",category="danger"), 500
############ Do not modify these route/functions ############

