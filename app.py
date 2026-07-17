from flask import Flask, render_template, request, redirect, url_for, session
import json
import os
import threading
import hashlib
import time
import shutil
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "devsecretkey")

monitoring = False
interval = 500
PASSWORD = os.environ.get("SECUREDB_PASSWORD", "admin")


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("home"))
        return f(*args, **kwargs)
    return decorated

@app.route("/logs",methods=["GET"])
@login_required
def logs():
    logs = []
    try:
        with open("./logs/logs.json","r", encoding="utf-8") as f:
            logs = json.load(f)
        issues = [issue for issue in load_issues() if issue.get("unresolved")]
        return render_template("logs.html", logs=logs, issues=issues)
    except Exception as e:
        return f"<script>alert(`{e}`)</script>"

@app.route("/acknowledge", methods=["POST"])
@login_required
def acknowledge():
    statement = request.form.get("statement")
    if statement:
        issues = load_issues()
        for issue in issues:
            if issue.get("statement") == statement:
                issue["acknowledged"] = True
                issue["last_seen"] = timestamp()
        save_issues(issues)
    return redirect(url_for("logs"))

@app.route("/login", methods=["POST"])
def login():
    if request.form.get("password") == PASSWORD:
        session["logged_in"] = True
        return redirect(url_for("main"))
    return redirect(url_for("home"))

@app.route("/logout", methods=["GET"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/",methods=["GET"])
def home():
    if session.get("logged_in"):
        return redirect(url_for("main"))
    return render_template("index.html")

@app.route("/main",methods=["GET","POST"])
@login_required
def main():
    global monitoring, interval
    security_score = compute_security_score()
    if request.method == "GET":
        return render_template("main.html", security_score=security_score, action_card=None)

    action_card = None
    if request.form["monitor"]=="monitor":
        directory = request.form["file"]
        x = startMonitoring(directory)
        if x == "e":
            action_card = {"title":"Monitoring","message":"Directory already being monitored","type":"warning"}
        elif x == "invalid":
            action_card = {"title":"Monitoring","message":"Invalid folder path provided","type":"danger"}
        else:
            action_card = {"title":"Monitoring","message":"Directory is now being monitored","type":"success"}
        return render_template("main.html", security_score=compute_security_score(), action_card=action_card)

    elif request.form["monitor"]=="integrity":
        results = integrity(m=False)
        if results == "No files found":
            results = []
            action_card = {"title":"Integrity check","message":"No monitored files were found.","type":"info"}
        else:
            action_card = {"title":"Integrity check","message":"Integrity check completed.","type":"info"}
        return render_template("integrity.html", results=results, action_card=action_card, security_score=security_score)

    elif request.form["monitor"]=="stop":
        directory = request.form["file"]
        x = stopMonitoring(directory)
        if x == "d":
            action_card = {"title":"Monitoring","message":"Directory has been stopped being monitored","type":"success"}
        else:
            action_card = {"title":"Monitoring","message":f"Error: {x}","type":"danger"}
        return render_template("main.html", security_score=compute_security_score(), action_card=action_card)

    elif request.form.get("monitor")=="start_scan":
        interval_value = request.form.get("time", "").strip()
        if not interval_value.isdigit():
            action_card = {"title":"Scan","message":"Please enter a valid scan interval in seconds.","type":"danger"}
            return render_template("main.html", security_score=security_score, action_card=action_card)
        monitoring = True
        interval = int(interval_value)
        new_log([
            {"type":"scan","statement":f"Started periodic scan every {interval} seconds","time":timestamp(),"irregularities":[],"score":0}
        ])
        action_card = {"title":"Scan","message":f"Started periodic scanning every {interval} seconds","type":"success"}
        return render_template("main.html", security_score=compute_security_score(), action_card=action_card)

    elif request.form.get("monitor")=="stop_scan":
        monitoring = False
        new_log([
            {"type":"scan","statement":"Paused periodic scanning","time":timestamp(),"irregularities":[],"score":0}
        ])
        action_card = {"title":"Scan","message":"Periodic scanning paused","type":"warning"}
        return render_template("main.html", security_score=compute_security_score(), action_card=action_card)

    return render_template("main.html", security_score=security_score, action_card=action_card)
    
malicious_hashes = []
def normalize_directory(directory):
    normalized = os.path.normpath(directory)
    normalized = os.path.abspath(normalized)
    normalized = os.path.normcase(normalized)
    return normalized


def monitor_folder_key(directory):
    normalized = normalize_directory(directory)
    return hashlib.md5(normalized.encode("utf-8")).hexdigest()


def malicious(path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            hash_line = line.strip()
            if hash_line:
                malicious_hashes.append(hash_line.lower())

malicious("./malwares/malware hashes.txt") # creating list of malicious hashes


def computeScore(items):
    s=0
    for it in items:
        lit = it.lower()
        if lit.startswith("malware detected"):
            s += 30
        elif lit.startswith("file deleted"):
            s += 8
        elif lit.startswith("file changed"):
            s += 5
        elif lit.startswith("new file"):
            s += 2
        else:
            s += 1
    return s


def compute_security_score():
    issues = [issue for issue in load_issues() if issue.get("unresolved")]
    if not issues:
        return 100

    total_severity = sum(issue.get("severity", 1) for issue in issues if not issue.get("acknowledged"))
    if total_severity <= 0:
        return 100

    penalty = min(total_severity, 20) * 5
    security_score = max(0, 100 - penalty)
    return security_score


def hash_file(path):
    md5_hash = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
            
    return md5_hash.hexdigest()

def log_file():
    folder="./logs"
    if os.path.exists(os.path.join(folder,"logs.json")):
        print("Log file found")
    else:
        print("Creating log file")
        with open(os.path.join(folder,"logs.json"),"w") as f:
            f.write(json.dumps([]))

def new_log(l):
    folder="./logs"
    with open(os.path.join(folder,"logs.json"),"r", encoding="utf-8") as f:
        x = json.load(f)
    for j in l:
        x.append(j)
    with open(os.path.join(folder,"logs.json"),"w", encoding="utf-8") as f:
        f.write(json.dumps(x,indent=4))


def issues_file():
    folder = "./logs"
    path = os.path.join(folder, "issues.json")
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            f.write(json.dumps([]))
    return path


def load_issues():
    path = issues_file()
    with open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception:
            return []


def save_issues(issues):
    path = issues_file()
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(issues, indent=4))


def issue_severity(statement):
    lit = statement.lower()
    if lit.startswith("malware detected"):
        return 6
    elif lit.startswith("file deleted"):
        return 3
    elif lit.startswith("file changed"):
        return 2
    elif lit.startswith("new file"):
        return 1
    else:
        return 1


def update_issue_store(irregularities):
    existing = load_issues()
    current = set(irregularities)
    updated = []
    now = timestamp()
    for issue in existing:
        stmt = issue.get("statement")
        if stmt in current:
            issue["last_seen"] = now
            issue["unresolved"] = True
            updated.append(issue)
            current.remove(stmt)
        else:
            issue["unresolved"] = False
            updated.append(issue)
    for stmt in current:
        updated.append({
            "statement": stmt,
            "first_seen": now,
            "last_seen": now,
            "severity": issue_severity(stmt),
            "acknowledged": False,
            "unresolved": True
        })
    save_issues(updated)
    return updated


def timestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")

def integrity(m):
    folder="./hashes"
    results=[]
    r=[]
    hash_files=[]
    malware_set = set(h.strip().lower() for h in malicious_hashes if h.strip()) # normalised hashes
    for root,dirs,files in os.walk(folder):
        if "info.json" in files:
            hash_root = root
            with open(os.path.join(hash_root,"info.json"),"r") as f:
                target_folder = json.load(f)["path"]
            for hroot, hdirs, hfiles in os.walk(hash_root):
                for hx in hfiles:
                    if hx.endswith(".json") and hx != "info.json":
                        hash_file_path = os.path.join(hroot, hx)
                        rel_path = os.path.relpath(hash_file_path, hash_root)
                        
                        rel_path_noext = rel_path[:-5]
                        rel_path_noext = os.path.normpath(rel_path_noext)
                        hash_files.append(rel_path_noext)

                        
                        file_path = os.path.join(target_folder, rel_path_noext)
                        if not os.path.exists(file_path):
                            results.append(f"{rel_path_noext} is deleted ❌")
                            r.append(f"File deleted - {rel_path_noext}")
                            continue
                        try:
                            current_hash = hash_file(file_path)
                        except:
                            results.append(f"Could not read {rel_path_noext}")
                            continue

                        if current_hash.lower() in malware_set:
                            results.append(f"{rel_path_noext} matches known malware hash ⚠️")
                            r.append(f"Malware detected - {rel_path_noext}")
                            continue
                        try:
                            with open(hash_file_path,"r") as f:
                                saved_hash = json.load(f)["hash"]
                        except:
                            results.append(f"Could not read saved hash for {rel_path_noext}")
                            continue
                        if current_hash==saved_hash:
                            results.append(f"{rel_path_noext} is intact ✅")
                            r.append("y")
                        else:
                            results.append(f"{rel_path_noext} is NOT same ❌")
                            r.append(f"File changed - {rel_path_noext}")

            # collect current files (preserve relative paths)
            current_files=[]
            for croot, cdirs, cfiles in os.walk(target_folder):
                for cx in cfiles:
                    full = os.path.join(croot, cx)
                    rel = os.path.relpath(full, target_folder)
                    current_files.append(os.path.normpath(rel))
            for x in current_files:
                if x not in hash_files:
                    full_path = os.path.join(target_folder, x)
                    try:
                        new_hash = hash_file(full_path)
                    except:
                        results.append(f"New file created {x} 🗃️ (could not read)")
                        r.append(f"New file - {x}")
                        continue
                    if new_hash.lower() in malware_set:
                        results.append(f"{x} matches known malware hash ⚠️")
                        r.append(f"Malware detected - {x}")
                    else:
                        results.append(f"New file created {x} 🗃️")
                        r.append(f"New file - {x}")
    if not m:
        if results == []:
            update_issue_store([])
            return "No files found"
        else:
            j=0
            irregularities=[]
            for x in r:
                if x!="y":
                    j+=1
                    irregularities.append(x)

            update_issue_store(irregularities)
            score = computeScore(irregularities)
            log=[]
            log.append({"type":"integrity","statement":f"Checked integrity - {j} irregularities found","time":timestamp(),"irregularities":irregularities,"score":score})
            new_log(log)
            return results
    else:
        if results == []:
            update_issue_store([])
            log=[]
            log.append({"type":"scan","statement":f"No files found - Routine scan","time":timestamp(),"irregularities":[],"score":0})
        else:
            j=0
            irregularities=[]
            for x in r:
                if x!="y":
                    j+=1
                    irregularities.append(x)

            update_issue_store(irregularities)
            score = computeScore(irregularities)
            log=[]
            log.append({"type":"scan","statement":f"Checked integrity - {j} irregularities found - Routine scan","time":timestamp(),"irregularities":irregularities,"score":score})
            new_log(log)

def background_monitor():
    while True:
        if monitoring:
            try:
                integrity(m=True)
            except Exception as e:
                print("Error during routine monitoring:",e)
            time.sleep(interval)
        else:
            time.sleep(10)

def startMonitoring(directory):
    folder_name = os.path.basename(directory)
    hash_dir = os.path.join("./hashes", folder_name)
    if os.path.exists(hash_dir):
        return "e"

    os.makedirs(hash_dir, exist_ok=True)
    result = []
    malware = []
    for root, dirs, files in os.walk(directory):
        for file_name in files:
            full_path = os.path.join(root, file_name)
            file_hash = hash_file(full_path)
            rel_path = os.path.relpath(full_path, directory)
            rel_path = os.path.normpath(rel_path)
            result.append((rel_path, file_hash))

    info=os.path.join(hash_dir,"info.json")
    with open(info, "w") as f:
        f.write(json.dumps({"path":directory}))
    r=0
    for x in result:
        rel = x[0]
        json_path = os.path.join(hash_dir, rel + ".json")
        json_dir = os.path.dirname(json_path)
        if json_dir and not os.path.exists(json_dir):
            os.makedirs(json_dir, exist_ok=True)
        with open(json_path, "w") as f:
            f.write(json.dumps({"hash": x[1]}))
        r+=1
    log=[]
    log.append({"type":"monitor","statement":f"Started to monitor directory - {directory} - Monitoring {r} files","time":timestamp(),"irregularities":[]})
    new_log(log)
    return "d"

def stopMonitoring(directory):
    folder_name = os.path.basename(directory)
    hash_dir = os.path.join("./hashes",folder_name)
    if not os.path.exists(hash_dir):
        return "File is not being monitored"
    else:
        shutil.rmtree(os.path.join("./hashes",folder_name))
        log = []
        log.append({"type":"monitor","statement":f"Stopped monitoring directory - {directory}","time":timestamp(),"irregularities":[]})
        new_log(log)
        return "d"

if __name__ == "__main__":
    log_file()
    t = threading.Thread(target=background_monitor, daemon=True)
    t.start()
    app.run(debug=True)
