from flask import *
import json
import os
import threading
import hashlib
import time
import shutil
app=Flask(__name__)

monitoring = False
interval=500

@app.route("/logs",methods=["GET"])
def logs():
    logs = []
    try:
        with open("./logs/logs.json","r") as f:
            logs = json.load(f)
        return render_template("logs.html",logs=logs)
    except Exception as e:
        return f"<script>alert(`{e}`)</script>"

@app.route("/",methods=["POST","GET"])
def home():
    if request.method=="GET":
        return render_template("index.html")
    elif request.method=="POST":
        global monitoring, interval
        if request.form["monitor"]=="monitor":
            directory=request.form["file"]
            x = startMonitoring(directory)
            if x == "e":
                return "directory already being monitored"
            else:
                return "directory is now being monitored"
        elif request.form["monitor"]=="integrity":
            results = integrity(m=False)
            if results == "No files found":
                return results
            else:
                return "<br>".join(results)
        elif request.form["monitor"]=="stop":
            directory=request.form["file"]
            x = stopMonitoring(directory)
            if x == "d":
                return "directory has been stopped being monitored"
            else:
                return f"Error: {x}"
        elif request.form["monitor"]=="start_scan":
            monitoring=True
            interval = int(request.form["time"])
        elif request.form["monitor"]=="stop_scan":
            monitoring=False
        return render_template("index.html")
    
def hash_file(path):
    with open(path, "rb") as f:
        file_data = f.read()
    return hashlib.sha256(file_data).hexdigest()

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
    with open(os.path.join(folder,"logs.json"),"r") as f:
        x = json.load(f)
    for j in l:
        x.append(j)
    with open(os.path.join(folder,"logs.json"),"w") as f:
        f.write(json.dumps(x,indent=4))

def timestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")

def integrity(m):
    folder="./hashes"
    results=[]
    r=[]
    hash_files=[]
    for root,dirs,files in os.walk(folder):
        if "info.json" in files:
            with open(os.path.join(root,"info.json"),"r") as f:
                target_folder = json.load(f)["path"]
            for x in files:
                if x.endswith(".json") and x!="info.json":
                    file_name = x[:-5]
                    hash_files.append(file_name)
                    file_path = os.path.join(target_folder,file_name)
                    hash_file_path = os.path.join(root,x)
                    if not os.path.exists(file_path):
                        results.append(f"{file_name} is deleted ❌")
                        r.append(f"File deleted - {file_name}")
                        continue
                    try:
                        with open(file_path, "rb") as f:
                            current_hash = hashlib.sha256(f.read()).hexdigest()
                    except:
                        results.append(f"Could not read {file_name}")
                        continue
                    try:
                        with open(hash_file_path,"r") as f:
                            saved_hash = json.load(f)["hash"]
                    except:
                        results.append(f"Could not read saved hash for {file_name}")
                        continue
                    if current_hash==saved_hash:
                        results.append(f"{file_name} is intact ✅")
                        r.append("y")
                    else:
                        results.append(f"{file_name} is NOT same ❌")
                        r.append(f"File changed - {file_name}")
            current_files=[]
            for root,dirs,files in os.walk(target_folder):
                for x in files:
                    current_files.append(x)
            for x in current_files:
                if x not in hash_files:
                    results.append(f"New file created {x} 🗃️")
                    r.append(f"New file - {x}")
    if not m:
        if results == []:
            return "No files found"
        else:
            j=0
            irregularities=[]
            for x in r:
                if x!="y":
                    j+=1
                    irregularities.append(x)
            log=[]
            log.append({"type":"integrity","statement":f"Checked integrity - {j} irregularities found","time":timestamp(),"irregularities":irregularities})
            new_log(log)
            return results
    else:
        if results == []:
            log=[]
            log.append({"type":"scan","statement":f"No files found - Routine scan","time":timestamp()})
        else:
            j=0
            irregularities=[]
            for x in r:
                if x!="y":
                    j+=1
                    irregularities.append(x)
            log=[]
            log.append({"type":"scan","statement":f"Checked integrity - {j} irregularities found - Routine scan","time":timestamp(),"irregularities":irregularities})
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
    for root, dirs, files in os.walk(directory):
        for file_name in files:
            full_path = os.path.join(root, file_name)
            file_hash = hash_file(full_path)
            result.append((file_name, file_hash))

    info=os.path.join(hash_dir,"info.json")
    with open(info, "w") as f:
        f.write(json.dumps({"path":directory}))
    r=0
    for x in result:
        file_path = os.path.join(hash_dir, x[0] + ".json")
        with open(file_path, "w") as f:
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