#!/usr/bin/env python3
"""龍蝦養殖場管理系統 - 後端 API 服務器"""
import sqlite3, json, hashlib, os, uuid
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_cors import CORS
import jwt

app = Flask(__name__)
CORS(app, origins="*", supports_credentials=True)

SECRET_KEY = os.environ.get("JWT_SECRET", "lobster-secret-key-2024")
DB_PATH = os.environ.get("DB_PATH", "/home/ubuntu/lobster-backend/lobster.db")

# ─── 資料庫初始化 ───────────────────────────────────────────────

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'operator',
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS fishermen (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        phone TEXT,
        address TEXT,
        prepayment REAL NOT NULL DEFAULT 0,
        notes TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS prepayment_transactions (
        id TEXT PRIMARY KEY,
        fisherman_id TEXT NOT NULL,
        date TEXT NOT NULL,
        type TEXT NOT NULL,
        amount REAL NOT NULL,
        balance REAL NOT NULL,
        notes TEXT,
        FOREIGN KEY (fisherman_id) REFERENCES fishermen(id)
    );

    CREATE TABLE IF NOT EXISTS receiving_records (
        id TEXT PRIMARY KEY,
        date TEXT NOT NULL,
        fisherman_id TEXT NOT NULL,
        fisherman_name TEXT NOT NULL,
        live_items TEXT NOT NULL DEFAULT '[]',
        dead_items TEXT NOT NULL DEFAULT '[]',
        live_total_price REAL NOT NULL DEFAULT 0,
        dead_total_price REAL NOT NULL DEFAULT 0,
        total_amount REAL NOT NULL DEFAULT 0,
        payment_method TEXT NOT NULL DEFAULT 'cash',
        cash_paid REAL,
        prepayment_deducted REAL,
        remaining_prepayment REAL,
        notes TEXT,
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS inventory_changes (
        id TEXT PRIMARY KEY,
        date TEXT NOT NULL,
        type TEXT NOT NULL,
        lobster_type TEXT NOT NULL,
        quantity INTEGER NOT NULL DEFAULT 0,
        weight REAL NOT NULL DEFAULT 0,
        unit_price REAL,
        total_price REAL,
        reason TEXT,
        notes TEXT,
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS operation_logs (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        username TEXT NOT NULL,
        action TEXT NOT NULL,
        details TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)

    # 建立預設管理員
    admin = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()
    if not admin:
        conn.execute(
            "INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?,?,?,?,?)",
            ("admin-001", "admin", hash_password("admin123"), "admin", now())
        )
    conn.commit()
    conn.close()
    print(f"Database initialized at {DB_PATH}")

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def now() -> str:
    return datetime.utcnow().isoformat() + "Z"

def new_id() -> str:
    return str(uuid.uuid4())

# ─── JWT 認證 ────────────────────────────────────────────────────

def make_token(user_id, username, role):
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return jsonify({"error": "未授權"}), 401
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            g.user_id = payload["sub"]
            g.username = payload["username"]
            g.role = payload["role"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token 已過期，請重新登入"}), 401
        except Exception:
            return jsonify({"error": "無效 Token"}), 401
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    @require_auth
    def decorated(*args, **kwargs):
        if g.role != "admin":
            return jsonify({"error": "需要管理員權限"}), 403
        return f(*args, **kwargs)
    return decorated

def add_log(action, details):
    try:
        db = get_db()
        db.execute(
            "INSERT INTO operation_logs (id,user_id,username,action,details,created_at) VALUES (?,?,?,?,?,?)",
            (new_id(), g.user_id, g.username, action, details, now())
        )
        db.commit()
    except Exception:
        pass

# ─── 認證 API ────────────────────────────────────────────────────

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username=? AND password_hash=?",
        (username, hash_password(password))
    ).fetchone()
    if not user:
        return jsonify({"error": "用戶名或密碼錯誤"}), 401
    token = make_token(user["id"], user["username"], user["role"])
    return jsonify({
        "token": token,
        "user": {"id": user["id"], "username": user["username"], "role": user["role"]}
    })

@app.route("/api/auth/me", methods=["GET"])
@require_auth
def me():
    db = get_db()
    user = db.execute("SELECT id,username,role,created_at FROM users WHERE id=?", (g.user_id,)).fetchone()
    if not user:
        return jsonify({"error": "用戶不存在"}), 404
    return jsonify(dict(user))

@app.route("/api/auth/change-password", methods=["POST"])
@require_auth
def change_password():
    data = request.json or {}
    old_pw = data.get("oldPassword", "")
    new_pw = data.get("newPassword", "")
    db = get_db()
    user = db.execute(
        "SELECT id FROM users WHERE id=? AND password_hash=?",
        (g.user_id, hash_password(old_pw))
    ).fetchone()
    if not user:
        return jsonify({"error": "舊密碼錯誤"}), 400
    db.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(new_pw), g.user_id))
    db.commit()
    add_log("修改密碼", f"用戶 {g.username} 修改了密碼")
    return jsonify({"ok": True})

# ─── 用戶管理 API ────────────────────────────────────────────────

@app.route("/api/users", methods=["GET"])
@require_admin
def get_users():
    db = get_db()
    rows = db.execute("SELECT id,username,role,created_at FROM users ORDER BY created_at").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/users", methods=["POST"])
@require_admin
def create_user():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role = data.get("role", "operator")
    if not username or not password:
        return jsonify({"error": "用戶名和密碼不能為空"}), 400
    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if existing:
        return jsonify({"error": "用戶名已存在"}), 400
    uid = new_id()
    db.execute(
        "INSERT INTO users (id,username,password_hash,role,created_at) VALUES (?,?,?,?,?)",
        (uid, username, hash_password(password), role, now())
    )
    db.commit()
    add_log("新增用戶", f"新增用戶 {username}，角色：{role}")
    return jsonify({"id": uid, "username": username, "role": role})

@app.route("/api/users/<uid>", methods=["DELETE"])
@require_admin
def delete_user(uid):
    if uid == g.user_id:
        return jsonify({"error": "不能刪除自己"}), 400
    db = get_db()
    user = db.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
    if not user:
        return jsonify({"error": "用戶不存在"}), 404
    db.execute("DELETE FROM users WHERE id=?", (uid,))
    db.commit()
    add_log("刪除用戶", f"刪除用戶 {user['username']}")
    return jsonify({"ok": True})

# ─── 漁民 API ────────────────────────────────────────────────────

@app.route("/api/fishermen", methods=["GET"])
@require_auth
def get_fishermen():
    db = get_db()
    rows = db.execute("SELECT * FROM fishermen ORDER BY created_at DESC").fetchall()
    result = []
    for r in rows:
        f = dict(r)
        txns = db.execute(
            "SELECT * FROM prepayment_transactions WHERE fisherman_id=? ORDER BY date DESC",
            (f["id"],)
        ).fetchall()
        f["transactions"] = [dict(t) for t in txns]
        # 轉換 snake_case -> camelCase
        result.append({
            "id": f["id"],
            "name": f["name"],
            "phone": f["phone"],
            "address": f["address"],
            "prepayment": f["prepayment"],
            "notes": f["notes"],
            "createdAt": f["created_at"],
            "updatedAt": f["updated_at"],
            "transactions": [{
                "id": t["id"],
                "date": t["date"],
                "type": t["type"],
                "amount": t["amount"],
                "balance": t["balance"],
                "notes": t["notes"],
            } for t in [dict(x) for x in db.execute(
                "SELECT * FROM prepayment_transactions WHERE fisherman_id=? ORDER BY date DESC",
                (f["id"],)
            ).fetchall()]]
        })
    return jsonify(result)

@app.route("/api/fishermen/<fid>", methods=["GET"])
@require_auth
def get_fisherman(fid):
    db = get_db()
    f = db.execute("SELECT * FROM fishermen WHERE id=?", (fid,)).fetchone()
    if not f:
        return jsonify({"error": "漁民不存在"}), 404
    f = dict(f)
    txns = db.execute(
        "SELECT * FROM prepayment_transactions WHERE fisherman_id=? ORDER BY date DESC",
        (fid,)
    ).fetchall()
    return jsonify({
        "id": f["id"], "name": f["name"], "phone": f["phone"],
        "address": f["address"], "prepayment": f["prepayment"],
        "notes": f["notes"], "createdAt": f["created_at"], "updatedAt": f["updated_at"],
        "transactions": [{"id": t["id"], "date": t["date"], "type": t["type"],
                          "amount": t["amount"], "balance": t["balance"], "notes": t["notes"]}
                         for t in [dict(x) for x in txns]]
    })

@app.route("/api/fishermen", methods=["POST"])
@require_auth
def create_fisherman():
    data = request.json or {}
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "漁民姓名不能為空"}), 400
    fid = new_id()
    t = now()
    db = get_db()
    db.execute(
        "INSERT INTO fishermen (id,name,phone,address,prepayment,notes,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
        (fid, name, data.get("phone"), data.get("address"), data.get("prepayment", 0), data.get("notes"), t, t)
    )
    # 如有初始預付款，記錄交易
    if data.get("prepayment", 0) > 0:
        db.execute(
            "INSERT INTO prepayment_transactions (id,fisherman_id,date,type,amount,balance,notes) VALUES (?,?,?,?,?,?,?)",
            (new_id(), fid, t[:10], "topup", data["prepayment"], data["prepayment"], "初始預付款")
        )
    db.commit()
    add_log("新增漁民", f"新增漁民：{name}")
    return jsonify({"id": fid, "name": name})

@app.route("/api/fishermen/<fid>", methods=["PUT"])
@require_auth
def update_fisherman(fid):
    data = request.json or {}
    db = get_db()
    f = db.execute("SELECT * FROM fishermen WHERE id=?", (fid,)).fetchone()
    if not f:
        return jsonify({"error": "漁民不存在"}), 404
    db.execute(
        "UPDATE fishermen SET name=?,phone=?,address=?,notes=?,updated_at=? WHERE id=?",
        (data.get("name", f["name"]), data.get("phone", f["phone"]),
         data.get("address", f["address"]), data.get("notes", f["notes"]), now(), fid)
    )
    db.commit()
    add_log("更新漁民", f"更新漁民：{f['name']}")
    return jsonify({"ok": True})

@app.route("/api/fishermen/<fid>/prepayment", methods=["POST"])
@require_auth
def add_prepayment(fid):
    data = request.json or {}
    amount = float(data.get("amount", 0))
    txn_type = data.get("type", "topup")
    db = get_db()
    f = db.execute("SELECT * FROM fishermen WHERE id=?", (fid,)).fetchone()
    if not f:
        return jsonify({"error": "漁民不存在"}), 404
    current = f["prepayment"]
    if txn_type == "topup":
        new_balance = current + amount
    else:
        new_balance = current - amount
    db.execute("UPDATE fishermen SET prepayment=?,updated_at=? WHERE id=?", (new_balance, now(), fid))
    txn_id = new_id()
    db.execute(
        "INSERT INTO prepayment_transactions (id,fisherman_id,date,type,amount,balance,notes) VALUES (?,?,?,?,?,?,?)",
        (txn_id, fid, data.get("date", now()[:10]), txn_type, amount, new_balance, data.get("notes"))
    )
    db.commit()
    add_log("預付款操作", f"漁民 {f['name']} {'充值' if txn_type=='topup' else '扣款'} {amount} Ar，餘額：{new_balance} Ar")
    return jsonify({"balance": new_balance, "transactionId": txn_id})

@app.route("/api/fishermen/<fid>", methods=["DELETE"])
@require_admin
def delete_fisherman(fid):
    db = get_db()
    f = db.execute("SELECT name FROM fishermen WHERE id=?", (fid,)).fetchone()
    if not f:
        return jsonify({"error": "漁民不存在"}), 404
    db.execute("DELETE FROM prepayment_transactions WHERE fisherman_id=?", (fid,))
    db.execute("DELETE FROM fishermen WHERE id=?", (fid,))
    db.commit()
    add_log("刪除漁民", f"刪除漁民：{f['name']}")
    return jsonify({"ok": True})

# ─── 收貨記錄 API ────────────────────────────────────────────────

@app.route("/api/receiving", methods=["GET"])
@require_auth
def get_receiving():
    db = get_db()
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 50))
    fisherman_id = request.args.get("fishermanId")
    date_from = request.args.get("dateFrom")
    date_to = request.args.get("dateTo")

    where = []
    params = []
    if fisherman_id:
        where.append("fisherman_id=?")
        params.append(fisherman_id)
    if date_from:
        where.append("date>=?")
        params.append(date_from)
    if date_to:
        where.append("date<=?")
        params.append(date_to)

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    total = db.execute(f"SELECT COUNT(*) FROM receiving_records {where_sql}", params).fetchone()[0]
    rows = db.execute(
        f"SELECT * FROM receiving_records {where_sql} ORDER BY date DESC, created_at DESC LIMIT ? OFFSET ?",
        params + [limit, (page - 1) * limit]
    ).fetchall()

    records = []
    for r in rows:
        rec = dict(r)
        records.append({
            "id": rec["id"], "date": rec["date"],
            "fishermanId": rec["fisherman_id"], "fishermanName": rec["fisherman_name"],
            "liveItems": json.loads(rec["live_items"]),
            "deadItems": json.loads(rec["dead_items"]),
            "liveTotalPrice": rec["live_total_price"],
            "deadTotalPrice": rec["dead_total_price"],
            "totalAmount": rec["total_amount"],
            "paymentMethod": rec["payment_method"],
            "cashPaid": rec["cash_paid"],
            "prepaymentDeducted": rec["prepayment_deducted"],
            "remainingPrepayment": rec["remaining_prepayment"],
            "notes": rec["notes"],
            "createdBy": rec["created_by"],
            "createdAt": rec["created_at"],
            "updatedAt": rec["updated_at"],
        })
    return jsonify({"records": records, "total": total, "page": page, "limit": limit})

@app.route("/api/receiving/<rid>", methods=["GET"])
@require_auth
def get_receiving_record(rid):
    db = get_db()
    r = db.execute("SELECT * FROM receiving_records WHERE id=?", (rid,)).fetchone()
    if not r:
        return jsonify({"error": "記錄不存在"}), 404
    rec = dict(r)
    return jsonify({
        "id": rec["id"], "date": rec["date"],
        "fishermanId": rec["fisherman_id"], "fishermanName": rec["fisherman_name"],
        "liveItems": json.loads(rec["live_items"]),
        "deadItems": json.loads(rec["dead_items"]),
        "liveTotalPrice": rec["live_total_price"],
        "deadTotalPrice": rec["dead_total_price"],
        "totalAmount": rec["total_amount"],
        "paymentMethod": rec["payment_method"],
        "cashPaid": rec["cash_paid"],
        "prepaymentDeducted": rec["prepayment_deducted"],
        "remainingPrepayment": rec["remaining_prepayment"],
        "notes": rec["notes"],
        "createdBy": rec["created_by"],
        "createdAt": rec["created_at"],
        "updatedAt": rec["updated_at"],
    })

@app.route("/api/receiving", methods=["POST"])
@require_auth
def create_receiving():
    data = request.json or {}
    rid = new_id()
    t = now()
    db = get_db()
    db.execute("""
        INSERT INTO receiving_records
        (id,date,fisherman_id,fisherman_name,live_items,dead_items,
         live_total_price,dead_total_price,total_amount,payment_method,
         cash_paid,prepayment_deducted,remaining_prepayment,notes,created_by,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        rid, data["date"], data["fishermanId"], data["fishermanName"],
        json.dumps(data.get("liveItems", []), ensure_ascii=False),
        json.dumps(data.get("deadItems", []), ensure_ascii=False),
        data.get("liveTotalPrice", 0), data.get("deadTotalPrice", 0),
        data.get("totalAmount", 0), data.get("paymentMethod", "cash"),
        data.get("cashPaid"), data.get("prepaymentDeducted"),
        data.get("remainingPrepayment"), data.get("notes"),
        g.username, t, t
    ))
    # 如果用預付款結算，更新漁民預付款餘額
    if data.get("paymentMethod") == "prepayment" and data.get("prepaymentDeducted"):
        deducted = float(data["prepaymentDeducted"])
        remaining = float(data.get("remainingPrepayment", 0))
        fid = data["fishermanId"]
        db.execute("UPDATE fishermen SET prepayment=?,updated_at=? WHERE id=?", (remaining, t, fid))
        db.execute(
            "INSERT INTO prepayment_transactions (id,fisherman_id,date,type,amount,balance,notes) VALUES (?,?,?,?,?,?,?)",
            (new_id(), fid, data["date"], "deduct", deducted, remaining, f"收貨結算 #{rid[:8]}")
        )
    db.commit()
    add_log("新增收貨", f"新增收貨記錄，漁民：{data['fishermanName']}，金額：{data.get('totalAmount', 0)} Ar")
    return jsonify({"id": rid})

@app.route("/api/receiving/<rid>", methods=["DELETE"])
@require_admin
def delete_receiving(rid):
    db = get_db()
    r = db.execute("SELECT fisherman_name,total_amount FROM receiving_records WHERE id=?", (rid,)).fetchone()
    if not r:
        return jsonify({"error": "記錄不存在"}), 404
    db.execute("DELETE FROM receiving_records WHERE id=?", (rid,))
    db.commit()
    add_log("刪除收貨", f"刪除收貨記錄，漁民：{r['fisherman_name']}，金額：{r['total_amount']} Ar")
    return jsonify({"ok": True})

# ─── 庫存 API ────────────────────────────────────────────────────

@app.route("/api/inventory", methods=["GET"])
@require_auth
def get_inventory():
    db = get_db()
    rows = db.execute("SELECT * FROM inventory_changes ORDER BY date DESC, created_at DESC LIMIT 200").fetchall()
    return jsonify([{
        "id": r["id"], "date": r["date"], "type": r["type"],
        "lobsterType": r["lobster_type"], "quantity": r["quantity"],
        "weight": r["weight"], "unitPrice": r["unit_price"],
        "totalPrice": r["total_price"], "reason": r["reason"],
        "notes": r["notes"], "createdBy": r["created_by"], "createdAt": r["created_at"]
    } for r in rows])

@app.route("/api/inventory/summary", methods=["GET"])
@require_auth
def get_inventory_summary():
    db = get_db()
    rows = db.execute("""
        SELECT lobster_type,
               SUM(CASE WHEN type='in' THEN quantity ELSE -quantity END) as quantity,
               SUM(CASE WHEN type='in' THEN weight ELSE -weight END) as weight
        FROM inventory_changes
        GROUP BY lobster_type
    """).fetchall()
    return jsonify([{
        "lobsterType": r["lobster_type"],
        "quantity": max(0, r["quantity"] or 0),
        "weight": max(0, r["weight"] or 0)
    } for r in rows])

@app.route("/api/inventory", methods=["POST"])
@require_auth
def create_inventory():
    data = request.json or {}
    iid = new_id()
    t = now()
    db = get_db()
    db.execute("""
        INSERT INTO inventory_changes
        (id,date,type,lobster_type,quantity,weight,unit_price,total_price,reason,notes,created_by,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        iid, data["date"], data["type"], data["lobsterType"],
        data.get("quantity", 0), data.get("weight", 0),
        data.get("unitPrice"), data.get("totalPrice"),
        data.get("reason"), data.get("notes"), g.username, t
    ))
    db.commit()
    type_names = {"in": "入池", "out": "出貨", "loss": "損耗"}
    add_log("庫存操作", f"{type_names.get(data['type'], data['type'])}：{data['lobsterType']} {data.get('weight', 0)} 斤")
    return jsonify({"id": iid})

@app.route("/api/inventory/<iid>", methods=["DELETE"])
@require_admin
def delete_inventory(iid):
    db = get_db()
    r = db.execute("SELECT lobster_type FROM inventory_changes WHERE id=?", (iid,)).fetchone()
    if not r:
        return jsonify({"error": "記錄不存在"}), 404
    db.execute("DELETE FROM inventory_changes WHERE id=?", (iid,))
    db.commit()
    add_log("刪除庫存記錄", f"刪除庫存記錄：{r['lobster_type']}")
    return jsonify({"ok": True})

# ─── 統計 API ────────────────────────────────────────────────────

@app.route("/api/analytics/dashboard", methods=["GET"])
@require_auth
def get_dashboard():
    db = get_db()
    today = datetime.utcnow().strftime("%Y-%m-%d")

    # 今日收貨
    today_records = db.execute(
        "SELECT * FROM receiving_records WHERE date=?", (today,)
    ).fetchall()
    today_live_weight = sum(
        sum(item["weight"] for item in json.loads(r["live_items"]))
        for r in today_records
    )
    today_dead_weight = sum(
        sum(item["weight"] for item in json.loads(r["dead_items"]))
        for r in today_records
    )
    today_total = sum(r["total_amount"] for r in today_records)

    # 當前庫存
    inv = db.execute("""
        SELECT SUM(CASE WHEN type='in' THEN quantity ELSE -quantity END) as qty,
               SUM(CASE WHEN type='in' THEN weight ELSE -weight END) as wt
        FROM inventory_changes
    """).fetchone()

    # 漁民統計
    total_fishermen = db.execute("SELECT COUNT(*) FROM fishermen").fetchone()[0]
    low_prepayment = db.execute("SELECT COUNT(*) FROM fishermen WHERE prepayment < 5000").fetchone()[0]

    return jsonify({
        "todayReceivingCount": len(today_records),
        "todayLiveWeight": today_live_weight,
        "todayDeadWeight": today_dead_weight,
        "todayTotalAmount": today_total,
        "currentInventoryCount": max(0, inv["qty"] or 0),
        "currentInventoryWeight": max(0, inv["wt"] or 0),
        "totalFishermen": total_fishermen,
        "lowPrepaymentCount": low_prepayment,
    })

@app.route("/api/analytics/monthly", methods=["GET"])
@require_auth
def get_monthly():
    db = get_db()
    year = request.args.get("year", datetime.utcnow().strftime("%Y"))
    rows = db.execute("""
        SELECT substr(date,1,7) as month,
               COUNT(*) as count,
               SUM(total_amount) as total,
               SUM(live_total_price) as live_total,
               SUM(dead_total_price) as dead_total,
               GROUP_CONCAT(live_items, '||') as all_live,
               GROUP_CONCAT(dead_items, '||') as all_dead
        FROM receiving_records
        WHERE date LIKE ?
        GROUP BY month
        ORDER BY month
    """, (f"{year}%",)).fetchall()
    result = []
    for r in rows:
        live_weight = 0.0
        dead_weight = 0.0
        if r["all_live"]:
            for items_str in r["all_live"].split('||'):
                try:
                    for it in json.loads(items_str):
                        live_weight += it.get("weight", 0) or 0
                except Exception:
                    pass
        if r["all_dead"]:
            for items_str in r["all_dead"].split('||'):
                try:
                    for it in json.loads(items_str):
                        dead_weight += it.get("weight", 0) or 0
                except Exception:
                    pass
        result.append({
            "month": r["month"],
            "count": r["count"],
            "totalAmount": r["total"] or 0,
            "liveTotal": r["live_total"] or 0,
            "deadTotal": r["dead_total"] or 0,
            "liveWeight": round(live_weight, 2),
            "deadWeight": round(dead_weight, 2),
        })
    return jsonify(result)

@app.route("/api/analytics/by-fisherman", methods=["GET"])
@require_auth
def get_by_fisherman():
    db = get_db()
    date_from = request.args.get("dateFrom", "2020-01-01")
    date_to = request.args.get("dateTo", "2099-12-31")
    rows = db.execute("""
        SELECT fisherman_id, fisherman_name,
               COUNT(*) as count,
               SUM(total_amount) as total,
               GROUP_CONCAT(live_items, '||') as all_live,
               GROUP_CONCAT(dead_items, '||') as all_dead
        FROM receiving_records
        WHERE date BETWEEN ? AND ?
        GROUP BY fisherman_id
        ORDER BY total DESC
    """, (date_from, date_to)).fetchall()
    result = []
    for r in rows:
        live_weight = 0.0
        dead_weight = 0.0
        if r["all_live"]:
            for items_str in r["all_live"].split('||'):
                try:
                    for it in json.loads(items_str):
                        live_weight += it.get("weight", 0) or 0
                except Exception:
                    pass
        if r["all_dead"]:
            for items_str in r["all_dead"].split('||'):
                try:
                    for it in json.loads(items_str):
                        dead_weight += it.get("weight", 0) or 0
                except Exception:
                    pass
        result.append({
            "fishermanId": r["fisherman_id"],
            "fishermanName": r["fisherman_name"],
            "count": r["count"],
            "totalAmount": r["total"] or 0,
            "liveWeight": round(live_weight, 2),
            "deadWeight": round(dead_weight, 2),
        })
    return jsonify(result)

# ─── 操作日誌 API ────────────────────────────────────────────────

@app.route("/api/logs", methods=["GET"])
@require_admin
def get_logs():
    db = get_db()
    limit = int(request.args.get("limit", 100))
    rows = db.execute(
        "SELECT * FROM operation_logs ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    return jsonify([{
        "id": r["id"], "userId": r["user_id"], "username": r["username"],
        "action": r["action"], "details": r["details"], "createdAt": r["created_at"]
    } for r in rows])

# ─── 健康檢查 ────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": now()})

# ─── 啟動 ────────────────────────────────────────────

# 初始化資料庫（gunicorn 和直接執行都會調用）
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 4000))
    print(f"Starting server on port {port}...")
    app.run(host="0.0.0.0", port=port, debug=False)