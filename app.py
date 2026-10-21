from datetime import datetime
import base64
import io
import json
import os
import random
import secrets

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from PIL import Image
from werkzeug.security import check_password_hash, generate_password_hash


ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
FREE_MONTHLY_LIMIT = 100
PREMIUM_MONTHLY_LIMIT = 5000
DEFAULT_BLOCK_SIZE = 8
SHORT_KEY_LENGTH = 10
MAX_IMAGE_BYTES = 25 * 1024 * 1024
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "bmp", "gif", "webp"}


def base62_encode(data_bytes: bytes) -> str:
    if not data_bytes:
        return ALPHABET[0]
    n = int.from_bytes(data_bytes, "big")
    if n == 0:
        return ALPHABET[0]
    chars = []
    while n:
        n, r = divmod(n, 62)
        chars.append(ALPHABET[r])
    return "".join(reversed(chars))


def base62_decode(token: str) -> bytes:
    if not token:
        return b""
    n = 0
    for ch in token:
        if ch not in ALPHABET:
            raise ValueError("密钥只能包含字母和数字")
        n = n * 62 + ALPHABET.index(ch)
    size = max(1, (n.bit_length() + 7) // 8)
    return n.to_bytes(size, "big")


def encode_key(key_obj: dict) -> str:
    payload = json.dumps(key_obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base62_encode(payload)


def decode_key(token: str) -> dict:
    try:
        return json.loads(base62_decode(token).decode("utf-8"))
    except Exception as exc:
        raise ValueError("无效的密钥格式") from exc


def data_url_to_image(image_data: str) -> Image.Image:
    if not image_data:
        raise ValueError("缺少图片数据")
    if "," in image_data and image_data.startswith("data:"):
        image_data = image_data.split(",", 1)[1]
    raw = base64.b64decode(image_data, validate=True)
    if len(raw) > MAX_IMAGE_BYTES:
        raise ValueError("图片过大")
    return Image.open(io.BytesIO(raw)).convert("RGBA")


def image_to_data_url(image: Image.Image) -> str:
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")


def clamp_region(region, image_width, image_height):
    x, y, w, h = [int(round(float(v))) for v in region[:4]]
    x = max(0, min(x, image_width - 1))
    y = max(0, min(y, image_height - 1))
    w = max(1, min(w, image_width - x))
    h = max(1, min(h, image_height - y))
    return [x, y, w, h]


def make_block_slots(region, block_size=DEFAULT_BLOCK_SIZE):
    x, y, w, h = region
    block_size = max(1, int(block_size))
    slots = []
    for by in range(y, y + h, block_size):
        bh = min(block_size, y + h - by)
        for bx in range(x, x + w, block_size):
            bw = min(block_size, x + w - bx)
            slots.append({"x": bx, "y": by, "w": bw, "h": bh})
    return slots


def build_region_plan(region, seed=None, block_size=DEFAULT_BLOCK_SIZE):
    seed = random.randint(0, 2**32 - 1) if seed is None else int(seed)
    slots = make_block_slots(region, block_size)
    groups = {}
    for index, slot in enumerate(slots):
        groups.setdefault((slot["w"], slot["h"]), []).append(index)

    rng = random.Random(seed)
    mappings = []
    for indexes in groups.values():
        shuffled = indexes[:]
        rng.shuffle(shuffled)
        for target_index, source_index in zip(indexes, shuffled):
            source = slots[source_index]
            target = slots[target_index]
            mappings.append(
                {
                    "from": [source["x"], source["y"]],
                    "to": [target["x"], target["y"]],
                    "size": [source["w"], source["h"]],
                }
            )

    return {
        "x": region[0],
        "y": region[1],
        "w": region[2],
        "h": region[3],
        "block_size": int(block_size),
        "seed": seed,
        "blocks": mappings,
    }


def apply_block_scramble(image: Image.Image, region_plan: dict) -> Image.Image:
    result = image.copy()
    pixels = result.load()
    source_blocks = []
    for block in region_plan["blocks"]:
        sx, sy = block["from"]
        bw, bh = block["size"]
        source_blocks.append((block, image.crop((sx, sy, sx + bw, sy + bh))))
    for block, tile in source_blocks:
        tx, ty = block["to"]
        pixels  # keeps Pillow loading before paste on some versions
        result.paste(tile, (tx, ty))
    return result


def apply_block_unscramble(image: Image.Image, region_plan: dict) -> Image.Image:
    result = image.copy()
    source_blocks = []
    for block in region_plan["blocks"]:
        tx, ty = block["to"]
        bw, bh = block["size"]
        source_blocks.append((block, image.crop((tx, ty, tx + bw, ty + bh))))
    for block, tile in source_blocks:
        sx, sy = block["from"]
        result.paste(tile, (sx, sy))
    return result


app = Flask(__name__)
app.secret_key = "your-secret-key-here-change-in-production"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_premium = db.Column(db.Boolean, default=False)
    usage_count = db.Column(db.Integer, default=0)
    last_reset = db.Column(db.DateTime, default=datetime.utcnow)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def monthly_limit(self):
        return PREMIUM_MONTHLY_LIMIT if self.is_premium else FREE_MONTHLY_LIMIT

    def reset_if_needed(self):
        now = datetime.utcnow()
        if self.last_reset.month != now.month or self.last_reset.year != now.year:
            self.usage_count = 0
            self.last_reset = now
            db.session.commit()

    def remaining_quota(self):
        self.reset_if_needed()
        return max(0, self.monthly_limit() - self.usage_count)

    def increment_usage(self, count=1):
        self.reset_if_needed()
        self.usage_count += count
        db.session.commit()


class RestorePlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(32), unique=True, nullable=False, index=True)
    plan_json = db.Column(db.Text, nullable=False)
    owner_user_id = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def as_key_obj(self):
        return json.loads(self.plan_json)


with app.app_context():
    db.create_all()


def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return User.query.get(user_id)


def current_quota_payload(user):
    if not user:
        return None
    return {
        "remaining": user.remaining_quota(),
        "limit": user.monthly_limit(),
        "used": user.usage_count,
        "is_premium": user.is_premium,
    }


def generate_short_token(length=SHORT_KEY_LENGTH):
    for _ in range(20):
        token = "".join(secrets.choice(ALPHABET) for _ in range(length))
        if not RestorePlan.query.filter_by(token=token).first():
            return token
    raise RuntimeError("无法生成唯一短密钥")


def save_restore_plan(key_obj, user=None):
    restore_plan = RestorePlan(
        token=generate_short_token(),
        plan_json=json.dumps(key_obj, ensure_ascii=False, separators=(",", ":")),
        owner_user_id=user.id if user else None,
    )
    db.session.add(restore_plan)
    db.session.commit()
    return restore_plan.token


def resolve_restore_key(key):
    if isinstance(key, dict):
        return key
    if not isinstance(key, str):
        raise ValueError("密钥格式不受支持")

    token = key.strip()
    if not token:
        raise ValueError("缺少密钥")

    restore_plan = RestorePlan.query.filter_by(token=token).first()
    if restore_plan:
        return restore_plan.as_key_obj()

    # Backward compatibility for old long self-contained base62 keys.
    return decode_key(token)


@app.route("/")
def index():
    user = get_current_user()
    return render_template("index.html", current_user=user, quota=current_quota_payload(user))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    if not email or not password:
        return render_template("register.html", error="请输入邮箱和密码")

    if User.query.filter_by(email=email).first():
        return render_template("register.html", error="该邮箱已被注册")

    user = User(email=email, password_hash=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()
    session["user_id"] = user.id
    return redirect(url_for("index"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    if not email or not password:
        return render_template("login.html", error="请输入邮箱和密码")

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return render_template("login.html", error="邮箱或密码错误")

    session["user_id"] = user.id
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect(url_for("index"))


@app.route("/activate", methods=["POST"])
def activate():
    user = get_current_user()
    if not user:
        return jsonify({"success": False, "error": "请先登录"}), 401

    data = request.get_json(silent=True) or request.form or {}
    key = data.get("key", "").strip()
    if not key:
        return jsonify({"success": False, "error": "缺少激活码"}), 400

    if key in {"PREMIUM-SECRET-123", "PREMIUM-KEY-2026"}:
        user.is_premium = True
        user.usage_count = 0
        user.last_reset = datetime.utcnow()
        db.session.commit()
        return jsonify({"success": True, "message": "激活成功", "quota": current_quota_payload(user)})

    return jsonify({"success": False, "error": "无效的激活码"}), 400


@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("image")
    if not file or file.filename == "":
        return jsonify({"error": "没有上传文件"}), 400
    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({"error": "不支持的文件格式"}), 400
    return jsonify({"success": True})


@app.route("/scramble", methods=["POST"])
def scramble():
    user = get_current_user()
    if not user:
        return jsonify({"error": "需要登录后才能使用加密功能"}), 401

    data = request.get_json(silent=True) or {}
    regions = data.get("regions") or data.get("region")
    if not regions:
        return jsonify({"error": "无效的区域信息"}), 400
    if isinstance(regions, list) and regions and not isinstance(regions[0], list):
        regions = [regions]

    if user.remaining_quota() < len(regions):
        return jsonify({"error": "本月可用额度不足，请升级或下月重置"}), 403

    try:
        image = data_url_to_image(data.get("image"))
        image_width, image_height = image.size
        block_size = int(data.get("block_size") or DEFAULT_BLOCK_SIZE)
        plans = [build_region_plan(clamp_region(r, image_width, image_height), block_size=block_size) for r in regions]

        result = image
        for plan in plans:
            result = apply_block_scramble(result, plan)

        key_obj = {
            "version": "2.0",
            "method": "block_shuffle",
            "image_size": [image_width, image_height],
            "regions": plans,
        }
        token = save_restore_plan(key_obj, user)
        user.increment_usage(len(plans))

        return jsonify(
            {
                "success": True,
                "image": image_to_data_url(result),
                "key_token": token,
                "key_mode": "server_restore_plan",
                "quota": current_quota_payload(user),
            }
        )
    except Exception as exc:
        return jsonify({"error": f"加密失败: {exc}"}), 400


@app.route("/unscramble", methods=["POST"])
def unscramble():
    data = request.get_json(silent=True) or {}
    key = data.get("key")
    if not key:
        return jsonify({"error": "缺少密钥"}), 400

    try:
        key_obj = resolve_restore_key(key)
        if key_obj.get("method") != "block_shuffle":
            return jsonify({"error": "当前版本仅支持块级打乱密钥"}), 400

        image = data_url_to_image(data.get("image"))
        result = image
        for plan in key_obj.get("regions", []):
            result = apply_block_unscramble(result, plan)

        return jsonify({"success": True, "image": image_to_data_url(result)})
    except Exception as exc:
        return jsonify({"error": f"还原失败: {exc}"}), 400


if __name__ == "__main__":
    os.makedirs("instance", exist_ok=True)
    app.run(debug=True, host="0.0.0.0", port=5000)
