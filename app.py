"""
منصة صحة - الاستعلام عن الإجازات المرضية + لوحة تحكم الأدمن
=====================================================================
يستخدم GitHub كمستودع للبيانات السحابية. السجلات محفوظة في ملف
data/sick_leaves.json داخل المستودع نفسه، وأي تعديل (إضافة/تعديل/حذف)
يتم حفظه مباشرة في GitHub عبر API.

بهذا الشكل:
- البيانات جزء من الكود (مثل البيانات الافتراضية)
- عند إعادة تشغيل Render، يسحب أحدث نسخة من GitHub
- السجلات تبقى للأبد حتى لو حُذفت Render أو أُعيد نشرها

المسارات العامة:
  GET  /                       الصفحة الرئيسية (الاستعلام)
  POST /api/public-lookup      نقطة API العامة للاستعلام

المسارات الإدارية:
  GET  /admin/login            صفحة تسجيل دخول الأدمن
  POST /admin/login            معالجة تسجيل الدخول
  GET  /admin/logout            تسجيل الخروج
  GET  /admin                  لوحة التحكم (عرض السجلات)
  GET  /admin/create           نموذج إنشاء سجل جديد
  POST /admin/create            حفظ السجل الجديد
  GET  /admin/edit/<id>         نموذج تعديل سجل
  POST /admin/edit/<id>         حفظ التعديلات
  POST /admin/delete/<id>       حذف سجل

بيانات دخول الأدمن:
  اسم المستخدم: shaher
  كلمة المرور: sh88664422
"""

import os
import json
import base64
import hmac
import secrets
import threading
import urllib.request
import urllib.error
from datetime import datetime, date
from functools import wraps
from flask import (
    Flask, request, render_template, jsonify, Response,
    redirect, url_for, session, flash, g, send_file
)
from io import BytesIO

# مكتبات توليد PDF وتحويل التواريخ
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import inch, cm, mm
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.lib.enums import TA_LEFT, TA_RIGHT, TA_CENTER
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    import arabic_reshaper
    from bidi.algorithm import get_display
    ARABIC_SHAPING_AVAILABLE = True
except ImportError:
    ARABIC_SHAPING_AVAILABLE = False

try:
    from hijridate import Gregorian
    HIJRI_AVAILABLE = True
except ImportError:
    HIJRI_AVAILABLE = False


# تسجيل خط Cairo للاستخدام في PDF
FONT_REGISTERED = False
def register_fonts():
    """تسجيل خط Cairo للاستخدام في توليد PDF."""
    global FONT_REGISTERED
    if FONT_REGISTERED or not REPORTLAB_AVAILABLE:
        return FONT_REGISTERED
    try:
        font_path_regular = os.path.join(BASE_DIR, "static", "fonts", "Cairo-VF.ttf")
        if os.path.exists(font_path_regular):
            pdfmetrics.registerFont(TTFont("Cairo", font_path_regular))
            pdfmetrics.registerFont(TTFont("Cairo-Bold", font_path_regular))
            FONT_REGISTERED = True
            return True
    except Exception:
        pass
    return False


def ar(text):
    """تشكيل النص العربي لعرضه بشكل صحيح في PDF (معRTL)."""
    if not text or not ARABIC_SHAPING_AVAILABLE:
        return text or ""
    try:
        reshaped = arabic_reshaper.reshape(str(text))
        return get_display(reshaped)
    except Exception:
        return str(text)

# ====================================================================
# إعدادات التطبيق
# ====================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
DATA_DIR = os.path.join(BASE_DIR, "data")
DATA_FILE_LOCAL = os.path.join(DATA_DIR, "sick_leaves.json")

SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# بيانات الأدمن
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "shaher")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "sh88664422")

# إعدادات GitHub للتخزين السحابي
GH_TOKEN = os.environ.get("GH_TOKEN", "")
GH_REPO = os.environ.get("GH_REPO", "shaher8642/sa-sehaty-sa")
GH_BRANCH = os.environ.get("GH_BRANCH", "main")
GH_DATA_PATH = "data/sick_leaves.json"

app = Flask(
    __name__,
    static_folder=STATIC_DIR,
    template_folder=os.path.join(BASE_DIR, "templates"),
)
app.config["JSON_SORT_KEYS"] = False
app.config["JSON_AS_ASCII"] = False
app.secret_key = SECRET_KEY

# قفل لمنع التعديلات المتزامنة
_records_lock = threading.Lock()

# الكاش الذاتي للسجلات
_records_cache = None


# ====================================================================
# ترويسات الأمان
# ====================================================================
@app.after_request
def set_security_headers(response):
    """ترويسات أمان أساسية."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin-allow-popups"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "base-uri 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'self'; "
        "form-action 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net "
        "https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "font-src 'self' data: https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: blob: https:; "
        "connect-src 'self'"
    )
    return response


# ====================================================================
# السجلات الافتراضية (تُستخدم فقط عند عدم وجود ملف)
# ====================================================================
DEFAULT_RECORDS = [
    {
        "id": 1,
        "service_number": "GSL26063953142",
        "id_number": "1104279680",
        "name": "عبدالرحمن القحطاني",
        "issue_date": "2026-09-25",
        "start_date": "2026-09-26",
        "end_date": "2026-09-28",
        "w_day": 3,
        "doctor": "د. أحمد الشهري",
        "doctor_title": "استشاري طب الأسرة",
    },
    {
        "id": 2,
        "service_number": "SL1234567890",
        "id_number": "1023456789",
        "name": "أحمد محمد العتيبي",
        "issue_date": "2026-09-20",
        "start_date": "2026-09-21",
        "end_date": "2026-09-23",
        "w_day": 3,
        "doctor": "د. خالد الزهراني",
        "doctor_title": "استشاري طب الأسرة",
    },
    {
        "id": 3,
        "service_number": "SL9876543210",
        "id_number": "1023456788",
        "name": "سارة عبدالله القحطاني",
        "issue_date": "2026-09-22",
        "start_date": "2026-09-22",
        "end_date": "2026-09-24",
        "w_day": 3,
        "doctor": "د. منى الشهري",
        "doctor_title": "استشاري باطنة",
    },
    {
        "id": 4,
        "service_number": "SL5555555555",
        "id_number": "1234567890",
        "name": "فهد ناصر الدوسري",
        "issue_date": "2026-09-23",
        "start_date": "2026-09-24",
        "end_date": "2026-09-26",
        "w_day": 3,
        "doctor": "د. ريم العنزي",
        "doctor_title": "اخصائي اطفال",
    },
    {
        "id": 5,
        "service_number": "SL1111111111",
        "id_number": "1234567891",
        "name": "نورة سعد الحربي",
        "issue_date": "2026-09-24",
        "start_date": "2026-09-25",
        "end_date": "2026-09-27",
        "w_day": 3,
        "doctor": "د. طارق المطيري",
        "doctor_title": "استشاري عظام",
    },
    {
        "id": 6,
        "service_number": "SL2222222222",
        "id_number": "1234567892",
        "name": "محمد علي الغامدي",
        "issue_date": "2026-09-25",
        "start_date": "2026-09-25",
        "end_date": "2026-09-26",
        "w_day": 2,
        "doctor": "د. هدى السبيعي",
        "doctor_title": "اخصائي ممارس عام",
    },
]


# ====================================================================
# طبقة التخزين: GitHub + ملف محلي
# ====================================================================
def _gh_request(url, method="GET", data=None, content_type="application/json"):
    """دالة مساعدة لتنفيذ طلبات GitHub API."""
    headers = {
        "Authorization": f"Bearer {GH_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "sa-sehaty-sa-app",
    }
    if data is not None:
        headers["Content-Type"] = content_type
        data = data.encode("utf-8") if isinstance(data, str) else data

    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_records_from_github():
    """جلب أحدث نسخة من السجلات من GitHub. يعيد (records, sha) أو (None, None)."""
    if not GH_TOKEN:
        return None, None

    url = f"https://api.github.com/repos/{GH_REPO}/contents/{GH_DATA_PATH}?ref={GH_BRANCH}"
    try:
        data = _gh_request(url)
        content = base64.b64decode(data.get("content", "")).decode("utf-8")
        records = json.loads(content)
        sha = data.get("sha")
        return records, sha
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None, None
        raise
    except Exception as e:
        print(f"⚠️ فشل الجلب من GitHub: {e}")
        return None, None


def push_records_to_github(records, sha=None):
    """رفع نسخة جديدة من السجلات إلى GitHub. يعيد True عند النجاح."""
    if not GH_TOKEN:
        return False

    content = json.dumps(records, ensure_ascii=False, indent=2)
    content_b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")

    payload = {
        "message": "chore: تحديث سجلات الإجازات المرضية",
        "content": content_b64,
        "branch": GH_BRANCH,
    }
    if sha:
        payload["sha"] = sha

    url = f"https://api.github.com/repos/{GH_REPO}/contents/{GH_DATA_PATH}"
    try:
        _gh_request(url, method="PUT", data=json.dumps(payload))
        return True
    except Exception as e:
        print(f"⚠️ فشل الرفع إلى GitHub: {e}")
        return False


def save_local_records(records):
    """حفظ السجلات في الملف المحلي (يفيد في التشغيل المحلي)."""
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(DATA_FILE_LOCAL, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)


def load_records(force_reload=False):
    """
    تحميل السجلات:
    - من الكاش الذاتي إن وُجد
    - من GitHub إن وُجد Token
    - من الملف المحلي إن وُجد
    - من DEFAULT_RECORDS كحل أخير
    """
    global _records_cache

    if _records_cache is not None and not force_reload:
        return _records_cache

    # محاولة GitHub أولاً (لأحدث نسخة)
    if GH_TOKEN:
        records, _ = fetch_records_from_github()
        if records is not None:
            _records_cache = records
            # حفظ محلياً للنسخ الاحتياطي
            try:
                save_local_records(records)
            except Exception:
                pass
            return records

    # محاولة الملف المحلي
    if os.path.exists(DATA_FILE_LOCAL):
        try:
            with open(DATA_FILE_LOCAL, "r", encoding="utf-8") as f:
                records = json.load(f)
                _records_cache = records
                return records
        except Exception:
            pass

    # الحل الافتراضي
    _records_cache = list(DEFAULT_RECORDS)
    return _records_cache


def save_records(records):
    """
    حفظ السجلات:
    - يحدّث الكاش الذاتي
    - يرفع إلى GitHub (إن وُجد Token)
    - يحفظ محلياً (للتشغيل المحلي)
    """
    global _records_cache
    with _records_lock:
        _records_cache = records

        # محاولة GitHub مع التحقق من SHA لتفادي التعارض
        if GH_TOKEN:
            _, sha = fetch_records_from_github()
            ok = push_records_to_github(records, sha=sha)
            if not ok:
                print("⚠️ فشل حفظ السجلات في GitHub")

        # حفظ محلي
        try:
            save_local_records(records)
        except Exception as e:
            print(f"⚠️ فشل الحفظ المحلي: {e}")


def find_record(records, service_number, id_number):
    """البحث عن سجل برمز الخدمة ورقم الهوية."""
    for r in records:
        if (
            r.get("service_number", "").upper() == service_number.upper()
            and r.get("id_number", "") == id_number
        ):
            return r
    return None


def normalize_digits(value):
    """تحويل الأرقام العربية/الفارسية إلى إنجليزية."""
    if not value:
        return ""
    out = []
    for ch in str(value):
        code = ord(ch)
        if 0x0660 <= code <= 0x0669:
            out.append(str(code - 0x0660))
        elif 0x06F0 <= code <= 0x06F9:
            out.append(str(code - 0x06F0))
        else:
            out.append(ch)
    return "".join(out)


def next_id(records):
    """إيجاد أحدث ID متاح."""
    max_id = 0
    for r in records:
        if r.get("id", 0) > max_id:
            max_id = r["id"]
    return max_id + 1


def json_response(data, status=200):
    """إرجاع JSON بنص عربي مباشر."""
    return Response(
        json.dumps(data, ensure_ascii=False),
        status=status,
        content_type="application/json; charset=utf-8",
    )


# ====================================================================
# دوال تحويل التواريخ وتوليد PDF
# ====================================================================
def to_hijri(gregorian_str):
    """تحويل تاريخ ميلادي (YYYY-MM-DD) إلى هجري بنفس الصيغة."""
    if not gregorian_str or not HIJRI_AVAILABLE:
        return gregorian_str or ""
    try:
        y, m, d = map(int, gregorian_str.split("-"))
        h = Gregorian(y, m, d).to_hijri()
        return f"{h.year}-{h.month:02d}-{h.day:02d}"
    except Exception:
        return gregorian_str


def format_gregorian_with_day_name(gregorian_str):
    """تنسيق تاريخ ميلادي مع اسم اليوم بالإنجليزي."""
    if not gregorian_str:
        return ""
    try:
        y, m, d = map(int, gregorian_str.split("-"))
        dt = date(y, m, d)
        day_names = ["Monday", "Tuesday", "Wednesday", "Thursday",
                     "Friday", "Saturday", "Sunday"]
        months = ["January", "February", "March", "April", "May", "June",
                  "July", "August", "September", "October", "November", "December"]
        return f"{day_names[dt.weekday()]}, {d} {months[m-1]} {y}"
    except Exception:
        return gregorian_str


def format_duration_en(start_date, end_date, w_day):
    """تنسيق مدة الإجازة بالإنجليزي."""
    if not start_date or not end_date:
        return ""
    # تحويل من YYYY-MM-DD إلى DD-MM-YYYY
    sd = "-".join(reversed(start_date.split("-")))
    ed = "-".join(reversed(end_date.split("-")))
    return f"{w_day} day ( {sd} to {ed} )"


def format_duration_ar(start_date, end_date, w_day, start_hijri, end_hijri):
    """تنسيق مدة الإجازة بالعربية مع التاريخ الهجري."""
    if not start_hijri or not end_hijri:
        return ""
    # تحويل من YYYY-MM-DD إلى DD-MM-YYYY
    sh = "-".join(reversed(start_hijri.split("-")))
    eh = "-".join(reversed(end_hijri.split("-")))
    return f"{w_day} يوم ( {sh} إلى {eh} )"


# ====================================================================
# دالة حماية مسارات الأدمن
# ====================================================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("admin_logged_in"):
            flash("يجب تسجيل الدخول للوصول إلى لوحة التحكم.", "error")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated_function


# ====================================================================
# المسارات العامة
# ====================================================================
@app.route("/")
def index():
    """الصفحة الرئيسية — الاستعلام عن الإجازات المرضية."""
    return render_template("inquiry.html")


@app.route("/api/public-lookup", methods=["POST"])
def public_lookup():
    """نقطة API العامة للاستعلام عن الإجازة المرضية."""
    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = request.form.to_dict()

    sn = data.get("service_number", "").strip().upper()
    idn = normalize_digits(data.get("id_number", "").strip())

    if not sn or not idn:
        return json_response(
            {"success": False, "message": "ادخل رمز الخدمة ورقم الهوية."}
        )

    records = load_records()
    record = find_record(records, sn, idn)

    if not record:
        return json_response(
            {"success": False, "message": "لا توجد بيانات مطابقة"}
        )

    return json_response({
        "success": True,
        "name": record["name"],
        "issue_date": record["issue_date"],
        "start_date": record["start_date"],
        "end_date": record["end_date"],
        "w_day": record["w_day"],
        "doctor": record["doctor"],
        "doctor_title": record["doctor_title"],
    })


# ====================================================================
# مسارات الأدمن
# ====================================================================
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """صفحة تسجيل دخول الأدمن."""
    if session.get("admin_logged_in"):
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user_ok = hmac.compare_digest(username, ADMIN_USERNAME)
        pass_ok = hmac.compare_digest(password, ADMIN_PASSWORD)

        if user_ok and pass_ok:
            session["admin_logged_in"] = True
            session["admin_username"] = username
            session.permanent = True
            flash("تم تسجيل الدخول بنجاح. مرحباً بك في لوحة التحكم.", "success")
            return redirect(url_for("admin_dashboard"))
        else:
            flash("اسم المستخدم أو كلمة المرور غير صحيحة.", "error")

    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    """تسجيل الخروج."""
    session.clear()
    flash("تم تسجيل الخروج بنجاح.", "success")
    return redirect(url_for("admin_login"))


@app.route("/admin")
@login_required
def admin_dashboard():
    """لوحة التحكم — عرض جميع السجلات والإحصاءات."""
    records = load_records(force_reload=True)

    total = len(records)
    unique_patients = len(set(r["id_number"] for r in records))
    unique_doctors = len(set(r["doctor"] for r in records))
    total_days = sum(int(r.get("w_day", 0)) for r in records)

    stats = {
        "total": total,
        "unique_patients": unique_patients,
        "unique_doctors": unique_doctors,
        "total_days": total_days,
    }

    return render_template(
        "admin_dashboard.html",
        records=records,
        stats=stats,
    )


@app.route("/admin/create", methods=["GET", "POST"])
@login_required
def admin_create():
    """نموذج إنشاء سجل إجازة جديد."""
    if request.method == "POST":
        service_number = request.form.get("service_number", "").strip().upper()
        id_number = normalize_digits(request.form.get("id_number", "").strip())
        name = request.form.get("name", "").strip()
        issue_date = request.form.get("issue_date", "")
        start_date = request.form.get("start_date", "")
        end_date = request.form.get("end_date", "")
        w_day = request.form.get("w_day", "1")
        doctor = request.form.get("doctor", "").strip()
        doctor_title = request.form.get("doctor_title", "").strip()

        errors = []
        if not service_number:
            errors.append("رمز الخدمة مطلوب")
        if not id_number:
            errors.append("رقم الهوية مطلوب")
        if not name:
            errors.append("اسم المريض مطلوب")
        if not issue_date:
            errors.append("تاريخ الإصدار مطلوب")
        if not start_date:
            errors.append("تاريخ البداية مطلوب")
        if not end_date:
            errors.append("تاريخ النهاية مطلوب")
        try:
            w_day_int = int(w_day)
            if w_day_int < 1:
                errors.append("عدد الأيام يجب أن يكون ≥ 1")
        except ValueError:
            errors.append("عدد الأيام يجب أن يكون رقماً")
            w_day_int = 1
        if not doctor:
            errors.append("اسم الطبيب مطلوب")
        if not doctor_title:
            errors.append("المسمى الوظيفي مطلوب")

        if errors:
            for err in errors:
                flash(err, "error")
            return render_template(
                "admin_form.html",
                is_edit=False,
                record=request.form,
            )

        # التحقق من عدم تكرار رمز الخدمة
        records = load_records(force_reload=True)
        for r in records:
            if r["service_number"].upper() == service_number:
                flash(
                    f"رمز الخدمة '{service_number}' موجود مسبقاً.",
                    "error",
                )
                return render_template(
                    "admin_form.html",
                    is_edit=False,
                    record=request.form,
                )

        # إنشاء السجل الجديد
        new_record = {
            "id": next_id(records),
            "service_number": service_number,
            "id_number": id_number,
            "name": name,
            "issue_date": issue_date,
            "start_date": start_date,
            "end_date": end_date,
            "w_day": w_day_int,
            "doctor": doctor,
            "doctor_title": doctor_title,
        }
        records.append(new_record)
        save_records(records)

        flash(f"تم إنشاء الإجازة لـ {name} بنجاح.", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("admin_form.html", is_edit=False, record=None)


@app.route("/admin/edit/<int:id>", methods=["GET", "POST"])
@login_required
def admin_edit(id):
    """تعديل سجل موجود."""
    records = load_records(force_reload=True)
    record = next((r for r in records if r["id"] == id), None)

    if not record:
        flash("السجل غير موجود.", "error")
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        service_number = request.form.get("service_number", "").strip().upper()
        id_number = normalize_digits(request.form.get("id_number", "").strip())
        name = request.form.get("name", "").strip()
        issue_date = request.form.get("issue_date", "")
        start_date = request.form.get("start_date", "")
        end_date = request.form.get("end_date", "")
        w_day = request.form.get("w_day", "1")
        doctor = request.form.get("doctor", "").strip()
        doctor_title = request.form.get("doctor_title", "").strip()

        try:
            w_day_int = int(w_day)
        except ValueError:
            w_day_int = record["w_day"]

        # التحقق من عدم تكرار رمز الخدمة
        for r in records:
            if r["id"] != id and r["service_number"].upper() == service_number:
                flash(
                    f"رمز الخدمة '{service_number}' مستخدم لسجل آخر.",
                    "error",
                )
                return render_template(
                    "admin_form.html", is_edit=True, record=record
                )

        # تحديث السجل
        record.update({
            "service_number": service_number,
            "id_number": id_number,
            "name": name,
            "issue_date": issue_date,
            "start_date": start_date,
            "end_date": end_date,
            "w_day": w_day_int,
            "doctor": doctor,
            "doctor_title": doctor_title,
        })

        save_records(records)
        flash(f"تم تحديث السجل #{id} بنجاح.", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("admin_form.html", is_edit=True, record=record)


@app.route("/admin/delete/<int:id>", methods=["POST"])
@login_required
def admin_delete(id):
    """حذف سجل."""
    records = load_records(force_reload=True)
    record = next((r for r in records if r["id"] == id), None)

    if not record:
        flash("السجل غير موجود.", "error")
    else:
        name = record["name"]
        records = [r for r in records if r["id"] != id]
        save_records(records)
        flash(f"تم حذف سجل {name}.", "success")

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/print/<int:id>")
@login_required
def admin_print(id):
    """عرض صفحة طباعة السجل (توليد PDF في المتصفح عبر html2pdf.js)."""
    records = load_records(force_reload=True)
    record = next((r for r in records if r["id"] == id), None)

    if not record:
        flash("السجل غير موجود.", "error")
        return redirect(url_for("admin_dashboard"))

    # حساب التواريخ الهجرية من الميلادية
    start_hijri = to_hijri(record.get("start_date"))
    end_hijri = to_hijri(record.get("end_date"))
    issue_hijri = to_hijri(record.get("issue_date"))

    # تنسيق التواريخ الميلادية بصيغة DD-MM-YYYY
    def to_ddmmyyyy(date_str):
        if not date_str:
            return ""
        parts = date_str.split("-")
        if len(parts) == 3:
            return f"{parts[2]}-{parts[1]}-{parts[0]}"
        return date_str

    # تنسيق تاريخ الإصدار + اسم اليوم بالإنجليزية
    issue_date_en = format_gregorian_with_day_name(record.get("issue_date"))

    # تنسيق مدد الإجازة
    duration_en = format_duration_en(
        record.get("start_date"), record.get("end_date"), record.get("w_day", 0)
    )
    duration_ar = format_duration_ar(
        record.get("start_date"), record.get("end_date"),
        record.get("w_day", 0), start_hijri, end_hijri
    )

    # تجميع بيانات الـ PDF (تُمرّر إلى قالب HTML)
    pdf_data = {
        "service_number": record.get("service_number", ""),
        "name": record.get("name", ""),
        "name_en": record.get("name_en", ""),
        "id_number": record.get("id_number", ""),
        "employer_ar": record.get("employer_ar", ""),
        "physician_name_ar": record.get("physician_name_ar") or record.get("doctor", ""),
        "physician_name_en": record.get("physician_name_en", ""),
        "position_ar": record.get("position_ar") or record.get("doctor_title", ""),
        "position_en": record.get("position_en", ""),
        "start_date_gregorian": to_ddmmyyyy(record.get("start_date")),
        "start_date_hijri": to_ddmmyyyy(start_hijri),
        "end_date_gregorian": to_ddmmyyyy(record.get("end_date")),
        "end_date_hijri": to_ddmmyyyy(end_hijri),
        "issue_date_gregorian": to_ddmmyyyy(record.get("issue_date")),
        "duration_en": duration_en,
        "duration_ar": duration_ar,
        "time": "10:20 AM",
        "issue_date_en": issue_date_en,
        "site_url": "https://sa-sehaty-sa.onrender.com/",
    }

    # عرض صفحة الطباعة (الـ PDF يُولّد في المتصفح عبر html2pdf.js)
    return render_template("admin_print.html", **pdf_data)


def build_pdf_elements(data):
    """بناء عناصر PDF (مطابقة لتنسيق docx الأصلي)."""
    from reportlab.platypus import Image as RLImage

    # تعريف الألوان
    COLOR_PRIMARY = colors.HexColor("#2F6CB5")
    COLOR_DARK_BLUE = colors.HexColor("#1F2D6C")
    COLOR_NAVY = colors.HexColor("#2C3D77")
    COLOR_LIGHT_GRAY = colors.HexColor("#F8F8F8")
    COLOR_TEXT = colors.HexColor("#212121")

    # أنماط النص (أحجام مضبوطة من الـ docx الأصلي)
    # الأعمدة في الأصل: 1.610 + 2.372 + 2.372 + 1.333 = 7.687 إنش
    style_ar_label = ParagraphStyle(
        "ArLabel", fontName="Cairo-Bold", fontSize=11.5, textColor=COLOR_PRIMARY,
        alignment=TA_RIGHT,
    )
    style_ar_value = ParagraphStyle(
        "ArValue", fontName="Cairo", fontSize=10.0, textColor=COLOR_TEXT,
        alignment=TA_RIGHT,
    )
    style_en_label = ParagraphStyle(
        "EnLabel", fontName="Cairo-Bold", fontSize=11.0, textColor=COLOR_PRIMARY,
        alignment=TA_LEFT,
    )
    style_en_value = ParagraphStyle(
        "EnValue", fontName="Cairo", fontSize=9.5, textColor=COLOR_NAVY,
        alignment=TA_LEFT,
    )
    style_center_ar = ParagraphStyle(
        "CenterAr", fontName="Cairo-Bold", fontSize=11.0, textColor=COLOR_TEXT,
        alignment=TA_CENTER,
    )
    style_center_en = ParagraphStyle(
        "CenterEn", fontName="Cairo-Bold", fontSize=9.7, textColor=COLOR_TEXT,
        alignment=TA_CENTER,
    )
    style_small_ar = ParagraphStyle(
        "SmallAr", fontName="Cairo-Bold", fontSize=10.0, textColor=COLOR_PRIMARY,
        alignment=TA_CENTER,
    )
    style_small_en = ParagraphStyle(
        "SmallEn", fontName="Cairo-Bold", fontSize=8.0, textColor=COLOR_TEXT,
        alignment=TA_CENTER,
    )
    style_meta = ParagraphStyle(
        "Meta", fontName="Cairo-Bold", fontSize=8.4, textColor=COLOR_TEXT,
        alignment=TA_LEFT,
    )
    style_url = ParagraphStyle(
        "Url", fontName="Cairo", fontSize=8.5, textColor=COLOR_PRIMARY,
        alignment=TA_CENTER,
    )

    elements = []

    # ===== [1] ترويسة الصفحة (شعار صحة + شعار المملكة + نمط هندسي) =====
    header_logo_path = os.path.join(BASE_DIR, "static", "images", "header_logo.jpeg")
    if os.path.exists(header_logo_path):
        try:
            # عرض الصورة: يأخذ عرض الصفحة المتاح (7.678 إنش)
            # الارتفاع يحسب من نسبة الأبعاد للصورة: 1297/336 = 3.86
            # 7.678 / 3.86 = 1.99 إنش
            img = RLImage(header_logo_path, width=7.678 * inch, height=1.99 * inch)
            elements.append(img)
            elements.append(Spacer(1, 4))
        except Exception as e:
            print(f"⚠️ فشل تحميل ترويسة الصفحة: {e}")

    # أنماط للصفوف المظللة (مضبوطة من الأصل)
    style_white_text = ParagraphStyle(
        "WhiteText", fontName="Cairo-Bold", fontSize=11.5, textColor=colors.white,
        alignment=TA_RIGHT,
    )
    style_white_en = ParagraphStyle(
        "WhiteEn", fontName="Cairo", fontSize=9.0, textColor=colors.white,
        alignment=TA_LEFT,
    )
    style_white_label = ParagraphStyle(
        "WhiteLabel", fontName="Cairo-Bold", fontSize=11.0, textColor=colors.white,
        alignment=TA_LEFT,
    )

    def cell(text, style):
        """Helper لإنشاء خلية فقرة."""
        return Paragraph(text, style)

    # تجميع بيانات الجدول
    rows = [
        # صف 0: Leave ID
        [cell("Leave ID", style_en_label),
         cell(data["service_number"], style_en_value),
         cell(data["service_number"], style_en_value),
         cell(ar("رمز الإجازة"), style_ar_label)],
        # صف 1: Leave Duration (highlighted)
        [cell("Leave Duration", style_white_label),
         cell(data["duration_en"], style_white_en),
         cell(ar(data["duration_ar"]), style_white_text),
         cell(ar("مدة الإجازة"), style_white_text)],
        # صف 2: Admission Date
        [cell("Admission Date", style_en_label),
         cell(data["start_date_gregorian"], style_en_value),
         cell(data["start_date_hijri"], style_en_value),
         cell(ar("تاريخ الدخول"), style_ar_label)],
        # صف 3: Discharge Date (alt)
        [cell("Discharge Date", style_en_label),
         cell(data["end_date_gregorian"], style_en_value),
         cell(data["end_date_hijri"], style_en_value),
         cell(ar("تاريخ الخروج"), style_ar_label)],
        # صف 4: Issue Date
        [cell("Issue Date", style_en_label),
         cell(data["issue_date_gregorian"], style_en_value),
         cell(data["issue_date_gregorian"], style_en_value),
         cell(ar("تاريخ إصدار التقرير"), style_ar_label)],
        # صف 5: Name (alt)
        [cell("Name", style_en_label),
         cell(data["name_en"], style_en_value),
         cell(ar(data["name"]), style_ar_value),
         cell(ar("الاسم"), style_ar_label)],
        # صف 6: National ID / Iqama
        [cell("National ID / Iqama", style_en_label),
         cell(data["id_number"], style_en_value),
         cell(data["id_number"], style_en_value),
         cell(ar("رقم الهوية / الإقامة"), style_ar_label)],
        # صف 7: Nationality (alt)
        [cell("Nationality", style_en_label),
         cell("Saudi Arabia", style_en_value),
         cell(ar("السعودية"), style_ar_value),
         cell(ar("الجنسية"), style_ar_label)],
        # صف 8: Employer
        [cell("Employer", style_en_label),
         cell("", style_en_value),
         cell(ar(data["employer_ar"]), style_ar_value),
         cell(ar("جهة العمل"), style_ar_label)],
        # صف 9: Physician Name (alt)
        [cell("Physician Name", style_en_label),
         cell(data["physician_name_en"], style_en_value),
         cell(ar(data["physician_name_ar"]), style_ar_value),
         cell(ar("اسم الممارس"), style_ar_label)],
        # صف 10: Position
        [cell("Position", style_en_label),
         cell(data["position_en"], style_en_value),
         cell(ar(data["position_ar"]), style_ar_value),
         cell(ar("المسمى الوظيفي"), style_ar_label)],
    ]

    table = Table(rows, colWidths=[1.610 * inch, 2.372 * inch, 2.372 * inch, 1.333 * inch])
    table.setStyle(TableStyle([
        # الخطوط
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D5D5D5")),
        ("BOX", (0, 0), (-1, -1), 1, COLOR_DARK_BLUE),
        # المحاذاة
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        # الصف 1 (Leave Duration): خلفية زرقاء داكنة
        ("BACKGROUND", (0, 1), (-1, 1), COLOR_DARK_BLUE),
        # الصفوف المتناوبة (3, 5, 7, 9)
        ("BACKGROUND", (0, 3), (-1, 3), COLOR_LIGHT_GRAY),
        ("BACKGROUND", (0, 5), (-1, 5), COLOR_LIGHT_GRAY),
        ("BACKGROUND", (0, 7), (-1, 7), COLOR_LIGHT_GRAY),
        ("BACKGROUND", (0, 9), (-1, 9), COLOR_LIGHT_GRAY),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 8))

    # ===== [3] تذييل بنفس تخطيط docx الأصلي =====
    # يسار: QR code + نص التحقق + URL + وقت + تاريخ
    # يمين: شعار MoH + اسم المستشفى (عربي) + اسم المستشفى (إنجليزي) + شعار NHIC

    qr_path = os.path.join(BASE_DIR, "static", "images", "qr_code.png")
    moh_path = os.path.join(BASE_DIR, "static", "images", "moh_logo.jpeg")
    nhic_path = os.path.join(BASE_DIR, "static", "images", "nhic_logo.jpeg")

    # --- العمود الأيسر: QR + نص التحقق + وقت ---
    left_cell = []
    if os.path.exists(qr_path):
        try:
            # الأصل: 0.75×0.74 إنش
            qr_img = RLImage(qr_path, width=0.75 * inch, height=0.74 * inch)
            # محاذاة يسار
            qr_table = Table([[qr_img]], colWidths=[3.5 * inch])
            qr_table.setStyle(TableStyle([
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]))
            left_cell.append(qr_table)
            left_cell.append(Spacer(1, 4))
        except Exception:
            pass

    left_cell.append(Paragraph(
        ar("للتحقق من بيانات التقرير يرجى التأكد من زيارة موقع منصة صحة الرسمي"),
        style_small_ar
    ))
    left_cell.append(Spacer(1, 2))
    left_cell.append(Paragraph(
        "To check the report please visit Seha's official website",
        style_small_en
    ))
    left_cell.append(Spacer(1, 2))
    left_cell.append(Paragraph("www.seha.sa/#/inquiries/slenquiry", style_url))
    left_cell.append(Spacer(1, 4))
    left_cell.append(Paragraph(data["time"], style_meta))
    left_cell.append(Paragraph(data["issue_date_en"], style_meta))

    # --- العمود الأيمن: شعار MoH + اسم المستشفى + شعار NHIC ---
    style_right_ar = ParagraphStyle(
        "RightAr", fontName="Cairo-Bold", fontSize=11.0, textColor=COLOR_TEXT,
        alignment=TA_CENTER,
    )
    style_right_en = ParagraphStyle(
        "RightEn", fontName="Cairo-Bold", fontSize=9.7, textColor=COLOR_TEXT,
        alignment=TA_CENTER,
    )

    right_cell = []
    if os.path.exists(moh_path):
        try:
            # الأصل: 0.95×0.86 إنش
            moh_img = RLImage(moh_path, width=0.95 * inch, height=0.86 * inch)
            moh_table = Table([[moh_img]], colWidths=[3.5 * inch])
            moh_table.setStyle(TableStyle([
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]))
            right_cell.append(moh_table)
            right_cell.append(Spacer(1, 2))
        except Exception:
            pass

    right_cell.append(Paragraph(ar("مستشفى الجدعاني"), style_right_ar))
    right_cell.append(Spacer(1, 1))
    right_cell.append(Paragraph("Al-Jadaani Hospital", style_right_en))
    right_cell.append(Spacer(1, 4))

    if os.path.exists(nhic_path):
        try:
            # الأصل: 1.35×0.66 إنش
            nhic_img = RLImage(nhic_path, width=1.35 * inch, height=0.66 * inch)
            nhic_table = Table([[nhic_img]], colWidths=[3.5 * inch])
            nhic_table.setStyle(TableStyle([
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]))
            right_cell.append(nhic_table)
        except Exception:
            pass

    # الجدول الرئيسي للتذييل: عمودان
    footer_table = Table(
        [[left_cell, right_cell]],
        colWidths=[3.75 * inch, 3.75 * inch],
    )
    footer_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(footer_table)

    return elements


# ====================================================================
# معالجة الأخطاء
# ====================================================================
@app.errorhandler(404)
def not_found(e):
    return (
        '<html dir="rtl"><meta charset="UTF-8">'
        '<style>body{font-family:Cairo;text-align:center;padding:80px;'
        'background:#f5f7fb}'
        "h1{font-size:6rem;color:#0F766E;margin:0}"
        "a{display:inline-block;background:#0F766E;color:white;"
        "padding:14px 30px;border-radius:12px;text-decoration:none;"
        "font-weight:700;margin-top:20px}</style>"
        '<h1>404</h1><a href="/">الرئيسية</a>',
        404,
    )


@app.errorhandler(500)
def server_error(e):
    return json_response(
        {"success": False, "message": "حدث خطأ داخلي في الخادم"},
        500,
    )


# ====================================================================
# تحميل السجلات عند بدء التشغيل
# ====================================================================
load_records()


# ====================================================================
# نقطة الدخول
# ====================================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
