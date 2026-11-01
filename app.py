import csv
import io
import json
import os
import re
from datetime import timezone

from flask import (
    Flask,
    Response,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_wtf import CSRFProtect, FlaskForm
from flask_wtf.csrf import generate_csrf
from wtforms import BooleanField, IntegerField, PasswordField, StringField
from wtforms.validators import DataRequired, EqualTo, Length, NumberRange, ValidationError

from config import Config
from models import Scan, User, db, utcnow
from scanner import JOBS, start_scan, validate_ipv4, validate_ports

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")

app = Flask(__name__, instance_relative_config=True)
app.config.from_object(Config)
os.makedirs(app.instance_path, exist_ok=True)

db.init_app(app)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "error"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


class RegisterForm(FlaskForm):
    full_name = StringField("Full name", validators=[DataRequired(), Length(min=2, max=120)])
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField("Email", validators=[DataRequired(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=128)])
    confirm = PasswordField(
        "Confirm password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )

    def validate_username(self, field):
        if not USERNAME_RE.match(field.data.strip()):
            raise ValidationError("Use 3–64 letters, numbers, dots, underscores or hyphens.")
        if User.query.filter_by(username=field.data.strip()).first():
            raise ValidationError("That username is already taken.")

    def validate_email(self, field):
        value = field.data.strip().lower()
        if not EMAIL_RE.match(value):
            raise ValidationError("Enter a valid email address.")
        if User.query.filter_by(email=value).first():
            raise ValidationError("That email is already registered.")


class LoginForm(FlaskForm):
    identifier = StringField("Username or email", validators=[DataRequired(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember me")


class ScanForm(FlaskForm):
    target_ip = StringField("Target IPv4", validators=[DataRequired(), Length(max=45)])
    start_port = IntegerField("Start port", validators=[DataRequired(), NumberRange(min=1, max=65535)])
    end_port = IntegerField("End port", validators=[DataRequired(), NumberRange(min=1, max=65535)])
    authorized = BooleanField("Authorized", validators=[DataRequired(message="Authorization is required.")])

    def validate_target_ip(self, field):
        try:
            validate_ipv4(field.data)
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc

    def validate_end_port(self, field):
        try:
            validate_ports(self.start_port.data, field.data)
        except (TypeError, ValueError) as exc:
            raise ValidationError(str(exc)) from exc


class PasswordForm(FlaskForm):
    current_password = PasswordField("Current password", validators=[DataRequired()])
    new_password = PasswordField("New password", validators=[DataRequired(), Length(min=8, max=128)])
    confirm = PasswordField(
        "Confirm new password",
        validators=[DataRequired(), EqualTo("new_password", message="Passwords must match.")],
    )


def json_error(message, status=400):
    return jsonify({"ok": False, "error": message}), status


def persist_scan(job):
    with app.app_context():
        record = Scan(
            user_id=job.user_id,
            target_ip=job.target_ip,
            start_port=job.start_port,
            end_port=job.end_port,
            open_count=len(job.open_ports),
            closed_count=job.closed_count,
            duration_ms=job.duration_ms,
            status="completed",
            results_json=json.dumps(job.results),
            created_at=utcnow(),
        )
        db.session.add(record)
        db.session.commit()
        job.scan_id = record.id


@app.context_processor
def inject_globals():
    return {"csrf_token": generate_csrf, "app_name": "SENTINEL"}


@app.before_request
def init_db_once():
    if not getattr(app, "_db_ready", False):
        db.create_all()
        app._db_ready = True


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(
            full_name=form.full_name.data.strip(),
            username=form.username.data.strip(),
            email=form.email.data.strip().lower(),
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Account created. Sign in to enter the SOC.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    form = LoginForm()
    if form.validate_on_submit():
        ident = form.identifier.data.strip()
        user = User.query.filter((User.username == ident) | (User.email == ident.lower())).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.", "error")
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Session terminated.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/scanner")
@login_required
def scanner_page():
    return render_template("scanner.html", form=ScanForm())


@app.route("/history")
@login_required
def history():
    return render_template("history.html")


@app.route("/analytics")
@login_required
def analytics():
    return render_template("analytics.html", page_title="Analytics")


@app.route("/reports")
@login_required
def reports():
    return render_template("analytics.html", page_title="Reports")


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    form = PasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash("Current password is incorrect.", "error")
        else:
            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash("Password updated.", "success")
            return redirect(url_for("profile"))
    return render_template("profile.html", form=form)


@app.route("/api/dashboard")
@login_required
def api_dashboard():
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.created_at.desc()).all()
    total_scans = len(scans)
    open_ports = sum(s.open_count for s in scans)
    closed_ports = sum(s.closed_count for s in scans)
    hosts = len({s.target_ip for s in scans})
    recent = [scan_payload(s, include_results=False) for s in scans[:8]]
    trend = activity_series(scans)
    return jsonify(
        {
            "ok": True,
            "stats": {
                "total_scans": total_scans,
                "open_ports": open_ports,
                "closed_ports": closed_ports,
                "hosts": hosts,
            },
            "recent": recent,
            "trend": trend,
            "ports": {"open": open_ports, "closed": closed_ports},
        }
    )


@app.route("/api/scan/start", methods=["POST"])
@login_required
def api_scan_start():
    form = ScanForm()
    if not form.validate_on_submit():
        errors = {field: msgs[0] for field, msgs in form.errors.items()}
        return jsonify({"ok": False, "errors": errors}), 400
    job = start_scan(
        current_user.id,
        form.target_ip.data,
        form.start_port.data,
        form.end_port.data,
        on_complete=persist_scan,
    )
    return jsonify({"ok": True, "job": job.snapshot()})


@app.route("/api/scan/status/<job_id>")
@login_required
def api_scan_status(job_id):
    job = JOBS.get(job_id)
    if not job or job.user_id != current_user.id:
        return json_error("Scan job not found.", 404)
    data = job.snapshot()
    if getattr(job, "scan_id", None):
        data["scan_id"] = job.scan_id
    return jsonify({"ok": True, "job": data})


@app.route("/api/history")
@login_required
def api_history():
    q = (request.args.get("q") or "").strip()
    query = Scan.query.filter_by(user_id=current_user.id)
    if q:
        like = f"%{q}%"
        query = query.filter(Scan.target_ip.like(like))
    rows = query.order_by(Scan.created_at.desc()).all()
    return jsonify({"ok": True, "scans": [scan_payload(s, include_results=False) for s in rows]})


@app.route("/api/history/<int:scan_id>")
@login_required
def api_history_detail(scan_id):
    scan = owned_scan(scan_id)
    if not scan:
        return json_error("Scan not found.", 404)
    return jsonify({"ok": True, "scan": scan_payload(scan, include_results=True)})


@app.route("/api/history/<int:scan_id>", methods=["DELETE"])
@login_required
def api_history_delete(scan_id):
    scan = owned_scan(scan_id)
    if not scan:
        return json_error("Scan not found.", 404)
    db.session.delete(scan)
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/api/history/<int:scan_id>/csv")
@login_required
def api_history_csv(scan_id):
    scan = owned_scan(scan_id)
    if not scan:
        return json_error("Scan not found.", 404)
    return csv_response(f"sentinel-scan-{scan.id}.csv", scan_csv_rows([scan], detailed=True))


@app.route("/api/reports/csv")
@login_required
def api_reports_csv():
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.created_at.desc()).all()
    return csv_response("sentinel-report.csv", scan_csv_rows(scans, detailed=False))


@app.route("/api/analytics")
@login_required
def api_analytics():
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.created_at.asc()).all()
    service_counts = {}
    for scan in scans:
        for row in json.loads(scan.results_json or "[]"):
            if row.get("state") == "open":
                name = row.get("service") or "Unknown"
                service_counts[name] = service_counts.get(name, 0) + 1
    top_services = sorted(service_counts.items(), key=lambda item: item[1], reverse=True)[:8]
    hosts = {}
    for scan in scans:
        hosts[scan.target_ip] = hosts.get(scan.target_ip, 0) + scan.open_count
    top_hosts = sorted(hosts.items(), key=lambda item: item[1], reverse=True)[:8]
    return jsonify(
        {
            "ok": True,
            "trend": activity_series(scans),
            "ports": {
                "open": sum(s.open_count for s in scans),
                "closed": sum(s.closed_count for s in scans),
            },
            "services": {"labels": [s[0] for s in top_services], "values": [s[1] for s in top_services]},
            "hosts": {"labels": [h[0] for h in top_hosts], "values": [h[1] for h in top_hosts]},
            "totals": {
                "scans": len(scans),
                "hosts": len({s.target_ip for s in scans}),
                "duration_ms": sum(s.duration_ms for s in scans),
            },
        }
    )


def owned_scan(scan_id):
    return Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()


def scan_payload(scan, include_results=False):
    payload = {
        "id": scan.id,
        "target_ip": scan.target_ip,
        "start_port": scan.start_port,
        "end_port": scan.end_port,
        "open_count": scan.open_count,
        "closed_count": scan.closed_count,
        "duration_ms": scan.duration_ms,
        "status": scan.status,
        "created_at": scan.created_at.replace(tzinfo=timezone.utc).isoformat()
        if scan.created_at.tzinfo is None
        else scan.created_at.isoformat(),
    }
    if include_results:
        payload["results"] = json.loads(scan.results_json or "[]")
    return payload


def activity_series(scans):
    buckets = {}
    for scan in scans:
        key = scan.created_at.strftime("%Y-%m-%d")
        bucket = buckets.setdefault(key, {"scans": 0, "open": 0})
        bucket["scans"] += 1
        bucket["open"] += scan.open_count
    labels = sorted(buckets)
    return {
        "labels": labels,
        "scans": [buckets[k]["scans"] for k in labels],
        "open": [buckets[k]["open"] for k in labels],
    }


def scan_csv_rows(scans, detailed=False):
    if detailed:
        rows = [["scan_id", "target_ip", "port", "state", "service", "timestamp"]]
        for scan in scans:
            stamp = scan.created_at.isoformat()
            for item in json.loads(scan.results_json or "[]"):
                rows.append(
                    [scan.id, scan.target_ip, item.get("port"), item.get("state"), item.get("service"), stamp]
                )
        return rows
    rows = [["id", "target_ip", "start_port", "end_port", "open_ports", "closed_ports", "duration_ms", "timestamp"]]
    for scan in scans:
        rows.append(
            [
                scan.id,
                scan.target_ip,
                scan.start_port,
                scan.end_port,
                scan.open_count,
                scan.closed_count,
                scan.duration_ms,
                scan.created_at.isoformat(),
            ]
        )
    return rows


def csv_response(filename, rows):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerows(rows)
    output = buffer.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def create_app():
    with app.app_context():
        db.create_all()
    return app


if __name__ == "__main__":
    create_app()
    app.run(host="127.0.0.1", port=5000, debug=True)
