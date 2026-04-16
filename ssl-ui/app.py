from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import subprocess, tempfile, os, zipfile, io, re, json, secrets, string

app = Flask(__name__)

# ── Config ──
app.config['SECRET_KEY']                   = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI']      = os.environ.get('DATABASE_URL', 'postgresql://ssluser:sslpass@db:5432/ssldb')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Mail config
app.config['MAIL_SERVER']   = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT']     = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS']  = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME', 'noreply@sslgenerator.com')

# OAuth config
app.config['GOOGLE_CLIENT_ID']     = os.environ.get('GOOGLE_CLIENT_ID', '')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET', '')
app.config['FACEBOOK_CLIENT_ID']     = os.environ.get('FACEBOOK_CLIENT_ID', '')
app.config['FACEBOOK_CLIENT_SECRET'] = os.environ.get('FACEBOOK_CLIENT_SECRET', '')

# ── Extensions ──
db           = SQLAlchemy(app)
login_manager = LoginManager(app)
mail         = Mail(app)
oauth        = OAuth(app)

login_manager.login_view       = 'login'
login_manager.login_message    = ''

# ── OAuth providers ──
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

facebook = oauth.register(
    name='facebook',
    client_id=app.config['FACEBOOK_CLIENT_ID'],
    client_secret=app.config['FACEBOOK_CLIENT_SECRET'],
    access_token_url='https://graph.facebook.com/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    api_base_url='https://graph.facebook.com/',
    client_kwargs={'scope': 'email public_profile'},
)

# ── Models ──
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id            = db.Column(db.Integer, primary_key=True)
    email         = db.Column(db.String(255), unique=True, nullable=False)
    name          = db.Column(db.String(255))
    avatar        = db.Column(db.String(512))
    provider      = db.Column(db.String(50), default='email')  # email/google/facebook
    password_hash = db.Column(db.String(512))
    is_verified   = db.Column(db.Boolean, default=False)
    verify_token  = db.Column(db.String(128))
    reset_token   = db.Column(db.String(128))
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    certificates  = db.relationship('Certificate', backref='user', lazy=True, order_by='Certificate.generated_at.desc()')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Certificate(db.Model):
    __tablename__ = 'certificates'
    id                  = db.Column(db.Integer, primary_key=True)
    user_id             = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    domain              = db.Column(db.String(255))
    org                 = db.Column(db.String(255))
    country             = db.Column(db.String(10))
    san_dns             = db.Column(db.Text)
    san_ip              = db.Column(db.Text)
    cert_dir            = db.Column(db.String(512))
    files               = db.Column(db.Text)   # JSON list of filenames
    file_contents_json  = db.Column(db.Text)   # JSON dict of filename -> content
    cert_info           = db.Column(db.Text)   # openssl x509 -text output
    zip_path            = db.Column(db.String(512))
    generated_at        = db.Column(db.DateTime, default=datetime.utcnow)

    def files_list(self):
        try:
            return json.loads(self.files)
        except Exception:
            return []

    def files_contents(self):
        try:
            return json.loads(self.file_contents_json)
        except Exception:
            return {}


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ── Helpers ──
def strip_ansi(text):
    return re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])').sub('', text)


def build_stdin_mode1(data):
    san_dns = data.get('san_dns', '')
    san_ip  = data.get('san_ip', '')
    lines = [
        '1',
        data.get('org', 'My Organization'),
        data.get('country', 'US').upper(),
        data.get('state', 'California'),
        data.get('city', 'San Francisco'),
        data.get('ou', ''),
        data.get('operator', ''),
        data.get('domain', 'example.com'),
    ]
    if san_dns.strip():
        lines += [san_dns, 'y']
    else:
        lines.append('')
    if san_ip.strip():
        lines += [san_ip, 'y']
    else:
        lines.append('')
    return '\n'.join(lines) + '\n'


def build_stdin_mode2(ca_dir, data):
    san_dns = data.get('san_dns', '')
    san_ip  = data.get('san_ip', '')
    lines = [
        '2',
        ca_dir,
        data.get('domain', 'example.com'),
    ]
    if san_dns.strip():
        lines += [san_dns, 'y']
    else:
        lines.append('')
    if san_ip.strip():
        lines += [san_ip, 'y']
    else:
        lines.append('')
    lines.append('n')
    return '\n'.join(lines) + '\n'


def build_stdin(data):
    return build_stdin_mode1(data)


def send_verification_email(user):
    token = secrets.token_urlsafe(32)
    user.verify_token = token
    db.session.commit()
    link = url_for('verify_email', token=token, _external=True)
    try:
        msg = Message('Verify your SSL Generator account', recipients=[user.email])
        msg.html = f'''
        <div style="font-family:-apple-system,sans-serif;max-width:480px;margin:0 auto;padding:2rem">
          <h2 style="font-size:1.3rem;color:#1d1d1f">Verify your email</h2>
          <p style="color:#6e6e73;margin:1rem 0">Click the button below to verify your account.</p>
          <a href="{link}" style="display:inline-block;background:#0071e3;color:#fff;padding:.7rem 1.4rem;border-radius:8px;text-decoration:none;font-weight:500">Verify Email</a>
          <p style="color:#a1a1a6;font-size:.8rem;margin-top:1.5rem">If you didn't create this account, ignore this email.</p>
        </div>
        '''
        mail.send(msg)
    except Exception:
        pass  # Mail not configured — skip silently


# ── Auth routes ──
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user     = User.query.filter_by(email=email, provider='email').first()
        if not user or not user.check_password(password):
            return render_template('login.html', error='Invalid email or password.')
        if not user.is_verified:
            return render_template('login.html', error='Please verify your email first.')
        login_user(user, remember=True)
        return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        name     = request.form.get('name', '').strip()
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if not name or not email or not password:
            return render_template('register.html', error='All fields are required.')
        if len(password) < 8:
            return render_template('register.html', error='Password must be at least 8 characters.')
        if User.query.filter_by(email=email).first():
            return render_template('register.html', error='Email already registered.')
        user = User(name=name, email=email, provider='email')
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        send_verification_email(user)
        return render_template('register.html', success='Account created! Check your email to verify.')
    return render_template('register.html')


@app.route('/verify/<token>')
def verify_email(token):
    user = User.query.filter_by(verify_token=token).first()
    if not user:
        return render_template('login.html', error='Invalid or expired verification link.')
    user.is_verified  = True
    user.verify_token = None
    db.session.commit()
    login_user(user)
    return redirect(url_for('dashboard'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# ── Google OAuth ──
@app.route('/auth/google')
def google_login():
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/auth/google/callback')
def google_callback():
    token    = google.authorize_access_token()
    userinfo = token.get('userinfo')
    if not userinfo:
        return redirect(url_for('login'))
    email  = userinfo.get('email', '').lower()
    name   = userinfo.get('name', '')
    avatar = userinfo.get('picture', '')
    user   = User.query.filter_by(email=email).first()
    if not user:
        user = User(email=email, name=name, avatar=avatar, provider='google', is_verified=True)
        db.session.add(user)
        db.session.commit()
    else:
        user.avatar = avatar
        db.session.commit()
    login_user(user, remember=True)
    return redirect(url_for('dashboard'))


# ── Facebook OAuth ──
@app.route('/auth/facebook')
def facebook_login():
    redirect_uri = url_for('facebook_callback', _external=True)
    return facebook.authorize_redirect(redirect_uri)


@app.route('/auth/facebook/callback')
def facebook_callback():
    token    = facebook.authorize_access_token()
    resp     = facebook.get('me?fields=id,name,email,picture', token=token)
    profile  = resp.json()
    email    = profile.get('email', '').lower()
    name     = profile.get('name', '')
    avatar   = profile.get('picture', {}).get('data', {}).get('url', '')
    if not email:
        return render_template('login.html', error='Facebook did not provide an email address.')
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(email=email, name=name, avatar=avatar, provider='facebook', is_verified=True)
        db.session.add(user)
        db.session.commit()
    else:
        user.avatar = avatar
        db.session.commit()
    login_user(user, remember=True)
    return redirect(url_for('dashboard'))


# ── Dashboard ──
@app.route('/')
@login_required
def dashboard():
    certs = Certificate.query.filter_by(user_id=current_user.id)\
                             .order_by(Certificate.generated_at.desc())\
                             .limit(10).all()
    return render_template('dashboard.html', certs=certs)


# ── Generate ──
@app.route('/generate', methods=['POST'])
@login_required
def generate():
    data    = request.json
    workdir = tempfile.mkdtemp(prefix='ssl_web_')

    try:
        mode = data.get('mode', '1')

        if mode == '2':
            # ── Mode 2: extract CA files from selected history cert ──
            ca_cert_id = data.get('ca_cert_id')
            if not ca_cert_id:
                return jsonify({'success': False, 'error': 'No CA certificate selected from history.'}), 400

            ca_cert = Certificate.query.filter_by(id=ca_cert_id, user_id=current_user.id).first()
            if not ca_cert:
                return jsonify({'success': False, 'error': 'Selected CA certificate not found.'}), 404

            # Extract CA files from zip into a temp ca_dir
            ca_dir = tempfile.mkdtemp(prefix='ssl_ca_')
            required_files = ['inter_key.pem', 'inter_cert.pem', 'root_cert.pem']

            # Try from DB first
            file_contents_db = ca_cert.files_contents()
            if file_contents_db:
                for fname, content_str in file_contents_db.items():
                    with open(os.path.join(ca_dir, fname), 'w') as f:
                        f.write(content_str)
            elif ca_cert.zip_path and os.path.exists(ca_cert.zip_path):
                with zipfile.ZipFile(ca_cert.zip_path, 'r') as zf:
                    zf.extractall(ca_dir)
            else:
                return jsonify({'success': False, 'error': 'CA files not available. Please regenerate the CA certificate.'}), 404

            # Verify required CA files exist
            missing = [f for f in required_files if not os.path.exists(os.path.join(ca_dir, f))]
            if missing:
                return jsonify({'success': False, 'error': f'Missing CA files: {", ".join(missing)}'}), 400

            stdin_input = build_stdin_mode2(ca_dir, data)
        else:
            # ── Mode 1: full PKI ──
            operator = data.get('operator', current_user.name or 'Web User')
            data['operator'] = operator
            stdin_input = build_stdin_mode1(data)
            ca_dir = None

        result = subprocess.run(
            ['bash', '/usr/local/bin/ssl-generator.sh'],
            input=stdin_input, capture_output=True, text=True,
            cwd=workdir, timeout=120,
            env={**os.environ, 'MSYS_NO_PATHCONV': '1', 'TERM': 'xterm'}
        )

        stdout_clean = strip_ansi(result.stdout)
        stderr_clean = strip_ansi(result.stderr)
        combined     = stdout_clean + ('\n--- stderr ---\n' + stderr_clean if stderr_clean else '')

        cert_dirs = [d for d in os.listdir(workdir)
                     if os.path.isdir(os.path.join(workdir, d)) and d.startswith('certs_')]

        if not cert_dirs:
            return jsonify({'success': False, 'error': 'No certs generated.\n' + combined}), 500

        cert_dir  = os.path.join(workdir, cert_dirs[0])
        file_contents = {}
        for fname in sorted(os.listdir(cert_dir)):
            fpath = os.path.join(cert_dir, fname)
            if os.path.isfile(fpath):
                try:
                    with open(fpath, 'r') as f:
                        file_contents[fname] = f.read()
                except Exception:
                    file_contents[fname] = '[binary]'

        # Create zip
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            for fname, content in file_contents.items():
                zf.writestr(fname, content)
        zip_buffer.seek(0)
        zip_path = os.path.join(workdir, 'certificates.zip')
        with open(zip_path, 'wb') as f:
            f.write(zip_buffer.getvalue())

        # Cert info
        cert_info  = ''
        domain_clean = data.get('domain', '').replace('.', '-')
        server_crt = os.path.join(cert_dir, f'{domain_clean}.crt')
        if os.path.exists(server_crt):
            ci = subprocess.run(['openssl', 'x509', '-in', server_crt, '-noout', '-text'],
                                capture_output=True, text=True)
            cert_info = ci.stdout

        # Save to DB
        cert_record = Certificate(
            user_id            = current_user.id,
            domain             = data.get('domain'),
            org                = data.get('org'),
            country            = data.get('country'),
            san_dns            = data.get('san_dns', ''),
            san_ip             = data.get('san_ip', ''),
            cert_dir           = cert_dirs[0],
            files              = json.dumps(list(file_contents.keys())),
            file_contents_json = json.dumps(file_contents),
            cert_info          = cert_info,
            zip_path           = zip_path,
        )
        db.session.add(cert_record)
        db.session.commit()

        app.config['LAST_ZIP']   = zip_path
        app.config['LAST_FILES'] = file_contents

        return jsonify({
            'success':       True,
            'output':        combined,
            'files':         list(file_contents.keys()),
            'file_contents': file_contents,
            'cert_info':     cert_info,
            'cert_dir':      cert_dirs[0],
            'cert_id':       cert_record.id,
        })

    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'Script timed out.'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ── Download ──
@app.route('/download')
@login_required
def download():
    zip_path = app.config.get('LAST_ZIP')
    if not zip_path or not os.path.exists(zip_path):
        return 'No certificates generated yet', 404
    return send_file(zip_path, as_attachment=True, download_name='certificates.zip')


@app.route('/download/<int:cert_id>')
@login_required
def download_cert(cert_id):
    cert = Certificate.query.filter_by(id=cert_id, user_id=current_user.id).first_or_404()
    if not cert.zip_path or not os.path.exists(cert.zip_path):
        return 'File no longer available', 404
    return send_file(cert.zip_path, as_attachment=True,
                     download_name=f'{cert.domain}-certificates.zip')


# ── History ──
@app.route('/history')
@login_required
def history():
    certs = Certificate.query.filter_by(user_id=current_user.id)\
                             .order_by(Certificate.generated_at.desc()).all()
    return render_template('history.html', certs=certs)


@app.route('/history/delete/<int:cert_id>', methods=['POST'])
@login_required
def delete_cert(cert_id):
    cert = Certificate.query.filter_by(id=cert_id, user_id=current_user.id).first_or_404()
    db.session.delete(cert)
    db.session.commit()
    return jsonify({'success': True})



# ── API: list available CA certificates from history ──
@app.route('/api/certs/ca-list')
@login_required
def api_ca_list():
    # Only certs that have inter_key.pem and inter_cert.pem (full PKI mode 1 certs)
    certs = Certificate.query.filter_by(user_id=current_user.id)                             .order_by(Certificate.generated_at.desc()).all()
    ca_certs = []
    for cert in certs:
        files = cert.files_list()
        if 'inter_key.pem' in files and 'inter_cert.pem' in files and 'root_cert.pem' in files:
            ca_certs.append({
                'id':           cert.id,
                'domain':       cert.domain,
                'org':          cert.org,
                'generated_at': cert.generated_at.strftime('%b %d, %Y'),
            })
    return jsonify({'success': True, 'ca_certs': ca_certs})

# ── API: get file contents for a cert from DB ──
@app.route('/api/cert/<int:cert_id>/files')
@login_required
def api_cert_files(cert_id):
    cert = Certificate.query.filter_by(id=cert_id, user_id=current_user.id).first_or_404()

    file_contents = cert.files_contents()

    # Old record — file_contents_json was empty (generated before the column existed)
    # Try to read files from disk if zip_path still exists
    if not file_contents and cert.zip_path and os.path.exists(cert.zip_path):
        try:
            with zipfile.ZipFile(cert.zip_path, 'r') as zf:
                for fname in zf.namelist():
                    try:
                        file_contents[fname] = zf.read(fname).decode('utf-8')
                    except Exception:
                        file_contents[fname] = '[binary]'
            # Save to DB so next time it loads from DB
            cert.file_contents_json = json.dumps(file_contents)
            db.session.commit()
        except Exception:
            pass

    if not file_contents:
        return jsonify({
            'success': False,
            'error': 'Files not available. This certificate was generated before file storage was enabled. Please regenerate it.'
        }), 404

    return jsonify({
        'success':       True,
        'files':         cert.files_list() or list(file_contents.keys()),
        'file_contents': file_contents,
        'cert_info':     cert.cert_info or '',
        'cert_dir':      cert.cert_dir or '',
        'domain':        cert.domain or '',
    })


# ── Init DB ──
with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)