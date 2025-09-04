import os
import json
import uuid
import secrets
import smtplib
import time
import io
import base64
import logging
from logging.handlers import RotatingFileHandler
from captcha.image import ImageCaptcha
from datetime import datetime
from pathlib import Path
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, request, jsonify, redirect, session, Response, url_for, send_file
from werkzeug.utils import secure_filename
from typing import Dict, Optional
import mimetypes

# Store login tokens and their states
login_tokens: Dict[str, dict] = {}
# Store email login tokens
email_tokens: Dict[str, dict] = {}

# Store visitor data
visitor_data = set()
last_email_sent = 0

def send_login_email(config: dict, recipient: str, token: str, base_url: str) -> bool:
    """Send login email with token."""
    # try:
    if True:
        email_config = config['email']
        login_url = f"{base_url}/api/login/email/verify?token={token}"
        body = f"""
        Hello,
        
        Click the following link to log in to LinkNote:
        {login_url}
        
        This link will expire in 15 minutes.
        
        If you didn't request this login, please ignore this email.
        """
        msg=MIMEText(body,'html','utf-8')
        msg['From'] = email_config['account']
        msg['To'] = recipient
        msg['Subject'] = "LinkNote Login Link"
        smtpObj = smtplib.SMTP_SSL(email_config['smtp_server'], email_config['smtp_port'])
        r = smtpObj.login(email_config['account'], email_config['password'])
        print(r)
        smtpObj.sendmail(email_config['account'],[recipient,],msg.as_string()) 
        smtpObj.quit()

        # server.starttls()
        # server.login(email_config['account'], email_config['password'])
        # server.send_message(msg)
        # server.quit()
        return True
    # except Exception as e:
    #     print(f"Error sending email: {e}")
    #     return False

def load_visitor_data(config: dict) -> set:
    """Load visitor data from file if it exists."""
    if not config.get('visitor_report', {}).get('enabled'):
        return set()

    log_file = Path(config['visitor_report']['log_file'])
    if not log_file.exists():
        return set()

    try:
        with open(log_file, 'r') as f:
            data = json.load(f)
            return set(tuple(x) for x in data)
    except:
        return set()

def save_visitor_data(visitors: set, config: dict):
    """Save visitor data to file."""
    if not config.get('visitor_report', {}).get('enabled'):
        return

    log_file = Path(config['visitor_report']['log_file'])
    with open(log_file, 'w') as f:
        json.dump([list(x) for x in visitors], f, ensure_ascii=False)

def get_client_ip():
    """Get client IP, supporting X-Real-IP header for nginx."""
    if 'X-Real-IP' in request.headers:
        return request.headers['X-Real-IP']
    return request.remote_addr

def setup_logging(config: dict) -> None:
    """Setup logging configuration."""
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)

    log_file = log_dir / 'auth.log'

    handler = RotatingFileHandler(
        log_file,
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )

    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    handler.setFormatter(formatter)

    logger = logging.getLogger('auth')
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)

def log_auth_event(event_type: str, email: str, user_agent: str) -> None:
    """Log authentication related events."""
    logger = logging.getLogger('auth')
    logger.info(f"{event_type} - Email: {email} - User Agent: {user_agent}")

def create_app(data_dir: Path, config: dict):
    # Setup logging
    setup_logging(config)
    static_folder = os.path.join(os.path.dirname(__file__), 'static')
    app = Flask(__name__, static_folder=static_folder)
    app.config['DATA_DIR'] = data_dir
    app.config['LOGIN_ENABLED'] = config['login']['enabled']
    app.config['LOGIN_CONFIG'] = config['login']
    app.secret_key = config['server']['secret_key']
    private = config['login'].get('private', False)
    admin_email = []
    if 'email' in config['login']:
        admin_email = config['login']['email'].get('admin_email', '')
        admin_email = admin_email.split(',')
    # Load initial visitor data
    global visitor_data
    visitor_data = load_visitor_data(config)
    try:
        os.mkdir(data_dir)
    except FileExistsError:
        pass
    print(f"Data directory set to: {data_dir}")

    def login_state():
        """Get the current login state."""
        if 'user_info' in session:
            return {
                'logged_in': True,
                'is_admin': session['user_info'].get('email') in admin_email,
                'user_info': session['user_info']
            }
        return {
            'logged_in': False,
            'is_admin': False,
            'user_info': None
        }

    def require_login(f):
        """Decorator to protect routes that require authentication."""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not app.config['LOGIN_ENABLED']:
                return f(*args, **kwargs)
                
            user_info = session.get('user_info')
            if not user_info:
                return jsonify({
                    'success': False,
                    'error': 'Authentication required'
                }), 401
            return f(*args, **kwargs)
        return decorated_function

    def check_ip_whitelist(ip: str) -> bool:
        """Check if IP is in the whitelist."""
        whitelist = config['login']['callback']['ip_whitelist']
        return not whitelist or ip in whitelist

    def load_data(filepath: Path):
        """Load data from a file (JSON or JS)."""
        if not filepath.exists():
            return []
        
        if filepath.suffix == '.js':
            # Remove 'var data = ' and ';' from js file
            content = filepath.read_text(encoding='utf-8')
            json_str = content.replace('var data = ', '').rstrip(';')
            return json.loads(json_str)
        else:
            return json.loads(filepath.read_text(encoding='utf-8'))

    def save_data(data, filepath: Path):
        """Save data to a file (JSON or JS)."""
        if filepath.suffix == '.js':
            content = f"var data = {json.dumps(data, indent=2, ensure_ascii=False)};"
            filepath.write_text(content, encoding='utf-8')
        else:
            filepath.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')

    # if 'data.js' and 'publis.js' not exisit, create empty file
    public_file = data_dir / 'public.js'
    if not public_file.exists():
        save_data([], public_file)
        print(f"Created public.js at {public_file}")
    # Create empty data.js if it doesn't exist
    data_file = data_dir / 'data.js'
    if not data_file.exists():
        save_data([], data_file)
        print(f"Created data.js at {data_file}")

    def send_visitor_notification(ip: str, user_agent: str, config: dict):
        """Send email notification about new visitor."""
        global last_email_sent
        current_time = time.time()
        
        if current_time - last_email_sent < config['visitor_report']['email_interval']:
            return
            
        admin_email = config['login']['email']['admin_email']
        base_url = request.url_root.rstrip('/')
        visitor_url = f"{base_url}/visitors"
        
        body = f"""
        New visitor detected:
        
        IP: {ip}
        User Agent: {user_agent}
        Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        View all visitors: {visitor_url}
        """
        
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['From'] = config['login']['email']['account']
        msg['To'] = admin_email
        msg['Subject'] = "New Visitor Alert - LinkNote"
        
        try:
            with smtplib.SMTP_SSL(config['login']['email']['smtp_server'], 
                                config['login']['email']['smtp_port']) as smtp:
                smtp.login(config['login']['email']['account'], 
                         config['login']['email']['password'])
                smtp.send_message(msg)
                last_email_sent = current_time
        except Exception as e:
            print(f"Error sending visitor notification: {e}")

    # before process request
    @app.before_request
    def visReportLogger():
        if config.get('visitor_report', {}).get('enabled'):
            ip = get_client_ip()
            ua = request.headers.get('User-Agent', '')
            visitor = (ip, ua)
            
            if visitor not in visitor_data:
                visitor_data.add(visitor)
                save_visitor_data(visitor_data, config)
                send_visitor_notification(ip, ua, config)

    @app.route('/')
    def index():
        return redirect('/static/index.html')

    @app.route('/visitors')
    @require_login
    def view_visitors():
        """Admin-only page to view visitors."""
        state = login_state()
        if not state['is_admin']:
            return jsonify({
                'success': False,
                'error': 'Admin access required'
            }), 403
            
        visitor_list = [{'ip': v[0], 'ua': v[1]} for v in visitor_data]
        return jsonify({
            'success': True,
            'visitors': visitor_list
        })

    @app.route('/api/login/state', methods=['GET'])
    def login_state_endpoint():
        """Get the current login state."""
        state = login_state()
        return jsonify(state)

    # logout
    @app.route('/api/logout', methods=['GET'])
    def logout():
        """Logout the user."""
        session.pop('user_info', None)
        return jsonify({
            'success': True,
            'message': 'Logged out successfully'
        })

    @app.route('/api/notes', methods=['GET'])
    def get_notes():
        filepath = request.args.get('file', '')
        dataFiles = os.listdir(app.config['DATA_DIR'])
        if not filepath or filepath not in dataFiles:
            return jsonify({
                'success': False,
                'error': 'File not found'
            }), 404
        filepath = Path(filepath)
        # Allow public access to public.js file
        is_public_file = filepath.name == 'public.js'
        # if not filepath.is_absolute():
        filepath = app.config['DATA_DIR'] / filepath

        if private and not is_public_file:
            state = login_state()
            if not state['logged_in']:
                return jsonify({
                    'success': False,
                    'error': 'Authentication required'
                }), 401
            if admin_email and not state['is_admin']:
                return jsonify({
                    'success': False,
                    'error': 'Admin access required'
                }), 403
        
        try:
            data = load_data(filepath)
            response = jsonify({
                'success': True,
                'data': data,
                'filepath': filepath.name
            })
            # Add login enabled state to headers
            response.headers['X-Login-Enabled'] = str(app.config['LOGIN_ENABLED']).lower()
            return response
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @app.route('/api/captcha', methods=['GET'])
    def get_captcha():
        """Generate and return a new CAPTCHA image."""
        image = ImageCaptcha(width=280, height=90)
        
        # Generate random CAPTCHA text
        chars = '23456789ABCDEFGHIJKMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        captcha_text = ''.join(secrets.choice(chars) for _ in range(6))
        
        # Store CAPTCHA text in session
        session['captcha'] = captcha_text
        session['captcha_time'] = time.time()
        
        # Generate image
        img_bytes = image.generate(captcha_text)
        
        # Convert to base64
        img_base64 = base64.b64encode(img_bytes.getvalue()).decode()
        
        return jsonify({
            'success': True,
            'image': f'data:image/png;base64,{img_base64}'
        })
        
    @app.route('/api/login/verify-captcha', methods=['POST'])
    def verify_captcha():
        """Verify the CAPTCHA value."""
        captcha = request.json.get('captcha')
        if not captcha:
            return jsonify({
                'success': False,
                'error': 'CAPTCHA is required'
            }), 400
        
        if captcha.lower() == session.get('captcha', '').lower():
            return jsonify({'success': True})
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid CAPTCHA'
            }), 400
            
    @app.route('/api/login/type', methods=['GET'])
    def get_login_type():
        """Get the configured login type."""
        if not app.config['LOGIN_ENABLED']:
            return jsonify({
                'success': False,
                'error': 'Login is not enabled'
            }), 400

        login_config = app.config['LOGIN_CONFIG']
        return jsonify({
            'success': True,
            'type': login_config['type'],
            'private': private,
            'email_enabled': login_config['email']['enabled'] if login_config['type'] == 'email' else False
        })

    @app.route('/api/login/email/request', methods=['POST'])
    def request_email_login():
        """Generate and send email login token."""
        if not app.config['LOGIN_ENABLED']:
            return jsonify({
                'success': False,
                'error': 'Login is not enabled'
            }), 400

        login_config = app.config['LOGIN_CONFIG']
        if login_config['type'] != 'email' or not login_config['email']['enabled']:
            return jsonify({
                'success': False,
                'error': 'Email login is not enabled'
            }), 400

        email = request.json.get('email')
        captcha = request.json.get('captcha')
        
        if not email:
            return jsonify({
                'success': False,
                'error': 'Email is required'
            }), 400
        # check time out
        if time.time() - session.get('captcha_time', 0) > 300:  # 5 minutes timeout
            return jsonify({
                'success': False,
                'error': 'CAPTCHA expired'
            }), 400
        if not captcha or captcha.lower() != session.get('captcha', '').lower():
            return jsonify({
                'success': False,
                'error': 'Invalid CAPTCHA'
            }), 400
        session['captcha'] = None  # Clear CAPTCHA after use
        session['captcha_time'] = 0
        # Generate token
        token = secrets.token_urlsafe(32)
        email_tokens[token] = {
            'email': email,
            'status': 'pending'
        }

        # Send email with login link
        base_url = request.url_root.rstrip('/')
        if send_login_email(login_config, email, token, base_url):
            session['token'] = token
            # Log email sent event
            log_auth_event(
                'EMAIL_SENT',
                email,
                request.headers.get('User-Agent', 'Unknown')
            )
            return jsonify({
                'success': True,
                'message': 'Login email sent'
            })
        else:
            del email_tokens[token]
            return jsonify({
                'success': False,
                'error': 'Failed to send login email'
            }), 500

    @app.route('/api/login/email/status', methods=['GET'])
    def login_status():
        token = session.get('token')
        if not token or token not in email_tokens:
            return jsonify({
                'success': False,
                'error': 'No active login request'
            }), 400
        else:
            token_data = email_tokens[token]
            if token_data['status'] == 'pending':
                return jsonify({
                    'success': False,
                    'status': token_data['status'],
                    'email': token_data['email']
                })
            elif token_data['status'] == 'success':
                email = token_data['email']
                session['user_info'] = {
                    'email': email,
                }
                del email_tokens[token]
                session.pop('token', None)
                
                # Log successful login
                log_auth_event(
                    'LOGIN_SUCCESS',
                    email,
                    request.headers.get('User-Agent', 'Unknown')
                )
                return jsonify({
                    'success': True,
                    'status': token_data['status'],
                    'email': token_data['email']
                })

    @app.route('/api/login/email/verify')
    def verify_email_login():
        """Verify email login token."""
        token = request.args.get('token')
        if not token or token not in email_tokens:
            return jsonify({
                'success': False,
                'error': 'Invalid token'
            }), 400
        token_data = email_tokens[token]
        token_data['status'] = 'success'
        return redirect('/static/index.html')

    @app.route('/api/login/request', methods=['POST'])
    def request_login():
        """Generate a login token and URL."""
        if not app.config['LOGIN_ENABLED']:
            return jsonify({
                'success': False,
                'error': 'Login is not enabled'
            }), 400
            
        # Generate token
        token = secrets.token_urlsafe(32)
        login_tokens[token] = {'status': 'pending'}
        session['login_token'] = token
        
        # Generate login URL
        login_url = config['login']['login_request_url']
        if '?' in login_url:
            login_url += f"&token={token}&appid={config['login']['appid']}"
        else:
            login_url += f"?token={token}&appid={config['login']['appid']}"
            
        return jsonify({
            'success': True,
            'login_url': login_url
        })
        
    @app.route('/api/login/callback', methods=['POST'])
    def login_callback():
        """Callback endpoint for the authentication server."""
        # Check IP whitelist
        if not check_ip_whitelist(request.remote_addr):
            return jsonify({
                'success': False,
                'error': 'Unauthorized IP'
            }), 403
            
        token = request.json.get('token')
        user_info = request.json.get('user_info')
        
        if not token or token not in login_tokens:
            return jsonify({
                'success': False,
                'error': 'Invalid token'
            }), 400
            
        # Update token status
        login_tokens[token] = {
            'status': 'success',
            'user_info': user_info
        }
        
        return jsonify({'success': True})
        
    @app.route('/api/login/check', methods=['GET'])
    def check_login():
        """Check login status."""
        token = session.get('login_token')
        if not token or token not in login_tokens:
            return jsonify({
                'success': False,
                'error': 'No active login request'
            })
            
        token_data = login_tokens[token]
        if token_data['status'] == 'success':
            # Store user info in session
            user_info = token_data['user_info']
            session['user_info'] = user_info
            # Clean up token
            del login_tokens[token]
            
            # Log successful login
            log_auth_event(
                'LOGIN_SUCCESS',
                user_info.get('email', 'Unknown'),
                request.headers.get('User-Agent', 'Unknown')
            )
            return jsonify({
                'success': True,
                'user_info': token_data['user_info']
            })
            
        return jsonify({
            'success': False,
            'status': token_data['status']
        })

    @app.route('/api/notes', methods=['POST'])
    @require_login
    def save_notes():
        """Save notes data to a file."""
        if private:
            state = login_state()
            if not state['logged_in'] or not state['is_admin']:
                return jsonify({
                    'success': False,
                    'error': 'Authentication required'
                }), 401
            if admin_email and not state['is_admin']:
                return jsonify({
                    'success': False,
                    'error': 'Admin access required'
                }), 403
        try:
            data = request.json.get('data', [])
            dataFiles = os.listdir(app.config['DATA_DIR'])
            filePath = request.json.get('filepath', '')
            if filePath not in dataFiles:
                return jsonify({
                    'success': False,
                    'error': 'File not found'
                }), 404
            filepath = app.config['DATA_DIR'] / filePath
            save_data(data, filepath)
            return jsonify({
                'success': True,
                'filepath': str(filepath)
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @app.route('/api/upload', methods=['POST'])
    @require_login
    def upload_file():
        """Upload a file and return its ID."""
        if private and admin_email:
            state = login_state()
            if not state['is_admin']:
                return jsonify({
                    'success': False,
                    'error': 'Admin access required'
                }), 403
        try:
            if 'file' not in request.files:
                return jsonify({
                    'success': False,
                    'error': 'No file provided'
                }), 400
            file = request.files['file']
            if file.filename == '':
                return jsonify({
                    'success': False,
                    'error': 'No file selected'
                }), 400
            # Create uploads directory
            uploads_dir = app.config['DATA_DIR'] / 'uploads'
            uploads_dir.mkdir(exist_ok=True)
            # Generate unique filename with original extension
            original_filename = secure_filename(file.filename)
            file_id = str(uuid.uuid4())
            file_extension = Path(original_filename).suffix
            filename = f"{file_id}{file_extension}"
            filepath = uploads_dir / filename
            # Save file
            file.save(filepath)
            # Store file metadata
            metadata_file = uploads_dir / 'metadata.json'
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
            else:
                metadata = {}
            metadata[file_id] = {
                'original_filename': original_filename,
                'filename': filename,
                'upload_time': time.time(),
                'size': filepath.stat().st_size,
                'mimetype': mimetypes.guess_type(original_filename)[0] or 'application/octet-stream'
            }
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
            return jsonify({
                'success': True,
                'file_id': file_id,
                'original_filename': original_filename,
                'url': f'/api/files/{file_id}'
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @app.route('/api/files/<file_id>')
    def get_file(file_id):
        """Get a file by ID."""
        try:
            uploads_dir = app.config['DATA_DIR'] / 'uploads'
            metadata_file = uploads_dir / 'metadata.json'
            if not metadata_file.exists():
                return jsonify({
                    'success': False,
                    'error': 'File not found'
                }), 404
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            if file_id not in metadata:
                return jsonify({
                    'success': False,
                    'error': 'File not found'
                }), 404
            file_info = metadata[file_id]
            filepath = uploads_dir / file_info['filename']
            if not filepath.exists():
                return jsonify({
                    'success': False,
                    'error': 'File not found on disk'
                }), 404
            return send_file(
                filepath,
                mimetype=file_info['mimetype'],
                as_attachment=False,
                download_name=file_info['original_filename']
            )
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @app.route('/api/files', methods=['GET'])
    @require_login
    def list_files():
        """List all uploaded files."""
        if private and admin_email:
            state = login_state()
            if not state['is_admin']:
                return jsonify({
                    'success': False,
                    'error': 'Admin access required'
                }), 403
        try:
            uploads_dir = app.config['DATA_DIR'] / 'uploads'
            metadata_file = uploads_dir / 'metadata.json'
            if not metadata_file.exists():
                return jsonify({
                    'success': True,
                    'files': []
                })
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            files = []
            for file_id, info in metadata.items():
                files.append({
                    'id': file_id,
                    'original_filename': info['original_filename'],
                    'upload_time': info['upload_time'],
                    'size': info['size'],
                    'mimetype': info['mimetype'],
                    'url': f'/api/files/{file_id}'
                })
            # Sort by upload time, newest first
            files.sort(key=lambda x: x['upload_time'], reverse=True)
            return jsonify({
                'success': True,
                'files': files
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @app.route('/api/files/<file_id>', methods=['DELETE'])
    @require_login
    def delete_file(file_id):
        """Delete a file by ID."""
        if private and admin_email:
            state = login_state()
            if not state['is_admin']:
                return jsonify({
                    'success': False,
                    'error': 'Admin access required'
                }), 403
        try:
            uploads_dir = app.config['DATA_DIR'] / 'uploads'
            metadata_file = uploads_dir / 'metadata.json'
            if not metadata_file.exists():
                return jsonify({
                    'success': False,
                    'error': 'File not found'
                }), 404
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            if file_id not in metadata:
                return jsonify({
                    'success': False,
                    'error': 'File not found'
                }), 404
            file_info = metadata[file_id]
            filepath = uploads_dir / file_info['filename']
            # Delete file from disk
            if filepath.exists():
                filepath.unlink()
            # Remove from metadata
            del metadata[file_id]
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
            return jsonify({
                'success': True,
                'message': 'File deleted successfully'
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @app.route('/api/data-files', methods=['GET'])
    def list_data_files():
        """List all available data files."""
        if private:
            state = login_state()
            if not state['logged_in']:
                return jsonify({
                    'success': False,
                    'error': 'Authentication required'
                }), 401
        try:
            data_dir = app.config['DATA_DIR']
            files = []
            # Add built-in public.js
            public_file = data_dir / 'public.js'
            if not public_file.exists():
                # Create public.js if it doesn't exist
                save_data([], public_file)
            files.append({
                'name': 'public.js',
                # 'path': str(public_file),
                'is_public': True,
                'size': public_file.stat().st_size if public_file.exists() else 0
            })
            # Find other .js and .json files
            for pattern in ['*.js', '*.json']:
                for filepath in data_dir.glob(pattern):
                    if filepath.name != 'public.js':  # Skip public.js as it's already added
                        files.append({
                            'name': filepath.name,
                            # 'path': str(filepath),
                            'is_public': False,
                            'size': filepath.stat().st_size
                        })
            return jsonify({
                'success': True,
                'files': files
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @app.route('/api/data-files', methods=['POST'])
    @require_login
    def create_data_file():
        """Create a new data file."""
        if private and admin_email:
            state = login_state()
            if not state['is_admin']:
                return jsonify({
                    'success': False,
                    'error': 'Admin access required'
                }), 403
        try:
            filename = request.json.get('filename', '').strip()
            if not filename:
                return jsonify({
                    'success': False,
                    'error': 'Filename is required'
                }), 400
            # Ensure proper extension
            if not filename.endswith(('.js', '.json')):
                return jsonify({
                    'success': False,
                    'error': 'Filename must end with .js or .json'
                }), 400
            # Secure the filename
            filename = secure_filename(filename)
            filepath = app.config['DATA_DIR'] / filename
            if filepath.exists():
                return jsonify({
                    'success': False,
                    'error': 'File already exists'
                }), 400
            # Create empty file
            save_data([], filepath)
            return jsonify({
                'success': True,
                'filename': filename,
                'path': str(filepath)
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @app.route('/api/notes/move', methods=['POST'])
    @require_login
    def move_note():
        """Move a note from one file to another."""
        if private and admin_email:
            state = login_state()
            if not state['is_admin']:
                return jsonify({
                    'success': False,
                    'error': 'Admin access required'
                }), 403
        
        try:
            source_file = Path(request.json.get('source_file', ''))
            target_file = Path(request.json.get('target_file', ''))
            note_index = request.json.get('note_index')
            
            if not source_file.is_absolute():
                source_file = app.config['DATA_DIR'] / source_file
            if not target_file.is_absolute():
                target_file = app.config['DATA_DIR'] / target_file
            
            if not source_file.exists():
                return jsonify({
                    'success': False,
                    'error': 'Source file not found'
                }), 404
            
            # Load source data
            source_data = load_data(source_file)
            
            if note_index < 0 or note_index >= len(source_data):
                return jsonify({
                    'success': False,
                    'error': 'Invalid note index'
                }), 400
            
            # Get note to move
            note = source_data.pop(note_index)
            
            # Load target data (create if doesn't exist)
            if target_file.exists():
                target_data = load_data(target_file)
            else:
                target_data = []
                target_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Add note to target
            target_data.append(note)
            
            # Save both files
            save_data(source_data, source_file)
            save_data(target_data, target_file)
            
            return jsonify({
                'success': True,
                'message': 'Note moved successfully'
            })
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    return app
