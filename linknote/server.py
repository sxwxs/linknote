import os
import json
import uuid
import secrets
import smtplib
from pathlib import Path
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, request, jsonify, redirect, session, Response, url_for
from typing import Dict, Optional

# Store login tokens and their states
login_tokens: Dict[str, dict] = {}
# Store email login tokens
email_tokens: Dict[str, dict] = {}

def send_login_email(config: dict, recipient: str, token: str, base_url: str) -> bool:
    """Send login email with token."""
    # try:
    if True:
        print(config)
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

def create_app(data_dir: Path, config: dict):
    static_folder = os.path.join(os.path.dirname(__file__), 'static')
    app = Flask(__name__, static_folder=static_folder)
    app.config['DATA_DIR'] = data_dir
    app.config['LOGIN_ENABLED'] = config['login']['enabled']
    app.config['LOGIN_CONFIG'] = config['login']
    app.secret_key = config['server']['secret_key']
    private = config['login'].get('private', False)
    if 'email' in config['login']:
        admin_email = config['login']['email'].get('admin_email', '')
        admin_email = admin_email.split(',')
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
    print(f"Data directory set to: {data_dir}")
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
            content = f"var data = {json.dumps(data, indent=2)};"
            filepath.write_text(content, encoding='utf-8')
        else:
            filepath.write_text(json.dumps(data, indent=2), encoding='utf-8')

    @app.route('/')
    def index():
        return redirect('/static/index.html')
    
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
        if private:
            state = login_state()
            if not state['logged_in']:
                return jsonify({
                    'success': False,
                    'error': 'Authentication required'
                }), 401
        filepath = Path(request.args.get('file', ''))
        if not filepath.is_absolute():
            filepath = app.config['DATA_DIR'] / 'data.js'
        
        try:
            data = load_data(filepath)
            response = jsonify({
                'success': True,
                'data': data,
                'filepath': str(filepath)
            })
            # Add login enabled state to headers
            response.headers['X-Login-Enabled'] = str(app.config['LOGIN_ENABLED']).lower()
            return response
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

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
        if not email:
            return jsonify({
                'success': False,
                'error': 'Email is required'
            }), 400

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
                session['user_info'] = {
                    'email': token_data['email'],
                }
                del email_tokens[token]
                session.pop('token', None)
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
            session['user_info'] = token_data['user_info']
            # Clean up token
            del login_tokens[token]
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
        try:
            data = request.json.get('data', [])
            filepath = Path(request.json.get('filepath', ''))
            
            if not filepath.is_absolute():
                filepath = app.config['DATA_DIR'] / 'data.js'
                
            filepath.parent.mkdir(parents=True, exist_ok=True)
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

    return app
