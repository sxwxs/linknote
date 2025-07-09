import os
import sys
import yaml
import shutil
import click
import webbrowser
from pathlib import Path
from .server import create_app

def load_config(config_path: Path = None) -> dict:
    """Load configuration from YAML file or return defaults."""
    default_config = {
        'data_dir': None,
        'login': {
            'enabled': False,
            'appid': '',
            'login_request_url': '',
            'endpoint': '',
            'callback': {
                'ip_whitelist': []
            }
        },
        'server': {
            'secret_key': 'default-secret-key'
        }
    }
    
    if not config_path:
        return default_config
        
    if not config_path.exists():
        # Create default config file for user
        default_config_path = Path(__file__).parent / 'config.default.yml'
        if default_config_path.exists():
            shutil.copy(default_config_path, config_path)
            click.echo(f"Created default config file at {config_path}")
        return default_config
    
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            return config if config else default_config
    except Exception as e:
        click.echo(f"Error loading config: {e}", err=True)
        return default_config

def get_default_data_dir():
    """Get the default data directory based on the operating system."""
    if sys.platform == 'win32':
        return Path(os.environ['APPDATA']) / 'linknote'
    return Path.home() / '.local' / 'share' / 'linknote'

def ensure_data_dir():
    """Ensure the data directory exists."""
    data_dir = get_default_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir

@click.group()
def main():
    """LinkNote - Manage your bookmarks with tags and notes."""
    pass

@main.command()
@click.option('--host', '-h', default='127.0.0.1', help='Host to bind to.')
@click.option('--port', '-p', default=5000, help='Port to bind to.')
@click.option('--config', '-c', type=click.Path(), help='Path to config file.')
def start(host, port, config):
    """Start the LinkNote web server."""
    config_path = Path(config) if config else None
    cfg = load_config(config_path)
    
    # Use configured data_dir or fall back to default
    data_dir = Path(cfg['data_dir']) if cfg.get('data_dir') else ensure_data_dir()
    app = create_app(data_dir, cfg)
    url = f"http://{host}:{port}"
    click.echo(f"Starting LinkNote server at {url}")
    webbrowser.open(url)
    app.run(host=host, port=port)

@main.command()
def data():
    """Open the default data directory."""
    data_dir = get_default_data_dir()
    if sys.platform == 'win32':
        os.startfile(data_dir)
    elif sys.platform == 'darwin':
        os.system(f'open "{data_dir}"')
    else:
        os.system(f'xdg-open "{data_dir}"')

@main.command()
@click.option('--output', '-o', type=click.Path(), help='Output path for the config file.')
def config(output):
    """Generate a sample configuration file."""
    sample_config = {
        'data_dir': None,
        'login': {
            'enabled': True,
            'private': False,
            'type': 'email',
            'email': {
                'enabled': True,
                'account': 'your-email@gmail.com',
                'password': 'your-app-password',
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 465,
                'endpoint': 'https://your-login-endpoint.com',
                'admin_email': 'admin@es2q.com,root@es2q.com',
            }
        },
        'server': {
            'secret_key': 'change-this-to-a-secure-secret-key'
        }
    }

    output_path = Path(output) if output else Path('config.yml')
    
    try:
        with open(output_path, 'w') as f:
            yaml.dump(sample_config, f, default_flow_style=False)
        click.echo(f"Created sample config file at {output_path}")
        click.echo("\nNOTE: Please update the email settings with your credentials.")
        click.echo("For Gmail, you'll need to use an App Password: https://support.google.com/accounts/answer/185833")
    except Exception as e:
        click.echo(f"Error creating config file: {e}", err=True)

if __name__ == '__main__':
    main()
