from app import app
import sqlalchemy as sa
import sqlalchemy.orm as so
from app.models import User, Scan, ToolResult, Vulnerability, Report, ApiKey, ConsentLog, Subscription

@app.shell_context_processor
def make_shell_context():
    """Provide a shell context with the application's models and database."""
    return {
        'app': app,
        'db': sa,
        'orm': so,
        'User': User,
        'Scan': Scan,
        'ToolResult': ToolResult,
        'Vulnerability': Vulnerability,
        'Report': Report,
        'ApiKey': ApiKey,
        'ConsentLog': ConsentLog,
        'Subscription': Subscription
    }