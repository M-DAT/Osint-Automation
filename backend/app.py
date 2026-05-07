from flask import Flask
from flask_cors import CORS
from core.database import init_osint_db, get_user_by_username, create_user
from routes.vt_scanner import vt_bp
from routes.osint_routes import osint_bp
from routes.auth_routes import auth_bp

app = Flask(__name__)
CORS(app)

# Register Blueprints
app.register_blueprint(vt_bp)
app.register_blueprint(osint_bp)
app.register_blueprint(auth_bp)

# Initialize Database
init_osint_db()

# Create default admin if not exists
if not get_user_by_username("admin"):
    create_user("admin", "admin123", role="admin")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True, threaded=True)