from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
from flask_restful import Api, Resource, reqparse
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import os
from datetime import datetime
import bcrypt
import uuid
from werkzeug.utils import secure_filename
import PyPDF2
import pikepdf

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
jwt = JWTManager()


class Config:
    BASE_DIR = '/opt/script/api_mb/pythonProject4'
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///pdf_archive.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
    MAX_CONTENT_LENGTH = 900 * 1024 * 1024  # 900MB


# Database Models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')
    _is_active = db.Column(db.Boolean, default=True, name='is_active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def get_id(self):
        return str(self.id)

    # Flask-Login required properties
    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return self._is_active

    @property
    def is_anonymous(self):
        return False


class Document(db.Model):
    __tablename__ = 'documents'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer)
    page_count = db.Column(db.Integer)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    extracted_text = db.Column(db.Text)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'filename': self.filename,
            'file_size': self.file_size,
            'page_count': self.page_count,
            'upload_date': self.upload_date.isoformat()
        }


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login_page'
    login_manager.login_message = 'Please log in to access this page.'
    jwt.init_app(app)
    CORS(app)

    # Create upload directory
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Setup REST API
    api = Api(app, prefix='/api')

    # API Resources
    class LoginResource(Resource):
        def post(self):
            print("ðŸ” Login endpoint called")

            # Get JSON data from request
            if not request.is_json:
                print("âŒ Request is not JSON")
                return {'message': 'Missing JSON in request'}, 400

            data = request.get_json()
            username = data.get('username')
            password = data.get('password')

            print(f"ðŸ“§ Username received: {username}")

            if not username or not password:
                print("âŒ Missing username or password")
                return {'message': 'Missing username or password'}, 400

            # Find user
            user = User.query.filter_by(username=username).first()

            if not user:
                print("âŒ User not found")
                return {'message': 'Invalid credentials'}, 401

            print(f"âœ… User found: {user.username}")

            # Check password
            if user.check_password(password) and user.is_active:
                print("âœ… Password correct, generating token")

                # Convert user.id to string for JWT identity
                access_token = create_access_token(
                    identity=str(user.id),
                    expires_delta=timedelta(hours=24)  # Add expiration
                )

                # Also login with Flask-Login for session management
                login_user(user, remember=True)

                response_data = {
                    'message': 'Login successful',
                    'access_token': access_token,
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'role': user.role
                    }
                }
                print("âœ… Login successful, returning response")
                return response_data, 200
            else:
                print("âŒ Password incorrect or user inactive")
                return {'message': 'Invalid credentials'}, 401

    class VerifyTokenResource(Resource):
        def post(self):
            """Verify a JWT token manually"""
            try:
                data = request.get_json()
                token = data.get('token')

                if not token:
                    return {'message': 'No token provided'}, 400

                import jwt as pyjwt

                try:
                    decoded = pyjwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
                    return {
                        'valid': True,
                        'decoded': decoded,
                        'user_id': decoded.get('sub'),
                        'expires': decoded.get('exp'),
                        'issued': decoded.get('iat')
                    }, 200
                except pyjwt.ExpiredSignatureError:
                    return {'valid': False, 'error': 'Token expired'}, 200
                except pyjwt.InvalidTokenError as e:
                    return {'valid': False, 'error': f'Invalid token: {str(e)}'}, 200

            except Exception as e:
                return {'message': f'Error: {str(e)}'}, 500

    class RegisterResource(Resource):
        def post(self):
            if not request.is_json:
                return {'message': 'Missing JSON in request'}, 400

            data = request.get_json()
            username = data.get('username')
            email = data.get('email')
            password = data.get('password')

            if not username or not email or not password:
                return {'message': 'Missing required fields'}, 400

            if User.query.filter_by(username=username).first():
                return {'message': 'Username already exists'}, 400

            if User.query.filter_by(email=email).first():
                return {'message': 'Email already exists'}, 400

            user = User(username=username, email=email)
            user.set_password(password)

            db.session.add(user)
            db.session.commit()

            return {'message': 'User created successfully'}, 201

    class TestAuthResource(Resource):
        @jwt_required()
        def get(self):
            current_user_id = get_jwt_identity()
            user = User.query.get(int(current_user_id))
            print(f"ðŸ” Test auth called by user ID: {current_user_id}")
            return {
                'message': 'JWT is working!',
                'user_id': current_user_id,
                'username': user.username if user else 'Unknown'
            }, 200

    class DocumentListResource(Resource):
        @jwt_required()
        def get(self):
            try:
                print("ðŸ” Documents endpoint called")
                print("ðŸ“‹ Request headers:", dict(request.headers))
                print("ðŸ“‹ Request headers:", dict(request.headers))

                # Manual JWT verification for debugging
                auth_header = request.headers.get('Authorization', '')
                print(f"ðŸ”‘ Authorization header: {auth_header}")

                if not auth_header.startswith('Bearer '):
                    print("âŒ No Bearer token in Authorization header")
                    return {'message': 'Missing or invalid Authorization header'}, 401

                token = auth_header[7:]  # Remove 'Bearer ' prefix
                print(f"ðŸ“¦ Token received (first 50 chars): {token[:50]}...")

                try:
                    # Manual token decoding
                    import jwt as pyjwt
                    decoded_token = pyjwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
                    print(f"âœ… Token manually decoded: {decoded_token}")
                    current_user_id = decoded_token.get('sub')

                    if not current_user_id:
                        print("âŒ No 'sub' claim in token")
                        return {'message': 'Invalid token: no user identity'}, 422

                except pyjwt.ExpiredSignatureError:
                    print("âŒ Token has expired")
                    return {'message': 'Token has expired'}, 401
                except pyjwt.InvalidTokenError as e:
                    print(f"âŒ Invalid token: {e}")
                    return {'message': f'Invalid token: {str(e)}'}, 422
                except Exception as e:
                    print(f"âŒ Token decoding error: {e}")
                    return {'message': f'Token error: {str(e)}'}, 422

                current_user_id = get_jwt_identity()
                print(f"âœ… JWT Identity extracted: {current_user_id}")

                # Verify user exists
                user = User.query.get(int(current_user_id))
                if not user:
                    print(f"âŒ User not found for ID: {current_user_id}")
                    return {'message': 'User not found'}, 404

                print(f"âœ… User verified: {user.username} (ID: {user.id})")

                # Get documents
                documents = Document.query.filter_by(user_id=int(current_user_id)).all()
                print(f"ðŸ“„ Found {len(documents)} documents for user {user.username}")

                return {
                    'documents': [doc.to_dict() for doc in documents],
                    'count': len(documents)
                }, 200

            except Exception as e:
                print(f"âŒ Error in documents endpoint: {str(e)}")
                import traceback
                traceback.print_exc()
                return {'message': f'Server error: {str(e)}'}, 500

        @jwt_required()
        def post(self):
            current_user_id = get_jwt_identity()

            if 'file' not in request.files:
                return {'message': 'No file provided'}, 400

            file = request.files['file']
            if file.filename == '':
                return {'message': 'No file selected'}, 400

            if not file.filename.lower().endswith('.pdf'):
                return {'message': 'Only PDF files are allowed'}, 400

            # Generate unique filename
            unique_filename = f"{uuid.uuid4().hex}.pdf"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)

            # --- Compress and archive ---
            try:
                # Optimize and compress the PDF directly in place (no extra copy)
                # Step 1: Compress PDF (overwrite original safely)
                with pikepdf.open(file_path, allow_overwriting_input=True) as pdf:
                    pdf.save(file_path, object_stream_mode=pikepdf.ObjectStreamMode.generate, recompress_flate=True)

                # Process PDF for metadata (using compressed file)
                with open(file_path, 'rb') as f:
                    reader = PyPDF2.PdfReader(f)
                    page_count = len(reader.pages)
                    text = ""
                    for page in reader.pages:
                        text += (page.extract_text() or "") + "\n"

                file_size = os.path.getsize(file_path)

            except Exception as e:
                return {'message': f'Error during PDF compression: {str(e)}'}, 400

            # Create document
            document = Document(
                title=request.form.get('title', file.filename),
                filename=file.filename,
                file_path=file_path,
                file_size=file_size,
                page_count=page_count,
                extracted_text=text,
                user_id=current_user_id
            )

            db.session.add(document)
            db.session.commit()

            return {
                'message': 'Document uploaded successfully',
                'document': document.to_dict()
            }, 201

    class ExternalRegisterResource(Resource):
        def post(self):
            """Register from Telegram or WhatsApp (no JWT needed)"""
            data = request.get_json()
            no_rujukan = data.get('no_rujukan')
            no_id_pelanggan = data.get('no_id_pelanggan')
            username = data.get('username')
            email = data.get('email') or f"{no_rujukan}@autogen.local"
            password = data.get('password') or no_id_pelanggan  # fallback password

            if not all([no_rujukan, no_id_pelanggan, username]):
                return {'message': 'no_rujukan, no_id_pelanggan, and username are required'}, 400

            if User.query.filter_by(email=email).first():
                return {'message': 'Email already registered'}, 400
            if User.query.filter_by(username=username).first():
                return {'message': 'Username already exists'}, 400

            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            return {
                'message': 'Registration successful',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'no_rujukan': no_rujukan,
                    'no_id_pelanggan': no_id_pelanggan
                }
            }, 201

    class DocumentResource(Resource):
        @jwt_required()
        def get(self, document_id):
            try:
                current_user_id = get_jwt_identity()
                print(f"ðŸ” Getting document {document_id} for user {current_user_id}")

                document = Document.query.get(document_id)
                if not document:
                    return {'message': 'Document not found'}, 404

                # Check if document belongs to current user
                if document.user_id != int(current_user_id):
                    print(
                        f"âŒ Access denied: Document {document_id} belongs to user {document.user_id}, but current user is {current_user_id}")
                    return {'message': 'Access denied'}, 403

                print(f"âœ… Access granted to document {document_id}")
                return {'document': document.to_dict()}, 200

            except Exception as e:
                print(f"âŒ Error in get document: {str(e)}")
                return {'message': f'Server error: {str(e)}'}, 500

        @jwt_required()
        def delete(self, document_id):
            current_user_id = get_jwt_identity()
            document = Document.query.get_or_404(document_id)


            user = User.query.get(int(current_user_id))
            if user.role != 'admin' and document.user_id != int(current_user_id):
                return {'message': 'Access denied'}, 403

            # Delete file
            try:
                if os.path.exists(document.file_path):
                    os.remove(document.file_path)
            except:
                pass

            db.session.delete(document)
            db.session.commit()

            return {'message': 'Document deleted successfully'}, 200

    # Register API resources
    api.add_resource(LoginResource, '/auth/login')
    api.add_resource(RegisterResource, '/auth/register')
    api.add_resource(ExternalRegisterResource, '/auth/register-external')
    api.add_resource(TestAuthResource, '/test-auth')
    api.add_resource(VerifyTokenResource, '/verify-token')
    api.add_resource(DocumentListResource, '/documents')
    api.add_resource(DocumentResource, '/documents/<int:document_id>')

    # Frontend routes
    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/login')
    def login_page():
        return render_template('login.html')

    @app.route('/dashboard')
    @login_required
    def dashboard():
        return render_template('dashboard.html')

    @app.route('/upload')
    @login_required
    def upload_page():
        return render_template('upload.html')

    @app.route('/api-docs')
    def api_docs():
        """API Documentation Page"""
        api_endpoints = [
            {
                'method': 'POST',
                'endpoint': '/api/auth/login',
                'description': 'User login with JWT token generation',
                'request': {
                    'username': 'string (required)',
                    'password': 'string (required)'
                },
                'response': {
                    'message': 'string',
                    'access_token': 'string (JWT)',
                    'user': 'object'
                }
            },
            {
                'method': 'POST',
                'endpoint': '/api/auth/register',
                'description': 'Register a new user',
                'request': {
                    'username': 'string (required)',
                    'email': 'string (required)',
                    'password': 'string (required)'
                },
                'response': {
                    'message': 'string'
                }
            },
            {
                'method': 'POST',
                'endpoint': '/api/auth/verify-token',
                'description': 'Verify JWT token validity',
                'request': {
                    'token': 'string (required)'
                },
                'response': {
                    'valid': 'boolean',
                    'user_id': 'string',
                    'expires': 'timestamp'
                }
            },
            {
                'method': 'GET',
                'endpoint': '/api/auth/test-auth',
                'description': 'Test JWT authentication (requires Bearer token)',
                'headers': {
                    'Authorization': 'Bearer <token>'
                },
                'response': {
                    'message': 'string',
                    'user_id': 'string',
                    'username': 'string'
                }
            },
            {
                'method': 'GET',
                'endpoint': '/api/documents',
                'description': 'Get all documents for authenticated user (requires Bearer token)',
                'headers': {
                    'Authorization': 'Bearer <token>'
                },
                'response': {
                    'documents': 'array',
                    'count': 'integer'
                }
            },
            {
                'method': 'POST',
                'endpoint': '/api/documents',
                'description': 'Upload a new PDF document (requires Bearer token)',
                'headers': {
                    'Authorization': 'Bearer <token>'
                },
                'request': {
                    'file': 'PDF file (required)',
                    'title': 'string (optional)'
                },
                'response': {
                    'message': 'string',
                    'document': 'object'
                }
            },
            {
                'method': 'GET',
                'endpoint': '/api/documents/<id>',
                'description': 'Get specific document by ID (requires Bearer token)',
                'headers': {
                    'Authorization': 'Bearer <token>'
                },
                'response': {
                    'document': 'object'
                }
            },
            {
                'method': 'DELETE',
                'endpoint': '/api/documents/<id>',
                'description': 'Delete a document (requires Bearer token)',
                'headers': {
                    'Authorization': 'Bearer <token>'
                },
                'response': {
                    'message': 'string'
                }
            },
            # Public endpoints
            {
                'method': 'GET',
                'endpoint': '/public/documents',
                'description': 'Public access to view all documents (no authentication required)',
                'response': {
                    'public_documents': 'array of document objects',
                    'total_count': 'integer'
                }
            },
            {
                'method': 'GET',
                'endpoint': '/public/documents/<id>/info',
                'description': 'Public access to document information',
                'response': {
                    'document': 'document object with details'
                }
            },
            {
                'method': 'GET',
                'endpoint': '/public/documents/<id>/view',
                'description': 'Public access to view/download PDF document',
                'response': 'PDF file'
            },
            {
                'method': 'GET',
                'endpoint': '/public/stats',
                'description': 'Public statistics about documents',
                'response': {
                    'statistics': 'object with totals',
                    'recent_documents': 'array of recent documents'
                }
            },
            {
                'method': 'GET',
                'endpoint': '/public/library',
                'description': 'Public HTML page to browse documents',
                'response': 'HTML page'
            }
        ]
        try:
            from flask_restx import Api
            has_swagger = True
        except ImportError:
            has_swagger = False

        return render_template('api_docs.html', endpoints=api_endpoints, has_swagger=has_swagger)

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('index'))

    # Debug routes
    @app.route('/api/debug/jwt-config')
    def debug_jwt_config():
        """Debug JWT configuration"""
        import jwt as pyjwt

        config_info = {
            'jwt_secret_key_set': bool(app.config.get('JWT_SECRET_KEY')),
            'secret_key_set': bool(app.config.get('SECRET_KEY')),
            'jwt_algorithm': 'HS256',
        }

        # Test if we can decode a token
        test_token = create_access_token(identity=1)
        try:
            decoded = pyjwt.decode(test_token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            config_info['token_decoding'] = 'SUCCESS'
            config_info['test_user_id'] = decoded.get('sub')
        except Exception as e:
            config_info['token_decoding'] = f'FAILED: {str(e)}'

        return jsonify(config_info)

    @app.route('/api/debug/endpoints')
    def debug_endpoints():
        """List all available API endpoints"""
        endpoints = []
        for rule in app.url_map.iter_rules():
            if rule.endpoint != 'static':
                methods = ','.join(rule.methods)
                endpoints.append({
                    'endpoint': rule.endpoint,
                    'methods': methods,
                    'path': str(rule)
                })

        return jsonify({
            'total_endpoints': len(endpoints),
            'endpoints': endpoints
        })

    @app.route('/api/debug/test')
    def debug_test():
        return jsonify({
            'status': 'API is working',
            'timestamp': datetime.utcnow().isoformat()
        })

    @app.route('/api/debug/headers')
    def debug_headers():
        return jsonify({
            'headers': dict(request.headers),
            'method': request.method,
            'content_type': request.content_type
        })

    @app.route('/debug/users')
    def debug_users():
        """Debug route to check users in database"""
        users = User.query.all()
        user_list = []
        for user in users:
            user_list.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'is_active': user.is_active
            })
        return jsonify({'users': user_list})

    @app.route('/debug/current-user')
    def debug_current_user():
        """Debug route to check current user session"""
        return jsonify({
            'is_authenticated': current_user.is_authenticated if current_user.is_authenticated else False,
            'username': current_user.username if current_user.is_authenticated else 'Anonymous',
            'user_id': current_user.get_id() if current_user.is_authenticated else None
        })

    # Public Document Sharing Routes
    @app.route('/public/documents')
    def public_documents():
        """Public endpoint to view all documents (read-only)"""
        documents = Document.query.all()

        document_list = []
        for doc in documents:
            # Get username for display
            user = User.query.get(doc.user_id)
            username = user.username if user else "Unknown"

            document_list.append({
                'id': doc.id,
                'title': doc.title,
                'filename': doc.filename,
                'file_size': doc.file_size,
                'file_size_mb': round(doc.file_size / (1024 * 1024), 2),
                'page_count': doc.page_count,
                'upload_date': doc.upload_date.isoformat(),
                'upload_date_formatted': doc.upload_date.strftime('%Y-%m-%d %H:%M:%S'),
                'uploaded_by': username,
                'view_url': f"/public/documents/{doc.id}/view",
                'info_url': f"/public/documents/{doc.id}/info"
            })

        return jsonify({
            'public_documents': document_list,
            'total_count': len(documents),
            'message': 'Public document access - Read only'
        })

    @app.route('/public/documents/<int:document_id>/info')
    def public_document_info(document_id):
        """Public endpoint to get document information"""
        document = Document.query.get_or_404(document_id)

        user = User.query.get(document.user_id)
        username = user.username if user else "Unknown"

        return jsonify({
            'document': {
                'id': document.id,
                'title': document.title,
                'filename': document.filename,
                'file_size': document.file_size,
                'file_size_mb': round(document.file_size / (1024 * 1024), 2),
                'page_count': document.page_count,
                'upload_date': document.upload_date.isoformat(),
                'upload_date_formatted': document.upload_date.strftime('%Y-%m-%d %H:%M:%S'),
                'uploaded_by': username,
                'extracted_text_preview': document.extracted_text[:500] + "..." if document.extracted_text and len(
                    document.extracted_text) > 500 else document.extracted_text
            }
        })

    @app.route('/public/documents/<int:document_id>/view')
    def public_document_view(document_id):
        """Public endpoint to download the original uncompressed PDF if available"""
        import tempfile
        import zipfile
        import shutil

        document = Document.query.get_or_404(document_id)

        # Extract UUID from the compressed filename, e.g., "compressed_<uuid>.pdf"
        basename = os.path.basename(document.file_path)
        if basename.startswith("compressed_"):
            uuid_part = basename.replace("compressed_", "").replace(".pdf", "")
        else:
            uuid_part = basename.replace(".pdf", "")

        archive_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{uuid_part}.pdf.zip")

        # Step 1: Try to decompress and send the original PDF
        if os.path.exists(archive_path):
            temp_dir = tempfile.mkdtemp()
            try:
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                    extracted_file = os.path.join(temp_dir, f"{uuid_part}.pdf")

                print(f"ðŸ“¦ Decompressed and sending original file: {extracted_file}")
                response = send_file(
                    extracted_file,
                    as_attachment=True,
                    download_name=document.filename,
                    mimetype='application/pdf'
                )

                # Clean up temp folder after response is sent
                @response.call_on_close
                def cleanup_temp():
                    shutil.rmtree(temp_dir, ignore_errors=True)

                return response

            except Exception as e:
                print(f"âš ï¸ Failed to decompress archive: {e}")

        # Step 2: Fallback to compressed version if ZIP not found
        if os.path.exists(document.file_path):
            print(f"ðŸ“¥ Sending compressed version (original ZIP not found): {document.file_path}")
            return send_file(
                document.file_path,
                as_attachment=False,
                download_name=document.filename,
                mimetype='application/pdf'
            )

        return jsonify({'error': 'File not found on server'}), 404


    @app.route('/public/stats')
    def public_stats():
        """Public statistics about documents"""
        total_documents = Document.query.count()
        total_users = User.query.count()
        total_size = db.session.query(db.func.sum(Document.file_size)).scalar() or 0
        total_pages = db.session.query(db.func.sum(Document.page_count)).scalar() or 0

        # Recent documents
        recent_documents = Document.query.order_by(Document.upload_date.desc()).limit(5).all()

        recent_list = []
        for doc in recent_documents:
            user = User.query.get(doc.user_id)
            recent_list.append({
                'title': doc.title,
                'uploaded_by': user.username if user else "Unknown",
                'upload_date': doc.upload_date.strftime('%Y-%m-%d'),
                'page_count': doc.page_count
            })

        return jsonify({
            'statistics': {
                'total_documents': total_documents,
                'total_users': total_users,
                'total_size_bytes': total_size,
                'total_size_gb': round(total_size / (1024 * 1024 * 1024), 2),
                'total_pages': total_pages,
                'average_pages_per_document': round(total_pages / total_documents, 2) if total_documents > 0 else 0
            },
            'recent_documents': recent_list,
            'access_info': {
                'public_access': True,
                'timestamp': datetime.utcnow().isoformat()
            }
        })

    @app.route('/public/library')
    def public_library():
        """Public HTML page to browse documents"""
        documents = Document.query.order_by(Document.upload_date.desc()).all()

        document_list = []
        for doc in documents:
            user = User.query.get(doc.user_id)
            document_list.append({
                'id': doc.id,
                'title': doc.title,
                'filename': doc.filename,
                'file_size_mb': round(doc.file_size / (1024 * 1024), 2),
                'page_count': doc.page_count,
                'upload_date': doc.upload_date.strftime('%Y-%m-%d'),
                'uploaded_by': user.username if user else "Unknown",
                'text_preview': (doc.extracted_text[:200] + "...") if doc.extracted_text and len(
                    doc.extracted_text) > 200 else (doc.extracted_text or "No text extracted")
            })

        return render_template('public_library.html', documents=document_list)

    # Custom Swagger Documentation Routes
    @app.route('/swagger')
    def swagger_ui():
        """Serve interactive Swagger UI"""
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>PDF Archive API - Swagger UI</title>
            <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@3/swagger-ui.css">
            <link rel="stylesheet" type="text/css" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
            <style>
                body { margin: 0; padding: 0; background: #fafafa; }
                .swagger-ui .topbar { display: none; }
                .header { 
                    background: white; 
                    padding: 20px; 
                    border-bottom: 1px solid #e0e0e0;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .header-content {
                    max-width: 1200px;
                    margin: 0 auto;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                .header h1 { 
                    margin: 0; 
                    color: #333;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }
                .btn-group { display: flex; gap: 10px; }
                #swagger-ui { padding: 20px; max-width: 1200px; margin: 0 auto; }
            </style>
        </head>
        <body>
            <div class="header">
                <div class="header-content">
                    <h1><i class="fas fa-book"></i> PDF Archive API Documentation</h1>
                    <div class="btn-group">
                        <a href="/api-docs" class="btn" style="background: #6c757d; color: white; padding: 10px 15px; text-decoration: none; border-radius: 5px;">
                            <i class="fas fa-file-alt"></i> Static Docs
                        </a>
                        <a href="/dashboard" class="btn" style="background: #007bff; color: white; padding: 10px 15px; text-decoration: none; border-radius: 5px;">
                            <i class="fas fa-tachometer-alt"></i> Dashboard
                        </a>
                        <a href="/public/library" class="btn" style="background: #28a745; color: white; padding: 10px 15px; text-decoration: none; border-radius: 5px;">
                            <i class="fas fa-book-open"></i> Public Library
                        </a>
                    </div>
                </div>
            </div>
            <div id="swagger-ui"></div>
            <script src="https://unpkg.com/swagger-ui-dist@3/swagger-ui-bundle.js"></script>
            <script>
                SwaggerUIBundle({
                    url: '/api/swagger.json',
                    dom_id: '#swagger-ui',
                    presets: [
                        SwaggerUIBundle.presets.apis,
                        SwaggerUIBundle.presets.ui
                    ],
                    layout: "BaseLayout",
                    deepLinking: true,
                    showExtensions: true,
                    showCommonExtensions: true
                });
            </script>
        </body>
        </html>
        '''

    @app.route('/api/swagger.json')
    def swagger_json():
        """Generate OpenAPI/Swagger specification for all API endpoints"""
        swagger_spec = {
            "openapi": "3.0.0",
            "info": {
                "title": "PDF Archive API",
                "description": "REST API for PDF Document Management System with JWT Authentication",
                "version": "1.0.0",
                "contact": {
                    "name": "API Support",
                    "url": "http://192.168.10.106:5000/api-docs"
                }
            },
            "servers": [
                {
                    "url": "http://192.168.10.106:5000",
                    "description": "Development server"
                }
            ],
            "paths": {
                "/api/auth/login": {
                    "post": {
                        "summary": "User Login",
                        "description": "Authenticate user and return JWT token",
                        "tags": ["Authentication"],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "username": {
                                                "type": "string",
                                                "example": "admin",
                                                "description": "Username for login"
                                            },
                                            "password": {
                                                "type": "string",
                                                "example": "Admin123!",
                                                "description": "Password for login"
                                            }
                                        },
                                        "required": ["username", "password"]
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "Login successful",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "message": {"type": "string", "example": "Login successful"},
                                                "access_token": {"type": "string",
                                                                 "description": "JWT token for authentication"},
                                                "user": {
                                                    "type": "object",
                                                    "properties": {
                                                        "id": {"type": "integer"},
                                                        "username": {"type": "string"},
                                                        "role": {"type": "string"}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            "400": {
                                "description": "Bad Request - Missing or invalid data"
                            },
                            "401": {
                                "description": "Unauthorized - Invalid credentials"
                            }
                        }
                    }
                },
                "/api/documents/{document_id}": {
                    "get": {
                        "summary": "Get Document Details",
                        "description": "Get specific document details by ID. Requires JWT token.",
                        "tags": ["Documents"],
                        "security": [{"bearerAuth": []}],
                        "parameters": [
                            {
                                "name": "document_id",
                                "in": "path",
                                "required": True,
                                "schema": {
                                    "type": "integer"
                                },
                                "description": "Document ID (e.g., 1, 2, 3)",
                                "example": 1
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "Success - Document details retrieved",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "document": {
                                                    "type": "object",
                                                    "properties": {
                                                        "id": {"type": "integer", "example": 1},
                                                        "title": {"type": "string", "example": "My Document"},
                                                        "filename": {"type": "string", "example": "document.pdf"},
                                                        "file_size": {"type": "integer", "example": 1024000},
                                                        "page_count": {"type": "integer", "example": 10},
                                                        "upload_date": {"type": "string",
                                                                        "example": "2024-01-01T12:00:00"}
                                                    }
                                                }
                                            }
                                        },
                                        "example": {
                                            "document": {
                                                "id": 1,
                                                "title": "Quarterly Report",
                                                "filename": "report.pdf",
                                                "file_size": 1024000,
                                                "page_count": 15,
                                                "upload_date": "2024-01-15T10:30:00"
                                            }
                                        }
                                    }
                                }
                            },
                            "401": {
                                "description": "Unauthorized - Missing or invalid JWT token"
                            },
                            "403": {
                                "description": "Forbidden - Document belongs to another user"
                            },
                            "404": {
                                "description": "Document not found - The specified document ID does not exist"
                            }
                        }
                    },
                    "delete": {
                        "summary": "Delete Document",
                        "description": "Delete a specific document. Requires JWT token.",
                        "tags": ["Documents"],
                        "security": [{"bearerAuth": []}],
                        "parameters": [
                            {
                                "name": "document_id",
                                "in": "path",
                                "required": True,
                                "schema": {
                                    "type": "integer"
                                },
                                "description": "Document ID to delete",
                                "example": 1
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "Document deleted successfully",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "message": {"type": "string",
                                                            "example": "Document deleted successfully"}
                                            }
                                        },
                                        "example": {
                                            "message": "Document deleted successfully"
                                        }
                                    }
                                }
                            },
                            "401": {
                                "description": "Unauthorized - Missing or invalid JWT token"
                            },
                            "403": {
                                "description": "Forbidden - Document belongs to another user"
                            },
                            "404": {
                                "description": "Document not found - The specified document ID does not exist"
                            }
                        }
                    }
                },
                # Public endpoints for Swagger
                "/public/documents": {
                    "get": {
                        "summary": "Get Public Documents",
                        "description": "Get all documents publicly available (no authentication required)",
                        "tags": ["Public"],
                        "responses": {
                            "200": {
                                "description": "Success",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "public_documents": {
                                                    "type": "array",
                                                    "items": {
                                                        "type": "object",
                                                        "properties": {
                                                            "id": {"type": "integer"},
                                                            "title": {"type": "string"},
                                                            "filename": {"type": "string"},
                                                            "file_size_mb": {"type": "number"},
                                                            "page_count": {"type": "integer"},
                                                            "upload_date": {"type": "string"},
                                                            "uploaded_by": {"type": "string"}
                                                        }
                                                    }
                                                },
                                                "total_count": {"type": "integer"}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "/public/documents/{document_id}/view": {
                    "get": {
                        "summary": "View Public Document",
                        "description": "View or download a PDF document publicly (no authentication required)",
                        "tags": ["Public"],
                        "parameters": [
                            {
                                "name": "document_id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "integer"},
                                "description": "Document ID"
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "PDF file",
                                "content": {
                                    "application/pdf": {
                                        "schema": {
                                            "type": "string",
                                            "format": "binary"
                                        }
                                    }
                                }
                            },
                            "404": {
                                "description": "Document not found"
                            }
                        }
                    }
                }
            },
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT",
                        "description": "JWT token obtained from /api/auth/login endpoint. Example: 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...'"
                    }
                }
            },
            "tags": [
                {
                    "name": "Authentication",
                    "description": "User authentication and registration endpoints"
                },
                {
                    "name": "Documents",
                    "description": "PDF document management endpoints"
                },
                {
                    "name": "Public",
                    "description": "Public document access endpoints (no authentication required)"
                },
                {
                    "name": "Debug",
                    "description": "Debug and utility endpoints"
                }
            ]
        }
        return jsonify(swagger_spec)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    return app


# Create the application
app = create_app()


@app.context_processor
def utility_processor():
    return dict(current_user=current_user)


# ============================================================
# 🔗 BOT GATEWAY INTEGRATION (Telegram + WhatsApp)
# ============================================================
import threading
import requests
from flask import request

# --- Optional Bot Configuration (fill later) ---
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_TOKEN", "")  # e.g. 123456789:ABC...
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")          # Meta Access Token
WHATSAPP_PHONE_ID = os.getenv("WHATSAPP_PHONE_ID", "")    # e.g. 123456789012345
WEBHOOK_VERIFY_TOKEN = os.getenv("WEBHOOK_VERIFY_TOKEN", "myverifytoken")

# --- Shared Helper: handle user input (for both bots) ---
def handle_user_query(source, sender_id, message_text):
    """
    Central handler for Telegram and WhatsApp messages.
    Integrates with your API endpoints.
    """
    print(f"[BOT] Message from {source} user {sender_id}: {message_text}")
    message_text = message_text.strip().lower()

    # REGISTER user via /api/auth/register-external
    if message_text.startswith("register"):
        try:
            parts = message_text.split()
            if len(parts) < 4:
                return " Usage: register <username> <no_akaun> <no_id_pelanggan>"

            _, username, no_akaun, no_id_pelanggan = parts[:4]
            payload = {
                "username": username,
                "no_rujukan": no_akaun,
                "no_id_pelanggan": no_id_pelanggan
            }
            resp = requests.post("http://192.168.10.106:5000/api/auth/register-external", json=payload)
            if resp.status_code == 201:
                return " Registration successful! You can now use /login or /list."
            else:
                return f"️ Registration failed: {resp.json().get('message', 'Unknown error')}"
        except Exception as e:
            return f" Error during registration: {e}"

    # LIST documents via /api/documents
    elif message_text.startswith("list"):
        try:
            # For now: list public documents (no token required)
            resp = requests.get("http://192.168.10.106:5000/public/documents")
            if resp.status_code == 200:
                docs = resp.json().get("public_documents", [])
                if not docs:
                    return " No documents available."
                reply = " Documents:\n"
                for d in docs[:5]:
                    reply += f" {d['title']} ({d['upload_date_formatted']})\n"
                    reply += f"  View: http://192.168.10.106:5000{d['view_url']}\n\n"
                return reply.strip()
            else:
                return " Failed to fetch documents."
        except Exception as e:
            return f" Error fetching documents: {e}"

    elif message_text.startswith("help"):
        return (
            " Commands available:\n"
            "- register <username> <no_akaun> <no_id_pelanggan>\n"
            "- list  Show recent documents\n"
            "- help  Show this help message"
        )

    else:
        return " Unknown command. Type 'help' for instructions."

# --- Telegram Bot Thread ---
def start_telegram_bot():
    if not TELEGRAM_BOT_TOKEN:
        print("[BOT] Telegram bot token not set, skipping Telegram startup.")
        return

    import telebot
    bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)

    @bot.message_handler(func=lambda message: True)
    def reply_all(message):
        reply = handle_user_query("telegram", message.chat.id, message.text)
        bot.send_message(message.chat.id, reply)

    print("[BOT] Telegram bot is running...")
    bot.infinity_polling(skip_pending=True)

# --- WhatsApp Webhook Routes ---
@app.route('/webhook', methods=['GET'])
def verify_webhook():
    """Meta (WhatsApp) webhook verification"""
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")
    if mode and token and token == WEBHOOK_VERIFY_TOKEN:
        return challenge
    else:
        return "Verification failed", 403

@app.route('/webhook', methods=['POST'])
def receive_whatsapp_message():
    """Receive incoming WhatsApp messages"""
    data = request.get_json()
    try:
        for entry in data.get("entry", []):
            for change in entry.get("changes", []):
                value = change.get("value", {})
                messages = value.get("messages", [])
                if messages:
                    msg = messages[0]
                    sender_id = msg["from"]
                    text = msg["text"]["body"]
                    reply = handle_user_query("whatsapp", sender_id, text)

                    # Send reply via WhatsApp Cloud API
                    if WHATSAPP_TOKEN and WHATSAPP_PHONE_ID:
                        url = f"https://graph.facebook.com/v17.0/{WHATSAPP_PHONE_ID}/messages"
                        payload = {
                            "messaging_product": "whatsapp",
                            "to": sender_id,
                            "type": "text",
                            "text": {"body": reply}
                        }
                        headers = {
                            "Authorization": f"Bearer {WHATSAPP_TOKEN}",
                            "Content-Type": "application/json"
                        }
                        requests.post(url, headers=headers, json=payload)
        return "EVENT_RECEIVED", 200
    except Exception as e:
        print(f"[BOT] Error handling WhatsApp message: {e}")
        return "ERROR", 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Create admin user if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@example.com', role='admin')
            admin.set_password('Admin123!')
            db.session.add(admin)
            db.session.commit()
            print("âœ“ Admin user created: admin / Admin123!")
        else:
            print("âœ“ Admin user already exists")

        # Create test user if not exists
        if not User.query.filter_by(username='test').first():
            test_user = User(username='test', email='test@example.com')
            test_user.set_password('Test123!')
            db.session.add(test_user)
            db.session.commit()
            print("âœ“ Test user created: test / Test123!")
        else:
            print("âœ“ Test user already exists")

    print(" PDF Archive Server starting...")
    print(" Web Interface: http://192.168.10.106:5000")
    print(" API Documentation: http://192.168.10.106:5000/api-docs")
    print(" Interactive Swagger: http://192.168.10.106:5000/swagger")
    print(" Public Document Library: http://192.168.10.106:5000/public/library")
    print(" Default Login: admin / Admin123!")
    print("\nAvailable API Endpoints:")
    print("  â€¢ POST   /api/auth/login     - User login with JWT")
    print("  â€¢ POST   /api/auth/register  - User registration")
    print("  â€¢ POST   /api/auth/verify-token - Verify JWT token")
    print("  â€¢ GET    /api/auth/test-auth - Test JWT authentication")
    print("  â€¢ GET    /api/documents      - List user documents")
    print("  â€¢ POST   /api/documents      - Upload PDF document")
    print("  â€¢ GET    /api/documents/<id> - Get specific document")
    print("  â€¢ DELETE /api/documents/<id> - Delete document")
    print("\nPublic Access Endpoints (No Login Required):")
    print("  â€¢ GET    /public/documents   - List all public documents")
    print("  â€¢ GET    /public/documents/<id>/info - Get document info")
    print("  â€¢ GET    /public/documents/<id>/view - View/download PDF")
    print("  â€¢ GET    /public/stats       - Get statistics")
    print("  â€¢ GET    /public/library     - Public library page")

    # Start bots in background threads
    if TELEGRAM_BOT_TOKEN:
        threading.Thread(target=start_telegram_bot, daemon=True).start()
    else:
        print("[BOT] Telegram disabled, no token set.")

    if WHATSAPP_TOKEN and WHATSAPP_PHONE_ID:
        print("[BOT] WhatsApp webhook active at /webhook")
    else:
        print("[BOT] WhatsApp disabled, no credentials set.")

    print(" PDF Archive Server starting...")
    app.run(debug=True, host='192.168.10.106', port=5000)
