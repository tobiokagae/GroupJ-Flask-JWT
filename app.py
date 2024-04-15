from datetime import timedelta
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import logout_user, LoginManager
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_bcrypt import Bcrypt
import inspect
from enum import Enum

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/db_repository'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 's3cr3tK3yF0rJWT@pp!23'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)

db = SQLAlchemy(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)

# Set to store invalidated tokens
invalid_tokens = set()

# Models

class InvalidToken(db.Model):
    __tablename__ = 'invalidtoken'
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, unique=True)  # jti: JWT ID

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class DataProdi(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    kode_prodi = db.Column(db.String(5), unique=True)
    nama_prodi = db.Column(db.String(100))

class DataDosen(db.Model):
    nip = db.Column(db.String(30), primary_key=True)
    nama_lengkap = db.Column(db.String(100))
    prodi_id = db.Column(db.Integer, db.ForeignKey('data_prodi.id'))
    prodi = db.relationship('DataProdi', backref=db.backref('dosen', lazy=True))

class TypeDokumen(Enum):
    file = 'file'
    url = 'url'

class DataDokumen(db.Model):
    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    nip = db.Column(db.String(30), db.ForeignKey('data_dosen.nip'))
    type_dokumen = db.Column(db.Enum(TypeDokumen))
    nama_dokumen = db.Column(db.String(255))
    nama_file = db.Column(db.String(255))

# Helper functions

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_initial_user():
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        admin_password = 'admin'
        new_admin_user = User(username='admin')
        new_admin_user.set_password(admin_password)
        db.session.add(new_admin_user)
        db.session.commit()

# Middleware to check if token is valid
@app.before_request
def before_request_func():
    create_initial_user()

    # Check if token is invalid
    if request.endpoint:
        view_func = app.view_functions.get(request.endpoint)
        if view_func:
            decorators = []
            for _, value in inspect.getmembers(view_func):
                if hasattr(value, "__call__") and hasattr(value, "__self__"):
                    decorators.extend(inspect.getmembers(value.__self__, inspect.ismethod))
            if jwt_required in decorators:
                jwt_token = get_jwt()
                jwt_jti = jwt_token['jti']
                # Check if the JTI exists in the invalid token table
                invalid_token = InvalidToken.query.filter_by(jti=jwt_jti).first()
                if invalid_token:
                    app.logger.info(f"Token {jwt_jti} is invalid.")
                    return jsonify({'message': 'Token has been invalidated'}), 401



# Routes

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 400

    new_user = User(username=username)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({'message': 'Invalid username or password'}), 401
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token), 200

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    try:
        jti = get_jwt()['jti']
        invalid_token = InvalidToken(jti=jti)
        db.session.add(invalid_token)
        db.session.commit()
        logout_user()
        return jsonify({'message': 'Logged out successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    jwt_token = get_jwt()
    jwt_jti = jwt_token['jti']
    # Check if the JTI exists in the invalid token table
    invalid_token = InvalidToken.query.filter_by(jti=jwt_jti).first()
    if invalid_token:
        app.logger.info(f"Token {jwt_jti} is invalid.")
        return jsonify({'message': 'Token has been invalidated'}), 401
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

# CRUD routes for Prodi

@app.route('/prodi', methods=['POST'])
@jwt_required()
def create_prodi():
    try :
        jwt_token = get_jwt()
        jwt_jti = jwt_token['jti']
        # Check if the JTI exists in the invalid token table
        invalid_token = InvalidToken.query.filter_by(jti=jwt_jti).first()

        if invalid_token:
            app.logger.info(f"Token {jwt_jti} is invalid.")
            return jsonify({'message': 'Token has been invalidated'}), 401
        data = request.json
        new_prodi = DataProdi(kode_prodi=data['kode_prodi'], nama_prodi=data['nama_prodi'])
        db.session.add(new_prodi)
        db.session.commit()
        return jsonify({'id': new_prodi.id, 'message': 'Prodi created successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}, 500)

@app.route('/prodi', methods=['GET'])
@jwt_required()
def get_prodi():
    try:
        jwt_token = get_jwt()
        jwt_jti = jwt_token['jti']
        # Check if the JTI exists in the invalid token table
        invalid_token = InvalidToken.query.filter_by(jti=jwt_jti).first()
        if invalid_token:
            app.logger.info(f"Token {jwt_jti} is invalid.")
            return jsonify({'message': 'Token has been invalidated'}), 401

        # Jika token valid, lanjutkan dengan mengambil data prodi
        prodi = DataProdi.query.all()
        output = []
        for p in prodi:
            prodi_data = {'id': p.id, 'kode_prodi': p.kode_prodi, 'nama_prodi': p.nama_prodi}
            output.append(prodi_data)
        return jsonify({'prodi': output}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/prodi/<int:prodi_id>', methods=['GET'])
@jwt_required()
def get_single_prodi(prodi_id):
        try:
            jwt_token = get_jwt()
            jwt_jti = jwt_token['jti']
            # Check if the JTI exists in the invalid token table
            invalid_token = InvalidToken.query.filter_by(jti=jwt_jti).first()
            if invalid_token:
                app.logger.info(f"Token {jwt_jti} is invalid.")
                return jsonify({'message': 'Token has been invalidated'}), 401
            
            # If the token is valid, continue with retrieving the single prodi
            prodi = DataProdi.query.get_or_404(prodi_id)
            prodi_data = {'id': prodi.id, 'kode_prodi': prodi.kode_prodi, 'nama_prodi': prodi.nama_prodi}
            return jsonify({'prodi': prodi_data}), 200
        except Exception as e:
            return jsonify({"error" : str(e)}, 500)



@app.route('/prodi/<int:prodi_id>', methods=['PUT'])
@jwt_required()
def update_prodi(prodi_id):

    try:
        jwt_token = get_jwt()
        jwt_jti = jwt_token['jti']
        # Check if the JTI exists in the invalid token table
        invalid_token = InvalidToken.query.filter_by(jti=jwt_jti).first()
        if invalid_token:
            app.logger.info(f"Token {jwt_jti} is invalid.")
            return jsonify({'message': 'Token has been invalidated'}), 401


        prodi = DataProdi.query.get_or_404(prodi_id)
        data = request.json
        prodi.kode_prodi = data['kode_prodi']
        prodi.nama_prodi = data['nama_prodi']
        db.session.commit()
        return jsonify({'message': 'Prodi updated successfully'})
    except Exception as e:
        return jsonify({"error" : str(e)}, 500)
   

@app.route('/prodi/<int:prodi_id>', methods=['DELETE'])
@jwt_required()
def delete_prodi(prodi_id):
    try:
        jwt_token = get_jwt()
        jwt_jti = jwt_token['jti']
        # Check if the JTI exists in the invalid token table
        invalid_token = InvalidToken.query.filter_by(jti=jwt_jti).first()
        if invalid_token:
            app.logger.info(f"Token {jwt_jti} is invalid.")
            return jsonify({'message': 'Token has been invalidated'}), 401


        prodi = DataProdi.query.get_or_404(prodi_id)
        db.session.delete(prodi)
        db.session.commit()
        return jsonify({'message': 'Prodi deleted successfully'})
    except Exception as e:
        return jsonify({'error' : str(e)},500)

# CRUD routes for Dosen

@app.route('/dosen', methods=['POST'])
@jwt_required()
def create_dosen():
    try:
        jwt_token = get_jwt()
        jwt_jti = jwt_token['jti']
        # Check if the JTI exists in the invalid token table
        invalid_token = InvalidToken.query.filter_by(jti=jwt_jti).first()
        if invalid_token:
            app.logger.info(f"Token {jwt_jti} is invalid.")
            return jsonify({'message': 'Token has been invalidated'}), 401


        data = request.json
        new_dosen = DataDosen(nip=data['nip'], nama_lengkap=data['nama_lengkap'], prodi_id=data['prodi_id'])
        db.session.add(new_dosen)
        db.session.commit()
        return jsonify({'message': 'Dosen created successfully'}), 201
    except Exception as e:
        return jsonify({'error' : str(e)}, 500)

@app.route('/dosen', methods=['GET'])
@jwt_required()
def get_dosen():
    try:
        jwt_token = get_jwt()
        jwt_jti = jwt_token['jti']
        # Check if the JTI exists in the invalid token table
        invalid_token = InvalidToken.query.filter_by(jti=jwt_jti).first()
        if invalid_token:
            app.logger.info(f"Token {jwt_jti} is invalid.")
            return jsonify({'message': 'Token has been invalidated'}), 401


        dosen = DataDosen.query.all()
        output = []
        for d in dosen:
            dosen_data = {'nip': d.nip, 'nama_lengkap': d.nama_lengkap, 'prodi_id': d.prodi_id}
            output.append(dosen_data)
        return jsonify({'dosen': output})
    except Exception as e:
        return jsonify({'error' : str(e)},500)
    
@app.route('/dosen/<string:nip>', methods=['PUT'])
@jwt_required()
def update_dosen(nip):
    try:

        jwt_token = get_jwt()
        jwt_jti = jwt_token['jti']
        # Check if the JTI exists in the invalid token table
        invalid_token = InvalidToken.query.filter_by(jti=jwt_jti).first()
        if invalid_token:
            app.logger.info(f"Token {jwt_jti} is invalid.")
            return jsonify({'message': 'Token has been invalidated'}), 401

        dosen = DataDosen.query.filter_by(nip=nip).first()
        if not dosen:
            return jsonify({'error': 'Dosen not found'}), 404

        data = request.json
        dosen.nama_lengkap = data.get('nama_lengkap', dosen.nama_lengkap)
        dosen.prodi_id = data.get('prodi_id', dosen.prodi_id)
        db.session.commit()
        return jsonify({'message': 'Dosen updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/dosen/<string:nip>', methods=['DELETE'])
@jwt_required()
def delete_dosen(nip):
    try:

        jwt_token = get_jwt()
        jwt_jti = jwt_token['jti']
        # Check if the JTI exists in the invalid token table
        invalid_token = InvalidToken.query.filter_by(jti=jwt_jti).first()
        if invalid_token:
            app.logger.info(f"Token {jwt_jti} is invalid.")
            return jsonify({'message': 'Token has been invalidated'}), 401


        dosen = DataDosen.query.filter_by(nip=nip).first()
        if not dosen:
            return jsonify({'error': 'Dosen not found'}), 404

        db.session.delete(dosen)
        db.session.commit()
        return jsonify({'message': 'Dosen deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# CRUD routes for Dokumen

@app.route('/dokumen', methods=['POST'])
@jwt_required()
def create_dokumen():
    try:
        jwt_token = get_jwt()
        jwt_jti = jwt_token['jti']
        # Check if the JTI exists in the invalid token table
        invalid_token = InvalidToken.query.filter_by(jti=jwt_jti).first()
        if invalid_token:
            app.logger.info(f"Token {jwt_jti} is invalid.")
            return jsonify({'message': 'Token has been invalidated'}), 401


        data = request.json
        new_dokumen = DataDokumen(nip=data['nip'], type_dokumen=data['type_dokumen'],
                                   nama_dokumen=data['nama_dokumen'], nama_file=data['nama_file'])
        db.session.add(new_dokumen)
        db.session.commit()
        return jsonify({'message': 'Dokumen created successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/dokumen', methods=['GET'])
@jwt_required()
def get_dokumen():
    try:
        jwt_token = get_jwt()
        jwt_jti = jwt_token['jti']
        # Check if the JTI exists in the invalid token table
        invalid_token = InvalidToken.query.filter_by(jti=jwt_jti).first()
        if invalid_token:
            app.logger.info(f"Token {jwt_jti} is invalid.")
            return jsonify({'message': 'Token has been invalidated'}), 401

        dokumen = DataDokumen.query.all()
        output = []
        for d in dokumen:
            dokumen_data = {'id': d.id, 'nip': d.nip, 'type_dokumen': d.type_dokumen.value,
                            'nama_dokumen': d.nama_dokumen, 'nama_file': d.nama_file}
            output.append(dokumen_data)
        return jsonify({'dokumen': output})
    except Exception as e:
        return jsonify({'error' : str(e)},500)

@app.route('/dokumen/<int:dokumen_id>', methods=['GET'])
@jwt_required()
def get_single_dokumen(dokumen_id):
    try:
        jwt_token = get_jwt()
        jwt_jti = jwt_token['jti']
        # Check if the JTI exists in the invalid token table
        invalid_token = InvalidToken.query.filter_by(jti=jwt_jti).first()
        if invalid_token:
            app.logger.info(f"Token {jwt_jti} is invalid.")
            return jsonify({'message': 'Token has been invalidated'}), 401

        dokumen = DataDokumen.query.get_or_404(dokumen_id)
        dokumen_data = {'id': dokumen.id, 'nip': dokumen.nip, 'type_dokumen': dokumen.type_dokumen.value,
                        'nama_dokumen': dokumen.nama_dokumen, 'nama_file': dokumen.nama_file}
        return jsonify({'dokumen': dokumen_data})
    except Exception as e:
        return jsonify({'error' : str(e)},500)

@app.route('/dokumen/<int:dokumen_id>', methods=['PUT'])
@jwt_required()
def update_dokumen(dokumen_id):
    try:

        jwt_token = get_jwt()
        jwt_jti = jwt_token['jti']
        # Check if the JTI exists in the invalid token table
        invalid_token = InvalidToken.query.filter_by(jti=jwt_jti).first()
        if invalid_token:
            app.logger.info(f"Token {jwt_jti} is invalid.")
            return jsonify({'message': 'Token has been invalidated'}), 401

        dokumen = DataDokumen.query.get_or_404(dokumen_id)
        data = request.json
        dokumen.nip = data['nip']
        dokumen.type_dokumen = data['type_dokumen']
        dokumen.nama_dokumen = data['nama_dokumen']
        dokumen.nama_file = data['nama_file']
        db.session.commit()
        return jsonify({'message': 'Dokumen updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/dokumen/<int:dokumen_id>', methods=['DELETE'])
@jwt_required()
def delete_dokumen(dokumen_id):
    try:

        jwt_token = get_jwt()
        jwt_jti = jwt_token['jti']
        # Check if the JTI exists in the invalid token table
        invalid_token = InvalidToken.query.filter_by(jti=jwt_jti).first()
        if invalid_token:
            app.logger.info(f"Token {jwt_jti} is invalid.")
            return jsonify({'message': 'Token has been invalidated'}), 401


        dokumen = DataDokumen.query.get_or_404(dokumen_id)
        db.session.delete(dokumen)
        db.session.commit()
        return jsonify({'message': 'Dokumen deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5001)
