from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, current_user, logout_user, login_user, UserMixin
from flask_bcrypt import Bcrypt

app = Flask(__name__)

# Defina a chave secreta
app.secret_key = 'startup_autenticators'

# Configuração do Banco de Dados MySQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:root@localhost/face_safety'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)

def encrypt_password(password):
    return bcrypt.generate_password_hash(password).decode('utf-8')
class Pessoa(db.Model, UserMixin):
    idPessoa = db.Column(db.Integer, primary_key=True)  # Renomeado para 'id' para conformidade com Flask-Login
    nome = db.Column(db.String(255))
    cpf = db.Column(db.String(11), unique=True)
    password = db.Column(db.String(255))

    def get_id(self):
        return str(self.idPessoa)

@login_manager.user_loader
def load_user(user_id):
    return Pessoa.query.get(int(user_id))

def validate_user_data(cpf, password):
    if len(cpf) != 11 or not cpf.isdigit():
        raise ValueError('CPF inválido.')
    if len(password) < 8:
        raise ValueError('Senha muito curta.')

def encrypt_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(hashed, plain_text):
    return bcrypt.checkpw(plain_text.encode('utf-8'), hashed)

@app.route('/', methods=['GET'])
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        cpf = request.form['cpf']
        password = request.form['password']

        try:
            validate_user_data(cpf, password)
        except ValueError as e:
            flash(str(e), 'danger')
            return redirect(url_for('login'))

        user = Pessoa.query.filter_by(cpf=cpf).first()
        print(user)
        print(user.password)
        print(password)
        if user and bcrypt.check_password_hash(user.password, password):
            # Faz login da pessoa
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Credenciais inválidas.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nome = request.form['nome']
        cpf = request.form['cpf']
        plain_text_password = request.form['password']

        hashed_password = bcrypt.generate_password_hash(plain_text_password).decode('utf-8')

        new_person = Pessoa(nome=nome, cpf=cpf, password=hashed_password)
        db.session.add(new_person)
        db.session.commit()
        # Redirecione para onde você deseja após o registro
        return redirect(url_for('index'))

    return render_template('register.html')

if __name__ == '__main__':
    app.run()
