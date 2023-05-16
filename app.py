from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField
from wtforms.validators import DataRequired, EqualTo, ValidationError
import bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://admin:Qwerty12@omat.cv5xiaopkvf0.us-east-1.rds.amazonaws.com/omat'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True
app.config['WTF_CSRF_ENABLED'] = False
app.secret_key = 'tu_clave_secreta_aqui'

login_manager = LoginManager()
login_manager.init_app(app)

try:
    db = SQLAlchemy(app)
except Exception as e:
    print('Error al conectarse a la base de datos:', e)


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

    def set_password(self, password):
        self.password = bcrypt.hashpw(password.encode(
            'utf-8'), bcrypt.gensalt()).decode('utf-8')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user is not None and user.check_password(password):
            login_user(user)
            flash('Has iniciado sesión exitosamente.')
            return redirect(url_for('index'))
        else:
            flash('Nombre de usuario o contraseña incorrectos.')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.')
    return redirect(url_for('index'))


def admin_required(view):
    @login_required
    def wrapped_view(**kwargs):
        if not current_user.is_admin:
            return redirect(url_for('index'))
        return view(**kwargs)
    return wrapped_view

class Documento(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(255), nullable=False)
    enlace = db.Column(db.String(255), nullable=False)
    categoria = db.Column(db.String(50), nullable=False)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/reporte")
def reporte():
    return render_template("reporte.html")


@app.route("/observatorio")
def observatorio():
    return render_template("observatorio.html")


@app.route("/transporte")
def transporte():
    transporte = listar_documentos_por_categoria('Transporte')
    return render_template("transporte.html", items=transporte)


@app.route("/transito")
def transito():
    transito = listar_documentos_por_categoria('Transito')
    return render_template("transito.html", items=transito)


@app.route("/infraestructura")
def infraestructura():
    infraestructura = listar_documentos_por_categoria('Infraestructura')
    # print(infraestructura)
    return render_template("infraestructura.html", items=infraestructura)


@app.route("/revista")
def revista():
    return render_template("revista.html")


# Documentos

def listar_documentos_por_categoria(categoria):
    try:
        datos = Documento.query.filter_by(categoria=categoria).all()
        return datos
    except Exception as ex:
        print(ex)
        return 'ERROR'

class DocumentoForm(FlaskForm):
    titulo = StringField('Nombre del documento', validators=[DataRequired()])
    enlace = StringField('Enlace del documento', validators=[DataRequired()])
    categoria = SelectField('Categoría', choices=[('Transito', 'Transito'), ('Transporte', 'Transporte'), ('Infraestructura', 'Infraestructura')], validators=[DataRequired()])
    submit = SubmitField('Aceptar') 

@app.route('/nuevo', methods=['GET', 'POST'])
@login_required
def nuevo():
    if not current_user.is_admin:
        abort(403)
    form = DocumentoForm()
    if form.validate_on_submit():
        titulo = form.titulo.data
        enlace = form.enlace.data
        categoria = form.categoria.data
        documento = Documento(titulo=titulo, enlace=enlace, categoria=categoria)
        db.session.add(documento)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('nuevo.html', form=form)

@app.route('/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar(id):
    documento = Documento.query.get_or_404(id)
    if not current_user.is_admin:
        abort(403)
    form = DocumentoForm(obj=documento)
    if form.validate_on_submit():
        form.populate_obj(documento)
        db.session.commit()
        flash('Documento actualizado correctamente.', 'success')
        return redirect(url_for('index'))
    return render_template('editar.html', form=form)


@app.route('/eliminar/<int:id>')
@login_required
def eliminar(id):
    documento = Documento.query.get_or_404(id)
    if not current_user.is_admin:
        abort(403)
    db.session.delete(documento)
    db.session.commit()
    flash('Documento eliminado correctamente.', 'success')
    return redirect(url_for('index'))

class RegistrationForm(FlaskForm):
    username = StringField('Nombre de usuario', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired(), EqualTo('password2')])
    password2 = PasswordField('Confirmar contraseña', validators=[DataRequired()])
    is_admin = BooleanField('¿Es un usuario administrador?')
    submit = SubmitField('Registrar')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Este nombre de usuario ya está en uso.')

class AdminRegistrationForm(RegistrationForm):
    is_admin = True

@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if not current_user.is_admin:
        abort(403)
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, is_admin=form.is_admin.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('¡Usuario registrado exitosamente!')
        return redirect(url_for('index'))
    return render_template('register.html', form=form)

@app.route('/admin/register', methods=['GET', 'POST'])
@login_required
def admin_register():
    if not current_user.is_admin:
        abort(403)
    form = AdminRegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, is_admin=form.is_admin.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('¡Usuario administrador registrado exitosamente!')
        return redirect(url_for('index'))
    return render_template('register.html', form=form)

def pagina_no_encontrada(error):
    return "<h1>Pagina no encontrada.<h1>"

if __name__ == "__main__":
    app.register_error_handler(404, pagina_no_encontrada)
    app.run(host="0.0.0.0", port=80, debug=True)
    #app.run(debug=True)

    #PARA REPORTE
    #Imagen, Titulo, fecha?