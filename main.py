# Khai báo thư viện,framework,...
from flask import Flask, render_template, redirect, url_for, Blueprint, flash, Response, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, FileField, IntegerField, FloatField,TextAreaField,EmailField,RadioField,SubmitField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import *
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import time
from datetime import datetime
from base64 import b64encode
import base64
from io import BytesIO
from werkzeug.utils import secure_filename
import os
from web3 import Web3
import json
from web3.middleware import geth_poa_middleware
from eth_account import Account
import secrets

web3 = Web3(Web3.HTTPProvider('https://sepolia.infura.io/v3/8c4c9235b7ed489ab0bc8c26795ae24e'))
web3.middleware_onion.inject(geth_poa_middleware, layer=0)
abi = json.loads('[{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"spender","type":"address"},{"name":"tokens","type":"uint256"}],"name":"approve","outputs":[{"name":"success","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"from","type":"address"},{"name":"to","type":"address"},{"name":"tokens","type":"uint256"}],"name":"transferFrom","outputs":[{"name":"success","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"_totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"tokenOwner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"a","type":"uint256"},{"name":"b","type":"uint256"}],"name":"safeSub","outputs":[{"name":"c","type":"uint256"}],"payable":false,"stateMutability":"pure","type":"function"},{"constant":false,"inputs":[{"name":"to","type":"address"},{"name":"tokens","type":"uint256"}],"name":"transfer","outputs":[{"name":"success","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"a","type":"uint256"},{"name":"b","type":"uint256"}],"name":"safeDiv","outputs":[{"name":"c","type":"uint256"}],"payable":false,"stateMutability":"pure","type":"function"},{"constant":true,"inputs":[{"name":"a","type":"uint256"},{"name":"b","type":"uint256"}],"name":"safeMul","outputs":[{"name":"c","type":"uint256"}],"payable":false,"stateMutability":"pure","type":"function"},{"constant":true,"inputs":[{"name":"tokenOwner","type":"address"},{"name":"spender","type":"address"}],"name":"allowance","outputs":[{"name":"remaining","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"a","type":"uint256"},{"name":"b","type":"uint256"}],"name":"safeAdd","outputs":[{"name":"c","type":"uint256"}],"payable":false,"stateMutability":"pure","type":"function"},{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"tokens","type":"uint256"}],"name":"Transfer","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"tokenOwner","type":"address"},{"indexed":true,"name":"spender","type":"address"},{"indexed":false,"name":"tokens","type":"uint256"}],"name":"Approval","type":"event"}]')
contract = web3.eth.contract(address='0x2519019C7251545be7B81521951874B2c4948A56', abi=abi)

db = SQLAlchemy()
app = Flask(__name__, template_folder='template')
app.config['SECRET_KEY'] = 'Teen-for-education'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
views = Blueprint("views", __name__)
bootstrap = Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
db.init_app(app)

class Teacher(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(15),nullable=False)
    email = db.Column(db.String(100),nullable=False)
    address = db.Column(db.String, unique=True,nullable=False)
    account_type = db.Column(db.Integer,nullable=False)
    cls_id = db.Column(db.Integer,nullable=False)
    nick = db.Column(db.String(30),nullable=False)
    private_key = db.Column(db.String(1000))
    password = db.Column(db.String(80),nullable=False)
    def __repr__(self):
        return '<User {}>'.format(self.name)

'''
class Student(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_name = db.Column(db.String(15),nullable=False)
    email = db.Column(db.String(100), unique=True,nullable=False)
    Class = db.Column(db.String(10),nullable=False)#db.relationship('Class', backref='article', lazy=True)
    cls_id = db.Column(db.Integer,nullable=False)
    address = db.Column(db.String, unique=True)
    present = db.Column(db.Integer)
    absent = db.Column(db.Integer)
    password = db.Column(db.String(80),nullable=False)

    def __repr__(self):
        return '<User {}>'.format(self.student_name)
'''

class Class(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    grade = db.Column(db.Integer,nullable=False)
    name = db.Column(db.String(10),nullable=False)
    nick = db.Column(db.String(10),nullable=False)
    #homework = db.relationship('Homework', backref='article', lazy=True)
    """
    def __repr__(self):
        return f"Comment('{self.body}', '{self.timestamp}')"
    """

class Homework(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Class = db.Column(db.String(10),nullable=False)
    name = db.Column(db.String(10000),nullable=False)
    mark = db.Column(db.String(2))
    present = db.Column(db.String(1000))
    cls_id = db.Column(db.Integer,nullable=False)
    by = db.Column(db.String(100), nullable=False)
    by_id = db.Column(db.Integer)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Std_name = db.Column(db.String(100),nullable=False)
    comment = db.Column(db.String(1000))
    present = db.Column(db.String(100))
    by = db.Column(db.String(100),nullable=False)
    std_id = db.Column(db.Integer,nullable=False)
    by_id = db.Column(db.Integer)

class Fail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    std_name = db.Column(db.String(100),nullable=False)
    std_id = db.Column(db.Integer,nullable=False)
    name = db.Column(db.String(1000),nullable=False)
    value = db.Column(db.String(1000),nullable=False)

class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200),nullable=False)
    cls = db.Column(db.Integer)
    cau = db.Column(db.Integer,nullable=False)
    teacher_id = db.Column(db.Integer,nullable=False)
    present = db.Column(db.String(1000),nullable=False)

class Score(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    std_id = db.Column(db.Integer,nullable=False)
    q_id = db.Column(db.Integer,nullable=False)
    score = db.Column(db.Integer,nullable=False)


class Questions(db.Model):
    q_id = db.Column(db.Integer, primary_key=True)
    q_no = db.Column(db.Integer,unique=True)
    ques = db.Column(db.String(350), unique=True)
    a = db.Column(db.String(100))
    b = db.Column(db.String(100))
    c = db.Column(db.String(100))
    d = db.Column(db.String(100))
    ans = db.Column(db.String(100))

    def __repr__(self):
        return '<Question: {}>'.format(self.ques)

@login_manager.user_loader
def load_user(user_id):
    return Teacher.query.get(int(user_id))

class st_comment(FlaskForm):
    comment = TextAreaField('Nhận xét')
    present = FloatField('Thưởng Teen')
    priv = PasswordField("Private key")

class homework(FlaskForm):
    name = TextAreaField("Bài tập")
    mark = FloatField("Điểm")
    present = FloatField("Thưởng Teen")

class fail_add(FlaskForm):
    name = TextAreaField("Lỗi")
    value = FloatField("Mức phạt")

class fail_delete(FlaskForm):
    id = IntegerField("Xóa lỗi")

class change_mail(FlaskForm):
    mail = EmailField("Đổi địa chỉ mail")

class change_password(FlaskForm):
    password = PasswordField("Đổi mật khẩu")

class change_address(FlaskForm):
    address = StringField("Đổi địa cỉ ví")

class QuestionForm(FlaskForm):
    options = RadioField('Options: ', default=1)
    submit = SubmitField('Next')

class Quescreate(FlaskForm):
    name = StringField('Nội dung câu hỏi')
    a = StringField('Đáp án A')
    b = StringField('Đáp án B')
    c = StringField('Đáp án C')
    d = StringField('Đáp án D')
    ans = StringField('Đáp án đúng')


@app.route('/register/teacher',methods=['GET','POST'])
def teacher_register():
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        nick = request.form.get('nick')
        password = request.form.get('password')

        user = Teacher.query.filter_by(email=email).first()  # Kiểm tra xem người dùng có tồn tại ko

        if user:
            flash('Tài khoản đã tồn tại')  # trả về kết quả và reload khi có tồn tại ng dùng
            return redirect(url_for('teacher_register'))
        else:
            priv = secrets.token_hex(32)  # tạo private key
            private_key = "0x" + priv  # hoàn thiện private key
            print("SAVE BUT DO NOT SHARE THIS:", private_key)
            acct = Account.from_key(private_key)  # tạo ví
            print("Address:", acct.address)
            hashpass = generate_password_hash(password, method='sha256')
            new_user = Teacher(email=email, address=acct.address, password=hashpass,name=name,account_type=1,cls_id=0,nick=nick,private_key=private_key)  # tạo user mới
            db.session.add(new_user)  # tạo user 2
            db.session.commit()  # commit user
            login_user(new_user)  # đăng nhập tài khoản
            return redirect(url_for('private_key',priv=private_key))
    return render_template('teacher_signup.html')

@login_required
@app.route('/private/key/<priv>')
def private_key(priv):
    return render_template("private_key.html",priv=priv) # biến trên front-end = biến trên back-end


@login_required
@app.route('/teacher/dashboard')
def teacher_dashboard():
    if current_user.account_type == 1:
        teen = float(web3.toWei(contract.functions.balanceOf(current_user.address).call(),'ether'))
        eth = float(web3.toWei(web3.eth.getBalance(current_user.address), 'ether'))
    else:
        return redirect(url_for('student_dashboard'))
    return render_template("teacher_dashboard.html",teen_balanced=teen,eth_balenced=eth)

@login_required
@app.route('/class/<Cls_id>')
def Class_check(Cls_id):
    if current_user.account_type == 1:
        Std = Teacher.query.filter_by(cls_id=Cls_id,account_type=2).all()
    else:
        return redirect(url_for('student_dashboard'))
    return render_template("class.html",users=Std)

@login_required
@app.route('/teacher/show/class/')
def show_cls():
    if current_user.account_type == 1:
        cls = Class.query.all()
    else:
        return redirect(url_for('student_dashboard'))
    return render_template('class_check.html',posts=cls)

@login_required
@app.route('/teacher/add/class',methods=['GET','POST'])
def create_class():
    if current_user.account_type == 1:
        if request.method == 'POST':
            grade = request.form.get('grade')
            name = request.form.get('name')
            new_cls = Class(grade=grade,name=name)
            db.session.add(new_cls)
            db.session.commit()
    else:
        return redirect(url_for('student_dashboard'))
    return render_template('add_class.html')

@login_required
@app.route('/student/comment/',methods=["GET","POST"])
def student_comment():
    if request.method == 'POST':
        comment = request.form.get('comment')
        nick = request.form.get('nick')
        present = request.form.get('present')
        private_key = request.form.get("private")
        std = Teacher.query.filter_by(nick=nick).first()
        test = os.environ["hello"] = private_key  # cho vào biến môi trường để có toàn bộ dữ liệu của private key
        test2 = os.getenv("hello")  # lấy dữ liệu từ biến môi trường
        new_cmt = Comment(Std_name=std.name, comment=comment, present=str(present), by=current_user.name, std_id=std.id, by_id=current_user.id)
        db.session.add(new_cmt)
        db.session.commit()
        if int(present) > 0:
            tran = contract.functions.transfer(std.address, web3.toWei(present, 'ether')).buildTransaction(
                    {'chainId': 11155111, 'gasPrice': web3.toWei('15', 'gwei'), 'gas': 210000,
                    'nonce': web3.eth.get_transaction_count(current_user.address), 'value': 0})  # tạo giao dịch
            signed_txn = web3.eth.account.sign_transaction(tran, test2)  # xác nhận giao dịch
            web3.eth.send_raw_transaction(signed_txn.rawTransaction)  # giao dịch
            time.sleep(23)
            return redirect(url_for('teacher_dashboard'))
        else:
            return redirect(url_for('teacher_dashboard'))
    return render_template('cmt.html')

@login_required
@app.route('/question/<int:q_id>/<int:id>', methods=['GET', 'POST'])
def question(id,q_id):
    form = QuestionForm()
    q = Questions.query.filter_by(q_no=id,q_id=q_id).first()
    if not q:
        return redirect(url_for('score',id=q.q_id,right=int(os.getenv(str(q.q_id)+str(current_user.id)))))
    if request.method == 'POST':
        option = request.form['options']
        if option == q.ans:
            os.environ[str(q.q_id)+str(current_user.id)] += 1
        return redirect(url_for('question',q_id=q_id, id=(id+1)))
    form.options.choices = [(q.a, q.a), (q.b, q.b), (q.c, q.c), (q.d, q.d)]
    return render_template('question.html', form=form, q=q, title='Question {}'.format(id))

@login_required
@app.route('/score/<int:id>/<int:right>')
def score(id,right):
    q = Quiz.query.filer_by(id=id).first()
    teacher = Teacher.query.filter_by(id=q.teacher_id).first()
    final = Score(std_id=current_user.id,q_id=q.id,score=right/q.cau*10)
    db.session.add(final)
    db.session.commit()
    if right/q.present*10 > 0:
        os.environ[str(q.id)+str(teacher.id)] = teacher.private_key
        test = os.getenv(str(q.id)+str(teacher.id))
        tran = contract.functions.transfer_form(teacher.address,current_user.address, web3.toWei(right/q.present*10, 'ether')).buildTransaction(
            {'chainId': 11155111, 'gasPrice': web3.toWei('15', 'gwei'), 'gas': 210000,
             'nonce': web3.eth.get_transaction_count(teacher.address), 'value': 0})  # tạo giao dịch
        signed_txn = web3.eth.account.sign_transaction(tran, test)  # xác nhận giao dịch
        web3.eth.send_raw_transaction(signed_txn.rawTransaction)  # giao dịch
        time.sleep(23)
    return render_template('score.html', score=right/q.cau*10)

@login_required
@app.route('/create/quiz',methods=['GET','POST'])
def create_quiz():
    if request.methos == 'POST':
        name = request.form.get('name')
        cau = request.form.get('cau')
        present = request.form.get('present')
        cls = request.form.get('cls')
        q = Quiz.query.filer_by(name=name).first()
        new_quiz = Quiz(name=name,cls=cls,cau=cau,present=present)
        db.session.add(new_quiz)
        db.session.commit()
        return redirect(url_for('create_question',id=cau,q_id=q.id))
    return render_template('quiz.html')

@login_required
@app.route('/create/question/<int:id>/<int:qi_d>',methods=['GET','POST'])
def create_question(id,q_id):
    form = Quescreate()
    if id != 0:
        if form.validate_on_submit():
            new_quest = Questions(name=form.name.data,q_id=q_id,q_no=id,ans=form.ans.data,a=form.a.data,b=form.b.data,c=form.c.data,d=form.d.data)
            db.session.add(new_quest)
            db.session.commit()
            return redirect(url_for('create_question',id=id-1,q_id=q_id))
    else:
        return redirect(url_for('teacher_dashboard'))
    return render_template('ques_create.html',form=form)

@login_required
@app.route('/class/homework/',methods = ['GET','POST'])
def class_homework():
    if request.method == 'POST':
        css = request.form.get('class')
        name = request.form.get('name')
        mark = request.form.get('mark')
        present = request.form.get('present')
        cls = Class.query.filter_by(id=int(css)).first()
        new_hwk = Homework(Class=cls.name, name=name, mark=mark, present=str(present), cls_id=cls.id,by=current_user.name,by_id=current_user.id)
        db.session.add(new_hwk)
        db.session.commit()
    return render_template('hw.html')

@login_required
@app.route('/student/fail/',methods=['GET','POST'])
def student_fail_add():
    if request.method == 'POST':
        nick = request.form.get('nick')
        name = request.form.get('name')
        value = request.form.get('value')
        std = Teacher.query.filter_by(nick=nick).first()
        fail = Fail(std_name=std.name,std_id=std.id,name=name,value=value)
        db.session.add(fail)
        db.session.commit()
        return redirect(url_for("teacher_dashboard"))
    return render_template("fail.html")

@login_required
@app.route('/student/fail/id/<std_id>')
def fail_id(std_id):
    if current_user.account_type == 1:
        fail = Fail.query.filter_by(std_id=std_id).all()
        final_fail = fail[-1].id
    else:
        return redirect(url_for('student_dashboard'))
    return render_template("fail_id.html",id=final_fail)

@login_required
@app.route('/student/fail/delete',methods=['GET','POST'])
def fail_delete():
    if request.method == 'POST':
        nick = request.form.get("nick")
        fail = Fail.query.filter_by(nick=nick).first()
        fail2 = Teacher.query.filter_by(std_id=fail.std_id).first()
        fail.delete()
        db.session.commit()
        return redirect('class_check',id=fail2.cls_id)
    return render_template('delete_fail.html')

@app.route('/teacher/login', methods=['GET','POST'])
def teacher_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = Teacher.query.filter_by(email=email).first() # Kiểm tra xem người dùng có tồn tại ko

        if not user or not check_password_hash(user.password, password):# check tài khoản và pass có đúng ko
            flash('Please check your login details and try again.') # trả về kết quả và reload khi có tồn tại ng dùng
            return redirect(url_for('teacher_login'))
        else:
            login_user(user)# đăng nhập tài khoản
            return redirect(url_for('teacher_dashboard'))

    return render_template('login.html')

@app.route('/student/login', methods=['GET','POST'])
def student_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = Teacher.query.filter_by(email=email).first() # Kiểm tra xem người dùng có tồn tại ko

        if not user or not check_password_hash(user.password, password):# check tài khoản và pass có đúng ko
            flash('Please check your login details and try again.') # trả về kết quả và reload khi có tồn tại ng dùng
            return redirect(url_for('student_login'))
        else:
            login_user(user)# đăng nhập tài khoản
            return redirect(url_for('student_dashboard'))

    return render_template('stu_login.html')

@login_required
@app.route('/add/student',methods=['GET','POST'])
def add_student():
    if current_user.account_type == 1:
        if request.method == 'POST':
            name = request.form.get('name')
            email = request.form.get('email')
            address = request.form.get('address')
            password = request.form.get('password')
            cls_id = request.form.get('Cls_id')
            nick = request.form.get('nick')
            hashpass = generate_password_hash(password, method='sha256')
            new_student = Teacher(name=name, email=email, address=address, password=hashpass, cls_id=cls_id, nick=nick, account_type=2)
            db.session.add(new_student)
            db.session.commit()
    else:
        return redirect(url_for('student_dashboard'))
    return render_template('add_student.html')

@login_required
@app.route('/delete/student',methods=['GET','POST'])
def delete_student():
    if request.method == 'POST':
        nick = request.form.get('nick')
        Teacher.query.filter_by(nick=nick).delete()
        db.session.commit()
        return redirect(url_for('teacher_dashboard'))
    return render_template('delete.html')


@login_required
@app.route('/change/mail/teacher/',methods=['GET','POST'])
def change_mail():
    if request.method == 'POST':
        email = request.form.get('email')
        current_user.email = email
        db.session.commit()
    return render_template("change_mail.html")


@login_required
@app.route('/change/password/teacher/',methods=['GET','POST'])
def change_pass():
    if request.method == 'POST':
        password = request.form.get('password')
        hashpass = generate_password_hash(password, method='sha256')
        current_user.password = hashpass
        db.session.commit()
    return render_template("change_password.html")

@login_required
@app.route('/change/address/teacher/',methods=['GET','POST'])
def teacher_change_address():
    if request.method == 'POST':
        address = request.form.get('address')
        current_user.address = address
        db.session.commit()
    return render_template("change_address.html")


@login_required
@app.route('/student/homework/check')
def student_homework_check():
    if current_user.account_type == 2:
        std = current_user.cls_id
        hw = Homework.query.filter_by(cls_id=std).all()
        hwk = hw[::-1]
    else:
        return redirect(url_for('teacher_dashboard'))
    return render_template("student_homework.html",posts=hwk)

@login_required
@app.route('/teacher/homework/check')
def teacher_homework_check():
    if current_user.account_type == 1:
        std = current_user.id
        hw = Homework.query.filter_by(by_id=std).all()
        hwk = hw[::-1]
    else:
        return redirect(url_for('student_dashboard'))
    return render_template("teacher_homework.html",posts=hwk)

@login_required
@app.route('/student/comment/check')
def student_comment_check():
    std = current_user.id
    hw = Comment.query.filter_by(std_id=std).all()
    hwk = hw[::-1]
    return render_template("student_comment.html",posts=hwk)

@login_required
@app.route('/teacher/comment/check')
def teacher_comment_check():
    if current_user.account_type == 1:
        std = current_user.id
        hw = Comment.query.filter_by(by_id=std).all()
        hwk = hw[::-1]
    else:
        return redirect(url_for('student_dashboard'))
    return render_template("teacher_comment.html",posts=hwk)

@login_required
@app.route('/student/fail/check')
def student_fail_check():
    if current_user.account_type == 2:
        std = current_user.id
        hw = Fail.query.filter_by(std_id=std).all()
        hwk = hw[::-1]
    else:
        return redirect(url_for('teacher_dashboard'))
    return render_template("student_fail.html",posts=hwk)

@login_required
@app.route('/teacher/fail/check')
def teacher_fail_check():
    if current_user.account_type == 1:
        hw = Fail.query.all()
        hwk = hw[::-1]
    else:
        return redirect(url_for('student_dashboard'))
    return render_template("teacher_fail.html",posts=hwk)

@login_required
@app.route('/student/dashboard')
def student_dashboard():
    if current_user.account_type == 2:
        teen = float(web3.toWei(contract.functions.balanceOf(current_user.address).call(), 'ether'))
        eth = float(web3.toWei(web3.eth.getBalance(current_user.address), 'ether'))
    else:
        return redirect(url_for('teacher_dashboard'))
    return render_template("student_dashboard.html", teen_balanced=teen, eth_balenced=eth,)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

'''
with app.app_context():
    db.create_all()

'''
if __name__ == '__main__':
    app.run(debug=True)




