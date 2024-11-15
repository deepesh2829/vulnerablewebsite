from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hospital.db'
db = SQLAlchemy(app)
#models for Users, Doctors, Patients, Appointments, Rooms, and Medications

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'doctor', 'patient', or 'manager'

class Doctor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    specialization = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    phone = db.Column(db.String(50), nullable=False)

class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    sex = db.Column(db.String(10), nullable=False)
    medical_history = db.Column(db.Text, nullable=True)

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'))
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctor.id'))
    appointment_time = db.Column(db.DateTime, nullable=False)

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    availability = db.Column(db.Boolean, default=True)

class Medication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

with app.app_context():
    db.create_all()

#Landing Page and Login(Routing stuff)

@app.route('/')
def landing_page():
    return render_template('landing.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get the form data
        username = request.form['username']
        password = request.form['password']

        # Find the user in the database
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):  # Check password hash
            # Successful login, store user info in session
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role

            flash('Login successful!', 'success')

            # Redirect based on user role
            if user.role == 'doctor':
                return redirect(url_for('doctor_home'))
            elif user.role == 'patient':
                return redirect(url_for('patient_home'))
            elif user.role == 'manager':
                return redirect(url_for('manager_home'))

            # Default redirect if no specific role match
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists!', 'error')
            return redirect(url_for('signup'))

        # Hash the password for storage
        hashed_password = generate_password_hash(password)

        # Create new user and add to the database
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))  # Or redirect to a login page or homepage

    return render_template('signup.html')

# Route to handle logout
@app.route('/logout')
def logout():
    # Clear session data
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)

    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# Doc homepage
@app.route('/doctor')
def doctor_home():
    # Check if the user is logged in and is a doctor
    if 'user_id' not in session or session['role'] != 'doctor':
        flash("You must be logged in as a doctor to view this page.")
        return redirect(url_for('login'))  # Redirect to login if not logged in

    # Get the logged-in doctor's ID
    doctor_id = session['user_id']

    # Query for the doctor's details (including username)
    doctor_user = User.query.get(doctor_id)

    # If no user found with the given ID (which shouldn't happen if logged in correctly)
    if not doctor_user:
        flash("Doctor not found.")
        return redirect(url_for('login'))  # Redirect to login if doctor not found

    # Query for appointments for the logged-in doctor
    appointments = Appointment.query.filter_by(doctor_id=doctor_id).all()

    # Prepare a list of appointment details, including patient objects
    appointment_details = []
    for appointment in appointments:
        patient = Patient.query.get(appointment.patient_id)
        appointment_details.append({
            'patient': patient,  # Pass the full patient object
            'appointment_time': appointment.appointment_time,
            'appointment_id': appointment.id
        })

    # Render the doctor home page and pass the username, doctor, and appointments data
    return render_template('doctor_home.html', doctor_user=doctor_user, appointments=appointment_details)

#Patient’s Homepage

@app.route('/patient')
def patient_home():
    if 'role' in session and session['role'] == 'patient':
        patient = Patient.query.filter_by(name=session['username']).first()
        appointments = Appointment.query.filter_by(patient_id=patient.id).all()
        return render_template('patient_home.html', patient=patient, appointments=appointments)
    else:
        return redirect(url_for('login'))

#Manager’s Homepage

@app.route('/manager')
def manager_home():
    if 'role' in session and session['role'] == 'manager':
        rooms = Room.query.all()
        doctors = Doctor.query.all()
        patients = Patient.query.all()
        medications = Medication.query.all()
        return render_template('manager_home.html', rooms=rooms, doctors=doctors, patients=patients, medications=medications)
    else:
        return redirect(url_for('login'))



#room availability toggle

@app.route('/toggle_room/<int:room_id>', methods=['POST'])
def toggle_room_availability(room_id):
    room = Room.query.get_or_404(room_id)
    room.availability = not room.availability
    db.session.commit()
    flash(f'Room {room.id} availability updated!', 'success')
    return redirect(url_for('manager_home'))

#to edit and update doctor details

@app.route('/edit_doctor/<int:doctor_id>', methods=['GET', 'POST'])
def edit_doctor(doctor_id):
    doctor = Doctor.query.get_or_404(doctor_id)
    if request.method == 'POST':
        doctor.name = request.form['name']
        doctor.specialization = request.form['specialization']
        doctor.age = request.form['age']
        doctor.phone = request.form['phone']
        db.session.commit()
        flash(f'Doctor {doctor.name} details updated!', 'success')
        return redirect(url_for('manager_home'))
    return render_template('edit_doctor.html', doctor=doctor)

@app.route('/delete_doctor/<int:doctor_id>')
def delete_doctor(doctor_id):
    doctor = Doctor.query.get_or_404(doctor_id)
    db.session.delete(doctor)
    db.session.commit()
    flash(f'Doctor {doctor.name} deleted!', 'success')
    return redirect(url_for('manager_home'))


#to edit and update patient details

@app.route('/edit_patient/<int:patient_id>', methods=['GET', 'POST'])
def edit_patient(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    if request.method == 'POST':
        patient.name = request.form['name']
        patient.age = request.form['age']
        patient.sex = request.form['sex']
        patient.medical_history = request.form['medical_history']
        db.session.commit()
        flash(f'Patient {patient.name} details updated!', 'success')
        return redirect(url_for('manager_home'))
    return render_template('edit_patient.html', patient=patient)

@app.route('/delete_patient/<int:patient_id>')
def delete_patient(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    db.session.delete(patient)
    db.session.commit()
    flash(f'Patient {patient.name} deleted!', 'success')
    return redirect(url_for('manager_home'))
#medication toggle

@app.route('/toggle_medication/<int:med_id>', methods=['POST'])
def toggle_medication(med_id):
    medication = Medication.query.get_or_404(med_id)
    # Assuming you want to toggle the availability based on quantity
    if medication.quantity > 0:
        medication.quantity = 0  # "Out of stock" logic
    else:
        medication.quantity = 10  # "In stock" logic (you can adjust as per your needs)
    db.session.commit()
    flash(f'Medication {medication.name} availability updated!', 'success')
    return redirect(url_for('manager_home'))


if __name__ == '__main__':
    app.run(debug=True)
