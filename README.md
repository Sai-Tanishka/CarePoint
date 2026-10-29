# ✚ CarePoint – Hospital Appointment Management System

**CarePoint** is a full-stack Hospital Appointment Management System designed for healthcare facilities, connecting patients, medical specialists, and administrators in a unified, modern web application.

---

## 🌟 Key Features

### 🧑 Patient Portal
- **Secure Registration & Login:** Patients register with their Full Name, Email, Mobile Number, and Password.
- **Department & Specialty Booking:** Patients book appointments by medical department (Cardiology, Pediatrics, Orthopedics, General Medicine, Dermatology, Neurology, ENT, etc.).
- **Smart Workload Allocation:** The system automatically checks real-time doctor availability and allocates the appointment to the **least-busy doctor** in that specialty.
- **Continuity of Care:** When an existing patient books in a department they previously visited, the system automatically retrieves past records and **re-allots their previous doctor**.
- **Prominent Doctor Allotment Card:** Immediately displays the assigned doctor, department, doctor's direct contact number, appointment date/time, and fee.
- **My Appointments:** Real-time personal appointment history with cancellation controls.

### 🩺 Doctor Portal
- **Doctor Registration & Login:** Doctors register with Name, Specialty, Email, Mobile Number, and Password.
- **Dynamic Monthly Timetable (Calendar):** An interactive monthly calendar highlighting days with patient appointments and showing patient count badges.
- **Single-Click Day Filtering:** Clicking any date on the calendar immediately displays that day's scheduled patient roster with full contact details.
- **Schedule Management:** Flexible date filtering with no arbitrary day-of-week restrictions.

### 📋 Admin Dashboard
- **Real-Time KPI Metric Cards:** Live tracking of Total Bookings, Confirmed Appointments, Attended Consultations, Revenue Received (₹), Total Doctors, and Total Patients.
- **Patient Attendance Tracking:** Mark patients as `Attended` or `Absent`.
- **Consultation Fee Collection:** Click **"Receive ₹500 Fee"** to collect payment, mark the appointment as `Completed`, and update hospital revenue in real time.
- **Doctor Reassignment:** Admin can reassign any booking to another doctor within the **same medical specialization** with real-time slot conflict detection.
- **Staff Provisioning:** Admin can register new doctors directly into the hospital directory.

### 🔒 Security & UX
- **Dedicated Full-Screen Dashboards:** When a user logs in, the role selection sidebar automatically disappears and the dashboard takes over the full screen.
- **Cryptographic Password Hashing:** Uses Node.js native `crypto.scryptSync` with unique salt generation.
- **SQL Injection Prevention:** 100% parameterized SQL queries via `mysql2/promise`.

---

## 🛠️ Technology Stack

- **Backend:** Node.js (v18+), Express.js 5
- **Database:** MySQL (InnoDB engine, UTF-8)
- **Database Driver:** `mysql2/promise` with connection pooling & date string normalization
- **Frontend:** HTML5, CSS3 (CSS Grid, Flexbox, Custom Properties), Vanilla JavaScript (ES6+)
- **Security & Config:** `dotenv`, Node.js native `crypto` module, `cors`

---

## 🚀 Getting Started

### Prerequisites
1. **Node.js** (v18.0.0 or higher)
2. **MySQL Server** (v8.0 or higher)

### 1. Clone the Repository
```bash
git clone https://github.com/Sai-Tanishka/CarePoint.git
cd CarePoint
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Setup the MySQL Database
Log in to your MySQL server and run the schema file:
```bash
mysql -u root -p < schema.sql
```
*Or execute the SQL commands found in [`schema.sql`](./schema.sql) in MySQL Workbench or phpMyAdmin.*

### 4. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Update `.env` with your local MySQL credentials:
```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_NAME=carepoint
PORT=3000
```

### 5. Start the Application
```bash
npm start
```
The server will start at:
```
http://localhost:3000
```

---

## 🔑 Demo Credentials

| Role | Email | Password | Features |
| :--- | :--- | :--- | :--- |
| **🧑 Patient** | `john@example.com` | `patient123` | Book by department, view personal appointments |
| **🩺 Doctor** | `sarah.jenkins@carepoint.com` | `doctor123` | Interactive monthly timetable, daily patient schedules |
| **📋 Admin** | `admin@carepoint.com` | `admin123` | KPI stats, attendance, fee collection, doctor reassignment |

---

## 📄 License
This project is licensed under the ISC License.
