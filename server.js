const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const pool = require("./db");
require("dotenv").config();

const app = express();
const PORT = Number(process.env.PORT || 3000);

app.use(cors());
app.use(express.json());
app.use(express.static("public"));

const formatDocName = (name) => String(name || "").startsWith("Dr.") ? name : `Dr. ${name}`;

// Helper: Password Hashing using Node.js crypto (scrypt)
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored || !stored.includes(":")) return false;
  const [salt, key] = stored.split(":");
  const keyBuffer = Buffer.from(key, "hex");
  const derived = crypto.scryptSync(password, salt, 64);
  return crypto.timingSafeEqual(keyBuffer, derived);
}

// -------------------------------------------------------------
// System Health
// -------------------------------------------------------------
app.get("/api/health", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT 1 AS connected");
    res.json({
      status: "ok",
      database: rows[0].connected === 1,
    });
  } catch (error) {
    console.error("Database health check failed:", error.message);
    res.status(500).json({ error: "Database connection failed" });
  }
});

// -------------------------------------------------------------
// Authentication Endpoints (Sign In & Registration)
// -------------------------------------------------------------

// Sign In for Patient, Doctor, Admin
app.post("/api/auth/login", async (req, res) => {
  const { role, email, password } = req.body;

  if (!role || !email || !password) {
    return res.status(400).json({ error: "Role, email, and password are required" });
  }

  const cleanEmail = String(email).trim().toLowerCase();
  const cleanPass = String(password);

  try {
    if (role === "patient") {
      const [rows] = await pool.execute(
        "SELECT patient_id, name, email, phone, password FROM patients WHERE LOWER(email) = ?",
        [cleanEmail]
      );

      if (rows.length === 0 || !verifyPassword(cleanPass, rows[0].password)) {
        return res.status(401).json({ error: "Invalid email or password" });
      }

      return res.json({
        user: {
          id: rows[0].patient_id,
          name: rows[0].name,
          email: rows[0].email,
          phone: rows[0].phone || null,
          role: "patient",
        },
      });
    }

    if (role === "doctor") {
      const [rows] = await pool.execute(
        "SELECT doctor_id, name, specialty, email, phone, password FROM doctors WHERE LOWER(email) = ?",
        [cleanEmail]
      );

      if (rows.length === 0 || !verifyPassword(cleanPass, rows[0].password)) {
        return res.status(401).json({ error: "Invalid email or password" });
      }

      return res.json({
        user: {
          id: rows[0].doctor_id,
          name: rows[0].name,
          specialty: rows[0].specialty,
          email: rows[0].email,
          phone: rows[0].phone || null,
          role: "doctor",
        },
      });
    }

    if (role === "admin") {
      const [rows] = await pool.execute(
        "SELECT admin_id, name, email, password FROM admins WHERE LOWER(email) = ?",
        [cleanEmail]
      );

      if (rows.length === 0 || !verifyPassword(cleanPass, rows[0].password)) {
        return res.status(401).json({ error: "Invalid email or password" });
      }

      return res.json({
        user: {
          id: rows[0].admin_id,
          name: rows[0].name,
          email: rows[0].email,
          role: "admin",
        },
      });
    }

    return res.status(400).json({ error: "Invalid role specified" });
  } catch (error) {
    console.error("Login failed:", error.message);
    res.status(500).json({ error: "Authentication failed. Please try again." });
  }
});

// Register for Patient, Doctor, Admin (with Mobile Number)
app.post("/api/auth/register", async (req, res) => {
  const { role, name, email, phone, password, specialty } = req.body;

  if (!role || !name || !email || !password) {
    return res.status(400).json({ error: "Name, email, and password are required" });
  }

  const cleanName = String(name).trim();
  const cleanEmail = String(email).trim().toLowerCase();
  const cleanPhone = phone ? String(phone).trim() : null;
  const cleanPass = String(password);

  if (cleanName.length < 2) {
    return res.status(400).json({ error: "Name must be at least 2 characters" });
  }
  if (!cleanEmail.includes("@") || !cleanEmail.includes(".")) {
    return res.status(400).json({ error: "Please provide a valid email address" });
  }
  if (cleanPass.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  }

  const hashedPassword = hashPassword(cleanPass);

  try {
    if (role === "patient") {
      const [existing] = await pool.execute(
        "SELECT patient_id FROM patients WHERE LOWER(email) = ?",
        [cleanEmail]
      );
      if (existing.length > 0) {
        return res.status(409).json({ error: "An account with this email already exists. Please sign in." });
      }

      const [result] = await pool.execute(
        "INSERT INTO patients (name, email, phone, password) VALUES (?, ?, ?, ?)",
        [cleanName, cleanEmail, cleanPhone, hashedPassword]
      );

      return res.status(201).json({
        user: {
          id: result.insertId,
          name: cleanName,
          email: cleanEmail,
          phone: cleanPhone,
          role: "patient",
        },
      });
    }

    if (role === "doctor") {
      const cleanSpecialty = String(specialty || "").trim();
      if (!cleanSpecialty) {
        return res.status(400).json({ error: "Medical specialty is required for doctor registration" });
      }

      const [existing] = await pool.execute(
        "SELECT doctor_id FROM doctors WHERE LOWER(email) = ?",
        [cleanEmail]
      );
      if (existing.length > 0) {
        return res.status(409).json({ error: "A doctor account with this email already exists. Please sign in." });
      }

      const [result] = await pool.execute(
        "INSERT INTO doctors (name, specialty, email, phone, password) VALUES (?, ?, ?, ?, ?)",
        [cleanName, cleanSpecialty, cleanEmail, cleanPhone, hashedPassword]
      );

      return res.status(201).json({
        user: {
          id: result.insertId,
          name: cleanName,
          specialty: cleanSpecialty,
          email: cleanEmail,
          phone: cleanPhone,
          role: "doctor",
        },
      });
    }

    if (role === "admin") {
      const [existing] = await pool.execute(
        "SELECT admin_id FROM admins WHERE LOWER(email) = ?",
        [cleanEmail]
      );
      if (existing.length > 0) {
        return res.status(409).json({ error: "An admin account with this email already exists. Please sign in." });
      }

      const [result] = await pool.execute(
        "INSERT INTO admins (name, email, password) VALUES (?, ?, ?)",
        [cleanName, cleanEmail, hashedPassword]
      );

      return res.status(201).json({
        user: {
          id: result.insertId,
          name: cleanName,
          email: cleanEmail,
          role: "admin",
        },
      });
    }

    return res.status(400).json({ error: "Invalid role specified" });
  } catch (error) {
    console.error("Registration failed:", error.message);
    res.status(500).json({ error: "Registration failed. Please try again." });
  }
});

// -------------------------------------------------------------
// Specialties & Doctor Listings
// -------------------------------------------------------------

// Get all distinct available specialties
app.get("/api/specialties", async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT DISTINCT specialty
      FROM doctors
      WHERE specialty IS NOT NULL AND TRIM(specialty) != ''
      ORDER BY specialty ASC
    `);
    res.json(rows.map((r) => r.specialty));
  } catch (error) {
    console.error("Get specialties failed:", error.message);
    res.status(500).json({ error: "Could not load specialties" });
  }
});

// Get all doctors (including phone)
app.get("/api/doctors", async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT doctor_id, name, specialty, email, phone
      FROM doctors
      ORDER BY name ASC
    `);
    res.json(rows);
  } catch (error) {
    console.error("Get doctors failed:", error.message);
    res.status(500).json({ error: "Could not load doctors" });
  }
});

// Monthly Timetable Summary: Counts patients per day for doctor
app.get("/api/doctors/:id/monthly-summary", async (req, res) => {
  const doctorId = Number(req.params.id);
  const { year, month } = req.query;

  if (!Number.isInteger(doctorId) || doctorId < 1 || !year || !month) {
    return res.status(400).json({ error: "Doctor ID, year, and month are required" });
  }

  const padMonth = String(month).padStart(2, "0");
  const startDate = `${year}-${padMonth}-01`;
  const lastDay = new Date(Number(year), Number(month), 0).getDate();
  const endDate = `${year}-${padMonth}-${String(lastDay).padStart(2, "0")}`;

  try {
    const [rows] = await pool.execute(
      `SELECT appointment_date, COUNT(*) AS count
       FROM appointments
       WHERE doctor_id = ?
         AND appointment_date BETWEEN ? AND ?
         AND status != 'Cancelled'
       GROUP BY appointment_date`,
      [doctorId, startDate, endDate]
    );

    res.json(rows);
  } catch (error) {
    console.error("Monthly summary failed:", error.message);
    res.status(500).json({ error: "Could not load monthly timetable" });
  }
});

// Get a doctor's appointments
app.get("/api/doctors/:id/appointments", async (req, res) => {
  const doctorId = Number(req.params.id);
  const { date, start, end } = req.query;

  if (!Number.isInteger(doctorId) || doctorId < 1) {
    return res.status(400).json({ error: "Valid doctor ID is required" });
  }

  try {
    let query = `
      SELECT
        a.appointment_id,
        a.patient_id,
        p.name AS patient,
        p.email AS patient_email,
        p.phone AS patient_phone,
        a.appointment_date,
        a.appointment_time,
        a.reason,
        a.status,
        a.attendance,
        a.payment_status,
        a.fee
      FROM appointments AS a
      INNER JOIN patients AS p ON p.patient_id = a.patient_id
      WHERE a.doctor_id = ?
    `;
    const params = [doctorId];

    if (date && /^\d{4}-\d{2}-\d{2}$/.test(date)) {
      query += " AND a.appointment_date = ?";
      params.push(date);
    } else if (start && end && /^\d{4}-\d{2}-\d{2}$/.test(start) && /^\d{4}-\d{2}-\d{2}$/.test(end)) {
      query += " AND a.appointment_date BETWEEN ? AND ?";
      params.push(start, end);
    }

    query += " ORDER BY a.appointment_date ASC, a.appointment_time ASC";

    const [rows] = await pool.execute(query, params);
    res.json(rows);
  } catch (error) {
    console.error("Get doctor appointments failed:", error.message);
    res.status(500).json({ error: "Could not load doctor appointments" });
  }
});

// -------------------------------------------------------------
// Patient Specific Endpoints
// -------------------------------------------------------------

// Get appointments for a specific logged-in patient (includes doctor_phone)
app.get("/api/patients/:id/appointments", async (req, res) => {
  const patientId = Number(req.params.id);

  if (!Number.isInteger(patientId) || patientId < 1) {
    return res.status(400).json({ error: "Valid patient ID is required" });
  }

  try {
    const [rows] = await pool.execute(
      `SELECT
         a.appointment_id,
         a.patient_id,
         a.doctor_id,
         p.name AS patient,
         d.name AS doctor,
         d.specialty,
         d.phone AS doctor_phone,
         a.appointment_date,
         a.appointment_time,
         a.reason,
         a.status,
         a.attendance,
         a.payment_status,
         a.fee
       FROM appointments AS a
       INNER JOIN patients AS p ON p.patient_id = a.patient_id
       INNER JOIN doctors AS d ON d.doctor_id = a.doctor_id
       WHERE a.patient_id = ?
       ORDER BY a.appointment_date DESC, a.appointment_time DESC`,
      [patientId]
    );

    res.json(rows);
  } catch (error) {
    console.error("Get patient appointments failed:", error.message);
    res.status(500).json({ error: "Could not load patient appointments" });
  }
});

// -------------------------------------------------------------
// Intelligent Appointment Booking & Allotment Logic
// -------------------------------------------------------------
app.post("/api/appointments", async (req, res) => {
  const {
    patient_id,
    specialty,
    doctor_id,
    appointment_date,
    appointment_time,
    reason,
  } = req.body;

  const patientId = Number(patient_id);

  if (
    !Number.isInteger(patientId) ||
    patientId < 1 ||
    typeof appointment_date !== "string" ||
    typeof appointment_time !== "string"
  ) {
    return res.status(400).json({
      error: "Please provide valid patient, appointment date and time",
    });
  }

  if (
    !/^\d{4}-\d{2}-\d{2}$/.test(appointment_date) ||
    !/^\d{2}:\d{2}(:\d{2})?$/.test(appointment_time)
  ) {
    return res.status(400).json({ error: "Invalid date or time format" });
  }

  const time =
    appointment_time.length === 5
      ? appointment_time + ":00"
      : appointment_time;

  try {
    // 1. Verify patient exists
    const [patients] = await pool.execute(
      "SELECT patient_id, name, phone FROM patients WHERE patient_id = ?",
      [patientId]
    );
    if (patients.length === 0) {
      return res.status(404).json({ error: "Patient record not found" });
    }

    let chosenDoctorId = null;
    let chosenDoctorName = "";
    let chosenSpecialty = "";
    let allotmentReason = "";

    // If explicit doctor_id provided
    if (doctor_id && Number.isInteger(Number(doctor_id)) && Number(doctor_id) > 0) {
      const docId = Number(doctor_id);
      const [doctors] = await pool.execute(
        "SELECT doctor_id, name, specialty, phone FROM doctors WHERE doctor_id = ?",
        [docId]
      );
      if (doctors.length === 0) {
        return res.status(404).json({ error: "Specified doctor not found" });
      }

      // Check slot availability
      const [conflict] = await pool.execute(
        `SELECT appointment_id FROM appointments
         WHERE doctor_id = ?
           AND appointment_date = ?
           AND appointment_time = ?
           AND status = 'Confirmed'`,
        [docId, appointment_date, time]
      );
      if (conflict.length > 0) {
        return res.status(409).json({
          error: `${formatDocName(doctors[0].name)} is already booked at ${appointment_time} on ${appointment_date}.`,
        });
      }

      chosenDoctorId = docId;
      chosenDoctorName = doctors[0].name;
      chosenSpecialty = doctors[0].specialty;
      allotmentReason = `Directly assigned to ${formatDocName(chosenDoctorName)}`;
    } else {
      // Patient selects only Specialty!
      if (typeof specialty !== "string" || !specialty.trim()) {
        return res.status(400).json({ error: "Please select a department / medical specialty" });
      }
      const reqSpecialty = specialty.trim();

      // Continuity of Care: Check past records for this patient in this specialty
      const [pastConsultations] = await pool.execute(
        `SELECT a.doctor_id, d.name AS doctor_name, d.specialty, d.phone AS doctor_phone
         FROM appointments a
         INNER JOIN doctors d ON d.doctor_id = a.doctor_id
         WHERE a.patient_id = ?
           AND (LOWER(d.specialty) = LOWER(?) OR LOWER(d.specialty) LIKE CONCAT(LOWER(?), '%'))
           AND a.status != 'Cancelled'
         ORDER BY a.appointment_date DESC, a.appointment_time DESC
         LIMIT 1`,
        [patientId, reqSpecialty, reqSpecialty]
      );

      if (pastConsultations.length > 0) {
        const pastDoctorId = pastConsultations[0].doctor_id;
        const pastDoctorName = pastConsultations[0].doctor_name;

        // Check if the previous doctor is available at the needed slot
        const [pastDocBusy] = await pool.execute(
          `SELECT appointment_id FROM appointments
           WHERE doctor_id = ?
             AND appointment_date = ?
             AND appointment_time = ?
             AND status = 'Confirmed'`,
          [pastDoctorId, appointment_date, time]
        );

        if (pastDocBusy.length === 0) {
          chosenDoctorId = pastDoctorId;
          chosenDoctorName = pastDoctorName;
          chosenSpecialty = pastConsultations[0].specialty;
          allotmentReason = `Continuity of Care: Re-allotted to your previous doctor, ${formatDocName(pastDoctorName)}.`;
        } else {
          return res.status(409).json({
            error: `Your regular doctor, ${formatDocName(pastDoctorName)} (${reqSpecialty}), is already booked at ${appointment_time} on ${appointment_date}. Please choose another time slot to consult ${formatDocName(pastDoctorName)}.`,
          });
        }
      } else {
        // Find all available doctors in this specialty and allot to LEAST BUSY
        const [availableDoctors] = await pool.execute(
          `SELECT
             d.doctor_id,
             d.name,
             d.specialty,
             d.phone,
             (
               SELECT COUNT(*) FROM appointments a
               WHERE a.doctor_id = d.doctor_id
                 AND a.appointment_date = ?
                 AND a.status = 'Confirmed'
             ) AS day_workload
           FROM doctors d
           WHERE (LOWER(d.specialty) = LOWER(?) OR LOWER(d.specialty) LIKE CONCAT(LOWER(?), '%'))
             AND d.doctor_id NOT IN (
               SELECT doctor_id FROM appointments
               WHERE appointment_date = ?
                 AND appointment_time = ?
                 AND status = 'Confirmed'
             )
           ORDER BY day_workload ASC, d.doctor_id ASC`,
          [appointment_date, reqSpecialty, reqSpecialty, appointment_date, time]
        );

        if (availableDoctors.length === 0) {
          const [specialtyExists] = await pool.execute(
            "SELECT doctor_id FROM doctors WHERE LOWER(specialty) = LOWER(?) OR LOWER(specialty) LIKE CONCAT(LOWER(?), '%')",
            [reqSpecialty, reqSpecialty]
          );

          if (specialtyExists.length === 0) {
            return res.status(404).json({
              error: `No doctors are currently registered under ${reqSpecialty}.`,
            });
          }

          return res.status(409).json({
            error: `All doctors in ${reqSpecialty} are fully booked at ${appointment_time} on ${appointment_date}. Please select another time or date.`,
          });
        }

        const bestDoctor = availableDoctors[0];
        chosenDoctorId = bestDoctor.doctor_id;
        chosenDoctorName = bestDoctor.name;
        chosenSpecialty = bestDoctor.specialty;
        allotmentReason = `Smart Workload Allocation: Allotted to ${formatDocName(bestDoctor.name)} based on availability and lowest daily workload (${bestDoctor.day_workload} existing appointment(s)).`;
      }
    }

    // Insert appointment
    const [result] = await pool.execute(
      `INSERT INTO appointments
       (patient_id, doctor_id, appointment_date, appointment_time, reason, status, attendance, payment_status, fee)
       VALUES (?, ?, ?, ?, ?, 'Confirmed', 'Pending', 'Unpaid', 500.00)`,
      [
        patientId,
        chosenDoctorId,
        appointment_date,
        time,
        typeof reason === "string" ? reason.trim() || null : null,
      ]
    );

    // Fetch doctor phone
    const [docRow] = await pool.execute("SELECT name, specialty, phone FROM doctors WHERE doctor_id = ?", [chosenDoctorId]);
    const chosenDoctorPhone = docRow.length > 0 && docRow[0].phone ? docRow[0].phone : "Contact Hospital Reception";

    res.status(201).json({
      message: `Appointment booked successfully! Allotted to ${formatDocName(chosenDoctorName)} (${chosenSpecialty}).`,
      appointment_id: result.insertId,
      doctor_id: chosenDoctorId,
      doctor_name: formatDocName(chosenDoctorName),
      doctor_phone: chosenDoctorPhone,
      specialty: chosenSpecialty,
      appointment_date: appointment_date,
      appointment_time: time,
      allotment_note: allotmentReason,
    });
  } catch (error) {
    console.error("Book appointment failed:", error.message);
    res.status(500).json({ error: "Could not book appointment" });
  }
});

// -------------------------------------------------------------
// Admin Appointments Roster & Powers
// -------------------------------------------------------------

// Get all appointments for admin (includes phone numbers)
app.get("/api/appointments", async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT
        a.appointment_id,
        a.patient_id,
        a.doctor_id,
        p.name AS patient,
        p.email AS patient_email,
        p.phone AS patient_phone,
        d.name AS doctor,
        d.specialty,
        d.phone AS doctor_phone,
        a.appointment_date,
        a.appointment_time,
        a.reason,
        a.status,
        a.attendance,
        a.payment_status,
        a.fee
      FROM appointments AS a
      INNER JOIN patients AS p
        ON p.patient_id = a.patient_id
      INNER JOIN doctors AS d
        ON d.doctor_id = a.doctor_id
      ORDER BY a.appointment_date DESC, a.appointment_time DESC
    `);

    res.json(rows);
  } catch (error) {
    console.error("Get appointments failed:", error.message);
    res.status(500).json({ error: "Could not load appointments" });
  }
});

// Get alternative doctors in the SAME specialization for reassignment
app.get("/api/appointments/:id/specialty-doctors", async (req, res) => {
  const appointmentId = Number(req.params.id);

  if (!Number.isInteger(appointmentId) || appointmentId < 1) {
    return res.status(400).json({ error: "Valid appointment ID required" });
  }

  try {
    const [appts] = await pool.execute(
      `SELECT
         a.appointment_id,
         a.doctor_id AS current_doctor_id,
         a.appointment_date,
         a.appointment_time,
         d.name AS current_doctor_name,
         d.specialty
       FROM appointments a
       INNER JOIN doctors d ON d.doctor_id = a.doctor_id
       WHERE a.appointment_id = ?`,
      [appointmentId]
    );

    if (appts.length === 0) {
      return res.status(404).json({ error: "Appointment not found" });
    }

    const appt = appts[0];

    const [sameSpecialtyDocs] = await pool.execute(
      `SELECT doctor_id, name, specialty, phone
       FROM doctors
       WHERE LOWER(specialty) = LOWER(?) OR LOWER(specialty) LIKE CONCAT(LOWER(?), '%')
       ORDER BY name ASC`,
      [appt.specialty, appt.specialty]
    );

    const result = [];
    for (const doc of sameSpecialtyDocs) {
      const isCurrent = doc.doctor_id === appt.current_doctor_id;
      let isAvailable = true;

      if (!isCurrent) {
        const [conflicts] = await pool.execute(
          `SELECT appointment_id FROM appointments
           WHERE doctor_id = ?
             AND appointment_date = ?
             AND appointment_time = ?
             AND status = 'Confirmed'`,
          [doc.doctor_id, appt.appointment_date, appt.appointment_time]
        );
        isAvailable = conflicts.length === 0;
      }

      result.push({
        doctor_id: doc.doctor_id,
        name: formatDocName(doc.name),
        specialty: doc.specialty,
        phone: doc.phone || "—",
        is_current: isCurrent,
        is_available: isAvailable,
      });
    }

    res.json({
      appointment_id: appt.appointment_id,
      current_doctor_id: appt.current_doctor_id,
      specialty: appt.specialty,
      appointment_date: appt.appointment_date,
      appointment_time: appt.appointment_time,
      doctors: result,
    });
  } catch (error) {
    console.error("Get specialty doctors error:", error.message);
    res.status(500).json({ error: "Could not fetch specialty doctors" });
  }
});

// Admin reassign doctor within the same specialization
app.patch("/api/appointments/:id/reassign-doctor", async (req, res) => {
  const appointmentId = Number(req.params.id);
  const { new_doctor_id } = req.body;

  const newDocId = Number(new_doctor_id);

  if (!Number.isInteger(appointmentId) || appointmentId < 1 || !Number.isInteger(newDocId) || newDocId < 1) {
    return res.status(400).json({ error: "Valid appointment ID and new doctor ID are required" });
  }

  try {
    const [appts] = await pool.execute(
      `SELECT a.appointment_id, a.doctor_id, a.appointment_date, a.appointment_time, a.status, d.specialty
       FROM appointments a
       INNER JOIN doctors d ON d.doctor_id = a.doctor_id
       WHERE a.appointment_id = ?`,
      [appointmentId]
    );

    if (appts.length === 0) {
      return res.status(404).json({ error: "Appointment not found" });
    }

    const appt = appts[0];
    if (appt.status === "Cancelled") {
      return res.status(400).json({ error: "Cannot change doctor on a cancelled appointment" });
    }

    const [newDocs] = await pool.execute(
      "SELECT doctor_id, name, specialty, phone FROM doctors WHERE doctor_id = ?",
      [newDocId]
    );

    if (newDocs.length === 0) {
      return res.status(404).json({ error: "Target doctor not found" });
    }

    const newDoc = newDocs[0];

    // Verify same respective specialization
    const oldSpec = appt.specialty.toLowerCase();
    const newSpec = newDoc.specialty.toLowerCase();
    if (oldSpec !== newSpec && !oldSpec.startsWith(newSpec) && !newSpec.startsWith(oldSpec)) {
      return res.status(400).json({
        error: `Doctor must belong to the same specialty (${appt.specialty}). ${formatDocName(newDoc.name)} is in ${newDoc.specialty}.`,
      });
    }

    // Verify slot availability
    if (newDocId !== appt.doctor_id) {
      const [conflicts] = await pool.execute(
        `SELECT appointment_id FROM appointments
         WHERE doctor_id = ?
           AND appointment_date = ?
           AND appointment_time = ?
           AND status = 'Confirmed'`,
        [newDocId, appt.appointment_date, appt.appointment_time]
      );

      if (conflicts.length > 0) {
        return res.status(409).json({
          error: `${formatDocName(newDoc.name)} already has a confirmed appointment at ${appt.appointment_time} on ${appt.appointment_date}.`,
        });
      }
    }

    await pool.execute(
      "UPDATE appointments SET doctor_id = ? WHERE appointment_id = ?",
      [newDocId, appointmentId]
    );

    res.json({
      message: `Doctor successfully reallocated to ${formatDocName(newDoc.name)} (${newDoc.specialty})`,
      doctor_id: newDocId,
      doctor_name: formatDocName(newDoc.name),
    });
  } catch (error) {
    console.error("Reassign doctor failed:", error.message);
    res.status(500).json({ error: "Could not change doctor" });
  }
});

// Admin update attendance status (Attended or Absent)
app.patch("/api/appointments/:id/attendance", async (req, res) => {
  const appointmentId = Number(req.params.id);
  const { attendance } = req.body;

  if (
    !Number.isInteger(appointmentId) ||
    appointmentId < 1 ||
    !["Attended", "Absent", "Pending"].includes(attendance)
  ) {
    return res.status(400).json({ error: "Valid attendance status ('Attended' or 'Absent') required" });
  }

  try {
    const [result] = await pool.execute(
      "UPDATE appointments SET attendance = ? WHERE appointment_id = ?",
      [attendance, appointmentId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Appointment not found" });
    }

    res.json({ message: `Patient attendance marked as ${attendance}` });
  } catch (error) {
    console.error("Attendance update failed:", error.message);
    res.status(500).json({ error: "Could not update attendance" });
  }
});

// Admin receive consultation fee
app.patch("/api/appointments/:id/payment", async (req, res) => {
  const appointmentId = Number(req.params.id);

  if (!Number.isInteger(appointmentId) || appointmentId < 1) {
    return res.status(400).json({ error: "Valid appointment ID required" });
  }

  try {
    const [result] = await pool.execute(
      `UPDATE appointments
       SET payment_status = 'Paid',
           attendance = 'Attended',
           status = 'Completed'
       WHERE appointment_id = ?`,
      [appointmentId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Appointment not found" });
    }

    res.json({ message: "Consultation payment received successfully! Marked as Completed." });
  } catch (error) {
    console.error("Payment receipt failed:", error.message);
    res.status(500).json({ error: "Could not process consultation payment" });
  }
});

// Cancel an appointment
app.patch("/api/appointments/:id/cancel", async (req, res) => {
  const appointmentId = Number(req.params.id);

  if (!Number.isInteger(appointmentId) || appointmentId < 1) {
    return res.status(400).json({ error: "Invalid appointment ID" });
  }

  try {
    const [result] = await pool.execute(
      `UPDATE appointments
       SET status = 'Cancelled',
           attendance = 'Absent'
       WHERE appointment_id = ?
         AND status != 'Cancelled'`,
      [appointmentId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        error: "Appointment not found or already cancelled",
      });
    }

    res.json({ message: "Appointment cancelled successfully" });
  } catch (error) {
    console.error("Cancel appointment failed:", error.message);
    res.status(500).json({ error: "Could not cancel appointment" });
  }
});

// Admin KPI Stats
app.get("/api/admin/stats", async (req, res) => {
  try {
    const [[apptTotal]] = await pool.query("SELECT COUNT(*) AS total FROM appointments");
    const [[apptConfirmed]] = await pool.query("SELECT COUNT(*) AS total FROM appointments WHERE status = 'Confirmed'");
    const [[apptAttended]] = await pool.query("SELECT COUNT(*) AS total FROM appointments WHERE attendance = 'Attended'");
    const [[revenueTotal]] = await pool.query("SELECT COALESCE(SUM(fee), 0) AS total FROM appointments WHERE payment_status = 'Paid'");
    const [[docTotal]] = await pool.query("SELECT COUNT(*) AS total FROM doctors");
    const [[patTotal]] = await pool.query("SELECT COUNT(*) AS total FROM patients");

    res.json({
      totalAppointments: apptTotal.total,
      confirmedAppointments: apptConfirmed.total,
      attendedAppointments: apptAttended.total,
      totalRevenue: Number(revenueTotal.total),
      totalDoctors: docTotal.total,
      totalPatients: patTotal.total,
    });
  } catch (error) {
    console.error("Get admin stats failed:", error.message);
    res.status(500).json({ error: "Could not load statistics" });
  }
});

// Admin add new doctor (with mobile number)
app.post("/api/admin/doctors", async (req, res) => {
  const { name, specialty, email, phone, password } = req.body;

  if (!name || !specialty || !email || !password) {
    return res.status(400).json({ error: "Name, specialty, email, and password are required" });
  }

  const cleanName = String(name).trim();
  const cleanSpecialty = String(specialty).trim();
  const cleanEmail = String(email).trim().toLowerCase();
  const cleanPhone = phone ? String(phone).trim() : null;
  const cleanPass = String(password);

  try {
    const [existing] = await pool.execute(
      "SELECT doctor_id FROM doctors WHERE LOWER(email) = ?",
      [cleanEmail]
    );
    if (existing.length > 0) {
      return res.status(409).json({ error: "Doctor with this email already exists" });
    }

    const hashedPassword = hashPassword(cleanPass);
    const [result] = await pool.execute(
      "INSERT INTO doctors (name, specialty, email, phone, password) VALUES (?, ?, ?, ?, ?)",
      [cleanName, cleanSpecialty, cleanEmail, cleanPhone, hashedPassword]
    );

    res.status(201).json({
      message: "Doctor added successfully",
      doctor_id: result.insertId,
    });
  } catch (error) {
    console.error("Add doctor failed:", error.message);
    res.status(500).json({ error: "Could not add doctor" });
  }
});

// Handle invalid API routes
app.use("/api", (req, res) => {
  res.status(404).json({ error: "API endpoint not found" });
});

// Start the server
app.listen(PORT, () => {
  console.log(`CarePoint server running at http://localhost:${PORT}`);
});
