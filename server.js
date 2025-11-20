const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const cors = require("cors");
const path = require("path");
require("dotenv").config();
const Groq = require("groq-sdk");

const app = express();
const PORT = 3000;

// Middleware global
app.use(cors());
app.use(express.json());
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));

// ========== BASE DE DATOS ==========
const db = new sqlite3.Database("./usuarios.db", (err) => {
  if (err) {
    console.error("❌ Error al conectar a SQLite:", err);
  } else {
    console.log("✅ Base de datos SQLite conectada");
    crearTabla();
  }
});

function crearTabla() {
  const sql = `
    CREATE TABLE IF NOT EXISTS usuarios (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nombre TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      usuario TEXT UNIQUE NOT NULL,
      contrasena TEXT NOT NULL,
      fecha_registro DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `;

  db.run(sql, (err) => {
    if (err) console.error("❌ Error al crear tabla:", err);
    else console.log("📌 Tabla 'usuarios' lista");
  });
}

// ========== RUTAS HTML LIMPIAS ==========
const sendPage = (res, file) =>
  res.sendFile(path.join(__dirname, "public", file));

app.get("/", (req, res) => sendPage(res, "inicio.html"));
app.get("/inicio", (req, res) => sendPage(res, "inicio.html"));
app.get("/dashboard", (req, res) => sendPage(res, "dashboard.html"));
app.get("/registro", (req, res) => sendPage(res, "registro.html"));
app.get("/metas", (req, res) => sendPage(res, "metas.html"));
app.get("/administrar", (req, res) => sendPage(res, "administrar.html"));
app.get("/asistente", (req, res) => sendPage(res, "asistente.html"));

// ========== API REGISTRO ==========
app.post("/api/registro", async (req, res) => {
  const { nombre, email, usuario, contrasena } = req.body;

  if (!nombre || !email || !usuario || !contrasena) {
    return res.status(400).json({
      success: false,
      message: "Todos los campos son requeridos",
    });
  }

  try {
    const hash = await bcrypt.hash(contrasena, 10);

    const sql = `
      INSERT INTO usuarios (nombre, email, usuario, contrasena)
      VALUES (?, ?, ?, ?)
    `;

    db.run(sql, [nombre, email, usuario, hash], function (err) {
      if (err) {
        if (err.message.includes("UNIQUE")) {
          return res.status(400).json({
            success: false,
            message: "El email o usuario ya está registrado",
          });
        }
        return res
          .status(500)
          .json({ success: false, message: "Error al registrar usuario" });
      }

      res.status(201).json({
        success: true,
        message: "Usuario registrado con éxito",
        id: this.lastID,
      });
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});

// ========== API LOGIN ==========
app.post("/api/login", (req, res) => {
  const { usuario, contrasena } = req.body;

  if (!usuario || !contrasena) {
    return res.status(400).json({
      success: false,
      message: "Faltan datos",
    });
  }

  const sql = `SELECT * FROM usuarios WHERE usuario = ? OR email = ?`;

  db.get(sql, [usuario, usuario], async (err, row) => {
    if (err)
      return res
        .status(500)
        .json({ success: false, message: "Error en el servidor" });

    if (!row) {
      return res
        .status(401)
        .json({ success: false, message: "Credenciales incorrectas" });
    }

    const valida = await bcrypt.compare(contrasena, row.contrasena);

    if (!valida) {
      return res.status(401).json({
        success: false,
        message: "Usuario o contraseña incorrectos",
      });
    }

    res.json({
      success: true,
      message: "Inicio de sesión exitoso",
      usuario: {
        id: row.id,
        nombre: row.nombre,
        email: row.email,
        usuario: row.usuario,
      },
    });
  });
});

// ========== OBTENER USUARIOS ==========
app.get("/api/usuarios", (req, res) => {
  const sql = `SELECT id, nombre, email, usuario, fecha_registro FROM usuarios`;

  db.all(sql, [], (err, rows) => {
    if (err)
      return res
        .status(500)
        .json({ success: false, message: "Error al consultar usuarios" });

    res.json({ success: true, usuarios: rows });
  });
});

// ========== IA: GROQ ==========
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

app.post("/api/chat-ia", async (req, res) => {
  const { message, gastos, objetivos } = req.body;

  if (!message) {
    return res.status(400).json({
      success: false,
      reply: "No recibí ningún mensaje.",
    });
  }

  try {
    const completion = await groq.chat.completions.create({
      model: "llama-3.1-8b-instant",
      messages: [
        {
          role: "system",
          content: `Eres un asistente financiero experto.
          Usa un tono cálido, profesional y claro.
          Datos del usuario:
          Gastos: ${JSON.stringify(gastos)}
          Objetivos: ${JSON.stringify(objetivos)}
          `,
        },
        { role: "user", content: message },
      ],
    });

    const respuesta = completion.choices[0].message.content;
    res.json({ success: true, reply: respuesta });
  } catch (error) {
    console.error("🔥 Error IA (Groq):", error);
    res.status(500).json({
      success: false,
      reply: "Hubo un problema con la IA. Inténtalo de nuevo.",
    });
  }
});

// ========== RUTA 404 ==========
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, "public", "404.html"));
});

// ========== INICIO DEL SERVIDOR ==========
app.listen(PORT, () => {
  console.log(`🚀 Servidor en ejecución: http://localhost:${PORT}`);
  console.log("📂 Archivos estáticos desde: /public");
});
