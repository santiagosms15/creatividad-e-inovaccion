const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const cors = require("cors");
const path = require("path");

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static("public")); // Carpeta para tus archivos HTML

// Crear/conectar base de datos
const db = new sqlite3.Database("./usuarios.db", (err) => {
  if (err) {
    console.error("Error al conectar con la base de datos:", err);
  } else {
    console.log("Conectado a la base de datos SQLite");
    crearTabla();
  }
});

// Crear tabla de usuarios si no existe
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
    if (err) {
      console.error("Error al crear tabla:", err);
    } else {
      console.log("Tabla de usuarios lista");
    }
  });
}

// RUTA: Registrar nuevo usuario
app.post("/api/registro", async (req, res) => {
  const { nombre, email, usuario, contrasena } = req.body;

  // Validaciones básicas
  if (!nombre || !email || !usuario || !contrasena) {
    return res.status(400).json({
      success: false,
      message: "Todos los campos son requeridos",
    });
  }

  try {
    // Encriptar contraseña
    const contrasenaHash = await bcrypt.hash(contrasena, 10);

    // Insertar usuario en la base de datos
    const sql = `INSERT INTO usuarios (nombre, email, usuario, contrasena) VALUES (?, ?, ?, ?)`;

    db.run(sql, [nombre, email, usuario, contrasenaHash], function (err) {
      if (err) {
        if (err.message.includes("UNIQUE")) {
          return res.status(400).json({
            success: false,
            message: "El email o usuario ya existe",
          });
        }
        return res.status(500).json({
          success: false,
          message: "Error al registrar usuario",
        });
      }

      res.status(201).json({
        success: true,
        message: "Usuario registrado exitosamente",
        userId: this.lastID,
      });
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error en el servidor",
    });
  }
});

// RUTA: Iniciar sesión
app.post("/api/login", (req, res) => {
  const { usuario, contrasena } = req.body;

  if (!usuario || !contrasena) {
    return res.status(400).json({
      success: false,
      message: "Usuario y contraseña son requeridos",
    });
  }

  // Buscar usuario en la base de datos
  const sql = `SELECT * FROM usuarios WHERE usuario = ? OR email = ?`;

  db.get(sql, [usuario, usuario], async (err, row) => {
    if (err) {
      return res.status(500).json({
        success: false,
        message: "Error en el servidor",
      });
    }

    if (!row) {
      return res.status(401).json({
        success: false,
        message: "Usuario o contraseña incorrectos",
      });
    }

    // Verificar contraseña
    const contrasenaValida = await bcrypt.compare(contrasena, row.contrasena);

    if (!contrasenaValida) {
      return res.status(401).json({
        success: false,
        message: "Usuario o contraseña incorrectos",
      });
    }

    // Login exitoso
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

// RUTA: Obtener todos los usuarios (para testing)
app.get("/api/usuarios", (req, res) => {
  const sql = `SELECT id, nombre, email, usuario, fecha_registro FROM usuarios`;

  db.all(sql, [], (err, rows) => {
    if (err) {
      return res.status(500).json({
        success: false,
        message: "Error al obtener usuarios",
      });
    }
    res.json({ success: true, usuarios: rows });
  });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
  console.log("Base de datos: usuarios.db");
});

// Cerrar base de datos al terminar
process.on("SIGINT", () => {
  db.close((err) => {
    if (err) {
      console.error(err.message);
    }
    console.log("Base de datos cerrada");
    process.exit(0);
  });
});
