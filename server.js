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
    crearTablas();
  }
});

function crearTablas() {
  // Tabla usuarios
  const sqlUsuarios = `
    CREATE TABLE IF NOT EXISTS usuarios (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nombre TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      usuario TEXT UNIQUE NOT NULL,
      contrasena TEXT NOT NULL,
      fecha_registro DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `;

  // Tabla metas
  const sqlMetas = `
    CREATE TABLE IF NOT EXISTS metas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      usuario_id INTEGER NOT NULL,
      nombre TEXT NOT NULL,
      categoria TEXT NOT NULL,
      prioridad TEXT NOT NULL,
      monto_actual REAL DEFAULT 0,
      monto_objetivo REAL NOT NULL,
      fecha_creacion DATE NOT NULL,
      fecha_objetivo DATE NOT NULL,
      completada INTEGER DEFAULT 0,
      FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
    )
  `;

  // Tabla aportes
  const sqlAportes = `
    CREATE TABLE IF NOT EXISTS aportes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      meta_id INTEGER NOT NULL,
      monto REAL NOT NULL,
      fecha DATE NOT NULL,
      FOREIGN KEY (meta_id) REFERENCES metas(id) ON DELETE CASCADE
    )
  `;

  db.run(sqlUsuarios, (err) => {
    if (err) console.error("❌ Error al crear tabla usuarios:", err);
    else console.log("📌 Tabla 'usuarios' lista");
  });

  db.run(sqlMetas, (err) => {
    if (err) console.error("❌ Error al crear tabla metas:", err);
    else console.log("📌 Tabla 'metas' lista");
  });

  db.run(sqlAportes, (err) => {
    if (err) console.error("❌ Error al crear tabla aportes:", err);
    else console.log("📌 Tabla 'aportes' lista");
  });

  // ✅ LLAMAR A LA FUNCIÓN PARA CREAR LAS TABLAS DE FINANZAS
  crearTablasFinanzas();
}

function crearTablasFinanzas() {
  // Tabla gastos
  const sqlGastos = `
    CREATE TABLE IF NOT EXISTS gastos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      usuario_id INTEGER NOT NULL,
      descripcion TEXT NOT NULL,
      monto REAL NOT NULL,
      categoria TEXT NOT NULL,
      fecha DATE NOT NULL,
      FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
    )
  `;

  // Tabla presupuestos
  const sqlPresupuestos = `
    CREATE TABLE IF NOT EXISTS presupuestos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      usuario_id INTEGER NOT NULL,
      categoria TEXT NOT NULL,
      limite REAL NOT NULL,
      UNIQUE(usuario_id, categoria),
      FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
    )
  `;

  // Tabla objetivos_ahorro
  const sqlObjetivos = `
    CREATE TABLE IF NOT EXISTS objetivos_ahorro (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      usuario_id INTEGER NOT NULL,
      nombre TEXT NOT NULL,
      monto REAL NOT NULL,
      actual REAL DEFAULT 0,
      fecha DATE NOT NULL,
      prioridad TEXT NOT NULL,
      fecha_inicio DATE NOT NULL,
      FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
    )
  `;

  db.run(sqlGastos, (err) => {
    if (err) console.error("❌ Error al crear tabla gastos:", err);
    else console.log("📌 Tabla 'gastos' lista");
  });

  db.run(sqlPresupuestos, (err) => {
    if (err) console.error("❌ Error al crear tabla presupuestos:", err);
    else console.log("📌 Tabla 'presupuestos' lista");
  });

  db.run(sqlObjetivos, (err) => {
    if (err) console.error("❌ Error al crear tabla objetivos_ahorro:", err);
    else console.log("📌 Tabla 'objetivos_ahorro' lista");
  });
}
// ========== API GASTOS ==========

// Obtener todos los gastos de un usuario
app.get("/api/gastos/:usuarioId", (req, res) => {
  const { usuarioId } = req.params;
  const sql = `SELECT * FROM gastos WHERE usuario_id = ? ORDER BY fecha DESC`;

  db.all(sql, [usuarioId], (err, gastos) => {
    if (err) {
      return res
        .status(500)
        .json({ success: false, message: "Error al obtener gastos" });
    }
    res.json({ success: true, gastos: gastos || [] });
  });
});

// Crear un nuevo gasto
app.post("/api/gastos", (req, res) => {
  const { usuarioId, descripcion, monto, categoria, fecha } = req.body;

  if (!usuarioId || !descripcion || !monto || !categoria || !fecha) {
    return res
      .status(400)
      .json({ success: false, message: "Faltan campos requeridos" });
  }

  const sql = `INSERT INTO gastos (usuario_id, descripcion, monto, categoria, fecha) VALUES (?, ?, ?, ?, ?)`;

  db.run(
    sql,
    [usuarioId, descripcion, monto, categoria, fecha],
    function (err) {
      if (err) {
        return res
          .status(500)
          .json({ success: false, message: "Error al crear gasto" });
      }
      res
        .status(201)
        .json({ success: true, message: "Gasto registrado", id: this.lastID });
    }
  );
});

// Eliminar un gasto
app.delete("/api/gastos/:id", (req, res) => {
  const { id } = req.params;
  const sql = `DELETE FROM gastos WHERE id = ?`;

  db.run(sql, [id], function (err) {
    if (err) {
      return res
        .status(500)
        .json({ success: false, message: "Error al eliminar gasto" });
    }
    res.json({ success: true, message: "Gasto eliminado" });
  });
});

// ========== API PRESUPUESTOS ==========

// Obtener presupuestos de un usuario
app.get("/api/presupuestos/:usuarioId", (req, res) => {
  const { usuarioId } = req.params;
  const sql = `SELECT * FROM presupuestos WHERE usuario_id = ?`;

  db.all(sql, [usuarioId], (err, presupuestos) => {
    if (err) {
      return res
        .status(500)
        .json({ success: false, message: "Error al obtener presupuestos" });
    }
    res.json({ success: true, presupuestos: presupuestos || [] });
  });
});

// Establecer o actualizar presupuesto
app.post("/api/presupuestos", (req, res) => {
  const { usuarioId, categoria, limite } = req.body;

  if (!usuarioId || !categoria || !limite) {
    return res
      .status(400)
      .json({ success: false, message: "Faltan campos requeridos" });
  }

  const sql = `INSERT INTO presupuestos (usuario_id, categoria, limite) 
               VALUES (?, ?, ?) 
               ON CONFLICT(usuario_id, categoria) 
               DO UPDATE SET limite = excluded.limite`;

  db.run(sql, [usuarioId, categoria, limite], function (err) {
    if (err) {
      return res
        .status(500)
        .json({ success: false, message: "Error al establecer presupuesto" });
    }
    res.json({ success: true, message: "Presupuesto establecido" });
  });
});

// ========== API OBJETIVOS DE AHORRO ==========

// Obtener objetivos de ahorro de un usuario
app.get("/api/objetivos-ahorro/:usuarioId", (req, res) => {
  const { usuarioId } = req.params;
  const sql = `SELECT * FROM objetivos_ahorro WHERE usuario_id = ? ORDER BY fecha ASC`;

  db.all(sql, [usuarioId], (err, objetivos) => {
    if (err) {
      return res
        .status(500)
        .json({ success: false, message: "Error al obtener objetivos" });
    }
    res.json({ success: true, objetivos: objetivos || [] });
  });
});

// Crear un nuevo objetivo de ahorro
app.post("/api/objetivos-ahorro", (req, res) => {
  const { usuarioId, nombre, monto, actual, fecha, prioridad, fechaInicio } =
    req.body;

  if (!usuarioId || !nombre || !monto || !fecha || !prioridad) {
    return res
      .status(400)
      .json({ success: false, message: "Faltan campos requeridos" });
  }

  const sql = `INSERT INTO objetivos_ahorro (usuario_id, nombre, monto, actual, fecha, prioridad, fecha_inicio) 
               VALUES (?, ?, ?, ?, ?, ?, ?)`;

  db.run(
    sql,
    [usuarioId, nombre, monto, actual || 0, fecha, prioridad, fechaInicio],
    function (err) {
      if (err) {
        return res
          .status(500)
          .json({ success: false, message: "Error al crear objetivo" });
      }
      res
        .status(201)
        .json({ success: true, message: "Objetivo creado", id: this.lastID });
    }
  );
});

// Actualizar monto actual de un objetivo
app.put("/api/objetivos-ahorro/:id", (req, res) => {
  const { id } = req.params;
  const { actual } = req.body;

  const sql = `UPDATE objetivos_ahorro SET actual = ? WHERE id = ?`;

  db.run(sql, [actual, id], function (err) {
    if (err) {
      return res
        .status(500)
        .json({ success: false, message: "Error al actualizar objetivo" });
    }
    res.json({ success: true, message: "Objetivo actualizado" });
  });
});

// Eliminar un objetivo de ahorro
app.delete("/api/objetivos-ahorro/:id", (req, res) => {
  const { id } = req.params;
  const sql = `DELETE FROM objetivos_ahorro WHERE id = ?`;

  db.run(sql, [id], function (err) {
    if (err) {
      return res
        .status(500)
        .json({ success: false, message: "Error al eliminar objetivo" });
    }
    res.json({ success: true, message: "Objetivo eliminado" });
  });
});
// ========== RUTAS HTML LIMPIAS ==========
const sendPage = (res, file) =>
  res.sendFile(path.join(__dirname, "public", file));

app.get("/", (req, res) => sendPage(res, "inicio.html"));
app.get("/inicio", (req, res) => sendPage(res, "inicio.html"));
app.get("/dashboard", (req, res) => sendPage(res, "dashboard.html"));
app.get("/registro", (req, res) => sendPage(res, "registro.html"));
app.get("/metas", (req, res) => sendPage(res, "metas.html"));
app.get("/restablecer.html", (req, res) => sendPage(res, "restablecer.html"));
app.get("/administrar", (req, res) => sendPage(res, "administrar.html"));
app.get("/asistente", (req, res) => sendPage(res, "asistente.html"));
app.get("/calculadora", (req, res) => sendPage(res, "calculadora.html"));
app.get("/quienes-somos", (req, res) => sendPage(res, "quienes-somos.html"));

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

// ========== API RECUPERAR CONTRASEÑA ==========

// 1. Verificar si el usuario existe
app.post("/api/verificar-usuario", (req, res) => {
  const { usuario } = req.body;

  if (!usuario) {
    return res
      .status(400)
      .json({ success: false, message: "Falta el nombre de usuario" });
  }

  const sql = `SELECT id FROM usuarios WHERE usuario = ?`;
  db.get(sql, [usuario], (err, row) => {
    if (err) {
      return res
        .status(500)
        .json({ success: false, message: "Error en el servidor" });
    }
    if (!row) {
      return res
        .status(404)
        .json({ success: false, message: "El usuario no fue encontrado" });
    }
    res.json({ success: true });
  });
});

// 2. Restablecer la contraseña
app.post("/api/restablecer-contrasena", async (req, res) => {
  const { usuario, nuevaContrasena } = req.body;

  if (!usuario || !nuevaContrasena) {
    return res.status(400).json({ success: false, message: "Faltan datos" });
  }

  if (nuevaContrasena.length < 6) {
    return res.status(400).json({
      success: false,
      message: "La contraseña debe tener al menos 6 caracteres",
    });
  }

  try {
    const hash = await bcrypt.hash(nuevaContrasena, 10);
    const sql = `UPDATE usuarios SET contrasena = ? WHERE usuario = ?`;

    db.run(sql, [hash, usuario], function (err) {
      if (err) {
        return res.status(500).json({
          success: false,
          message: "Error al actualizar la contraseña",
        });
      }
      if (this.changes === 0) {
        return res.status(404).json({
          success: false,
          message: "Usuario no encontrado para actualizar",
        });
      }
      res.json({ success: true, message: "Contraseña actualizada con éxito" });
    });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
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

// ========== API METAS ==========

// 1. Obtener todas las metas de un usuario
app.get("/api/metas/:usuarioId", (req, res) => {
  const { usuarioId } = req.params;

  const sql = `SELECT * FROM metas WHERE usuario_id = ? ORDER BY fecha_creacion DESC`;

  db.all(sql, [usuarioId], (err, metas) => {
    if (err) {
      return res
        .status(500)
        .json({ success: false, message: "Error al obtener metas" });
    }

    // Para cada meta, obtener sus aportes
    const metasConAportes = [];
    let processed = 0;

    if (metas.length === 0) {
      return res.json({ success: true, metas: [] });
    }

    metas.forEach((meta) => {
      const sqlAportes = `SELECT * FROM aportes WHERE meta_id = ? ORDER BY fecha DESC`;

      db.all(sqlAportes, [meta.id], (err, aportes) => {
        if (err) {
          metasConAportes.push({ ...meta, aportes: [] });
        } else {
          metasConAportes.push({ ...meta, aportes: aportes || [] });
        }

        processed++;
        if (processed === metas.length) {
          res.json({ success: true, metas: metasConAportes });
        }
      });
    });
  });
});

// 2. Crear una nueva meta
app.post("/api/metas", (req, res) => {
  const {
    usuarioId,
    nombre,
    categoria,
    prioridad,
    montoObjetivo,
    montoInicial, // ✅ Debe ser montoInicial
    fechaObjetivo,
  } = req.body;

  // Validaciones
  if (
    !usuarioId ||
    !nombre ||
    !categoria ||
    !prioridad ||
    !montoObjetivo ||
    !fechaObjetivo
  ) {
    return res
      .status(400)
      .json({ success: false, message: "Faltan campos requeridos" });
  }

  const fechaCreacion = new Date().toISOString().split("T")[0];
  const montoActual = montoInicial || 0; // ✅ Convertir montoInicial a montoActual

  const sql = `
    INSERT INTO metas (usuario_id, nombre, categoria, prioridad, monto_actual, monto_objetivo, fecha_creacion, fecha_objetivo)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.run(
    sql,
    [
      usuarioId,
      nombre,
      categoria,
      prioridad,
      montoActual,
      montoObjetivo,
      fechaCreacion,
      fechaObjetivo,
    ],
    function (err) {
      if (err) {
        console.error("Error al crear meta:", err); // ✅ Agregar log para debug
        return res
          .status(500)
          .json({ success: false, message: "Error al crear meta" });
      }

      const metaId = this.lastID;

      // Si hay monto inicial, crear el primer aporte
      if (montoInicial && montoInicial > 0) {
        const sqlAporte = `INSERT INTO aportes (meta_id, monto, fecha) VALUES (?, ?, ?)`;
        db.run(sqlAporte, [metaId, montoInicial, fechaCreacion], (err) => {
          if (err) console.error("Error al crear aporte inicial:", err);
        });
      }

      res.status(201).json({
        success: true,
        message: "Meta creada exitosamente",
        metaId: metaId,
      });
    }
  );
});

// 3. Agregar un aporte a una meta
app.post("/api/metas/:metaId/aportes", (req, res) => {
  const { metaId } = req.params;
  const { monto, fecha } = req.body;

  if (!monto || !fecha) {
    return res
      .status(400)
      .json({ success: false, message: "Faltan datos del aporte" });
  }

  // Insertar el aporte
  const sqlAporte = `INSERT INTO aportes (meta_id, monto, fecha) VALUES (?, ?, ?)`;

  db.run(sqlAporte, [metaId, monto, fecha], function (err) {
    if (err) {
      return res
        .status(500)
        .json({ success: false, message: "Error al agregar aporte" });
    }

    // Actualizar el monto actual de la meta
    const sqlUpdate = `UPDATE metas SET monto_actual = monto_actual + ? WHERE id = ?`;

    db.run(sqlUpdate, [monto, metaId], (err) => {
      if (err) {
        return res
          .status(500)
          .json({ success: false, message: "Error al actualizar meta" });
      }

      res.json({ success: true, message: "Aporte agregado exitosamente" });
    });
  });
});

// 4. Marcar meta como completada
app.put("/api/metas/:metaId/completar", (req, res) => {
  const { metaId } = req.params;

  const sql = `UPDATE metas SET completada = 1 WHERE id = ?`;

  db.run(sql, [metaId], function (err) {
    if (err) {
      return res
        .status(500)
        .json({ success: false, message: "Error al completar meta" });
    }

    if (this.changes === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Meta no encontrada" });
    }

    res.json({ success: true, message: "¡Meta completada! 🎉" });
  });
});

// 5. Eliminar una meta
app.delete("/api/metas/:metaId", (req, res) => {
  const { metaId } = req.params;

  const sql = `DELETE FROM metas WHERE id = ?`;

  db.run(sql, [metaId], function (err) {
    if (err) {
      return res
        .status(500)
        .json({ success: false, message: "Error al eliminar meta" });
    }

    if (this.changes === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Meta no encontrada" });
    }

    res.json({ success: true, message: "Meta eliminada exitosamente" });
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
