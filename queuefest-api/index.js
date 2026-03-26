const express = require('express');
const mysql2 = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const db = mysql2.createPool({
  host: '10.0.0.5',
  port: 3306,
  user: 'admin',
  password: 'Proyecto_Seguro2026!',
  database: 'queuefest'
});

const JWT_SECRET = 'queuefest_secret_2026';

// ─── PUSH NOTIFICATION SETUP ───
const webpush = require('web-push');

if (!process.env.VAPID_PUBLIC_KEY || !process.env.VAPID_PRIVATE_KEY) {
  console.warn('WARN: VAPID keys missing. Push will not work.');
} else {
  webpush.setVapidDetails(
    process.env.VAPID_SUBJECT || 'mailto:soporte@queuefest.com',
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
  );
}

// Asegurar que la tabla existe al arrancar
async function initDB() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS push_subscriptions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        usuario_id INT NOT NULL,
        endpoint VARCHAR(512) NOT NULL,
        p256dh VARCHAR(255) NOT NULL,
        auth VARCHAR(255) NOT NULL,
        creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
        UNIQUE KEY uq_endpoint (endpoint(255))
      )
    `);
    console.log('SQL Migration push_subscriptions checked.');
  } catch (err) {
    console.error('DB Init push_subscriptions Failed:', err);
  }
}
initDB();

// Middleware para verificar tokenn
const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No autorizado' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido' });
  }
};

// ==================== AUTH ====================

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await db.query(
      'SELECT u.*, r.nombre as rol FROM usuarios u JOIN roles r ON u.rol_id = r.id WHERE u.email = ?',
      [email]
    );
    if (rows.length === 0) return res.status(401).json({ error: 'Credenciales incorrectas' });
    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Credenciales incorrectas' });
    const token = jwt.sign(
      { id: user.id, email: user.email, rol: user.rol, nombre: user.nombre },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    res.json({ token, user: { id: user.id, email: user.email, nombre: user.nombre, rol: user.rol } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Register
app.post('/api/auth/register', async (req, res) => {
  const { email, password, nombre } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    await db.query(
      'INSERT INTO usuarios (email, password_hash, nombre, rol_id) VALUES (?, ?, ?, 4)',
      [email, hash, nombre]
    );
    res.json({ message: 'Usuario registrado correctamente' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== PUESTOS ====================

app.get('/api/puestos', async (req, res) => {
  try {
    const { festival_id, tipo } = req.query;

    let query = 'SELECT * FROM puestos WHERE abierto = true';
    const params = [];

    if (festival_id) {
      query += ' AND festival_id = ?';
      params.push(Number(festival_id));
    }

    if (tipo) {
      query += ' AND tipo = ?';
      params.push(tipo); // 'barra' o 'foodtruck'
    }

    const [rows] = await db.query(query, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/puestos/:id', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM puestos WHERE id = ?', [req.params.id]);
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// MODIFICADO: acepta ?festival_id=X para filtrar por festival (AdminScreen lo usa)
// Sin parámetro devuelve todos, igual que antes → retrocompatible
app.get('/api/admin/puestos', auth, async (req, res) => {
  try {
    const { festival_id } = req.query;

    let query = 'SELECT * FROM puestos';
    const params = [];

    if (festival_id) {
      query += ' WHERE festival_id = ?';
      params.push(Number(festival_id));
    }

    query += ' ORDER BY nombre ASC';

    const [rows] = await db.query(query, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/puestos', auth, async (req, res) => {
  const { festival_id, nombre, tipo, capacidad_max, num_empleados } = req.body;
  try {
    const [result] = await db.query(
      'INSERT INTO puestos (festival_id, nombre, tipo, capacidad_max, num_empleados) VALUES (?, ?, ?, ?, ?)',
      [festival_id, nombre, tipo, capacidad_max, num_empleados]
    );
    res.json({ id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/admin/puestos/:id', auth, async (req, res) => {
  const { nombre, tipo, capacidad_max, num_empleados, abierto } = req.body;
  try {
    await db.query(
      'UPDATE puestos SET nombre = ?, tipo = ?, capacidad_max = ?, num_empleados = ?, abierto = ? WHERE id = ?',
      [nombre, tipo, capacidad_max, num_empleados, abierto, req.params.id]
    );
    res.json({ message: 'Puesto actualizado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/puestos/:id', auth, async (req, res) => {
  try {
    await db.query('DELETE FROM puestos WHERE id = ?', [req.params.id]);
    res.json({ message: 'Puesto eliminado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ==================== PRODUCTOSss =====================

app.get('/api/puestos/:id/productos', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM productos WHERE puesto_id = ? AND activo = true',
      [req.params.id]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/productos', auth, async (req, res) => {
  const { puesto_id, nombre, descripcion, precio, precio_dinamico, stock } = req.body;
  try {
    const [result] = await db.query(
      'INSERT INTO productos (puesto_id, nombre, descripcion, precio, precio_dinamico, stock) VALUES (?, ?, ?, ?, ?, ?)',
      [puesto_id, nombre, descripcion, precio, precio_dinamico || 0, stock]
    );
    res.json({ id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/admin/productos/:id', auth, async (req, res) => {
  const { nombre, descripcion, precio, precio_dinamico, stock, activo } = req.body;
  try {
    await db.query(
      'UPDATE productos SET nombre = ?, descripcion = ?, precio = ?, precio_dinamico = ?, stock = ?, activo = ? WHERE id = ?',
      [nombre, descripcion, precio, precio_dinamico, stock, activo, req.params.id]
    );
    res.json({ message: 'Producto actualizado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/productos/:id', auth, async (req, res) => {
  try {
    await db.query('DELETE FROM productos WHERE id = ?', [req.params.id]);
    res.json({ message: 'Producto eliminado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== PEDIDOS ====================

const VALID_TRANSITIONS = {
  'pendiente': ['confirmado', 'cancelado'],
  'confirmado': ['preparando', 'cancelado'],
  'preparando': ['listo', 'cancelado'],
  'listo': ['entregado', 'cancelado'],
  'entregado': [],
  'cancelado': [],
};

// Historial del usuario
app.get('/api/pedidos/mis-pedidos', auth, async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT p.*, pu.nombre as puesto_nombre FROM pedidos p JOIN puestos pu ON p.puesto_id = pu.id WHERE p.usuario_id = ? ORDER BY p.creado_en DESC',
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/pedidos/:id', auth, async (req, res) => {
  try {
    const pedidoId = req.params.id;
    const usuarioId = req.user.id;

    // 1. Obtener pedido junto con información del puesto
    const [pedidos] = await db.query(`
            SELECT p.*, pu.nombre AS puesto_nombre, pu.tiempo_servicio_medio
            FROM pedidos p
            JOIN puestos pu ON p.puesto_id = pu.id
            WHERE p.id = ?
        `, [pedidoId]);

    if (pedidos.length === 0) {
      return res.status(404).json({ error: 'Pedido no encontrado' });
    }

    const pedido = pedidos[0];

    // Validar permisos de lectura (Seguridad)
    if (req.user.rol === 'usuario' && pedido.usuario_id !== usuarioId) {
      return res.status(403).json({ error: 'No tienes permiso para ver este pedido' });
    } else if (req.user.rol === 'operador') {
      const [ops] = await db.query('SELECT id FROM puesto_operadores WHERE puesto_id = ? AND usuario_id = ?', [pedido.puesto_id, usuarioId]);
      if (ops.length === 0) {
        return res.status(403).json({ error: 'No tienes permiso para ver los pedidos de este puesto' });
      }
    }

    // 2. Obtener items del pedido
    const [items] = await db.query(`
            SELECT pi.*, pr.nombre AS producto_nombre
            FROM pedido_items pi
            JOIN productos pr ON pi.producto_id = pr.id
            WHERE pi.pedido_id = ?
        `, [pedidoId]);

    pedido.items = items;
    res.json(pedido);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

app.post('/api/pedidos', auth, async (req, res) => {
  const { puesto_id, items, total } = req.body;
  const conn = await db.getConnection();
  try {
    // ═══ VEND-004: Comprobación Botón Pánico ═══
    const [puestoCheck] = await conn.query('SELECT abierto FROM puestos WHERE id = ?', [puesto_id]);
    if (puestoCheck.length > 0 && puestoCheck[0].abierto === 0) {
      conn.release();
      return res.status(429).json({ error: 'Cocina saturada temporalmente, inténtalo en unos minutos' });
    }
    // ═══ FIN VEND-004 ═══

    await conn.beginTransaction();
    const [result] = await conn.query(
      'INSERT INTO pedidos (usuario_id, puesto_id, total) VALUES (?, ?, ?)',
      [req.user.id, puesto_id, total]
    );
    const pedidoId = result.insertId;
    for (const item of items) {
      await conn.query(
        'INSERT INTO pedido_items (pedido_id, producto_id, cantidad, precio_unitario) VALUES (?, ?, ?, ?)',
        [pedidoId, item.producto_id, item.cantidad, item.precio_unitario]
      );
    }
    // Sumar puntos loyalty (1 punto por euro)
    const puntos = Math.floor(total);
    await conn.query(
      'INSERT INTO loyalty (usuario_id, puntos_total) VALUES (?, ?) ON DUPLICATE KEY UPDATE puntos_total = puntos_total + ?',
      [req.user.id, puntos, puntos]
    );
    await conn.commit();
    res.json({ pedido_id: pedidoId, puntos_ganados: puntos });
  } catch (err) {
    await conn.rollback();
    res.status(500).json({ error: err.message });
  } finally {
    conn.release();
  }
});

// (Route mis-pedidos moved up)

// Operador: ver pedidos de su puesto
app.get('/api/pedidos/puesto/:id', auth, async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT p.*, u.nombre as usuario_nombre FROM pedidos p JOIN usuarios u ON p.usuario_id = u.id WHERE p.puesto_id = ? ORDER BY p.creado_en DESC',
      [req.params.id]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Vendedor: actualizar estado del pedido
app.patch('/api/pedidos/:id/estado', auth, async (req, res) => {
  try {
    const pedidoId = req.params.id;
    const nuevo_estado = req.body.estado;

    // (Omitimos validación de rol para pruebas, o asumimos auth de rol Vendedor/Admin)
    await db.query('UPDATE pedidos SET estado = ? WHERE id = ?', [nuevo_estado, pedidoId]);

    // -- NOTIFICACIÓN PUSH --
    if (nuevo_estado === 'listo' && process.env.VAPID_PUBLIC_KEY) {
      try {
        const [pedidoTemp] = await db.query('SELECT usuario_id FROM pedidos WHERE id = ?', [pedidoId]);
        if (pedidoTemp.length > 0) {
          const ownerId = pedidoTemp[0].usuario_id;
          const [subs] = await db.query('SELECT * FROM push_subscriptions WHERE usuario_id = ?', [ownerId]);

          if (subs.length > 0) {
            const payload = JSON.stringify({
              title: '¡Tu pedido está listo!',
              body: `Tu pedido #${pedidoId} ya puede ser recogido en el puesto.`,
              icon: '/favicon.ico',
              data: { url: `/track-order/${pedidoId}` }
            });

            const pushPromises = subs.map(sub => {
              const pushConfig = {
                endpoint: sub.endpoint,
                keys: { p256dh: sub.p256dh, auth: sub.auth }
              };
              return webpush.sendNotification(pushConfig, payload).catch(err => {
                if (err.statusCode === 410 || err.statusCode === 404) {
                  return db.query('DELETE FROM push_subscriptions WHERE id = ?', [sub.id]);
                }
              });
            });
            await Promise.all(pushPromises);
          }
        }
      } catch (pushErr) {
        console.error('Error enviando push:', pushErr);
      }
    }
    // -- FIN NOTIFICACIÓN PUSH --

    res.json({ message: 'Estado actualizado correctamente' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== VEND-004: BOTÓN PÁNICO ====================

// Pausar / Reanudar / Llamar camarero
app.patch('/api/puestos/:id/panico', auth, async (req, res) => {
  const puestoId = req.params.id;
  const { accion } = req.body;

  if (!['pausar', 'reanudar', 'llamar_camarero'].includes(accion)) {
    return res.status(400).json({ error: 'Acción inválida. Usa: pausar | reanudar | llamar_camarero' });
  }

  try {
    if (accion === 'pausar') {
      await db.query('UPDATE puestos SET abierto = 0 WHERE id = ?', [puestoId]);
      return res.json({ message: 'Puesto pausado. Ya no se aceptan nuevos pedidos.' });
    }

    if (accion === 'reanudar') {
      await db.query('UPDATE puestos SET abierto = 1 WHERE id = ?', [puestoId]);
      return res.json({ message: 'Puesto reactivado. Se aceptan nuevos pedidos.' });
    }

    if (accion === 'llamar_camarero') {
      const [puestos] = await db.query('SELECT num_empleados, capacidad_max FROM puestos WHERE id = ?', [puestoId]);
      if (puestos.length === 0) return res.status(404).json({ error: 'Puesto no encontrado' });

      const { num_empleados, capacidad_max } = puestos[0];
      if (num_empleados >= capacidad_max) {
        return res.status(403).json({
          error: 'Capacidad máxima de barra alcanzada, debes pausar pedidos',
          suggerir_pausa: true
        });
      }
      await db.query('UPDATE puestos SET num_empleados = num_empleados + 1 WHERE id = ?', [puestoId]);
      return res.json({ message: 'Camarero de apoyo llamado.', num_empleados: num_empleados + 1, capacidad_max });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Estado del puesto (para el frontend)
app.get('/api/puestos/:id/estado', auth, async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT id, nombre, abierto, num_empleados, capacidad_max, tiempo_servicio_medio FROM puestos WHERE id = ?',
      [req.params.id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Puesto no encontrado' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== LOYALTY ====================

app.get('/api/loyalty', auth, async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT puntos_total FROM loyalty WHERE usuario_id = ?',
      [req.user.id]
    );
    res.json(rows[0] || { puntos_total: 0 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== GESTOR ====================

app.get('/api/gestor/estadisticas', auth, async (req, res) => {
  try {
    const [pedidos] = await db.query('SELECT COUNT(*) as total, SUM(total) as ingresos FROM pedidos WHERE DATE(creado_en) = CURDATE()');
    const [esperas] = await db.query('SELECT AVG(tiempo_servicio_medio) as espera_media FROM puestos WHERE abierto = true');
    const [puestos] = await db.query('SELECT COUNT(*) as abiertos FROM puestos WHERE abierto = true');
    res.json({
      pedidos_hoy: pedidos[0].total,
      ingresos_hoy: pedidos[0].ingresos || 0,
      espera_media: esperas[0].espera_media || 0,
      puestos_abiertos: puestos[0].abiertos
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== FESTIVALES PÚBLICOS ====================
// Sin auth — usado en la pantalla de selección de festival del usuario

app.get('/api/festivales', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT id, nombre, fecha_inicio, fecha_fin, activo FROM festivales WHERE activo = 1 ORDER BY fecha_inicio DESC'
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== ADMIN ====================

// ── Festivales ────────────────────────────────────────────────────────────

app.get('/api/admin/festivales', auth, async (req, res) => {
  try {
    const [festivales] = await db.query('SELECT * FROM festivales ORDER BY fecha_inicio DESC');
    res.json(festivales);
  } catch (err) {
    console.error('Error al obtener los festivales:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/festivales', auth, async (req, res) => {
  const { nombre, fecha_inicio, fecha_fin } = req.body;
  try {
    const [result] = await db.query(
      'INSERT INTO festivales (nombre, fecha_inicio, fecha_fin, creado_por) VALUES (?, ?, ?, ?)',
      [nombre, fecha_inicio, fecha_fin, req.user.id]
    );
    res.json({ id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Desactiva un festival (activo = 0) sin eliminarlo
app.patch('/api/admin/festivales/:id/desactivar', auth, async (req, res) => {
  try {
    const [result] = await db.query(
      'UPDATE festivales SET activo = 0 WHERE id = ?',
      [req.params.id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Festival no encontrado' });
    }
    res.json({ message: 'Festival desactivado correctamente' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Activa un festival (activo = 1)
app.patch('/api/admin/festivales/:id/activar', auth, async (req, res) => {
  try {
    const [result] = await db.query(
      'UPDATE festivales SET activo = 1 WHERE id = ?',
      [req.params.id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Festival no encontrado' });
    }
    res.json({ message: 'Festival activado correctamente' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/festivales/:id', auth, async (req, res) => {
  try {
    await db.query('DELETE FROM festivales WHERE id = ?', [req.params.id]);
    res.json({ message: 'Festival eliminado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Parámetros ────────────────────────────────────────────────────────────

app.get('/api/admin/parametros', auth, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM parametros LIMIT 1');
    res.json(rows[0] || {});
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/admin/parametros', auth, async (req, res) => {
  const { pricing_dinamico_activo, umbral_cola, porcentaje_subida, promociones_activas, stock_minimo } = req.body;
  try {
    await db.query(
      `INSERT INTO parametros (id, pricing_dinamico_activo, umbral_cola, porcentaje_subida, promociones_activas, stock_minimo)
       VALUES (1, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         pricing_dinamico_activo = VALUES(pricing_dinamico_activo),
         umbral_cola = VALUES(umbral_cola),
         porcentaje_subida = VALUES(porcentaje_subida),
         promociones_activas = VALUES(promociones_activas),
         stock_minimo = VALUES(stock_minimo)`,
      [pricing_dinamico_activo, umbral_cola, porcentaje_subida, promociones_activas, stock_minimo]
    );
    res.json({ message: 'Parámetros actualizados' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Usuarios ──────────────────────────────────────────────────────────────

// Todos los usuarios (sin filtro)
app.get('/api/admin/usuarios', auth, async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT u.id, u.nombre, u.email, u.rol_id, r.nombre as rol, u.creado_en FROM usuarios u JOIN roles r ON u.rol_id = r.id ORDER BY u.creado_en DESC'
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// NUEVO: Solo staff — administrador (rol_id 1), gestor (2), operador (3)
// IMPORTANTE: declarado ANTES de /api/admin/usuarios/:id para que Express
// no interprete "staff" como un parámetro dinámico :id
app.get('/api/admin/usuarios/staff', auth, async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT u.id, u.nombre, u.email, u.rol_id, r.nombre as rol, u.creado_en
       FROM usuarios u
       JOIN roles r ON u.rol_id = r.id
       WHERE u.rol_id IN (1, 2, 3)
       ORDER BY u.rol_id ASC, u.nombre ASC`
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/usuarios', auth, async (req, res) => {
  const { email, password, nombre, rol, puesto_id } = req.body;
  const rolMap = { administrador: 1, gestor: 2, operador: 3, usuario: 4 };
  const rol_id = rolMap[rol] || 3;
  try {
    const hash = await bcrypt.hash(password, 10);
    const [result] = await db.query(
      'INSERT INTO usuarios (email, password_hash, nombre, rol_id) VALUES (?, ?, ?, ?)',
      [email, hash, nombre, rol_id]
    );
    res.json({ id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/usuarios/:id', auth, async (req, res) => {
  try {
    await db.query('DELETE FROM usuarios WHERE id = ?', [req.params.id]);
    res.json({ message: 'Usuario eliminado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Promociones ───────────────────────────────────────────────────────────

app.get('/api/admin/promociones', auth, async (req, res) => {
  try {
    const { puesto_id } = req.query;
    let query = 'SELECT * FROM promociones';
    const params = [];
    if (puesto_id) {
      query += ' WHERE puesto_id = ?';
      params.push(Number(puesto_id));
    }
    query += ' ORDER BY creado_en DESC';
    const [rows] = await db.query(query, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/promociones', auth, async (req, res) => {
  const { puesto_id, titulo, descripcion, precio_promo, activa } = req.body;
  try {
    const [result] = await db.query(
      'INSERT INTO promociones (puesto_id, titulo, descripcion, precio_promo, activa) VALUES (?, ?, ?, ?, ?)',
      [puesto_id, titulo, descripcion, precio_promo, activa ?? true]
    );
    res.json({ id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/admin/promociones/:id', auth, async (req, res) => {
  const { titulo, descripcion, precio_promo, activa } = req.body;
  try {
    await db.query(
      'UPDATE promociones SET titulo = ?, descripcion = ?, precio_promo = ?, activa = ? WHERE id = ?',
      [titulo, descripcion, precio_promo, activa, req.params.id]
    );
    res.json({ message: 'Promoción actualizada' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/promociones/:id', auth, async (req, res) => {
  try {
    await db.query('DELETE FROM promociones WHERE id = ?', [req.params.id]);
    res.json({ message: 'Promoción eliminada' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ─── PUSH SUBSCRIPTION ENDPOINT ───
app.get('/api/notifications/public-key', (req, res) => {
  if (!process.env.VAPID_PUBLIC_KEY) return res.status(500).json({ error: 'Push no configurado' });
  res.json({ publicKey: process.env.VAPID_PUBLIC_KEY });
});

app.post('/api/notifications/subscribe', auth, async (req, res) => {
  const { endpoint, keys } = req.body;
  if (!endpoint || !keys || !keys.p256dh || !keys.auth) {
    return res.status(400).json({ error: 'Faltan datos' });
  }
  try {
    await db.query(
      `INSERT IGNORE INTO push_subscriptions (usuario_id, endpoint, p256dh, auth) VALUES (?, ?, ?, ?)`,
      [req.user.id, endpoint, keys.p256dh, keys.auth]
    );
    res.status(201).json({ message: 'Suscripción guardada' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Arrancar jbio gouyg
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server Express (Oracle VM) corriendo en puerto ${port}`);
});
