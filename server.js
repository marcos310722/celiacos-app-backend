const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const multer = require('multer');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
}));
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Conexión a PostgreSQL
const pool = new Pool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
});

// Configuración de multer para manejar la subida de imágenes
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Middleware para verificar JWT
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ message: 'No token provided' });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ message: 'Unauthorized' });
        req.userId = decoded.id;
        req.userRole = decoded.role;
        next();
    });
};

// Validaciones para el registro
const validateRegister = (data) => {
    const errors = {};

    if (!/^[A-Za-záéíóúüñÁÉÍÓÚÜÑ\s]+$/.test(data.nombre)) {
        errors.nombre = 'El nombre debe contener solo letras y espacios.';
    } else {
        const palabrasNombre = data.nombre.trim().split(/\s+/);
        for (let palabra of palabrasNombre) {
            if (/^(.)\1+$/.test(palabra)) {
                errors.nombre = 'El nombre no puede contener palabras con letras repetidas (ejemplo: yyyy).';
                break;
            }
        }
    }

    if (!/^[A-Za-záéíóúüñÁÉÍÓÚÜÑ\s]+$/.test(data.apellido)) {
        errors.apellido = 'El apellido debe contener solo letras y espacios.';
    } else {
        const palabrasApellido = data.apellido.trim().split(/\s+/);
        for (let palabra of palabrasApellido) {
            if (/^(.)\1+$/.test(palabra)) {
                errors.apellido = 'El apellido no puede contener palabras con letras repetidas (ejemplo: yyyy).';
                break;
            }
        }
    }

    if (data.direccion && !/^[A-Za-z0-9áéíóúüñÁÉÍÓÚÜÑ\s]+$/.test(data.direccion)) {
        errors.direccion = 'La dirección solo puede contener letras, números y espacios.';
    }

    if (!/^\d{11}$/.test(data.ci)) {
        errors.ci = 'El CI debe contener exactamente 11 números.';
    }

    if (data.telefono && !/^\d{8}$/.test(data.telefono)) {
        errors.telefono = 'El teléfono debe contener exactamente 8 números.';
    }

    if (!/^[A-Za-záéíóúüñÁÉÍÓÚÜÑ\s]+$/.test(data.provincia)) {
        errors.provincia = 'La provincia debe contener solo letras y espacios.';
    }

    if (!/^[A-Za-záéíóúüñÁÉÍÓÚÜÑ\s]+$/.test(data.municipio)) {
        errors.municipio = 'El municipio debe contener solo letras y espacios.';
    }

    if (!data.correo_electronico) {
        errors.correo_electronico = 'El correo electrónico es obligatorio.';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.correo_electronico)) {
        errors.correo_electronico = 'El correo electrónico no tiene un formato válido.';
    }

    if (!data.contrasena) {
        errors.contrasena = 'La contraseña es obligatoria.';
    }

    return errors;
};

// Configurar el transportador de correo
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,  // celiacosapp56@gmail.com
      pass: process.env.EMAIL_PASS   // La contraseña de aplicación generada
    }
  });
  
  // Verificar conexión (opcional pero recomendado)
  transporter.verify((error, success) => {
    if (error) {
      console.error('Error al conectar con Gmail:', error);
    } else {
      console.log('✔ Servidor de correo listo');
    }
  });
  
  // Generar token seguro
  const generateResetToken = () => {
    return crypto.randomBytes(20).toString('hex');
  };


// Login de usuario
app.post('/api/login', async (req, res) => {
    const { ci, contrasena, correo_electronico } = req.body;

    console.log('Solicitud de login recibida:', { ci, correo_electronico, contrasena });

    try {
        let userResult;
        if (ci) {
            userResult = await pool.query('SELECT * FROM Usuarios WHERE CI = $1', [ci]);
        } else if (correo_electronico) {
            userResult = await pool.query('SELECT * FROM Usuarios WHERE correo_electronico = $1', [correo_electronico]);
        } else {
            return res.status(400).json({ message: 'Debe proporcionar CI o correo electrónico' });
        }

        const user = userResult.rows[0];
        if (!user) {
            console.log('Usuario no encontrado');
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        const validPassword = await bcrypt.compare(contrasena, user.contrasena);        if (!validPassword) {
            console.log('Contraseña incorrecta');
            return res.status(401).json({ message: 'Contraseña incorrecta' });
        }

        const roleResult = await pool.query('SELECT Rol FROM Admin_Usuarios WHERE UsuariosID = $1', [user.id]);
        const role = roleResult.rows[0] ? roleResult.rows[0].rol : 'Usuario';

        const token = jwt.sign({ id: user.id, role }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, role, user: { id: user.id, nombre: user.nombre, apellido: user.apellido } });
    } catch (error) {
        console.error('Error en el endpoint /api/login:', error);
        res.status(500).json({ message: 'Error en el servidor', error: error.message });
    }
});

// Registro de usuario
app.post('/api/register', async (req, res) => {
    console.log('Datos recibidos en /api/register:', req.body);

    const { nombre, apellido, direccion, ci, telefono, provincia, municipio, celiaco, contrasena, correo_electronico } = req.body;

    const validationErrors = validateRegister(req.body);
    if (Object.keys(validationErrors).length > 0) {
        console.log('Errores de validación en /api/register:', validationErrors);
        return res.status(400).json({ message: 'Errores de validación', errors: validationErrors });
    }

    try {
        const userResult = await pool.query('SELECT * FROM Usuarios WHERE CI = $1', [ci]);
        if (userResult.rows.length > 0) return res.status(400).json({ message: 'Usuario ya registrado' });

        const correoResult = await pool.query('SELECT * FROM Usuarios WHERE correo_electronico = $1', [correo_electronico]);
        if (correoResult.rows.length > 0) {
            return res.status(400).json({ message: 'El correo electrónico ya está registrado' });
        }

        const hashedPassword = await bcrypt.hash(contrasena, 10);
        const newUser = await pool.query(
            'INSERT INTO Usuarios (Nombre, Apellido, Direccion, CI, Telefono, Provincia, Municipio, Celiaco, Contrasena, correo_electronico) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *',
            [nombre, apellido, direccion, ci, telefono, provincia, municipio, celiaco, hashedPassword, correo_electronico]
        );
        
        await pool.query('INSERT INTO Admin_Usuarios (Rol, UsuariosID) VALUES ($1, $2)', ['Usuario', newUser.rows[0].id]);
        res.status(201).json({ message: 'Usuario registrado con éxito' });
    } catch (error) {
        console.error('Error al registrar usuario:', error);
        res.status(500).json({ message: 'Error en el servidor', error: error.message });
    }
});

// Endpoint para solicitar recuperación
app.post('/api/forgot-password', async (req, res) => {
    const { correo_electronico } = req.body;
  
    try {
      // Validar formato de correo
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correo_electronico)) {
        return res.status(400).json({ message: 'Formato de correo electrónico inválido' });
      }
  
      // Buscar usuario
      const userResult = await pool.query('SELECT * FROM Usuarios WHERE correo_electronico = $1', [correo_electronico]);
      const user = userResult.rows[0];
      
      if (!user) {
        // Por seguridad, no revelamos si el correo existe o no
        return res.json({ message: 'Si el correo existe, se ha enviado un enlace de recuperación' });
      }
  
      // Generar token y fecha de expiración
      const resetToken = generateResetToken();
      const resetTokenExpires = new Date(Date.now() + 3600000); // 1 hora
  
      // Guardar token en la base de datos
      await pool.query(
        'UPDATE Usuarios SET reset_token = $1, reset_token_expires = $2 WHERE id = $3',
        [resetToken, resetTokenExpires, user.id]
      );
// Validar token de restablecimiento
app.get('/api/validate-reset-token', async (req, res) => {
    const { token } = req.query;
    try {
        const result = await pool.query(
            'SELECT * FROM usuarios WHERE reset_token = $1 AND reset_token_expires > $2',
            [token, new Date()]
        );
        if (result.rows.length === 0) {
            return res.json({ valid: false });
        }
        res.json({ valid: true });
    } catch (error) {
        console.error('Error al validar el token de restablecimiento:', error);
        res.status(500).json({ valid: false, message: 'Error al validar el token' });
    }
});

// Restablecer contraseña
app.post('/api/reset-password', async (req, res) => {
    const { token, nueva_contrasena } = req.body;
    try {
        const result = await pool.query(
            'SELECT * FROM usuarios WHERE reset_token = $1 AND reset_token_expires > $2',
            [token, new Date()]
        );
        if (result.rows.length === 0) {
            return res.status(400).json({ message: 'Token inválido o expirado' });
        }
        const user = result.rows[0];
        // Actualizar contraseña (considera hashear en producción)
        const hashedPassword = await bcrypt.hash(nueva_contrasena, 10);
        await pool.query(
            'UPDATE usuarios SET contrasena = $1, reset_token = NULL, reset_token_expires = NULL WHERE id = $2',
            [hashedPassword, user.id]
        );
        res.json({ message: 'Contraseña actualizada con éxito' });
    } catch (error) {
        console.error('Error al restablecer la contraseña:', error);
        res.status(500).json({ message: 'Error al actualizar la contraseña' });
    }
});  
      // Crear enlace de recuperación
      const resetUrl = `http://tudominio.com/reset-password?token=${resetToken}`;
  
      // Configurar correo
      const mailOptions = {
        to: user.correo_electronico,
        from: process.env.EMAIL_FROM,
        subject: 'Recuperación de contraseña - Celíacos App',
        text: `Por favor, haz clic en el siguiente enlace para restablecer tu contraseña:\n\n${resetUrl}\n\n` +
              `Si no solicitaste este cambio, ignora este correo.`,
        html: `<p>Por favor, haz clic en el siguiente enlace para restablecer tu contraseña:</p>
               <p><a href="${resetUrl}">${resetUrl}</a></p>
               <p>Si no solicitaste este cambio, ignora este correo.</p>`
      };
  
      // Enviar correo
      await transporter.sendMail(mailOptions);
  
      res.json({ message: 'Se ha enviado un correo con instrucciones para restablecer tu contraseña' });
    } catch (error) {
      console.error('Error en recuperación de contraseña:', error);
      res.status(500).json({ message: 'Error al procesar la solicitud' });
    }
  });
  
// Endpoint para recuperación de contraseña (versión mejorada)
app.post('/api/forgot-password', async (req, res) => {
    const { correo_electronico } = req.body;
  
    // Validación mejorada
    if (!correo_electronico || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correo_electronico)) {
      return res.status(400).json({ 
        success: false,
        message: 'Por favor proporcione un correo electrónico válido'
      });
    }
  
    try {
      // 1. Buscar usuario
      const userResult = await pool.query(
        'SELECT id, nombre FROM usuarios WHERE correo_electronico = $1', 
        [correo_electronico]
      );
      
      // Respuesta genérica por seguridad
      const genericResponse = {
        success: true,
        message: 'Si el correo existe, se ha enviado un enlace de recuperación'
      };
  
      if (userResult.rows.length === 0) {
        return res.json(genericResponse);
      }
  
      const user = userResult.rows[0];
      
      // 2. Generar token seguro
      const resetToken = crypto.randomBytes(20).toString('hex');
      const resetTokenExpires = new Date(Date.now() + 3600000); // 1 hora
  
      // 3. Guardar token en la base de datos
      await pool.query(
        'UPDATE usuarios SET reset_token = $1, reset_token_expires = $2 WHERE id = $3',
        [resetToken, resetTokenExpires, user.id]
      );
  
      // 4. Crear enlace de recuperación
      const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;
      
      // 5. Configurar el correo
      const mailOptions = {
        to: correo_electronico,
        from: process.env.EMAIL_FROM,
        subject: 'Recuperación de contraseña - Celíacos App',
        html: `
          <div style="font-family: Arial, sans-serif; line-height: 1.6;">
            <h2 style="color: #6b48ff;">Recuperación de contraseña</h2>
            <p>Hola ${user.nombre},</p>
            <p>Hemos recibido una solicitud para restablecer tu contraseña.</p>
            <p>Por favor, haz clic en el siguiente enlace para continuar:</p>
            <p>
              <a href="${resetUrl}" 
                 style="background-color: #6b48ff; color: white; padding: 10px 15px; 
                        text-decoration: none; border-radius: 5px; display: inline-block;">
                Restablecer contraseña
              </a>
            </p>
            <p>Si no solicitaste este cambio, puedes ignorar este mensaje.</p>
            <p><small>Este enlace expirará en 1 hora.</small></p>
          </div>
        `
      };
  
      // 6. Enviar el correo
      await transporter.sendMail(mailOptions);
      console.log(`Correo de recuperación enviado a: ${correo_electronico}`);
  
      res.json(genericResponse);
  
    } catch (error) {
      console.error('Error detallado en recuperación:', {
        message: error.message,
        stack: error.stack,
        fullError: error
      });
      
      res.status(500).json({
        success: false,
        message: 'Ocurrió un error al procesar tu solicitud. Por favor intenta nuevamente más tarde.'
      });
    }
  });



// Obtener información del usuario autenticado
app.get('/api/user', verifyToken, async (req, res) => {
    try {
        const userResult = await pool.query('SELECT id, nombre, apellido, direccion, ci, telefono, provincia, municipio, celiaco, correo_electronico FROM Usuarios WHERE ID = $1', [req.userId]);
        const user = userResult.rows[0];
        if (!user) return res.status(404).json({ message: 'Usuario no encontrado' });
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: 'Error en el servidor', error: error.message });
    }
});

// Editar información del usuario
app.put('/api/user', verifyToken, async (req, res) => {
    const { nombre, apellido, direccion, ci, telefono, provincia, municipio, celiaco, contrasena, correo_electronico } = req.body;

    const validationErrors = validateRegister(req.body);
    if (Object.keys(validationErrors).length > 0) {
        return res.status(400).json({ message: 'Errores de validación', errors: validationErrors });
    }

    try {
        const userResult = await pool.query('SELECT * FROM Usuarios WHERE CI = $1 AND ID != $2', [ci, req.userId]);
        if (userResult.rows.length > 0) return res.status(400).json({ message: 'El CI ya está registrado por otro usuario' });

        const correoResult = await pool.query('SELECT * FROM Usuarios WHERE correo_electronico = $1 AND ID != $2', [correo_electronico, req.userId]);
        if (correoResult.rows.length > 0) {
            return res.status(400).json({ message: 'El correo electrónico ya está registrado por otro usuario' });
        }

        const hashedPassword = contrasena ? await bcrypt.hash(contrasena, 10) : undefined;
        await pool.query(
            'UPDATE Usuarios SET Nombre = $1, Apellido = $2, Direccion = $3, CI = $4, Telefono = $5, Provincia = $6, Municipio = $7, Celiaco = $8, Contrasena = COALESCE($9, Contrasena), correo_electronico = $10 WHERE ID = $11',
            [nombre, apellido, direccion, ci, telefono, provincia, municipio, celiaco, hashedPassword, correo_electronico, req.userId]
        );
        res.json({ message: 'Información actualizada con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error en el servidor', error: error.message });
    }
});

// Eliminar cuenta del usuario autenticado
app.delete('/api/user', verifyToken, async (req, res) => {
    try {
        const userResult = await pool.query('SELECT CI FROM Usuarios WHERE ID = $1', [req.userId]);
        const user = userResult.rows[0];

        if (user.ci === '02022781222') return res.status(403).json({ message: 'No se puede eliminar al administrador principal' });

        await pool.query('DELETE FROM Admin_Usuarios WHERE UsuariosID = $1', [req.userId]);
        await pool.query('DELETE FROM Usuarios WHERE ID = $1', [req.userId]);
        res.json({ message: 'Cuenta eliminada con éxito' });
    } catch (error) {
        console.error('Error al eliminar cuenta:', error);
        res.status(500).json({ message: 'Error en el servidor', error: error.message });
    }
});

// Obtener todos los usuarios (solo para administradores)
app.get('/api/users', verifyToken, async (req, res) => {
    if (req.userRole !== 'Administrador') return res.status(403).json({ message: 'Acceso denegado' });

    try {
        const usersResult = await pool.query('SELECT id, nombre, apellido, direccion, ci, telefono, provincia, municipio, celiaco, correo_electronico FROM Usuarios');
        res.json(usersResult.rows);
    } catch (error) {
        res.status(500).json({ message: 'Error en el servidor', error: error.message });
    }
});

// Editar información de un usuario (solo para administradores)
app.put('/api/users/:id', verifyToken, async (req, res) => {
    if (req.userRole !== 'Administrador') return res.status(403).json({ message: 'Acceso denegado' });

    const userId = req.params.id;
    const { nombre, apellido, direccion, ci, telefono, provincia, municipio, celiaco, contrasena, correo_electronico } = req.body;

    const validationErrors = validateRegister(req.body);
    if (Object.keys(validationErrors).length > 0) {
        return res.status(400).json({ message: 'Errores de validación', errors: validationErrors });
    }

    try {
        const userResult = await pool.query('SELECT * FROM Usuarios WHERE CI = $1 AND ID != $2', [ci, userId]);
        if (userResult.rows.length > 0) return res.status(400).json({ message: 'El CI ya está registrado por otro usuario' });

        const correoResult = await pool.query('SELECT * FROM Usuarios WHERE correo_electronico = $1 AND ID != $2', [correo_electronico, userId]);
        if (correoResult.rows.length > 0) {
            return res.status(400).json({ message: 'El correo electrónico ya está registrado por otro usuario' });
        }

        await pool.query(
            'UPDATE Usuarios SET Nombre = $1, Apellido = $2, Direccion = $3, CI = $4, Telefono = $5, Provincia = $6, Municipio = $7, Celiaco = $8, Contrasena = $9, correo_electronico = $10 WHERE ID = $11',
            [nombre, apellido, direccion, ci, telefono, provincia, municipio, celiaco, contrasena, correo_electronico, userId]
        );
        res.json({ message: 'Información actualizada con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error en el servidor', error: error.message });
    }
});

// Eliminar un usuario (solo para administradores)
app.delete('/api/users/:id', verifyToken, async (req, res) => {
    if (req.userRole !== 'Administrador') return res.status(403).json({ message: 'Acceso denegado' });

    const userId = req.params.id;
    const userResult = await pool.query('SELECT CI FROM Usuarios WHERE ID = $1', [userId]);
    const user = userResult.rows[0];

    if (!user) return res.status(404).json({ message: 'Usuario no encontrado' });
    if (user.ci === '02022781222') return res.status(403).json({ message: 'No se puede eliminar al administrador principal' });

    try {
        await pool.query('DELETE FROM Admin_Usuarios WHERE UsuariosID = $1', [userId]);
        await pool.query('DELETE FROM Usuarios WHERE ID = $1', [userId]);
        res.json({ message: 'Usuario eliminado' });
    } catch (error) {
        console.error('Error al eliminar usuario:', error);
        res.status(500).json({ message: 'Error en el servidor', error: error.message });
    }
});

// Agregar un nuevo usuario (solo para administradores)
app.post('/api/users', verifyToken, async (req, res) => {
    if (req.userRole !== 'Administrador') return res.status(403).json({ message: 'Acceso denegado' });

    console.log('Datos recibidos en /api/users:', req.body);

    const { nombre, apellido, direccion, ci, telefono, provincia, municipio, celiaco, contrasena, correo_electronico } = req.body;

    const validationErrors = validateRegister(req.body);
    if (Object.keys(validationErrors).length > 0) {
        console.log('Errores de validación en /api/users:', validationErrors);
        return res.status(400).json({ message: 'Errores de validación', errors: validationErrors });
    }

    try {
        const userResult = await pool.query('SELECT * FROM Usuarios WHERE CI = $1', [ci]);
        if (userResult.rows.length > 0) return res.status(400).json({ message: 'Usuario ya registrado' });

        const correoResult = await pool.query('SELECT * FROM Usuarios WHERE correo_electronico = $1', [correo_electronico]);
        if (correoResult.rows.length > 0) {
            return res.status(400).json({ message: 'El correo electrónico ya está registrado' });
        }

        const newUser = await pool.query(
            'INSERT INTO Usuarios (Nombre, Apellido, Direccion, CI, Telefono, Provincia, Municipio, Celiaco, Contrasena, correo_electronico) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *',
            [nombre, apellido, direccion, ci, telefono, provincia, municipio, celiaco, contrasena, correo_electronico]
        );

        await pool.query('INSERT INTO Admin_Usuarios (Rol, UsuariosID) VALUES ($1, $2)', ['Usuario', newUser.rows[0].id]);
        res.status(201).json(newUser.rows[0]);
    } catch (error) {
        console.error('Error al agregar usuario:', error);
        res.status(500).json({ message: 'Error en el servidor', error: error.message });
    }
});

// CRUD para Puntos de Venta (solo para administradores)

// Crear un nuevo punto de venta
app.post('/api/puntos-de-venta', verifyToken, async (req, res) => {
    if (req.userRole !== 'Administrador') return res.status(403).json({ message: 'Acceso denegado' });

    const { nombre, tipo, telefono, provincia, direccion, dia_de_venta } = req.body;

    // Validaciones
    if (!nombre) {
        return res.status(400).json({ message: 'El nombre es obligatorio' });
    }
    if (tipo && !/^[A-Za-zÁÉÍÓÚáéíóúÑñÜü\s]+$/.test(tipo)) {
        return res.status(400).json({ message: 'El tipo debe contener solo letras y espacios' });
    }
    if (provincia && !/^[A-Za-zÁÉÍÓÚáéíóúÑñÜü\s]+$/.test(provincia)) {
        return res.status(400).json({ message: 'La provincia debe contener solo letras y espacios' });
    }
    if (telefono && !/^\d{8}$/.test(telefono)) {
        return res.status(400).json({ message: 'El teléfono debe contener exactamente 8 números' });
    }
    if (dia_de_venta && !Array.isArray(dia_de_venta)) {
        return res.status(400).json({ message: 'Los días de venta deben ser un array' });
    }
    if (dia_de_venta && !dia_de_venta.every(day => ['Lunes', 'Martes', 'Miércoles', 'Jueves', 'Viernes', 'Sábado', 'Domingo'].includes(day))) {
        return res.status(400).json({ message: 'Cada día de venta debe ser un día de la semana válido (Lunes a Domingo)' });
    }

    try {
        const newPunto = await pool.query(
            'INSERT INTO puntos_de_venta (nombre, tipo, telefono, provincia, direccion, dia_de_venta) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [nombre, tipo, telefono, provincia, direccion, dia_de_venta]
        );
        res.status(201).json(newPunto.rows[0]);
    } catch (error) {
        console.error('Error al crear punto de venta:', error);
        res.status(500).json({ message: 'Error en el servidor', error: error.message });
    }
});

// Leer todos los puntos de venta (permitido para Administradores y Usuarios)
app.get('/api/puntos-de-venta', verifyToken, async (req, res) => {
    if (req.userRole !== 'Administrador' && req.userRole !== 'Usuario') {
        return res.status(403).json({ message: 'Acceso denegado' });
    }

    try {
        const puntosResult = await pool.query('SELECT * FROM puntos_de_venta');
        res.json(puntosResult.rows);
    } catch (error) {
        console.error('Error al obtener puntos de venta:', error);
        res.status(500).json({ message: 'Error en el servidor', error: error.message });
    }
});

// Actualizar un punto de venta
app.put('/api/puntos-de-venta/:id', verifyToken, async (req, res) => {
    if (req.userRole !== 'Administrador') return res.status(403).json({ message: 'Acceso denegado' });

    const puntoId = req.params.id;
    const { nombre, tipo, telefono, provincia, direccion, dia_de_venta } = req.body;

    // Validaciones
    if (!nombre) {
        return res.status(400).json({ message: 'El nombre es obligatorio' });
    }
    if (tipo && !/^[A-Za-zÁÉÍÓÚáéíóúÑñÜü\s]+$/.test(tipo)) {
        return res.status(400).json({ message: 'El tipo debe contener solo letras y espacios' });
    }
    if (provincia && !/^[A-Za-zÁÉÍÓÚáéíóúÑñÜü\s]+$/.test(provincia)) {
        return res.status(400).json({ message: 'La provincia debe contener solo letras y espacios' });
    }    
    if (telefono && !/^\d{8}$/.test(telefono)) {
        return res.status(400).json({ message: 'El teléfono debe contener exactamente 8 números' });
    }
    if (dia_de_venta && !Array.isArray(dia_de_venta)) {
        return res.status(400).json({ message: 'Los días de venta deben ser un array' });
    }
    if (dia_de_venta && !dia_de_venta.every(day => ['Lunes', 'Martes', 'Miércoles', 'Jueves', 'Viernes', 'Sábado', 'Domingo'].includes(day))) {
        return res.status(400).json({ message: 'Cada día de venta debe ser un día de la semana válido (Lunes a Domingo)' });
    }

    try {
        const updatedPunto = await pool.query(
            'UPDATE puntos_de_venta SET nombre = $1, tipo = $2, telefono = $3, provincia = $4, direccion = $5, dia_de_venta = $6 WHERE id = $7 RETURNING *',
            [nombre, tipo, telefono, provincia, direccion, dia_de_venta, puntoId]
        );

        if (updatedPunto.rows.length === 0) {
            return res.status(404).json({ message: 'Punto de venta no encontrado' });
        }

        res.json(updatedPunto.rows[0]);
    } catch (error) {
        console.error('Error al actualizar punto de venta:', error);
        res.status(500).json({ message: 'Error en el servidor', error: error.message });
    }
});

// Eliminar un punto de venta
app.delete('/api/puntos-de-venta/:id', verifyToken, async (req, res) => {
    if (req.userRole !== 'Administrador') return res.status(403).json({ message: 'Acceso denegado' });

    const puntoId = req.params.id;

    try {
        const deletedPunto = await pool.query('DELETE FROM puntos_de_venta WHERE id = $1 RETURNING *', [puntoId]);

        if (deletedPunto.rows.length === 0) {
            return res.status(404).json({ message: 'Punto de venta no encontrado' });
        }

        res.json({ message: 'Punto de venta eliminado' });
    } catch (error) {
        console.error('Error al eliminar punto de venta:', error);
        res.status(500).json({ message: 'Error en el servidor', error: error.message });
    }
});

// CRUD para Ofertas (solo para administradores)

// Crear una nueva oferta
app.post('/api/puntos-de-venta/:puntoId/ofertas', verifyToken, async (req, res) => {
    if (req.userRole !== 'Administrador') return res.status(403).json({ message: 'Acceso denegado' });

    const puntoId = req.params.puntoId;
    const { nombre, tipo, gramaje, informacion, precio } = req.body;

    // Validaciones
    if (!nombre) {
        return res.status(400).json({ message: 'El nombre es obligatorio' });
    }
    if (nombre && !/^[A-Za-zÁÉÍÓÚáéíóúÑñÜü\s]+$/.test(nombre)) {
        return res.status(400).json({ message: 'El nombre no debe contener números' });
    }    
    if (gramaje && (gramaje <= 0 || isNaN(gramaje))) {
        return res.status(400).json({ message: 'El gramaje debe ser un número positivo' });
    }
    if (precio && (isNaN(precio) || precio <= 0)) {
        return res.status(400).json({ message: 'El precio debe ser un número positivo' });
    }

    try {
        const newOferta = await pool.query(
            'INSERT INTO ofertas (nombre, tipo, gramaje, informacion, precio, punto_venta_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [nombre, tipo, gramaje, informacion, precio, puntoId]
        );
        res.status(201).json(newOferta.rows[0]);
    } catch (error) {
        console.error('Error al crear oferta:', error);
        res.status(500).json({ message: 'Error en el servidor', error: error.message });
    }
});

// Leer todas las ofertas de un punto de venta (permitido para Administradores y Usuarios)
app.get('/api/puntos-de-venta/:puntoId/ofertas', verifyToken, async (req, res) => {
    if (req.userRole !== 'Administrador' && req.userRole !== 'Usuario') {
        return res.status(403).json({ message: 'Acceso denegado' });
    }

    const puntoId = req.params.puntoId;

    try {
        const ofertasResult = await pool.query('SELECT * FROM ofertas WHERE punto_venta_id = $1', [puntoId]);
        res.json(ofertasResult.rows);
    } catch (error) {
        console.error('Error al obtener ofertas:', error);
        res.status(500).json({ message: 'Error en el servidor', error: error.message });
    }
});

// Actualizar una oferta
app.put('/api/puntos-de-venta/:puntoId/ofertas/:ofertaId', verifyToken, async (req, res) => {
    if (req.userRole !== 'Administrador') return res.status(403).json({ message: 'Acceso denegado' });

    const puntoId = req.params.puntoId;
    const ofertaId = req.params.ofertaId;
    const { nombre, tipo, gramaje, informacion, precio } = req.body;

    // Validaciones
    if (!nombre) {
        return res.status(400).json({ message: 'El nombre es obligatorio' });
    }
    if (nombre && !/^[A-Za-zÁÉÍÓÚáéíóúÑñÜü\s]+$/.test(nombre)) {
        return res.status(400).json({ message: 'El nombre no debe contener números' });
    }    
    if (gramaje && (gramaje <= 0 || isNaN(gramaje))) {
        return res.status(400).json({ message: 'El gramaje debe ser un número positivo' });
    }
    if (precio && (isNaN(precio) || precio <= 0)) {
        return res.status(400).json({ message: 'El precio debe ser un número positivo' });
    }

    try {
        const updatedOferta = await pool.query(
            'UPDATE ofertas SET nombre = $1, tipo = $2, gramaje = $3, informacion = $4, precio = $5 WHERE id = $6 AND punto_venta_id = $7 RETURNING *',
            [nombre, tipo, gramaje, informacion, precio, ofertaId, puntoId]
        );

        if (updatedOferta.rows.length === 0) {
            return res.status(404).json({ message: 'Oferta no encontrada' });
        }

        res.json(updatedOferta.rows[0]);
    } catch (error) {
        console.error('Error al actualizar oferta:', error);
        res.status(500).json({ message: 'Error en el servidor', error: error.message });
    }
});

// Eliminar una oferta
app.delete('/api/puntos-de-venta/:puntoId/ofertas/:ofertaId', verifyToken, async (req, res) => {
    if (req.userRole !== 'Administrador') return res.status(403).json({ message: 'Acceso denegado' });

    const puntoId = req.params.puntoId;
    const ofertaId = req.params.ofertaId;

    try {
        const deletedOferta = await pool.query(
            'DELETE FROM ofertas WHERE id = $1 AND punto_venta_id = $2 RETURNING *',
            [ofertaId, puntoId]
        );

        if (deletedOferta.rows.length === 0) {
            return res.status(404).json({ message: 'Oferta no encontrada' });
        }

        res.json({ message: 'Oferta eliminada' });
    } catch (error) {
        console.error('Error al eliminar oferta:', error);
        res.status(500).json({ message: 'Error en el servidor', error: error.message });
    }
});

// CRUD para Publicaciones (consolidado)

// Crear una nueva publicación con imagen (solo para administradores)
app.post('/api/publicaciones', verifyToken, upload.single('imagen'), async (req, res) => {
    if (req.userRole !== 'Administrador') return res.status(403).json({ message: 'Acceso denegado' });
  
    console.log('Received body:', req.body);
    console.log('Received file:', req.file);
  
    const { titulo, contenido } = req.body;
    const imagenBuffer = req.file ? req.file.buffer.toString('base64') : null;
  
    if (!titulo) return res.status(400).json({ message: 'El título es obligatorio' });
    if (!contenido) return res.status(400).json({ message: 'El contenido es obligatorio' });
  
    try {
      const newPublicacion = await pool.query(
        'INSERT INTO publicaciones (titulo, contenido, autor_id, imagen) VALUES ($1, $2, $3, $4) RETURNING *',
        [titulo, contenido, req.userId, imagenBuffer]
      );
  
      const result = newPublicacion.rows[0];
      res.status(201).json({
        ...result,
        imagen: result.imagen ? `data:image/jpeg;base64,${result.imagen}` : null
      });
    } catch (error) {
      console.error('Error al crear publicación:', error);
      res.status(500).json({ message: 'Error en el servidor', error: error.message });
    }
  });

// Leer todas las publicaciones (permitido para Administradores y Usuarios)
app.get('/api/publicaciones', verifyToken, async (req, res) => {
  if (req.userRole !== 'Administrador' && req.userRole !== 'Usuario') {
    return res.status(403).json({ message: 'Acceso denegado' });
  }

  try {
    const publicacionesResult = await pool.query(
      'SELECT p.*, u.nombre AS autor_nombre FROM publicaciones p JOIN usuarios u ON p.autor_id = u.id ORDER BY p.fecha_creacion DESC'
    );
    // Convertir imágenes base64 a formato usable en el frontend
    const publicacionesConImagen = publicacionesResult.rows.map(pub => ({
      ...pub,
      imagen: pub.imagen ? `data:image/jpeg;base64,${pub.imagen}` : null
    }));
    res.json(publicacionesConImagen);
  } catch (error) {
    console.error('Error al obtener publicaciones:', error);
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

// Actualizar una publicación con imagen (solo para administradores)
app.put('/api/publicaciones/:id', verifyToken, upload.single('imagen'), async (req, res) => {
    if (req.userRole !== 'Administrador') return res.status(403).json({ message: 'Acceso denegado' });
  
    console.log('Received body:', req.body);
    console.log('Received file:', req.file);
  
    const publicacionId = req.params.id;
    const { titulo, contenido, removeImage } = req.body;
    const imagenBuffer = req.file ? req.file.buffer.toString('base64') : undefined;
  
    if (!titulo) return res.status(400).json({ message: 'El título es obligatorio' });
    if (!contenido) return res.status(400).json({ message: 'El contenido es obligatorio' });
  
    try {
      const updateFields = [];
      const values = [titulo, contenido, publicacionId];
      let query = 'UPDATE publicaciones SET titulo = $1, contenido = $2';
  
      if (imagenBuffer !== undefined) {
        updateFields.push('imagen = $3');
        values.push(imagenBuffer);
      } else if (removeImage === 'true') {
        updateFields.push('imagen = NULL');
      }
  
      query += updateFields.length > 0 ? `, ${updateFields.join(', ')}` : '';
      query += ' WHERE id = $' + (values.length) + ' RETURNING *';
  
      const updatedPublicacion = await pool.query(query, values);
  
      if (updatedPublicacion.rows.length === 0) {
        return res.status(404).json({ message: 'Publicación no encontrada' });
      }
  
      const result = updatedPublicacion.rows[0];
      res.json({
        ...result,
        imagen: result.imagen ? `data:image/jpeg;base64,${result.imagen}` : null
      });
    } catch (error) {
      console.error('Error al actualizar publicación:', error);
      res.status(500).json({ message: 'Error en el servidor', error: error.message });
    }
  });
    
// Eliminar una publicación (solo para administradores)
app.delete('/api/publicaciones/:id', verifyToken, async (req, res) => {
    if (req.userRole !== 'Administrador') return res.status(403).json({ message: 'Acceso denegado' });

    const publicacionId = req.params.id;

    try {
        const deletedPublicacion = await pool.query(
            'DELETE FROM publicaciones WHERE id = $1 RETURNING *',
            [publicacionId]
        );

        if (deletedPublicacion.rows.length === 0) {
            return res.status(404).json({ message: 'Publicación no encontrada' });
        }

        res.json({ message: 'Publicación eliminada' });
    } catch (error) {
        console.error('Error al eliminar publicación:', error);
        res.status(500).json({ message: 'Error en el servidor', error: error.message });
    }
});


app.listen(process.env.PORT || 5000, '0.0.0.0', () => {
    console.log(`Servidor corriendo en el puerto ${process.env.PORT || 5000}`);
});