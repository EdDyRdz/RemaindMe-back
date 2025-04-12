app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "https://remaindme-front.onrender.com");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.header("Access-Control-Allow-Credentials", "true"); // Para cookies
  next();
});

const express = require("express");
const cors = require("cors");
const conectarDB = require("./database");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const Task = require("./models/Task");
const User = require("./models/User");
const mongoose = require("mongoose");
const speakeasy = require('speakeasy');

require("dotenv").config();

conectarDB();

const app = express();
app.use(cors());
app.use(express.json());

app.use(cors({
  origin: [
    "https://remaindme-front.onrender.com", // Dominio de producción
    "http://localhost:3000" // Para desarrollo local
  ],
  credentials: true, // Si usas cookies/tokens
  methods: ["GET", "POST", "PUT", "DELETE"]
  }));

const PORT = process.env.PORT || 10000;

const authenticate = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).json({ error: "Acceso denegado. Token no proporcionado." });
    }

    try {
        const decoded = jwt.verify(token.split(" ")[1], process.env.JWT_SECRET || "secret-key");
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ error: "Token inválido" });
    }
};

app.post("/api/auth/register", async (req, res) => {
    try {
        const { username, email, password } = req.body;

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: "El usuario ya existe" });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Generar secreto MFA automáticamente
        const secret = speakeasy.generateSecret({
            name: `RemindMe:${email}`,
            issuer: "RemindMe"
        });

        const newUser = new User({ 
            username, 
            email, 
            password: hashedPassword,
            mfaSecret: secret.base32,
            mfaEnabled: true
        });

        await newUser.save();

        res.status(201).json({ 
            message: "Usuario registrado correctamente",
            mfaSecret: secret.base32,
            mfaQR: secret.otpauth_url
        });
    } catch (error) {
        res.status(500).json({ error: "Error al registrar usuario", details: error.message });
    }
});

app.post("/api/auth/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: "Usuario no encontrado" });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: "Contraseña incorrecta" });
        }

        user.last_login = new Date();
        await user.save();

        return res.json({ 
            message: "Se requiere verificación MFA", 
            mfaRequired: true,
            tempToken: jwt.sign(
                { userId: user._id, mfaPending: true },
                process.env.JWT_SECRET || "secret-key",
                { expiresIn: "5m" }
            ),
            email: user.email
        });
    } catch (error) {
        res.status(500).json({ error: "Error al iniciar sesión", details: error.message });
    }
});

app.post("/api/auth/verify-mfa", async (req, res) => {
    try {
        const { tempToken, mfaToken } = req.body;
        
        // Validación más robusta
        if (!tempToken || !mfaToken) {
            return res.status(400).json({ 
                error: "Se requieren tempToken y mfaToken",
                details: {
                    received: {
                        tempToken: !!tempToken,
                        mfaToken: !!mfaToken
                    }
                }
            });
        }

        if (!/^\d{6}$/.test(mfaToken)) {
            return res.status(400).json({ 
                error: "El mfaToken debe ser un código de 6 dígitos" 
            });
        }

        let decoded;
        try {
            decoded = jwt.verify(tempToken, process.env.JWT_SECRET || "secret-key");
        } catch (jwtError) {
            return res.status(400).json({ 
                error: "Token temporal inválido o expirado",
                details: jwtError.message
            });
        }

        if (!decoded.mfaPending) {
            return res.status(400).json({ 
                error: "Token no es para verificación MFA" 
            });
        }

        const user = await User.findById(decoded.userId);
        if (!user) {
            return res.status(404).json({ 
                error: "Usuario no encontrado" 
            });
        }

        // Verificar el token MFA
        const verified = speakeasy.totp.verify({
            secret: user.mfaSecret,
            encoding: 'base32',
            token: mfaToken,
            window: 2 // Permite un margen de 2 intervalos (60 segundos)
        });

        if (!verified) {
            return res.status(400).json({ 
                error: "Token MFA inválido",
                details: {
                    secretConfigured: !!user.mfaSecret,
                    mfaEnabled: user.mfaEnabled
                }
            });
        }

        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET || "secret-key",
            { expiresIn: "1h" }
        );

        res.json({ 
            success: true,
            message: "Verificación MFA exitosa", 
            token, 
            user: {
                _id: user._id,
                email: user.email,
                username: user.username
            }
        });
    } catch (error) {
        console.error("Error en verify-mfa:", error);
        res.status(500).json({ 
            error: "Error interno verificando MFA", 
            details: error.message 
        });
    }
});

app.post("/api/tasks", authenticate, async (req, res) => {
    try {
        const { nametask, description, dead_line, remind_me, status, category } = req.body;

        // Validaciones adicionales
        if (remind_me && dead_line && new Date(remind_me) > new Date(dead_line)) {
            return res.status(400).json({ 
                error: "El recordatorio debe ser antes de la fecha límite" 
            });
        }

        if (remind_me && new Date(remind_me) < new Date()) {
            return res.status(400).json({ 
                error: "El recordatorio debe ser en el futuro" 
            });
        }

        const newTask = new Task({
            nametask,
            description,
            dead_line,
            remind_me,
            status,
            category,
            createdBy: req.user.userId,
            reminderSent: false
        });

        await newTask.save();
        res.status(201).json({ message: "Tarea agregada correctamente", task: newTask });
    } catch (error) {
        console.error("Error al agregar la tarea:", error);
        res.status(500).json({ error: "Error al agregar la tarea", details: error.message });
    }
});

app.get("/api/tasks", authenticate, async (req, res) => {
    try {
      const tasks = await Task.find({ 
        createdBy: new mongoose.Types.ObjectId(req.user.userId)
      })
      .sort({ dead_line: 1 })
      .lean();
      
      const formattedTasks = tasks.map(task => ({
        ...task,
        _id: task._id.toString(),
        dead_line: task.dead_line ? new Date(task.dead_line).toISOString() : null,
        remind_me: task.remind_me ? new Date(task.remind_me).toISOString() : null,
        createdBy: task.createdBy.toString()
      }));
      
      res.status(200).json(formattedTasks);
    } catch (error) {
      console.error("Error:", error);
      res.status(500).json({ error: "Error al obtener tareas", details: error.message });
    }
  });

  app.put("/api/tasks/:id/status", authenticate, async (req, res) => {
    try {
      const { status } = req.body;
      const taskId = req.params.id;
      
      // Validar el estado
      const validStatuses = ["In Progress", "Done", "Paused", "Revision"];
      if (!validStatuses.includes(status)) {
        return res.status(400).json({ error: "Estado no válido" });
      }
  
      const updatedTask = await Task.findOneAndUpdate(
        { 
          _id: taskId,
          createdBy: req.user.userId 
        },
        { status },
        { new: true }
      );
  
      if (!updatedTask) {
        return res.status(404).json({ error: "Tarea no encontrada" });
      }
  
      res.json(updatedTask);
    } catch (error) {
      console.error("Error al actualizar estado:", error);
      res.status(500).json({ error: "Error al actualizar estado", details: error.message });
    }
  });
  
  app.delete("/api/tasks/:id", authenticate, async (req, res) => {
    try {
        const taskId = req.params.id;
        
        const task = await Task.findOne({
            _id: taskId,
            createdBy: req.user.userId
        });
        
        if (!task) {
            return res.status(404).json({ 
                error: "Tarea no encontrada o no tienes permisos para eliminarla" 
            });
        }

        await Task.deleteOne({ _id: taskId });
        
        res.status(200).json({ 
            message: "Tarea eliminada exitosamente",
            deletedTaskId: taskId
        });
        
    } catch (error) {
        console.error("Error al eliminar tarea:", error);
        res.status(500).json({ 
            error: "Error al eliminar la tarea",
            details: error.message 
        });
    }
});

app.get("/api/users", authenticate, async (req, res) => {
    try {
        const users = await User.find({}, "name email");
        res.json(users);
    } catch (error) {
        console.error("Error al obtener usuarios:", error);
        res.status(500).json({ error: "Error al obtener usuarios" });
    }
});

app.get("/api/currentUser", authenticate, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId)
            .select('-password -mfaSecret -__v'); // Excluimos datos sensibles
        
        if (!user) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }

        res.json(user);
    } catch (error) {
        console.error("Error al obtener usuario:", error);
        res.status(500).json({ error: "Error al obtener información del usuario" });
    }
});

app.post("/api/requestPasswordChange", authenticate, async (req, res) => {
    try {
      const { currentPassword } = req.body;
      const user = await User.findById(req.user.userId);
      
      if (!user) {
        return res.status(404).json({ error: "Usuario no encontrado" });
      }
  
      const validPassword = await bcrypt.compare(currentPassword, user.password);
      if (!validPassword) {
        return res.status(400).json({ error: "Contraseña actual incorrecta" });
      }
  
      // Generar token temporal para el cambio de contraseña
      const tempToken = jwt.sign(
        { userId: user._id, action: "password-change" },
        process.env.JWT_SECRET || "secret-key",
        { expiresIn: "5m" }
      );
  
      res.json({ 
        success: true,
        message: "Por favor verifica con tu código MFA",
        tempToken 
      });
    } catch (error) {
      console.error("Error en requestPasswordChange:", error);
      res.status(500).json({ 
        error: "Error al solicitar cambio de contraseña", 
        details: error.message 
      });
    }
  });
  
  app.post("/api/verifyPasswordChange", async (req, res) => {
    try {
      const { tempToken, mfaCode, newPassword, confirmPassword } = req.body;
      
      // Validaciones básicas
      if (!tempToken || !mfaCode || !newPassword || !confirmPassword) {
        return res.status(400).json({ 
          error: "Faltan campos requeridos",
          details: {
            received: {
              tempToken: !!tempToken,
              mfaCode: !!mfaCode,
              newPassword: !!newPassword,
              confirmPassword: !!confirmPassword
            }
          }
        });
      }
  
      if (newPassword !== confirmPassword) {
        return res.status(400).json({ error: "Las contraseñas no coinciden" });
      }
  
      // Verificar token temporal
      let decoded;
      try {
        decoded = jwt.verify(tempToken, process.env.JWT_SECRET || "secret-key");
      } catch (error) {
        return res.status(400).json({ error: "Token inválido o expirado" });
      }
  
      if (decoded.action !== "password-change") {
        return res.status(400).json({ error: "Token no válido para esta acción" });
      }
  
      // Verificar usuario
      const user = await User.findById(decoded.userId);
      if (!user) {
        return res.status(404).json({ error: "Usuario no encontrado" });
      }
  
      // Verificar MFA
      const verified = speakeasy.totp.verify({
        secret: user.mfaSecret,
        encoding: 'base32',
        token: mfaCode,
        window: 2
      });
  
      if (!verified) {
        return res.status(400).json({ error: "Código MFA inválido" });
      }
  
      // Validar nueva contraseña
      if (newPassword.length < 6) {
        return res.status(400).json({ error: "La contraseña debe tener al menos 6 caracteres" });
      }
  
      // Verificar que no sea igual a la anterior
      const isSamePassword = await bcrypt.compare(newPassword, user.password);
      if (isSamePassword) {
        return res.status(400).json({ error: "La nueva contraseña debe ser diferente a la actual" });
      }
  
      // Actualizar contraseña
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(newPassword, salt);
      
      user.password = hashedPassword;
      await user.save();
  
      res.json({ 
        success: true,
        message: "Contraseña cambiada exitosamente" 
      });
    } catch (error) {
      console.error("Error en verifyPasswordChange:", error);
      res.status(500).json({ 
        error: "Error al verificar cambio de contraseña", 
        details: error.message 
      });
    }
  });

  app.get('/api/tasks/active-reminders', authenticate, async (req, res) => {
    try {
      const now = new Date();
      // Ajustamos para que coincida exactamente con el momento del recordatorio
      const threshold = new Date(now.getTime() + 30000); // Reducir a 30 segundos de margen
  
      const tasks = await Task.find({
        createdBy: req.user.userId,
        remind_me: { 
          $lte: threshold,
          $gte: now
        },
        status: { $ne: 'Done' }
      });
  
      const reminders = tasks.map(task => ({
        taskId: task._id,
        taskName: task.nametask,
        reminderTime: task.remind_me,
        message: `Recordatorio: ${task.nametask} - ${task.description}`,
        // Añadir información de zona horaria
        timezoneOffset: new Date().getTimezoneOffset()
      }));
  
      res.status(200).json(reminders);
    } catch (error) {
      console.error('Error getting active reminders:', error);
      res.status(500).json({ error: "Error al obtener recordatorios activos" });
    }
  });

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});