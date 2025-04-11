const mongoose = require("mongoose");

const TaskSchema = new mongoose.Schema({
    nametask: { 
        type: String, 
        required: [true, "El nombre de la tarea es obligatorio"],
        trim: true,
        maxlength: [100, "El nombre no puede exceder 100 caracteres"]
    },
    description: { 
        type: String, 
        required: [true, "La descripción es obligatoria"],
        trim: true
    },
    dead_line: { 
        type: Date, 
        required: [true, "La fecha límite es obligatoria"],
        validate: {
            validator: function(value) {
                return value > new Date();
            },
            message: "La fecha límite debe ser en el futuro"
        }
    },
    remind_me: { 
        type: Date,
        validate: {
            validator: function(value) {
                return !value || value > new Date();
            },
            message: "El recordatorio debe ser en el futuro"
        }
    },
    status: {
        type: String,
        required: true,
        enum: {
            values: ["In Progress", "Done", "Paused", "Revision"],
            message: "Estado no válido"
        },
        default: "In Progress"
    },
    category: { 
        type: String, 
        required: true,
        enum: ["Work", "Study", "Personal"]
    },
    createdBy: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: "User", 
        required: true 
    }
}, { 
    timestamps: true 
});

module.exports = mongoose.model("Task", TaskSchema);