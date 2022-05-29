// Aplicación de Tienda

/*
    GET consultarProductos
    GET consultarProducto/:id
    POST login
    POST comprar
    POST crearProducto
    POST borrarProducto
    POST modificarProducto
*/

// Nota: Nn middleware es una función que se ejecuta antes de llamar a un método

// Importamos Express
const express = require('express')
const app = express()
app.use(express.json()) // Creamos un middleware // Nota: "use" es un middleware. En este caso es para decodificar el JSON que va en el body de las peticiones

// Importamos Rate Limit
const rateLimit = require('express-rate-limit')
const limite = rateLimit({
	windowMs: 15 * 60 * 1000,   // 15 minutos (1000ms * 60 segundos = 6000ms  y  6000 * 15 = 15 mins)
	max: 100,                   // Limitamos a 100 peticiones cada IP (cada 15 mins)
	standardHeaders: true,      // Return rate limit info in the `RateLimit-*` headers
	legacyHeaders: false,       // Disable the `X-RateLimit-*` headers
})
app.use(limite) // Creamos un middleware

// Importamos HTTPS
const fs = require('fs');
const https = require('https');

// Importamos Util para sobreescribir el console.log
const util = require('util');
const fichero_logs = fs.createWriteStream(__dirname + '/debug.log', {flags : 'w'});

// Importamos JWT (JSON Web Token)
const jwt = require('jsonwebtoken')

// Importamos SQLite
const sqlite3 = require('sqlite3');

// Creamos la base de datos
const db = new sqlite3.Database('./midb.db');

// Declaro una clave secreta para generar y desifrar a partir de ella los token
const secreto = '!cwJr)$/$aT+_]+6SR^%DYu<bDkh~7C*9Bx4$KXM7QM[Zre~kHg83$.4u$2{6!&%'

// Elegimos el puerto de escucha
const PORT = 8443;


// Creamos un middleware para comprobar en el JWT si el que está realizando la llamada tiene el rol de Administrador
function comprobarRolAdministrador (req, res, next) {
    let token = req.headers.authorization
    token = token.slice(7, token.lenght)     // Eliminamos la palabra "Bearer" de la cabecera del token
    try {   // Verificamos que el token es válido (para ello necesitamos el "Secreto", y si no es válido devolvemos un 401)
        let decode = jwt.verify(token, secreto)
        if (decode.data.administrador !== 1 ) return res.writeHead(401).end()
    } catch (error) {
        return res.writeHead(401).end() // 401 Unauthorized
    }
    next()
}

// Creamos un middleware para comprobar en el JWT si el que está realizando la llamada tiene el rol de Cliente
function comprobarRolCliente (req, res, next) {
    let token = req.headers.authorization
    token = token.slice(7, token.lenght)     // Eliminamos la palabra "Bearer" de la cabecera del token
    try {   // Verificamos que el token es válido (para ello necesitamos el "Secreto", y si no es válido devolvemos un 401)
        let decode = jwt.verify(token, secreto)
        if (decode.data.administrador !== 0 ) return res.writeHead(401).end()
    } catch (error) {
        return res.writeHead(401).end() // 401 Unauthorized
    }
    next()
}

// Método para consultar listado de todos los productos de la tienda
app.get('/consultarProductos', (req,res) => {
    db.all('SELECT * FROM Productos', (error, rows) => {
        if (error) {
            console.error(error)
            res.writeHead(500) // 500 Internal Server Error
            return res.end()
        }
        res.send(rows)
    })
})

// Método para consultar un producto concreto de la tienda
app.get('/consultarProducto/:id', (req,res) => {
    let id = req.params.id
    if (!id.match(/^[0-9]{1,19}$/)) return res.writeHead(400).end() // Comprobamos esto aquí porque los parámetros de la URL se tratan como un string   // 400 Bad Request
    if (id > 9223372036854775807) return res.writeHead(400).end()   // Para el BufferOverFlow   // 400 Bad Request
    db.get('SELECT * FROM Productos WHERE id = ?', [id], (error, rows) => {
        if (error) {
            console.error(error)
            res.writeHead(500) // 500 Internal Server Error
            return res.end()
        }
        res.send(rows)
    })
})

// Método para autenticar a un administrador
app.post('/login', (req,res) => {
    let usuario = String(req.body.usuario)
    let contrasena = String(req.body.contrasena)
    if (usuario.length > 50 || contrasena.length > 50) return res.writeHead(400).end()  // 400 Bad Request
    db.get('SELECT * FROM Usuarios WHERE usuario = ? AND contrasena = ?', [usuario, contrasena], (error, row) => {
        if (error) {
            console.error(error)
            res.writeHead(500) // 500 Internal Server Error // Error en los datos recibidos por el usuario
            return res.end()
        }
        if (!row) {
            console.log = fichero_logs.write(new Date() + " " + req.socket.remoteAddress + " Login fallido. Usuario: " + usuario + '\n')
            return res.writeHead(401).end() // 401 Unauthorized
        }
        console.log = fichero_logs.write(new Date() + " " + req.socket.remoteAddress + " Login exitoso. Usuario: " + usuario + '\n')
        let token = jwt.sign(
            {
                data: { // Datos que van dentro del Token
                    usuario: row.usuario,
                    administrador: row.administrador
                }
            }, secreto, { expiresIn: '1h' }) // Nota: el secreto es una cadena aleatoria que va a servir para generar los token y verificarlos luego
        
        res.send({  // Mandamos al usuario el token en formato JSON
            token: token
        })
    })
})

app.post('/comprar', comprobarRolCliente, (req,res) => {    // Nota: Comprobamos que sea cliente, porque solo el cliente puede comprar
    let id = req.body.id
    if (id > 9223372036854775807) return res.writeHead(400).end()
    db.get('SELECT * FROM Productos WHERE id = ?', [id], (error, row) => {
        if (error) {
            console.error(error)
            res.writeHead(500) // Error en los datos recibidos por el usuario
            return res.end()
        }
        if (!row) return res.writeHead(404).end() // Error en los datos recibidos por el usuario
        res.send({
            mensaje: 'El producto se ha comprado correctamente',
            producto: row
        }
        )
    })
})

// Método para crear un nuevo producto en la tienda
app.post('/crearProducto', comprobarRolAdministrador, (req,res) => {
    let nombre = String(req.body.nombre)
    let precio = req.body.precio
    let descripcion = String(req.body.descripcion)
    let calorias = req.body.calorias
    if (nombre.length > 50) return res.writeHead(400).end()
    if (typeof(precio) != "number") return res.writeHead(400).end()
    if (descripcion.length > 400) return res.writeHead(400).end()
    if (typeof(calorias) != "number" || calorias > 9223372036854775807) return res.writeHead(400).end()
    db.run('INSERT INTO Productos (nombre, precio, descripcion, calorias) VALUES (?, ?, ?, ?)', [nombre, precio, descripcion, calorias], (error) => { // Nota: el "id" no lo metemos ya que lo metimos como "autoincremetar" en la base de datos
        if (error) {
            console.error(error)
            res.writeHead(400) // Error en los datos recibidos por el usuario
            return res.end()
        }
        console.log = fichero_logs.write(new Date() + " " + req.socket.remoteAddress + " Producto creado. Producto: " + nombre + " " + precio + " " + descripcion + " " + calorias + '\n')
        res.writeHead(200).end()
    })
})

// Método para borrar un producto de la tienda
app.post('/borrarProducto', comprobarRolAdministrador, (req,res) => {
    let id = req.body.id
    if (id > 9223372036854775807) return res.writeHead(400).end()
    db.run('DELETE FROM Productos WHERE id = ?', [id], (error) => {
        if (error) {
            console.error(error)
            res.writeHead(400) // Error en los datos recibidos por el usuario
            return res.end()
        }
        console.log = fichero_logs.write(new Date() + " " + req.socket.remoteAddress + " Producto borrado. Producto: " + req.body.id + '\n')
        res.writeHead(200).end()
    })
})

// Método para modificar un producto de la tienda
app.post('/modificarProducto', comprobarRolAdministrador, (req,res) => {
    let nombre = String(req.body.nombre)
    let precio = req.body.precio
    let descripcion = String(req.body.descripcion)
    let calorias = req.body.calorias
    let id = req.body.id
    if (nombre.length > 50) return res.writeHead(400).end()
    if (typeof(precio) != "number") return res.writeHead(400).end()
    if (descripcion.length > 400) return res.writeHead(400).end()
    if (typeof(calorias) != "number" || calorias > 9223372036854775807) return res.writeHead(400).end()
    if (typeof(id) != "number" || id > 9223372036854775807) return res.writeHead(400).end()
    db.run('UPDATE Productos SET nombre = ?, precio = ?, descripcion = ?, calorias= ? WHERE id = ?', [nombre, precio, descripcion, calorias, id], (error) => {
        if (error) {
            console.error(error)
            res.writeHead(400) // Error en los datos recibidos por el usuario
            return res.end()
        }
        console.log = fichero_logs.write(new Date() + " " + req.socket.remoteAddress + " Producto modificado. Producto ID: " + nombre + " " + precio + " " + descripcion + " " + calorias + " " + id + '\n')
        res.writeHead(200).end()
    })
})

// Arrancar el servicio
https.createServer({
    key: fs.readFileSync('my_cert.key'),
    cert: fs.readFileSync('my_cert.crt')
  }, app).listen(PORT)