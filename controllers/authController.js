const Usuario = require('../models/Usuario');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken')
require('dotenv').config({path:'variables.env'});
const { validationResult } = require('express-validator');



exports.autenticarUsuario = async (req,res, next) => {

       //  //Revisar si hay errores
       const errores = validationResult(req);
    
       if (!errores.isEmpty()) {
           return res.status(400).json({errores: errores.array()})
       }

  


    // Buscar el usuario par ver si esta registrado

    const { email, password } = req.body;

    const usuario = await Usuario.findOne({email});
    //console.log(usuario)

    if(!usuario) {
        res.status(401).json({msg: 'El Usuario No Existe'});
        return next();
    }

    // Verificar elpassword y autenticar el usuario

    if(bcrypt.compareSync(password, usuario.password)) {
        //Crear JWT!
        
        const token = jwt.sign({
            nombre: usuario.nombre,
            id: usuario._id,
            email: usuario.email
        }, process.env.SECRETA,{
            expiresIn:'48h'
        });

        res.json({token});




    } else {
        res.status(401).json({msg:'Password Incorrecto'})
        return next();
    }

   
    
    //const usuariok = await Usuario.password({password})
    

}

exports.usuarioAuntenticado = (req, res, next) => {

    res.json({usuario: req.usuario});
}
