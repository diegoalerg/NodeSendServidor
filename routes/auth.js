const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { check } = require('express-validator');
const auth = require('../middleware/auth')

router.post('/', [
        check('email','Afrega un email valido').isEmail(),
        check('password','El password no puede ir vacio').not().isEmpty()
],
 authController.autenticarUsuario)

 router.get('/', [

],
 auth,   
 authController.usuarioAuntenticado
 )


 module.exports = router;