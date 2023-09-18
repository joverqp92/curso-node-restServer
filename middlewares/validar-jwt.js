const { response, request } = require('express');
const  jwt = require('jsonwebtoken');

const Usuario = require('../models/usuario');

const validarJWT = async( req = request, res = response, next ) => {

    const token = req.header('x-token');

    if ( !token ){
        return res.status(401).json({
            msg: 'No hay token en la petición'
        })
    }

    try {

        const { uid } = jwt.verify(token, process.env.SECRETORPRIVATEKEY);

        //LEER EL USUARIO QUE CORRESPONDE AL UID
        const usuario = await Usuario.findById( uid );
        if( !usuario ){
            return res.status(401).json({
                msg: 'token no válido - usuario no existe en DB'
            })
        }

        //VERIFICAR SI EL UID TIENE EL ESTADO EN TRUE
        if ( !usuario.estado ) {
            return res.status(401).json({
                msg: 'token no válido - usuario con estado false'
            })
        }

        req.usuario = usuario;
        next();

    } catch (error) {

        console.log(error)
        res.status(401).json({
            msg: 'Token no válido'
        })
    }

}






module.exports = {
    validarJWT
}