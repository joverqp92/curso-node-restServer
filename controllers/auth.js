const { response } = require('express');
const bcryptjs = require('bcryptjs')

const Usuario = require('../models/usuario');

const { generarJWT } = require('../helpers/generar-.JWT');
const { googleVerify } = require('../helpers/google-verify');


const login = async( req, res = response ) => {
    
    const { correo, password } = req.body;

    try {

        //VERIFICAR SI EL EMAIL EXISTE
        const usuario = await Usuario.findOne({ correo });
        if ( !usuario ){
            return res.status(400).json({
                msg: 'Usuario / Password no son correctos - correo'
            });
        }


        //SI EL USUARIO ESTÁ ACTIVO
        if ( !usuario.estado ){
            return res.status(400).json({
                msg: 'Usuario / Password no son correctos - estado: false'
            });
        }


        //VERIFICAR LA CONTRASEÑA
        const validPassword = bcryptjs.compareSync( password, usuario.password );
        if( !validPassword ){
            return res.status(400).json({
                msg: 'Usuario / Password no son correctos - password'
            });
        }


        //GENERAR EL JWT
        const token = await generarJWT( usuario.id );

        res.json({
            usuario,
            token
            
        })
    
    } catch (error) {
        console.log(error)
        res.status(500).json({
            msg: 'Hable con el administrador'
        })
    }

}

const googleSignin = async( req, res = response) => {

    const { id_token } = req.body;

    try {

        const { correo, nombre, img } = await googleVerify( id_token );

        let usuario = await Usuario.findOne({ correo });

        if ( !usuario ){
            //TENGO QUE CREARLO
            const data = {
                nombre,
                correo,
                password: ':P',
                img,
                rol : 'USER_ROLE',
                google: true,
            };

            usuario = new Usuario( data );
            await usuario.save();
        }

        //SI EL USUARIO EN BD
        if ( !usuario.estado ) {
            return res.status(401).json({
                msg: 'Hable con el administrador, usuario bloqueado'
            });
        }

        //GENERAR EL JWT
        const token = await generarJWT( usuario.id );
    
        res.json({
            usuario,
            token
        });
        
    } catch (error) {

        res.status(400).json({
            msg: 'Token de google no es válido'
        })
    }

}


module.exports = {
    login,
    googleSignin
}