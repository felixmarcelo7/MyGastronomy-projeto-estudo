import express from 'express';
import passport from 'passport';
import LocalStrategy from 'passport-local'; // Estratégia de login local (email/senha)
import crypto from 'crypto'; // Módulo nativo de criptografia
import { Mongo } from '../src/database/mongo.js'; // Conexão com o banco MongoDB
import jwt from 'jsonwebtoken'; // Geração de tokens JWT
import { ObjectId } from 'mongodb'; // Utilizado para manipular IDs do MongoDB
import { text } from 'stream/consumers';
import { error } from 'console';

const collectionName = 'users'; // Nome da coleção no banco

// Configuração da estratégia de autenticação com Passport
passport.use(
  new LocalStrategy(
    { usernameField: 'email' }, // Indica que o campo "email" será usado como usuário
    async (email, password, callback) => {
      // Procura o usuário pelo e-mail
      const user = await Mongo.db
        .collection(collectionName)
        .findOne({ email: email });

      // Se o usuário não for encontrado, retorna erro
      if (!user) {
        return callback(null, false);
      }

      const saltBuffer = user.salt.saltBuffer; // Recupera o salt salvo no cadastro

      // Recalcula o hash da senha informada no login
      crypto.pbkdf2(
        password,
        saltBuffer,
        310000,
        16,
        'sha256',
        (err, hashedPassword) => {
          if (err) {
            return callback(null, false);
          }

          // Converte a senha armazenada em buffer para comparar
          const usePasswordBuffer = Buffer.from(user.password.buffer);

          // Compara as senhas de forma segura (evita ataques de tempo)
          if (!crypto.timingSafeEqual(usePasswordBuffer, hashedPassword)) {
            return callback(null, false);
          }

          // Remove dados sensíveis antes de retornar o usuário autenticado
          const { passport, salt, ...rest } = user;

          // Login bem-sucedido, retorna o usuário
          return callback(null, rest);
        }
      );
    }
  )
);

// Criação do router para autenticação
const authRouter = express.Router();

// Rota de cadastro de usuário
authRouter.post('/signup', async (req, res) => {
  // Verifica se o usuário já existe pelo e-mail
  const checkUser = await Mongo.db
    .collection(collectionName)
    .findOne({ email: req.body.email });

  // Se já existir, retorna erro
  if (checkUser) {
    return res.status(500).send({
      success: false,
      statusCode: 500,
      body: {
        text: 'User already exists!',
      },
    });
  }

  // Gera um salt aleatório para a senha
  const salt = crypto.randomBytes(16);

  // Gera o hash da senha usando o salt
  crypto.pbkdf2(
    req.body.password,
    salt,
    310000,
    16,
    'sha256',
    async (err, hashedPassword) => {
      if (err) {
        // Retorna erro se falhar ao gerar hash
        return res.status(500).send({
          success: false,
          statusCode: 500,
          body: {
            text: 'Error on crypto password!',
            err: err,
          },
        });
      }

      // Insere o novo usuário no banco de dados
      const result = await Mongo.db.collection(collectionName).insertOne({
        email: req.body.email,
        password: hashedPassword, // Armazena o hash da senha
        salt, // Armazena o salt usado na criptografia
      });

      // Se inserção foi bem-sucedida
      if (result.insertedId) {
        // Busca o usuário recém-criado
        const user = await Mongo.db
          .collection(collectionName)
          .findOne({ _id: new ObjectId(result.insertedId) });

        // Gera um token JWT com os dados do usuário
        const token = jwt.sign(user, 'secret');

        // Retorna resposta de sucesso com token e dados do usuário
        return res.send({
          success: true,
          statusCode: 200,
          body: {
            text: 'User registered correctly!',
            token,
            user,
            logged: true,
          },
        });
      }
    }
  );
});

// Exporta o router para ser usado no servidor principal
export default authRouter;
