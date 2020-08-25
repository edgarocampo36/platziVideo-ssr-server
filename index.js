const express = require("express");
const passport = require("passport");
const boom = require("@hapi/boom");
const cookieParser = require("cookie-parser");
const axios = require("axios");
const session = require("express-session");
const helmet = require("helmet");

//Archivo de configuracion
const { config } = require("./config");

//Variables de tiempo para la cookie
const THIRTY_DAYS_IN_SECONDS = 2592000;
const TWO_HOURS_IN_SECONDS = 7200;

//Aplicacion de Express
const app = express();

// body parser - para leer del body el archivo JSON (por ej en createMovies)
app.use(express.json());
app.use(helmet());
app.use(cookieParser()); //Middleware de cookie parser
app.use(session({ secret: config.sessionSecret })); //Middleware de manejo de sesion activa
app.use(passport.initialize()); //Inicializamos la sesion con passport
app.use(passport.session()); //Mantenemos la sesion activa

//Basic Strategy
require("./utils/auth/strategies/basic");

//OAuth Strategy
require("./utils/auth/strategies/oauth");

//Google Strategy (OpenIDConnect)
require("./utils/auth/strategies/google");

//Twitter Strategy
//require("./utils/auth/strategies/twitter");

//Linkedin Strategy
require("./utils/auth/strategies/linkedin");

//Facebook Strategy
require("./utils/auth/strategies/facebook");

//Ruta de SignIn
app.post("/auth/sign-in", async function (req, res, next) {
  const { rememberMe } = req.body;

  passport.authenticate("basic", (error, data) => {
    try {
      if (error || !data) {
        next(boom.unauthorized());
      }
      req.login(data, { session: false }, async (error) => {
        if (error) next(error);

        const { token, ...user } = data; //destructuramos el data

        if (!config.dev) {
          res.cookie("token", token, {
            httpOnly: true,
            secure: true,
            maxAge: rememberMe ? THIRTY_DAYS_IN_SECONDS : TWO_HOURS_IN_SECONDS,
          });
        } else {
          res.cookie("token", token, {
            withCredentials: true,
          });
        }
        res.status(200).json(user);
      });
    } catch (error) {
      next(error);
    }
  })(req, res, next);
});

//Ruta de SignUp
app.post("/auth/sign-up", async function (req, res, next) {
  const { body: user } = req;
  try {
    await axios({
      url: `${config.apiUrl}/api/auth/sign-up`,
      method: "post",
      data: user,
    });
    res.status(201).json("user created");
  } catch (error) {
    next(error);
  }
});

//Ruta de GetMovies
app.get("/movies", async function (req, res, next) {});

//Ruta de CreateUserMovies
app.post("/user-movies", async function (req, res, next) {
  try {
    const { body: userMovie } = req;
    const { token } = req.cookies;

    const { data, status } = await axios({
      url: `${config.apiUrl}/api/user-movies`,
      headers: { Authorization: `Bearer ${token}` },
      method: "post",
      data: userMovie,
      withCredentials: true,
    });

    if (status !== 201) {
      return next(boom.badImplementation());
    }

    res.status(201).json(data);
  } catch (error) {
    next(error);
  }
});

//Ruta de DeleteUserMovies
app.delete("/user-movies/:userMovieId", async function (req, res, next) {
  try {
    const { userMovieId } = req.params;
    const { token } = req.cookies;

    const { data, status } = await axios({
      url: `${config.apiUrl}/api/user-movies/${userMovieId}`,
      headers: { Authorization: `Bearer ${token}` },
      method: "delete",
    });

    if (status !== 200) {
      return next(boom.badImplementation());
    }

    res.status(200).json(data);
  } catch (error) {
    next(error);
  }
});

//Ruta de autenticacion OAuth2 con Google
app.get(
  "/auth/google-oauth",
  passport.authenticate("google-oauth", {
    scope: ["email", "profile", "openid"],
  })
);

//Ruta del callback OAuth2 de Google
app.get(
  "/auth/google-oauth/callback",
  passport.authenticate("google-oauth", { session: false }),
  function (req, res, next) {
    if (!req.user) {
      next(boom.unauthorized());
    }

    const { token, ...user } = req.user;

    res.cookie("token", token, {
      httpOnly: !config.dev,
      secure: !config.dev,
    });

    res.status(200).json(user);
  }
);

//Ruta de autenticacion OpenID con Google
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["email", "profile", "openid"],
  })
);

//Ruta del callback OpenID de Google
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { session: false }),
  function (req, res, next) {
    if (!req.user) {
      next(boom.unauthorized());
    }

    const { token, ...user } = req.user;

    res.cookie("token", token, {
      httpOnly: !config.dev,
      secure: !config.dev,
    });

    res.status(200).json(user);
  }
);

//Ruta de autenticacion con Twitter
app.get("/auth/twitter", passport.authenticate("twitter"));

//Ruta del callback de Twitter  (con el que creamos el token)
app.get(
  "/auth/twitter/callback",
  passport.authenticate("twitter", { session: false }),
  function (req, res, next) {
    if (!req.user) {
      next(boom.unauthorized());
    }

    const { token, ...user } = req.user;

    res.cookie("token", token, {
      httpOnly: !config.dev,
      secure: !config.dev,
    });

    res.status(200).json(user);
  }
);

//Ruta de autenticacion con Linkedin
app.get(
  "/auth/linkedin",
  passport.authenticate("linkedin", { state: "SOME STATE" })
);

//Ruta del callback de Linkedin
app.get(
  "/auth/linkedin/callback",
  passport.authenticate("linkedin", { session: false }),
  function (req, res, next) {
    if (!req.user) {
      next(boom.unauthorized());
    }

    const { token, ...user } = req.user;

    res.cookie("token", token, {
      httpOnly: !config.dev,
      secure: !config.dev,
    });

    res.status(200).json(user);
  }
);

//Ruta de autenticacion con facebook
app.get(
  "/auth/facebook",
  passport.authenticate("facebook", { scope: ["email"] })
);

//Ruta del callback de facebook
app.get(
  "/auth/facebook/callback",
  passport.authenticate("facebook", { session: false }),
  function (req, res, next) {
    if (!req.user) {
      next(boom.unauthorized());
    }

    const { token, ...user } = req.user;

    res.cookie("token", token, {
      httpOnly: !config.dev,
      secure: !config.dev,
    });

    res.status(200).json(user);
  }
);

//Puerto del servidor de express
app.listen(config.port, function () {
  console.log(`Listening http://localhost:${config.port}`);
});
