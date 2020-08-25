const passport = require("passport");
const { Strategy: FacebookStrategy } = require("passport-facebook");
const boom = require("@hapi/boom");
const axios = require("axios");

const { config } = require("../../../config/index");

passport.use(
  new FacebookStrategy(
    {
      clientID: config.facebookClientId,
      clientSecret: config.facebookClientSecret,
      callbackURL: "/auth/facebook/callback",
      profileFields: ["id", "displayName", "photos", "email"],
    },
    async function (accessToken, refreshToken, { _json: profile }, cb) {
      console.log(profile);
      try {
        const { data, status } = await axios({
          url: `${config.apiUrl}/api/auth/sign-provider`,
          method: "post",
          data: {
            name: profile.name,
            email: profile.email,
            password: profile.id,
            apiKeyToken: config.apiKeyToken,
          },
        });

        if (!data || status !== 200) {
          return cb(boom.unauthorized(), false);
        }

        return cb(null, data);
      } catch (error) {
        cb(error);
      }
    }
  )
);
