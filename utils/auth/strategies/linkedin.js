const passport = require("passport");
const boom = require("@hapi/boom");
const axios = require("axios");
const { Strategy: LinkedinStrategy } = require("passport-linkedin-oauth2");

const { config } = require("../../../config");

passport.use(
  new LinkedinStrategy(
    {
      clientID: config.linkedinClientId,
      clientSecret: config.linkedinClientSecret,
      callbackURL: "auth/linkedin/callback",
      scope: ["r_emailaddress", "r_liteprofile"],
    },
    async (accessToken, refreshToken, profile, done) => {
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
          return done(boom.unauthorized(), false);
        }

        return done(null, data);
      } catch (error) {
        cb(error);
      }
    }
  )
);
