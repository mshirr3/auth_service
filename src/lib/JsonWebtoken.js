/**
 * @file  Provides helper methods for working with JSON Web Tokens (JWTs).
 * @module lib/JsonWebTokens
 * @author Mats Loock
 * @version 1.0.0
 */

import jwt from 'jsonwebtoken'

/**
 * Exposes methods for working with JSON Web Tokens (JWTs).
 */
export class JsonWebToken {
  /**
   * Decodes a JWT and returns the user object extracted from the payload.
   *
   * @param {string} token - The JWT to decode.
   * @param {string} key - The secret key used for verifying the JWT.
   * @returns {Promise<object>} A Promise that resolves to the user object extracted from the JWT payload.
   */
  static async decodeUser (token, key) {
    return new Promise((resolve, reject) => {
      jwt.verify(token, key, (error, decoded) => {
        if (error) {
          reject(error)
          return
        }

        console.log(decoded)
        const user = {
          id: decoded.sub,
          firstName: decoded.firstName,
          lastName: decoded.lastName,
          email: decoded.email,
          permissionLevel: decoded.permissionLevel,
          username: decoded.username
        }

        resolve(user)
      })
    })
  }

  /**
   * Encodes user information into a JSON Web Token (JWT) payload.
   *
   * @param {object} user - The user object containing user information to encode.
   * @param {string} secret - The secret key used for signing the JWT.
   * @param {string|number} expiresIn - The expiration time for the JWT, specified in seconds or as a string describing a time span (e.g., '1d', '2h') using the vercel/ms library.
   * @returns {Promise<string>} A Promise that resolves to the generated JWT.
   */
  static async encodeUser (user, secret, expiresIn) {
    const payload = {
      sub: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      permissionLevel: user.permissionLevel,
      username: user.username
    }

    return new Promise((resolve, reject) => {
      jwt.sign(
        payload,
        secret,
        {
          algorithm: 'RS256',
          expiresIn
        },
        (error, token) => {
          if (error) {
            reject(error)
            return
          }

          resolve(token)
        }
      )
    })
  }
}
