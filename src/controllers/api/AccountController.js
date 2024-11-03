/**
 * @file Defines the AccountController class.
 * @module controllers/AccountController
 * @author Mats Loock
 * @version 3.1.0
 */

import http from 'node:http'
import { logger } from '../../config/winston.js'
import { JsonWebToken } from '../../lib/JsonWebtoken.js'
import { UserModel } from '../../models/UserModel.js'
import fs from 'fs-extra'
import jwt from 'jsonwebtoken'

/**
 * Encapsulates a controller.
 */
export class AccountController {
  #accessToken

  constructor () {
    this.#accessToken = fs.readFileSync('private.pem', 'utf8')
  }

  async userInfo (req, res, next) {
    const secret = 'djsakhduh28'
    const { token } = req.cookies
    // const user = await JsonWebToken.decodeUser(jwt, secret)

    jwt.verify(token, secret, {}, (err, info) => {
      if (err) throw err
      res.status(200).json(info)
    })
  }

  /**
   * Authenticates a user.
   *
   * @param {object} req - Express request object.
   * @param {object} res - Express response object.
   * @param {Function} next - Express next middleware function.
   */
  async login (req, res, next) {
    try {
      const secret = 'djsakhduh28'
      logger.silly('Authenticating user', { body: req.body })

      const userDocument = await UserModel.authenticate(req.body.username, req.body.password, next)
      const user = userDocument.toObject()

      // Create the access token with the shorter lifespan.
      const accessToken = await JsonWebToken.encodeUser(user,
        secret,
        86400000
      )

      logger.silly('Authenticated user', { user })

      res.cookie('token', accessToken, {
        httpOnly: true, // Prevents JavaScript access
        secure: true, // Use true if serving over HTTPS
        sameSite: 'Strict', // Helps prevent CSRF attacks
        maxAge: 86400000 // Cookie expiration in milliseconds (1 day)
      })

      res
        .status(201)
        .json({
          message: 'Login successful'
        })
    } catch (error) {
      next(error)
    }
  }

  logout (req, res, next) {
    res.cookie('token', '').json('ok')
  }

  /**
   * Registers a user.
   *
   * @param {object} req - Express request object.
   * @param {object} res - Express response object.
   * @param {Function} next - Express next middleware function.
   */
  async register (req, res, next) {
    try {
      logger.silly('Creating new user document', { body: req.body })

      const { username, password } = req.body

      // Validate input
      if (!username || !password) {
        const error = new Error('Username and password are required')
        error.status = 400 // Bad request
        throw error
      }

      if (password.length < 5) {
        const error = new Error('The password must be at least 5 characters long')
        error.status = 400
        throw error
      }

      const userDocument = await UserModel.create({
        username,
        password
      })

      logger.silly('Created new user document')

      res
        .status(201)
        .json({ message: 'User created successfully', id: userDocument.id })
    } catch (error) {
      let httpStatusCode = 500

      if (error.code === 11_000) {
        // Duplicated keys.
        httpStatusCode = 409
      } else if (error.name === 'ValidationError') {
        // Validation error(s).
        httpStatusCode = 400
      }

      const err = new Error(http.STATUS_CODES[httpStatusCode])
      err.status = httpStatusCode
      err.cause = error

      next(err)
    }
  }
}
