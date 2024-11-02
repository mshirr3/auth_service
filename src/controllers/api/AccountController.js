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

/**
 * Encapsulates a controller.
 */
export class AccountController {
  #accessToken

  constructor () {
    this.#accessToken = fs.readFileSync('private.pem', 'utf8')
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
      logger.silly('Authenticating user', { body: req.body })

      const userDocument = await UserModel.authenticate(req.body.username, req.body.password, next)
      const user = userDocument.toObject()
      console.log(user)
      console.log(process.env.ACCESS_TOKEN_LIFE)
      console.log('private key set as env')
      // Create the access token with the shorter lifespan.
      const accessToken = await JsonWebToken.encodeUser(user,
        this.#accessToken,
        process.env.ACCESS_TOKEN_LIFE
      )

      logger.silly('Authenticated user', { user })

      res
        .cookie('token', accessToken) // send as cookie
        .status(201)
        .json({
          message: 'Login successful'
        })
    } catch (error) {
      next(error)
    }
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
