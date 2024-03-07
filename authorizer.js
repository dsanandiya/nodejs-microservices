const jwt = require('jsonwebtoken')
const JWT_SECRET = 'rocketseat-api-secret'

module.exports.handler = async (event) => {
  const authorization = event.authorizationToken
  const methodArn = event.methodArn

  if (!authorization) {
    return generateAuthResponse('Deny', methodArn)
  }

  try {
    const token = authorization.replace('Bearer ', '')

    const decoded = jwt.verify(token, JWT_SECRET)
    console.log('Allow', decoded)

    return generateAuthResponse('Allow', methodArn)
  } catch (err) {
    return generateAuthResponse('Deny', methodArn)
  }

  function generateAuthResponse (effect, methodArn) {
    const policyDocument = generatePolicyDocument(effect, methodArn)

    return {
      principalId: 'lambda-authorizer',
      policyDocument,
    }
  }

  function generatePolicyDocument (effect, methodArn) {
    if (!effect || !methodArn) return null

    const policyDocument = {
      Version: '2012-10-17',
      Statement: [{
        Action: 'execute-api:invoke',
        Effect: effect,
        Resouce: methodArn,
      }],
    }

    return policyDocument
  }
}
