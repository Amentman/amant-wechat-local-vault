# Public implementation sources

This Skill does not vendor or copy files from the user-supplied
`mcncarl/yichen-skills` reference repository. That repository's license limits
redistribution, so its source is not a code dependency of this package.

The implementation is maintained against public interface documentation:

- Frida JavaScript API: global export lookup, `Interceptor.attach`, invocation
  context and pointer reads: <https://frida.re/docs/javascript-api/>
- Apple's CommonCrypto export list confirms the public
  `CCKeyDerivationPBKDF` symbol:
  <https://github.com/apple-oss-distributions/CommonCrypto/blob/main/exports.exp-in>
- Apple's bypass-code sample demonstrates calling `CCKeyDerivationPBKDF` with
  password, salt, rounds and derived-key output arguments:
  <https://developer.apple.com/documentation/devicemanagement/creating-and-using-bypass-codes>
- SQLCipher design and API documentation for page size, salt, HMAC and KDF
  behavior: <https://www.zetetic.net/sqlcipher/design/> and
  <https://www.zetetic.net/sqlcipher/sqlcipher-api/>

Frida, PyCryptodome and Zstandard retain their own licenses. They are installed
as runtime dependencies and are not copied into this repository.
