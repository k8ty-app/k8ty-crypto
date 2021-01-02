package app.k8ty.crypto

import java.security.SecureRandom
import java.util.Base64

import javax.crypto.{Cipher, Mac, SecretKeyFactory}
import javax.crypto.spec.{PBEKeySpec, SecretKeySpec}

import scala.util.Try

object Crypto extends Crypto

trait Crypto {

  private val PBKDF2_ALGORITHM: String = "PBKDF2WithHmacSHA1"
  private val SALT_BYTE_SIZE: Int = 24
  private val HASH_BYTE_SIZE: Int = 24
  private val PBKDF2_ITERATIONS: Int = 1000
  private val ITERATION_INDEX: Int = 0
  private val SALT_INDEX: Int = 1
  private val PBKDF2_INDEX: Int = 2

  private def slowEquals(a: Array[Byte], b: Array[Byte]): Boolean = {
    val range = 0 until math.min(a.length, b.length)
    val diff = range.foldLeft(a.length ^ b.length) {
      case (acc, i) => acc | a(i) ^ b(i)
    }
    diff == 0
  }

  private def pbkdf2(message: Array[Char], salt: Array[Byte], iterations: Int, bytes: Int): Array[Byte] = {
    val keySpec: PBEKeySpec = new PBEKeySpec(message, salt, iterations, bytes * 8)
    val skf: SecretKeyFactory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM)
    skf.generateSecret(keySpec).getEncoded
  }

  private def fromHex(hex: String): Array[Byte] = {
    hex.sliding(2, 2).toArray.map(Integer.parseInt(_, 16).toByte)
  }

  private def toHex(array: Array[Byte]): String = {
    array.map("%02X" format _).mkString
  }

  /**
   * Creates a PBKDF2 hash
   *
   * @param str
   * @return A hash of the form nIteration:salt:hash
   *         where salt and hash are in hex form
   */
  def pbkdf2Hash(str: String, iterations: Int = PBKDF2_ITERATIONS): String = {

    val rng: SecureRandom = new SecureRandom()
    val salt: Array[Byte] = Array.ofDim[Byte](SALT_BYTE_SIZE)
    rng.nextBytes(salt)
    val hashBytes = pbkdf2(str.toCharArray, salt, iterations, HASH_BYTE_SIZE)
    s"$iterations:${toHex(salt)}:${toHex(hashBytes)}"

  }

  /**
   * Validates a PBKDF2 hash
   *
   * @param str  The plain text you are confirming
   * @param hash The hash, in form of nIteration:salt:hash
   * @return
   */
  def validatePbkdf2Hash(str: String, hash: String): Boolean = {
    val hashSegments = hash.split(":")
    val validHash = fromHex(hashSegments(PBKDF2_INDEX))
    val hashIterations = hashSegments(ITERATION_INDEX).toInt
    val hashSalt = fromHex(hashSegments(SALT_INDEX))
    val testHash = pbkdf2(str.toCharArray, hashSalt, hashIterations, HASH_BYTE_SIZE)
    slowEquals(validHash, testHash)
  }

  private class AESKeyLengthException extends Exception("AES key length must be 16, 24, or 32")

  /**
   * Validate the length of a key used for AES De/Encryption
   *
   * @param key
   * @return true if key length is valid
   */
  private def validateAESKeyLength(key: String): Boolean = {
    key.getBytes.length == 16 || key.getBytes.length == 24 || key.getBytes.length == 32
  }

  /**
   * AES encrypt plainText using key. key must be of length 16, 24, or 32
   *
   * @param key
   * @param message
   * @return
   */
  def aesEncrypt(message: String, key: String): Try[String] = {
    val attempt = for {
      cipher <- Try(Cipher.getInstance("AES/ECB/PKCS5PADDING"))
      secretKey <- Try(new SecretKeySpec(key.getBytes("UTF-8"), "AES"))
    } yield {
      Try {
        if (!validateAESKeyLength(key)) throw new AESKeyLengthException
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        base64Encode(cipher.doFinal(message.getBytes))
      }
    }
    attempt.flatten
  }

  def aesDecrypt(message: String, key: String): Try[String] = {
    val attempt = for {
      cipher <- Try(Cipher.getInstance("AES/ECB/PKCS5PADDING"))
      secretKey <- Try(new SecretKeySpec(key.getBytes("UTF-8"), "AES"))
    } yield {
      Try {
        if (!validateAESKeyLength(key)) throw new AESKeyLengthException
        cipher.init(Cipher.DECRYPT_MODE, secretKey)
        cipher.doFinal(base64DecodeToBytes(message)).map(_.toChar).mkString
      }
    }
    attempt.flatten
  }

  private def hmac(message: String, key: String, macInstance: String) = {

    val mac = Mac.getInstance(macInstance)
    val secretKey = new SecretKeySpec(key.getBytes("UTF-8"), macInstance)
    mac.init(secretKey)
    base64Encode(mac.doFinal(message.getBytes("UTF-8")))

  }

  def hmac256(message: String, key: String): String = hmac(message, key, "HmacSHA256")

  def validateHmac256(message: String, key: String, hs256: String): Boolean = {
    val calc = hmac256(message, key)
    slowEquals(calc.getBytes("UTF-8"), hs256.getBytes("UTF-8"))
  }

  def hmac512(message: String, key: String): String = hmac(message, key, "HmacSHA512")

  def validateHmac512(message: String, key: String, hs512: String): Boolean = {
    val calc = hmac512(message, key)
    slowEquals(calc.getBytes("UTF-8"), hs512.getBytes("UTF-8"))
  }

  def base64Encode(bytes: Array[Byte]): String = Base64.getUrlEncoder.withoutPadding().encodeToString(bytes)
  def base64Encode(str: String): String = Base64.getUrlEncoder.withoutPadding().encodeToString(str.getBytes("UTF-8"))
  def base64Decode(str: String): String = new String(Base64.getUrlDecoder.decode(str))
  def base64DecodeToBytes(str: String): Array[Byte] = Base64.getUrlDecoder.decode(str)

  def generatePublicKey: String = {

    val random = new SecureRandom()

    // exclude 58-64, 91-96
    def loop(list: List[Int]): List[Int] = list.length match {
      case 16 => list
      case tl if list.length < 16 => {
        val nextInt = random.nextInt(75) + 48
        if ((nextInt >= 58 && nextInt <= 64) || (nextInt >= 91 && nextInt <= 96)) {
          loop(list)
        } else {
          loop(list :+ nextInt)
        }
      }
      case _ => loop(List())
    }

    loop(List()).map(_.toChar).mkString
  }

  def generatePrivateKey: String = {
    val random = new SecureRandom()
    (1 to 32).map { _ =>
      (random.nextInt(75) + 48).toChar
    }.mkString.replaceAll("\\\\+", "/")
  }

}
